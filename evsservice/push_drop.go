// The DROP push's I/O on evs (§11.7's action, fence and cancel rows, §11.8's 5c, step 7 and step 8; D-EVS-16,
// D-QUOTA-12, I-EVS-15, FS-91, FS-95; DESIGN-DETAILS 10.2.2, 10.2.5, 10.2.7 and 10.7's note; EVS2-M10-09). Step 5's
// rules over what this reads are check_drop.go's and check_dropped.go's.
//
//	fence     at a format-2 instance, step 4 reads, in its round, the bodies of every bit-5 entry of the window of the
//	          head it read of the push's own ref and of each reuse source's ref, whatever its digest says (reading 4),
//	          from the process's DropIndex or a batch range, a DROP in parts' from its part 1; a seal's heads, and an
//	          attempt's after a refusal on a cached head, from the cluster
//	reads     a DROP's own at a one-part push or a seal: its lists as received, section 10's slices; each removed
//	          lineage's newest entry where its epoch is current or a listed source; a cancel's target at
//	          cancels_version (window or log page), the window's later cancels of it, and drops/<repo>/_
//	counted   after step 5, at a one-part push or a seal, for a drop and never a cancel: 429 RESOURCE_EXHAUSTED while
//	          the table's pending, executing and observed entries and void records would pass its admit bound (QD-179's
//	          rule 5), then evs_drops_per_day through Quota.CountRate under the push's id, a refusal 429 refusing
//	          nothing (owner decision 183). A part counts nothing
//	step 7    the window entry's bit 5 (sidecar.NewEvsWindowEntry sets it for flag 256)
//	step 8    off the reply path, DropSink.Append of the committed DROP or cancel with seen_ms, the engine's clock read
//	          after step 7's 200, paid at P1 from the repo's network; nothing on an unsure clock. Its loss is covered by
//	          evacuation's append and the daily LIST of drops/
//	repair    a push that met a bit-5 entry on a head read from the cluster appends it again, with seen_ms read after
//	          that read, once a process (DropIndex.Appended), off the reply path, since the table may lack it
//
// evs reads no hold/ here: a hold never refuses a DROP (owner decision 184).

package evsservice

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A bit-5 window entry an attempt met on a head read from the cluster, and the clock read after that read.
type metDrop struct {
	refId  sidecar.Id
	body   *DropBody
	seenAt time.Time
}

// The fence of refId at head: the DROPs of action 1 among its window's bit-5 entries. readAt is the clock read after
// the head's cluster read, for the repair append; a cached head appends nothing.
func (self *pushAttempt) readDropFence(refId sidecar.Id, head *EvsStoredHead, readAt time.Time) (*EvsDropFence, []*metDrop, error) {
	fence := &EvsDropFence{Cached: head.Cached}
	if head.Absent() || head.Version() == 0 {
		return fence, nil, nil
	}
	window, err := EvsHeadWindow(head.Head)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrEvsHeadInvalid, err)
	}
	first := EvsHeadWindowFirstVersion(head.Head)
	met := []*metDrop{}
	for i, entry := range window {
		if !entry.Drop() {
			continue
		}
		body, err := self.engine.dropIndex.Body(self.ctx, self.cluster, self.repoId, refId, first+uint64(i), entry)
		if err != nil {
			return nil, nil, err
		}
		if body.Drop() {
			fence.Drops = append(fence.Drops, body)
		}
		if !head.Cached {
			met = append(met, &metDrop{refId: refId, body: body, seenAt: readAt})
		}
	}
	return fence, met, nil
}

// The fence of the push's own ref on self.head again, after a 412 or a lost answer made the attempt reread it from
// the cluster: a DROP may have committed since step 4. Nothing at a format-1 instance.
func (self *pushAttempt) rereadOwnFence() *pushOutcome {
	if !self.engine.format2Instance() || self.reads == nil {
		return nil
	}
	fence, met, err := self.readDropFence(self.refId, self.head, self.engine.clock.Now())
	if err != nil {
		return self.unavailableOn(err)
	}
	self.reads.ownFence = fence
	self.metDrops = append(self.metDrops, met...)
	return nil
}

// A DROP's own reads at a one-part push or a seal over head: nil for any other push and for a part.
func (self *pushAttempt) readDropReads(head *EvsStoredHead) (*PushDropReads, error) {
	if self.payload == nil || self.payload.Drop == nil || self.part != nil {
		return nil, nil
	}
	reads := &PushDropReads{
		Removed:      map[int]*DropRemovedRead{},
		CancelMargin: self.settings.Drop.CancelMargin,
	}
	if self.seal != nil {
		reads.ListSlices = self.seal.dropListSlices
	} else {
		payload, err := sidecar.ParseEvsPayloadFormat2(self.payloadBytes)
		if err != nil {
			return nil, err
		}
		reads.ListSlices = [][]byte{payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_LISTS)}
	}
	history := self.payload.Drop.History
	if self.payload.Drop.Cancel() {
		cancel, err := self.readDropCancel(head, history)
		if err != nil {
			return nil, err
		}
		reads.Cancel = cancel
		return reads, nil
	}
	if head.Absent() || head.Version() == 0 {
		return reads, nil
	}
	currentEpoch := EvsHeadCurrentEpoch(head.Head)
	listed := map[uint64]bool{}
	for _, source := range head.Head.GetPathEpoch().GetSources() {
		listed[source.GetEpoch()] = true
	}
	for i, path := range history.GetPaths() {
		if path.GetBoundary() != evsDropBoundaryRemoved {
			continue
		}
		newest := path.GetLineage()[0]
		if newest.GetEpoch() != currentEpoch && !listed[newest.GetEpoch()] {
			// an older epoch's: its shape alone here, its boundary resolve's (10.7's note)
			continue
		}
		tokenPath, err := sidecar.ParseEvsChangedTokenPath(newest.GetTokenPath())
		if err != nil {
			return nil, err
		}
		removed, err := self.readDropRemoved(head, newest.GetEpoch(), tokenPath)
		if err != nil {
			return nil, err
		}
		reads.Removed[i] = removed
	}
	return reads, nil
}

// A removed lineage's newest entry at epoch: the current epoch's by §11.7's newest rule over the head's window, a
// listed source's by its entry, its marker's path version the removal's.
func (self *pushAttempt) readDropRemoved(head *EvsStoredHead, epoch uint64, tokenPath sidecar.EvsTokenPath) (*DropRemovedRead, error) {
	if epoch != EvsHeadCurrentEpoch(head.Head) {
		read, err := ReadEntry(self.ctx, self.cluster, self.repoId, self.refId, epoch, tokenPath, head.Head.GetFoldedThrough())
		if err != nil {
			return nil, err
		}
		switch {
		case read.Absent():
			return &DropRemovedRead{}, nil
		case read.Entry.GetMarker() != nil:
			return &DropRemovedRead{Known: true, RemovalVersion: read.Entry.GetMarker().GetPathVersion()}, nil
		}
		return &DropRemovedRead{Known: true, Exists: 0 < len(read.Entry.GetVersions()) || read.Entry.GetNames() != nil}, nil
	}
	read, err := ReadPathEntry(self.ctx, self.cluster, self.repoId, self.refId, head.Head, &EvsPathTokens{Current: tokenPath})
	if err != nil {
		return nil, err
	}
	newest, err := Newest(self.ctx, read.EvsEntryRead, head.Head, self.pushes)
	switch {
	case errors.Is(err, ErrEvsEntryBehindWindow), errors.Is(err, ErrEvsEntryAheadOfHead), errors.Is(err, ErrEvsHorizonAhead):
		// the head moved under the read: resolve judges it against history
		return &DropRemovedRead{}, nil
	case err != nil:
		return nil, err
	}
	if !newest.Exists && newest.RemovalVersion == 0 {
		// never written, or its marker collected: resolve judges it
		return &DropRemovedRead{}, nil
	}
	return &DropRemovedRead{Known: true, Exists: newest.Exists, RemovalVersion: newest.RemovalVersion}, nil
}

// A cancel's target at cancels_version on head: the DROP committed there, whether the window after it holds a cancel
// of it, and whether the table shows it ended.
func (self *pushAttempt) readDropCancel(head *EvsStoredHead, history *protocol.EvsDropHistory) (*DropCancelRead, error) {
	cancel := &DropCancelRead{}
	version := history.GetCancelsVersion()
	if head.Absent() || version == 0 || head.Version() < version {
		return cancel, nil
	}
	entry := windowEntryAt(head.Head, version)
	if entry == nil {
		page, err := self.engine.readLogPage(self.ctx, self.cluster, self.repoId, self.refId, EvsLogPageOf(version))
		if err != nil {
			return nil, err
		}
		var found bool
		if entry, _, found = page.At(version); !found {
			return nil, fmt.Errorf("%w: log page %d lacks version %d", ErrEvsStatementMismatch, page.Page, version)
		}
	}
	if !entry.Drop() {
		return cancel, nil
	}
	target, err := self.engine.dropIndex.Body(self.ctx, self.cluster, self.repoId, self.refId, version, entry)
	if err != nil {
		return nil, err
	}
	if !target.Drop() || !bytes.Equal(target.Lists.History().GetDropId(), history.GetCancelsDropId()) {
		return cancel, nil
	}
	cancel.Found = true
	cancel.NotBeforeMs = target.Lists.History().GetNotBeforeMs()
	// a cancel of it in the window after it
	window, err := EvsHeadWindow(head.Head)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsHeadInvalid, err)
	}
	first := EvsHeadWindowFirstVersion(head.Head)
	for i, later := range window {
		laterVersion := first + uint64(i)
		if laterVersion <= version || !later.Drop() {
			continue
		}
		body, err := self.engine.dropIndex.Body(self.ctx, self.cluster, self.repoId, self.refId, laterVersion, later)
		if err != nil {
			return nil, err
		}
		laterHistory := body.Lists.History()
		if !body.Drop() && bytes.Equal(laterHistory.GetCancelsDropId(), history.GetCancelsDropId()) && laterHistory.GetCancelsVersion() == version {
			cancel.Ended = true
			return cancel, nil
		}
	}
	// the table, which its cancel's append and the job move
	table, err := self.engine.drops.Read(self.ctx, self.cluster, self.repoId)
	if err != nil {
		return nil, err
	}
	dropId := sidecar.Id(history.GetCancelsDropId())
	if table.State.Void(dropId) != nil {
		cancel.Ended = true
	} else if tableEntry := table.State.Drop(dropId); tableEntry != nil && tableEntry.State != DropStatePending {
		cancel.Ended = true
	}
	return cancel, nil
}

// After step 5, at a one-part push or a seal, for a drop: the table's admit bound, then evs_drops_per_day. A cancel,
// a part and any other push pass.
func (self *pushAttempt) countDrop() *pushOutcome {
	if self.part != nil || self.payload == nil || self.payload.Drop == nil || self.payload.Drop.Cancel() {
		return nil
	}
	settings := self.settings.Drop
	table, err := self.engine.drops.Read(self.ctx, self.cluster, self.repoId)
	if err != nil {
		return self.unavailableOn(err)
	}
	dropId := sidecar.Id(self.payload.Drop.History.GetDropId())
	if table.State.Drop(dropId) == nil && table.State.Void(dropId) == nil && !table.State.AdmitsDrop(settings) {
		return refusedOutcome(&protocol.EvsRefusalReply{
			PushId:       self.pushId.Bytes(),
			Code:         protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED,
			RetryAfterMs: uint32(max(1, settings.TableFullRetryAfter.Milliseconds())),
		})
	}
	quota := self.engine.host.Quota
	if quota == nil {
		return self.unavailable()
	}
	refusal, err := quota.CountRate(self.ctx, connect.Id(self.networkId), map[string]int64{sidecar.QuotaRateKeyDrop: 1}, connect.Id(self.pushId))
	switch {
	case err != nil:
		return self.unavailable()
	case refusal != nil:
		reply := evsQuotaRefusalReply(refusal)
		reply.PushId = self.pushId.Bytes()
		return refusedOutcome(reply)
	}
	return nil
}

// The drop sink step 8 and the repair appends use: the deps', else the engine's own table.
func (self *EvsEngine) dropSink() DropSink {
	if self.deps.Drops != nil {
		return self.deps.Drops
	}
	return self.drops
}

// Step 8's append of a committed DROP or cancel, with seenAt the clock read after step 7's 200. Off the reply path; a
// failure is logged, since evacuation's append and the daily LIST cover it.
func (self *EvsEngine) appendCommittedDrop(committed *EvsCommitted) {
	if committed.Payload == nil || committed.Payload.Drop == nil || committed.Head == nil || committed.Head.Absent() {
		return
	}
	window, err := EvsHeadWindow(committed.Head.Head)
	if err != nil || len(window) == 0 {
		return
	}
	entry := window[len(window)-1]
	self.appendDrop(committed.RepoNetworkId, committed.ClusterId, committed.RepoId, &DropCommit{
		ClusterId: committed.ClusterId,
		RepoId:    committed.RepoId,
		RefId:     committed.RefId,
		PushId:    sidecar.Id(committed.Statement.Push.GetPushId()),
		Version:   committed.Head.Version(),
		Place:     entry.Place,
		Body:      committed.Payload.Drop.History,
	}, committed.SeenAt)
}

// The repair appends of the bit-5 entries an attempt met on heads read from the cluster, each once a process.
func (self *EvsEngine) appendMetDrops(networkId sidecar.Id, clusterId string, repoId sidecar.Id, met []*metDrop) {
	type metKey struct {
		refId   sidecar.Id
		version uint64
	}
	seen := map[metKey]bool{}
	for _, drop := range met {
		key := metKey{refId: drop.refId, version: drop.body.Version}
		if seen[key] || self.dropIndex.Appended(clusterId, repoId, drop.refId, drop.body.Version) {
			continue
		}
		seen[key] = true
		self.appendDrop(networkId, clusterId, repoId, &DropCommit{
			ClusterId: clusterId,
			RepoId:    repoId,
			RefId:     drop.refId,
			PushId:    drop.body.PushId,
			Version:   drop.body.Version,
			Place:     drop.body.Place,
			Body:      drop.body.Lists.History(),
		}, drop.seenAt)
	}
}

// appendMetDrops off the caller's path, counted as a step 8 is, so a test waits for it as for any step 8.
func (self *EvsEngine) appendMetDropsAsync(networkId sidecar.Id, clusterId string, repoId sidecar.Id, met []*metDrop) {
	self.stepEightCount.Update(func(count int) int { return count + 1 })
	go func() {
		defer self.stepEightDoneCount.Update(func(count int) int { return count + 1 })
		self.appendMetDrops(networkId, clusterId, repoId, met)
	}()
}

// One append through the sink, paid at P1 from networkId: one overwrite of the table. Logged when it does not land.
func (self *EvsEngine) appendDrop(networkId sidecar.Id, clusterId string, repoId sidecar.Id, commit *DropCommit, seenAt time.Time) {
	sink := self.dropSink()
	if sink == nil || seenAt.IsZero() {
		return
	}
	cost, err := PricePush(self.priceTable, &PushOperations{
		Immediate: []WriteOperation{{Kind: WriteOperationOverwrite, ObjectByteCount: int64(self.settings.Drop.TableByteCount), Count: 1}},
	})
	if err != nil {
		self.log.Warningf("[evs] repo %s: a DROP's append not priced: %v", sidecar.EvsKeyId(repoId), err)
		return
	}
	grant, err := self.budget.AdmitP1(self.ctx, clusterId, connect.Id(networkId), cost)
	if err != nil {
		self.log.Infof("[evs] repo %s: a DROP's append not admitted, left to evacuation: %v", sidecar.EvsKeyId(repoId), err)
		return
	}
	defer grant.Close()
	err = sink.Append(grant.Context(), commit, seenAt.UnixMilli())
	switch {
	case errors.Is(err, ErrDropClockUnsure):
		self.log.Infof("[evs] repo %s: a DROP's append waits for a sure clock, left to evacuation", sidecar.EvsKeyId(repoId))
	case err != nil:
		self.log.Warningf("[evs] repo %s: a DROP's append failed, left to evacuation: %v", sidecar.EvsKeyId(repoId), err)
	default:
		self.dropIndex.NoteAppended(clusterId, repoId, commit.RefId, commit.Version)
	}
}
