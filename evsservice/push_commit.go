// Steps 6, 7 and 8 of a push (§11.8), once step 5 passed:
//
//	budget  the push's writes spend its cluster's write budget first: P1, queued in the token network's fair share at
//	        full price, its own writes and the P2 work it causes (§11.13's push row), so one grant pays the record,
//	        the slots, the page-out and the head; a budget past its shed delay answers 429 RESOURCE_EXHAUSTED, which
//	        refuses nothing
//	6       the record joins this process's open batch for the repo's cluster and waits for its write (batch.go);
//	        then, for a push with new slots, the slot round (DESIGN-DETAILS 14.2.3): each slot is created If-None-Match
//	        with the statement as its origin (slot_origin.go), and on a 412 or a lost answer the object's origin
//	        decides. The statement's own with equal bytes is success under 23 h old, older 409 SLOT_STALE, recorded;
//	        its own with other bytes sends the attempt to a cluster read of the head, where 5a finds the push
//	        committed if an ERASE rewrote the slot, else an alarm and SLOT_STALE. A retoken takes over the object of
//	        the statement it replaces, which can never commit (14.2.4): a settled DELETE naming its LastModified, then
//	        the create again. Any other object, one with no origin among them, is a cluster read of the head and 5a,
//	        then SLOT_STALE, recorded. So the record names every slot written, and a slot object is held by one
//	        statement. A window about to pass 127 versions pages out first (logpage.go)
//	7       the head If-Match step 4's ETag (If-None-Match for a ref with none): version v+1, C_{v+1}, the push, its
//	        pins, the window with the push's entry and without what was paged, folded_through as this process's
//	        folds raise it, the lease cleared, deleted for a DELETE; issued only within PushStepSevenWindow of step
//	        4's reads, else steps 4 and 5 run again. Its outcomes are outcome.go's
//	8       off the reply path: the push sequence and hints (EvsCommitNotifier, EVS1-M2-15's), usage, the head cache
//	        entry, which records the sequence the commit raised, and the fold trigger
//
// A record is committed only at the place its window entry names, so another attempt's copy of the same push is
// dead weight evacuation drops (§11.8's bind row), and nothing here deletes anything but the slot object a takeover
// takes from a statement that can never commit (DESIGN-DETAILS 14.2.4).

package evsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// What step 8 learns of a commit.
type EvsCommitted struct {
	RepoId    sidecar.Id
	RefId     sidecar.Id
	ClusterId string
	// The repo's network, whose stored bytes the commit adds to, and the caller's, whose transfer it is.
	RepoNetworkId   sidecar.Id
	CallerNetworkId sidecar.Id
	// The head as this commit wrote it.
	Head *EvsStoredHead
	// The statement and what its payload checked to.
	Statement *sidecar.EvsStatement
	Payload   *sidecar.EvsCheckedPayload
	// The record's bytes, which the batch stores until evacuation moves them, and the request's.
	RecordByteCount  int64
	RequestByteCount int64
	// The record's purge list for the purge, nil when it lists none the purge takes (push_purge.go).
	Purge *PurgeCommit
}

// Step 8's push sequence and hints (§11.10), which EVS1-M2-15 builds: raises {evsq_<repo_id>} and returns its new
// value, then hints every lease holder the commit matches. An error leaves the commit to the hourly resync, never
// an alarm, since all of it is soft state.
type EvsCommitNotifier interface {
	Notify(ctx context.Context, committed *EvsCommitted) (pushSequence uint64, err error)
}

// Steps 6 and 7 with step 7's outcomes. again asks for steps 4 and 5 again: the 5 s window passed, or a reread sent
// the attempt back.
func (self *pushAttempt) commit() (*pushOutcome, bool) {
	barrierKey := barrierRefKey(self.repoId, self.refId)
	testHookBarrier(BarrierPushStep6Before, barrierKey)
	outcome := self.step6()
	testHookBarrier(BarrierPushStep6After, barrierKey)
	if outcome != nil {
		return outcome, false
	}
	if outcome, again := self.raiseFormat(); outcome != nil || again {
		return outcome, again
	}
	conflicts := 0
	for {
		if !self.withinStepSeven() {
			return nil, true
		}
		next, outcome := self.nextHead()
		if outcome != nil {
			return outcome, false
		}
		prior := self.head
		self.issued = true
		written, err := self.engine.heads.Commit(self.writeCtx, self.cluster, self.repoId, self.refId, prior, next)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			self.head = written
			return self.committed(written), false
		case errors.Is(err, sidecar.ErrBlobPrecondition):
			// another write came first: this PUT can never apply, since an ETag never repeats
			self.issued = false
			conflicts += 1
			if self.settings.PushConflictRetryCount < conflicts {
				return self.busy(), false
			}
			outcome, again := self.afterConflict()
			if outcome != nil || again {
				return outcome, again
			}
		case errors.As(err, &unknown):
			outcome, again := self.afterUnknown(prior)
			if outcome != nil || again {
				return outcome, again
			}
		case errors.Is(err, ErrEvsHeadRule):
			// nothing was sent: a next head that breaks the head's rules is this code's fault
			self.issued = false
			self.engine.log.Errorf("[evs] alarm push_head_rule: repo %s ref %s: %v", sidecar.EvsKeyId(self.repoId), sidecar.EvsKeyId(self.refId), err)
			self.engine.metrics.alarms.Add(1, "push_head_rule")
			return self.unavailable(), false
		default:
			return self.unknown(), false
		}
	}
}

// §11.6's format row, between step 6's record and step 7: a push carrying a format-2 value, which 5c held to the
// format2 gate, raises a format-1 repo/ to format 2 (repo_format.go), under the push's own grant. The raise reads
// repo/ from the cluster, so a sibling's raise, or this push's own on an earlier attempt, is found there and nothing
// is written twice. A repo it finds in any state but active sends the attempt back to steps 4 and 5, where 5c
// refuses by its own rule on a head read from the cluster; lost races past RepoTransitionRetryCount answer 429,
// which refuses nothing. A raise whose push then fails stands, since format-1 data is valid format 2, and step 7's
// window still bounds the whole: a slow raise reruns steps 4 and 5. again asks for them.
func (self *pushAttempt) raiseFormat() (*pushOutcome, bool) {
	if !self.needsFormat2 || !self.engine.format2Instance() || sidecar.EvsRepoFormat2 <= self.reads.repo.Object.GetFormat() {
		return nil, false
	}
	classify := func(ctx context.Context, objectByteCount int) context.Context { return ctx }
	read, err := RaiseRepoFormat(self.writeCtx, self.cluster, self.engine.repos, self.repoId, self.settings.RepoTransitionRetryCount, classify)
	var refusal *EvsRepoRefusal
	switch {
	case err == nil:
		self.reads.repo = read
		return nil, false
	case errors.As(err, &refusal):
		// keying, deleted, shredding or shredded: no push commits on it, and 5c says which
		return nil, true
	case errors.Is(err, ErrEvsRepoBusy):
		return self.busy(), false
	}
	return self.unavailableOn(err), false
}

// Whether step 7 may still issue: within PushStepSevenWindow of step 4's reads.
func (self *pushAttempt) withinStepSeven() bool {
	return self.engine.clock.Now().Before(self.reads.readAt.Add(self.settings.PushStepSevenWindow))
}

// The 200 for this attempt's own commit.
func (self *pushAttempt) committed(written *EvsStoredHead) *pushOutcome {
	outcome := committedOutcome(written.Version(), written)
	if self.ownDepositRef() {
		outcome.depositHead = self.depositHeadOf(written.Head)
	}
	return outcome
}

// Step 6, once per attempt: the budget, the record and the new slots. A rerun of step 7 on a reread head keeps all
// three, since the record and the slots are this statement's whatever head it commits on.
func (self *pushAttempt) step6() *pushOutcome {
	// the tail first, so the push's price counts its purge list (push_staged.go)
	tail, err := self.recordTail()
	if err != nil {
		return self.unavailableOn(err)
	}
	if outcome := self.admit(); outcome != nil {
		return outcome
	}
	if self.place == nil {
		place, err := self.engine.batches.AppendFormat2(self.writeCtx, self.cluster.ClusterId(), self.batchRecord(), tail)
		if err != nil {
			// nothing this attempt carried reached a head
			return self.unavailable()
		}
		self.place = place
	}
	if !self.slotsWritten {
		if outcome := self.writeSlots(); outcome != nil {
			return outcome
		}
		self.slotsWritten = true
	}
	return nil
}

// The batch record this attempt appends at step 6: a push's statement and payload, or a seal's statement and parts
// (push_seal.go); a part's is push_part.go's.
func (self *pushAttempt) batchRecord() *sidecar.EvsBatchRecord {
	record := &sidecar.EvsBatchRecord{
		Type:            protocol.EvsBatchRecordType_EVS_BATCH_PUSH,
		RepoId:          self.repoId,
		RefId:           self.refId,
		PushId:          self.pushId,
		SignerSidecarId: sidecar.Id(self.statement.Push.GetSignerSidecarId()),
		TimeMs:          self.statement.Push.GetTimeMs(),
		Body:            sidecar.EvsPushRecordBody(self.statement.Bytes, self.payloadBytes),
	}
	if self.seal != nil {
		record.Type = protocol.EvsBatchRecordType_EVS_BATCH_SEAL
		record.Body = self.seal.body
	}
	return record
}

// The record's bytes as its batch holds them, for the cost and the usage count: a format-2 record's tail included,
// its purge list as bounded once computed (push_staged.go).
func (self *pushAttempt) recordByteCount() int64 {
	byteCount := int64(sidecar.EvsBatchRecordHeaderByteCount + len(self.batchRecord().Body))
	if 0 < len(self.staged) || (self.purge != nil && self.purge.list != nil) {
		byteCount += 8 + int64(len(self.staged))
		if self.purge != nil && self.purge.list != nil {
			byteCount += int64(proto.Size(self.purge.list))
		}
	}
	return byteCount
}

// The budget for the push's writes, once per attempt: AdmitP1 at its full price in the token network's queue.
func (self *pushAttempt) admit() *pushOutcome {
	if self.grant != nil {
		return nil
	}
	cost, err := self.cost()
	if err != nil {
		return self.unavailableOn(err)
	}
	if self.erasureP0() {
		// within its network's 60 a minute: P0, never queued or refused (§11.13's classes)
		self.writeCtx = self.engine.budget.IssueP0(self.ctx, self.cluster.ClusterId(), sidecar.WriteP0KindErasure, cost.ByteCount())
		self.grant = p0Grant{ctx: self.writeCtx}
		return nil
	}
	grant, err := self.engine.budget.AdmitP1(self.ctx, self.cluster.ClusterId(), connect.Id(self.tokenNetworkId), cost)
	var refusal *sidecar.WriteRefusal
	switch {
	case errors.As(err, &refusal):
		return refusedOutcome(&protocol.EvsRefusalReply{
			PushId:       self.pushId.Bytes(),
			Code:         protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED,
			RetryAfterMs: max(1, refusal.RetryAfterMs()),
		})
	case err != nil:
		return self.unavailable()
	}
	self.grant = grant
	self.writeCtx = grant.Context()
	return nil
}

// A P0 issue's ctx as a grant: nothing to release.
type p0Grant struct {
	ctx context.Context
}

func (self p0Grant) Context() context.Context {
	return self.ctx
}

func (self p0Grant) Close() {}

// §11.13's push row for this push, at one record a batch: now its head's overwrite, its batch share and its new
// slots; deferred its fold share (~0.3 folded entries a changed path), its batch's delete and evacuation (a parcel
// of its record and a pidx/ entry, as evacuation prices a batch) and its share of a log page.
func (self *pushAttempt) cost() (sidecar.WriteCost, error) {
	recordByteCount := self.recordByteCount()
	headByteCount := int64(len(self.head.Bytes) + sidecar.EvsWindowEntryByteCount)
	slotCount := 0
	changeCount := 0
	if self.payload != nil {
		changeCount = len(self.payload.Changes)
		for _, object := range self.payload.NewObjects {
			if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT {
				slotCount += 1
			}
		}
	}
	// the raise of a format-1 repo/ is priced with its push (§11.6's format row): one overwrite of repo/
	raiseCount := 0
	if self.needsFormat2 && self.reads.repo.Object.GetFormat() < sidecar.EvsRepoFormat2 {
		raiseCount = 1
	}
	return PricePush(self.engine.priceTable, &PushOperations{
		Immediate: []WriteOperation{
			{Kind: WriteOperationOverwrite, ObjectByteCount: headByteCount, Count: 1},
			{Kind: WriteOperationCreate, ObjectByteCount: recordByteCount, Count: 1},
			{Kind: WriteOperationCreate, ObjectByteCount: self.settings.SlotMaxByteCount, Count: float64(slotCount)},
			{Kind: WriteOperationOverwrite, ObjectByteCount: sidecar.EvsRepoObjectMaxByteCount, Count: float64(raiseCount)},
		},
		Deferred: []WriteOperation{
			{Kind: WriteOperationOverwrite, Count: 0.3 * float64(changeCount)},
			{Kind: WriteOperationDelete, Count: 1},
			{Kind: WriteOperationCreate, ObjectByteCount: recordByteCount, Count: 1},
			{Kind: WriteOperationCreate, Count: 1},
			{Kind: WriteOperationCreate, ObjectByteCount: sidecar.EvsLogPageMaxByteCount, Count: 1.0 / EvsLogPageVersionCount},
		},
	})
}

// Step 6's new slots, the slot round of DESIGN-DETAILS 14.2.3, once per attempt. The slots go in parallel, and a
// takeover's wait is per slot. See the file header.
func (self *pushAttempt) writeSlots() *pushOutcome {
	if self.payload == nil {
		return nil
	}
	slotIds := []sidecar.Id{}
	for _, object := range self.payload.NewObjects {
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT {
			slotIds = append(slotIds, sidecar.Id(object.Id))
		}
	}
	if len(slotIds) == 0 {
		return nil
	}
	if len(slotIds) != len(self.payload.SlotBodies) {
		return refusedOutcome(newEvsCheckRefusal(EvsCheckReasonInvalid, "slot bodies unlike the new slots").Reply(self.pushId))
	}
	// the statement's origin, which every create carries and every 412 is read against
	own, err := EvsSlotOriginOf(self.statement)
	if err != nil {
		return self.unavailableOn(err)
	}
	metadata, err := own.Metadata(self.settings.SlotOriginMaxByteCount)
	if err != nil {
		return self.unavailableOn(err)
	}
	results := make([]slotWriteResult, len(slotIds))
	var waitGroup sync.WaitGroup
	for i, slotId := range slotIds {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			results[i] = self.writeSlot(slotId, self.payload.SlotBodies[i], own, metadata)
		}()
	}
	waitGroup.Wait()
	for _, result := range results {
		switch result {
		case slotWritten:
		case slotStale:
			return self.refuse(newEvsCheckRefusal(EvsCheckReasonSlotStale, "a slot of this statement's that exists past 23 h"))
		case slotOtherBytes:
			// §11.8 step 6: a cluster read of the head, where 5a finds the push committed if an ERASE rewrote its slot
			head, err := self.engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
			if err != nil {
				return self.unavailableOn(err)
			}
			if outcome := self.settle(head); outcome != nil {
				return outcome
			}
			self.engine.log.Errorf("[evs] alarm slot_mismatch: repo %s: a new slot of this statement's holds other bytes", sidecar.EvsKeyId(self.repoId))
			self.engine.metrics.alarms.Add(1, "slot_mismatch")
			self.head = head
			return self.refuse(newEvsCheckRefusal(EvsCheckReasonSlotStale, "a slot that holds other bytes"))
		case slotForeign:
			// 14.2.3's anything-else row: the cluster read and 5a first, so an attempt of a push that has committed is
			// answered its 200 and never a refusal (I-EVS-3), its slot since deleted with its version and the id
			// created again; then SLOT_STALE, whatever the bytes, and the client seals again with new ids
			head, err := self.engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
			if err != nil {
				return self.unavailableOn(err)
			}
			if outcome := self.settle(head); outcome != nil {
				return outcome
			}
			self.engine.metrics.slotForeign.Add(1)
			self.head = head
			return self.refuse(newEvsCheckRefusal(EvsCheckReasonSlotStale, "a slot another statement holds, or no statement"))
		default:
			return self.unavailable()
		}
	}
	return nil
}

// What one slot's write found.
type slotWriteResult int

const (
	// A store error, an unsure clock, a wait the attempt's context ended, or the rounds spent: 503.
	slotUnwritten slotWriteResult = iota
	// The object stands under this statement's origin.
	slotWritten
	// This statement's object with equal bytes, past SlotExistingMaxAge.
	slotStale
	// This statement's object with other bytes: an ERASE rewrote it, or a fault.
	slotOtherBytes
	// Another statement's object this attempt may not take over, a re-seeded one, or one with no origin.
	slotForeign
)

// One new slot, at most SlotWriteRoundCount rounds (DESIGN-DETAILS 14.2.3): a create If-None-Match carrying own's
// origin; on a 412 or an unknown outcome a GET, whose 404 is the create again and whose origin decides: own's is
// written, under 23 h old with equal bytes, as before the origin; another statement's that this attempt takes over
// (takeOver) is the create again once its DELETE was sent; anything else is foreign. Bytes are compared only for
// own's object, since whose an object is decides, and a statement listing another's id gets one answer whatever it
// sends.
func (self *pushAttempt) writeSlot(slotId sidecar.Id, body []byte, own EvsSlotOrigin, metadata map[string]string) slotWriteResult {
	key := SlotKey(self.repoId, slotId)
	barrierKey := barrierRefKey(self.repoId, self.refId)
	options := &sidecar.BlobPutOptions{Metadata: metadata}
	for round := 0; round < self.settings.SlotWriteRoundCount; round += 1 {
		testHookBarrier(BarrierPushSlotPutBefore, barrierKey)
		_, err := self.cluster.PutIfNoneMatch(self.writeCtx, key, body, options)
		testHookBarrier(BarrierPushSlotPutAfter, barrierKey)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			return slotWritten
		case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
		default:
			return slotUnwritten
		}
		object, err := self.cluster.Get(self.ctx, key)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			// deleted since the 412, or the lost create never landed and by the settle rule never will
			continue
		}
		if err != nil {
			return slotUnwritten
		}
		stored, err := readAllLimited(object, self.settings.SlotMaxByteCount)
		object.Body.Close()
		if err != nil {
			return slotUnwritten
		}
		origin := ParseEvsSlotOrigin(object.Metadata, self.settings.SlotOriginMaxByteCount)
		if origin.SameStatement(own) || evsSlotTwinBreaks(evsSlotTwinTakesForeign) {
			switch {
			case !bytes.Equal(stored, body):
				return slotOtherBytes
			case self.settings.SlotExistingMaxAge < self.engine.clock.Now().Sub(object.LastModified) && unknown == nil:
				return slotStale
			}
			return slotWritten
		}
		if taken, result := self.takeOver(key, origin, stored, body, object.LastModified); !taken {
			return result
		}
		// the DELETE went, whatever it answered: the create again decides, and one creator wins
	}
	return slotUnwritten
}

// DESIGN-DETAILS 14.2.4's takeover of another statement o's object: taken once the settled DELETE naming the
// object's LastModified was sent, which sends the round to its create again; else slotForeign when o's object is not
// this attempt's to take, and slotUnwritten when a read failed, the clock is unsure or the wait was cut short. It
// takes over only when all of these hold:
//
//  1. o's origin is a push's, on this ref, by this statement's signer;
//  2. o declared a lower path epoch than this statement, a push other than a PATH_EPOCH on a ref with a head, whose
//     declared epoch step 5 found to be the current epoch of the head this attempt holds;
//  3. EvsPushStandingIn on that head, for o's push id, statement prefix, base version and mode, finds o neither
//     committed nor its push id under another statement;
//  4. the object's bytes equal the body this statement carries;
//  5. no hold covers the repo.
//
// 2 and 3 prove o can never commit: o commits only on a head whose current epoch is the one it declares, the ref's
// epoch only rises, and a commit of o lies in (b, b+64] of its base b, below the first head of the higher epoch, so
// the head this attempt holds or the log pages under it name it if it exists. Both facts are permanent. 1, 4 and 5
// narrow it to 9.2.5's retoken. The epoch compared is the statement's own, which step 5 checked, never one read
// from a head fetched since.
//
// The wait: the DELETE goes only once evs's checked clock is SlotSettleAge past the object's LastModified, so a
// DELETE naming that LastModified can take no object another attempt created after it (the store's second of
// slack and the clocks' error, 14.2.4). While the clock is unsure the takeover answers 503 rather than wait on it.
func (self *pushAttempt) takeOver(key string, origin EvsSlotOrigin, stored []byte, body []byte, lastModified time.Time) (bool, slotWriteResult) {
	push := self.statement.Push
	switch {
	case origin.Kind != EvsSlotOriginPush || origin.RefId != self.refId || origin.SignerSidecarId != sidecar.Id(push.GetSignerSidecarId()):
		return false, slotForeign
	case push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 || self.head.Absent() || self.head.Version() == 0:
		return false, slotForeign
	case EvsHeadCurrentEpoch(self.head.Head) != push.GetPathEpoch():
		return false, slotForeign
	case push.GetPathEpoch() <= origin.PathEpoch && !evsSlotTwinBreaks(evsSlotTwinTakesLive):
		return false, slotForeign
	case !bytes.Equal(stored, body):
		return false, slotForeign
	}
	standing, err := EvsPushStandingInPrefix(self.ctx, self.head.Head, origin.PushId, origin.StatementPrefix, origin.BaseVersion, origin.GitMode,
		func(ctx context.Context, page uint64) (*LogPage, error) {
			return self.engine.readLogPage(ctx, self.cluster, self.repoId, self.refId, page)
		})
	if err != nil {
		return false, slotUnwritten
	}
	if (standing.Committed || standing.Reused) && !evsSlotTwinBreaks(evsSlotTwinTakesCommitted) {
		return false, slotForeign
	}
	cover, err := self.engine.holds.CoveringRepo(self.ctx, self.repoId, self.reads.repo.Object)
	if err != nil {
		return false, slotUnwritten
	}
	if cover.Covered() {
		// a hold keeps the object, as it keeps a dead record's slot, and the retoken is rebuilt
		return false, slotForeign
	}

	clockCheck := self.engine.host.ClockCheck
	if clockCheck == nil {
		return false, slotUnwritten
	}
	unsure := clockCheck.UnsureChannel()
	if !clockCheck.Sure() {
		return false, slotUnwritten
	}
	if wait := lastModified.Add(self.settings.SlotSettleAge).Sub(self.engine.clock.Now()); 0 < wait && !evsSlotTwinBreaks(evsSlotTwinTakesUnsettled) {
		select {
		case <-self.engine.clock.After(wait):
		case <-unsure:
			return false, slotUnwritten
		case <-self.ctx.Done():
			return false, slotUnwritten
		}
	}
	barrierKey := barrierRefKey(self.repoId, self.refId)
	testHookBarrier(BarrierPushSlotTakeBefore, barrierKey)
	// whatever it answers: a 412 is an object stored since, which the create's 412 and GET then judge, and an error
	// leaves the key as it was or as the DELETE's settle leaves it
	if err := self.cluster.Delete(sidecar.WithBlobUnmodified(self.writeCtx, lastModified), key); err != nil && self.engine.log.V(1).Enabled() {
		self.engine.log.Infof("[evs] repo %s: a slot takeover's DELETE: %v", sidecar.EvsKeyId(self.repoId), err)
	}
	testHookBarrier(BarrierPushSlotTakeAfter, barrierKey)
	return true, slotWritten
}

// Step 7's head over self.head: a page-out first when the window would pass 127 versions, then the commit's fields.
// A page-out that cannot finish pages nothing, and past 255 versions answers 429 FOLD_BEHIND.
func (self *pushAttempt) nextHead() (*protocol.EvsHead, *pushOutcome) {
	engine := self.engine
	if self.statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
		if outcome := self.foldEverything(); outcome != nil {
			return nil, outcome
		}
	}
	pageOut, err := engine.folder.PageOut(self.writeCtx, &EvsPageOutRequest{
		Cluster:    self.cluster,
		RepoId:     self.repoId,
		RefId:      self.refId,
		Head:       self.head,
		Cached:     self.head.Cached,
		HeadReadAt: self.reads.readAt,
		Deadline:   self.reads.readAt.Add(self.settings.PushStepSevenWindow - self.settings.PushPageOutReserve),
	})
	var behind *EvsFoldBehindError
	switch {
	case errors.As(err, &behind):
		return nil, refusedOutcome(&protocol.EvsRefusalReply{
			PushId:       self.pushId.Bytes(),
			Code:         protocol.EvsRefusalCode_EVS_REFUSAL_FOLD_BEHIND,
			RetryAfterMs: max(1, behind.RetryAfterMs()),
		})
	case err != nil:
		return nil, self.unavailableOn(err)
	}
	next, err := self.buildNextHead(pageOut)
	if err != nil {
		return nil, self.unavailableOn(err)
	}
	return next, nil
}

// §11.7's when row (4): a PATH_EPOCH's own process folds every version through the head it commits on, so its step-7
// head sets folded_through = v; a fold that cannot finish within step 7's window answers 503, refusing nothing.
func (self *pushAttempt) foldEverything() *pushOutcome {
	engine := self.engine
	readAt := engine.clock.Now()
	head, err := engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
	if err != nil {
		return self.unavailableOn(err)
	}
	deadline := self.reads.readAt.Add(self.settings.PushStepSevenWindow - self.settings.PushPageOutReserve)
	if _, err := engine.folder.FoldAll(self.writeCtx, self.cluster, self.repoId, self.refId, head, readAt, deadline); err != nil {
		return self.unavailable()
	}
	if engine.folder.Horizon(self.repoId, self.refId, self.head.Head) < self.head.Version() {
		return self.unavailable()
	}
	return nil
}

// The commit's head over self.head, with pageOut applied. See the file header.
func (self *pushAttempt) buildNextHead(pageOut *EvsPageOut) (*protocol.EvsHead, error) {
	prior := self.head.Head
	push := self.statement.Push
	next := CloneEvsHead(prior)
	chain := sidecar.EvsChainStart(self.repoId, self.refId)
	if prior.GetVersion() == 0 {
		// the ref's first commit, on no head or on a placeholder holding refusal records, which it keeps
		next.RefKind = push.GetRefKind()
		next.RefMode = push.GetRefMode()
		next.OwnerSidecarId = push.GetOwnerSidecarId()
		next.PathEpoch = &protocol.EvsPathEpoch{Current: max(1, push.GetPathEpoch())}
		next.WindowBaseChain = append([]byte{}, chain[:]...)
		next.Window = nil
		// a creating push's payload sections 15 and 16, which 5c took on this push alone (DESIGN-DETAILS 8.2.2)
		self.copyCreatingSections(next)
	} else {
		if prior.GetDeleted() {
			// the first push after a DELETE: a name it carries again, its base the head's, which 5c held it to
			self.copyCreatingSections(next)
		}
		var err error
		chain, err = sidecar.EvsChainFromBytes(prior.GetChain())
		if err != nil {
			return nil, fmt.Errorf("%w: a head chain of %d bytes", ErrEvsHeadInvalid, len(prior.GetChain()))
		}
	}
	nextChain := sidecar.EvsChainNext(chain, self.pushId, self.statement.Sha256)
	next.Version = prior.GetVersion() + 1
	next.Chain = nextChain[:]
	next.PushId = self.pushId.Bytes()
	next.Auth = push.GetAuth()
	next.GroupId = push.GetGroupId()
	next.Generation = push.GetGeneration()
	next.GenerationCommitment = push.GetGenerationCommitment()
	var coveringPrefixes []sidecar.EvsTokenPath
	if len(push.GetChangesRoot()) != 0 {
		coveringPrefixes = self.statement.ChangedPrefixes
	}
	entry := sidecar.NewEvsWindowEntry(self.statement.Sha256, push, self.payload.ChangedPaths(), coveringPrefixes, self.payload.CreatesPath, self.place)
	if self.purge != nil && self.purge.replacesVersionless {
		// window bit 4: the push replaces or removes a versionless version (EVS2-M10-06)
		entry.Flags |= uint32(protocol.EvsWindowFlag_EVS_WINDOW_VERSIONLESS_REPLACED)
	}
	next.Window = append(append([]byte{}, next.GetWindow()...), entry.Encode()...)
	next.Lease = nil
	next.Deleted = push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) != 0
	switch {
	case push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0:
		next.PathEpoch = committedPathEpoch(prior, push.GetPathEpoch(), push.GetPathMapSha256())
	case self.due != nil:
		next.PathEpoch = applyPathEpochDue(next.GetPathEpoch(), self.due, self.engine.clock.Now())
	}
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_CONSUME) != 0 {
		next.ConsumedThrough = consumedThroughOf(prior, push)
	}
	if err := pageOut.Apply(next); err != nil {
		return nil, err
	}
	return next, nil
}

// A creating push's sealed ref name and overlay base into the head it commits, each where the push carries it.
func (self *pushAttempt) copyCreatingSections(next *protocol.EvsHead) {
	if refName := self.payload.RefName; len(refName) != 0 {
		next.SealedRefName = bytes.Clone(refName)
	}
	if base := self.payload.Base; base != nil {
		next.Base = &protocol.EvsOverlay{RefId: bytes.Clone(base.GetRefId()), Version: base.GetVersion()}
	}
}

// What step 8 takes of this attempt's commit.
func (self *pushAttempt) newCommitted(head *EvsStoredHead) *EvsCommitted {
	return &EvsCommitted{
		RepoId:           self.repoId,
		RefId:            self.refId,
		ClusterId:        self.cluster.ClusterId(),
		RepoNetworkId:    self.networkId,
		CallerNetworkId:  self.tokenNetworkId,
		Head:             head,
		Statement:        self.statement,
		Payload:          self.payload,
		RecordByteCount:  self.recordByteCount(),
		RequestByteCount: self.request.requestByteCount,
		Purge:            self.purgeCommit(head.Version()),
	}
}

// Step 8, off the reply path, in this order: the push sequence and hints, which the head cache entry records, so
// the sequence is raised first; usage; the head cache; the fold trigger. Each failure is logged and costs only
// latency: everything here is soft state.
func (self *EvsEngine) afterCommit(committed *EvsCommitted) {
	self.stepEightCount.Update(func(count int) int { return count + 1 })
	go func() {
		defer self.stepEightDoneCount.Update(func(count int) int { return count + 1 })
		barrierKey := barrierRefKey(committed.RepoId, committed.RefId)
		testHookBarrier(BarrierPushStep8Before, barrierKey)
		defer testHookBarrier(BarrierPushStep8After, barrierKey)
		ctx := self.ctx
		pushSequence := uint64(0)
		if self.notifier != nil {
			sequence, err := self.notifier.Notify(ctx, committed)
			if err != nil {
				self.log.Infof("[evs] repo %s: push sequence or hints not sent: %v", sidecar.EvsKeyId(committed.RepoId), err)
			} else {
				pushSequence = sequence
			}
		}
		if uploads := self.deps.Uploads; uploads != nil && uploads.Usage != nil {
			if err := uploads.Usage.AddStored(connect.Id(committed.RepoNetworkId), committed.RecordByteCount); err != nil {
				self.log.Infof("[evs] stored bytes of a commit not counted: %v", err)
			}
			// transfer is the router's to count, every request's and reply's bytes once (transfer_meter.go)
		}
		self.heads.CacheCommit(ctx, committed.RepoId, committed.RefId, committed.Head, pushSequence)
		// a certain commit's candidates: the purge waits its 60 s from here (§11.13's who row)
		self.handPurge(committed.Purge)
		self.folder.NoteCommit(committed.ClusterId, committed.RepoId, committed.RefId, committed.Head.Head)
		if push := committed.Statement.Push; push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
			self.queueEpochCopy(ctx, committed.RepoId, committed.RefId, push.GetPathEpoch())
		}
	}()
}

// Queues §11.6's copy of a committed PATH_EPOCH's sources into epoch (epoch_copy.go), once-keyed by repo, ref and
// epoch. A queue that does not answer is logged: the sources stand until a copy runs, which costs reads, never
// correctness.
func (self *EvsEngine) queueEpochCopy(ctx context.Context, repoId sidecar.Id, refId sidecar.Id, epoch uint64) {
	if self.host.Tasks == nil {
		self.log.Warningf("[evs] repo %s: no task queue, so its path-epoch copy waits", sidecar.EvsKeyId(repoId))
		return
	}
	if err := self.host.Tasks.Schedule(ctx, EvsEpochCopyTaskRequest(repoId, refId, epoch, self.clock.Now())); err != nil {
		self.log.Warningf("[evs] repo %s: its path-epoch copy was not queued: %v", sidecar.EvsKeyId(repoId), err)
	}
}

// How many commits have started step 8 and how many have finished it, with a channel that closes at the next
// finish: what a test waits on before it reads what step 8 wrote.
func (self *EvsEngine) StepEights() (started int, finished int, changed chan struct{}) {
	started, _ = self.stepEightCount.Get()
	finished, changed = self.stepEightDoneCount.Get()
	return started, finished, changed
}
