// Serving a DROP's listed versions on the read route (§11.9's reply, serve and dropped rows; R-ABUSE-5, D-ABUSE-8,
// D-EVS-63, D-EVS-65, I-EVS-1, FI-27, FS-89, FS-92, FS-94; DESIGN-DETAILS 10.2.3 and 10.2.9; EVS2-M10-10). A read of an
// older version V by number answers, beside V as any older version, the drop that lists it:
//
//	DropOf(V)  0  drops/<repo>/_ absent (a GET cached TableCacheTtl, DropIndex.Table): none, which is all a repo that
//	              never had a drop pays
//	           1  the live drops, newest first: each table entry on V's ref pending, executing, held, done or observed
//	              with version > u(V), and each bit-5 entry of the head's window the table lacks (whose append is made
//	              again, once a process, when the head came from the cluster), none a cancel in that window names:
//	              Covers(body, e(V), t(V), k(V)) (sidecar.EvsDropLists.Lists) gives that drop
//	           2  each list file of the repo (bloom, then the rows by entry hash): a row with h(V) whose drop has no
//	              void record gives that drop, a void record outranking a row
//	           3  none
//	state      drop_pending {drop_id, not_before_ms} while the drop is pending and evs's clock is before its
//	           not_before_ms, else dropped {drop_id, drop_version}; evs's clock decides the wire and the reader's own
//	           what it shows
//	statement  the DROP's Signed EvsPush once a reply, unless the reply's statements after the pin hold it, and its
//	           body once a reply, none for a version the request's held_drops names, at most BodyReplyByteCount of
//	           bodies a reply: a path naming a drop past it carries the state with no body and the reader reads it again
//	withheld   from not_before_ms: the version's entry version only when its chain names no inline record; its
//	           record's bytes elsewhere zeroed (read_elide.go); its job's deleted and held ids 404 (read_withheld.go)
//
// e(V) is the epoch V's statement declares and t(V) the request's token path in it; a request naming none there is
// judged by the list files alone. Membership reads no idx/ entry and no drop mark: the body and the list files decide,
// for the repo's life. A list file that cannot be read fails the read 503 rather than serve a version it could not
// clear. Nothing here reads hold/: a sealed hold's answers, listing and bill equal a no-hold twin's (owner decision 93).

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"slices"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A version a read serves, as DropOf judges it: where it committed and its entry hash.
type readDropTarget struct {
	// e(V), and t(V): nil when the request names no token path in e(V), so only the list files judge it
	epoch     uint64
	tokenPath sidecar.EvsTokenPath
	// k(V) and u(V)
	version       uint64
	commitVersion uint64
	entrySha256   [sha256.Size]byte
}

// The drop a read found a version listed by, and whether it is still pending at evs's clock.
type readDropVerdict struct {
	body    *DropBody
	pending bool
}

// What one read keeps of the repo's drops: the table, loaded once an attempt; nil table, a repo with no drop.
type readDrops struct {
	loaded bool
	table  *DropTableState
	lists  []*DropListFile
	// the bodies and statements this reply has carried, by DROP version, and the bodies' bytes
	statementSent map[uint64]bool
	bodySent      map[uint64]bool
	bodyByteCount int
	// the drops a cancel in the head's window names, read once
	cancels map[sidecar.Id]bool
}

// The repo's table, read once an attempt through the index; nil while the repo never had a drop. Nothing at a format-1
// instance, which knows no drop.
func (self *readAttempt) dropTable() (*DropTableState, error) {
	if self.drops == nil {
		self.drops = &readDrops{statementSent: map[uint64]bool{}, bodySent: map[uint64]bool{}}
	}
	if self.drops.loaded || !self.engine.format2Instance() {
		return self.drops.table, nil
	}
	table, err := self.engine.dropIndex.Table(self.ctx, self.engine.drops, self.cluster, self.repoId, self.engine.clock.Now())
	if err != nil {
		return nil, err
	}
	self.drops.loaded, self.drops.table = true, table
	return table, nil
}

// DropOf(V): see the file header. nil for a version no drop lists.
func (self *readAttempt) dropOf(target *readDropTarget) (*readDropVerdict, error) {
	table, err := self.dropTable()
	if err != nil || table == nil {
		return nil, err
	}
	engine := self.engine
	now := engine.clock.Now()
	verdictOf := func(body *DropBody, pending bool) *readDropVerdict {
		notBeforeMs := body.Lists.History().GetNotBeforeMs()
		return &readDropVerdict{body: body, pending: pending && now.UnixMilli() < notBeforeMs}
	}
	// the drops a committed cancel in the head's window names, which no table write may have caught up with yet
	cancelled, err := self.windowCancels()
	if err != nil {
		return nil, err
	}
	// 1: the live drops on this ref, newest first
	entries := []*DropTableEntry{}
	for _, entry := range table.Drops {
		if entry.RefId != self.refId || entry.Version <= target.commitVersion || cancelled[entry.DropId] {
			continue
		}
		switch entry.State {
		case DropStatePending, DropStateExecuting, DropStateHeld, DropStateDone, DropStateObserved:
			entries = append(entries, entry)
		}
	}
	slices.SortFunc(entries, func(a *DropTableEntry, b *DropTableEntry) int { return compareUint64(b.Version, a.Version) })
	for _, entry := range entries {
		if target.tokenPath == nil {
			break
		}
		body, err := engine.dropIndex.Body(self.ctx, self.cluster, self.repoId, self.refId, entry.Version, &sidecar.EvsWindowEntry{PushId: entry.PushId, Place: entry.Place})
		if err != nil {
			return nil, err
		}
		if _, listed := body.Lists.Lists(target.epoch, target.tokenPath, target.version, false); listed && body.Drop() {
			return verdictOf(body, entry.State == DropStatePending), nil
		}
	}
	// the window's bit-5 entries the table lacks: a lost append, made again
	verdict, err := self.windowDropOf(target, table, cancelled, verdictOf)
	if err != nil || verdict != nil {
		return verdict, err
	}
	// 2: the list files, for the repo's life
	if self.drops.lists == nil {
		segmentCluster, err := engine.blobs.SegmentCluster()
		if err != nil {
			return nil, err
		}
		lists, err := engine.dropIndex.Lists(self.ctx, segmentCluster, self.cluster.ClusterId(), self.repoId, now)
		if err != nil {
			return nil, err
		}
		self.drops.lists = lists
	}
	for _, file := range self.drops.lists {
		if !file.MayHold(target.entrySha256) {
			continue
		}
		at, found := slices.BinarySearchFunc(file.Rows, target.entrySha256, func(row DropListRow, entrySha256 [sha256.Size]byte) int {
			return bytes.Compare(row.EntrySha256[:], entrySha256[:])
		})
		for ; found && at < len(file.Rows) && file.Rows[at].EntrySha256 == target.entrySha256; at += 1 {
			drop := file.Drops[file.Rows[at].Drop]
			if drop.RefId != self.refId || table.Void(drop.DropId) != nil {
				continue
			}
			push, err := self.pushes.at(drop.Version)
			if err != nil {
				return nil, err
			}
			body, err := engine.dropIndex.Body(self.ctx, self.cluster, self.repoId, self.refId, drop.Version, push.entry)
			if err != nil {
				return nil, err
			}
			return verdictOf(body, false), nil
		}
	}
	return nil, nil
}

// Step 1's second half: each bit-5 entry of the head's window after u(V) whose drop the table holds neither an entry
// nor a void record for, its append made again off the reply path when the head came from the cluster.
func (self *readAttempt) windowDropOf(target *readDropTarget, table *DropTableState, cancelled map[sidecar.Id]bool, verdictOf func(body *DropBody, pending bool) *readDropVerdict) (*readDropVerdict, error) {
	head := self.head.Head
	window, err := EvsHeadWindow(head)
	if err != nil {
		return nil, err
	}
	first := EvsHeadWindowFirstVersion(head)
	met := []*metDrop{}
	defer func() {
		if 0 < len(met) && !self.head.Cached {
			self.engine.appendMetDropsAsync(self.repoNetworkId(), self.cluster.ClusterId(), self.repoId, met)
		}
	}()
	for i := len(window) - 1; 0 <= i; i -= 1 {
		version := first + uint64(i)
		entry := window[i]
		if version <= target.commitVersion || !entry.Drop() {
			continue
		}
		body, err := self.engine.dropIndex.Body(self.ctx, self.cluster, self.repoId, self.refId, version, entry)
		if err != nil {
			return nil, err
		}
		dropId := body.DropId()
		tableEntry, void := table.Drop(dropId), table.Void(dropId)
		lacks := tableEntry == nil && void == nil
		if !body.Drop() {
			// a cancel the table lacks: its drop still pending there, or neither its entry nor its void record
			lacks = lacks || (tableEntry != nil && tableEntry.State == DropStatePending)
		}
		if !lacks {
			continue
		}
		met = append(met, &metDrop{refId: self.refId, body: body, seenAt: self.engine.clock.Now()})
		if !body.Drop() || target.tokenPath == nil || cancelled[dropId] {
			continue
		}
		if _, listed := body.Lists.Lists(target.epoch, target.tokenPath, target.version, false); listed {
			return verdictOf(body, true), nil
		}
	}
	return nil, nil
}

// The drops a cancel among the head's window's bit-5 entries names, read once an attempt.
func (self *readAttempt) windowCancels() (map[sidecar.Id]bool, error) {
	if self.drops.cancels != nil {
		return self.drops.cancels, nil
	}
	head := self.head.Head
	window, err := EvsHeadWindow(head)
	if err != nil {
		return nil, err
	}
	first := EvsHeadWindowFirstVersion(head)
	cancels := map[sidecar.Id]bool{}
	for i, entry := range window {
		if !entry.Drop() {
			continue
		}
		body, err := self.engine.dropIndex.Body(self.ctx, self.cluster, self.repoId, self.refId, first+uint64(i), entry)
		if err != nil {
			return nil, err
		}
		if !body.Drop() {
			cancels[body.DropId()] = true
		}
	}
	self.drops.cancels = cancels
	return cancels, nil
}

// The repo's network, as repo/ names it (cached at most 5 s, which the guard read), for an append's admission; the
// token's when repo/ cannot be read.
func (self *readAttempt) repoNetworkId() sidecar.Id {
	if read, err := self.engine.repos.Read(self.ctx, self.cluster, self.repoId); err == nil {
		if networkId, err := sidecar.IdFromBytes(read.Object.GetNetworkId()); err == nil {
			return networkId
		}
	}
	return networkIdOf(self.request.Principal)
}

// An older version's reply, answered its drop's state where DropOf finds one, with the DROP's statement and body as
// the file header has them, and its entry version withheld from not_before_ms when its chain holds an inline record.
func (self *readAttempt) answerDropped(path *readPath, reply *protocol.EvsReadPathReply) error {
	version := reply.GetVersion()
	if version == nil || len(version.GetEntryVersion()) == 0 || !self.engine.format2Instance() {
		return nil
	}
	table, err := self.dropTable()
	if err != nil || table == nil {
		return err
	}
	push, err := self.pushes.at(version.GetCommitVersion())
	if err != nil {
		return err
	}
	epoch := push.statement.Push.GetPathEpoch()
	target := &readDropTarget{
		epoch:         epoch,
		tokenPath:     path.tokens.In(epoch, EvsHeadCurrentEpoch(self.head.Head)),
		version:       path.version,
		commitVersion: version.GetCommitVersion(),
		entrySha256:   sha256.Sum256(version.GetEntryVersion()),
	}
	verdict, err := self.dropOf(target)
	if err != nil || verdict == nil {
		return err
	}
	body := verdict.body
	history := body.Lists.History()
	reply.DropId = history.GetDropId()
	if verdict.pending {
		reply.State = protocol.EvsReadPathState_EVS_READ_PATH_DROP_PENDING
		reply.NotBeforeMs = history.GetNotBeforeMs()
	} else {
		reply.State = protocol.EvsReadPathState_EVS_READ_PATH_DROPPED
		reply.DropVersion = body.Version
		if evsEntryHoldsInline(version.GetEntryVersion()) {
			// never an inline record of a dropped version's chain: the statement and state alone
			version.EntryVersion = nil
		}
	}
	self.attachDrop(reply, body)
	return nil
}

// The DROP's statement and body on reply, each once a reply, the body within BodyReplyByteCount and never one the
// request's held_drops names.
func (self *readAttempt) attachDrop(reply *protocol.EvsReadPathReply, body *DropBody) {
	drops := self.drops
	if !drops.statementSent[body.Version] && !self.replyHoldsStatement(body.Version) {
		reply.DropStatement = body.Statement
		drops.statementSent[body.Version] = true
	}
	if drops.bodySent[body.Version] || slices.Contains(self.body.GetHeldDrops(), body.Version) {
		return
	}
	if self.engine.settings.Drop.BodyReplyByteCount < drops.bodyByteCount+len(body.Body) {
		// past the reply's bodies: the state alone, and the reader reads this path again
		return
	}
	reply.DropBody = body.Body
	drops.bodySent[body.Version] = true
	drops.bodyByteCount += len(body.Body)
}

// Whether the reply's statements after the pin hold the statement committed at version: those the window holds after
// the pin.
func (self *readAttempt) replyHoldsStatement(version uint64) bool {
	head := self.head.Head
	return self.body.GetPinVersion() < version && EvsHeadWindowFirstVersion(head) <= version && version <= head.GetVersion()
}

// Whether entry version bytes name an inline record in their chain.
func evsEntryHoldsInline(entryBytes []byte) bool {
	entry, err := parseEvsEntryVersion(entryBytes)
	if err != nil {
		return false
	}
	for _, locator := range entry.GetChain() {
		if protocol.EvsLocatorKind(locator.GetKind()) == protocol.EvsLocatorKind_EVS_LOCATOR_INLINE {
			return true
		}
	}
	return false
}

// a's order against b.
func compareUint64(a uint64, b uint64) int {
	switch {
	case a < b:
		return -1
	case b < a:
		return 1
	}
	return 0
}
