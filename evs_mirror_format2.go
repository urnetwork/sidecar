//go:build !ios_extension

// A full mirror in format 2 (§11.13's contents row; R-EVS-17, D-EVS-17, D-EVS-37, FI-5, FI-16, FS-70, FS-96;
// EVS2-M10-13): what a mirror keeps of a versionless path and of a version a drop took. A mirror of a format-2 repo
// syncs only on a client whose format-2 reader is installed; one of format 1 alone refuses it, as before.
//
//	newest   for a versionless path the mirror keeps only its newest version's content: when it holds a push whose
//	         version replaces a versionless one, the replaced version's unstaged kind-5 segments that no version of the
//	         push names go from the mirror, read from the replaced version's own entry in the record the mirror holds
//	         of its push, never from evs's purge list. Staged content rides inside its push's record, which the mirror
//	         keeps whole; a replaced version whose push the mirror holds in parts keeps its segments (not built)
//	drops    a DROP the mirror holds is kept pending in its state, a cancel it holds removing it; once a pending drop's
//	         window passed by this device's clock, the executed drop is built by Covers over every version the mirror
//	         holds of every ref (EvsExecutedDropOf), so what a live version names stays, and handed to the client's
//	         drop applier, Sidecar.ApplyExecutedDrop, which takes the listed versions' segment and slot copies out of
//	         the mirror; with no applier set nothing is deleted and the drop stays pending. Statements, entry versions
//	         and records stay: inline records of listed versions inside held records are not elided (not built)
//
//	missing  a segment evs does not serve is judged at the walk's end, once the mirror holds what follows its version
//	         (FS-70's syncing mirror): complete with no content when kind-5 locators alone name it and a later version
//	         whose records the walk holds writes or removes each path naming it, the replaced version reading
//	         `collected`, or when a held DROP whose window passed with no cancel held lists each version naming it;
//	         else named missing, the ref left below its version. Where one is still unjudged and kind 5 alone names
//	         it, the ref's head is read again once a sync, the replacement having perhaps committed past the head the
//	         sync listed, and the walk runs on to it: nothing alarms for a purge that lands during a sync
//
// Coverage counts what the mirror's state names (evs_mirror_coverage.go), so a replaced version counts complete with
// no content, and a drop's listed content stays required until the drop's window passes; a pending drop's listed
// content that evs no longer serves is named missing.
//
// On every leg but ios_extension.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A DROP the mirror holds whose window has not passed, or whose apply has not run.
type EvsMirrorDrop struct {
	RefId       Id     `json:"ref_id"`
	Version     uint64 `json:"version"`
	DropId      Id     `json:"drop_id"`
	NotBeforeMs int64  `json:"not_before_ms"`
}

// After a version is held whole: the newest-version rule over its changes, and its DROP noted. See the file header.
func (self *evsMirrorRun) holdFormat2(ctx context.Context, head *EvsVerifiedHead, statement *EvsVerifiedStatement, checked *EvsCheckedPayload) error {
	if self.mirror.client.format2Reader() == nil {
		return nil
	}
	push := statement.Statement.Push
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) != 0 && checked.Drop != nil {
		history := checked.Drop.History
		switch history.GetAction() {
		case evsDropActionDrop:
			dropId, err := IdFromBytes(history.GetDropId())
			if err != nil {
				return fmt.Errorf("%w: a drop id", ErrEvsMirrorRecordInvalid)
			}
			// a version walked again, below a hole an earlier sync left, holds its DROP once
			held := slices.ContainsFunc(self.drops, func(drop *EvsMirrorDrop) bool {
				return drop.RefId == head.RefId && drop.Version == statement.Version && drop.DropId == dropId
			})
			if !held {
				self.drops = append(self.drops, &EvsMirrorDrop{RefId: head.RefId, Version: statement.Version, DropId: dropId, NotBeforeMs: history.GetNotBeforeMs()})
			}
		case evsDropActionCancel:
			kept := self.drops[:0]
			for _, drop := range self.drops {
				if drop.RefId != head.RefId || drop.Version != history.GetCancelsVersion() || !bytes.Equal(drop.DropId.Bytes(), history.GetCancelsDropId()) {
					kept = append(kept, drop)
				}
			}
			self.drops = kept
		}
	}
	named := map[string]bool{}
	for _, change := range checked.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if proto.Unmarshal(change.EntryVersion, entry) != nil {
			continue
		}
		for _, locator := range entry.GetChain() {
			named[string(locator.GetId())] = true
		}
	}
	for _, change := range checked.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if proto.Unmarshal(change.EntryVersion, entry) != nil || len(entry.GetPrevPushId()) == 0 {
			continue
		}
		replaced, err := self.heldEntry(ctx, head.RefId, entry.GetPrevPushId(), entry.GetPrevCommitVersion(), change.TokenPath)
		if err != nil || replaced == nil || replaced.GetVersioning() == uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
			continue
		}
		for _, segmentId := range EvsMirrorReplacedSegmentIds(replaced, named) {
			if err := self.mirror.store.Remove(EvsMirrorSegmentKey(segmentId)); err != nil {
				return err
			}
			self.result.CollectedCount += 1
		}
	}
	return nil
}

// The unstaged kind-5 segments of a replaced versionless version that no version of the replacing push names: what the
// mirror drops of it (the file header's newest row).
func EvsMirrorReplacedSegmentIds(replaced *protocol.EvsEntryVersion, named map[string]bool) [][]byte {
	ids := [][]byte{}
	for _, locator := range replaced.GetChain() {
		if locator.GetKind() != uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT) || locator.GetStaged() ||
			len(locator.GetId()) == 0 || named[string(locator.GetId())] {
			continue
		}
		ids = append(ids, locator.GetId())
	}
	return ids
}

// The entry the held one-part push pushId, committed at version, wrote at tokenPath, from the records the mirror holds;
// nil where it holds none of them, or the push went in parts.
func (self *evsMirrorRun) heldEntry(ctx context.Context, refId Id, pushIdBytes []byte, version uint64, tokenPath EvsTokenPath) (*protocol.EvsEntryVersion, error) {
	pushId, err := IdFromBytes(pushIdBytes)
	if err != nil {
		return nil, nil
	}
	statementBytes, err := self.heldBytes(EvsMirrorStatementKey(refId, version))
	if err != nil || statementBytes == nil {
		return nil, err
	}
	statement, err := ParseEvsStatementFormat2(statementBytes)
	if err != nil || !bytes.Equal(statement.Push.GetPushId(), pushId.Bytes()) || statement.Push.GetPartCount() != 0 {
		return nil, nil
	}
	record, err := self.heldBytes(EvsMirrorRecordKey(pushId, 0))
	if err != nil || record == nil {
		return nil, err
	}
	checked, err := evsMirrorCheckRecordsOf(statement, [][]byte{record}, true)
	if err != nil {
		return nil, nil
	}
	for _, change := range checked.Changes {
		if change.TokenPath.Equal(tokenPath) && change.WritesEntry() {
			entry := &protocol.EvsEntryVersion{}
			if proto.Unmarshal(change.EntryVersion, entry) == nil {
				return entry, nil
			}
		}
	}
	return nil, nil
}

// At a sync's end: each pending drop whose window passed applied over what the mirror holds, the rest kept pending.
func (self *evsMirrorRun) applyDrops(ctx context.Context, refStates []*EvsMirrorRefState) error {
	now := self.mirror.client.clock.Now()
	pending := []*EvsMirrorDrop{}
	for _, drop := range self.drops {
		if now.Before(evsTime(drop.NotBeforeMs)) {
			pending = append(pending, drop)
			continue
		}
		applied, err := self.applyDrop(ctx, drop, refStates)
		if err != nil {
			return err
		}
		if !applied {
			pending = append(pending, drop)
			continue
		}
		self.result.DropCount += 1
	}
	self.drops = pending
	return nil
}

// One executed drop applied: false where no applier is set, so nothing was deleted.
func (self *evsMirrorRun) applyDrop(ctx context.Context, drop *EvsMirrorDrop, refStates []*EvsMirrorRefState) (bool, error) {
	held := []*EvsDropHeldVersion{}
	var dropStatement *EvsStatement
	var dropBody []byte
	for _, refState := range refStates {
		for version := uint64(1); version <= refState.HeadVersion; version += 1 {
			statementBytes, err := self.heldBytes(EvsMirrorStatementKey(refState.RefId, version))
			if err != nil {
				return false, err
			}
			if statementBytes == nil {
				continue
			}
			statement, err := ParseEvsStatementFormat2(statementBytes)
			if err != nil {
				return false, err
			}
			pushId, err := IdFromBytes(statement.Push.GetPushId())
			if err != nil {
				return false, err
			}
			records := [][]byte{}
			whole := true
			for part := uint32(0); part <= statement.Push.GetPartCount(); part += 1 {
				record, err := self.heldBytes(EvsMirrorRecordKey(pushId, part))
				if err != nil {
					return false, err
				}
				if record == nil {
					whole = false
					break
				}
				records = append(records, record)
			}
			if !whole {
				continue
			}
			checked, err := evsMirrorCheckRecordsOf(statement, records, true)
			if err != nil {
				return false, err
			}
			if refState.RefId == drop.RefId && version == drop.Version && checked.Drop != nil {
				dropStatement, dropBody = statement, checked.Drop.Body
			}
			for _, change := range checked.Changes {
				if !change.WritesEntry() {
					continue
				}
				entry := &protocol.EvsEntryVersion{}
				if proto.Unmarshal(change.EntryVersion, entry) != nil {
					continue
				}
				held = append(held, &EvsDropHeldVersion{
					RefId: refState.RefId, Epoch: max(1, statement.Push.GetPathEpoch()), TokenPath: change.TokenPath,
					Version: entry.GetVersion(), Entry: entry,
				})
			}
		}
	}
	if dropStatement == nil {
		// the DROP's own records are not held: it waits for a sync that holds them
		return false, nil
	}
	executed, err := EvsExecutedDropOf(self.mirror.repoId, drop.RefId, dropStatement, dropBody, held, self.mirror.store)
	if err != nil {
		return false, err
	}
	err = self.mirror.client.ApplyExecutedDrop(ctx, executed)
	switch {
	case errors.Is(err, ErrEvsDropApplierMissing):
		return false, nil
	case err != nil:
		return false, err
	}
	return true, nil
}

// A segment of a version the walk holds the records of: the paths whose versions name it, and whether kind-5 locators
// alone do.
type evsMirrorNamed struct {
	kind5Only bool
	paths     []*evsMirrorNamedPath
}

// One version naming a segment: its path in its statement's epoch and its path version.
type evsMirrorNamedPath struct {
	epoch     uint64
	tokenPath EvsTokenPath
	version   uint64
}

// A segment evs did not serve, judged at the walk's end.
type evsMirrorPending struct {
	version uint64
	named   *evsMirrorNamed
	missing *EvsMirrorMissing
}

// Notes, for a format-2 reader, the token paths a version whose records the walk holds writes or removes.
func (self *evsMirrorRun) noteChanges(refId Id, version uint64, checked *EvsCheckedPayload) {
	if self.mirror.client.format2Reader() == nil || checked == nil {
		return
	}
	if self.changes == nil {
		self.changes = map[Id]map[string]uint64{}
	}
	changes := self.changes[refId]
	if changes == nil {
		changes = map[string]uint64{}
		self.changes[refId] = changes
	}
	for _, change := range checked.Changes {
		key := change.TokenPath.KeyString()
		changes[key] = max(changes[key], version)
	}
}

// For a format-2 reader, by segment id: the versions of the push naming each segment. nil for format 1 alone.
func (self *evsMirrorRun) segmentNames(statement *EvsVerifiedStatement, checked *EvsCheckedPayload) map[string]*evsMirrorNamed {
	if self.mirror.client.format2Reader() == nil || checked == nil {
		return nil
	}
	return evsMirrorSegmentNames(statement, checked)
}

// By segment id, the versions of the push naming each segment.
func evsMirrorSegmentNames(statement *EvsVerifiedStatement, checked *EvsCheckedPayload) map[string]*evsMirrorNamed {
	epoch := max(1, statement.Statement.Push.GetPathEpoch())
	names := map[string]*evsMirrorNamed{}
	for _, change := range checked.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if proto.Unmarshal(change.EntryVersion, entry) != nil {
			continue
		}
		for _, locator := range entry.GetChain() {
			kind := protocol.EvsLocatorKind(locator.GetKind())
			if len(locator.GetId()) == 0 || kind == protocol.EvsLocatorKind_EVS_LOCATOR_INLINE {
				continue
			}
			named := names[string(locator.GetId())]
			if named == nil {
				named = &evsMirrorNamed{kind5Only: true}
				names[string(locator.GetId())] = named
			}
			if kind != protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT {
				named.kind5Only = false
			}
			named.paths = append(named.paths, &evsMirrorNamedPath{epoch: epoch, tokenPath: change.TokenPath, version: entry.GetVersion()})
		}
	}
	return names
}

// Whether a segment evs did not serve waits for the walk's end: for a format-2 reader, one a version of the push names.
func (self *evsMirrorRun) deferMissing(refId Id, version uint64, segmentId []byte, names map[string]*evsMirrorNamed, missing *EvsMirrorMissing) bool {
	named := names[string(segmentId)]
	if named == nil || len(named.paths) == 0 {
		return false
	}
	if self.pending == nil {
		self.pending = map[Id][]*evsMirrorPending{}
	}
	self.pending[refId] = append(self.pending[refId], &evsMirrorPending{version: version, named: named, missing: missing})
	return true
}

// At the walk's end: each segment evs did not serve judged by what the mirror holds (see the file header), the rest
// named missing and their versions not whole. A head to walk on to instead, read again once a sync, when one judged
// missing is named by kind 5 alone and evs's head moved past the walk's.
func (self *evsMirrorRun) resolvePending(ctx context.Context, head *EvsVerifiedHead, walked []*EvsVerifiedStatement, wholes []bool) (*protocol.EvsHeadSummary, error) {
	pending := self.pending[head.RefId]
	delete(self.pending, head.RefId)
	if len(pending) == 0 {
		return nil, nil
	}
	executed, err := self.executedDropLists(head.RefId)
	if err != nil {
		return nil, err
	}
	changes := self.changes[head.RefId]
	unjudged := []*evsMirrorPending{}
	for _, item := range pending {
		switch {
		case item.named.kind5Only && evsMirrorReplacedAll(item, changes):
			self.result.ReplacedMissingCount += 1
		case evsMirrorDroppedAll(item, executed):
			self.result.DroppedMissingCount += 1
		default:
			unjudged = append(unjudged, item)
		}
	}
	if len(unjudged) == 0 {
		return nil, nil
	}
	rereads := slices.ContainsFunc(unjudged, func(item *evsMirrorPending) bool { return item.named.kind5Only })
	if rereads && !self.reread[head.RefId] {
		if self.reread == nil {
			self.reread = map[Id]bool{}
		}
		self.reread[head.RefId] = true
		heads, err := self.mirror.listHeads(ctx)
		if err != nil {
			return nil, err
		}
		for _, summary := range heads {
			if bytes.Equal(summary.GetRefId(), head.RefId.Bytes()) && head.Version < summary.GetVersion() {
				return summary, nil
			}
		}
	}
	for _, item := range unjudged {
		self.missing.add(item.missing)
		for i, statement := range walked {
			if statement.Version == item.version {
				wholes[i] = false
			}
		}
	}
	return nil, nil
}

// Whether a later version the walk holds the records of writes or removes each path naming the segment.
func evsMirrorReplacedAll(item *evsMirrorPending, changes map[string]uint64) bool {
	for _, path := range item.named.paths {
		if changes[path.tokenPath.KeyString()] <= item.version {
			return false
		}
	}
	return true
}

// Whether an executed drop the mirror holds lists each version naming the segment.
func evsMirrorDroppedAll(item *evsMirrorPending, executed []*EvsDropLists) bool {
	if len(executed) == 0 {
		return false
	}
	for _, path := range item.named.paths {
		listed := false
		for _, lists := range executed {
			if _, covered := lists.Lists(path.epoch, path.tokenPath, path.version, false); covered {
				listed = true
				break
			}
		}
		if !listed {
			return false
		}
	}
	return true
}

// The lists of each DROP held on the ref whose window passed by this device's clock with no cancel held: its body read
// from the records the mirror holds. One whose records it lacks lists nothing yet.
func (self *evsMirrorRun) executedDropLists(refId Id) ([]*EvsDropLists, error) {
	now := self.mirror.client.clock.Now()
	executed := []*EvsDropLists{}
	for _, drop := range self.drops {
		if drop.RefId != refId || now.Before(evsTime(drop.NotBeforeMs)) {
			continue
		}
		statementBytes, err := self.heldBytes(EvsMirrorStatementKey(refId, drop.Version))
		if err != nil {
			return nil, err
		}
		if statementBytes == nil {
			continue
		}
		statement, err := ParseEvsStatementFormat2(statementBytes)
		if err != nil {
			continue
		}
		pushId, err := IdFromBytes(statement.Push.GetPushId())
		if err != nil {
			continue
		}
		records := [][]byte{}
		for part := uint32(0); part <= statement.Push.GetPartCount(); part += 1 {
			record, err := self.heldBytes(EvsMirrorRecordKey(pushId, part))
			if err != nil {
				return nil, err
			}
			if record == nil {
				records = nil
				break
			}
			records = append(records, record)
		}
		if records == nil {
			continue
		}
		checked, err := evsMirrorCheckRecordsOf(statement, records, true)
		if err != nil || checked.Drop == nil {
			continue
		}
		lists, err := NewEvsDropLists(statement.Push, checked.Drop.Body)
		if err != nil {
			continue
		}
		executed = append(executed, lists)
	}
	return executed, nil
}

// A format-2 mirror's hash check of the segments it lacks (Check): one a version of its push names is judged once the
// check walked the ref, complete when kind-5 locators alone name it and a later held version writes or removes each
// path naming it, or when a held DROP whose window passed by this device's clock, with no held cancel, lists each
// version naming it; else it is the check's failure, as for format 1.
type evsMirrorCheckLack struct {
	now     time.Time
	changes map[string]uint64
	// by drop id in hex
	drops     map[string]*evsMirrorHeldDrop
	cancelled map[string]bool
	lacking   []*evsMirrorLacking
}

// A DROP the check walked.
type evsMirrorHeldDrop struct {
	lists     *EvsDropLists
	notBefore time.Time
}

// A segment the check found the mirror lacks.
type evsMirrorLacking struct {
	name    string
	detail  string
	version uint64
	named   *evsMirrorNamed
}

// The check's judge for one ref, nil on a client of format 1 alone.
func (self *EvsMirror) newCheckLack() *evsMirrorCheckLack {
	if self.client.format2Reader() == nil {
		return nil
	}
	return &evsMirrorCheckLack{now: self.client.clock.Now(), changes: map[string]uint64{}, drops: map[string]*evsMirrorHeldDrop{}, cancelled: map[string]bool{}}
}

// Notes a walked version's changes and DROP.
func (self *evsMirrorCheckLack) note(statement *EvsVerifiedStatement, checked *EvsCheckedPayload) {
	if self == nil {
		return
	}
	for _, change := range checked.Changes {
		key := change.TokenPath.KeyString()
		self.changes[key] = max(self.changes[key], statement.Version)
	}
	push := statement.Statement.Push
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) == 0 || checked.Drop == nil {
		return
	}
	history := checked.Drop.History
	switch history.GetAction() {
	case evsDropActionDrop:
		lists, err := NewEvsDropLists(push, checked.Drop.Body)
		if err == nil {
			self.drops[hex.EncodeToString(history.GetDropId())] = &evsMirrorHeldDrop{lists: lists, notBefore: evsTime(history.GetNotBeforeMs())}
		}
	case evsDropActionCancel:
		self.cancelled[hex.EncodeToString(history.GetCancelsDropId())] = true
	}
}

// Whether the check holds a lacking segment over to the ref's end: one a version of its push names.
func (self *evsMirrorCheckLack) hold(name string, detail string, statement *EvsVerifiedStatement, checked *EvsCheckedPayload, segmentId []byte) bool {
	if self == nil {
		return false
	}
	named := evsMirrorSegmentNames(statement, checked)[string(segmentId)]
	if named == nil || len(named.paths) == 0 {
		return false
	}
	self.lacking = append(self.lacking, &evsMirrorLacking{name: name, detail: detail, version: statement.Version, named: named})
	return true
}

// At the ref's end: each lacking segment's failure that neither a replacement nor an executed drop explains.
func (self *evsMirrorCheckLack) failures(fail func(name string, detail string)) {
	if self == nil {
		return
	}
	executed := []*EvsDropLists{}
	for dropId, drop := range self.drops {
		if !self.cancelled[dropId] && !self.now.Before(drop.notBefore) {
			executed = append(executed, drop.lists)
		}
	}
	for _, lacking := range self.lacking {
		item := &evsMirrorPending{version: lacking.version, named: lacking.named}
		if (lacking.named.kind5Only && evsMirrorReplacedAll(item, self.changes)) || evsMirrorDroppedAll(item, executed) {
			continue
		}
		fail(lacking.name, lacking.detail)
	}
}
