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
// Coverage counts what the mirror holds: a replaced version's kind-5 segment that evs no longer serves is still named
// missing, and a drop's listed content stays required until the drop is applied (not built: §11.13's coverage of both).
//
// On every leg but ios_extension.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"

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
			self.drops = append(self.drops, &EvsMirrorDrop{RefId: head.RefId, Version: statement.Version, DropId: dropId, NotBeforeMs: history.GetNotBeforeMs()})
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
