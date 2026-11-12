// A push's purge candidates and their hand-off (§11.13's purge and who rows, §11.8's 5h and step 7; D-EVS-37, I-EVS-2,
// I-EVS-9, FI-16, FS-65; EVS2-M10-06, DESIGN-DETAILS 10.2.6):
//
//	push      after 5h, PurgeCandidates over the versions step 4 read: each versionless version V a change replaces
//	          or removes, less every id a version of the push names, listed in the push's record; marked past 2,048
//	          ids or the record's 1 MiB
//	part      each replaced version's ids whole, nothing subtracted, the list's replaced flag set: a part cannot know
//	          what another part's versions name, so nothing deletes from it
//	seal      each part's candidates in part order, each less every id any part's versions name, an emptied one
//	          dropped; marked when any part was, or past the bounds; so a rename whose removal and target sit in two
//	          parts lists none of the target's ids
//	bit 4     set at step 7 on every push and seal replacing or removing a versionless version, candidates left or
//	          not (EVS-FORMAT.md's window row)
//	certain   a 200 from step 7, or a reread or a 5a retry showing the push committed, hands the record's list to
//	          PurgeSink once (EvsEngineDeps.Purge); a refused or unknown outcome hands nothing (I-EVS-2), and a nil
//	          sink queues nothing, which is safe, since evacuation's sweep takes every list
//
// The list is computed once an attempt, at its record's first write: a 412 rerun keeps it, since path-level CAS
// proves each V unchanged. A 5a retry, whose step 4 read the head after its push committed, takes the list from the
// record at the place the head names, and each V's entry version from the path's entry or the window below the
// commit, for the times the purge decides by; a V it cannot find is left to the sweep.
//
// Not safe for concurrent use: it lives on its attempt.

package evsservice

import (
	"context"
	"errors"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// What an attempt's record lists, once computed.
type pushPurge struct {
	// the record's list, nil when it lists none
	list *protocol.EvsPurgeList
	// each versionless version the push replaces or removes, as step 4 read it
	replaced []*PurgeReplaced
	// window bit 4
	replacesVersionless bool
}

// Each versionless version the view's changes replace or remove, as step 4 read it at the view's head.
func evsPurgeReplacedOf(view *PushView) []*PurgeReplaced {
	replaced := []*PurgeReplaced{}
	for _, change := range view.Payload.Changes {
		newest, refusal := evsPathNewestEntry(view, change.TokenPath)
		if refusal != nil || newest == nil || newest.GetVersioning() == uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
			continue
		}
		replaced = append(replaced, &PurgeReplaced{TokenPath: change.TokenPath, Version: newest})
	}
	return replaced
}

// Every new entry version of the view's changes.
func evsPushVersionsOf(view *PushView) []*protocol.EvsEntryVersion {
	versions := []*protocol.EvsEntryVersion{}
	for _, change := range view.Payload.Changes {
		if !change.WritesEntry() {
			continue
		}
		if entry, err := parseEvsEntryVersion(change.EntryVersion); err == nil {
			versions = append(versions, entry)
		}
	}
	return versions
}

// The room a record of baseByteCount bytes, its staged item included, leaves its purge list within 1 MiB.
func evsPurgeListRoom(baseByteCount int) int {
	// the list's own item length
	return max(0, sidecar.EvsBatchMaxRecordByteCount-baseByteCount-4)
}

// A one-part push's list: PurgeCandidates over step 4's versions, nil when nothing is left to purge.
func evsPushPurge(view *PushView, roomByteCount int) *pushPurge {
	replaced := evsPurgeReplacedOf(view)
	purge := &pushPurge{replaced: replaced, replacesVersionless: 0 < len(replaced)}
	if len(replaced) == 0 {
		return purge
	}
	list := PurgeCandidates(replaced, evsPushVersionsOf(view), roomByteCount)
	if list.GetMarked() || 0 < len(list.GetCandidates()) {
		purge.list = list
	}
	return purge
}

// A part's list: each replaced version's ids whole, replaced set, nil when the part replaces no versionless version.
func evsPartPurge(view *PushView, roomByteCount int) *pushPurge {
	replaced := evsPurgeReplacedOf(view)
	purge := &pushPurge{replaced: replaced, replacesVersionless: 0 < len(replaced)}
	if len(replaced) == 0 {
		return purge
	}
	// nothing subtracted: no version is passed
	list := PurgeCandidates(replaced, nil, roomByteCount)
	if !list.GetMarked() && len(list.GetCandidates()) == 0 {
		return purge
	}
	list.Replaced = true
	purge.list = list
	return purge
}

// A seal's list from its parts' (DESIGN-DETAILS 10.2.6): each part's candidates in part order less every id the push's
// versions name, an emptied one dropped; marked when a part was marked or past the bounds. partLists holds each part
// record's list, nil for none.
func evsSealPurge(view *PushView, partLists []*protocol.EvsPurgeList, roomByteCount int) *pushPurge {
	purge := &pushPurge{replaced: evsPurgeReplacedOf(view)}
	named := map[string]bool{}
	for _, version := range evsPushVersionsOf(view) {
		for _, locator := range version.GetChain() {
			if len(locator.GetId()) != 0 {
				named[string(locator.GetId())] = true
			}
		}
		for _, slotId := range version.GetSlotIds() {
			named[string(slotId)] = true
		}
	}
	marked := false
	list := &protocol.EvsPurgeList{}
	idCount := 0
	keep := func(ids [][]byte) [][]byte {
		kept := [][]byte{}
		for _, id := range ids {
			if !named[string(id)] {
				kept = append(kept, id)
			}
		}
		return kept
	}
	for _, partList := range partLists {
		if partList == nil {
			continue
		}
		purge.replacesVersionless = true
		if partList.GetMarked() {
			marked = true
			continue
		}
		for _, candidate := range partList.GetCandidates() {
			kept := &protocol.EvsPurgeCandidate{
				TokenPath:        candidate.GetTokenPath(),
				ReplacedVersion:  candidate.GetReplacedVersion(),
				SegmentIds:       keep(candidate.GetSegmentIds()),
				StagedSegmentIds: keep(candidate.GetStagedSegmentIds()),
				SlotIds:          keep(candidate.GetSlotIds()),
			}
			count := len(kept.GetSegmentIds()) + len(kept.GetStagedSegmentIds()) + len(kept.GetSlotIds())
			if count == 0 {
				continue
			}
			idCount += count
			list.Candidates = append(list.Candidates, kept)
		}
	}
	if 0 < len(purge.replaced) {
		purge.replacesVersionless = true
	}
	switch {
	case marked, sidecar.DefaultEvsFormatSettings().PurgeListMaxIdCount < idCount:
		purge.list = &protocol.EvsPurgeList{Marked: true}
	case 0 < len(list.GetCandidates()):
		if roomByteCount < proto.Size(list) {
			purge.list = &protocol.EvsPurgeList{Marked: true}
		} else {
			purge.list = list
		}
	}
	return purge
}

// The PurgeCommit step 8 hands PurgeSink for this attempt's commit at version, nil when its record lists nothing the
// purge takes (none, or marked: the sweep's).
func (self *pushAttempt) purgeCommit(version uint64) *PurgeCommit {
	if self.purge == nil || self.purge.list == nil || self.purge.list.GetMarked() || self.purge.list.GetReplaced() {
		return nil
	}
	return &PurgeCommit{
		ClusterId: self.cluster.ClusterId(),
		RepoId:    self.repoId,
		RefId:     self.refId,
		NetworkId: self.networkId,
		PushId:    self.pushId,
		Version:   version,
		PathEpoch: self.statement.Push.GetPathEpoch(),
		List:      self.purge.list,
		Replaced:  self.purge.replaced,
	}
}

// Hands a certain commit's list to the purge, off the reply path; a nil sink or commit queues nothing.
func (self *EvsEngine) handPurge(commit *PurgeCommit) {
	if commit == nil || self.deps.Purge == nil {
		return
	}
	self.deps.Purge.Certain(commit)
}

// A 5a retry's certainty: the push committed at version, by another attempt, its record at place. The list is the
// record's, and each replaced version's entry version is read from its path's entry or the window below version, for
// the purge's times; one not found is left out, which leaves its candidate to the sweep. Off the reply path.
func (self *pushAttempt) handRetriedPurge(version uint64, place *protocol.EvsPlace) {
	if self.engine.deps.Purge == nil || place == nil || !self.engine.format2Instance() {
		return
	}
	ctx := self.engine.ctx
	recordBytes, err := self.engine.readRecordBytesAt(ctx, self.cluster, self.repoId, self.refId, place)
	if err != nil {
		return
	}
	record, tail, err := sidecar.ParseEvsBatchRecordFormat2(recordBytes)
	if err != nil || tail.Empty() || record.PushId != self.pushId {
		return
	}
	list, err := tail.PurgeListValue()
	if err != nil || list == nil || list.GetMarked() || list.GetReplaced() {
		return
	}
	pathEpoch := self.statement.Push.GetPathEpoch()
	replaced := []*PurgeReplaced{}
	for _, candidate := range list.GetCandidates() {
		tokenPath, err := sidecar.ParseEvsTokenPath(candidate.GetTokenPath())
		if err != nil {
			continue
		}
		entry, err := self.readReplacedVersion(ctx, pathEpoch, tokenPath, candidate.GetReplacedVersion(), version)
		if err != nil || entry == nil {
			continue
		}
		replaced = append(replaced, &PurgeReplaced{TokenPath: tokenPath, Version: entry})
	}
	self.engine.handPurge(&PurgeCommit{
		ClusterId: self.cluster.ClusterId(),
		RepoId:    self.repoId,
		RefId:     self.refId,
		NetworkId: self.networkId,
		PushId:    self.pushId,
		Version:   version,
		PathEpoch: pathEpoch,
		List:      list,
		Replaced:  replaced,
	})
}

// The entry version of tokenPath at pathVersion that the push committed at commitVersion replaced: from the path's
// entry's folded versions, else from a window change below commitVersion. nil when neither holds it.
func (self *pushAttempt) readReplacedVersion(ctx context.Context, pathEpoch uint64, tokenPath sidecar.EvsTokenPath, pathVersion uint64, commitVersion uint64) (*protocol.EvsEntryVersion, error) {
	head, err := self.engine.heads.ReadCluster(ctx, self.cluster, self.repoId, self.refId)
	if err != nil {
		return nil, err
	}
	if head.Absent() || EvsHeadCurrentEpoch(head.Head) != pathEpoch {
		return nil, nil
	}
	read, err := ReadEntry(ctx, self.cluster, self.repoId, self.refId, pathEpoch, tokenPath, head.Head.GetFoldedThrough())
	if err != nil {
		return nil, err
	}
	for _, version := range read.Entry.GetVersions() {
		entry, err := parseEvsEntryVersion(version.GetEntryVersion())
		if err == nil && entry.GetVersion() == pathVersion {
			return entry, nil
		}
	}
	window, err := EvsHeadWindow(head.Head)
	if err != nil {
		return nil, err
	}
	first := EvsHeadWindowFirstVersion(head.Head)
	pushes := NewRecordPushSource(self.engine.records, self.engine.locator, self.cluster, self.repoId, self.refId)
	for i := len(window) - 1; 0 <= i; i -= 1 {
		version := first + uint64(i)
		if commitVersion <= version || !window[i].PathsDigest.MayChange(tokenPath) {
			continue
		}
		changes, err := pushes.ChangesAt(ctx, version, window[i], tokenPath)
		if errors.Is(err, ErrEvsRecordEvacuated) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		for _, change := range changes {
			if !change.TokenPath.Equal(tokenPath) || change.Removes() {
				continue
			}
			if entry, err := parseEvsEntryVersion(change.EntryVersion); err == nil && entry.GetVersion() == pathVersion {
				return entry, nil
			}
		}
	}
	return nil, nil
}
