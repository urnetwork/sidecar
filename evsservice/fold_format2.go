// Format 2 in the fold, the removal markers and the path-epoch copy (§11.7's fold, removal and epochs rows, §11.6's
// copy row; D-EVS-31, D-EVS-40, D-EVS-64, I-EVS-6, I-EVS-8, FI-6, FI-16; EVS2-M10-07):
//
//	versions  a folded versionless version keeps its versioning and its locators, kind 5 staged or not, as its
//	          statement's entry version holds them: the fold copies those bytes, and elision cuts only inline
//	          records, which a versionless version never has
//	unlisted  a removal at r covering an entry below a removed directory, a ref DELETE's removals included, whose
//	          newest version is versionless (1 or 2) and whose path the removing push's change list does not name:
//	          the marker carries that version's kind-5 segment ids, staged or not, and its slot ids, and the fold
//	          alarms fold_unlisted_versionless; marker collection deletes them (collect_markers.go). A listed file's
//	          marker carries nothing, since the purge has its content, and a path the push writes below the removed
//	          directory keeps its own version, its write coming before the prefix's removal at one version
//	drop      a DROP's written version (a lineage of boundary 1 whose newest entry is in the push's path epoch)
//	          replaces what the entry held, carrying nothing, and sets the drop mark {drop_id, through_version}; it
//	          is never skipped for a later window version, so the mark stands before the DROP leaves the window; a
//	          later fold keeps the mark through versions, markers and re-creations and raises it only for a newer
//	          drop; a cancel writes nothing
//	removed   a DROP's removed boundary writes no version, but the fold of the DROP sets, for each lineage of
//	          boundary 2 whose newest entry (e, t) is in the head's current epoch or a listed source, the drop mark
//	          {drop_id, through_version} on the entry at (e, t) while that entry holds a marker with folded versions
//	          below it: PUT If-Match, read again on 412; a 404, or a marker with no version beside it, needs none,
//	          since nothing is left there to cite. Like a written boundary's it is never skipped for a later window
//	          version, so it stands before the DROP is paged out, and 5h's fence finds it once window bit 5 is gone
//	          (DESIGN-DETAILS 10.2.7's removed row; EVS2-M10-36); its through_version may equal the marker's path
//	          version
//	copy      a copy keeps folded versions, markers with their carried ids and the drop mark in every entry it
//	          carries (carryEvsIndexEntry); under a removed or fresh prefix, the marker it writes carries a
//	          versionless entry's ids only where the removing push is known not to list the path (epoch_copy.go)
//	ids lost  plan-EVS2-marker-carried-ids decided an orphan marker under idx/<repo>/<ref>/_o/ for every write or
//	          delete that would drop carried ids; until its collection case and evs-11's store row land, each such
//	          write or delete alarms fold_carried_ids and the content stays: a creation or a directory's delta over a
//	          marker carrying ids (format1_guard.go), a fold's delete of a source copy holding a marker with ids or,
//	          below a removed directory, an unlisted versionless file, and a copy's delete of a source marker with ids
//
// Every write keeps the fold's and the copy's own rules: §11.7's 15 s stale deadline from the head read it relies
// on, a marker only over an older version, a 412 read again and merged, and the entry state while sources stand.
// The extra GETs before a source delete are made only in a format-2 repo, where a versionless file can stand.

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// EvsDropPath.boundary's values: a lineage whose DROP writes through_version, and one whose through_version is the
// standing removal's (§11.7's boundary row).
const (
	evsDropBoundaryWritten = 1
	evsDropBoundaryRemoved = 2
)

// A removed boundary's drop mark the fold sets on its marker's entry: the entry's epoch and token path, the mark, and
// the DROP's commit version, for alarms.
type foldRemovedMark struct {
	epoch         uint64
	tokenPath     sidecar.EvsTokenPath
	mark          *protocol.EvsDropMark
	commitVersion uint64
}

// The removed boundaries' marks the DROP committed at version sets (DESIGN-DETAILS 10.2.7's removed row): one per
// lineage of boundary 2 whose newest entry is in the head's current epoch or a source it lists. Nothing for any other
// push, a cancel included.
func (self *foldRun) planRemovedMarks(version uint64, windowEntry *sidecar.EvsWindowEntry, statement *sidecar.EvsStatement) error {
	if statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) == 0 {
		return nil
	}
	push, err := self.pushes.pushAt(self.ctx, version, windowEntry)
	if err != nil {
		return err
	}
	if push.drop == nil {
		return fmt.Errorf("%w: version %d is a DROP whose body was not read", ErrEvsFoldInvalid, version)
	}
	if push.drop.Cancel() {
		return nil
	}
	epochs := map[uint64]bool{self.epoch: true}
	for _, source := range self.head.Head.GetPathEpoch().GetSources() {
		epochs[source.GetEpoch()] = true
	}
	for _, path := range push.drop.History.GetPaths() {
		newest := path.GetLineage()[0]
		if path.GetBoundary() != evsDropBoundaryRemoved || !epochs[newest.GetEpoch()] {
			// an entry in no epoch the head reads has nothing left to cite: resolve checks the boundary (10.7)
			continue
		}
		tokenPath, err := sidecar.ParseEvsChangedTokenPath(newest.GetTokenPath())
		if err != nil {
			return fmt.Errorf("%w: version %d's DROP names a token path that does not parse", ErrEvsFoldInvalid, version)
		}
		self.removedMarks = append(self.removedMarks, &foldRemovedMark{
			epoch:     newest.GetEpoch(),
			tokenPath: tokenPath,
			mark: &protocol.EvsDropMark{
				DropId:         bytes.Clone(push.drop.History.GetDropId()),
				ThroughVersion: path.GetThroughVersion(),
			},
			commitVersion: version,
		})
	}
	return nil
}

// Writes each planned removed boundary's mark: see the file header.
func (self *foldRun) writeRemovedMarks() error {
	for _, removed := range self.removedMarks {
		if err := self.writeRemovedMark(removed); err != nil {
			return err
		}
	}
	return nil
}

// One removed boundary's mark on its entry: read, and while it holds a marker with folded versions whose mark is
// lower, PUT If-Match with the mark raised; a 412 or an unknown outcome reads and tries again.
func (self *foldRun) writeRemovedMark(removed *foldRemovedMark) error {
	for attempt := 0; attempt < self.folder.settings.FoldEntryRetryCount; attempt += 1 {
		if err := self.ready(); err != nil {
			return err
		}
		read, err := ReadEntry(self.ctx, self.cluster, self.request.RepoId, self.request.RefId, removed.epoch, removed.tokenPath, self.head.Head.GetFoldedThrough())
		if err != nil {
			return err
		}
		entry := read.Entry
		if read.Absent() || entry.GetMarker() == nil || len(entry.GetVersions()) == 0 {
			// nothing is left there to cite
			return nil
		}
		if held := entry.GetDropMark(); held != nil && removed.mark.GetThroughVersion() <= held.GetThroughVersion() {
			// written already, or a newer drop's
			return nil
		}
		if entry.GetMarker().GetPathVersion() < removed.mark.GetThroughVersion() {
			// a boundary past the standing removal, which 5h and resolve refuse: alarmed, and the entry stays
			self.folder.log.Errorf("[evs] alarm fold_drop: version %d's DROP marks a removed boundary through %d past its marker's version %d", removed.commitVersion, removed.mark.GetThroughVersion(), entry.GetMarker().GetPathVersion())
			return nil
		}
		marked := proto.Clone(entry).(*protocol.EvsIndexEntry)
		marked.DropMark = raisedDropMark(entry.GetDropMark(), removed.mark, self.folder.log)
		err = self.putAt(removed.epoch, removed.tokenPath, read, marked, read.State)
		if retryEntryWrite(err) {
			continue
		}
		if err != nil {
			return err
		}
		self.result.EntryWriteCount += 1
		return nil
	}
	return fmt.Errorf("%w: %d tries on one entry", ErrEvsFoldBusy, self.folder.settings.FoldEntryRetryCount)
}

// The ids a marker carries for a removed versionless version: its kind-5 segment ids, staged or not, and its slot
// ids, each once and in chain order. None for a versioned version, whose content its history keeps, nor for the kind-1
// locators a versionless version may cite, which are never purged (§11.7's content row).
func evsCarriedIdsOf(entryVersion *protocol.EvsEntryVersion) ([][]byte, [][]byte) {
	if entryVersion.GetVersioning() == uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
		return nil, nil
	}
	seen := map[string]bool{}
	segmentIds := [][]byte{}
	for _, locator := range entryVersion.GetChain() {
		id := locator.GetId()
		if protocol.EvsLocatorKind(locator.GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT ||
			len(id) != sha256.Size || seen[string(id)] {
			continue
		}
		seen[string(id)] = true
		segmentIds = append(segmentIds, bytes.Clone(id))
	}
	slotIds := [][]byte{}
	for _, slotId := range entryVersion.GetSlotIds() {
		if len(slotId) != 16 || seen[string(slotId)] {
			continue
		}
		seen[string(slotId)] = true
		slotIds = append(slotIds, bytes.Clone(slotId))
	}
	return segmentIds, slotIds
}

// The entry version of an entry's newest folded version, nil when it holds none. ParseEvsIndexEntry held each to
// parse.
func evsNewestEntryVersion(entry *protocol.EvsIndexEntry) *protocol.EvsEntryVersion {
	versions := entry.GetVersions()
	if len(versions) == 0 {
		return nil
	}
	entryVersion, err := parseEvsEntryVersion(versions[0].GetEntryVersion())
	if err != nil {
		return nil
	}
	return entryVersion
}

// Gives marker the carried ids of entry's newest version when that version is versionless: a removal whose push did
// not list the file (§11.7's removal row, D-EVS-40), which alarms. what names the writer for the alarm. Whether it
// carries any.
func carryUnlistedIds(marker *protocol.EvsRemovalMarker, entry *protocol.EvsIndexEntry, log sidecar.Logger, what string) bool {
	newest := evsNewestEntryVersion(entry)
	if newest == nil {
		return false
	}
	segmentIds, slotIds := evsCarriedIdsOf(newest)
	if len(segmentIds) == 0 && len(slotIds) == 0 {
		return false
	}
	marker.SegmentIds = segmentIds
	marker.SlotIds = slotIds
	log.Errorf("[evs] alarm fold_unlisted_versionless: %s marks version %d of a versionless file its removing push did not list, carrying %d segment ids and %d slot ids for its marker's collection",
		what, newest.GetVersion(), len(segmentIds), len(slotIds))
	return true
}

// Whether every id marker carries is carried by kept as well, so a write or delete dropping marker loses none.
func carriedIdsKept(marker *protocol.EvsRemovalMarker, kept *protocol.EvsRemovalMarker) bool {
	held := map[string]bool{}
	for _, id := range kept.GetSegmentIds() {
		held[string(id)] = true
	}
	for _, id := range kept.GetSlotIds() {
		held[string(id)] = true
	}
	for _, ids := range [][][]byte{marker.GetSegmentIds(), marker.GetSlotIds()} {
		for _, id := range ids {
			if !held[string(id)] {
				return false
			}
		}
	}
	return true
}

// The drop mark an entry keeps once a DROP's written version sets next over held: next, unless held is a drop's at or
// past next's through_version, which only a fault gives and which the entry keeps (§11.7's fold row: a later fold
// raises the mark only for a newer drop).
func raisedDropMark(held *protocol.EvsDropMark, next *protocol.EvsDropMark, log sidecar.Logger) *protocol.EvsDropMark {
	if held == nil || held.GetThroughVersion() < next.GetThroughVersion() {
		return next
	}
	log.Errorf("[evs] alarm fold_drop: a drop through version %d over a mark through %d, which stays", next.GetThroughVersion(), held.GetThroughVersion())
	return held
}

// A DROP's written version merged into its entry (§11.7's fold row): it replaces what the entry held, carrying
// nothing, and sets the drop mark. A marker it would replace, which no honest DROP meets (its boundary is the path's
// head), alarms if it carries ids.
func applyFoldDropVersion(entry *protocol.EvsIndexEntry, event *foldEvent, version *protocol.EvsIndexVersion, log sidecar.Logger) *protocol.EvsIndexEntry {
	alarmCarriedIdsDropped(log, entry.GetMarker(), "a DROP's written version")
	return &protocol.EvsIndexEntry{
		Versions: []*protocol.EvsIndexVersion{version},
		DropMark: raisedDropMark(entry.GetDropMark(), event.dropMark, log),
	}
}

// The drop marks the DROP committed at version sets, by the token path each written version has in the push's path
// epoch: {drop_id, through_version} for each lineage of boundary 1 whose newest entry is in that epoch. nil for any
// other push, a cancel and a removed boundary included, which write no version (§11.7's boundary row). Called after
// allChangesAt read the push, which reads a sealed DROP's body with its parts.
func (self *foldRun) dropMarksAt(version uint64, windowEntry *sidecar.EvsWindowEntry, statement *sidecar.EvsStatement) (map[string]*protocol.EvsDropMark, error) {
	if statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) == 0 {
		return nil, nil
	}
	push, err := self.pushes.pushAt(self.ctx, version, windowEntry)
	if err != nil {
		return nil, err
	}
	if push.drop == nil {
		// the stored checks read a DROP's body with its changes, so this is a fault
		return nil, fmt.Errorf("%w: version %d is a DROP whose body was not read", ErrEvsFoldInvalid, version)
	}
	if push.drop.Cancel() {
		return nil, nil
	}
	marks := map[string]*protocol.EvsDropMark{}
	for _, path := range push.drop.History.GetPaths() {
		newest := path.GetLineage()[0]
		if path.GetBoundary() != evsDropBoundaryWritten || newest.GetEpoch() != statement.Push.GetPathEpoch() {
			continue
		}
		tokenPath, err := sidecar.ParseEvsChangedTokenPath(newest.GetTokenPath())
		if err != nil {
			return nil, fmt.Errorf("%w: version %d's DROP names a token path that does not parse", ErrEvsFoldInvalid, version)
		}
		marks[string(tokenPath.Bytes())] = &protocol.EvsDropMark{
			DropId:         bytes.Clone(push.drop.History.GetDropId()),
			ThroughVersion: path.GetThroughVersion(),
		}
	}
	return marks, nil
}

// The mark a DROP's write event sets, from the marks its push's body gives: its lineage's, its through_version the
// version written, which §11.7's boundary row makes the path's next. A write of a DROP that names no written lineage
// for it, or a lineage through another version, breaks the rules 5c and 5h hold a DROP to: it alarms, and the first
// folds as an ordinary write, the second with the version written.
func (self *foldRun) dropMarkOf(marks map[string]*protocol.EvsDropMark, event *foldEvent) *protocol.EvsDropMark {
	if marks == nil || event.kind != foldEventWrite {
		return nil
	}
	mark := marks[string(event.change.TokenPath.Bytes())]
	written := event.entryVersion.GetVersion()
	switch {
	case mark == nil:
		self.folder.log.Errorf("[evs] alarm fold_drop: version %d's DROP writes a path no written lineage names", event.commitVersion)
		return nil
	case mark.GetThroughVersion() != written:
		self.folder.log.Errorf("[evs] alarm fold_drop: version %d's DROP writes version %d for a lineage through %d", event.commitVersion, written, mark.GetThroughVersion())
		return &protocol.EvsDropMark{DropId: mark.GetDropId(), ThroughVersion: written}
	}
	return mark
}

// Whether the repo's repo/ shows format 2, where a versionless file can stand: the extra reads before a source
// delete are made only there. The read comes from the process's repo cache, which every write's recheck fills.
func (self *foldRun) repoFormat2() (bool, error) {
	read, err := self.folder.repos.Read(self.ctx, self.cluster, self.request.RepoId)
	if err != nil {
		return false, err
	}
	return sidecar.EvsRepoFormat2 <= read.Object.GetFormat(), nil
}

// Before the fold deletes the source copy at key (fold_sources.go), in a format-2 repo: one GET of it, and an alarm
// when ids would leave the index with it, its content staying (plan-EVS2-marker-carried-ids's interim): a marker's
// carried ids that kept, the current entry's marker, does not also carry, and, below a removed directory (unlisted),
// a versionless file no change of the range names.
func (self *foldRun) alarmSourceIdsLeaving(key string, kept *protocol.EvsRemovalMarker, unlisted bool) error {
	format2, err := self.repoFormat2()
	if err != nil || !format2 {
		return err
	}
	object, err := self.cluster.Get(self.ctx, key)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	defer object.Body.Close()
	entryBytes, err := io.ReadAll(io.LimitReader(object.Body, EvsIndexEntryMaxByteCount+1))
	if err != nil {
		return err
	}
	entry, err := ParseEvsIndexEntry(entryBytes)
	if err != nil {
		// a copy that breaks its shape leaves with nothing to keep, and the read's alarm is the fold's
		self.folder.log.Errorf("[evs] alarm fold_source_entry: a source copy deleted below a removal: %v", err)
		return nil
	}
	switch {
	case markerCarriesIds(entry.GetMarker()) && !carriedIdsKept(entry.GetMarker(), kept):
		alarmCarriedIdsDropped(self.folder.log, entry.GetMarker(), "a fold's delete of a source copy")
	case unlisted && entry.GetMarker() == nil:
		if newest := evsNewestEntryVersion(entry); newest != nil {
			if segmentIds, slotIds := evsCarriedIdsOf(newest); 0 < len(segmentIds)+len(slotIds) {
				self.folder.log.Errorf("[evs] alarm fold_carried_ids: a fold's delete below a removed directory drops an unlisted versionless file's %d segment ids and %d slot ids, whose content stays", len(segmentIds), len(slotIds))
			}
		}
	}
	return nil
}

// Whether the push that removed a prefix of the copy's path at version, whose window entry the head the copy relies
// on holds, names that path itself, so the purge has a versionless file's content and its marker carries none (§11.7's
// removal row). A version at or below folded_through, or paged out of the window, lists no path the copy finds absent
// from the current epoch: its fold wrote every path it names there before its range was folded, and every older
// version's fold with it. A fresh prefix keeps only its re-creation's version, not its removal's, so for one
// (removed false) only that rule tells. known is false where the copy cannot tell: a fresh prefix's re-creation not
// yet folded, a version past the head it relies on, or a record it cannot read.
func (self *copyRun) removalLists(version uint64, removed bool, tokenPath sidecar.EvsTokenPath) (listed bool, known bool, err error) {
	head := self.head.Head
	first := EvsHeadWindowFirstVersion(head)
	switch {
	case version <= head.GetFoldedThrough() || version < first:
		return false, true, nil
	case !removed || head.GetVersion() < version:
		return false, false, nil
	}
	removalVersion := version
	window, err := EvsHeadWindow(head)
	if err != nil {
		return false, false, fmt.Errorf("%w: %v", ErrEvsHeadInvalid, err)
	}
	source := NewRecordPushSource(self.records, self.locator, self.cluster, self.repoId, self.refId)
	changes, err := source.ChangesAt(self.ctx, removalVersion, window[removalVersion-first], tokenPath)
	switch {
	case errors.Is(err, ErrEvsRecordEvacuated):
		return false, false, nil
	case err != nil:
		return false, false, err
	}
	for _, change := range changes {
		if change.TokenPath.Equal(tokenPath) {
			return true, true, nil
		}
	}
	return false, true, nil
}

// The marker the copy writes under a removed or fresh prefix (§11.6's prefixes row), given the carried ids of the
// moved entry's newest version when it is versionless and the prefix's removal is known not to list it; where the copy
// cannot tell, the marker carries nothing and the content stays, which it warns of. removalVersion is the prefix's
// marker's removal, or a fresh prefix's newest version (prefixRemoval).
func (self *copyRun) carryUnderPrefix(marker *protocol.EvsRemovalMarker, entry *protocol.EvsIndexEntry, path sidecar.EvsTokenPath, removalVersion uint64, prefixRemoved bool) error {
	newest := evsNewestEntryVersion(entry)
	if newest == nil || newest.GetVersioning() == uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
		return nil
	}
	listed, known, err := self.removalLists(removalVersion, prefixRemoved, path)
	switch {
	case err != nil:
		return err
	case !known:
		self.log.Warningf("[evs] copy: repo %s: a versionless file marked under a prefix removed at %d, which the copy cannot tell listed it or not; its marker carries no ids",
			sidecar.EvsKeyId(self.repoId), removalVersion)
		return nil
	case listed:
		return nil
	}
	carryUnlistedIds(marker, entry, self.log, "a path-epoch copy under a removed prefix")
	return nil
}

// Before the copy deletes a source copy of a path whose current entry stands (§11.6's 412 row): an alarm when the
// source's marker carries ids the current entry does not, which leave with it, their content staying
// (plan-EVS2-marker-carried-ids's interim).
func (self *copyRun) alarmSourceIdsLeaving(source *EvsEntryRead, current *EvsEntryRead) {
	marker := source.Entry.GetMarker()
	if markerCarriesIds(marker) && !carriedIdsKept(marker, current.Entry.GetMarker()) {
		alarmCarriedIdsDropped(self.log, marker, "a copy's delete of a source marker under a standing entry")
	}
}
