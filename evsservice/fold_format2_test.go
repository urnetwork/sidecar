// EVS2-M10-07's tests on T2: folds, markers and copies in format 2. A world of real format-2 statements and records,
// a record listing purge candidates in format 2's form, folded by the real Folder: versionless versions folded as
// written; FS-67's fold clauses (an unlisted versionless file below a removed directory alarms and its kind-5
// segment and slot ids land in its marker, a listed one's do not, a ref DELETE's alike, a path the removing push
// writes below the directory keeping its own content); a DROP's fold leaving only through_version and the mark, a
// new version keeping it, a newer drop raising it, a cancel and a removed boundary writing nothing; FS-58's stale and
// late folds rerun over format-2 entries; the path-epoch copy keeping versionless versions, carried ids and the drop
// mark, at each of its boundaries; and the alarms where ids would leave the index, which keep the content.

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A logger keeping every line, safe for concurrent use, for alarms a test counts.
type format2Lines struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *format2Lines) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *format2Lines) Info(args ...any) {
	self.add(fmt.Sprint(args...))
}

func (self *format2Lines) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *format2Lines) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *format2Lines) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}

func (self *format2Lines) V(level int32) sidecar.Verbose {
	return sidecar.NewNoopLogger().V(level)
}

// How many lines name the alarm.
func (self *format2Lines) count(alarm string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, line := range self.lines {
		if strings.Contains(line, "alarm "+alarm+":") {
			count += 1
		}
	}
	return count
}

// The lines so far, for a failure's message.
func (self *format2Lines) String() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return strings.Join(self.lines, "\n")
}

// A world whose repo/ is format 2 and whose folder logs to lines.
func newFormat2World(t *testing.T) (*evsWorld, *format2Lines) {
	world := newEvsWorld(t)
	lines := &format2Lines{}
	world.folder = world.folderLoggingTo(lines)
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat2, NetworkId: testId("network-a").Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	object, err := world.cluster.Head(world.ctx, RepoKey(world.repoId))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.cluster.PutIfMatch(world.paidCtx, RepoKey(world.repoId), object.Etag, repoBytes, nil); err != nil {
		t.Fatal(err)
	}
	return world, lines
}

// A folder over the world's clusters, as its own process, logging to log.
func (self *evsWorld) folderLoggingTo(log sidecar.Logger) *Folder {
	priceTable, err := DefaultPriceTable(self.settings.PriceBlockByteCount)
	if err != nil {
		self.t.Fatal(err)
	}
	return NewFolder(self.ctx, self.clock, self.host.ClockCheck, self.budgetedBlob, self.host.Budget, self.heads, NewRecordCache(self.settings),
		NewRepoCache(self.clock, self.settings), priceTable, self.settings, log)
}

// One change of a format-2 world push: the world's change, and for a versionless file's write its versioning, its
// kind-5 locators, unstaged and staged, and its slot ids.
type format2Change struct {
	*worldChange
	versioning uint32
	segmentIds [][]byte
	stagedIds  [][]byte
	slotIds    [][]byte
}

// A versionless write of change, its ids drawn from label: two unstaged kind-5 segments, one staged and one slot.
func versionless(change *worldChange, label string) *format2Change {
	return &format2Change{
		worldChange: change,
		versioning:  uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS),
		segmentIds:  [][]byte{format2Id(label + " segment 1"), format2Id(label + " segment 2")},
		stagedIds:   [][]byte{format2Id(label + " staged")},
		slotIds:     [][]byte{format2SlotId(label)},
	}
}

// A versioned change of a format-2 push.
func versioned(change *worldChange) *format2Change {
	return &format2Change{worldChange: change}
}

// A 32 B id from a label.
func format2Id(label string) []byte {
	digest := sha256.Sum256([]byte("format2 " + label))
	return digest[:]
}

// A 16 B slot id from a label.
func format2SlotId(label string) []byte {
	digest := sha256.Sum256([]byte("format2 slot " + label))
	return digest[:16]
}

// One format-2 push of the world.
type format2Push struct {
	changes []*format2Change
	flags   uint32
	// a DROP's body, its paths' lists from listed in their order, which the push's commit sorts by newest token path
	drop   *protocol.EvsDropHistory
	listed [][][]byte
	// the purge candidates its record lists, which makes the record format 2's form; nil for format 1's
	purge *protocol.EvsPurgeList
	// the record's batch instance and seq when it is format 2's form
	seq uint32
}

// The entry version bytes a format-2 change writes: the world's own for a versioned file or a directory, else a
// versionless file's, its chain of kind-5 locators and its slots.
func (self *evsWorld) format2EntryVersion(pushId sidecar.Id, baseVersion uint64, change *format2Change) []byte {
	if change.versioning == 0 {
		return self.entryVersion(pushId, baseVersion, change.worldChange)
	}
	entry := &protocol.EvsEntryVersion{
		Version: change.version, PushId: pushId.Bytes(), BaseVersion: baseVersion, TimeMs: self.clock.Now().UnixMilli(),
		PaddedSize: 4096, Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), Versioning: change.versioning,
		SealedFields: []byte(fmt.Sprintf("sealed fields and content_sha256 %d", change.version)),
		SlotIds:      change.slotIds,
	}
	for _, id := range change.segmentIds {
		entry.Chain = append(entry.Chain, &protocol.EvsLocator{
			Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: id,
			Offset: sidecar.EvsKind5SegmentHeaderByteCount, Length: uint32(sidecar.EvsRecordByteCount(4096)),
		})
	}
	for _, id := range change.stagedIds {
		entry.Chain = append(entry.Chain, &protocol.EvsLocator{
			Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: id, Staged: true,
			Offset: sidecar.EvsKind5SegmentHeaderByteCount, Length: uint32(sidecar.EvsRecordByteCount(1024)),
		})
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	return entryBytes
}

// The plan of a format-2 push at the head's next version: its id, base and chain.
func (self *evsWorld) format2Plan(push *format2Push) (*sidecar.EvsPushPlan, []*worldChange) {
	self.pushSeq += 1
	pushId := testId(fmt.Sprintf("push-%d", self.pushSeq))
	baseVersion := self.head.Version()
	baseChain := sidecar.EvsChainStart(self.repoId, self.refId)
	if !self.head.Absent() && 0 < baseVersion {
		baseChain = [32]byte(self.head.Head.GetChain())
	}
	pathEpoch := uint64(1)
	if !self.head.Absent() {
		pathEpoch = EvsHeadCurrentEpoch(self.head.Head)
	}
	plan := &sidecar.EvsPushPlan{
		RepoId: self.repoId, RefId: self.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		PushId: pushId, BaseVersion: baseVersion, BaseChain: baseChain, Generation: 1, GroupId: testId("group"),
		GenerationCommitment: make([]byte, 32), PathEpoch: pathEpoch, Auth: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)},
		SignerSidecarId: self.signerId, ClientId: testId("client"), TimeMs: self.clock.Now().UnixMilli(),
		SealedMetadata: []byte("sealed metadata"), Flags: push.flags,
		SourcesStand: !self.head.Absent() && 0 < len(self.head.Head.GetPathEpoch().GetSources()),
	}
	// a statement lists its changes by token path
	slices.SortStableFunc(push.changes, func(a *format2Change, b *format2Change) int { return a.path.Compare(b.path) })
	worldChanges := []*worldChange{}
	for _, change := range push.changes {
		planned := &sidecar.EvsPlannedChange{TokenPath: change.path, BaseEntryVersion: change.base, SourcePaths: change.sourcePaths}
		if change.version != 0 {
			planned.EntryVersion = self.format2EntryVersion(pushId, baseVersion, change)
		}
		plan.Changes = append(plan.Changes, planned)
		worldChanges = append(worldChanges, change.worldChange)
	}
	if push.drop != nil {
		history := proto.Clone(push.drop).(*protocol.EvsDropHistory)
		if history.GetAction() == 1 && history.GetNotBeforeMs() == 0 {
			history.NotBeforeMs = plan.TimeMs + sidecar.EvsDropWindowMs
		}
		lists := []byte{}
		if 0 < len(history.GetPaths()) {
			var err error
			lists, err = sidecar.EvsBuildDropLists(history.GetPaths(), push.listed)
			if err != nil {
				self.t.Fatal(err)
			}
		}
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(history)
		if err != nil {
			self.t.Fatal(err)
		}
		plan.DropBody = body
		plan.DropLists = lists
	}
	return plan, worldChanges
}

// Commits a format-2 push at the head's next version, its record of format 2's form in a batch of its own when it
// lists purge candidates, else through the batch writer, and its window entry appended: its version.
func (self *evsWorld) pushFormat2(push *format2Push) uint64 {
	self.t.Helper()
	plan, worldChanges := self.format2Plan(push)
	built, err := self.builder.BuildFormat2(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	if len(built.Parts) != 0 {
		self.t.Fatal("a one-part format-2 push built in parts")
	}
	record := &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: self.repoId, RefId: self.refId, PushId: plan.PushId,
		SignerSidecarId: self.signerId, TimeMs: plan.TimeMs, Body: sidecar.EvsPushRecordBody(built.Statement.Bytes, built.Payload),
	}
	place := self.putFormat2Record(record, push.purge)
	changedPaths := make([]sidecar.EvsTokenPath, len(plan.Changes))
	createsPath := false
	for i, change := range plan.Changes {
		changedPaths[i] = change.TokenPath
		createsPath = createsPath || (change.BaseEntryVersion == 0 && len(change.EntryVersion) != 0)
	}
	var coveringPrefixes []sidecar.EvsTokenPath
	if len(built.Statement.Push.GetChangesRoot()) != 0 {
		coveringPrefixes = built.Statement.ChangedPrefixes
	}
	return self.commitWindowEntry(plan, built.Statement, sidecar.NewEvsWindowEntry(built.Statement.Sha256, built.Statement.Push, changedPaths, coveringPrefixes, createsPath, place), worldChanges)
}

// A record at its place: of format 2's form with purge's candidates, in a batch of its own, else through the batch
// writer in format 1's.
func (self *evsWorld) putFormat2Record(record *sidecar.EvsBatchRecord, purge *protocol.EvsPurgeList) *protocol.EvsPlace {
	self.t.Helper()
	if purge == nil {
		place, err := self.batches.Append(self.paidCtx, "meta-1", record)
		if err != nil {
			self.t.Fatal(err)
		}
		return place
	}
	listBytes, err := sidecar.EncodeEvsPurgeList(purge)
	if err != nil {
		self.t.Fatal(err)
	}
	now := self.clock.Now()
	self.pushSeq += 1
	seq := uint32(0x5000 + self.pushSeq)
	writer := sidecar.NewEvsBatchWriter(0x7e59, BatchMinute(now), seq, now.UnixMilli())
	place, err := writer.AddFormat2(record, &sidecar.EvsBatchRecordTail{PurgeList: listBytes})
	if err != nil {
		self.t.Fatal(err)
	}
	batchBytes, err := writer.Bytes()
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfNoneMatch(self.paidCtx, BatchKey(BatchMinute(now), 0x7e59, seq), batchBytes, nil); err != nil {
		self.t.Fatal(err)
	}
	return place
}

// The head moved to the push's version by one CAS, windowEntry appended, and the world's history kept.
func (self *evsWorld) commitWindowEntry(plan *sidecar.EvsPushPlan, statement *sidecar.EvsStatement, windowEntry *sidecar.EvsWindowEntry, changes []*worldChange) uint64 {
	self.t.Helper()
	next := CloneEvsHead(self.head.Head)
	if self.head.Absent() {
		next = &protocol.EvsHead{
			RefKind: uint32(protocol.EvsRefKind_EVS_REF_SHARED), RefMode: uint32(protocol.EvsRefMode_EVS_REF_FILE),
			PathEpoch: &protocol.EvsPathEpoch{Current: 1}, WindowBaseChain: plan.BaseChain[:],
		}
	}
	chain := sidecar.EvsChainNext(plan.BaseChain, plan.PushId, statement.Sha256)
	next.Version = plan.BaseVersion + 1
	next.Chain = chain[:]
	next.PushId = plan.PushId.Bytes()
	next.Window = append(bytes.Clone(next.GetWindow()), windowEntry.Encode()...)
	next.Deleted = plan.Flags&uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) != 0
	written, err := self.heads.Commit(self.ctx, self.cluster, self.repoId, self.refId, self.head, next)
	if err != nil {
		self.t.Fatal(err)
	}
	self.head = written
	self.history = append(self.history, &worldPush{version: next.Version, changes: changes})
	return next.Version
}

// The candidates a push removing or replacing versionless versions lists: per change, the ids the replaced
// version's write named.
func format2PurgeList(replaced ...*format2Change) *protocol.EvsPurgeList {
	list := &protocol.EvsPurgeList{}
	for _, change := range replaced {
		list.Candidates = append(list.Candidates, &protocol.EvsPurgeCandidate{
			TokenPath: change.path.Components(), ReplacedVersion: change.version,
			SegmentIds: change.segmentIds, StagedSegmentIds: change.stagedIds, SlotIds: change.slotIds,
		})
	}
	return list
}

// A file removal of change's path, the version it removes being change's.
func format2Removal(change *format2Change) *format2Change {
	return versioned(&worldChange{path: change.path, base: change.version})
}

// Whether the marker carries exactly the ids change's versionless write named, staged included.
func carriesIdsOf(marker *protocol.EvsRemovalMarker, change *format2Change) bool {
	wantSegments := append(slices.Clone(change.segmentIds), change.stagedIds...)
	return slices.EqualFunc(marker.GetSegmentIds(), wantSegments, bytes.Equal) &&
		slices.EqualFunc(marker.GetSlotIds(), change.slotIds, bytes.Equal)
}

// The entry version a folded version holds, parsed.
func foldedEntryVersion(t *testing.T, version *protocol.EvsIndexVersion) *protocol.EvsEntryVersion {
	t.Helper()
	entryVersion, err := parseEvsEntryVersion(version.GetEntryVersion())
	if err != nil {
		t.Fatal(err)
	}
	return entryVersion
}

// §11.7's holds row in format 2: a versionless file's folded versions keep their versioning and their locators, kind
// 5 staged or not, and their slots, byte for byte as the statements' entry versions hold them, none elided since they
// hold no inline record; an index file's versioning 2 the same; the records listing purge candidates are of format
// 2's form, which the fold reads; and the newest rule agrees.
func TestFormat2FoldKeepsVersionlessVersionsAndTheirLocatorsAsWritten(t *testing.T) {
	world, lines := newFormat2World(t)
	x, index := worldPath("x"), worldPath("i")
	first := versionless(&worldChange{path: x, version: 1}, "x1")
	world.pushFormat2(&format2Push{changes: []*format2Change{first}})
	second := versionless(&worldChange{path: x, base: 1, version: 2}, "x2")
	second.slotIds = first.slotIds
	world.pushFormat2(&format2Push{changes: []*format2Change{second}, purge: &protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{{
		TokenPath: x.Components(), ReplacedVersion: 1, SegmentIds: first.segmentIds, StagedSegmentIds: first.stagedIds,
	}}}})
	third := versionless(&worldChange{path: x, base: 2, version: 3}, "x3")
	third.slotIds = first.slotIds
	world.pushFormat2(&format2Push{changes: []*format2Change{third}, purge: &protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{{
		TokenPath: x.Components(), ReplacedVersion: 2, SegmentIds: second.segmentIds, StagedSegmentIds: second.stagedIds,
	}}}})
	indexFile := versionless(&worldChange{path: index, version: 4}, "i")
	indexFile.versioning = uint32(protocol.EvsVersioning_EVS_VERSIONING_INDEX)
	world.pushFormat2(&format2Push{changes: []*format2Change{indexFile}})
	world.fold(4)

	versions := world.entryOf(x).Entry.GetVersions()
	if len(versions) != 3 {
		t.Fatalf("x's entry holds %d versions", len(versions))
	}
	for i, change := range []*format2Change{third, second, first} {
		entryVersion := foldedEntryVersion(t, versions[i])
		if versions[i].GetElided() || entryVersion.GetVersion() != change.version ||
			entryVersion.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS) {
			t.Fatalf("folded version %d: %v", i, entryVersion)
		}
		kinds, staged := 0, 0
		for _, locator := range entryVersion.GetChain() {
			if protocol.EvsLocatorKind(locator.GetKind()) == protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT {
				kinds += 1
			}
			if locator.GetStaged() {
				staged += 1
			}
		}
		if kinds != 3 || staged != 1 || !slices.EqualFunc(entryVersion.GetSlotIds(), first.slotIds, bytes.Equal) {
			t.Fatalf("folded version %d's locators: %v", i, entryVersion.GetChain())
		}
	}
	// the bytes are the statement's: the newest's entry_sha256 is its change's
	head := world.head
	window, err := EvsHeadWindow(head.Head)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := NewRecordPushSource(NewRecordCache(world.settings), world.cluster, world.repoId, world.refId).ChangesAt(world.ctx, 3, window[2], x)
	if err != nil || len(changes) != 1 || !bytes.Equal(changes[0].EntryVersion, versions[0].GetEntryVersion()) {
		t.Fatalf("the newest folded version is not its statement's bytes: %v", err)
	}
	// those records are of format 2's form, which a format-1 instance's cache refuses
	format1Settings := *world.settings
	format1Settings.InstanceFormat = sidecar.EvsRepoFormat1
	if _, err := ReadRecord(world.ctx, NewRecordCache(&format1Settings), world.cluster, window[2].Place); !errors.Is(err, sidecar.ErrEvsFormatUnsupported) {
		t.Fatalf("a format-1 read of a record listing candidates: %v", err)
	}
	if indexed := foldedEntryVersion(t, world.entryOf(index).Entry.GetVersions()[0]); indexed.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_INDEX) {
		t.Fatalf("the index file's versioning %d", indexed.GetVersioning())
	}
	world.requireNewest(x)
	world.requireNewest(index)
	if lines.count("fold_unlisted_versionless") != 0 || lines.count("fold_carried_ids") != 0 || lines.count("fold_invalid") != 0 {
		t.Fatalf("a fold of writes alarmed:\n%s", lines)
	}
}

// FS-67's fold clauses: a directory removed by one push that lists one versionless file below it and not the
// others. The listed file's marker carries nothing, since the purge has its content; an unlisted versionless file
// the removal's LIST marks carries its newest version's kind-5 segment ids, the staged one included, and its slot,
// with an alarm; so does one the fold's range changed itself, whose marker comes from its own merge; a versioned
// file carries nothing; and a refold by another process writes and alarms nothing more.
func TestFormat2RemovalFoldCarriesAnUnlistedVersionlessFilesIds(t *testing.T) {
	world, lines := newFormat2World(t)
	directory := worldPath("d")
	listed := versionless(&worldChange{path: worldPath("d", "x"), version: 1}, "x")
	unlisted := versionless(&worldChange{path: worldPath("d", "y"), version: 1}, "y")
	kept := versioned(&worldChange{path: worldPath("d", "z"), version: 1})
	changed := versionless(&worldChange{path: worldPath("d", "w"), version: 1}, "w1")
	world.pushFormat2(&format2Push{changes: []*format2Change{
		versioned(&worldChange{path: directory, directory: true, version: 1, names: []sidecar.EvsToken{worldToken("w"), worldToken("x"), worldToken("y"), worldToken("z")}}),
		changed, listed, unlisted, kept,
	}})
	world.fold(1)
	rewritten := versionless(&worldChange{path: changed.path, base: 1, version: 2}, "w2")
	world.pushFormat2(&format2Push{changes: []*format2Change{rewritten}, purge: format2PurgeList(changed)})
	removal := world.pushFormat2(&format2Push{
		changes: []*format2Change{versioned(&worldChange{path: directory, base: 1}), format2Removal(listed)},
		purge:   format2PurgeList(listed),
	})
	before := world.head
	world.fold(removal)

	marker := func(path sidecar.EvsTokenPath) *protocol.EvsRemovalMarker {
		entry := world.entryOf(path).Entry
		if entry.GetMarker() == nil || entry.GetMarker().GetRemovalVersion() != removal {
			t.Fatalf("path %x: %v", path.Last().Bytes()[:2], entry)
		}
		return entry.GetMarker()
	}
	if markerCarriesIds(marker(directory)) || markerCarriesIds(marker(listed.path)) || markerCarriesIds(marker(kept.path)) {
		t.Fatal("a directory, a listed or a versioned file's marker carries ids")
	}
	if !carriesIdsOf(marker(unlisted.path), unlisted) {
		t.Fatalf("the unlisted file's marker carries %v", marker(unlisted.path))
	}
	if !carriesIdsOf(marker(changed.path), rewritten) {
		t.Fatalf("the unlisted file the range changed carries %v, not its newest version's ids", marker(changed.path))
	}
	if count := lines.count("fold_unlisted_versionless"); count != 2 {
		t.Fatalf("%d unlisted alarms:\n%s", count, lines)
	}
	for _, change := range []*format2Change{listed, unlisted, kept, changed} {
		world.requireNewest(change.path)
	}
	refold, err := world.folderLoggingTo(lines).Fold(world.ctx, &EvsFoldRequest{
		Cluster: world.foldCluster, RepoId: world.repoId, RefId: world.refId, Head: before, HeadReadAt: world.clock.Now(),
		Rank: sidecar.WriteP2RankFold,
	})
	if err != nil || refold.EntryWriteCount != 0 || lines.count("fold_unlisted_versionless") != 2 {
		t.Fatalf("a refold: %+v %v\n%s", refold, err, lines)
	}
}

// FS-67's ref DELETE: a ref's DELETE removes its paths and lists each versionless file below a removed directory as a
// file removal; one it leaves unlisted is marked by the removal's LIST and carries its ids, with one alarm, while the
// listed one and a listed top-level file carry nothing (a reading: a DELETE's effect on idx/ is its change list).
func TestFormat2RefDeleteCarriesAnUnlistedVersionlessFilesIds(t *testing.T) {
	world, lines := newFormat2World(t)
	directory := worldPath("d")
	listed := versionless(&worldChange{path: worldPath("d", "x"), version: 1}, "x")
	unlisted := versionless(&worldChange{path: worldPath("d", "y"), version: 1}, "y")
	top := versionless(&worldChange{path: worldPath("f"), version: 1}, "f")
	world.pushFormat2(&format2Push{changes: []*format2Change{
		versioned(&worldChange{path: directory, directory: true, version: 1, names: []sidecar.EvsToken{worldToken("x"), worldToken("y")}}),
		listed, unlisted, top,
	}})
	world.fold(1)
	deleted := world.pushFormat2(&format2Push{
		flags:   uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE),
		changes: []*format2Change{versioned(&worldChange{path: directory, base: 1}), format2Removal(listed), format2Removal(top)},
		purge:   format2PurgeList(listed, top),
	})
	if !world.head.Head.GetDeleted() {
		t.Fatal("the DELETE left no tombstone head")
	}
	world.fold(deleted)
	for _, change := range []*format2Change{listed, top} {
		if marker := world.entryOf(change.path).Entry.GetMarker(); marker == nil || markerCarriesIds(marker) {
			t.Fatalf("a listed file's marker %v", marker)
		}
	}
	if marker := world.entryOf(unlisted.path).Entry.GetMarker(); marker == nil || !carriesIdsOf(marker, unlisted) {
		t.Fatalf("the unlisted file's marker %v", marker)
	}
	if count := lines.count("fold_unlisted_versionless"); count != 1 {
		t.Fatalf("%d unlisted alarms:\n%s", count, lines)
	}
	for _, change := range []*format2Change{listed, unlisted, top} {
		world.requireNewest(change.path)
	}
}

// FS-67: a path the removing push writes below the directory it removes keeps its own content, its write coming
// before the prefix's removal at one version: the rewritten versionless file and a new one created there stand with
// their own versions and no marker, no ids are carried for them and nothing alarms for them, while an unlisted
// sibling's marker carries its ids.
func TestFormat2PathWrittenBelowTheRemovedDirectoryKeepsItsOwnContent(t *testing.T) {
	world, lines := newFormat2World(t)
	directory := worldPath("d")
	rewritten := versionless(&worldChange{path: worldPath("d", "x"), version: 1}, "x1")
	unlisted := versionless(&worldChange{path: worldPath("d", "y"), version: 1}, "y")
	world.pushFormat2(&format2Push{changes: []*format2Change{
		versioned(&worldChange{path: directory, directory: true, version: 1, names: []sidecar.EvsToken{worldToken("x"), worldToken("y")}}),
		rewritten, unlisted,
	}})
	world.fold(1)
	again := versionless(&worldChange{path: rewritten.path, base: 1, version: 2}, "x2")
	created := versionless(&worldChange{path: worldPath("d", "n"), version: 2}, "n")
	removal := world.pushFormat2(&format2Push{
		changes: []*format2Change{versioned(&worldChange{path: directory, base: 1}), again, created},
		purge:   format2PurgeList(rewritten),
	})
	world.fold(removal)
	for _, change := range []*format2Change{again, created} {
		entry := world.entryOf(change.path).Entry
		if entry.GetMarker() != nil || len(entry.GetVersions()) == 0 || foldedEntryVersion(t, entry.GetVersions()[0]).GetVersion() != change.version {
			t.Fatalf("a path written in the removing push: %v", entry)
		}
		if newest := world.requireNewest(change.path); !newest.Exists || newest.Version != change.version {
			t.Fatalf("a path written in the removing push reads %+v", newest)
		}
	}
	if marker := world.entryOf(unlisted.path).Entry.GetMarker(); marker == nil || !carriesIdsOf(marker, unlisted) {
		t.Fatalf("the unlisted sibling's marker %v", marker)
	}
	if count := lines.count("fold_unlisted_versionless"); count != 1 {
		t.Fatalf("%d unlisted alarms:\n%s", count, lines)
	}
}

// A drop of the lineage of path in epoch through through, of boundary written or removed.
func format2DropPath(path sidecar.EvsTokenPath, epoch uint64, through uint64, boundary uint32) *protocol.EvsDropPath {
	return &protocol.EvsDropPath{
		Lineage:        []*protocol.EvsSourcePath{{Epoch: epoch, TokenPath: path.Components()}},
		ThroughVersion: through,
		Boundary:       boundary,
	}
}

// count synthetic entry hashes a drop lists for label.
func format2Listed(label string, count int) [][]byte {
	listed := [][]byte{}
	for i := range count {
		listed = append(listed, format2Id(fmt.Sprintf("%s listed %d", label, i)))
	}
	return listed
}

// A DROP push writing path's next version, through it, its base the path's newest.
func format2DropPush(dropId sidecar.Id, path sidecar.EvsTokenPath, epoch uint64, base uint64) *format2Push {
	return &format2Push{
		flags:   uint32(protocol.EvsPushFlag_EVS_PUSH_DROP),
		changes: []*format2Change{versioned(&worldChange{path: path, base: base, version: base + 1})},
		drop: &protocol.EvsDropHistory{DropId: dropId.Bytes(), Action: 1, Paths: []*protocol.EvsDropPath{
			format2DropPath(path, epoch, base+1, evsDropBoundaryWritten),
		}},
		listed: [][][]byte{format2Listed(fmt.Sprint(dropId), int(base))},
	}
}

// Whether entry's drop mark is {dropId, through}.
func hasDropMark(entry *protocol.EvsIndexEntry, dropId sidecar.Id, through uint64) bool {
	mark := entry.GetDropMark()
	return mark != nil && bytes.Equal(mark.GetDropId(), dropId.Bytes()) && mark.GetThroughVersion() == through
}

// §11.7's fold row for a DROP: its written version replaces what the entry held, carrying nothing, and sets the drop
// mark {drop_id, through_version}; a new version, a removal and a re-creation keep the mark; a newer drop raises it.
func TestFormat2DropFoldLeavesOnlyThroughVersionAndTheMark(t *testing.T) {
	world, lines := newFormat2World(t)
	x := worldPath("x")
	for version := uint64(1); version <= 5; version += 1 {
		world.pushFormat2(&format2Push{changes: []*format2Change{versioned(&worldChange{path: x, base: version - 1, version: version})}})
	}
	world.fold(5)
	if count := len(world.entryOf(x).Entry.GetVersions()); count != 4 {
		t.Fatalf("x holds %d versions before the drop", count)
	}
	first, second := testId("drop-1"), testId("drop-2")
	dropped := world.pushFormat2(format2DropPush(first, x, 1, 5))
	world.fold(dropped)
	entry := world.entryOf(x).Entry
	if len(entry.GetVersions()) != 1 || foldedEntryVersion(t, entry.GetVersions()[0]).GetVersion() != 6 || !hasDropMark(entry, first, 6) {
		t.Fatalf("the DROP's fold left %v", entry)
	}
	world.requireNewest(x)

	world.fold(world.pushFormat2(&format2Push{changes: []*format2Change{versioned(&worldChange{path: x, base: 6, version: 7})}}))
	entry = world.entryOf(x).Entry
	if len(entry.GetVersions()) != 2 || entry.GetVersions()[0].GetCommitVersion() != 7 || !hasDropMark(entry, first, 6) {
		t.Fatalf("a new version after the drop left %v", entry)
	}
	world.fold(world.pushFormat2(&format2Push{changes: []*format2Change{versioned(&worldChange{path: x, base: 7})}}))
	entry = world.entryOf(x).Entry
	if entry.GetMarker() == nil || entry.GetMarker().GetPathVersion() != 8 || !hasDropMark(entry, first, 6) {
		t.Fatalf("a removal after the drop left %v", entry)
	}
	world.requireNewest(x)
	creation := ExpectedEntryVersion(0, world.head.Version(), 8)
	world.fold(world.pushFormat2(&format2Push{changes: []*format2Change{versioned(&worldChange{path: x, version: creation})}}))
	entry = world.entryOf(x).Entry
	if entry.GetMarker() != nil || len(entry.GetVersions()) != 1 || !hasDropMark(entry, first, 6) {
		t.Fatalf("a re-creation after the drop left %v", entry)
	}
	world.fold(world.pushFormat2(format2DropPush(second, x, 1, creation)))
	entry = world.entryOf(x).Entry
	if len(entry.GetVersions()) != 1 || !hasDropMark(entry, second, creation+1) {
		t.Fatalf("a newer drop left %v", entry)
	}
	world.requireNewest(x)
	if lines.count("fold_drop") != 0 || lines.count("fold_invalid") != 0 {
		t.Fatalf("an honest drop alarmed:\n%s", lines)
	}
}

// The skip rule never takes a DROP's written version: a fold whose range ends at the DROP while a later window
// version writes the path again still writes the DROP's version and its mark, which must stand before the DROP leaves
// the window; the later version's fold then keeps the mark.
func TestFormat2DropIsNeverSkippedForALaterWindowVersion(t *testing.T) {
	world, _ := newFormat2World(t)
	x := worldPath("x")
	world.pushFormat2(&format2Push{changes: []*format2Change{versioned(&worldChange{path: x, version: 1})}})
	dropId := testId("drop")
	dropped := world.pushFormat2(format2DropPush(dropId, x, 1, 1))
	world.pushFormat2(&format2Push{changes: []*format2Change{versioned(&worldChange{path: x, base: 2, version: 3})}})
	world.fold(dropped)
	entry := world.entryOf(x).Entry
	if len(entry.GetVersions()) != 1 || entry.GetVersions()[0].GetCommitVersion() != dropped || !hasDropMark(entry, dropId, 2) {
		t.Fatalf("the fold through the DROP left %v", entry)
	}
	world.fold(3)
	entry = world.entryOf(x).Entry
	if len(entry.GetVersions()) != 2 || entry.GetVersions()[0].GetCommitVersion() != 3 || !hasDropMark(entry, dropId, 2) {
		t.Fatalf("the later version's fold left %v", entry)
	}
	world.requireNewest(x)
}

// A removed-boundary lineage writes no version, so no fold touches its path, and a cancel writes nothing and lifts
// no mark (§11.7's boundary and fence rows): a DROP writing x through its next version and naming y's standing
// removal marks x alone, y's marker staying as it was; its cancel folds to no write.
func TestFormat2DropRemovedBoundaryAndCancelWriteNothing(t *testing.T) {
	world, lines := newFormat2World(t)
	x, y := worldPath("x"), worldPath("y")
	world.pushFormat2(&format2Push{changes: []*format2Change{versioned(&worldChange{path: x, version: 1}), versioned(&worldChange{path: y, version: 1})}})
	world.pushFormat2(&format2Push{changes: []*format2Change{versioned(&worldChange{path: y, base: 1})}})
	world.fold(2)
	removedBefore := world.entryOf(y)
	dropId := testId("drop")
	push := format2DropPush(dropId, x, 1, 1)
	push.drop.Paths = append(push.drop.Paths, format2DropPath(y, 1, 2, 2))
	push.listed = append(push.listed, format2Listed("y", 1))
	dropped := world.pushFormat2(push)
	world.fold(dropped)
	if entry := world.entryOf(x).Entry; !hasDropMark(entry, dropId, 2) {
		t.Fatalf("x after the drop: %v", entry)
	}
	if after := world.entryOf(y); after.Etag != removedBefore.Etag || after.Entry.GetDropMark() != nil {
		t.Fatalf("a removed boundary's path was written: %v", after.Entry)
	}
	cancel := world.pushFormat2(&format2Push{
		flags: uint32(protocol.EvsPushFlag_EVS_PUSH_DROP),
		drop:  &protocol.EvsDropHistory{DropId: testId("cancel").Bytes(), Action: 2, CancelsDropId: dropId.Bytes(), CancelsVersion: dropped},
	})
	result, err := world.folder.Fold(world.ctx, &EvsFoldRequest{Cluster: world.foldCluster, RepoId: world.repoId, RefId: world.refId, Through: cancel, Rank: sidecar.WriteP2RankFold})
	if err != nil || result.EntryWriteCount != 0 || result.Through != cancel {
		t.Fatalf("the cancel's fold: %+v %v", result, err)
	}
	if entry := world.entryOf(x).Entry; !hasDropMark(entry, dropId, 2) {
		t.Fatalf("the cancel lifted the mark: %v", entry)
	}
	world.raiseHorizon()
	world.requireNewest(x)
	world.requireNewest(y)
	if lines.count("fold_drop") != 0 {
		t.Fatalf("an honest drop alarmed:\n%s", lines)
	}
}
