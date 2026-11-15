package evsservice

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Writes the job's cand file of candidates.
func (self *dropWorld) writeCandidates(jobId sidecar.Id, candidates ...DropScanId) {
	self.t.Helper()
	encoded, err := EncodeDropIdFile(DropFileCand, self.repoId, jobId, 0, candidates)
	if err != nil {
		self.t.Fatal(err)
	}
	if err := self.files(jobId).Put(self.ctx, DropFileCand, 0, encoded); err != nil {
		self.t.Fatal(err)
	}
}

// Writes a list file under jobId listing entries under dropId, as resolve leaves one.
func (self *dropWorld) writeList(jobId sidecar.Id, dropId sidecar.Id, entries ...[]byte) {
	self.t.Helper()
	rows := []DropListRow{}
	for _, entryBytes := range entries {
		rows = append(rows, DropListRow{EntrySha256: sha256.Sum256(entryBytes)})
	}
	slices.SortFunc(rows, compareDropListRows)
	encoded := EncodeDropListFile(self.repoId, jobId, 0, []*DropListDrop{{DropId: dropId, RefId: testId("ref-a"), Version: 1, PushId: testId("listing push")}}, rows)
	if err := self.files(jobId).Put(self.ctx, DropFileList, 0, encoded); err != nil {
		self.t.Fatal(err)
	}
}

// A mark on the world.
func (self *dropWorld) marker(settings *DropSettings) *DropMark {
	self.t.Helper()
	if settings == nil {
		settings = dropTestSettings()
	}
	marker, err := NewDropMark(self.host.ServiceHost(), &DropMarkDeps{Settings: settings, EvsSettings: self.settings})
	if err != nil {
		self.t.Fatal(err)
	}
	return marker
}

// The job's marks, every mark file's ids.
func (self *dropWorld) marks(jobId sidecar.Id) []DropScanId {
	self.t.Helper()
	marks, _, _, err := self.files(jobId).Marks(self.ctx)
	if err != nil {
		self.t.Fatal(err)
	}
	scanIds := []DropScanId{}
	for scanId := range marks {
		scanIds = append(scanIds, scanId)
	}
	return sortedDropScanIds(scanIds...)
}

// The liveness of a table holding dropId in state.
func dropLivenessOf(dropId sidecar.Id, state DropState) *DropLiveness {
	return dropLiveness(&DropTableState{Drops: []*DropTableEntry{{DropId: dropId, State: state}}}, nil)
}

// The history the mark tests share: on file ref A, x's listed version naming s5 alone, y naming s1 by a kind-1 locator,
// z's versionless version naming s2 by a kind-5 one and w naming slot k1; on git ref G, a push whose new objects carry
// s3, a history segment no entry version names. s4 is a candidate nothing names.
type dropMarkHistory struct {
	world              *dropWorld
	refA, refG         sidecar.Id
	listedX            []byte
	s1, s2, s3, s4, s5 [32]byte
	k1                 sidecar.Id
	doneDrop           sidecar.Id
}

func newDropMarkHistory(t *testing.T) *dropMarkHistory {
	world := newDropWorld(t)
	history := &dropMarkHistory{
		world: world, refA: testId("ref-a"), refG: testId("ref-g"), doneDrop: testId("done-drop"),
		s1: dropTestId("s1"), s2: dropTestId("s2"), s3: dropTestId("s3"), s4: dropTestId("s4"), s5: dropTestId("s5"), k1: testId("slot-k1"),
	}
	history.listedX, _ = world.write(history.refA, worldPath("x"), 0, &dropEntry{segments: [][32]byte{history.s5}})
	world.write(history.refA, worldPath("y"), 0, &dropEntry{segments: [][32]byte{history.s1}})
	world.write(history.refA, worldPath("z"), 0, &dropEntry{kind5: [][32]byte{history.s2}})
	world.write(history.refA, worldPath("w"), 0, &dropEntry{slots: []sidecar.Id{history.k1}, inline: true})
	world.commit(history.refG, protocol.EvsRefMode_EVS_REF_GIT, &dropPush{
		changes:    []*dropChange{{path: worldPath("g"), spec: &dropEntry{version: 1, inline: true}}},
		newObjects: []*sidecar.EvsNewObject{{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: history.s3[:], PaddedSize: 4096, UploadDay: 1}},
	})
	world.writeCandidates(world.jobId, DropSegmentId(history.s1), DropSegmentId(history.s2), DropSegmentId(history.s3), DropSegmentId(history.s4),
		DropSegmentId(history.s5), DropSlotId(history.k1))
	world.writeList(testId("done-job"), history.doneDrop, history.listedX)
	return history
}

// A round 1 mark of the world's job under liveness.
func (self *dropWorld) mark(marker *DropMark, since map[sidecar.Id]uint64, liveness *DropLiveness, listed map[[32]byte]bool, renew func(ctx context.Context) error) (*DropMarkResult, error) {
	if since == nil {
		since = map[sidecar.Id]uint64{}
	}
	return marker.Mark(self.ctx, &DropMarkRequest{
		Cluster: self.cluster, SegmentCluster: self.segment, RepoId: self.repoId, JobId: self.jobId, Round: 1,
		Horizon: self.clock.Now(), Since: since, Liveness: liveness, Listed: listed, Renew: renew,
	})
}

// DESIGN-DETAILS 10.6's drop_mark_test.go row: Names over kind-1, kind-5 and slot ids and a git-mode push's new-objects
// list (G11), and a version a done drop lists marking nothing; M_r is each ref's head.
func TestDropMarkMarksWhatLiveVersionsName(t *testing.T) {
	history := newDropMarkHistory(t)
	world := history.world
	result, err := world.mark(world.marker(nil), nil, dropLivenessOf(history.doneDrop, DropStateDone), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := sortedDropScanIds(DropSegmentId(history.s1), DropSegmentId(history.s2), DropSegmentId(history.s3), DropSlotId(history.k1))
	if got := world.marks(world.jobId); !slices.Equal(got, want) {
		t.Fatalf("marks %x, want %x", got, want)
	}
	if result.Snapshot[history.refA] != 4 || result.Snapshot[history.refG] != 1 || len(result.Snapshot) != 2 {
		t.Fatalf("snapshot %v", result.Snapshot)
	}
	if result.ScanByteCount == 0 {
		t.Fatal("mark counted no bytes read")
	}
}

// The live row: a pending, cancelled, refused or observed drop's versions are live, so a version it lists marks.
func TestDropMarkTakesAnUnexecutedDropsVersionsAsLive(t *testing.T) {
	for _, state := range []DropState{DropStatePending, DropStateCancelled, DropStateRefusedVerify, DropStateObserved} {
		history := newDropMarkHistory(t)
		world := history.world
		if _, err := world.mark(world.marker(nil), nil, dropLivenessOf(history.doneDrop, state), nil, nil); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(world.marks(world.jobId), DropSegmentId(history.s5)) {
			t.Fatalf("a version a drop in state %d lists marked nothing", state)
		}
	}
	// gone from the table with no void record: executed, so its version marks nothing
	history := newDropMarkHistory(t)
	world := history.world
	if _, err := world.mark(world.marker(nil), nil, dropLiveness(&DropTableState{}, nil), nil, nil); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(world.marks(world.jobId), DropSegmentId(history.s5)) {
		t.Fatal("a version an executed drop whose entry left lists marked its candidate")
	}
}

// A dry run's mark takes the versions its paths would list as naming nothing.
func TestDropMarkForADryRunTakesItsListedVersionsAsNamingNothing(t *testing.T) {
	history := newDropMarkHistory(t)
	world := history.world
	listed := map[[32]byte]bool{sha256.Sum256(history.listedX): true}
	if _, err := world.mark(world.marker(nil), nil, dropLiveness(&DropTableState{Drops: []*DropTableEntry{{DropId: history.doneDrop, State: DropStatePending}}}, nil), listed, nil); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(world.marks(world.jobId), DropSegmentId(history.s5)) {
		t.Fatal("a dry run's listed version marked its candidate")
	}
}

// A later round reads only versions after M_{r-1}, and a ref created since from version 1.
func TestDropMarkReadsARefCreatedSinceFromItsFirstVersion(t *testing.T) {
	history := newDropMarkHistory(t)
	world := history.world
	refB := testId("ref-b")
	world.write(refB, worldPath("b"), 0, &dropEntry{segments: [][32]byte{history.s4}})
	since := map[sidecar.Id]uint64{history.refA: 4, history.refG: 1}
	result, err := world.mark(world.marker(nil), since, dropLivenessOf(history.doneDrop, DropStateDone), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := world.marks(world.jobId); !slices.Equal(got, []DropScanId{DropSegmentId(history.s4)}) {
		t.Fatalf("marks %x: only ref B's version reads", got)
	}
	if result.Snapshot[refB] != 1 || result.Snapshot[history.refA] != 4 {
		t.Fatalf("snapshot %v", result.Snapshot)
	}
}

// A held head key is the store's 503: mark stops for its phase to wait, and skips no ref.
func TestDropMarkWaitsOutAHeldHead(t *testing.T) {
	history := newDropMarkHistory(t)
	world := history.world
	if _, err := world.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpGet, KeyPrefix: HeadKey(world.repoId, history.refG), ClusterId: "meta-1", Result: sidecartest.Held,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := world.mark(world.marker(nil), nil, dropLivenessOf(history.doneDrop, DropStateDone), nil, nil); !errors.Is(err, sidecar.ErrBlobHeld) {
		t.Fatalf("a held head: %v", err)
	}
}

// Marks only grow (DESIGN-DETAILS 10.5): a mark killed after a checkpoint keeps what it wrote, and the round run again
// marks the rest with every earlier mark standing.
func TestDropMarkKeepsItsMarksAcrossAKill(t *testing.T) {
	history := newDropMarkHistory(t)
	world := history.world
	calls := 0
	kill := errors.New("killed")
	renew := func(ctx context.Context) error {
		calls += 1
		world.clock.Advance(time.Minute)
		if calls == 3 {
			return kill
		}
		return nil
	}
	liveness := dropLivenessOf(history.doneDrop, DropStateDone)
	if _, err := world.mark(world.marker(nil), nil, liveness, nil, renew); !errors.Is(err, kill) {
		t.Fatalf("the killed mark: %v", err)
	}
	first := world.marks(world.jobId)
	if !slices.Contains(first, DropSegmentId(history.s1)) {
		t.Fatalf("the checkpoint before the kill kept %x", first)
	}
	if _, err := world.mark(world.marker(nil), nil, liveness, nil, nil); err != nil {
		t.Fatal(err)
	}
	second := world.marks(world.jobId)
	for _, scanId := range first {
		if !slices.Contains(second, scanId) {
			t.Fatal("a mark shrank across a kill")
		}
	}
	if len(second) != 4 {
		t.Fatalf("marks after the rerun %x", second)
	}
}

// Names counts each locator kind as its row says: kind-1 and kind-5 segment ids and slot ids of entry versions not
// listed, none of an inline record or a removal, and a git-mode push's new-objects segments, never a file-mode one's.
func TestDropNamesCountsWhatEachKindNames(t *testing.T) {
	world := newDropWorld(t)
	refA, refG := testId("ref-a"), testId("ref-g")
	s1, s2, s3, s4 := dropTestId("s1"), dropTestId("s2"), dropTestId("s3"), dropTestId("s4")
	k1 := testId("slot-k1")
	listedEntry, _ := world.write(refA, worldPath("listed"), 0, &dropEntry{segments: [][32]byte{s4}})
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{
		changes: []*dropChange{
			{path: worldPath("a"), spec: &dropEntry{version: 1, segments: [][32]byte{s1}, slots: []sidecar.Id{k1}}},
			{path: worldPath("b"), spec: &dropEntry{version: 1, kind5: [][32]byte{s2}}},
			{path: worldPath("listed"), base: 1},
		},
		newObjects: []*sidecar.EvsNewObject{{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: s1[:], PaddedSize: 4096, UploadDay: 1}},
	})
	world.commit(refG, protocol.EvsRefMode_EVS_REF_GIT, &dropPush{
		changes:    []*dropChange{{path: worldPath("g"), spec: &dropEntry{version: 1, inline: true}}},
		newObjects: []*sidecar.EvsNewObject{{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: s3[:], PaddedSize: 4096, UploadDay: 1}},
	})
	payloadAt := func(refId sidecar.Id, version uint64) *sidecar.EvsCheckedPayload {
		ref := world.refs[refId]
		reader, err := newDropRefReader(world.ctx, world.cluster, world.repoId, refId, ref.head.Head, NewRecordCache(world.settings), NewRecordLocator(world.host.Blobs, nil), NewLogPageCache(world.settings), nil)
		if err != nil {
			t.Fatal(err)
		}
		entry, _, err := reader.entryAt(version)
		if err != nil {
			t.Fatal(err)
		}
		_, payload, err := reader.pushAt(version, entry)
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	names, err := DropNames(payloadAt(refA, 2), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sortedDropScanIds(names...), sortedDropScanIds(DropSegmentId(s1), DropSlotId(k1), DropSegmentId(s2)); !slices.Equal(got, want) {
		t.Fatalf("file mode names %x, want %x", got, want)
	}
	names, err = DropNames(payloadAt(refG, 1), true, nil)
	if err != nil || !slices.Equal(names, []DropScanId{DropSegmentId(s3)}) {
		t.Fatalf("git mode names %x (%v)", names, err)
	}
	names, err = DropNames(payloadAt(refA, 1), false, map[[32]byte]bool{sha256.Sum256(listedEntry): true})
	if err != nil || len(names) != 0 {
		t.Fatalf("a listed version names %x (%v)", names, err)
	}
}
