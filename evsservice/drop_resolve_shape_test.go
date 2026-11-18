package evsservice

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A new-objects item for a segment a test push introduces.
func dropNewSegment(id [32]byte) *sidecar.EvsNewObject {
	return &sidecar.EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: id[:], PaddedSize: 4096, UploadDay: 1}
}

// One drop job over world's history under format2.drop: observe, its resolve the real one and its mark and verify
// stand-ins that mark nothing: appends covered's drops to the table as step 8 would, runs the job to observed and
// returns what its snap-0 records of the listed versions.
func (self *dropWorld) observedShape(covered ...*DropCovered) DropListedShape {
	self.t.Helper()
	events := &dropJobEvents{}
	snapshot := map[sidecar.Id]uint64{}
	for refId, ref := range self.refs {
		snapshot[refId] = ref.head.Version()
	}
	resolver, err := NewDropResolve(self.host.ServiceHost(), &DropResolveDeps{Settings: dropTestSettings(), EvsSettings: self.settings})
	if err != nil {
		self.t.Fatal(err)
	}
	horizon := &fakeDropHorizon{events: events}
	job, err := NewDropJob(self.host.ServiceHost(), &DropJobDeps{
		Resolver: resolver, Marker: &fakeDropMarker{events: events, snapshot: snapshot}, Verifier: &fakeDropVerifier{events: events},
		Locks: &fakeDropLocks{answer: EvsAuthAllowed}, Horizon: horizon, Format2: &fakeDropFormat2{mode: sidecar.Format2Observe},
		Settings: dropTestSettings(), EvsSettings: self.settings, Instance: testId("instance-shape"),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	for _, drop := range covered {
		commit := &DropCommit{
			ClusterId: "meta-1", RepoId: self.repoId, RefId: drop.RefId, PushId: drop.PushId, Version: drop.Version, Place: drop.Place,
			Body: &protocol.EvsDropHistory{DropId: drop.DropId.Bytes(), Action: 1, NotBeforeMs: self.clock.Now().UnixMilli()},
		}
		if err := job.Table().Append(self.paidCtx, commit, drop.SeenMs); err != nil {
			self.t.Fatal(err)
		}
	}
	// past the drops' start and their cite bound, the segment cluster's figures known and under the pause line
	self.clock.Advance(26 * time.Minute)
	horizon.horizon = self.clock.Now()
	if err := publishHddFigures(self.ctx, self.host.Redis, &HddFigures{
		ClusterId: "seg-1", TimeMs: self.clock.Now().UnixMilli(), DriveOpsPerSecond: 10, CapacityOps: 1000,
	}, 1000*time.Hour); err != nil {
		self.t.Fatal(err)
	}
	result, err := job.Run(self.ctx, "meta-1", self.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	if !result.Ended || result.Moved[DropStateObserved] != len(covered) {
		self.t.Fatalf("the job did not observe its %d drops: %+v", len(covered), result)
	}
	var jobIds []sidecar.Id
	prefix := dropscanKeyPrefix + sidecar.EvsKeyId(self.repoId) + "/"
	objects, _, err := self.segment.List(self.ctx, prefix, "", 1000)
	if err != nil {
		self.t.Fatal(err)
	}
	for _, object := range objects {
		jobId, err := parseEvsHexId(object.Key[len(prefix) : len(prefix)+32])
		if err != nil {
			self.t.Fatal(err)
		}
		if object.Key == DropFileKey(self.repoId, jobId, DropFileSnap, 0) {
			jobIds = append(jobIds, jobId)
		}
	}
	if len(jobIds) != 1 {
		self.t.Fatalf("%d jobs left a snap-0", len(jobIds))
	}
	snap, err := NewDropFiles(self.segment, self.repoId, jobIds[0], dropTestSettings()).Read(self.ctx, DropFileSnap, 0)
	if err != nil || snap == nil || len(snap.Covered) != len(covered) {
		self.t.Fatalf("snap-0 %+v: %v", snap, err)
	}
	return snap.Shape
}

// Owner decision 513 on a history with neither: a path written three times on its own segments, beside another ref
// nothing copies from, records no rename and no cross-ref copy.
func TestDropJobRecordsNeitherOnAPlainHistory(t *testing.T) {
	history := newDropResolveHistory(t)
	covered := history.dropX(testId("drop-x"), history.xVersions)
	if shape := history.world.observedShape(covered); shape != (DropListedShape{}) {
		t.Fatalf("a plain history recorded %+v", shape)
	}
}

// Owner decision 513's renames: a versionless a renamed to b by one push, which removes a and creates b citing a's
// kind-5 segment without introducing it. A drop that lists b's versions records the rename, and no cross-ref copy.
func TestDropJobRecordsARenameItsListedVersionsPushMade(t *testing.T) {
	world := newDropWorld(t)
	refA := testId("ref-a")
	a, b := worldPath("a"), worldPath("b")
	v5 := dropTestId("v5")
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{
		changes:    []*dropChange{{path: a, base: 0, spec: &dropEntry{version: 1, kind5: [][32]byte{v5}}}},
		newObjects: []*sidecar.EvsNewObject{dropNewSegment(v5)},
	})
	created := &dropChange{path: b, base: 0, spec: &dropEntry{version: 1, kind5: [][32]byte{v5}}}
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{changes: []*dropChange{{path: a, base: 1}, created}})
	covered := world.drop(refA, testId("drop-b"), []*protocol.EvsDropPath{dropPathOf(2, evsDropBoundaryWritten, nil, dropSource(1, b))}, [][][]byte{{created.entry}})
	if shape := world.observedShape(covered); shape != (DropListedShape{Renames: true}) {
		t.Fatalf("a rename recorded %+v", shape)
	}
}

// The renames row's limits: a push that removes one path and creates another on a kind-5 segment it introduces itself
// moved no content, a push that creates a path citing nothing it removes is no rename, and neither is a push that
// removes one path and writes a standing one again on the content its base holds.
func TestDropResolveReadsNoRenameWithoutCitedContentOrARemoval(t *testing.T) {
	world := newDropWorld(t)
	refA := testId("ref-a")
	a, b, c, d := worldPath("a"), worldPath("b"), worldPath("c"), worldPath("d")
	v5, w5, d5 := dropTestId("v5"), dropTestId("w5"), dropTestId("d5")
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{
		changes: []*dropChange{
			{path: a, base: 0, spec: &dropEntry{version: 1, kind5: [][32]byte{v5}}},
			{path: d, base: 0, spec: &dropEntry{version: 1, kind5: [][32]byte{d5}}},
		},
		newObjects: []*sidecar.EvsNewObject{dropNewSegment(v5), dropNewSegment(d5)},
	})
	// removes a and creates b on content of the push's own
	fresh := &dropChange{path: b, base: 0, spec: &dropEntry{version: 1, kind5: [][32]byte{w5}}}
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{
		changes:    []*dropChange{{path: a, base: 1}, fresh},
		newObjects: []*sidecar.EvsNewObject{dropNewSegment(w5)},
	})
	// creates c on a kind-5 segment it does not introduce, removing nothing
	alone := &dropChange{path: c, base: 0, spec: &dropEntry{version: 1, kind5: [][32]byte{w5}}}
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{changes: []*dropChange{alone}})
	// removes d and writes b again on the kind-5 segment b's version before it holds
	again := &dropChange{path: b, base: 1, spec: &dropEntry{version: 2, kind5: [][32]byte{w5}}}
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{changes: []*dropChange{{path: d, base: 1}, again}})
	covered := world.drop(refA, testId("drop-bc"), []*protocol.EvsDropPath{
		dropPathOf(3, evsDropBoundaryWritten, nil, dropSource(1, b)),
		dropPathOf(2, evsDropBoundaryWritten, nil, dropSource(1, c)),
	}, [][][]byte{{fresh.entry, again.entry}, {alone.entry}})
	result := world.resolve(covered)
	if len(result.Mismatch) != 0 || result.Shape != (DropListedShape{}) {
		t.Fatalf("mismatch %v, shape %+v", result.Mismatch, result.Shape)
	}
}

// Owner decision 513's cross-ref copies: x's second version names a segment ref B's y holds, which its push neither
// introduces nor has from x's first version, under a reuse item naming y on ref B. A drop that lists x's versions
// records the copy, and no rename.
func TestDropJobRecordsACopyFromAnotherRef(t *testing.T) {
	world := newDropWorld(t)
	refA, refB := testId("ref-a"), testId("ref-b")
	x, y := worldPath("x"), worldPath("y")
	s1, s9 := dropTestId("s1"), dropTestId("s9")
	world.commit(refB, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{
		changes:    []*dropChange{{path: y, base: 0, spec: &dropEntry{version: 1, segments: [][32]byte{s9}}}},
		newObjects: []*sidecar.EvsNewObject{dropNewSegment(s9)},
	})
	first := &dropChange{path: x, base: 0, spec: &dropEntry{version: 1, segments: [][32]byte{s1}}}
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{changes: []*dropChange{first}, newObjects: []*sidecar.EvsNewObject{dropNewSegment(s1)}})
	second := &dropChange{path: x, base: 1, spec: &dropEntry{version: 2, segments: [][32]byte{s1, s9}}}
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{
		changes: []*dropChange{second},
		reuse:   []*sidecar.EvsReuse{{RefId: refB, EntryVersion: 1, TokenPath: y}},
	})
	covered := world.drop(refA, testId("drop-x"), []*protocol.EvsDropPath{dropPathOf(3, evsDropBoundaryWritten, nil, dropSource(1, x))}, [][][]byte{{first.entry, second.entry}})
	if shape := world.observedShape(covered); shape != (DropListedShape{CrossRefCopies: true}) {
		t.Fatalf("a copy across refs recorded %+v", shape)
	}
}

// The cross-ref row's limits: a copy from another path of the same ref is no cross-ref copy, and a listed version
// that names only its own base's segments, or those and one its push uploads, is none either, though its push copies
// across refs for another path.
func TestDropResolveReadsNoCrossRefCopyFromItsOwnRefOrItsBase(t *testing.T) {
	world := newDropWorld(t)
	refA, refB := testId("ref-a"), testId("ref-b")
	x, y, z, w, u := worldPath("x"), worldPath("y"), worldPath("z"), worldPath("w"), worldPath("u")
	s1, s2, s7, s9 := dropTestId("s1"), dropTestId("s2"), dropTestId("s7"), dropTestId("s9")
	world.commit(refB, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{
		changes:    []*dropChange{{path: y, base: 0, spec: &dropEntry{version: 1, segments: [][32]byte{s9}}}},
		newObjects: []*sidecar.EvsNewObject{dropNewSegment(s9)},
	})
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{
		changes:    []*dropChange{{path: z, base: 0, spec: &dropEntry{version: 1, segments: [][32]byte{s7}}}},
		newObjects: []*sidecar.EvsNewObject{dropNewSegment(s7)},
	})
	first := &dropChange{path: x, base: 0, spec: &dropEntry{version: 1, segments: [][32]byte{s1}}}
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{changes: []*dropChange{first}, newObjects: []*sidecar.EvsNewObject{dropNewSegment(s1)}})
	// x takes z's segment, a path of its own ref
	second := &dropChange{path: x, base: 1, spec: &dropEntry{version: 2, segments: [][32]byte{s1, s7}}}
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{
		changes: []*dropChange{second},
		reuse:   []*sidecar.EvsReuse{{RefId: refA, EntryVersion: 1, TokenPath: z}},
	})
	// x keeps its base's segments while the same push copies ref B's y into w
	third := &dropChange{path: x, base: 2, spec: &dropEntry{version: 3, segments: [][32]byte{s1, s7}}}
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{
		changes: []*dropChange{third, {path: w, base: 0, spec: &dropEntry{version: 1, segments: [][32]byte{s9}}}},
		reuse:   []*sidecar.EvsReuse{{RefId: refB, EntryVersion: 1, TokenPath: y}},
	})
	// x adds a segment the push uploads while the same push copies ref B's y into u
	fourth := &dropChange{path: x, base: 3, spec: &dropEntry{version: 4, segments: [][32]byte{s1, s7, s2}}}
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{
		changes:    []*dropChange{fourth, {path: u, base: 0, spec: &dropEntry{version: 1, segments: [][32]byte{s9}}}},
		newObjects: []*sidecar.EvsNewObject{dropNewSegment(s2)},
		reuse:      []*sidecar.EvsReuse{{RefId: refB, EntryVersion: 1, TokenPath: y}},
	})
	covered := world.drop(refA, testId("drop-x"), []*protocol.EvsDropPath{dropPathOf(5, evsDropBoundaryWritten, nil, dropSource(1, x))},
		[][][]byte{{first.entry, second.entry, third.entry, fourth.entry}})
	result := world.resolve(covered)
	if len(result.Mismatch) != 0 || result.Shape != (DropListedShape{}) {
		t.Fatalf("mismatch %v, shape %+v", result.Mismatch, result.Shape)
	}
}

// Both on one repo: a drop of the renamed path and a drop of the copied one, on two refs, in one job, whose snap-0
// records both; resolve run again reads the same shape, so its snap-0 is the same bytes.
func TestDropJobRecordsBothAcrossItsDrops(t *testing.T) {
	world := newDropWorld(t)
	refA, refB := testId("ref-a"), testId("ref-b")
	a, b, x, y := worldPath("a"), worldPath("b"), worldPath("x"), worldPath("y")
	v5, s1, s9 := dropTestId("v5"), dropTestId("s1"), dropTestId("s9")
	world.commit(refB, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{
		changes: []*dropChange{
			{path: a, base: 0, spec: &dropEntry{version: 1, kind5: [][32]byte{v5}}},
			{path: y, base: 0, spec: &dropEntry{version: 1, segments: [][32]byte{s9}}},
		},
		newObjects: []*sidecar.EvsNewObject{dropNewSegment(v5), dropNewSegment(s9)},
	})
	created := &dropChange{path: b, base: 0, spec: &dropEntry{version: 1, kind5: [][32]byte{v5}}}
	world.commit(refB, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{changes: []*dropChange{{path: a, base: 1}, created}})
	copied := &dropChange{path: x, base: 0, spec: &dropEntry{version: 1, segments: [][32]byte{s1, s9}}}
	world.commit(refA, protocol.EvsRefMode_EVS_REF_FILE, &dropPush{
		changes:    []*dropChange{copied},
		newObjects: []*sidecar.EvsNewObject{dropNewSegment(s1)},
		reuse:      []*sidecar.EvsReuse{{RefId: refB, EntryVersion: 1, TokenPath: y}},
	})
	renamed := world.drop(refB, testId("drop-b"), []*protocol.EvsDropPath{dropPathOf(2, evsDropBoundaryWritten, nil, dropSource(1, b))}, [][][]byte{{created.entry}})
	copies := world.drop(refA, testId("drop-x"), []*protocol.EvsDropPath{dropPathOf(2, evsDropBoundaryWritten, nil, dropSource(1, x))}, [][][]byte{{copied.entry}})
	want := DropListedShape{Renames: true, CrossRefCopies: true}
	for range 2 {
		if result := world.resolve(renamed, copies); len(result.Mismatch) != 0 || result.Shape != want {
			t.Fatalf("mismatch %v, shape %+v", result.Mismatch, result.Shape)
		}
	}
	if shape := world.observedShape(renamed, copies); shape != want {
		t.Fatalf("the job recorded %+v", shape)
	}
}
