// EVS1-M2-17's tests: FS-4's copy half on T2. A committed PATH_EPOCH to epoch 2, a in its map and late in its tail,
// copies both into epoch 2, deletes their sources and drops them by a fence write; a current entry a fold wrote first
// is done as it stands; a missed entry keeps its source; a marker in a source is deleted unmoved; a child under a
// removed prefix becomes a marker; a kill at each boundary resumes; a newer epoch supersedes; a directory's rows are
// translated in their own epochs; and the rate holds the pace on the clock.

package evsservice

import (
	"bytes"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Commits a and late, then a PATH_EPOCH to epoch 2 whose map moves a and whose tail moves late, so epoch 1 is its
// source.
func (self *pushFixture) committedEpochTwo() {
	commitment := self.crossRemove(false)
	partBytes, mapSha256 := self.mapPart(pathEpochTestMove("a"))
	source := self.head()
	if recorder := self.postRoute("/path-epoch", &protocol.EvsPathMapRequest{PathMapSha256: mapSha256, Part: partBytes}); recorder.Code != http.StatusOK {
		self.t.Fatalf("map part answered %d", recorder.Code)
	}
	creation := self.planAtTwo(commitment)
	self.create(creation, "late")
	self.requireCommitted(self.push(creation), 3)
	covered := self.pathEpochPlan(commitment, mapSha256, source.Version(), source.Head.GetChain(), pathEpochTestMove("late"))
	self.requireCommitted(self.push(covered), 4)
	if sources := self.head().Head.GetPathEpoch().GetSources(); len(sources) != 1 || sources[0].GetEpoch() != 1 {
		self.t.Fatalf("sources %v", sources)
	}
}

// The copy's args for the fixture's ref into epoch.
func (self *pushFixture) copyArgs(epoch uint64) []byte {
	return EvsEpochCopyArgs(self.check.repoId, self.check.refId, epoch)
}

// The entry at a path in epoch, read raw.
func (self *pushFixture) entryAt(epoch uint64, labels ...string) *EvsEntryRead {
	read, err := ReadEntry(self.ctx, self.cluster, self.check.repoId, self.check.refId, epoch, checkTestPath(labels...), 0)
	if err != nil {
		self.t.Fatal(err)
	}
	return read
}

// Writes an entry by hand, as a fold would have, under state.
func (self *pushFixture) plantEntry(epoch uint64, entry *protocol.EvsIndexEntry, state EvsEntryStateValue, labels ...string) {
	if _, err := PutEntry(self.ctx, self.cluster, self.check.repoId, self.check.refId, epoch, checkTestPath(labels...), nil, entry, state); err != nil {
		self.t.Fatal(err)
	}
}

// The keys under an epoch's prefix.
func (self *pushFixture) epochKeys(epoch uint64) []string {
	keys := []string{}
	prefix := IndexEpochPrefix(self.check.repoId, self.check.refId, epoch)
	for key := range self.host.Blobs.Dump() {
		_, objectKey, _ := strings.Cut(key, "/")
		if strings.HasPrefix(objectKey, prefix) {
			keys = append(keys, objectKey)
		}
	}
	slices.Sort(keys)
	return keys
}

// FS-4's copy half: the map's and the tail's paths move into epoch 2, carried from epoch 1 with their versions; every
// source copy goes once its new copy stands; the LIST finds epoch 1 empty and one fence write drops the source.
func TestEpochCopyMovesTheMapAndTailAndDropsTheSource(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.committedEpochTwo()
	before := fixture.entryAt(1, "a")
	if before.Absent() || len(fixture.epochKeys(1)) != 2 {
		t.Fatalf("epoch 1 holds %q", fixture.epochKeys(1))
	}
	// step 8 of the PATH_EPOCH queued this copy
	fixture.awaitStepEights()
	queued := false
	for _, request := range fixture.host.Tasks.Pending() {
		queued = queued || (request.Name == EvsEpochCopyTaskName && bytes.Equal(request.Args, fixture.copyArgs(2)))
	}
	if !queued {
		t.Fatalf("no copy queued: %v", fixture.host.Tasks.Pending())
	}
	fence := fixture.head().Head.GetFence()
	result, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), nil, fixture.copyArgs(2))
	if err != nil {
		t.Fatal(err)
	}
	if result.MovedCount != 2 || result.DeletedCount != 2 || result.MovesLeft != 0 || !result.SourcesDropped || result.MissedCount != 0 {
		t.Fatalf("result %+v", result)
	}
	moved := fixture.entryAt(2, "epoch 2", "a")
	if moved.Absent() || moved.State.State != EvsEntryStateCarried || moved.State.Epoch != 1 || !proto.Equal(moved.Entry, before.Entry) {
		t.Fatalf("epoch 2's a %+v", moved)
	}
	if late := fixture.entryAt(2, "epoch 2", "late"); late.Absent() {
		t.Fatal("the tail's late did not move")
	}
	if keys := fixture.epochKeys(1); len(keys) != 0 {
		t.Fatalf("epoch 1 keeps %q", keys)
	}
	head := fixture.head().Head
	if len(head.GetPathEpoch().GetSources()) != 0 || head.GetPathEpoch().GetCurrent() != 2 || head.GetFence() != fence+1 || head.GetVersion() != 4 {
		t.Fatalf("head %v", head)
	}
	// a rerun finds nothing to do
	again, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), nil, fixture.copyArgs(2))
	if err != nil || again.MovedCount != 0 || again.DeletedCount != 0 {
		t.Fatalf("a rerun: %+v %v", again, err)
	}
}

// 412's rule: a current entry a fold wrote first, fresh, is done as it stands, its source deleted unmoved; and a source
// marker no move names is deleted at the end.
func TestEpochCopyLeavesACurrentEntryAndDeletesSourceMarkers(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.committedEpochTwo()
	fresh := proto.Clone(fixture.entryAt(1, "late").Entry).(*protocol.EvsIndexEntry)
	fixture.plantEntry(2, fresh, EvsEntryStateValue{State: EvsEntryStateFresh}, "epoch 2", "late")
	marker := &protocol.EvsIndexEntry{Marker: &protocol.EvsRemovalMarker{PushId: testId("old removal").Bytes(), RemovalVersion: 1, PathVersion: 2}}
	fixture.plantEntry(1, marker, EvsEntryStateValue{}, "gone")
	result, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), nil, fixture.copyArgs(2))
	if err != nil {
		t.Fatal(err)
	}
	if result.MovedCount != 1 || result.DoneCount != 1 || !result.SourcesDropped {
		t.Fatalf("result %+v", result)
	}
	if late := fixture.entryAt(2, "epoch 2", "late"); late.State.State != EvsEntryStateFresh {
		t.Fatalf("the fresh entry was written over: %+v", late.State)
	}
	if keys := fixture.epochKeys(1); len(keys) != 0 {
		t.Fatalf("epoch 1 keeps %q", keys)
	}
}

// FS-4: a fold landing between the copy's GET and its If-None-Match PUT: the PUT gets 412, the copy reads the entry
// the fold wrote, and that fresh entry stands, the source deleted unmoved; no row is lost or written twice.
func TestEpochCopyRereadsAfterAFoldBetweenItsGetAndPut(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.committedEpochTwo()
	folded := proto.Clone(fixture.entryAt(1, "a").Entry).(*protocol.EvsIndexEntry)
	target := IndexEntryKey(fixture.check.repoId, fixture.check.refId, 2, checkTestPath("epoch 2", "a"))
	landed := false
	deps := &EvsEpochCopyDeps{beforeWrite: func(key string) {
		if key == target && !landed {
			landed = true
			fixture.plantEntry(2, folded, EvsEntryStateValue{State: EvsEntryStateFresh}, "epoch 2", "a")
		}
	}}
	result, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), deps, fixture.copyArgs(2))
	if err != nil {
		t.Fatal(err)
	}
	if !landed || result.DoneCount != 1 || result.MovedCount != 1 || !result.SourcesDropped {
		t.Fatalf("landed %t, result %+v", landed, result)
	}
	if moved := fixture.entryAt(2, "epoch 2", "a"); moved.State.State != EvsEntryStateFresh || !proto.Equal(moved.Entry, folded) {
		t.Fatalf("the fold's entry %+v", moved.State)
	}
}

// The end row: an entry no move names is missed, alarmed and kept, and the source stays listed.
func TestEpochCopyKeepsASourceTheMapMissed(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.committedEpochTwo()
	orphan := proto.Clone(fixture.entryAt(1, "a").Entry).(*protocol.EvsIndexEntry)
	fixture.plantEntry(1, orphan, EvsEntryStateValue{}, "orphan")
	result, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), nil, fixture.copyArgs(2))
	if err != nil {
		t.Fatal(err)
	}
	if result.MissedCount != 1 || result.SourcesDropped {
		t.Fatalf("result %+v", result)
	}
	if fixture.entryAt(1, "orphan").Absent() || len(fixture.head().Head.GetPathEpoch().GetSources()) != 1 {
		t.Fatal("a missed entry's source went")
	}
}

// The prefixes row: a path moved under a removed prefix in the current epoch becomes a marker of that removal.
func TestEpochCopyMarksAPathUnderARemovedPrefix(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.committedEpochTwo()
	removed := &protocol.EvsIndexEntry{Marker: &protocol.EvsRemovalMarker{PushId: testId("removal").Bytes(), RemovalVersion: 40, PathVersion: 41}}
	fixture.plantEntry(2, removed, EvsEntryStateValue{State: EvsEntryStateRemoved}, "epoch 2")
	result, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), nil, fixture.copyArgs(2))
	if err != nil {
		t.Fatal(err)
	}
	if result.MarkedCount != 2 {
		t.Fatalf("result %+v", result)
	}
	moved := fixture.entryAt(2, "epoch 2", "a")
	if moved.State.State != EvsEntryStateRemoved || moved.Entry.GetMarker().GetRemovalVersion() != 40 || len(moved.Entry.GetVersions()) == 0 {
		t.Fatalf("a under the removed prefix %+v %v", moved.State, moved.Entry)
	}
}

// FS-4: a kill at each copy boundary, a write failing before it applies or applying with its answer lost: the rerun
// ends where an unbroken run does.
func TestEpochCopyResumesAfterAKillAtEachBoundary(t *testing.T) {
	plans := []*sidecartest.FaultPlan{
		{Op: sidecartest.FaultOpPut, KeyPrefix: "idx/", Nth: 1, Result: sidecartest.FailBeforeApply},
		{Op: sidecartest.FaultOpPut, KeyPrefix: "idx/", Nth: 2, Result: sidecartest.ApplyThenDrop},
		{Op: sidecartest.FaultOpDelete, KeyPrefix: "idx/", Nth: 1, Result: sidecartest.FailBeforeApply},
		{Op: sidecartest.FaultOpDelete, KeyPrefix: "idx/", Nth: 2, Result: sidecartest.ApplyThenDrop},
		{Op: sidecartest.FaultOpPut, KeyPrefix: "head/", Nth: 1, Result: sidecartest.ApplyThenDrop},
		{Op: sidecartest.FaultOpGet, KeyPrefix: "pmap/", Nth: 1, Result: sidecartest.FailBeforeApply},
	}
	for i, plan := range plans {
		fixture := newPushFixture(t, nil)
		fixture.committedEpochTwo()
		if _, err := fixture.host.Blobs.Faults().Add(plan); err != nil {
			t.Fatal(err)
		}
		dropped := false
		for range 4 {
			result, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), nil, fixture.copyArgs(2))
			if err == nil && result.SourcesDropped || len(fixture.head().Head.GetPathEpoch().GetSources()) == 0 {
				dropped = true
				break
			}
		}
		if !dropped || len(fixture.epochKeys(1)) != 0 || fixture.entryAt(2, "epoch 2", "a").Absent() || fixture.entryAt(2, "epoch 2", "late").Absent() {
			t.Errorf("plan %d: dropped %t, epoch 1 %q", i, dropped, fixture.epochKeys(1))
		}
		if unfired := fixture.host.Blobs.Faults().Unfired(); len(unfired) != 0 {
			t.Errorf("plan %d never fired: %v", i, unfired)
		}
	}
}

// A head whose current epoch passed the job's is a newer map's: the job ends, moving and deleting nothing.
func TestEpochCopyStopsWhenANewerEpochSupersedesIt(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.committedEpochTwo()
	head := fixture.head()
	next := CloneEvsHead(head.Head)
	next.Fence = head.Head.GetFence() + 1
	next.PathEpoch = CloneEvsPathEpoch(head.Head.GetPathEpoch())
	next.PathEpoch.Current = 3
	next.PathEpoch.Sources = append([]*protocol.EvsEpochSource{{Epoch: 2, MapSha256: bytes.Repeat([]byte{3}, 32)}}, next.PathEpoch.Sources...)
	ctx := fixture.host.Budget.IssueP0(fixture.ctx, "meta-1", sidecar.WriteP0KindLifecycle, 1)
	if _, err := fixture.engine.heads.Commit(ctx, fixture.cluster, fixture.check.repoId, fixture.check.refId, head, next); err != nil {
		t.Fatal(err)
	}
	keys := fixture.epochKeys(1)
	result, err := RunPathEpochCopy(fixture.ctx, fixture.host.ServiceHost(), nil, fixture.copyArgs(2))
	if err != nil || !result.Superseded || result.MovedCount != 0 || result.DeletedCount != 0 {
		t.Fatalf("result %+v %v", result, err)
	}
	if !slices.Equal(fixture.epochKeys(1), keys) {
		t.Error("a superseded copy deleted")
	}
}

// The moves row's directories: a source table's untagged rows, in the source's epoch, and a row carried from an older
// source, in its own, each become their child's move's row, untagged, under its re-sealed name; a row no move names
// stays carried and is counted missed.
func TestEpochCopyTranslatesADirectorysRowsInTheirOwnEpochs(t *testing.T) {
	token := func(label string) sidecar.EvsToken {
		return checkTestPath(label).Last()
	}
	directory := &copyMove{
		newPath:     checkTestPath("p3", "d"),
		sourcePaths: map[uint64]sidecar.EvsTokenPath{2: checkTestPath("p2", "d"), 1: checkTestPath("p1", "d")},
	}
	childX := &copyMove{newPath: checkTestPath("p3", "d", "x"), sealedName: []byte("x sealed for p3")}
	childY := &copyMove{newPath: checkTestPath("p3", "d", "y"), sealedName: []byte("y sealed for p3")}
	run := &copyRun{
		result: &EvsEpochCopyResult{},
		epochMoves: map[uint64]map[string]*copyMove{
			2: {append(checkTestPath("p2", "d"), token("x")).KeyString(): childX},
			1: {append(checkTestPath("p1", "d"), token("y")).KeyString(): childY},
		},
	}
	entry := &protocol.EvsIndexEntry{Names: &protocol.EvsNameTable{Names: []*protocol.EvsName{
		{Token: token("x").Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: []byte("x sealed for p2")},
		{Token: token("y").Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: []byte("y sealed for p1"), Epoch: 1},
		{Token: token("z").Bytes(), Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: []byte("z sealed for p2")},
	}}, NamesThrough: 3}
	translated := run.translated(directory, entry, 2, carryEvsIndexEntry)
	rows := map[string]*protocol.EvsName{}
	for _, row := range translated.GetNames().GetNames() {
		rows[string(row.GetSealedName())] = row
	}
	if row := rows["x sealed for p3"]; row == nil || row.GetEpoch() != 0 || !bytes.Equal(row.GetToken(), childX.newPath.Last().Bytes()) {
		t.Errorf("x %v", row)
	}
	if row := rows["y sealed for p3"]; row == nil || row.GetEpoch() != 0 || !bytes.Equal(row.GetToken(), childY.newPath.Last().Bytes()) {
		t.Errorf("y %v", row)
	}
	if row := rows["z sealed for p2"]; row == nil || row.GetEpoch() != 2 {
		t.Errorf("z %v", row)
	}
	if run.result.MissedCount != 1 || entry.GetNames().GetNames()[0].GetEpoch() != 0 {
		t.Errorf("missed %d, the source entry changed %v", run.result.MissedCount, entry.GetNames().GetNames()[0])
	}
}

// §11.6's rate: past the operations a second the cluster's share allows, the copy waits for the next second on the
// clock; the repo's own rate bounds it too, faster while two sources stand.
func TestEpochCopyHoldsItsPace(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(t.Context(), clock, nil, nil, nil)
	host.Budget.SetCopyOpsPerSecond("meta-1", 3)
	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	run := &copyRun{ctx: t.Context(), host: host.ServiceHost(), settings: DefaultEvsSettings(), clock: clock, cluster: cluster, sourceEpochs: []uint64{1}}
	for range 3 {
		if err := run.pace(); err != nil {
			t.Fatal(err)
		}
	}
	paced := make(chan error, 1)
	go func() { paced <- run.pace() }()
	if err := clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-paced:
		t.Fatal("a fourth operation in the second went at once")
	default:
	}
	clock.Advance(time.Second)
	if err := <-paced; err != nil {
		t.Fatal(err)
	}
	// the repo's own rate bounds a larger share: 50 with one source, 150 with two
	host.Budget.SetCopyOpsPerSecond("meta-1", 1000)
	clock.Advance(time.Second)
	count := 0
	for ; count < 200; count += 1 {
		if run.windowCount == run.settings.CopyRepoOpsPerSecond {
			break
		}
		if err := run.pace(); err != nil {
			t.Fatal(err)
		}
	}
	if count != run.settings.CopyRepoOpsPerSecond {
		t.Errorf("%d operations before the repo's rate held", count)
	}
}
