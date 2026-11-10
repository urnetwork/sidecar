package evsservice

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A directory d with children a and b, then d removed at version 2 and 64 more versions on another file, folded
// through: the fold has passed the removal by a base range, and d, d/a and d/b hold its markers.
func newCollectWorld(t *testing.T) (*evsWorld, []sidecar.EvsTokenPath, sidecar.EvsTokenPath) {
	world := newEvsWorld(t)
	directory, a, b, other := worldPath("d"), worldPath("d", "a"), worldPath("d", "b"), worldPath("other")
	world.push(sortedChanges(
		&worldChange{path: directory, directory: true, version: 1, names: []sidecar.EvsToken{worldToken("a"), worldToken("b")}},
		&worldChange{path: a, version: 1}, &worldChange{path: b, version: 1}, &worldChange{path: other, version: 1},
	)...)
	world.push(&worldChange{path: directory, base: 1})
	for version := uint64(2); version <= 65; version += 1 {
		world.push(&worldChange{path: other, base: version - 1, version: version})
	}
	world.fold(world.head.Version())
	marked := []sidecar.EvsTokenPath{directory, a, b}
	for _, path := range marked {
		if marker := world.entryOf(path).Entry.GetMarker(); marker == nil || marker.GetRemovalVersion() != 2 {
			t.Fatalf("path %x's marker %v", path.Bytes()[:2], marker)
		}
	}
	return world, marked, other
}

// A collector over the world's host, its wait moving the fake clock, and the barriers it reached.
func collectorOf(t *testing.T, world *evsWorld, onStep func(name string)) (*MarkerCollector, *[]string) {
	steps := []string{}
	collector, err := NewMarkerCollector(world.host.ServiceHost(), &MarkerCollectorDeps{
		EvsSettings: world.settings,
		atStep: func(name string, key string) error {
			steps = append(steps, name)
			if onStep != nil {
				onStep(name)
			}
			return nil
		},
		wait: func(wait time.Duration) { world.clock.Advance(wait) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return collector, &steps
}

func (self *evsWorld) collect(collector *MarkerCollector) *MarkerCollectResult {
	self.t.Helper()
	result, err := collector.Collect(self.ctx, "meta-1", self.repoId, self.refId)
	if err != nil {
		self.t.Fatalf("collect: %v (%+v)", err, result)
	}
	return result
}

// §11.7's collect row: a window opens by a fence-only CAS, waits out every fold planned on an older head, deletes
// each marker of a removal at or below through, a removed directory's by a LIST, and closes with done at through;
// what the removal did not mark stays.
func TestMarkerCollectionDeletesAFoldedRemovalsMarkersInAWindow(t *testing.T) {
	world, marked, other := newCollectWorld(t)
	before, err := world.heads.ReadCluster(world.ctx, world.cluster, world.repoId, world.refId)
	if err != nil {
		t.Fatal(err)
	}
	collector, steps := collectorOf(t, world, nil)
	result := world.collect(collector)
	if !result.Opened || !result.Closed || result.Done != 2 || result.MarkerDeletedCount != 3 || result.MarkerLeftCount != 0 || result.RemovalCount != 1 {
		t.Fatalf("result %+v", result)
	}
	for _, path := range marked {
		if read := world.entryOf(path); !read.Absent() {
			t.Errorf("path %x stands: %v", path.Bytes()[:2], read.Entry)
		}
	}
	if world.entryOf(other).Absent() {
		t.Error("a path the removal did not mark went")
	}
	after, err := world.heads.ReadCluster(world.ctx, world.cluster, world.repoId, world.refId)
	if err != nil {
		t.Fatal(err)
	}
	collect := after.Head.GetCollect()
	if after.Head.GetVersion() != before.Head.GetVersion() || after.Head.GetFence() != before.Head.GetFence()+2 ||
		after.Head.GetFenceMs() != before.Head.GetFenceMs() || collect.GetDone() != 2 || collect.GetThrough() != 2 || collect.GetUntilMs() == 0 {
		t.Fatalf("head %v after %v", after.Head, before.Head)
	}
	want := []string{BarrierCollectOpenBefore, BarrierCollectOpenAfter}
	for range 3 {
		want = append(want, BarrierCollectDeleteBefore, BarrierCollectDeleteAfter)
	}
	want = append(want, BarrierCollectCloseBefore, BarrierCollectCloseAfter)
	if len(*steps) != len(want) {
		t.Fatalf("steps %v, want %v", *steps, want)
	}
	for i := range want {
		if (*steps)[i] != want[i] {
			t.Fatalf("steps %v, want %v", *steps, want)
		}
	}
	// nothing left: the next run finds nothing due
	if again := world.collect(collector); again.Skipped != "nothing due" {
		t.Fatalf("again %+v", again)
	}
}

// DELETE is unconditional, so on a build that has not passed FS-114 no window opens and the markers stay; nor on an
// unsure clock.
func TestMarkerCollectionOpensNoWindowOnAnUnpassedBuildOrAnUnsureClock(t *testing.T) {
	world, marked, _ := newCollectWorld(t)
	collector, steps := collectorOf(t, world, nil)
	world.host.Blobs.SetSettlePassed("meta-1", false)
	if result := world.collect(collector); result.Skipped != "settle not passed" || result.Opened {
		t.Fatalf("an unpassed build: %+v", result)
	}
	world.host.Blobs.SetSettlePassed("meta-1", true)
	world.host.ClockCheck.SetUnknown()
	if result := world.collect(collector); result.Skipped != "clock unsure" || result.Opened {
		t.Fatalf("an unsure clock: %+v", result)
	}
	if len(*steps) != 0 {
		t.Fatalf("steps %v", *steps)
	}
	for _, path := range marked {
		if world.entryOf(path).Entry.GetMarker() == nil {
			t.Fatal("a marker went")
		}
	}
}

// A window still open, or lapsed under 150 ms ago by the opener's clock, opens no other.
func TestMarkerCollectionWaitsForTheLastWindowToLapse(t *testing.T) {
	world, _, _ := newCollectWorld(t)
	untilMs := world.clock.Now().Add(10 * time.Second).UnixMilli()
	world.fenceWrite(func(next *protocol.EvsHead) {
		next.Collect = &protocol.EvsCollect{Through: 1, UntilMs: untilMs}
	})
	collector, _ := collectorOf(t, world, nil)
	if result := world.collect(collector); result.Skipped != "window open" {
		t.Fatalf("an open window: %+v", result)
	}
	world.clock.AdvanceTo(time.UnixMilli(untilMs).Add(149 * time.Millisecond))
	if result := world.collect(collector); result.Skipped != "window open" {
		t.Fatalf("149 ms past it: %+v", result)
	}
	world.clock.Advance(time.Millisecond)
	if result := world.collect(collector); !result.Closed || result.MarkerDeletedCount != 3 {
		t.Fatalf("150 ms past it: %+v", result)
	}
}

// FS-58: a window held at a barrier past until_ms while a fold, now free to, re-creates a covered path: the
// window's DELETE carries a deadline 50 ms before until_ms, so the store takes none, the live entry stays, and done
// stays below the marker it could not delete.
func TestMarkerCollectionHeldPastItsWindowDeletesNoLiveEntry(t *testing.T) {
	world, marked, _ := newCollectWorld(t)
	recreated := marked[1]
	var collector *MarkerCollector
	held := false
	collector, _ = collectorOf(t, world, func(name string) {
		if name != BarrierCollectDeleteBefore || held {
			return
		}
		held = true
		head, err := world.heads.ReadCluster(world.ctx, world.cluster, world.repoId, world.refId)
		if err != nil {
			t.Error(err)
			return
		}
		world.clock.AdvanceTo(time.UnixMilli(head.Head.GetCollect().GetUntilMs()).Add(200 * time.Millisecond))
		// a fold past the margin writes a live version over the marker
		read := world.entryOf(recreated)
		live := proto.Clone(read.Entry).(*protocol.EvsIndexEntry)
		live.Marker = nil
		liveBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(live)
		if err != nil {
			t.Error(err)
			return
		}
		key := IndexEntryKey(world.repoId, world.refId, read.Epoch, recreated)
		if _, err := world.cluster.PutIfMatch(sidecartest.InspectContext(world.ctx), key, read.Etag, liveBytes, nil); err != nil {
			t.Error(err)
		}
	})
	result := world.collect(collector)
	if !result.Opened || result.MarkerDeletedCount != 0 || result.MarkerLeftCount == 0 || result.Done != 1 {
		t.Fatalf("result %+v", result)
	}
	if read := world.entryOf(recreated); read.Absent() || read.Entry.GetMarker() != nil {
		t.Fatalf("the re-created entry: %v", read.Entry)
	}
}

// A hold over what a marker carries keeps the marker for a later window, and done stays below it.
func TestMarkerCollectionLeavesAMarkerWhoseCarriedIdsAHoldKeeps(t *testing.T) {
	world, marked, _ := newCollectWorld(t)
	carrier := marked[0]
	read := world.entryOf(carrier)
	carrying := proto.Clone(read.Entry).(*protocol.EvsIndexEntry)
	carrying.Marker.SegmentIds = [][]byte{make([]byte, 32)}
	carryingBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(carrying)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.cluster.PutIfMatch(sidecartest.InspectContext(world.ctx), IndexEntryKey(world.repoId, world.refId, read.Epoch, carrier), read.Etag, carryingBytes, nil); err != nil {
		t.Fatal(err)
	}
	if err := sidecartest.PlaceHold(world.ctx, world.host.Blobs, &sidecar.HoldRecord{
		NetworkId: testId("network-a"), CaseId: testId("hold case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: world.clock.Now(), ExpireTime: world.clock.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	collector, _ := collectorOf(t, world, nil)
	result := world.collect(collector)
	if result.MarkerLeftCount != 1 || result.MarkerDeletedCount != 2 || result.Done != 1 || result.CarriedDeletedCount != 0 {
		t.Fatalf("result %+v", result)
	}
	if world.entryOf(carrier).Entry.GetMarker() == nil {
		t.Fatal("the held marker went")
	}
}

// The nightly pass's test of a head, and the job's args.
func TestMarkerCollectionDueAndItsArgs(t *testing.T) {
	cases := []struct {
		head *protocol.EvsHead
		due  bool
	}{
		{head: nil, due: false},
		{head: &protocol.EvsHead{Version: 0, FoldedThrough: 100}, due: false},
		{head: &protocol.EvsHead{Version: 100, FoldedThrough: 64}, due: false},
		{head: &protocol.EvsHead{Version: 100, FoldedThrough: 65}, due: true},
		{head: &protocol.EvsHead{Version: 100, FoldedThrough: 90, Collect: &protocol.EvsCollect{Done: 26}}, due: false},
		{head: &protocol.EvsHead{Version: 100, FoldedThrough: 91, Collect: &protocol.EvsCollect{Done: 26}}, due: true},
		{head: &protocol.EvsHead{Version: 100, FoldedThrough: 91, PathEpoch: &protocol.EvsPathEpoch{Current: 2, Sources: []*protocol.EvsEpochSource{{Epoch: 1}}}}, due: false},
	}
	for i, c := range cases {
		if due := MarkerCollectionDue(c.head); due != c.due {
			t.Errorf("case %d: due %t", i, due)
		}
	}
	repoId, refId := testId("repo"), testId("ref")
	clusterId, parsedRepoId, parsedRefId, ok := ParseEvsCollectArgs(EvsCollectArgs("meta-1", repoId, refId))
	if !ok || clusterId != "meta-1" || parsedRepoId != repoId || parsedRefId != refId {
		t.Fatalf("args round trip: %s %v %v %t", clusterId, parsedRepoId, parsedRefId, ok)
	}
	for _, args := range []string{"", "meta-1", "meta-1\nx\ny", "\n" + sidecar.EvsKeyId(repoId) + "\n" + sidecar.EvsKeyId(refId)} {
		if _, _, _, ok := ParseEvsCollectArgs([]byte(args)); ok {
			t.Errorf("args %q parsed", args)
		}
	}
	if _, err := NewMarkerCollector(sidecartest.NewFakeHost(t.Context(), sidecartest.NewFakeClock(sidecartest.DefaultClockStart()), nil, nil, nil).ServiceHost(), &MarkerCollectorDeps{
		Settings: &MarkerCollectorSettings{Window: 30 * time.Second, OpenWait: 15 * time.Second, ReopenMargin: 150 * time.Millisecond, DeleteMargin: 50 * time.Millisecond, ScanVersionCount: 1, WindowEntryCount: 1, DoneAdvanceVersionCount: 1, HeadAge: time.Hour, RunMaxTime: time.Minute, ListLimit: 1},
	}); err == nil {
		t.Error("a wait no longer than a fold write's deadline was taken")
	}
}

// The nightly pass queues one evs.collect run for a ref whose head is due a window, once-keyed by the ref, and
// none for a ref with nothing due.
func TestNightlyPassQueuesMarkerCollectionForADueRef(t *testing.T) {
	world, _, _ := newCollectWorld(t)
	pass, err := NewNightlyPass(world.host.ServiceHost(), &NightlyPassDeps{
		EvsSettings:        world.settings,
		SegmentClusterBusy: func(ctx context.Context, clusterId string) bool { return false },
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := pass.Run(world.ctx, "meta-1", "", "")
	if err != nil || result.CollectQueuedCount != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	onceKey := EvsCollectTaskRequest("meta-1", world.repoId, world.refId, time.Time{}, nil).OnceKey
	queued := 0
	for _, request := range world.host.Tasks.AllRequests() {
		if request.Name == EvsCollectTaskName && request.OnceKey == onceKey {
			queued += 1
		}
	}
	if queued != 1 {
		t.Fatalf("%d evs.collect requests for the ref", queued)
	}
}
