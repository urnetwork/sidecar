package evsservice

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The bound a hold binds evs's deleters by (owner decision 629), and a stall past it.
var (
	holdTestBound = DefaultHoldCacheSettings().HoldSet.RereadInterval
	holdTestStall = holdTestBound + time.Second
)

// A store whose first cluster counts the LISTs of hold/ a HoldCache makes, its reads of the holds.
type holdReadCountingBlobs struct {
	sidecar.BlobStore
	stateLock sync.Mutex
	listCount int
}

func (self *holdReadCountingBlobs) FirstCluster() (sidecar.BlobCluster, error) {
	cluster, err := self.BlobStore.FirstCluster()
	if err != nil {
		return nil, err
	}
	return &holdReadCountingCluster{BlobCluster: cluster, blobs: self}, nil
}

func (self *holdReadCountingBlobs) reads() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.listCount
}

type holdReadCountingCluster struct {
	sidecar.BlobCluster
	blobs *holdReadCountingBlobs
}

func (self *holdReadCountingCluster) List(ctx context.Context, keyPrefix string, startAfter string, limit int) ([]*sidecar.BlobInfo, bool, error) {
	if strings.HasPrefix(keyPrefix, "hold/") {
		func() {
			self.blobs.stateLock.Lock()
			defer self.blobs.stateLock.Unlock()
			self.blobs.listCount += 1
		}()
	}
	return self.BlobCluster.List(ctx, keyPrefix, startAfter, limit)
}

// A cluster whose HEADs first run a hook: a store whose HEAD stalls, the hook moving the clock on and placing what
// the stall's time brings.
type holdStallingCluster struct {
	sidecar.BlobCluster
	stateLock sync.Mutex
	headCount int
	onHead    func(count int, key string)
}

func (self *holdStallingCluster) Head(ctx context.Context, key string) (*sidecar.BlobInfo, error) {
	count := func() int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.headCount += 1
		return self.headCount
	}()
	if self.onHead != nil {
		self.onHead(count, key)
	}
	return self.BlobCluster.Head(ctx, key)
}

// A network-wide §2703(f) hold of networkId placed at the clock's now, which api acknowledged then.
func placeTestHold(t *testing.T, ctx context.Context, blobs sidecar.BlobStore, clock sidecar.Clock, networkId sidecar.Id, label string) {
	t.Helper()
	if err := sidecartest.PlaceHold(ctx, blobs, &sidecar.HoldRecord{
		NetworkId: networkId, CaseId: testId(label), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: clock.Now(), ExpireTime: clock.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
}

// A stall of holdTestStall: a hold is acknowledged half a second in when hold is set, and the caller comes back past
// the bound.
func stallPastTheBound(t *testing.T, ctx context.Context, blobs sidecar.BlobStore, clock *sidecartest.FakeClock, networkId sidecar.Id, hold bool) {
	t.Helper()
	clock.Advance(500 * time.Millisecond)
	if hold {
		placeTestHold(t, ctx, blobs, clock, networkId, "stall case")
	}
	clock.Advance(holdTestStall - 500*time.Millisecond)
}

// The drop deletes with their own HoldCache over a store that counts its hold/ reads, and a segment cluster whose
// HEADs can stall.
func newDropDeleteStallFixture(t *testing.T) (*dropDeleteFixture, *holdReadCountingBlobs, *holdStallingCluster) {
	fixture := newDropDeleteFixture(t)
	world := fixture.world
	counting := &holdReadCountingBlobs{BlobStore: world.host.Blobs}
	deleter, err := NewDropDelete(world.host.ServiceHost(), &DropDeleteDeps{
		Format2: fixture.format2, Holds: NewHoldCache(counting, world.clock, nil), Settings: dropTestSettings(), EvsSettings: world.settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.deleter = deleter
	stalling := &holdStallingCluster{BlobCluster: world.segment}
	fixture.segment = &dropHookedCluster{BlobCluster: stalling}
	return fixture, counting, stalling
}

// Owner decision 629 at a drop's DELETE: a hold acknowledged while a HEAD stalled past the bound is in the read the
// DELETE acts on, so no DELETE issues, and this id and the rest of D move to held.
func TestDropDeleteHoldAcknowledgedDuringAStalledHeadStopsTheDelete(t *testing.T) {
	fixture, counting, stalling := newDropDeleteStallFixture(t)
	world := fixture.world
	a, b := fixture.putSegment("a", 100), fixture.putSegment("b", 200)
	world.clock.Advance(30 * time.Hour)
	fixture.horizon = world.clock.Now()
	stalling.onHead = func(count int, key string) {
		if count == 1 {
			stallPastTheBound(t, world.ctx, world.host.Blobs, world.clock, testId("network-a"), true)
		}
	}
	result := fixture.run(a, b)
	if !result.Held || fixture.segment.deletes() != 0 || !fixture.stored(a) || !fixture.stored(b) {
		t.Fatalf("held %t, %d DELETEs", result.Held, fixture.segment.deletes())
	}
	if answers := fixture.answers(); answers[a] != DropOutcomeHeld || answers[b] != DropOutcomeHeld {
		t.Fatalf("answers %v", answers)
	}
	if got := counting.reads(); got != 2 {
		t.Fatalf("%d hold/ reads, want the one before the HEAD and the one at the DELETE", got)
	}
}

// A quick HEAD deletes on the cached read, as before: a hold acknowledged under the bound before the DELETE does not
// bind it yet, and no read of hold/ is added.
func TestDropDeleteQuickHeadDeletesOnTheCachedRead(t *testing.T) {
	fixture, counting, _ := newDropDeleteStallFixture(t)
	world := fixture.world
	a := fixture.putSegment("a", 100)
	world.clock.Advance(30 * time.Hour)
	fixture.horizon = world.clock.Now()
	// the job's cache read hold/ a moment ago; a hold is acknowledged since, under the bound before the DELETE
	if _, err := fixture.deleter.holds.Covering(world.ctx, testId("network-a"), world.repoId); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(time.Second)
	placeTestHold(t, world.ctx, world.host.Blobs, world.clock, testId("network-a"), "recent case")
	result := fixture.run(a)
	if result.Held || fixture.segment.deletes() != 1 || fixture.stored(a) {
		t.Fatalf("held %t, %d DELETEs", result.Held, fixture.segment.deletes())
	}
	if got := counting.reads(); got != 1 {
		t.Fatalf("%d hold/ reads, want the cached one alone", got)
	}
}

// A stall costs one read of hold/, not one per id: the read at the stalled id's DELETE serves every later id's.
func TestDropDeleteStallCostsOneHoldRead(t *testing.T) {
	fixture, counting, stalling := newDropDeleteStallFixture(t)
	world := fixture.world
	ids := []DropScanId{fixture.putSegment("a", 100), fixture.putSegment("b", 100), fixture.putSegment("c", 100), fixture.putSegment("d", 100)}
	world.clock.Advance(30 * time.Hour)
	fixture.horizon = world.clock.Now()
	stalling.onHead = func(count int, key string) {
		if count == 1 {
			stallPastTheBound(t, world.ctx, world.host.Blobs, world.clock, testId("network-a"), false)
		}
	}
	result := fixture.run(ids...)
	if result.Held || fixture.segment.deletes() != len(ids) {
		t.Fatalf("held %t, %d DELETEs", result.Held, fixture.segment.deletes())
	}
	if got := counting.reads(); got != 2 {
		t.Fatalf("%d hold/ reads, want 2: the first and one after the stall", got)
	}
}

// A store whose segment cluster is a stalling one; its other clusters are the store's own.
type holdStallingBlobs struct {
	sidecar.BlobStore
	segment *holdStallingCluster
}

func (self *holdStallingBlobs) SegmentCluster() (sidecar.BlobCluster, error) {
	return self.segment, nil
}

func (self *holdStallingBlobs) Cluster(clusterId string) (sidecar.BlobCluster, error) {
	if clusterId == self.segment.ClusterId() {
		return self.segment, nil
	}
	return self.BlobStore.Cluster(clusterId)
}

// The fake host's ServiceHost with its segment cluster's HEADs stalling, and a HoldCache over a store that counts its
// reads of hold/.
func newHoldStallHost(t *testing.T, host *sidecartest.FakeHost, clock sidecar.Clock) (*sidecar.ServiceHost, *HoldCache, *holdReadCountingBlobs, *holdStallingCluster) {
	t.Helper()
	segment, err := host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	stalling := &holdStallingCluster{BlobCluster: segment}
	serviceHost := host.ServiceHost()
	serviceHost.Blobs = &holdStallingBlobs{BlobStore: host.Blobs, segment: stalling}
	counting := &holdReadCountingBlobs{BlobStore: host.Blobs}
	return serviceHost, NewHoldCache(counting, clock, nil), counting, stalling
}

// The purge fixture with a purger whose segment HEADs can stall, whose hold/ reads are counted, and whose barriers
// run onStep, when set, after the fixture's own.
func newPurgeStallFixture(t *testing.T, onStep func(name string)) (*purgeFixture, *holdReadCountingBlobs, *holdStallingCluster) {
	fixture := newPurgeFixture(t, nil)
	serviceHost, holds, counting, stalling := newHoldStallHost(t, fixture.host, fixture.clock)
	purger, err := newPurger(fixture.ctx, serviceHost, &PurgerDeps{
		Format2: fixture.gate, Newest: fixture.newest, Holds: holds, Usage: fixture.usage,
		atStep: func(name string, key string) error {
			if err := fixture.atStep(name, key); err != nil {
				return err
			}
			if onStep != nil {
				onStep(name)
			}
			return nil
		},
		wait: fixture.clock.Advance,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(purger.Close)
	fixture.purger = purger
	return fixture, counting, stalling
}

// Owner decision 629 at the purge's DELETE: a hold acknowledged while the first candidate's HEAD stalled past the
// bound keeps it, as it keeps every candidate after it, each existing at the hold's placement.
func TestPurgerHoldAcknowledgedDuringAStalledHeadStopsTheDelete(t *testing.T) {
	fixture, counting, stalling := newPurgeStallFixture(t, nil)
	path := checkTestPath("x")
	first, second := fixture.segment("first", 100), fixture.segment("second", 100)
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{first, second}, nil, nil))
	fixture.clock.Advance(time.Minute)
	stalling.onHead = func(count int, key string) {
		if count == 1 {
			stallPastTheBound(t, fixture.ctx, fixture.host.Blobs, fixture.clock, fixture.networkId, true)
		}
	}
	fixture.purger.runDue()
	if !fixture.segmentStored(first) || !fixture.segmentStored(second) {
		t.Fatal("a DELETE issued past the bound on a read that missed the hold")
	}
	if stats := fixture.purger.Stats(); stats.DeletedCount != 0 || stats.HeldCount != 2 {
		t.Fatalf("stats %+v", stats)
	}
	if got := counting.reads(); got != 2 {
		t.Fatalf("%d hold/ reads, want the first and the one at the stalled DELETE", got)
	}
}

// A quick HEAD deletes on the cached read: a hold acknowledged under the bound before the DELETE does not bind it yet.
func TestPurgerQuickHeadDeletesOnTheCachedRead(t *testing.T) {
	fixture, counting, _ := newPurgeStallFixture(t, nil)
	path := checkTestPath("x")
	gone := fixture.segment("gone", 100)
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), [][]byte{gone}, nil, nil))
	fixture.clock.Advance(time.Minute)
	if _, err := fixture.purger.holds.Covering(fixture.ctx, fixture.networkId, fixture.repoId); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(time.Second)
	placeTestHold(t, fixture.ctx, fixture.host.Blobs, fixture.clock, fixture.networkId, "recent case")
	fixture.purger.runDue()
	if fixture.segmentStored(gone) {
		t.Fatal("a quick HEAD's DELETE waited on a read it did not need")
	}
	if got := counting.reads(); got != 1 {
		t.Fatalf("%d hold/ reads, want the cached one alone", got)
	}
}

// A stall costs the purge one read of hold/: the read at the stalled DELETE serves every candidate after it.
func TestPurgerStallCostsOneHoldRead(t *testing.T) {
	fixture, counting, stalling := newPurgeStallFixture(t, nil)
	path := checkTestPath("x")
	ids := [][]byte{fixture.segment("a", 100), fixture.segment("b", 100), fixture.segment("c", 100), fixture.segment("d", 100)}
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), ids, nil, nil))
	fixture.clock.Advance(time.Minute)
	stalling.onHead = func(count int, key string) {
		if count == 1 {
			stallPastTheBound(t, fixture.ctx, fixture.host.Blobs, fixture.clock, fixture.networkId, false)
		}
	}
	fixture.purger.runDue()
	if stats := fixture.purger.Stats(); stats.DeletedCount != len(ids) {
		t.Fatalf("stats %+v", stats)
	}
	if got := counting.reads(); got != 2 {
		t.Fatalf("%d hold/ reads, want 2: the first and one after the stall", got)
	}
}

// A slot whose DELETE waits on the budget: a hold placed since the purge's read, which made no HEAD of the slot, now
// covers it at the DELETE, and the slot is left to the sweep, which reads its LastModified under that hold.
func TestPurgerLeavesASlotAHoldCoversAtItsDelete(t *testing.T) {
	var fixture *purgeFixture
	stalled := false
	fixture, _, _ = newPurgeStallFixture(t, func(name string) {
		// the time between the read and the budget's turn, which a hold is acknowledged in
		if name == BarrierPurgeHoldsAfter && !stalled {
			stalled = true
			stallPastTheBound(t, fixture.ctx, fixture.host.Blobs, fixture.clock, fixture.networkId, true)
		}
	})
	path := checkTestPath("x")
	slot := fixture.slot("x slot")
	fixture.purger.Certain(fixture.commit(path, fixture.clock.Now().Add(-time.Hour), nil, nil, [][]byte{slot}))
	fixture.clock.Advance(time.Minute)
	fixture.purger.runDue()
	if !fixture.slotStored(slot) {
		t.Fatal("a slot went on a read that missed the hold")
	}
	if stats := fixture.purger.Stats(); stats.DeletedCount != 0 || stats.HeldCount != 0 {
		t.Fatalf("stats %+v", stats)
	}
}

// The sweep fixture with a sweep whose segment HEADs can stall and whose hold/ reads are counted.
func newSweepStallFixture(t *testing.T) (*sweepFixture, *holdReadCountingBlobs, *holdStallingCluster) {
	fixture := newSweepFixture(t)
	serviceHost, holds, counting, stalling := newHoldStallHost(t, fixture.host, fixture.clock)
	sweep, err := NewSweep(serviceHost, &SweepDeps{Format2: fixture.gate, Newest: fixture.newest, Holds: holds})
	if err != nil {
		t.Fatal(err)
	}
	fixture.sweep = sweep
	return fixture, counting, stalling
}

// Owner decision 629 at the sweep's DELETE: a hold acknowledged while a HEAD stalled past the bound keeps the
// candidate, and every one after it.
func TestSweepHoldAcknowledgedDuringAStalledHeadStopsTheDelete(t *testing.T) {
	fixture, counting, stalling := newSweepStallFixture(t)
	path := checkTestPath("x")
	first, second := fixture.segment("first", 100), fixture.segment("second", 100)
	fixture.clock.Advance(time.Minute)
	stalling.onHead = func(count int, key string) {
		if count == 1 {
			stallPastTheBound(t, fixture.ctx, fixture.host.Blobs, fixture.clock, fixture.networkId, true)
		}
	}
	result, err := fixture.sweepList(sweepTestList(path, [][]byte{first, second}, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !fixture.segmentStored(first) || !fixture.segmentStored(second) || result.DeletedCount != 0 || result.HeldCount != 2 {
		t.Fatalf("result %+v", result)
	}
	if got := counting.reads(); got != 2 {
		t.Fatalf("%d hold/ reads, want the first and the one at the stalled DELETE", got)
	}
}

// A quick HEAD deletes on the cached read, and a stall costs one read of hold/ across the candidates after it.
func TestSweepStallCostsOneHoldRead(t *testing.T) {
	fixture, counting, stalling := newSweepStallFixture(t)
	path := checkTestPath("x")
	ids := [][]byte{fixture.segment("a", 100), fixture.segment("b", 100), fixture.segment("c", 100)}
	fixture.clock.Advance(time.Minute)
	stalling.onHead = func(count int, key string) {
		if count == 2 {
			stallPastTheBound(t, fixture.ctx, fixture.host.Blobs, fixture.clock, fixture.networkId, false)
		}
	}
	result, err := fixture.sweepList(sweepTestList(path, ids, nil, nil))
	if err != nil || result.DeletedCount != len(ids) {
		t.Fatalf("result %+v %v", result, err)
	}
	if got := counting.reads(); got != 2 {
		t.Fatalf("%d hold/ reads, want 2: the first, which the quick HEAD's DELETE used, and one after the stall", got)
	}
}
