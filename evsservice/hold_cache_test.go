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
