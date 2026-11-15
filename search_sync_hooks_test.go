//go:build sidecar_testhooks && !ios_extension

package sidecar

// SEARCH-M10-19's crash schedule (DESIGN-DETAILS 7.6's TestACrashResumesFromThePlan): a round killed at each of its
// barriers, replayed, fetched (a file), tables, swapped and retired, leaves a manifest whose runs and files exist; a
// fresh process over the same store finishes from its plan, and its snapshot is one version of the ref.

import (
	"context"
	"sync"
	"testing"
)

// Kills the round at the named barrier of the world's ref, once.
func testSyncKillAt(t *testing.T, world *testSyncWorld, kill string) {
	key := searchSyncBarrierKey(world.repoId, world.refId)
	once := sync.Once{}
	SetTestHooks(&TestHooks{Barrier: func(name string, barrierKey string) {
		if barrierKey != key || name != kill {
			return
		}
		fired := false
		once.Do(func() { fired = true })
		if fired {
			panic(testIndexKill{barrier: name})
		}
	}})
	t.Cleanup(func() { SetTestHooks(nil) })
}

func TestACrashResumesFromThePlan(t *testing.T) {
	for _, barrier := range []string{"search.sync.replayed", "search.sync.fetched", "search.sync.tables", "search.sync.swapped", "search.sync.retired"} {
		world := newTestSyncWorld(t, false)
		world.push(t, evsTestId("writer a"), "a", 1)
		world.round(t)
		world.push(t, evsTestId("writer a"), "a again", 1)
		world.push(t, evsTestId("writer b"), "b", 1)
		world.push(t, evsTestId("writer c"), "c", 1)
		world.sync.args.readPathCount = 1
		testSyncKillAt(t, world, barrier)
		killed := testIndexKilled(func() {
			world.sync.RunRound(context.Background(), world.repoId, world.refId, false)
		})
		SetTestHooks(nil)
		if !killed {
			t.Fatalf("the round never reached %s", barrier)
		}
		// a process start: a cache and an engine afresh over the same store
		cache, err := NewSearchCache(context.Background(), world.cache.instance.Store(&world.cache.networkId), world.cache.settings, world.cache.clock, NewNoopLogger())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(cache.Close)
		world.cache.cache = cache
		world.restart(t)
		world.round(t)
		snapshot := world.snapshot(t)
		world.assertOneVersion(t, snapshot)
		head, _ := world.head.ref.store(evsTestId("reader")).Head(context.Background())
		if snapshot.Pin().Version != head.version {
			t.Fatalf("killed at %s, the resumed round reached v%d of v%d", barrier, snapshot.Pin().Version, head.version)
		}
	}
}
