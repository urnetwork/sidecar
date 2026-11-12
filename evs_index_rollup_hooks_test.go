//go:build sidecar_testhooks && !ios_extension

// FS-75's kills and the barriers' order (SEARCH-M10-10, SEARCH-M10-11; DESIGN-DETAILS 1.5): a merge and a roll-up pass
// their barriers in order, keyed <repo>/<ref>; killed at each barrier before its push, a merge commits nothing and the
// next merge writes what it would have, and a roll-up leaves its bucket and all as they were, its lock to lapse, after
// which a second runner rolls the same plaintext; killed after its push, the push stands.

package sidecar

import (
	"context"
	"crypto/sha256"
	"slices"
	"sync"
	"testing"
	"time"
)

// What a barrier hook panics with, as a process dying there.
type testIndexKill struct {
	barrier string
}

// Installs a hook that records each index barrier passed and kills the caller at kill, if named.
func testIndexBarriers(t *testing.T, kill string) *[]string {
	stateLock := sync.Mutex{}
	passed := []string{}
	key := evsTestId("view repo").String() + "/" + evsTestId("view ref").String()
	SetTestHooks(&TestHooks{Barrier: func(name string, barrierKey string) {
		if barrierKey != key {
			return
		}
		stateLock.Lock()
		passed = append(passed, name)
		stateLock.Unlock()
		if name == kill {
			panic(testIndexKill{barrier: name})
		}
	}})
	t.Cleanup(func() { SetTestHooks(nil) })
	return &passed
}

// Runs f, recovering a kill at a barrier; whether one happened.
func testIndexKilled(f func()) (killed bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if _, ok := recovered.(testIndexKill); !ok {
				panic(recovered)
			}
			killed = true
		}
	}()
	f()
	return false
}

// The files a commit wrote, by path, their plaintexts' hashes.
func testIndexCommittedHashes(world *testHeadWorld) map[string][sha256.Size]byte {
	world.ref.stateLock.Lock()
	defer world.ref.stateLock.Unlock()
	hashes := map[string][sha256.Size]byte{}
	for path, versions := range world.ref.headStateWithLock().files {
		hashes[path] = versions[len(versions)-1].version.contentSha256
	}
	return hashes
}

func TestIndexMergePassesItsBarriersInOrder(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("k", 1, 1, 0, testHeadKeys(1, 0)))
	world.fillUntilSealed(t, a, "f", 0)
	passed := testIndexBarriers(t, "")
	world.merge(t, evsTestId("merger"))
	if want := []string{"evs.index.merge.built", "evs.index.merge.uploaded", "evs.index.merge.pushed"}; !slices.Equal(*passed, want) {
		t.Fatalf("passed %v", *passed)
	}
}

// Killed at built or uploaded, a merge commits nothing, and the next one commits what it would have; killed at pushed,
// its push stands.
func TestIndexMergeKilledAtEachBarrier(t *testing.T) {
	for _, barrier := range []string{"evs.index.merge.built", "evs.index.merge.uploaded", "evs.index.merge.pushed"} {
		world := testNewHeadWorld()
		a := evsTestId("writer a")
		world.push(t, a, testLive("k", 1, 1, 0, testHeadKeys(1, 0)))
		world.fillUntilSealed(t, a, "f", 0)
		startDay := world.view(t, a).writeRoot().newestBucket().window.startDay
		before := testIndexCommittedHashes(world)
		testIndexBarriers(t, barrier)
		killed := testIndexKilled(func() {
			world.merger(t, evsTestId("merger one")).Merge(context.Background(), indexRootNumber, startDay)
		})
		SetTestHooks(nil)
		if !killed {
			t.Fatalf("%s: not killed", barrier)
		}
		after := testIndexCommittedHashes(world)
		if barrier == "evs.index.merge.pushed" {
			if len(after) == len(before) {
				t.Fatalf("%s: the push did not stand", barrier)
			}
			continue
		}
		if len(after) != len(before) {
			t.Fatalf("%s: a killed merge wrote", barrier)
		}
		outcome, err := world.merger(t, evsTestId("merger two")).Merge(context.Background(), indexRootNumber, startDay)
		if err != nil || outcome.committed == nil {
			t.Fatalf("%s: the next merge: %v", barrier, err)
		}
	}
}

func TestIndexRollupPassesItsBarriersInOrder(t *testing.T) {
	world, a := testRollupWorld(t)
	first := world.view(t, a).writeRoot().newestBucket()
	world.at = testDayTime(first.window.endDay()+first.window.days, time.Hour)
	passed := testIndexBarriers(t, "")
	world.rollUp(t, evsTestId("runner"))
	if want := []string{"evs.index.rollup.locked", "evs.index.rollup.built", "evs.index.rollup.uploaded", "evs.index.rollup.pushed"}; !slices.Equal(*passed, want) {
		t.Fatalf("passed %v", *passed)
	}
}

// FS-75: a runner killed at each barrier before its push leaves the bucket and all as they were and its lock held; a
// second runner is refused until the lock is LockGrace past its until_ms, then rolls, writing what the first would
// have, the roll-up being a function of its inputs; killed after its push, the roll-up stands and the second finds
// nothing expired.
func TestIndexRollupKilledAtEachBarrier(t *testing.T) {
	// what an unkilled roll-up writes, for the plaintext the reruns must equal
	reference, a := testRollupWorld(t)
	first := reference.view(t, a).writeRoot().newestBucket()
	expiredAt := testDayTime(first.window.endDay()+first.window.days, time.Hour)
	reference.at = expiredAt
	want := map[string][sha256.Size]byte{}
	for _, file := range reference.rollUp(t, evsTestId("runner two")).result.files {
		want[file.path] = sha256.Sum256(file.plaintext)
	}
	for _, barrier := range []string{"evs.index.rollup.locked", "evs.index.rollup.built", "evs.index.rollup.uploaded", "evs.index.rollup.pushed"} {
		world, _ := testRollupWorld(t)
		world.at = expiredAt
		testIndexBarriers(t, barrier)
		killed := testIndexKilled(func() {
			world.roller(t, evsTestId("runner one")).Roll(context.Background(), indexRootNumber)
		})
		SetTestHooks(nil)
		if !killed {
			t.Fatalf("%s: not killed", barrier)
		}
		if barrier == "evs.index.rollup.pushed" {
			again, err := world.roller(t, evsTestId("runner two")).Roll(context.Background(), indexRootNumber)
			if err != nil || again.skipped != indexRollupSkipNone {
				t.Fatalf("%s: a second runner after the push: %+v %v", barrier, again, err)
			}
			continue
		}
		view := world.view(t, a)
		if view.writeRoot().bucket(first.window.startDay) == nil || view.writeRoot().lock == nil || len(view.writeRoot().lock.HolderSidecarId) == 0 {
			t.Fatalf("%s: a killed runner moved the bucket or freed the lock", barrier)
		}
		if outcome, _ := world.roller(t, evsTestId("runner two")).Roll(context.Background(), indexRootNumber); outcome.skipped != indexRollupSkipLocked {
			t.Fatalf("%s: a held lock was taken", barrier)
		}
		world.at = time.UnixMilli(view.writeRoot().lock.UntilMs).Add(world.settings.LockGrace)
		outcome := world.rollUp(t, evsTestId("runner two"))
		for _, file := range outcome.result.files {
			if want[file.path] != sha256.Sum256(file.plaintext) {
				t.Errorf("%s: the rerun's %s differs from the roll-up's", barrier, file.path)
			}
		}
	}
}
