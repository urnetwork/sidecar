//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-75 on T2 (§11.14's roll-up, lock and epoch rows; I-EVS-11, I-EVS-12, FI-18, FI-19, FI-20; SEARCH-M10-35): the
// indexer designated for search rolls an expired bucket and is killed at each of the roll-up's barriers, its lock
// taken, its merge built, its uploads, and after its commit; each rerun, by the same runner past the lock's term,
// ends in one committed roll-up whose all files equal a twin's uninterrupted one, and a search after it equals
// SearchOracle's set. A roll-up built before an erasure's CUT is refused 409 INDEX_EPOCH and rebuilt, and no all file it
// commits holds the listed document.
//
// Not here yet, each named for what it waits on: the head CAS with its response dropped and a kill between the commit
// and the purge (a store that drops a reply, on T3); an offline indexer and the first writer after expiry rolling,
// the lock's expiry fought by two rollers, and a search at every barrier merging the expired bucket (a world device
// syncing between barriers); the storage limit and a phone as the first writer; both CLOSURE orders against a roll-up
// (SEARCH-M10-17's eraser on the world's store, which takes no CLOSURE yet); a window change; ApplyThenDrop on every
// write; and T3.

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The roll-up's barriers, in its order.
var fs75Barriers = []string{"evs.index.rollup.locked", "evs.index.rollup.built", "evs.index.rollup.uploaded", "evs.index.rollup.pushed"}

// A world holding a bucket of documents, a merge of its seals and the writer's head after it, its clock moved past
// the bucket's expiry: what a roll-up rolls.
func newFs75World(t *testing.T, label string) (*searchWorld, *sidecartest.FakeClock) {
	t.Helper()
	world, clock := newFsIndexWorld(t, label)
	ctx := t.Context()
	a := searchId("writer a")
	world.fillSeals(t, a, "rolled", 160, clock.Now())
	if _, err := world.index.Merge(ctx, searchId("merger"), 0); err != nil {
		t.Fatal(err)
	}
	late := &sidecar.SearchTestDocument{Path: "notes/late.md", Version: 1, Title: "Late", Text: "a lighthouse keeper", Time: clock.Now()}
	if err := world.index.PushDocuments(ctx, a, clock.Now(), []*sidecar.SearchTestDocument{late}); err != nil {
		t.Fatal(err)
	}
	if err := world.record(clock.Now(), late); err != nil {
		t.Fatal(err)
	}
	// past the bucket's window and the next one, so it is expired
	clock.Advance(100 * 24 * time.Hour)
	return world, clock
}

// The digests of all's files at the head: a/m and its shards.
func fs75AllDigests(world *searchWorld) map[string][32]byte {
	digests := map[string][32]byte{}
	for path, digest := range world.index.FileDigests() {
		if fs75IsAll(path) {
			digests[path] = digest
		}
	}
	return digests
}

// Whether path is under a root's a/.
func fs75IsAll(path string) bool {
	for index := 0; index+3 <= len(path); index += 1 {
		if path[index:index+3] == "/a/" {
			return true
		}
	}
	return false
}

// Runs the roll-up as runner, killed at barrier: its goroutine ends there, as a process the OS killed, running no
// more of the roll-up. Answers whether it reached the barrier.
func fs75RollKilledAt(t *testing.T, world *searchWorld, runner sidecar.Id, barrier string) bool {
	t.Helper()
	reached := make(chan bool, 1)
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name == barrier {
			reached <- true
			runtime.Goexit()
		}
	}})
	defer sidecar.SetTestHooks(nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		world.index.RollUp(context.Background(), runner)
	}()
	<-done
	select {
	case <-reached:
		return true
	default:
		return false
	}
}

// FS-75's kill clause: killed at each barrier, the rerun past the lock's term ends in one committed roll-up whose all
// files equal a twin's uninterrupted one, and a search finds what the oracle does.
func TestFs75RollupKilledAtEachBarrierEndsInOneRollup(t *testing.T) {
	twin, _ := newFs75World(t, "rollup")
	if version, err := twin.index.RollUp(t.Context(), searchId("indexer")); err != nil || version == 0 {
		t.Fatalf("the twin's roll-up: %d, %v", version, err)
	}
	want := fs75AllDigests(twin)
	if len(want) < 2 {
		t.Fatalf("the twin's all holds %d files", len(want))
	}
	for _, barrier := range fs75Barriers {
		world, clock := newFs75World(t, "rollup")
		indexer := searchId("indexer")
		if !fs75RollKilledAt(t, world, indexer, barrier) {
			t.Fatalf("the roll-up never reached %s", barrier)
		}
		// the dead holder's lock lapses at its term and grace
		clock.Advance(45 * time.Minute)
		if _, err := world.index.RollUp(t.Context(), indexer); err != nil {
			t.Fatalf("the rerun after %s: %v", barrier, err)
		}
		if again, err := world.index.RollUp(t.Context(), indexer); err != nil || again != 0 {
			t.Fatalf("a second rerun after %s committed %d, %v", barrier, again, err)
		}
		got := fs75AllDigests(world)
		if len(got) != len(want) {
			t.Fatalf("killed at %s, all holds %d files, the twin %d", barrier, len(got), len(want))
		}
		for path, digest := range want {
			if got[path] != digest {
				t.Fatalf("killed at %s, %s differs from the twin's", barrier, path)
			}
		}
		days, err := world.index.BucketStartDays(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if 1 < len(days) {
			t.Fatalf("killed at %s, buckets %v stand", barrier, days)
		}
		world.checkSearch(t, "marker0042")
		world.checkSearch(t, "lighthouse")
	}
}

// FS-75's last clause: a roll-up built before an erasure's CUT gets 409 INDEX_EPOCH, is rebuilt at the new epoch, and
// commits no all file holding the document the CUT lists (FI-19's fence).
func TestFs75RollupBuiltBeforeACutGets409(t *testing.T) {
	world, _ := newFs75World(t, "cut")
	ctx := t.Context()
	erased := &sidecar.SearchTestDocument{Path: "notes/rolled-3.md", Version: 1}
	key, err := world.index.DocKey(erased.Path)
	if err != nil {
		t.Fatal(err)
	}
	built, release := make(chan struct{}), make(chan struct{})
	first := true
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, barrierKey string) {
		if name == "evs.index.rollup.built" && first {
			first = false
			close(built)
			<-release
		}
	}})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	type rolled struct {
		version uint64
		err     error
	}
	result := make(chan rolled, 1)
	go func() {
		version, err := world.index.RollUp(context.Background(), searchId("indexer"))
		result <- rolled{version: version, err: err}
	}()
	<-built
	if _, err := world.index.Cut(ctx, searchId("erasure"), []*sidecar.SearchTestDocument{erased}); err != nil {
		t.Fatal(err)
	}
	close(release)
	outcome := <-result
	if outcome.err != nil || outcome.version == 0 {
		t.Fatalf("the roll-up after the CUT: %d, %v", outcome.version, outcome.err)
	}
	live, err := world.index.LiveDocKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := live[key]; ok {
		t.Fatal("a roll-up built before the CUT committed the listed document")
	}
	other, err := world.index.DocKey("notes/rolled-4.md")
	if err != nil {
		t.Fatal(err)
	}
	if live[other] != 1 {
		t.Fatal("the roll-up lost a document the CUT does not list")
	}
}
