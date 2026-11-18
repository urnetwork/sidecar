//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-75 on T2 (§11.14's roll-up, trigger, runner, lock, limit, window and epoch rows; I-EVS-11, I-EVS-12, FI-18,
// FI-19, FI-20; DESIGN-DETAILS 1.7's cases; SEARCH-M10-35): the roll-up of an expired bucket through the index's own
// roller, merger, schedule and reproducer on the search world (search_index_testhooks.go), each search held to
// SearchOracle's set.
//
//	killed     the roll-up killed at each barrier (the lock taken, its build, its uploads, after its commit): each
//	           rerun, past the lock's term, ends in one committed roll-up whose all files equal an uninterrupted twin's
//	runner     SEARCH-M10-11's schedule: an indexer serving the repo rolls at once; beside that indexer offline a
//	           desktop rolls only once it commits a day past the expiry; with none the first desktop committing after
//	           the expiry does, and a phone only where it may run
//	lock       a runner beside a held lock waits; a holder past its lock's term loses it to another runner, who builds
//	           equal plaintext and commits, the late holder's push refused at the lock
//	barriers   a search at every barrier merges the expired bucket until the roll-up commits, its set unchanged
//	answer     a head CAS whose response is lost: the rerun finds nothing to roll, one roll-up standing
//	limit      at the storage limit the roll-up is refused and the bucket stays, searched, until under the limit
//	window     an admin's new window applies from the next bucket, every document searchable
//	promotion  a version above an older entry in a newer bucket promoted into that bucket's shards, a merge of that
//	           bucket racing the roll-up in both orders, the held one building again; killed at each barrier, rerun,
//	           equal to a twin's
//	reproduce  a device holding the inputs rebuilds the roll-up and fetches nothing; signed before the bucket's
//	           expiry, it is index_mismatch at the reproducer
//	cut        a roll-up built before an erasure's CUT is refused 409 INDEX_EPOCH and rebuilt without the document
//
// Not here, each named for what it waits on: these on real engines and on T3 (a roll-up over EvsRepo, and evs's
// purge after the commit); a device holding a stale all keeping a rolled bucket until its all records it, dropping it
// at an ERASE and after 2W days (the retained bucket on a phone, SEARCH-M10-19's, beside a stale all); a phone's
// §18.4 budget for a roll-up (SEARCH-M10-20's conditions, which the schedule's mayRun stands for here); both CLOSURE
// orders against the roll-up (SEARCH-M10-17's eraser on the world's store, which takes no CLOSURE yet); a roll-up
// carrying a tombstone to a newer bucket (a version is promoted here); FI-19's and FI-20's checkers (TEST-M10-02's);
// and ApplyThenDrop on every write.

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
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

// When the bucket newFs75World holds expires: the end of the window after its own (§11.14's latest row), its windows
// 30 days and no bucket after it.
func fs75Expiry(t *testing.T, world *searchWorld) time.Time {
	t.Helper()
	windows, err := world.index.BucketWindows(t.Context())
	if err != nil || len(windows) == 0 {
		t.Fatalf("the world's buckets: %v, %v", windows, err)
	}
	return time.UnixMilli(int64(windows[0].StartDay+2*windows[0].Days) * 24 * 60 * 60 * 1000)
}

// Whether world's all equals want, file by file.
func fs75AllEqual(t *testing.T, world *searchWorld, want map[string][32]byte, label string) {
	t.Helper()
	got := fs75AllDigests(world)
	if len(got) != len(want) {
		t.Fatalf("%s: all holds %d files, the twin's %d", label, len(got), len(want))
	}
	for path, digest := range want {
		if got[path] != digest {
			t.Fatalf("%s: %s differs from the twin's", label, path)
		}
	}
	days, err := world.index.BucketStartDays(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if 1 < len(days) {
		t.Fatalf("%s: buckets %v stand", label, days)
	}
}

// A twin's all after one uninterrupted roll-up by an indexer.
func fs75TwinAll(t *testing.T, label string) map[string][32]byte {
	t.Helper()
	twin, _ := newFs75World(t, label)
	if version, err := twin.index.RollUp(t.Context(), searchId("indexer")); err != nil || version == 0 {
		t.Fatalf("the twin's roll-up: %d, %v", version, err)
	}
	return fs75AllDigests(twin)
}

// FS-75's runner clauses through SEARCH-M10-11's schedule: an indexer serving the repo for search rolls an expired
// bucket at once; with that indexer offline, a desktop writer rolls it only once it commits a day past the expiry;
// with no indexer the first desktop committing after the expiry rolls it, and a phone only where it may run, else it
// defers. Each ends in one roll-up equal to an uninterrupted twin's.
func TestFs75TheScheduleChoosesWhoRolls(t *testing.T) {
	want := fs75TwinAll(t, "roles")
	type role struct {
		label    string
		args     *sidecar.SearchTestUpkeepArgs
		early    time.Duration
		on       time.Duration
		mayRun   *bool
		runAfter bool
	}
	serving := func() bool { return true }
	mayRun := false
	roles := []*role{
		{label: "indexer", args: &sidecar.SearchTestUpkeepArgs{Device: sidecar.SearchTestUpkeepIndexer}},
		{label: "desktop beside an offline indexer", args: &sidecar.SearchTestUpkeepArgs{Device: sidecar.SearchTestUpkeepDesktop, IndexerServes: serving}, early: 23 * time.Hour, on: 25 * time.Hour},
		{label: "first desktop", args: &sidecar.SearchTestUpkeepArgs{Device: sidecar.SearchTestUpkeepDesktop}, early: -time.Hour, on: time.Minute},
		{label: "phone", args: &sidecar.SearchTestUpkeepArgs{Device: sidecar.SearchTestUpkeepPhone, MayRun: func() bool { return mayRun }}, early: time.Minute, on: time.Minute, mayRun: &mayRun},
	}
	for _, role := range roles {
		world, _ := newFs75World(t, "roles")
		ctx := t.Context()
		role.args.Self = searchId(role.label)
		upkeep, err := world.index.NewUpkeep(role.args)
		if err != nil {
			t.Fatal(err)
		}
		expiry := fs75Expiry(t, world)
		if role.args.Device != sidecar.SearchTestUpkeepIndexer {
			// a commit too early for this device's role, or a phone that may not run, rolls nothing
			upkeep.Committed(expiry.Add(role.early))
			if tick := upkeep.Tick(ctx); tick.RollUpRan || 0 < len(tick.Errs) {
				t.Fatalf("%s rolled up after a commit %s past the expiry: %+v", role.label, role.early, tick)
			}
			if role.mayRun != nil {
				*role.mayRun = true
			}
			upkeep.Committed(expiry.Add(role.on))
		}
		tick := upkeep.Tick(ctx)
		if tick.RolledUp == 0 || 0 < len(tick.Errs) {
			t.Fatalf("%s did not roll up: %+v", role.label, tick)
		}
		if again := upkeep.Tick(ctx); again.RolledUp != 0 || 0 < len(again.Errs) {
			t.Fatalf("%s rolled up twice: %+v", role.label, again)
		}
		fs75AllEqual(t, world, want, role.label)
		world.checkSearch(t, "marker0042")
		world.checkSearch(t, "lighthouse")
	}
}

// FS-75's lock clauses: an indexer returning mid-roll finds the lock held and waits; a holder that dies loses the lock
// at its expiry, another runner then building equal plaintext and committing, and the late holder's push is refused at
// the lock: one roll-up commits.
func TestFs75ALapsedRollerLosesItsLock(t *testing.T) {
	want := fs75TwinAll(t, "lapsed")
	world, clock := newFs75World(t, "lapsed")
	ctx := t.Context()
	a, b := searchId("runner a"), searchId("runner b")
	held, release := make(chan struct{}), make(chan struct{})
	once := sync.Once{}
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name != "evs.index.rollup.built" {
			return
		}
		first := false
		once.Do(func() { first = true })
		if first {
			close(held)
			<-release
		}
	}})
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	type rolled struct {
		result *sidecar.SearchTestRollUp
		err    error
	}
	late := make(chan rolled, 1)
	go func() {
		result, err := world.index.RollUpResult(context.Background(), a)
		late <- rolled{result: result, err: err}
	}()
	<-held
	if waiting, err := world.index.RollUpResult(ctx, b); err != nil || waiting.Skipped != "locked" || waiting.Version != 0 {
		t.Fatalf("a runner beside a held lock: %+v, %v", waiting, err)
	}
	// the holder is past its lock's term and grace
	clock.Advance(45 * time.Minute)
	taker, err := world.index.RollUpResult(ctx, b)
	if err != nil || taker.Version == 0 {
		t.Fatalf("a runner past a lapsed lock: %+v, %v", taker, err)
	}
	close(release)
	lost := <-late
	if lost.result == nil || lost.result.Version != 0 || (lost.err != nil && !errors.Is(lost.err, sidecar.ErrSearchTestLockLost)) {
		t.Fatalf("the lapsed holder: %+v, %v", lost.result, lost.err)
	}
	for path, digest := range taker.Content {
		if fs75IsAll(path) && lost.result.Content[path] != digest {
			t.Fatalf("the two runners built %s differently", path)
		}
	}
	fs75AllEqual(t, world, want, "after the lapsed lock")
	world.checkSearch(t, "marker0042")
}

// FS-75's search clause and FI-20's last: a search at every barrier of the roll-up merges the expired bucket until the
// roll-up commits, and finds what the oracle does before, during and after.
func TestFs75ASearchAtEveryBarrierMergesTheExpiredBucket(t *testing.T) {
	world, _ := newFs75World(t, "barriers")
	ctx := t.Context()
	queries := []string{"marker0042", "lighthouse"}
	want := map[string][]string{}
	for _, query := range queries {
		want[query] = world.checkSearch(t, query)
	}
	reached := []string{}
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if !strings.HasPrefix(name, "evs.index.rollup.") {
			return
		}
		reached = append(reached, name)
		for _, query := range queries {
			if hits := world.checkSearch(t, query); !slices.Equal(hits, want[query]) {
				t.Fatalf("at %s %q found %v, before %v", name, query, hits, want[query])
			}
		}
	}})
	version, err := world.index.RollUp(ctx, searchId("indexer"))
	sidecar.SetTestHooks(nil)
	if err != nil || version == 0 {
		t.Fatalf("the roll-up: %d, %v", version, err)
	}
	if !slices.Equal(reached, fs75Barriers) {
		t.Fatalf("the roll-up reached %v", reached)
	}
}

// FS-75's dropped answer: the roll-up's head CAS applies and its response is lost; the runner's rerun finds nothing to
// roll, and the one roll-up stands equal to an uninterrupted twin's.
func TestFs75ARollUpWhoseAnswerWasLostCommitsOnce(t *testing.T) {
	want := fs75TwinAll(t, "lost answer")
	world, _ := newFs75World(t, "lost answer")
	ctx := t.Context()
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name == "evs.index.rollup.uploaded" {
			world.index.LoseNextReply()
		}
	}})
	_, err := world.index.RollUp(ctx, searchId("indexer"))
	sidecar.SetTestHooks(nil)
	if !errors.Is(err, sidecar.ErrSearchTestReplyLost) {
		t.Fatalf("a roll-up whose answer was lost: %v", err)
	}
	rerun, err := world.index.RollUpResult(ctx, searchId("indexer"))
	if err != nil || rerun.Version != 0 {
		t.Fatalf("the rerun: %+v, %v", rerun, err)
	}
	fs75AllEqual(t, world, want, "after the lost answer")
	world.checkSearch(t, "lighthouse")
}

// FS-75's limit clause: at the storage limit the roll-up is refused, since it adds payload; the expired bucket stays
// and searches merge it until the network is under the limit, when the roll-up commits.
func TestFs75AtTheStorageLimitTheRollUpWaits(t *testing.T) {
	want := fs75TwinAll(t, "limit")
	world, clock := newFs75World(t, "limit")
	ctx := t.Context()
	world.index.SetStorageLimit(func(shape sidecar.SearchTestPushShape) bool { return 0 < shape.FileCount })
	if _, err := world.index.RollUp(ctx, searchId("indexer")); !errors.Is(err, sidecar.ErrSearchTestQuota) {
		t.Fatalf("a roll-up at the limit: %v", err)
	}
	days, err := world.index.BucketStartDays(ctx)
	if err != nil || len(days) != 1 {
		t.Fatalf("at the limit the buckets are %v: %v", days, err)
	}
	world.checkSearch(t, "marker0042")
	world.checkSearch(t, "lighthouse")
	world.index.SetStorageLimit(nil)
	// any lock it took lapses
	clock.Advance(45 * time.Minute)
	if version, err := world.index.RollUp(ctx, searchId("indexer")); err != nil || version == 0 {
		t.Fatalf("the roll-up under the limit: %d, %v", version, err)
	}
	fs75AllEqual(t, world, want, "under the limit")
	world.checkSearch(t, "marker0042")
}

// FS-75's window clause: an admin's new window applies from the next bucket, the open bucket keeping its own, and every
// document stays searchable.
func TestFs75AWindowChangeAppliesFromTheNextBucket(t *testing.T) {
	world, clock := newFsIndexWorld(t, "window")
	ctx := t.Context()
	a := searchId("writer a")
	now := clock.Now()
	first := fsIndexDocument("notes/harbor.md", 1, "harbor", now)
	if err := world.index.PushDocuments(ctx, a, now, []*sidecar.SearchTestDocument{first}); err != nil {
		t.Fatal(err)
	}
	if err := world.record(now, first); err != nil {
		t.Fatal(err)
	}
	if _, err := world.index.SetIndex(ctx, world.index.AdminId(), sidecar.EvsIndexWindow, 14); err != nil {
		t.Fatal(err)
	}
	if err := world.ledger.SetIndexSettings(world.index.RepoId(), world.index.RefId(), &sidecartest.SearchIndexSettings{WindowDays: 14}, now); err != nil {
		t.Fatal(err)
	}
	second := fsIndexDocument("notes/lighthouse.md", 1, "lighthouse", now)
	if err := world.index.PushDocuments(ctx, a, now, []*sidecar.SearchTestDocument{second}); err != nil {
		t.Fatal(err)
	}
	if err := world.record(now, second); err != nil {
		t.Fatal(err)
	}
	windows, err := world.index.BucketWindows(ctx)
	if err != nil || len(windows) != 1 || windows[0].Days != 30 {
		t.Fatalf("the open bucket after the change: %v, %v", windows, err)
	}
	boundary := time.UnixMilli(int64(windows[0].StartDay+windows[0].Days) * 24 * 60 * 60 * 1000)
	clock.Advance(boundary.Sub(now) + time.Hour)
	later := clock.Now()
	third := fsIndexDocument("notes/cormorant.md", 1, "cormorant", later)
	if err := world.index.PushDocuments(ctx, a, later, []*sidecar.SearchTestDocument{third}); err != nil {
		t.Fatal(err)
	}
	if err := world.record(later, third); err != nil {
		t.Fatal(err)
	}
	windows, err = world.index.BucketWindows(ctx)
	if err != nil || len(windows) != 2 || windows[0].Days != 30 || windows[1].Days != 14 || windows[1].StartDay != windows[0].StartDay+30 {
		t.Fatalf("the buckets past the change: %v, %v", windows, err)
	}
	for _, query := range []string{"harbor", "lighthouse", "cormorant"} {
		if hits := world.checkSearch(t, query); len(hits) != 1 {
			t.Fatalf("%q found %v", query, hits)
		}
	}
}

// A world in which a newer bucket holds an older version of a document than the bucket before it: writer b's push
// of version 2, planned in the older bucket before writer a's push of version 1 opened the newer one, commits after
// it, its files disjoint from a's. The clock is then past the older bucket's expiry and not the newer's. Answers the
// world, its clock, the newer bucket's start day and the phrase each version alone holds.
func newFs75PromotionWorld(t *testing.T, label string) (*searchWorld, *sidecartest.FakeClock, uint32) {
	t.Helper()
	world, clock := newFsIndexWorld(t, label)
	ctx := t.Context()
	a, b := searchId("writer a"), searchId("writer b")
	now := clock.Now()
	world.fillSeals(t, a, "older", 3, now)
	startDay := sidecar.SearchTestBucketStartDay(now)
	boundary := time.UnixMilli(int64(startDay+30) * 24 * 60 * 60 * 1000)
	clock.Advance(boundary.Sub(now) + time.Minute)
	behind := boundary.Add(-time.Minute)
	ahead := clock.Now()
	two := &sidecar.SearchTestDocument{Path: "notes/tide.md", Version: 2, Title: "Tide", Text: "the spring tide table", Time: behind}
	planned, err := world.index.PlanPush(ctx, b, behind, []*sidecar.SearchTestDocument{two})
	if err != nil {
		t.Fatal(err)
	}
	one := &sidecar.SearchTestDocument{Path: "notes/tide.md", Version: 1, Title: "Tide", Text: "the neap tide chart", Time: ahead}
	if err := world.index.PushDocuments(ctx, a, ahead, []*sidecar.SearchTestDocument{one}); err != nil {
		t.Fatal(err)
	}
	if err := world.record(ahead, one); err != nil {
		t.Fatal(err)
	}
	if _, err := planned.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := world.record(behind, two); err != nil {
		t.Fatal(err)
	}
	// sealed slots in the newer bucket, which a merge of it takes (a merge reads no head, R3)
	world.fillSeals(t, a, "newer", 160, ahead)
	windows, err := world.index.BucketWindows(ctx)
	if err != nil || len(windows) != 2 {
		t.Fatalf("the promotion world's buckets: %v, %v", windows, err)
	}
	// past the older bucket's expiry, the end of the newer one's window, and not the newer one's
	clock.Advance(time.UnixMilli(int64(windows[1].StartDay+windows[1].Days)*24*60*60*1000).Sub(clock.Now()) + time.Hour)
	return world, clock, windows[1].StartDay
}

// The digests of all's files and of the newer bucket's manifest and shards, which a promoting roll-up writes.
func fs75PromotionDigests(world *searchWorld, newer uint32) map[string][32]byte {
	digests := map[string][32]byte{}
	marker := fmt.Sprintf("/b/%d/", newer)
	for path, digest := range world.index.FileDigests() {
		if fs75IsAll(path) || (strings.Contains(path, marker) && fsIndexPathIsMerged(path)) {
			digests[path] = digest
		}
	}
	return digests
}

// FS-75's promotion clause (R4; DESIGN-DETAILS 1.7): a roll-up carrying a version above an older entry in a newer
// bucket writes it into that bucket's shards with its manifest; a merge of that bucket racing it, in both orders, makes
// one of the two build again on the other's result; and a promoting roll-up killed at each barrier ends, rerun, in one
// roll-up equal to an uninterrupted twin's. Searches find the newer version alone throughout.
func TestFs75APromotingRollUpRacesAMergeOfItsTarget(t *testing.T) {
	twin, _, newer := newFs75PromotionWorld(t, "promotion")
	alone, err := twin.index.RollUpResult(t.Context(), searchId("indexer"))
	if err != nil || alone.Version == 0 || !slices.Equal(alone.PromotedTo, []uint32{newer}) {
		t.Fatalf("a lone promoting roll-up: %+v, %v", alone, err)
	}
	if hits := twin.checkSearch(t, "spring tide"); len(hits) != 1 || hits[0] != "notes/tide.md@2" {
		t.Fatalf("after the promotion the newer version found %v", hits)
	}
	if hits := twin.checkSearch(t, "neap tide"); len(hits) != 0 {
		t.Fatalf("after the promotion the older version found %v", hits)
	}
	want := fs75PromotionDigests(twin, newer)

	for _, mergeFirst := range []bool{true, false} {
		world, _, _ := newFs75PromotionWorld(t, "promotion")
		ctx := t.Context()
		holdAt := "evs.index.rollup.built"
		if !mergeFirst {
			holdAt = "evs.index.merge.built"
		}
		held, release := make(chan struct{}), make(chan struct{})
		once := sync.Once{}
		sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
			if name != holdAt {
				return
			}
			first := false
			once.Do(func() { first = true })
			if first {
				close(held)
				<-release
			}
		}})
		type outcome struct {
			attempts int
			version  uint64
			err      error
		}
		heldDone := make(chan outcome, 1)
		go func() {
			if mergeFirst {
				result, err := world.index.RollUpResult(context.Background(), searchId("indexer"))
				heldDone <- outcome{attempts: result.Attempts, version: result.Version, err: err}
				return
			}
			result, err := world.index.MergeResult(context.Background(), searchId("merger"), newer)
			heldDone <- outcome{attempts: result.Attempts, version: result.Version, err: err}
		}()
		<-held
		var first outcome
		if mergeFirst {
			result, err := world.index.MergeResult(ctx, searchId("merger"), newer)
			first = outcome{attempts: result.Attempts, version: result.Version, err: err}
		} else {
			result, err := world.index.RollUpResult(ctx, searchId("indexer"))
			first = outcome{attempts: result.Attempts, version: result.Version, err: err}
		}
		close(release)
		second := <-heldDone
		sidecar.SetTestHooks(nil)
		if first.err != nil || first.version == 0 || first.attempts != 1 {
			t.Fatalf("merge first %v: the unheld one: %+v", mergeFirst, first)
		}
		if second.err != nil || second.version == 0 || second.attempts < 2 {
			t.Fatalf("merge first %v: the held one did not build again on the other's result: %+v", mergeFirst, second)
		}
		days, err := world.index.BucketStartDays(ctx)
		if err != nil || !slices.Equal(days, []uint32{newer}) {
			t.Fatalf("merge first %v: buckets %v, %v", mergeFirst, days, err)
		}
		if hits := world.checkSearch(t, "spring tide"); len(hits) != 1 || hits[0] != "notes/tide.md@2" {
			t.Fatalf("merge first %v: the newer version found %v", mergeFirst, hits)
		}
		if hits := world.checkSearch(t, "neap tide"); len(hits) != 0 {
			t.Fatalf("merge first %v: the older version found %v", mergeFirst, hits)
		}
	}

	for _, barrier := range fs75Barriers {
		world, clock, _ := newFs75PromotionWorld(t, "promotion")
		if !fs75RollKilledAt(t, world, searchId("indexer"), barrier) {
			t.Fatalf("the promoting roll-up never reached %s", barrier)
		}
		clock.Advance(45 * time.Minute)
		if _, err := world.index.RollUp(t.Context(), searchId("indexer")); err != nil {
			t.Fatalf("the rerun after %s: %v", barrier, err)
		}
		got := fs75PromotionDigests(world, newer)
		if len(got) != len(want) {
			t.Fatalf("killed at %s, %d files, the twin's %d", barrier, len(got), len(want))
		}
		for path, digest := range want {
			if got[path] != digest {
				t.Fatalf("killed at %s, %s differs from the twin's", barrier, path)
			}
		}
		if hits := world.checkSearch(t, "spring tide"); len(hits) != 1 {
			t.Fatalf("killed at %s, the newer version found %v", barrier, hits)
		}
	}
}

// FS-75's reproducer clauses (SEARCH-M10-21): a device holding a roll-up's inputs rebuilds it, holds every output to its
// content_sha256 and fetches nothing; the same roll-up signed before its bucket's expiry is index_mismatch at every
// reproducer.
func TestFs75AReproducerRebuildsTheRollUp(t *testing.T) {
	world, _ := newFs75World(t, "reproduce")
	ctx := t.Context()
	expiry := fs75Expiry(t, world)
	rolled, err := world.index.RollUpResult(ctx, searchId("indexer"))
	if err != nil || rolled.Version == 0 {
		t.Fatalf("the roll-up: %+v, %v", rolled, err)
	}
	reproduced, err := world.index.ReproducePush(ctx, rolled.Version, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if reproduced.Kind != "rollup" || len(reproduced.Fetch) != 0 || reproduced.Mismatches != 0 || reproduced.Lacking || len(reproduced.Matched) == 0 {
		t.Fatalf("a reproduction of the roll-up: %+v", reproduced)
	}
	early, err := world.index.ReproducePush(ctx, rolled.Version, expiry.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if early.Mismatches == 0 || len(early.Matched) != 0 {
		t.Fatalf("a roll-up signed before its bucket's expiry: %+v", early)
	}
}
