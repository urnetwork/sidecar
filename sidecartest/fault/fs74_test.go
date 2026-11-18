//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-74 on T2 (§11.14's commit path, conflict, seal, bucket, coverage and merge rows; D-EVS-46, D-EVS-47, FI-18,
// FI-20; DESIGN-DETAILS 1.7's cases; SEARCH-M10-35): writers' heads on one ref, through the index's own planner,
// merger, backfiller, schedule and store on the search world (search_index_testhooks.go, search_content_testhooks.go),
// a desktop device's search held to SearchOracle's set after every step.
//
//	disjoint  two writers' pushes, each changing only its own head, land at v+1 and v+2, and both documents are found
//	race      one writer's two pushes planned at one base: one commits, the other gets 409 and its index code plans it
//	          again on the winner's head, so neither document is lost or entered twice
//	seal      one writer's two pushes on one base, one appending and one sealing its head, in both orders: one 409, a
//	          replan, every entry once, the seal opening one slot; and a head idle for days seals nothing
//	mergers   two mergers of one bucket's seals race: the one held at its built barrier finds its push refused, one
//	          merge commits, and the shards equal those a lone merger writes
//	boundary  a commit just past a bucket's end by its signed time writes its writer's first slot in the new bucket
//	skipped   a phone's push that skips the index reads not yet searchable until an indexer serving the repo
//	          backfills it, past BackfillAge and not before, a desktop beside that indexer leaving it; with none, the
//	          desktop does
//	reader    a reader syncing across a merge, at each of its barriers, and across a seal that reuses a slot the merge
//	          absorbed, finds the same set, a fresh one and one that synced before alike (DESIGN-DETAILS section 7)
//	large     a writer's large entry, absorbed by a merge that leaves it, is removed by the writer's next push
//
// Not here, each named for what it waits on: these on real engines and on T3 (pushes, merges and backfills through
// EvsRepo on evsservice, and a device's sync over EvsRepo, SEARCH-M10-19's source); a writer killed between its git push and its companion push (the search world is a file-mode ref: a
// companion world over a git-mode content ref and SEARCH-M10-14's journal); index_none (QD-209's field is not in
// evs.proto, so no push carries it); a user's versionless file never retried as an index 409 is (the in-ref writer's
// sender on EvsRepo); FI-20's checker and the ten explorer seeds a merge (TEST-M10-02's fault.FI(18) and FI(20), and
// DESIGN-DETAILS 1.6's explorer); and ApplyThenDrop on every write (the world's store drops no answer but where a
// schedule says).

import (
	"context"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A search world on a fake clock of its own, the oracle's ledger beside it.
func newFsIndexWorld(t *testing.T, label string) (*searchWorld, *sidecartest.FakeClock) {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	repoId, refId := searchId("fs index repo "+label), searchId("fs index ref "+label)
	index, err := sidecar.NewSearchTestWorld(&sidecar.SearchTestWorldArgs{RepoId: repoId, RefId: refId, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	world := &searchWorld{
		index: index, ledger: sidecartest.NewSearchLedger(), readByteCount: 32 * 1024 * 1024,
		readerId: searchId("fs index reader " + label), networkId: searchId("fs index network " + label),
		writerId: searchId("fs index writer " + label),
	}
	err = world.ledger.AddRepo(&sidecartest.SearchLedgerRepo{
		RepoId: repoId, NetworkId: world.networkId, Kind: protocol.RepoKind_REPO_KIND_GENERAL, DefaultRefId: refId,
		Key: index.RepoKey(), ReaderIds: []sidecar.Id{world.readerId},
	})
	if err != nil {
		t.Fatal(err)
	}
	world.oracle = sidecartest.NewSearchOracle(world.ledger)
	t.Cleanup(world.close)
	return world, clock
}

// A document of path at version, its text holding word.
func fsIndexDocument(path string, version uint64, word string, at time.Time) *sidecar.SearchTestDocument {
	return &sidecar.SearchTestDocument{Path: path, Version: version, Title: "Notes", Text: "the " + word + " at noon", Time: at}
}

// A fresh desktop device syncs the world and searches query: its hits must be the oracle's.
func (self *searchWorld) checkSearch(t *testing.T, query string) []string {
	t.Helper()
	ctx := t.Context()
	device, err := self.device(ctx, searchHostNamed("desktop"), nil, nil, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer self.done(device)
	if err := device.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	search, err := device.Search(ctx, &sidecar.SearchRequest{Text: query, Scope: sidecar.SearchAll, Remote: "off"}, 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	// near hits are the vocabulary's corrections (SEARCH-M10-25), which the oracle's exact set leaves out
	exact := []sidecar.SearchHit{}
	for _, hit := range search.Hits() {
		if hit.State != sidecar.SearchNear {
			exact = append(exact, hit)
		}
	}
	hits, oracle := searchHitNames(exact), self.oracleMatches(query)
	if !slices.Equal(hits, oracle) {
		t.Fatalf("a search for %q found %v, the oracle %v", query, hits, oracle)
	}
	return hits
}

// Two writers' pushes, each changing only its own head in the current bucket, land at v+1 and v+2, and both
// documents are found (FI-18).
func TestFs74DisjointHeadsLandAtSuccessiveVersions(t *testing.T) {
	world, clock := newFsIndexWorld(t, "disjoint")
	ctx := t.Context()
	now := clock.Now()
	a, b := searchId("writer a"), searchId("writer b")
	before, err := world.index.HeadVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first := fsIndexDocument("notes/harbor.md", 1, "harbor", now)
	second := fsIndexDocument("notes/lighthouse.md", 1, "lighthouse", now)
	if err := world.index.PushDocuments(ctx, a, now, []*sidecar.SearchTestDocument{first}); err != nil {
		t.Fatal(err)
	}
	if err := world.index.PushDocuments(ctx, b, now, []*sidecar.SearchTestDocument{second}); err != nil {
		t.Fatal(err)
	}
	after, err := world.index.HeadVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != before+2 {
		t.Fatalf("two pushes took the head from %d to %d", before, after)
	}
	if err := world.record(now, first, second); err != nil {
		t.Fatal(err)
	}
	if hits := world.checkSearch(t, "harbor"); len(hits) != 1 {
		t.Fatalf("harbor's hits %v", hits)
	}
	if hits := world.checkSearch(t, "lighthouse"); len(hits) != 1 {
		t.Fatalf("lighthouse's hits %v", hits)
	}
}

// One sidecar's two concurrent pushes race on its head: one commits, the other gets 409, and planned again on the
// winner's head it lands, so neither document is lost or entered twice.
func TestFs74RacingPushesOnOneHead(t *testing.T) {
	world, clock := newFsIndexWorld(t, "race")
	ctx := t.Context()
	now := clock.Now()
	a := searchId("writer a")
	first := fsIndexDocument("notes/harbor.md", 1, "harbor", now)
	second := fsIndexDocument("notes/lighthouse.md", 1, "lighthouse", now)
	planFirst, err := world.index.PlanPush(ctx, a, now, []*sidecar.SearchTestDocument{first})
	if err != nil {
		t.Fatal(err)
	}
	planSecond, err := world.index.PlanPush(ctx, a, now, []*sidecar.SearchTestDocument{second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := planFirst.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := planSecond.Commit(ctx); err != sidecar.ErrSearchTestConflict {
		t.Fatalf("the losing push: %v", err)
	}
	// its index code plans it again on the winner's head
	again, err := world.index.PlanPush(ctx, a, now, []*sidecar.SearchTestDocument{second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	live, err := world.index.LiveDocKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range []*sidecar.SearchTestDocument{first, second} {
		key, err := world.index.DocKey(document.Path)
		if err != nil {
			t.Fatal(err)
		}
		if live[key] != document.Version {
			t.Fatalf("%s is live at %d", document.Path, live[key])
		}
	}
	if err := world.record(now, first, second); err != nil {
		t.Fatal(err)
	}
	world.checkSearch(t, "harbor")
	world.checkSearch(t, "lighthouse")
}

// Fills writer's head until it seals: documents a push, each its own word, recorded in the ledger.
func (self *searchWorld) fillSeals(t *testing.T, writer sidecar.Id, label string, count int, at time.Time) {
	t.Helper()
	ctx := t.Context()
	for index := range count {
		document := &sidecar.SearchTestDocument{
			Path: fmt.Sprintf("notes/%s-%d.md", label, index), Version: 1, Title: "Fill",
			Text: fmt.Sprintf("filler %s marker%04d with enough words to take room in a slot", label, index), Time: at,
		}
		if err := self.index.PushDocuments(ctx, writer, at, []*sidecar.SearchTestDocument{document}); err != nil {
			t.Fatal(err)
		}
		if err := self.record(at, document); err != nil {
			t.Fatal(err)
		}
	}
}

// Two mergers of one bucket's seals race: one held at its built barrier while the other commits finds its push
// refused and commits nothing, one merge stands, and the shards are those a lone merger of the same seals writes.
func TestFs74TwoMergersRace(t *testing.T) {
	world, clock := newFsIndexWorld(t, "mergers")
	twin, twinClock := newFsIndexWorld(t, "mergers")
	ctx := t.Context()
	a := searchId("writer a")
	world.fillSeals(t, a, "seal", 160, clock.Now())
	twin.fillSeals(t, a, "seal", 160, twinClock.Now())
	if _, err := twin.index.Merge(ctx, searchId("merger 1"), 0); err != nil {
		t.Fatal(err)
	}

	held, release := make(chan struct{}), make(chan struct{})
	once := sync.Once{}
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name != "evs.index.merge.built" {
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
	type merged struct {
		version uint64
		err     error
	}
	heldResult := make(chan merged, 1)
	go func() {
		version, err := world.index.Merge(context.Background(), searchId("merger 1"), 0)
		heldResult <- merged{version: version, err: err}
	}()
	<-held
	winner, err := world.index.Merge(ctx, searchId("merger 2"), 0)
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	loser := <-heldResult
	if winner == 0 {
		t.Fatal("the merger that was not held committed nothing")
	}
	if loser.err == nil && loser.version != 0 {
		t.Fatalf("both mergers committed: %d and %d", winner, loser.version)
	}
	digests, twinDigests := world.index.FileDigests(), twin.index.FileDigests()
	for path, digest := range twinDigests {
		if !fsIndexPathIsMerged(path) {
			continue
		}
		if digests[path] != digest {
			t.Fatalf("the raced merge's %s differs from a lone merger's", path)
		}
	}
	twin.checkSearch(t, "marker0007")
	world.checkSearch(t, "marker0007")
	world.checkSearch(t, "seal 7")
}

// Whether path is a bucket's manifest b/<S>/m or one of its shards b/<S>/<n>, which a merge writes, rather than a
// writer's slot under b/<S>/w/.
func fsIndexPathIsMerged(path string) bool {
	parts := strings.Split(path, "/")
	for index, part := range parts {
		if part == "b" && index+2 < len(parts) {
			return parts[index+2] != "w"
		}
	}
	return false
}

// A device's exact hits for query, synced first: what a reader holding one version of the ref finds.
func (self *searchWorld) searchOn(t *testing.T, device *sidecar.SearchTestDevice, query string) []string {
	t.Helper()
	ctx := t.Context()
	if err := device.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	search, err := device.Search(ctx, &sidecar.SearchRequest{Text: query, Scope: sidecar.SearchAll, Remote: "off"}, 4096, nil)
	if err != nil {
		t.Fatal(err)
	}
	exact := []sidecar.SearchHit{}
	for _, hit := range search.Hits() {
		if hit.State != sidecar.SearchNear {
			exact = append(exact, hit)
		}
	}
	return searchHitNames(exact)
}

// A document of count random CJK ideographs from seed: a key set as wide as its length, which no ASCII query's
// trigrams meet, so it is a candidate for no other document's word. Its first four ideographs are a phrase that finds it.
func fs74IdeographDocument(path string, version uint64, count int, seed int64, at time.Time) (*sidecar.SearchTestDocument, string) {
	random := rand.New(rand.NewSource(seed))
	text := []rune{}
	for range count {
		text = append(text, rune(0x4E00+random.Intn(0x9FA5-0x4E00)))
	}
	return &sidecar.SearchTestDocument{Path: path, Version: version, Title: "Ideographs", Text: string(text), Time: at}, string(text[:4])
}

// FS-74's seal clause with DESIGN-DETAILS 1.7's two pushes: one sidecar's two pushes planned on one base, one
// appending to its head and one sealing it, in both orders: the first commits, the second gets 409 and, planned again
// on the winner's head, lands, every entry once, the seal opening one slot; and a head seals only past 16,208 B, never
// on idle.
func TestFs74AppendAndSealRaceOnOneHead(t *testing.T) {
	slotMax := sidecar.DefaultIndexFormatSettings().SlotMaxByteCount
	for _, sealFirst := range []bool{false, true} {
		world, clock := newFsIndexWorld(t, fmt.Sprintf("seal first %v", sealFirst))
		ctx := t.Context()
		a := searchId("writer a")
		// a's head filled until it has less room than the sealing push's entry and more than the appending one's
		for index := 0; ; index += 1 {
			files, err := world.index.WriterFiles(ctx, a, 0)
			if err != nil {
				t.Fatal(err)
			}
			if files.Head != "" && slotMax-files.HeadByteCount < 1200 {
				break
			}
			world.fillSeals(t, a, fmt.Sprintf("fill%d", index), 1, clock.Now())
		}
		// idle: two days on, in the same bucket, a small push appends to the head
		idle, err := world.index.WriterFiles(ctx, a, 0)
		if err != nil {
			t.Fatal(err)
		}
		clock.Advance(2 * 24 * time.Hour)
		now := clock.Now()
		if 30*24*time.Hour <= now.Sub(time.UnixMilli(int64(idle.StartDay)*24*60*60*1000)) {
			t.Fatal("the idle wait left the bucket")
		}
		pause := &sidecar.SearchTestDocument{Path: "notes/pause.md", Version: 1, Title: "Pause", Text: "a pause", Time: now}
		if err := world.index.PushDocuments(ctx, a, now, []*sidecar.SearchTestDocument{pause}); err != nil {
			t.Fatal(err)
		}
		if err := world.record(now, pause); err != nil {
			t.Fatal(err)
		}
		before, err := world.index.WriterFiles(ctx, a, 0)
		if err != nil {
			t.Fatal(err)
		}
		if before.Head != idle.Head || len(before.Slots) != len(idle.Slots) {
			t.Fatalf("an idle head sealed: %s with %d slots, then %s with %d", idle.Head, len(idle.Slots), before.Head, len(before.Slots))
		}

		small := &sidecar.SearchTestDocument{Path: "notes/tern.md", Version: 1, Title: "Tern", Text: "a tern", Time: now}
		wide, phrase := fs74IdeographDocument("notes/wide.md", 1, 500, 7, now)
		planSmall, err := world.index.PlanPush(ctx, a, now, []*sidecar.SearchTestDocument{small})
		if err != nil {
			t.Fatal(err)
		}
		planWide, err := world.index.PlanPush(ctx, a, now, []*sidecar.SearchTestDocument{wide})
		if err != nil {
			t.Fatal(err)
		}
		first, second, again := planSmall, planWide, wide
		if sealFirst {
			first, second, again = planWide, planSmall, small
		}
		if _, err := first.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := second.Commit(ctx); err != sidecar.ErrSearchTestConflict {
			t.Fatalf("the second of two pushes on one head: %v", err)
		}
		replanned, err := world.index.PlanPush(ctx, a, now, []*sidecar.SearchTestDocument{again})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := replanned.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		after, err := world.index.WriterFiles(ctx, a, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(after.Slots) != len(before.Slots)+1 || after.Head == before.Head {
			t.Fatalf("the seal left %d slots from %d, head %s from %s", len(after.Slots), len(before.Slots), after.Head, before.Head)
		}
		live, err := world.index.LiveDocKeys(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, document := range []*sidecar.SearchTestDocument{small, wide, pause} {
			key, err := world.index.DocKey(document.Path)
			if err != nil {
				t.Fatal(err)
			}
			if live[key] != document.Version {
				t.Fatalf("%s is live at %d", document.Path, live[key])
			}
		}
		if err := world.record(now, small, wide); err != nil {
			t.Fatal(err)
		}
		world.checkSearch(t, "tern")
		world.checkSearch(t, phrase)
		world.checkSearch(t, "pause")
	}
}

// FS-74's bucket clause: a commit just past a bucket's end by its signed time writes its writer's first slot in the
// new current bucket, and both documents are found.
func TestFs74ACommitPastABucketBoundaryOpensTheNewBucket(t *testing.T) {
	world, clock := newFsIndexWorld(t, "boundary")
	ctx := t.Context()
	a := searchId("writer a")
	now := clock.Now()
	first := fsIndexDocument("notes/harbor.md", 1, "harbor", now)
	if err := world.index.PushDocuments(ctx, a, now, []*sidecar.SearchTestDocument{first}); err != nil {
		t.Fatal(err)
	}
	startDay := sidecar.SearchTestBucketStartDay(now)
	windows, err := world.index.BucketWindows(ctx)
	if err != nil || len(windows) != 1 || windows[0].StartDay != startDay {
		t.Fatalf("the first push's bucket: %v, %v", windows, err)
	}
	boundary := time.UnixMilli(int64(startDay+windows[0].Days) * 24 * 60 * 60 * 1000)
	clock.Advance(boundary.Sub(now) + time.Millisecond)
	past := clock.Now()
	second := fsIndexDocument("notes/lighthouse.md", 1, "lighthouse", past)
	if err := world.index.PushDocuments(ctx, a, past, []*sidecar.SearchTestDocument{second}); err != nil {
		t.Fatal(err)
	}
	windows, err = world.index.BucketWindows(ctx)
	if err != nil || len(windows) != 2 || windows[1].StartDay != startDay+windows[0].Days {
		t.Fatalf("buckets past the boundary: %v, %v", windows, err)
	}
	files, err := world.index.WriterFiles(ctx, a, windows[1].StartDay)
	if err != nil || len(files.Slots) != 1 || files.Head != files.Slots[0].Path || !strings.HasSuffix(files.Head, "/0") {
		t.Fatalf("the writer's files in the new bucket: %+v, %v", files, err)
	}
	if err := world.record(now, first); err != nil {
		t.Fatal(err)
	}
	if err := world.record(past, second); err != nil {
		t.Fatal(err)
	}
	world.checkSearch(t, "harbor")
	world.checkSearch(t, "lighthouse")
}

// FS-74's skipped-index clause: a commit from a client that skips the index, a phone or an old client, reads not yet
// searchable until an indexer serving the repo for search backfills it, which a desktop beside that indexer leaves
// alone, and none backfills before BackfillAge; with no indexer the next capable writer, a desktop, does.
func TestFs74ASkippedIndexIsBackfilled(t *testing.T) {
	world := newFs79World(t, "fs74 backfill", protocol.RepoKind_REPO_KIND_GENERAL)
	ctx := t.Context()
	a, phone := searchId("writer a"), searchId("phone")
	world.commitIndexed(t, a, fs79Change("notes/harbor.md", "the harbor at noon"))
	world.clock.Advance(time.Minute)
	world.commitContent(t, phone, fs79Change("notes/tern.md", "a tern over the pier"))
	if searched := world.checkSearch(t, "tern"); searched.uncovered != 1 {
		t.Fatalf("a skipped push before any backfill: %d uncovered", searched.uncovered)
	}
	world.checkSearch(t, "harbor")

	serves := true
	indexer, err := world.index.NewUpkeep(&sidecar.SearchTestUpkeepArgs{Device: sidecar.SearchTestUpkeepIndexer, Self: searchId("indexer"), Backfill: true})
	if err != nil {
		t.Fatal(err)
	}
	desktop, err := world.index.NewUpkeep(&sidecar.SearchTestUpkeepArgs{
		Device: sidecar.SearchTestUpkeepDesktop, Self: searchId("desktop"), IndexerServes: func() bool { return serves }, Backfill: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tick := func(upkeep *sidecar.SearchTestUpkeep) {
		t.Helper()
		if result := upkeep.Tick(ctx); 0 < len(result.Errs) {
			t.Fatalf("a tick: %v", result.Errs)
		}
	}
	unindexed := func() int {
		t.Helper()
		_, count, err := world.index.Coverage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return count
	}
	// younger than BackfillAge: nobody backfills
	world.clock.Advance(5 * time.Minute)
	tick(indexer)
	if count := unindexed(); count != 1 {
		t.Fatalf("a backfill before its age: %d unindexed", count)
	}
	world.clock.Advance(6 * time.Minute)
	// a desktop beside an indexer serving the repo leaves it to that indexer
	tick(desktop)
	if count := unindexed(); count != 1 {
		t.Fatalf("a desktop beside a serving indexer backfilled: %d unindexed", count)
	}
	tick(indexer)
	through, count, err := world.index.Coverage(ctx)
	if err != nil || count != 0 {
		t.Fatalf("after the indexer's backfill: %d unindexed, %v", count, err)
	}
	world.cover(t, through)
	if searched := world.checkSearch(t, "tern"); searched.uncovered != 0 || len(searched.hits) != 1 {
		t.Fatalf("after the backfill tern found %v, %d uncovered", searched.hits, searched.uncovered)
	}

	// with no indexer, the next capable writer, a desktop, backfills
	serves = false
	world.clock.Advance(time.Minute)
	world.commitContent(t, phone, fs79Change("notes/cormorant.md", "a cormorant on the rail"))
	if searched := world.checkSearch(t, "cormorant"); searched.uncovered != 1 {
		t.Fatalf("a skipped push above the horizon: %d uncovered", searched.uncovered)
	}
	world.clock.Advance(11 * time.Minute)
	tick(desktop)
	through, count, err = world.index.Coverage(ctx)
	if err != nil || count != 0 {
		t.Fatalf("after the desktop's backfill: %d unindexed, %v", count, err)
	}
	world.cover(t, through)
	if searched := world.checkSearch(t, "cormorant"); searched.uncovered != 0 || len(searched.hits) != 1 {
		t.Fatalf("after the desktop's backfill cormorant found %v, %d uncovered", searched.hits, searched.uncovered)
	}
	world.checkSearch(t, "harbor")
}

// FS-74's reader clause (DESIGN-DETAILS section 7) and FI-18's: a reader syncing across a merge and a slot's reuse
// holds one version of the ref at every barrier. At each of the merge's barriers a fresh device and one that synced
// before the merge find what the oracle does, and after the writer's next seal takes a slot the merge absorbed, both
// find the same again: a merge and a slot's reuse change no result set.
func TestFs74AReaderAcrossAMergeAndASlotReuse(t *testing.T) {
	world, clock := newFsIndexWorld(t, "reader")
	ctx := t.Context()
	a := searchId("writer a")
	world.fillSeals(t, a, "seal", 160, clock.Now())
	early, err := world.device(ctx, searchHostNamed("desktop"), nil, nil, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	queries := []string{"marker0007", "marker0151"}
	want := map[string][]string{}
	for _, query := range queries {
		want[query] = world.checkSearch(t, query)
		if hits := world.searchOn(t, early, query); !slices.Equal(hits, want[query]) {
			t.Fatalf("before the merge %q found %v, the oracle %v", query, hits, want[query])
		}
	}
	reached := []string{}
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if !strings.HasPrefix(name, "evs.index.merge.") {
			return
		}
		reached = append(reached, name)
		for _, query := range queries {
			if hits := world.checkSearch(t, query); !slices.Equal(hits, want[query]) {
				t.Fatalf("at %s a fresh reader's %q found %v, before %v", name, query, hits, want[query])
			}
			if hits := world.searchOn(t, early, query); !slices.Equal(hits, want[query]) {
				t.Fatalf("at %s an earlier reader's %q found %v, before %v", name, query, hits, want[query])
			}
		}
	}})
	merged, err := world.index.Merge(ctx, searchId("merger"), 0)
	sidecar.SetTestHooks(nil)
	if err != nil || merged == 0 {
		t.Fatalf("the merge: %d, %v", merged, err)
	}
	if !slices.Equal(reached, []string{"evs.index.merge.built", "evs.index.merge.uploaded", "evs.index.merge.pushed"}) {
		t.Fatalf("the merge reached %v", reached)
	}

	// a's next seal takes a slot the merge absorbed
	absorbed, err := world.index.WriterFiles(ctx, a, 0)
	if err != nil {
		t.Fatal(err)
	}
	slotVersions := map[string]uint64{}
	for _, slot := range absorbed.Slots {
		if slot.Path != absorbed.Head {
			slotVersions[slot.Path] = slot.Version
		}
	}
	reused := ""
	for index := 0; reused == "" && index < 200; index += 1 {
		world.fillSeals(t, a, fmt.Sprintf("after%d", index), 1, clock.Now())
		files, err := world.index.WriterFiles(ctx, a, 0)
		if err != nil {
			t.Fatal(err)
		}
		if version, ok := slotVersions[files.Head]; ok && files.Head != absorbed.Head {
			for _, slot := range files.Slots {
				if slot.Path == files.Head && version < slot.Version {
					reused = files.Head
				}
			}
		}
	}
	if reused == "" {
		t.Fatal("no seal took an absorbed slot")
	}
	for _, query := range queries {
		if hits := world.checkSearch(t, query); !slices.Equal(hits, want[query]) {
			t.Fatalf("after the reuse of %s a fresh reader's %q found %v, before %v", reused, query, hits, want[query])
		}
		if hits := world.searchOn(t, early, query); !slices.Equal(hits, want[query]) {
			t.Fatalf("after the reuse of %s the earlier reader's %q found %v, before %v", reused, query, hits, want[query])
		}
	}
	world.checkSearch(t, "after3")
}

// DESIGN-DETAILS 1.7's FS-74 case: a writer's large entry, which a merge absorbs and leaves in place, is removed by the
// writer's next push, its document still found, now from the bucket's shards.
func TestFs74AWritersReturnRemovesItsAbsorbedLargeEntries(t *testing.T) {
	world, clock := newFsIndexWorld(t, "large")
	ctx := t.Context()
	a := searchId("writer a")
	now := clock.Now()
	large, phrase := fs74IdeographDocument("notes/atlas.md", 1, 4000, 11, now)
	if err := world.index.PushDocuments(ctx, a, now, []*sidecar.SearchTestDocument{large}); err != nil {
		t.Fatal(err)
	}
	if err := world.record(now, large); err != nil {
		t.Fatal(err)
	}
	files, err := world.index.WriterFiles(ctx, a, 0)
	if err != nil || len(files.Large) != 1 {
		t.Fatalf("the writer's large entries: %+v, %v", files, err)
	}
	world.checkSearch(t, phrase)
	if merged, err := world.index.Merge(ctx, searchId("merger"), 0); err != nil || merged == 0 {
		t.Fatalf("the merge: %d, %v", merged, err)
	}
	if files, err := world.index.WriterFiles(ctx, a, 0); err != nil || len(files.Large) != 1 {
		t.Fatalf("a merge removed a writer's file: %+v, %v", files, err)
	}
	shard, err := world.index.ShardHolding(large.Path)
	if err != nil || !strings.Contains(shard, "/b/") {
		t.Fatalf("the merge left the large entry out of the shards: %q, %v", shard, err)
	}
	back := fsIndexDocument("notes/harbor.md", 1, "harbor", now)
	if err := world.index.PushDocuments(ctx, a, now, []*sidecar.SearchTestDocument{back}); err != nil {
		t.Fatal(err)
	}
	if err := world.record(now, back); err != nil {
		t.Fatal(err)
	}
	if files, err := world.index.WriterFiles(ctx, a, 0); err != nil || len(files.Large) != 0 {
		t.Fatalf("the writer's return kept its absorbed large entry: %+v, %v", files, err)
	}
	world.checkSearch(t, phrase)
	world.checkSearch(t, "harbor")
}
