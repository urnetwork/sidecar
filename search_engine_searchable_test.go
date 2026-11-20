//go:build !ios_extension

package sidecar

// §16.10's merge row on the engine (§16.8's searchable row; FS-76, FS-87; QD-1104): a repo's searchable_days, which
// its scope gives as SearchableAge, masks its older documents from every search at query time, the buckets, the all a
// device holds and the shards "search more" lands alike, and a rise finds them again with nothing fetched or rebuilt.
// Before this, no mask the engine built was given the age, so a document past searchable_days was returned.

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The age that puts a search's cut halfway between two document times, at now.
func testSearchableAgeBetween(now time.Time, older time.Time, newer time.Time) time.Duration {
	return now.Sub(older.Add(newer.Sub(older) / 2))
}

// The cut is a whole second: a row a second short of it is masked, one at it is not, and an age of 0 or one reaching
// back to the epoch masks none.
func TestSearchSearchableSinceSeconds(t *testing.T) {
	cases := []struct {
		nowMs int64
		age   time.Duration
		want  uint64
	}{
		{nowMs: 100_000, age: 0, want: 0},
		{nowMs: 100_000, age: -time.Second, want: 0},
		{nowMs: 100_000, age: 100 * time.Second, want: 0},
		{nowMs: 100_000, age: 200 * time.Second, want: 0},
		{nowMs: 100_000, age: 40 * time.Second, want: 60},
		{nowMs: 100_500, age: 40 * time.Second, want: 61},
		{nowMs: 100_001, age: 40 * time.Second, want: 61},
	}
	for _, c := range cases {
		if got := searchSearchableSinceSeconds(c.nowMs, c.age); got != c.want {
			t.Errorf("at %d ms with age %s: %d, want %d", c.nowMs, c.age, got, c.want)
		}
	}
}

// Two documents of one bucket ten days apart: with no age both are found; with the cut between them only the newer,
// the older counted masked; raised past the older, both again, the cache read as it was, nothing fetched.
func TestSearchEngineMasksDocumentsPastTheScopesSearchableAge(t *testing.T) {
	world := newTestEngineWorld(t, nil, testEngineDocument(t, "doc", 1, 1, "notes/older.md", "Harbor survey\nthe older pass"))
	world.sync.head.at = world.sync.head.at.Add(10 * 24 * time.Hour)
	world.sync.head.push(t, evsTestId("writer"), testEngineDocument(t, "doc", 2, 1, "notes/newer.md", "Harbor survey\nthe newer pass"))
	world.sync.round(t)
	repo := world.scope.repos[0]

	hits, _ := world.all(t, &SearchRequest{Text: "survey"})
	if paths := testHitPaths(hits); !slices.Equal(paths, []string{"notes/newer.md", "notes/older.md"}) {
		t.Fatalf("with no age: %v", paths)
	}
	times := map[string]time.Time{}
	for _, hit := range hits {
		times[hit.Path] = hit.Time
	}
	now := world.sync.cache.clock.Now()
	fetched := len(world.sync.source.fetched())

	repo.SearchableAge = testSearchableAgeBetween(now, times["notes/older.md"], times["notes/newer.md"])
	hits, progress := world.all(t, &SearchRequest{Text: "survey"})
	if paths := testHitPaths(hits); !slices.Equal(paths, []string{"notes/newer.md"}) {
		t.Fatalf("with the cut between them: %v", paths)
	}
	if progress.Counts.Masked == 0 {
		t.Fatalf("the older document was not counted masked: %+v", progress.Counts)
	}

	repo.SearchableAge = now.Sub(times["notes/older.md"]) + 24*time.Hour
	hits, _ = world.all(t, &SearchRequest{Text: "survey"})
	if paths := testHitPaths(hits); !slices.Equal(paths, []string{"notes/newer.md", "notes/older.md"}) {
		t.Fatalf("raised past the older: %v", paths)
	}
	if now := len(world.sync.source.fetched()); now != fetched {
		t.Fatalf("the searches fetched %d index files", now-fetched)
	}
}

// all's rows are masked as the buckets' are: the shards "search more" lands while the age is set, which matchLanded
// masks with the cut taken at the search's open, and all once held, which the stream's own mask reads; a rise finds
// the masked shard's document from the cache with nothing fetched.
func TestSearchEngineMasksAllsRowsPastTheScopesSearchableAge(t *testing.T) {
	world := newTestSyncWorld(t, false)
	world.head.push(t, evsTestId("writer"), testEngineDocument(t, "doc", 1, 1, "notes/new.md", "harbor today"))
	testWriteTextAll(t, world, 3, func(n int, index int) string {
		if index == 0 {
			return fmt.Sprintf("harbor of shard %d", n)
		}
		return fmt.Sprintf("garden of shard %d", n)
	})
	world.round(t)
	engineWorld := newTestEngineWorldOver(t, world)
	repo := engineWorld.scope.repos[0]
	now := world.cache.clock.Now()
	// each all shard's documents are a day apart: the cut falls between shard 0's and shard 1's
	shardTime := func(n int) time.Time {
		return testDayTime(testSyncBucket-60+uint32(n), 0)
	}
	repo.SearchableAge = testSearchableAgeBetween(now, shardTime(0), shardTime(1))

	more, _ := engineWorld.all(t, &SearchRequest{Text: "harbor", Scope: SearchAll})
	want := []string{"notes/new.md", "old/1/0.md", "old/2/0.md"}
	if paths := testHitPaths(more); !slices.Equal(paths, want) {
		t.Fatalf("SearchAll as its shards landed, the cut past shard 0: %v", paths)
	}
	for _, hit := range more {
		if hit.Path != "notes/new.md" && hit.Partition != SearchPartitionAll {
			t.Fatalf("a hit of all from %v", hit.Partition)
		}
	}
	fetched := len(world.source.fetched())

	// all is held now: the stream's own mask reads it, the cut where it was
	cached, _ := engineWorld.all(t, &SearchRequest{Text: "harbor", Scope: SearchAll})
	if paths := testHitPaths(cached); !slices.Equal(paths, want) {
		t.Fatalf("SearchAll over the all it holds: %v", paths)
	}
	repo.SearchableAge = 0
	raised, _ := engineWorld.all(t, &SearchRequest{Text: "harbor", Scope: SearchAll})
	if paths := testHitPaths(raised); !slices.Equal(paths, []string{"notes/new.md", "old/0/0.md", "old/1/0.md", "old/2/0.md"}) {
		t.Fatalf("with no age: %v", paths)
	}
	if now := len(world.source.fetched()); now != fetched {
		t.Fatalf("the rise fetched %d index files", now-fetched)
	}
}

// An engine over world's cache and sync, a desktop's, its scope the world's repo alone.
func newTestEngineWorldOver(t *testing.T, world *testSyncWorld) *testEngineWorld {
	t.Helper()
	scope := &testSearchScope{repos: []*SearchScopeRepo{{
		RepoId: world.repoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL, Readable: true,
		Refs: []*SearchScopeRef{{RefId: world.refId, Default: true}},
	}}}
	policy := testNewSearchPolicy(t, world.cache.settings, nil, world.cache.clock, &SearchConditions{DaemonHost: true})
	engine, err := NewSearchEngine(&SearchEngineArgs{
		Settings: world.cache.settings, Cache: world.cache.cache, Sync: world.sync, Policy: policy, Scope: scope,
		Gkm: &evsTestReadGkm{newest: 1}, Clock: world.cache.clock, Log: NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	return &testEngineWorld{sync: world, scope: scope, engine: engine, policy: policy}
}
