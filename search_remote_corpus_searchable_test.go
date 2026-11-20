//go:build !sidecar_http && !ios_extension

package sidecar

// §11.14's serve row on the engine's corpus (§16.8; QD-1104): an indexer serving a remote search masks a repo's
// documents past its searchable_days as a local search does, with the cut its scope gives at the view's open, and a
// rise serves them again. Before this the served refs' masks were given no age.

import (
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The locators a view of the world's repo serves from its index for query, every page.
func testRemoteCorpusLocators(t *testing.T, world *testEngineWorld, query string) []string {
	t.Helper()
	corpus := newSearchEngineRemoteCorpus(world.engine, nil)
	view, rows, err := corpus.Open(t.Context(), &searchRemoteQuery{text: query}, []searchRemoteRefAsk{{repoId: world.sync.repoId}})
	if err != nil {
		t.Fatal(err)
	}
	defer view.Close()
	if len(rows) != 1 || rows[0].served != protocol.SearchServed_SERVED_INDEX {
		t.Fatalf("the repo's row: %+v", rows)
	}
	locators := []string{}
	for range 100 {
		hits, done, err := view.Tail(t.Context(), 50)
		if err != nil {
			t.Fatal(err)
		}
		for _, hit := range hits {
			locators = append(locators, hit.GetLocator())
		}
		if done {
			slices.Sort(locators)
			return locators
		}
	}
	t.Fatal("the view's tail never ended")
	return nil
}

// Two documents ten days apart: served both with no age, the newer alone with the cut between them, both again once
// the age is raised past the older.
func TestSearchRemoteCorpusMasksDocumentsPastTheScopesSearchableAge(t *testing.T) {
	world := newTestEngineWorld(t, nil, testEngineDocument(t, "doc", 1, 1, "notes/older.md", "Harbor survey\nthe older pass"))
	world.sync.head.at = world.sync.head.at.Add(10 * 24 * time.Hour)
	world.sync.head.push(t, evsTestId("writer"), testEngineDocument(t, "doc", 2, 1, "notes/newer.md", "Harbor survey\nthe newer pass"))
	world.sync.round(t)
	repo := world.scope.repos[0]

	hits, _ := world.all(t, &SearchRequest{Text: "survey"})
	times := map[string]time.Time{}
	for _, hit := range hits {
		times[hit.Path] = hit.Time
	}
	if len(times) != 2 {
		t.Fatalf("the local search found %v", testHitPaths(hits))
	}
	if served := testRemoteCorpusLocators(t, world, "survey"); !slices.Equal(served, []string{"notes/newer.md", "notes/older.md"}) {
		t.Fatalf("with no age: %v", served)
	}
	now := world.sync.cache.clock.Now()
	repo.SearchableAge = testSearchableAgeBetween(now, times["notes/older.md"], times["notes/newer.md"])
	if served := testRemoteCorpusLocators(t, world, "survey"); !slices.Equal(served, []string{"notes/newer.md"}) {
		t.Fatalf("with the cut between them: %v", served)
	}
	repo.SearchableAge = now.Sub(times["notes/older.md"]) + 24*time.Hour
	if served := testRemoteCorpusLocators(t, world, "survey"); !slices.Equal(served, []string{"notes/newer.md", "notes/older.md"}) {
		t.Fatalf("raised past the older: %v", served)
	}
}
