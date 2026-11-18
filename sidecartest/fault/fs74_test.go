//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-74 on T2 (§11.14's commit path, conflict and seal rows; D-EVS-46, D-EVS-47, FI-18, FI-20; SEARCH-M10-35): writers'
// heads on one ref, through the index's own planner, merger and store on the search world (search_index_testhooks.go),
// a desktop device's search held to SearchOracle's set after every step.
//
//	disjoint  two writers' pushes, each changing only its own head, land at v+1 and v+2, and both documents are found
//	race      one writer's two pushes planned at one base: one commits, the other gets 409 and its index code plans it
//	          again on the winner's head, so neither document is lost or entered twice
//	mergers   two mergers of one bucket's seals race: the one held at its built barrier finds its push refused, one
//	          merge commits, and the shards equal those a lone merger writes
//
// Not here yet, each named for what it waits on: a seal racing the writer's next commit at 16,208 B (a world push that
// seals mid-race); a writer killed between its git push and its companion push and a client that skips the index
// (SEARCH-M10-13's in-ref writer and SEARCH-M10-14's journal on a world with content); the bucket boundary, index_none
// and a reader across a merge and a slot's reuse at every barrier (DESIGN-DETAILS section 7's sync); FI-20's checker;
// ten explorer seeds a merge; and T3 (server's handlers, fs74_t3_test.go).

import (
	"context"
	"fmt"
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
