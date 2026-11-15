//go:build !ios_extension

package sidecar

// SEARCH-M10-26 (§16.10; FS-80's scope and exclusion cases at unit level, on the sync engine's fake): a search finds
// what the cache holds through the kept records' wrapped keys and never reads evs; repo and network breadth and every
// exclusion; a receipt that cannot land skipping its repo; cursor_expired after an erasure ends the snapshot; a third
// search of a session busy once its wait ends; too_broad; pages within Search.PageByteCount; forged and foreign cursors
// refused (§22.6's cursor target); phase 2 over all as "search more" lands each shard; the candidate iterator after a
// watermark; and no query canary in anything stored.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A scope source answering repos as given.
type testSearchScope struct {
	repos []*SearchScopeRepo
}

func (self *testSearchScope) Repos(ctx context.Context) ([]*SearchScopeRepo, error) {
	return self.repos, nil
}

// A live document of label index whose key set and row are text's, as extractor 1 gives a file's: its trigrams over
// the normalized, space-padded text, and its path and title in the row.
func testEngineDocument(t *testing.T, label string, index int, version uint64, path string, text string) *indexPendingDocument {
	t.Helper()
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizer.normalize([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	keys := indexSortedKeys(indexTrigrams([]byte(" " + string(normalized) + " ")))
	row := &indexRow{docKind: indexDocFile, byteCount: uint64(len(text)), trigramCount: uint64(len(keys)), locator: path}
	row.fields[indexFieldTitle] = strings.SplitN(text, "\n", 2)[0]
	replaces := uint64(0)
	if 1 < version {
		replaces = version - 1
	}
	return &indexPendingDocument{kind: indexEntryFull, key: testIndexId(label, index), version: version, replaces: replaces, keys: keys, row: row}
}

// A sync world whose ref holds documents, synced, and an engine over its cache.
type testEngineWorld struct {
	sync   *testSyncWorld
	scope  *testSearchScope
	engine *SearchEngine
	policy *SearchPolicy
}

func newTestEngineWorld(t *testing.T, tune func(settings *SidecarSearchSettings), documents ...*indexPendingDocument) *testEngineWorld {
	t.Helper()
	world := newTestSyncWorld(t, true)
	if 0 < len(documents) {
		world.head.push(t, evsTestId("writer"), documents...)
	}
	world.round(t)
	settings := world.cache.settings
	if tune != nil {
		tune(settings)
	}
	scope := &testSearchScope{repos: []*SearchScopeRepo{{
		RepoId: world.repoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL, Readable: true,
		Refs: []*SearchScopeRef{{RefId: world.refId, Default: true}},
	}}}
	policy := testNewSearchPolicy(t, settings, nil, world.cache.clock, &SearchConditions{DaemonHost: true})
	engine, err := NewSearchEngine(&SearchEngineArgs{
		Settings: settings, Cache: world.cache.cache, Sync: world.sync, Policy: policy, Scope: scope,
		Gkm: &evsTestReadGkm{newest: 1}, Clock: world.cache.clock, Log: NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	return &testEngineWorld{sync: world, scope: scope, engine: engine, policy: policy}
}

// Every hit of a search, page by page, and the last progress.
func (self *testEngineWorld) all(t *testing.T, request *SearchRequest) ([]SearchHit, SearchProgress) {
	t.Helper()
	stream, err := self.engine.Search(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	hits := []SearchHit{}
	var progress SearchProgress
	for range 1000 {
		page, pageProgress, done, err := stream.Next()
		if err != nil {
			t.Fatal(err)
		}
		hits = append(hits, page...)
		progress = pageProgress
		if done {
			return hits, progress
		}
	}
	t.Fatal("a search never finished")
	return nil, progress
}

// The paths of hits, sorted.
func testHitPaths(hits []SearchHit) []string {
	paths := []string{}
	for _, hit := range hits {
		paths = append(paths, hit.Path)
	}
	slices.Sort(paths)
	return paths
}

// A search finds the documents holding the query in the buckets the sync engine kept, reading each kept record
// through its wrapped key and gkm's RK_g alone, and reads nothing of evs; a document without the query is no hit.
func TestSearchEngineFindsWhatTheCacheHolds(t *testing.T) {
	world := newTestEngineWorld(t, nil,
		testEngineDocument(t, "doc", 1, 1, "notes/harbor.md", "Harbor lights at the evening ferry\nthe schedule for the harbor"),
		testEngineDocument(t, "doc", 2, 1, "notes/garden.md", "Garden notes\nbeans and tomatoes"),
		testEngineDocument(t, "doc", 3, 1, "notes/ferry.md", "Ferry timetable\nthe harbor ferry leaves at noon"),
	)
	fetchesBefore := len(world.sync.source.fetched())
	hits, progress := world.all(t, &SearchRequest{Text: "harbor"})
	if paths := testHitPaths(hits); !slices.Equal(paths, []string{"notes/ferry.md", "notes/harbor.md"}) {
		t.Fatalf("hits %v", paths)
	}
	for _, hit := range hits {
		if hit.Repo != world.sync.repoId || hit.Ref != world.sync.refId || hit.Partition != SearchPartitionLatest || hit.Version != 1 {
			t.Fatalf("a hit %+v", hit)
		}
		if hit.State != SearchPossible && hit.State != SearchConfirmed {
			t.Fatalf("a hit's state %d with no text held", hit.State)
		}
	}
	if len(world.sync.source.fetched()) != fetchesBefore {
		t.Fatal("a search read evs")
	}
	if progress.Counts.Repos != 1 || len(progress.Coverage) != 1 || progress.Coverage[0].State != "searched" {
		t.Fatalf("the progress %+v", progress)
	}
	if hits, _ := world.all(t, &SearchRequest{Text: "zebra crossing"}); len(hits) != 0 {
		t.Fatalf("a query nothing holds found %v", testHitPaths(hits))
	}
}

// §16.10's scope and excluded rows: a secret repo and a repo this sidecar cannot read are never listed; config and
// mailcfg hold no index; a deposit-only repo and a parked device's own owner-bound repo are named; in network breadth a
// ref whose index is off is left out with its reason; repo breadth reads only the repos named.
func TestSearchEngineScopeAndExclusions(t *testing.T) {
	world := newTestEngineWorld(t, nil, testEngineDocument(t, "doc", 1, 1, "notes/harbor.md", "harbor lights"))
	repo := func(label string, kind protocol.RepoKind) *SearchScopeRepo {
		return &SearchScopeRepo{RepoId: evsTestId(label), Kind: kind, Readable: true, Refs: []*SearchScopeRef{{RefId: evsTestId(label + " ref"), Default: true}}}
	}
	secret := repo("secret", protocol.RepoKind_REPO_KIND_SECRET)
	config := repo("config", protocol.RepoKind_REPO_KIND_CONFIG)
	deposit := repo("deposit", protocol.RepoKind_REPO_KIND_GENERAL)
	deposit.Readable, deposit.DepositOnly = false, true
	parked := repo("parked", protocol.RepoKind_REPO_KIND_VAULT)
	parked.ConsentPending = true
	unreadable := repo("unreadable", protocol.RepoKind_REPO_KIND_GENERAL)
	unreadable.Readable = false
	off := repo("off", protocol.RepoKind_REPO_KIND_GENERAL)
	off.Refs[0].IndexOff = true
	world.scope.repos = append(world.scope.repos, secret, config, deposit, parked, unreadable, off)
	hits, progress := world.all(t, &SearchRequest{Text: "harbor"})
	if len(hits) != 1 {
		t.Fatalf("hits %v", testHitPaths(hits))
	}
	reasons := map[Id]string{}
	for _, exclusion := range progress.Excluded {
		reasons[exclusion.RepoId] = exclusion.Reason
	}
	want := map[Id]string{
		evsTestId("config"): SearchExcludedNoIndex, evsTestId("deposit"): SearchExcludedDepositOnly,
		evsTestId("parked"): SearchExcludedConsentPending, evsTestId("off"): SearchExcludedIndexOff,
	}
	for repoId, reason := range want {
		if reasons[repoId] != reason {
			t.Errorf("%s excluded as %q, want %q", repoId, reasons[repoId], reason)
		}
	}
	for _, never := range []Id{evsTestId("secret"), evsTestId("unreadable")} {
		if _, listed := reasons[never]; listed {
			t.Errorf("%s was listed", never)
		}
	}
	// repo breadth: an unreadable repo named reads nothing and is not listed
	hits, progress = world.all(t, &SearchRequest{Text: "harbor", Repos: []Id{evsTestId("unreadable")}})
	if len(hits) != 0 || len(progress.Excluded) != 0 || progress.Counts.Repos != 0 {
		t.Fatalf("an unreadable repo named: %v, %+v", testHitPaths(hits), progress.Excluded)
	}
	hits, _ = world.all(t, &SearchRequest{Text: "harbor", Repos: []Id{world.sync.repoId}})
	if len(hits) != 1 {
		t.Fatalf("repo breadth found %v", testHitPaths(hits))
	}
}

// §16.10's owner-bound row: a reader that is not the writer deposits a receipt of purpose search naming each index file
// it fetches before the round's first fetch; a receipt that cannot land fetches nothing, and the search skips the repo,
// coverage naming it.
func TestSearchEngineReceiptsBeforeDecrypts(t *testing.T) {
	world := newTestSyncWorld(t, true)
	world.head.push(t, evsTestId("writer"), testEngineDocument(t, "doc", 1, 1, "notes/harbor.md", "harbor lights"))
	requests := []*RecordReceiptRequest{}
	fail := true
	deposit := func(ctx context.Context, request *RecordReceiptRequest) error {
		if 0 < len(world.source.fetched()) {
			t.Error("a receipt came after a fetch")
		}
		requests = append(requests, request)
		if fail {
			return ErrRecordReceiptRefused
		}
		return nil
	}
	repo := &SearchScopeRepo{RepoId: world.repoId, Kind: protocol.RepoKind_REPO_KIND_VAULT, Readable: true, ReceiptRequired: true,
		Refs: []*SearchScopeRef{{RefId: world.refId, Default: true}}}
	nonWriter, depositor := searchReceiptFollowArgs(repo, deposit)
	err := world.sync.Follow(&searchSyncRefArgs{
		repoId: world.repoId, refId: world.refId, repoKind: repo.Kind, source: world.source, nonWriter: nonWriter,
		depositReceipt: depositor, mayErase: func(Id, int64) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := world.sync.RunRound(context.Background(), world.repoId, world.refId, false); !errors.Is(err, errSearchSyncReceipt) {
		t.Fatalf("a round whose receipt failed answered %v", err)
	}
	if len(world.source.fetched()) != 0 || len(requests) != 1 || requests[0].Purpose != RecordReadPurposeSearch || len(requests[0].ObjectIds) == 0 {
		t.Fatalf("receipts %+v, fetched %v", requests, world.source.fetched())
	}
	for _, objectId := range requests[0].ObjectIds {
		if len(objectId) != 32 {
			t.Fatal("a receipt named an object by other than its content_sha256")
		}
	}
	engine, err := NewSearchEngine(&SearchEngineArgs{
		Settings: world.cache.settings, Cache: world.cache.cache, Sync: world.sync, Scope: &testSearchScope{repos: []*SearchScopeRepo{repo}},
		Gkm: &evsTestReadGkm{newest: 1}, Clock: world.cache.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	stream, err := engine.Search(context.Background(), &SearchRequest{Text: "harbor"})
	if err != nil {
		t.Fatal(err)
	}
	page, progress, _, err := stream.Next()
	stream.Close()
	if err != nil || len(page) != 0 || len(progress.Excluded) != 1 || progress.Excluded[0].Reason != SearchExcludedReceipt {
		t.Fatalf("a repo whose receipt failed: %v, %+v, %v", page, progress.Excluded, err)
	}
	fail = false
	world.round(t)
	stream, err = engine.Search(context.Background(), &SearchRequest{Text: "harbor"})
	if err != nil {
		t.Fatal(err)
	}
	page, _, _, err = stream.Next()
	stream.Close()
	if err != nil || len(page) != 1 {
		t.Fatalf("after the receipt landed: %v, %v", page, err)
	}
}

// §16.10's pages row: an erasure in scope ends the snapshot a cursor pins, and the cursor answers cursor_expired.
func TestSearchEngineCursorExpiresAfterAnErase(t *testing.T) {
	world := newTestEngineWorld(t, func(settings *SidecarSearchSettings) { settings.PageHitCount = 1 },
		testEngineDocument(t, "doc", 1, 1, "notes/a.md", "harbor a"), testEngineDocument(t, "doc", 2, 1, "notes/b.md", "harbor b"))
	stream, token, err := world.engine.SearchIn(context.Background(), evsTestId("session"), &SearchRequest{Text: "harbor"})
	if err != nil {
		t.Fatal(err)
	}
	if page, _, done, err := stream.Next(); err != nil || len(page) != 1 || done {
		t.Fatalf("the first page %v %v %v", page, done, err)
	}
	// CORE-M10-04's ApplyErase ends the repo's open snapshots before it returns
	world.sync.sync.EndRepo(world.sync.repoId)
	if _, _, _, err := stream.Next(); !errors.Is(err, ErrSearchCursorExpired) {
		t.Fatalf("a page after the erasure answered %v", err)
	}
	if _, err := world.engine.Resume(evsTestId("session"), token); !errors.Is(err, ErrSearchCursorExpired) {
		t.Fatalf("the cursor after the erasure answered %v", err)
	}
}

// §16.10's limits row: a session's third search at once waits until its wait ends, then answers busy.
func TestSearchEngineThirdSearchIsBusy(t *testing.T) {
	world := newTestEngineWorld(t, nil, testEngineDocument(t, "doc", 1, 1, "notes/a.md", "harbor a"))
	session := evsTestId("session")
	for range world.engine.args.Settings.SessionSearchCount {
		release, err := world.engine.limits.admit(context.Background(), session, true)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
	}
	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan error, 1)
	go func() {
		_, _, err := world.engine.SearchIn(ctx, session, &SearchRequest{Text: "harbor"})
		waiting <- err
	}()
	// the wait_ms elapsing
	cancel()
	if err := <-waiting; !errors.Is(err, ErrSearchBusy) {
		t.Fatalf("a third search answered %v", err)
	}
	// another session is not held by these
	if _, _, err := world.engine.SearchIn(context.Background(), evsTestId("other session"), &SearchRequest{Text: "harbor"}); err != nil {
		t.Fatalf("another session's search answered %v", err)
	}
}

// §16.10's limits row: a partition with more candidates than Search.TooBroadCandidateCount answers too_broad.
func TestSearchEngineTooBroad(t *testing.T) {
	documents := []*indexPendingDocument{}
	for index := range 6 {
		documents = append(documents, testEngineDocument(t, "doc", index, 1, fmt.Sprintf("notes/%d.md", index), fmt.Sprintf("harbor note %d", index)))
	}
	world := newTestEngineWorld(t, func(settings *SidecarSearchSettings) { settings.TooBroadCandidateCount = 2 }, documents...)
	_, progress := world.all(t, &SearchRequest{Text: "harbor"})
	if !progress.TooBroad {
		t.Fatalf("too broad was not said: %+v", progress)
	}
}

// §16.10's result row: no page passes Search.PageByteCount; hits held back come on the next page, none lost.
func TestSearchEnginePagesStayWithinTheirBytes(t *testing.T) {
	documents := []*indexPendingDocument{}
	for index := range 12 {
		documents = append(documents, testEngineDocument(t, "doc", index, 1, fmt.Sprintf("notes/%s-%d.md", strings.Repeat("long-name", 10), index), fmt.Sprintf("harbor %d", index)))
	}
	world := newTestEngineWorld(t, func(settings *SidecarSearchSettings) { settings.PageByteCount = 1200 }, documents...)
	stream, err := world.engine.Search(context.Background(), &SearchRequest{Text: "harbor"})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	total := 0
	for range 100 {
		page, _, done, err := stream.Next()
		if err != nil {
			t.Fatal(err)
		}
		byteCount := 0
		for index := range page {
			byteCount += searchHitByteCount(&page[index])
		}
		if 1 < len(page) && 1200 < byteCount {
			t.Fatalf("a page of %d B", byteCount)
		}
		total += len(page)
		if done {
			break
		}
	}
	if total != 12 {
		t.Fatalf("%d hits across the pages", total)
	}
}

// §22.6's cursor target: a token of another session, a changed token and garbage are refused as invalid; the right
// session's token resumes.
func TestSearchCursorsRefuseForgedAndForeignTokens(t *testing.T) {
	world := newTestEngineWorld(t, nil, testEngineDocument(t, "doc", 1, 1, "notes/a.md", "harbor a"))
	session := evsTestId("session")
	_, token, err := world.engine.SearchIn(context.Background(), session, &SearchRequest{Text: "harbor"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.engine.Resume(session, token); err != nil {
		t.Fatalf("the session's own token: %v", err)
	}
	if _, err := world.engine.Resume(evsTestId("other"), token); !errors.Is(err, ErrSearchCursorInvalid) {
		t.Fatalf("a foreign token answered %v", err)
	}
	forged := []byte(token)
	forged[3] ^= 1
	for _, bad := range []string{string(forged), "", "not a token", token + "A"} {
		if _, err := world.engine.Resume(session, bad); !errors.Is(err, ErrSearchCursorInvalid) {
			t.Fatalf("%q answered %v", bad, err)
		}
	}
	world.sync.cache.clock.advance(world.engine.args.Settings.CursorTimeout + time.Second)
	if _, err := world.engine.Resume(session, token); !errors.Is(err, ErrSearchCursorExpired) {
		t.Fatalf("an idle token answered %v", err)
	}
}

// Writes an all partition of shardCount shards whose documents hold real text, a/m naming each.
func testWriteTextAll(t *testing.T, world *testSyncWorld, shardCount int, text func(n int, index int) string) {
	t.Helper()
	paths := indexNewPaths(false, indexRootNumber)
	roller := world.head.ref.store(evsTestId("roller"))
	manifest := &protocol.IndexManifest{RolledThroughDay: testSyncBucket - 30}
	files := []*indexPushFile{}
	for n := range shardCount {
		documents := []*indexShardDocument{}
		for index := range 3 {
			pending := testEngineDocument(t, fmt.Sprintf("all %d", n), index, 1, fmt.Sprintf("old/%d/%d.md", n, index), text(n, index))
			documents = append(documents, &indexShardDocument{key: pending.key, version: 1, timeSeconds: uint64(testDayTime(testSyncBucket-60+uint32(n), 0).Unix()), row: pending.row, keys: pending.keys})
		}
		slices.SortFunc(documents, func(a *indexShardDocument, b *indexShardDocument) int { return compareIndexKeys(a.key, b.key) })
		shard := &indexShard{header: testShardHeader(indexFileAllShard), documents: documents}
		manifest.Shards = append(manifest.Shards, &protocol.IndexShard{N: uint32(n), Docs: uint32(len(documents)), FirstDay: testSyncBucket - 60 + uint32(n), LastDay: testSyncBucket - 60 + uint32(n)})
		files = append(files, &indexPushFile{path: paths.allShard(uint32(n)), plaintext: testBuildShard(t, shard, false, testPadKey(t, 2)), replaces: roller.testVersionOf(paths.allShard(uint32(n)))})
	}
	files = append(files, &indexPushFile{path: paths.allManifest(), plaintext: testSmallFile(t, manifest), replaces: roller.testVersionOf(paths.allManifest())})
	if _, err := roller.Commit(context.Background(), roller.testPush(t, world.head.at, files, nil)); err != nil {
		t.Fatal(err)
	}
	world.head.at = world.head.at.Add(time.Minute)
}

// §16.10's phase rows with "search more": SearchCached reads the buckets only while all is not held; SearchAll fetches
// every all shard, searching each as it lands, its hits after every phase-1 hit and never revised.
func TestSearchEngineSearchMoreRanksEachShardAsItLands(t *testing.T) {
	world := newTestSyncWorld(t, false)
	world.head.push(t, evsTestId("writer"), testEngineDocument(t, "doc", 1, 1, "notes/new.md", "harbor today"))
	testWriteTextAll(t, world, 3, func(n int, index int) string {
		if index == 0 {
			return fmt.Sprintf("harbor of shard %d", n)
		}
		return fmt.Sprintf("garden of shard %d", n)
	})
	world.round(t)
	scope := &testSearchScope{repos: []*SearchScopeRepo{{RepoId: world.repoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL, Readable: true,
		Refs: []*SearchScopeRef{{RefId: world.refId, Default: true}}}}}
	policy := testNewSearchPolicy(t, world.cache.settings, nil, world.cache.clock, &SearchConditions{DaemonHost: true})
	engine, err := NewSearchEngine(&SearchEngineArgs{Settings: world.cache.settings, Cache: world.cache.cache, Sync: world.sync, Policy: policy,
		Scope: scope, Gkm: &evsTestReadGkm{newest: 1}, Clock: world.cache.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	engineWorld := &testEngineWorld{sync: world, scope: scope, engine: engine, policy: policy}
	cached, _ := engineWorld.all(t, &SearchRequest{Text: "harbor"})
	if paths := testHitPaths(cached); !slices.Equal(paths, []string{"notes/new.md"}) {
		t.Fatalf("SearchCached with all not held found %v", paths)
	}
	more, progress := engineWorld.all(t, &SearchRequest{Text: "harbor", Scope: SearchAll})
	if len(more) != 4 || more[0].Path != "notes/new.md" || more[0].Partition != SearchPartitionLatest {
		t.Fatalf("SearchAll found %v", testHitPaths(more))
	}
	for _, hit := range more[1:] {
		if hit.Partition != SearchPartitionAll || !strings.HasPrefix(hit.Path, "old/") {
			t.Fatalf("a phase-2 hit %+v", hit)
		}
		if !hit.Time.Before(more[0].Time) {
			t.Fatal("a phase-2 hit newer than a phase-1 hit")
		}
	}
	if progress.FetchedBytes == 0 {
		t.Fatal("the fetched bytes were not reported")
	}
}

// DESIGN-DETAILS 7.7's iterator for SEARCH-M10-32: candidates after a watermark in 7.2.5's order, at most k and the one
// after, each current.
func TestSearchCandidatesAfterAWatermark(t *testing.T) {
	documents := []*indexPendingDocument{}
	for index := range 5 {
		documents = append(documents, testEngineDocument(t, "doc", index, 1, fmt.Sprintf("notes/%d.md", index), fmt.Sprintf("harbor %d", index)))
	}
	world := newTestEngineWorld(t, nil, documents...)
	stream, err := world.engine.Search(context.Background(), &SearchRequest{Text: "harbor"})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	engineStream := world.engine.openStreams()[0]
	step := 0
	inputs, _, err := engineStream.refs[0].phaseOne(context.Background(), engineStream.query, &step)
	if err != nil {
		t.Fatal(err)
	}
	repoIndex := func(source *searchRankSource) uint16 { return 0 }
	first, next, err := searchCandidatesAfter(inputs, repoIndex, searchWatermark{}, 2)
	if err != nil || len(first) != 2 || next == nil {
		t.Fatalf("the first two: %d, next %v, %v", len(first), next, err)
	}
	rest, after, err := searchCandidatesAfter(inputs, repoIndex, first[1].place, 10)
	if err != nil || len(rest) != 3 || after != nil || rest[0].place != next.place {
		t.Fatalf("after the watermark: %d, %v, %v", len(rest), after, err)
	}
	if !searchWatermarkBefore(first[0].place, first[1].place) || !searchWatermarkBefore(first[1].place, rest[0].place) {
		t.Fatal("the order is not the candidate order")
	}
	confirmation, err := searchVerifyCandidate(context.Background(), rest[0])
	if err != nil || confirmation.state == searchMatchRejected {
		t.Fatalf("a candidate verified as %+v, %v", confirmation, err)
	}
}

// I-13, R-CORE-18: a query is never persisted: after a search and its pages, nothing stored holds it.
func TestSearchEngineLeavesNoQueryCanaryOnDisk(t *testing.T) {
	world := newTestEngineWorld(t, nil, testEngineDocument(t, "doc", 1, 1, "notes/a.md", "harbor a"))
	canary := "synthetic-canary-5f2e9d"
	if _, err := ParseSearchQuery(canary); err != nil {
		t.Fatal(err)
	}
	world.all(t, &SearchRequest{Text: canary + " harbor"})
	backend := world.sync.cache.backend.(*memoryStoreBackend)
	backend.stateLock.Lock()
	defer backend.stateLock.Unlock()
	for path, content := range backend.pathContents {
		if bytes.Contains(content, []byte(canary)) || strings.Contains(path, canary) {
			t.Fatalf("%s holds the query", path)
		}
	}
}

// §11.14's typos row: a term with fewer than three exact hits is corrected by a one-edit variant the partitions hold,
// and the corrected query's hits come as near hits labeled with the correction, after every exact hit.
func TestSearchEngineNearHitsCorrectATypo(t *testing.T) {
	world := newTestEngineWorld(t, nil,
		testEngineDocument(t, "doc", 1, 1, "notes/harbor.md", "harbor lights"),
		testEngineDocument(t, "doc", 2, 1, "notes/garden.md", "garden notes"),
	)
	hits, progress := world.all(t, &SearchRequest{Text: "harbr"})
	if len(hits) != 1 || hits[0].State != SearchNear || hits[0].Correction != "harbor" || hits[0].Path != "notes/harbor.md" {
		t.Fatalf("near hits %+v", hits)
	}
	if progress.Counts.Near != 1 {
		t.Fatalf("the counts %+v", progress.Counts)
	}
}
