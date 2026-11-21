//go:build !ios_extension

package sidecar

// SEARCH-M10-26 (§16.10; FS-80's scope and exclusion cases at unit level, on the sync engine's fake): a search finds
// what the cache holds through the kept records' wrapped keys and never reads evs; repo and network breadth and every
// exclusion; a receipt that cannot land skipping its repo; cursor_expired after an erasure ends the snapshot; a third
// search of a session busy once its wait ends; too_broad; pages within Search.PageByteCount; forged and foreign cursors
// refused (§22.6's cursor target); phase 2 over all as "search more" lands each shard; a first shard's hit given before
// a long download ends and the rest through the cursor, none lost or repeated, the download going on without a page
// (QD-999); the candidate iterator after a watermark; and no query canary in anything stored.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
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
	return &indexPendingDocument{kind: indexEntryFull, key: testIndexId(label, index), version: version, keys: keys, row: row}
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

// A named-ref scan with two visible documents and one index file. The returned cut removes the second document.
func newTestNamedRefScan(t *testing.T) (*testEngineWorld, func()) {
	t.Helper()
	world := newTestEngineWorld(t, nil, testEngineDocument(t, "other", 1, 1, "indexed.md", "harbor"))
	repoId, refId := world.sync.repoId, world.sync.refId
	repo := world.scope.repos[0]
	repo.Refs = []*SearchScopeRef{
		{RefId: evsTestId("other default"), Default: true, Name: "main", Unbuilt: true},
		{RefId: refId, Name: "draft", IndexOff: true},
	}
	key, err := NewEvsRefKey(evsTestRepoKey(repoId, 1))
	if err != nil {
		t.Fatal(err)
	}
	docs := testSearchScan{}
	for _, name := range []string{"harbor-a.md", ".ur-index/harbor", "harbor-b.md"} {
		docs = append(docs, &SearchScanDocument{RefId: refId, Name: []byte(name), Kind: IndexDocFile,
			Version: 1, TimeMs: world.sync.head.at.UnixMilli(), Signer: evsTestId("my laptop"), Display: &SearchScanDisplay{}})
	}
	world.engine.args.Scan = func(_ context.Context, repo, ref Id) (*SearchScanView, error) {
		if repo != repoId || ref != refId {
			return nil, nil
		}
		return &SearchScanView{Source: docs, RefKey: key}, nil
	}
	return world, func() {
		t.Helper()
		through, err := indexDocKey(key.key, refId, []byte("harbor-b.md"), 0)
		if err != nil {
			t.Fatal(err)
		}
		eraser := testNewEraser(t, world.sync.head.ref.store(evsTestId("scan eraser")), false, &testIndexWorldClock{world: world.sync.head}, nil)
		testCut(t, eraser, "scan cut", &IndexCutDocument{Key: through, Version: 1})
		world.sync.round(t)
	}
}

func TestSearchEngineNamedRefScansLocalVersionsAcrossACut(t *testing.T) {
	world, cut := newTestNamedRefScan(t)
	repoId, refId := world.sync.repoId, world.sync.refId
	repo := world.scope.repos[0]
	request := &SearchRequest{Text: "harbor", Repos: []Id{repoId}, Ref: "draft", PageSize: 1}
	session := evsTestId("scan session")
	stream, cursor, err := world.engine.SearchIn(t.Context(), session, request)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	first, progress, done, err := stream.Next()
	if err != nil || done || len(first) != 1 || first[0].Path != "harbor-a.md" || first[0].DocKey == ([16]byte{}) ||
		len(progress.Coverage) != 1 || progress.Coverage[0].State != SearchExcludedIndexOff || len(progress.Excluded) != 0 {
		t.Fatalf("first scan page: %+v, %+v, done %t, %v", first, progress, done, err)
	}
	cut()
	if _, err := world.engine.Resume(session, cursor); !errors.Is(err, ErrSearchCursorExpired) {
		t.Fatalf("scan cursor after cut: %v", err)
	}
	if hits, _, _, err := stream.Next(); len(hits) != 0 || !errors.Is(err, ErrSearchCursorExpired) {
		t.Fatalf("old scan after cut: %+v, %v", hits, err)
	}
	request.Ref = "id:" + refId.String()
	repo.Refs[1].IndexOff, repo.Refs[1].Unbuilt = false, true
	hits, coverage := world.all(t, request)
	if !slices.Equal(testHitPaths(hits), []string{"harbor-a.md"}) || coverage.Coverage[0].State != SearchExcludedUnbuilt {
		t.Fatalf("fresh scan: %+v, %+v", hits, coverage)
	}
	request.Ref = ""
	hits, coverage = world.all(t, request)
	if len(hits) != 0 || len(coverage.Excluded) != 1 || *coverage.Excluded[0].RefId != repo.Refs[0].RefId {
		t.Fatalf("default ref: %+v, %+v", hits, coverage)
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
	repo.Refs[0].Unbuilt = true
	engine.args.Scan = func(context.Context, Id, Id) (*SearchScanView, error) {
		t.Fatal("opened a scan after a refused search receipt")
		return nil, nil
	}
	stream, err = engine.Search(t.Context(), &SearchRequest{Text: "harbor", Repos: []Id{world.repoId}})
	if err != nil {
		t.Fatal(err)
	}
	page, progress, _, err = stream.Next()
	stream.Close()
	if err != nil || len(page) != 0 || len(progress.Excluded) != 1 || progress.Excluded[0].Reason != SearchExcludedReceipt {
		t.Fatalf("named repo after a refused receipt: %v, %+v, %v", page, progress.Excluded, err)
	}
	repo.Refs[0].Unbuilt = false
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

// Learning a valid cut during an ordinary round expires both live pages and the hit references from finished searches.
func TestSearchEngineSyncedCutExpiresItsCursors(t *testing.T) {
	for _, listing := range []bool{false, true} {
		first := testEngineDocument(t, "cut document", 1, 1, "a.txt", "harbor a")
		second := testEngineDocument(t, "cut document", 2, 1, "b.txt", "harbor b")
		world := newTestEngineWorld(t, nil, first, second)
		ctx := context.Background()
		session := evsTestId("cut search session")
		request := &SearchRequest{Text: "harbor", PageSize: 1}
		stream, token, err := world.engine.SearchIn(ctx, session, request)
		if err != nil {
			t.Fatal(err)
		}
		page, _, done, err := stream.Next()
		if err != nil || len(page) != 1 || done {
			t.Fatalf("first page: %v, done %v, %v", page, done, err)
		}
		_, finished, err := world.engine.SearchIn(ctx, session, request)
		if err != nil {
			t.Fatal(err)
		}
		cursors := world.engine.cursors
		cursors.noteHits(session, finished, page, 1)
		hitId := cursors.hitId(session, &page[0])
		cursors.finish(session, finished)
		if _, err := cursors.openHit(session, hitId); err != nil {
			t.Fatal(err)
		}
		// An ordinary content push leaves the previous query alive. It also puts two statements in the listing case.
		world.sync.head.push(t, evsTestId("writer"), testEngineDocument(t, "outside query", 1, 1, "c.txt", "city"))
		if listing {
			world.sync.source.catchUpCount = 1
		}
		eraser := testNewEraser(t, world.sync.head.ref.store(evsTestId("eraser")), false, &testIndexWorldClock{world: world.sync.head}, nil)
		testCut(t, eraser, "cut search", &IndexCutDocument{Key: second.key, Version: second.version})
		world.sync.round(t)
		if hits, _, _, err := stream.Next(); !errors.Is(err, ErrSearchCursorExpired) || len(hits) != 0 {
			t.Fatalf("listing %v: continued with %v, %v", listing, hits, err)
		}
		if _, err := world.engine.Resume(session, token); !errors.Is(err, ErrSearchCursorExpired) {
			t.Fatalf("listing %v: resumed cursor: %v", listing, err)
		}
		if _, err := cursors.openHit(session, hitId); !errors.Is(err, ErrSearchHitUnknown) {
			t.Fatalf("listing %v: finished cursor kept its hit: %v", listing, err)
		}
		hits, _ := world.all(t, request)
		if !slices.Equal(testHitPaths(hits), []string{"a.txt"}) {
			t.Fatalf("listing %v: fresh search found %v", listing, testHitPaths(hits))
		}
		stream.Close()
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
	testSearchEngineColdShards(t, false)
}

func TestSearchEngineReadsColdShardsAboveTheRetentionCap(t *testing.T) {
	testSearchEngineColdShards(t, true)
}

func testSearchEngineColdShards(t *testing.T, overCap bool) {
	t.Helper()
	world := newTestSyncWorld(t, false)
	if overCap {
		world.cache.settings.AllCacheByteCount = 1
	}
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
	more, progress := engineWorld.all(t, &SearchRequest{Text: "harbor", Scope: SearchAll, PageSize: 1})
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
	if overCap {
		ref, err := world.cache.cache.Ref(world.repoId, world.refId)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range ref.Files {
			path, ok := indexParsePath(file.Key.Path, false)
			if ok && path.kind == indexPathAllShard {
				t.Fatalf("over-cap shard still held after its last page: %s", file.Key.Path)
			}
		}
	}
}

// A source whose reads, once held, each wait for a token the test gives, so a test says how far a download has got.
type testHeldSyncSource struct {
	*testSyncSource
	stateLock sync.Mutex
	held      bool
	tokens    chan struct{}
}

func (self *testHeldSyncSource) Fetch(ctx context.Context, files []*indexFileVersion) ([]*searchSyncFetched, error) {
	self.stateLock.Lock()
	held, tokens := self.held, self.tokens
	self.stateLock.Unlock()
	if held {
		select {
		case <-tokens:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return self.testSyncSource.Fetch(ctx, files)
}

// Holds every read from now, but the first count.
func (self *testHeldSyncSource) hold(count int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.held, self.tokens = true, make(chan struct{}, count)
	for range count {
		self.tokens <- struct{}{}
	}
}

// Lets every read go from now, the held ones included.
func (self *testHeldSyncSource) free() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.held = false
	close(self.tokens)
}

// A ref whose latest set is synced and whose all, shardCount shards of text's documents, is not, an engine reading it
// one file a read through a held source.
type testEngineMoreWorld struct {
	sync   *testSyncWorld
	source *testHeldSyncSource
	engine *SearchEngine
	// all's shards in fetch order, youngest first
	order []string
}

func newTestEngineMoreWorld(t *testing.T, shardCount int, text func(n int, index int) string) *testEngineMoreWorld {
	t.Helper()
	world := newTestSyncWorld(t, false)
	world.head.push(t, evsTestId("writer"), testEngineDocument(t, "doc", 1, 1, "notes/new.md", "harbor today"))
	testWriteTextAll(t, world, shardCount, text)
	source := &testHeldSyncSource{testSyncSource: world.source}
	moreSync, err := newSearchSync(&searchSyncArgs{
		cache: world.cache.cache, settings: world.cache.settings, format: DefaultIndexFormatSettings(), clock: world.cache.clock,
		log: NewNoopLogger(), readPathCount: 1, readByteCount: 32 * 1024 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(moreSync.Close)
	err = moreSync.Follow(&searchSyncRefArgs{
		repoId: world.repoId, refId: world.refId, repoKind: protocol.RepoKind_REPO_KIND_GENERAL, source: source,
		keepAll: func() bool { return false }, mayErase: func(Id, int64) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := moreSync.RunRound(context.Background(), world.repoId, world.refId, false); err != nil {
		t.Fatal(err)
	}
	scope := &testSearchScope{repos: []*SearchScopeRepo{{RepoId: world.repoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL, Readable: true,
		Refs: []*SearchScopeRef{{RefId: world.refId, Default: true}}}}}
	engine, err := NewSearchEngine(&SearchEngineArgs{
		Settings: world.cache.settings, Cache: world.cache.cache, Sync: moreSync, Scope: scope, Gkm: &evsTestReadGkm{newest: 1},
		Policy: testNewSearchPolicy(t, world.cache.settings, nil, world.cache.clock, &SearchConditions{DaemonHost: true}),
		Clock:  world.cache.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	more := &testEngineMoreWorld{sync: world, source: source, engine: engine}
	paths := indexNewPaths(false, indexRootNumber)
	for n := shardCount - 1; 0 <= n; n -= 1 {
		more.order = append(more.order, fmt.Sprintf("%s@", paths.allShard(uint32(n))))
	}
	world.source.stateLock.Lock()
	world.source.fetches = nil
	world.source.stateLock.Unlock()
	return more
}

// The all shards read so far, in order, as path@.
func (self *testEngineMoreWorld) fetchedShards() []string {
	shards := []string{}
	for _, fetched := range self.sync.source.fetched() {
		path, _, _ := strings.Cut(fetched, "@")
		if strings.Contains(path, "/a/") && !strings.HasSuffix(path, "/a/m") {
			shards = append(shards, path+"@")
		}
	}
	return shards
}

// The paths of hits, in their order.
func testHitPathsInOrder(hits []SearchHit) []string {
	paths := []string{}
	for _, hit := range hits {
		paths = append(paths, hit.Path)
	}
	return paths
}

// Every page of stream until it is done, with the last page's progress.
func testPagesToTheEnd(t *testing.T, stream *SearchStream) ([]SearchHit, SearchProgress) {
	t.Helper()
	hits := []SearchHit{}
	for range 1000 {
		page, progress, done, err := stream.Next()
		if err != nil {
			t.Fatal(err)
		}
		hits = append(hits, page...)
		if done {
			return hits, progress
		}
	}
	t.Fatal("a search never finished")
	return nil, SearchProgress{}
}

// The three shards of six whose first document holds "lantern": the first, a middle and the last fetched.
func testLanternText(n int, index int) string {
	if index == 0 && (n == 5 || n == 2 || n == 0) {
		return fmt.Sprintf("lantern of shard %d", n)
	}
	return fmt.Sprintf("garden of shard %d", n)
}

// QD-999 (§16.10's arrival row on delivery): a match in the first shard of a long download is given the moment its
// shard lands, before the download reads another, and the rest come through the cursor's next pages as their shards
// land, each hit once, in fetch order, every shard read once, youngest first, and the counts counting each hit once.
func TestSearchEngineGivesAFirstShardHitBeforeTheDownloadEnds(t *testing.T) {
	world := newTestEngineMoreWorld(t, 6, testLanternText)
	session := evsTestId("session")
	world.source.hold(1)
	stream, token, err := world.engine.SearchIn(context.Background(), session, &SearchRequest{Text: "lantern", Scope: SearchAll})
	if err != nil {
		t.Fatal(err)
	}
	first, progress, done, err := stream.Next()
	if err != nil || done || !slices.Equal(testHitPathsInOrder(first), []string{"old/5/0.md"}) {
		t.Fatalf("the first page %v, done %t, %v", testHitPathsInOrder(first), done, err)
	}
	if fetched := world.fetchedShards(); !slices.Equal(fetched, world.order[:1]) {
		t.Fatalf("the first shard's hit came after the download read %v", fetched)
	}
	if progress.FetchBytes <= 0 || progress.Counts.Confirmed+progress.Counts.Possible != 1 {
		t.Fatalf("the first page's progress %+v", progress)
	}
	world.source.free()
	resumed, err := world.engine.Resume(session, token)
	if err != nil {
		t.Fatal(err)
	}
	rest, last := testPagesToTheEnd(t, resumed)
	hits := testHitPathsInOrder(append(first, rest...))
	if !slices.Equal(hits, []string{"old/5/0.md", "old/2/0.md", "old/0/0.md"}) {
		t.Fatalf("the search gave %v, want each match once in fetch order", hits)
	}
	if fetched := world.fetchedShards(); !slices.Equal(fetched, world.order) {
		t.Fatalf("the download read %v, want each shard once in %v", fetched, world.order)
	}
	if last.FetchBytes != 0 || last.Counts.Confirmed+last.Counts.Possible != 3 {
		t.Fatalf("the last progress %+v", last)
	}
}

// QD-999 with I-19 and D-MCP-20: the download goes on whatever the pages do, so a page answering at a hit stops
// nothing a server could see: with no page asking, the window reads every shard left, and the next page gives every
// hit they hold at once.
func TestSearchEngineDownloadGoesOnWithoutAPage(t *testing.T) {
	world := newTestEngineMoreWorld(t, 6, testLanternText)
	world.source.hold(1)
	stream, err := world.engine.Search(context.Background(), &SearchRequest{Text: "lantern", Scope: SearchAll})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	first, _, _, err := stream.Next()
	if err != nil || !slices.Equal(testHitPathsInOrder(first), []string{"old/5/0.md"}) {
		t.Fatalf("the first page %v, %v", testHitPathsInOrder(first), err)
	}
	engineStream := world.engine.openStreams()[0]
	world.source.free()
	for {
		state, changed := engineStream.more.state()
		if !state.running {
			if state.ended != searchMoreEndFinished {
				t.Fatalf("the window ended as %d", state.ended)
			}
			break
		}
		<-changed
	}
	if fetched := world.fetchedShards(); !slices.Equal(fetched, world.order) {
		t.Fatalf("with no page asking the download read %v, want every shard %v", fetched, world.order)
	}
	page, progress, done, err := stream.Next()
	if err != nil || !done || !slices.Equal(testHitPathsInOrder(page), []string{"old/2/0.md", "old/0/0.md"}) {
		t.Fatalf("the next page %v, done %t, %v", testHitPathsInOrder(page), done, err)
	}
	if progress.Counts.Confirmed+progress.Counts.Possible != 3 {
		t.Fatalf("the counts %+v", progress.Counts)
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

// QD-1025: a drop of the cache, of every repo or of one, resets the sync's state of what it dropped, so a search before
// the next round leaves the ref out as unbuilt, reading no manifest whose files are gone, and the next round fetches the
// latest set again and a search finds what it found before the drop. Before, the round replayed from the pin the sync
// held in memory, counted every dropped file as held and fetched nothing, and every search found nothing until a
// restart.
func TestSearchEngineDropCacheSyncsAgain(t *testing.T) {
	world := newTestEngineWorld(t, nil, testEngineDocument(t, "doc", 1, 1, "notes/harbor.md", "Harbor lights\nthe evening boat"))
	if hits, _ := world.all(t, &SearchRequest{Text: "harbor"}); !slices.Equal(testHitPaths(hits), []string{"notes/harbor.md"}) {
		t.Fatalf("before a drop, hits %v", testHitPaths(hits))
	}
	repoId, refId := world.sync.repoId, world.sync.refId
	for _, dropped := range []*Id{nil, &repoId} {
		fetched := len(world.sync.source.fetched())
		if err := world.engine.DropCache(dropped); err != nil {
			t.Fatal(err)
		}
		if held, err := world.sync.cache.cache.Ref(repoId, refId); err != nil || held != nil {
			t.Fatalf("the drop left %+v, %v", held, err)
		}
		hits, progress := world.all(t, &SearchRequest{Text: "harbor"})
		if len(hits) != 0 || len(progress.Excluded) != 1 || progress.Excluded[0].Reason != SearchExcludedUnbuilt {
			t.Fatalf("a search between the drop and the next round found %v, excluding %+v", testHitPaths(hits), progress.Excluded)
		}
		world.sync.round(t)
		if len(world.sync.source.fetched()) == fetched {
			t.Fatal("the round after a drop fetched nothing")
		}
		if hits, _ := world.all(t, &SearchRequest{Text: "harbor"}); !slices.Equal(testHitPaths(hits), []string{"notes/harbor.md"}) {
			t.Fatalf("after a drop and a round, hits %v", testHitPaths(hits))
		}
	}
}

// QD-1025: a drop of one repo's cache resets that repo's sync state alone. The other repo's manifest, plan and version
// table stay as the sync held them, its files stay cached and its snapshot open, its hits are found with no round
// between and its next round fetches nothing; the dropped repo's open snapshot ends, its search reads it as unbuilt,
// and its next round fetches its files again.
func TestSearchEngineDropCacheOfOneRepoLeavesAnother(t *testing.T) {
	world := newTestEngineWorld(t, nil, testEngineDocument(t, "doc", 1, 1, "notes/harbor.md", "Harbor lights\nthe evening boat"))
	synced := world.sync
	repoId, refId := synced.repoId, synced.refId
	otherRepoId, otherRefId := evsTestId("other repo"), evsTestId("other ref")
	otherHead := testNewHeadWorld()
	otherSource := newTestSyncSource(t, otherHead.ref, otherRepoId, otherRefId)
	err := synced.sync.Follow(&searchSyncRefArgs{
		repoId: otherRepoId, refId: otherRefId, repoKind: protocol.RepoKind_REPO_KIND_GENERAL, source: otherSource,
		mayErase: func(signer Id, signedTimeMs int64) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	otherHead.push(t, evsTestId("writer"), testEngineDocument(t, "other", 1, 1, "notes/harbor-wall.md", "Harbor wall\nthe old stones"))
	if err := synced.sync.RunRound(context.Background(), otherRepoId, otherRefId, false); err != nil {
		t.Fatal(err)
	}
	world.scope.repos = append(world.scope.repos, &SearchScopeRepo{
		RepoId: otherRepoId, Kind: protocol.RepoKind_REPO_KIND_GENERAL, Readable: true,
		Refs: []*SearchScopeRef{{RefId: otherRefId, Default: true}},
	})
	if hits, _ := world.all(t, &SearchRequest{Text: "harbor"}); !slices.Equal(testHitPaths(hits), []string{"notes/harbor-wall.md", "notes/harbor.md"}) {
		t.Fatalf("before a drop, hits %v", testHitPaths(hits))
	}
	// what the sync holds of a ref
	type syncState struct {
		loaded   bool
		manifest *SearchManifest
		plan     *SearchSyncPlan
		table    *SearchVersionTable
	}
	stateOf := func(repoId Id, refId Id) syncState {
		synced.sync.stateLock.Lock()
		defer synced.sync.stateLock.Unlock()
		ref := synced.sync.refs[[2]Id{repoId, refId}]
		return syncState{loaded: ref.loaded, manifest: ref.manifest, plan: ref.plan, table: ref.table}
	}
	other := stateOf(otherRepoId, otherRefId)
	if !other.loaded || other.manifest == nil || other.table == nil {
		t.Fatalf("the other repo was never synced: %+v", other)
	}
	otherHeld, err := synced.cache.cache.Ref(otherRepoId, otherRefId)
	if err != nil || otherHeld == nil {
		t.Fatalf("the other repo's cache %+v, %v", otherHeld, err)
	}
	snapshot := synced.snapshot(t)
	otherSnapshot, err := synced.sync.Snapshot(otherRepoId, otherRefId)
	if err != nil {
		t.Fatal(err)
	}
	defer otherSnapshot.Release()

	if err := world.engine.DropCache(&repoId); err != nil {
		t.Fatal(err)
	}
	if after := stateOf(otherRepoId, otherRefId); after != other {
		t.Fatalf("a drop of one repo reset another's sync state: %+v, was %+v", after, other)
	}
	if held, err := synced.cache.cache.Ref(otherRepoId, otherRefId); err != nil || held == nil || len(held.Files) != len(otherHeld.Files) {
		t.Fatalf("a drop of one repo took another's files: %+v, %v", held, err)
	}
	if dropped := stateOf(repoId, refId); dropped != (syncState{}) {
		t.Fatalf("the dropped repo's sync state stayed: %+v", dropped)
	}
	select {
	case <-snapshot.Ended():
	default:
		t.Fatal("a snapshot of the dropped repo stayed open")
	}
	select {
	case <-otherSnapshot.Ended():
		t.Fatal("a drop of one repo ended another's snapshot")
	default:
	}
	hits, progress := world.all(t, &SearchRequest{Text: "harbor"})
	if !slices.Equal(testHitPaths(hits), []string{"notes/harbor-wall.md"}) {
		t.Fatalf("after one repo's drop, hits %v", testHitPaths(hits))
	}
	if len(progress.Excluded) != 1 || progress.Excluded[0].RepoId != repoId || progress.Excluded[0].Reason != SearchExcludedUnbuilt {
		t.Fatalf("after one repo's drop, excluded %+v", progress.Excluded)
	}
	otherFetched := len(otherSource.fetched())
	if err := synced.sync.RunRound(context.Background(), otherRepoId, otherRefId, false); err != nil {
		t.Fatal(err)
	}
	if len(otherSource.fetched()) != otherFetched {
		t.Fatalf("the other repo's round after the drop fetched %v", otherSource.fetched()[otherFetched:])
	}
	fetched := len(synced.source.fetched())
	synced.round(t)
	if len(synced.source.fetched()) == fetched {
		t.Fatal("the dropped repo's round fetched nothing")
	}
	if hits, _ := world.all(t, &SearchRequest{Text: "harbor"}); !slices.Equal(testHitPaths(hits), []string{"notes/harbor-wall.md", "notes/harbor.md"}) {
		t.Fatalf("after the dropped repo's round, hits %v", testHitPaths(hits))
	}
}
