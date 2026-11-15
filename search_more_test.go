//go:build !ios_extension

package sidecar

// SEARCH-M10-20 (§16.10's cold contract; FS-110's traces on a fake clock at 10 MB/s): every missing all shard fetched
// whole, youngest first, in one fixed order whatever the query; the first report at once, a report at each shard and
// none further apart than a second; each shard handed to the search the moment it lands; complete within B / R + 1 s;
// past MoreByteCount a partial call whose cursor fetches on from the first unsearched shard, never restarting; a cache
// cap under all's size, every shard searched and the youngest kept; and the metered wait.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Writes an all partition of shardCount shards, a/m naming each, as a roll-up leaves one: shard n holds documents of
// its own, so each is a distinct file of a few KiB.
func testWriteAll(t *testing.T, world *testSyncWorld, shardCount int) {
	t.Helper()
	paths := indexNewPaths(false, indexRootNumber)
	roller := world.head.ref.store(evsTestId("roller"))
	manifest := &protocol.IndexManifest{RolledThroughDay: testSyncBucket - 30}
	files := []*indexPushFile{}
	for n := range shardCount {
		documents := []*indexShardDocument{}
		for index := range 20 {
			documents = append(documents, testShardCopy(fmt.Sprintf("rolled %d", n), index, 1, testIndexKeys(0x500000+n*0x10000+index*0x100, 120, 3)))
		}
		shard := &indexShard{header: testShardHeader(indexFileAllShard), documents: documents}
		manifest.Shards = append(manifest.Shards, &protocol.IndexShard{N: uint32(n), Docs: uint32(len(documents)), FirstDay: testSyncBucket - 60, LastDay: testSyncBucket - 31})
		files = append(files, &indexPushFile{path: paths.allShard(uint32(n)), plaintext: testBuildShard(t, shard, false, testPadKey(t, 2)), replaces: roller.testVersionOf(paths.allShard(uint32(n)))})
	}
	files = append(files, &indexPushFile{path: paths.allManifest(), plaintext: testSmallFile(t, manifest), replaces: roller.testVersionOf(paths.allManifest())})
	if _, err := roller.Commit(context.Background(), roller.testPush(t, world.head.at, files, nil)); err != nil {
		t.Fatal(err)
	}
	world.head.at = world.head.at.Add(time.Minute)
}

// A source whose every read takes its bytes at rate bytes a second on the world's clock, so fetch times follow B / R.
type testRatedSyncSource struct {
	*testSyncSource
	clock *identityTestClock
	rate  int64
	// When each read finished, by the paths it carried.
	stateLock sync.Mutex
	landedAt  map[string]time.Time
}

func (self *testRatedSyncSource) Fetch(ctx context.Context, files []*indexFileVersion) ([]*searchSyncFetched, error) {
	byteCount := int64(0)
	for _, file := range files {
		byteCount += int64(file.byteCount)
	}
	self.clock.advance(time.Duration(byteCount * int64(time.Second) / self.rate))
	fetched, err := self.testSyncSource.Fetch(ctx, files)
	self.stateLock.Lock()
	for _, file := range files {
		self.landedAt[file.path] = self.clock.Now()
	}
	self.stateLock.Unlock()
	return fetched, err
}

// A sync world whose ref holds a latest set and an all partition of shardCount shards, the latest set already synced,
// and a second engine over the same cache reading one file a read at 10 MB/s, the one "search more" runs on.
type testMoreWorld struct {
	sync   *testSyncWorld
	engine *SearchSync
	source *testRatedSyncSource
	clock  *identityTestClock
	// the all shards' paths in a/m's fixed order, youngest first, and their sizes
	order []string
	sizes map[string]int64
}

func newTestMoreWorld(t *testing.T, shardCount int) *testMoreWorld {
	t.Helper()
	world := newTestSyncWorld(t, false)
	world.push(t, evsTestId("writer"), "doc", 4)
	testWriteAll(t, world, shardCount)
	world.round(t)
	more := &testMoreWorld{sync: world, clock: world.cache.clock, sizes: map[string]int64{}}
	more.source = &testRatedSyncSource{testSyncSource: world.source, clock: world.cache.clock, rate: 10 * 1000 * 1000, landedAt: map[string]time.Time{}}
	engine, err := newSearchSync(&searchSyncArgs{
		cache: world.cache.cache, settings: world.cache.settings, format: DefaultIndexFormatSettings(), clock: world.cache.clock,
		log: NewNoopLogger(), readPathCount: 1, readByteCount: 32 * 1024 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	err = engine.Follow(&searchSyncRefArgs{
		repoId: world.repoId, refId: world.refId, repoKind: protocol.RepoKind_REPO_KIND_GENERAL, source: more.source,
		keepAll: func() bool { return false }, mayErase: func(Id, int64) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	more.engine = engine
	listing, err := world.head.ref.store(evsTestId("reader")).List(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	paths := indexNewPaths(false, indexRootNumber)
	for n := shardCount - 1; 0 <= n; n -= 1 {
		more.order = append(more.order, paths.allShard(uint32(n)))
	}
	for _, file := range listing.files {
		more.sizes[file.path] = int64(file.byteCount)
	}
	world.source.stateLock.Lock()
	world.source.fetches = nil
	world.source.stateLock.Unlock()
	return more
}

// The all shards fetched so far, in order, by path.
func (self *testMoreWorld) fetchedShards() []string {
	shards := []string{}
	for _, fetched := range self.sync.source.fetched() {
		path, _, _ := strings.Cut(fetched, "@")
		if strings.Contains(path, "/a/") && !strings.HasSuffix(path, "/a/m") {
			shards = append(shards, path)
		}
	}
	return shards
}

// What one call saw: its reports and each shard handed to the search, with the time each happened.
type testMoreRecord struct {
	stateLock sync.Mutex
	reports   []SearchMoreProgress
	shards    []string
	shardAt   []time.Time
}

// A call on world's engine, settings tuned by tune, recording into record; query stands for what a search asked, which
// the call never reads.
func (self *testMoreWorld) call(t *testing.T, policy *SearchPolicy, settings *SidecarSearchSettings, cursor *SearchMoreCursor, allowMetered bool, query string, record *testMoreRecord) (*SearchMore, SearchMoreProgress) {
	t.Helper()
	more, err := NewSearchMore(&SearchMoreArgs{
		Sync: self.engine, Policy: policy, Settings: settings, RepoId: self.sync.repoId, RefId: self.sync.refId,
		AllowMetered: allowMetered, Cursor: cursor, Clock: self.clock,
		OnShard: func(ctx context.Context, file *SearchManifestFile) error {
			// a search of the shard for query would run here; the call itself never sees the query
			record.stateLock.Lock()
			defer record.stateLock.Unlock()
			record.shards = append(record.shards, file.Path)
			record.shardAt = append(record.shardAt, self.clock.Now())
			_ = query
			return nil
		},
		OnProgress: func(progress SearchMoreProgress) {
			record.stateLock.Lock()
			defer record.stateLock.Unlock()
			record.reports = append(record.reports, progress)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	progress, err := more.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return more, progress
}

// A desktop's policy on the world's clock.
func (self *testMoreWorld) desktopPolicy(t *testing.T, settings *SidecarSearchSettings) *SearchPolicy {
	t.Helper()
	return testNewSearchPolicy(t, settings, nil, self.clock, &SearchConditions{DaemonHost: true})
}

// FS-110: four queries give one fetch trace, every missing all shard whole and youngest first; the first report comes
// at once, a report at each shard, none a second apart; each shard reaches the search as it lands; complete within
// B / R + 1 s.
func TestSearchMoreColdContract(t *testing.T) {
	traces := [][]string{}
	for _, query := range []string{"harbor lights", "invoice 2031", "\"ferry schedule\"", "-noise quiet"} {
		world := newTestMoreWorld(t, 6)
		settings := DefaultSidecarSettings().Search
		record := &testMoreRecord{}
		start := world.clock.Now()
		_, progress := world.call(t, world.desktopPolicy(t, settings), settings, nil, false, query, record)
		trace := world.fetchedShards()
		traces = append(traces, trace)
		if !slices.Equal(trace, world.order) {
			t.Fatalf("%s: the fetch order %v, want %v", query, trace, world.order)
		}
		if !progress.Complete || progress.SearchedCount != 6 || progress.ShardCount != 6 {
			t.Fatalf("%s: the call %+v", query, progress)
		}
		total := int64(0)
		for _, path := range world.order {
			total += world.sizes[path]
		}
		if progress.MissingByteCount != total || progress.FetchedByteCount != total || progress.MeteredByteCount < total {
			t.Fatalf("%s: bytes %+v, want B %d", query, progress, total)
		}
		bound := start.Add(time.Duration(total*int64(time.Second)/(10*1000*1000)) + time.Second)
		if progress.At.After(bound) {
			t.Fatalf("%s: complete at %s, past B / R + 1 s at %s", query, progress.At, bound)
		}
		if first := record.reports[0]; first.At.Sub(start) > settings.MoreFirstProgress || first.Complete {
			t.Fatalf("%s: the first report %+v", query, first)
		}
		for index := 1; index < len(record.reports); index += 1 {
			if gap := record.reports[index].At.Sub(record.reports[index-1].At); settings.MoreProgressInterval < gap {
				t.Fatalf("%s: reports %s apart", query, gap)
			}
		}
		if !slices.Equal(record.shards, world.order) {
			t.Fatalf("%s: shards searched %v", query, record.shards)
		}
		for index, path := range record.shards {
			if landed := world.source.landedAt[path]; !record.shardAt[index].Equal(landed) {
				t.Fatalf("%s: a shard searched at %s, landed at %s", query, record.shardAt[index], landed)
			}
		}
	}
	for _, trace := range traces[1:] {
		if !slices.Equal(trace, traces[0]) {
			t.Fatal("two queries gave two fetch traces")
		}
	}
}

// §16.10's complete row: past MoreByteCount a call is partial, and the next call with its cursor fetches on from the
// first shard not yet searched, in the same fixed order, never fetching one twice.
func TestSearchMorePartialGoesOnFromItsCursor(t *testing.T) {
	world := newTestMoreWorld(t, 5)
	settings := DefaultSidecarSettings().Search
	settings.MoreByteCount = world.sizes[world.order[0]] + world.sizes[world.order[1]]
	policy := world.desktopPolicy(t, settings)
	record := &testMoreRecord{}
	more, progress := world.call(t, policy, settings, nil, false, "q", record)
	if !progress.Partial || progress.Complete || progress.SearchedCount != 2 {
		t.Fatalf("the first call %+v", progress)
	}
	if !slices.Equal(world.fetchedShards(), world.order[:2]) {
		t.Fatalf("the first call fetched %v", world.fetchedShards())
	}
	cursor := more.Cursor()
	for calls := 0; calls < 5 && !progress.Complete; calls += 1 {
		more, progress = world.call(t, policy, settings, cursor, false, "q", record)
		cursor = more.Cursor()
	}
	if !progress.Complete {
		t.Fatalf("the calls never completed: %+v", progress)
	}
	if !slices.Equal(world.fetchedShards(), world.order) || !slices.Equal(record.shards, world.order) {
		t.Fatalf("fetched %v, searched %v, want each once in %v", world.fetchedShards(), record.shards, world.order)
	}
}

// §18.4's caps row: under a cap smaller than all, every shard is still searched as it lands, the youngest within the
// cap stay, and the call completes.
func TestSearchMoreKeepsTheYoungestWithinTheCap(t *testing.T) {
	world := newTestMoreWorld(t, 4)
	settings := DefaultSidecarSettings().Search
	settings.AllCacheByteCount = world.sizes[world.order[0]] + world.sizes[world.order[1]]
	record := &testMoreRecord{}
	_, progress := world.call(t, world.desktopPolicy(t, settings), settings, nil, false, "q", record)
	if !progress.Complete || !slices.Equal(record.shards, world.order) {
		t.Fatalf("the call %+v searched %v", progress, record.shards)
	}
	held, err := world.sync.cache.cache.Ref(world.sync.repoId, world.sync.refId)
	if err != nil {
		t.Fatal(err)
	}
	kept := []string{}
	for _, file := range held.Files {
		if strings.Contains(file.Key.Path, "/a/") && !strings.HasSuffix(file.Key.Path, "/a/m") {
			kept = append(kept, file.Key.Path)
		}
	}
	slices.Sort(kept)
	want := slices.Clone(world.order[:2])
	slices.Sort(want)
	if !slices.Equal(kept, want) {
		t.Fatalf("kept %v, want the youngest %v", kept, want)
	}
}

// §18.4's metered row: a call past MeteredMoreByteCount on a metered link fetches nothing and waits; asked again with
// AllowMetered it fetches.
func TestSearchMoreWaitsOnAMeteredLink(t *testing.T) {
	world := newTestMoreWorld(t, 3)
	settings := testPhoneSearchSettings()
	settings.MeteredMoreByteCount = 1
	conditions := &SearchConditions{Reported: true}
	policy := testNewSearchPolicy(t, settings, nil, world.clock, conditions)
	record := &testMoreRecord{}
	_, progress := world.call(t, policy, settings, nil, false, "q", record)
	if progress.Waiting != SearchWaitingMetered || progress.Complete || len(world.fetchedShards()) != 0 || len(record.shards) != 0 {
		t.Fatalf("a metered call %+v fetched %v", progress, world.fetchedShards())
	}
	if progress.MissingByteCount == 0 {
		t.Fatal("the wait does not say the bytes")
	}
	_, progress = world.call(t, policy, settings, nil, true, "q", record)
	if !progress.Complete || !slices.Equal(world.fetchedShards(), world.order) {
		t.Fatalf("with AllowMetered %+v fetched %v", progress, world.fetchedShards())
	}
}
