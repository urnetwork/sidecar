//go:build !ios_extension

package sidecar

// SEARCH-M10-19 (DESIGN-DETAILS 7.2.7 and 7.6's search_sync_test.go): the sync engine on a fake source over the fake
// index ref's every version. A snapshot is one version of the index ref even when a merge and a slot's reuse land
// between the replay and the fetch (IndexSync's MixedPin); collected restarts the round; the swap waits for every
// latest file (SwapPartial); all is never ahead (AllAhead); a retained bucket bridges a stale all only when its copy is
// the roll-up's input (RetainStale) and a stale all without it is never searched (StaleAllSearched); a listing
// retains nothing; a bad file never blocks the swap and alarms naming its signer; hints coalesce leading-edge; the
// fetch order reads nothing a search did (FI-23); an erasure ends open snapshots; and a running search keeps its
// snapshot through a swap.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A fake of searchSyncSource over one fake ref's versions: a replay diffs consecutive versions, a fetch seals each
// file's plaintext as evs seals a record and answers collected for a version the head no longer keeps.
type testSyncSource struct {
	t      *testing.T
	ref    *testIndexRef
	repoId Id
	refId  Id

	stateLock sync.Mutex
	// A replay past this many statements answers catch-up; 0 never does.
	catchUpCount int
	// Each Fetch's (path, version), in order.
	fetches [][]string
	// Run before the fetch call of that index answers, outside every lock: a push racing the round.
	beforeFetch map[int]func()
	// The fetch call of that index fails.
	failFetch  map[int]error
	fetchCalls int
	// Paths whose bytes are changed in transit.
	tamper map[string]bool
	// Changes a replayed statement.
	mutate func(statement *searchSyncStatement)
	// Replays so far.
	replays int
}

func newTestSyncSource(t *testing.T, ref *testIndexRef, repoId Id, refId Id) *testSyncSource {
	return &testSyncSource{t: t, ref: ref, repoId: repoId, refId: refId, beforeFetch: map[int]func(){}, failFetch: map[int]error{}, tamper: map[string]bool{}}
}

// The newest version of each path in a state.
func testSyncNewest(state *testIndexState) map[string]*indexFileVersion {
	newest := map[string]*indexFileVersion{}
	for path, versions := range state.files {
		file := *versions[len(versions)-1].version
		newest[path] = &file
	}
	return newest
}

func (self *testSyncSource) Replay(ctx context.Context, pin SearchSyncPin) (*searchSyncReplay, error) {
	self.ref.stateLock.Lock()
	states := slices.Clone(self.ref.states)
	self.ref.stateLock.Unlock()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.replays += 1
	head := states[len(states)-1].head
	if head.version < pin.Version {
		return nil, errors.New("test sync source: a pin past the head")
	}
	replay := &searchSyncReplay{head: head}
	for version := pin.Version + 1; version <= head.version; version += 1 {
		previous, current := states[version-1], states[version]
		before, after := testSyncNewest(previous), testSyncNewest(current)
		statement := &searchSyncStatement{
			version: version, chain: current.head.chain, signedTimeMs: current.head.signedTimeMs, signer: evsTestId("remover"),
			indexEpoch: previous.head.indexEpoch, cut: current.head.indexEpoch != previous.head.indexEpoch,
		}
		paths := []string{}
		for path := range after {
			paths = append(paths, path)
		}
		for path := range before {
			if after[path] == nil {
				paths = append(paths, path)
			}
		}
		slices.Sort(paths)
		for _, path := range paths {
			file, old := after[path], before[path]
			switch {
			case file == nil:
				statement.changes = append(statement.changes, &searchSyncChange{path: path})
			case old == nil || old.version != file.version:
				statement.changes = append(statement.changes, &searchSyncChange{path: path, file: file})
				statement.signer = file.signerSidecarId
			}
		}
		if self.mutate != nil {
			self.mutate(statement)
		}
		replay.statements = append(replay.statements, statement)
	}
	if 0 < self.catchUpCount && self.catchUpCount < len(replay.statements) {
		return &searchSyncReplay{head: head, catchUp: true}, nil
	}
	return replay, nil
}

func (self *testSyncSource) List(ctx context.Context) (*indexListing, error) {
	return self.ref.store(evsTestId("reader")).List(ctx, 0)
}

func (self *testSyncSource) Fetch(ctx context.Context, files []*indexFileVersion) ([]*searchSyncFetched, error) {
	self.stateLock.Lock()
	call := self.fetchCalls
	self.fetchCalls += 1
	before := self.beforeFetch[call]
	fail := self.failFetch[call]
	asked := []string{}
	for _, file := range files {
		asked = append(asked, fmt.Sprintf("%s@%d", file.path, file.version))
	}
	self.fetches = append(self.fetches, asked)
	self.stateLock.Unlock()
	if before != nil {
		before()
	}
	if fail != nil {
		return nil, fail
	}
	self.ref.stateLock.Lock()
	head := self.ref.headStateWithLock()
	plaintexts := map[string][]byte{}
	for _, file := range files {
		for _, stored := range head.files[file.path] {
			if stored.version.version == file.version {
				plaintexts[file.path] = stored.plaintext
			}
		}
	}
	self.ref.stateLock.Unlock()
	fetched := []*searchSyncFetched{}
	for _, file := range files {
		plaintext, ok := plaintexts[file.path]
		if !ok {
			fetched = append(fetched, &searchSyncFetched{file: file, collected: true})
			continue
		}
		plaintext = slices.Clone(plaintext)
		self.stateLock.Lock()
		tampered := self.tamper[file.path]
		self.stateLock.Unlock()
		if tampered {
			plaintext[len(plaintext)-1] ^= 1
		}
		key := SearchCacheKey{RepoId: self.repoId, RefId: self.refId, Path: file.path, Version: file.version}
		record := newTestSearchRecord(self.t, key, SearchCachePartition{}, plaintext)
		record.record.WrappedObjectKey = testSyncWrappedKey(file.path, file.version)
		fetched = append(fetched, &searchSyncFetched{file: file, record: record.record})
	}
	return fetched, nil
}

// The fetch log, flattened.
func (self *testSyncSource) fetched() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Concat(self.fetches...)
}

// A cache, a fake index ref with its writers, and an engine following the ref.
type testSyncWorld struct {
	cache     *testSearchCacheWorld
	head      *testHeadWorld
	source    *testSyncSource
	sync      *SearchSync
	repoId    Id
	refId     Id
	keepAll   bool
	stateLock sync.Mutex
	events    []SidecarEvent
}

func newTestSyncWorld(t *testing.T, keepAll bool) *testSyncWorld {
	t.Helper()
	world := &testSyncWorld{
		cache:   newTestSearchCacheWorld(t, 1<<30),
		head:    testNewHeadWorld(),
		repoId:  evsTestId("view repo"),
		refId:   evsTestId("view ref"),
		keepAll: keepAll,
	}
	world.source = newTestSyncSource(t, world.head.ref, world.repoId, world.refId)
	world.restart(t)
	return world
}

// A fresh engine over the world's cache and source, as a process start makes one.
func (self *testSyncWorld) restart(t *testing.T) {
	t.Helper()
	engine, err := newSearchSync(&searchSyncArgs{
		cache:    self.cache.cache,
		settings: self.cache.settings,
		format:   DefaultIndexFormatSettings(),
		clock:    self.cache.clock,
		log:      NewNoopLogger(),
		events: func(event SidecarEvent) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.events = append(self.events, event)
		},
		readPathCount: 64,
		readByteCount: 32 * 1024 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = engine.Follow(&searchSyncRefArgs{
		repoId: self.repoId, refId: self.refId, repoKind: protocol.RepoKind_REPO_KIND_GENERAL, source: self.source,
		keepAll: func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.keepAll
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	self.sync = engine
}

func (self *testSyncWorld) setKeepAll(keepAll bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.keepAll = keepAll
}

// One round now, failing on an error.
func (self *testSyncWorld) round(t *testing.T) {
	t.Helper()
	if err := self.sync.RunRound(context.Background(), self.repoId, self.refId, false); err != nil {
		t.Fatal(err)
	}
}

// A snapshot, released when the test ends.
func (self *testSyncWorld) snapshot(t *testing.T) *SearchSyncSnapshot {
	t.Helper()
	snapshot, err := self.sync.Snapshot(self.repoId, self.refId)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(snapshot.Release)
	return snapshot
}

// The index_malformed events raised so far, by path.
func (self *testSyncWorld) malformed() map[string]Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	malformed := map[string]Id{}
	for _, event := range self.events {
		if event.Kind == SidecarEventIndexMalformed && event.SidecarId != nil {
			malformed[event.Path] = *event.SidecarId
		}
	}
	return malformed
}

// The fake ref's newest file versions at refVersion, the lock left out.
func (self *testSyncWorld) listingAt(t *testing.T, refVersion uint64) map[string]uint64 {
	t.Helper()
	self.head.ref.stateLock.Lock()
	defer self.head.ref.stateLock.Unlock()
	state, err := self.head.ref.stateAtWithLock(refVersion)
	if err != nil {
		t.Fatal(err)
	}
	listing := map[string]uint64{}
	for path, file := range testSyncNewest(state) {
		if !strings.HasSuffix(path, "/lock") {
			listing[path] = file.version
		}
	}
	return listing
}

// FI-18's one pin: the snapshot's latest-set files are exactly those its pin lists, each at the listed version.
func (self *testSyncWorld) assertOneVersion(t *testing.T, snapshot *SearchSyncSnapshot) {
	t.Helper()
	listing := self.listingAt(t, snapshot.Pin().Version)
	held := map[string]uint64{}
	for _, file := range snapshot.manifest.Files {
		if !file.Partition.All && !self.retained(t, file.Partition.StartDay) {
			held[file.Path] = file.Version
		}
	}
	for path, version := range listing {
		if strings.Contains(path, "/a/") && !strings.HasSuffix(path, "/a/m") {
			continue
		}
		if held[path] != version {
			t.Fatalf("a snapshot at v%d holds %d of a file the pin lists at %d", snapshot.Pin().Version, held[path], version)
		}
	}
	for path, version := range held {
		if listing[path] != version {
			t.Fatalf("a snapshot at v%d holds a file at %d that its pin lists at %d", snapshot.Pin().Version, version, listing[path])
		}
	}
}

// Whether the cache retains the bucket starting on startDay.
func (self *testSyncWorld) retained(t *testing.T, startDay uint32) bool {
	t.Helper()
	held, err := self.cache.cache.Ref(self.repoId, self.refId)
	if err != nil {
		t.Fatal(err)
	}
	if held == nil {
		return false
	}
	return slices.ContainsFunc(held.Retained, func(retained SearchCacheRetained) bool { return retained.StartDay == startDay })
}

// A writer's push of documents label 0 to count-1 at version 1.
func (self *testSyncWorld) push(t *testing.T, writer Id, label string, count int) {
	t.Helper()
	pending := []*indexPendingDocument{}
	for index := range count {
		pending = append(pending, testLive(label, index, 1, 0, testIndexKeys(0x100000+index*0x1000, 60, 3)))
	}
	self.head.push(t, writer, pending...)
}

// The paths of the bucket starting on startDay at the head.
func (self *testSyncWorld) bucketFiles(t *testing.T, startDay uint32) []*indexFileVersion {
	t.Helper()
	listing, err := self.head.ref.store(evsTestId("reader")).List(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	prefix := indexNewPaths(false, indexRootNumber).bucket(startDay) + "/"
	files := []*indexFileVersion{}
	for _, file := range listing.files {
		if strings.HasPrefix(file.path, prefix) {
			files = append(files, file)
		}
	}
	return files
}

// A roll-up of the bucket starting on startDay, as DESIGN-DETAILS 1.2.5 leaves it: every file of the bucket removed,
// all's shard 0 and a/m written in one push.
func (self *testSyncWorld) rollUp(t *testing.T, startDay uint32) {
	t.Helper()
	paths := indexNewPaths(false, indexRootNumber)
	roller := self.head.ref.store(evsTestId("roller"))
	removals := []*indexPushRemoval{}
	for _, file := range self.bucketFiles(t, startDay) {
		removals = append(removals, &indexPushRemoval{path: file.path, version: file.version})
	}
	shard := &indexShard{header: testShardHeader(indexFileAllShard), documents: []*indexShardDocument{testShardCopy("rolled", 0, 1, testIndexKeys(0x500000, 40, 3))}}
	manifest := &protocol.IndexManifest{Shards: []*protocol.IndexShard{{N: 0, Docs: 1, FirstDay: startDay, LastDay: startDay}}, RolledThroughDay: startDay}
	files := []*indexPushFile{
		{path: paths.allManifest(), plaintext: testSmallFile(t, manifest), replaces: roller.testVersionOf(paths.allManifest())},
		{path: paths.allShard(0), plaintext: testBuildShard(t, shard, false, testPadKey(t, 2)), replaces: roller.testVersionOf(paths.allShard(0))},
	}
	if _, err := roller.Commit(context.Background(), roller.testPush(t, self.head.at, files, removals)); err != nil {
		t.Fatal(err)
	}
	self.head.at = self.head.at.Add(time.Minute)
}

// The bucket every push of a test world writes.
const testSyncBucket = uint32(20340)

// 7.2.7's manifest and plan round-trip their formats exactly, and a decoder refuses all ahead of the pin.
func TestSearchManifestRoundTrip(t *testing.T) {
	manifest := &SearchManifest{
		Root: ".ur-index/i1", Pin: SearchSyncPin{Version: 9, Chain: sha256.Sum256([]byte("c9")), TimeMs: 1700000000000}, IndexEpoch: 4,
		Files: []*SearchManifestFile{
			{Path: ".ur-index/i1/b/20340/s/0", Version: 3, ContentSha256: sha256.Sum256([]byte("s")), ByteCount: 1024, Partition: SearchCachePartition{StartDay: 20340}, State: SearchManifestHeld, TimeMinMs: 1000, TimeMaxMs: 2000, Signer: evsTestId("merger"), Run: 77, WindowDays: 30},
			{Path: ".ur-index/i1/settings", Version: 1, State: SearchManifestBad, Signer: evsTestId("forger"), Small: []byte{1, 2}},
			{Path: ".ur-index/i1/b/20340/w/aa/" + strings.Repeat("aa", 16) + "/0", Version: 2, State: SearchManifestHeld, Signer: evsTestId("w"), Coverage: []*SearchManifestFileCoverage{{RefId: evsTestId("content"), Version: 8, Horizon: true}}},
		},
		All:     SearchManifestAll{Held: true, Pin: SearchSyncPin{Version: 7}, RolledThroughDay: 20310},
		Rolled:  []*SearchManifestRolled{{StartDay: 20310, WindowDays: 30, AtVersion: 8}},
		Content: []*SearchManifestContent{{RefId: evsTestId("content"), IndexedThrough: 8, Rows: []*SearchManifestCoverage{{Writer: evsTestId("w"), Version: 8, Horizon: true}}}},
		Pins:    []SearchSyncPinPair{{Version: 8, Chain: sha256.Sum256([]byte("c8"))}, {Version: 9, Chain: sha256.Sum256([]byte("c9"))}},
		Runs:    []*SearchManifestRun{{Slot: SearchVersionSlot{Kind: SearchVersionShards, StartDay: 20340}, RunId: 77, Inputs: []SearchVersionRunId{77}}},
		Listing: []*SearchSyncWanted{{Path: ".ur-index/i1/b/20340/s/0", Version: 3, ByteCount: 1024, Partition: SearchCachePartition{StartDay: 20340}, Signer: evsTestId("merger"), CommitVersion: 6}},
	}
	encoded, err := manifest.encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := searchDecodeManifest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, manifest) {
		t.Fatalf("the manifest came back changed:\n%+v\n%+v", decoded, manifest)
	}
	plan := &SearchSyncPlan{
		Root: "i1", Target: SearchSyncPin{Version: 12}, IndexEpoch: 4, By: SearchSyncByListing, Wanted: manifest.Listing,
		Staged: manifest.Files[:1], Rolled: []*SearchSyncRolled{{StartDay: 20310, WindowDays: 30, AtVersion: 11, InputWhole: true}},
		Pins: manifest.Pins,
	}
	encoded, err = plan.encode()
	if err != nil {
		t.Fatal(err)
	}
	decodedPlan, err := searchDecodePlan(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decodedPlan, plan) {
		t.Fatalf("the plan came back changed")
	}
	ahead := *manifest
	ahead.All.Pin.Version = 10
	encoded, err = ahead.encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := searchDecodeManifest(encoded); !errors.Is(err, errSearchManifestUndecodable) {
		t.Fatalf("all ahead of the pin decoded: %v", err)
	}
}

// IndexSync's MixedPin: a merge folds the writer's head into a shard and the writer reuses the slot between the replay
// and the fetch; the fetch answers collected, the round starts again on the new head, and the snapshot holds every
// file at one version of the ref, never a mix.
func TestASnapshotIsOneVersion(t *testing.T) {
	world := newTestSyncWorld(t, false)
	writer := evsTestId("writer")
	world.push(t, writer, "first", 1)
	world.round(t)
	world.assertOneVersion(t, world.snapshot(t))

	world.push(t, writer, "second", 1)
	world.source.beforeFetch[world.source.fetchCalls] = func() {
		world.head.absorb(t, writer, 2, testShardCopy("first", 0, 1, testIndexKeys(0x100000, 60, 3)), testShardCopy("second", 0, 1, testIndexKeys(0x100000, 60, 3)))
		world.push(t, writer, "third", 1)
	}
	world.round(t)
	snapshot := world.snapshot(t)
	head, _ := world.head.ref.store(writer).Head(context.Background())
	if snapshot.Pin().Version != head.version {
		t.Fatalf("the snapshot is at v%d, the head at v%d", snapshot.Pin().Version, head.version)
	}
	world.assertOneVersion(t, snapshot)
	if 0 < len(world.malformed()) {
		t.Fatalf("an honest index alarmed: %v", world.malformed())
	}
}

// 7.2.7's collected row: a read answering collected for a wanted version restarts the round at step 1, which reads
// the new head; the replaced version is never kept beside the new files.
func TestCollectedRestartsTheRound(t *testing.T) {
	world := newTestSyncWorld(t, false)
	writer := evsTestId("writer")
	world.push(t, writer, "first", 1)
	world.round(t)
	world.push(t, writer, "second", 1)
	replaysBefore := world.source.replays
	world.source.beforeFetch[world.source.fetchCalls] = func() { world.push(t, writer, "third", 1) }
	world.round(t)
	if world.source.replays != replaysBefore+2 {
		t.Fatalf("%d replays for one restarted round", world.source.replays-replaysBefore)
	}
	snapshot := world.snapshot(t)
	world.assertOneVersion(t, snapshot)
	held, err := world.cache.cache.Ref(world.repoId, world.refId)
	if err != nil {
		t.Fatal(err)
	}
	listing := world.listingAt(t, snapshot.Pin().Version)
	for _, file := range held.Files {
		if listing[file.Key.Path] != file.Key.Version {
			t.Fatalf("the cache keeps a replaced version past the round")
		}
	}
}

// IndexSync's SwapPartial: a round whose read fails midway swaps nothing, keeps what it staged, and the next round
// fetches only the rest.
func TestTheSwapWaitsForEveryFile(t *testing.T) {
	world := newTestSyncWorld(t, false)
	world.push(t, evsTestId("writer a"), "a", 1)
	world.push(t, evsTestId("writer b"), "b", 1)
	world.push(t, evsTestId("writer c"), "c", 1)
	world.sync.args.readPathCount = 1
	world.source.failFetch[1] = errors.New("test sync source: the read failed")
	if err := world.sync.RunRound(context.Background(), world.repoId, world.refId, false); err == nil {
		t.Fatal("a round whose read failed swapped")
	}
	if _, err := world.sync.Snapshot(world.repoId, world.refId); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Fatalf("a partial round left a snapshot: %v", err)
	}
	_, plan := world.sync.state(world.sync.refs[[2]Id{world.repoId, world.refId}])
	if plan == nil || len(plan.Staged) != 1 {
		t.Fatalf("the round kept no staged file")
	}
	first := world.source.fetched()[0]
	world.round(t)
	world.assertOneVersion(t, world.snapshot(t))
	count := 0
	for _, fetched := range world.source.fetched() {
		if fetched == first {
			count += 1
		}
	}
	if count != 1 {
		t.Fatalf("a staged file was fetched %d times", count)
	}
}

// IndexSync's AllAhead: all swaps only at the latest set's pin; an all read that fails leaves the latest swapped and
// all behind, and all reaches the pin in a later round.
func TestAllNeverLeads(t *testing.T) {
	world := newTestSyncWorld(t, true)
	writer := evsTestId("writer")
	world.push(t, writer, "first", 1)
	world.round(t)
	world.push(t, writer, "second", 1)
	world.rollUp(t, testSyncBucket)
	world.push(t, writer, "third", 1)
	// the latest set is one read; the all shard the next, which fails
	world.source.failFetch[world.source.fetchCalls+1] = errors.New("test sync source: the all read failed")
	if err := world.sync.RunRound(context.Background(), world.repoId, world.refId, false); err == nil {
		t.Fatal("the failed all read went unreported")
	}
	snapshot := world.snapshot(t)
	head, _ := world.head.ref.store(writer).Head(context.Background())
	if snapshot.Pin().Version != head.version || snapshot.manifest.All.Pin.Version == head.version {
		t.Fatalf("latest at v%d and all at v%d of v%d", snapshot.Pin().Version, snapshot.manifest.All.Pin.Version, head.version)
	}
	if snapshot.manifest.Pin.Version < snapshot.manifest.All.Pin.Version {
		t.Fatal("all leads the latest set")
	}
	snapshot.Release()
	world.round(t)
	snapshot = world.snapshot(t)
	if snapshot.manifest.All.Pin.Version != snapshot.Pin().Version || !snapshot.AllUsable() {
		t.Fatalf("all at v%d, latest at v%d", snapshot.manifest.All.Pin.Version, snapshot.Pin().Version)
	}
}

// The retained row: a device keeping all only at times sees a roll-up it did not take; the bucket it holds is the
// roll-up's input, so it is retained and bridges the stale all, which stays usable.
func TestARetainedBucketBridgesAStaleAll(t *testing.T) {
	world := newTestSyncWorld(t, true)
	world.push(t, evsTestId("writer"), "first", 1)
	world.round(t)
	world.setKeepAll(false)
	world.rollUp(t, testSyncBucket)
	world.round(t)
	if !world.retained(t, testSyncBucket) {
		t.Fatal("the roll-up's input bucket was not retained")
	}
	snapshot := world.snapshot(t)
	if !snapshot.AllUsable() {
		t.Fatal("a bridged stale all is not usable")
	}
	if len(snapshot.manifest.Rolled) != 1 || snapshot.manifest.Rolled[0].StartDay != testSyncBucket {
		t.Fatalf("rolled: %+v", snapshot.manifest.Rolled)
	}
	found := false
	for _, file := range snapshot.Files() {
		found = found || file.Partition.StartDay == testSyncBucket
	}
	if !found {
		t.Fatal("the retained bucket's files are not searched")
	}
}

// IndexSync's RetainStale: a push changed the bucket after this device's copy and before the roll-up, so its copy is
// not the roll-up's input: nothing is retained and the stale all is not searched.
func TestAStaleBucketIsNotRetained(t *testing.T) {
	world := newTestSyncWorld(t, true)
	writer := evsTestId("writer")
	world.push(t, writer, "first", 1)
	world.round(t)
	world.setKeepAll(false)
	world.push(t, writer, "deleted later", 1)
	world.rollUp(t, testSyncBucket)
	world.round(t)
	if world.retained(t, testSyncBucket) {
		t.Fatal("a stale copy of the bucket was retained")
	}
	if world.snapshot(t).AllUsable() {
		t.Fatal("a stale all with no bridge is usable")
	}
}

// IndexSync's StaleAllSearched: the retained bucket that bridged a stale all goes at an ERASE (or an executed drop,
// the same DropRetained), at RetainFactor windows past the roll-up, and with all evicted; each time all is no longer
// searched until it is fetched again.
func TestAStaleAllIsNotSearchedWithoutItsBucket(t *testing.T) {
	bridged := func(t *testing.T) *testSyncWorld {
		world := newTestSyncWorld(t, true)
		world.push(t, evsTestId("writer"), "first", 1)
		world.round(t)
		world.setKeepAll(false)
		world.rollUp(t, testSyncBucket)
		world.round(t)
		if !world.snapshot(t).AllUsable() {
			t.Fatal("no bridge to begin with")
		}
		return world
	}

	erased := bridged(t)
	if err := erased.cache.cache.DropRetained(erased.repoId); err != nil {
		t.Fatal(err)
	}
	if erased.snapshot(t).AllUsable() {
		t.Fatal("an ERASE's dropped bucket still bridges all")
	}

	aged := bridged(t)
	aged.cache.clock.advance(time.Duration(aged.cache.settings.RetainFactor) * 30 * 24 * time.Hour)
	aged.round(t)
	if aged.retained(t, testSyncBucket) || aged.snapshot(t).AllUsable() {
		t.Fatal("a bucket two windows past its roll-up still bridges all")
	}

	evicted := newTestSyncWorld(t, true)
	evicted.push(t, evsTestId("writer"), "first", 1)
	evicted.rollUp(t, testSyncBucket)
	evicted.push(t, evsTestId("writer"), "second", 1)
	evicted.round(t)
	snapshot := evicted.snapshot(t)
	if !snapshot.AllUsable() {
		t.Fatal("a fetched all is not usable")
	}
	snapshot.Release()
	for _, file := range snapshot.manifest.Files {
		if file.Partition.All {
			if err := evicted.cache.cache.Remove(SearchCacheKey{RepoId: evicted.repoId, RefId: evicted.refId, Path: file.Path, Version: file.Version}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if evicted.snapshot(t).AllUsable() {
		t.Fatal("an evicted all is usable")
	}
}

// 7.2.7's listing: past the catch-up budget the round re-pins and lists; a roll-up it did not see joins rolled[] as
// one entry with no bucket retained, so the stale all is not searched.
func TestAListingRetainsNothing(t *testing.T) {
	world := newTestSyncWorld(t, true)
	writer := evsTestId("writer")
	world.push(t, writer, "first", 1)
	world.round(t)
	world.setKeepAll(false)
	world.source.catchUpCount = 1
	world.rollUp(t, testSyncBucket)
	world.push(t, writer, "second", 1)
	world.round(t)
	snapshot := world.snapshot(t)
	if world.retained(t, testSyncBucket) {
		t.Fatal("a listing retained a bucket")
	}
	if snapshot.AllUsable() {
		t.Fatal("a stale all is usable after a listing")
	}
	if len(snapshot.manifest.Rolled) != 1 {
		t.Fatalf("rolled: %+v", snapshot.manifest.Rolled)
	}
	world.assertOneVersion(t, snapshot)
}

// 7.2.7's bad file: a file that fails indexValidateFile, or content_sha256 in transit, is listed bad, holds nothing,
// raises index_malformed naming its path and its push's signer, and does not hold the swap.
func TestABadFileDoesNotBlockTheSwap(t *testing.T) {
	world := newTestSyncWorld(t, false)
	world.push(t, evsTestId("writer"), "first", 1)
	forger := evsTestId("forger")
	forgedPath, err := indexNewPaths(false, indexRootNumber).slot(testSyncBucket, [indexIdByteCount]byte(forger), 0)
	if err != nil {
		t.Fatal(err)
	}
	world.head.ref.store(forger).testCommit(t, world.head.at, &indexPushFile{path: forgedPath, plaintext: []byte("not a slot")})
	tamperedWriter := evsTestId("tampered")
	world.push(t, tamperedWriter, "tampered", 1)
	tamperedPath, _ := indexNewPaths(false, indexRootNumber).slot(testSyncBucket, [indexIdByteCount]byte(tamperedWriter), 0)
	world.source.tamper[tamperedPath] = true
	world.round(t)
	snapshot := world.snapshot(t)
	world.assertOneVersion(t, snapshot)
	bad := map[string]bool{}
	for _, file := range snapshot.Bad() {
		bad[file.Path] = true
	}
	if !bad[forgedPath] || !bad[tamperedPath] || len(bad) != 2 {
		t.Fatalf("bad files: %v", bad)
	}
	for _, file := range snapshot.Files() {
		if bad[file.Path] {
			t.Fatal("a bad file is searched")
		}
	}
	malformed := world.malformed()
	if malformed[forgedPath] != forger || malformed[tamperedPath] != tamperedWriter {
		t.Fatalf("index_malformed named %v", malformed)
	}
	held, _ := world.cache.cache.Ref(world.repoId, world.refId)
	for _, file := range held.Files {
		if bad[file.Key.Path] {
			t.Fatal("a bad file's copy is kept")
		}
	}
}

// QD-048: the first hint in a quiet HintCoalesce starts a round at once; later ones in that interval start one at its
// end; the round at the end opens the next interval.
func TestLeadingEdgeCoalescing(t *testing.T) {
	world := newTestSyncWorld(t, false)
	world.push(t, evsTestId("writer"), "first", 1)
	ctx := context.Background()
	interval := world.cache.settings.HintCoalesce
	world.sync.Trigger(world.repoId, nil, SearchSyncHint)
	world.sync.RunDue(ctx)
	if world.source.replays != 1 {
		t.Fatalf("%d rounds for the leading hint", world.source.replays)
	}
	world.cache.clock.advance(interval / 6)
	world.sync.Trigger(world.repoId, nil, SearchSyncHint)
	world.cache.clock.advance(interval / 6)
	world.sync.Trigger(world.repoId, nil, SearchSyncHint)
	next := world.sync.RunDue(ctx)
	if world.source.replays != 1 {
		t.Fatalf("a hint inside the interval ran a round at once")
	}
	if want := world.cache.clock.Now().Add(interval - interval/3); !next.Equal(want) {
		t.Fatalf("the trailing round is due %s, not %s", next, want)
	}
	world.cache.clock.advance(interval - interval/3)
	world.sync.RunDue(ctx)
	if world.source.replays != 2 {
		t.Fatalf("%d rounds after the interval's end", world.source.replays)
	}
	world.cache.clock.advance(interval / 2)
	world.sync.Trigger(world.repoId, nil, SearchSyncHint)
	world.sync.RunDue(ctx)
	if world.source.replays != 2 {
		t.Fatal("a hint inside the interval the trailing round opened ran at once")
	}
}

// FI-23: what a round fetches and in what order follows from sync state alone. Two worlds in one sync state, one of
// them searched and snapshotted between rounds and one not, send equal reads; and a read's order is the settings and
// the erasure set, a/m, then the buckets newest first, each its manifest, its shards, then slots by path.
func TestFetchOrderIsQueryBlind(t *testing.T) {
	build := func(t *testing.T, searched bool) *testSyncWorld {
		world := newTestSyncWorld(t, true)
		writer := evsTestId("writer")
		world.push(t, writer, "first", 2)
		world.round(t)
		if searched {
			world.cache.cache.MarkSearched(world.repoId, world.refId, SearchCachePartition{All: true})
			world.snapshot(t).Release()
		}
		world.head.absorb(t, writer, 1, testShardCopy("first", 0, 1, testIndexKeys(0x100000, 60, 3)))
		world.push(t, evsTestId("other writer"), "second", 2)
		world.head.at = testDayTime(20371, 0)
		world.push(t, writer, "newer bucket", 1)
		if searched {
			world.snapshot(t).Release()
		}
		world.round(t)
		return world
	}
	plain, searched := build(t, false), build(t, true)
	if !slices.Equal(plain.source.fetched(), searched.source.fetched()) {
		t.Fatalf("the fetch traces differ:\n%v\n%v", plain.source.fetched(), searched.source.fetched())
	}
	last := plain.source.fetches[len(plain.source.fetches)-1]
	ranks := []int{}
	days := []uint32{}
	for _, fetched := range last {
		path, _, _ := strings.Cut(fetched, "@")
		parsed, ok := indexParsePath(path, false)
		if !ok {
			t.Fatalf("an unknown path fetched")
		}
		_, rank := searchFetchRank(parsed)
		ranks = append(ranks, rank)
		days = append(days, parsed.bucketStartDay)
	}
	if !slices.IsSortedFunc(days, func(a uint32, b uint32) int { return int(b) - int(a) }) {
		t.Fatalf("buckets were not fetched newest first: %v", days)
	}
	for index := 1; index < len(ranks); index += 1 {
		if days[index] == days[index-1] && ranks[index] < ranks[index-1] {
			t.Fatalf("a bucket's files out of order: %v", last)
		}
	}
}

// §16.10's pages row: an erasure ends every open snapshot of its repo at once, and a file only that snapshot held
// goes then.
func TestAnErasureEndsOpenSnapshots(t *testing.T) {
	world := newTestSyncWorld(t, false)
	writer := evsTestId("writer")
	world.push(t, writer, "first", 1)
	world.round(t)
	snapshot := world.snapshot(t)
	old := snapshot.Files()
	world.push(t, writer, "second", 1)
	world.round(t)
	select {
	case <-snapshot.Ended():
		t.Fatal("a swap ended a running search's snapshot")
	default:
	}
	world.sync.EndRepo(world.repoId)
	select {
	case <-snapshot.Ended():
	default:
		t.Fatal("an erasure left a snapshot open")
	}
	held, _ := world.cache.cache.Ref(world.repoId, world.refId)
	kept := map[SearchCacheKey]bool{}
	for _, file := range held.Files {
		kept[file.Key] = true
	}
	for _, file := range old {
		key := SearchCacheKey{RepoId: world.repoId, RefId: world.refId, Path: file.Path, Version: file.Version}
		if !kept[key] && world.listingAt(t, 0)[file.Path] == file.Version {
			t.Fatal("a current file went with the snapshot")
		}
		if kept[key] && world.listingAt(t, 0)[file.Path] != file.Version {
			t.Fatal("a replaced file outlived the snapshot that held it")
		}
	}
}

// §11.14's swap row: a running search keeps its snapshot through a swap; the replaced file stays readable until the
// snapshot is released, and goes then.
func TestASwapUnderARunningSearch(t *testing.T) {
	world := newTestSyncWorld(t, false)
	writer := evsTestId("writer")
	world.push(t, writer, "first", 1)
	world.round(t)
	snapshot := world.snapshot(t)
	replaced := []SearchCacheKey{}
	for _, file := range snapshot.Files() {
		replaced = append(replaced, SearchCacheKey{RepoId: world.repoId, RefId: world.refId, Path: file.Path, Version: file.Version})
	}
	world.push(t, writer, "second", 1)
	world.round(t)
	for _, key := range replaced {
		if _, err := world.cache.cache.OpenRecord(key); err != nil {
			t.Fatalf("a running search's file went at the swap: %v", err)
		}
	}
	if world.snapshot(t).Pin().Version <= snapshot.Pin().Version {
		t.Fatal("the swap did not move the manifest")
	}
	snapshot.Release()
	listing := world.listingAt(t, 0)
	for _, key := range replaced {
		_, err := world.cache.cache.OpenRecord(key)
		if listing[key.Path] != key.Version && !errors.Is(err, ErrSidecarStoreAbsent) {
			t.Fatalf("a replaced file outlived its last snapshot: %v", err)
		}
	}
}

// §11.14's epoch row in the round: an index push naming another index_epoch than the ref's newest CUT before it
// raises index_malformed naming its signer; FI-17: a path under the index prefix that is not §11.14's is ignored and
// alarmed once; and a config repo is never followed.
func TestSearchSyncAlarms(t *testing.T) {
	world := newTestSyncWorld(t, false)
	writer := evsTestId("writer")
	world.push(t, writer, "first", 1)
	world.source.mutate = func(statement *searchSyncStatement) {
		statement.indexEpoch = 99
	}
	world.round(t)
	slotPath, _ := indexNewPaths(false, indexRootNumber).slot(testSyncBucket, [indexIdByteCount]byte(writer), 0)
	if world.malformed()[slotPath] != writer {
		t.Fatalf("an index push naming another epoch raised %v", world.malformed())
	}
	world.source.mutate = nil
	junk := indexFileModePrefix + "i1/junk"
	world.head.ref.store(evsTestId("planter")).testCommit(t, world.head.at, &indexPushFile{path: junk, plaintext: []byte("x")})
	world.round(t)
	world.round(t)
	count := 0
	world.stateLock.Lock()
	for _, event := range world.events {
		if event.Path == junk {
			count += 1
		}
	}
	world.stateLock.Unlock()
	if count != 1 {
		t.Fatalf("an unknown index path alarmed %d times", count)
	}
	for _, fetched := range world.source.fetched() {
		if strings.HasPrefix(fetched, junk) {
			t.Fatal("an unknown index path was fetched")
		}
	}
	err := world.sync.Follow(&searchSyncRefArgs{repoId: NewId(), refId: NewId(), repoKind: protocol.RepoKind_REPO_KIND_CONFIG, source: world.source})
	if !errors.Is(err, ErrSearchSyncUnfollowed) {
		t.Fatalf("a config repo was followed: %v", err)
	}
}

// §11.14's swap row: a search never waits for a round. A snapshot taken while a round is inside its fetch returns the
// manifest it holds at once, and it stays readable after that round swaps past it.
func TestASnapshotNeverWaitsForARound(t *testing.T) {
	world := newTestSyncWorld(t, false)
	writer := evsTestId("writer")
	world.push(t, writer, "first", 1)
	world.round(t)
	world.push(t, writer, "second", 1)
	var during *SearchSyncSnapshot
	world.source.beforeFetch[world.source.fetchCalls] = func() {
		snapshot, err := world.sync.Snapshot(world.repoId, world.refId)
		if err != nil {
			t.Error(err)
			return
		}
		during = snapshot
	}
	world.round(t)
	if during == nil {
		t.Fatal("no snapshot was taken inside the round")
	}
	defer during.Release()
	world.assertOneVersion(t, during)
	if after := world.snapshot(t); after.Pin().Version <= during.Pin().Version {
		t.Fatal("the round did not swap past the snapshot taken inside it")
	}
	for _, file := range during.Files() {
		key := SearchCacheKey{RepoId: world.repoId, RefId: world.refId, Path: file.Path, Version: file.Version}
		if _, err := world.cache.cache.OpenRecord(key); err != nil {
			t.Fatalf("a file the snapshot holds went at the swap: %v", err)
		}
	}
}

// What the fake source gives as a record's wrapped object key: bytes of its own a file version.
func testSyncWrappedKey(path string, version uint64) []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("wrapped %s %d", path, version)))
	return sum[:]
}

// QD-838: every file a round keeps carries its record's wrapped object key and file id in the cache, so a reader with
// the generation's key reopens it after the round with no read of evs.
func TestAKeptFileKeepsItsWrappedKey(t *testing.T) {
	world := newTestSyncWorld(t, false)
	world.push(t, evsTestId("writer"), "first", 2)
	world.round(t)
	snapshot := world.snapshot(t)
	if len(snapshot.Files()) == 0 {
		t.Fatal("no file kept")
	}
	for _, file := range snapshot.Files() {
		frames, err := world.cache.cache.OpenRecord(SearchCacheKey{RepoId: world.repoId, RefId: world.refId, Path: file.Path, Version: file.Version})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(frames.WrappedObjectKey(), testSyncWrappedKey(file.Path, file.Version)) {
			t.Fatal("a kept file lost its wrapped key")
		}
		if fileId, err := frames.FileId(); err != nil || fileId == (Id{}) {
			t.Fatalf("a kept file lost its file id: %v", err)
		}
	}
}
