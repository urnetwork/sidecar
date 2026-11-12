//go:build !ios_extension

package sidecar

// CORE-M10-02: §5.9's version table. Runs built by a bounded streaming merge from shards, slots and lists, each key's
// highest version kept; probes one page a level through the version-page LRU; a snapshot keeping its runs through a
// retirement; erased keys masked; FS-109's half a million changed files probed per candidate in a phone's working set;
// and the runs' bytes pinned by vectors on every leg (D-TEST-15).

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"slices"
	"strconv"
	"testing"
)

// A ref the cache follows, and a table of its index root.
type versionTableTestWorld struct {
	cache  *SearchCache
	table  *SearchVersionTable
	repoId Id
	refId  Id
}

// pageByteCount 0 keeps the default page size.
func newVersionTableTestWorld(t *testing.T, pageByteCount int) *versionTableTestWorld {
	t.Helper()
	cacheWorld := newTestSearchCacheWorld(t, 1<<40)
	if 0 < pageByteCount {
		cacheWorld.settings.VersionPageByteCount = pageByteCount
	}
	repoId, refId := NewId(), NewId()
	if err := cacheWorld.cache.SetRefVersion(repoId, refId, 1); err != nil {
		t.Fatal(err)
	}
	table, err := NewSearchVersionTable(cacheWorld.cache, repoId, refId, ".ur-index/i1")
	if err != nil {
		t.Fatal(err)
	}
	return &versionTableTestWorld{cache: cacheWorld.cache, table: table, repoId: repoId, refId: refId}
}

// A doc key from a label and an index.
func versionTestKey(label string, index int) [indexIdByteCount]byte {
	return testIndexId(label, index)
}

// A record of a document.
func versionTestRecord(label string, index int, version uint64, tombstone bool, path string) SearchVersionRecord {
	return SearchVersionRecord{Key: versionTestKey(label, index), Version: version, Tombstone: tombstone, File: SearchVersionFile{Path: path, Version: 3}}
}

// Builds slot's run from sources.
func (self *versionTableTestWorld) merge(t *testing.T, slot SearchVersionSlot, sources ...SearchVersionSource) SearchVersionRunId {
	t.Helper()
	runId, err := self.table.Merge(t.Context(), slot, sources)
	if err != nil {
		t.Fatal(err)
	}
	return runId
}

// Probes one doc key over runIds.
func (self *versionTableTestWorld) probe(t *testing.T, runIds []SearchVersionRunId, key [indexIdByteCount]byte, refId *Id) SearchVersionProbe {
	t.Helper()
	probe, err := self.table.Probe(runIds, key, refId)
	if err != nil {
		t.Fatal(err)
	}
	return probe
}

// Each key keeps its highest version over a run's inputs, a tombstone winning a tie; across runs a probe takes the
// highest, and a candidate is current only at that version, not deleted, below its ref's tombstone.
func TestVersionTableKeepsNewest(t *testing.T) {
	world := newVersionTableTestWorld(t, 0)
	shards := world.merge(t, SearchVersionSlot{Kind: SearchVersionShards, StartDay: 20340},
		SearchVersionRecordsSource{versionTestRecord("doc", 1, 4, false, "b/20340/0"), versionTestRecord("doc", 2, 7, false, "b/20340/0")},
		SearchVersionRecordsSource{versionTestRecord("doc", 1, 6, false, "b/20340/1"), versionTestRecord("doc", 3, 2, false, "b/20340/1")},
	)
	others := world.merge(t, SearchVersionSlot{Kind: SearchVersionOthers, StartDay: 20340},
		SearchVersionRecordsSource{versionTestRecord("doc", 2, 7, true, "b/20340/w/aa/1"), versionTestRecord("doc", 3, 9, false, "b/20340/w/aa/2")},
	)
	all := world.merge(t, SearchVersionSlot{Kind: SearchVersionAll},
		SearchVersionRecordsSource{versionTestRecord("doc", 1, 2, false, "a/0"), versionTestRecord("doc", 4, 1, false, "a/0")},
	)
	runs := []SearchVersionRunId{shards, others, all}

	probe := world.probe(t, runs, versionTestKey("doc", 1), nil)
	if probe.Version != 6 || probe.Tombstone || probe.File.Path != "b/20340/1" || probe.Slot.Kind != SearchVersionShards {
		t.Errorf("doc 1: %+v", probe)
	}
	if !probe.Current(6) || probe.Current(2) || probe.Current(4) {
		t.Error("doc 1 current at the wrong versions")
	}
	// a tombstone at the version a shard holds masks it
	if probe := world.probe(t, runs, versionTestKey("doc", 2), nil); !probe.Tombstone || probe.Current(7) {
		t.Errorf("doc 2: %+v", probe)
	}
	if probe := world.probe(t, runs, versionTestKey("doc", 3), nil); probe.Version != 9 || probe.Slot.Kind != SearchVersionOthers {
		t.Errorf("doc 3: %+v", probe)
	}
	if probe := world.probe(t, runs, versionTestKey("doc", 4), nil); !probe.Current(1) || probe.Slot.Kind != SearchVersionAll {
		t.Errorf("doc 4: %+v", probe)
	}
	if probe := world.probe(t, runs, versionTestKey("doc", 5), nil); probe.Found || probe.Current(0) {
		t.Errorf("an absent doc: %+v", probe)
	}

	// a ref tombstone above a row's version masks it on ur/index
	refId := NewId()
	refStone := SearchVersionRecord{Key: [indexIdByteCount]byte(refId), RefTombstone: true, Version: 5, File: SearchVersionFile{Path: "b/20340/w/bb/1", Version: 1}}
	stones := world.merge(t, SearchVersionSlot{Kind: SearchVersionOthers, StartDay: 20370}, SearchVersionRecordsSource{refStone})
	withStones := append(slices.Clone(runs), stones)
	if probe := world.probe(t, withStones, versionTestKey("doc", 4), &refId); probe.RefTombstoneVersion != 5 || probe.Current(1) {
		t.Errorf("under a ref tombstone: %+v", probe)
	}
	if probe := world.probe(t, withStones, versionTestKey("doc", 1), &refId); !probe.Current(6) {
		t.Errorf("above a ref tombstone: %+v", probe)
	}
	otherRef := NewId()
	if probe := world.probe(t, withStones, versionTestKey("doc", 4), &otherRef); probe.RefTombstoneVersion != 0 || !probe.Current(1) {
		t.Errorf("another ref: %+v", probe)
	}
	// a ref tombstone masks what it is above, so a row at its own version stands (§11.14's newest row)
	level := world.merge(t, SearchVersionSlot{Kind: SearchVersionOthers, StartDay: 20400}, SearchVersionRecordsSource{
		{Key: [indexIdByteCount]byte(refId), RefTombstone: true, Version: 6, File: SearchVersionFile{Path: "b/20400/w/bb/1", Version: 1}},
	})
	if probe := world.probe(t, append(slices.Clone(runs), level), versionTestKey("doc", 1), &refId); probe.RefTombstoneVersion != 6 || !probe.Current(6) {
		t.Errorf("a ref tombstone at the row's version: %+v", probe)
	}
}

// Keys an ERASE names are masked at every version until the rewritten files are cached; an erasure set's documents
// at and below their version.
func TestErasedKeysMasked(t *testing.T) {
	world := newVersionTableTestWorld(t, 0)
	bucket := world.merge(t, SearchVersionSlot{Kind: SearchVersionShards, StartDay: 20340},
		SearchVersionRecordsSource{versionTestRecord("doc", 1, 3, false, "b/20340/0"), versionTestRecord("doc", 2, 8, false, "b/20340/0"),
			versionTestRecord("doc", 3, 4, false, "b/20340/0")},
	)
	erase := world.merge(t, SearchVersionSlot{Kind: SearchVersionErased},
		SearchVersionRecordsSource{{Key: versionTestKey("doc", 1), Version: SearchVersionErasedAll}},
	)
	set := world.merge(t, SearchVersionSlot{Kind: SearchVersionErased},
		SearchVersionRecordsSource{{Key: versionTestKey("doc", 2), Version: 8}, {Key: versionTestKey("doc", 3), Version: 2}},
	)
	runs := []SearchVersionRunId{bucket, erase, set}
	if probe := world.probe(t, runs, versionTestKey("doc", 1), nil); probe.ErasedThrough != SearchVersionErasedAll || probe.Current(3) {
		t.Errorf("an ERASE's key: %+v", probe)
	}
	if probe := world.probe(t, runs, versionTestKey("doc", 2), nil); probe.Current(8) {
		t.Errorf("a version the erasure set lists: %+v", probe)
	}
	// a newer version than the set lists is not erased
	if probe := world.probe(t, runs, versionTestKey("doc", 3), nil); !probe.Current(4) {
		t.Errorf("a version above the erasure set's: %+v", probe)
	}
	// once the rewritten files are cached the ERASE's run leaves the snapshot, and the key reads as its files say
	if probe := world.probe(t, []SearchVersionRunId{bucket, set}, versionTestKey("doc", 1), nil); !probe.Current(3) {
		t.Errorf("after the ERASE's run left: %+v", probe)
	}
}

// A snapshot keeps its runs: retiring them while it is open removes nothing until it closes, and its probes read on.
func TestSnapshotKeepsRuns(t *testing.T) {
	world := newVersionTableTestWorld(t, 0)
	old := world.merge(t, SearchVersionSlot{Kind: SearchVersionShards, StartDay: 20340},
		SearchVersionRecordsSource{versionTestRecord("doc", 1, 3, false, "b/20340/0")})
	snapshot, err := world.table.Snapshot([]SearchVersionRunId{old})
	if err != nil {
		t.Fatal(err)
	}
	replacement := world.merge(t, SearchVersionSlot{Kind: SearchVersionShards, StartDay: 20340},
		SearchVersionRecordsSource{versionTestRecord("doc", 1, 5, false, "b/20340/0")})
	if err := world.table.Retire([]SearchVersionRunId{replacement}); err != nil {
		t.Fatal(err)
	}
	if probe, err := snapshot.Probe(versionTestKey("doc", 1), nil); err != nil || !probe.Current(3) {
		t.Fatalf("the open snapshot: %+v %v", probe, err)
	}
	runIds, err := world.table.RunIds()
	if err != nil || !slices.Contains(runIds, old) {
		t.Fatalf("a held run was removed: %v %v", runIds, err)
	}
	snapshot.Close()
	runIds, err = world.table.RunIds()
	if err != nil || slices.Contains(runIds, old) || !slices.Contains(runIds, replacement) {
		t.Errorf("after the close: %v %v", runIds, err)
	}
	if _, err := world.table.Snapshot([]SearchVersionRunId{old}); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("a removed run opened: %v", err)
	}
	if probe := world.probe(t, []SearchVersionRunId{replacement}, versionTestKey("doc", 1), nil); !probe.Current(5) {
		t.Errorf("the replacement: %+v", probe)
	}
}

// A probe reads one page a level of each run, and only through the version-page LRU: probed again it reads nothing
// from the store, and the LRU never holds more than Search.VersionCacheByteCount.
func TestProbeUsesPageCacheOnly(t *testing.T) {
	world := newVersionTableTestWorld(t, 0)
	records := SearchVersionRecordsSource{}
	for index := range 20000 {
		records = append(records, versionTestRecord("doc", index, uint64(index%7+1), false, "b/20340/0"))
	}
	runId := world.merge(t, SearchVersionSlot{Kind: SearchVersionShards, StartDay: 20340}, records)
	snapshot, err := world.table.Snapshot([]SearchVersionRunId{runId})
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	levels := snapshot.runs[0].meta.Levels
	if levels < 2 {
		t.Fatalf("%d levels for 20,000 records", levels)
	}
	before := world.table.PageReadCount()
	if probe, err := snapshot.Probe(versionTestKey("doc", 12345), nil); err != nil || !probe.Current(uint64(12345%7+1)) {
		t.Fatalf("probe %+v %v", probe, err)
	}
	if read := world.table.PageReadCount() - before; read != uint64(levels) {
		t.Errorf("a cold probe read %d pages over %d levels", read, levels)
	}
	before = world.table.PageReadCount()
	if _, err := snapshot.Probe(versionTestKey("doc", 12345), nil); err != nil {
		t.Fatal(err)
	}
	if read := world.table.PageReadCount() - before; read != 0 {
		t.Errorf("a warm probe read %d pages", read)
	}
	random := rand.New(rand.NewSource(7))
	for range 2000 {
		index := random.Intn(20000)
		probe, err := snapshot.Probe(versionTestKey("doc", index), nil)
		if err != nil || !probe.Current(uint64(index%7+1)) {
			t.Fatalf("doc %d: %+v %v", index, probe, err)
		}
		if held := world.cache.versionPages.heldByteCount(); world.cache.settings.VersionCacheByteCount < held {
			t.Fatalf("the page LRU holds %d", held)
		}
	}
}

// A source that counts how many of its kind are open at once.
type versionTestCountingSource struct {
	records SearchVersionRecordsSource
	bytes   int64
	open    *int
	maxOpen *int
}

func (self *versionTestCountingSource) Open() (SearchVersionInput, error) {
	*self.open += 1
	*self.maxOpen = max(*self.maxOpen, *self.open)
	input, err := self.records.Open()
	if err != nil {
		return nil, err
	}
	return &versionTestCountingInput{SearchVersionInput: input, source: self}, nil
}

// An open counting source, which says it holds its source's bytes.
type versionTestCountingInput struct {
	SearchVersionInput
	source *versionTestCountingSource
	closed bool
}

func (self *versionTestCountingInput) ByteCount() int64 {
	return self.source.bytes
}

func (self *versionTestCountingInput) Close() {
	if !self.closed {
		self.closed = true
		*self.source.open -= 1
	}
}

// Forty inputs merge at most sixteen at a time, within 1 MiB counting what each input holds, through intermediate runs
// that go once the run is whole; inputs that hold more are taken fewer at a time.
func TestMergeBoundedToSixteenAndOneMiB(t *testing.T) {
	world := newVersionTableTestWorld(t, 0)
	open, maxOpen := 0, 0
	sources := []SearchVersionSource{}
	for input := range 40 {
		records := SearchVersionRecordsSource{}
		for index := range 50 {
			// every input names key index at its own version; input 23's is the highest
			version := uint64(input + 1)
			if input == 23 {
				version = 100
			}
			records = append(records, versionTestRecord("doc", index, version, false, "b/20340/w/"+strconv.Itoa(input)))
		}
		sources = append(sources, &versionTestCountingSource{records: records, bytes: 16 * 1024, open: &open, maxOpen: &maxOpen})
	}
	runId := world.merge(t, SearchVersionSlot{Kind: SearchVersionOthers, StartDay: 20340}, sources...)
	if maxOpen != world.cache.settings.VersionMergeInputCount {
		t.Errorf("%d inputs open at once", maxOpen)
	}
	if held := world.table.MergeHeldMax(); held > world.cache.settings.VersionMergeByteCount {
		t.Errorf("the merge held %d", held)
	}
	if open != 0 {
		t.Errorf("%d inputs left open", open)
	}
	for index := range 50 {
		if probe := world.probe(t, []SearchVersionRunId{runId}, versionTestKey("doc", index), nil); !probe.Current(100) || probe.File.Path != "b/20340/w/23" {
			t.Fatalf("doc %d: %+v", index, probe)
		}
	}
	runIds, err := world.table.RunIds()
	if err != nil || !slices.Equal(runIds, []SearchVersionRunId{runId}) {
		t.Errorf("intermediates left: %v %v", runIds, err)
	}

	// inputs of 128 KiB each: at most seven fit beside the writer
	open, maxOpen = 0, 0
	heavy := []SearchVersionSource{}
	for input := range 20 {
		heavy = append(heavy, &versionTestCountingSource{
			records: SearchVersionRecordsSource{versionTestRecord("heavy", input, 1, false, "x")},
			bytes:   128 * 1024, open: &open, maxOpen: &maxOpen,
		})
	}
	world.merge(t, SearchVersionSlot{Kind: SearchVersionOthers, StartDay: 20370}, heavy...)
	if held := world.table.MergeHeldMax(); held > world.cache.settings.VersionMergeByteCount {
		t.Errorf("heavy inputs held %d", held)
	}
	if maxOpen >= world.cache.settings.VersionMergeInputCount {
		t.Errorf("%d heavy inputs open at once", maxOpen)
	}
}

// A shard's doc table and tombstones read as one key-ordered input: its documents, its kind 3 tombstones by key among
// them, then its ref tombstones; and a slot's entries, sorted in memory.
func TestVersionInputsFromIndexFiles(t *testing.T) {
	world := newVersionTableTestWorld(t, 0)
	documents := testShardDocuments(3, "shard doc", 12, indexDocDerived)
	shard := &indexShard{
		header:     testShardHeader(indexFileBucketShard),
		documents:  documents,
		tombstones: []*indexShardTombstone{testShardTombstone(indexEntryTombstone, "gone", 1), testShardTombstone(indexEntryRefTombstone, "ref", 2)},
	}
	file := testBuildShard(t, shard, true, testPadKey(t, 1))
	reader, err := indexOpenShard(indexBytesFrames(file), true)
	if err != nil {
		t.Fatal(err)
	}
	shardFile := SearchVersionFile{Path: "i1/b/20340/0", Version: 4}
	slotEntries := []*indexEntry{
		{kind: indexEntryTombstone, key: documents[0].key, version: documents[0].version + 1},
		{kind: indexEntryRefTombstone, key: testIndexId("ref", 9), version: 30},
		{kind: indexEntryFull, key: testIndexId("slot doc", 1), version: 2},
	}
	runId := world.merge(t, SearchVersionSlot{Kind: SearchVersionShards, StartDay: 20340},
		&searchVersionShardSource{reader: reader, file: shardFile},
		searchVersionEntriesSource(slotEntries, SearchVersionFile{Path: "i1/b/20340/w/aa/1", Version: 2}),
	)
	runs := []SearchVersionRunId{runId}
	for index, document := range documents[1:] {
		if probe := world.probe(t, runs, document.key, nil); !probe.Current(document.version) || probe.File != shardFile {
			t.Errorf("document %d: %+v", index+1, probe)
		}
	}
	if probe := world.probe(t, runs, documents[0].key, nil); !probe.Tombstone || probe.Version != documents[0].version+1 {
		t.Errorf("a document a slot deletes: %+v", probe)
	}
	if probe := world.probe(t, runs, testIndexId("gone", 1), nil); !probe.Tombstone {
		t.Errorf("a shard's tombstone: %+v", probe)
	}
	// the shard's ref tombstone of ref 2 is at 7: a row of that ref at 2 is gone, and a slot's ref tombstone of ref 9
	// at 30 reads too
	shardRef, slotRef := Id(testIndexId("ref", 2)), Id(testIndexId("ref", 9))
	if probe := world.probe(t, runs, testIndexId("slot doc", 1), &shardRef); probe.RefTombstoneVersion != 7 || probe.Current(2) {
		t.Errorf("a shard's ref tombstone: %+v", probe)
	}
	if probe := world.probe(t, runs, testIndexId("slot doc", 1), &slotRef); probe.RefTombstoneVersion != 30 || probe.Current(2) {
		t.Errorf("a slot's ref tombstone: %+v", probe)
	}
	if probe := world.probe(t, runs, testIndexId("slot doc", 1), nil); !probe.Current(2) {
		t.Errorf("a slot's document: %+v", probe)
	}
}

// FS-109: a ref with 500,000 changed files inside the working set. The table is built within the merge's bound and
// each candidate is probed in rank order through the page LRU, so a search never holds the partitions' keys.
func TestFs109ChangedFilesInsideWorkingSet(t *testing.T) {
	const changed = 500000
	world := newVersionTableTestWorld(t, 0)
	// four writers' worth of the bucket's files, each a key-ordered input, as a bucket's shards are
	sources := []SearchVersionSource{}
	for writer := range 4 {
		records := SearchVersionRecordsSource{}
		for index := writer; index < changed; index += 4 {
			records = append(records, versionTestRecord("fs109", index, uint64(index%11+1), index%97 == 0, "b/20340/"+strconv.Itoa(writer)))
		}
		sources = append(sources, &versionTestCountingSource{records: records, bytes: 64 * 1024, open: new(int), maxOpen: new(int)})
	}
	runId := world.merge(t, SearchVersionSlot{Kind: SearchVersionShards, StartDay: 20340}, sources...)
	if held := world.table.MergeHeldMax(); held > world.cache.settings.VersionMergeByteCount {
		t.Errorf("the build held %d", held)
	}
	snapshot, err := world.table.Snapshot([]SearchVersionRunId{runId})
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if records := snapshot.runs[0].meta.Records; records != changed {
		t.Fatalf("%d records", records)
	}
	// candidates in rank order, newest first: an order that has nothing to do with the keys'
	random := rand.New(rand.NewSource(109))
	for range 5000 {
		index := random.Intn(changed)
		probe, err := snapshot.Probe(versionTestKey("fs109", index), nil)
		if err != nil {
			t.Fatal(err)
		}
		if probe.Current(uint64(index%11+1)) == (index%97 == 0) {
			t.Fatalf("candidate %d: %+v", index, probe)
		}
	}
	if held := world.cache.versionPages.heldByteCount(); world.cache.settings.VersionCacheByteCount < held {
		t.Errorf("the page LRU holds %d", held)
	}
}

// One run's bytes as a vector: its records, page size and the plaintext of its pages and meta.
type versionTableVector struct {
	Name          string                     `json:"name"`
	PageByteCount int                        `json:"page_byte_count"`
	Kind          int                        `json:"kind"`
	StartDay      uint32                     `json:"start_day,omitempty"`
	Records       []versionTableVectorRecord `json:"records"`
	Pages         []string                   `json:"pages"`
	Meta          string                     `json:"meta"`
}

type versionTableVectorRecord struct {
	Key          string `json:"key"`
	RefTombstone bool   `json:"ref_tombstone,omitempty"`
	Version      uint64 `json:"version"`
	Tombstone    bool   `json:"tombstone,omitempty"`
	Path         string `json:"path"`
	FileVersion  uint64 `json:"file_version"`
}

const versionTableVectorsPath = "testdata/version_table/vectors.json"

//go:embed testdata/version_table/vectors.json
var versionTableVectorsJson []byte

// The vectors' inputs: one page, three levels on a small page, every class and flag, an erased run, an empty run.
func versionTableVectorInputs() []versionTableVector {
	record := func(label string, index int, version uint64, tombstone bool, path string) versionTableVectorRecord {
		key := testIndexId(label, index)
		return versionTableVectorRecord{Key: hex.EncodeToString(key[:]), Version: version, Tombstone: tombstone, Path: path, FileVersion: 7}
	}
	small := []versionTableVectorRecord{}
	for index := range 24 {
		small = append(small, record("vector", index, uint64(1+index*37), index%5 == 0, "b/20340/"+strconv.Itoa(index%3)))
	}
	refKey := testIndexId("vector ref", 1)
	mixed := []versionTableVectorRecord{
		record("vector", 1, 1, false, "a/0"),
		record("vector", 2, 300, true, "a/1"),
		record("vector", 3, 1<<40, false, "a/1"),
		{Key: hex.EncodeToString(refKey[:]), RefTombstone: true, Version: 12, Path: "w/aa/3", FileVersion: 2},
	}
	return []versionTableVector{
		{Name: "one page", PageByteCount: 4096, Kind: int(SearchVersionAll), Records: mixed},
		{Name: "three levels", PageByteCount: 96, Kind: int(SearchVersionShards), StartDay: 20340, Records: small},
		{Name: "erased", PageByteCount: 4096, Kind: int(SearchVersionErased), Records: []versionTableVectorRecord{
			{Key: hex.EncodeToString(refKey[:]), Version: SearchVersionErasedAll},
			record("vector", 9, 44, false, ""),
		}},
		{Name: "empty", PageByteCount: 4096, Kind: int(SearchVersionOthers), StartDay: 20370},
	}
}

// Builds a vector's run and reads back its pages' and meta's plaintext.
func buildVersionTableVector(t *testing.T, vector versionTableVector) ([]string, string) {
	t.Helper()
	world := newVersionTableTestWorld(t, vector.PageByteCount)
	records := SearchVersionRecordsSource{}
	for _, input := range vector.Records {
		key, err := hex.DecodeString(input.Key)
		if err != nil || len(key) != indexIdByteCount {
			t.Fatalf("%s: a key %q", vector.Name, input.Key)
		}
		records = append(records, SearchVersionRecord{
			Key:          [indexIdByteCount]byte(key),
			RefTombstone: input.RefTombstone,
			Version:      input.Version,
			Tombstone:    input.Tombstone,
			File:         SearchVersionFile{Path: input.Path, Version: input.FileVersion},
		})
	}
	runId := world.merge(t, SearchVersionSlot{Kind: SearchVersionSlotKind(vector.Kind), StartDay: vector.StartDay}, records)
	run, err := world.table.openRun(runId)
	if err != nil {
		t.Fatal(err)
	}
	pages := []string{}
	for index := range run.meta.Pages {
		page, err := world.table.page(run, index)
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, hex.EncodeToString(bytes.TrimRight(page, "\x00")))
	}
	meta, err := world.cache.readSmall(world.table.runBase(runId)+"/"+searchCacheMetaName, searchCacheMetaMax)
	if err != nil {
		t.Fatal(err)
	}
	// the vectors' records probe as they were given
	for _, input := range vector.Records {
		key, _ := hex.DecodeString(input.Key)
		if input.RefTombstone {
			continue
		}
		probe := world.probe(t, []SearchVersionRunId{runId}, [indexIdByteCount]byte(key), nil)
		if vector.Kind == int(SearchVersionErased) {
			if probe.ErasedThrough != input.Version {
				t.Errorf("%s: erased %+v", vector.Name, probe)
			}
		} else if probe.Version != input.Version || probe.Tombstone != input.Tombstone {
			t.Errorf("%s: %s probed %+v", vector.Name, input.Key, probe)
		}
	}
	return pages, string(meta)
}

// D-TEST-15: a run's bytes are a function of its records and page size, the same on every leg.
func TestVersionTableVectors(t *testing.T) {
	inputs := versionTableVectorInputs()
	encoded := versionTableVectorsJson
	if os.Getenv("SIDECAR_REGENERATE_VERSION_TABLE_VECTORS") == "1" {
		for index := range inputs {
			inputs[index].Pages, inputs[index].Meta = buildVersionTableVector(t, inputs[index])
		}
		generated, err := json.MarshalIndent(inputs, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(generated, '\n')
		if err := os.WriteFile(versionTableVectorsPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	vectors := []versionTableVector{}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != len(inputs) {
		t.Fatalf("%d vectors, %d inputs", len(vectors), len(inputs))
	}
	for index, vector := range vectors {
		if vector.Name != inputs[index].Name || !slices.Equal(vector.Records, inputs[index].Records) {
			t.Errorf("vector %q's inputs moved", vector.Name)
			continue
		}
		pages, meta := buildVersionTableVector(t, vector)
		if !slices.Equal(pages, vector.Pages) {
			t.Errorf("%s: pages %v, want %v", vector.Name, pages, vector.Pages)
		}
		if meta != vector.Meta {
			t.Errorf("%s: meta %s, want %s", vector.Name, meta, vector.Meta)
		}
	}
	if len(vectors[1].Pages) < 4 {
		t.Errorf("the small-page vector has %d pages, too few for three levels", len(vectors[1].Pages))
	}
}

// Merge refuses inputs out of order and a ref the cache does not follow; a run that fails AEAD is dropped and answers
// ErrSearchCacheRefetch, which the probe's caller reads as masked.
func TestVersionTableRefusals(t *testing.T) {
	world := newVersionTableTestWorld(t, 0)
	if _, err := world.table.Merge(t.Context(), SearchVersionSlot{Kind: SearchVersionSlotKind(9)}, nil); !errors.Is(err, ErrSearchVersionArgs) {
		t.Errorf("an unknown slot: %v", err)
	}
	if _, err := world.table.Merge(t.Context(), SearchVersionSlot{Kind: SearchVersionAll, StartDay: 4}, nil); !errors.Is(err, ErrSearchVersionArgs) {
		t.Errorf("all with a day: %v", err)
	}
	stranger, err := NewSearchVersionTable(world.cache, NewId(), NewId(), ".ur-index/i1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stranger.Merge(t.Context(), SearchVersionSlot{Kind: SearchVersionAll}, nil); !errors.Is(err, ErrSearchCacheUnnamed) {
		t.Errorf("a ref not followed: %v", err)
	}
	// an input that goes back in key order
	backward := &versionTestBackwardSource{}
	if _, err := world.table.Merge(t.Context(), SearchVersionSlot{Kind: SearchVersionAll}, []SearchVersionSource{backward}); !errors.Is(err, ErrSearchVersionArgs) {
		t.Errorf("an input out of order: %v", err)
	}
	if runIds, _ := world.table.RunIds(); len(runIds) != 0 {
		t.Errorf("a refused merge left %v", runIds)
	}
	// an input past the bound by itself, and two that do not fit together, are refused, never merged past it
	alone := &versionTestCountingSource{records: SearchVersionRecordsSource{versionTestRecord("doc", 1, 1, false, "a/0")},
		bytes: world.cache.settings.VersionMergeByteCount, open: new(int), maxOpen: new(int)}
	if _, err := world.table.Merge(t.Context(), SearchVersionSlot{Kind: SearchVersionAll}, []SearchVersionSource{alone}); !errors.Is(err, ErrSearchVersionArgs) {
		t.Errorf("an input past the bound: %v", err)
	}
	half := world.cache.settings.VersionMergeByteCount / 2
	pair := []SearchVersionSource{
		&versionTestCountingSource{records: SearchVersionRecordsSource{versionTestRecord("doc", 1, 1, false, "a/0")}, bytes: half, open: new(int), maxOpen: new(int)},
		&versionTestCountingSource{records: SearchVersionRecordsSource{versionTestRecord("doc", 2, 1, false, "a/0")}, bytes: half, open: new(int), maxOpen: new(int)},
	}
	if _, err := world.table.Merge(t.Context(), SearchVersionSlot{Kind: SearchVersionAll}, pair); !errors.Is(err, ErrSearchVersionArgs) {
		t.Errorf("two inputs past the bound together: %v", err)
	}
	if held := world.table.MergeHeldMax(); world.cache.settings.VersionMergeByteCount < held {
		t.Errorf("a refused merge held %d", held)
	}

	runId := world.merge(t, SearchVersionSlot{Kind: SearchVersionAll}, SearchVersionRecordsSource{versionTestRecord("doc", 1, 2, false, "a/0")})
	// damage the run's root page under its seal: write garbage in its place
	if err := world.cache.writeSmall(world.table.runBase(runId)+"/0", []byte("not a page"), true); err != nil {
		t.Fatal(err)
	}
	world.cache.versionPages.drop()
	if _, err := world.table.Probe([]SearchVersionRunId{runId}, versionTestKey("doc", 1), nil); !errors.Is(err, ErrSearchCacheRefetch) {
		t.Errorf("a damaged run: %v", err)
	}
	if runIds, _ := world.table.RunIds(); slices.Contains(runIds, runId) {
		t.Error("a damaged run was kept")
	}
}

// A source whose records go back in key order.
type versionTestBackwardSource struct{}

func (self *versionTestBackwardSource) Open() (SearchVersionInput, error) {
	records := []SearchVersionRecord{versionTestRecord("doc", 1, 1, false, "a/0"), versionTestRecord("doc", 2, 1, false, "a/0")}
	// the higher key first
	if compareSearchVersionRecords(&records[0], &records[1]) < 0 {
		records[0], records[1] = records[1], records[0]
	}
	return &searchVersionListInput{records: records}, nil
}
