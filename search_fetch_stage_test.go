//go:build !ios_extension

package sidecar

// QD-1007 (FS-109's sync steps under load; SEARCH-M10-19's staging; §5.9's version table): the sync engine stages a
// shard's documents in one pass over its tables, which decrypts each frame once. The draft read each document by docid
// through a one-frame cursor whose window, near a frame's end, crossed into the next frame, so the next document read
// the frame it left again: some 4,100 frame reads to stage FS-109's 15-frame shard of 16,384 documents, about 65 µs a
// document. Here: a cursor reads what the file holds, a table pass decrypts each frame once, one-pass staging and the
// per-document path stage the same run and two times for the same shard, staging reads each kept frame a few times
// whatever the shard's document count, and a benchmark stages a shard of FS-109's documents.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// FS-109's update text and the documents a bucket shard of its takes (sidecartest/fault/fs109_test.go).
const (
	testFs109UpdateText    = "1000 2000 3000"
	testFs109ShardDocCount = 16384
)

// FS-109's bucket shards of count updates, notes/current-<i> each holding the update text, built as the search world's
// WriteShards builds them (search_schedule_testhooks.go): doc_key order, testFs109ShardDocCount a shard, halved past
// the cap, with tombstones in the first shard.
func testFs109Shards(tb testing.TB, repoId Id, refId Id, count int, startDay uint32, tombstones []*indexShardTombstone) [][]byte {
	tb.Helper()
	repoKey := evsTestRepoKey(repoId, 1)
	refKey, err := indexRefKey(repoKey)
	if err != nil {
		tb.Fatal(err)
	}
	padKey, err := indexNewPadKey(repoKey)
	if err != nil {
		tb.Fatal(err)
	}
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		tb.Fatal(err)
	}
	template := &IndexDocument{Kind: IndexDocFile, Name: []byte("notes/current-template"), Version: 1, ByteCount: uint64(len(testFs109UpdateText))}
	template.Fields[indexFieldBody] = []byte(testFs109UpdateText)
	prepared, err := template.prepare(normalizer, false, refId, DefaultIndexFormatSettings())
	if err != nil {
		tb.Fatal(err)
	}
	at := uint64(startDay)*uint64(indexDayMs/1000) + 3600
	documents := make([]*indexShardDocument, 0, count)
	for index := range count {
		path := fmt.Sprintf("notes/current-%d", index)
		key, err := indexDocKey(refKey, refId, []byte(path), 0)
		if err != nil {
			tb.Fatal(err)
		}
		row := *prepared.row
		row.locator = path
		documents = append(documents, &indexShardDocument{key: key, version: 1, timeSeconds: at, row: &row, keys: prepared.keys})
	}
	slices.SortFunc(documents, func(a *indexShardDocument, b *indexShardDocument) int {
		return bytes.Compare(a.key[:], b.key[:])
	})
	builder := indexNewShardBuilder(false)
	shards := [][]byte{}
	var build func(batch []*indexShardDocument)
	build = func(batch []*indexShardDocument) {
		header := indexNewFileHeader(indexFileBucketShard, indexLinkedTables())
		header.BucketStartDay = startDay
		header.BucketDays = indexDefaultWindowDays
		header.PadGeneration = padKey.generation
		shard := &indexShard{header: header, documents: batch}
		if len(shards) == 0 {
			shard.tombstones = tombstones
		}
		file, err := builder.build(shard, padKey)
		if errors.Is(err, errIndexShardFull) && 1 < len(batch) {
			build(batch[:len(batch)/2])
			build(batch[len(batch)/2:])
			return
		}
		if err != nil {
			tb.Fatal(err)
		}
		shards = append(shards, file)
	}
	for start := 0; start < len(documents); start += testFs109ShardDocCount {
		build(documents[start:min(len(documents), start+testFs109ShardDocCount)])
	}
	return shards
}

// A frame source over a whole file that writes each frame into the reader's buffer, as a decrypting source does, and
// counts each frame's reads.
type testCountingFrames struct {
	file  []byte
	reads map[int]int
}

func (self *testCountingFrames) indexLength() int {
	return len(self.file)
}

func (self *testCountingFrames) indexReadFrame(index int, dst []byte) ([]byte, error) {
	start := index * EvsRecordFrameByteCount
	if index < 0 || len(self.file) <= start {
		return nil, indexMalformed("a frame past the file")
	}
	self.reads[index] += 1
	return append(dst[:0], self.file[start:min(len(self.file), start+EvsRecordFrameByteCount)]...), nil
}

// The most reads of any one frame, and the frames read.
func (self *testCountingFrames) most() (int, int) {
	most := 0
	for _, count := range self.reads {
		most = max(most, count)
	}
	return most, len(self.reads)
}

// A store that counts the opens of each name, over the instance's.
type testCountingStore struct {
	SidecarStore
	stateLock *sync.Mutex
	opens     map[string]int
}

func (self *testCountingStore) Open(name string) (io.ReadCloser, error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.opens[name] += 1
	}()
	return self.SidecarStore.Open(name)
}

func (self *testCountingStore) Directory(name string, class string) (SidecarStore, error) {
	directory, err := self.SidecarStore.Directory(name, class)
	if err != nil {
		return nil, err
	}
	return &testCountingStore{SidecarStore: directory, stateLock: self.stateLock, opens: self.opens}, nil
}

// The opens of a kept record's frames.
func (self *testCountingStore) frameOpens(key SearchCacheKey) map[int]int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	prefix := searchCachePartName(key, searchCachePartRecord) + "/"
	opens := map[int]int{}
	for name, count := range self.opens {
		if index, err := strconv.Atoi(strings.TrimPrefix(name, prefix)); err == nil && strings.HasPrefix(name, prefix) {
			opens[index] += count
		}
	}
	return opens
}

func (self *testCountingStore) reset() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	clear(self.opens)
}

// A source the staging never reads: a round's own steps are search_sync_test.go's.
type testStageNoSource struct{}

func (testStageNoSource) Replay(ctx context.Context, pin SearchSyncPin) (*searchSyncReplay, error) {
	return nil, errors.New("test stage source: no replay")
}

func (testStageNoSource) List(ctx context.Context) (*indexListing, error) {
	return nil, errors.New("test stage source: no listing")
}

func (testStageNoSource) Fetch(ctx context.Context, files []*indexFileVersion) ([]*searchSyncFetched, error) {
	return nil, errors.New("test stage source: no fetch")
}

// A sync engine following one ref, its cache on a store that counts opens, and the plan a round stages toward.
type testStageWorld struct {
	cache     *SearchCache
	store     *testCountingStore
	sync      *SearchSync
	ref       *searchSyncRef
	repoId    Id
	refId     Id
	companion bool
	plan      *SearchSyncPlan
}

func newTestStageWorld(tb testing.TB, companion bool) *testStageWorld {
	tb.Helper()
	ctx := context.Background()
	settings := DefaultSidecarSettings()
	settings.Log = NewNoopLogger()
	settings.KeychainSettings.PassMemoryByteCount = 64 * 1024
	settings.KeychainSettings.PassIterationCount = 1
	settings.KeychainSettings.PassThreadCount = 1
	settings.KeychainSettings.AutoLockTimeout = 0
	instance, err := NewSidecarInstance(ctx, &SidecarInstanceArgs{Backend: NewSidecarMemoryBackend(), KeyStore: NewSidecarMemoryKeyStore(), Settings: settings})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(instance.Close)
	if err := instance.Unlock(nil); err != nil {
		tb.Fatal(err)
	}
	networkId := NewId()
	if _, err := instance.createKeychain(networkId); err != nil {
		tb.Fatal(err)
	}
	store := &testCountingStore{SidecarStore: instance.Store(&networkId), stateLock: &sync.Mutex{}, opens: map[string]int{}}
	search := DefaultSidecarSettings().Search
	clock := newIdentityTestClock()
	cache, err := NewSearchCache(ctx, store, search, clock, NewNoopLogger())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(cache.Close)
	engine, err := newSearchSync(&searchSyncArgs{
		cache: cache, settings: search, format: DefaultIndexFormatSettings(), clock: clock, log: NewNoopLogger(),
		readPathCount: 64, readByteCount: 32 * 1024 * 1024,
	})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(engine.Close)
	world := &testStageWorld{cache: cache, store: store, sync: engine, repoId: evsTestId("stage repo"), refId: evsTestId("stage ref"), companion: companion}
	err = engine.Follow(&searchSyncRefArgs{
		repoId: world.repoId, refId: world.refId, repoKind: protocol.RepoKind_REPO_KIND_GENERAL, companion: companion,
		source: testStageNoSource{}, mayErase: func(Id, int64) bool { return false },
	})
	if err != nil {
		tb.Fatal(err)
	}
	world.ref = engine.refs[[2]Id{world.repoId, world.refId}]
	if err := cache.SetRefVersion(world.repoId, world.refId, 1); err != nil {
		tb.Fatal(err)
	}
	root := indexNewPaths(companion, indexRootNumber).root
	if err := engine.openTable(world.ref, root); err != nil {
		tb.Fatal(err)
	}
	world.plan = &SearchSyncPlan{Root: root, Target: SearchSyncPin{Version: 1}}
	return world
}

// The wanted file and the cache key of bucket shard n at version.
func (self *testStageWorld) shardFile(n uint32, version uint64, startDay uint32, file []byte) (*SearchSyncWanted, SearchCacheKey) {
	path := indexNewPaths(self.companion, indexRootNumber).bucketShard(startDay, n)
	wanted := &SearchSyncWanted{
		Path: path, Version: version, ContentSha256: sha256.Sum256(file), ByteCount: int64(len(file)),
		Partition: SearchCachePartition{StartDay: startDay}, Signer: evsTestId("stage writer"),
	}
	return wanted, SearchCacheKey{RepoId: self.repoId, RefId: self.refId, Path: path, Version: version}
}

// Stages file as bucket shard n at version, as a round's fetch does once its read answers.
func (self *testStageWorld) stage(tb testing.TB, n uint32, version uint64, startDay uint32, file []byte) *SearchManifestFile {
	tb.Helper()
	wanted, key := self.shardFile(n, version, startDay, file)
	record := newTestSearchRecord(tb, key, wanted.Partition, file)
	staged, err := self.sync.stage(context.Background(), self.ref, self.plan, wanted, record.record)
	if err != nil {
		tb.Fatal(err)
	}
	if staged.State != SearchManifestHeld {
		tb.Fatalf("a shard staged %v", staged.State)
	}
	return staged
}

// A run's records in key order, as a merge reads it.
func testRunRecords(tb testing.TB, table *SearchVersionTable, runId SearchVersionRunId) []SearchVersionRecord {
	tb.Helper()
	input, err := (&searchVersionRunSource{table: table, runId: runId}).Open()
	if err != nil {
		tb.Fatal(err)
	}
	defer input.Close()
	records := []SearchVersionRecord{}
	for {
		record, ok, err := input.Next()
		if err != nil {
			tb.Fatal(err)
		}
		if !ok {
			return records
		}
		records = append(records, record)
	}
}

// The staging the one pass replaced, as SEARCH-M10-19 drafted it: the two times from each document read by docid
// through the reader's one-frame cursor, its row decoded, then the tombstones read and held; and the run merged from a
// second such read, the tombstones interleaved by key.
type testShardSourceByDocument struct {
	reader *indexShardReader
	file   SearchVersionFile
}

type testShardInputByDocument struct {
	reader     *indexShardReader
	file       SearchVersionFile
	docId      uint32
	tombstones []*indexShardTombstone
	nextStone  int
	document   *SearchVersionRecord
}

func (self *testShardSourceByDocument) Open() (SearchVersionInput, error) {
	input := &testShardInputByDocument{reader: self.reader, file: self.file}
	if err := input.readTombstones(); err != nil {
		return nil, err
	}
	return input, nil
}

func (self *testShardInputByDocument) readTombstones() error {
	layout := self.reader.layout
	position := layout.tombstonesStart
	for range layout.header.Tombstones {
		window, err := self.reader.window(position, layout.dictionaryStart, indexTombstoneMaxByteCount)
		if err != nil {
			return err
		}
		decoder := indexDecoder{src: window}
		tombstone := decoder.tombstone(self.reader.companion)
		if decoder.err != nil {
			return decoder.err
		}
		self.tombstones = append(self.tombstones, tombstone)
		position += len(window) - decoder.remaining()
	}
	return indexCheckTombstoneOrder(self.tombstones, self.reader.companion)
}

func (self *testShardInputByDocument) Next() (SearchVersionRecord, bool, error) {
	if self.document == nil && int(self.docId) < self.reader.documentCount() {
		document, err := self.reader.document(self.docId)
		if err != nil {
			return SearchVersionRecord{}, false, err
		}
		self.docId += 1
		self.document = &SearchVersionRecord{Key: document.key, Version: document.version, File: self.file}
	}
	var stone *SearchVersionRecord
	if self.nextStone < len(self.tombstones) {
		tombstone := self.tombstones[self.nextStone]
		stone = &SearchVersionRecord{Key: tombstone.key, Version: tombstone.version, File: self.file}
		if tombstone.kind == indexEntryRefTombstone {
			stone.RefTombstone = true
		} else {
			stone.Tombstone = true
		}
	}
	switch {
	case self.document == nil && stone == nil:
		return SearchVersionRecord{}, false, nil
	case stone == nil || (self.document != nil && compareSearchVersionRecords(self.document, stone) < 0):
		record := *self.document
		self.document = nil
		return record, true, nil
	}
	self.nextStone += 1
	return *stone, true, nil
}

func (self *testShardInputByDocument) ByteCount() int64 {
	return int64(EvsRecordFrameByteCount) + int64(len(self.tombstones))*int64(indexTombstoneMaxByteCount+16)
}

func (self *testShardInputByDocument) Close() {}

// The per-document path's two times of a shard.
func testShardTimesByDocument(tb testing.TB, reader *indexShardReader) *SearchManifestFile {
	tb.Helper()
	times := &SearchManifestFile{}
	for docId := range reader.documentCount() {
		document, err := reader.document(uint32(docId))
		if err != nil {
			tb.Fatal(err)
		}
		times.observe(document.timeSeconds)
	}
	input := &testShardInputByDocument{reader: reader}
	if err := input.readTombstones(); err != nil {
		tb.Fatal(err)
	}
	for _, tombstone := range input.tombstones {
		times.observe(tombstone.timeSeconds)
	}
	return times
}

// What a shard holds for the version table, from its whole decode: each document's and tombstone's record in key
// order, and the two times.
func testShardRecordsDecoded(tb testing.TB, file []byte, companion bool, shardFile SearchVersionFile) ([]SearchVersionRecord, *SearchManifestFile) {
	tb.Helper()
	sum := sha256.Sum256(file)
	shard, err := indexDecodeShard(file, sum[:], companion)
	if err != nil {
		tb.Fatal(err)
	}
	records := []SearchVersionRecord{}
	times := &SearchManifestFile{}
	for _, document := range shard.documents {
		records = append(records, SearchVersionRecord{Key: document.key, Version: document.version, File: shardFile})
		times.observe(document.timeSeconds)
	}
	for _, tombstone := range shard.tombstones {
		record := SearchVersionRecord{Key: tombstone.key, Version: tombstone.version, File: shardFile, Tombstone: tombstone.kind == indexEntryTombstone}
		record.RefTombstone = tombstone.kind == indexEntryRefTombstone
		records = append(records, record)
		times.observe(tombstone.timeSeconds)
	}
	slices.SortFunc(records, func(a SearchVersionRecord, b SearchVersionRecord) int {
		return compareSearchVersionRecords(&a, &b)
	})
	return records, times
}

// A cursor's reads and windows give the file's bytes at every position, forward and back, over the tail it keeps and
// across frames; and a forward pass of a table's entries, windows reaching past a frame's end and the next entry
// starting back before it, reads each frame once.
func TestAFrameCursorReadsWhatTheFileHolds(t *testing.T) {
	file := make([]byte, 3*EvsRecordFrameByteCount+1000)
	for start := 0; start < len(file); start += sha256.Size {
		sum := sha256.Sum256([]byte(strconv.Itoa(start)))
		copy(file[start:], sum[:])
	}
	random := rand.New(rand.NewSource(1007))
	source := &testCountingFrames{file: file, reads: map[int]int{}}
	cursor := indexNewFrameCursor(source)
	check := func(label string, position int, got []byte) {
		t.Helper()
		if !bytes.Equal(got, file[position:position+len(got)]) {
			t.Fatalf("%s at %d of %d B differs from the file", label, position, len(got))
		}
	}
	// forward, as a table's pass reads: entries of 20 to 80 B under windows of up to an entry's most
	entries := 0
	for position := 0; position < len(file); {
		window, err := cursor.window(position, len(file), indexDocumentEntryMaxByteCount)
		if err != nil {
			t.Fatal(err)
		}
		check("a window", position, window)
		if len(window) != min(indexDocumentEntryMaxByteCount, len(file)-position) {
			t.Fatalf("a window of %d B at %d", len(window), position)
		}
		entry := 20 + random.Intn(61)
		if entries%7 == 0 && position+entry <= len(file) {
			read := make([]byte, entry)
			if err := cursor.read(position, read); err != nil {
				t.Fatal(err)
			}
			check("a read", position, read)
		}
		entries += 1
		position += entry
	}
	if most, frames := source.most(); most != 1 || frames != 4 {
		t.Fatalf("a forward pass read a frame %d times, %d frames of 4", most, frames)
	}
	// back and forth: anywhere, any length up to two frames, windows bounded by an end before the file's
	for range 2000 {
		position := random.Intn(len(file))
		switch random.Intn(3) {
		case 0:
			read := make([]byte, random.Intn(min(len(file)-position, 2*EvsRecordFrameByteCount)+1))
			if err := cursor.read(position, read); err != nil {
				t.Fatal(err)
			}
			check("a read", position, read)
		default:
			end := position + random.Intn(len(file)-position+1)
			window, err := cursor.window(position, end, 1+random.Intn(3*indexDocumentEntryMaxByteCount))
			if err != nil {
				t.Fatal(err)
			}
			check("a window", position, window)
		}
	}
	if _, err := cursor.window(len(file)-10, len(file)+10, 20); !errors.Is(err, errIndexMalformed) {
		t.Fatalf("a window past the file: %v", err)
	}
	if err := cursor.read(len(file)-10, make([]byte, 11)); !errors.Is(err, errIndexMalformed) {
		t.Fatalf("a read past the file: %v", err)
	}
}

// Opening a shard of FS-109's documents, whose doc table spans its frames, reads each frame once, where the draft's
// one-frame cursor read one up to 79 times; and the version table's pass over its tables reads each frame once a table.
func TestATablePassReadsEachFrameOnce(t *testing.T) {
	gone := []*indexShardTombstone{}
	for index := range 300 {
		gone = append(gone, testShardTombstone(indexEntryTombstone, "gone", index))
	}
	shards := testFs109Shards(t, evsTestId("frames repo"), evsTestId("frames ref"), testFs109ShardDocCount, 20340, gone)
	file := shards[0]
	frameCount := (len(file) + EvsRecordFrameByteCount - 1) / EvsRecordFrameByteCount
	if frameCount < 10 {
		t.Fatalf("a shard of %d frames", frameCount)
	}
	source := &testCountingFrames{file: file, reads: map[int]int{}}
	reader, err := indexOpenShard(source, false)
	if err != nil {
		t.Fatal(err)
	}
	// opening reads up to where the postings start, which a search reads by key
	tablesFrameCount := (reader.layout.postingsStart-1)/EvsRecordFrameByteCount + 1
	if most, frames := source.most(); most != 1 || frames < tablesFrameCount || frameCount < frames {
		t.Fatalf("opening read a frame %d times, %d frames of %d, its tables' %d", most, frames, frameCount, tablesFrameCount)
	}
	clear(source.reads)
	world := newTestStageWorld(t, false)
	_, err = world.ref.table.Merge(context.Background(), SearchVersionSlot{Kind: SearchVersionShards, StartDay: 20340},
		[]SearchVersionSource{&searchVersionShardSource{reader: reader, file: SearchVersionFile{Path: "b/20340/s/0", Version: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	// the documents' reader and the tombstones' each read their table's frames once: the frame where the doc table
	// ends and the tombstones start is read by both
	if most, frames := source.most(); most > 2 || frames > frameCount {
		t.Fatalf("the version table's pass read a frame %d times, %d frames of %d", most, frames, frameCount)
	}
	for index, count := range source.reads {
		if count == 2 && index != reader.layout.tombstonesStart/EvsRecordFrameByteCount {
			t.Fatalf("frame %d read twice", index)
		}
	}
}

// One-pass staging and the per-document path stage the same shard alike: the same run, record for record, as the
// shard's whole decode holds it, and the same two times, tombstones' included; for FS-109's documents with a bucket's
// tombstones across 15 frames, and for ur/index's rows with both tombstone kinds. The build stays within
// Search.VersionMergeByteCount.
func TestOnePassStagingStagesWhatThePerDocumentPathDid(t *testing.T) {
	type shardCase struct {
		label     string
		companion bool
		file      []byte
	}
	gone := []*indexShardTombstone{}
	for index := range 300 {
		gone = append(gone, testShardTombstone(indexEntryTombstone, "gone", index))
	}
	refRows := &indexShard{
		header:    testShardHeader(indexFileBucketShard),
		documents: testShardDocuments(1007, "ur/index rows", 2000, indexDocDerived),
		tombstones: []*indexShardTombstone{
			testShardTombstone(indexEntryTombstone, "gone row", 1), testShardTombstone(indexEntryTombstone, "gone row", 2),
			testShardTombstone(indexEntryRefTombstone, "deleted ref", 3), testShardTombstone(indexEntryRefTombstone, "deleted ref", 4),
		},
	}
	cases := []shardCase{
		{label: "FS-109's documents", file: testFs109Shards(t, evsTestId("stage repo"), evsTestId("stage ref"), testFs109ShardDocCount, 20340, gone)[0]},
		{label: "ur/index rows", companion: true, file: testBuildShard(t, refRows, true, testPadKey(t, 1))},
	}
	for _, c := range cases {
		if len(c.file) < 2*EvsRecordFrameByteCount {
			t.Fatalf("%s: a shard of %d B crosses too few frames", c.label, len(c.file))
		}
		world := newTestStageWorld(t, c.companion)
		staged := world.stage(t, 0, 1, 20340, c.file)
		shardFile := SearchVersionFile{Path: staged.Path, Version: staged.Version}
		onePass := testRunRecords(t, world.ref.table, staged.Run)
		if held := world.ref.table.MergeHeldMax(); world.cache.settings.VersionMergeByteCount < held {
			t.Errorf("%s: the build held %d B", c.label, held)
		}

		reader, err := indexOpenShard(indexBytesFrames(c.file), c.companion)
		if err != nil {
			t.Fatal(err)
		}
		byDocumentRun, err := world.ref.table.Merge(context.Background(), SearchVersionSlot{Kind: SearchVersionShards, StartDay: 20340},
			[]SearchVersionSource{&testShardSourceByDocument{reader: reader, file: shardFile}})
		if err != nil {
			t.Fatal(err)
		}
		byDocument := testRunRecords(t, world.ref.table, byDocumentRun)
		byDocumentTimes := testShardTimesByDocument(t, reader)
		decoded, decodedTimes := testShardRecordsDecoded(t, c.file, c.companion, shardFile)

		if !slices.Equal(onePass, byDocument) || !slices.Equal(onePass, decoded) {
			t.Errorf("%s: one pass staged %d records, the per-document path %d and the decode %d", c.label, len(onePass), len(byDocument), len(decoded))
		}
		if staged.TimeMinMs != byDocumentTimes.TimeMinMs || staged.TimeMaxMs != byDocumentTimes.TimeMaxMs ||
			staged.TimeMinMs != decodedTimes.TimeMinMs || staged.TimeMaxMs != decodedTimes.TimeMaxMs {
			t.Errorf("%s: one pass's times [%d, %d], the per-document path's [%d, %d], the decode's [%d, %d]", c.label,
				staged.TimeMinMs, staged.TimeMaxMs, byDocumentTimes.TimeMinMs, byDocumentTimes.TimeMaxMs, decodedTimes.TimeMinMs, decodedTimes.TimeMaxMs)
		}
		if staged.TimeMinMs == staged.TimeMaxMs {
			t.Errorf("%s: the tombstones' times were not taken", c.label)
		}
		if staged.WindowDays != reader.layout.header.BucketDays {
			t.Errorf("%s: a window of %d days", c.label, staged.WindowDays)
		}
		tombstones := 0
		for _, record := range onePass {
			if record.Tombstone || record.RefTombstone {
				tombstones += 1
			}
		}
		if tombstones != int(reader.layout.header.Tombstones) || len(onePass) != reader.documentCount()+tombstones {
			t.Errorf("%s: %d records of %d documents and %d tombstones", c.label, len(onePass), reader.documentCount(), tombstones)
		}
	}
}

// The composed path: staging a kept shard of FS-109's documents opens each of its kept frames a few times, a pass
// each (the hash, opening, walk's parts, the version table's pass), whatever the shard's document count; the draft's
// per-document cursor opened them some 275 times each.
func TestStagingReadsEachKeptFrameAFewTimes(t *testing.T) {
	world := newTestStageWorld(t, false)
	file := testFs109Shards(t, world.repoId, world.refId, testFs109ShardDocCount, 20340, nil)[0]
	frameCount := (len(file) + EvsRecordFrameByteCount - 1) / EvsRecordFrameByteCount
	world.store.reset()
	world.stage(t, 0, 1, 20340, file)
	_, key := world.shardFile(0, 1, 20340, file)
	opens := world.store.frameOpens(key)
	total := 0
	for index := range frameCount {
		if opens[index] == 0 {
			t.Fatalf("frame %d of %d was never read", index, frameCount)
		}
		if 6 < opens[index] {
			t.Errorf("frame %d was read %d times", index, opens[index])
		}
		total += opens[index]
	}
	t.Logf("staging %d documents read %d frames %d times", testFs109ShardDocCount, frameCount, total)
}

// Staging a kept shard of FS-109's 16,384 documents, as a fresh device's sync stages each of its shards: its hash, its
// validation, its run and its two times, in ns a document (QD-1007's before and after).
func BenchmarkStageFs109Shard(b *testing.B) {
	world := newTestStageWorld(b, false)
	file := testFs109Shards(b, world.repoId, world.refId, testFs109ShardDocCount, 20340, nil)[0]
	b.SetBytes(int64(len(file)))
	for iteration := 0; b.Loop(); iteration += 1 {
		version := uint64(iteration + 1)
		world.stage(b, 0, version, 20340, file)
		b.StopTimer()
		_, key := world.shardFile(0, version, 20340, file)
		if err := world.cache.Remove(key); err != nil {
			b.Fatal(err)
		}
		if err := world.ref.table.Retire(nil); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*testFs109ShardDocCount), "ns/doc")
}
