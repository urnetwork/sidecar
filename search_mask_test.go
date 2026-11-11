// Masks (SEARCH-M10-24): FS-109's mask memory at unit level, one all row that a newer version masks on a
// 500,000-key table, probed once a candidate; FS-108's tombstones, ref tombstones and a re-created ref; erasures and
// searchable_days; a branch overlay; and a table that does not cover a candidate reading not yet searchable.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"runtime"
	"slices"
	"testing"
)

// A fake of §5.9's version table (CORE-M10-02): records in key order, in pages of a 4 KiB page's worth under an index
// of each page's first key, so a probe reads one page, which the test counts.
type testVersionTable struct {
	keys      [][indexIdByteCount]byte
	records   []searchVersionRecord
	firstKeys [][indexIdByteCount]byte
	pageReads int
	probes    int
}

// A record's bytes in a page: key, version, a tombstone byte and erasedThrough.
const testVersionPageEntryCount = 4 * 1024 / (indexIdByteCount + 8 + 1 + 8)

// A table of these records, sorted and paged.
func newTestVersionTable(keys [][indexIdByteCount]byte, records []searchVersionRecord) *testVersionTable {
	order := make([]int, len(keys))
	for index := range order {
		order[index] = index
	}
	slices.SortFunc(order, func(a int, b int) int { return compareIndexKeys(keys[a], keys[b]) })
	table := &testVersionTable{}
	for _, index := range order {
		table.keys = append(table.keys, keys[index])
		table.records = append(table.records, records[index])
	}
	for start := 0; start < len(table.keys); start += testVersionPageEntryCount {
		table.firstKeys = append(table.firstKeys, table.keys[start])
	}
	return table
}

// A table of one record a key, the highest version given for each.
func testVersionTableOf(records map[[indexIdByteCount]byte]searchVersionRecord) *testVersionTable {
	keys := [][indexIdByteCount]byte{}
	values := []searchVersionRecord{}
	for key, record := range records {
		keys = append(keys, key)
		values = append(values, record)
	}
	return newTestVersionTable(keys, values)
}

// Probes one key: the page index, then one page.
func (self *testVersionTable) probe(key [indexIdByteCount]byte) (searchVersionRecord, error) {
	self.probes += 1
	page, _ := slices.BinarySearchFunc(self.firstKeys, key, func(first [indexIdByteCount]byte, target [indexIdByteCount]byte) int {
		return compareIndexKeys(first, target)
	})
	if page == len(self.firstKeys) || self.firstKeys[page] != key {
		page -= 1
	}
	if page < 0 {
		return searchVersionRecord{}, nil
	}
	self.pageReads += 1
	start := page * testVersionPageEntryCount
	end := min(len(self.keys), start+testVersionPageEntryCount)
	index, found := slices.BinarySearchFunc(self.keys[start:end], key, func(held [indexIdByteCount]byte, target [indexIdByteCount]byte) int {
		return compareIndexKeys(held, target)
	})
	if !found {
		return searchVersionRecord{}, nil
	}
	return self.records[start+index], nil
}

// Normalizer 1 on this build's tables.
func testSearchNormalizer(t testing.TB) *indexNormalizer {
	t.Helper()
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	return normalizer
}

// K_ref of a test repo, 32 fixed bytes.
func testSearchRefKey(label string) []byte {
	sum := sha256.Sum256([]byte("K_ref " + label))
	return sum[:]
}

// What a test document is.
type testSearchDocument struct {
	kind    IndexDocKind
	path    string
	title   string
	subject string
	from    string
	body    string
	version uint64
	// Seconds; an entry's time.
	time uint64
	// ur/index's rows carry it.
	refId Id
}

// The document as a writer builds it: its key under refKey and its ref, its key set and its row through normalizer 1.
func testSearchEntry(t testing.TB, refKey []byte, refId Id, companion bool, document *testSearchDocument) *indexEntry {
	t.Helper()
	kind := document.kind
	if kind == 0 {
		kind = IndexDocFile
	}
	indexDocument := &IndexDocument{Kind: kind, Name: []byte(document.path), Version: document.version, ByteCount: uint64(len(document.body))}
	indexDocument.Fields[indexFieldSubject] = []byte(document.subject)
	indexDocument.Fields[indexFieldFrom] = []byte(document.from)
	indexDocument.Fields[indexFieldTitle] = []byte(document.title)
	indexDocument.Fields[indexFieldBody] = []byte(document.body)
	prepared, err := indexDocument.prepare(testSearchNormalizer(t), companion, refId)
	if err != nil {
		t.Fatal(err)
	}
	key, err := indexDocKey(refKey, refId, indexDocument.Name, 0)
	if err != nil {
		t.Fatal(err)
	}
	return &indexEntry{kind: indexEntryFull, key: key, version: document.version, timeSeconds: document.time, row: prepared.row, keys: prepared.keys}
}

// A bucket partition of one writer's head holding entries.
func testSearchSlotPartition(kind searchPartitionKind, entries ...*indexEntry) *searchPartitionSource {
	sorted := slices.Clone(entries)
	slices.SortFunc(sorted, indexCompareEntries)
	writer := evsTestId("search writer")
	return &searchPartitionSource{
		partition: kind,
		slots:     []*searchSlotSource{{slot: &indexSlot{entries: sorted}, writer: writer, seq: 1, head: true, path: "w/head", signer: writer}},
	}
}

// An all partition of one shard holding the entries' documents, under ur/index's root where companion says.
func testSearchShardPartition(t testing.TB, companion bool, entries ...*indexEntry) *searchPartitionSource {
	t.Helper()
	documents := []*indexShardDocument{}
	for _, entry := range entries {
		documents = append(documents, &indexShardDocument{key: entry.key, version: entry.version, timeSeconds: entry.timeSeconds, row: entry.row, keys: entry.keys})
	}
	file := testBuildShard(t, &indexShard{header: testShardHeader(indexFileAllShard), documents: documents}, companion, testPadKey(t, 2))
	reader, err := indexOpenShard(indexBytesFrames(file), companion)
	if err != nil {
		t.Fatal(err)
	}
	return &searchPartitionSource{partition: searchPartitionAll, shards: []*searchShardSource{{n: 0, reader: reader}}}
}

// The current record of each entry, as a table built from the files holding them has it.
func testSearchRecords(entries ...*indexEntry) map[[indexIdByteCount]byte]searchVersionRecord {
	records := map[[indexIdByteCount]byte]searchVersionRecord{}
	for _, entry := range entries {
		if record, ok := records[entry.key]; !ok || record.version < entry.version {
			records[entry.key] = searchVersionRecord{found: true, version: entry.version, tombstone: entry.kind == indexEntryTombstone || entry.kind == indexEntryRefTombstone}
		}
	}
	return records
}

// One search's sources and settings, for a test to rank partitions with.
type testSearchRun struct {
	t          testing.TB
	query      *SearchQuery
	normalizer *indexNormalizer
	settings   *SearchResultSettings
	search     *SidecarSearchSettings
	order      searchRankOrder
}

// A run of query on this build's normalizer.
func newTestSearchRun(t testing.TB, query string) *testSearchRun {
	t.Helper()
	parsed, err := ParseSearchQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	return &testSearchRun{t: t, query: parsed, normalizer: testSearchNormalizer(t), settings: DefaultSearchResultSettings(), search: DefaultSidecarSettings().Search}
}

// A rank source for one repo's index over mask args and a confirmer with these sources.
func (self *testSearchRun) source(repoId Id, refId Id, maskArgs *searchMaskArgs, text SearchTextSource, display SearchDisplaySource) *searchRankSource {
	self.t.Helper()
	mask, err := newSearchMask(maskArgs)
	if err != nil {
		self.t.Fatal(err)
	}
	return &searchRankSource{
		repoId:    repoId,
		refId:     refId,
		companion: maskArgs.companion,
		mask:      mask,
		confirmer: &searchConfirmer{query: self.query, normalizer: self.normalizer, text: text, display: display, settings: self.settings, repoId: repoId},
	}
}

// The inputs of one source's partitions matched against the run's query, in plan order.
func (self *testSearchRun) inputs(source *searchRankSource, partitions ...*searchPartitionSource) []*searchRankInput {
	self.t.Helper()
	inputs := []*searchRankInput{}
	for step, partition := range partitions {
		result, err := searchMatch(&searchMatchArgs{query: self.query, source: partition, maxCandidateCount: self.search.TooBroadCandidateCount})
		if err != nil {
			self.t.Fatal(err)
		}
		inputs = append(inputs, &searchRankInput{source: source, partition: partition.partition, step: step, result: result})
	}
	return inputs
}

// Every hit of one phase over inputs, near hits settled as none, and the phase's last counts.
func (self *testSearchRun) all(inputs []*searchRankInput) ([]*searchRankedHit, searchRankCounts) {
	self.t.Helper()
	ranker, err := newSearchRanker(&searchRankerArgs{settings: self.settings, search: self.search, order: self.order, query: self.query})
	if err != nil {
		self.t.Fatal(err)
	}
	if err := ranker.beginPhase(inputs); err != nil {
		self.t.Fatal(err)
	}
	if err := ranker.settleNear(nil, "", 0); err != nil {
		self.t.Fatal(err)
	}
	hits := []*searchRankedHit{}
	for range 1000 {
		page, err := ranker.page(context.Background(), 20)
		if err != nil {
			self.t.Fatal(err)
		}
		hits = append(hits, page.hits...)
		if page.phaseDone {
			return hits, page.counts
		}
	}
	self.t.Fatal("a phase that never ends")
	return nil, searchRankCounts{}
}

// The hits' keys.
func testHitKeys(hits []*searchRankedHit) [][indexIdByteCount]byte {
	keys := [][indexIdByteCount]byte{}
	for _, hit := range hits {
		keys = append(keys, hit.key)
	}
	return keys
}

// FS-109 at unit level: a ref with 500,000 recent nonmatching file updates in its buckets and one all row that a newer
// nonmatching version masks. The all row never shows; the bucket documents that match do. The mask probes the table
// once a candidate and holds nothing of it, so the walk's live heap stays far below the table's: a build that
// collected the partitions' keys per search would hold the 500,000 keys and fail the bound.
func TestSearchMaskMemoryOnAHalfMillionKeyTable(t *testing.T) {
	repoId, refId := evsTestId("fs109 repo"), evsTestId("fs109 ref")
	refKey := testSearchRefKey("fs109")
	run := newTestSearchRun(t, "quarterly forecast")
	stale := testSearchEntry(t, refKey, refId, false, &testSearchDocument{path: "plans/forecast.md", title: "Old plan", body: "the quarterly forecast as it stood", version: 3, time: 1700000000})
	others := []*indexEntry{
		testSearchEntry(t, refKey, refId, false, &testSearchDocument{path: "notes/a.md", body: "unrelated words about lunch", version: 4, time: 1700000100}),
	}
	matching := []*indexEntry{}
	for index := range 3 {
		matching = append(matching, testSearchEntry(t, refKey, refId, false, &testSearchDocument{
			path: "plans/recent-" + string(rune('a'+index)) + ".md", body: "this quarterly forecast is new", version: uint64(500 + index), time: uint64(1800000000 + index),
		}))
	}

	const bulkCount = 500000
	keys := make([][indexIdByteCount]byte, 0, bulkCount+8)
	records := make([]searchVersionRecord, 0, bulkCount+8)
	for index := range bulkCount {
		keys = append(keys, testIndexId("fs109 bulk", index))
		records = append(records, searchVersionRecord{found: true, version: uint64(100 + index%7)})
	}
	for key, record := range testSearchRecords(append(slices.Clone(matching), others...)...) {
		keys, records = append(keys, key), append(records, record)
	}
	// the all row's document has a newer, nonmatching version in a bucket
	keys, records = append(keys, stale.key), append(records, searchVersionRecord{found: true, version: 9})
	table := newTestVersionTable(keys, records)

	// the heap is sampled at each probe as well as after, so a walk that built and dropped a key set shows too
	peak := uint64(0)
	probe := func(key [indexIdByteCount]byte) (searchVersionRecord, error) {
		stats := &runtime.MemStats{}
		runtime.ReadMemStats(stats)
		peak = max(peak, stats.HeapAlloc)
		return table.probe(key)
	}
	source := run.source(repoId, refId, &searchMaskArgs{probe: probe, refId: refId}, nil, nil)
	inputs := run.inputs(source, testSearchSlotPartition(searchPartitionCurrent, matching...), testSearchShardPartition(t, false, append(slices.Clone(others), stale)...))
	candidateCount := 0
	for _, input := range inputs {
		candidateCount += len(input.result.candidates)
	}

	runtime.GC()
	before := &runtime.MemStats{}
	runtime.ReadMemStats(before)
	hits, counts := run.all(inputs)
	runtime.GC()
	after := &runtime.MemStats{}
	runtime.ReadMemStats(after)
	runtime.KeepAlive(table)
	runtime.KeepAlive(inputs)
	runtime.KeepAlive(source)

	if got := testHitKeys(hits); len(got) != len(matching) || slices.Contains(got, stale.key) {
		t.Fatalf("%d hits, the masked all row among them: %v", len(got), slices.Contains(got, stale.key))
	}
	if counts.masked != 1 {
		t.Errorf("masked %d, want the all row", counts.masked)
	}
	if table.probes != candidateCount || table.pageReads != candidateCount {
		t.Errorf("%d probes and %d page reads for %d candidates", table.probes, table.pageReads, candidateCount)
	}
	if growth := int64(after.HeapAlloc) - int64(before.HeapAlloc); 1024*1024 < growth {
		t.Errorf("the walk's live heap grew %d B beside a %d-key table", growth, len(keys))
	}
	// the table's keys alone are 8 MB: a walk holding them, even for a moment, passes this
	if growth := int64(peak) - int64(before.HeapAlloc); 4*1024*1024 < growth {
		t.Errorf("the walk's heap reached %d B past its start beside a %d-key table", growth, len(keys))
	}
}

// FS-108's masks: a document removed in a newer partition is masked by its tombstone in every older one; one whose
// newer version lives elsewhere is masked by it; a ref tombstone masks every older document of its ref in ur/index,
// and a re-created ref's documents above it stay.
func TestSearchMaskTombstonesAndRefTombstones(t *testing.T) {
	repoId, refId := evsTestId("fs108 repo"), evsTestId("fs108 ref")
	refKey := testSearchRefKey("fs108")
	run := newTestSearchRun(t, "launch checklist")
	removed := testSearchEntry(t, refKey, refId, true, &testSearchDocument{path: "a.md", body: "the launch checklist", version: 3, time: 1700000000, refId: refId})
	edited := testSearchEntry(t, refKey, refId, true, &testSearchDocument{path: "b.md", body: "an old launch checklist", version: 4, time: 1700000100, refId: refId})
	beforeDelete := testSearchEntry(t, refKey, refId, true, &testSearchDocument{path: "c.md", body: "the launch checklist again", version: 5, time: 1700000200, refId: refId})
	recreated := testSearchEntry(t, refKey, refId, true, &testSearchDocument{path: "d.md", body: "a new launch checklist", version: 30, time: 1800000000, refId: refId})

	records := testSearchRecords(removed, edited, beforeDelete, recreated)
	records[removed.key] = searchVersionRecord{found: true, version: 8, tombstone: true}
	records[edited.key] = searchVersionRecord{found: true, version: 9}
	records[[indexIdByteCount]byte(refId)] = searchVersionRecord{found: true, version: 20, tombstone: true}
	table := testVersionTableOf(records)
	source := run.source(repoId, refId, &searchMaskArgs{probe: table.probe, companion: true, refId: refId}, nil, nil)
	hits, counts := run.all(run.inputs(source, testSearchSlotPartition(searchPartitionCurrent, recreated), testSearchShardPartition(t, true, removed, edited, beforeDelete)))
	if got := testHitKeys(hits); !slices.Equal(got, [][indexIdByteCount]byte{recreated.key}) {
		t.Fatalf("hits %d, want the re-created ref's document alone", len(got))
	}
	if counts.masked != 3 {
		t.Errorf("masked %d, want 3", counts.masked)
	}
	mask, err := newSearchMask(&searchMaskArgs{probe: table.probe, companion: true, refId: refId})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		entry *indexEntry
		want  searchMaskVerdict
	}{
		{entry: removed, want: searchMaskSuperseded},
		{entry: edited, want: searchMaskSuperseded},
		{entry: beforeDelete, want: searchMaskRefDeleted},
		{entry: recreated, want: searchMaskCurrent},
	} {
		verdict, err := mask.judge(&searchMaskCandidate{key: c.entry.key, version: c.entry.version, timeSeconds: c.entry.timeSeconds, row: c.entry.row})
		if err != nil || verdict != c.want {
			t.Errorf("%s: verdict %d, want %d (%v)", c.entry.row.locator, verdict, c.want, err)
		}
	}
	// the ref's tombstone is probed once a search, whatever its documents
	refProbes := 0
	probe := func(key [indexIdByteCount]byte) (searchVersionRecord, error) {
		if key == [indexIdByteCount]byte(refId) {
			refProbes += 1
		}
		return table.probe(key)
	}
	mask, _ = newSearchMask(&searchMaskArgs{probe: probe, companion: true, refId: refId})
	for _, entry := range []*indexEntry{recreated, beforeDelete, recreated} {
		if _, err := mask.judge(&searchMaskCandidate{key: entry.key, version: entry.version, row: entry.row}); err != nil {
			t.Fatal(err)
		}
	}
	if refProbes != 1 {
		t.Errorf("the ref's tombstone probed %d times", refProbes)
	}
}

// An ERASE masks every version of its key, the erasure set at or below the version it lists, a newer re-creation
// standing; an entry past its log's searchable_days is masked; a row of another ref in ur/index is out of scope, not
// masked; a candidate above anything the table holds reads not yet searchable; and no table, no mask.
func TestSearchMaskErasuresAndScope(t *testing.T) {
	refId, otherRefId := evsTestId("erase ref"), evsTestId("other ref")
	refKey := testSearchRefKey("erase")
	entry := func(path string, version uint64, time uint64, ref Id) *indexEntry {
		return testSearchEntry(t, refKey, ref, true, &testSearchDocument{path: path, body: "words", version: version, time: time, refId: ref})
	}
	erased := entry("e.md", 4, 1800000000, refId)
	listed := entry("l.md", 4, 1800000000, refId)
	recreated := entry("r.md", 9, 1800000000, refId)
	old := entry("o.md", 4, 1600000000, refId)
	foreign := entry("f.md", 4, 1800000000, otherRefId)
	ahead := entry("x.md", 12, 1800000000, refId)
	records := testSearchRecords(erased, listed, recreated, old, foreign)
	records[erased.key] = searchVersionRecord{found: true, version: 4, erasedThrough: searchErasedAll}
	records[listed.key] = searchVersionRecord{found: true, version: 4, erasedThrough: 4}
	records[recreated.key] = searchVersionRecord{found: true, version: 9, erasedThrough: 6}
	records[ahead.key] = searchVersionRecord{found: true, version: 11}
	table := testVersionTableOf(records)
	mask, err := newSearchMask(&searchMaskArgs{probe: table.probe, companion: true, refId: refId, searchableSinceSeconds: 1700000000})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		entry *indexEntry
		want  searchMaskVerdict
	}{
		{entry: erased, want: searchMaskErased},
		{entry: listed, want: searchMaskErased},
		{entry: recreated, want: searchMaskCurrent},
		{entry: old, want: searchMaskExpired},
		{entry: foreign, want: searchMaskOtherRef},
		{entry: ahead, want: searchMaskUnknown},
	} {
		verdict, err := mask.judge(&searchMaskCandidate{key: c.entry.key, version: c.entry.version, timeSeconds: c.entry.timeSeconds, row: c.entry.row})
		if err != nil || verdict != c.want {
			t.Errorf("%s: verdict %d, want %d (%v)", c.entry.row.locator, verdict, c.want, err)
		}
	}
	if searchMaskOtherRef.masked() || !searchMaskErased.masked() {
		t.Error("only masks count as masked")
	}
	if _, err := newSearchMask(&searchMaskArgs{refId: refId}); err != errSearchMaskNoTable {
		t.Errorf("a mask without a table: %v", err)
	}
}

// A branch's search (§11.7's overlays): the branch's own documents, and its base ref's documents for paths it has not
// changed, probing the table for the branch's own key of each; a path the branch changed or removed shows the
// branch's version alone, and a base row whose locator is not the exact path is not shown.
func TestSearchMaskBranchOverlay(t *testing.T) {
	repoId := evsTestId("overlay repo")
	baseId, branchId := evsTestId("main"), evsTestId("agent branch")
	refKey := testSearchRefKey("overlay")
	run := newTestSearchRun(t, "retry budget")
	document := func(ref Id, path string, body string, version uint64, time uint64) *indexEntry {
		return testSearchEntry(t, refKey, ref, true, &testSearchDocument{path: path, body: body, version: version, time: time, refId: ref})
	}
	unchanged := document(baseId, "src/client.go", "the retry budget of the client", 5, 1700000000)
	changedBase := document(baseId, "src/server.go", "the retry budget of the server", 6, 1700000100)
	changedBranch := document(branchId, "src/server.go", "the retry budget, raised", 11, 1700000500)
	removedBase := document(baseId, "src/old.go", "a retry budget long gone", 4, 1700000050)
	branchOnly := document(branchId, "src/new.go", "a new retry budget", 12, 1700000600)
	otherBranch := document(evsTestId("someone else's branch"), "src/x.go", "their retry budget", 13, 1700000700)
	inexact := document(baseId, "src/cut.go", "a retry budget behind a cut path", 7, 1700000200)
	inexact.row.flags |= indexRowInexact

	records := testSearchRecords(unchanged, changedBase, changedBranch, removedBase, branchOnly, otherBranch, inexact)
	removedKey, err := indexDocKey(refKey, branchId, []byte("src/old.go"), 0)
	if err != nil {
		t.Fatal(err)
	}
	records[removedKey] = searchVersionRecord{found: true, version: 10, tombstone: true}
	table := testVersionTableOf(records)
	branchKey := func(row *indexRow) ([indexIdByteCount]byte, bool) {
		if row.flags&indexRowInexact != 0 {
			return [indexIdByteCount]byte{}, false
		}
		key, err := indexDocKey(refKey, branchId, []byte(row.locator), uint32(row.chunk))
		return key, err == nil
	}
	source := run.source(repoId, branchId, &searchMaskArgs{probe: table.probe, companion: true, refId: branchId, baseRefId: &baseId, branchKey: branchKey}, nil, nil)
	hits, counts := run.all(run.inputs(source, testSearchSlotPartition(searchPartitionCurrent, changedBranch, branchOnly, otherBranch, unchanged, changedBase, removedBase, inexact)))
	// no text here and the terms only in bodies: every hit is possible, ranked by overlap, so the set is what counts
	got := testHitKeys(hits)
	want := [][indexIdByteCount]byte{branchOnly.key, changedBranch.key, unchanged.key}
	slices.SortFunc(got, compareIndexKeys)
	slices.SortFunc(want, compareIndexKeys)
	if !slices.Equal(got, want) {
		locators := []string{}
		for _, hit := range hits {
			locators = append(locators, hit.row.locator)
		}
		t.Fatalf("hits %v", locators)
	}
	for _, hit := range hits {
		if hit.key == unchanged.key && hit.refId != baseId || hit.key == changedBranch.key && hit.refId != branchId {
			t.Errorf("%s's hit names the wrong ref", hit.row.locator)
		}
	}
	if counts.masked != 2 || counts.unsearchable != 1 {
		t.Errorf("masked %d and unsearchable %d, want the two overlaid base documents and the cut one", counts.masked, counts.unsearchable)
	}
}

// The local layer joins newest-wins: a version this host indexed past the index supersedes the index's older one, and
// once a partition holds its version the local copy is superseded in turn.
func TestSearchMaskLocalLayerJoinsNewestWins(t *testing.T) {
	refId := evsTestId("local ref")
	refKey := testSearchRefKey("local")
	indexed := testSearchEntry(t, refKey, refId, false, &testSearchDocument{path: "a.md", body: "words", version: 4, time: 1})
	table := testVersionTableOf(testSearchRecords(indexed))
	localVersion := uint64(6)
	mask, err := newSearchMask(&searchMaskArgs{
		probe: table.probe, refId: refId,
		local: func(key [indexIdByteCount]byte) (uint64, bool, bool) {
			return localVersion, false, key == indexed.key
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	judge := func(version uint64, local bool) searchMaskVerdict {
		verdict, err := mask.judge(&searchMaskCandidate{key: indexed.key, version: version, row: indexed.row, local: local})
		if err != nil {
			t.Fatal(err)
		}
		return verdict
	}
	if judge(4, false) != searchMaskSuperseded || judge(6, true) != searchMaskCurrent {
		t.Error("the local layer's newer version does not win")
	}
	table = testVersionTableOf(map[[indexIdByteCount]byte]searchVersionRecord{indexed.key: {found: true, version: 6}})
	mask.args.probe = table.probe
	if judge(6, true) != searchMaskSuperseded || judge(6, false) != searchMaskCurrent {
		t.Error("the index's copy does not answer once it holds the local version")
	}
	if !bytes.Equal(indexed.row.refId, nil) {
		t.Error("an in-ref row carries a ref_id")
	}
}
