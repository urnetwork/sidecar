// The local layer and the no-index scan (SEARCH-M10-25): FS-74's uncovered commit found from local text at once and
// dropped once the index covers it; removals and lost chunks as tombstones; an erasure dropping its entry from the
// layer and from the sealed copy that replaces the last; the memory bound counting what it leaves out; the journal
// joining newest-wins; and a ref with no index scanned by text, by names and i/ fields, a page at a time, "index off".

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// A layer for one in-ref index.
func testSearchLocalLayer(t testing.TB, refId Id, refKey []byte, settings *SearchResultSettings) *SearchLocalLayer {
	t.Helper()
	layer, err := NewSearchLocalLayer(&SearchLocalLayerArgs{RepoId: evsTestId("local repo"), RefId: refId, RefKey: refKey, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	return layer
}

// A file version past what the index covers, from content.
func testSearchLocalVersion(t testing.TB, refId Id, path string, content string, version uint64, timeMs int64) *SearchLocalVersion {
	t.Helper()
	documents, ok := indexExtractFile([]byte(path), []byte(content), DefaultIndexFormatSettings())
	if !ok {
		t.Fatalf("%s is no text", path)
	}
	return &SearchLocalVersion{RefId: refId, Path: []byte(path), Version: version, TimeMs: timeMs, Documents: documents}
}

// FS-74 at unit level: a commit past what the index covers is found at once from this host's text, in the local
// layer, and the index's older version of the document is masked by it; once a validated file holds that version,
// Cover drops the local entry and the index's copy answers.
func TestSearchLocalLayerFindsAnUncoveredCommit(t *testing.T) {
	repoId, refId := evsTestId("local repo"), evsTestId("local ref")
	refKey := testSearchRefKey("local layer")
	indexed := testSearchEntry(t, refKey, refId, false, &testSearchDocument{path: "notes/plan.md", title: "Plan", body: "the old outline", version: 4, time: 1800000000})
	layer := testSearchLocalLayer(t, refId, refKey, nil)
	if err := layer.Index(testSearchNormalizer(t), testSearchLocalVersion(t, refId, "notes/plan.md", "# Plan\nthe fresh outline\n", 7, 1800000600000)); err != nil {
		t.Fatal(err)
	}
	search := func(query string, table *testVersionTable, partitions ...*searchPartitionSource) []*searchRankedHit {
		run := newTestSearchRun(t, query)
		local, err := layer.partition()
		if err != nil {
			t.Fatal(err)
		}
		source := run.source(repoId, refId, &searchMaskArgs{probe: table.probe, refId: refId, local: layer.newest}, nil, nil)
		hits, _ := run.all(run.inputs(source, append(partitions, local)...))
		return hits
	}
	table := testVersionTableOf(testSearchRecords(indexed))
	current := testSearchSlotPartition(searchPartitionCurrent, indexed)
	hits := search("fresh outline", table, current)
	if len(hits) != 1 || hits[0].partition != searchPartitionLocal || hits[0].version != 7 || hits[0].timeSeconds != 1800000600 {
		t.Fatalf("the uncovered commit: %+v", hits)
	}
	if hits := search("old outline", table, current); len(hits) != 0 {
		t.Fatal("the index's older version showed beside the local layer's")
	}

	covering := testSearchEntry(t, refKey, refId, false, &testSearchDocument{path: "notes/plan.md", title: "Plan", body: "the fresh outline", version: 7, time: 1800000600})
	table = testVersionTableOf(testSearchRecords(indexed, covering))
	if dropped, err := layer.Cover(table.probe); err != nil || dropped != 1 {
		t.Fatalf("cover dropped %d, %v", dropped, err)
	}
	hits = search("fresh outline", table, testSearchSlotPartition(searchPartitionCurrent, covering))
	if len(hits) != 1 || hits[0].partition != searchPartitionCurrent || hits[0].version != 7 {
		t.Fatalf("once covered: %+v", hits)
	}
	if _, _, ok := layer.newest(covering.key); ok {
		t.Error("the covered entry is still held")
	}
}

// A removal past what the index covers is a tombstone in the layer, so the index's version is masked meanwhile; a
// version with fewer chunks tombstones the chunks past its own; a skipped chunk is a tombstone too.
func TestSearchLocalLayerTombstones(t *testing.T) {
	refId := evsTestId("local ref")
	refKey := testSearchRefKey("tombstones")
	layer := testSearchLocalLayer(t, refId, refKey, nil)
	normalizer := testSearchNormalizer(t)
	if err := layer.Index(normalizer, &SearchLocalVersion{RefId: refId, Path: []byte("gone.md"), Version: 9, TimeMs: 1}); err != nil {
		t.Fatal(err)
	}
	gone, err := indexDocKey(refKey, refId, []byte("gone.md"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if version, tombstone, ok := layer.newest(gone); !ok || !tombstone || version != 9 {
		t.Fatalf("the removal: %d %v %v", version, tombstone, ok)
	}
	shrunk := testSearchLocalVersion(t, refId, "big.md", "# Big\nnow small\n", 5, 1)
	shrunk.ReplacedChunkCount = 3
	if err := layer.Index(normalizer, shrunk); err != nil {
		t.Fatal(err)
	}
	for chunk := uint32(0); chunk < 3; chunk += 1 {
		key, err := indexDocKey(refKey, refId, []byte("big.md"), chunk)
		if err != nil {
			t.Fatal(err)
		}
		version, tombstone, ok := layer.newest(key)
		if !ok || version != 5 || tombstone != (0 < chunk) {
			t.Errorf("chunk %d: %d %v %v", chunk, version, tombstone, ok)
		}
	}
	// an older version arriving late leaves the newer one in place
	if err := layer.Index(normalizer, testSearchLocalVersion(t, refId, "gone.md", "# Back\nearlier text\n", 8, 1)); err != nil {
		t.Fatal(err)
	}
	if version, tombstone, _ := layer.newest(gone); version != 9 || !tombstone {
		t.Error("a late older version replaced the removal")
	}
	partition, err := layer.partition()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.IsSortedFunc(partition.slots[0].slot.entries, indexCompareEntries) || len(partition.slots[0].slot.entries) != 4 {
		t.Errorf("the partition holds %d entries", len(partition.slots[0].slot.entries))
	}
}

// An erasure drops the document's entry from the layer, and the sealed copy that replaces the last holds none of its
// text; the layer comes back from its sealed copy whole.
func TestSearchLocalLayerErasureAndItsSealedCopy(t *testing.T) {
	refId := evsTestId("local ref")
	refKey := testSearchRefKey("erasure")
	layer := testSearchLocalLayer(t, refId, refKey, nil)
	normalizer := testSearchNormalizer(t)
	for index, body := range []string{"the quixotical memo", "an ordinary note"} {
		if err := layer.Index(normalizer, testSearchLocalVersion(t, refId, fmt.Sprintf("n/%d.md", index), "# Note "+body+"\n"+body+"\n", uint64(3+index), 1)); err != nil {
			t.Fatal(err)
		}
	}
	world := newTestSearchCacheWorld(t, 64*1024*1024)
	key := SearchCacheKey{RepoId: evsTestId("local repo"), RefId: refId, Path: SearchCacheRefPath}
	if err := world.cache.SetRefVersion(key.RepoId, key.RefId, 9); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := layer.Save(ctx, world.cache, key); err != nil {
		t.Fatal(err)
	}
	erased, err := indexDocKey(refKey, refId, []byte("n/0.md"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if layer.Erase(erased, 2) || !layer.Erase(erased, searchErasedAll) {
		t.Fatal("an erasure through a version below the entry's dropped it, or one past it did not")
	}
	if err := layer.Save(ctx, world.cache, key); err != nil {
		t.Fatal(err)
	}
	frames, err := world.cache.OpenDerived(key, SearchCachePartLocalLayer)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := frames.ReadAll()
	if err != nil || bytes.Contains(plaintext, []byte("quixotical")) || bytes.Contains(plaintext, []byte("n/0.md")) {
		t.Fatalf("the sealed copy holds the erased document: %v", err)
	}
	restored := testSearchLocalLayer(t, refId, refKey, nil)
	if err := restored.Load(world.cache, key); err != nil {
		t.Fatal(err)
	}
	encoded, err := restored.encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, plaintext) || restored.byteCount != layer.byteCount {
		t.Error("the layer did not come back whole")
	}
	if err := restored.decode(append(slices.Clone(plaintext), 0)); err == nil {
		t.Error("trailing bytes decoded")
	}
}

// Past LocalLayerByteCount a version is left out and counted, so coverage reads it not yet searchable.
func TestSearchLocalLayerBound(t *testing.T) {
	refId := evsTestId("local ref")
	settings := DefaultSearchResultSettings()
	settings.LocalLayerByteCount = 600
	layer := testSearchLocalLayer(t, refId, testSearchRefKey("bound"), settings)
	normalizer := testSearchNormalizer(t)
	for index := range 6 {
		words := []string{}
		for word := range 60 {
			words = append(words, fmt.Sprintf("w%d", index*100+word))
		}
		if err := layer.Index(normalizer, testSearchLocalVersion(t, refId, fmt.Sprintf("b/%d.md", index), "# Bound\n"+strings.Join(words, " ")+"\n", 2, 1)); err != nil {
			t.Fatal(err)
		}
	}
	if layer.Uncovered() == 0 || 600 < layer.byteCount || len(layer.entries)+layer.Uncovered() != 6 {
		t.Errorf("%d held in %d B, %d left out", len(layer.entries), layer.byteCount, layer.Uncovered())
	}
}

// A journal of the device's own committed documents.
type testSearchJournal []*indexEntry

func (self testSearchJournal) searchJournalEntries(visit func(entry *indexEntry) error) error {
	for _, entry := range self {
		if err := visit(entry); err != nil {
			return err
		}
	}
	return nil
}

// The journal joins the layer: its entries are searched, the newer of the two copies of a key wins.
func TestSearchLocalLayerJoinsTheJournal(t *testing.T) {
	refId := evsTestId("local ref")
	refKey := testSearchRefKey("journal")
	layer := testSearchLocalLayer(t, refId, refKey, nil)
	if err := layer.Index(testSearchNormalizer(t), testSearchLocalVersion(t, refId, "j.md", "# J\nfirst\n", 3, 1)); err != nil {
		t.Fatal(err)
	}
	newer := testSearchEntry(t, refKey, refId, false, &testSearchDocument{path: "j.md", body: "second", version: 4, time: 2})
	other := testSearchEntry(t, refKey, refId, false, &testSearchDocument{path: "k.md", body: "third", version: 2, time: 2})
	layer.setJournal(testSearchJournal{newer, other})
	if version, _, ok := layer.newest(newer.key); !ok || version != 4 {
		t.Errorf("the journal's newer version: %d %v", version, ok)
	}
	partition, err := layer.partition()
	if err != nil {
		t.Fatal(err)
	}
	if entries := partition.slots[0].slot.entries; len(entries) != 2 || !slices.Contains(entries, newer) || !slices.Contains(entries, other) {
		t.Errorf("the joined partition holds %d entries", len(entries))
	}
}

// A ref's documents in a fixed order.
type testSearchScan []*SearchScanDocument

func (self testSearchScan) SearchScan(ctx context.Context, after uint64, visit func(position uint64, document *SearchScanDocument) (bool, error)) error {
	for index := after; index < uint64(len(self)); index += 1 {
		more, err := visit(index+1, self[index])
		if err != nil || !more {
			return err
		}
	}
	return nil
}

// A ref with no index: a host with the text scans every document and verifies each, a page at a time from where the
// last stopped; a phone matches names and i/ fields, confirming or giving nothing; every result says index off.
func TestSearchNoIndexScan(t *testing.T) {
	refId := evsTestId("off ref")
	normalizer := testSearchNormalizer(t)
	query, err := ParseSearchQuery("ledger")
	if err != nil {
		t.Fatal(err)
	}
	texts := testSearchScan{}
	for index, content := range []string{"# A\nthe ledger\n", "# B\nnothing here\n", "# C\na ledger again\n", "# D\nnor here\n", "# E\nledger once more\n"} {
		documents, ok := indexExtractFile([]byte(fmt.Sprintf("off/%d.md", index)), []byte(content), DefaultIndexFormatSettings())
		if !ok {
			t.Fatal("no text")
		}
		texts = append(texts, &SearchScanDocument{RefId: refId, Kind: IndexDocFile, Name: []byte(fmt.Sprintf("off/%d.md", index)), Version: 1, TimeMs: 1800000000000, Documents: documents})
	}
	settings := DefaultSearchResultSettings()
	settings.ScanDocumentCount = 3
	scan := func(source SearchScanSource, after uint64) *searchScanResult {
		result, err := searchNoIndexScan(context.Background(), &searchScanArgs{query: query, normalizer: normalizer, settings: settings, source: source, repoId: evsTestId("off repo"), after: after})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := scan(texts, 0)
	if !first.indexOff || first.done || first.scanned != 3 || first.position != 3 || !slices.Equal(testHitLocators(first.hits), []string{"off/0.md", "off/2.md"}) {
		t.Fatalf("first page: %+v %v", first, testHitLocators(first.hits))
	}
	second := scan(texts, first.position)
	if !second.done || second.scanned != 2 || !slices.Equal(testHitLocators(second.hits), []string{"off/4.md"}) {
		t.Fatalf("second page: %+v %v", second, testHitLocators(second.hits))
	}
	for _, hit := range append(first.hits, second.hits...) {
		if hit.match != searchMatchVerified || !hit.scanned || !strings.Contains(hit.snippet, "ledger") {
			t.Errorf("%s: match %d, snippet %q", hit.row.locator, hit.match, hit.snippet)
		}
	}

	phone := testSearchScan{
		{RefId: refId, Kind: IndexDocFile, Name: []byte("books/ledger.csv"), Version: 1, Display: &SearchScanDisplay{}},
		{RefId: refId, Kind: IndexDocMail, Name: []byte("m/x"), Version: 1, Display: &SearchScanDisplay{Subject: "Your ledger", From: "a@example.com"}},
		{RefId: refId, Kind: IndexDocMail, Name: []byte("m/y"), Version: 1, Display: &SearchScanDisplay{Subject: "Hi", Snippet: "see the ledger attached"}},
		{RefId: refId, Kind: IndexDocMail, Name: []byte("m/z"), Version: 1, Display: &SearchScanDisplay{Subject: "Hi", Snippet: "nothing"}},
	}
	settings.ScanDocumentCount = 10
	result := scan(phone, 0)
	if !result.indexOff || !result.done || !slices.Equal(testHitLocators(result.hits), []string{"books/ledger.csv", "m/x", "m/y"}) {
		t.Fatalf("by names and i/ fields: %v", testHitLocators(result.hits))
	}
	for _, hit := range result.hits {
		if hit.match != searchMatchConfirmed {
			t.Errorf("%s: match %d", hit.row.locator, hit.match)
		}
	}
	if _, err := searchNoIndexScan(context.Background(), &searchScanArgs{query: query, normalizer: normalizer, settings: settings}); err == nil {
		t.Error("a scan of no source ran")
	}
}
