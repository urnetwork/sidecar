// Matching (SEARCH-M10-23 and SEARCH-M10-45): shard intersection against a brute-force scan on random shards, heads
// and slots with their diffs on own bases, an absorbed slot read only as a base, FS-107's forged diff reading not yet
// searchable, too_broad, and a phone's working set.

package sidecar

import (
	"math/rand"
	"runtime"
	"slices"
	"testing"
)

// A query of groups of terms with these trigrams, as a parsed one would hold them.
func testQueryOf(groups ...[]indexKeySet) *SearchQuery {
	query := &SearchQuery{}
	for _, group := range groups {
		terms := []*SearchTerm{}
		for _, keys := range group {
			terms = append(terms, &SearchTerm{normalized: "t", trigrams: indexSortedKeys(keys)})
		}
		query.Groups = append(query.Groups, terms)
	}
	return query
}

// A shard of documents opened for reading.
func testOpenShard(t testing.TB, documents []*indexShardDocument) (*indexShardReader, []*indexShardDocument) {
	t.Helper()
	shard := &indexShard{header: testShardHeader(indexFileBucketShard), documents: documents}
	file := testBuildShard(t, shard, false, testPadKey(t, 2))
	reader, err := indexOpenShard(indexBytesFrames(file), false)
	if err != nil {
		t.Fatal(err)
	}
	sorted := slices.Clone(documents)
	slices.SortFunc(sorted, func(a *indexShardDocument, b *indexShardDocument) int {
		return compareIndexKeys(a.key, b.key)
	})
	return reader, sorted
}

// Random documents over a narrow key range, a dense range shared by the first ones so some lists are bitsets.
func testMatchDocuments(random *rand.Rand, count int) []*indexShardDocument {
	documents := []*indexShardDocument{}
	for index := range count {
		keys := testRandomKeys(random, 5+random.Intn(60), 0x616100, 400)
		if index < count/3 {
			keys = indexSortedKeys(append(keys, testIndexKeys(0x626200, 20, 1)...))
		}
		documents = append(documents, testShardDocument("match", index, indexDocFile, keys))
	}
	return documents
}

// Whether a key set holds the query, by brute force.
func testBruteHolds(query *SearchQuery, keys indexKeySet) bool {
	held := map[uint32]bool{}
	for _, key := range keys {
		held[key] = true
	}
	for _, group := range query.Groups {
		groupHolds := false
		for _, term := range group {
			termHolds := true
			for _, key := range term.trigrams {
				termHolds = termHolds && held[key]
			}
			groupHolds = groupHolds || termHolds
		}
		if !groupHolds {
			return false
		}
	}
	return true
}

// A shard's candidates equal a brute-force scan of its documents' key sets, over random shards and random queries of
// words, alternatives and absent trigrams.
func TestSearchMatchAgainstBruteForce(t *testing.T) {
	for seed := range int64(12) {
		random := rand.New(rand.NewSource(seed))
		reader, documents := testOpenShard(t, testMatchDocuments(random, 50+random.Intn(400)))
		listsRead := 0
		for query := range 60 {
			groups := [][]indexKeySet{}
			for range 1 + random.Intn(3) {
				group := []indexKeySet{}
				for range 1 + random.Intn(2) {
					group = append(group, testRandomKeys(random, 1+random.Intn(3), 0x616100, 420))
				}
				if query%5 == 0 {
					group = append(group, testIndexKeys(0x626200+random.Intn(20), 1, 1))
				}
				groups = append(groups, group)
			}
			parsed := testQueryOf(groups...)
			want := []uint32{}
			for docId, document := range documents {
				if testBruteHolds(parsed, document.keys) {
					want = append(want, uint32(docId))
				}
			}
			result := &searchPartitionResult{}
			got, err := searchMatchShard(parsed, reader, result)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
				t.Fatalf("seed %d query %d: %d candidates, want %d", seed, query, len(got), len(want))
			}
			listsRead += result.listCount
		}
		if listsRead == 0 {
			t.Errorf("seed %d read no list", seed)
		}
	}
}

// Intersections and unions agree with sets, whatever form each side takes.
func TestSearchDocSetsAgreeWithSets(t *testing.T) {
	random := rand.New(rand.NewSource(3))
	for round := range 200 {
		documentCount := 1 + random.Intn(300)
		draw := func(dense bool) (*indexPostingList, map[uint32]bool) {
			members := map[uint32]bool{}
			for range random.Intn(documentCount + 1) {
				members[uint32(random.Intn(documentCount))] = true
			}
			docIds := []uint32{}
			for docId := range members {
				docIds = append(docIds, docId)
			}
			slices.Sort(docIds)
			if dense {
				bitset := make([]byte, indexBitsetByteCount(documentCount))
				for _, docId := range docIds {
					bitset[docId/8] |= 1 << (docId % 8)
				}
				return &indexPostingList{count: len(docIds), bitset: bitset}, members
			}
			return &indexPostingList{count: len(docIds), docIds: docIds}, members
		}
		left, leftMembers := draw(round%2 == 0)
		right, rightMembers := draw(round%3 == 0)
		other, otherMembers := draw(round%5 == 0)
		set := searchDocSetOf(left, documentCount)
		set.intersect(right)
		union := searchDocSetOf(other, documentCount)
		union.union(set)
		want := []uint32{}
		wantUnion := []uint32{}
		for docId := range uint32(documentCount) {
			both := leftMembers[docId] && rightMembers[docId]
			if both {
				want = append(want, docId)
			}
			if both || otherMembers[docId] {
				wantUnion = append(wantUnion, docId)
			}
		}
		if !slices.Equal(set.all(), want) && len(want)+len(set.all()) != 0 || set.count() != len(want) {
			t.Fatalf("round %d: intersection %v, want %v", round, set.all(), want)
		}
		if !slices.Equal(union.all(), wantUnion) && len(wantUnion)+len(union.all()) != 0 {
			t.Fatalf("round %d: union %v, want %v", round, union.all(), wantUnion)
		}
	}
	docIds := []uint32{1, 4, 9, 16, 25, 36, 49, 64, 81, 100}
	for target := uint32(0); target <= 101; target += 1 {
		want, _ := slices.BinarySearch(docIds, target)
		for from := 0; from <= want; from += 1 {
			if got := searchGallop(docIds, from, target); got != want {
				t.Fatalf("gallop from %d to %d: %d, want %d", from, target, got, want)
			}
		}
	}
}

// A term with an absent trigram matches nothing in a shard, and a group none of whose terms is present ends the shard
// before any list is read.
func TestSearchMatchAbsentTrigramEndsTheShard(t *testing.T) {
	random := rand.New(rand.NewSource(5))
	reader, _ := testOpenShard(t, testMatchDocuments(random, 100))
	result := &searchPartitionResult{}
	present := testIndexKeys(0x626200, 2, 1)
	got, err := searchMatchShard(testQueryOf([]indexKeySet{present}, []indexKeySet{{0x7f7f7f}}), reader, result)
	if err != nil || len(got) != 0 {
		t.Fatalf("%d candidates, %v", len(got), err)
	}
	if result.listCount != 0 {
		t.Errorf("read %d lists for a query one of whose groups the shard lacks", result.listCount)
	}
}

// A bucket on own bases (DESIGN-DETAILS 1.2.9): A's sealed slot holds D's v1 full and A's head v2, a diff on it; B's
// head holds E full. v2 matches its own trigrams through A's slot, a trigram v1 and v2 share offers both, one v2
// removed offers v1 alone, and nothing alarms.
func TestSearchMatchChainsOnOwnBases(t *testing.T) {
	base := testIndexKeys(0x616100, 40, 1)
	v2 := slices.Clone(base)
	v2[1] = 0x727272
	v2 = indexSortedKeys(v2)
	d := testIndexId("d", 1)
	a, b := evsTestId("a"), evsTestId("b")
	eKeys := testIndexKeys(0x737373, 10, 1)
	source := &searchPartitionSource{
		partition: searchPartitionCurrent,
		slots: []*searchSlotSource{
			{slot: &indexSlot{entries: []*indexEntry{{kind: indexEntryFull, key: d, version: 1, timeSeconds: 1, row: testFileRow(base), keys: base}}}, writer: a, seq: 1, path: "s/1", signer: a},
			{slot: &indexSlot{entries: []*indexEntry{{kind: indexEntryDiff, key: d, version: 2, baseVersion: 1, timeSeconds: 2, row: testFileRow(v2), delta: indexDeltaBetween(base, v2)}}}, writer: a, seq: 2, head: true, path: "s/2", signer: a},
			{slot: &indexSlot{entries: []*indexEntry{{kind: indexEntryFull, key: testIndexId("e", 1), version: 1, row: testFileRow(eKeys), keys: eKeys}}}, writer: b, seq: 1, head: true},
		},
	}
	match := func(keys ...uint32) []uint64 {
		result, err := searchMatch(&searchMatchArgs{query: testQueryOf([]indexKeySet{keys}), source: source, maxCandidateCount: 20000, newest: func(key [indexIdByteCount]byte) (uint64, bool) { return 0, false }})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.unresolved) != 0 {
			t.Fatalf("unresolved %+v", result.unresolved)
		}
		versions := []uint64{}
		for _, candidate := range result.candidates {
			if candidate.entry.key == d {
				versions = append(versions, candidate.entry.version)
				if candidate.entry.version == 2 && (candidate.chain == nil || candidate.trigramCount != len(v2)) {
					t.Fatalf("v2's chain %+v", candidate.chain)
				}
			}
		}
		slices.Sort(versions)
		return versions
	}
	if versions := match(0x727272); !slices.Equal(versions, []uint64{2}) {
		t.Errorf("v2's own trigram: %v", versions)
	}
	if versions := match(base[5], base[6]); !slices.Equal(versions, []uint64{1, 2}) {
		t.Errorf("a trigram v1 and v2 share: %v", versions)
	}
	if versions := match(base[1]); !slices.Equal(versions, []uint64{1}) {
		t.Errorf("a trigram v2 removed: %v", versions)
	}
}

// An absorbed slot holds no candidate: its version is in the shard, which answers for it. It is still a diff's base,
// so the head's diff on it resolves.
func TestSearchMatchAbsorbedSlotIsOnlyABase(t *testing.T) {
	base := testIndexKeys(0x616100, 40, 1)
	v2 := slices.Clone(base)
	v2[1] = 0x727272
	v2 = indexSortedKeys(v2)
	d := testIndexId("d", 1)
	a := evsTestId("a")
	reader, _ := testOpenShard(t, []*indexShardDocument{{key: d, version: 1, timeSeconds: 1, row: testFileRow(base), keys: base}})
	source := &searchPartitionSource{
		partition: searchPartitionCurrent,
		shards:    []*searchShardSource{{n: 0, reader: reader}},
		slots: []*searchSlotSource{
			{slot: &indexSlot{entries: []*indexEntry{{kind: indexEntryFull, key: d, version: 1, timeSeconds: 1, row: testFileRow(base), keys: base}}}, writer: a, seq: 1, absorbed: true, path: "s/1", signer: a},
			{slot: &indexSlot{entries: []*indexEntry{{kind: indexEntryDiff, key: d, version: 2, baseVersion: 1, timeSeconds: 2, row: testFileRow(v2), delta: indexDeltaBetween(base, v2)}}}, writer: a, seq: 2, head: true, path: "s/2", signer: a},
		},
	}
	result, err := searchMatch(&searchMatchArgs{query: testQueryOf([]indexKeySet{{base[1]}}), source: source, maxCandidateCount: 20000})
	if err != nil || len(result.unresolved) != 0 {
		t.Fatalf("%v, unresolved %+v", err, result.unresolved)
	}
	if len(result.candidates) != 1 || result.candidates[0].shard == nil {
		t.Errorf("v1 offered %d times, the absorbed slot's among them: %+v", len(result.candidates), result.candidates)
	}
	result, err = searchMatch(&searchMatchArgs{query: testQueryOf([]indexKeySet{{0x727272}}), source: source, maxCandidateCount: 20000})
	if err != nil || len(result.unresolved) != 0 || len(result.candidates) != 1 || result.candidates[0].entry == nil || result.candidates[0].entry.version != 2 {
		t.Errorf("v2 on its absorbed base: %v, %+v", err, result)
	}
}

// FS-107: an unabsorbed diff whose base no file of its own writer holds, another writer's copy of the version not
// counting, reads not yet searchable naming its signer, never a match and never no match; so does one whose composed
// set's size is not its row's count, and one below its key's newest version, since under own bases nothing excuses
// it. A diff of a document the erasure set lists is left out unresolved and alarms nothing.
func TestSearchMatchForgedDiffReadsNotYetSearchable(t *testing.T) {
	keys := testIndexKeys(0x616100, 40, 1)
	forger, other := evsTestId("forger"), evsTestId("other")
	forged := &indexEntry{kind: indexEntryDiff, key: testIndexId("d", 1), version: 5, baseVersion: 4, timeSeconds: 2, row: testFileRow(keys), delta: indexDelta{added: indexKeySet{0x616100}, removed: indexKeySet{}}}
	othersCopy := &indexEntry{kind: indexEntryFull, key: testIndexId("d", 1), version: 4, row: testFileRow(keys[1:]), keys: keys[1:]}
	base := &indexEntry{kind: indexEntryFull, key: testIndexId("d", 2), version: 1, row: testFileRow(keys[1:]), keys: keys[1:]}
	misCounted := &indexEntry{kind: indexEntryDiff, key: testIndexId("d", 2), version: 2, baseVersion: 1, timeSeconds: 2, row: testFileRow(testIndexKeys(0x616100, 45, 1)), delta: indexDelta{added: indexKeySet{0x616100}, removed: indexKeySet{}}}
	stale := &indexEntry{kind: indexEntryDiff, key: testIndexId("d", 3), version: 6, baseVersion: 5, timeSeconds: 2, row: testFileRow(keys), delta: indexDelta{}}
	newer := &indexEntry{kind: indexEntryFull, key: testIndexId("d", 3), version: 7, row: testFileRow(keys), keys: keys}
	erased := &indexEntry{kind: indexEntryDiff, key: testIndexId("d", 4), version: 3, baseVersion: 2, timeSeconds: 2, row: testFileRow(keys), delta: indexDelta{}}
	source := &searchPartitionSource{
		partition: searchPartitionCurrent,
		slots: []*searchSlotSource{
			{slot: &indexSlot{entries: []*indexEntry{base}}, writer: forger, seq: 1, path: "s/1", signer: forger},
			{slot: &indexSlot{entries: []*indexEntry{forged, misCounted, stale, erased}}, writer: forger, seq: 2, path: "s/2", signer: forger},
			{slot: &indexSlot{entries: []*indexEntry{newer}}, writer: forger, seq: 3, head: true, path: "s/3", signer: forger},
			{slot: &indexSlot{entries: []*indexEntry{othersCopy}}, writer: other, seq: 1, path: "o/1", signer: other},
			{slot: &indexSlot{}, writer: other, seq: 2, head: true, path: "o/2", signer: other},
		},
	}
	result, err := searchMatch(&searchMatchArgs{
		query: testQueryOf([]indexKeySet{{keys[3]}}), source: source, maxCandidateCount: 20000,
		erased: func(key [indexIdByteCount]byte, version uint64) bool {
			return key == testIndexId("d", 4) && version <= 3
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	unresolved := map[[indexIdByteCount]byte]*searchUnresolved{}
	for _, entry := range result.unresolved {
		unresolved[entry.key] = entry
	}
	if len(unresolved) != 3 || unresolved[testIndexId("d", 1)] == nil || unresolved[testIndexId("d", 2)] == nil || unresolved[testIndexId("d", 3)] == nil {
		t.Fatalf("unresolved %+v", result.unresolved)
	}
	if entry := unresolved[testIndexId("d", 1)]; entry.signer != forger || entry.path != "s/2" || entry.version != 5 {
		t.Errorf("the alarm names %+v", entry)
	}
	for _, candidate := range result.candidates {
		if candidate.entry != nil && (candidate.entry == forged || candidate.entry == misCounted || candidate.entry == stale || candidate.entry == erased) {
			t.Errorf("a broken or erased diff is a candidate")
		}
	}
}

// A diff whose composed set D6 skips under its own row reads as a diff with no base does (DESIGN-DETAILS 1.2.9;
// QD-760): not yet searchable, its slot's signer alarmed, never a candidate; one that composes to lone = ShardBody,
// keys 0 to 199,607 under a 36 B row, is a candidate.
func TestSearchMatchChainPastAShardReadsNotYetSearchable(t *testing.T) {
	writer := evsTestId("writer")
	base := func(index int) *indexEntry {
		keys := testIndexKeys(0, 199001, 1)
		return &indexEntry{kind: indexEntryFull, key: testIndexId("lone", index), version: 1, row: testFileRowOfByteCount(t, len(keys), 36), keys: keys}
	}
	diff := func(index int, addedCount int) *indexEntry {
		return &indexEntry{kind: indexEntryDiff, key: testIndexId("lone", index), version: 2, baseVersion: 1, timeSeconds: 2, row: testFileRowOfByteCount(t, 199001+addedCount, 36), delta: indexDelta{added: testIndexKeys(199001, addedCount, 1)}}
	}
	atBound, pastBound := diff(1, 607), diff(2, 1000)
	sealed := []*indexEntry{atBound, pastBound}
	slices.SortFunc(sealed, indexCompareEntries)
	bases := []*indexEntry{base(1), base(2)}
	slices.SortFunc(bases, indexCompareEntries)
	source := &searchPartitionSource{
		partition: searchPartitionCurrent,
		slots: []*searchSlotSource{
			{slot: &indexSlot{entries: bases}, writer: writer, seq: 1, path: "s/1", signer: writer},
			{slot: &indexSlot{entries: sealed}, writer: writer, seq: 2, path: "s/2", signer: writer},
			{slot: &indexSlot{}, writer: writer, seq: 3, head: true, path: "s/3", signer: writer},
		},
	}
	result, err := searchMatch(&searchMatchArgs{query: testQueryOf([]indexKeySet{{5}}), source: source, maxCandidateCount: 20000})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.unresolved) != 1 || result.unresolved[0].key != pastBound.key || result.unresolved[0].signer != writer || result.unresolved[0].path != "s/2" {
		t.Fatalf("unresolved %+v", result.unresolved)
	}
	found := false
	for _, candidate := range result.candidates {
		if candidate.entry == pastBound {
			t.Fatal("a diff composing past a shard is a candidate")
		}
		found = found || candidate.entry == atBound && candidate.trigramCount == 199608
	}
	if !found {
		t.Fatal("the diff composing to lone = ShardBody is no candidate")
	}
}

// Past the cap a partition answers too_broad with its count, keeping no more candidates than the cap.
func TestSearchMatchTooBroad(t *testing.T) {
	random := rand.New(rand.NewSource(9))
	reader, _ := testOpenShard(t, testMatchDocuments(random, 300))
	source := &searchPartitionSource{partition: searchPartitionAll, shards: []*searchShardSource{{n: 0, reader: reader}}}
	result, err := searchMatch(&searchMatchArgs{query: testQueryOf([]indexKeySet{testIndexKeys(0x626200, 1, 1)}), source: source, maxCandidateCount: 50})
	if err != nil {
		t.Fatal(err)
	}
	if !result.tooBroad || result.candidateCount != 100 || len(result.candidates) != 50 {
		t.Errorf("too broad %v, %d counted, %d kept", result.tooBroad, result.candidateCount, len(result.candidates))
	}
	empty, err := searchMatch(&searchMatchArgs{query: &SearchQuery{}, source: source, maxCandidateCount: 1000})
	if err != nil || len(empty.candidates) != 300 {
		t.Errorf("an empty query offers %d documents, %v", len(empty.candidates), err)
	}
	none, err := searchMatch(&searchMatchArgs{query: &SearchQuery{Excluded: []*SearchTerm{{normalized: "x"}}}, source: source, maxCandidateCount: 1000})
	if err != nil || len(none.candidates) != 0 {
		t.Errorf("excluded terms alone offer %d documents, %v", len(none.candidates), err)
	}
}

// R-EVS-14: matching a broad query over four shards near their 1 MiB cap, 18,000 candidates, allocates within a
// phone's 4 MiB working set, the shards standing for the cache, which a phone reads a frame at a time.
func TestSearchMatchStaysInsideAPhoneWorkingSet(t *testing.T) {
	random := rand.New(rand.NewSource(11))
	shards := []*searchShardSource{}
	for n := range 4 {
		documents := []*indexShardDocument{}
		for index := range 4500 {
			keys := testRandomKeys(random, 80, 0x616100, 2000)
			keys = indexSortedKeys(append(keys, 0x626262))
			documents = append(documents, testShardDocument("phone", n*100000+index, indexDocMail, keys))
		}
		reader, _ := testOpenShard(t, documents)
		if reader.layout.length < 768*1024 {
			t.Fatalf("shard %d is %d B", n, reader.layout.length)
		}
		shards = append(shards, &searchShardSource{n: uint32(n), reader: reader})
	}
	source := &searchPartitionSource{partition: searchPartitionAll, shards: shards}
	query := testQueryOf([]indexKeySet{{0x626262}}, []indexKeySet{testRandomKeys(random, 2, 0x616100, 2000), {0x626262}})
	runtime.GC()
	before := runtime.MemStats{}
	runtime.ReadMemStats(&before)
	result, err := searchMatch(&searchMatchArgs{query: query, source: source, maxCandidateCount: 20000})
	after := runtime.MemStats{}
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if result.candidateCount != 18000 {
		t.Fatalf("%d candidates", result.candidateCount)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	if 4*1024*1024 < allocated {
		t.Errorf("matching allocated %d B, past a phone's 4 MiB", allocated)
	}
	t.Logf("matching 4 shards of %d B allocated %d B for %d candidates", shards[0].reader.layout.length, allocated, result.candidateCount)
}
