// Shards, their doc and tombstone tables, the keyed pad, rewrites in place, the frame reader, paths and the small
// files, against testdata/index/shard/'s vectors and against bytes assembled by hand here, since a decoder that only
// ever saw its own encoder proves nothing about the format.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand"
	"reflect"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

const testShardVectorPath = "testdata/index/shard/vectors.json"

// A shard's header on fixed tables, so a vector's bytes do not ride on the build running the test.
func testShardHeader(fileType uint32) *protocol.IndexFileHeader {
	header := indexNewFileHeader(fileType, indexTables{normVersion: "17.0.0", textModuleVersion: "v0.43.0"})
	if fileType == indexFileBucketShard {
		header.BucketStartDay = 20340
		header.BucketDays = 30
	}
	header.PadGeneration = 2
	return header
}

// K_index_g of a repo whose keys are fixed, as a ladder walk leaves them.
func testPadKey(t testing.TB, generation uint64) *indexPadKey {
	t.Helper()
	padKey, err := indexNewPadKey(evsTestRepoKey(evsTestId("index repo"), generation))
	if err != nil {
		t.Fatal(err)
	}
	return padKey
}

// count distinct keys drawn from [low, low+span), ascending.
func testRandomKeys(random *rand.Rand, count int, low int, span int) indexKeySet {
	keys := make(indexKeySet, 0, count)
	for range count {
		keys = append(keys, uint32(low+random.Intn(span)))
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}

// One live document of a shard with these keys: a file row, a mail row or, on ur/index, a derived one.
func testShardDocument(label string, index int, docKind indexDocKind, keys indexKeySet) *indexShardDocument {
	var row *indexRow
	switch docKind {
	case indexDocMail:
		row = testMailRow(keys)
	case indexDocDerived:
		row = testDerivedRow(keys)
	default:
		row = testFileRow(keys)
	}
	return &indexShardDocument{
		key:         testIndexId(label, index),
		version:     uint64(10 + index),
		timeSeconds: uint64(1800000000 + 60*index),
		row:         row,
		keys:        keys,
	}
}

// count documents whose keys come from a small range, so lists repeat, and whose first few share one key range
// densely enough that their lists are bitsets.
func testShardDocuments(seed int64, label string, count int, docKind indexDocKind) []*indexShardDocument {
	random := rand.New(rand.NewSource(seed))
	documents := []*indexShardDocument{}
	for index := range count {
		keys := testRandomKeys(random, 20+random.Intn(60), 0x616100, 600)
		if index%3 == 0 {
			keys = keys.with(testIndexKeys(0x700000, 8, 1).without(keys))
		}
		documents = append(documents, testShardDocument(label, index, docKind, keys))
	}
	return documents
}

// A tombstone of kind for label's index-th key.
func testShardTombstone(kind indexEntryKind, label string, index int) *indexShardTombstone {
	return &indexShardTombstone{kind: kind, key: testIndexId(label, index), version: uint64(5 + index), timeSeconds: uint64(1800001000 + index)}
}

// Builds a shard with its keyed pad.
func testBuildShard(t testing.TB, shard *indexShard, companion bool, padKey *indexPadKey) []byte {
	t.Helper()
	file, err := indexNewShardBuilder(companion).build(shard, padKey)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// Decodes under the file's true hash.
func testDecodeShard(file []byte, companion bool) (*indexShard, error) {
	sum := sha256.Sum256(file)
	return indexDecodeShard(file, sum[:], companion)
}

// plan-SEARCH-shrink-claim's probe case: one small document alone holds the lowest key, ahead of keys laid out so
// that each block's first key shares no byte with the key before it and its second shares two with it. Removing the
// probe moves every block's start one key on, so a rebuild by 64 writes each block's second key whole.
func testProbeShard() (*indexShard, [indexIdByteCount]byte) {
	const groupCount = 64
	keys := indexKeySet{}
	for group := range uint32(groupCount) {
		for index := range uint32(indexBlockMaxKeyCount) {
			switch index {
			case 0:
				keys = append(keys, group<<16)
			case 1:
				keys = append(keys, group<<16|1)
			default:
				keys = append(keys, group<<16|index<<8)
			}
		}
	}
	probe := testShardDocument("probe", 0, indexDocFile, keys[:1])
	rest := testShardDocument("probe", 1, indexDocFile, keys[1:])
	return &indexShard{
		header:    testShardHeader(indexFileBucketShard),
		documents: []*indexShardDocument{probe, rest},
	}, probe.key
}

// The named shards testdata/index/shard/ pins.
type testShardCase struct {
	name      string
	companion bool
	file      []byte
}

func testShardCases(t testing.TB) []testShardCase {
	t.Helper()
	bucket := &indexShard{
		header:    testShardHeader(indexFileBucketShard),
		documents: testShardDocuments(1, "bucket", 40, indexDocFile),
		tombstones: []*indexShardTombstone{
			testShardTombstone(indexEntryTombstone, "gone", 1),
			testShardTombstone(indexEntryTombstone, "gone", 2),
			testShardTombstone(indexEntryTombstone, "gone", 3),
		},
	}
	all := &indexShard{
		header:    testShardHeader(indexFileAllShard),
		documents: testShardDocuments(2, "all", 30, indexDocMail),
	}
	companion := &indexShard{
		header:    testShardHeader(indexFileBucketShard),
		documents: testShardDocuments(3, "companion", 12, indexDocDerived),
		tombstones: []*indexShardTombstone{
			testShardTombstone(indexEntryTombstone, "gone", 4),
			testShardTombstone(indexEntryRefTombstone, "ref", 9),
			testShardTombstone(indexEntryTombstone, "gone", 5),
		},
	}
	tombstonesOnly := &indexShard{
		header:     testShardHeader(indexFileBucketShard),
		tombstones: []*indexShardTombstone{testShardTombstone(indexEntryTombstone, "gone", 6), testShardTombstone(indexEntryTombstone, "gone", 7)},
	}
	emptyAll := &indexShard{header: testShardHeader(indexFileAllShard)}

	probe, probeKey := testProbeShard()
	builder := indexNewShardBuilder(false)
	replaced, _, err := builder.encodeUnpadded(probe)
	if err != nil {
		t.Fatal(err)
	}
	probeRewrite, _, err := builder.rewriteWithout(probe, func(kind indexEntryKind, key [indexIdByteCount]byte, version uint64) bool {
		return key == probeKey
	}, len(replaced))
	if err != nil {
		t.Fatal(err)
	}
	return []testShardCase{
		{name: "bucket", file: testBuildShard(t, bucket, false, testPadKey(t, 2))},
		{name: "all", file: testBuildShard(t, all, false, testPadKey(t, 3))},
		{name: "companion-bucket", companion: true, file: testBuildShard(t, companion, true, testPadKey(t, 2))},
		{name: "tombstones-only", file: testBuildShard(t, tombstonesOnly, false, testPadKey(t, 2))},
		{name: "empty-all", file: testBuildShard(t, emptyAll, false, testPadKey(t, 2))},
		{name: "probe-rewrite", file: probeRewrite},
	}
}

// A shard's parts, as its layout places them.
func testShardParts(t testing.TB, file []byte, companion bool) *indexShardLayout {
	t.Helper()
	reader, err := indexOpenShard(indexBytesFrames(file), companion)
	if err != nil {
		t.Fatal(err)
	}
	return reader.layout
}

// D-TEST-15: each shard's bytes, and its doc and tombstone tables', the same on every leg, decoding and encoding back
// unchanged.
func TestShardVectors(t *testing.T) {
	cases := testShardCases(t)
	built := []testCodecVector{}
	for _, c := range cases {
		built = append(built, testVectorOf(c.name, c.companion, c.file))
	}
	for _, c := range cases {
		layout := testShardParts(t, c.file, c.companion)
		if c.name == "bucket" || c.name == "companion-bucket" {
			built = append(built,
				testVectorOf(c.name+"-doc-table", c.companion, c.file[layout.docTableStart:layout.tombstonesStart]),
				testVectorOf(c.name+"-tombstone-table", c.companion, c.file[layout.tombstonesStart:layout.dictionaryStart]))
		}
	}
	vectors := testReadVectors(t, testShardVectorPath, built)
	for _, vector := range built {
		if vectors[vector.Name] != vector {
			t.Errorf("%s: its bytes moved", vector.Name)
		}
	}
	for _, c := range cases {
		file, err := hex.DecodeString(vectors[c.name].Hex)
		if err != nil {
			t.Fatal(err)
		}
		shard, err := testDecodeShard(file, c.companion)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		again, err := indexNewShardBuilder(c.companion).encode(shard)
		if err != nil || !bytes.Equal(again, file) {
			t.Errorf("%s re-encoded differently: %v", c.name, err)
		}
	}
}

// Every document and tombstone a shard was built from comes back from its bytes, keys inverted back from the postings.
func TestShardDecodesWhatBuiltIt(t *testing.T) {
	documents := testShardDocuments(4, "round", 50, indexDocFile)
	tombstones := []*indexShardTombstone{testShardTombstone(indexEntryTombstone, "gone", 1)}
	shard := &indexShard{header: testShardHeader(indexFileBucketShard), documents: documents, tombstones: tombstones}
	file := testBuildShard(t, shard, false, testPadKey(t, 4))
	decoded, err := testDecodeShard(file, false)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.header.PadGeneration != 4 || decoded.header.Count != 50 || decoded.header.Tombstones != 1 {
		t.Errorf("header %v", decoded.header)
	}
	sorted := slices.Clone(documents)
	slices.SortFunc(sorted, func(a *indexShardDocument, b *indexShardDocument) int {
		return bytes.Compare(a.key[:], b.key[:])
	})
	if len(decoded.documents) != len(sorted) {
		t.Fatalf("%d documents", len(decoded.documents))
	}
	for docId, document := range decoded.documents {
		want := sorted[docId]
		if document.key != want.key || document.version != want.version || document.timeSeconds != want.timeSeconds ||
			!reflect.DeepEqual(document.keys, want.keys) || !reflect.DeepEqual(testComparableEntry(&indexEntry{row: document.row}), testComparableEntry(&indexEntry{row: want.row})) {
			t.Errorf("docid %d decoded differently", docId)
		}
	}
	if !reflect.DeepEqual(decoded.tombstones, tombstones) {
		t.Errorf("tombstones %v", decoded.tombstones)
	}
}

// A shard's bytes depend on its documents, not on the order they were given in.
func TestShardBytesDependOnlyOnItsInputs(t *testing.T) {
	documents := testShardDocuments(5, "order", 30, indexDocFile)
	tombstones := []*indexShardTombstone{testShardTombstone(indexEntryTombstone, "gone", 1), testShardTombstone(indexEntryTombstone, "gone", 2)}
	first := testBuildShard(t, &indexShard{header: testShardHeader(indexFileBucketShard), documents: documents, tombstones: tombstones}, false, testPadKey(t, 2))
	reversed := slices.Clone(documents)
	slices.Reverse(reversed)
	second := testBuildShard(t, &indexShard{header: testShardHeader(indexFileBucketShard), documents: reversed, tombstones: []*indexShardTombstone{tombstones[1], tombstones[0]}}, false, testPadKey(t, 2))
	if !bytes.Equal(first, second) {
		t.Error("the order documents came in changed the shard")
	}
}

// The reader finds every key's list and every row through the layout opening gives, and finds no key the shard lacks.
func TestReaderFindsEveryKey(t *testing.T) {
	documents := testShardDocuments(6, "reader", 45, indexDocFile)
	shard := &indexShard{header: testShardHeader(indexFileAllShard), documents: documents}
	file := testBuildShard(t, shard, false, testPadKey(t, 2))
	decoded, err := testDecodeShard(file, false)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := indexOpenShard(indexBytesFrames(file), false)
	if err != nil {
		t.Fatal(err)
	}
	if reader.documentCount() != len(documents) {
		t.Fatalf("%d documents", reader.documentCount())
	}
	postings := map[uint32][]uint32{}
	for docId, document := range decoded.documents {
		if reader.layout.trigramCounts[docId] != uint32(len(document.keys)) {
			t.Errorf("docid %d's n_d %d", docId, reader.layout.trigramCounts[docId])
		}
		row, err := reader.document(uint32(docId))
		if err != nil || row.key != document.key {
			t.Errorf("docid %d's row: %v", docId, err)
		}
		for _, key := range document.keys {
			postings[key] = append(postings[key], uint32(docId))
		}
	}
	sawBitset := false
	for key, want := range postings {
		location, ok, err := reader.lookup(key)
		if err != nil || !ok {
			t.Fatalf("key %06x: %v %v", key, ok, err)
		}
		list, err := reader.list(location)
		if err != nil {
			t.Fatal(err)
		}
		sawBitset = sawBitset || list.bitset != nil
		if !slices.Equal(list.all(), want) {
			t.Errorf("key %06x lists %v, want %v", key, list.all(), want)
		}
		for _, docId := range want {
			if !list.contains(docId) {
				t.Errorf("key %06x does not contain %d", key, docId)
			}
		}
	}
	if !sawBitset {
		t.Error("no list took the bitset form")
	}
	for _, key := range []uint32{0, 0x6160FF, 0x616101 + 0x10000, 0x6FFFFF, 0xFFFFFF} {
		if _, ok := postings[key]; ok {
			continue
		}
		if _, ok, err := reader.lookup(key); ok || err != nil {
			t.Errorf("key %06x found: %v", key, err)
		}
	}
}

// §11.14's postings row: a bitset only when it is strictly shorter, gaps on a tie, and a bitset's spare bits zero.
func TestShorterListRule(t *testing.T) {
	cases := []struct {
		docIds        []uint32
		documentCount int
		bitset        bool
	}{
		{docIds: []uint32{0, 1, 2, 3, 4, 5, 6, 7}, documentCount: 8, bitset: true},
		// One byte either way: a tie, so gaps.
		{docIds: []uint32{3}, documentCount: 8, bitset: false},
		// Five one-byte gaps against a five-byte bitset.
		{docIds: []uint32{0, 1, 2, 3, 4}, documentCount: 40, bitset: false},
		{docIds: []uint32{0, 1, 2, 3, 4, 5}, documentCount: 40, bitset: true},
		{docIds: []uint32{200}, documentCount: 201, bitset: false},
	}
	for _, c := range cases {
		encoded, bitset := indexAppendList(nil, c.docIds, c.documentCount)
		if bitset != c.bitset {
			t.Errorf("%v of %d took bitset %t", c.docIds, c.documentCount, bitset)
		}
		list, err := indexDecodeList(encoded, bitset, uint64(len(c.docIds)), c.documentCount)
		if err != nil || !slices.Equal(list.all(), c.docIds) {
			t.Errorf("%v of %d read back %v: %v", c.docIds, c.documentCount, list, err)
		}
		// The other form of the same docids is refused.
		other := []byte{}
		if bitset {
			last := -1
			for _, docId := range c.docIds {
				other = indexAppendVByte(other, uint64(int(docId)-last))
				last = int(docId)
			}
		} else {
			other = make([]byte, indexBitsetByteCount(c.documentCount))
			for _, docId := range c.docIds {
				other[docId/8] |= 1 << (docId % 8)
			}
		}
		if _, err := indexDecodeList(other, !bitset, uint64(len(c.docIds)), c.documentCount); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%v of %d in its other form: %v", c.docIds, c.documentCount, err)
		}
	}
	if _, err := indexDecodeList([]byte{0xFF, 0xFF, 0x03}, true, 18, 17); !errors.Is(err, errIndexMalformed) {
		t.Errorf("a spare bit set: %v", err)
	}
}

// A shard assembled from parts written by hand, its header's counts and body length filled from them unless the case
// says otherwise, under a true hash.
type testRawShard struct {
	header     *protocol.IndexFileHeader
	docs       [][]byte
	tombstones [][]byte
	dictionary []byte
	postings   []byte
	pad        []byte
	// When set, the header keeps the counts and body length it was given.
	keepHeader bool
}

func (self *testRawShard) assemble(t testing.TB) []byte {
	body := []byte{}
	for _, doc := range self.docs {
		body = append(body, doc...)
	}
	for _, tombstone := range self.tombstones {
		body = append(body, tombstone...)
	}
	body = append(body, self.dictionary...)
	body = append(body, self.postings...)
	header := proto.CloneOf(self.header)
	if !self.keepHeader {
		header.Count = uint32(len(self.docs))
		header.Tombstones = uint32(len(self.tombstones))
		header.BodyLength = uint32(len(body))
	}
	return testRawFile(t, header, body, self.pad)
}

// A tombstone by hand.
func testRawTombstone(kind byte, label string, index int) []byte {
	key := testIndexId(label, index)
	return append(append([]byte{kind}, key[:]...), 1, 1)
}

// One key entry by hand.
func testRawKeyEntry(flag byte, other []byte, documentCount uint64, listByteCount uint64) []byte {
	entry := append([]byte{flag}, other...)
	entry = indexAppendVByte(entry, documentCount)
	return indexAppendVByte(entry, listByteCount)
}

// A dictionary by hand: the block index's entries as given, then the key entries.
func testRawDictionary(blocks []indexDictionaryBlock, entries ...[]byte) []byte {
	dictionary := indexAppendVByte(nil, uint64(len(blocks)))
	for _, block := range blocks {
		keyBytes := indexTrigramBytes(block.firstKey)
		dictionary = append(dictionary, keyBytes[:]...)
		dictionary = indexAppendVByte(dictionary, block.entriesOffset)
		dictionary = indexAppendVByte(dictionary, block.listOffset)
	}
	for _, entry := range entries {
		dictionary = append(dictionary, entry...)
	}
	return dictionary
}

// A shard of twenty documents written byte by byte: key 0x616263 in docids 0-9 as a bitset, 0x616264 in docid 0 and
// 0x626364 in docid 19 as one gap each, one block. The cases below each break one thing about it.
func testTinyShard() *testRawShard {
	trigramCounts := make([]uint64, 20)
	trigramCounts[0] = 2
	for docId := 1; docId < 10; docId += 1 {
		trigramCounts[docId] = 1
	}
	trigramCounts[19] = 1
	return &testRawShard{
		header: testShardHeader(indexFileBucketShard),
		docs:   testTinyDocuments(trigramCounts),
		dictionary: testRawDictionary([]indexDictionaryBlock{{firstKey: 0x616263}},
			testRawKeyEntry(indexKeyEntryBitset, []byte{0x61, 0x62, 0x63}, 10, 3),
			testRawKeyEntry(2, []byte{0x64}, 1, 1),
			testRawKeyEntry(0, []byte{0x62, 0x63, 0x64}, 1, 1)),
		postings: []byte{0xFF, 0x03, 0x00, 0x01, 0x14},
	}
}

// Twenty hand-built documents in docid order with these trigram counts.
func testTinyDocuments(trigramCounts []uint64) [][]byte {
	keys := [][indexIdByteCount]byte{}
	for index := range trigramCounts {
		keys = append(keys, testIndexId("tiny", index))
	}
	slices.SortFunc(keys, func(a [indexIdByteCount]byte, b [indexIdByteCount]byte) int {
		return bytes.Compare(a[:], b[:])
	})
	docs := [][]byte{}
	for docId, key := range keys {
		entry := append([]byte{}, key[:]...)
		entry = append(entry, 1)
		entry = indexAppendVByte(entry, 1800000000)
		row := []byte{byte(indexDocFile), 0, 10, 0}
		row = indexAppendVByte(row, trigramCounts[docId])
		row = append(row, 0, 0, 1, 'f', 0, 0, 0, 0)
		docs = append(docs, append(entry, row...))
	}
	return docs
}

// The hand-built shard is what the builder writes for the same documents, so the two readings of the format agree.
func TestTinyShardIsTheBuildersShard(t *testing.T) {
	file := testTinyShard().assemble(t)
	shard, err := testDecodeShard(file, false)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint32][]uint32{0x616263: {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, 0x616264: {0}, 0x626364: {19}}
	for key, docIds := range want {
		for _, docId := range docIds {
			if !slices.Contains(shard.documents[docId].keys, key) {
				t.Errorf("docid %d lacks %06x", docId, key)
			}
		}
	}
	unpadded, _, err := indexNewShardBuilder(false).encodeUnpadded(shard)
	if err != nil || !bytes.Equal(unpadded, file) {
		t.Errorf("the builder wrote other bytes: %v", err)
	}
}

// Each a hand-built shard that is close to canonical and is not, refused whole and by the streaming walk alike.
func testBadShards(t testing.TB) map[string][]byte {
	bad := map[string][]byte{}
	add := func(name string, mutate func(raw *testRawShard)) {
		raw := testTinyShard()
		mutate(raw)
		bad[name] = raw.assemble(t)
	}
	add("gaps-where-a-bitset-is-shorter", func(raw *testRawShard) {
		raw.dictionary = testRawDictionary([]indexDictionaryBlock{{firstKey: 0x616263}},
			testRawKeyEntry(0, []byte{0x61, 0x62, 0x63}, 10, 10),
			testRawKeyEntry(2, []byte{0x64}, 1, 1),
			testRawKeyEntry(0, []byte{0x62, 0x63, 0x64}, 1, 1))
		raw.postings = []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0x01, 0x14}
	})
	add("a-bitset-where-gaps-are-shorter", func(raw *testRawShard) {
		raw.dictionary = testRawDictionary([]indexDictionaryBlock{{firstKey: 0x616263}},
			testRawKeyEntry(indexKeyEntryBitset, []byte{0x61, 0x62, 0x63}, 10, 3),
			testRawKeyEntry(2|indexKeyEntryBitset, []byte{0x64}, 1, 3),
			testRawKeyEntry(0, []byte{0x62, 0x63, 0x64}, 1, 1))
		raw.postings = []byte{0xFF, 0x03, 0x00, 0x01, 0x00, 0x00, 0x14}
	})
	add("a-non-minimal-gap", func(raw *testRawShard) {
		raw.dictionary = testRawDictionary([]indexDictionaryBlock{{firstKey: 0x616263}},
			testRawKeyEntry(indexKeyEntryBitset, []byte{0x61, 0x62, 0x63}, 10, 3),
			testRawKeyEntry(2, []byte{0x64}, 1, 2),
			testRawKeyEntry(0, []byte{0x62, 0x63, 0x64}, 1, 1))
		raw.postings = []byte{0xFF, 0x03, 0x00, 0x81, 0x00, 0x14}
	})
	add("a-docid-out-of-range", func(raw *testRawShard) {
		raw.postings = []byte{0xFF, 0x03, 0x00, 0x01, 0x15}
	})
	add("a-bitset-spare-bit", func(raw *testRawShard) {
		raw.postings = []byte{0xFF, 0x03, 0x10, 0x01, 0x14}
	})
	add("a-repeated-docid", func(raw *testRawShard) {
		raw.dictionary = testRawDictionary([]indexDictionaryBlock{{firstKey: 0x616263}},
			testRawKeyEntry(indexKeyEntryBitset, []byte{0x61, 0x62, 0x63}, 10, 3),
			testRawKeyEntry(2, []byte{0x64}, 2, 2),
			testRawKeyEntry(0, []byte{0x62, 0x63, 0x64}, 1, 1))
		raw.postings = []byte{0xFF, 0x03, 0x00, 0x01, 0x00, 0x14}
	})
	add("documents-out-of-order", func(raw *testRawShard) {
		raw.docs[3], raw.docs[4] = raw.docs[4], raw.docs[3]
	})
	add("a-repeated-document", func(raw *testRawShard) {
		raw.docs[12] = raw.docs[11]
	})
	add("keys-out-of-order", func(raw *testRawShard) {
		raw.dictionary = testRawDictionary([]indexDictionaryBlock{{firstKey: 0x616263}},
			testRawKeyEntry(indexKeyEntryBitset, []byte{0x61, 0x62, 0x63}, 10, 3),
			testRawKeyEntry(0, []byte{0x62, 0x63, 0x64}, 1, 1),
			testRawKeyEntry(0, []byte{0x61, 0x62, 0x64}, 1, 1))
		raw.postings = []byte{0xFF, 0x03, 0x00, 0x14, 0x01}
	})
	add("a-repeated-key", func(raw *testRawShard) {
		raw.dictionary = testRawDictionary([]indexDictionaryBlock{{firstKey: 0x616263}},
			testRawKeyEntry(indexKeyEntryBitset, []byte{0x61, 0x62, 0x63}, 10, 3),
			testRawKeyEntry(3, []byte{}, 1, 1),
			testRawKeyEntry(0, []byte{0x62, 0x63, 0x64}, 1, 1))
	})
	add("a-prefix-not-the-longest", func(raw *testRawShard) {
		raw.dictionary = testRawDictionary([]indexDictionaryBlock{{firstKey: 0x616263}},
			testRawKeyEntry(indexKeyEntryBitset, []byte{0x61, 0x62, 0x63}, 10, 3),
			testRawKeyEntry(1, []byte{0x62, 0x64}, 1, 1),
			testRawKeyEntry(0, []byte{0x62, 0x63, 0x64}, 1, 1))
	})
	add("a-first-key-sharing-a-prefix", func(raw *testRawShard) {
		raw.dictionary = testRawDictionary([]indexDictionaryBlock{{firstKey: 0x616263}, {firstKey: 0x616264, entriesOffset: 6, listOffset: 3}},
			testRawKeyEntry(indexKeyEntryBitset, []byte{0x61, 0x62, 0x63}, 10, 3),
			testRawKeyEntry(2, []byte{0x64}, 1, 1),
			testRawKeyEntry(0, []byte{0x62, 0x63, 0x64}, 1, 1))
	})
	add("a-block-index-first-key-off", func(raw *testRawShard) {
		raw.dictionary = testRawDictionary([]indexDictionaryBlock{{firstKey: 0x616262}},
			testRawKeyEntry(indexKeyEntryBitset, []byte{0x61, 0x62, 0x63}, 10, 3),
			testRawKeyEntry(2, []byte{0x64}, 1, 1),
			testRawKeyEntry(0, []byte{0x62, 0x63, 0x64}, 1, 1))
	})
	add("a-list-offset-off", func(raw *testRawShard) {
		raw.dictionary = testRawDictionary([]indexDictionaryBlock{{firstKey: 0x616263}, {firstKey: 0x626364, entriesOffset: 10, listOffset: 5}},
			testRawKeyEntry(indexKeyEntryBitset, []byte{0x61, 0x62, 0x63}, 10, 3),
			testRawKeyEntry(2, []byte{0x64}, 1, 1),
			testRawKeyEntry(0, []byte{0x62, 0x63, 0x64}, 1, 1))
	})
	add("a-flag-spare-bit", func(raw *testRawShard) {
		raw.dictionary = testRawDictionary([]indexDictionaryBlock{{firstKey: 0x616263}},
			testRawKeyEntry(indexKeyEntryBitset|0x08, []byte{0x61, 0x62, 0x63}, 10, 3),
			testRawKeyEntry(2, []byte{0x64}, 1, 1),
			testRawKeyEntry(0, []byte{0x62, 0x63, 0x64}, 1, 1))
	})
	add("a-trigram-count-off-its-lists", func(raw *testRawShard) {
		trigramCounts := make([]uint64, 20)
		trigramCounts[0] = 2
		for docId := 1; docId < 10; docId += 1 {
			trigramCounts[docId] = 1
		}
		trigramCounts[19] = 2
		raw.docs = testTinyDocuments(trigramCounts)
	})
	add("a-key-in-both-tables", func(raw *testRawShard) {
		raw.tombstones = [][]byte{testRawTombstone(3, "tiny", 0)}
	})
	add("a-ref-tombstone-outside-ur-index", func(raw *testRawShard) {
		raw.tombstones = [][]byte{testRawTombstone(4, "ref", 1)}
	})
	add("tombstones-out-of-order", func(raw *testRawShard) {
		a, b := testRawTombstone(3, "gone", 1), testRawTombstone(3, "gone", 2)
		if bytes.Compare(a[1:17], b[1:17]) < 0 {
			a, b = b, a
		}
		raw.tombstones = [][]byte{a, b}
	})
	add("a-tombstone-in-an-all-shard", func(raw *testRawShard) {
		raw.header = testShardHeader(indexFileAllShard)
		raw.tombstones = [][]byte{testRawTombstone(3, "gone", 1)}
	})
	add("a-pad-byte-not-zero", func(raw *testRawShard) {
		raw.pad = []byte{0, 0, 7}
	})
	add("bytes-past-the-last-list", func(raw *testRawShard) {
		raw.postings = append(raw.postings, 0x01)
	})
	add("a-writer-on-a-shard", func(raw *testRawShard) {
		raw.header.WriterSidecarId = testIndexIdBytes("writer", 1)
	})
	add("no-pad-generation", func(raw *testRawShard) {
		raw.header.PadGeneration = 0
	})
	add("a-count-past-its-input", func(raw *testRawShard) {
		raw.keepHeader = true
		raw.header.Count = 1000000
		raw.header.BodyLength = 600
	})
	add("a-body-past-the-cap", func(raw *testRawShard) {
		raw.keepHeader = true
		raw.header.Count = 20
		raw.header.BodyLength = indexShardMaxByteCount + 1
		raw.pad = make([]byte, indexShardMaxByteCount)
	})
	add("a-file-past-1-MiB", func(raw *testRawShard) {
		raw.pad = make([]byte, indexShardPaddedMaxByteCount)
	})
	sixtyFive := [][]byte{}
	for index := range 65 {
		flag := byte(2)
		other := []byte{byte(index)}
		if index == 0 {
			flag, other = 0, []byte{0x61, 0x61, 0x00}
		}
		sixtyFive = append(sixtyFive, testRawKeyEntry(flag, other, 1, 1))
	}
	add("a-block-of-65-keys", func(raw *testRawShard) {
		trigramCounts := make([]uint64, 20)
		trigramCounts[0] = 65
		raw.docs = testTinyDocuments(trigramCounts)
		raw.dictionary = testRawDictionary([]indexDictionaryBlock{{firstKey: 0x616100}}, sixtyFive...)
		raw.postings = bytes.Repeat([]byte{0x01}, 65)
	})
	return bad
}

func TestShardRefusals(t *testing.T) {
	for name, file := range testBadShards(t) {
		if _, err := testDecodeShard(file, false); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%s decoded: %v", name, err)
		}
		reader, err := indexOpenShard(indexBytesFrames(file), false)
		if err == nil {
			err = reader.walk(indexShardVisitor{})
		}
		if !errors.Is(err, errIndexMalformed) {
			t.Errorf("%s passed the walk: %v", name, err)
		}
	}
}

// A shard built under ur/index takes a ref tombstone and rows with their ref_id; read as a file-mode ref's, it is
// refused, and the reverse too.
func TestShardRootDecidesItsRows(t *testing.T) {
	for _, c := range testShardCases(t) {
		if c.name != "companion-bucket" && c.name != "bucket" {
			continue
		}
		if _, err := testDecodeShard(c.file, !c.companion); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%s read under the other root: %v", c.name, err)
		}
	}
}

// A shard of a newer format is left unread, which search reports as status update, not as a malformation.
func TestShardOfANewerFormatIsUnread(t *testing.T) {
	raw := testTinyShard()
	raw.header.Format = 2
	if _, err := testDecodeShard(raw.assemble(t), false); !errors.Is(err, errIndexNewerFormat) {
		t.Errorf("a format-2 shard: %v", err)
	}
}

// Tampering is caught by the plaintext hash before any parser runs.
func TestShardTamperingFailsTheHash(t *testing.T) {
	file := testShardCases(t)[0].file
	sum := sha256.Sum256(file)
	tampered := bytes.Clone(file)
	tampered[len(tampered)/2] ^= 1
	if _, err := indexDecodeShard(tampered, sum[:], false); err == nil || !errors.Is(err, errIndexMalformed) {
		t.Errorf("a tampered shard: %v", err)
	}
}

// The builder refuses what a shard may not hold.
func TestShardBuilderRefuses(t *testing.T) {
	documents := testShardDocuments(7, "refuse", 4, indexDocFile)
	builder := indexNewShardBuilder(false)
	cases := map[string]*indexShard{
		"a document twice": {header: testShardHeader(indexFileBucketShard), documents: []*indexShardDocument{documents[0], documents[0]}},
		"a count off its keys": {header: testShardHeader(indexFileBucketShard), documents: []*indexShardDocument{
			{key: documents[0].key, row: testFileRow(indexKeySet{1}), keys: indexKeySet{1, 2}},
		}},
		"a key in both tables": {header: testShardHeader(indexFileBucketShard), documents: documents[:1], tombstones: []*indexShardTombstone{
			{kind: indexEntryTombstone, key: documents[0].key, version: 1},
		}},
		"a tombstone in an all shard":      {header: testShardHeader(indexFileAllShard), tombstones: []*indexShardTombstone{testShardTombstone(indexEntryTombstone, "gone", 1)}},
		"a ref tombstone outside ur/index": {header: testShardHeader(indexFileBucketShard), tombstones: []*indexShardTombstone{testShardTombstone(indexEntryRefTombstone, "ref", 1)}},
		"a key under both tombstone kinds": {header: testShardHeader(indexFileBucketShard), tombstones: []*indexShardTombstone{
			testShardTombstone(indexEntryTombstone, "gone", 1), {kind: indexEntryRefTombstone, key: testIndexId("gone", 1)},
		}},
		"a slot's header": {header: testSlotHeader(indexFileSlot), documents: documents},
	}
	for name, shard := range cases {
		companion := name == "a key under both tombstone kinds"
		if _, err := indexNewShardBuilder(companion).build(shard, testPadKey(t, 2)); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%s built: %v", name, err)
		}
	}
	if _, err := builder.build(&indexShard{header: testShardHeader(indexFileBucketShard)}, nil); !errors.Is(err, errIndexMalformed) {
		t.Errorf("a shard without its pad key: %v", err)
	}
}

// §11.14's pad row: Padmé's step at the shard's length, 16 KiB near the cap, the count below it and drawn from
// K_index_g, which the header names.
func TestKeyedPadIsBelowPadmesStep(t *testing.T) {
	for length := 4; length < 2*1024*1024; length = length*3/2 + 1 {
		step := indexPadStep(length)
		padded := EvsPadme(uint64(length))
		if padded%uint64(step) != 0 || uint64(step) <= padded-uint64(length) {
			t.Errorf("step %d at %d, where Padmé gives %d", step, length, padded)
		}
	}
	if step := indexPadStep(indexShardMaxByteCount); step != 16*1024 || indexShardMaxByteCount+step != indexShardPaddedMaxByteCount {
		t.Errorf("the step at the cap is %d", step)
	}
	shard := &indexShard{header: testShardHeader(indexFileBucketShard), documents: testShardDocuments(8, "pad", 20, indexDocFile)}
	named := testShardHeader(indexFileBucketShard)
	named.PadGeneration = 5
	unpadded, _, err := indexNewShardBuilder(false).encodeUnpadded(&indexShard{header: named, documents: shard.documents})
	if err != nil {
		t.Fatal(err)
	}
	file := testBuildShard(t, shard, false, testPadKey(t, 5))
	if !bytes.Equal(file[:len(unpadded)], unpadded) {
		t.Fatal("the pad's header did not name generation 5")
	}
	pad := len(file) - len(unpadded)
	if pad != testPadKey(t, 5).padByteCount(unpadded) || indexPadStep(len(unpadded)) <= pad {
		t.Errorf("a pad of %d at step %d", pad, indexPadStep(len(unpadded)))
	}
	// Another generation's key draws another pad for the same body, so the count is keyed, not a function of the
	// bytes alone.
	pads := map[int]bool{}
	for generation := uint64(1); generation <= 8; generation += 1 {
		pads[(&indexPadKey{generation: generation, key: testPadKey(t, generation).key}).padByteCount(unpadded)] = true
	}
	if len(pads) < 2 {
		t.Error("every key drew the same pad")
	}
}

// A frame source that writes each frame into the buffer it is given, poisoning the rest, and records which buffers
// it was handed: a reader holding two frames would need two.
type testOneFrameSource struct {
	file    []byte
	buffers map[*byte]bool
	frames  []int
}

func (self *testOneFrameSource) indexLength() int {
	return len(self.file)
}

func (self *testOneFrameSource) indexReadFrame(index int, dst []byte) ([]byte, error) {
	self.buffers[&dst[0]] = true
	self.frames = append(self.frames, index)
	for position := range dst {
		dst[position] = 0xEE
	}
	start := index * EvsRecordFrameByteCount
	frame := self.file[start:min(len(self.file), start+EvsRecordFrameByteCount)]
	return dst[:copy(dst, frame)], nil
}

// §11.14's plan row: a list that spans a frame boundary reads whole through one frame at a time.
func TestListAcrossAFrameBoundaryWithOneFrame(t *testing.T) {
	random := rand.New(rand.NewSource(10))
	documents := []*indexShardDocument{}
	for index := range 2400 {
		documents = append(documents, testShardDocument("frames", index, indexDocFile, testRandomKeys(random, 200, 0x616100, 400)))
	}
	file := testBuildShard(t, &indexShard{header: testShardHeader(indexFileAllShard), documents: documents}, false, testPadKey(t, 2))
	if len(file) < 2*EvsRecordFrameByteCount {
		t.Fatalf("a shard of %d B crosses too few frames", len(file))
	}
	decoded, err := testDecodeShard(file, false)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := indexOpenShard(indexBytesFrames(file), false)
	if err != nil {
		t.Fatal(err)
	}
	// Every key whose list straddles a frame boundary, with its docids.
	straddling := map[uint32][]uint32{}
	err = reader.walk(indexShardVisitor{key: func(blockIndex int, key indexDictionaryKey, list *indexPostingList) error {
		straddling[key.key] = list.all()
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for key, docIds := range straddling {
		location, ok, err := reader.lookup(key)
		if err != nil || !ok {
			t.Fatal(err)
		}
		end := location.listPosition + int(location.key.listByteCount)
		if location.listPosition/EvsRecordFrameByteCount == (end-1)/EvsRecordFrameByteCount {
			continue
		}
		found += 1
		source := &testOneFrameSource{file: file, buffers: map[*byte]bool{}}
		oneFrame, err := indexOpenShard(source, false)
		if err != nil {
			t.Fatal(err)
		}
		source.buffers = map[*byte]bool{}
		source.frames = nil
		location, ok, err = oneFrame.lookup(key)
		if err != nil || !ok {
			t.Fatal(err)
		}
		list, err := oneFrame.list(location)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(list.all(), docIds) {
			t.Errorf("key %06x read across frames as %v", key, list.all())
		}
		if len(source.buffers) != 1 {
			t.Errorf("key %06x took %d frame buffers", key, len(source.buffers))
		}
		for _, docId := range docIds {
			if !slices.Contains(decoded.documents[docId].keys, key) {
				t.Errorf("docid %d lacks %06x", docId, key)
			}
		}
	}
	if found == 0 {
		t.Fatal("no list straddles a frame boundary")
	}
}

// plan-SEARCH-shrink-claim's probe: rebuilt by 64 without its probe, the shard grows, as the question's model found,
// so the rewrite keeps the replaced partition, which fits.
func TestRewriteWithoutTheProbeKeepsThePartition(t *testing.T) {
	probe, probeKey := testProbeShard()
	builder := indexNewShardBuilder(false)
	replaced, replacedKeys, err := builder.encodeUnpadded(probe)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, err := builder.encodeUnpadded(&indexShard{header: probe.header, documents: probe.documents[1:]})
	if err != nil {
		t.Fatal(err)
	}
	if len(canonical) <= len(replaced) {
		t.Fatalf("by 64 the shard went from %d to %d B, which needs no partition kept", len(replaced), len(canonical))
	}
	rewrite, rewritten, err := builder.rewriteWithout(probe, func(kind indexEntryKind, key [indexIdByteCount]byte, version uint64) bool {
		return key == probeKey
	}, len(replaced))
	if err != nil {
		t.Fatal(err)
	}
	if len(rewrite) != len(replaced) || rewritten.header.PadGeneration != probe.header.PadGeneration {
		t.Errorf("a rewrite of %d B for %d", len(rewrite), len(replaced))
	}
	wantPartition := []int{indexBlockMaxKeyCount - 1}
	for range len(replacedKeys)/indexBlockMaxKeyCount - 1 {
		wantPartition = append(wantPartition, indexBlockMaxKeyCount)
	}
	decoded, err := testDecodeShard(rewrite, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(decoded.blockKeyCounts, wantPartition) || len(decoded.documents) != 1 || decoded.documents[0].key == probeKey {
		t.Errorf("the rewrite holds %d documents in blocks %v", len(decoded.documents), decoded.blockKeyCounts[:4])
	}
}

// A rewrite that cannot fit its replaced length fails closed, writing nothing.
func TestRewritePastItsReplacedLengthFailsClosed(t *testing.T) {
	shard := &indexShard{header: testShardHeader(indexFileBucketShard), documents: testShardDocuments(11, "closed", 10, indexDocFile)}
	builder := indexNewShardBuilder(false)
	unpadded, _, err := builder.encodeUnpadded(shard)
	if err != nil {
		t.Fatal(err)
	}
	keep := func(kind indexEntryKind, key [indexIdByteCount]byte, version uint64) bool {
		return false
	}
	if file, _, err := builder.rewriteWithout(shard, keep, len(unpadded)-1); err == nil || file != nil {
		t.Errorf("a rewrite one byte short of its body wrote %d B: %v", len(file), err)
	}
	if file, err := indexPadToExactly(unpadded, len(unpadded)-1); err == nil || file != nil {
		t.Errorf("a pad to a shorter length: %v", err)
	}
	if file, err := indexPadToExactly(unpadded, len(unpadded)+5); err != nil || len(file) != len(unpadded)+5 {
		t.Errorf("a pad of five: %v", err)
	}
}

// plan-SEARCH-shrink-claim's property on random shards: a rewrite without any documents and tombstones is exactly its
// replaced length, decodes to what survived, keeps its pad's generation, and keeps the replaced partition only when
// blocks of 64 would not fit.
func TestRewriteWithoutOnRandomShards(t *testing.T) {
	for seed := int64(1); seed <= 40; seed += 1 {
		random := rand.New(rand.NewSource(seed))
		documents := []*indexShardDocument{}
		for index := range 1 + random.Intn(60) {
			documents = append(documents, testShardDocument("random", int(seed)*1000+index, indexDocFile, testRandomKeys(random, random.Intn(300), random.Intn(1<<20), 1+random.Intn(5000))))
		}
		tombstones := []*indexShardTombstone{}
		for index := range random.Intn(5) {
			tombstones = append(tombstones, testShardTombstone(indexEntryTombstone, "random gone", int(seed)*1000+index))
		}
		file := testBuildShard(t, &indexShard{header: testShardHeader(indexFileBucketShard), documents: documents, tombstones: tombstones}, false, testPadKey(t, uint64(1+seed%3)))
		shard, err := testDecodeShard(file, false)
		if err != nil {
			t.Fatal(err)
		}
		// Rewrites chain, as successive erasures in one shard do.
		for round := range 3 {
			dropped := map[[indexIdByteCount]byte]bool{}
			for _, document := range shard.documents {
				if random.Intn(4) == 0 {
					dropped[document.key] = true
				}
			}
			for _, tombstone := range shard.tombstones {
				if random.Intn(2) == 0 {
					dropped[tombstone.key] = true
				}
			}
			builder := indexNewShardBuilder(false)
			rewrite, _, err := builder.rewriteWithout(shard, func(kind indexEntryKind, key [indexIdByteCount]byte, version uint64) bool {
				return dropped[key]
			}, len(file))
			if err != nil {
				t.Fatalf("seed %d round %d: %v", seed, round, err)
			}
			if len(rewrite) != len(file) {
				t.Fatalf("seed %d round %d: %d B for %d", seed, round, len(rewrite), len(file))
			}
			rewritten, err := testDecodeShard(rewrite, false)
			if err != nil {
				t.Fatalf("seed %d round %d: %v", seed, round, err)
			}
			survivors := 0
			for _, document := range shard.documents {
				if !dropped[document.key] {
					want := document
					got := rewritten.documents[survivors]
					if got.key != want.key || !slices.Equal(got.keys, want.keys) {
						t.Fatalf("seed %d round %d: docid %d differs", seed, round, survivors)
					}
					survivors += 1
				}
			}
			if survivors != len(rewritten.documents) || rewritten.header.PadGeneration != shard.header.PadGeneration {
				t.Fatalf("seed %d round %d: %d documents", seed, round, len(rewritten.documents))
			}
			canonical, _, err := builder.encodeUnpadded(&indexShard{header: rewritten.header, documents: rewritten.documents, tombstones: rewritten.tombstones})
			if err != nil {
				t.Fatal(err)
			}
			keptPartition := len(file) < len(canonical)
			keyCount := 0
			for _, count := range rewritten.blockKeyCounts {
				keyCount += count
			}
			partition64, _ := indexBlockPartition(keyCount, nil)
			if !keptPartition && !slices.Equal(partition64, rewritten.blockKeyCounts) {
				t.Errorf("seed %d round %d: blocks of 64 fit and were not kept", seed, round)
			}
			shard, file = rewritten, rewrite
		}
	}
}

// §11.14's paths row with search-format-all-directory-names's k: every kind spelled and read back.
func TestIndexPathSpellings(t *testing.T) {
	writer := testIndexId("writer", 1)
	writerHex := hex.EncodeToString(writer[:])
	fileMode := indexNewPaths(false, 1)
	companion := indexNewPaths(true, 1)
	slot, err := fileMode.slot(20340, writer, 15)
	if err != nil {
		t.Fatal(err)
	}
	large, err := fileMode.largeEntry(20340, writer, 7)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path      string
		companion bool
		kind      indexPathKind
	}{
		{path: fileMode.settings(), kind: indexPathSettings},
		{path: companion.settings(), companion: true, kind: indexPathSettings},
		{path: fileMode.lock(), kind: indexPathLock},
		{path: fileMode.allManifest(), kind: indexPathAllManifest},
		{path: fileMode.allShard(0), kind: indexPathAllShard},
		{path: fileMode.allShard(3498), kind: indexPathAllShard},
		{path: fileMode.allShard(3499), kind: indexPathAllShard},
		{path: fileMode.allShard(4498), kind: indexPathAllShard},
		{path: fileMode.allShard(4499), kind: indexPathAllShard},
		{path: fileMode.bucketManifest(20340), kind: indexPathBucketManifest},
		{path: fileMode.bucketShard(20340, 12), kind: indexPathBucketShard},
		{path: slot, kind: indexPathSlot},
		{path: large, kind: indexPathLargeEntry},
		{path: indexErasureSetPath(false), kind: indexPathErasureSet},
		{path: indexErasureSetPath(true), companion: true, kind: indexPathErasureSet},
		{path: indexNewPaths(true, 2).allShard(5), companion: true, kind: indexPathAllShard},
	}
	want := []string{
		".ur-index/i1/settings", "i1/settings", ".ur-index/i1/lock", ".ur-index/i1/a/m", ".ur-index/i1/a/0",
		".ur-index/i1/a/3498", ".ur-index/i1/a/3499/3499", ".ur-index/i1/a/3499/4498", ".ur-index/i1/a/3500/4499",
		".ur-index/i1/b/20340/m", ".ur-index/i1/b/20340/s/12",
		".ur-index/i1/b/20340/w/" + writerHex[:2] + "/" + writerHex + "/15",
		".ur-index/i1/b/20340/w/" + writerHex[:2] + "/" + writerHex + "/L7",
		".ur-index/x", "x", "i2/a/5",
	}
	for index, c := range cases {
		if c.path != want[index] {
			t.Errorf("spelled %q, want %q", c.path, want[index])
		}
		parsed, ok := indexParsePath(c.path, c.companion)
		if !ok || parsed.kind != c.kind || parsed.String() != c.path {
			t.Errorf("%q parsed as %+v", c.path, parsed)
		}
	}
	if _, err := fileMode.slot(20340, writer, 16); err == nil {
		t.Error("a 17th slot")
	}
	if _, err := fileMode.largeEntry(20340, writer, 0); err == nil {
		t.Error("a large entry of seq 0")
	}
}

// Only the canonical spelling parses, and nothing under a root that is none of §11.14's files (FI-17).
func TestIndexPathRefusals(t *testing.T) {
	writer := testIndexId("writer", 1)
	writerHex := hex.EncodeToString(writer[:])
	upper := []byte(writerHex)
	for index, c := range upper {
		if 'a' <= c && c <= 'f' {
			upper[index] = c - 'a' + 'A'
		}
	}
	for _, path := range []string{
		".ur-index/i1/a/03", ".ur-index/i1/a/3499", ".ur-index/i1/a/0/3499", ".ur-index/i1/a/3499/4499",
		".ur-index/i1/a/3499/3498", ".ur-index/i1/b/020340/m", ".ur-index/i1/b/20340/s/x",
		".ur-index/i1/b/20340/w/" + string(upper[:2]) + "/" + string(upper) + "/1",
		".ur-index/i1/b/20340/w/00/" + writerHex + "/1",
		".ur-index/i1/b/20340/w/" + writerHex[:2] + "/" + writerHex + "/16",
		".ur-index/i1/b/20340/w/" + writerHex[:2] + "/" + writerHex + "/L0",
		".ur-index/i1/b/20340/w/" + writerHex[:2] + "/" + writerHex + "/L01",
		".ur-index/i0/settings", ".ur-index/i01/settings", ".ur-index/i1/other", ".ur-index/i1", ".ur-index/i1/a",
		"i1/settings", "x", ".ur-index/i1/b/20340", ".ur-index/i1/b/20340/s", ".ur-index/i1/lock/x",
	} {
		if parsed, ok := indexParsePath(path, false); ok {
			t.Errorf("%q parsed as %+v", path, parsed)
		}
	}
	if _, ok := indexParsePath(".ur-index/x", true); ok {
		t.Error("ur/index's erasure set under .ur-index/")
	}
}

// A field the message does not have, appended to its bytes.
func testWithUnknownField(encoded []byte) []byte {
	encoded = protowire.AppendTag(encoded, 99, protowire.VarintType)
	return protowire.AppendVarint(encoded, 1)
}

// The small files: deterministic proto, sorted, and refused when a re-marshal does not reproduce them.
func TestSmallFilesAreCanonical(t *testing.T) {
	writerA, writerB := testIndexIdBytes("writer", 1), testIndexIdBytes("writer", 2)
	if bytes.Compare(writerA, writerB) > 0 {
		writerA, writerB = writerB, writerA
	}
	settings, err := indexEncodeSettings(&protocol.IndexSettings{WindowDays: 90})
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := indexDecodeSettings(settings); err != nil || decoded.WindowDays != 90 || indexWindowDays(decoded) != 90 {
		t.Errorf("settings: %v", err)
	}
	if indexWindowDays(&protocol.IndexSettings{}) != 30 || indexWindowDays(nil) != 30 {
		t.Error("no window is not 30 days")
	}
	manifest := &protocol.IndexManifest{
		StartDay: 20340, Days: 30,
		Shards:   []*protocol.IndexShard{{N: 3, Docs: 10}, {N: 0, Docs: 4}},
		Absorbed: []*protocol.IndexWatermark{{WriterSidecarId: writerB, Seq: 2}, {WriterSidecarId: writerA, Seq: 9}},
	}
	bucketManifest, err := indexEncodeManifest(manifest, false)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := indexDecodeManifest(bucketManifest, false)
	if err != nil || decoded.Shards[0].N != 0 || !bytes.Equal(decoded.Absorbed[0].WriterSidecarId, writerA) {
		t.Errorf("a bucket manifest: %v", err)
	}
	if manifest.Shards[0].N != 3 {
		t.Error("encoding sorted its caller's manifest")
	}
	erasureSet, err := indexEncodeErasureSet(&protocol.IndexErasureSet{ListedSince: 4, Erasures: []*protocol.IndexErasure{
		{ErasureId: writerB, EraserSidecarId: writerA, Epoch: 5, CutMs: 1800000000000, Docs: []*protocol.IndexErased{{DocKey: writerB, Version: 3}, {DocKey: writerA, Version: 1}}},
		{ErasureId: writerA, EraserSidecarId: writerA, Epoch: 4},
	}}, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := indexDecodeErasureSet(erasureSet, DefaultIndexFormatSettings()); err != nil || !bytes.Equal(decoded.Erasures[0].ErasureId, writerA) || !bytes.Equal(decoded.Erasures[1].Docs[0].DocKey, writerA) {
		t.Errorf("an erasure set: %v", err)
	}
	lock, err := indexEncodeLock(&protocol.IndexLock{HolderSidecarId: writerA, BucketStartDay: 20310, UntilMs: 1800000000000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := indexDecodeLock(lock); err != nil {
		t.Errorf("a held lock: %v", err)
	}
	if free, err := indexEncodeLock(&protocol.IndexLock{}); err != nil || len(free) != 0 {
		t.Errorf("a free lock is %x: %v", free, err)
	}

	raw := func(message proto.Message) []byte {
		encoded, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	reordered := protowire.AppendTag(nil, 2, protowire.VarintType)
	reordered = protowire.AppendVarint(reordered, 30)
	reordered = protowire.AppendTag(reordered, 1, protowire.VarintType)
	reordered = protowire.AppendVarint(reordered, 1)
	refused := map[string]func() error{
		"a window of 6 days": func() error {
			_, err := indexDecodeSettings(raw(&protocol.IndexSettings{WindowDays: 6}))
			return err
		},
		"a window of 366 days": func() error {
			_, err := indexEncodeSettings(&protocol.IndexSettings{WindowDays: 366})
			return err
		},
		"settings with an unknown field": func() error {
			_, err := indexDecodeSettings(testWithUnknownField(settings))
			return err
		},
		"settings out of field order": func() error {
			_, err := indexDecodeSettings(reordered)
			return err
		},
		"a free lock with a time": func() error {
			_, err := indexDecodeLock(raw(&protocol.IndexLock{UntilMs: 5}))
			return err
		},
		"a held lock with no time": func() error {
			_, err := indexDecodeLock(raw(&protocol.IndexLock{HolderSidecarId: writerA}))
			return err
		},
		"a holder of 15 bytes": func() error {
			_, err := indexDecodeLock(raw(&protocol.IndexLock{HolderSidecarId: writerA[:15], UntilMs: 5}))
			return err
		},
		"shards out of order": func() error {
			_, err := indexDecodeManifest(raw(&protocol.IndexManifest{StartDay: 1, Days: 30, Shards: []*protocol.IndexShard{{N: 3}, {N: 0}}}), false)
			return err
		},
		"a shard twice": func() error {
			_, err := indexDecodeManifest(raw(&protocol.IndexManifest{Shards: []*protocol.IndexShard{{N: 3}, {N: 3}}}), true)
			return err
		},
		"a writer absorbed twice": func() error {
			_, err := indexEncodeManifest(&protocol.IndexManifest{StartDay: 1, Days: 30, Absorbed: []*protocol.IndexWatermark{{WriterSidecarId: writerA, Seq: 1}, {WriterSidecarId: writerA, Seq: 2}}}, false)
			return err
		},
		"a bucket with no window": func() error {
			_, err := indexDecodeManifest(raw(&protocol.IndexManifest{StartDay: 1}), false)
			return err
		},
		"all's manifest naming a bucket": func() error {
			_, err := indexDecodeManifest(raw(&protocol.IndexManifest{StartDay: 1, Days: 30}), true)
			return err
		},
		"a shard's days backwards": func() error {
			_, err := indexDecodeManifest(raw(&protocol.IndexManifest{Shards: []*protocol.IndexShard{{N: 1, FirstDay: 9, LastDay: 8}}}), true)
			return err
		},
		"an unknown field in a shard": func() error {
			shard := testWithUnknownField(raw(&protocol.IndexShard{N: 1}))
			encoded := protowire.AppendTag(nil, 3, protowire.BytesType)
			_, err := indexDecodeManifest(protowire.AppendBytes(encoded, shard), true)
			return err
		},
		"erasures out of order": func() error {
			_, err := indexDecodeErasureSet(raw(&protocol.IndexErasureSet{Erasures: []*protocol.IndexErasure{
				{ErasureId: writerB, EraserSidecarId: writerA}, {ErasureId: writerA, EraserSidecarId: writerA},
			}}), DefaultIndexFormatSettings())
			return err
		},
		"erased documents out of order": func() error {
			_, err := indexDecodeErasureSet(raw(&protocol.IndexErasureSet{Erasures: []*protocol.IndexErasure{
				{ErasureId: writerA, EraserSidecarId: writerA, Docs: []*protocol.IndexErased{{DocKey: writerB}, {DocKey: writerA}}},
			}}), DefaultIndexFormatSettings())
			return err
		},
		"an erasure set past 16,208 B": func() error {
			docs := []*protocol.IndexErased{}
			for index := range 1000 {
				docs = append(docs, &protocol.IndexErased{DocKey: testIndexIdBytes("erased", index), Version: 1})
			}
			_, err := indexEncodeErasureSet(&protocol.IndexErasureSet{Erasures: []*protocol.IndexErasure{{ErasureId: writerA, EraserSidecarId: writerA, Docs: docs}}}, DefaultIndexFormatSettings())
			return err
		},
	}
	for name, decode := range refused {
		if err := decode(); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// §11.14's verify row: the hash first, then each kind's format, and the header against its path.
func TestValidateFileByPath(t *testing.T) {
	writer := testIndexId("writer", 1)
	paths := indexNewPaths(false, 1)
	parse := func(path string) indexPath {
		parsed, ok := indexParsePath(path, false)
		if !ok {
			t.Fatalf("%q", path)
		}
		return parsed
	}
	slotPath, _ := paths.slot(20340, writer, 0)
	largePath, _ := paths.largeEntry(20340, writer, 7)
	large := &indexSlot{header: testSlotHeader(indexFileLargeEntry), entries: []*indexEntry{testLargeEntry()}}
	largeFile, err := indexEncodeSlot(large, false, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	slotFile, err := indexEncodeSlot(testSlotOfLength(t, 3000), false, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	bucketShard := testShardCases(t)[0].file
	allShard := testShardCases(t)[1].file
	manifest, err := indexEncodeManifest(&protocol.IndexManifest{StartDay: 20340, Days: 30}, false)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := indexEncodeSettings(&protocol.IndexSettings{Off: true})
	if err != nil {
		t.Fatal(err)
	}
	valid := []struct {
		path string
		file []byte
	}{
		{path: paths.bucketShard(20340, 0), file: bucketShard},
		{path: paths.allShard(4499), file: allShard},
		{path: slotPath, file: slotFile},
		{path: largePath, file: largeFile},
		{path: paths.bucketManifest(20340), file: manifest},
		{path: paths.settings(), file: settings},
		{path: paths.lock(), file: []byte{}},
		{path: indexErasureSetPath(false), file: []byte{}},
	}
	for _, c := range valid {
		sum := sha256.Sum256(c.file)
		if _, err := indexValidateFile(parse(c.path), indexBytesFrames(c.file), sum[:], DefaultIndexFormatSettings()); err != nil {
			t.Errorf("%s: %v", c.path, err)
		}
		if _, err := indexValidateFile(parse(c.path), indexBytesFrames(c.file), make([]byte, sha256.Size), DefaultIndexFormatSettings()); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%s under another hash: %v", c.path, err)
		}
	}
	otherWriter, _ := paths.slot(20340, testIndexId("writer", 2), 0)
	misplaced := []struct {
		path string
		file []byte
	}{
		{path: paths.bucketShard(20341, 0), file: bucketShard},
		{path: paths.allShard(0), file: bucketShard},
		{path: paths.bucketShard(20340, 0), file: allShard},
		{path: slotPath, file: bucketShard},
		{path: otherWriter, file: slotFile},
		{path: largePath, file: slotFile},
		{path: paths.bucketManifest(20341), file: manifest},
		{path: paths.allManifest(), file: manifest},
		{path: paths.lock(), file: settings},
	}
	for _, c := range misplaced {
		sum := sha256.Sum256(c.file)
		if _, err := indexValidateFile(parse(c.path), indexBytesFrames(c.file), sum[:], DefaultIndexFormatSettings()); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%s held another file: %v", c.path, err)
		}
	}
	raw := testTinyShard()
	raw.header.Format = 2
	newer := raw.assemble(t)
	sum := sha256.Sum256(newer)
	if _, err := indexValidateFile(parse(paths.bucketShard(20340, 0)), indexBytesFrames(newer), sum[:], DefaultIndexFormatSettings()); !errors.Is(err, errIndexNewerFormat) {
		t.Errorf("a newer format: %v", err)
	}
	tooLong := make([]byte, DefaultIndexFormatSettings().SlotMaxByteCount+1)
	sum = sha256.Sum256(tooLong)
	if _, err := indexValidateFile(parse(slotPath), indexBytesFrames(tooLong), sum[:], DefaultIndexFormatSettings()); !errors.Is(err, errIndexMalformed) {
		t.Errorf("a slot past its cap: %v", err)
	}
}

// §5.9's derived data: the layout encodes for SearchCache.PutDerived, decodes to itself, and a reader opened on it
// reads every key and row as one that walked the tables did, while a layout of another length is refused.
func TestShardLayoutReopensTheShard(t *testing.T) {
	for _, c := range testShardCases(t) {
		reader, err := indexOpenShard(indexBytesFrames(c.file), c.companion)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := reader.layout.appendEncoded(nil)
		if err != nil {
			t.Fatal(err)
		}
		layout, err := indexDecodeShardLayout(encoded)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !proto.Equal(layout.header, reader.layout.header) {
			t.Errorf("%s: the header changed", c.name)
		}
		layout.header = reader.layout.header
		if !reflect.DeepEqual(layout, reader.layout) {
			t.Errorf("%s: the layout changed", c.name)
		}
		reopened, err := indexOpenShardWithLayout(indexBytesFrames(c.file), c.companion, layout)
		if err != nil {
			t.Fatal(err)
		}
		err = reader.walk(indexShardVisitor{key: func(blockIndex int, key indexDictionaryKey, list *indexPostingList) error {
			location, ok, err := reopened.lookup(key.key)
			if err != nil || !ok {
				t.Fatalf("%s: key %06x: %v", c.name, key.key, err)
			}
			again, err := reopened.list(location)
			if err != nil || !slices.Equal(again.all(), list.all()) {
				t.Errorf("%s: key %06x lists otherwise: %v", c.name, key.key, err)
			}
			return nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := indexOpenShardWithLayout(indexBytesFrames(c.file[:len(c.file)-1]), c.companion, layout); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%s: a layout of another length: %v", c.name, err)
		}
		if _, err := indexDecodeShardLayout(append(encoded, 0)); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%s: bytes past a layout: %v", c.name, err)
		}
	}
}
