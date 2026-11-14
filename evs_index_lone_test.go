//go:build !ios_extension

// D6's shard test (DESIGN-DETAILS 11.2.3 and 11.6; QD-760): skip.json's rows through the index's own lone(d) and
// verdict, the bound against the shard encoder at the widest header, version and time and below it at every other,
// a generated chunk of mixed-script letters skipped through prepare and the one-pass form, in a file and in a
// message's body, beside a chunk of base64 kept, and FuzzIndexLoneShard holding the 33 B margin on any key set and row.

package sidecar

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"math/rand"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/protocol"
)

const testSkipVectorPath = "testdata/index/conformance/skip.json"

// skip.json, as 11.6 has it.
type testSkipVectors struct {
	ShardBody int               `json:"shard_body"`
	ShardLone int               `json:"shard_lone"`
	KeySetMax int               `json:"key_set_max"`
	Rows      []*testSkipVector `json:"rows"`
}

// One row: a key set as runs, a row's length, lone(d) and the verdict.
type testSkipVector struct {
	Name         string        `json:"name"`
	Runs         []testSkipRun `json:"runs"`
	RowByteCount int           `json:"row_byte_count"`
	Lone         int           `json:"lone"`
	Skipped      bool          `json:"skipped"`
}

// first + i x step for i in [0, count).
type testSkipRun struct {
	First int `json:"first"`
	Count int `json:"count"`
	Step  int `json:"step"`
}

func testReadSkipVectors(t testing.TB) *testSkipVectors {
	t.Helper()
	encoded, err := testIndexFiles.ReadFile(testSkipVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testSkipVectors{}
	if err := json.Unmarshal(encoded, vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

// The row's key set, its runs joined, which must ascend.
func (self *testSkipVector) keys(t testing.TB) indexKeySet {
	t.Helper()
	keys := indexKeySet{}
	for _, run := range self.Runs {
		keys = append(keys, testIndexKeys(run.First, run.Count, run.Step)...)
	}
	if err := keys.check(); err != nil {
		t.Fatalf("%s: %v", self.Name, err)
	}
	return keys
}

// A record row of exactly byteCount bytes as its entry encodes it, for a document of keyCount keys: the shortest such
// row, its locator and fields filled in order with ASCII until it reaches byteCount.
func testRowOfByteCount(t testing.TB, keyCount int, byteCount int) *indexRow {
	t.Helper()
	row := &indexRow{docKind: indexDocRecord, trigramCount: uint64(keyCount)}
	remaining := byteCount - row.encodedByteCount()
	fill := func(capByteCount int) string {
		// a value of k bytes adds k to the row below 128 and k + 1 from 128, its length taking two bytes
		extra := min(remaining, capByteCount+1)
		if capByteCount < 128 {
			extra = min(remaining, capByteCount)
		}
		if extra == 128 {
			extra = 127
		}
		remaining -= extra
		if 128 <= extra {
			return string(bytes.Repeat([]byte("r"), extra-1))
		}
		return string(bytes.Repeat([]byte("r"), extra))
	}
	row.locator = fill(indexLocatorMaxByteCount)
	for _, field := range row.docKind.rowFields() {
		row.fields[field] = fill(indexRowFieldCap(field))
	}
	if remaining != 0 || row.encodedByteCount() != byteCount {
		t.Fatalf("no row of %d B for %d keys", byteCount, keyCount)
	}
	if err := row.check(false); err != nil {
		t.Fatal(err)
	}
	return row
}

// A bucket shard's header with every number at its widest, the tables normalizer 1's: 54 B once the encoder sets a
// count of 1 and a body_length of three VByte bytes.
func testWidestShardHeader() *protocol.IndexFileHeader {
	header := indexNewFileHeader(indexFileBucketShard, testHeadTables)
	header.BucketStartDay, header.BucketDays = math.MaxUint32, math.MaxUint32
	header.PadGeneration = math.MaxUint64
	return header
}

// The shard holding one document alone under header, before its pad.
func testLoneShard(t testing.TB, header *protocol.IndexFileHeader, keys indexKeySet, row *indexRow, version uint64, timeSeconds uint64) ([]byte, error) {
	t.Helper()
	document := &indexShardDocument{key: testIndexId("lone", 1), version: version, timeSeconds: timeSeconds, row: row, keys: keys}
	file, _, err := indexNewShardBuilder(row.refId != nil).encodeUnpadded(&indexShard{header: header, documents: []*indexShardDocument{document}})
	return file, err
}

// skip.json's limits are the code's, and every row's lone(d) and verdict are the index's own.
func TestIndexSkipVectors(t *testing.T) {
	settings := DefaultIndexFormatSettings()
	vectors := testReadSkipVectors(t)
	if vectors.ShardBody != indexShardMaxByteCount || vectors.ShardLone != settings.ShardLoneByteCount || vectors.KeySetMax != indexKeySetMaxByteCount {
		t.Fatalf("skip.json's limits %d, %d and %d", vectors.ShardBody, vectors.ShardLone, vectors.KeySetMax)
	}
	if len(vectors.Rows) < 20 {
		t.Fatalf("%d rows", len(vectors.Rows))
	}
	for _, vector := range vectors.Rows {
		keys := vector.keys(t)
		if lone := indexLoneShardByteCount(vector.RowByteCount, keys, settings); lone != vector.Lone {
			t.Errorf("%s: lone %d, held %d", vector.Name, lone, vector.Lone)
		}
		row := testRowOfByteCount(t, len(keys), vector.RowByteCount)
		if skipped := indexDocumentSkipped(keys, row, settings); skipped != vector.Skipped {
			t.Errorf("%s: skipped %v, held %v", vector.Name, skipped, vector.Skipped)
		}
	}
}

// 11.6's bound: a shard holding a kept document alone encodes to lone(d) - 33 at the widest header, version and time,
// the body_length's width aside, and to less under an ordinary header; it is never refused. Held on skip.json's kept
// rows and on generated sets of every shape, dense, sparse and random, under rows from the shortest to 2,048 B.
func TestLoneShardBoundsTheEncoder(t *testing.T) {
	settings := DefaultIndexFormatSettings()
	type loneCase struct {
		name         string
		keys         indexKeySet
		rowByteCount int
	}
	cases := []loneCase{}
	for _, vector := range testReadSkipVectors(t).Rows {
		if !vector.Skipped {
			cases = append(cases, loneCase{name: vector.Name, keys: vector.keys(t), rowByteCount: vector.RowByteCount})
		}
	}
	random := rand.New(rand.NewSource(11))
	for index := range 24 {
		var keys indexKeySet
		switch index % 4 {
		case 0:
			keys = testRandomKeys(random, random.Intn(20000), 0, indexKeyMax+1)
		case 1:
			keys = testRandomKeys(random, random.Intn(20000), random.Intn(0x100000), 0x10000)
		case 2:
			keys = testIndexKeys(random.Intn(0x10000), random.Intn(30000), 1+random.Intn(300))
		default:
			keys = testRandomKeys(random, 60000+random.Intn(60000), 0, indexKeyMax+1)
		}
		minimal := (&indexRow{docKind: indexDocRecord, trigramCount: uint64(len(keys))}).encodedByteCount()
		cases = append(cases, loneCase{name: "generated", keys: keys, rowByteCount: minimal + random.Intn(indexRowMaxByteCount-minimal+1)})
	}
	for _, c := range cases {
		row := testRowOfByteCount(t, len(c.keys), c.rowByteCount)
		lone := indexLoneShardByteCount(c.rowByteCount, c.keys, settings)
		if indexShardMaxByteCount < lone {
			t.Fatalf("%s: a kept case of lone %d", c.name, lone)
		}
		widest, err := testLoneShard(t, testWidestShardHeader(), c.keys, row, math.MaxUint64, math.MaxUint64)
		if err != nil {
			t.Fatalf("%s: a kept document's lone shard refused: %v", c.name, err)
		}
		// the header's length is one VByte byte; at the widest it is 54 B once body_length takes three bytes
		headerByteCount := int(widest[len(indexFileMagic)])
		bodyByteCount := len(widest) - len(indexFileMagic) - 1 - headerByteCount
		if 54 < headerByteCount || (16*1024 <= bodyByteCount && headerByteCount != 54) {
			t.Fatalf("%s: a widest header of %d B over a body of %d B", c.name, headerByteCount, bodyByteCount)
		}
		if got := len(widest) - headerByteCount + 54; got != lone-33 {
			t.Errorf("%s: %d keys under a %d B row encode to %d B at the widest, lone %d", c.name, len(c.keys), c.rowByteCount, got, lone)
		}
		ordinary, err := testLoneShard(t, testShardHeader(indexFileBucketShard), c.keys, row, 7, 1800000000)
		if err != nil || lone-33 <= len(ordinary) {
			t.Errorf("%s: %d B under an ordinary header, lone %d: %v", c.name, len(ordinary), lone, err)
		}
	}
}

// The BMP's letters that UTF-8 writes in two bytes and in three, in code point order: 1,380 and 47,549 under Unicode
// 17.0.0.
func testBmpLetters() ([]rune, []rune) {
	two, three := []rune{}, []rune{}
	for letter := rune(0x80); letter <= 0xFFFF; letter += 1 {
		switch {
		case !unicode.IsLetter(letter):
		case utf8.RuneLen(letter) == 2:
			two = append(two, letter)
		default:
			three = append(three, letter)
		}
	}
	return two, three
}

// At most byteCount bytes of letters drawn by a fixed generator, a two-byte or a three-byte one with equal odds and
// then any of its kind: 11.6's chunk, a text of many scripts with little repeated, whose key set stays within
// KeySetMax and whose lone shard passes ShardBody. At 1 MiB it gives some 327,000 keys, a key set of some 334,000 B
// and a lone(d) of some 1.7 MB, as 11.2.3 measured.
func testMixedScriptLetters(seed int64, byteCount int) []byte {
	two, three := testBmpLetters()
	random := rand.New(rand.NewSource(seed))
	text := make([]byte, 0, byteCount)
	for {
		letters := three
		if random.Intn(2) == 0 {
			letters = two
		}
		letter := letters[random.Intn(len(letters))]
		if byteCount < len(text)+utf8.RuneLen(letter) {
			return text
		}
		text = utf8.AppendRune(text, letter)
	}
}

// The document's key set and its row as prepare builds them, whatever D6 says of them.
func testPreparedParts(t testing.TB, document *IndexDocument) (indexKeySet, *indexRow) {
	t.Helper()
	keys, err := testIndexNormalizer(t).documentKeys(document.textFields())
	if err != nil {
		t.Fatal(err)
	}
	return keys, document.row(len(keys), false, Id{})
}

// 11.6's TestADocumentPastAShardIsSkipped: 1 MiB of mixed-script letters has a key set within KeySetMax and is
// skipped, in a file and in a message's body, through prepare and through the one-pass form; 1 MiB of base64 is kept.
// In a host's local layer a version skipped where its key was indexed before is a tombstone masking that version, and
// one never indexed leaves no live entry.
func TestADocumentPastAShardIsSkipped(t *testing.T) {
	settings := DefaultIndexFormatSettings()
	normalizer := testIndexNormalizer(t)
	letters := testMixedScriptLetters(5, settings.ChunkByteCount)
	path := []byte("notes/noise.txt")

	files, ok := indexExtractFile(path, letters, settings)
	if !ok || len(files) != 1 {
		t.Fatalf("%d documents of a text file", len(files))
	}
	keys, row := testPreparedParts(t, files[0])
	if indexKeySetMaxByteCount < keys.encodedByteCount() || !indexDocumentPastAShard(keys, row, settings) {
		t.Fatalf("%d keys in %d B, lone %d: not the case D6's shard test adds", len(keys), keys.encodedByteCount(), indexLoneShardByteCount(row.encodedByteCount(), keys, settings))
	}
	t.Logf("%d B of letters: %d keys in a %d B key set, lone %d", len(letters), len(keys), keys.encodedByteCount(), indexLoneShardByteCount(row.encodedByteCount(), keys, settings))
	if prepared, err := files[0].prepare(normalizer, false, Id{}, settings); err != nil || !prepared.skipped || prepared.keys != nil || prepared.row != nil {
		t.Fatalf("the file's chunk through prepare: %+v %v", prepared, err)
	}
	streamed, ok := testIndexStreamFile(t, path, letters, settings)
	if !ok || len(streamed) != 1 || !streamed[0].skipped || streamed[0].keys != nil || streamed[0].row != nil {
		t.Fatalf("the file's chunk through the one-pass form: %+v", streamed)
	}

	message := append([]byte("From: Ann Example <ann@example.com>\r\nSubject: noise\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"), letters...)
	mails := indexExtractMail([]byte("m/202611/7"), message, settings)
	if len(mails) != 1 {
		t.Fatalf("%d documents of a message", len(mails))
	}
	if prepared, err := mails[0].prepare(normalizer, false, Id{}, settings); err != nil || !prepared.skipped {
		t.Fatalf("the message's chunk through prepare: %+v %v", prepared, err)
	}
	streamedMail := testIndexStreamMail(t, []byte("m/202611/7"), message, settings, func(remaining int) int { return 64 * 1024 })
	if len(streamedMail) != 1 || !streamedMail[0].skipped {
		t.Fatalf("the message's chunk through the one-pass form: %+v", streamedMail)
	}

	raw := make([]byte, settings.ChunkByteCount/4*3)
	rand.New(rand.NewSource(6)).Read(raw)
	encoded := []byte(base64.StdEncoding.EncodeToString(raw))
	base64Files, ok := indexExtractFile([]byte("notes/blob.b64"), encoded, settings)
	if !ok || len(base64Files) != 1 {
		t.Fatalf("%d documents of base64", len(base64Files))
	}
	if prepared, err := base64Files[0].prepare(normalizer, false, Id{}, settings); err != nil || prepared.skipped {
		t.Fatalf("1 MiB of base64 was skipped: %v", err)
	}
	if streamed, ok := testIndexStreamFile(t, []byte("notes/blob.b64"), encoded, settings); !ok || len(streamed) != 1 || streamed[0].skipped {
		t.Fatal("1 MiB of base64 was skipped by the one-pass form")
	}

	refKey := bytes.Repeat([]byte{7}, 32)
	refId := evsTestId("noise ref")
	layer, err := NewSearchLocalLayer(&SearchLocalLayerArgs{RepoId: evsTestId("noise repo"), RefId: refId, RefKey: refKey, FormatSettings: settings})
	if err != nil {
		t.Fatal(err)
	}
	index := func(path []byte, content []byte, version uint64) [indexIdByteCount]byte {
		documents, ok := indexExtractFile(path, content, settings)
		if !ok {
			t.Fatal("a binary")
		}
		if err := layer.Index(normalizer, &SearchLocalVersion{RefId: refId, Path: path, Version: version, TimeMs: 1800000000000, Documents: documents, ReplacedChunkCount: 1}); err != nil {
			t.Fatal(err)
		}
		key, err := indexDocKey(refKey, refId, path, 0)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	key := index(path, letters[:4096], 1)
	if entry := layer.entries[key]; entry == nil || entry.kind != indexEntryFull {
		t.Fatal("the smaller text was not indexed")
	}
	index(path, letters, 2)
	if entry := layer.entries[key]; entry == nil || entry.kind != indexEntryTombstone || entry.version != 2 {
		t.Fatalf("the skipped version over an indexed one: %+v", entry)
	}
	never := index([]byte("notes/never.txt"), letters, 1)
	if entry := layer.entries[never]; entry != nil && entry.kind == indexEntryFull {
		t.Fatal("a skipped version never indexed left a live entry")
	}
}
