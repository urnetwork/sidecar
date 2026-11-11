// The entry, row, key set, slot and large-entry codec against testdata/index/'s vectors, and against bytes built by
// hand here, since a decoder that only ever saw its own encoder proves nothing about the format.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

const (
	testEntryVectorPath = "testdata/index/entry/vectors.json"
	testSlotVectorPath  = "testdata/index/slot/vectors.json"
)

// Fixed ids, so vectors never change by accident. Each is a counter under a label, opaque like the real thing.
func testIndexId(label string, index int) [indexIdByteCount]byte {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s %d", label, index))
	return [indexIdByteCount]byte(sum[:indexIdByteCount])
}

// testIndexId as a slice.
func testIndexIdBytes(label string, index int) []byte {
	id := testIndexId(label, index)
	return id[:]
}

// count keys spread over the key space by a counter, ascending.
func testIndexKeys(start int, count int, step int) indexKeySet {
	keys := make(indexKeySet, 0, count)
	for index := range count {
		keys = append(keys, uint32(start+index*step))
	}
	return keys
}

// A slot's header with every field a slot needs, on tables that are fixed so a header's bytes do not ride on the
// build running the test.
func testSlotHeader(fileType uint32) *protocol.IndexFileHeader {
	header := indexNewFileHeader(fileType, indexTables{normVersion: "17.0.0", textModuleVersion: "v0.43.0"})
	header.BucketStartDay = 20340
	header.BucketDays = 30
	header.WriterSidecarId = testIndexIdBytes("writer", 1)
	header.Seq = 7
	return header
}

// A file row of a document with these keys.
func testFileRow(keys indexKeySet) *indexRow {
	row := &indexRow{
		docKind:      indexDocFile,
		flags:        indexRowTainted,
		byteCount:    4096,
		trigramCount: uint64(len(keys)),
		locator:      "notes/plan.md",
	}
	row.fields[indexFieldTitle] = "The plan"
	row.fit()
	return row
}

// A mail row, the shape D-MAIL-16 reads: subject, from and to.
func testMailRow(keys indexKeySet) *indexRow {
	row := &indexRow{
		docKind:      indexDocMail,
		flags:        indexRowOutside,
		byteCount:    70000,
		chunk:        2,
		trigramCount: uint64(len(keys)),
		locator:      "m/202611/42",
	}
	row.fields[indexFieldSubject] = "Quarterly numbers"
	row.fields[indexFieldFrom] = "Ann Example <ann@example.com>"
	row.fields[indexFieldTo] = "Bob Example <bob@example.com>"
	row.fit()
	return row
}

// A derived row in ur/index: every kind of value a row can hold.
func testDerivedRow(keys indexKeySet) *indexRow {
	row := &indexRow{
		docKind:        indexDocDerived,
		flags:          indexRowPrivate | indexRowTainted,
		byteCount:      900,
		trigramCount:   uint64(len(keys)),
		startedSeconds: 1800000000,
		expiresSeconds: 1800086400,
		refId:          testIndexIdBytes("ref", 1),
		locator:        "run/0123456789abcdef",
	}
	row.fields[indexFieldTitle] = "Build the codec"
	for field := indexFieldBody + 1; field <= indexFieldLast; field += 1 {
		row.fields[field] = fmt.Sprintf("value of field %d", field)
	}
	row.fit()
	return row
}

// Every value at its widest, so the row's own 2 KiB is what decides, in the trimming order.
func testMaximalRow() *indexRow {
	row := &indexRow{
		docKind:        indexDocDerived,
		flags:          indexRowTainted | indexRowOutside | indexRowPrivate,
		byteCount:      math.MaxUint64,
		chunk:          math.MaxUint64,
		trigramCount:   16,
		startedSeconds: math.MaxUint64,
		expiresSeconds: math.MaxUint64,
		refId:          testIndexIdBytes("ref", 2),
		locator:        strings.Repeat("\u00E9", 600),
	}
	for _, field := range row.docKind.rowFields() {
		row.fields[field] = strings.Repeat("\u3042", 200)
	}
	row.fit()
	return row
}

// A named entry for the vectors, encoded in or out of ur/index as it says.
type testEntryCase struct {
	name      string
	companion bool
	entry     *indexEntry
}

// One of each kind, on every doc kind, and a maximal row.
func testEntryCases() []testEntryCase {
	keys := testIndexKeys(0x206120, 40, 257)
	return []testEntryCase{
		{
			name:  "full-file",
			entry: &indexEntry{kind: indexEntryFull, key: testIndexId("doc", 1), version: 3, timeSeconds: 1800000000, row: testFileRow(keys), keys: keys},
		},
		{
			name:  "full-mail",
			entry: &indexEntry{kind: indexEntryFull, key: testIndexId("doc", 2), version: 1, timeSeconds: 1800000123, row: testMailRow(keys), keys: keys},
		},
		{
			name:      "full-derived",
			companion: true,
			entry:     &indexEntry{kind: indexEntryFull, key: testIndexId("doc", 3), version: 300, timeSeconds: 1800000456, row: testDerivedRow(keys), keys: keys},
		},
		{
			name: "diff",
			entry: &indexEntry{
				kind: indexEntryDiff, key: testIndexId("doc", 4), version: 9, timeSeconds: 1800001000, baseVersion: 8,
				row:   testFileRow(keys),
				delta: indexDelta{added: indexKeySet{5, 0xFFFFFF}, removed: indexKeySet{0, 0x206120}},
			},
		},
		{
			name:  "tombstone",
			entry: &indexEntry{kind: indexEntryTombstone, key: testIndexId("doc", 5), version: 10, timeSeconds: 1800002000},
		},
		{
			name:      "ref-tombstone",
			companion: true,
			entry:     &indexEntry{kind: indexEntryRefTombstone, key: testIndexId("ref", 3), version: 11, timeSeconds: 1800003000},
		},
		{
			name:      "maximal-row",
			companion: true,
			entry: &indexEntry{
				kind: indexEntryFull, key: testIndexId("doc", 6), version: math.MaxUint64, timeSeconds: math.MaxUint64,
				row: testMaximalRow(), keys: testIndexKeys(0, 16, 0xFFFFF),
			},
		},
	}
}

// A named file for the vectors.
type testSlotCase struct {
	name      string
	companion bool
	slot      *indexSlot
}

// A slot of exactly byteCount bytes: full entries filling it, the last one's locator taking up what is left.
func testSlotOfLength(t testing.TB, byteCount int) *indexSlot {
	keys := testIndexKeys(0x100000, 300, 3)
	slot := &indexSlot{header: testSlotHeader(indexFileSlot)}
	full := func(index int, locator string) *indexEntry {
		row := testFileRow(keys)
		row.locator = locator
		return &indexEntry{kind: indexEntryFull, key: testIndexId("fill", index), version: uint64(index + 1), timeSeconds: 1800000000, row: row, keys: keys}
	}
	length := func() int {
		file, err := indexEncodeSlot(slot, false, DefaultIndexFormatSettings())
		if err != nil {
			t.Fatal(err)
		}
		return len(file)
	}
	for index := 0; ; index += 1 {
		slot.entries = append(slot.entries, full(index, "f"))
		if byteCount < length()+500 {
			break
		}
	}
	last := slot.entries[len(slot.entries)-1]
	for extra := 0; extra < indexLocatorMaxByteCount; extra += 1 {
		last.row.locator = "f" + strings.Repeat("x", extra)
		if length() == byteCount {
			return slot
		}
	}
	slot.entries = append(slot.entries, &indexEntry{kind: indexEntryTombstone, key: testIndexId("fill", -1), version: 1, timeSeconds: 1800000000})
	for extra := 0; extra < indexLocatorMaxByteCount; extra += 1 {
		last.row.locator = "f" + strings.Repeat("x", extra)
		if length() == byteCount {
			return slot
		}
	}
	t.Fatalf("no slot of %d bytes", byteCount)
	return nil
}

// A large entry's one entry: a key set past 8 KiB.
func testLargeEntry() *indexEntry {
	keys := testIndexKeys(0, 9000, 3)
	return &indexEntry{kind: indexEntryFull, key: testIndexId("large", 1), version: 2, timeSeconds: 1800000000, row: testFileRow(keys), keys: keys}
}

// A head on ur/index carrying coverage and every entry kind, and the files §11.14's slot and large rows describe.
func testSlotCases(t testing.TB) []testSlotCase {
	head := testSlotHeader(indexFileSlot)
	head.Coverage = []*protocol.IndexCoverage{
		{RefId: testIndexIdBytes("ref", 1), Version: 40},
		{RefId: testIndexIdBytes("ref", 3), Version: 11, Horizon: true},
	}
	entries := []*indexEntry{}
	for _, c := range testEntryCases() {
		if c.companion {
			entries = append(entries, c.entry)
		}
	}
	padded := testSlotOfLength(t, 2000)
	padded.padByteCount = 1234
	large := &indexSlot{header: testSlotHeader(indexFileLargeEntry), entries: []*indexEntry{testLargeEntry()}}
	return []testSlotCase{
		{name: "head-on-ur-index", companion: true, slot: &indexSlot{header: head, entries: entries}},
		{name: "empty", slot: &indexSlot{header: testSlotHeader(indexFileSlot)}},
		{name: "full-16208", slot: testSlotOfLength(t, DefaultIndexFormatSettings().SlotMaxByteCount)},
		{name: "closure-padded", slot: padded},
		{name: "large", slot: large},
	}
}

// One byte-exact vector.
type testCodecVector struct {
	Name      string `json:"name"`
	Companion bool   `json:"companion"`
	Hex       string `json:"hex"`
	Sha256    string `json:"sha256"`
}

// The vector of encoded bytes.
func testVectorOf(name string, companion bool, encoded []byte) testCodecVector {
	sum := sha256.Sum256(encoded)
	return testCodecVector{Name: name, Companion: companion, Hex: hex.EncodeToString(encoded), Sha256: hex.EncodeToString(sum[:])}
}

// A vector file by name, written first in rewrite mode.
func testReadVectors(t *testing.T, path string, built []testCodecVector) map[string]testCodecVector {
	vectors := built
	if os.Getenv(testWriteVectorsEnvironment) != "" {
		testWriteJson(t, path, built)
	} else {
		encoded, err := testIndexFiles.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		vectors = []testCodecVector{}
		if err := json.Unmarshal(encoded, &vectors); err != nil {
			t.Fatal(err)
		}
	}
	if len(vectors) != len(built) {
		t.Errorf("%s holds %d vectors for %d cases", path, len(vectors), len(built))
	}
	byName := map[string]testCodecVector{}
	for _, vector := range vectors {
		byName[vector.Name] = vector
	}
	return byName
}

// An entry decoded alone, every byte consumed.
func testDecodeEntry(encoded []byte, companion bool) (*indexEntry, error) {
	decoder := indexDecoder{src: encoded}
	entry := decoder.entry(companion)
	if decoder.err != nil {
		return nil, decoder.err
	}
	if decoder.remaining() != 0 {
		return nil, indexMalformed("bytes after the entry")
	}
	return entry, nil
}

// Fields a decoder fills with empties where a builder left nil.
func testComparableEntry(entry *indexEntry) indexEntry {
	comparable := *entry
	if entry.row != nil {
		row := *entry.row
		comparable.row = &row
		if len(row.refId) == 0 {
			comparable.row.refId = nil
		}
	}
	if len(comparable.keys) == 0 {
		comparable.keys = nil
	}
	if len(comparable.delta.added) == 0 {
		comparable.delta.added = nil
	}
	if len(comparable.delta.removed) == 0 {
		comparable.delta.removed = nil
	}
	return comparable
}

// D-TEST-15: each kind's bytes, the same on every leg, decoding to what built them and encoding back unchanged.
func TestEntryVectors(t *testing.T) {
	built := []testCodecVector{}
	cases := testEntryCases()
	for _, c := range cases {
		encoded, err := c.entry.appendEncoded(nil, c.companion)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		built = append(built, testVectorOf(c.name, c.companion, encoded))
	}
	vectors := testReadVectors(t, testEntryVectorPath, built)
	for index, c := range cases {
		vector := vectors[c.name]
		if vector != built[index] {
			t.Errorf("%s: built %s", c.name, built[index].Hex)
		}
		encoded, err := hex.DecodeString(vector.Hex)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := testDecodeEntry(encoded, c.companion)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(testComparableEntry(decoded), testComparableEntry(c.entry)) {
			t.Errorf("%s decoded differently", c.name)
		}
		again, err := decoded.appendEncoded(nil, c.companion)
		if err != nil || !bytes.Equal(again, encoded) {
			t.Errorf("%s re-encoded differently: %v", c.name, err)
		}
	}
}

// D-TEST-15 for whole files: a head, the fullest slot a head can be, a CLOSURE's pad and a large entry.
func TestSlotVectors(t *testing.T) {
	built := []testCodecVector{}
	cases := testSlotCases(t)
	for _, c := range cases {
		file, err := indexEncodeSlot(c.slot, c.companion, DefaultIndexFormatSettings())
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		built = append(built, testVectorOf(c.name, c.companion, file))
	}
	vectors := testReadVectors(t, testSlotVectorPath, built)
	for index, c := range cases {
		vector := vectors[c.name]
		if vector != built[index] {
			t.Errorf("%s: its bytes moved", c.name)
		}
		file, err := hex.DecodeString(vector.Hex)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(file)
		slot, err := indexDecodeSlot(file, sum[:], c.companion, DefaultIndexFormatSettings())
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if len(slot.entries) != len(c.slot.entries) || slot.padByteCount != c.slot.padByteCount {
			t.Errorf("%s: %d entries and %d pad", c.name, len(slot.entries), slot.padByteCount)
		}
		again, err := indexEncodeSlot(slot, c.companion, DefaultIndexFormatSettings())
		if err != nil || !bytes.Equal(again, file) {
			t.Errorf("%s re-encoded differently: %v", c.name, err)
		}
	}
	if full := vectors["full-16208"]; len(full.Hex) != 2*DefaultIndexFormatSettings().SlotMaxByteCount {
		t.Errorf("the full slot is %d bytes", len(full.Hex)/2)
	}
}

func TestVByteEncodings(t *testing.T) {
	cases := []struct {
		value   uint64
		encoded string
	}{
		{value: 0, encoded: "00"},
		{value: 1, encoded: "01"},
		{value: 127, encoded: "7f"},
		{value: 128, encoded: "8001"},
		{value: 300, encoded: "ac02"},
		{value: 16383, encoded: "ff7f"},
		{value: 16384, encoded: "808001"},
		{value: math.MaxUint32, encoded: "ffffffff0f"},
		{value: math.MaxUint64, encoded: "ffffffffffffffffff01"},
	}
	for _, c := range cases {
		encoded := hex.EncodeToString(indexAppendVByte(nil, c.value))
		if encoded != c.encoded {
			t.Errorf("%d encodes to %s, want %s", c.value, encoded, c.encoded)
		}
		if length := indexVByteLength(c.value); 2*length != len(c.encoded) {
			t.Errorf("%d has length %d", c.value, length)
		}
		src, err := hex.DecodeString(c.encoded + "ff")
		if err != nil {
			t.Fatal(err)
		}
		value, byteCount, ok := indexReadVByte(src)
		if !ok || value != c.value || 2*byteCount != len(c.encoded) {
			t.Errorf("%s reads %d in %d (%t)", c.encoded, value, byteCount, ok)
		}
	}
}

// Everything but a minimal encoding of a value that fits: the forms binary.Uvarint would take or wrap.
func TestVByteRefusals(t *testing.T) {
	for _, encoded := range []string{
		"",                       // nothing
		"80",                     // cut
		"ffff",                   // cut
		"8000",                   // zero, in two bytes
		"8100",                   // one, in two bytes
		"808000",                 // zero, in three bytes
		"ffffffffffffffffff00",   // the 10th byte adds nothing
		"ffffffffffffffffff02",   // past 64 bits
		"ffffffffffffffffff81",   // a continuation on the 10th byte
		"ffffffffffffffffffff01", // eleven bytes
	} {
		src, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if value, _, ok := indexReadVByte(src); ok {
			t.Errorf("%q read as %d", encoded, value)
		}
	}
}

func TestDecoderStopsAtItsFirstRefusal(t *testing.T) {
	decoder := indexDecoder{src: []byte{0x80, 0x00, 0x05}}
	if value := decoder.vbyte(); value != 0 || decoder.err == nil {
		t.Fatalf("read %d, %v", value, decoder.err)
	}
	first := decoder.err
	if value := decoder.vbyte(); value != 0 || decoder.err != first {
		t.Errorf("read %d past a refusal", value)
	}
	if taken := decoder.take(1); taken != nil {
		t.Errorf("took %x past a refusal", taken)
	}
	if b := decoder.oneByte(); b != 0 {
		t.Errorf("read %x past a refusal", b)
	}
}

func TestKeySetEncoding(t *testing.T) {
	cases := []struct {
		keys    indexKeySet
		encoded string
	}{
		{keys: indexKeySet{}, encoded: "00"},
		{keys: indexKeySet{0}, encoded: "0101"},
		{keys: indexKeySet{1, 2}, encoded: "020201"},
		{keys: indexKeySet{0, 1, 128}, encoded: "0301017f"},
		{keys: indexKeySet{0, 129}, encoded: "02018101"},
		{keys: indexKeySet{indexKeyMax}, encoded: "0180808008"},
		{keys: indexKeySet{0, indexKeyMax}, encoded: "0201ffffff07"},
	}
	for _, c := range cases {
		encoded, err := c.keys.appendEncoded(nil)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(encoded) != c.encoded {
			t.Errorf("%x encodes to %x, want %s", c.keys, encoded, c.encoded)
		}
		if c.keys.encodedByteCount() != len(encoded) {
			t.Errorf("%x counts %d", c.keys, c.keys.encodedByteCount())
		}
		decoder := indexDecoder{src: encoded}
		decoded := decoder.keySet()
		if decoder.err != nil || !slices.Equal(decoded, c.keys) || decoder.remaining() != 0 {
			t.Errorf("%s decodes to %x: %v", c.encoded, decoded, decoder.err)
		}
	}
}

func TestKeySetRefusals(t *testing.T) {
	for _, keys := range []indexKeySet{{2, 1}, {1, 1}, {indexKeyMax + 1}} {
		if _, err := keys.appendEncoded(nil); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%x encoded: %v", keys, err)
		}
	}
	for _, encoded := range []string{
		"0100",                 // a first gap of zero is no key
		"020100",               // a repeated key
		"01 8180 8008",         // a key past 24 bits, in one gap
		"02ffffff07ffff",       // a cut gap
		"02ffffff0702",         // a key past 24 bits, by the gaps' sum
		"0201",                 // a count past its input
		"ffffffffffffffffff01", // a count no input holds, refused before it sizes anything
		"80000101",             // a non-minimal count
		"01810001",             // a non-minimal gap
	} {
		src, err := hex.DecodeString(strings.ReplaceAll(encoded, " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		decoder := indexDecoder{src: src}
		if keys := decoder.keySet(); !errors.Is(decoder.err, errIndexMalformed) {
			t.Errorf("%s decoded to %x", encoded, keys)
		}
	}
}

// §11.14's sniff row bounds a key set at 512 KiB, one byte past which is refused both ways.
func TestKeySetCap(t *testing.T) {
	// every gap here is one byte, so the count's three bytes and the keys fill it exactly
	atCap := testIndexKeys(0, indexKeySetMaxByteCount-3, 1)
	encoded, err := atCap.appendEncoded(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != indexKeySetMaxByteCount {
		t.Fatalf("%d bytes", len(encoded))
	}
	decoder := indexDecoder{src: encoded}
	if decoder.keySet(); decoder.err != nil {
		t.Error(decoder.err)
	}
	past := testIndexKeys(0, indexKeySetMaxByteCount-2, 1)
	if _, err := past.appendEncoded(nil); !errors.Is(err, errIndexMalformed) {
		t.Errorf("one past encoded: %v", err)
	}
	encoded = indexAppendVByte(nil, uint64(len(past)))
	encoded = append(encoded, bytes.Repeat([]byte{1}, len(past))...)
	decoder = indexDecoder{src: encoded}
	if decoder.keySet(); !errors.Is(decoder.err, errIndexMalformed) {
		t.Errorf("one past decoded: %v", decoder.err)
	}
}

func TestDeltaBetweenAndApply(t *testing.T) {
	base := indexKeySet{1, 2, 3, 5, 8}
	next := indexKeySet{2, 3, 4, 8, 9}
	delta := indexDeltaBetween(base, next)
	if !slices.Equal(delta.added, indexKeySet{4, 9}) || !slices.Equal(delta.removed, indexKeySet{1, 5}) {
		t.Fatalf("%+v", delta)
	}
	got, err := delta.applyTo(base)
	if err != nil || !slices.Equal(got, next) {
		t.Errorf("%x: %v", got, err)
	}
	for _, wrong := range []indexKeySet{{1, 2, 3, 4, 5, 8}, {2, 3, 8}, {}} {
		if got, err := delta.applyTo(wrong); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%x gave %x", wrong, got)
		}
	}
	if _, err := (indexDelta{added: indexKeySet{1}, removed: indexKeySet{1}}).applyTo(indexKeySet{1}); !errors.Is(err, errIndexMalformed) {
		t.Errorf("a key added and removed: %v", err)
	}
}

// A random walk of key sets, so composing has something to cancel: keys added then removed, and removed then added.
func testDeltaChain(rng *rand.Rand, length int) (base indexKeySet, sets []indexKeySet, deltas []indexDelta) {
	universe := 200
	pick := func() indexKeySet {
		keys := indexKeySet{}
		for key := range universe {
			if rng.Intn(2) == 0 {
				keys = append(keys, uint32(key))
			}
		}
		return keys
	}
	base = pick()
	last := base
	for range length {
		next := slices.Clone(last)
		for range 12 {
			key := uint32(rng.Intn(universe))
			if index, found := slices.BinarySearch(next, key); found {
				next = slices.Delete(next, index, index+1)
			} else {
				next = slices.Insert(next, index, key)
			}
		}
		deltas = append(deltas, indexDeltaBetween(last, next))
		sets = append(sets, next)
		last = next
	}
	return base, sets, deltas
}

// SEARCH-M10-04's test: across a 16-entry chain every grouping of the compositions is one delta, and it takes the base
// to the chain's last set.
func TestDeltaCompositionIsAssociativeAcrossAChain(t *testing.T) {
	rng := rand.New(rand.NewSource(14))
	for range 200 {
		base, sets, deltas := testDeltaChain(rng, 16)
		left := deltas[0]
		for _, delta := range deltas[1:] {
			var err error
			if left, err = indexComposeDelta(left, delta); err != nil {
				t.Fatal(err)
			}
		}
		right := deltas[len(deltas)-1]
		for index := len(deltas) - 2; 0 <= index; index -= 1 {
			var err error
			if right, err = indexComposeDelta(deltas[index], right); err != nil {
				t.Fatal(err)
			}
		}
		if !slices.Equal(left.added, right.added) || !slices.Equal(left.removed, right.removed) {
			t.Fatalf("left %+v, right %+v", left, right)
		}
		// a split at every point composes to the same delta too
		for split := 1; split < len(deltas); split += 1 {
			head, tail := deltas[0], deltas[split]
			for _, delta := range deltas[1:split] {
				var err error
				if head, err = indexComposeDelta(head, delta); err != nil {
					t.Fatal(err)
				}
			}
			for _, delta := range deltas[split+1:] {
				var err error
				if tail, err = indexComposeDelta(tail, delta); err != nil {
					t.Fatal(err)
				}
			}
			joined, err := indexComposeDelta(head, tail)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(joined.added, left.added) || !slices.Equal(joined.removed, left.removed) {
				t.Fatalf("split at %d differs", split)
			}
		}
		last := sets[len(sets)-1]
		got, err := left.applyTo(base)
		if err != nil || !slices.Equal(got, last) {
			t.Fatalf("%x, %v", got, err)
		}
		if want := indexDeltaBetween(base, last); !slices.Equal(left.added, want.added) || !slices.Equal(left.removed, want.removed) {
			t.Fatalf("composed %+v, direct %+v", left, want)
		}
	}
}

// A key added and removed again cancels, and so does the other way round, and neither reaches the composed delta.
func TestComposedDeltaCancels(t *testing.T) {
	composed, err := indexComposeDelta(
		indexDelta{added: indexKeySet{1, 2}, removed: indexKeySet{7, 8}},
		indexDelta{added: indexKeySet{7, 9}, removed: indexKeySet{2, 6}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(composed.added, indexKeySet{1, 9}) || !slices.Equal(composed.removed, indexKeySet{6, 8}) {
		t.Errorf("%+v", composed)
	}
}

func TestDeltasThatCannotComposeAreRefused(t *testing.T) {
	cases := []struct{ first, second indexDelta }{
		{first: indexDelta{added: indexKeySet{1}}, second: indexDelta{added: indexKeySet{1}}},
		{first: indexDelta{removed: indexKeySet{1}}, second: indexDelta{removed: indexKeySet{1}}},
		{first: indexDelta{added: indexKeySet{1}, removed: indexKeySet{1}}, second: indexDelta{}},
		{first: indexDelta{}, second: indexDelta{added: indexKeySet{2, 1}}},
	}
	for _, c := range cases {
		if composed, err := indexComposeDelta(c.first, c.second); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%+v then %+v gave %+v", c.first, c.second, composed)
		}
	}
}

func TestRowFlagBits(t *testing.T) {
	if indexRowCutFlag(indexFieldSubject) != 1<<3 || indexRowCutFlag(indexFieldLast) != 1<<17 {
		t.Errorf("subject %b, last %b", indexRowCutFlag(indexFieldSubject), indexRowCutFlag(indexFieldLast))
	}
	for _, c := range []struct {
		docKind indexDocKind
		want    uint64
	}{
		{docKind: indexDocFile, want: 0x4007F},
		{docKind: indexDocMail, want: 0x4007F},
		{docKind: indexDocRecord, want: 0x7FF7F},
		{docKind: indexDocDerived, want: 0x7FF7F},
	} {
		if got := c.docKind.rowFlags(); got != c.want {
			t.Errorf("kind %d allows %x, want %x", c.docKind, got, c.want)
		}
	}
}

// §11.14's caps sum past the row's own 2 KiB, so the fixed order decides who gives way, and each loser's bit says so.
func TestRowTrimmingFollowsItsOrder(t *testing.T) {
	row := testMaximalRow()
	encoded, err := row.appendEncoded(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != indexRowMaxByteCount {
		t.Fatalf("%d bytes", len(encoded))
	}
	if len(row.locator) != 512 {
		t.Errorf("locator %d", len(row.locator))
	}
	for field, want := range map[int]int{
		// a 3-byte letter stops short of a cap that is no multiple of 3
		1: 159, 2: 159, 3: 159, 4: 159, 6: 255, 7: 255, 8: 255,
		// what the row has left, less a length byte for each field after it
		9:  51,
		10: 0, 11: 0, 12: 0, 13: 0, 14: 0, 15: 0,
	} {
		if len(row.fields[field]) != want {
			t.Errorf("field %d kept %d, want %d", field, len(row.fields[field]), want)
		}
	}
	for _, field := range row.docKind.rowFields() {
		if row.flags&indexRowCutFlag(field) == 0 {
			t.Errorf("field %d's bit is clear", field)
		}
		if !utf8.ValidString(row.fields[field]) {
			t.Errorf("field %d is not UTF-8", field)
		}
	}
	if row.flags&indexRowInexact == 0 {
		t.Error("a cut locator reads as exact")
	}
	// a row within its caps loses nothing and sets nothing
	fits := testFileRow(indexKeySet{1})
	if fits.flags != indexRowTainted || fits.locator != "notes/plan.md" || fits.fields[indexFieldTitle] != "The plan" {
		t.Errorf("%+v", fits)
	}
}

// A field that fits to the byte keeps its bit clear, and fitting twice changes nothing.
func TestRowFitIsExactAndStable(t *testing.T) {
	row := &indexRow{docKind: indexDocMail, locator: strings.Repeat("l", 512)}
	row.fields[indexFieldSubject] = strings.Repeat("s", 160)
	row.fields[indexFieldFrom] = strings.Repeat("f", 161)
	row.fit()
	if row.locator != strings.Repeat("l", 512) || row.fields[indexFieldSubject] != strings.Repeat("s", 160) {
		t.Errorf("a value at its cap was cut")
	}
	if len(row.fields[indexFieldFrom]) != 160 {
		t.Errorf("from kept %d", len(row.fields[indexFieldFrom]))
	}
	if want := indexRowCutFlag(indexFieldFrom); row.flags != want {
		t.Errorf("flags %x, want %x", row.flags, want)
	}
	again := *row
	again.fit()
	if !reflect.DeepEqual(again, *row) {
		t.Error("a second fit changed the row")
	}
	maximal := testMaximalRow()
	again = *maximal
	again.fit()
	if !reflect.DeepEqual(again, *maximal) {
		t.Error("a second fit changed the maximal row")
	}
}

// A row that fits once each value is at its own cap is not walked at all, down to its last byte, and one byte more is.
func TestRowFitWalksOnlyPastItsOwnCap(t *testing.T) {
	row := func(fieldLength int) *indexRow {
		built := &indexRow{docKind: indexDocRecord, locator: strings.Repeat("l", 512)}
		for _, field := range built.docKind.rowFields() {
			built.fields[field] = strings.Repeat("x", indexRowFieldCap(field))
		}
		for field := 9; field <= indexFieldLast; field += 1 {
			built.fields[field] = ""
		}
		built.fields[9] = strings.Repeat("x", fieldLength)
		return built
	}
	// the other values take 1,949 of the row's 2,048 B, so 98 B and a length byte fill it exactly
	exact := row(98)
	if used := exact.encodedByteCount(); used != indexRowMaxByteCount {
		t.Fatalf("the row is %d bytes", used)
	}
	exact.fit()
	if exact.flags != 0 || len(exact.fields[9]) != 98 {
		t.Errorf("a row at its cap was cut: flags %x, field 9 %d", exact.flags, len(exact.fields[9]))
	}
	over := row(99)
	over.fit()
	if over.flags&indexRowCutFlag(9) == 0 || over.flags&indexRowCutFlag(8) != 0 || over.encodedByteCount() > indexRowMaxByteCount {
		t.Errorf("flags %x, %d bytes", over.flags, over.encodedByteCount())
	}
}

// Setting a cut bit can widen the flags' VByte, which the walk counts ahead of time, so a row filled to the byte still
// fits after its last cut sets bit 17.
func TestRowFitCountsItsWidestFlags(t *testing.T) {
	for locatorLength := 400; locatorLength <= 512; locatorLength += 1 {
		row := &indexRow{docKind: indexDocRecord, locator: strings.Repeat("l", locatorLength)}
		for _, field := range row.docKind.rowFields() {
			row.fields[field] = strings.Repeat("x", 300)
		}
		row.fit()
		encoded, err := row.appendEncoded(nil, false)
		if err != nil {
			t.Fatalf("locator %d: %v", locatorLength, err)
		}
		if indexRowMaxByteCount < len(encoded) {
			t.Errorf("locator %d: %d bytes", locatorLength, len(encoded))
		}
	}
}

// A path may be any bytes, and a row's text is UTF-8 by step 1's rule, one U+FFFD for each ill-formed byte. A replaced
// locator is no longer the exact path, and says so.
func TestRowTextIsValidUtf8(t *testing.T) {
	row := &indexRow{docKind: indexDocFile, locator: "a\xFF\xFEb"}
	row.fit()
	if row.locator != "a\uFFFD\uFFFDb" {
		t.Errorf("%+q", row.locator)
	}
	if row.flags != indexRowInexact {
		t.Errorf("flags %x", row.flags)
	}
	exact := &indexRow{docKind: indexDocFile, locator: strings.Repeat("\u00E9", 256)}
	exact.fit()
	if exact.flags != 0 {
		t.Errorf("a locator at its cap set flags %x", exact.flags)
	}
	cut := &indexRow{docKind: indexDocFile, locator: strings.Repeat("\u00E9", 257)}
	cut.fit()
	if cut.flags != indexRowInexact || len(cut.locator) != 512 {
		t.Errorf("flags %x, %d bytes", cut.flags, len(cut.locator))
	}
	row = &indexRow{docKind: indexDocMail}
	row.fields[indexFieldSubject] = strings.Repeat("\xFF", 100)
	row.fit()
	// 100 replacements are 300 bytes, cut to 53 whole code points
	if want := strings.Repeat("\uFFFD", 53); row.fields[indexFieldSubject] != want {
		t.Errorf("%+q", row.fields[indexFieldSubject])
	}
	if row.flags != indexRowCutFlag(indexFieldSubject) {
		t.Errorf("flags %x", row.flags)
	}
}

// A row built by hand, each value given as bytes, so a refusal below is about those bytes alone.
func testRawRow(docKind byte, flags uint64, started uint64, refId []byte, texts ...string) []byte {
	row := []byte{docKind}
	row = indexAppendVByte(row, flags)
	row = indexAppendVByte(row, 10)
	row = indexAppendVByte(row, 0)
	row = indexAppendVByte(row, 0)
	row = indexAppendVByte(row, started)
	row = indexAppendVByte(row, 0)
	row = append(row, refId...)
	for _, text := range texts {
		row = indexAppendVByte(row, uint64(len(text)))
		row = append(row, text...)
	}
	return row
}

func TestRowRefusals(t *testing.T) {
	five := []string{"f", "", "", "", ""}
	registered := append(slices.Clone(five), make([]string, 10)...)
	refId := testIndexIdBytes("ref", 1)
	cases := []struct {
		name      string
		companion bool
		row       []byte
	}{
		{name: "doc kind 0", row: testRawRow(0, 0, 0, nil, five...)},
		{name: "doc kind 5", row: testRawRow(5, 0, 0, nil, five...)},
		{name: "flag bit 7", row: testRawRow(1, 1<<7, 0, nil, five...)},
		{name: "flag bit 19", row: testRawRow(3, 1<<19, 0, nil, registered...)},
		{name: "a registered cut bit on a file", row: testRawRow(1, 1<<8, 0, nil, five...)},
		{name: "times on a file", row: testRawRow(1, 0, 1, nil, five...)},
		{name: "times on a record", row: testRawRow(3, 0, 1, nil, registered...)},
		{name: "ref_id where the root has none", row: testRawRow(1, 0, 0, refId, five...)},
		{name: "no ref_id in ur/index", companion: true, row: testRawRow(1, 0, 0, nil, five...)},
		{name: "a locator past its cap", row: testRawRow(1, 0, 0, nil, strings.Repeat("l", 513), "", "", "", "")},
		{name: "a subject past its cap", row: testRawRow(1, 0, 0, nil, "f", strings.Repeat("s", 161), "", "", "")},
		{name: "a registered field past its cap", row: testRawRow(3, 0, 0, nil, append([]string{"f", "", "", "", "", strings.Repeat("r", 257)}, make([]string, 9)...)...)},
		{name: "text that is not UTF-8", row: testRawRow(1, 0, 0, nil, "\xFF", "", "", "", "")},
		{name: "a field cut inside a code point", row: testRawRow(2, 0, 0, nil, "m", "\xE3\x81", "", "", "")},
		{name: "a file row cut short", row: testRawRow(1, 0, 0, nil, "f", "", "")},
		{name: "a non-minimal length", row: append(testRawRow(1, 0, 0, nil), 0x81, 0x00, 'f', 0, 0, 0, 0)},
		{name: "no registered fields on a record", row: testRawRow(3, 0, 0, nil, five...)},
	}
	for _, c := range cases {
		decoder := indexDecoder{src: c.row}
		if row := decoder.row(c.companion); !errors.Is(decoder.err, errIndexMalformed) {
			t.Errorf("%s decoded to %+v", c.name, row)
		}
	}
}

// The encoder holds the same line, never trusting a row that skipped fit.
func TestRowEncoderRefuses(t *testing.T) {
	refId := testIndexIdBytes("ref", 1)
	cases := []struct {
		name      string
		companion bool
		row       indexRow
	}{
		{name: "no doc kind", row: indexRow{}},
		{name: "a ref_id off ur/index", row: indexRow{docKind: indexDocFile, refId: refId}},
		{name: "no ref_id on ur/index", companion: true, row: indexRow{docKind: indexDocFile}},
		{name: "a short ref_id", companion: true, row: indexRow{docKind: indexDocFile, refId: refId[:8]}},
		{name: "a long locator", row: indexRow{docKind: indexDocFile, locator: strings.Repeat("l", 513)}},
		{name: "ill-formed text", row: indexRow{docKind: indexDocFile, locator: "\xFF"}},
		{name: "times on mail", row: indexRow{docKind: indexDocMail, expiresSeconds: 1}},
	}
	for _, c := range cases {
		if encoded, err := c.row.appendEncoded(nil, c.companion); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%s encoded to %x", c.name, encoded)
		}
	}
	for _, field := range []int{0, indexFieldBody, 6} {
		row := indexRow{docKind: indexDocFile}
		row.fields[field] = "x"
		if encoded, err := row.appendEncoded(nil, false); !errors.Is(err, errIndexMalformed) {
			t.Errorf("field %d on a file encoded to %x", field, encoded)
		}
	}
	over := indexRow{docKind: indexDocRecord, locator: strings.Repeat("l", 512)}
	for _, field := range over.docKind.rowFields() {
		over.fields[field] = strings.Repeat("x", indexRowFieldCap(field))
	}
	if encoded, err := over.appendEncoded(nil, false); !errors.Is(err, errIndexMalformed) {
		t.Errorf("a row past 2 KiB encoded to %d bytes", len(encoded))
	}
}

// Every 2 KiB row the caps allow reads back: the decoder's own cap is the row's, not a smaller one.
func TestRowAtItsCapDecodes(t *testing.T) {
	row := testMaximalRow()
	encoded, err := row.appendEncoded(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	decoder := indexDecoder{src: encoded}
	decoded := decoder.row(true)
	if decoder.err != nil {
		t.Fatal(decoder.err)
	}
	if !reflect.DeepEqual(decoded, row) {
		t.Error("the maximal row changed")
	}
	// one byte more, in a field with room for it, is past the row's cap though within the field's
	wide := *row
	wide.fields[indexFieldLast] = strings.Repeat("x", 256)
	encoded = encoded[:len(encoded)-1]
	encoded = indexAppendVByte(encoded, 256)
	encoded = append(encoded, wide.fields[indexFieldLast]...)
	decoder = indexDecoder{src: encoded}
	if decoder.row(true); !errors.Is(decoder.err, errIndexMalformed) {
		t.Errorf("a row of %d bytes decoded: %v", len(encoded), decoder.err)
	}
}

// An entry built by hand up to its row.
func testRawEntry(kind byte, version uint64, rest ...[]byte) []byte {
	key := testIndexId("doc", 1)
	entry := append([]byte{kind}, key[:]...)
	entry = indexAppendVByte(entry, version)
	entry = indexAppendVByte(entry, 1800000000)
	for _, part := range rest {
		entry = append(entry, part...)
	}
	return entry
}

// A key set's bytes, for a hand-built entry.
func testKeySetBytes(t *testing.T, keys indexKeySet) []byte {
	encoded, err := keys.appendEncoded(nil)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestEntryRefusals(t *testing.T) {
	row := func(trigramCount uint64) []byte {
		encoded, err := (&indexRow{docKind: indexDocFile, trigramCount: trigramCount, locator: "f"}).appendEncoded(nil, false)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	two := testKeySetBytes(t, indexKeySet{1, 2})
	empty := testKeySetBytes(t, indexKeySet{})
	cases := []struct {
		name  string
		entry []byte
	}{
		{name: "kind 0", entry: testRawEntry(0, 1)},
		{name: "kind 5", entry: testRawEntry(5, 1)},
		{name: "a ref tombstone outside ur/index", entry: testRawEntry(4, 1)},
		{name: "a cut key", entry: []byte{3, 1, 2, 3}},
		{name: "a full entry's count off its set", entry: testRawEntry(1, 1, row(1), two)},
		{name: "a full entry with no set", entry: testRawEntry(1, 1, row(0))},
		{name: "a diff's base at its version", entry: testRawEntry(2, 5, indexAppendVByte(nil, 5), row(2), two, empty)},
		{name: "a diff's base above its version", entry: testRawEntry(2, 5, indexAppendVByte(nil, 6), row(2), two, empty)},
		{name: "a key added and removed", entry: testRawEntry(2, 5, indexAppendVByte(nil, 4), row(2), two, two)},
		{name: "a diff's count below what it added", entry: testRawEntry(2, 5, indexAppendVByte(nil, 4), row(1), two, empty)},
		{name: "a non-minimal version", entry: append(append([]byte{3}, make([]byte, 16)...), 0x81, 0x00, 0x01)},
	}
	for _, c := range cases {
		if entry, err := testDecodeEntry(c.entry, false); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%s decoded to %+v", c.name, entry)
		}
	}
}

// §11.14's entry row: a time is the push's, given as seconds, floored, and a future clock has no way in.
func TestEntrySecondsComeFromTheSignedTime(t *testing.T) {
	for _, c := range []struct {
		timeMs int64
		want   uint64
	}{{timeMs: 0, want: 0}, {timeMs: 999, want: 0}, {timeMs: 1000, want: 1}, {timeMs: 1800000000999, want: 1800000000}, {timeMs: -1, want: 0}} {
		if got := indexEntrySeconds(c.timeMs); got != c.want {
			t.Errorf("%d reads %d", c.timeMs, got)
		}
	}
}

// Files assembled by hand: a body and header this package's encoder would never write, under a true hash, so what
// refuses them is the format and not the hash.
func testRawFile(t testing.TB, header *protocol.IndexFileHeader, body []byte, pad []byte) []byte {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	file := []byte(indexFileMagic)
	file = indexAppendVByte(file, uint64(len(encoded)))
	file = append(file, encoded...)
	file = append(file, body...)
	return append(file, pad...)
}

// A header that matches a body of count entries.
func testFilledHeader(fileType uint32, count int, body []byte) *protocol.IndexFileHeader {
	header := testSlotHeader(fileType)
	header.Count = uint32(count)
	header.BodyLength = uint32(len(body))
	return header
}

// Decodes under the file's true hash.
func testDecodeFile(file []byte, companion bool) (*indexSlot, error) {
	sum := sha256.Sum256(file)
	return indexDecodeSlot(file, sum[:], companion, DefaultIndexFormatSettings())
}

// Two tombstones' bytes, ordered as asked.
func testTombstones(first string, second string) []byte {
	a := testIndexId(first, 1)
	b := testIndexId(second, 1)
	if bytes.Compare(a[:], b[:]) >= 0 {
		a, b = b, a
	}
	body := append([]byte{3}, a[:]...)
	body = append(body, 1, 1, 3)
	body = append(body, b[:]...)
	return append(body, 1, 1)
}

func TestSlotRefusals(t *testing.T) {
	body := testTombstones("a", "b")
	sorted := testFilledHeader(indexFileSlot, 2, body)
	if _, err := testDecodeFile(testRawFile(t, sorted, body, nil), false); err != nil {
		t.Fatalf("the control refused: %v", err)
	}
	swapped := append(slices.Clone(body[19:]), body[:19]...)
	repeated := append(slices.Clone(body[:19]), body[:19]...)
	change := func(edit func(header *protocol.IndexFileHeader)) []byte {
		header := proto.CloneOf(sorted)
		edit(header)
		return testRawFile(t, header, body, nil)
	}
	unknown := testRawFile(t, sorted, body, nil)
	{
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(sorted)
		if err != nil {
			t.Fatal(err)
		}
		encoded = protowire.AppendVarint(protowire.AppendTag(encoded, 99, protowire.VarintType), 1)
		unknown = append(indexAppendVByte([]byte(indexFileMagic), uint64(len(encoded))), encoded...)
		unknown = append(unknown, body...)
	}
	reordered := func() []byte {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(sorted)
		if err != nil {
			t.Fatal(err)
		}
		// field 1 written again at the end changes nothing it means, and is no canonical form
		encoded = protowire.AppendVarint(protowire.AppendTag(encoded, 1, protowire.VarintType), 1)
		file := append(indexAppendVByte([]byte(indexFileMagic), uint64(len(encoded))), encoded...)
		return append(file, body...)
	}()
	nonMinimalHeaderLength := func() []byte {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(sorted)
		if err != nil {
			t.Fatal(err)
		}
		if 127 < len(encoded) {
			t.Fatal("the header needs a one-byte length")
		}
		file := append([]byte(indexFileMagic), byte(len(encoded))|0x80, 0)
		return append(append(file, encoded...), body...)
	}()
	cases := []struct {
		name string
		file []byte
	}{
		{name: "nothing", file: nil},
		{name: "no magic", file: []byte("URiy")},
		{name: "a magic cut short", file: []byte("UR")},
		{name: "a header length past the file", file: append([]byte(indexFileMagic), 0x7F)},
		{name: "a non-minimal header length", file: nonMinimalHeaderLength},
		{name: "a header that does not parse", file: append([]byte(indexFileMagic), 1, 0xFF)},
		{name: "a header with a field format 1 lacks", file: unknown},
		{name: "a header field repeated", file: reordered},
		{name: "entries out of order", file: testRawFile(t, sorted, swapped, nil)},
		{name: "an entry repeated", file: testRawFile(t, sorted, repeated, nil)},
		{name: "a count past the entries", file: change(func(header *protocol.IndexFileHeader) { header.Count = 3 })},
		{name: "a count under the entries", file: change(func(header *protocol.IndexFileHeader) { header.Count = 1 })},
		{name: "a body length past the file", file: change(func(header *protocol.IndexFileHeader) { header.BodyLength += 1 })},
		{name: "a body length under the entries", file: change(func(header *protocol.IndexFileHeader) { header.BodyLength -= 1 })},
		{name: "a pad byte set", file: testRawFile(t, sorted, body, []byte{0, 1, 0})},
		{name: "format 0", file: change(func(header *protocol.IndexFileHeader) { header.Format = 0 })},
		{name: "a shard's type", file: change(func(header *protocol.IndexFileHeader) { header.Type = indexFileBucketShard })},
		{name: "no type", file: change(func(header *protocol.IndexFileHeader) { header.Type = 0 })},
		{name: "no normalizer", file: change(func(header *protocol.IndexFileHeader) { header.Normalizer = 0 })},
		{name: "no extractor", file: change(func(header *protocol.IndexFileHeader) { header.Extractor = 0 })},
		{name: "no unicode version", file: change(func(header *protocol.IndexFileHeader) { header.UnicodeVersion = "" })},
		{name: "no module version", file: change(func(header *protocol.IndexFileHeader) { header.TextModuleVersion = "" })},
		{name: "no bucket length", file: change(func(header *protocol.IndexFileHeader) { header.BucketDays = 0 })},
		{name: "a short writer", file: change(func(header *protocol.IndexFileHeader) { header.WriterSidecarId = header.WriterSidecarId[:8] })},
		{name: "seq 0", file: change(func(header *protocol.IndexFileHeader) { header.Seq = 0 })},
		{name: "a pad generation", file: change(func(header *protocol.IndexFileHeader) { header.PadGeneration = 1 })},
		{name: "a tombstone count", file: change(func(header *protocol.IndexFileHeader) { header.Tombstones = 1 })},
		{name: "unsorted coverage", file: change(func(header *protocol.IndexFileHeader) {
			header.Coverage = []*protocol.IndexCoverage{{RefId: testIndexIdBytes("z", 1)}, {RefId: testIndexIdBytes("a", 1)}}
			slices.SortFunc(header.Coverage, func(a *protocol.IndexCoverage, b *protocol.IndexCoverage) int {
				return bytes.Compare(b.RefId, a.RefId)
			})
		})},
		{name: "repeated coverage", file: change(func(header *protocol.IndexFileHeader) {
			header.Coverage = []*protocol.IndexCoverage{{RefId: testIndexIdBytes("a", 1)}, {RefId: testIndexIdBytes("a", 1)}}
		})},
		{name: "coverage with a short ref", file: change(func(header *protocol.IndexFileHeader) {
			header.Coverage = []*protocol.IndexCoverage{{RefId: []byte{1}}}
		})},
	}
	for _, c := range cases {
		if slot, err := testDecodeFile(c.file, false); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%s decoded to %+v: %v", c.name, slot, err)
		}
	}
}

// A nested field format 1 does not have hides from a top-level look, and is refused all the same.
func TestSlotRefusesAnUnknownFieldInCoverage(t *testing.T) {
	header := testFilledHeader(indexFileSlot, 0, nil)
	coverage := &protocol.IndexCoverage{RefId: testIndexIdBytes("a", 1)}
	coverage.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	header.Coverage = []*protocol.IndexCoverage{coverage}
	if slot, err := testDecodeFile(testRawFile(t, header, nil, nil), false); !errors.Is(err, errIndexMalformed) {
		t.Errorf("decoded to %+v: %v", slot, err)
	}
}

// §11.14's off row: a newer format is another thing than a broken file, and its bytes are not judged.
func TestNewerFormatIsNotMalformed(t *testing.T) {
	header := testFilledHeader(indexFileSlot, 0, nil)
	header.Format = 2
	_, err := testDecodeFile(testRawFile(t, header, []byte("anything format 2 writes"), nil), false)
	if !errors.Is(err, errIndexNewerFormat) || errors.Is(err, errIndexMalformed) {
		t.Errorf("reads %v", err)
	}
}

// A slot's order is the format's, whatever its builder held, so two writers of one set write one file: the property
// §16.11's head reproduction rests on.
func TestSlotBytesDependOnlyOnItsEntries(t *testing.T) {
	entries := []*indexEntry{}
	for _, c := range testEntryCases() {
		if c.companion {
			entries = append(entries, c.entry)
		}
	}
	entries = append(entries, &indexEntry{kind: indexEntryTombstone, key: testIndexId("doc", 9), version: 1})
	entries = append(entries, &indexEntry{kind: indexEntryRefTombstone, key: [indexIdByteCount]byte{}, version: 1})
	entries = append(entries, &indexEntry{kind: indexEntryRefTombstone, key: [indexIdByteCount]byte{0xFF}, version: 1})
	want, err := indexEncodeSlot(&indexSlot{header: testSlotHeader(indexFileSlot), entries: entries}, true, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(15))
	for range 20 {
		shuffled := slices.Clone(entries)
		rng.Shuffle(len(shuffled), func(i int, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		got, err := indexEncodeSlot(&indexSlot{header: testSlotHeader(indexFileSlot), entries: shuffled}, true, DefaultIndexFormatSettings())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("a shuffle changed the file")
		}
	}
	slot, err := testDecodeFile(want, true)
	if err != nil {
		t.Fatal(err)
	}
	// plan-SEARCH-index-format-bytes#2: one order by key, a ref_id taking its place among the doc_keys
	if first := slot.entries[0]; first.kind != indexEntryRefTombstone || first.key != ([indexIdByteCount]byte{}) {
		t.Errorf("the first entry is kind %d", first.kind)
	}
	if last := slot.entries[len(slot.entries)-1]; last.kind != indexEntryRefTombstone {
		t.Errorf("the last entry is kind %d", last.kind)
	}
	for index := 1; index < len(slot.entries); index += 1 {
		if 0 <= bytes.Compare(slot.entries[index-1].key[:], slot.entries[index].key[:]) {
			t.Errorf("entry %d is out of order", index)
		}
	}
}

func TestEncoderKeepsOneEntryAKey(t *testing.T) {
	tombstone := &indexEntry{kind: indexEntryTombstone, key: testIndexId("doc", 1), version: 1}
	newer := &indexEntry{kind: indexEntryTombstone, key: testIndexId("doc", 1), version: 2}
	slot := &indexSlot{header: testSlotHeader(indexFileSlot), entries: []*indexEntry{tombstone, newer}}
	if file, err := indexEncodeSlot(slot, false, DefaultIndexFormatSettings()); !errors.Is(err, errIndexMalformed) {
		t.Errorf("encoded to %d bytes", len(file))
	}
	// plan-SEARCH-index-format-bytes#2's one entry a key holds across kinds, a ref_id equal to a doc_key included
	ref := &indexEntry{kind: indexEntryRefTombstone, key: testIndexId("doc", 1), version: 3}
	slot.entries = []*indexEntry{ref, tombstone}
	file, err := indexEncodeSlot(slot, true, DefaultIndexFormatSettings())
	if !errors.Is(err, errIndexMalformed) {
		t.Errorf("encoded to %d bytes", len(file))
	}
	body := []byte{}
	for _, entry := range []*indexEntry{tombstone, ref} {
		if body, err = entry.appendEncoded(body, true); err != nil {
			t.Fatal(err)
		}
	}
	decoded, err := testDecodeFile(testRawFile(t, testFilledHeader(indexFileSlot, 2, body), body, nil), true)
	if !errors.Is(err, errIndexMalformed) {
		t.Errorf("decoded to %+v", decoded)
	}
}

// Coverage arrives from its writer in any order and leaves sorted, and a header keeps its order on decode.
func TestEncoderSortsCoverage(t *testing.T) {
	header := testSlotHeader(indexFileSlot)
	a, b := testIndexIdBytes("a", 1), testIndexIdBytes("b", 1)
	if 0 < bytes.Compare(a, b) {
		a, b = b, a
	}
	header.Coverage = []*protocol.IndexCoverage{{RefId: b, Version: 2}, {RefId: a, Version: 1, Horizon: true}}
	file, err := indexEncodeSlot(&indexSlot{header: header}, false, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	slot, err := testDecodeFile(file, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(slot.header.Coverage[0].RefId, a) || !bytes.Equal(slot.header.Coverage[1].RefId, b) {
		t.Error("coverage is not sorted")
	}
	if !bytes.Equal(header.Coverage[0].RefId, b) {
		t.Error("the caller's header was sorted in place")
	}
}

// The 16,208th byte is the slot's last, by entries or by pad.
func TestSlotCap(t *testing.T) {
	full := testSlotOfLength(t, DefaultIndexFormatSettings().SlotMaxByteCount)
	file, err := indexEncodeSlot(full, false, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	if len(file) != DefaultIndexFormatSettings().SlotMaxByteCount {
		t.Fatalf("%d bytes", len(file))
	}
	if _, err := testDecodeFile(file, false); err != nil {
		t.Error(err)
	}
	full.padByteCount = 1
	if file, err := indexEncodeSlot(full, false, DefaultIndexFormatSettings()); !errors.Is(err, errIndexMalformed) {
		t.Errorf("one past encoded to %d bytes", len(file))
	}
	if slot, err := testDecodeFile(append(slices.Clone(file), 0), false); !errors.Is(err, errIndexMalformed) {
		t.Errorf("one past decoded to %+v", slot)
	}
}

// §11.14's seal and large rows: 8 KiB is a slot entry's cap and a large entry's floor, with nothing between.
func TestEntrySizeDecidesItsFile(t *testing.T) {
	// a key set of 1-byte gaps sized to bring the encoded entry to byteCount
	entryOf := func(byteCount int) *indexEntry {
		count := byteCount - 100
		for {
			keys := testIndexKeys(0, count, 1)
			entry := &indexEntry{kind: indexEntryFull, key: testIndexId("size", 1), version: 1, row: testFileRow(keys), keys: keys}
			encoded, err := entry.appendEncoded(nil, false)
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) == byteCount {
				return entry
			}
			count += byteCount - len(encoded)
		}
	}
	inSlot := &indexSlot{header: testSlotHeader(indexFileSlot), entries: []*indexEntry{entryOf(DefaultIndexFormatSettings().SlotEntryMaxByteCount)}}
	if _, err := indexEncodeSlot(inSlot, false, DefaultIndexFormatSettings()); err != nil {
		t.Errorf("8 KiB in a slot: %v", err)
	}
	inSlot.entries = []*indexEntry{entryOf(DefaultIndexFormatSettings().SlotEntryMaxByteCount + 1)}
	if _, err := indexEncodeSlot(inSlot, false, DefaultIndexFormatSettings()); !errors.Is(err, errIndexMalformed) {
		t.Errorf("past 8 KiB in a slot: %v", err)
	}
	large := &indexSlot{header: testSlotHeader(indexFileLargeEntry), entries: []*indexEntry{entryOf(DefaultIndexFormatSettings().SlotEntryMaxByteCount + 1)}}
	file, err := indexEncodeSlot(large, false, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatalf("past 8 KiB alone: %v", err)
	}
	if _, err := testDecodeFile(file, false); err != nil {
		t.Errorf("past 8 KiB alone: %v", err)
	}
	large.entries = []*indexEntry{entryOf(DefaultIndexFormatSettings().SlotEntryMaxByteCount)}
	if _, err := indexEncodeSlot(large, false, DefaultIndexFormatSettings()); !errors.Is(err, errIndexMalformed) {
		t.Errorf("8 KiB alone: %v", err)
	}
	large.entries = []*indexEntry{}
	if _, err := indexEncodeSlot(large, false, DefaultIndexFormatSettings()); !errors.Is(err, errIndexMalformed) {
		t.Errorf("no entry: %v", err)
	}
	other := *entryOf(DefaultIndexFormatSettings().SlotEntryMaxByteCount + 1)
	other.key = testIndexId("size", 2)
	large.entries = []*indexEntry{entryOf(DefaultIndexFormatSettings().SlotEntryMaxByteCount + 1), &other}
	if _, err := indexEncodeSlot(large, false, DefaultIndexFormatSettings()); !errors.Is(err, errIndexMalformed) {
		t.Errorf("two entries: %v", err)
	}
	// the same bytes by hand, since the encoder refusing proves nothing about the decoder
	one, err := entryOf(DefaultIndexFormatSettings().SlotEntryMaxByteCount+1).appendEncoded(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	two, err := other.appendEncoded(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(one[1:17], two[1:17]) > 0 {
		one, two = two, one
	}
	body := append(slices.Clone(one), two...)
	if slot, err := testDecodeFile(testRawFile(t, testFilledHeader(indexFileLargeEntry, 2, body), body, nil), false); !errors.Is(err, errIndexMalformed) {
		t.Errorf("two entries decoded to %+v", slot)
	}
	if slot, err := testDecodeFile(testRawFile(t, testFilledHeader(indexFileSlot, 1, one), one, nil), false); !errors.Is(err, errIndexMalformed) {
		t.Errorf("a large entry in a slot decoded to %+v", slot)
	}
}

// §11.14's large row, and a CLOSURE's pad may reach it too but not pass it.
func TestLargeEntryCap(t *testing.T) {
	large := &indexSlot{header: testSlotHeader(indexFileLargeEntry), entries: []*indexEntry{testLargeEntry()}}
	file, err := indexEncodeSlot(large, false, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	large.padByteCount = DefaultIndexFormatSettings().LargeMaxByteCount - len(file)
	file, err = indexEncodeSlot(large, false, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	if len(file) != DefaultIndexFormatSettings().LargeMaxByteCount {
		t.Fatalf("%d bytes", len(file))
	}
	if _, err := testDecodeFile(file, false); err != nil {
		t.Error(err)
	}
	if slot, err := testDecodeFile(append(slices.Clone(file), 0), false); !errors.Is(err, errIndexMalformed) {
		t.Errorf("one past decoded to %+v", slot)
	}
}

// A pad's length is an input to re-encoding, so a rewrite padded to its replaced length comes back exactly.
func TestPaddedSlotReencodes(t *testing.T) {
	slot := testSlotOfLength(t, 3000)
	slot.padByteCount = 777
	file, err := indexEncodeSlot(slot, false, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := testDecodeFile(file, false)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.padByteCount != 777 {
		t.Errorf("pad %d", decoded.padByteCount)
	}
	again, err := indexEncodeSlot(decoded, false, DefaultIndexFormatSettings())
	if err != nil || !bytes.Equal(again, file) {
		t.Errorf("re-encoded differently: %v", err)
	}
}

// A rewrite that outgrew what it replaces has no pad to give, so its caller's sum arrives negative and is refused.
func TestNegativePadIsRefused(t *testing.T) {
	slot := &indexSlot{header: testSlotHeader(indexFileSlot), padByteCount: -1}
	if file, err := indexEncodeSlot(slot, false, DefaultIndexFormatSettings()); !errors.Is(err, errIndexMalformed) {
		t.Errorf("encoded to %d bytes", len(file))
	}
}

// §22.6: tampering is caught by the plaintext hash before anything parses, so every single-bit flip of a file is
// refused as a hash mismatch, and a wrong or missing hash refuses a good file.
func TestTamperingFailsThePlaintextHash(t *testing.T) {
	file, err := indexEncodeSlot(testSlotCases(t)[0].slot, true, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(file)
	if _, err := indexDecodeSlot(file, sum[:], true, DefaultIndexFormatSettings()); err != nil {
		t.Fatal(err)
	}
	for index := range file {
		for bit := range 8 {
			tampered := slices.Clone(file)
			tampered[index] ^= 1 << bit
			if slot, err := indexDecodeSlot(tampered, sum[:], true, DefaultIndexFormatSettings()); !errors.Is(err, errIndexMalformed) || !strings.Contains(err.Error(), "hash") {
				t.Fatalf("byte %d bit %d: %+v, %v", index, bit, slot, err)
			}
		}
	}
	for _, hash := range [][]byte{nil, {}, sum[:31], make([]byte, 32)} {
		if slot, err := indexDecodeSlot(file, hash, true, DefaultIndexFormatSettings()); !errors.Is(err, errIndexMalformed) {
			t.Errorf("%x decoded to %+v", hash, slot)
		}
	}
}

// §11.14's root decides whether a row holds a ref_id, so a file read under the wrong root is refused, never misread.
func TestWrongRootIsRefused(t *testing.T) {
	cases := testSlotCases(t)
	onIndex, err := indexEncodeSlot(cases[0].slot, true, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	if slot, err := testDecodeFile(onIndex, false); !errors.Is(err, errIndexMalformed) {
		t.Errorf("read off ur/index as %+v", slot)
	}
	inRef, err := indexEncodeSlot(cases[2].slot, false, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	if slot, err := testDecodeFile(inRef, true); !errors.Is(err, errIndexMalformed) {
		t.Errorf("read on ur/index as %+v", slot)
	}
}

// A file's tables are its builder's, read at run time: nothing writes a header's versions but the build.
func TestNewHeaderNamesItsTables(t *testing.T) {
	tables := indexLinkedTables()
	header := indexNewFileHeader(indexFileSlot, tables)
	if header.UnicodeVersion != tables.normVersion || header.TextModuleVersion != tables.textModuleVersion {
		t.Errorf("%+v", header)
	}
	if header.Format != 1 || header.Normalizer != 1 || header.Extractor != 1 || header.Type != indexFileSlot {
		t.Errorf("%+v", header)
	}
}
