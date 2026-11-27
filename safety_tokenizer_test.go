//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The classifier's tokenizer (safety_sentencepiece.go, safety_tokenizer.go; SAFE-M13-01): a synthetic SentencePiece
// model built here, its character map a darts-clone double array this file lays out, and vectors whose ids are worked
// by hand from its scores in the comments beside them. The ids' equality with Prompt Guard 2's own tokenizer over the
// whole corpus is the bench's, with the real vocabulary (External).

import (
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// One piece of a synthetic vocabulary.
type testSafetyPiece struct {
	text  string
	score float32
	kind  safetyPieceType
}

// The synthetic vocabulary's pieces, by id. Scores are chosen so each vector below has one best path.
var testSafetyPieces = []testSafetyPiece{
	{text: "[PAD]", kind: safetyPieceControl},
	{text: "[CLS]", kind: safetyPieceControl},
	{text: "[SEP]", kind: safetyPieceControl},
	{text: "[UNK]", kind: safetyPieceUnknown},
	{text: "\u2581", score: -2, kind: safetyPieceNormal},          // 4
	{text: "a", score: -3, kind: safetyPieceNormal},               // 5
	{text: "b", score: -3, kind: safetyPieceNormal},               // 6
	{text: "ab", score: -4, kind: safetyPieceNormal},              // 7
	{text: "\u2581a", score: -2.5, kind: safetyPieceNormal},       // 8
	{text: "\u2581ab", score: -3, kind: safetyPieceNormal},        // 9
	{text: "c", score: -5, kind: safetyPieceNormal},               // 10
	{text: "\u2581the", score: -1, kind: safetyPieceNormal},       // 11
	{text: "the", score: -2, kind: safetyPieceNormal},             // 12
	{text: "t", score: -4, kind: safetyPieceNormal},               // 13
	{text: "h", score: -4, kind: safetyPieceNormal},               // 14
	{text: "e", score: -4, kind: safetyPieceNormal},               // 15
	{text: "fi", score: -3.5, kind: safetyPieceNormal},            // 16
	{text: "f", score: -4, kind: safetyPieceNormal},               // 17
	{text: "i", score: -4, kind: safetyPieceNormal},               // 18
	{text: "A", score: -3, kind: safetyPieceNormal},               // 19
	{text: "<x>", kind: safetyPieceUserDefined},                   // 20
	{text: "zz", score: -1, kind: safetyPieceUnused},              // 21
	{text: "\u2581\u2581", score: -1.5, kind: safetyPieceNormal},  // 22
	{text: "\u2581b", score: -2.75, kind: safetyPieceNormal},      // 23
	{text: "\u2581\u2603", score: -2.25, kind: safetyPieceNormal}, // 24
}

// The synthetic character map's rules, as NFKC and nmt's whitespace give them: fullwidth A, the fi ligature, the
// no-break space and the tab to a space, and the zero-width space removed.
var testSafetyCharsmapRules = map[string]string{
	"\uff21": "A",
	"\ufb01": "fi",
	"\u00a0": " ",
	"\t":     " ",
	"\u200b": "",
}

// A darts-clone double array over keys, each with its value, laid out by trying each node's bases in turn, as a test's
// own builder: SentencePiece's real maps come from darts-clone's, and the reader walks either alike.
func testSafetyDartsUnits(t testing.TB, keyValues map[string]uint32) []uint32 {
	t.Helper()
	type dartsNode struct {
		children map[byte]*dartsNode
		value    int64
	}
	newNode := func() *dartsNode {
		return &dartsNode{children: map[byte]*dartsNode{}, value: -1}
	}
	root := newNode()
	for key, value := range keyValues {
		node := root
		for i := 0; i < len(key); i += 1 {
			child := node.children[key[i]]
			if child == nil {
				child = newNode()
				node.children[key[i]] = child
			}
			node = child
		}
		node.value = int64(value)
	}
	units := []uint32{0}
	used := []bool{true}
	grow := func(position uint32) {
		for uint32(len(units)) <= position {
			units = append(units, 0)
			used = append(used, false)
		}
	}
	var place func(node *dartsNode, position uint32)
	place = func(node *dartsNode, position uint32) {
		labels := []byte{}
		for label := range node.children {
			labels = append(labels, label)
		}
		slices.Sort(labels)
		slots := []uint32{}
		if 0 <= node.value {
			slots = append(slots, 0)
		}
		for _, label := range labels {
			slots = append(slots, uint32(label))
		}
		base := uint32(1)
		for ; ; base += 1 {
			free := true
			for _, slot := range slots {
				if at := base ^ slot; at < uint32(len(used)) && used[at] {
					free = false
					break
				}
			}
			if free {
				break
			}
		}
		offset := position ^ base
		if 1<<21 <= offset {
			t.Fatalf("a test trie's offset %d needs darts-clone's extended form", offset)
		}
		units[position] |= offset << 10
		if 0 <= node.value {
			units[position] |= 1 << 8
			grow(base)
			used[base] = true
			units[base] = 1<<31 | uint32(node.value)
		}
		for _, label := range labels {
			at := base ^ uint32(label)
			grow(at)
			used[at] = true
			units[at] = uint32(label)
		}
		for _, label := range labels {
			place(node.children[label], base^uint32(label))
		}
	}
	place(root, 0)
	return units
}

// A precompiled character map over rules: the trie's byte count, the trie, then each replacement and its NUL.
func testSafetyCharsmap(t testing.TB, rules map[string]string) []byte {
	t.Helper()
	keys := []string{}
	for key := range rules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	replacements := []byte{}
	keyValues := map[string]uint32{}
	for _, key := range keys {
		keyValues[key] = uint32(len(replacements))
		replacements = append(append(replacements, rules[key]...), 0)
	}
	units := testSafetyDartsUnits(t, keyValues)
	blob := binary.LittleEndian.AppendUint32(nil, uint32(4*len(units)))
	for _, unit := range units {
		blob = binary.LittleEndian.AppendUint32(blob, unit)
	}
	return append(blob, replacements...)
}

// The switches and fields a synthetic model sets beside its pieces; a nil field leaves its default.
type testSafetyModel struct {
	pieces             []testSafetyPiece
	modelType          *uint64
	byteFallback       bool
	whitespaceAsSuffix bool
	charsmap           []byte
	addDummyPrefix     *bool
	removeExtra        *bool
	escapeWhitespaces  *bool
}

// The model as a SentencePiece ModelProto's bytes.
func (self *testSafetyModel) proto() []byte {
	data := []byte{}
	for _, piece := range self.pieces {
		body := protowire.AppendTag(nil, safetySpPiecePiece, protowire.BytesType)
		body = protowire.AppendString(body, piece.text)
		body = protowire.AppendTag(body, safetySpPieceScore, protowire.Fixed32Type)
		body = protowire.AppendFixed32(body, math.Float32bits(piece.score))
		body = protowire.AppendTag(body, safetySpPieceType, protowire.VarintType)
		body = protowire.AppendVarint(body, uint64(piece.kind))
		data = protowire.AppendTag(data, safetySpModelPieces, protowire.BytesType)
		data = protowire.AppendBytes(data, body)
	}
	flag := func(value bool) uint64 {
		if value {
			return 1
		}
		return 0
	}
	trainer := []byte{}
	if self.modelType != nil {
		trainer = protowire.AppendTag(trainer, safetySpTrainerModelType, protowire.VarintType)
		trainer = protowire.AppendVarint(trainer, *self.modelType)
	}
	// a field the reader skips, as it skips every one it does not read
	trainer = protowire.AppendTag(trainer, 4, protowire.VarintType)
	trainer = protowire.AppendVarint(trainer, uint64(len(self.pieces)))
	trainer = protowire.AppendTag(trainer, safetySpTrainerByteFallback, protowire.VarintType)
	trainer = protowire.AppendVarint(trainer, flag(self.byteFallback))
	trainer = protowire.AppendTag(trainer, safetySpTrainerTreatWhitespaceAsSuffix, protowire.VarintType)
	trainer = protowire.AppendVarint(trainer, flag(self.whitespaceAsSuffix))
	data = protowire.AppendTag(data, safetySpModelTrainerSpec, protowire.BytesType)
	data = protowire.AppendBytes(data, trainer)
	normalizer := protowire.AppendTag(nil, 1, protowire.BytesType)
	normalizer = protowire.AppendString(normalizer, "test_nfkc")
	if self.charsmap != nil {
		normalizer = protowire.AppendTag(normalizer, safetySpNormalizerPrecompiledCharsmap, protowire.BytesType)
		normalizer = protowire.AppendBytes(normalizer, self.charsmap)
	}
	for _, field := range []struct {
		number protowire.Number
		value  *bool
	}{
		{number: safetySpNormalizerAddDummyPrefix, value: self.addDummyPrefix},
		{number: safetySpNormalizerRemoveExtraWhitespaces, value: self.removeExtra},
		{number: safetySpNormalizerEscapeWhitespaces, value: self.escapeWhitespaces},
	} {
		if field.value != nil {
			normalizer = protowire.AppendTag(normalizer, field.number, protowire.VarintType)
			normalizer = protowire.AppendVarint(normalizer, flag(*field.value))
		}
	}
	data = protowire.AppendTag(data, safetySpModelNormalizerSpec, protowire.BytesType)
	return protowire.AppendBytes(data, normalizer)
}

// The synthetic model with its character map.
func testSafetyModelWithCharsmap(t testing.TB) *testSafetyModel {
	t.Helper()
	return &testSafetyModel{pieces: slices.Clone(testSafetyPieces), charsmap: testSafetyCharsmap(t, testSafetyCharsmapRules)}
}

// The synthetic vocabulary's tokenizer, on the default settings.
func newTestSafetyTokenizer(t testing.TB, model *testSafetyModel) *SafetyTokenizer {
	t.Helper()
	settings := DefaultSafetySettings()
	vocabulary, err := LoadSafetyVocabulary(model.proto(), settings)
	if err != nil {
		t.Fatal(err)
	}
	tokenizer, err := NewSafetyTokenizer(vocabulary, settings)
	if err != nil {
		t.Fatal(err)
	}
	return tokenizer
}

// The model read back: every piece by id, its scores, types and specials, and the normalizer's switches.
func TestSafetyVocabularyReadsAModelProto(t *testing.T) {
	model := testSafetyModelWithCharsmap(t)
	vocabulary, err := LoadSafetyVocabulary(model.proto(), DefaultSafetySettings())
	if err != nil {
		t.Fatal(err)
	}
	if vocabulary.PieceCount() != len(testSafetyPieces) {
		t.Fatalf("%d pieces, want %d", vocabulary.PieceCount(), len(testSafetyPieces))
	}
	for id, want := range testSafetyPieces {
		if got := vocabulary.pieces[id]; got.text != want.text || got.score != want.score || got.kind != want.kind {
			t.Errorf("piece %d is %+v, want %+v", id, got, want)
		}
	}
	if cls, sep := vocabulary.Specials(); cls != 1 || sep != 2 || vocabulary.unkId != 3 {
		t.Errorf("specials %d %d and unknown %d", cls, sep, vocabulary.unkId)
	}
	// the highest normal score is -1, under FLT_MIN, so the library's highest stays FLT_MIN; the lowest normal is -5
	if vocabulary.maxScore != safetyFloatMinNormal || vocabulary.minScore != -5 {
		t.Errorf("scores %v to %v", vocabulary.minScore, vocabulary.maxScore)
	}
	if !vocabulary.addDummyPrefix || !vocabulary.removeExtraWhitespaces || !vocabulary.escapeWhitespaces || vocabulary.charsmap == nil {
		t.Errorf("the normalizer's defaults: %+v", vocabulary)
	}
	// the unused piece is no match, and the user-defined one is both a match and the normalizer's
	if slices.Contains(vocabulary.matchIds, 21) || !slices.Contains(vocabulary.matchIds, 20) || !slices.Equal(vocabulary.userDefinedIds, []int32{20}) {
		t.Errorf("match ids %v, user-defined %v", vocabulary.matchIds, vocabulary.userDefinedIds)
	}
}

// One text and the ids worked by hand from the synthetic scores.
type testSafetyVector struct {
	name string
	text string
	ids  []int64
}

// The encoder on vectors worked by hand: whitespace, the dummy prefix, an unknown character and an unknown run, the
// character map's NFKC and removal, a user-defined piece and an unused one.
func TestSafetyTokenizerEncodesHandWorkedVectors(t *testing.T) {
	tokenizer := newTestSafetyTokenizer(t, testSafetyModelWithCharsmap(t))
	vectors := []testSafetyVector{
		// "▁ab": ▁ab -3 beats ▁a then b (-5.5) and ▁ then ab (-6)
		{name: "the dummy prefix", text: "ab", ids: []int64{9}},
		// "▁the": ▁the -1 beats ▁ then the (-4)
		{name: "a word", text: "the", ids: []int64{11}},
		// leading, trailing and repeated spaces go: "▁a▁b"; ▁a -2.5 then ▁b -2.75 beats ▁a, ▁, b (-7.5)
		{name: "whitespace", text: "  a   b  ", ids: []int64{8, 23}},
		// "▁azb": ▁a, then z, which no piece covers, unknown at -5 - 10, then b
		{name: "an unknown character", text: "azb", ids: []int64{8, 3, 6}},
		// "▁azzb": the unused zz is no piece, and two unknowns in a row are one unknown id
		{name: "an unknown run", text: "azzb", ids: []int64{8, 3, 6}},
		// the ligature U+FB01 is "fi" by the map: "▁fi", ▁ then fi (-5.5) beats ▁, f, i (-10)
		{name: "the map's NFKC ligature", text: "\ufb01", ids: []int64{4, 16}},
		// fullwidth A is A: "▁Ab", ▁, A, b
		{name: "the map's NFKC fullwidth", text: "\uff21b", ids: []int64{4, 19, 6}},
		// no-break spaces and a tab are spaces, and collapse as spaces do: "▁a▁b"
		{name: "the map's spaces", text: "a\u00a0\u00a0b\t", ids: []int64{8, 23}},
		// the zero-width space maps to nothing: "▁ab"
		{name: "the map's removal", text: "a\u200bb", ids: []int64{9}},
		// "▁<x>ab": <x> passes the normalizer and scores 3 FLT_MIN - 0.1, so ▁ <x> ab (-6.1) beats any unknown path
		{name: "a user-defined piece", text: "<x>ab", ids: []int64{4, 20, 7}},
		// an invalid byte is U+FFFD, which no piece covers: "▁a�b"
		{name: "an invalid byte", text: "a\xffb", ids: []int64{8, 3, 6}},
		// a whole snowman piece: "▁☃" -2.25
		{name: "a piece of several bytes", text: "\u2603", ids: []int64{24}},
		{name: "spaces alone", text: " \u00a0\t ", ids: []int64{}},
		{name: "nothing", text: "", ids: []int64{}},
	}
	for _, vector := range vectors {
		ids, err := tokenizer.Encode(vector.text)
		if err != nil {
			t.Errorf("%s: %v", vector.name, err)
			continue
		}
		if !slices.Equal(ids, vector.ids) {
			t.Errorf("%s: %q encodes to %v, want %v", vector.name, vector.text, ids, vector.ids)
		}
	}
}

// The normalizer's switches off: no dummy prefix, spaces kept, and spaces not escaped.
func TestSafetyTokenizerNormalizerSwitches(t *testing.T) {
	off := false
	model := testSafetyModelWithCharsmap(t)
	model.addDummyPrefix = &off
	model.removeExtra = &off
	tokenizer := newTestSafetyTokenizer(t, model)
	// "a▁▁b": a, then ▁▁ -1.5, then b; with the dummy prefix and extra spaces off nothing goes or is added
	ids, err := tokenizer.Encode("a  b")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ids, []int64{5, 22, 6}) {
		t.Errorf("%v, want a \u2581\u2581 b", ids)
	}
	normalized, err := tokenizer.vocabulary.normalize([]byte(" a "))
	if err != nil || string(normalized) != "\u2581a\u2581" {
		t.Errorf("%q, %v", normalized, err)
	}
	model.escapeWhitespaces = &off
	tokenizer = newTestSafetyTokenizer(t, model)
	normalized, err = tokenizer.vocabulary.normalize([]byte(" a\tb "))
	if err != nil || string(normalized) != " a b " {
		t.Errorf("unescaped: %q, %v", normalized, err)
	}
}

// With byte fallback an unknown character is its bytes' pieces, never the unknown id.
func TestSafetyTokenizerByteFallback(t *testing.T) {
	pieces := []testSafetyPiece{
		{text: "[PAD]", kind: safetyPieceControl},
		{text: "[CLS]", kind: safetyPieceControl},
		{text: "[SEP]", kind: safetyPieceControl},
		{text: "[UNK]", kind: safetyPieceUnknown},
		{text: "\u2581", score: -1, kind: safetyPieceNormal},
		{text: "a", score: -2, kind: safetyPieceNormal},
	}
	const firstByteId = 6
	for value := range 256 {
		pieces = append(pieces, testSafetyPiece{text: testSafetyBytePiece(byte(value)), kind: safetyPieceByte})
	}
	tokenizer := newTestSafetyTokenizer(t, &testSafetyModel{pieces: pieces, byteFallback: true})
	// "▁a☃": ▁, a, then the snowman's three bytes E2 98 83, and the invalid byte's U+FFFD as EF BF BD
	ids, err := tokenizer.Encode("a\u2603\xff")
	if err != nil {
		t.Fatal(err)
	}
	want := []int64{4, 5, firstByteId + 0xe2, firstByteId + 0x98, firstByteId + 0x83, firstByteId + 0xef, firstByteId + 0xbf, firstByteId + 0xbd}
	if !slices.Equal(ids, want) {
		t.Errorf("%v, want %v", ids, want)
	}
}

// The library's name for a byte's piece.
func testSafetyBytePiece(value byte) string {
	const digits = "0123456789ABCDEF"
	return "<0x" + string(digits[value>>4]) + string(digits[value&0xf]) + ">"
}

// Refusals: a file cut short, past its bounds, a model type other than unigram, and each piece the reader refuses.
func TestSafetyVocabularyRefusals(t *testing.T) {
	bpe := uint64(2)
	whole := testSafetyModelWithCharsmap(t).proto()
	withPieces := func(change func(pieces []testSafetyPiece) []testSafetyPiece) []byte {
		return (&testSafetyModel{pieces: change(slices.Clone(testSafetyPieces))}).proto()
	}
	cases := []struct {
		name     string
		data     []byte
		settings func(settings *SafetySettings)
	}{
		{name: "cut short", data: whole[:len(whole)-3]},
		{name: "cut in a piece", data: whole[:5]},
		{name: "past its bytes", data: whole, settings: func(settings *SafetySettings) {
			settings.VocabularyMaxByteCount = len(whole) - 1
		}},
		{name: "past its pieces", data: whole, settings: func(settings *SafetySettings) {
			settings.VocabularyMaxPieceCount = len(testSafetyPieces) - 1
		}},
		{name: "a piece past its bytes", data: whole, settings: func(settings *SafetySettings) {
			settings.VocabularyPieceMaxByteCount = 4
		}},
		{name: "a model type other than unigram", data: (&testSafetyModel{pieces: testSafetyPieces, modelType: &bpe}).proto()},
		{name: "whitespace as a suffix", data: (&testSafetyModel{pieces: testSafetyPieces, whitespaceAsSuffix: true}).proto()},
		{name: "an unknown piece type", data: withPieces(func(pieces []testSafetyPiece) []testSafetyPiece {
			pieces[10].kind = 9
			return pieces
		})},
		{name: "an empty piece", data: withPieces(func(pieces []testSafetyPiece) []testSafetyPiece {
			pieces[10].text = ""
			return pieces
		})},
		{name: "a piece twice", data: withPieces(func(pieces []testSafetyPiece) []testSafetyPiece {
			pieces[10].text = "a"
			return pieces
		})},
		{name: "a piece not UTF-8", data: withPieces(func(pieces []testSafetyPiece) []testSafetyPiece {
			pieces[10].text = "\xff"
			return pieces
		})},
		{name: "a score not a number", data: withPieces(func(pieces []testSafetyPiece) []testSafetyPiece {
			pieces[10].score = float32(math.NaN())
			return pieces
		})},
		{name: "no unknown piece", data: withPieces(func(pieces []testSafetyPiece) []testSafetyPiece {
			pieces[3].kind = safetyPieceControl
			return pieces
		})},
		{name: "two unknown pieces", data: withPieces(func(pieces []testSafetyPiece) []testSafetyPiece {
			pieces[0].kind = safetyPieceUnknown
			return pieces
		})},
		{name: "no [SEP]", data: withPieces(func(pieces []testSafetyPiece) []testSafetyPiece {
			pieces[2].text = "[END]"
			return pieces
		})},
		{name: "a byte piece without byte fallback", data: withPieces(func(pieces []testSafetyPiece) []testSafetyPiece {
			return append(pieces, testSafetyPiece{text: "<0x41>", kind: safetyPieceByte})
		})},
		{name: "byte fallback without its bytes", data: (&testSafetyModel{pieces: append(slices.Clone(testSafetyPieces), testSafetyPiece{text: "<0x41>", kind: safetyPieceByte}), byteFallback: true}).proto()},
		{name: "a character map without its trie", data: (&testSafetyModel{pieces: testSafetyPieces, charsmap: []byte{0xff, 0xff, 0, 0, 1, 2, 3, 4}}).proto()},
		{name: "a character map too short", data: (&testSafetyModel{pieces: testSafetyPieces, charsmap: []byte{4, 0, 0}}).proto()},
		{name: "a field of the wrong wire type", data: protowire.AppendFixed32(protowire.AppendTag(nil, safetySpModelPieces, protowire.Fixed32Type), 1)},
	}
	for _, c := range cases {
		settings := DefaultSafetySettings()
		if c.settings != nil {
			c.settings(settings)
		}
		_, err := LoadSafetyVocabulary(c.data, settings)
		if !errors.Is(err, ErrSafetyVocabularyInvalid) || !errors.Is(err, ErrSafetyUnavailable) {
			t.Errorf("%s: %v, want a refusal", c.name, err)
		}
	}
}

// A character map whose rule points past its replacements loads, since only a search reaches the rule, and then
// refuses the text, never guessing a replacement; a text past the input bound is refused too.
func TestSafetyTokenizerRefusesWhatItCannotRead(t *testing.T) {
	units := testSafetyDartsUnits(t, map[string]uint32{"q": 1000})
	blob := binary.LittleEndian.AppendUint32(nil, uint32(4*len(units)))
	for _, unit := range units {
		blob = binary.LittleEndian.AppendUint32(blob, unit)
	}
	blob = append(blob, 'x', 0)
	tokenizer := newTestSafetyTokenizer(t, &testSafetyModel{pieces: testSafetyPieces, charsmap: blob})
	if _, err := tokenizer.Encode("ab"); err != nil {
		t.Errorf("a text no broken rule reaches: %v", err)
	}
	if _, err := tokenizer.Encode("aqb"); !errors.Is(err, ErrSafetyVocabularyInvalid) || !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("a rule past the replacements: %v", err)
	}
	if _, err := tokenizer.Encode(strings.Repeat("a", tokenizer.settings.InputMaxByteCount+1)); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("a text past the bound: %v", err)
	}
}

// Windows: 510 ids and the two specials in one, 511 in two that share 64 ids, overlap all along a long text, and the
// two specials alone for no text.
func TestSafetyWindows(t *testing.T) {
	settings := DefaultSafetySettings()
	ids := func(count int) []int64 {
		ids := make([]int64, count)
		for i := range ids {
			ids[i] = int64(100 + i)
		}
		return ids
	}
	const cls, sep = 1, 2
	windows, err := SafetyWindows(ids(510), cls, sep, settings)
	if err != nil || len(windows) != 1 || len(windows[0]) != 512 || windows[0][0] != cls || windows[0][511] != sep {
		t.Fatalf("510 ids: %d windows, %v", len(windows), err)
	}
	windows, err = SafetyWindows(ids(511), cls, sep, settings)
	if err != nil || len(windows) != 2 || len(windows[0]) != 512 || len(windows[1]) != 2+511-446 {
		t.Fatalf("511 ids: %d windows, %v", len(windows), err)
	}
	if !slices.Equal(windows[0][1+446:511], windows[1][1:1+64]) || windows[1][len(windows[1])-2] != 100+510 {
		t.Errorf("511 ids: the windows do not share 64 ids")
	}
	long := ids(5000)
	windows, err = SafetyWindows(long, cls, sep, settings)
	if err != nil {
		t.Fatal(err)
	}
	covered := []int64{}
	for i, window := range windows {
		if len(window) < 3 || 512 < len(window) || window[0] != cls || window[len(window)-1] != sep {
			t.Fatalf("window %d of %d ids", i, len(window))
		}
		text := window[1 : len(window)-1]
		if 0 < i {
			previous := windows[i-1][1 : len(windows[i-1])-1]
			if !slices.Equal(previous[len(previous)-64:], text[:64]) {
				t.Errorf("windows %d and %d do not share 64 ids", i-1, i)
			}
			text = text[64:]
		}
		covered = append(covered, text...)
	}
	if !slices.Equal(covered, long) {
		t.Errorf("the windows do not cover the ids once each in order")
	}
	windows, err = SafetyWindows(nil, cls, sep, settings)
	if err != nil || len(windows) != 1 || !slices.Equal(windows[0], []int64{cls, sep}) {
		t.Errorf("no ids: %v, %v", windows, err)
	}
	settings.WindowOverlapTokenCount = settings.WindowTokenCount - 2
	if _, err := SafetyWindows(long, cls, sep, settings); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("an overlap leaving no room: %v", err)
	}
}

// A text's windows through the tokenizer: its ids, cut as SafetyWindows cuts them.
func TestSafetyTokenizerWindows(t *testing.T) {
	tokenizer := newTestSafetyTokenizer(t, testSafetyModelWithCharsmap(t))
	// "▁ab" 600 times: one id each
	windows, err := tokenizer.Windows(strings.Repeat("ab ", 600))
	if err != nil {
		t.Fatal(err)
	}
	if len(windows) != 2 || len(windows[0]) != 512 || len(windows[1]) != 2+600-446 {
		t.Fatalf("%d windows", len(windows))
	}
	for _, window := range windows {
		for _, id := range window[1 : len(window)-1] {
			if id != 9 {
				t.Fatalf("an id %d", id)
			}
		}
	}
}

// Defaults: each of §27's limits as the design and the questions' answers set it.
func TestDefaultSidecarSafetySettings(t *testing.T) {
	settings := DefaultSafetySettings()
	checks := []struct {
		name string
		got  int64
		want int64
	}{
		{name: "WindowTokenCount", got: int64(settings.WindowTokenCount), want: 512},
		{name: "WindowOverlapTokenCount", got: int64(settings.WindowOverlapTokenCount), want: 64},
		{name: "DecisionTimeout", got: int64(settings.DecisionTimeout), want: int64(10 * 1000 * 1000 * 1000)},
		{name: "EngineIdleTimeout", got: int64(settings.EngineIdleTimeout), want: int64(10 * 60 * 1000 * 1000 * 1000)},
		{name: "RunAutoMaxCount", got: int64(settings.RunAutoMaxCount), want: 10},
		{name: "MinuteAutoMaxCount", got: int64(settings.MinuteAutoMaxCount), want: 3},
		{name: "DayAutoMaxCount", got: int64(settings.DayAutoMaxCount), want: 50},
		{name: "DefaultThresholdBasisPoints", got: int64(settings.DefaultThresholdBasisPoints), want: 2000},
		{name: "MaxThresholdBasisPoints", got: int64(settings.MaxThresholdBasisPoints), want: 5000},
		{name: "KnownDestinationDays", got: int64(settings.KnownDestinationDays), want: 90},
		{name: "DigestHour", got: int64(settings.DigestHour), want: 18},
		{name: "AmountRuleNanoUsd", got: settings.AmountRuleNanoUsd, want: 1000 * 1000 * 1000},
		{name: "CopiedSpanMinCharCount", got: int64(settings.CopiedSpanMinCharCount), want: 32},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s is %d, want %d", check.name, check.got, check.want)
		}
	}
	// every number positive, as SidecarSettings.validate holds every settings struct
	if err := checkSettingsNumbers("SafetySettings", reflect.ValueOf(settings), false); err != nil {
		t.Errorf("a default that validate refuses: %v", err)
	}
	if err := safetyCheckWindowSettings(settings); err != nil {
		t.Error(err)
	}
}
