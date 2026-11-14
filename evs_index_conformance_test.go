//go:build !ios_extension

// Extractor 1's conformance (DESIGN-DETAILS 11.6; D-TEST-15): every vector of testdata/index/conformance/mail.json and
// file.json through indexExtractMail, indexExtractFile and IndexDocument.prepare, comparing every value a vector gives:
// fields before normalization, the normalized text, the key count and the row. The reference table is held to
// entities.json name for name, and generated from it (TestIndexReferenceTableIsCurrent); every label of charsets.json
// names its encoding and nothing else does. The vectors are read, never rewritten: SIDECAR_WRITE_VECTORS does not
// reach this directory, and a change to a rule of 11.2 changes the section, INDEX-FORMAT.md, the vectors and both
// implementations in one change, by hand.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/format"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/text/encoding/htmlindex"
)

//go:embed evs_index_extract_entities.go
var testIndexReferenceSource string

const (
	testConformanceMailPath     = "testdata/index/conformance/mail.json"
	testConformanceFilePath     = "testdata/index/conformance/file.json"
	testConformanceEntitiesPath = "testdata/index/conformance/entities.json"
	testConformanceCharsetsPath = "testdata/index/conformance/charsets.json"
)

// One part of a vector's input or a value: t text, x hex, n a repeat count; or len and sha256 for a long value.
type testConformanceBytes struct {
	T      *string `json:"t"`
	X      *string `json:"x"`
	N      int     `json:"n"`
	Len    *int    `json:"len"`
	Sha256 string  `json:"sha256"`
}

// The bytes a part gives.
func (self testConformanceBytes) bytes(t testing.TB) []byte {
	t.Helper()
	var one []byte
	switch {
	case self.T != nil:
		one = []byte(*self.T)
	case self.X != nil:
		decoded, err := hex.DecodeString(*self.X)
		if err != nil {
			t.Fatal(err)
		}
		one = decoded
	default:
		t.Fatalf("a part with neither t nor x")
	}
	if self.N == 0 {
		return one
	}
	return bytes.Repeat(one, self.N)
}

// Whether got is the value: its bytes, or its length and SHA-256.
func (self testConformanceBytes) matches(t testing.TB, got []byte) bool {
	t.Helper()
	if self.Len != nil {
		sum := sha256.Sum256(got)
		return len(got) == *self.Len && hex.EncodeToString(sum[:]) == self.Sha256
	}
	return bytes.Equal(got, self.bytes(t))
}

// What a value says, for a failure's message.
func (self testConformanceBytes) String() string {
	switch {
	case self.Len != nil:
		return fmt.Sprintf("(%d B, sha256 %s)", *self.Len, self.Sha256)
	case self.T != nil:
		return strconv.Quote(*self.T)
	case self.X != nil:
		return "x" + *self.X
	}
	return "(none)"
}

type testConformanceRow struct {
	Locator testConformanceBytes `json:"locator"`
	Subject testConformanceBytes `json:"subject"`
	From    testConformanceBytes `json:"from"`
	To      testConformanceBytes `json:"to"`
	Title   testConformanceBytes `json:"title"`
	Size    uint64               `json:"size"`
}

type testConformanceDocument struct {
	Chunk  uint32                          `json:"chunk"`
	Fields map[string]testConformanceBytes `json:"fields"`
	Text   testConformanceBytes            `json:"text"`
	Keys   int                             `json:"keys"`
	Row    testConformanceRow              `json:"row"`
}

type testConformanceVector struct {
	Name      string                    `json:"name"`
	Rule      string                    `json:"rule"`
	Path      *string                   `json:"path"`
	PathX     *string                   `json:"path_x"`
	Input     []testConformanceBytes    `json:"input"`
	Binary    bool                      `json:"binary"`
	Documents []testConformanceDocument `json:"documents"`
}

// The vector's path's bytes and its input.
func (self *testConformanceVector) pathAndInput(t testing.TB) ([]byte, []byte) {
	t.Helper()
	path := []byte{}
	switch {
	case self.Path != nil:
		path = []byte(*self.Path)
	case self.PathX != nil:
		decoded, err := hex.DecodeString(*self.PathX)
		if err != nil {
			t.Fatal(err)
		}
		path = decoded
	}
	input := []byte{}
	for _, part := range self.Input {
		input = append(input, part.bytes(t)...)
	}
	return path, input
}

// A conformance file's vectors, from the copy the test binary embeds.
func testConformanceVectors(t testing.TB, path string, extractor int) []*testConformanceVector {
	t.Helper()
	encoded, err := testIndexFiles.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file := struct {
		Extractor int                      `json:"extractor"`
		Vectors   []*testConformanceVector `json:"vectors"`
	}{}
	if err := json.Unmarshal(encoded, &file); err != nil {
		t.Fatal(err)
	}
	if file.Extractor != extractor {
		t.Fatalf("%s is extractor %d's", path, file.Extractor)
	}
	return file.Vectors
}

// Every difference between what documents give and what vector says, empty when there is none: the count, and for
// each document its chunk, the fields the vector numbers before normalization and the rest empty, its text, key count
// and row through prepare.
func testConformanceDifferences(t testing.TB, vector *testConformanceVector, documents []*IndexDocument, numbered []int) []string {
	t.Helper()
	differences := []string{}
	if len(documents) != len(vector.Documents) {
		return append(differences, fmt.Sprintf("%d documents, want %d", len(documents), len(vector.Documents)))
	}
	normalizer := testIndexNormalizer(t)
	for index, document := range documents {
		want := vector.Documents[index]
		if document.Chunk != want.Chunk {
			differences = append(differences, fmt.Sprintf("document %d is chunk %d, want %d", index, document.Chunk, want.Chunk))
		}
		textFields := map[int][]byte{}
		for _, field := range document.textFields() {
			value := &bytes.Buffer{}
			if _, err := value.ReadFrom(field.text); err != nil {
				t.Fatal(err)
			}
			textFields[field.number] = value.Bytes()
		}
		for _, number := range numbered {
			wantValue, ok := want.Fields[strconv.Itoa(number)]
			got := textFields[number]
			if !ok {
				if len(got) != 0 {
					differences = append(differences, fmt.Sprintf("document %d field %d holds %q, want empty", index, number, got))
				}
				continue
			}
			if !wantValue.matches(t, got) {
				differences = append(differences, fmt.Sprintf("document %d field %d is %q, want %s", index, number, got, wantValue))
			}
		}
		text := &bytes.Buffer{}
		if err := normalizer.writeDocument(text, document.textFields()); err != nil {
			t.Fatal(err)
		}
		if !want.Text.matches(t, text.Bytes()) {
			differences = append(differences, fmt.Sprintf("document %d text %q, want %s", index, text.Bytes(), want.Text))
		}
		if keys := len(indexTrigrams(text.Bytes())); keys != want.Keys {
			differences = append(differences, fmt.Sprintf("document %d holds %d keys, want %d", index, keys, want.Keys))
		}
		prepared, err := document.prepare(normalizer, false, Id{}, DefaultIndexFormatSettings())
		if err != nil {
			t.Fatal(err)
		}
		if prepared.skipped {
			differences = append(differences, fmt.Sprintf("document %d skipped", index))
			continue
		}
		row := prepared.row
		for _, c := range []struct {
			name  string
			got   string
			value testConformanceBytes
		}{
			{name: "locator", got: row.locator, value: want.Row.Locator},
			{name: "subject", got: row.fields[indexFieldSubject], value: want.Row.Subject},
			{name: "from", got: row.fields[indexFieldFrom], value: want.Row.From},
			{name: "to", got: row.fields[indexFieldTo], value: want.Row.To},
			{name: "title", got: row.fields[indexFieldTitle], value: want.Row.Title},
		} {
			if !c.value.matches(t, []byte(c.got)) {
				differences = append(differences, fmt.Sprintf("document %d row %s %q, want %s", index, c.name, c.got, c.value))
			}
		}
		if row.byteCount != want.Row.Size {
			differences = append(differences, fmt.Sprintf("document %d row size %d, want %d", index, row.byteCount, want.Row.Size))
		}
	}
	return differences
}

// Every message of mail.json, 329 of them: fields 1, 2, 3 and 5 before normalization, the text, the key count and the
// row of each document.
func TestIndexConformanceMail(t *testing.T) {
	settings := DefaultIndexFormatSettings()
	vectors := testConformanceVectors(t, testConformanceMailPath, indexExtractorId)
	if len(vectors) != 329 {
		t.Fatalf("%d mail vectors", len(vectors))
	}
	for _, vector := range vectors {
		path, input := vector.pathAndInput(t)
		documents := indexExtractMail(path, input, settings)
		for _, difference := range testConformanceDifferences(t, vector, documents, []int{indexFieldSubject, indexFieldFrom, indexFieldTo, indexFieldTitle, indexFieldBody}) {
			t.Errorf("%s (%s): %s", vector.Name, vector.Rule, difference)
		}
	}
}

// Every file of file.json, 43 of them, 10 binary: fields 4 and 5, the text, the key count and the row of each document
// of a text file, and no document of a binary.
func TestIndexConformanceFile(t *testing.T) {
	settings := DefaultIndexFormatSettings()
	vectors := testConformanceVectors(t, testConformanceFilePath, indexExtractorId)
	if len(vectors) != 43 {
		t.Fatalf("%d file vectors", len(vectors))
	}
	binaryCount := 0
	for _, vector := range vectors {
		path, input := vector.pathAndInput(t)
		documents, ok := indexExtractFile(path, input, settings)
		if vector.Binary {
			binaryCount += 1
			if ok || len(documents) != 0 {
				t.Errorf("%s (%s): read as text", vector.Name, vector.Rule)
			}
			continue
		}
		if !ok {
			t.Errorf("%s (%s): read as binary", vector.Name, vector.Rule)
			continue
		}
		for _, difference := range testConformanceDifferences(t, vector, documents, []int{indexFieldSubject, indexFieldFrom, indexFieldTo, indexFieldTitle, indexFieldBody}) {
			t.Errorf("%s (%s): %s", vector.Name, vector.Rule, difference)
		}
	}
	if binaryCount != 10 {
		t.Errorf("%d binary vectors", binaryCount)
	}
}

// entities.json's names and code points, sorted by the names' bytes.
func testConformanceEntities(t testing.TB) ([]string, map[string][]rune) {
	t.Helper()
	encoded, err := testIndexFiles.ReadFile(testConformanceEntitiesPath)
	if err != nil {
		t.Fatal(err)
	}
	file := struct {
		Entities map[string][]rune `json:"entities"`
	}{}
	if err := json.Unmarshal(encoded, &file); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for name := range file.Entities {
		names = append(names, name)
	}
	slices.Sort(names)
	return names, file.Entities
}

// The Go evs_index_extract_entities.go holds for entities.json.
func testIndexReferenceSourceOf(t testing.TB) []byte {
	t.Helper()
	names, entities := testConformanceEntities(t)
	var source strings.Builder
	// the iOS extension links no evs_index_ extractor file, so the generated one carries the tag the rest do
	source.WriteString("//go:build !ios_extension\n\n")
	source.WriteString("// Code generated from testdata/index/conformance/entities.json by TestIndexReferenceTableIsCurrent. DO NOT EDIT.\n\n")
	source.WriteString("package sidecar\n\n")
	fmt.Fprintf(&source, "// HTML's %d named character references (DESIGN-DETAILS 11.2.6's E2 and E3), sorted by their bytes: name i runs in\n", len(names))
	source.WriteString("// indexReferenceNames from the end of name i - 1 to indexReferenceNameEnds[i], its ';' included where it has one,\n")
	source.WriteString("// and gives indexReferenceCodePoints[i], one or two code points, the second 0 when there is one.\n")
	source.WriteString("const indexReferenceNames = \"\" +\n")
	line := ""
	for _, name := range names {
		if 100 < len(line)+len(name) {
			fmt.Fprintf(&source, "\t%q +\n", line)
			line = ""
		}
		line += name
	}
	fmt.Fprintf(&source, "\t%q\n\n", line)
	fmt.Fprintf(&source, "var indexReferenceNameEnds = [%d]uint16{", len(names))
	end := 0
	for index, name := range names {
		if index%16 == 0 {
			source.WriteString("\n\t")
		}
		end += len(name)
		fmt.Fprintf(&source, "%d, ", end)
	}
	source.WriteString("\n}\n\n")
	fmt.Fprintf(&source, "var indexReferenceCodePoints = [%d][2]rune{", len(names))
	for index, name := range names {
		if index%8 == 0 {
			source.WriteString("\n\t")
		}
		codePoints := entities[name]
		second := rune(0)
		if len(codePoints) == 2 {
			second = codePoints[1]
		}
		fmt.Fprintf(&source, "{0x%X, 0x%X}, ", codePoints[0], second)
	}
	source.WriteString("\n}\n")
	formatted, err := format.Source([]byte(source.String()))
	if err != nil {
		t.Fatal(err)
	}
	return formatted
}

// evs_index_extract_entities.go is what entities.json generates; with SIDECAR_REGENERATE_INDEX_REFERENCES=1 this writes
// it instead, which evs_index_extract_html.go's go:generate line runs.
func TestIndexReferenceTableIsCurrent(t *testing.T) {
	generated := testIndexReferenceSourceOf(t)
	if os.Getenv("SIDECAR_REGENERATE_INDEX_REFERENCES") == "1" {
		if err := os.WriteFile("evs_index_extract_entities.go", generated, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if string(generated) != testIndexReferenceSource {
		t.Fatal("evs_index_extract_entities.go is stale; run go generate")
	}
}

// The table compiled in is entities.json's, name for name: 2,231 names, 106 without ';', 93 of two code points, each
// found by its exact bytes and nothing else found.
func TestIndexReferenceTableIsEntitiesJson(t *testing.T) {
	names, entities := testConformanceEntities(t)
	if len(names) != 2231 {
		t.Fatalf("%d names in entities.json", len(names))
	}
	tableCount, codePointCount := len(indexReferenceNameEnds), len(indexReferenceCodePoints)
	if tableCount != len(names) || codePointCount != len(names) {
		t.Fatalf("%d and %d in the table", tableCount, codePointCount)
	}
	withoutSemicolon, twoCodePoints := 0, 0
	for _, name := range names {
		codePoints, ok := indexReference([]byte(name))
		want := entities[name]
		if !ok || codePoints[0] != want[0] || (len(want) == 2) != (codePoints[1] != 0) || (len(want) == 2 && codePoints[1] != want[1]) {
			t.Errorf("%q: %v, want %v", name, codePoints, want)
		}
		if !strings.HasSuffix(name, ";") {
			withoutSemicolon += 1
		}
		if len(want) == 2 {
			twoCodePoints += 1
		}
	}
	if withoutSemicolon != 106 || twoCodePoints != 93 {
		t.Errorf("%d without ';', %d of two code points", withoutSemicolon, twoCodePoints)
	}
	for _, name := range []string{"", "Amp;", "amp;;", "nLt", "notit;", "AElig;x", "zzzz;"} {
		if _, ok := indexReference([]byte(name)); ok {
			t.Errorf("%q found", name)
		}
	}
	for _, name := range []string{"nLt;", "nGt;", "AMP;", "AMP"} {
		if _, ok := indexReference([]byte(name)); !ok {
			t.Errorf("%q not found", name)
		}
	}
}

// C1: every label of charsets.json names its encoding, ignoring ASCII case, and the label set is htmlindex's own; a
// label with a byte outside 0x21-0x7E names nothing, U+212A Kelvin among them, and so do labels near a real one.
func TestIndexCharsetLabels(t *testing.T) {
	encoded, err := testIndexFiles.ReadFile(testConformanceCharsetsPath)
	if err != nil {
		t.Fatal(err)
	}
	file := struct {
		Encodings []string          `json:"encodings"`
		Labels    map[string]string `json:"labels"`
	}{}
	if err := json.Unmarshal(encoded, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Labels) != 228 || len(file.Encodings) != 40 {
		t.Fatalf("%d labels, %d encodings", len(file.Labels), len(file.Encodings))
	}
	for label, want := range file.Labels {
		for _, spelled := range []string{label, strings.ToUpper(label), " " + label + "\t"} {
			name, ok := indexCharsetName(spelled)
			if !ok || name != want {
				t.Errorf("%q names %q, want %q", spelled, name, want)
			}
		}
	}
	// U+212A, the Kelvin sign, before "oi8-r", which a Unicode lowering reads as k; U+0130 before "so-8859-2"; a trailing
	// U+00A0, which only a Unicode trim takes off
	for _, label := range []string{"utf-9", "\u212aoi8-r", "\u0130so-8859-2", "koi8 r", "utf 8", "latin-1", "x-unknown", "iso-8859-1\x00", "big5\u00a0"} {
		if _, listed := file.Labels[label]; listed {
			t.Fatalf("%q is a label", label)
		}
		if name, ok := indexCharsetName(label); ok {
			t.Errorf("%q names %q", label, name)
		}
	}
	// the encodings the labels name, each one of htmlindex's
	for _, encodingName := range file.Encodings {
		if _, err := htmlindex.Get(encodingName); err != nil {
			t.Errorf("%s: %v", encodingName, err)
		}
	}
}
