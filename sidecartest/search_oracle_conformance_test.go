// SEARCH-M10-43's conformance run (DESIGN-DETAILS 11.6): every vector of testdata/index/conformance/'s mail.json and
// file.json through the oracle's own entry points, comparing each document's chunk, its fields before normalization,
// its normalized text, its key count and its row; the oracle's reference table against entities.json, name for name;
// and its label lookup against charsets.json, label for label. The vector files are read, never written: no
// SIDECAR_WRITE_VECTORS reaches them. The reference table is generated from entities.json by
//
//	SIDECAR_REGENERATE_ORACLE_REFERENCES=1 go test -run '^TestSearchOracleReferenceTableIsCurrent$' ./sidecartest
//
// which search_oracle_entities.go's go:generate line runs.

package sidecartest

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
	"unicode/utf8"
)

//go:embed search_oracle_entities.go
var searchOracleEntitiesSourceForTest string

// One value of a vector: text, hex, or the length and SHA-256 of a value too long to print.
type searchConformanceValue struct {
	T      *string `json:"t"`
	X      *string `json:"x"`
	Len    *int    `json:"len"`
	Sha256 string  `json:"sha256"`
}

// Whether got is the value, and how it differs when not.
func (self *searchConformanceValue) check(got []byte) (bool, string) {
	switch {
	case self == nil:
		if len(got) == 0 {
			return true, ""
		}
		return false, fmt.Sprintf("%q, want empty", searchConformanceShow(got))
	case self.T != nil:
		if string(got) == *self.T {
			return true, ""
		}
		return false, fmt.Sprintf("%q, want %q", searchConformanceShow(got), searchConformanceShow([]byte(*self.T)))
	case self.X != nil:
		want, err := hex.DecodeString(*self.X)
		if err != nil {
			return false, "the vector's hex does not decode: " + err.Error()
		}
		if bytes.Equal(got, want) {
			return true, ""
		}
		return false, fmt.Sprintf("%x, want %x", searchConformanceShow(got), want)
	case self.Len != nil:
		sum := sha256.Sum256(got)
		if len(got) == *self.Len && hex.EncodeToString(sum[:]) == self.Sha256 {
			return true, ""
		}
		return false, fmt.Sprintf("%d B sha256 %x, want %d B sha256 %s", len(got), sum, *self.Len, self.Sha256)
	}
	return false, "the vector's value has no form"
}

// A value cut for a failure message.
func searchConformanceShow(value []byte) []byte {
	if 120 < len(value) {
		return append(slices.Clone(value[:120]), "..."...)
	}
	return value
}

// One part of a vector's input: text or hex, repeated n times (once when n is absent).
type searchConformancePart struct {
	T *string `json:"t"`
	X *string `json:"x"`
	N int     `json:"n"`
}

type searchConformanceRow struct {
	Locator *searchConformanceValue `json:"locator"`
	Subject *searchConformanceValue `json:"subject"`
	From    *searchConformanceValue `json:"from"`
	To      *searchConformanceValue `json:"to"`
	Title   *searchConformanceValue `json:"title"`
	Size    uint64                  `json:"size"`
}

type searchConformanceDocument struct {
	Chunk uint32 `json:"chunk"`
	// by field number, an absent one empty
	Fields map[string]*searchConformanceValue `json:"fields"`
	Text   *searchConformanceValue            `json:"text"`
	Keys   int                                `json:"keys"`
	Row    searchConformanceRow               `json:"row"`
}

type searchConformanceVector struct {
	Name      string                       `json:"name"`
	Rule      string                       `json:"rule"`
	Path      *string                      `json:"path"`
	PathX     *string                      `json:"path_x"`
	Input     []*searchConformancePart     `json:"input"`
	Binary    bool                         `json:"binary"`
	Documents []*searchConformanceDocument `json:"documents"`
}

type searchConformanceFile struct {
	About     string                     `json:"about"`
	Extractor int                        `json:"extractor"`
	Vectors   []*searchConformanceVector `json:"vectors"`
}

// The vector's path and input bytes.
func (self *searchConformanceVector) bytes() (string, []byte, error) {
	path := ""
	switch {
	case self.PathX != nil:
		decoded, err := hex.DecodeString(*self.PathX)
		if err != nil {
			return "", nil, err
		}
		path = string(decoded)
	case self.Path != nil:
		path = *self.Path
	}
	var input []byte
	for _, part := range self.Input {
		var piece []byte
		switch {
		case part.X != nil:
			decoded, err := hex.DecodeString(*part.X)
			if err != nil {
				return "", nil, err
			}
			piece = decoded
		case part.T != nil:
			piece = []byte(*part.T)
		default:
			return "", nil, fmt.Errorf("a part with no form")
		}
		repeat := max(1, part.N)
		for range repeat {
			input = append(input, piece...)
		}
	}
	return path, input, nil
}

func searchConformanceLoad(t testing.TB, name string) *searchConformanceFile {
	data, err := os.ReadFile("../testdata/index/conformance/" + name)
	if err != nil {
		t.Fatal(err)
	}
	file := &searchConformanceFile{}
	if err := json.Unmarshal(data, file); err != nil {
		t.Fatal(err)
	}
	if file.Extractor != 1 {
		t.Fatalf("%s is extractor %d's, the oracle reads extractor 1", name, file.Extractor)
	}
	if len(file.Vectors) == 0 {
		t.Fatalf("%s holds no vectors: the run would pass vacuously", name)
	}
	return file
}

// The count of distinct 3-byte windows of text (normalizer 1's key set, N8).
func searchConformanceKeyCount(text string) int {
	keys := map[uint32]bool{}
	for i := 0; i+3 <= len(text); i += 1 {
		keys[uint32(text[i])<<16|uint32(text[i+1])<<8|uint32(text[i+2])] = true
	}
	return len(keys)
}

// How a document the oracle gave differs from the vector's, or nil.
func searchConformanceDiffer(got *searchOracleDocument, want *searchConformanceDocument) []string {
	differences := []string{}
	if got.chunk != want.Chunk {
		differences = append(differences, fmt.Sprintf("chunk %d, want %d", got.chunk, want.Chunk))
	}
	for field := 1; field <= 5; field += 1 {
		if ok, why := want.Fields[strconv.Itoa(field)].check(got.fields[field]); !ok {
			differences = append(differences, fmt.Sprintf("field %d %s", field, why))
		}
	}
	if ok, why := want.Text.check([]byte(got.text)); !ok {
		differences = append(differences, "text "+why)
	}
	if keys := searchConformanceKeyCount(got.text); keys != want.Keys {
		differences = append(differences, fmt.Sprintf("%d keys, want %d", keys, want.Keys))
	}
	for i, value := range []*searchConformanceValue{want.Row.Locator, want.Row.Subject, want.Row.From, want.Row.To, want.Row.Title} {
		if ok, why := value.check([]byte(got.row[i])); !ok {
			differences = append(differences, fmt.Sprintf("row %s %s", []string{"locator", "subject", "from", "to", "title"}[i], why))
		}
	}
	if got.byteCount != want.Row.Size {
		differences = append(differences, fmt.Sprintf("row size %d, want %d", got.byteCount, want.Row.Size))
	}
	return differences
}

// Runs every vector of name through extract and returns the names of those that fail, reporting each difference.
func searchConformanceRun(t *testing.T, name string, extract func(path string, content []byte) []*searchOracleDocument) []string {
	file := searchConformanceLoad(t, name)
	failed := []string{}
	for _, vector := range file.Vectors {
		path, input, err := vector.bytes()
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		documents := extract(path, input)
		differences := []string{}
		switch {
		case vector.Binary && documents != nil:
			differences = append(differences, fmt.Sprintf("binary, but %d documents", len(documents)))
		case vector.Binary:
		case len(documents) != len(vector.Documents):
			differences = append(differences, fmt.Sprintf("%d documents, want %d", len(documents), len(vector.Documents)))
		default:
			for i, document := range documents {
				for _, difference := range searchConformanceDiffer(document, vector.Documents[i]) {
					differences = append(differences, fmt.Sprintf("document %d: %s", i, difference))
				}
				if (name == "file.json") != (document.kind == SearchDocKindFile) {
					differences = append(differences, fmt.Sprintf("document %d: kind %d", i, document.kind))
				}
			}
		}
		if len(differences) != 0 {
			failed = append(failed, vector.Name)
			t.Errorf("%s (%s): %s", vector.Name, vector.Rule, strings.Join(differences, "; "))
		}
	}
	return failed
}

func TestSearchOracleMailConformance(t *testing.T) {
	settings := DefaultSearchOracleExtractSettings()
	if failed := searchConformanceRun(t, "mail.json", func(path string, content []byte) []*searchOracleDocument {
		return searchOracleMailDocuments(path, content, settings)
	}); len(failed) != 0 {
		t.Errorf("%d mail vectors fail: %s", len(failed), strings.Join(failed, " "))
	}
}

func TestSearchOracleFileConformance(t *testing.T) {
	settings := DefaultSearchOracleExtractSettings()
	if failed := searchConformanceRun(t, "file.json", func(path string, content []byte) []*searchOracleDocument {
		return searchOracleFileDocuments(path, content, settings)
	}); len(failed) != 0 {
		t.Errorf("%d file vectors fail: %s", len(failed), strings.Join(failed, " "))
	}
}

// entities.json's names and their code points.
func searchConformanceEntities(t *testing.T) map[string][]rune {
	data, err := os.ReadFile("../testdata/index/conformance/entities.json")
	if err != nil {
		t.Fatal(err)
	}
	file := struct {
		Entities map[string][]rune `json:"entities"`
	}{}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	return file.Entities
}

// The Go search_oracle_entities.go holds for entities.
func searchOracleReferenceTableSource(entities map[string][]rune) ([]byte, error) {
	var source strings.Builder
	source.WriteString("// Code generated from testdata/index/conformance/entities.json by TestSearchOracleReferenceTableIsCurrent. DO NOT EDIT.\n\n")
	source.WriteString("//go:generate env SIDECAR_REGENERATE_ORACLE_REFERENCES=1 go test -run ^TestSearchOracleReferenceTableIsCurrent$ .\n\n")
	source.WriteString("package sidecartest\n\n")
	source.WriteString("// HTML's named character references (DESIGN-DETAILS 11.2.6's E2 and E3), each name with its ';' where it has one,\n")
	source.WriteString("// as the UTF-8 of its one or two code points: the oracle's own copy of entities.json, which shares nothing with the\n")
	source.WriteString("// index's table.\n")
	source.WriteString("var searchOracleReferenceTable = map[string]string{\n")
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for name := range entities {
			if !yield(name) {
				return
			}
		}
	}) {
		fmt.Fprintf(&source, "\t%s: %s,\n", strconv.Quote(name), strconv.QuoteToASCII(string(entities[name])))
	}
	source.WriteString("}\n")
	return format.Source([]byte(source.String()))
}

// search_oracle_entities.go is what entities.json generates, and the table compiled in is the file's, name for name;
// with SIDECAR_REGENERATE_ORACLE_REFERENCES=1 this writes it instead.
func TestSearchOracleReferenceTableIsCurrent(t *testing.T) {
	entities := searchConformanceEntities(t)
	if len(entities) != 2231 {
		t.Fatalf("entities.json holds %d names, DESIGN-DETAILS 11.2.1 2,231", len(entities))
	}
	generated, err := searchOracleReferenceTableSource(entities)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("SIDECAR_REGENERATE_ORACLE_REFERENCES") == "1" {
		if err := os.WriteFile("search_oracle_entities.go", generated, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if string(generated) != searchOracleEntitiesSourceForTest {
		t.Fatal("search_oracle_entities.go is stale; run go generate")
	}
	if len(searchOracleReferenceTable) != len(entities) {
		t.Fatalf("the table holds %d names, entities.json %d", len(searchOracleReferenceTable), len(entities))
	}
	withoutSemicolon, twoCodePoints := 0, 0
	for name, codePoints := range entities {
		value, ok := searchOracleReferenceTable[name]
		if !ok {
			t.Errorf("%q missing from the table", name)
			continue
		}
		if !slices.Equal([]rune(value), codePoints) || !utf8.ValidString(value) {
			t.Errorf("%q gives %U, want %U", name, []rune(value), codePoints)
		}
		if !strings.HasSuffix(name, ";") {
			withoutSemicolon += 1
		}
		if len(codePoints) == 2 {
			twoCodePoints += 1
		}
	}
	// 11.2.1's counts: 106 of them also without their ';', 93 two code points
	if withoutSemicolon != 106 || twoCodePoints != 93 {
		t.Errorf("%d names without ';' and %d of two code points, want 106 and 93", withoutSemicolon, twoCodePoints)
	}
	if searchOracleLegacyNameByteCount != 6 {
		t.Errorf("the longest name without ';' is %d B, HTML's is 6", searchOracleLegacyNameByteCount)
	}
}

// Every label of charsets.json names its encoding through the oracle's lookup, ignoring ASCII case and white bytes
// around it (C1), and no other label names one: not one cut, lengthened, holding a white byte inside, or spelled with
// a code point outside 0x21 to 0x7E that Unicode case maps onto a label (11.1 B's c-label-not-ascii).
func TestSearchOracleCharsetLabels(t *testing.T) {
	data, err := os.ReadFile("../testdata/index/conformance/charsets.json")
	if err != nil {
		t.Fatal(err)
	}
	file := struct {
		Encodings []string          `json:"encodings"`
		Labels    map[string]string `json:"labels"`
	}{}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Labels) != 228 || len(file.Encodings) != 40 {
		t.Fatalf("charsets.json holds %d labels and %d encodings, DESIGN-DETAILS 11.2.1 228 and 40", len(file.Labels), len(file.Encodings))
	}
	named := map[string]bool{}
	for label, encodingName := range file.Labels {
		for _, spelled := range []string{label, strings.ToUpper(label), " \t" + label + "\r\n", "\v" + label + "\f"} {
			_, name, ok := searchOracleCharset([]byte(spelled))
			if !ok || name != encodingName {
				t.Errorf("label %q: %q %v, want %q", spelled, name, ok, encodingName)
			}
		}
		named[encodingName] = true
		for _, spelled := range []string{label + "x", label[:len(label)-1], "x" + label, label[:1] + " " + label[1:], label + "\x00",
			strings.Replace(label, "k", "K", 1), strings.Replace(label, "i", "İ", 1), label + " "} {
			if _, ok := file.Labels[strings.ToLower(spelled)]; ok {
				continue
			}
			if _, name, ok := searchOracleCharset([]byte(spelled)); ok {
				t.Errorf("label %q names %q", spelled, name)
			}
		}
	}
	if len(named) != len(file.Encodings) {
		t.Errorf("the labels name %d encodings, want %d", len(named), len(file.Encodings))
	}
	for _, label := range []string{"", " ", "x-unknown", "utf 8"} {
		if _, name, ok := searchOracleCharset([]byte(label)); ok {
			t.Errorf("label %q names %q", label, name)
		}
	}
}
