//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The confusables table (safety_confusables.go; SAFE-M13-02): a synthetic excerpt of Unicode's confusables.txt read
// whole, and each way a table is refused.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The synthetic table the normalizer's tests read.
func testSafetyConfusables(t testing.TB) *SafetyConfusables {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "safety", "normalize", "confusables.txt"))
	if err != nil {
		t.Fatal(err)
	}
	table, err := LoadSafetyConfusables(data, DefaultSafetySettings())
	if err != nil {
		t.Fatal(err)
	}
	return table
}

// The excerpt, its byte order mark and comments passed over: each line's source to its prototype.
func TestSafetyConfusablesLoads(t *testing.T) {
	table := testSafetyConfusables(t)
	if table.EntryCount() != 13 {
		t.Errorf("%d entries, want 13", table.EntryCount())
	}
	for source, prototype := range map[rune]string{0x0456: "i", 0x043e: "o", 'm': "rn", '0': "O", 0x2024: "."} {
		if got := table.prototypes[source]; got != prototype {
			t.Errorf("U+%04X maps to %q, want %q", source, got, prototype)
		}
	}
}

// Each refusal: a line of two fields, a source twice, a surrogate, an unknown type, a file not UTF-8 or of no entry,
// and the settings' bounds on the bytes, the entries and a prototype's length.
func TestSafetyConfusablesRefusals(t *testing.T) {
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join("testdata", "safety", "normalize", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	whole := read("confusables.txt")
	cases := []struct {
		name     string
		data     []byte
		settings func(settings *SafetySettings)
	}{
		{name: "two fields", data: read("bad-fields.txt")},
		{name: "a source twice", data: read("bad-twice.txt")},
		{name: "a surrogate", data: read("bad-scalar.txt")},
		{name: "an unknown type", data: read("bad-type.txt")},
		{name: "not UTF-8", data: []byte("0456 ;\t0069 ;\tMA\t# \xff\n")},
		{name: "no entry", data: []byte("# only a comment\n\n")},
		{name: "a source of two code points", data: []byte("0456 0457 ;\t0069 ;\tMA\n")},
		{name: "a short code point", data: []byte("456 ;\t0069 ;\tMA\n")},
		{name: "past its bytes", data: whole, settings: func(settings *SafetySettings) {
			settings.ConfusablesMaxByteCount = len(whole) - 1
		}},
		{name: "past its entries", data: whole, settings: func(settings *SafetySettings) {
			settings.ConfusablesMaxEntryCount = 12
		}},
		{name: "a prototype too long", data: whole, settings: func(settings *SafetySettings) {
			settings.ConfusablesTargetMaxCodePointCount = 1
		}},
	}
	for _, c := range cases {
		settings := DefaultSafetySettings()
		if c.settings != nil {
			c.settings(settings)
		}
		table, err := LoadSafetyConfusables(c.data, settings)
		if table != nil || !errors.Is(err, ErrSafetyConfusablesInvalid) || !errors.Is(err, ErrSafetyUnavailable) {
			t.Errorf("%s: %v, want a refusal", c.name, err)
		}
	}
	// the error names the line, never the file's bytes
	_, err := LoadSafetyConfusables(read("bad-twice.txt"), DefaultSafetySettings())
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("%v, want line 2 named", err)
	}
}
