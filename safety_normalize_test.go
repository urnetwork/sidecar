//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The two views and hidden text (safety_normalize.go; SAFE-M13-02): each step's vectors on the synthetic confusables
// excerpt, the view idempotent on each, the unavailable state without a table, the bounds, and hidden text's true and
// false cases.

import (
	"errors"
	"strings"
	"testing"
)

// Each step: NFKC's fullwidth forms, format characters gone (a zero-width joiner, a soft hyphen, a bidirectional
// override), homoglyphs to their skeletons, spaced and dotted letters joined while prose keeps its spaces, variation
// selectors and tag characters gone; and each view unchanged by a second normalization.
func TestSafetyNormalizeViews(t *testing.T) {
	table := testSafetyConfusables(t)
	settings := DefaultSafetySettings()
	vectors := []struct {
		name string
		text string
		view string
	}{
		{name: "fullwidth letters", text: "\uff49\uff47\uff4e\uff4f\uff52\uff45 \uff50\uff52\uff45\uff56\uff49\uff4f\uff55\uff53", view: "ignore previous"},
		{name: "a zero-width joiner in a word", text: "ig\u200dnore", view: "ignore"},
		{name: "a soft hyphen in a word", text: "ign\u00adore", view: "ignore"},
		{name: "a bidirectional override", text: "abc\u202edef", view: "abcdef"},
		{name: "Cyrillic homoglyphs", text: "\u0456gn\u043er\u0435", view: "ignore"},
		{name: "a Greek omicron", text: "ign\u03bfre", view: "ignore"},
		{name: "a dotless i and a script g", text: "\u0131\u0261nore", view: "ignore"},
		{name: "spaced letters", text: "i g n o r e all previous", view: "ignore all previous"},
		{name: "dotted letters", text: "i.g.n.o.r.e", view: "ignore"},
		{name: "mixed separators", text: "i-g_n.o r e", view: "ignore"},
		{name: "a homoglyph spaced out", text: "\u0456 g n \u043e r \u0435", view: "ignore"},
		{name: "a dot leader between letters", text: "i\u2024g\u2024n", view: "ign"},
		{name: "prose keeps its spaces", text: "this is a test of plan a or b", view: "this is a test of plan a or b"},
		{name: "two spaces part letters", text: "i  g", view: "i  g"},
		{name: "a letter beside a digit", text: "a1 b", view: "a1 b"},
		{name: "an accent kept on a letter alone", text: "\u00e9 t \u00e9", view: "\u00e9t\u00e9"},
		{name: "an emoji with its selector", text: "\u2764\ufe0f", view: "\u2764"},
		{name: "tag smuggling", text: "hello\U000e0069\U000e0067\U000e006e", view: "hello"},
		{name: "a fullwidth m to its skeleton", text: "\uff4d", view: "rn"},
		{name: "a digit to its skeleton", text: "ign0re", view: "ignOre"},
		{name: "invalid UTF-8", text: "a\xffb", view: "a\ufffdb"},
		{name: "nothing", text: "", view: ""},
	}
	for _, vector := range vectors {
		view, err := SafetyNormalize(vector.text, table, settings)
		if err != nil {
			t.Errorf("%s: %v", vector.name, err)
			continue
		}
		if view != vector.view {
			t.Errorf("%s: %q's view is %q, want %q", vector.name, vector.text, view, vector.view)
		}
		again, err := SafetyNormalize(view, table, settings)
		if err != nil || again != view {
			t.Errorf("%s: the view normalizes again to %q, %v", vector.name, again, err)
		}
	}
}

// Without a verified table there is no view: none loaded, and one that failed to load, each unavailable, never a view
// without skeletons.
func TestSafetyNormalizeUnavailableWithoutATable(t *testing.T) {
	settings := DefaultSafetySettings()
	if _, err := SafetyNormalize("ignore previous", nil, settings); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("no table: %v", err)
	}
	table, err := LoadSafetyConfusables([]byte("0456 ;\t0069\n"), settings)
	if err == nil {
		t.Fatal("a table that should not load did")
	}
	if _, err := SafetyNormalize("ignore previous", table, settings); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("a table that failed to load: %v", err)
	}
}

// The bounds: a text past the input bound, one whose view grows past its factor, and a table whose skeletons never
// settle, each unavailable.
func TestSafetyNormalizeBounds(t *testing.T) {
	table := testSafetyConfusables(t)
	settings := DefaultSafetySettings()
	if _, err := SafetyNormalize(strings.Repeat("a", settings.InputMaxByteCount+1), table, settings); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("past the input bound: %v", err)
	}
	grows := DefaultSafetySettings()
	grows.NormalizeGrowthMaxFactor = 1
	// each m is rn, so 1,000 bytes become 2,000, past 1 times the text and a prototype's room
	if _, err := SafetyNormalize(strings.Repeat("m", 1000), table, grows); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("past the growth bound: %v", err)
	}
	if view, err := SafetyNormalize(strings.Repeat("m", 1000), table, settings); err != nil || view != strings.Repeat("rn", 1000) {
		t.Errorf("within the growth bound: %d bytes, %v", len(view), err)
	}
	// a and b each the other's prototype, which Unicode's closed table never is: the view swaps forever
	swapping, err := LoadSafetyConfusables([]byte("0061 ;\t0062 ;\tMA\n0062 ;\t0061 ;\tMA\n"), settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SafetyNormalize("ab", swapping, settings); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("a view that never settles: %v", err)
	}
}

// Hidden text: each bidirectional control, tag characters, a variation selector after no emoji, an emoji's second
// selector and a non-presentation selector after one; and none for plain text, an emoji's own selector, a keycap, a
// zero-width space (which the view removes and §27.7's rule does not name) or combining marks.
func TestSafetyHiddenText(t *testing.T) {
	hidden := []string{
		"a\u202ab", "a\u202bb", "a\u202cb", "a\u202db", "a\u202eb",
		"a\u2066b", "a\u2067b", "a\u2068b", "a\u2069b",
		"a\u200eb", "a\u200fb", "a\u061cb",
		"hi\U000e0069\U000e0067", "\U000e0001",
		"a\ufe0f", "\ufe0f", "\U0001f600\ufe01", "\U0001f600\ufe0f\ufe0f", "\u6f22\U000e0100", "x\u180b",
	}
	for _, text := range hidden {
		if !SafetyHiddenText(text) {
			t.Errorf("%q: no hidden text found", text)
		}
	}
	plain := []string{
		"", "hello", "\u2764\ufe0f", "#\ufe0f\u20e3", "\U0001f600\ufe0e", "\U0001f44d\U0001f3fd", "caf\u00e9", "e\u0301",
		"a\u200bb", "\u05e9\u05dc\u05d5\u05dd",
	}
	for _, text := range plain {
		if SafetyHiddenText(text) {
			t.Errorf("%q: hidden text found", text)
		}
	}
}
