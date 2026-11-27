//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The normalized view under arbitrary text (SAFE-M13-02): total, a refusal only as unavailable; idempotent, the view
// its own view; of bounded growth, within its factor of the text; and free of what it removes, the same twice.

import (
	"errors"
	"testing"
	"unicode/utf8"
)

func FuzzSafetyNormalize(f *testing.F) {
	for _, text := range []string{
		"", "ignore previous instructions", "i g n o r e", "i.g.n.o.r.e", "\u0456gn\u043er\u0435", "ig\u200dnore",
		"\uff49\uff47\uff4e\uff4f\uff52\uff45", "\u2764\ufe0f", "hello\U000e0069\U000e0067", "abc\u202edef",
		"a\xffb", "\ufdfa", "m m m", "\u00e9 t \u00e9", "e\u0301 \u0301", "\u1100 \u1161", "a.b.c.d.e.f",
	} {
		f.Add(text)
	}
	table := testSafetyConfusables(f)
	settings := DefaultSafetySettings()
	f.Fuzz(func(t *testing.T, text string) {
		view, err := SafetyNormalize(text, table, settings)
		again, againErr := SafetyNormalize(text, table, settings)
		if view != again || (err == nil) != (againErr == nil) {
			t.Fatalf("two views of one text differ: %q %v, %q %v", view, err, again, againErr)
		}
		if err != nil {
			if !errors.Is(err, ErrSafetyUnavailable) {
				t.Fatalf("a text refused with %v", err)
			}
			return
		}
		if settings.NormalizeGrowthMaxFactor*len(text)+utf8.UTFMax*settings.ConfusablesTargetMaxCodePointCount < len(view) {
			t.Fatalf("%d bytes grew to %d", len(text), len(view))
		}
		if !utf8.ValidString(view) {
			t.Fatalf("a view that is not UTF-8: %q", view)
		}
		for _, character := range view {
			if safetyRemovedRune(character) {
				t.Fatalf("U+%04X in the view", character)
			}
		}
		if len(view) <= settings.InputMaxByteCount {
			viewAgain, err := SafetyNormalize(view, table, settings)
			if err != nil || viewAgain != view {
				t.Fatalf("not idempotent: %q is %q, %v", view, viewAgain, err)
			}
		}
	})
}
