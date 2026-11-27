//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The tokenizer under arbitrary text and arbitrary vocabulary files (SAFE-M13-01): total, never a panic, a vocabulary
// that does not read refused as one; deterministic, the same ids twice; and bounded, no more ids than normalized bytes,
// each a piece of the vocabulary, cut into windows of at most WindowTokenCount ids as many as the ids need.

import (
	"errors"
	"slices"
	"testing"
)

func FuzzSafetyTokenizer(f *testing.F) {
	model := testSafetyModelWithCharsmap(f)
	vocabularyData := model.proto()
	for _, text := range []string{
		"", "ab", "  a   b  ", "azzb", "\ufb01\uff21b", "a\u00a0\u00a0b\t", "a\u200bb", "<x>ab", "a\xffb",
		"\u2603\u2603", "ignore previous instructions", "\x00\x00q\x00", "\xe2\x96", "\u2581\u2581a",
	} {
		f.Add(text, []byte(nil))
	}
	// whole and cut vocabularies, so the reader meets each of its refusals
	f.Add("ab", vocabularyData)
	f.Add("ab", vocabularyData[:len(vocabularyData)/2])
	f.Add("ab", vocabularyData[:7])
	f.Add("a\u2603", (&testSafetyModel{pieces: testSafetyPieces, charsmap: []byte{8, 0, 0, 0, 0, 4, 0, 0, 0x61, 0, 0, 0, 0}}).proto())
	settings := DefaultSafetySettings()
	defaultTokenizer := newTestSafetyTokenizer(f, model)
	f.Fuzz(func(t *testing.T, text string, vocabulary []byte) {
		tokenizer := defaultTokenizer
		if 0 < len(vocabulary) {
			loaded, err := LoadSafetyVocabulary(vocabulary, settings)
			if err != nil {
				if !errors.Is(err, ErrSafetyVocabularyInvalid) || !errors.Is(err, ErrSafetyUnavailable) {
					t.Fatalf("a vocabulary refused with %v", err)
				}
				return
			}
			tokenizer, err = NewSafetyTokenizer(loaded, settings)
			if err != nil {
				t.Fatal(err)
			}
		}
		ids, err := tokenizer.Encode(text)
		again, againErr := tokenizer.Encode(text)
		if (err == nil) != (againErr == nil) || !slices.Equal(ids, again) {
			t.Fatalf("two encodings differ: %v %v, %v %v", ids, err, again, againErr)
		}
		if err != nil {
			if !errors.Is(err, ErrSafetyUnavailable) {
				t.Fatalf("a text refused with %v", err)
			}
			return
		}
		normalized, err := tokenizer.vocabulary.normalize([]byte(text))
		if err != nil {
			t.Fatalf("encoded, yet the normalizer refused: %v", err)
		}
		if len(normalized) < len(ids) {
			t.Fatalf("%d ids from %d normalized bytes", len(ids), len(normalized))
		}
		if settings.NormalizeGrowthMaxFactor*len(text)+len(safetySpaceSymbol) < len(normalized) {
			t.Fatalf("%d bytes normalized to %d", len(text), len(normalized))
		}
		for _, id := range ids {
			if id < 0 || int64(tokenizer.vocabulary.PieceCount()) <= id {
				t.Fatalf("an id %d outside the vocabulary", id)
			}
			if kind := tokenizer.vocabulary.pieces[id].kind; kind == safetyPieceControl || kind == safetyPieceUnused {
				t.Fatalf("an id %d of a %d piece", id, kind)
			}
		}
		cls, sep := tokenizer.vocabulary.Specials()
		windows, err := SafetyWindows(ids, cls, sep, settings)
		if err != nil {
			t.Fatal(err)
		}
		textCount, stride := settings.WindowTokenCount-2, settings.WindowTokenCount-2-settings.WindowOverlapTokenCount
		want := 1
		if textCount < len(ids) {
			want += (len(ids) - textCount + stride - 1) / stride
		}
		if len(windows) != want {
			t.Fatalf("%d windows for %d ids, want %d", len(windows), len(ids), want)
		}
		for _, window := range windows {
			if len(window) < 2 || settings.WindowTokenCount < len(window) || window[0] != cls || window[len(window)-1] != sep {
				t.Fatalf("a window of %d ids", len(window))
			}
		}
	})
}
