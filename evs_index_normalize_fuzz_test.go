//go:build !js

// §22.6's target for the normalizer and trigram extractor: idempotent, output within a fixed multiple of its input,
// invalid UTF-8 by one rule, and sets equal to a reference written apart. Seeds in testdata/fuzz/ run in every go test,
// but not on js, where testing.F cannot open its corpus directory.

package sidecar

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// The widest expansion of any code point: U+FDFA, TestEveryCodePointIsIdempotentAndBounded's find.
const testNormalizeExpansion = 11

func FuzzIndexNormalize(f *testing.F) {
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, text []byte, split int) {
		normalized, err := normalizer.normalize(text)
		reference, ok := testReferenceNormalize(string(text))
		if errors.Is(err, errIndexCherokeeUnsettled) {
			if ok {
				t.Fatalf("%+q was refused, and only cherokee case is", text)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if !ok || reference != string(normalized) {
			t.Fatalf("%+q: got %+q, the reference reads %+q (%t)", text, normalized, reference, ok)
		}
		if !utf8.Valid(normalized) {
			t.Fatalf("%+q came out as invalid UTF-8", text)
		}
		if strings.Contains(string(normalized), "  ") {
			t.Fatalf("%+q kept a run: %+q", text, normalized)
		}
		if testNormalizeExpansion*len(text) < len(normalized) {
			t.Fatalf("%d bytes grew to %d", len(text), len(normalized))
		}
		twice, err := normalizer.normalize(normalized)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(twice, normalized) {
			t.Fatalf("%+q: %+q then %+q", text, normalized, twice)
		}
		replaced, err := normalizer.normalize([]byte(string([]rune(string(text)))))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(replaced, normalized) {
			t.Fatalf("%+q: invalid bytes have two rules", text)
		}
		split = min(max(split, 0), len(text))
		streamed, err := io.ReadAll(normalizer.stream(io.MultiReader(bytes.NewReader(text[:split]), bytes.NewReader(text[split:]))))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(streamed, normalized) {
			t.Fatalf("%+q differs split at %d", text, split)
		}
		want := testReferenceTrigrams(normalized)
		if got := indexTrigrams(normalized); !slices.Equal(got, want) {
			t.Fatalf("%+q: trigrams %x, want %x", normalized, got, want)
		}
		keys, err := normalizer.documentKeys([]indexTextField{{number: indexFieldBody, text: bytes.NewReader(text)}})
		if err != nil {
			t.Fatal(err)
		}
		if len(text) != 0 {
			want = testReferenceTrigrams([]byte(" " + reference + " "))
		}
		if !slices.Equal(keys, want) {
			t.Fatalf("%+q: document keys %x, want %x", text, keys, want)
		}
	})
}
