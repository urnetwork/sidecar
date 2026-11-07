//go:build !js

// Normalizer 1 at its largest: every code point, and a chunk of the widest one. These are too slow for the sidecar_http
// leg's Worker, and what they prove is a property of the tables and the steps, which that leg's vectors pin byte for
// byte.

package sidecar

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
	"unicode"
)

// §22.6's idempotence on every code point there is, and the 11x bound with its widest case found, not assumed.
func TestEveryCodePointIsIdempotentAndBounded(t *testing.T) {
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	widest := 0.0
	widestRune := rune(0)
	for r := rune(0); r <= unicode.MaxRune; r += 1 {
		if 0xD800 <= r && r <= 0xDFFF || indexIsCherokeeCased(r) {
			continue
		}
		text := string(r)
		once, err := normalizer.normalize([]byte(text))
		if err != nil {
			t.Fatalf("%U: %v", r, err)
		}
		twice, err := normalizer.normalize(once)
		if err != nil {
			t.Fatalf("%U again: %v", r, err)
		}
		if !bytes.Equal(once, twice) {
			t.Errorf("%U: %+q then %+q", r, once, twice)
		}
		if ratio := float64(len(once)) / float64(len(text)); widest < ratio {
			widest, widestRune = ratio, r
		}
	}
	if widest != 11 || widestRune != 0xFDFA {
		t.Errorf("widest is %U at %v", widestRune, widest)
	}
}

// A 1 MiB chunk of the widest expansion is 11 MiB of text, and streaming must not hold it. The ceiling sits under that
// and over the collector's fixed 3 MiB.
func TestAChunkNormalizesInBoundedMemory(t *testing.T) {
	chunk := []byte(strings.Repeat("\uFDFA", 1024*1024/3))
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	keys, err := normalizer.documentKeys([]indexTextField{{number: indexFieldBody, text: bytes.NewReader(chunk)}})
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal("no keys")
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; 6*1024*1024 < allocated {
		t.Errorf("allocated %d bytes", allocated)
	}
}
