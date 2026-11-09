// The forms a needle can take where a capture holds it (§22.7's scan list): raw, hex, base64 and
// base64url at all three alignments, base32 and base32hex at all five, percent, UTF-16 both ways.
// Quoted-printable and percent escapes are decoded instead (privacy_decompress.go), which finds a
// value whatever a writer escaped and wherever its soft breaks fell.
//
// A form that is printable text compares case-insensitively, so hex in either case, base32 in lower
// case and a canary's text after a product lower-cased it (a DNS label, a folded query) all match. A
// form holding other bytes, the raw bytes of a canary or key, compares exactly.

package sidecartest

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"unicode/utf16"
)

// One way a needle can appear.
type privacyPattern struct {
	needle *privacyNeedle
	form   string
	// lower-cased when folded
	body   []byte
	folded bool
}

// Base64's or base32's characters for needle inside something longer: the encoder's alignment depends
// on where the needle fell, so each offset has its own form, its partly-filled edge groups dropped
// and so its padding with them. groupByteCount bytes encode as groupCharCount characters.
func alignedForms(encode func(body []byte) string, groupByteCount int, groupCharCount int, needle []byte) []string {
	forms := []string{}
	for offset := 0; offset < groupByteCount; offset += 1 {
		padded := append(make([]byte, offset), needle...)
		encoded := encode(padded)
		// the first whole character after the offset's bytes, and the last before the needle's end
		start := (offset*8 + 5) / 6
		end := ((offset + len(needle)) * 8) / 6
		if groupCharCount == 8 {
			start = (offset*8 + 4) / 5
			end = ((offset + len(needle)) * 8) / 5
		}
		if start < end && end <= len(encoded) {
			forms = append(forms, encoded[start:end])
		}
	}
	return forms
}

func isPrintableText(body []byte) bool {
	for _, b := range body {
		if b < 0x20 || 0x7e < b {
			return false
		}
	}
	return true
}

func foldText(body []byte) []byte {
	folded := make([]byte, len(body))
	for index, b := range body {
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		folded[index] = b
	}
	return folded
}

// Every form of needle the scan looks for. A forbidden value under 16 bytes takes its raw form alone.
func needlePatterns(needle *privacyNeedle) []*privacyPattern {
	patterns := []*privacyPattern{}
	add := func(form string, body []byte) {
		if len(body) < privacyValueMinByteCount {
			return
		}
		pattern := &privacyPattern{needle: needle, form: form, body: body}
		if isPrintableText(body) {
			pattern.folded = true
			pattern.body = foldText(body)
		}
		patterns = append(patterns, pattern)
	}
	add("raw", needle.body)
	if needle.kind == privacyNeedleValue && len(needle.body) < privacySecretMinByteCount {
		return patterns
	}
	add("hex", []byte(hex.EncodeToString(needle.body)))
	for _, form := range alignedForms(base64.StdEncoding.EncodeToString, 3, 4, needle.body) {
		add("base64", []byte(form))
	}
	for _, form := range alignedForms(base64.URLEncoding.EncodeToString, 3, 4, needle.body) {
		add("base64url", []byte(form))
	}
	for _, form := range alignedForms(base32.StdEncoding.EncodeToString, 5, 8, needle.body) {
		add("base32", []byte(form))
	}
	for _, form := range alignedForms(base32.HexEncoding.EncodeToString, 5, 8, needle.body) {
		add("base32hex", []byte(form))
	}
	add("percent", []byte(url.QueryEscape(string(needle.body))))
	add("percent", []byte(url.PathEscape(string(needle.body))))
	wide := utf16.Encode([]rune(string(needle.body)))
	littleEndian := make([]byte, 0, 2*len(wide))
	bigEndian := make([]byte, 0, 2*len(wide))
	for _, unit := range wide {
		littleEndian = append(littleEndian, byte(unit), byte(unit>>8))
		bigEndian = append(bigEndian, byte(unit>>8), byte(unit))
	}
	add("utf-16le", littleEndian)
	add("utf-16be", bigEndian)
	return dedupePatterns(patterns)
}

// One pattern per body: a text needle's raw and percent forms are often the same bytes.
func dedupePatterns(patterns []*privacyPattern) []*privacyPattern {
	seen := map[string]bool{}
	unique := []*privacyPattern{}
	for _, pattern := range patterns {
		key := string(pattern.body)
		if pattern.folded {
			key = "\x00folded" + key
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, pattern)
	}
	return unique
}
