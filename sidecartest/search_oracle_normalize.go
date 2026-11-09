// The oracle's own reading of normalizer 1 and of a document's indexed text (protocol/INDEX-FORMAT.md's
// Normalizer 1 and Trigrams, D-TEST-14). It is written from that file's text alone and calls x/text
// directly, never a root evs_index_ or search_ file, so a misreading in the index's normalizer is not
// repeated here (TestSearchOracleImportsNoIndexCode).
//
// Package-level functions are safe for concurrent use.

package sidecartest

import (
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// The tables normalizer 1 is published for (INDEX-FORMAT.md's Tables), and what its steps cut. These are
// the format's facts, not tunables.
const (
	searchOracleUnicodeVersion    = "17.0.0"
	searchOracleTextModulePath    = "golang.org/x/text"
	searchOracleTextModuleVersion = "v0.43.0"
	// Step 6: fields 1-4 keep at most this much of their normalized text.
	searchOracleHeaderFieldByteCount = 1024
	// A key set that encodes past this skips its chunk (§11.14's sniff row).
	searchOracleKeySetByteCount = 512 * 1024
)

// The linked build is not normalizer 1's: its tables or x/text module differ, so the oracle's reading
// of a document would not be the published one, and it refuses to judge.
var ErrSearchOracleTables = errors.New("search oracle: the linked tables are not normalizer 1's")

// Nil when the linked build carries normalizer 1's tables: norm.Version, cases.UnicodeVersion and
// unicode.Version at 17.0.0, and golang.org/x/text at v0.43.0 with no replace, as
// runtime/debug.ReadBuildInfo reports it.
func searchOracleTablesErr() error {
	for _, linked := range [][2]string{
		{"norm.Version", norm.Version},
		{"cases.UnicodeVersion", cases.UnicodeVersion},
		{"unicode.Version", unicode.Version},
	} {
		if linked[1] != searchOracleUnicodeVersion {
			return fmt.Errorf("%w: %s is %s, not %s", ErrSearchOracleTables, linked[0], linked[1], searchOracleUnicodeVersion)
		}
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Errorf("%w: the build carries no module information", ErrSearchOracleTables)
	}
	for _, dep := range info.Deps {
		if dep.Path != searchOracleTextModulePath {
			continue
		}
		if dep.Replace != nil {
			return fmt.Errorf("%w: %s is replaced by %s %s", ErrSearchOracleTables, dep.Path, dep.Replace.Path, dep.Replace.Version)
		}
		if dep.Version != searchOracleTextModuleVersion {
			return fmt.Errorf("%w: %s is %s, not %s", ErrSearchOracleTables, dep.Path, dep.Version, searchOracleTextModuleVersion)
		}
		return nil
	}
	return fmt.Errorf("%w: %s is not linked", ErrSearchOracleTables, searchOracleTextModulePath)
}

// Steps 1 to 5 of normalizer 1 over one value: invalid UTF-8 to U+FFFD, NFKC, full case folding with
// the Cherokee map, nonspacing marks after a Latin, Greek, Cyrillic, Arabic or Hebrew letter dropped
// under NFD and then NFC, and each run of code points outside L, M and N to one space.
func searchOracleNormalize(value []byte) string {
	text := searchOracleValidUtf8(value)
	text = norm.NFKC.String(text)
	text = searchOracleCherokee(cases.Fold().String(text))
	text = norm.NFC.String(searchOracleDropMarks(norm.NFD.String(text)))
	return searchOracleFoldSeparators(text)
}

// Step 1: each byte that does not begin a well-formed sequence, a cut final sequence included, is one
// U+FFFD; an encoded U+FFFD stays as it is.
func searchOracleValidUtf8(value []byte) string {
	var out strings.Builder
	out.Grow(len(value))
	for 0 < len(value) {
		r, size := utf8.DecodeRune(value)
		if r == utf8.RuneError && size == 1 {
			out.WriteRune(utf8.RuneError)
		} else {
			out.Write(value[:size])
		}
		value = value[size:]
	}
	return out.String()
}

// Step 3's fixed map after cases.Fold(): U+AB70-U+ABBF to U+13A0-U+13EF and U+13F8-U+13FD to
// U+13F0-U+13F5 (plan-SEARCH-cherokee-fold, as the owner decided it).
func searchOracleCherokee(text string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case 0xAB70 <= r && r <= 0xABBF:
			return r - 0xAB70 + 0x13A0
		case 0x13F8 <= r && r <= 0x13FD:
			return r - 0x13F8 + 0x13F0
		}
		return r
	}, text)
}

// Step 4's middle, over NFD text: a nonspacing mark goes when the nearest code point before it that is
// not one is a letter of the five scripts. A spacing or enclosing mark is not nonspacing, so it keeps
// what follows it.
func searchOracleDropMarks(text string) string {
	var out strings.Builder
	out.Grow(len(text))
	// the nearest code point so far that is not a nonspacing mark, -1 before the first
	base := rune(-1)
	for _, r := range text {
		if unicode.Is(unicode.Mn, r) {
			if 0 <= base && unicode.IsLetter(base) &&
				unicode.In(base, unicode.Latin, unicode.Greek, unicode.Cyrillic, unicode.Arabic, unicode.Hebrew) {
				continue
			}
			out.WriteRune(r)
			continue
		}
		base = r
		out.WriteRune(r)
	}
	return out.String()
}

// Step 5: each maximal run of code points outside categories L, M and N becomes one space, at the ends
// too.
func searchOracleFoldSeparators(text string) string {
	var out strings.Builder
	out.Grow(len(text))
	inRun := false
	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsMark(r) || unicode.IsNumber(r) {
			out.WriteRune(r)
			inRun = false
			continue
		}
		if !inRun {
			out.WriteByte(' ')
			inRun = true
		}
	}
	return out.String()
}

// The longest prefix of text of at most byteCount bytes that ends on a code point.
func searchOracleCut(text string, byteCount int) string {
	if len(text) <= byteCount {
		return text
	}
	cut := byteCount
	for 0 < cut && !utf8.RuneStart(text[cut]) {
		cut -= 1
	}
	return text[:cut]
}

// A document's text from its fields, field numbers 1 to 5 at indexes 1 to 5 (steps 6 and 7): each
// normalized, fields 1-4 then cut to 1,024 B on a code point, and each field with text added as one
// space, the text and one space, in field order with nothing between.
func searchOracleDocumentText(fields *searchOracleFields) string {
	var out strings.Builder
	for field := 1; field <= 5; field += 1 {
		text := searchOracleNormalize(fields[field])
		if field <= 4 {
			text = searchOracleCut(text, searchOracleHeaderFieldByteCount)
		}
		if text == "" {
			continue
		}
		out.WriteByte(' ')
		out.WriteString(text)
		out.WriteByte(' ')
	}
	return out.String()
}

// Whether the distinct trigram keys of text, every 3-byte window, encode past 512 KiB as a key set:
// a VByte count, then VByte gaps between ascending keys, the first gap key + 1 (INDEX-FORMAT.md's
// Entries). Such a chunk is skipped.
func searchOracleKeySetTooLarge(text string) bool {
	if len(text) < 3 {
		return false
	}
	seen := map[uint32]bool{}
	for i := 0; i+3 <= len(text); i += 1 {
		seen[uint32(text[i])<<16|uint32(text[i+1])<<8|uint32(text[i+2])] = true
	}
	keys := make([]uint32, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	vbyteLen := func(value uint64) int {
		n := 1
		for 0x80 <= value {
			value >>= 7
			n += 1
		}
		return n
	}
	size := vbyteLen(uint64(len(keys)))
	previous := int64(-1)
	for _, key := range keys {
		size += vbyteLen(uint64(int64(key) - previous))
		previous = int64(key)
	}
	return searchOracleKeySetByteCount < size
}
