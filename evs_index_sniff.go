//go:build !ios_extension

// Whether a file is text, and its title (§11.14's sniff and extract rows; DESIGN-DETAILS 11.2.4's S1 to S4). A file
// that opens with a UTF-16 byte-order mark is UTF-16 in that order, the mark dropped. Any other is binary when its
// first SniffByteCount bytes hold a NUL or a byte that begins no well-formed UTF-8 sequence, unless what follows that
// byte to the window's end is a proper prefix of one, a character the window cut; git's rule with UTF-8 added, and no
// charset guessed from content, so a Latin-1 file whose first 8,000 bytes are not UTF-8 is binary. A UTF-8 file loses
// a leading UTF-8 byte-order mark, once (S3; QD-693's reading 1).
//
// Well-formed UTF-8 is Unicode's table 3-7, which unicode/utf8 reads exactly: no overlong form, no surrogate, nothing
// past U+10FFFF, so E0 80, ED A0 and F4 90 begin nothing.

package sidecar

import (
	"bytes"
	"unicode"
	"unicode/utf8"
)

// UTF-16's byte-order marks, and UTF-8's.
var (
	indexUtf16BigEndianMark    = []byte{0xFE, 0xFF}
	indexUtf16LittleEndianMark = []byte{0xFF, 0xFE}
	indexUtf8Mark              = []byte{0xEF, 0xBB, 0xBF}
)

// S1 to S3: a file's text, or false for a binary. A UTF-16 file comes back as UTF-8, an unpaired surrogate or an odd
// last byte as U+FFFD; any other text comes back as it is but for a leading UTF-8 mark, ill-formed bytes past the
// window included, which normalizer 1's N1 maps.
func indexSniff(content []byte, settings *IndexFormatSettings) ([]byte, bool) {
	switch {
	case bytes.HasPrefix(content, indexUtf16BigEndianMark):
		return indexDecodeUtf16(content[len(indexUtf16BigEndianMark):], true), true
	case bytes.HasPrefix(content, indexUtf16LittleEndianMark):
		return indexDecodeUtf16(content[len(indexUtf16LittleEndianMark):], false), true
	}
	window := content[:min(len(content), settings.SniffByteCount)]
	if 0 <= bytes.IndexByte(window, 0) {
		return nil, false
	}
	for index := 0; index < len(window); {
		r, size := utf8.DecodeRune(window[index:])
		if r == utf8.RuneError && size == 1 {
			// only the window's end may cut a sequence; anywhere else this byte begins none
			if utf8.FullRune(window[index:]) {
				return nil, false
			}
			break
		}
		index += size
	}
	return bytes.TrimPrefix(content, indexUtf8Mark), true
}

// S1: UTF-16 code units in the byte order given, as UTF-8: a surrogate pair is its code point, a surrogate with no
// partner U+FFFD, and an odd last byte U+FFFD. U+0000 is allowed.
func indexDecodeUtf16(content []byte, bigEndian bool) []byte {
	unitAt := func(index int) rune {
		if bigEndian {
			return rune(content[index])<<8 | rune(content[index+1])
		}
		return rune(content[index+1])<<8 | rune(content[index])
	}
	text := make([]byte, 0, len(content)*3/2+3)
	index := 0
	for ; index+1 < len(content); index += 2 {
		unit := unitAt(index)
		switch {
		case 0xD800 <= unit && unit <= 0xDBFF && index+3 < len(content):
			if next := unitAt(index + 2); 0xDC00 <= next && next <= 0xDFFF {
				text = utf8.AppendRune(text, 0x10000+(unit-0xD800)<<10+(next-0xDC00))
				index += 2
				continue
			}
			text = utf8.AppendRune(text, utf8.RuneError)
		case 0xD800 <= unit && unit <= 0xDFFF:
			text = utf8.AppendRune(text, utf8.RuneError)
		default:
			text = utf8.AppendRune(text, unit)
		}
	}
	if index < len(content) {
		text = utf8.AppendRune(text, utf8.RuneError)
	}
	return text
}

// S4: a file's title: the first line, split at LF, holding a code point of category L or N, read as UTF-8 with N1's
// rule, so U+FFFD stands for each ill-formed byte and is neither; without its leading run of '#' and SP and its
// trailing run of SP, HT and CR; N1 applied; cut to TitleMaxByteCount on a code point. Empty when no line has one.
func indexTitle(text []byte, settings *IndexFormatSettings) string {
	for 0 < len(text) {
		line := text
		if end := bytes.IndexByte(text, '\n'); 0 <= end {
			line, text = text[:end], text[end+1:]
		} else {
			text = nil
		}
		if !bytes.ContainsFunc(line, func(r rune) bool {
			return unicode.IsLetter(r) || unicode.IsNumber(r)
		}) {
			continue
		}
		line = bytes.TrimLeft(line, "# ")
		line = bytes.TrimRight(line, " \t\r")
		return indexCutUtf8(indexRowText(string(line)), settings.TitleMaxByteCount)
	}
	return ""
}
