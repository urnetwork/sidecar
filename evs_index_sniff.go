// Whether a file is text, and its title (§11.14's sniff and extract rows; protocol/INDEX-FORMAT.md's Extractor 1). A
// file is text when its first 8,000 bytes hold no NUL and are valid UTF-8 but for a cut final sequence, git's rule
// with UTF-8 added, or when it opens with a UTF-16 byte-order mark, which selects the decoding and is dropped. No
// charset is guessed from content, so a Latin-1 file whose first 8,000 bytes are not UTF-8 is a binary.

package sidecar

import (
	"bytes"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// The bytes the sniff reads.
const indexSniffByteCount = 8000

// The longest title, cut on a code point.
const indexTitleMaxByteCount = 80

// UTF-16's byte-order marks.
var (
	indexUtf16BigEndianMark    = []byte{0xFE, 0xFF}
	indexUtf16LittleEndianMark = []byte{0xFF, 0xFE}
)

// A file's text, or false for a binary. A UTF-16 file comes back as UTF-8, an unpaired surrogate or an odd last byte
// as U+FFFD; any other text comes back as it is, ill-formed bytes past the first 8,000 included, which normalizer 1's
// step 1 maps.
func indexSniff(content []byte) ([]byte, bool) {
	switch {
	case bytes.HasPrefix(content, indexUtf16BigEndianMark):
		return indexDecodeUtf16(content[len(indexUtf16BigEndianMark):], true), true
	case bytes.HasPrefix(content, indexUtf16LittleEndianMark):
		return indexDecodeUtf16(content[len(indexUtf16LittleEndianMark):], false), true
	}
	window := content[:min(len(content), indexSniffByteCount)]
	if bytes.IndexByte(window, 0) >= 0 {
		return nil, false
	}
	for index := 0; index < len(window); {
		r, size := utf8.DecodeRune(window[index:])
		if r == utf8.RuneError && size == 1 {
			// Only the window's end may cut a sequence; anywhere else this byte begins none.
			return content, !utf8.FullRune(window[index:])
		}
		index += size
	}
	return content, true
}

// UTF-16 code units in the byte order given, as UTF-8.
func indexDecodeUtf16(content []byte, bigEndian bool) []byte {
	units := make([]uint16, 0, len(content)/2)
	for index := 0; index+1 < len(content); index += 2 {
		if bigEndian {
			units = append(units, uint16(content[index])<<8|uint16(content[index+1]))
		} else {
			units = append(units, uint16(content[index+1])<<8|uint16(content[index]))
		}
	}
	text := make([]byte, 0, len(content)*3/2)
	for _, r := range utf16.Decode(units) {
		text = utf8.AppendRune(text, r)
	}
	if len(content)%2 == 1 {
		text = utf8.AppendRune(text, utf8.RuneError)
	}
	return text
}

// A file's title: its first line holding a letter or number, without a leading run of '#' and spaces or trailing
// spaces, tabs and carriage returns, ill-formed bytes as U+FFFD, cut to 80 B on a code point. Empty when no line has
// one.
func indexTitle(text []byte) string {
	for len(text) != 0 {
		line := text
		if end := bytes.IndexByte(text, '\n'); end >= 0 {
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
		return indexCutUtf8(indexRowText(string(line)), indexTitleMaxByteCount)
	}
	return ""
}
