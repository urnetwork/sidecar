//go:build !ios_extension

// Extractor 1's html_to_text (§11.14's extract row; DESIGN-DETAILS 11.2.6; protocol/INDEX-FORMAT.md's Extractor 1):
// references(tags(t)). Every tag goes first, by X1-X7, and character references are decoded in what is left, once,
// by E1-E4 over HTML's own table of 2,231 names (evs_index_extract_entities.go), so "&lt;b&gt;" stays the text
// "<b>". Whitespace is copied as it stands and normalizer 1 folds it. Nothing is read from an attribute. An element's
// text is kept whatever the element, script and style apart, and only the 44 block tags leave a space, so a
// document's title joins its first body word.
//
// No parser library and no html.UnescapeString: their readings of damaged markup and of references are not the
// format's (QD-690), and a library's bump would change the bytes an index holds.

//go:generate env SIDECAR_REGENERATE_INDEX_REFERENCES=1 go test -run ^TestIndexReferenceTableIsCurrent$ .

package sidecar

import (
	"bytes"
	"unicode/utf8"
)

// X4's block tags, QD-474's 44 names (QD-693's reading 12): a tag named one leaves one SP, closing or not, so
// "<p>a</p><p>b</p>" reads " a  b " and "<b>a</b>b" reads "ab".
var indexHtmlBlockTags = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true, "br": true, "center": true, "dd": true,
	"details": true, "dialog": true, "dir": true, "div": true, "dl": true, "dt": true, "fieldset": true,
	"figcaption": true, "figure": true, "footer": true, "form": true, "h1": true, "h2": true, "h3": true, "h4": true,
	"h5": true, "h6": true, "header": true, "hgroup": true, "hr": true, "li": true, "main": true, "menu": true,
	"nav": true, "ol": true, "p": true, "pre": true, "section": true, "summary": true, "table": true, "tbody": true,
	"td": true, "tfoot": true, "th": true, "thead": true, "tr": true, "ul": true,
}

// E1's C1 table: what numeric references 0x80 to 0x9F mean, in order.
var indexReferenceC1CodePoints = [32]rune{
	0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D,
	0x017D, 0x008F, 0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A,
	0x0153, 0x009D, 0x017E, 0x0178,
}

// X3: where the '>' ending the tag that starts text sits, outside quotes, looking from the byte after its '<', or -1.
// A '"' or a "'" opens quotes and the next byte equal to it closes them.
func indexHtmlTagEnd(text []byte) int {
	quote := byte(0)
	for index := 1; index < len(text); index += 1 {
		b := text[index]
		switch {
		case quote != 0:
			if b == quote {
				quote = 0
			}
		case b == '"' || b == '\'':
			quote = b
		case b == '>':
			return index
		}
	}
	return -1
}

// X5: where the end tag of a script or style element named name, lowercase, starts in text: the first "</" followed by
// name ignoring ASCII case and then by the end of text or a byte that is not alphanumeric; or -1.
func indexHtmlEndTag(text []byte, name string) int {
	for start := 0; start+2+len(name) <= len(text); start += 1 {
		if text[start] != '<' || text[start+1] != '/' {
			continue
		}
		if indexLower(string(text[start+2:start+2+len(name)])) != name {
			continue
		}
		if after := start + 2 + len(name); after == len(text) || !indexAsciiAlphanumeric(text[after]) {
			return start
		}
	}
	return -1
}

// html_to_text: text with its tags removed by X1-X7 and then its character references decoded by E1-E4.
func indexStripHtml(text []byte) []byte {
	return indexDecodeReferences(indexStripTags(text))
}

// X1 to X7, tags(t): t read from the left, a byte other than '<' copied. "<!--" opens a comment, which ends after the
// first "-->" beginning 4 or more bytes past the '<'; else "<!" or "<?" a declaration, which ends after the next '>';
// else '<' and a letter or '/' a tag, to its first '>' outside quotes, whose name is lower of the alphanumeric bytes
// after the '<' or "</" and which gives one SP when the name is a block tag. A script or style that is not a closing
// tag also takes its content, through its end tag. Any other '<' is copied, and whatever has no end takes the rest.
func indexStripTags(text []byte) []byte {
	stripped := make([]byte, 0, len(text))
	for index := 0; index < len(text); {
		b := text[index]
		if b != '<' {
			stripped = append(stripped, b)
			index += 1
			continue
		}
		rest := text[index:]
		switch {
		case bytes.HasPrefix(rest, []byte("<!--")):
			end := bytes.Index(rest[4:], []byte("-->"))
			if end < 0 {
				index = len(text)
			} else {
				index += 4 + end + 3
			}
		case bytes.HasPrefix(rest, []byte("<!")) || bytes.HasPrefix(rest, []byte("<?")):
			end := bytes.IndexByte(rest, '>')
			if end < 0 {
				index = len(text)
			} else {
				index += end + 1
			}
		case 2 <= len(rest) && (indexAsciiLetter(rest[1]) || rest[1] == '/'):
			end := indexHtmlTagEnd(rest)
			if end < 0 {
				index = len(text)
				continue
			}
			closing := rest[1] == '/'
			nameStart := 1
			if closing {
				nameStart = 2
			}
			nameEnd := nameStart
			for nameEnd < end && indexAsciiAlphanumeric(rest[nameEnd]) {
				nameEnd += 1
			}
			name := indexLower(string(rest[nameStart:nameEnd]))
			index += end + 1
			if !closing && (name == "script" || name == "style") {
				endTag := indexHtmlEndTag(text[index:], name)
				if endTag < 0 {
					index = len(text)
					continue
				}
				endTagEnd := indexHtmlTagEnd(text[index+endTag:])
				if endTagEnd < 0 {
					index = len(text)
					continue
				}
				index += endTag + endTagEnd + 1
				continue
			}
			if indexHtmlBlockTags[name] {
				stripped = append(stripped, ' ')
			}
		default:
			stripped = append(stripped, '<')
			index += 1
		}
	}
	return stripped
}

// E1's code point for a numeric reference's value, held at 0x110000 once past it: the C1 table's for 0x80 to 0x9F,
// U+FFFD for 0, a surrogate or anything past U+10FFFF, and the value itself otherwise.
func indexNumericReference(value int) rune {
	switch {
	case 0x80 <= value && value <= 0x9F:
		return indexReferenceC1CodePoints[value-0x80]
	case value == 0, 0xD800 <= value && value <= 0xDFFF, utf8.MaxRune < value:
		return utf8.RuneError
	}
	return rune(value)
}

// E1 to E4, references(u): u read from the left, a byte other than '&' copied. At an '&': "&#", an optional x or X,
// one or more digits (hex digits after an x) and an optional ';' is a numeric reference, all consumed; with no digit
// the '&' is copied. Otherwise the alphanumeric bytes after the '&', and a ';' if one follows them, are a name, which
// gives its one or two code points when it is one of HTML's 2,231, matched by exact bytes; else the longest of its
// prefixes of 6 down to 2 bytes, short of the whole, that is one of the 106 names without ';' gives its code point and
// is consumed; else the '&' and the name are copied. An '&' with no alphanumeric byte after it is copied.
func indexDecodeReferences(text []byte) []byte {
	decoded := make([]byte, 0, len(text))
	for index := 0; index < len(text); {
		if text[index] != '&' {
			decoded = append(decoded, text[index])
			index += 1
			continue
		}
		rest := text[index+1:]
		if 0 < len(rest) && rest[0] == '#' {
			position := 1
			base := 10
			if position < len(rest) && (rest[position] == 'x' || rest[position] == 'X') {
				base = 16
				position += 1
			}
			digitStart := position
			value := 0
			for position < len(rest) {
				digit := indexHexValue(rest[position])
				if digit < 0 || base <= digit {
					break
				}
				if value <= utf8.MaxRune {
					value = min(value*base+digit, utf8.MaxRune+1)
				}
				position += 1
			}
			if digitStart < position {
				if position < len(rest) && rest[position] == ';' {
					position += 1
				}
				decoded = utf8.AppendRune(decoded, indexNumericReference(value))
				index += 1 + position
				continue
			}
			decoded = append(decoded, '&')
			index += 1
			continue
		}
		nameEnd := 0
		for nameEnd < len(rest) && indexAsciiAlphanumeric(rest[nameEnd]) {
			nameEnd += 1
		}
		if nameEnd == 0 {
			decoded = append(decoded, '&')
			index += 1
			continue
		}
		name := rest[:nameEnd]
		if nameEnd < len(rest) && rest[nameEnd] == ';' {
			name = rest[:nameEnd+1]
		}
		if codePoints, ok := indexReference(name); ok {
			decoded = indexAppendReference(decoded, codePoints)
			index += 1 + len(name)
			continue
		}
		matched := false
		for prefixByteCount := min(6, len(name)-1); 2 <= prefixByteCount; prefixByteCount -= 1 {
			if codePoints, ok := indexReference(name[:prefixByteCount]); ok {
				decoded = indexAppendReference(decoded, codePoints)
				index += 1 + prefixByteCount
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		decoded = append(decoded, '&')
		decoded = append(decoded, name...)
		index += 1 + len(name)
	}
	return decoded
}

// Appends a named reference's one or two code points, the second 0 when there is one.
func indexAppendReference(decoded []byte, codePoints [2]rune) []byte {
	decoded = utf8.AppendRune(decoded, codePoints[0])
	if codePoints[1] != 0 {
		decoded = utf8.AppendRune(decoded, codePoints[1])
	}
	return decoded
}

// The code points of the named reference whose bytes are name, its ';' included where it has one, by a binary search
// of the generated table, which is sorted by bytes.
func indexReference(name []byte) ([2]rune, bool) {
	low, high := 0, len(indexReferenceNameEnds)
	for low < high {
		middle := (low + high) / 2
		start := 0
		if 0 < middle {
			start = int(indexReferenceNameEnds[middle-1])
		}
		switch candidate := indexReferenceNames[start:indexReferenceNameEnds[middle]]; {
		case candidate == string(name):
			return indexReferenceCodePoints[middle], true
		case candidate < string(name):
			low = middle + 1
		default:
			high = middle
		}
	}
	return [2]rune{}, false
}
