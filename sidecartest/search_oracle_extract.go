// The oracle's own reading of extractor 1 (DESIGN-DETAILS 11.2; protocol/INDEX-FORMAT.md's Documents, Extractor 1 and
// Rows; D-TEST-14): what a file or a mail message gives each field and each row, written from those rules alone and
// apart from the index's extractor. Every reading is a rule of the format and calls no parser of the standard library
// or of a module: header fields, RFC 2047 words, RFC 2231 parameters, multipart bodies, base64, quoted-printable, HTML
// tags and character references are byte loops here, and HTML's reference table is generated into
// search_oracle_entities.go from entities.json. What comes from outside is tables: x/text v0.43.0's encoding/htmlindex
// labels and decoders (C1-C3), which normalizer 1 already pins, and Go's unicode package for S4's letters and numbers.
//
// Extraction is total: every byte string gives exactly one result and there is no error. Names, labels and encodings
// compare under ASCII lower, and only the six white bytes are trimmed (11.2.1).
//
// Where the oracle once read otherwise than the index (DESIGN-DETAILS 11.1 A), it takes the canonical reading: a
// script's end tag is "</" and the name, then the end or a byte that is not alphanumeric (X5); base64 skips the six
// white bytes only (T2); a word whose charset holds a blank byte is text (W2); only blank bytes between two words
// are dropped (W6); of two pieces of one section the first counts, and sections that join to nothing fall through to
// the extended and then the plain piece (P3, P5); an unterminated multipart's last part keeps its last line break
// (B4).
//
// Package-level functions are safe for concurrent use.

package sidecartest

import (
	"bytes"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
)

// Extractor 1's limits as the oracle reads them (DESIGN-DETAILS 11.2.1; INDEX-FORMAT.md's Rows). Each default is the
// format's value, and any other is another extractor, which no index holds (QD-702 keeps them settings).
type SearchOracleExtractSettings struct {
	// D4: a document's share of its source's text, and what it repeats of the next.
	ChunkByteCount   int
	OverlapByteCount int
	// S2: the bytes that decide text or binary.
	SniffByteCount int
	// S4: a file's title.
	TitleByteCount int
	// H4 and H6: a logical header line, and the joined values of one field name.
	HeaderMaxByteCount int
	// B1: the longest delimiter line; T3: the longest blank run inside a soft line break.
	LineWindowByteCount int
	// M2: the multipart levels entered.
	MimeDepth int
	// P3: the most digits an RFC 2231 section number holds.
	SectionDigitCount int
	// Rows' Trimming: the locator's cap, and fields 1 to 4's.
	LocatorByteCount  int
	RowFieldByteCount int
}

func DefaultSearchOracleExtractSettings() *SearchOracleExtractSettings {
	return &SearchOracleExtractSettings{
		ChunkByteCount:      1024 * 1024,
		OverlapByteCount:    256,
		SniffByteCount:      8000,
		TitleByteCount:      80,
		HeaderMaxByteCount:  16 * 1024,
		LineWindowByteCount: 1024,
		MimeDepth:           16,
		SectionDigitCount:   9,
		LocatorByteCount:    512,
		RowFieldByteCount:   160,
	}
}

// Fields 1 to 5 at their numbers: subject, from, to, title and body. Index 0 is unused.
type searchOracleFields [6][]byte

// One document, a chunk of one version of a path, as the oracle reads it.
type searchOracleDocument struct {
	chunk uint32
	kind  SearchDocKind
	// fields 1 to 5 as extraction hands them to normalizer 1, at their numbers
	fields searchOracleFields
	// the row's text values, fields 1 to 4 at their numbers and the locator at 0, as the doc table holds them:
	// invalid UTF-8 replaced and cut to their caps on a code point
	row [5]string
	// the row's size: the whole source's length in bytes, on every chunk's row
	byteCount uint64
	// the document's normalized text, fields padded and joined
	text string
}

// The block tags, whose removal leaves one space (X4; QD-474's 44 names).
var searchOracleBlockTags = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true, "br": true, "center": true,
	"dd": true, "details": true, "dialog": true, "dir": true, "div": true, "dl": true, "dt": true,
	"fieldset": true, "figcaption": true, "figure": true, "footer": true, "form": true, "h1": true,
	"h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "header": true, "hgroup": true,
	"hr": true, "li": true, "main": true, "menu": true, "nav": true, "ol": true, "p": true, "pre": true,
	"section": true, "summary": true, "table": true, "tbody": true, "td": true, "tfoot": true, "th": true,
	"thead": true, "tr": true, "ul": true,
}

// What numeric references 0x80 to 0x9F give, in order (11.2.1's C1 table; E1).
var searchOracleC1References = [32]rune{
	0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
	0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
	0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
	0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
}

// Past Unicode's last code point, where E1 holds a numeric reference's value.
const searchOracleCodePointLimit = 0x110000

// The longest of the reference names without ';' (E3), from the table itself.
var searchOracleLegacyNameByteCount = func() int {
	longest := 0
	for name := range searchOracleReferenceTable {
		if name[len(name)-1] != ';' {
			longest = max(longest, len(name))
		}
	}
	return longest
}()

// The documents of a file version at path, one a chunk (D2, D4, D5), or none for a binary (S1-S3).
func searchOracleFileDocuments(path string, content []byte, settings *SearchOracleExtractSettings) []*searchOracleDocument {
	text, ok := searchOracleSniff(content, settings)
	if !ok {
		return nil
	}
	title := searchOracleTitle(text, settings)
	var row [5]string
	row[0] = searchOracleRowValue([]byte(path), settings.LocatorByteCount)
	row[4] = searchOracleRowValue([]byte(title), settings.RowFieldByteCount)
	// D2: the title, one SP and the path's bytes, whatever the title
	field4 := make([]byte, 0, len(title)+1+len(path))
	field4 = append(append(append(field4, title...), ' '), path...)
	documents := []*searchOracleDocument{}
	for chunk, chunkText := range searchOracleChunks(text, settings) {
		fields := searchOracleFields{}
		fields[4] = field4
		fields[5] = chunkText
		documents = append(documents, &searchOracleDocument{
			chunk:     uint32(chunk),
			kind:      SearchDocKindFile,
			fields:    fields,
			row:       row,
			byteCount: uint64(len(content)),
			text:      searchOracleDocumentText(&fields),
		})
	}
	return documents
}

// The documents of a mail message at path (D3, D4, D5; 11.2.5's extract_mail): its own Subject, From, To and Cc with
// their words decoded, and the walk's pieces in the message's order, at least one document even for empty input.
func searchOracleMailDocuments(path string, content []byte, settings *SearchOracleExtractSettings) []*searchOracleDocument {
	header, body := searchOracleHeaderBlock(content, settings)
	subject := searchOracleWords(header.joined("subject", settings))
	from := searchOracleWords(header.joined("from", settings))
	to := searchOracleJoin(searchOracleWords(header.joined("to", settings)), searchOracleWords(header.joined("cc", settings)))
	pieces := [][]byte{}
	searchOracleWalk(header, body, 0, false, &pieces, settings)
	var row [5]string
	row[0] = searchOracleRowValue([]byte(path), settings.LocatorByteCount)
	row[1] = searchOracleRowValue(subject, settings.RowFieldByteCount)
	row[2] = searchOracleRowValue(from, settings.RowFieldByteCount)
	row[3] = searchOracleRowValue(to, settings.RowFieldByteCount)
	documents := []*searchOracleDocument{}
	for chunk, chunkText := range searchOracleChunks(searchOracleJoin(pieces...), settings) {
		fields := searchOracleFields{}
		fields[1] = subject
		fields[2] = from
		fields[3] = to
		fields[5] = chunkText
		documents = append(documents, &searchOracleDocument{
			chunk:     uint32(chunk),
			kind:      SearchDocKindMail,
			fields:    fields,
			row:       row,
			byteCount: uint64(len(content)),
			text:      searchOracleDocumentText(&fields),
		})
	}
	return documents
}

// The values that are not empty, in order, with one SP between each two.
func searchOracleJoin(values ...[]byte) []byte {
	joined := []byte{}
	for _, value := range values {
		if len(value) == 0 {
			continue
		}
		if 0 < len(joined) {
			joined = append(joined, ' ')
		}
		joined = append(joined, value...)
	}
	return joined
}

// A row's text value: invalid UTF-8 replaced as N1 does, then cut to its cap on a code point (Rows' Trimming).
func searchOracleRowValue(value []byte, byteCount int) string {
	return searchOracleCut(searchOracleValidUtf8(value), byteCount)
}

// D4: t[k*C : min(len(t), (k+1)*C + Overlap)] while k*C < len(t), and the one empty chunk of an empty text.
func searchOracleChunks(text []byte, settings *SearchOracleExtractSettings) [][]byte {
	chunks := [][]byte{}
	for start := 0; start == 0 || start < len(text); start += settings.ChunkByteCount {
		end := min(len(text), start+settings.ChunkByteCount+settings.OverlapByteCount)
		chunks = append(chunks, text[start:end])
	}
	return chunks
}

// 0x09 to 0x0D and SP (11.2.1).
func searchOracleWhite(c byte) bool {
	return (0x09 <= c && c <= 0x0D) || c == ' '
}

// SP and HT (11.2.1).
func searchOracleBlank(c byte) bool {
	return c == ' ' || c == '\t'
}

func searchOracleLetter(c byte) bool {
	return ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z')
}

func searchOracleAlphanumeric(c byte) bool {
	return searchOracleLetter(c) || ('0' <= c && c <= '9')
}

// A hex digit's value, 0-9, A-F and a-f.
func searchOracleHexValue(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

// value without its leading and trailing white bytes.
func searchOracleTrim(value []byte) []byte {
	start, end := 0, len(value)
	for start < end && searchOracleWhite(value[start]) {
		start += 1
	}
	for start < end && searchOracleWhite(value[end-1]) {
		end -= 1
	}
	return value[start:end]
}

// A copy of value with each byte 0x41-0x5A raised by 0x20 and every other byte as it is.
func searchOracleLower(value []byte) []byte {
	lowered := make([]byte, len(value))
	for i, c := range value {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		lowered[i] = c
	}
	return lowered
}

// A lead byte's sequence length under Unicode's table 3-7 and the range of the byte after it; 0 for a byte that
// begins no sequence, 1 for ASCII.
func searchOracleUtf8Lead(lead byte) (int, byte, byte) {
	switch {
	case lead <= 0x7F:
		return 1, 0, 0
	case 0xC2 <= lead && lead <= 0xDF:
		return 2, 0x80, 0xBF
	case lead == 0xE0:
		return 3, 0xA0, 0xBF
	case lead == 0xED:
		return 3, 0x80, 0x9F
	case 0xE1 <= lead && lead <= 0xEF:
		return 3, 0x80, 0xBF
	case lead == 0xF0:
		return 4, 0x90, 0xBF
	case 0xF1 <= lead && lead <= 0xF3:
		return 4, 0x80, 0xBF
	case lead == 0xF4:
		return 4, 0x80, 0x8F
	}
	return 0, 0, 0
}

// How many of value's bytes after its lead sit in their ranges, in a row, up to n - 1.
func searchOracleUtf8Continued(value []byte, n int, low byte, high byte) int {
	count := 0
	for k := 1; k < n && k < len(value); k += 1 {
		c := value[k]
		if (k == 1 && (c < low || high < c)) || (1 < k && (c < 0x80 || 0xBF < c)) {
			break
		}
		count += 1
	}
	return count
}

// S1-S3: a file's text, or false for a binary.
func searchOracleSniff(content []byte, settings *SearchOracleExtractSettings) ([]byte, bool) {
	switch {
	case 2 <= len(content) && content[0] == 0xFE && content[1] == 0xFF:
		return searchOracleUtf16(content[2:], true), true
	case 2 <= len(content) && content[0] == 0xFF && content[1] == 0xFE:
		return searchOracleUtf16(content[2:], false), true
	}
	window := content[:min(len(content), settings.SniffByteCount)]
	for i := 0; i < len(window); {
		if window[i] == 0x00 {
			return nil, false
		}
		n, low, high := searchOracleUtf8Lead(window[i])
		if n == 0 {
			return nil, false
		}
		continued := searchOracleUtf8Continued(window[i:], n, low, high)
		if continued == n-1 {
			i += n
			continue
		}
		// a byte that begins no well-formed sequence: text only when what is left of the window is a proper
		// prefix of one, a character the window cut
		if i+1+continued == len(window) {
			break
		}
		return nil, false
	}
	// S3: a UTF-8 mark goes, once
	if 3 <= len(content) && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF {
		return content[3:], true
	}
	return content, true
}

// S1: code units in the byte order given, as UTF-8; a surrogate pair is its code point, a surrogate with no partner
// and an odd last byte U+FFFD.
func searchOracleUtf16(units []byte, bigEndian bool) []byte {
	unit := func(i int) rune {
		if bigEndian {
			return rune(units[i])<<8 | rune(units[i+1])
		}
		return rune(units[i+1])<<8 | rune(units[i])
	}
	out := make([]byte, 0, len(units)*3/2+3)
	for i := 0; i+1 < len(units); i += 2 {
		u := unit(i)
		switch {
		case 0xD800 <= u && u <= 0xDBFF && i+3 < len(units) && 0xDC00 <= unit(i+2) && unit(i+2) <= 0xDFFF:
			out = utf8.AppendRune(out, 0x10000+(u-0xD800)<<10+(unit(i+2)-0xDC00))
			i += 2
		case 0xD800 <= u && u <= 0xDFFF:
			out = utf8.AppendRune(out, utf8.RuneError)
		default:
			out = utf8.AppendRune(out, u)
		}
	}
	if len(units)%2 == 1 {
		out = utf8.AppendRune(out, utf8.RuneError)
	}
	return out
}

// S4: the first line holding a code point of category L or N, read with N1's rule; without its leading run of '#'
// and SP and its trailing run of SP, HT and CR; N1 applied, then cut to TitleByteCount on a code point.
func searchOracleTitle(text []byte, settings *SearchOracleExtractSettings) string {
	for start := 0; ; {
		end := len(text)
		if lf := bytes.IndexByte(text[start:], '\n'); 0 <= lf {
			end = start + lf
		}
		line := text[start:end]
		holds := false
		for _, r := range searchOracleValidUtf8(line) {
			if unicode.IsLetter(r) || unicode.IsNumber(r) {
				holds = true
				break
			}
		}
		if holds {
			left, right := 0, len(line)
			for left < right && (line[left] == '#' || line[left] == ' ') {
				left += 1
			}
			for left < right && (line[right-1] == ' ' || line[right-1] == '\t' || line[right-1] == '\r') {
				right -= 1
			}
			return searchOracleCut(searchOracleValidUtf8(line[left:right]), settings.TitleByteCount)
		}
		if end == len(text) {
			return ""
		}
		start = end + 1
	}
}

// One field of a header block (H5): its name lowered and trimmed, its value trimmed.
type searchOracleHeaderField struct {
	name  string
	value []byte
}

// A header block's fields, in order.
type searchOracleHeader []*searchOracleHeaderField

// H6: the value of the first field of name, or empty.
func (self searchOracleHeader) first(name string) []byte {
	for _, field := range self {
		if field.name == name {
			return field.value
		}
	}
	return nil
}

// H6: the values of every field of name, in order, one SP between each two, an empty value included, cut to its first
// HeaderMaxByteCount bytes.
func (self searchOracleHeader) joined(name string, settings *SearchOracleExtractSettings) []byte {
	joined := []byte{}
	count := 0
	for _, field := range self {
		if field.name != name {
			continue
		}
		if 0 < count {
			joined = append(joined, ' ')
		}
		joined = append(joined, field.value...)
		count += 1
	}
	return joined[:min(len(joined), settings.HeaderMaxByteCount)]
}

// H1-H5: the header block's fields and the body after it. Lines end at LF, less one CR; the block ends at the first
// empty line, whose LF the body follows; with none, everything is header. A line beginning with a blank byte joins
// the logical line before it as it is, and a logical line keeps its first HeaderMaxByteCount bytes.
func searchOracleHeaderBlock(content []byte, settings *SearchOracleExtractSettings) (searchOracleHeader, []byte) {
	logicalLines := [][]byte{}
	var body []byte
	for start := 0; start < len(content); {
		end, next := len(content), len(content)
		if lf := bytes.IndexByte(content[start:], '\n'); 0 <= lf {
			end, next = start+lf, start+lf+1
		}
		line := content[start:end]
		if 0 < len(line) && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			body = content[next:]
			break
		}
		if searchOracleBlank(line[0]) && 0 < len(logicalLines) {
			last := logicalLines[len(logicalLines)-1]
			logicalLines[len(logicalLines)-1] = append(last, line[:min(len(line), settings.HeaderMaxByteCount-len(last))]...)
		} else {
			logicalLines = append(logicalLines, bytes.Clone(line[:min(len(line), settings.HeaderMaxByteCount)]))
		}
		start = next
	}
	header := searchOracleHeader{}
	for _, line := range logicalLines {
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		header = append(header, &searchOracleHeaderField{
			name:  string(searchOracleLower(searchOracleTrim(line[:colon]))),
			value: searchOracleTrim(line[colon+1:]),
		})
	}
	return header, body
}

// W1-W6: value with its RFC 2047 encoded words decoded. The scan takes the leftmost "=?" that starts a word, or moves
// 2 bytes past one that does not; text between two words that is empty or only blank bytes is dropped, and all other
// text kept.
func searchOracleWords(value []byte) []byte {
	out := []byte{}
	// where the text not yet given begins, and whether a word stands before it
	textStart := 0
	afterWord := false
	for position := 0; ; {
		at := bytes.Index(value[position:], []byte("=?"))
		if at < 0 {
			break
		}
		at += position
		decoded, end, ok := searchOracleEncodedWord(value, at)
		if !ok {
			position = at + 2
			continue
		}
		between := value[textStart:at]
		blank := true
		for _, c := range between {
			if !searchOracleBlank(c) {
				blank = false
				break
			}
		}
		if !afterWord || !blank {
			out = append(out, between...)
		}
		out = append(out, decoded...)
		position, textStart, afterWord = end, end, true
	}
	return append(out, value[textStart:]...)
}

// The encoded word "=?" C "?" E "?" T "?=" starting at value[at:] (W1-W4): its text and where it ends, or false.
func searchOracleEncodedWord(value []byte, at int) ([]byte, int, bool) {
	cEnd := bytes.IndexByte(value[at+2:], '?')
	if cEnd < 0 {
		return nil, 0, false
	}
	cEnd += at + 2
	if len(value) <= cEnd+2 || value[cEnd+2] != '?' {
		return nil, 0, false
	}
	wordEncoding := value[cEnd+1]
	tStart := cEnd + 3
	tEnd := bytes.IndexByte(value[tStart:], '?')
	if tEnd < 0 {
		return nil, 0, false
	}
	tEnd += tStart
	if len(value) <= tEnd+1 || value[tEnd+1] != '=' {
		return nil, 0, false
	}
	charset := value[at+2 : cEnd]
	if star := bytes.IndexByte(charset, '*'); 0 <= star {
		charset = charset[:star]
	}
	text := value[tStart:tEnd]
	if len(charset) == 0 || 0 <= bytes.IndexAny(charset, " \t") || 0 <= bytes.IndexAny(text, " \t") {
		return nil, 0, false
	}
	var raw []byte
	switch wordEncoding {
	case 'B', 'b':
		// W3: every '=' at the end goes, and what is left is all alphabet and not 1 more than a multiple of 4
		end := len(text)
		for 0 < end && text[end-1] == '=' {
			end -= 1
		}
		values := make([]byte, 0, end)
		for _, c := range text[:end] {
			v, ok := searchOracleBase64Value(c)
			if !ok {
				return nil, 0, false
			}
			values = append(values, v)
		}
		if len(values)%4 == 1 {
			return nil, 0, false
		}
		raw = searchOracleBase64Groups(values)
	case 'Q', 'q':
		// W4
		raw = make([]byte, 0, len(text))
		for i := 0; i < len(text); i += 1 {
			switch c := text[i]; c {
			case '_':
				raw = append(raw, ' ')
			case '=':
				if len(text) <= i+2 {
					return nil, 0, false
				}
				high, highOk := searchOracleHexValue(text[i+1])
				low, lowOk := searchOracleHexValue(text[i+2])
				if !highOk || !lowOk {
					return nil, 0, false
				}
				raw = append(raw, high<<4|low)
				i += 2
			default:
				raw = append(raw, c)
			}
		}
	default:
		return nil, 0, false
	}
	return searchOracleDecodeCharset(charset, raw), tEnd + 2, true
}

// A base64 alphabet byte's value (A-Z a-z 0-9 + /).
func searchOracleBase64Value(c byte) (byte, bool) {
	switch {
	case 'A' <= c && c <= 'Z':
		return c - 'A', true
	case 'a' <= c && c <= 'z':
		return c - 'a' + 26, true
	case '0' <= c && c <= '9':
		return c - '0' + 52, true
	case c == '+':
		return 62, true
	case c == '/':
		return 63, true
	}
	return 0, false
}

// Each 4 values give 3 bytes; a last 2 give 1 and a last 3 give 2, the unused bits ignored; a last 1 gives none.
func searchOracleBase64Groups(values []byte) []byte {
	out := make([]byte, 0, len(values)/4*3+2)
	whole := len(values) / 4 * 4
	for i := 0; i < whole; i += 4 {
		v := uint32(values[i])<<18 | uint32(values[i+1])<<12 | uint32(values[i+2])<<6 | uint32(values[i+3])
		out = append(out, byte(v>>16), byte(v>>8), byte(v))
	}
	switch rest := values[whole:]; len(rest) {
	case 2:
		out = append(out, rest[0]<<2|rest[1]>>4)
	case 3:
		out = append(out, rest[0]<<2|rest[1]>>4, rest[1]<<4|rest[2]>>2)
	}
	return out
}

// The encoding a charset label names (C1): its trimmed bytes all 0x21 to 0x7E, and their lower one of x/text
// v0.43.0's htmlindex labels; with htmlindex's name for it.
func searchOracleCharset(label []byte) (encoding.Encoding, string, bool) {
	label = searchOracleTrim(label)
	if len(label) == 0 {
		return nil, "", false
	}
	for _, c := range label {
		if c < 0x21 || 0x7E < c {
			return nil, "", false
		}
	}
	named, err := htmlindex.Get(string(searchOracleLower(label)))
	if err != nil {
		return nil, "", false
	}
	name, err := htmlindex.Name(named)
	if err != nil {
		return nil, "", false
	}
	return named, name, true
}

// C1-C3: raw as label says. No label, one that names nothing, and utf-8 and replacement leave the bytes as they are,
// for N1; any other is x/text's decoder, which answers malformed input with U+FFFD and never fails.
func searchOracleDecodeCharset(label []byte, raw []byte) []byte {
	named, name, ok := searchOracleCharset(label)
	if !ok || name == "utf-8" || name == "replacement" {
		return raw
	}
	decoded, err := named.NewDecoder().Bytes(raw)
	if err != nil {
		return raw
	}
	return decoded
}

// One RFC 2231 section piece: its raw value and whether it is extended.
type searchOracleSection struct {
	raw      []byte
	extended bool
}

// A Content-Type or Content-Disposition field read by P1-P3: its value, and the first plain, extended and section
// pieces of each parameter name.
type searchOracleParams struct {
	value           []byte
	namePlains      map[string][]byte
	nameExtendeds   map[string][]byte
	nameSectionSets map[string]map[int]*searchOracleSection
}

func searchOracleParseParams(field []byte, settings *SearchOracleExtractSettings) *searchOracleParams {
	params := &searchOracleParams{
		namePlains:      map[string][]byte{},
		nameExtendeds:   map[string][]byte{},
		nameSectionSets: map[string]map[int]*searchOracleSection{},
	}
	semicolon := bytes.IndexByte(field, ';')
	if semicolon < 0 {
		params.value = searchOracleLower(searchOracleTrim(field))
		return params
	}
	params.value = searchOracleLower(searchOracleTrim(field[:semicolon]))
	// P2: split at each ';' outside quotes; inside, a '\' and the byte after it pass together; an open quote runs on
	pieces := [][]byte{}
	rest := field[semicolon+1:]
	pieceStart := 0
	quoted := false
	for i := 0; i < len(rest); i += 1 {
		switch c := rest[i]; {
		case quoted && c == '\\':
			i += 1
		case c == '"':
			quoted = !quoted
		case c == ';' && !quoted:
			pieces = append(pieces, rest[pieceStart:i])
			pieceStart = i + 1
		}
	}
	pieces = append(pieces, rest[pieceStart:])
	for _, piece := range pieces {
		// P3
		equals := bytes.IndexByte(piece, '=')
		if equals < 0 {
			continue
		}
		name := searchOracleLower(searchOracleTrim(piece[:equals]))
		raw := searchOracleTrim(piece[equals+1:])
		extended := false
		if 0 < len(name) && name[len(name)-1] == '*' {
			extended = true
			name = name[:len(name)-1]
		}
		star := bytes.IndexByte(name, '*')
		if star < 0 {
			pieceValues := params.namePlains
			if extended {
				pieceValues = params.nameExtendeds
			}
			if _, ok := pieceValues[string(name)]; !ok {
				pieceValues[string(name)] = raw
			}
			continue
		}
		digits := name[star+1:]
		if len(digits) < 1 || settings.SectionDigitCount < len(digits) {
			continue
		}
		section := 0
		numeric := true
		for _, c := range digits {
			if c < '0' || '9' < c {
				numeric = false
				break
			}
			section = section*10 + int(c-'0')
		}
		if !numeric {
			continue
		}
		sectionSet := params.nameSectionSets[string(name[:star])]
		if sectionSet == nil {
			sectionSet = map[int]*searchOracleSection{}
			params.nameSectionSets[string(name[:star])] = sectionSet
		}
		if _, ok := sectionSet[section]; !ok {
			sectionSet[section] = &searchOracleSection{raw: raw, extended: extended}
		}
	}
	return params
}

// P5 and P6: the joined sections from 0 where they join to something, else the extended piece, else the plain
// piece, else empty.
func (self *searchOracleParams) param(name string) []byte {
	if sectionSet := self.nameSectionSets[name]; sectionSet != nil {
		var charset []byte
		joined := []byte{}
		for n := 0; ; n += 1 {
			section, ok := sectionSet[n]
			if !ok {
				break
			}
			switch {
			case section.extended && n == 0:
				var text []byte
				charset, text = searchOracleSplitExtended(section.raw)
				joined = append(joined, searchOracleUnpercent(text)...)
			case section.extended:
				joined = append(joined, searchOracleUnpercent(section.raw)...)
			default:
				joined = append(joined, searchOracleUnquote(section.raw)...)
			}
		}
		if 0 < len(joined) {
			return searchOracleDecodeCharset(charset, joined)
		}
	}
	if raw, ok := self.nameExtendeds[name]; ok {
		charset, text := searchOracleSplitExtended(raw)
		return searchOracleDecodeCharset(charset, searchOracleUnpercent(text))
	}
	if raw, ok := self.namePlains[name]; ok {
		return searchOracleUnquote(raw)
	}
	return nil
}

// P4: a plain piece's raw value unquoted, when it is at least 2 bytes and begins and ends with '"'; inside, a '\'
// followed by a byte gives that byte. Anything else as written.
func searchOracleUnquote(raw []byte) []byte {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return raw
	}
	inner := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(inner))
	for i := 0; i < len(inner); i += 1 {
		if inner[i] == '\\' && i+1 < len(inner) {
			i += 1
		}
		out = append(out, inner[i])
	}
	return out
}

// P6: an extended value's charset and text when it holds two "'", the first two splitting it; else all text and no
// charset.
func searchOracleSplitExtended(raw []byte) ([]byte, []byte) {
	first := bytes.IndexByte(raw, '\'')
	if first < 0 {
		return nil, raw
	}
	second := bytes.IndexByte(raw[first+1:], '\'')
	if second < 0 {
		return nil, raw
	}
	return raw[:first], raw[first+1+second+1:]
}

// P6: '%' and two hex digits are that byte; if any '%' is followed by anything else, the whole text stands.
func searchOracleUnpercent(text []byte) []byte {
	out := make([]byte, 0, len(text))
	for i := 0; i < len(text); i += 1 {
		if text[i] != '%' {
			out = append(out, text[i])
			continue
		}
		if len(text) <= i+2 {
			return text
		}
		high, highOk := searchOracleHexValue(text[i+1])
		low, lowOk := searchOracleHexValue(text[i+2])
		if !highOk || !lowOk {
			return text
		}
		out = append(out, high<<4|low)
		i += 2
	}
	return out
}

// M1-M6: what an entity gives the pieces. A multipart's parts are walked one level deeper, down to MimeDepth levels;
// any other entity gives its name, and then, unless it is an attachment, a text/plain or text/html part's text.
func searchOracleWalk(header searchOracleHeader, body []byte, depth int, inDigest bool, pieces *[][]byte, settings *SearchOracleExtractSettings) {
	contentType := searchOracleParseParams(header.first("content-type"), settings)
	disposition := searchOracleParseParams(header.first("content-disposition"), settings)
	mediaType := string(contentType.value)
	if mediaType == "" {
		mediaType = "text/plain"
		if inDigest {
			mediaType = "message/rfc822"
		}
	}
	if bytes.HasPrefix([]byte(mediaType), []byte("multipart/")) {
		boundary := contentType.param("boundary")
		if len(boundary) == 0 || settings.MimeDepth <= depth {
			return
		}
		for _, part := range searchOracleParts(body, boundary, settings) {
			partHeader, partBody := searchOracleHeaderBlock(part, settings)
			searchOracleWalk(partHeader, partBody, depth+1, mediaType == "multipart/digest", pieces, settings)
		}
		return
	}
	name := disposition.param("filename")
	if len(name) == 0 {
		name = contentType.param("name")
	}
	if 0 < len(name) {
		*pieces = append(*pieces, searchOracleWords(name))
	}
	if string(disposition.value) == "attachment" {
		return
	}
	switch mediaType {
	case "text/plain":
		*pieces = append(*pieces, searchOracleDecodeCharset(contentType.param("charset"), searchOracleTransfer(header.first("content-transfer-encoding"), body, settings)))
	case "text/html":
		*pieces = append(*pieces, searchOracleHtmlText(searchOracleDecodeCharset(contentType.param("charset"), searchOracleTransfer(header.first("content-transfer-encoding"), body, settings))))
	}
}

// B1-B4: a multipart body's parts. A delimiter line is at most LineWindowByteCount bytes and, less its trailing run of
// SP, HT and CR, is "--" boundary, or "--" boundary "--" to close; a part runs from after one delimiter line's LF to
// before the next, less that line's own break, and with no close the last runs to the end with its break.
func searchOracleParts(body []byte, boundary []byte, settings *SearchOracleExtractSettings) [][]byte {
	delimiter := append([]byte("--"), boundary...)
	closeDelimiter := append(bytes.Clone(delimiter), "--"...)
	parts := [][]byte{}
	inPart := false
	partStart := 0
	for start := 0; ; {
		end, next := len(body), len(body)
		lf := bytes.IndexByte(body[start:], '\n')
		if 0 <= lf {
			end, next = start+lf, start+lf+1
		}
		line := body[start:end]
		if len(line) <= settings.LineWindowByteCount {
			stripped := len(line)
			for 0 < stripped && (line[stripped-1] == ' ' || line[stripped-1] == '\t' || line[stripped-1] == '\r') {
				stripped -= 1
			}
			isDelimiter := bytes.Equal(line[:stripped], delimiter)
			isClose := bytes.Equal(line[:stripped], closeDelimiter)
			if isDelimiter || isClose {
				if inPart {
					part := body[partStart:start]
					if 0 < len(part) && part[len(part)-1] == '\n' {
						part = part[:len(part)-1]
						if 0 < len(part) && part[len(part)-1] == '\r' {
							part = part[:len(part)-1]
						}
					}
					parts = append(parts, part)
				}
				if isClose {
					return parts
				}
				inPart = true
				partStart = next
			}
		}
		if lf < 0 {
			break
		}
		start = next
	}
	if inPart {
		parts = append(parts, body[partStart:])
	}
	return parts
}

// T1-T3: a body under its Content-Transfer-Encoding: base64 and quoted-printable decoded by their rules, anything
// else as it is.
func searchOracleTransfer(transferEncoding []byte, body []byte, settings *SearchOracleExtractSettings) []byte {
	switch string(searchOracleLower(searchOracleTrim(transferEncoding))) {
	case "base64":
		// T2: white bytes are skipped, and decoding ends at the first byte that is neither white nor alphabet
		values := make([]byte, 0, len(body))
		for _, c := range body {
			if searchOracleWhite(c) {
				continue
			}
			v, ok := searchOracleBase64Value(c)
			if !ok {
				break
			}
			values = append(values, v)
		}
		return searchOracleBase64Groups(values)
	case "quoted-printable":
		return searchOracleQuotedPrintable(body, settings)
	}
	return body
}

// T3: '=' and two hex digits are that byte; an '=' followed by at most LineWindowByteCount blank bytes and then LF,
// CR LF or the end is a soft line break, all of it consumed; any other '=' and every other byte are themselves.
func searchOracleQuotedPrintable(body []byte, settings *SearchOracleExtractSettings) []byte {
	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); {
		c := body[i]
		if c != '=' {
			out = append(out, c)
			i += 1
			continue
		}
		if i+2 < len(body) {
			high, highOk := searchOracleHexValue(body[i+1])
			low, lowOk := searchOracleHexValue(body[i+2])
			if highOk && lowOk {
				out = append(out, high<<4|low)
				i += 3
				continue
			}
		}
		// the blank run after the '=', counted to one past what a soft break may hold
		j := i + 1
		for j < len(body) && searchOracleBlank(body[j]) && j-(i+1) <= settings.LineWindowByteCount {
			j += 1
		}
		if j-(i+1) <= settings.LineWindowByteCount {
			switch {
			case j == len(body):
				i = j
				continue
			case body[j] == '\n':
				i = j + 1
				continue
			case body[j] == '\r' && j+1 < len(body) && body[j+1] == '\n':
				i = j + 2
				continue
			}
		}
		out = append(out, c)
		i += 1
	}
	return out
}

// 11.2.6: every tag goes, then character references decode in what is left, once.
func searchOracleHtmlText(text []byte) []byte {
	return searchOracleReferences(searchOracleTags(text))
}

// The index of the '>' that ends a tag beginning at tag[0], looking from tag[1], outside quotes: a '"' or "'" opens
// quotes and the next byte equal to it closes them (X3); -1 with none.
func searchOracleTagEnd(tag []byte) int {
	var quote byte
	for i := 1; i < len(tag); i += 1 {
		switch c := tag[i]; {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '>':
			return i
		}
	}
	return -1
}

// X1-X7: text without its comments, declarations and tags, a script's or style's content going with it; a block tag
// leaves one SP. A comment, declaration or tag with no end, a script or style with no end tag, and an end tag with no
// '>' take everything to the end.
func searchOracleTags(text []byte) []byte {
	out := make([]byte, 0, len(text))
	for i := 0; i < len(text); {
		if text[i] != '<' {
			out = append(out, text[i])
			i += 1
			continue
		}
		rest := text[i:]
		switch {
		case bytes.HasPrefix(rest, []byte("<!--")):
			// X1: ends after the first "-->" beginning 4 or more bytes past the '<'
			end := bytes.Index(rest[4:], []byte("-->"))
			if end < 0 {
				return out
			}
			i += 4 + end + 3
		case bytes.HasPrefix(rest, []byte("<!")) || bytes.HasPrefix(rest, []byte("<?")):
			// X2
			end := bytes.IndexByte(rest[2:], '>')
			if end < 0 {
				return out
			}
			i += 2 + end + 1
		case 2 <= len(rest) && (searchOracleLetter(rest[1]) || rest[1] == '/'):
			// X3 and X4
			end := searchOracleTagEnd(rest)
			if end < 0 {
				return out
			}
			closing := rest[1] == '/'
			nameStart := 1
			if closing {
				nameStart = 2
			}
			nameEnd := nameStart
			for nameEnd < len(rest) && searchOracleAlphanumeric(rest[nameEnd]) {
				nameEnd += 1
			}
			name := string(searchOracleLower(rest[nameStart:nameEnd]))
			i += end + 1
			if !closing && (name == "script" || name == "style") {
				// X5: the content to the first "</" and the name, ignoring case, then the end or a byte that is
				// not alphanumeric; that end tag ends by X3
				closeAt := -1
				for j := i; j+1 < len(text); j += 1 {
					if text[j] != '<' || text[j+1] != '/' || len(text) < j+2+len(name) {
						continue
					}
					if string(searchOracleLower(text[j+2:j+2+len(name)])) != name {
						continue
					}
					if after := j + 2 + len(name); after == len(text) || !searchOracleAlphanumeric(text[after]) {
						closeAt = j
						break
					}
				}
				if closeAt < 0 {
					return out
				}
				closeEnd := searchOracleTagEnd(text[closeAt:])
				if closeEnd < 0 {
					return out
				}
				i = closeAt + closeEnd + 1
				continue
			}
			if searchOracleBlockTags[name] {
				out = append(out, ' ')
			}
		default:
			// X6
			out = append(out, '<')
			i += 1
		}
	}
	return out
}

// E1-E4: text with its character references decoded, by HTML's rule for text outside attributes with its table
// whole.
func searchOracleReferences(text []byte) []byte {
	out := make([]byte, 0, len(text))
	for i := 0; i < len(text); {
		if text[i] != '&' {
			out = append(out, text[i])
			i += 1
			continue
		}
		if i+1 < len(text) && text[i+1] == '#' {
			// E1: decimal digits, or hex digits after an 'x' or 'X', then an optional ';'
			j := i + 2
			base := 10
			if j < len(text) && (text[j] == 'x' || text[j] == 'X') {
				base = 16
				j += 1
			}
			value := 0
			digits := 0
			for ; j < len(text); j += 1 {
				d, ok := searchOracleHexValue(text[j])
				if !ok || (base == 10 && 9 < d) {
					break
				}
				value = min(value*base+int(d), searchOracleCodePointLimit)
				digits += 1
			}
			if digits == 0 {
				out = append(out, '&')
				i += 1
				continue
			}
			if j < len(text) && text[j] == ';' {
				j += 1
			}
			switch {
			case 0x80 <= value && value <= 0x9F:
				out = utf8.AppendRune(out, searchOracleC1References[value-0x80])
			case value == 0, 0xD800 <= value && value <= 0xDFFF, searchOracleCodePointLimit <= value:
				out = utf8.AppendRune(out, utf8.RuneError)
			default:
				out = utf8.AppendRune(out, rune(value))
			}
			i = j
			continue
		}
		// E2: the alphanumeric bytes after the '&', and a ';' if one follows them
		j := i + 1
		for j < len(text) && searchOracleAlphanumeric(text[j]) {
			j += 1
		}
		if j == i+1 {
			out = append(out, '&')
			i += 1
			continue
		}
		nameEnd := j
		if j < len(text) && text[j] == ';' {
			nameEnd = j + 1
		}
		name := text[i+1 : nameEnd]
		if value, ok := searchOracleReferenceTable[string(name)]; ok {
			out = append(out, value...)
			i = nameEnd
			continue
		}
		// E3: the longest prefix, 6 bytes at most and 2 at least, that is a name without ';'
		matched := false
		for k := min(searchOracleLegacyNameByteCount, len(name)-1); 2 <= k; k -= 1 {
			if value, ok := searchOracleReferenceTable[string(name[:k])]; ok {
				out = append(out, value...)
				i += 1 + k
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		// E4
		out = append(out, text[i:nameEnd]...)
		i = nameEnd
	}
	return out
}
