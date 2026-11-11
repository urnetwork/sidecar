//go:build !ios_extension

// Extractor 1 for mail (§11.14's extract row; §15.7's search index row; D-MAIL-16; DESIGN-DETAILS 11.2.5 and
// protocol/INDEX-FORMAT.md's Extractor 1): a message is read as RFC 5322 and MIME lay it out, by the rules H1-H6
// (the header block), W1-W6 (encoded words), P1-P6 (media values and parameters), C1-C3 (charsets), M1-M6 (the walk)
// and B1-B4 (multipart bodies), and no others. Its documents carry the message's own Subject, From, and To with Cc,
// words decoded, and in field 5 each part's name and each text/plain and text/html part's text in the message's order
// (D3); never a transport header, an attachment's bytes or a message/rfc822 part's text.
//
// Every reading is this file's own byte loop, so no library's release changes the bytes an index holds (QD-690): the
// one outside table is x/text v0.43.0's charset decoders, which normalizer 1 already pins. Names, labels and
// encodings compare under lower, only the white bytes are trimmed (evs_index_extract_transfer.go), and two limits from
// IndexFormatSettings bound what one pass holds: HeaderMaxByteCount for a header line and a joined value, and
// LineWindowByteCount for a delimiter line (QD-691).
//
// Extraction is total: every byte string gives at least one document and no error, and the fields hold at most 3.6
// times the message (11.3's R3). Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
)

// One header field: its name, lower(trim()) of the bytes before its first ':', and its value, trim() of those after
// (H5).
type indexMailHeaderField struct {
	name  string
	value string
}

// A message's or an entity's header fields, in order.
type indexMailHeader []indexMailHeaderField

// H6's first(name): the value of the first field of that name, or empty.
func (self indexMailHeader) first(name string) string {
	for _, field := range self {
		if field.name == name {
			return field.value
		}
	}
	return ""
}

// H6's joined(name): the values of every field of that name, in order, one SP between each two, an empty one
// included, cut to its first HeaderMaxByteCount bytes.
func (self indexMailHeader) joined(name string, settings *IndexFormatSettings) string {
	joined := []byte{}
	found := false
	for _, field := range self {
		if field.name != name {
			continue
		}
		if found {
			joined = append(joined, ' ')
		}
		found = true
		joined = append(joined, field.value...)
		if settings.HeaderMaxByteCount <= len(joined) {
			break
		}
	}
	return string(joined[:min(len(joined), settings.HeaderMaxByteCount)])
}

// H1 to H5: the header block's fields and the body. Lines end at LF, a line's content is its bytes before the LF less
// one CR, and the last line may end at the end of content. The block ends at the first line whose content is empty,
// and the body is everything after that line's LF; with no empty line, everything is header and the body is empty. A
// line opening with a blank byte, after a logical line, is appended to it as it is; any other begins one. A logical
// line keeps its first HeaderMaxByteCount bytes, the rest dropped as they arrive, and one with no ':' is no field.
func indexSplitMailHeader(content []byte, settings *IndexFormatSettings) (indexMailHeader, []byte) {
	header := indexMailHeader{}
	logical := []byte{}
	open := false
	finish := func() {
		if !open {
			return
		}
		if name, value, ok := bytes.Cut(logical, []byte(":")); ok {
			header = append(header, indexMailHeaderField{name: indexLower(indexTrim(string(name))), value: indexTrim(string(value))})
		}
	}
	appendKept := func(line []byte) {
		logical = append(logical, line[:min(len(line), settings.HeaderMaxByteCount-len(logical))]...)
	}
	rest := content
	for 0 < len(rest) {
		line := rest
		if end := bytes.IndexByte(rest, '\n'); 0 <= end {
			line, rest = rest[:end], rest[end+1:]
		} else {
			rest = nil
		}
		if 0 < len(line) && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			finish()
			return header, rest
		}
		if open && indexBlank(line[0]) {
			appendKept(line)
			continue
		}
		finish()
		logical = logical[:0]
		open = true
		appendKept(line)
	}
	finish()
	return header, nil
}

// C1: the encoding a charset label names, by x/text's htmlindex name, and false when it names none. A label, trimmed,
// names one when every byte of it is 0x21 to 0x7E and lower of it is one of htmlindex's labels
// (testdata/index/conformance/charsets.json's 228), so no label is ever read as Unicode text.
func indexCharsetEncoding(label string) (encoding.Encoding, string, bool) {
	label = indexTrim(label)
	if label == "" {
		return nil, "", false
	}
	for index := 0; index < len(label); index += 1 {
		if label[index] < 0x21 || 0x7E < label[index] {
			return nil, "", false
		}
	}
	// htmlindex lowers and trims as it looks up, which on these bytes is lower and nothing
	labelled, err := htmlindex.Get(label)
	if err != nil {
		return nil, "", false
	}
	name, err := htmlindex.Name(labelled)
	if err != nil {
		return nil, "", false
	}
	return labelled, name, true
}

// C1's name for a label: the htmlindex name of the encoding it names, false for none.
func indexCharsetName(label string) (string, bool) {
	_, name, ok := indexCharsetEncoding(label)
	return name, ok
}

// C2 and C3: raw as the charset label says. No label, one that names nothing, and one naming utf-8 or replacement
// leave the bytes as they are, ill-formed UTF-8 then meeting normalizer 1's N1; any other is decoded by x/text
// v0.43.0's decoder for its encoding, which answers malformed input with U+FFFD and never fails. No charset is guessed
// from content.
func indexDecodeCharset(label string, raw []byte) []byte {
	labelled, name, ok := indexCharsetEncoding(label)
	if !ok || name == "utf-8" || name == "replacement" {
		return raw
	}
	decoded, err := labelled.NewDecoder().Bytes(raw)
	if err != nil {
		return raw
	}
	return decoded
}

// W1 to W4: one encoded word, "=?" C "?" E "?" T "?=", at value's start, C, E and T holding no '?' and E one byte of
// B, b, Q or q: its text decoded, T by W3 or W4 and then as the charset says, and its length; false when value does
// not start with one, or when its charset, C up to its first '*', is empty, it or T holds a blank byte, or W3 or W4
// refuses T.
func indexDecodeEncodedWord(value string) (string, int, bool) {
	if !strings.HasPrefix(value, "=?") {
		return "", 0, false
	}
	// C, E and T, each up to the next '?', and then '='
	ends := [3]int{}
	position := 2
	for part := range 3 {
		end := strings.IndexByte(value[position:], '?')
		if end < 0 {
			return "", 0, false
		}
		ends[part] = position + end
		position = position + end + 1
	}
	if position == len(value) || value[position] != '=' {
		return "", 0, false
	}
	charsetPart, encodingPart, text := value[2:ends[0]], value[ends[0]+1:ends[1]], value[ends[1]+1:ends[2]]
	if len(encodingPart) != 1 {
		return "", 0, false
	}
	charset := charsetPart
	if star := strings.IndexByte(charsetPart, '*'); 0 <= star {
		charset = charsetPart[:star]
	}
	if charset == "" || strings.ContainsAny(charset, " \t") || strings.ContainsAny(text, " \t") {
		return "", 0, false
	}
	var raw []byte
	switch encodingPart[0] {
	case 'B', 'b':
		decoded, ok := indexBase64Word([]byte(text))
		if !ok {
			return "", 0, false
		}
		raw = decoded
	case 'Q', 'q':
		for index := 0; index < len(text); index += 1 {
			switch b := text[index]; b {
			case '_':
				raw = append(raw, ' ')
			case '=':
				if len(text) < index+3 {
					return "", 0, false
				}
				high, low := indexHexValue(text[index+1]), indexHexValue(text[index+2])
				if high < 0 || low < 0 {
					return "", 0, false
				}
				raw = append(raw, byte(high<<4|low))
				index += 2
			default:
				raw = append(raw, b)
			}
		}
	default:
		return "", 0, false
	}
	return string(indexDecodeCharset(charset, raw)), position + 1, true
}

// W5 and W6, words(value): value scanned from the left for the leftmost "=?" at or after the position; an encoded word
// starting there is taken and the position moves past its "?=", else the position moves 2 bytes on. The text between
// two encoded words is dropped when it is empty or only blank bytes and kept otherwise; text before the first, after
// the last, and between a word and anything that is not one is kept.
func indexDecodeEncodedWords(value string) string {
	decoded := []byte{}
	// where the text since the last word starts, which goes only if it is blank between two; an offset, so a value
	// of many "=?" that open no word is read once
	pendingStart := 0
	afterWord := false
	for search := 0; ; {
		offset := strings.Index(value[search:], "=?")
		if offset < 0 {
			break
		}
		start := search + offset
		word, length, ok := indexDecodeEncodedWord(value[start:])
		if !ok {
			search = start + 2
			continue
		}
		pending := value[pendingStart:start]
		if !afterWord || strings.Trim(pending, " \t") != "" {
			decoded = append(decoded, pending...)
		}
		decoded = append(decoded, word...)
		afterWord = true
		search = start + length
		pendingStart = search
	}
	decoded = append(decoded, value[pendingStart:]...)
	return string(decoded)
}

// One piece of a parameter (P3): its value as it stands, raw for an extended piece and unquoted for a plain one, and
// whether it is extended.
type indexMediaPiece struct {
	text     string
	extended bool
}

// A Content-Type's or Content-Disposition's value and parameters (P1 to P3), each kept by name, kind and section, the
// first piece of each counting.
type indexMediaValue struct {
	// lower(trim()) of the bytes before the first ';'.
	value    string
	plain    map[string]string
	extended map[string]string
	sections map[string]map[int]indexMediaPiece
}

// P1 to P4: a media value's value and its parameters. The bytes after the first ';' split at each ';' outside quotes,
// a '"' opening quotes and the next closing them, inside which a '\' and the byte after it pass together; a quote
// left open runs to the end. A piece with no '=' is no parameter; its name is lower(trim()) of the bytes before the
// first '=' and its raw value trim() of those after. A name ending in '*' is extended and loses that '*', and one that
// then holds a '*' is the name before it and a section after it of 1 to 9 digits, or no parameter.
func indexParseMediaValue(value string) *indexMediaValue {
	head, rest, _ := strings.Cut(value, ";")
	media := &indexMediaValue{
		value:    indexLower(indexTrim(head)),
		plain:    map[string]string{},
		extended: map[string]string{},
		sections: map[string]map[int]indexMediaPiece{},
	}
	pieces := []string{}
	pieceStart := 0
	quoted := false
	for index := 0; index < len(rest); index += 1 {
		switch b := rest[index]; {
		case quoted && b == '\\':
			index += 1
		case b == '"':
			quoted = !quoted
		case !quoted && b == ';':
			pieces = append(pieces, rest[pieceStart:index])
			pieceStart = index + 1
		}
	}
	pieces = append(pieces, rest[pieceStart:])
	for _, piece := range pieces {
		equals := strings.IndexByte(piece, '=')
		if equals < 0 {
			continue
		}
		name := indexLower(indexTrim(piece[:equals]))
		raw := indexTrim(piece[equals+1:])
		extended := strings.HasSuffix(name, "*")
		name = strings.TrimSuffix(name, "*")
		if star := strings.IndexByte(name, '*'); 0 <= star {
			section, ok := indexParseSection(name[star+1:])
			if !ok {
				continue
			}
			name = name[:star]
			text := raw
			if !extended {
				text = indexUnquote(raw)
			}
			if media.sections[name] == nil {
				media.sections[name] = map[int]indexMediaPiece{}
			}
			if _, ok := media.sections[name][section]; !ok {
				media.sections[name][section] = indexMediaPiece{text: text, extended: extended}
			}
			continue
		}
		if extended {
			if _, ok := media.extended[name]; !ok {
				media.extended[name] = raw
			}
		} else if _, ok := media.plain[name]; !ok {
			media.plain[name] = indexUnquote(raw)
		}
	}
	return media
}

// P3's section: 1 to 9 ASCII digits and nothing else, read as their number, which fits 31 bits on every leg.
func indexParseSection(digits string) (int, bool) {
	if len(digits) < 1 || 9 < len(digits) {
		return 0, false
	}
	section := 0
	for index := 0; index < len(digits); index += 1 {
		if !indexAsciiDigit(digits[index]) {
			return 0, false
		}
		section = section*10 + int(digits[index]-'0')
	}
	return section, true
}

// P5 and P6, param(name): sections 0, 1, 2, ... joined up to the first missing number when there is a section 0 and
// the join is not empty; else the extended piece; else the plain piece; else empty. An extended section is
// percent-decoded and a plain one is not, and only section 0, when extended, is split for a charset; the bytes then
// decode as that charset's label says.
func (self *indexMediaValue) param(name string) string {
	if sections := self.sections[name]; sections != nil {
		if _, ok := sections[0]; ok {
			charset := ""
			joined := []byte{}
			for section := 0; ; section += 1 {
				piece, ok := sections[section]
				if !ok {
					break
				}
				text := piece.text
				if piece.extended && section == 0 {
					charset, text = indexSplitExtended(text)
				}
				if piece.extended {
					joined = append(joined, indexPercentDecode(text)...)
				} else {
					joined = append(joined, text...)
				}
			}
			if 0 < len(joined) {
				return string(indexDecodeCharset(charset, joined))
			}
		}
	}
	if raw, ok := self.extended[name]; ok {
		charset, text := indexSplitExtended(raw)
		return string(indexDecodeCharset(charset, indexPercentDecode(text)))
	}
	return self.plain[name]
}

// P4: a plain piece's value unquoted: when it is at least 2 bytes and begins and ends with '"', those two go, and
// inside, a '\' followed by a byte gives that byte. Anything else is as written.
func indexUnquote(value string) string {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return value
	}
	inner := value[1 : len(value)-1]
	unquoted := make([]byte, 0, len(inner))
	for index := 0; index < len(inner); index += 1 {
		if inner[index] == '\\' && index+1 < len(inner) {
			index += 1
		}
		unquoted = append(unquoted, inner[index])
	}
	return string(unquoted)
}

// P6: an extended value's charset and its text, split at its first two "'" when it holds two, the language between
// them dropped; else all text with no charset.
func indexSplitExtended(value string) (string, string) {
	charset, rest, ok := strings.Cut(value, "'")
	if !ok {
		return "", value
	}
	_, text, ok := strings.Cut(rest, "'")
	if !ok {
		return "", value
	}
	return charset, text
}

// P6's percent-decoding: '%' and two hex digits are that byte; if any '%' is followed by anything else, the whole
// text stands as written.
func indexPercentDecode(text string) []byte {
	decoded := make([]byte, 0, len(text))
	for index := 0; index < len(text); index += 1 {
		if text[index] != '%' {
			decoded = append(decoded, text[index])
			continue
		}
		if len(text) < index+3 {
			return []byte(text)
		}
		high, low := indexHexValue(text[index+1]), indexHexValue(text[index+2])
		if high < 0 || low < 0 {
			return []byte(text)
		}
		decoded = append(decoded, byte(high<<4|low))
		index += 2
	}
	return decoded
}

// B1 to B4, parts(body, boundary): body split into lines at each LF. A line is a delimiter line when it is at most
// LineWindowByteCount bytes and, without its trailing run of SP, HT and CR, is "--" boundary, and the close delimiter
// when it is "--" boundary "--", compared as bytes from its first. A part runs from after a delimiter line's LF to
// before the next delimiter line, less that line's own break: a last LF, then a CR before it. Lines before the first
// delimiter, and everything after the close delimiter, belong to no part; with no close delimiter the last part runs
// to the end of body and keeps its last line break.
func indexMultipartParts(body []byte, boundary string, settings *IndexFormatSettings) [][]byte {
	delimiter := []byte("--" + boundary)
	closeDelimiter := []byte("--" + boundary + "--")
	parts := [][]byte{}
	partStart := -1
	for position := 0; position < len(body); {
		lineEnd := len(body)
		next := len(body)
		if end := bytes.IndexByte(body[position:], '\n'); 0 <= end {
			lineEnd = position + end
			next = lineEnd + 1
		}
		if lineEnd-position <= settings.LineWindowByteCount {
			trimmed := bytes.TrimRight(body[position:lineEnd], " \t\r")
			isClose := bytes.Equal(trimmed, closeDelimiter)
			if isClose || bytes.Equal(trimmed, delimiter) {
				if 0 <= partStart {
					part := bytes.TrimSuffix(body[partStart:position], []byte("\n"))
					if len(part) < position-partStart {
						part = bytes.TrimSuffix(part, []byte("\r"))
					}
					parts = append(parts, part)
				}
				if isClose {
					return parts
				}
				partStart = next
			}
		}
		position = next
	}
	if 0 <= partStart {
		parts = append(parts, body[partStart:])
	}
	return parts
}

// M1 to M6, walk: appends what an entity gives the body text. Its media type is its first Content-Type's value, or
// when that is empty text/plain, or message/rfc822 directly inside a multipart/digest; its parameters stand either way.
// A multipart with a boundary, above MimeMaxDepth, walks each of its parts, every part of an alternative too, and its
// own name is not read. Any other entity gives words of its name, its disposition's filename or else its type's name,
// when not empty; then, unless its disposition is attachment, a text/plain part its body transfer-decoded and as its
// charset says, and a text/html part html_to_text of the same. Nothing else gives more: no other type's bytes are
// decoded, and a message/rfc822 part is not entered.
func indexMimeWalk(header indexMailHeader, body []byte, depth int, inDigest bool, pieces *[][]byte, settings *IndexFormatSettings) {
	contentType := indexParseMediaValue(header.first("content-type"))
	disposition := indexParseMediaValue(header.first("content-disposition"))
	mediaType := contentType.value
	if mediaType == "" {
		mediaType = "text/plain"
		if inDigest {
			mediaType = "message/rfc822"
		}
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := contentType.param("boundary")
		if boundary == "" || settings.MimeMaxDepth <= depth {
			return
		}
		digest := mediaType == "multipart/digest"
		for _, part := range indexMultipartParts(body, boundary, settings) {
			partHeader, partBody := indexSplitMailHeader(part, settings)
			indexMimeWalk(partHeader, partBody, depth+1, digest, pieces, settings)
		}
		return
	}
	name := disposition.param("filename")
	if name == "" {
		name = contentType.param("name")
	}
	if name != "" {
		*pieces = append(*pieces, []byte(indexDecodeEncodedWords(name)))
	}
	if disposition.value == "attachment" {
		return
	}
	switch mediaType {
	case "text/plain":
		decoded := indexTransferDecode(header.first("content-transfer-encoding"), body, settings)
		*pieces = append(*pieces, indexDecodeCharset(contentType.param("charset"), decoded))
	case "text/html":
		decoded := indexTransferDecode(header.first("content-transfer-encoding"), body, settings)
		*pieces = append(*pieces, indexStripHtml(indexDecodeCharset(contentType.param("charset"), decoded)))
	}
}

// The values that are not empty, in order, with one SP between each two.
func indexJoinNonEmpty(values ...[]byte) []byte {
	joined := []byte{}
	for _, value := range values {
		if len(value) == 0 {
			continue
		}
		if len(joined) != 0 {
			joined = append(joined, ' ')
		}
		joined = append(joined, value...)
	}
	return joined
}

// D3: the documents of one message at path (§15.7's m/ files), one for each chunk of its body text (D4), each carrying
// the decoded Subject, From, and To with Cc, which are words of H6's joined value of the message's own header block.
// Version, provenance and the outside flag are the caller's to set.
func indexExtractMail(path []byte, content []byte, settings *IndexFormatSettings) []*IndexDocument {
	header, body := indexSplitMailHeader(content, settings)
	words := func(name string) []byte {
		return []byte(indexDecodeEncodedWords(header.joined(name, settings)))
	}
	subject := words("subject")
	from := words("from")
	to := indexJoinNonEmpty(words("to"), words("cc"))
	pieces := [][]byte{}
	indexMimeWalk(header, body, 0, false, &pieces, settings)
	text := indexJoinNonEmpty(pieces...)
	documents := []*IndexDocument{}
	for chunk, chunkText := range indexChunks(text, settings) {
		document := &IndexDocument{
			Kind:      IndexDocMail,
			Name:      path,
			Chunk:     uint32(chunk),
			ByteCount: uint64(len(content)),
		}
		document.Fields[indexFieldSubject] = subject
		document.Fields[indexFieldFrom] = from
		document.Fields[indexFieldTo] = to
		document.Fields[indexFieldBody] = chunkText
		documents = append(documents, document)
	}
	return documents
}
