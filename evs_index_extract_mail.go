// Extractor 1 for mail (§11.14's extract row; §15.7's search index row; D-MAIL-16): a message's From, To, Cc and
// Subject values, RFC 2047-decoded, and its text/plain parts, text/html parts stripped of tags, scripts and styles,
// and attachment names, MIME-decoded (RFC 2045-2047, 2231); never a transport header, an attachment's bytes or
// base64. Charsets decode through x/text's htmlindex from the pinned module, a label it does not know or none
// reading as UTF-8, and nothing is guessed from content (protocol/INDEX-FORMAT.md's Extractor 1). The parser is this
// file's own, as the HTML scanner is, so no library's bump changes the bytes an index holds.
//
// Readings this file takes where the format is silent, which SearchOracle takes too, pending question
// search-m10-07-extractor-field-placement: field 3 is To then Cc, and field 5 each part's name and then its text in
// MIME order, each joined by one space, empty ones left out; a part whose disposition is attachment gives only its
// name; a message's chunks are of its field 5 text, every chunk keeping fields 1-3; several fields of one name join
// by one space before their encoded words decode. And these of its own: the header ends at the first empty line, a
// continuation line keeps its leading whitespace, a line with no colon is passed over; no Content-Type reads as
// text/plain; multipart nesting is read 16 deep; base64 skips ASCII whitespace and stops at its first other
// character outside the alphabet, keeping what decoded before it, as quoted-printable does; an RFC 2231 value with a
// malformed %-escape stays as written, and an extended or continued parameter wins over a plain one of its name.
//
// Extraction is total and bounded: every input gives documents, never an error, and what they hold is at most a few
// times the message, since decoding only shrinks bytes and a charset at most triples them. Package-level functions
// are safe for concurrent use.

package sidecar

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"mime/quotedprintable"
	"strconv"
	"strings"

	"golang.org/x/text/encoding/htmlindex"
)

// How deep multipart parts are read, part of extractor 1's definition, so two devices extract alike.
const indexMimeMaxDepth = 16

// One header field: its name, lowercase, and its value, unfolded and trimmed.
type indexMailHeaderField struct {
	name  string
	value string
}

// A message's or part's header fields, in order.
type indexMailHeader []indexMailHeaderField

// Every value of fields named name, in order.
func (self indexMailHeader) values(name string) []string {
	values := []string{}
	for _, field := range self {
		if field.name == name {
			values = append(values, field.value)
		}
	}
	return values
}

// The first value of fields named name, or "".
func (self indexMailHeader) first(name string) string {
	for _, field := range self {
		if field.name == name {
			return field.value
		}
	}
	return ""
}

// The header up to the first empty line, and the body after it; a message with no empty line is all header.
func indexSplitMailHeader(content []byte) (indexMailHeader, []byte) {
	lines := [][]byte{}
	rest := content
	for len(rest) != 0 {
		line := rest
		if end := bytes.IndexByte(rest, '\n'); end >= 0 {
			line, rest = rest[:end], rest[end+1:]
		} else {
			rest = nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			break
		}
		if (line[0] == ' ' || line[0] == '\t') && len(lines) != 0 {
			// Unfolding drops the line break and keeps the whitespace after it.
			lines[len(lines)-1] = append(lines[len(lines)-1], line...)
			continue
		}
		lines = append(lines, bytes.Clone(line))
	}
	header := indexMailHeader{}
	for _, line := range lines {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		header = append(header, indexMailHeaderField{
			name:  strings.ToLower(strings.TrimSpace(string(name))),
			value: strings.TrimSpace(string(value)),
		})
	}
	return header, rest
}

// raw in the charset label names, through htmlindex: raw as it is for no label, one htmlindex does not know, UTF-8,
// or a decoding that fails, for normalizer 1's step 1 to map.
func indexDecodeCharset(label string, raw []byte) []byte {
	label = strings.TrimSpace(label)
	if label == "" {
		return raw
	}
	encoding, err := htmlindex.Get(label)
	if err != nil {
		return raw
	}
	if name, err := htmlindex.Name(encoding); err == nil && name == "utf-8" {
		return raw
	}
	decoded, err := encoding.NewDecoder().Bytes(raw)
	if err != nil {
		return raw
	}
	return decoded
}

// One RFC 2047 encoded word, =?charset[*language]?B|Q?text?=, at value's start: its text decoded, and its length; or
// false when value does not start with one, so its "=?" stays text.
func indexDecodeEncodedWord(value string) (string, int, bool) {
	if !strings.HasPrefix(value, "=?") {
		return "", 0, false
	}
	parts := strings.SplitN(value[2:], "?", 4)
	if len(parts) < 4 || !strings.HasPrefix(parts[3], "=") || len(parts[1]) != 1 {
		return "", 0, false
	}
	charset, _, _ := strings.Cut(parts[0], "*")
	encoded := parts[2]
	if charset == "" || strings.ContainsAny(charset, " \t") || strings.ContainsAny(encoded, " \t") {
		return "", 0, false
	}
	var raw []byte
	switch parts[1] {
	case "B", "b":
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(encoded, "="))
			if err != nil {
				return "", 0, false
			}
		}
		raw = decoded
	case "Q", "q":
		for index := 0; index < len(encoded); index += 1 {
			switch b := encoded[index]; {
			case b == '_':
				raw = append(raw, ' ')
			case b == '=':
				if len(encoded) < index+3 {
					return "", 0, false
				}
				decoded, err := hex.DecodeString(encoded[index+1 : index+3])
				if err != nil {
					return "", 0, false
				}
				raw = append(raw, decoded...)
				index += 2
			default:
				raw = append(raw, b)
			}
		}
	default:
		return "", 0, false
	}
	length := 2 + len(parts[0]) + 1 + len(parts[1]) + 1 + len(encoded) + 2
	return string(indexDecodeCharset(charset, raw)), length, true
}

// A header value with its encoded words decoded. Whitespace between two adjacent encoded words goes (RFC 2047 6.2);
// anything else stays as it is.
func indexDecodeEncodedWords(value string) string {
	var decoded strings.Builder
	// Where the text since the last encoded word starts, which goes only if it is whitespace between two. Kept as an
	// offset, so a value of many "=?" that open no word is read once.
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
		if pending := value[pendingStart:start]; !afterWord || strings.Trim(pending, " \t") != "" {
			decoded.WriteString(pending)
		}
		decoded.WriteString(word)
		afterWord = true
		search = start + length
		pendingStart = search
	}
	decoded.WriteString(value[pendingStart:])
	return decoded.String()
}

// A Content-Type's or Content-Disposition's value and parameters.
type indexMediaValue struct {
	// Lowercase, trimmed.
	value string
	// By lowercase name: a plain value, the first of its name; an RFC 2231 extended one; and continuation sections.
	plain    map[string]string
	extended map[string]string
	sections map[string]map[int]indexMediaSection
}

// One RFC 2231 continuation section.
type indexMediaSection struct {
	text     string
	extended bool
}

// Parses value; ";" inside a quoted string does not split it.
func indexParseMediaValue(value string) *indexMediaValue {
	head, rest, _ := strings.Cut(value, ";")
	media := &indexMediaValue{
		value:    strings.ToLower(strings.TrimSpace(head)),
		plain:    map[string]string{},
		extended: map[string]string{},
		sections: map[string]map[int]indexMediaSection{},
	}
	params := []string{}
	var current strings.Builder
	quoted := false
	for index := 0; index < len(rest); index += 1 {
		b := rest[index]
		switch {
		case b == '\\' && quoted && index+1 < len(rest):
			current.WriteByte(b)
			current.WriteByte(rest[index+1])
			index += 1
			continue
		case b == '"':
			quoted = !quoted
		case b == ';' && !quoted:
			params = append(params, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(b)
	}
	params = append(params, current.String())
	for _, param := range params {
		name, raw, ok := strings.Cut(param, "=")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		raw = strings.TrimSpace(raw)
		isExtended := strings.HasSuffix(name, "*")
		name = strings.TrimSuffix(name, "*")
		base, section, hasSection := strings.Cut(name, "*")
		switch {
		case hasSection:
			n, err := strconv.Atoi(section)
			if err != nil || n < 0 {
				continue
			}
			if !isExtended {
				raw = indexUnquote(raw)
			}
			if media.sections[base] == nil {
				media.sections[base] = map[int]indexMediaSection{}
			}
			if _, ok := media.sections[base][n]; !ok {
				media.sections[base][n] = indexMediaSection{text: raw, extended: isExtended}
			}
		case isExtended:
			if _, ok := media.extended[base]; !ok {
				media.extended[base] = raw
			}
		default:
			if _, ok := media.plain[base]; !ok {
				media.plain[base] = indexUnquote(raw)
			}
		}
	}
	return media
}

// A parameter's value: its continuation sections joined from 0 while they run, else its extended value, else its
// plain one, extended text %-decoded and through its charset.
func (self *indexMediaValue) param(name string) string {
	if sections := self.sections[name]; sections != nil {
		charset := ""
		joined := []byte{}
		for n := 0; ; n += 1 {
			section, ok := sections[n]
			if !ok {
				break
			}
			text := section.text
			if section.extended && n == 0 {
				charset, text = indexSplitExtended(text)
			}
			if section.extended {
				joined = append(joined, indexPercentDecode(text)...)
			} else {
				joined = append(joined, text...)
			}
		}
		if 0 < len(joined) {
			return string(indexDecodeCharset(charset, joined))
		}
	}
	if raw, ok := self.extended[name]; ok {
		charset, text := indexSplitExtended(raw)
		return string(indexDecodeCharset(charset, indexPercentDecode(text)))
	}
	return self.plain[name]
}

// A quoted string's content with its backslash escapes undone; anything else as it is.
func indexUnquote(value string) string {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return value
	}
	var unquoted strings.Builder
	inner := value[1 : len(value)-1]
	for index := 0; index < len(inner); index += 1 {
		if inner[index] == '\\' && index+1 < len(inner) {
			index += 1
		}
		unquoted.WriteByte(inner[index])
	}
	return unquoted.String()
}

// An RFC 2231 extended value's charset and its %-encoded text, the language dropped; no quote marks, no charset.
func indexSplitExtended(value string) (string, string) {
	parts := strings.SplitN(value, "'", 3)
	if len(parts) != 3 {
		return "", value
	}
	return parts[0], parts[2]
}

// %XX escapes undone, or the text as written when any escape is malformed.
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
		b, err := hex.DecodeString(text[index+1 : index+3])
		if err != nil {
			return []byte(text)
		}
		decoded = append(decoded, b...)
		index += 2
	}
	return decoded
}

// The parts between a multipart body's delimiter lines, up to its close delimiter or the end. A delimiter line is
// "--" and the boundary, with only whitespace after it, and the line break before it is its own, not the part's.
func indexMultipartParts(body []byte, boundary string) [][]byte {
	delimiter := []byte("--" + boundary)
	closeDelimiter := []byte("--" + boundary + "--")
	parts := [][]byte{}
	partStart := -1
	for position := 0; position < len(body); {
		lineEnd := len(body)
		next := len(body)
		if end := bytes.IndexByte(body[position:], '\n'); end >= 0 {
			lineEnd = position + end
			next = lineEnd + 1
		}
		trimmed := bytes.TrimRight(body[position:lineEnd], " \t\r")
		isClose := bytes.Equal(trimmed, closeDelimiter)
		if isClose || bytes.Equal(trimmed, delimiter) {
			if 0 <= partStart {
				part := body[partStart:position]
				part = bytes.TrimSuffix(part, []byte("\n"))
				parts = append(parts, bytes.TrimSuffix(part, []byte("\r")))
			}
			if isClose {
				return parts
			}
			partStart = next
		}
		position = next
	}
	if 0 <= partStart && partStart <= len(body) {
		parts = append(parts, body[partStart:])
	}
	return parts
}

// Whether b is ASCII whitespace.
func indexAsciiSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\v' || b == '\f'
}

// A part's body under its Content-Transfer-Encoding: base64 and quoted-printable decoded, keeping what decoded before
// anything that does not, and any other encoding as it is.
func indexTransferDecode(encoding string, body []byte) []byte {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		compact := make([]byte, 0, len(body))
		for _, b := range body {
			if !indexAsciiSpace(b) {
				compact = append(compact, b)
			}
		}
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(compact)))
		decodedByteCount, _ := base64.StdEncoding.Decode(decoded, compact)
		return decoded[:decodedByteCount]
	case "quoted-printable":
		decoded, _ := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
		return decoded
	}
	return body
}

// Appends what a part gives field 5: its name if it has one, then its text when it is a text/plain or text/html part
// and no attachment. Multipart parts are read 16 deep; nothing else is entered, a message/rfc822 part included.
func indexMimeWalk(header indexMailHeader, body []byte, depth int, pieces *[][]byte) {
	contentType := indexParseMediaValue(header.first("content-type"))
	mediaType := contentType.value
	if mediaType == "" {
		mediaType = "text/plain"
	}
	disposition := indexParseMediaValue(header.first("content-disposition"))
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := contentType.param("boundary")
		if boundary == "" || indexMimeMaxDepth <= depth {
			return
		}
		for _, part := range indexMultipartParts(body, boundary) {
			partHeader, partBody := indexSplitMailHeader(part)
			indexMimeWalk(partHeader, partBody, depth+1, pieces)
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
		decoded := indexTransferDecode(header.first("content-transfer-encoding"), body)
		*pieces = append(*pieces, indexDecodeCharset(contentType.param("charset"), decoded))
	case "text/html":
		decoded := indexTransferDecode(header.first("content-transfer-encoding"), body)
		*pieces = append(*pieces, indexStripHtml(indexDecodeCharset(contentType.param("charset"), decoded)))
	}
}

// Non-empty values joined by one space.
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

// The documents of one message at path (§15.7's m/ files), one per 1 MiB chunk of its field 5 text, each carrying
// its subject, from and to. Version, provenance and the outside flag are the caller's to set.
func indexExtractMail(path []byte, content []byte) []*IndexDocument {
	header, body := indexSplitMailHeader(content)
	headerValue := func(name string) []byte {
		return []byte(indexDecodeEncodedWords(strings.Join(header.values(name), " ")))
	}
	subject := headerValue("subject")
	from := headerValue("from")
	to := indexJoinNonEmpty(headerValue("to"), headerValue("cc"))
	pieces := [][]byte{}
	indexMimeWalk(header, body, 0, &pieces)
	text := indexJoinNonEmpty(pieces...)
	documents := []*IndexDocument{}
	for chunk, chunkText := range indexChunks(text) {
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
