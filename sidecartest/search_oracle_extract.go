// The oracle's own reading of extractor 1 and of §11.14's documents (protocol/INDEX-FORMAT.md's Extractor 1,
// Documents and Rows; D-TEST-14): what a file or a mail message gives each field and each row, read apart
// from the index's extractors. It parses MIME, RFC 2047 words and RFC 2231 values itself, decodes charsets
// through x/text's htmlindex as the format says, and strips HTML with its own scanner.
//
// Readings the format leaves open, which the oracle takes and its report names:
//   - a file's field 4 holds its title, then one space, then its path ("title ... indexed with the path");
//   - a mail's field 3 joins To and Cc, and field 5 joins its text parts and attachment names in MIME order,
//     each joined by one space, which normalization makes equal to any other separator but none;
//   - a part whose disposition is attachment gives only its name, never its text;
//   - a message's chunks are of its field 5 text, as a file's are of its decoded text, every chunk keeping
//     the fields before 5.
//
// Package-level functions are safe for concurrent use.

package sidecartest

import (
	"bytes"
	"encoding/base64"
	"html"
	"io"
	"mime/quotedprintable"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"
)

// The format's sizes (§11.14's documents and sniff rows; INDEX-FORMAT.md's Rows and Extractor 1).
const (
	searchOracleChunkByteCount    = 1024 * 1024
	searchOracleOverlapByteCount  = 256
	searchOracleSniffByteCount    = 8000
	searchOracleTitleByteCount    = 80
	searchOracleLocatorByteCount  = 512
	searchOracleRowFieldByteCount = 160
	// How deep a message's multipart nesting is read.
	searchOracleMimeDepth = 16
)

// Fields 1 to 5 at their numbers: subject, from, to, title and body. Index 0 is unused.
type searchOracleFields [6][]byte

// One document, a chunk of one version of a path, as the oracle reads it.
type searchOracleDocument struct {
	chunk uint32
	kind  SearchDocKind
	// the row's text values, fields 1 to 4 at their numbers and the locator at 0, as the doc table
	// holds them: invalid UTF-8 replaced and cut to their caps on a code point
	row [5]string
	// the document's normalized text, fields padded and joined
	text string
}

// The tags whose removal leaves one space (INDEX-FORMAT.md's HTML).
var searchOracleBlockTags = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true, "br": true, "center": true,
	"dd": true, "details": true, "dialog": true, "dir": true, "div": true, "dl": true, "dt": true,
	"fieldset": true, "figcaption": true, "figure": true, "footer": true, "form": true, "h1": true,
	"h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "header": true, "hgroup": true,
	"hr": true, "li": true, "main": true, "menu": true, "nav": true, "ol": true, "p": true, "pre": true,
	"section": true, "summary": true, "table": true, "tbody": true, "td": true, "tfoot": true, "th": true,
	"thead": true, "tr": true, "ul": true,
}

// The documents of a file version at path, one a chunk, or none for a binary: text when its first
// 8,000 bytes hold no NUL and are valid UTF-8 but for a cut final sequence, or when it opens with a
// UTF-16 byte-order mark, which is dropped and selects the decoding.
func searchOracleFileDocuments(path string, content []byte) []*searchOracleDocument {
	text, ok := searchOracleSniff(content)
	if !ok {
		return nil
	}
	title := searchOracleTitle(text)
	var row [5]string
	row[0] = searchOracleRowValue([]byte(path), searchOracleLocatorByteCount)
	row[4] = searchOracleRowValue([]byte(title), searchOracleRowFieldByteCount)
	documents := []*searchOracleDocument{}
	for chunk, chunkText := range searchOracleChunks(text) {
		fields := &searchOracleFields{}
		fields[4] = []byte(title + " " + path)
		fields[5] = chunkText
		documents = append(documents, &searchOracleDocument{
			chunk: uint32(chunk),
			kind:  SearchDocKindFile,
			row:   row,
			text:  searchOracleDocumentText(fields),
		})
	}
	return documents
}

// The documents of a mail message at path (§15.7's m/ files): From, To, Cc and Subject values, decoded
// as RFC 2047 says, and its text/plain parts, text/html parts stripped and its attachments' names,
// never transport headers, attachment bytes or base64.
func searchOracleMailDocuments(path string, content []byte) []*searchOracleDocument {
	header, body := searchOracleSplitHeader(content)
	subject := searchOracleDecodeWords(strings.Join(header.values("subject"), " "))
	from := searchOracleDecodeWords(strings.Join(header.values("from"), " "))
	to := searchOracleJoin(
		searchOracleDecodeWords(strings.Join(header.values("to"), " ")),
		searchOracleDecodeWords(strings.Join(header.values("cc"), " ")),
	)
	pieces := []string{}
	searchOracleMimeWalk(header, body, 0, &pieces)
	var row [5]string
	row[0] = searchOracleRowValue([]byte(path), searchOracleLocatorByteCount)
	row[1] = searchOracleRowValue([]byte(subject), searchOracleRowFieldByteCount)
	row[2] = searchOracleRowValue([]byte(from), searchOracleRowFieldByteCount)
	row[3] = searchOracleRowValue([]byte(to), searchOracleRowFieldByteCount)
	documents := []*searchOracleDocument{}
	for chunk, chunkText := range searchOracleChunks([]byte(searchOracleJoin(pieces...))) {
		fields := &searchOracleFields{}
		fields[1] = []byte(subject)
		fields[2] = []byte(from)
		fields[3] = []byte(to)
		fields[5] = chunkText
		documents = append(documents, &searchOracleDocument{
			chunk: uint32(chunk),
			kind:  SearchDocKindMail,
			row:   row,
			text:  searchOracleDocumentText(fields),
		})
	}
	return documents
}

// Non-empty values joined by one space.
func searchOracleJoin(values ...string) string {
	kept := []string{}
	for _, value := range values {
		if value != "" {
			kept = append(kept, value)
		}
	}
	return strings.Join(kept, " ")
}

// A row's text value: invalid UTF-8 replaced as step 1 does, then cut to its cap on a code point.
func searchOracleRowValue(value []byte, byteCount int) string {
	return searchOracleCut(searchOracleValidUtf8(value), byteCount)
}

// One document per 1 MiB of text, each with the next 256 B, and one for an empty text.
func searchOracleChunks(text []byte) [][]byte {
	chunks := [][]byte{}
	for start := 0; start == 0 || start < len(text); start += searchOracleChunkByteCount {
		end := min(len(text), start+searchOracleChunkByteCount+searchOracleOverlapByteCount)
		chunks = append(chunks, text[start:end])
	}
	return chunks
}

// The text of a file, or false for a binary.
func searchOracleSniff(content []byte) ([]byte, bool) {
	switch {
	case bytes.HasPrefix(content, []byte{0xFE, 0xFF}):
		return searchOracleUtf16(content[2:], true), true
	case bytes.HasPrefix(content, []byte{0xFF, 0xFE}):
		return searchOracleUtf16(content[2:], false), true
	}
	window := content[:min(len(content), searchOracleSniffByteCount)]
	if bytes.IndexByte(window, 0) >= 0 {
		return nil, false
	}
	for i := 0; i < len(window); {
		r, size := utf8.DecodeRune(window[i:])
		if r == utf8.RuneError && size == 1 {
			// a cut final sequence: what is left begins a sequence that the window ends
			if !utf8.FullRune(window[i:]) {
				break
			}
			return nil, false
		}
		i += size
	}
	return content, true
}

// UTF-16 in the byte order given, as UTF-8, an unpaired surrogate or an odd last byte becoming U+FFFD.
func searchOracleUtf16(content []byte, bigEndian bool) []byte {
	units := make([]uint16, 0, len(content)/2)
	for i := 0; i+1 < len(content); i += 2 {
		if bigEndian {
			units = append(units, uint16(content[i])<<8|uint16(content[i+1]))
		} else {
			units = append(units, uint16(content[i+1])<<8|uint16(content[i]))
		}
	}
	var out strings.Builder
	for _, r := range utf16.Decode(units) {
		out.WriteRune(r)
	}
	if len(content)%2 == 1 {
		out.WriteRune(utf8.RuneError)
	}
	return []byte(out.String())
}

// A file's title: its first line holding a letter or number, without a leading run of '#' and spaces
// or trailing spaces, cut to 80 B on a code point.
func searchOracleTitle(text []byte) string {
	for _, line := range strings.Split(searchOracleValidUtf8(text), "\n") {
		if !strings.ContainsFunc(line, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsNumber(r) }) {
			continue
		}
		line = strings.TrimLeft(line, "# ")
		line = strings.TrimRight(line, " \t\r")
		return searchOracleCut(line, searchOracleTitleByteCount)
	}
	return ""
}

// A message's or part's header fields by lowercase name, unfolded, in order.
type searchOracleHeader map[string][]string

func (self searchOracleHeader) values(name string) []string {
	return self[name]
}

func (self searchOracleHeader) first(name string) string {
	if values := self[name]; 0 < len(values) {
		return values[0]
	}
	return ""
}

// The header block up to the first empty line, and the body after it.
func searchOracleSplitHeader(content []byte) (searchOracleHeader, []byte) {
	header := searchOracleHeader{}
	lines := []string{}
	rest := content
	for 0 < len(rest) {
		end := bytes.IndexByte(rest, '\n')
		var line []byte
		if end < 0 {
			line, rest = rest, nil
		} else {
			line, rest = rest[:end], rest[end+1:]
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			break
		}
		if (line[0] == ' ' || line[0] == '\t') && 0 < len(lines) {
			// unfolding drops the line break before the whitespace
			lines[len(lines)-1] += string(line)
			continue
		}
		lines = append(lines, string(line))
	}
	for _, line := range lines {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(name))
		header[key] = append(header[key], strings.TrimSpace(value))
	}
	return header, rest
}

// Appends what a part gives field 5: its text when it is a text/plain or text/html part that is no
// attachment, and its name when it has one.
func searchOracleMimeWalk(header searchOracleHeader, body []byte, depth int, pieces *[]string) {
	mediaType, typeParams := searchOracleParseParams(header.first("content-type"))
	if mediaType == "" {
		mediaType = "text/plain"
	}
	disposition, dispositionParams := searchOracleParseParams(header.first("content-disposition"))
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := typeParams["boundary"]
		if boundary == "" || searchOracleMimeDepth <= depth {
			return
		}
		for _, part := range searchOracleMultipartParts(body, boundary) {
			partHeader, partBody := searchOracleSplitHeader(part)
			searchOracleMimeWalk(partHeader, partBody, depth+1, pieces)
		}
		return
	}
	name := dispositionParams["filename"]
	if name == "" {
		name = typeParams["name"]
	}
	if name != "" {
		*pieces = append(*pieces, searchOracleDecodeWords(name))
	}
	if disposition == "attachment" {
		return
	}
	decoded := searchOracleTransferDecode(strings.ToLower(header.first("content-transfer-encoding")), body)
	switch mediaType {
	case "text/plain":
		*pieces = append(*pieces, string(searchOracleDecodeCharset(typeParams["charset"], decoded)))
	case "text/html":
		*pieces = append(*pieces, searchOracleStripHtml(string(searchOracleDecodeCharset(typeParams["charset"], decoded))))
	}
}

// The parts between a multipart body's boundary lines, up to its close delimiter.
func searchOracleMultipartParts(body []byte, boundary string) [][]byte {
	delimiter := "--" + boundary
	parts := [][]byte{}
	var current []byte
	inPart := false
	for _, line := range strings.SplitAfter(string(body), "\n") {
		trimmed := strings.TrimRight(line, " \t\r\n")
		switch {
		case trimmed == delimiter+"--":
			if inPart {
				parts = append(parts, searchOracleTrimLastBreak(current))
			}
			return parts
		case trimmed == delimiter:
			if inPart {
				parts = append(parts, searchOracleTrimLastBreak(current))
			}
			current = nil
			inPart = true
		case inPart:
			current = append(current, line...)
		}
	}
	if inPart {
		parts = append(parts, searchOracleTrimLastBreak(current))
	}
	return parts
}

// A part without the line break that belongs to the delimiter after it.
func searchOracleTrimLastBreak(part []byte) []byte {
	part = bytes.TrimSuffix(part, []byte("\n"))
	return bytes.TrimSuffix(part, []byte("\r"))
}

// A part's body under its Content-Transfer-Encoding: base64 and quoted-printable decoded, anything else
// as it is. What does not decode gives what decoded before it.
func searchOracleTransferDecode(encoding string, body []byte) []byte {
	switch strings.TrimSpace(encoding) {
	case "base64":
		compact := bytes.Map(func(r rune) rune {
			if unicode.IsSpace(r) {
				return -1
			}
			return r
		}, body)
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(compact)))
		n, _ := base64.StdEncoding.Decode(decoded, compact)
		return decoded[:n]
	case "quoted-printable":
		decoded, _ := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
		return decoded
	}
	return body
}

// Bytes in charset label as UTF-8, through x/text's htmlindex: no label, an unknown one or UTF-8 leave
// the bytes as they are, for normalizer 1's step 1.
func searchOracleDecodeCharset(label string, raw []byte) []byte {
	if strings.TrimSpace(label) == "" {
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

// A header value with its RFC 2047 encoded words decoded, whitespace between two adjacent encoded
// words dropped; a word that does not parse stays as it is.
func searchOracleDecodeWords(value string) string {
	var out strings.Builder
	// the text since the last encoded word
	held := ""
	afterWord := false
	for {
		start := strings.Index(value, "=?")
		if start < 0 {
			break
		}
		decoded, length, ok := searchOracleDecodeWord(value[start:])
		if !ok {
			held += value[:start+2]
			value = value[start+2:]
			continue
		}
		between := held + value[:start]
		if !afterWord || strings.TrimSpace(between) != "" {
			out.WriteString(between)
		}
		out.WriteString(decoded)
		held = ""
		value = value[start+length:]
		afterWord = true
	}
	out.WriteString(held)
	out.WriteString(value)
	return out.String()
}

// One encoded word =?charset?B|Q?text?= at the start of value: its text and its length.
func searchOracleDecodeWord(value string) (string, int, bool) {
	fields := strings.SplitN(value[2:], "?", 4)
	if len(fields) < 4 || !strings.HasPrefix(fields[3], "=") {
		return "", 0, false
	}
	charset, _, _ := strings.Cut(fields[0], "*")
	encoded := fields[2]
	if strings.ContainsAny(encoded, " \t") || charset == "" {
		return "", 0, false
	}
	var raw []byte
	switch strings.ToUpper(fields[1]) {
	case "B":
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(encoded, "="))
			if err != nil {
				return "", 0, false
			}
		}
		raw = decoded
	case "Q":
		for i := 0; i < len(encoded); i += 1 {
			switch c := encoded[i]; {
			case c == '_':
				raw = append(raw, ' ')
			case c == '=' && i+2 < len(encoded):
				b, err := strconv.ParseUint(encoded[i+1:i+3], 16, 8)
				if err != nil {
					return "", 0, false
				}
				raw = append(raw, byte(b))
				i += 2
			case c == '=':
				return "", 0, false
			default:
				raw = append(raw, c)
			}
		}
	default:
		return "", 0, false
	}
	length := 2 + len(fields[0]) + 1 + len(fields[1]) + 1 + len(fields[2]) + 2
	return string(searchOracleDecodeCharset(charset, raw)), length, true
}

// A Content-Type or Content-Disposition value: its lowercase value and its parameters by lowercase
// name, RFC 2231's continuations joined and extended values decoded through their charset.
func searchOracleParseParams(value string) (string, map[string]string) {
	head, rest, _ := strings.Cut(value, ";")
	params := map[string]string{}
	type piece struct {
		value    string
		extended bool
	}
	// name -> section -> piece, for name*N and name*N*
	sections := map[string]map[int]piece{}
	for _, param := range searchOracleSplitParams(rest) {
		name, raw, ok := strings.Cut(param, "=")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		raw = strings.TrimSpace(raw)
		extended := strings.HasSuffix(name, "*")
		name = strings.TrimSuffix(name, "*")
		if !extended {
			raw = searchOracleUnquote(raw)
		}
		base, section, hasSection := strings.Cut(name, "*")
		if !hasSection {
			if extended {
				charset, encoded := searchOracleSplitExtended(raw)
				params[base] = string(searchOracleDecodeCharset(charset, searchOracleUnescape(encoded)))
			} else if _, ok := params[base]; !ok {
				params[base] = raw
			}
			continue
		}
		n, err := strconv.Atoi(section)
		if err != nil || n < 0 {
			continue
		}
		if sections[base] == nil {
			sections[base] = map[int]piece{}
		}
		sections[base][n] = piece{value: raw, extended: extended}
	}
	for base, pieces := range sections {
		charset := ""
		var joined []byte
		for n := 0; ; n += 1 {
			p, ok := pieces[n]
			if !ok {
				break
			}
			switch {
			case p.extended && n == 0:
				var encoded string
				charset, encoded = searchOracleSplitExtended(p.value)
				joined = append(joined, searchOracleUnescape(encoded)...)
			case p.extended:
				joined = append(joined, searchOracleUnescape(p.value)...)
			default:
				joined = append(joined, searchOracleUnquote(p.value)...)
			}
		}
		params[base] = string(searchOracleDecodeCharset(charset, joined))
	}
	return strings.ToLower(strings.TrimSpace(head)), params
}

// The parameters after a value's first ';', split at each ';' outside a quoted string.
func searchOracleSplitParams(rest string) []string {
	params := []string{}
	var current strings.Builder
	quoted := false
	for i := 0; i < len(rest); i += 1 {
		c := rest[i]
		switch {
		case c == '\\' && quoted && i+1 < len(rest):
			current.WriteByte(c)
			current.WriteByte(rest[i+1])
			i += 1
			continue
		case c == '"':
			quoted = !quoted
		case c == ';' && !quoted:
			params = append(params, current.String())
			current.Reset()
			continue
		}
		current.WriteByte(c)
	}
	if strings.TrimSpace(current.String()) != "" {
		params = append(params, current.String())
	}
	return params
}

// A quoted string's content, its backslash escapes undone; anything else as it is.
func searchOracleUnquote(value string) string {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return value
	}
	var out strings.Builder
	inner := value[1 : len(value)-1]
	for i := 0; i < len(inner); i += 1 {
		if inner[i] == '\\' && i+1 < len(inner) {
			i += 1
		}
		out.WriteByte(inner[i])
	}
	return out.String()
}

// An RFC 2231 extended value's charset and its %-encoded rest, the language dropped.
func searchOracleSplitExtended(value string) (string, string) {
	parts := strings.SplitN(value, "'", 3)
	if len(parts) != 3 {
		return "", value
	}
	return parts[0], parts[2]
}

// %XX escapes undone; a malformed one stays as it is.
func searchOracleUnescape(value string) []byte {
	if unescaped, err := url.PathUnescape(value); err == nil {
		return []byte(unescaped)
	}
	return []byte(value)
}

// Text with A-Z lowered byte by byte and nothing else changed, invalid UTF-8 included, so its byte
// offsets are text's.
func searchOracleAsciiLower(text string) string {
	lowered := []byte(text)
	for i, c := range lowered {
		if 'A' <= c && c <= 'Z' {
			lowered[i] = c + ('a' - 'A')
		}
	}
	return string(lowered)
}

// Text with its HTML removed by INDEX-FORMAT.md's scanner: script and style elements with their content,
// comments, <!...> and <?...> go; a tag is '<', a letter or '/', to the next '>' outside quotes, and a
// block-list tag leaves one space and any other nothing; any other '<' is text. Entities decode after
// every tag is gone.
func searchOracleStripHtml(text string) string {
	var out strings.Builder
	isLetter := func(c byte) bool { return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') }
	// the index of the '>' ending a tag that starts at 0, outside quotes, or -1
	tagEnd := func(tag string) int {
		var quote byte
		for i := 1; i < len(tag); i += 1 {
			c := tag[i]
			switch {
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
	for i := 0; i < len(text); {
		c := text[i]
		if c != '<' {
			out.WriteByte(c)
			i += 1
			continue
		}
		rest := text[i:]
		if strings.HasPrefix(rest, "<!--") {
			end := strings.Index(rest[4:], "-->")
			if end < 0 {
				break
			}
			i += 4 + end + 3
			continue
		}
		if strings.HasPrefix(rest, "<!") || strings.HasPrefix(rest, "<?") {
			end := strings.IndexByte(rest, '>')
			if end < 0 {
				break
			}
			i += end + 1
			continue
		}
		if len(rest) < 2 || !(isLetter(rest[1]) || rest[1] == '/') {
			out.WriteByte('<')
			i += 1
			continue
		}
		end := tagEnd(rest)
		if end < 0 {
			break
		}
		closing := rest[1] == '/'
		nameStart := 1
		if closing {
			nameStart = 2
		}
		nameEnd := nameStart
		for nameEnd < end && (isLetter(rest[nameEnd]) || ('0' <= rest[nameEnd] && rest[nameEnd] <= '9')) {
			nameEnd += 1
		}
		name := strings.ToLower(rest[nameStart:nameEnd])
		i += end + 1
		if !closing && (name == "script" || name == "style") {
			closeAt := strings.Index(searchOracleAsciiLower(text[i:]), "</"+name)
			if closeAt < 0 {
				break
			}
			closeEnd := tagEnd(text[i+closeAt:])
			if closeEnd < 0 {
				break
			}
			i += closeAt + closeEnd + 1
			continue
		}
		if searchOracleBlockTags[name] {
			out.WriteByte(' ')
		}
	}
	return html.UnescapeString(out.String())
}
