// The text a message walk keeps (MAIL-M7-11), made safe to re-emit: every value here is a sender's, and it reaches
// IMAP clients, agents, indexes and the headers ingest renders. A single-line value has each run of whitespace, CR
// and LF among it, as one space and every other control character dropped, so it can never split a header or a list
// row; text keeps its line breaks and nothing else of C0 or C1. Both replace each invalid UTF-8 byte with U+FFFD
// before any cap applies (MAIL-FORMAT.md), and cap on a UTF-8 boundary.
//
// Charsets and HTML are read as INDEX-FORMAT.md's Extractor 1 reads them (plan-SEARCH-index-format-bytes#8), so a
// snippet says what search indexes: a part's charset decodes through x/text's htmlindex, no charset or one it does
// not know reads as UTF-8, and none is guessed from content; HTML goes through the format's own scanner. RFC 2047's
// words decode through the standard library, which reads UTF-8, US-ASCII and ISO-8859-1 itself and hands every other
// charset to htmlindex here.
//
// No connect, go-smtp or mox, and no go-message: on every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"html"
	"io"
	"mime"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"
)

// MAIL-FORMAT.md's caps on IndexEntry, past which a value is cut on a UTF-8 boundary or, for an id or a code,
// left empty. Format values.
const (
	mailIndexAddressMaxByteCount        = MailAddressMaxByteCount
	mailIndexFromMaxByteCount           = 512
	mailIndexSubjectMaxByteCount        = 512
	mailIndexSnippetMaxByteCount        = 200
	mailIndexMessageIdMaxByteCount      = 256
	mailIndexOneTimeCodeMaxByteCount    = 32
	mailIndexAttachmentMaxCount         = 32
	mailIndexAttachmentNameMaxByteCount = 256
	mailIndexAttachmentTypeMaxByteCount = 128
	mailIndexOperatorIdMaxByteCount     = 64
)

// The longest value a header field ingest renders takes from evidence, past which it is cut: a domain name's
// 253 bytes, rounded up. A format value.
const mailHeaderValueMaxByteCount = 255

// The tags whose removal leaves one space, the rest leaving nothing (INDEX-FORMAT.md's HTML).
var mailHtmlBlockTags = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true, "br": true, "center": true,
	"dd": true, "details": true, "dialog": true, "dir": true, "div": true, "dl": true, "dt": true,
	"fieldset": true, "figcaption": true, "figure": true, "footer": true, "form": true, "h1": true,
	"h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "header": true, "hgroup": true,
	"hr": true, "li": true, "main": true, "menu": true, "nav": true, "ol": true, "p": true, "pre": true,
	"section": true, "summary": true, "table": true, "tbody": true, "td": true, "tfoot": true, "th": true,
	"thead": true, "tr": true, "ul": true,
}

// Whether character is one a single-line value drops: C0, DEL and C1 controls, Unicode's line and paragraph
// separators, and the bidi embeddings, overrides and isolates, which can make a file name or a subject read as
// something it is not.
func isMailControl(character rune) bool {
	switch {
	case character < 0x20, character == 0x7f, 0x80 <= character && character <= 0x9f:
		return true
	case character == ' ', character == ' ':
		return true
	case '‪' <= character && character <= '‮', '⁦' <= character && character <= '⁩':
		return true
	}
	return false
}

// value as one line: each invalid UTF-8 byte U+FFFD, each run of whitespace, line breaks among it, one space,
// every other control character dropped, trimmed, then cut at maxByteCount on a UTF-8 boundary.
func mailCleanLine(value string, maxByteCount int) string {
	var builder strings.Builder
	space := false
	for _, character := range value {
		if unicode.IsSpace(character) {
			space = builder.Len() != 0
			continue
		}
		if isMailControl(character) {
			continue
		}
		if space {
			builder.WriteByte(' ')
			space = false
		}
		builder.WriteRune(character)
	}
	return mailCutUtf8(builder.String(), maxByteCount)
}

// value as text: each invalid UTF-8 byte U+FFFD, CR LF and lone CR a line feed, Unicode's line and paragraph
// separators a line feed, tab kept, every other control character dropped, then cut at maxByteCount on a UTF-8
// boundary.
func mailCleanText(value []byte, maxByteCount int) string {
	var builder strings.Builder
	builder.Grow(min(len(value), maxByteCount))
	for index := 0; index < len(value) && builder.Len() < maxByteCount; {
		character, width := utf8.DecodeRune(value[index:])
		index += width
		switch {
		case character == '\r':
			builder.WriteByte('\n')
			if index < len(value) && value[index] == '\n' {
				index += 1
			}
		case character == '\n', character == '\t':
			builder.WriteRune(character)
		case character == ' ', character == ' ':
			builder.WriteByte('\n')
		case isMailControl(character):
		default:
			builder.WriteRune(character)
		}
	}
	return mailCutUtf8(builder.String(), maxByteCount)
}

// value cut to at most maxByteCount bytes, never inside a UTF-8 sequence.
func mailCutUtf8(value string, maxByteCount int) string {
	if len(value) <= maxByteCount {
		return value
	}
	cut := maxByteCount
	for 0 < cut && !utf8.RuneStart(value[cut]) {
		cut -= 1
	}
	return value[:cut]
}

// The snippet of text: one line, at most §15.7's 200 bytes.
func mailSnippet(text string) string {
	return mailCleanLine(text, mailIndexSnippetMaxByteCount)
}

// raw in the charset label names, as UTF-8 by htmlindex; or raw as it is for no label, one htmlindex does not know,
// UTF-8 itself, or bytes its decoder refuses, so mailCleanText reads them as UTF-8.
func mailDecodeCharset(label string, raw []byte) []byte {
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

// RFC 2047's encoded words, decoded by mime's own UTF-8, US-ASCII and ISO-8859-1 and by htmlindex for any other
// charset, whose unknown labels pass their bytes through, so one word never stops the rest decoding.
var mailWordDecoder = &mime.WordDecoder{
	CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
		raw, err := io.ReadAll(input)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(mailDecodeCharset(charset, raw)), nil
	},
}

// value with its encoded words decoded, or as it is where they do not decode.
func mailDecodeWords(value string) string {
	decoded, err := mailWordDecoder.DecodeHeader(value)
	if err != nil {
		return value
	}
	return decoded
}

// Whether character is an ASCII letter.
func isMailAsciiLetter(character byte) bool {
	return ('a' <= character && character <= 'z') || ('A' <= character && character <= 'Z')
}

// The index of the > that ends the tag starting at text[0], outside quotes, or -1.
func mailHtmlTagEnd(text []byte) int {
	var quote byte
	for index := 1; index < len(text); index += 1 {
		character := text[index]
		switch {
		case quote != 0:
			if character == quote {
				quote = 0
			}
		case character == '"' || character == '\'':
			quote = character
		case character == '>':
			return index
		}
	}
	return -1
}

// The index of the first ASCII-case-insensitive match of lowercase needle, which starts with <, in data, or -1.
// Nothing is allocated, and each try begins at a <.
func mailHtmlIndexFold(data []byte, needle string) int {
	for index := 0; index+len(needle) <= len(data); {
		open := bytes.IndexByte(data[index:], needle[0])
		if open < 0 || len(data) < index+open+len(needle) {
			return -1
		}
		index += open
		match := true
		for offset := 1; offset < len(needle); offset += 1 {
			character := data[index+offset]
			if 'A' <= character && character <= 'Z' {
				character += 'a' - 'A'
			}
			if character != needle[offset] {
				match = false
				break
			}
		}
		if match {
			return index
		}
		index += 1
	}
	return -1
}

// markup's text by INDEX-FORMAT.md's scanner: script and style elements go with their content, up to the matching end
// tag or the input's end; comments, <!...> and <?...> go; a tag is <, a letter or /, to the next > outside quotes,
// and a block-list tag leaves one space and any other nothing; any other < is text; a construct with no end ends
// the text. Entities decode once every tag is gone, so &lt; stays text. One pass, linear in markup.
func mailHtmlText(markup []byte) []byte {
	text := make([]byte, 0, len(markup))
	for index := 0; index < len(markup); {
		open := bytes.IndexByte(markup[index:], '<')
		if open < 0 {
			text = append(text, markup[index:]...)
			break
		}
		text = append(text, markup[index:index+open]...)
		index += open
		rest := markup[index:]
		if bytes.HasPrefix(rest, []byte("<!--")) {
			end := bytes.Index(rest[4:], []byte("-->"))
			if end < 0 {
				break
			}
			index += 4 + end + 3
			continue
		}
		if bytes.HasPrefix(rest, []byte("<!")) || bytes.HasPrefix(rest, []byte("<?")) {
			end := bytes.IndexByte(rest, '>')
			if end < 0 {
				break
			}
			index += end + 1
			continue
		}
		if len(rest) < 2 || !(isMailAsciiLetter(rest[1]) || rest[1] == '/') {
			text = append(text, '<')
			index += 1
			continue
		}
		end := mailHtmlTagEnd(rest)
		if end < 0 {
			break
		}
		closing := rest[1] == '/'
		nameStart := 1
		if closing {
			nameStart = 2
		}
		nameEnd := nameStart
		for nameEnd < end && (isMailAsciiLetter(rest[nameEnd]) || ('0' <= rest[nameEnd] && rest[nameEnd] <= '9')) {
			nameEnd += 1
		}
		name := dnsAsciiLower(string(rest[nameStart:nameEnd]))
		index += end + 1
		if !closing && (name == "script" || name == "style") {
			closeAt := mailHtmlIndexFold(markup[index:], "</"+name)
			if closeAt < 0 {
				index = len(markup)
				break
			}
			closeEnd := mailHtmlTagEnd(markup[index+closeAt:])
			if closeEnd < 0 {
				index = len(markup)
				break
			}
			index += closeAt + closeEnd + 1
			continue
		}
		if mailHtmlBlockTags[name] {
			text = append(text, ' ')
		}
	}
	if bytes.IndexByte(text, '&') < 0 {
		return text
	}
	return []byte(html.UnescapeString(string(text)))
}

// The message ids of a msg-id list (RFC 5322 §3.6.4), in order, each without its angle brackets: the text of each
// <...>, or, with no bracket at all, the value's first word, as some senders write it. A reading for threading,
// which must agree on every device, not a validator.
func mailMessageIds(value string) []string {
	ids := []string{}
	if !strings.Contains(value, "<") {
		if fields := strings.Fields(value); len(fields) != 0 {
			ids = append(ids, fields[0])
		}
		return ids
	}
	for {
		open := strings.IndexByte(value, '<')
		if open < 0 {
			return ids
		}
		value = value[open+1:]
		end := strings.IndexByte(value, '>')
		if end < 0 {
			return ids
		}
		if id := strings.TrimSpace(value[:end]); id != "" {
			ids = append(ids, id)
		}
		value = value[end+1:]
	}
}
