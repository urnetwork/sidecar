// The text a message walk keeps (MAIL-M7-11), made safe to re-emit: every value here is a sender's, and it reaches
// IMAP clients, agents, indexes and headers ingest renders. A single-line value has its whitespace, CR and LF among
// it, as single spaces and every other control character dropped, so it can never split a header or a list row;
// text keeps its line breaks and nothing else of C0 or C1. Both replace each invalid UTF-8 byte with U+FFFD before any cap applies (MAIL-FORMAT.md), and cap on a
// UTF-8 boundary. Charsets: UTF-8 and US-ASCII as they are and ISO-8859-1 by mapping, which needs no table; any
// other charset's bytes stay as they are, so its non-ASCII bytes show as U+FFFD rather than as a guess.
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

// Whether character is one a single-line value drops or turns to a space: C0, DEL and C1 controls, Unicode's line
// and paragraph separators, and the bidi embeddings, overrides and isolates, which can make a file name or a
// subject read as something it is not.
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

// Whether charset names ISO-8859-1, which maps each byte to the rune of its value, under its IANA aliases.
func isMailLatin1Charset(charset string) bool {
	switch strings.ToLower(strings.TrimSpace(charset)) {
	case "iso-8859-1", "iso8859-1", "iso_8859-1", "iso_8859-1:1987", "latin1", "l1", "cp819", "ibm819", "csisolatin1", "iso-ir-100":
		return true
	}
	return false
}

// raw in charset as UTF-8, or as it is for any charset this does not map, which mailCleanText then reads as UTF-8.
func mailDecodeCharset(charset string, raw []byte) []byte {
	if !isMailLatin1Charset(charset) {
		return raw
	}
	decoded := make([]byte, 0, len(raw)+len(raw)/2)
	for _, value := range raw {
		decoded = utf8.AppendRune(decoded, rune(value))
	}
	return decoded
}

// RFC 2047's encoded words, decoded by mime's own UTF-8, US-ASCII and ISO-8859-1, and any other charset's bytes
// passed through as they are, so one word in an unknown charset never stops the rest decoding.
var mailWordDecoder = &mime.WordDecoder{
	CharsetReader: func(charset string, input io.Reader) (io.Reader, error) {
		return input, nil
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

// Elements whose content is not text a person reads.
var mailHtmlSkippedElements = []string{"script", "style", "head", "title", "template"}

// html's text: its tags and comments gone, the content of mailHtmlSkippedElements gone, each tag a space so words
// stay apart, entities decoded. A snippet's reading of the first text part, not a renderer: one pass, linear in
// html, nothing kept but the text.
func mailHtmlText(html []byte) []byte {
	text := make([]byte, 0, len(html))
	flush := func(segment []byte) {
		if len(segment) != 0 {
			text = append(text, mailHtmlUnescape(segment)...)
		}
	}
	for index := 0; index < len(html); {
		open := bytes.IndexByte(html[index:], '<')
		if open < 0 {
			flush(html[index:])
			break
		}
		flush(html[index : index+open])
		index += open
		if bytes.HasPrefix(html[index:], []byte("<!--")) {
			end := bytes.Index(html[index+4:], []byte("-->"))
			if end < 0 {
				break
			}
			index += 4 + end + 3
			continue
		}
		end := bytes.IndexByte(html[index:], '>')
		if end < 0 {
			break
		}
		tag := html[index+1 : index+end]
		index += end + 1
		text = append(text, ' ')
		name := mailHtmlTagName(tag)
		if name == "" || tag[0] == '/' || tag[len(tag)-1] == '/' {
			continue
		}
		for _, skipped := range mailHtmlSkippedElements {
			if name != skipped {
				continue
			}
			// past the element's closing tag, or to the end where it has none
			closing := mailHtmlIndexFold(html[index:], "</"+skipped)
			if closing < 0 {
				index = len(html)
			} else {
				index += closing
			}
			break
		}
	}
	return text
}

// A tag's element name, lowercase: the letters and digits after < and any /.
func mailHtmlTagName(tag []byte) string {
	tag = bytes.TrimPrefix(tag, []byte("/"))
	end := 0
	for end < len(tag) && (('a' <= tag[end]|0x20 && tag[end]|0x20 <= 'z') || ('0' <= tag[end] && tag[end] <= '9')) {
		end += 1
	}
	return dnsAsciiLower(string(tag[:end]))
}

// The index of the first ASCII-case-insensitive match of lowercase needle in data, or -1. needle starts with <,
// so each try begins at a <, and nothing is allocated.
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

// segment with its character references decoded.
func mailHtmlUnescape(segment []byte) []byte {
	if bytes.IndexByte(segment, '&') < 0 {
		return segment
	}
	return []byte(html.UnescapeString(string(segment)))
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
