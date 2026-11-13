//go:build !ios_extension

// The text a message walk keeps (MAIL-M7-11), made safe to re-emit: every value here is a sender's, and it reaches
// IMAP clients, agents, indexes and the headers ingest renders. A single-line value has each run of whitespace, CR
// and LF among it, as one space and every other control character dropped, so it can never split a header or a list
// row; text keeps its line breaks and nothing else of C0 or C1. Both replace each invalid UTF-8 byte with U+FFFD
// before any cap applies (MAIL-FORMAT.md), and cap on a UTF-8 boundary.
//
// Charsets and HTML are read by Extractor 1's own functions (QD-694; DESIGN-DETAILS 11.2.5 and 11.2.6;
// evs_index_extract_mail.go's indexDecodeCharset and evs_index_extract_html.go's indexStripHtml), so a snippet says
// what search indexes: a part's charset decodes by C1-C3, no label, one that names nothing, utf-8 and replacement
// leaving the bytes as they are, and none guessed from content; HTML loses its tags by X1-X7 and then has its
// character references decoded by E1-E4. Nothing of either reading is kept here. RFC 2047's words, the transfer
// encodings and the walk stay this lane's own readings, since they feed MAIL-FORMAT.md's fields, which no other
// device rebuilds: the words decode through the standard library, which reads UTF-8, US-ASCII and ISO-8859-1 itself
// and hands every other charset to mailDecodeCharset.
//
// No connect, go-smtp or mox, and no go-message: on every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
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

// raw as the charset label says, by Extractor 1's C1-C3 (QD-694): see the file header.
func mailDecodeCharset(label string, raw []byte) []byte {
	return indexDecodeCharset(label, raw)
}

// RFC 2047's encoded words, decoded by mime's own UTF-8, US-ASCII and ISO-8859-1 and by mailDecodeCharset for any
// other charset, whose unknown labels pass their bytes through, so one word never stops the rest decoding.
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

// markup's text, by Extractor 1's html_to_text (QD-694): see the file header.
func mailHtmlText(markup []byte) []byte {
	return indexStripHtml(markup)
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
