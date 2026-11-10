//go:build !ios_extension

// Extractor 1's HTML stripping (§11.14's extract row; protocol/INDEX-FORMAT.md's Extractor 1, HTML): a scanner of our
// own over decoded text, since the determinism row bans library-version input and a parser library's bump would
// change which bytes reach the index. Script and style elements go with their content, comments and <!...> and
// <?...> go, a tag is '<' then a letter or '/' up to the next '>' outside quotes, a block-level tag leaves one space
// and any other nothing, and entities decode once every tag is gone, so "&lt;" stays text.
//
// Readings this file takes where the format is silent: a tag, comment or declaration with no end runs to the end of
// the input, as a script with no end tag does; a script's or style's end tag is "</" and its name followed by
// anything but a letter or digit; a quote is any '"' or '\'' inside a tag; a tag's name is its run of ASCII letters
// and digits.

package sidecar

import (
	"bytes"
	"html"
)

// The tags that leave one space, so "<p>a</p><p>b</p>" reads "a b" and "<b>a</b>b" reads "ab".
var indexHtmlBlockTags = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true, "br": true, "center": true, "dd": true,
	"details": true, "dialog": true, "dir": true, "div": true, "dl": true, "dt": true, "fieldset": true,
	"figcaption": true, "figure": true, "footer": true, "form": true, "h1": true, "h2": true, "h3": true, "h4": true,
	"h5": true, "h6": true, "header": true, "hgroup": true, "hr": true, "li": true, "main": true, "menu": true,
	"nav": true, "ol": true, "p": true, "pre": true, "section": true, "summary": true, "table": true, "tbody": true,
	"td": true, "tfoot": true, "th": true, "thead": true, "tr": true, "ul": true,
}

// Whether b is an ASCII letter.
func indexAsciiLetter(b byte) bool {
	return 'a' <= b|0x20 && b|0x20 <= 'z'
}

// Whether b is an ASCII letter or digit.
func indexAsciiAlphanumeric(b byte) bool {
	return indexAsciiLetter(b) || ('0' <= b && b <= '9')
}

// Where the '>' ending the tag that starts text sits, outside quotes, or -1.
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

// Where the end tag of a script or style element named name starts in text, or -1.
func indexHtmlEndTag(text []byte, name string) int {
	for start := 0; start+2+len(name) <= len(text); start += 1 {
		if text[start] != '<' || text[start+1] != '/' {
			continue
		}
		candidate := text[start+2 : start+2+len(name)]
		if !bytes.EqualFold(candidate, []byte(name)) {
			continue
		}
		if after := start + 2 + len(name); after == len(text) || !indexAsciiAlphanumeric(text[after]) {
			return start
		}
	}
	return -1
}

// text with its HTML removed and its entities decoded.
func indexStripHtml(text []byte) []byte {
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
			name := string(bytes.ToLower(rest[nameStart:nameEnd]))
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
	return []byte(html.UnescapeString(string(stripped)))
}
