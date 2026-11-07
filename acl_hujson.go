// The policy's text format (§8.5): JSON with comments and trailing commas. §8.5 leaves its parser to
// §4, which never chose one (question plan-ACL-hujson-parser), so the whole choice sits behind
// aclStandardizeHujson: taking github.com/tailscale/hujson instead changes this file and
// dependencies.yml, and nothing that reads the result.
//
// On every leg, the sidecar_http page Worker's included, since every admitted sidecar compiles policy.
// That leg is why nesting is bounded here, before any parser sees the document: encoding/json recurses
// per level, and on js the stack it runs out of is the host's, which kills the Worker with no error to
// catch. Whatever stands in for this file has to hold the same bound first.

package sidecar

import (
	"bytes"
	"fmt"
	"unicode/utf8"
)

// How deep a document nests: §8.5's deepest value is a test's accept entry, four levels down. A format
// value, as what a reader refuses must not differ by leg.
const aclPolicyMaxNestingDepth = 4

// The same document as standard JSON, at the same byte offsets: each comment and trailing comma
// becomes spaces, as hujson's Standardize does, so a line number read off this text is the source's.
// source stays as it was. Everything else is left for encoding/json to accept or refuse, so a
// malformed document passes through here and fails there, unless it nests too deep to hand over.
//
// A comment turns to spaces and never to nothing, or tr/**/ue would read as true. A comma counts as
// trailing only after a value, or [,] would read as an empty list.
func aclStandardizeHujson(source []byte) ([]byte, error) {
	// encoding/json would pass bad UTF-8 in a string as U+FFFD, and never look inside a comment
	if !utf8.Valid(source) {
		return nil, aclPolicyRefusal("the source is not UTF-8")
	}
	standard := bytes.Clone(source)
	blank := func(start int, end int) {
		for i := start; i < end; i += 1 {
			// line ends stay, so a block comment keeps the lines after it where they are
			if standard[i] != '\n' && standard[i] != '\r' {
				standard[i] = ' '
			}
		}
	}
	// the comma that only space and comments have followed, while it could still be trailing
	commaIndex := -1
	// the last byte of what came before, which says whether a comma follows a value
	var previous byte
	depth := 0
	for i := 0; i < len(standard); {
		switch c := standard[i]; {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i += 1
		case c == '/' && i+1 < len(standard) && standard[i+1] == '/':
			end := len(standard)
			if lineEnd := bytes.IndexByte(standard[i:], '\n'); 0 <= lineEnd {
				end = i + lineEnd
			}
			blank(i, end)
			i = end
		case c == '/' && i+1 < len(standard) && standard[i+1] == '*':
			length := bytes.Index(standard[i+2:], []byte("*/"))
			if length < 0 {
				return nil, aclPolicyRefusal("a block comment does not end")
			}
			end := i + 2 + length + 2
			blank(i, end)
			i = end
		case c == '"':
			i = aclSkipJsonString(standard, i)
			commaIndex = -1
			previous = c
		case c == ',':
			commaIndex = -1
			if previous != 0 && previous != '[' && previous != '{' && previous != ',' && previous != ':' {
				commaIndex = i
			}
			previous = c
			i += 1
		default:
			switch c {
			case '[', '{':
				depth += 1
				if aclPolicyMaxNestingDepth < depth {
					line, column := aclSourcePosition(source, i)
					return nil, fmt.Errorf("line %d, column %d: %w", line, column, aclPolicyRefusal("nested too deep"))
				}
			case ']', '}':
				depth = max(depth-1, 0)
				if 0 <= commaIndex {
					standard[commaIndex] = ' '
				}
			}
			commaIndex = -1
			previous = c
			i += 1
		}
	}
	return standard, nil
}

// The index after the string opening at start, or the text's end for one that never closes, which
// encoding/json then refuses.
func aclSkipJsonString(text []byte, start int) int {
	for i := start + 1; i < len(text); i += 1 {
		switch text[i] {
		case '\\':
			i += 1
		case '"':
			return i + 1
		}
	}
	return len(text)
}

// The 1-based line and column of a byte offset, for a refusal to point at without quoting anything.
func aclSourcePosition(source []byte, offset int) (line int, column int) {
	offset = min(offset, len(source))
	line = 1 + bytes.Count(source[:offset], []byte("\n"))
	column = offset - bytes.LastIndexByte(source[:offset], '\n')
	return line, column
}
