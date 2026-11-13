//go:build !js && !ios && !android && !sdk_mobile_bind

// The harness config files `ur install-harness` edits and the config check reads (§16.7; MCP-M3-16), read for exact
// edits: a person's other settings stay byte for byte, so no file is ever parsed and written back. Each value's byte
// span is found, and an edit replaces or inserts text there, leaving every byte outside it, comments and spacing
// included, as the person left it.
//
//	JSON  Claude Code's files, Codex's hooks.json and Cursor's files, read as JSONC: // and /* */ comments and a
//	      trailing comma are skipped and kept, since Claude Code and Cursor take them. A duplicate key where ur edits
//	      is refused, since which one the harness reads is its own choice
//	TOML  Codex's config.toml, by a bounded reader of TOML 1.0's statements: table headers, keys, and values of every
//	      kind, strings of all four forms, arrays and inline tables across lines among them, enough to find every
//	      table and every definition of mcp_servers.ur and to read ur's own tables as values. ur's tables are
//	      replaced whole, by line, and a file that defines mcp_servers.ur any other way (a dotted key, an inline table,
//	      an array of tables) is refused, since no exact edit of it exists
//
// A value ur reads comes out as encoding/json decodes one, numbers as json.Number, so the seal hashes one RFC 8785
// form for both formats (QD-103). Every refusal names what it could not read, never a value (I-13).
//
// Package-level functions are safe for concurrent use.

package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A harness config file ur will not edit or read: its syntax, its size or depth, or a shape no exact edit fits.
var ErrHarnessConfig = errors.New("harness config cannot be read for an exact edit")

// A refusal naming what could not be read, never a value.
func harnessConfigError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrHarnessConfig, fmt.Sprintf(format, args...))
}

// What a JSON value is.
type harnessJsonKind int

const (
	harnessJsonObject harnessJsonKind = iota + 1
	harnessJsonArray
	harnessJsonString
	// true, false, null or a number
	harnessJsonScalar
)

// One JSON value and where it sits: [start, end) is its text, from its first byte to past its last.
type harnessJsonNode struct {
	kind  harnessJsonKind
	start int
	end   int
	// an object's members and an array's elements, in order
	members  []*harnessJsonMember
	elements []*harnessJsonNode
	// a string's value
	text string
}

// One member of an object: its key, where the key's quote opens, and its value.
type harnessJsonMember struct {
	key      string
	keyStart int
	value    *harnessJsonNode
}

// A reader over one document.
type harnessJsonReader struct {
	content  []byte
	position int
	depth    int
	maxDepth int
}

// The document's root value, nil for a document of only space and comments. A UTF-8 byte order mark is skipped.
func harnessParseJson(content []byte, maxDepth int) (*harnessJsonNode, error) {
	if !utf8.Valid(content) {
		return nil, harnessConfigError("not utf-8")
	}
	reader := &harnessJsonReader{content: content, maxDepth: maxDepth}
	if bytes.HasPrefix(content, []byte("\xef\xbb\xbf")) {
		reader.position = 3
	}
	if err := reader.skip(); err != nil {
		return nil, err
	}
	if reader.position == len(content) {
		return nil, nil
	}
	root, err := reader.value()
	if err != nil {
		return nil, err
	}
	if err := reader.skip(); err != nil {
		return nil, err
	}
	if reader.position != len(content) {
		return nil, harnessConfigError("text after the document at byte %d", reader.position)
	}
	return root, nil
}

// Skips space and comments.
func (self *harnessJsonReader) skip() error {
	for self.position < len(self.content) {
		switch self.content[self.position] {
		case ' ', '\t', '\n', '\r':
			self.position += 1
		case '/':
			if self.position+1 == len(self.content) {
				return harnessConfigError("a stray / at byte %d", self.position)
			}
			switch self.content[self.position+1] {
			case '/':
				end := bytes.IndexByte(self.content[self.position:], '\n')
				if end < 0 {
					self.position = len(self.content)
				} else {
					self.position += end + 1
				}
			case '*':
				end := bytes.Index(self.content[self.position+2:], []byte("*/"))
				if end < 0 {
					return harnessConfigError("an unclosed comment at byte %d", self.position)
				}
				self.position += 2 + end + 2
			default:
				return harnessConfigError("a stray / at byte %d", self.position)
			}
		default:
			return nil
		}
	}
	return nil
}

// One value at the position.
func (self *harnessJsonReader) value() (*harnessJsonNode, error) {
	if self.position == len(self.content) {
		return nil, harnessConfigError("a value missing at the end")
	}
	switch self.content[self.position] {
	case '{':
		return self.object()
	case '[':
		return self.array()
	case '"':
		start := self.position
		text, err := self.string()
		if err != nil {
			return nil, err
		}
		return &harnessJsonNode{kind: harnessJsonString, start: start, end: self.position, text: text}, nil
	}
	start := self.position
	for self.position < len(self.content) && !strings.ContainsRune(" \t\r\n,]}/", rune(self.content[self.position])) {
		self.position += 1
	}
	token := self.content[start:self.position]
	if len(token) == 0 || !json.Valid(token) || token[0] == '"' || token[0] == '{' || token[0] == '[' {
		return nil, harnessConfigError("a value that is no JSON at byte %d", start)
	}
	return &harnessJsonNode{kind: harnessJsonScalar, start: start, end: self.position}, nil
}

// A string at the position, its value decoded strictly.
func (self *harnessJsonReader) string() (string, error) {
	start := self.position
	self.position += 1
	for self.position < len(self.content) {
		switch c := self.content[self.position]; {
		case c == '\\':
			self.position += 2
		case c == '"':
			self.position += 1
			text := ""
			if err := json.Unmarshal(self.content[start:self.position], &text); err != nil {
				return "", harnessConfigError("a string that is no JSON at byte %d", start)
			}
			return text, nil
		case c < 0x20:
			return "", harnessConfigError("a control character in a string at byte %d", self.position)
		default:
			self.position += 1
		}
	}
	return "", harnessConfigError("an unclosed string at byte %d", start)
}

// One level deeper, refused past maxDepth.
func (self *harnessJsonReader) enter() error {
	self.depth += 1
	if self.maxDepth < self.depth {
		return harnessConfigError("nested past %d levels", self.maxDepth)
	}
	return nil
}

// An object at the position: members, each a string key, a colon and a value, a trailing comma taken.
func (self *harnessJsonReader) object() (*harnessJsonNode, error) {
	if err := self.enter(); err != nil {
		return nil, err
	}
	defer func() { self.depth -= 1 }()
	node := &harnessJsonNode{kind: harnessJsonObject, start: self.position}
	self.position += 1
	for {
		if err := self.skip(); err != nil {
			return nil, err
		}
		if self.position == len(self.content) {
			return nil, harnessConfigError("an unclosed object at byte %d", node.start)
		}
		if self.content[self.position] == '}' {
			self.position += 1
			node.end = self.position
			return node, nil
		}
		if self.content[self.position] != '"' {
			return nil, harnessConfigError("a member with no string key at byte %d", self.position)
		}
		keyStart := self.position
		key, err := self.string()
		if err != nil {
			return nil, err
		}
		if err := self.skip(); err != nil {
			return nil, err
		}
		if self.position == len(self.content) || self.content[self.position] != ':' {
			return nil, harnessConfigError("a member with no colon at byte %d", self.position)
		}
		self.position += 1
		if err := self.skip(); err != nil {
			return nil, err
		}
		value, err := self.value()
		if err != nil {
			return nil, err
		}
		node.members = append(node.members, &harnessJsonMember{key: key, keyStart: keyStart, value: value})
		if err := self.skip(); err != nil {
			return nil, err
		}
		if self.position < len(self.content) && self.content[self.position] == ',' {
			self.position += 1
			continue
		}
		if self.position < len(self.content) && self.content[self.position] == '}' {
			continue
		}
		return nil, harnessConfigError("an object missing a comma at byte %d", self.position)
	}
}

// An array at the position: values, a trailing comma taken.
func (self *harnessJsonReader) array() (*harnessJsonNode, error) {
	if err := self.enter(); err != nil {
		return nil, err
	}
	defer func() { self.depth -= 1 }()
	node := &harnessJsonNode{kind: harnessJsonArray, start: self.position}
	self.position += 1
	for {
		if err := self.skip(); err != nil {
			return nil, err
		}
		if self.position == len(self.content) {
			return nil, harnessConfigError("an unclosed array at byte %d", node.start)
		}
		if self.content[self.position] == ']' {
			self.position += 1
			node.end = self.position
			return node, nil
		}
		value, err := self.value()
		if err != nil {
			return nil, err
		}
		node.elements = append(node.elements, value)
		if err := self.skip(); err != nil {
			return nil, err
		}
		if self.position < len(self.content) && self.content[self.position] == ',' {
			self.position += 1
			continue
		}
		if self.position < len(self.content) && self.content[self.position] == ']' {
			continue
		}
		return nil, harnessConfigError("an array missing a comma at byte %d", self.position)
	}
}

// The object's member of key, nil for none, refused where the key is there twice.
func (self *harnessJsonNode) member(key string) (*harnessJsonMember, error) {
	var found *harnessJsonMember
	for _, member := range self.members {
		if member.key != key {
			continue
		}
		if found != nil {
			return nil, harnessConfigError("the key %q twice in one object", key)
		}
		found = member
	}
	return found, nil
}

// The value of key in the object, nil for none or for a node that is no object.
func (self *harnessJsonNode) get(key string) *harnessJsonNode {
	if self == nil || self.kind != harnessJsonObject {
		return nil
	}
	var found *harnessJsonNode
	for _, member := range self.members {
		if member.key == key {
			found = member.value
		}
	}
	return found
}

// The node as the value encoding/json decodes, numbers as json.Number. An object's duplicate key keeps its last
// value, as JSON.parse does.
func harnessJsonValue(content []byte, node *harnessJsonNode) (any, error) {
	if node == nil {
		return nil, nil
	}
	switch node.kind {
	case harnessJsonObject:
		object := map[string]any{}
		for _, member := range node.members {
			value, err := harnessJsonValue(content, member.value)
			if err != nil {
				return nil, err
			}
			object[member.key] = value
		}
		return object, nil
	case harnessJsonArray:
		array := []any{}
		for _, element := range node.elements {
			value, err := harnessJsonValue(content, element)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		return array, nil
	case harnessJsonString:
		return node.text, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(content[node.start:node.end]))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, harnessConfigError("a value that is no JSON at byte %d", node.start)
	}
	return value, nil
}

// value through JSON, as harnessJsonValue reads text: what a template's value is once written and read back.
func harnessJsonNormal(value any) (any, error) {
	encoded, err := harnessJsonEncode(value, "", "")
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.UseNumber()
	var normal any
	if err := decoder.Decode(&normal); err != nil {
		return nil, err
	}
	return normal, nil
}

// value's JSON, HTML characters unescaped, indented by unit under prefix after its first line; compact for an
// empty unit.
func harnessJsonEncode(value any, prefix string, unit string) (string, error) {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if unit != "" {
		encoder.SetIndent(prefix, unit)
	}
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buffer.String(), "\n"), nil
}

// One edit: content[start:end] becomes text.
type harnessEdit struct {
	start int
	end   int
	text  string
}

// content with edit made, a new slice.
func harnessApplyEdit(content []byte, edit *harnessEdit) []byte {
	edited := make([]byte, 0, len(content)-(edit.end-edit.start)+len(edit.text))
	edited = append(edited, content[:edit.start]...)
	edited = append(edited, edit.text...)
	return append(edited, content[edit.end:]...)
}

// The space and tabs that start the line holding position.
func harnessLineIndent(content []byte, position int) string {
	lineStart := bytes.LastIndexByte(content[:position], '\n') + 1
	end := lineStart
	for end < len(content) && (content[end] == ' ' || content[end] == '\t') {
		end += 1
	}
	return string(content[lineStart:end])
}

// Whether a newline lies in content[start:end].
func harnessHasNewline(content []byte, start int, end int) bool {
	return bytes.IndexByte(content[start:end], '\n') >= 0
}

// The document's indent unit: the leading space of its first indented line, else two spaces.
func harnessIndentUnit(content []byte) string {
	for _, line := range bytes.Split(content, []byte("\n")) {
		trimmed := bytes.TrimLeft(line, " \t")
		if len(trimmed) != 0 && len(trimmed) < len(line) {
			return string(line[:len(line)-len(trimmed)])
		}
	}
	return "  "
}

// The position just past a comma that follows end over space and comments, or -1 for none.
func harnessCommaAfter(content []byte, end int) int {
	reader := &harnessJsonReader{content: content, position: end}
	if reader.skip() != nil {
		return -1
	}
	if reader.position < len(content) && content[reader.position] == ',' {
		return reader.position + 1
	}
	return -1
}

// The end of position's line where only space and comments follow it there, so an entry added after it keeps them
// with what they follow; else position.
func harnessLineRest(content []byte, position int) int {
	at := position
	for at < len(content) {
		switch {
		case content[at] == ' ' || content[at] == '\t' || content[at] == '\r':
			at += 1
		case bytes.HasPrefix(content[at:], []byte("//")):
			end := bytes.IndexByte(content[at:], '\n')
			if end < 0 {
				return len(content)
			}
			return at + end
		case bytes.HasPrefix(content[at:], []byte("/*")):
			end := bytes.Index(content[at+2:], []byte("*/"))
			if end < 0 || harnessHasNewline(content, at, at+2+end) {
				return position
			}
			at += 2 + end + 2
		case content[at] == '\n':
			return at
		default:
			return position
		}
	}
	return at
}

// The edit that puts entries, each a rendered value or member, into container, an object or an array, after its
// last: on one line where the container sits on one line, else each on a line of its own at the indent of the
// container's entries. render gives an entry's text for the indent it starts at.
func harnessJsonAppend(content []byte, container *harnessJsonNode, count int, render func(indent string) (string, error)) (*harnessEdit, error) {
	unit := harnessIndentUnit(content)
	closeIndent := harnessLineIndent(content, container.start)
	lastEnd := -1
	firstStart := -1
	switch container.kind {
	case harnessJsonObject:
		if 0 < len(container.members) {
			firstStart = container.members[0].keyStart
			lastEnd = container.members[len(container.members)-1].value.end
		}
	case harnessJsonArray:
		if 0 < len(container.elements) {
			firstStart = container.elements[0].start
			lastEnd = container.elements[len(container.elements)-1].end
		}
	default:
		return nil, harnessConfigError("an edit inside no object or array")
	}
	if lastEnd < 0 {
		// empty: the entries on lines of their own, the closing bracket on its own after them
		indent := closeIndent + unit
		texts := []string{}
		for i := 0; i < count; i += 1 {
			text, err := render(indent)
			if err != nil {
				return nil, err
			}
			texts = append(texts, text)
		}
		interior := content[container.start+1 : container.end-1]
		if len(bytes.TrimSpace(interior)) == 0 {
			text := "\n" + indent + strings.Join(texts, ",\n"+indent) + "\n" + closeIndent
			return &harnessEdit{start: container.start + 1, end: container.end - 1, text: text}, nil
		}
		// comments inside: kept after the entries
		text := "\n" + indent + strings.Join(texts, ",\n"+indent)
		return &harnessEdit{start: container.start + 1, end: container.start + 1, text: text}, nil
	}
	inline := !harnessHasNewline(content, container.start, firstStart)
	indent := harnessLineIndent(content, firstStart)
	texts := []string{}
	for i := 0; i < count; i += 1 {
		var text string
		var err error
		if inline {
			text, err = render("")
		} else {
			text, err = render(indent)
		}
		if err != nil {
			return nil, err
		}
		texts = append(texts, text)
	}
	separator := ",\n" + indent
	if inline {
		separator = ", "
	}
	if comma := harnessCommaAfter(content, lastEnd); 0 <= comma {
		// a trailing comma stays one: each entry ends with its own
		if inline {
			return &harnessEdit{start: comma, end: comma, text: " " + strings.Join(texts, ", ") + ","}, nil
		}
		at := harnessLineRest(content, comma)
		return &harnessEdit{start: at, end: at, text: "\n" + indent + strings.Join(texts, separator) + ","}, nil
	}
	return &harnessEdit{start: lastEnd, end: lastEnd, text: separator + strings.Join(texts, separator)}, nil
}

// The edit that adds the member key: value to object, value rendered as JSON at the member's indent.
func harnessJsonAddMember(content []byte, object *harnessJsonNode, key string, value any) (*harnessEdit, error) {
	unit := harnessIndentUnit(content)
	return harnessJsonAppend(content, object, 1, func(indent string) (string, error) {
		keyText, err := harnessJsonEncode(key, "", "")
		if err != nil {
			return "", err
		}
		valueUnit := unit
		if indent == "" {
			valueUnit = ""
		}
		valueText, err := harnessJsonEncode(value, indent, valueUnit)
		if err != nil {
			return "", err
		}
		return keyText + ": " + valueText, nil
	})
}

// The edit that adds values to array, after its last element.
func harnessJsonAddElements(content []byte, array *harnessJsonNode, values []any) (*harnessEdit, error) {
	unit := harnessIndentUnit(content)
	next := 0
	return harnessJsonAppend(content, array, len(values), func(indent string) (string, error) {
		valueUnit := unit
		if indent == "" {
			valueUnit = ""
		}
		text, err := harnessJsonEncode(values[next], indent, valueUnit)
		next += 1
		return text, err
	})
}

// The edit that replaces node's text with value, rendered at the indent of node's line.
func harnessJsonReplace(content []byte, node *harnessJsonNode, value any) (*harnessEdit, error) {
	indent := harnessLineIndent(content, node.start)
	unit := harnessIndentUnit(content)
	if !harnessHasNewline(content, node.start, node.end) && node.kind != harnessJsonObject && node.kind != harnessJsonArray {
		unit = ""
	}
	text, err := harnessJsonEncode(value, indent, unit)
	if err != nil {
		return nil, err
	}
	return &harnessEdit{start: node.start, end: node.end, text: text}, nil
}

// The edit that removes array's element at index with the comma that joins it, so the elements around it keep their
// lines and spacing.
func harnessJsonRemoveElement(content []byte, array *harnessJsonNode, index int) *harnessEdit {
	element := array.elements[index]
	switch {
	case index+1 < len(array.elements):
		return &harnessEdit{start: element.start, end: array.elements[index+1].start}
	case 0 < index:
		return &harnessEdit{start: array.elements[index-1].end, end: element.end}
	}
	interior := content[array.start+1 : array.end-1]
	if !bytes.Contains(interior, []byte("/")) {
		return &harnessEdit{start: array.start + 1, end: array.end - 1}
	}
	end := element.end
	if comma := harnessCommaAfter(content, end); 0 <= comma {
		end = comma
	}
	return &harnessEdit{start: element.start, end: end}
}

// The TOML key path a header or a key names.
type harnessTomlKey []string

// Whether the key starts with prefix.
func (self harnessTomlKey) hasPrefix(prefix ...string) bool {
	return len(prefix) <= len(self) && slices.Equal(self[:len(prefix)], prefix)
}

// One table of a TOML document: its header's keys, and [start, end) the lines it owns, from its header's line to the
// next header's. The root table, before any header, has no keys.
type harnessTomlTable struct {
	keys        harnessTomlKey
	arrayOfThem bool
	start       int
	end         int
	values      []*harnessTomlValue
}

// One key = value of a table: the keys after the table's, and its value as JSON's.
type harnessTomlValue struct {
	keys  harnessTomlKey
	start int
	value any
}

// A TOML document's tables, the root first.
type harnessTomlDocument struct {
	tables []*harnessTomlTable
}

// A reader over one TOML document.
type harnessTomlReader struct {
	content  []byte
	position int
	depth    int
	maxDepth int
}

// The document's tables: every header and key = value of TOML 1.0, a value of any kind read in full.
func harnessParseToml(content []byte, maxDepth int) (*harnessTomlDocument, error) {
	if !utf8.Valid(content) {
		return nil, harnessConfigError("not utf-8")
	}
	reader := &harnessTomlReader{content: content, maxDepth: maxDepth}
	if bytes.HasPrefix(content, []byte("\xef\xbb\xbf")) {
		reader.position = 3
	}
	root := &harnessTomlTable{start: 0}
	document := &harnessTomlDocument{tables: []*harnessTomlTable{root}}
	table := root
	for {
		reader.skipBlank()
		if reader.position == len(content) {
			table.end = len(content)
			return document, nil
		}
		lineStart := bytes.LastIndexByte(content[:reader.position], '\n') + 1
		if content[reader.position] == '[' {
			header, err := reader.header()
			if err != nil {
				return nil, err
			}
			table.end = lineStart
			header.start = lineStart
			document.tables = append(document.tables, header)
			table = header
		} else {
			start := reader.position
			keys, err := reader.key()
			if err != nil {
				return nil, err
			}
			reader.skipSpace()
			if reader.position == len(content) || content[reader.position] != '=' {
				return nil, harnessConfigError("a key with no = at byte %d", reader.position)
			}
			reader.position += 1
			reader.skipSpace()
			value, err := reader.value()
			if err != nil {
				return nil, err
			}
			table.values = append(table.values, &harnessTomlValue{keys: keys, start: start, value: value})
		}
		if err := reader.endLine(); err != nil {
			return nil, err
		}
	}
}

// Skips space, tabs, newlines and comments between statements.
func (self *harnessTomlReader) skipBlank() {
	for self.position < len(self.content) {
		switch self.content[self.position] {
		case ' ', '\t', '\r', '\n':
			self.position += 1
		case '#':
			self.skipComment()
		default:
			return
		}
	}
}

// Skips space and tabs.
func (self *harnessTomlReader) skipSpace() {
	for self.position < len(self.content) && (self.content[self.position] == ' ' || self.content[self.position] == '\t') {
		self.position += 1
	}
}

// Skips a comment to its line's end.
func (self *harnessTomlReader) skipComment() {
	end := bytes.IndexByte(self.content[self.position:], '\n')
	if end < 0 {
		self.position = len(self.content)
		return
	}
	self.position += end
}

// The rest of a statement's line: space, an optional comment, then a newline or the end.
func (self *harnessTomlReader) endLine() error {
	self.skipSpace()
	if self.position < len(self.content) && self.content[self.position] == '#' {
		self.skipComment()
	}
	if self.position < len(self.content) && self.content[self.position] == '\r' {
		self.position += 1
	}
	if self.position == len(self.content) {
		return nil
	}
	if self.content[self.position] != '\n' {
		return harnessConfigError("more after a statement at byte %d", self.position)
	}
	self.position += 1
	return nil
}

// A table header: [keys] or [[keys]].
func (self *harnessTomlReader) header() (*harnessTomlTable, error) {
	table := &harnessTomlTable{}
	self.position += 1
	if self.position < len(self.content) && self.content[self.position] == '[' {
		table.arrayOfThem = true
		self.position += 1
	}
	self.skipSpace()
	keys, err := self.key()
	if err != nil {
		return nil, err
	}
	table.keys = keys
	self.skipSpace()
	closing := "]"
	if table.arrayOfThem {
		closing = "]]"
	}
	if !bytes.HasPrefix(self.content[self.position:], []byte(closing)) {
		return nil, harnessConfigError("a header with no %s at byte %d", closing, self.position)
	}
	self.position += len(closing)
	return table, nil
}

// A dotted key: bare, basic or literal parts joined by dots.
func (self *harnessTomlReader) key() (harnessTomlKey, error) {
	keys := harnessTomlKey{}
	for {
		self.skipSpace()
		if self.position == len(self.content) {
			return nil, harnessConfigError("a key missing at the end")
		}
		switch self.content[self.position] {
		case '"':
			if bytes.HasPrefix(self.content[self.position:], []byte(`"""`)) {
				return nil, harnessConfigError("a multi-line string as a key at byte %d", self.position)
			}
			part, err := self.basicString()
			if err != nil {
				return nil, err
			}
			keys = append(keys, part)
		case '\'':
			if bytes.HasPrefix(self.content[self.position:], []byte(`'''`)) {
				return nil, harnessConfigError("a multi-line string as a key at byte %d", self.position)
			}
			part, err := self.literalString()
			if err != nil {
				return nil, err
			}
			keys = append(keys, part)
		default:
			start := self.position
			for self.position < len(self.content) && harnessTomlBareKeyByte(self.content[self.position]) {
				self.position += 1
			}
			if start == self.position {
				return nil, harnessConfigError("a key that is none at byte %d", start)
			}
			keys = append(keys, string(self.content[start:self.position]))
		}
		self.skipSpace()
		if self.position < len(self.content) && self.content[self.position] == '.' {
			self.position += 1
			continue
		}
		return keys, nil
	}
}

// Whether b may be in a bare key.
func harnessTomlBareKeyByte(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9' || b == '_' || b == '-'
}

// One level deeper, refused past maxDepth.
func (self *harnessTomlReader) enter() error {
	self.depth += 1
	if self.maxDepth < self.depth {
		return harnessConfigError("nested past %d levels", self.maxDepth)
	}
	return nil
}

// A value at the position, as JSON's: strings, arrays, inline tables as objects, booleans, numbers as json.Number,
// and dates, times, inf and nan as their text.
func (self *harnessTomlReader) value() (any, error) {
	if self.position == len(self.content) {
		return nil, harnessConfigError("a value missing at the end")
	}
	switch {
	case bytes.HasPrefix(self.content[self.position:], []byte(`"""`)):
		return self.multiLineBasicString()
	case bytes.HasPrefix(self.content[self.position:], []byte(`'''`)):
		return self.multiLineLiteralString()
	case self.content[self.position] == '"':
		return self.basicString()
	case self.content[self.position] == '\'':
		return self.literalString()
	case self.content[self.position] == '[':
		return self.array()
	case self.content[self.position] == '{':
		return self.inlineTable()
	}
	start := self.position
	for self.position < len(self.content) && !strings.ContainsRune(" \t\r\n,]}#", rune(self.content[self.position])) {
		self.position += 1
	}
	// a date and a time may be joined by one space
	if self.position+1 < len(self.content) && self.content[self.position] == ' ' && 10 == self.position-start &&
		'0' <= self.content[self.position+1] && self.content[self.position+1] <= '9' {
		self.position += 1
		for self.position < len(self.content) && !strings.ContainsRune(" \t\r\n,]}#", rune(self.content[self.position])) {
			self.position += 1
		}
	}
	token := string(self.content[start:self.position])
	switch token {
	case "":
		return nil, harnessConfigError("a value that is none at byte %d", start)
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	plain := strings.ReplaceAll(token, "_", "")
	if integer, err := strconv.ParseInt(plain, 0, 64); err == nil {
		return json.Number(strconv.FormatInt(integer, 10)), nil
	}
	if float, err := strconv.ParseFloat(plain, 64); err == nil && !strings.ContainsAny(plain, "xXnNiI") {
		return json.Number(strconv.FormatFloat(float, 'g', -1, 64)), nil
	}
	if !strings.ContainsAny(token[:1], "0123456789+-in") {
		return nil, harnessConfigError("a value that is no TOML at byte %d", start)
	}
	return token, nil
}

// A basic string, its escapes decoded.
func (self *harnessTomlReader) basicString() (string, error) {
	start := self.position
	self.position += 1
	text := strings.Builder{}
	for self.position < len(self.content) {
		c := self.content[self.position]
		switch {
		case c == '"':
			self.position += 1
			return text.String(), nil
		case c == '\\':
			if err := self.escape(&text); err != nil {
				return "", err
			}
		case c == '\n' || (c < 0x20 && c != '\t') || c == 0x7f:
			return "", harnessConfigError("a control character in a string at byte %d", self.position)
		default:
			text.WriteByte(c)
			self.position += 1
		}
	}
	return "", harnessConfigError("an unclosed string at byte %d", start)
}

// One escape of a basic string at the position, written to text.
func (self *harnessTomlReader) escape(text *strings.Builder) error {
	if self.position+1 == len(self.content) {
		return harnessConfigError("an escape at the end")
	}
	c := self.content[self.position+1]
	self.position += 2
	switch c {
	case 'b':
		text.WriteByte('\b')
	case 't':
		text.WriteByte('\t')
	case 'n':
		text.WriteByte('\n')
	case 'f':
		text.WriteByte('\f')
	case 'r':
		text.WriteByte('\r')
	case '"':
		text.WriteByte('"')
	case '\\':
		text.WriteByte('\\')
	case 'u', 'U':
		count := 4
		if c == 'U' {
			count = 8
		}
		if len(self.content) < self.position+count {
			return harnessConfigError("a short unicode escape at byte %d", self.position)
		}
		code, err := strconv.ParseUint(string(self.content[self.position:self.position+count]), 16, 32)
		if err != nil || !utf8.ValidRune(rune(code)) {
			return harnessConfigError("a unicode escape that is none at byte %d", self.position)
		}
		text.WriteRune(rune(code))
		self.position += count
	default:
		return harnessConfigError("an escape that is none at byte %d", self.position-2)
	}
	return nil
}

// A literal string, as written.
func (self *harnessTomlReader) literalString() (string, error) {
	start := self.position
	end := bytes.IndexAny(self.content[start+1:], "'\n")
	if end < 0 || self.content[start+1+end] != '\'' {
		return "", harnessConfigError("an unclosed string at byte %d", start)
	}
	self.position = start + 1 + end + 1
	return string(self.content[start+1 : start+1+end]), nil
}

// A multi-line basic string: a newline right after its opening dropped, escapes decoded, and a backslash at a line's
// end joining it to the next line's first non-space.
func (self *harnessTomlReader) multiLineBasicString() (string, error) {
	start := self.position
	self.position += 3
	if bytes.HasPrefix(self.content[self.position:], []byte("\r\n")) {
		self.position += 2
	} else if self.position < len(self.content) && self.content[self.position] == '\n' {
		self.position += 1
	}
	text := strings.Builder{}
	for self.position < len(self.content) {
		if bytes.HasPrefix(self.content[self.position:], []byte(`"""`)) {
			// up to two quotes may close it
			extra := 0
			for extra < 2 && self.position+3+extra < len(self.content) && self.content[self.position+3+extra] == '"' {
				extra += 1
			}
			text.WriteString(strings.Repeat(`"`, extra))
			self.position += 3 + extra
			return text.String(), nil
		}
		c := self.content[self.position]
		if c == '\\' {
			rest := self.position + 1
			for rest < len(self.content) && (self.content[rest] == ' ' || self.content[rest] == '\t') {
				rest += 1
			}
			if rest < len(self.content) && (self.content[rest] == '\n' || self.content[rest] == '\r') {
				for rest < len(self.content) && strings.ContainsRune(" \t\r\n", rune(self.content[rest])) {
					rest += 1
				}
				self.position = rest
				continue
			}
			if err := self.escape(&text); err != nil {
				return "", err
			}
			continue
		}
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return "", harnessConfigError("a control character in a string at byte %d", self.position)
		}
		text.WriteByte(c)
		self.position += 1
	}
	return "", harnessConfigError("an unclosed string at byte %d", start)
}

// A multi-line literal string, as written, a newline right after its opening dropped.
func (self *harnessTomlReader) multiLineLiteralString() (string, error) {
	start := self.position
	self.position += 3
	if bytes.HasPrefix(self.content[self.position:], []byte("\r\n")) {
		self.position += 2
	} else if self.position < len(self.content) && self.content[self.position] == '\n' {
		self.position += 1
	}
	end := bytes.Index(self.content[self.position:], []byte(`'''`))
	if end < 0 {
		return "", harnessConfigError("an unclosed string at byte %d", start)
	}
	stop := self.position + end
	extra := 0
	for extra < 2 && stop+3+extra < len(self.content) && self.content[stop+3+extra] == '\'' {
		extra += 1
	}
	text := string(self.content[self.position:stop]) + strings.Repeat("'", extra)
	self.position = stop + 3 + extra
	return text, nil
}

// Skips space, newlines and comments inside an array or an inline table.
func (self *harnessTomlReader) skipInside() {
	for self.position < len(self.content) {
		switch self.content[self.position] {
		case ' ', '\t', '\r', '\n':
			self.position += 1
		case '#':
			self.skipComment()
		default:
			return
		}
	}
}

// An array: values joined by commas, across lines, a trailing comma taken.
func (self *harnessTomlReader) array() (any, error) {
	if err := self.enter(); err != nil {
		return nil, err
	}
	defer func() { self.depth -= 1 }()
	start := self.position
	self.position += 1
	values := []any{}
	for {
		self.skipInside()
		if self.position == len(self.content) {
			return nil, harnessConfigError("an unclosed array at byte %d", start)
		}
		if self.content[self.position] == ']' {
			self.position += 1
			return values, nil
		}
		value, err := self.value()
		if err != nil {
			return nil, err
		}
		values = append(values, value)
		self.skipInside()
		if self.position < len(self.content) && self.content[self.position] == ',' {
			self.position += 1
			continue
		}
		if self.position < len(self.content) && self.content[self.position] == ']' {
			continue
		}
		return nil, harnessConfigError("an array missing a comma at byte %d", self.position)
	}
}

// An inline table: key = value pairs joined by commas, as an object. A newline or a trailing comma inside, which TOML
// 1.1 allows, is taken.
func (self *harnessTomlReader) inlineTable() (any, error) {
	if err := self.enter(); err != nil {
		return nil, err
	}
	defer func() { self.depth -= 1 }()
	start := self.position
	self.position += 1
	object := map[string]any{}
	for {
		self.skipInside()
		if self.position == len(self.content) {
			return nil, harnessConfigError("an unclosed inline table at byte %d", start)
		}
		if self.content[self.position] == '}' {
			self.position += 1
			return object, nil
		}
		keys, err := self.key()
		if err != nil {
			return nil, err
		}
		self.skipSpace()
		if self.position == len(self.content) || self.content[self.position] != '=' {
			return nil, harnessConfigError("a key with no = at byte %d", self.position)
		}
		self.position += 1
		self.skipSpace()
		value, err := self.value()
		if err != nil {
			return nil, err
		}
		if err := harnessTomlSet(object, keys, value); err != nil {
			return nil, err
		}
		self.skipInside()
		if self.position < len(self.content) && self.content[self.position] == ',' {
			self.position += 1
			continue
		}
		if self.position < len(self.content) && self.content[self.position] == '}' {
			continue
		}
		return nil, harnessConfigError("an inline table missing a comma at byte %d", self.position)
	}
}

// Sets keys in object to value, making the objects between, refused where a key is there already.
func harnessTomlSet(object map[string]any, keys harnessTomlKey, value any) error {
	for _, key := range keys[:len(keys)-1] {
		next, ok := object[key]
		if !ok {
			made := map[string]any{}
			object[key] = made
			object = made
			continue
		}
		nested, ok := next.(map[string]any)
		if !ok {
			return harnessConfigError("the key %q is a value and a table", key)
		}
		object = nested
	}
	last := keys[len(keys)-1]
	if _, taken := object[last]; taken {
		return harnessConfigError("the key %q twice", last)
	}
	object[last] = value
	return nil
}

// A TOML basic string of text.
func harnessTomlString(text string) string {
	encoded, err := harnessJsonEncode(text, "", "")
	if err != nil {
		// a Go string always encodes
		return `""`
	}
	return encoded
}
