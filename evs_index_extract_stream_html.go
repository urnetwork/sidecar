//go:build !ios_extension

// html_to_text in one pass (DESIGN-DETAILS 11.2.6's X1 to X7 and E1 to E4, as 11.2.8's tags and references rows hold
// them): tags keeps a state, a quote byte, at most a block tag's longest name and the end tag of a script or style
// being matched; references keeps an '&' and at most 32 bytes after it, enough since the longest name is 32 bytes with
// its ';', so a run of more than 31 alphanumeric bytes matches no name whole and E3 looks only at its first 6. Each
// gives exactly what evs_index_extract_html.go's whole-value function gives, whatever pieces the text arrives in.
// Not safe for concurrent use.

package sidecar

import (
	"unicode/utf8"
)

// Where the tag scanner stands.
type indexStreamTagState int

const (
	// Copying text.
	indexTagText indexStreamTagState = iota
	// A '<', and the bytes after it that decide what it opens.
	indexTagOpen
	// "<!".
	indexTagBang
	// "<!-".
	indexTagBangDash
	// In a comment, after its "<!--".
	indexTagComment
	// In a declaration, "<!" or "<?" to the next '>'.
	indexTagDeclaration
	// In a tag, its name being read or read.
	indexTagInside
	// In a script's or style's content, its end tag being matched.
	indexTagRaw
	// In a script's or style's end tag, to its '>'.
	indexTagRawEnd
)

// X1 to X7 in one pass.
type indexStreamTags struct {
	next  indexStreamStage
	state indexStreamTagState
	// A tag: whether it closes, its name's bytes as lower while they are a block tag's at most, whether the name
	// passed that, whether it ended, and the quote it is in.
	closing  bool
	name     []byte
	nameLong bool
	nameDone bool
	quote    byte
	// A comment: the dashes just read.
	dashes int
	// A script or style: "</" and its name, and how many bytes of it matched.
	endTag  []byte
	matched int
	out     []byte
}

// The longest name a tag's end can depend on, a block tag's or script's: blockquote's and figcaption's 10 B, read from
// X4's list so it cannot drift from it. A longer name is none of them.
var indexStreamTagNameMax = func() int {
	longest := max(len("script"), len("style"))
	for name := range indexHtmlBlockTags {
		longest = max(longest, len(name))
	}
	return longest
}()

// lower of one byte (11.2.1).
func indexLowerByte(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + 'a' - 'A'
	}
	return b
}

// html_to_text's first half before next.
func indexNewStreamTags(next indexStreamStage) *indexStreamTags {
	return &indexStreamTags{next: next, name: make([]byte, 0, indexStreamTagNameMax)}
}

// Takes text's bytes.
func (self *indexStreamTags) write(text []byte) {
	self.out = self.out[:0]
	for _, b := range text {
		self.push(b)
	}
	self.next.write(self.out)
}

// Opens a tag after its '<' and the byte that makes it one.
func (self *indexStreamTags) openTag(b byte) {
	self.state = indexTagInside
	self.closing = b == '/'
	self.name = self.name[:0]
	self.nameLong, self.nameDone = false, false
	self.quote = 0
	if !self.closing {
		self.tagByte(b)
	}
}

// One byte inside a tag, from the byte after its '<' or "</": the name while alphanumeric, then quotes, to the first
// '>' outside them.
func (self *indexStreamTags) tagByte(b byte) {
	if !self.nameDone {
		if indexAsciiAlphanumeric(b) {
			if len(self.name) < indexStreamTagNameMax {
				self.name = append(self.name, indexLowerByte(b))
			} else {
				self.nameLong = true
			}
			return
		}
		self.nameDone = true
	}
	switch {
	case self.quote != 0:
		if b == self.quote {
			self.quote = 0
		}
	case b == '"' || b == '\'':
		self.quote = b
	case b == '>':
		self.endOfTag()
	}
}

// A tag's '>': a script or style that is not a closing tag takes its content to its end tag, and a block tag gives
// one SP.
func (self *indexStreamTags) endOfTag() {
	self.state = indexTagText
	name := string(self.name)
	if self.nameLong {
		return
	}
	if !self.closing && (name == "script" || name == "style") {
		self.endTag = append(append(self.endTag[:0], '<', '/'), name...)
		self.matched = 0
		self.state = indexTagRaw
		return
	}
	if indexHtmlBlockTags[name] {
		self.out = append(self.out, ' ')
	}
}

// Takes one byte.
func (self *indexStreamTags) push(b byte) {
	switch self.state {
	case indexTagText:
		if b == '<' {
			self.state = indexTagOpen
		} else {
			self.out = append(self.out, b)
		}
	case indexTagOpen:
		switch {
		case b == '!':
			self.state = indexTagBang
		case b == '?':
			self.state = indexTagDeclaration
		case indexAsciiLetter(b) || b == '/':
			self.openTag(b)
		default:
			self.out = append(self.out, '<')
			self.state = indexTagText
			self.push(b)
		}
	case indexTagBang:
		switch b {
		case '-':
			self.state = indexTagBangDash
		case '>':
			self.state = indexTagText
		default:
			self.state = indexTagDeclaration
		}
	case indexTagBangDash:
		switch b {
		case '-':
			self.state = indexTagComment
			self.dashes = 0
		case '>':
			self.state = indexTagText
		default:
			self.state = indexTagDeclaration
		}
	case indexTagComment:
		switch {
		case b == '-':
			self.dashes += 1
		case b == '>' && 2 <= self.dashes:
			self.state = indexTagText
		default:
			self.dashes = 0
		}
	case indexTagDeclaration:
		if b == '>' {
			self.state = indexTagText
		}
	case indexTagInside:
		self.tagByte(b)
	case indexTagRaw:
		if self.matched == len(self.endTag) {
			if indexAsciiAlphanumeric(b) {
				self.matched = 0
				return
			}
			// X5's end tag opens a tag by X3, looking from the byte after its '<'; its name's bytes hold no quote
			self.state = indexTagRawEnd
			self.quote = 0
			self.rawEndByte(b)
			return
		}
		switch {
		case indexLowerByte(b) == self.endTag[self.matched]:
			self.matched += 1
		case b == '<':
			self.matched = 1
		default:
			self.matched = 0
		}
	case indexTagRawEnd:
		self.rawEndByte(b)
	}
}

// One byte of a script's or style's end tag, after its name: quotes, and the first '>' outside them ends it. It gives
// nothing.
func (self *indexStreamTags) rawEndByte(b byte) {
	switch {
	case self.quote != 0:
		if b == self.quote {
			self.quote = 0
		}
	case b == '"' || b == '\'':
		self.quote = b
	case b == '>':
		self.state = indexTagText
	}
}

// The text's end: a lone '<' is copied, and a comment, declaration, tag, script or style with no end takes
// everything to the end (X7).
func (self *indexStreamTags) finish() {
	self.out = self.out[:0]
	if self.state == indexTagOpen {
		self.out = append(self.out, '<')
	}
	self.state = indexTagText
	self.next.write(self.out)
	self.next.finish()
}

// Where the reference decoder stands.
type indexStreamReferenceState int

const (
	// Copying text.
	indexReferenceText indexStreamReferenceState = iota
	// An '&' and nothing yet.
	indexReferenceAmpersand
	// "&#", maybe an 'x', and digits.
	indexReferenceNumeric
	// '&' and a run of alphanumeric bytes, held.
	indexReferenceName
	// A run past 31 alphanumeric bytes, decided: the rest of it is copied.
	indexReferenceRun
)

// E1 to E4 in one pass.
type indexStreamReferences struct {
	next  indexStreamStage
	state indexStreamReferenceState
	// A numeric reference: its base, its value held at 0x110000, whether it read an 'x' or 'X' and which, and its
	// digits' count.
	base    int
	value   int
	x       byte
	digits  int
	name    []byte
	out     []byte
	runSize int
}

// What E2 and E3 can match, read from the table so neither drifts from it: the longest run of alphanumeric bytes any
// name is, without its ';' (31 B), and the longest name without a ';', E3's longest prefix (6 B).
var indexStreamReferenceRunMax, indexStreamReferencePrefixMax = func() (int, int) {
	run, prefix := 0, 0
	start := 0
	for _, end := range indexReferenceNameEnds {
		name := indexReferenceNames[start:end]
		start = int(end)
		if name[len(name)-1] == ';' {
			run = max(run, len(name)-1)
		} else {
			run = max(run, len(name))
			prefix = max(prefix, len(name))
		}
	}
	return run, prefix
}()

// html_to_text's second half before next.
func indexNewStreamReferences(next indexStreamStage) *indexStreamReferences {
	return &indexStreamReferences{next: next, name: make([]byte, 0, indexStreamReferenceRunMax+1)}
}

// Takes text's bytes.
func (self *indexStreamReferences) write(text []byte) {
	self.out = self.out[:0]
	for _, b := range text {
		self.push(b)
	}
	self.next.write(self.out)
}

// Takes one byte.
func (self *indexStreamReferences) push(b byte) {
	switch self.state {
	case indexReferenceText:
		if b == '&' {
			self.state = indexReferenceAmpersand
		} else {
			self.out = append(self.out, b)
		}
	case indexReferenceAmpersand:
		switch {
		case b == '#':
			self.state = indexReferenceNumeric
			self.base, self.value, self.x, self.digits = 10, 0, 0, 0
		case indexAsciiAlphanumeric(b):
			self.state = indexReferenceName
			self.name = append(self.name[:0], b)
		default:
			self.out = append(self.out, '&')
			self.state = indexReferenceText
			self.push(b)
		}
	case indexReferenceNumeric:
		if self.digits == 0 && self.x == 0 && (b == 'x' || b == 'X') {
			self.base, self.x = 16, b
			return
		}
		if digit := indexHexValue(b); 0 <= digit && digit < self.base {
			if self.value <= utf8.MaxRune {
				self.value = min(self.value*self.base+digit, utf8.MaxRune+1)
			}
			self.digits += 1
			return
		}
		self.endNumeric()
		if b == ';' && 0 < self.digits {
			return
		}
		self.push(b)
	case indexReferenceName:
		switch {
		case indexAsciiAlphanumeric(b) && len(self.name) < indexStreamReferenceRunMax:
			self.name = append(self.name, b)
		case indexAsciiAlphanumeric(b):
			// past any name: E3 on its first bytes, and the rest of the run is copied
			self.decideName(false)
			self.out = append(self.out, b)
			self.state = indexReferenceRun
		case b == ';':
			self.name = append(self.name, b)
			self.decideName(true)
		default:
			self.decideName(true)
			self.push(b)
		}
	case indexReferenceRun:
		if indexAsciiAlphanumeric(b) {
			self.out = append(self.out, b)
			return
		}
		self.state = indexReferenceText
		self.push(b)
	}
}

// A numeric reference ends: with a digit, its code point; with none, the '&' and what followed it are text.
func (self *indexStreamReferences) endNumeric() {
	self.state = indexReferenceText
	if 0 < self.digits {
		self.out = utf8.AppendRune(self.out, indexNumericReference(self.value))
		return
	}
	self.out = append(self.out, '&', '#')
	if self.x != 0 {
		self.out = append(self.out, self.x)
	}
}

// E2 to E4 on the name held: the whole of it, its ';' included where it has one, one of the 2,231; else the longest
// of its prefixes of 6 down to 2 bytes, short of the whole, one of the 106 without ';', and the rest of it text; else
// the '&' and the name as text. complete says the run ended, so the name is whole; a run past 31 bytes matches no name
// whole, and its E3 reads only its first bytes.
func (self *indexStreamReferences) decideName(complete bool) {
	self.state = indexReferenceText
	name := self.name
	if complete {
		if codePoints, ok := indexReference(name); ok {
			self.out = indexAppendReference(self.out, codePoints)
			return
		}
	}
	longest := min(indexStreamReferencePrefixMax, len(name)-1)
	if !complete {
		longest = indexStreamReferencePrefixMax
	}
	for prefixByteCount := longest; 2 <= prefixByteCount; prefixByteCount -= 1 {
		if codePoints, ok := indexReference(name[:prefixByteCount]); ok {
			self.out = indexAppendReference(self.out, codePoints)
			self.out = append(self.out, name[prefixByteCount:]...)
			return
		}
	}
	self.out = append(self.out, '&')
	self.out = append(self.out, name...)
}

// The text's end: what is held decides as the end of the text leaves it.
func (self *indexStreamReferences) finish() {
	self.out = self.out[:0]
	switch self.state {
	case indexReferenceAmpersand:
		self.out = append(self.out, '&')
	case indexReferenceNumeric:
		self.endNumeric()
	case indexReferenceName:
		self.decideName(true)
	}
	self.state = indexReferenceText
	self.next.write(self.out)
	self.next.finish()
}
