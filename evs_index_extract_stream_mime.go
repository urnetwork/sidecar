//go:build !ios_extension

// A text part's transfer encoding and charset in one pass (DESIGN-DETAILS 11.2.5's T1 to T3 and C1 to C3, as 11.2.8's
// base64, quoted-printable and charset rows hold them): base64 keeps up to three alphabet bytes, quoted-printable an
// '=' and what may follow it, at most LineWindowByteCount blank bytes and a CR, and the charset stage x/text v0.43.0's
// decoder with its own few bytes. Each gives exactly what evs_index_extract_transfer.go's whole-value function gives
// the same body, whatever pieces the body arrives in. Not safe for concurrent use.

package sidecar

import (
	"golang.org/x/text/transform"
)

// T1: the stage that decodes a body under its Content-Transfer-Encoding, base64 by T2 and quoted-printable by T3,
// before next. Anything else, absent included, gives the body to next as it is.
func indexNewStreamTransfer(encoding string, next indexStreamStage, settings *IndexFormatSettings) indexStreamStage {
	switch indexLower(indexTrim(encoding)) {
	case "base64":
		return &indexStreamBase64{next: next}
	case "quoted-printable":
		return &indexStreamQuotedPrintable{next: next, settings: settings}
	}
	return next
}

// T2 in one pass: white bytes skipped, alphabet bytes taken up to the first byte that is neither, where decoding ends;
// each 4 give 3 bytes, and at the end a last 2 give 1 and a last 3 give 2.
type indexStreamBase64 struct {
	next    indexStreamStage
	values  []byte
	stopped bool
	out     []byte
}

// Decodes text's alphabet bytes until the first that is neither alphabet nor white.
func (self *indexStreamBase64) write(text []byte) {
	if self.stopped {
		return
	}
	self.out = self.out[:0]
	for _, b := range text {
		if indexWhite(b) {
			continue
		}
		value := indexBase64Value(b)
		if value < 0 {
			self.stopped = true
			break
		}
		self.values = append(self.values, byte(value))
		if len(self.values) == 4 {
			self.out = indexBase64AppendValues(self.out, self.values)
			self.values = self.values[:0]
		}
	}
	self.next.write(self.out)
}

// The last group: 2 values give 1 byte, 3 give 2, 1 gives none.
func (self *indexStreamBase64) finish() {
	self.next.write(indexBase64AppendValues(nil, self.values))
	self.values = self.values[:0]
	self.next.finish()
}

// Where quoted-printable stands after an '='.
type indexStreamQuotedState int

const (
	// No '=' held.
	indexQuotedText indexStreamQuotedState = iota
	// An '=' and nothing yet.
	indexQuotedEquals
	// An '=' and one hex digit.
	indexQuotedHex
	// An '=' and a run of blank bytes, held.
	indexQuotedBlanks
	// An '=', a run of blank bytes and a CR.
	indexQuotedCr
)

// T3 in one pass: '=' and two hex digits are that byte; any other '=' is a soft line break when at most
// LineWindowByteCount blank bytes and then LF, CR LF or the end of the body follow it, all of it consumed, and is
// itself otherwise, reading going on from the byte after it. Every other byte is itself.
type indexStreamQuotedPrintable struct {
	next     indexStreamStage
	settings *IndexFormatSettings
	state    indexStreamQuotedState
	// The hex digit after an '=', or the blank bytes after one.
	hex    byte
	blanks []byte
	out    []byte
}

// Decodes text, holding an '=' and what may follow it.
func (self *indexStreamQuotedPrintable) write(text []byte) {
	self.out = self.out[:0]
	for _, b := range text {
		self.push(b)
	}
	self.next.write(self.out)
}

// Takes one byte.
func (self *indexStreamQuotedPrintable) push(b byte) {
	switch self.state {
	case indexQuotedText:
		if b == '=' {
			self.state = indexQuotedEquals
		} else {
			self.out = append(self.out, b)
		}
	case indexQuotedEquals:
		switch {
		case 0 <= indexHexValue(b):
			self.hex, self.state = b, indexQuotedHex
		default:
			self.scan(b)
		}
	case indexQuotedHex:
		if low := indexHexValue(b); 0 <= low {
			self.out = append(self.out, byte(indexHexValue(self.hex)<<4|low))
			self.state = indexQuotedText
			return
		}
		// no escape, and a hex digit is neither blank nor a line end: the '=' is itself
		self.out = append(self.out, '=', self.hex)
		self.state = indexQuotedText
		self.push(b)
	case indexQuotedBlanks:
		self.scan(b)
	case indexQuotedCr:
		if b == '\n' {
			self.blanks = self.blanks[:0]
			self.state = indexQuotedText
			return
		}
		self.literal()
		self.out = append(self.out, '\r')
		self.push(b)
	}
}

// The soft line break's scan after an '=', one byte at a time: blank bytes up to LineWindowByteCount held, then LF
// ends a break, CR may, and anything else, a further blank included, makes the '=' itself.
func (self *indexStreamQuotedPrintable) scan(b byte) {
	switch {
	case indexBlank(b) && len(self.blanks) < self.settings.LineWindowByteCount:
		self.blanks = append(self.blanks, b)
		self.state = indexQuotedBlanks
	case b == '\n':
		self.blanks = self.blanks[:0]
		self.state = indexQuotedText
	case b == '\r':
		self.state = indexQuotedCr
	default:
		self.literal()
		self.push(b)
	}
}

// The '=' was itself: it and the blank bytes held after it are text.
func (self *indexStreamQuotedPrintable) literal() {
	self.out = append(self.out, '=')
	self.out = append(self.out, self.blanks...)
	self.blanks = self.blanks[:0]
	self.state = indexQuotedText
}

// The body's end: an '=' held decides as the end leaves it.
func (self *indexStreamQuotedPrintable) finish() {
	self.out = self.out[:0]
	switch self.state {
	case indexQuotedHex:
		// one byte after the '=': no escape, and a hex digit is no line end
		self.out = append(self.out, '=', self.hex)
	case indexQuotedCr:
		// a CR with no LF after it ends no break
		self.literal()
		self.out = append(self.out, '\r')
	}
	// an '=' with nothing or only blank bytes after it is a break at the end of the body
	self.blanks = self.blanks[:0]
	self.state = indexQuotedText
	self.next.write(self.out)
	self.next.finish()
}

// C2 and C3 as a stage: bytes under a label that names utf-8, replacement or nothing go to next as they are; any other
// label's go through x/text v0.43.0's decoder for its encoding, which answers malformed input with U+FFFD and never
// fails, so its output pieced is its output whole.
func indexNewStreamCharset(label string, next indexStreamStage) indexStreamStage {
	labelled, name, ok := indexCharsetEncoding(label)
	if !ok || name == "utf-8" || name == "replacement" {
		return next
	}
	charset := &indexStreamCharset{next: next}
	charset.writer = transform.NewWriter(&indexStreamStageWriter{stage: next}, labelled.NewDecoder())
	return charset
}

// A charset decoder's stage.
type indexStreamCharset struct {
	next   indexStreamStage
	writer *transform.Writer
	// A decoder that failed, which C3 says none does: what is left goes on as it is.
	failed bool
}

// Decodes text.
func (self *indexStreamCharset) write(text []byte) {
	if self.failed {
		self.next.write(text)
		return
	}
	if _, err := self.writer.Write(text); err != nil {
		self.failed = true
	}
}

// Flushes the decoder at the end of its input.
func (self *indexStreamCharset) finish() {
	if !self.failed {
		self.writer.Close()
	}
	self.next.finish()
}

// A stage as the io.Writer a decoder writes to.
type indexStreamStageWriter struct {
	stage indexStreamStage
}

// Gives text to the stage.
func (self *indexStreamStageWriter) Write(text []byte) (int, error) {
	self.stage.write(text)
	return len(text), nil
}
