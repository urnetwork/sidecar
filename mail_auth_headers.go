//go:build !sidecar_http

// §15.5's headers row (D-MAIL-14, FS-121; MAIL-M7-08): what the checks read of a message. mox's dkim.Verify parses the
// whole header section before anything else, so a sender could make it read megabytes of fields; it is only ever
// handed a MailHeaderView, which presents the header section's first 256 KiB, cut at the end of the last whole field
// within it, then the empty line, then the body as received. DKIM-Signature fields past the cut, or past the 64th,
// are only counted, and a signature that fails under a cut view is incomplete, not fail (plan-MAIL-small-readings#12).
//
// The view is read once from the start to find the header section's end, counting DKIM-Signature fields and taking
// the first From field's value, holding one buffer at a time; the message itself stays where the caller keeps it, the
// receiver's sealed spool. A field starts at a line that does not begin with a space or a tab; the header section
// ends at the first empty line, CRLF or a bare LF. Safe for concurrent reads once made.

package sidecar

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
)

// The most of the first From field's value kept, an address and a display name's worth: the rest names no domain
// DMARC reads. A format value.
const mailHeaderFromMaxByteCount = 4 * 1024

// The scan's buffer, which a line longer than it passes through in pieces.
const mailHeaderScanBufferByteCount = 64 * 1024

// The empty line a cut view puts after its last whole field.
var mailHeaderEmptyLine = []byte("\r\n")

// A message as the checks read it. See the file header.
type MailHeaderView struct {
	message io.ReaderAt
	// The header bytes kept: whole fields, ending within the bound.
	keptByteCount int64
	// Where the body starts in the message, past the empty line, or its end where it has none.
	bodyOffset int64
	size       int64
	// The header section passed the bound, so fields after the kept bytes are out of the view, which then puts an
	// empty line after them.
	Cut bool
	// DKIM-Signature fields in the whole header section, and those inside the view.
	DkimFieldCount     int
	DkimViewFieldCount int
	// The first From field's value, unfolded, at most 4 KiB, or empty where there is none.
	From string
}

// The view of the size bytes of message, its header section held to headerMaxByteCount. The only error is message's
// own.
func NewMailHeaderView(message io.ReaderAt, size int64, headerMaxByteCount int) (*MailHeaderView, error) {
	view := &MailHeaderView{message: message, size: size, bodyOffset: size}
	reader := bufio.NewReaderSize(io.NewSectionReader(message, 0, size), mailHeaderScanBufferByteCount)
	bound := int64(max(0, headerMaxByteCount))
	offset := int64(0)
	// the field being read: where it started, and whether it is a DKIM-Signature or the first From
	fieldStart := int64(-1)
	fieldDkim := false
	fromOpen := false
	fromTaken := false
	var from strings.Builder
	// the end of the last whole field within the bound
	kept := int64(0)
	endField := func(end int64) {
		if fieldStart < 0 {
			return
		}
		if end <= bound {
			kept = end
			if fieldDkim {
				view.DkimViewFieldCount += 1
			}
		}
		if fromOpen {
			fromOpen, fromTaken = false, true
		}
	}
	lineStart := true
	for {
		line, err := reader.ReadSlice('\n')
		if len(line) != 0 {
			// what a From field gives its value: the whole line, or past its name on the field's first
			captured := line
			if lineStart {
				isEmpty := bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n"))
				switch {
				case isEmpty:
					endField(offset)
					view.bodyOffset = offset + int64(len(line))
					view.Cut = bound < view.bodyOffset
					view.keptByteCount = kept
					if !view.Cut {
						view.keptByteCount = view.bodyOffset
					}
					view.From = mailHeaderUnfold(from.String())
					return view, nil
				case line[0] == ' ' || line[0] == '\t':
					// a continuation of the field being read
				default:
					endField(offset)
					fieldStart = offset
					name, _, _ := bytes.Cut(line, []byte(":"))
					name = bytes.TrimRight(name, " \t")
					fieldDkim = strings.EqualFold(string(name), "dkim-signature")
					if fieldDkim {
						view.DkimFieldCount += 1
					}
					if !fromTaken && strings.EqualFold(string(name), "from") {
						fromOpen = true
						if _, value, found := bytes.Cut(line, []byte(":")); found {
							captured = value
						}
					}
				}
			}
			if fromOpen && from.Len() < mailHeaderFromMaxByteCount {
				from.Write(captured[:min(len(captured), mailHeaderFromMaxByteCount-from.Len())])
			}
			offset += int64(len(line))
			lineStart = line[len(line)-1] == '\n'
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	// a header section with no empty line runs to the end, and the message has no body
	endField(offset)
	view.Cut = bound < offset
	view.keptByteCount = kept
	if !view.Cut {
		view.keptByteCount = offset
	}
	view.From = mailHeaderUnfold(from.String())
	return view, nil
}

// A field value with its folds and its ends' white space gone.
func mailHeaderUnfold(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "")
	value = strings.ReplaceAll(value, "\n", "")
	return strings.TrimSpace(value)
}

// The view's length: its kept header, the empty line a cut adds, and the body.
func (self *MailHeaderView) Size() int64 {
	if !self.Cut {
		return self.size
	}
	return self.keptByteCount + int64(len(mailHeaderEmptyLine)) + (self.size - self.bodyOffset)
}

// Reads the view at offset, as io.ReaderAt does.
func (self *MailHeaderView) ReadAt(data []byte, offset int64) (int, error) {
	if !self.Cut {
		return self.message.ReadAt(data, offset)
	}
	if offset < 0 {
		return 0, errors.New("mail header view: a negative offset")
	}
	count := 0
	for count < len(data) {
		position := offset + int64(count)
		var read int
		var err error
		switch {
		case position < self.keptByteCount:
			read, err = self.message.ReadAt(data[count:count+int(min(int64(len(data)-count), self.keptByteCount-position))], position)
		case position < self.keptByteCount+int64(len(mailHeaderEmptyLine)):
			read = copy(data[count:], mailHeaderEmptyLine[position-self.keptByteCount:])
		case position < self.Size():
			bodyPosition := self.bodyOffset + position - self.keptByteCount - int64(len(mailHeaderEmptyLine))
			read, err = self.message.ReadAt(data[count:count+int(min(int64(len(data)-count), self.size-bodyPosition))], bodyPosition)
		default:
			return count, io.EOF
		}
		count += read
		if err != nil && err != io.EOF {
			return count, err
		}
		if read == 0 {
			return count, io.EOF
		}
	}
	return count, nil
}
