// An MX's replies before TLS (RFC 5321 §4.2), read as the edge's own pre-TLS dialog needs them: the
// code and each line's text. Bounded as connect's dialog is, MxReplyMaxByteCount a reply and
// MxReplyLineMaxByteCount a line without its line end, so whatever an MX sends, a parser holds one
// reply's buffer and refuses past it; FuzzSmtpMxReplies holds it to that.
//
// A reply's lines share one code, first digit 2 to 5, each line the code, then '-' for a line that
// follows or ' ' (or nothing) for the last, then text. A line ends in LF, a CR before it dropped; any
// other control octet but a tab refuses the reply. Bytes read past a reply wait in the buffer for the
// next, and buffered says how many, which is how the edge sees an octet an MX sent behind STARTTLS's
// 220 (the CVE-2011-0411 class).
//
// Not safe for concurrent use: one dialog owns each parser.

package smtpedgeservice

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// A reply that breaks RFC 5321 §4.2's form or the bounds.
var errSmtpReplyMalformed = errors.New("smtp reply malformed")

// One reply: its code, and each line's text after the code and its separator.
type smtpReply struct {
	code  int
	lines []string
}

// One dialog's reader of replies, holding at most one reply's buffer.
type smtpReplyParser struct {
	reader   io.Reader
	settings *SmtpEdgeSettings
	// read and not yet taken: buffer[start:end]
	buffer []byte
	start  int
	end    int
}

// A parser over reader, holding at most MxReplyMaxByteCount octets.
func newSmtpReplyParser(reader io.Reader, settings *SmtpEdgeSettings) *smtpReplyParser {
	return &smtpReplyParser{reader: reader, settings: settings, buffer: make([]byte, settings.MxReplyMaxByteCount)}
}

// Octets read past the last reply taken.
func (self *smtpReplyParser) buffered() int {
	return self.end - self.start
}

// Reads at least one more octet into the buffer, moving what waits to its front first.
func (self *smtpReplyParser) fill() error {
	if self.end == len(self.buffer) {
		if self.start == 0 {
			return fmt.Errorf("%w: a reply past %d octets", errSmtpReplyMalformed, len(self.buffer))
		}
		copy(self.buffer, self.buffer[self.start:self.end])
		self.end -= self.start
		self.start = 0
	}
	for {
		n, err := self.reader.Read(self.buffer[self.end:])
		self.end += n
		if 0 < n {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// The next whole reply. io.EOF when the stream ends before one starts, io.ErrUnexpectedEOF inside one.
func (self *smtpReplyParser) next() (*smtpReply, error) {
	reply := &smtpReply{}
	// octets of this reply taken so far, which the reply bound counts
	taken := 0
	for {
		lineEnd := bytes.IndexByte(self.buffer[self.start:self.end], '\n')
		if lineEnd < 0 {
			if self.settings.MxReplyLineMaxByteCount+1 < self.end-self.start {
				return nil, fmt.Errorf("%w: a line past %d octets", errSmtpReplyMalformed, self.settings.MxReplyLineMaxByteCount)
			}
			if self.settings.MxReplyMaxByteCount <= taken+self.end-self.start {
				return nil, fmt.Errorf("%w: a reply past %d octets", errSmtpReplyMalformed, self.settings.MxReplyMaxByteCount)
			}
			if err := self.fill(); err != nil {
				if errors.Is(err, io.EOF) {
					if taken == 0 && self.end == self.start {
						return nil, io.EOF
					}
					return nil, io.ErrUnexpectedEOF
				}
				return nil, err
			}
			continue
		}
		line := self.buffer[self.start : self.start+lineEnd]
		taken += lineEnd + 1
		self.start += lineEnd + 1
		line = bytes.TrimSuffix(line, []byte("\r"))
		if self.settings.MxReplyLineMaxByteCount < len(line) {
			return nil, fmt.Errorf("%w: a line past %d octets", errSmtpReplyMalformed, self.settings.MxReplyLineMaxByteCount)
		}
		if self.settings.MxReplyMaxByteCount < taken {
			return nil, fmt.Errorf("%w: a reply past %d octets", errSmtpReplyMalformed, self.settings.MxReplyMaxByteCount)
		}
		code, last, text, ok := parseSmtpReplyLine(line)
		if !ok {
			return nil, fmt.Errorf("%w: a line not of RFC 5321's form", errSmtpReplyMalformed)
		}
		if len(reply.lines) != 0 && code != reply.code {
			return nil, fmt.Errorf("%w: a reply whose lines change code", errSmtpReplyMalformed)
		}
		reply.code = code
		reply.lines = append(reply.lines, text)
		if last {
			return reply, nil
		}
	}
}

// One line without its line end: its code, whether it is the reply's last, and its text.
func parseSmtpReplyLine(line []byte) (code int, last bool, text string, ok bool) {
	if len(line) < 3 {
		return 0, false, "", false
	}
	if line[0] < '2' || '5' < line[0] || line[1] < '0' || '5' < line[1] || line[2] < '0' || '9' < line[2] {
		return 0, false, "", false
	}
	code = int(line[0]-'0')*100 + int(line[1]-'0')*10 + int(line[2]-'0')
	last = true
	if 3 < len(line) {
		switch line[3] {
		case '-':
			last = false
		case ' ':
		default:
			return 0, false, "", false
		}
		text = string(line[4:])
	}
	for i := range len(text) {
		if c := text[i]; (c < ' ' && c != '\t') || c == 0x7f {
			return 0, false, "", false
		}
	}
	return code, last, text, true
}
