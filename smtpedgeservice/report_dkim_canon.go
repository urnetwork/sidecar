// RFC 6376's canonicalizations (§3.4) and tag lists (§3.2), shared by both of report_dkim.go's checks.
// The body canonicalizers stream, so the intake feeds a report's raw bytes through them in the same
// single pass as the seal, and never holds a canonical copy.

package smtpedgeservice

import (
	"bytes"
	"hash"
	"strings"
)

// The bytes a body canonicalizer buffers before writing to its hash.
const smtpDkimCanonBufferByteCount = 4 * 1024

// An RFC 6376 tag list as name to value, values trimmed of surrounding whitespace and folding. Not ok
// when a spec has no "=", a name is empty, or a name repeats, which §3.2 makes the whole list invalid.
func smtpDkimTagList(value string) (map[string]string, bool) {
	tags := map[string]string{}
	for _, spec := range strings.Split(value, ";") {
		if strings.TrimSpace(smtpStripFws(spec)) == "" {
			continue
		}
		name, tagValue, ok := strings.Cut(spec, "=")
		if !ok {
			return nil, false
		}
		name = smtpStripFws(name)
		if name == "" {
			return nil, false
		}
		if _, repeated := tags[name]; repeated {
			return nil, false
		}
		tags[name] = strings.Trim(tagValue, " \t\r\n")
	}
	return tags, true
}

// value with every space, tab, CR and LF removed: how a tag's name, or a base64 value, is read.
func smtpStripFws(value string) string {
	if strings.IndexAny(value, " \t\r\n") < 0 {
		return value
	}
	var builder strings.Builder
	for i := range len(value) {
		switch value[i] {
		case ' ', '\t', '\r', '\n':
		default:
			builder.WriteByte(value[i])
		}
	}
	return builder.String()
}

// Whether c is RFC 5234's WSP.
func smtpWsp(c byte) bool {
	return c == ' ' || c == '\t'
}

// A header field canonicalized, its CRLF included (§3.4.1, §3.4.2).
func smtpDkimCanonHeader(field *smtpHeaderField, relaxed bool) []byte {
	if !relaxed {
		return field.raw
	}
	return smtpDkimRelaxedHeader(field.name, field.value)
}

// §3.4.2: the name lowercased, the value unfolded, each run of WSP one space, no WSP at either end
// of the value or around the colon.
func smtpDkimRelaxedHeader(name string, value []byte) []byte {
	out := make([]byte, 0, len(name)+len(value)+3)
	out = append(out, strings.ToLower(strings.Trim(name, " \t"))...)
	out = append(out, ':')
	space := false
	written := false
	for _, c := range value {
		switch {
		case c == '\r' || c == '\n':
			// unfolding: a fold's CRLF goes, and the WSP after it joins the run
		case smtpWsp(c):
			space = true
		default:
			if space && written {
				out = append(out, ' ')
			}
			space = false
			out = append(out, c)
			written = true
		}
	}
	return append(out, smtpCrlf...)
}

// The DKIM-Signature field as its own signature covers it: the b= tag's value, with the whitespace
// around it, deleted (§3.7), canonicalized, and with no final CRLF.
func smtpDkimCanonSignatureField(field *smtpHeaderField, relaxed bool) []byte {
	raw := field.raw
	if bytes.HasSuffix(raw, smtpCrlf) {
		raw = raw[:len(raw)-2]
	}
	valueStart := len(raw) - len(field.value)
	value := field.value
	stripped := raw
	position := 0
	for position <= len(value) {
		tagEnd := len(value)
		if index := bytes.IndexByte(value[position:], ';'); 0 <= index {
			tagEnd = position + index
		}
		tag := value[position:tagEnd]
		if equals := bytes.IndexByte(tag, '='); 0 <= equals && smtpStripFws(string(tag[:equals])) == "b" {
			stripped = make([]byte, 0, len(raw))
			stripped = append(stripped, raw[:valueStart+position+equals+1]...)
			stripped = append(stripped, raw[valueStart+tagEnd:]...)
			break
		}
		position = tagEnd + 1
	}
	if !relaxed {
		return stripped
	}
	// stripped keeps raw's name and colon, so its value starts where raw's does
	canon := smtpDkimRelaxedHeader(field.name, stripped[valueStart:])
	return canon[:len(canon)-2]
}

// A body canonicalizer streaming into a hash (§3.4.3, §3.4.4). Trailing empty lines are held back
// until something follows them, so they are dropped if nothing does; relaxed also holds back a run of
// WSP until it knows whether the line ends there.
type smtpDkimBodyCanon struct {
	relaxed bool
	out     hash.Hash
	buffer  []byte
	// A CR whose next byte has not yet been seen.
	crPending bool
	// CRLFs held back: empty lines, or the last line's end.
	crlfCount int
	// relaxed: a run of WSP held back.
	spacePending bool
	// Whether any content has been written.
	written bool
}

// A canonicalizer writing into out.
func newSmtpDkimBodyCanon(relaxed bool, out hash.Hash) *smtpDkimBodyCanon {
	return &smtpDkimBodyCanon{relaxed: relaxed, out: out, buffer: make([]byte, 0, smtpDkimCanonBufferByteCount)}
}

// Appends to the buffer, flushing it to the hash when full.
func (self *smtpDkimBodyCanon) emit(data ...byte) {
	self.buffer = append(self.buffer, data...)
	if smtpDkimCanonBufferByteCount <= len(self.buffer) {
		self.out.Write(self.buffer)
		self.buffer = self.buffer[:0]
	}
}

// One content byte, after whatever was held back before it.
func (self *smtpDkimBodyCanon) content(c byte) {
	for ; 0 < self.crlfCount; self.crlfCount -= 1 {
		self.emit('\r', '\n')
	}
	if self.spacePending {
		self.emit(' ')
		self.spacePending = false
	}
	self.emit(c)
	self.written = true
}

// Feeds body bytes.
func (self *smtpDkimBodyCanon) write(data []byte) {
	for _, c := range data {
		if self.crPending {
			self.crPending = false
			if c == '\n' {
				// a line's end: relaxed drops the WSP before it
				self.spacePending = false
				self.crlfCount += 1
				continue
			}
			self.content('\r')
		}
		switch {
		case c == '\r':
			self.crPending = true
		case self.relaxed && smtpWsp(c):
			self.spacePending = true
		default:
			self.content(c)
		}
	}
}

// Ends the body and returns its digest. Simple always ends in one CRLF, which is all an empty body
// is; relaxed ends a non-empty body in one CRLF and leaves an empty one empty (RFC 6376 erratum 1384).
func (self *smtpDkimBodyCanon) finish() []byte {
	if self.crPending {
		self.crPending = false
		self.content('\r')
	}
	// trailing WSP on a last line with no CRLF is a line's end too
	self.spacePending = false
	if !self.relaxed || self.written {
		self.buffer = append(self.buffer, smtpCrlf...)
	}
	self.out.Write(self.buffer)
	self.buffer = nil
	return self.out.Sum(nil)
}
