//go:build !sidecar_http && !js

// RFC 6376's header fields, tag-lists, canonicalization and signature hash, written again for ARC (RFC 8617;
// MAIL-M7-09), since mox keeps its own unexported (plan-MAIL-mox-subset#1). ARC imports these from DKIM (RFC 8617
// §5.2), so they follow RFC 6376 §3.2, §3.4 and §3.7 and nothing ARC adds.
//
// A header section is read as mox's dkim reads it, so the two see one message: a line ends at CRLF, a line that
// starts with a space or a tab continues the field before it, and the first empty line ends the section. A line with
// no colon, or a name with a byte outside 0x21 to 0x7e, is kept as a field with no name, which nothing selects. A body
// is canonicalized as it streams, in chunks, holding only a count of the empty lines not yet written, so a body of
// any size costs one buffer. Nothing here logs. Safe for concurrent use.

package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strings"
)

// The chunk a body is read in while it is canonicalized. A format value of this file's, not a tunable: it bounds
// only memory, and any size gives the same hash.
const mailCanonBodyChunkByteCount = 64 * 1024

// One header field as received.
type mailHeaderField struct {
	// Lowercase, any white space before the colon gone; empty for a line that names no field.
	name string
	// The field as received: its name, colon, value, folds and the CRLF that ends it.
	raw []byte
}

// The view's header section, top first. Reads only the header bytes the view keeps, at most its bound.
func mailHeaderFields(view *MailHeaderView) ([]mailHeaderField, error) {
	headerByteCount := view.bodyOffset
	if view.Cut {
		headerByteCount = view.keptByteCount
	}
	header := make([]byte, headerByteCount)
	if _, err := view.ReadAt(header, 0); err != nil && err != io.EOF {
		return nil, err
	}
	fields := []mailHeaderField{}
	for 0 < len(header) {
		lineEnd := bytes.Index(header, []byte("\r\n"))
		line := header
		if 0 <= lineEnd {
			line = header[:lineEnd+2]
		}
		header = header[len(line):]
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
		if (line[0] == ' ' || line[0] == '\t') && 0 < len(fields) {
			fields[len(fields)-1].raw = append(fields[len(fields)-1].raw, line...)
			continue
		}
		fields = append(fields, mailHeaderField{name: mailHeaderFieldName(line), raw: bytes.Clone(line)})
	}
	return fields, nil
}

// The lowercase name a field's first line gives, or empty where it gives none.
func mailHeaderFieldName(line []byte) string {
	name, _, found := bytes.Cut(line, []byte(":"))
	if !found {
		return ""
	}
	name = bytes.TrimRight(name, " \t")
	if len(name) == 0 {
		return ""
	}
	for _, c := range name {
		if c <= ' ' || 0x7f <= c {
			return ""
		}
	}
	return strings.ToLower(string(name))
}

// Whether c is RFC 5234's WSP.
func mailIsWsp(c byte) bool {
	return c == ' ' || c == '\t'
}

// RFC 6376 §3.4.2 for a field given without its final CRLF: the name lowercased, the value unfolded, each run of WSP
// one space, none at either end of the value or around the colon. Without a CRLF of its own.
func mailCanonHeaderRelaxed(field []byte) []byte {
	name, value, _ := bytes.Cut(field, []byte(":"))
	canonical := make([]byte, 0, len(field))
	for _, c := range bytes.TrimRight(name, " \t") {
		// ASCII only, so a byte past it stays as received
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		canonical = append(canonical, c)
	}
	canonical = append(canonical, ':')
	unfolded := bytes.ReplaceAll(value, []byte("\r\n"), nil)
	space := false
	wrote := false
	for _, c := range unfolded {
		if mailIsWsp(c) {
			space = true
			continue
		}
		if space && wrote {
			canonical = append(canonical, ' ')
		}
		space = false
		wrote = true
		canonical = append(canonical, c)
	}
	return canonical
}

// A field as a signature over it hashes it under c='s header half, with its CRLF: relaxed, or simple, which is the
// field as received.
func mailCanonHeader(field mailHeaderField, relaxed bool) []byte {
	if !relaxed {
		return field.raw
	}
	return append(mailCanonHeaderRelaxed(bytes.TrimSuffix(field.raw, []byte("\r\n"))), '\r', '\n')
}

// The fields h= names, each name taking that field's last instance not yet taken, from the bottom of the header up
// (RFC 6376 §5.4.2); a name with no instance left takes nothing, as if it named an empty field.
func mailSelectHeaderFields(fields []mailHeaderField, names []string) []mailHeaderField {
	taken := make([]bool, len(fields))
	selected := []mailHeaderField{}
	for _, name := range names {
		name = strings.ToLower(name)
		for index := len(fields) - 1; 0 <= index; index -= 1 {
			if !taken[index] && fields[index].name == name {
				taken[index] = true
				selected = append(selected, fields[index])
				break
			}
		}
	}
	return selected
}

// The signature's own field as it covers it (RFC 6376 §3.7): its b= tag's value gone, with all the white space and
// folds around that value, and no final CRLF. false where the field has no b= tag.
func mailFieldWithoutSignature(raw []byte) ([]byte, bool) {
	field := bytes.TrimSuffix(raw, []byte("\r\n"))
	colon := bytes.IndexByte(field, ':')
	if colon < 0 {
		return nil, false
	}
	// each tag-spec runs from just past a ; or the colon to the next ; or the field's end, and ; occurs in no value
	start := colon + 1
	for start <= len(field) {
		end := start + bytes.IndexByte(field[start:], ';')
		if end < start {
			end = len(field)
		}
		spec := field[start:end]
		if equals := bytes.IndexByte(spec, '='); 0 <= equals && string(bytes.Trim(spec[:equals], " \t\r\n")) == "b" {
			stripped := make([]byte, 0, len(field))
			stripped = append(stripped, field[:start+equals+1]...)
			return append(stripped, field[end:]...), true
		}
		start = end + 1
	}
	return nil, false
}

// A tag-list's tags (RFC 6376 §3.2), from a field's value as received, folds and final CRLF included: each name to
// its value, white space trimmed from its ends. false where the list breaks the grammar or repeats a tag, which makes
// the whole list invalid.
func mailParseTagList(value []byte) (map[string]string, bool) {
	unfolded := bytes.ReplaceAll(bytes.TrimSuffix(value, []byte("\r\n")), []byte("\r\n"), nil)
	tags := map[string]string{}
	specs := bytes.Split(unfolded, []byte(";"))
	for index, spec := range specs {
		spec = bytes.Trim(spec, " \t")
		if len(spec) == 0 {
			// only a ; that ends the list may be followed by nothing
			if index == len(specs)-1 && 0 < index {
				continue
			}
			return nil, false
		}
		name, tagValue, found := bytes.Cut(spec, []byte("="))
		if !found {
			return nil, false
		}
		name = bytes.TrimRight(name, " \t")
		tagValue = bytes.TrimLeft(tagValue, " \t")
		if !mailValidTagName(name) || !mailValidTagValue(tagValue) {
			return nil, false
		}
		if _, ok := tags[string(name)]; ok {
			return nil, false
		}
		tags[string(name)] = string(tagValue)
	}
	return tags, true
}

// RFC 6376's tag-name: ALPHA *(ALPHA / DIGIT / "_").
func mailValidTagName(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	for index, c := range name {
		alpha := ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
		if !alpha && (index == 0 || !(('0' <= c && c <= '9') || c == '_')) {
			return false
		}
	}
	return true
}

// RFC 6376's tag-value, its ends already trimmed: VALCHARs, 0x21 to 0x7e but ;, with WSP between them.
func mailValidTagValue(value []byte) bool {
	for _, c := range value {
		if !mailIsWsp(c) && (c < 0x21 || 0x7e < c || c == ';') {
			return false
		}
	}
	return true
}

// A base64 tag value, white space inside it dropped (RFC 6376 §3.5); false where it is not base64.
func mailTagBase64(value string) ([]byte, bool) {
	compact := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, value)
	decoded, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return nil, false
	}
	return decoded, true
}

// Canonicalizes a body as it streams, writing the result to digest through out: RFC 6376 §3.4.4's relaxed form, or
// §3.4.3's simple one.
type mailBodyCanonicalizer struct {
	out     *bufio.Writer
	relaxed bool
	// Empty lines read and not yet written, written only once a line with content follows.
	pendingEmptyLines int
	// A CR waiting to learn whether an LF follows.
	pendingCr bool
	// The current line has content written: for simple, any byte; for relaxed, a byte that is not WSP.
	lineHasContent bool
	// relaxed: WSP read since the line's last content, written as one space only if content follows.
	pendingSpace bool
	// Any content written at all, which simple's empty body needs.
	wroteAny bool
}

// One content byte of the current line.
func (self *mailBodyCanonicalizer) content(c byte) {
	if !self.lineHasContent {
		for range self.pendingEmptyLines {
			self.out.WriteString("\r\n")
		}
		self.pendingEmptyLines = 0
		self.lineHasContent = true
	}
	if self.pendingSpace {
		self.out.WriteByte(' ')
		self.pendingSpace = false
	}
	self.out.WriteByte(c)
	self.wroteAny = true
}

// A CRLF that ends the current line.
func (self *mailBodyCanonicalizer) endLine() {
	if self.lineHasContent {
		self.out.WriteString("\r\n")
	} else {
		self.pendingEmptyLines += 1
	}
	self.lineHasContent = false
	self.pendingSpace = false
}

// Takes one chunk of the body.
func (self *mailBodyCanonicalizer) write(chunk []byte) {
	for _, c := range chunk {
		if self.pendingCr {
			self.pendingCr = false
			if c == '\n' {
				self.endLine()
				continue
			}
			// a bare CR is content, never a line end
			self.content('\r')
		}
		switch {
		case c == '\r':
			self.pendingCr = true
		case self.relaxed && mailIsWsp(c):
			self.pendingSpace = true
		default:
			self.content(c)
		}
	}
}

// Ends the body: a last line with content gets its CRLF, empty lines at the end go, and simple's empty body is one
// CRLF.
func (self *mailBodyCanonicalizer) close() error {
	if self.pendingCr {
		self.pendingCr = false
		self.content('\r')
	}
	if self.lineHasContent {
		self.out.WriteString("\r\n")
	}
	if !self.relaxed && !self.wroteAny {
		self.out.WriteString("\r\n")
	}
	return self.out.Flush()
}

// The SHA-256 of body's canonical form, relaxed or simple, read in chunks, stopping with ctx's error when ctx ends.
func mailCanonBodyHash(ctx context.Context, body io.Reader, relaxed bool) ([]byte, error) {
	digest := sha256.New()
	canonicalizer := &mailBodyCanonicalizer{out: bufio.NewWriterSize(digest, mailCanonBodyChunkByteCount), relaxed: relaxed}
	buffer := make([]byte, mailCanonBodyChunkByteCount)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		count, err := body.Read(buffer)
		canonicalizer.write(buffer[:count])
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if err := canonicalizer.close(); err != nil {
		return nil, err
	}
	return digest.Sum(nil), nil
}

// Whether signature holds over data's SHA-256 under publicKey: PKCS #1 v1.5 for rsa-sha256, Ed25519 over the hash
// for ed25519-sha256 (RFC 8463 §3).
func mailVerifySignatureData(publicKey crypto.PublicKey, data []byte, signature []byte) bool {
	digest := sha256.Sum256(data)
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize && ed25519.Verify(key, digest[:], signature)
	}
	return false
}
