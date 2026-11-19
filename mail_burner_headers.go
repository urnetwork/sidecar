//go:build !ios_extension

// BURNER's header rules (§15.10's step 3, §14.4's step 3, §15.9's replies; R-MAIL-6, D-MAIL-7, I-8; MAIL-M9-03): what a
// burner's reply or forward looks like once it leaves the device, so it reveals no device, client or timezone.
//
//	received  every Received field removed, and none added
//	date      Date rewritten to UTC at minute precision: the message's own instant where it parses, else the send's
//	client    User-Agent, X-Mailer and every client X-* field stripped; the forward's own X-UR-Forwarded is added after
//	          these rules by its writer (mail_forward.go), so a client's X-UR-Forwarded never survives
//	ids       the Message-ID regenerated under <blabel>.<net>.<root>, the send's MailOutboxMessageId; every MIME
//	          boundary regenerated, in the header that declares it and on each delimiter line, nested parts included,
//	          so a client's boundary, which often names it or its clock, is gone
//	kept      every other field byte for byte, folding included, and every body byte but the delimiter lines
//
// A message past HeaderMaxByteCount's header, PartMaxDepth's nesting or PartMaxCount's parts is refused, never sent
// with a rule half applied. Pure and on every leg but the extension's, so the vectors run everywhere
// (testdata/mail/burner_headers.yml). Nothing here logs a field or a byte of a message (I-13).

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"mime"
	"net/mail"
	"strings"
	"time"
)

// The rules met a message they cannot apply whole: no header end, a header or a nesting past its bound, a boundary
// with no closing delimiter. Nothing was sent.
var ErrMailBurnerHeaders = errors.New("mail burner headers: a message the rules cannot apply to")

// The Date layout of a rewritten field: RFC 5322's, at UTC, its seconds 00.
const mailBurnerDateLayout = "Mon, 02 Jan 2006 15:04:00 +0000"

// What the rules are held to. Every value must be positive.
type MailBurnerHeadersSettings struct {
	// The most bytes of one entity's header: 256 KiB, as ingest's walk reads (MailParseSettings).
	HeaderMaxByteCount int
	// The deepest nesting of multiparts whose boundaries are regenerated: 16, deeper than any client writes.
	PartMaxDepth int
	// The most parts over the whole message: 512.
	PartMaxCount int
}

// The one default.
func DefaultMailBurnerHeadersSettings() *MailBurnerHeadersSettings {
	return &MailBurnerHeadersSettings{
		HeaderMaxByteCount: 256 * 1024,
		PartMaxDepth:       16,
		PartMaxCount:       512,
	}
}

// What one application of the rules names.
type MailBurnerHeadersArgs struct {
	// The new Message-ID's addr-spec, without brackets: MailOutboxMessageId under <blabel>.<net>.<root>.
	MessageId string
	// The send's time, the Date of a message whose own does not parse.
	Now time.Time
	// The nth boundary the rules draw, from 0: nil draws each at random. The vectors fix it.
	Boundary func(index int) string
}

// The rules. See the file header.
type MailBurnerHeaders struct {
	settings *MailBurnerHeadersSettings
}

// The rules on settings, nil taking the defaults.
func NewMailBurnerHeaders(settings *MailBurnerHeadersSettings) *MailBurnerHeaders {
	if settings == nil {
		settings = DefaultMailBurnerHeadersSettings()
	}
	return &MailBurnerHeaders{settings: settings}
}

// The rules a client applies to its burners' replies.
func (self *MailClient) burnerHeaders() *MailBurnerHeaders {
	return NewMailBurnerHeaders(nil)
}

// One header field as written: its name and its whole text, folding and line end included.
type mailBurnerField struct {
	name string
	raw  []byte
}

// An entity's header taken apart at its end: its fields, the line end it uses, and its body.
func mailBurnerSplit(entity []byte, maxByteCount int) ([]*mailBurnerField, []byte, []byte, error) {
	// the line end the entity's first line uses, CRLF as RFC 5322 has it or a client's bare LF
	lineEnd := []byte("\r\n")
	if first := bytes.IndexByte(entity, '\n'); 0 <= first && (first == 0 || entity[first-1] != '\r') {
		lineEnd = []byte("\n")
	}
	if bytes.HasPrefix(entity, lineEnd) {
		// an entity with an empty header
		return []*mailBurnerField{}, lineEnd, entity[len(lineEnd):], nil
	}
	headerEnd := bytes.Index(entity, append(bytes.Clone(lineEnd), lineEnd...))
	if headerEnd < 0 {
		return nil, nil, nil, fmt.Errorf("%w: no header end", ErrMailBurnerHeaders)
	}
	if maxByteCount < headerEnd {
		return nil, nil, nil, fmt.Errorf("%w: a header past its bound", ErrMailBurnerHeaders)
	}
	header := entity[:headerEnd+len(lineEnd)]
	body := entity[headerEnd+2*len(lineEnd):]
	fields := []*mailBurnerField{}
	for 0 < len(header) {
		line := header
		if index := bytes.Index(header, lineEnd); 0 <= index {
			line = header[:index+len(lineEnd)]
		}
		header = header[len(line):]
		if 0 < len(fields) && (line[0] == ' ' || line[0] == '\t') {
			fields[len(fields)-1].raw = append(fields[len(fields)-1].raw, line...)
			continue
		}
		name, _, found := bytes.Cut(line, []byte(":"))
		if !found {
			return nil, nil, nil, fmt.Errorf("%w: a header line with no name", ErrMailBurnerHeaders)
		}
		fields = append(fields, &mailBurnerField{name: strings.ToLower(strings.TrimSpace(string(name))), raw: bytes.Clone(line)})
	}
	return fields, lineEnd, body, nil
}

// A field's value, unfolded and trimmed.
func (self *mailBurnerField) value() string {
	_, value, _ := bytes.Cut(self.raw, []byte(":"))
	unfolded := strings.NewReplacer("\r\n", "", "\n", "").Replace(string(value))
	return strings.TrimSpace(unfolded)
}

// Whether the rules strip a field of this name (the file header's received and client rows).
func mailBurnerStripped(name string) bool {
	return name == "received" || name == "user-agent" || name == "x-mailer" || strings.HasPrefix(name, "x-")
}

// The state of one application: the boundaries drawn so far and the parts met.
type mailBurnerApply struct {
	settings  *MailBurnerHeadersSettings
	args      *MailBurnerHeadersArgs
	drawn     int
	partCount int
}

// The next boundary.
func (self *mailBurnerApply) boundary() string {
	index := self.drawn
	self.drawn += 1
	if self.args.Boundary != nil {
		return self.args.Boundary(index)
	}
	random := NewEvsRandomToken()
	return "b" + mailBinaryName(random[:])
}

// Applies the rules to message (see the file header), answering the message as it is to leave.
func (self *MailBurnerHeaders) Apply(message []byte, args *MailBurnerHeadersArgs) ([]byte, error) {
	if args == nil || args.MessageId == "" || strings.ContainsAny(args.MessageId, "<>\r\n \t") {
		return nil, fmt.Errorf("%w: no message id", ErrMailBurnerHeaders)
	}
	apply := &mailBurnerApply{settings: self.settings, args: args}
	fields, lineEnd, body, err := mailBurnerSplit(message, self.settings.HeaderMaxByteCount)
	if err != nil {
		return nil, err
	}
	// the header's lines in order, the Content-Type's slot filled once its body is done
	lines := [][]byte{}
	contentTypeSlot := -1
	sawDate, sawMessageId := false, false
	var contentType *mailBurnerField
	for _, field := range fields {
		switch {
		case mailBurnerStripped(field.name):
			continue
		case field.name == "date":
			if sawDate {
				continue
			}
			sawDate = true
			lines = append(lines, append([]byte("Date: "+mailBurnerDate(field.value(), args.Now)), lineEnd...))
		case field.name == "message-id":
			if sawMessageId {
				continue
			}
			sawMessageId = true
			lines = append(lines, append([]byte("Message-ID: <"+args.MessageId+">"), lineEnd...))
		case field.name == "content-type" && contentType == nil:
			contentType = field
			contentTypeSlot = len(lines)
			lines = append(lines, nil)
		default:
			lines = append(lines, field.raw)
		}
	}
	if !sawDate {
		lines = append(lines, append([]byte("Date: "+mailBurnerDate("", args.Now)), lineEnd...))
	}
	if !sawMessageId {
		lines = append(lines, append([]byte("Message-ID: <"+args.MessageId+">"), lineEnd...))
	}
	contentTypeLine, newBody, err := apply.entity(contentType, lineEnd, body, 0)
	if err != nil {
		return nil, err
	}
	if 0 <= contentTypeSlot {
		lines[contentTypeSlot] = contentTypeLine
	}
	result := bytes.Join(lines, nil)
	result = append(result, lineEnd...)
	return append(result, newBody...), nil
}

// The Date the rules write: value's instant at UTC, at minute precision, or now's where value does not parse.
func mailBurnerDate(value string, now time.Time) string {
	moment := now
	if value != "" {
		if parsed, err := mail.ParseDate(value); err == nil {
			moment = parsed
		}
	}
	return moment.UTC().Truncate(time.Minute).Format(mailBurnerDateLayout)
}

// An entity's Content-Type field and body with its boundaries regenerated: a multipart's boundary drawn anew, each
// delimiter line rewritten and each part done the same, depth deep. A field that is no multipart is kept as written.
func (self *mailBurnerApply) entity(contentType *mailBurnerField, lineEnd []byte, body []byte, depth int) ([]byte, []byte, error) {
	if contentType == nil {
		return nil, body, nil
	}
	mediaType, params, err := mime.ParseMediaType(contentType.value())
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") || params["boundary"] == "" {
		return contentType.raw, body, nil
	}
	if self.settings.PartMaxDepth <= depth {
		return nil, nil, fmt.Errorf("%w: parts nested past their bound", ErrMailBurnerHeaders)
	}
	oldBoundary := params["boundary"]
	newBoundary := self.boundary()
	params["boundary"] = newBoundary
	formatted := mime.FormatMediaType(mediaType, params)
	if formatted == "" {
		return nil, nil, fmt.Errorf("%w: a content type that does not format", ErrMailBurnerHeaders)
	}
	field := append([]byte("Content-Type: "+formatted), lineEnd...)

	// the body: preamble, then each part between delimiter lines, then the close and the epilogue
	delimiter := []byte("--" + oldBoundary)
	out := &bytes.Buffer{}
	rest := body
	var part []byte
	inPart := false
	closed := false
	flush := func() error {
		if !inPart {
			return nil
		}
		self.partCount += 1
		if self.settings.PartMaxCount < self.partCount {
			return fmt.Errorf("%w: parts past their bound", ErrMailBurnerHeaders)
		}
		done, err := self.part(part, lineEnd, depth)
		if err != nil {
			return err
		}
		out.Write(done)
		return nil
	}
	for 0 < len(rest) && !closed {
		line := rest
		if index := bytes.Index(rest, lineEnd); 0 <= index {
			line = rest[:index+len(lineEnd)]
		}
		rest = rest[len(line):]
		content := bytes.TrimRight(line, "\r\n")
		trimmed := bytes.TrimRight(content, " \t")
		switch {
		case bytes.Equal(trimmed, delimiter):
			if err := flush(); err != nil {
				return nil, nil, err
			}
			out.WriteString("--" + newBoundary)
			out.Write(line[len(content):])
			inPart, part = true, nil
		case bytes.Equal(trimmed, append(bytes.Clone(delimiter), '-', '-')):
			if err := flush(); err != nil {
				return nil, nil, err
			}
			out.WriteString("--" + newBoundary + "--")
			out.Write(line[len(content):])
			inPart, closed = false, true
		case inPart:
			part = append(part, line...)
		default:
			// the preamble, kept
			out.Write(line)
		}
	}
	if !closed {
		return nil, nil, fmt.Errorf("%w: a multipart with no closing delimiter", ErrMailBurnerHeaders)
	}
	// the epilogue, kept
	out.Write(rest)
	return field, out.Bytes(), nil
}

// One part of a multipart, its header kept and its own Content-Type's boundaries regenerated. The line end before the
// next delimiter belongs to the delimiter (RFC 2046 §5.1.1), and stays where it was.
func (self *mailBurnerApply) part(part []byte, lineEnd []byte, depth int) ([]byte, error) {
	fields, partLineEnd, body, err := mailBurnerSplit(part, self.settings.HeaderMaxByteCount)
	if err != nil {
		// a part with no header end is body alone
		return part, nil
	}
	lines := [][]byte{}
	contentTypeSlot := -1
	var contentType *mailBurnerField
	for _, field := range fields {
		if field.name == "content-type" && contentType == nil {
			contentType = field
			contentTypeSlot = len(lines)
			lines = append(lines, nil)
			continue
		}
		lines = append(lines, field.raw)
	}
	contentTypeLine, newBody, err := self.entity(contentType, partLineEnd, body, depth+1)
	if err != nil {
		return nil, err
	}
	if 0 <= contentTypeSlot {
		lines[contentTypeSlot] = contentTypeLine
	}
	result := bytes.Join(lines, nil)
	result = append(result, partLineEnd...)
	return append(result, newBody...), nil
}
