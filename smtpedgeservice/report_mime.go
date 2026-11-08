// The bounded MIME walk every report goes through (§14.8, D-SMTP-12). It finds part boundaries and
// reads each part's own few header fields, and decodes nothing: a part's body stays a slice of the raw
// report, and only the parser that needs a part decodes it, as far as it needs. message/rfc822 parts
// are leaves, so the walk never enters an enclosed message, whose body and attachments are never
// decoded (owner decision 78).
//
// Bounds: a header block's bytes (ReportHeaderByteCount), multipart depth (ReportMimeDepth) and leaf
// count (ReportMimePartCount). Past one, the report is refused, never read further. Every search is a
// linear scan of the raw bytes, so a walk costs at most depth times the report's length, and it
// allocates per part, not per byte.

package smtpedgeservice

import (
	"bytes"
	"errors"
	"fmt"
	"mime"
	"strings"
)

const (
	// RFC 2046 §5.1.1's longest boundary.
	smtpMimeBoundaryMaxByteCount = 70
)

var (
	smtpCrlf     = []byte("\r\n")
	smtpCrlfCrlf = []byte("\r\n\r\n")
)

// A report that cannot be read within the bounds, or is not shaped as the parser needs: it is dropped
// and never stored. No error carries the report's text.
var ErrSmtpReportRefused = errors.New("smtp report refused")

// One leaf part, its body borrowed from the raw report and never decoded here.
type SmtpReportPart struct {
	// type/subtype, lowercased.
	MediaType string
	// Content-Disposition's filename, else Content-Type's name, as written: read only to recognize an
	// aggregate's attachment by its extension.
	FileName string
	// Content-Transfer-Encoding, lowercased. Empty means 7bit.
	TransferEncoding string
	// A slice of the raw report.
	Body []byte
}

// What the walk found: the report's own header block and its leaves, in order.
type SmtpReportParts struct {
	// Through its blank line, a slice of the raw report.
	HeaderBlock []byte
	// A report that is not multipart is one leaf, its own body.
	Parts []*SmtpReportPart
}

// One header field as written.
type smtpHeaderField struct {
	// As written, without the colon.
	name string
	// The whole field, folding and its final CRLF included, a slice of the block.
	raw []byte
	// Everything after the colon, folding included, without the final CRLF.
	value []byte
}

// value with every CRLF that precedes a space or tab removed (RFC 5322 §2.2.3).
func smtpUnfold(value []byte) string {
	if !bytes.Contains(value, smtpCrlf) {
		return string(value)
	}
	return string(bytes.ReplaceAll(value, smtpCrlf, nil))
}

// Splits data into its header block, through the CRLF CRLF that ends it, and the body after. A block
// longer than maxByteCount, or one never ended, is not found.
func smtpSplitHeaderBlock(data []byte, maxByteCount int) (block []byte, body []byte, ok bool) {
	if bytes.HasPrefix(data, smtpCrlf) {
		return data[:2], data[2:], true
	}
	window := data
	if maxByteCount < len(window) {
		window = window[:maxByteCount]
	}
	end := bytes.Index(window, smtpCrlfCrlf)
	if end < 0 {
		return nil, nil, false
	}
	return data[:end+4], data[end+4:], true
}

// The fields of a header block, in order. strict refuses a line that is neither a field nor its
// continuation; otherwise such a line is skipped, since a report's malformed line carries nothing this
// parser reads. The fields end at the block's blank line, or at its end.
func smtpHeaderFields(block []byte, strict bool) ([]*smtpHeaderField, error) {
	fields := []*smtpHeaderField{}
	var current *smtpHeaderField
	currentStart := 0
	currentValueStart := 0
	// ends the current field just before end, which follows its final CRLF or is the block's end
	finish := func(end int) {
		if current == nil {
			return
		}
		current.raw = block[currentStart:end]
		valueEnd := end
		if bytes.HasSuffix(current.raw, smtpCrlf) {
			valueEnd -= 2
		}
		current.value = block[currentValueStart:valueEnd]
		fields = append(fields, current)
		current = nil
	}
	position := 0
	for position < len(block) {
		lineEnd := len(block)
		next := len(block)
		if index := bytes.Index(block[position:], smtpCrlf); 0 <= index {
			lineEnd = position + index
			next = lineEnd + 2
		}
		line := block[position:lineEnd]
		switch {
		case len(line) == 0:
			finish(position)
			return fields, nil
		case line[0] == ' ' || line[0] == '\t':
			if current == nil && strict {
				return nil, fmt.Errorf("%w: a continuation with no field", ErrSmtpReportRefused)
			}
		default:
			finish(position)
			colon := bytes.IndexByte(line, ':')
			if colon <= 0 {
				if strict {
					return nil, fmt.Errorf("%w: a line that is not a field", ErrSmtpReportRefused)
				}
				break
			}
			current = &smtpHeaderField{name: string(bytes.TrimRight(line[:colon], " \t"))}
			currentStart = position
			currentValueStart = position + colon + 1
		}
		position = next
	}
	finish(len(block))
	return fields, nil
}

// The first field named name, compared without case, unfolded, or empty.
func smtpHeaderValue(fields []*smtpHeaderField, name string) string {
	for _, field := range fields {
		if strings.EqualFold(field.name, name) {
			return smtpUnfold(field.value)
		}
	}
	return ""
}

// Walks raw within settings' bounds.
func parseSmtpReportMime(raw []byte, settings *SmtpEdgeSettings) (*SmtpReportParts, error) {
	headerBlock, body, ok := smtpSplitHeaderBlock(raw, settings.ReportHeaderByteCount)
	if !ok {
		return nil, fmt.Errorf("%w: no header block within the bound", ErrSmtpReportRefused)
	}
	parts := &SmtpReportParts{HeaderBlock: headerBlock}
	walker := &smtpMimeWalker{settings: settings, parts: parts}
	if err := walker.entity(headerBlock, body, 1); err != nil {
		return nil, err
	}
	return parts, nil
}

// One walk's state.
type smtpMimeWalker struct {
	settings *SmtpEdgeSettings
	parts    *SmtpReportParts
}

// One entity at depth: a leaf, or a multipart whose parts it walks.
func (self *smtpMimeWalker) entity(headerBlock []byte, body []byte, depth int) error {
	fields, err := smtpHeaderFields(headerBlock, false)
	if err != nil {
		return err
	}
	mediaType := "text/plain"
	params := map[string]string{}
	if contentType := smtpHeaderValue(fields, "Content-Type"); contentType != "" {
		parsedType, parsedParams, err := mime.ParseMediaType(contentType)
		if err != nil {
			// a part whose type cannot be read is no part this parser reads
			parsedType = "application/octet-stream"
			parsedParams = map[string]string{}
		}
		mediaType = parsedType
		params = parsedParams
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		if self.settings.ReportMimeDepth <= depth {
			return fmt.Errorf("%w: multiparts nest past the bound", ErrSmtpReportRefused)
		}
		boundary := params["boundary"]
		if boundary == "" || smtpMimeBoundaryMaxByteCount < len(boundary) {
			return fmt.Errorf("%w: a multipart with no usable boundary", ErrSmtpReportRefused)
		}
		return self.multipart(body, boundary, depth)
	}
	if self.settings.ReportMimePartCount <= len(self.parts.Parts) {
		return fmt.Errorf("%w: more parts than the bound", ErrSmtpReportRefused)
	}
	fileName := ""
	if disposition := smtpHeaderValue(fields, "Content-Disposition"); disposition != "" {
		if _, dispositionParams, err := mime.ParseMediaType(disposition); err == nil {
			fileName = dispositionParams["filename"]
		}
	}
	if fileName == "" {
		fileName = params["name"]
	}
	self.parts.Parts = append(self.parts.Parts, &SmtpReportPart{
		MediaType:        mediaType,
		FileName:         fileName,
		TransferEncoding: strings.ToLower(strings.TrimSpace(smtpHeaderValue(fields, "Content-Transfer-Encoding"))),
		Body:             body,
	})
	return nil
}

// The parts of one multipart body (RFC 2046 §5.1.1). A delimiter line opens at the body's start or
// after a CRLF, which belongs to the delimiter, and is the boundary after two hyphens, then either two
// more hyphens, closing, or transport padding and a CRLF. The preamble and epilogue are skipped. A
// body that never closes ends its last part at the body's end.
func (self *smtpMimeWalker) multipart(body []byte, boundary string, depth int) error {
	delimiter := []byte("--" + boundary)
	crlfDelimiter := append([]byte("\r\n"), delimiter...)
	// the next delimiter line at or after from: where its content ends, where the next part begins, and
	// whether it closes
	next := func(from int) (contentEnd int, partStart int, closing bool, found bool) {
		search := from
		for search <= len(body) {
			var at int
			if search == 0 && bytes.HasPrefix(body, delimiter) {
				at = 0
				contentEnd = 0
			} else {
				index := bytes.Index(body[search:], crlfDelimiter)
				if index < 0 {
					return 0, 0, false, false
				}
				contentEnd = search + index
				at = contentEnd + 2
			}
			rest := body[at+len(delimiter):]
			if bytes.HasPrefix(rest, []byte("--")) {
				return contentEnd, len(body), true, true
			}
			padding := 0
			for padding < len(rest) && (rest[padding] == ' ' || rest[padding] == '\t') {
				padding += 1
			}
			if padding == len(rest) {
				// a delimiter with nothing after it opens no part
				return contentEnd, len(body), true, true
			}
			if bytes.HasPrefix(rest[padding:], smtpCrlf) {
				return contentEnd, at + len(delimiter) + padding + 2, false, true
			}
			// the boundary's bytes inside content, which a sender should never write: not a delimiter
			search = at + len(delimiter)
		}
		return 0, 0, false, false
	}
	_, partStart, closing, found := next(0)
	if !found {
		return fmt.Errorf("%w: a multipart with no delimiter", ErrSmtpReportRefused)
	}
	for !closing {
		contentEnd, nextStart, nextClosing, nextFound := next(partStart)
		if !nextFound {
			contentEnd = len(body)
			nextClosing = true
		}
		if contentEnd < partStart {
			contentEnd = partStart
		}
		part := body[partStart:contentEnd]
		partHeaderBlock, partBody, ok := smtpSplitHeaderBlock(part, self.settings.ReportHeaderByteCount)
		if !ok {
			// a part with fields and no blank line: its fields run to its end, and its body is empty
			if self.settings.ReportHeaderByteCount < len(part) {
				return fmt.Errorf("%w: a part's header block past the bound", ErrSmtpReportRefused)
			}
			partHeaderBlock = part
			partBody = nil
		}
		if err := self.entity(partHeaderBlock, partBody, depth+1); err != nil {
			return err
		}
		partStart = nextStart
		closing = nextClosing
	}
	return nil
}
