// An aggregate report's attachment (§14.8, D-SMTP-23): found among the leaves by type or file name,
// decoded from its transfer encoding, and inflated from gzip or a one-file zip
// (plan-SMTP-small-readings#15) within ReportInflateByteCount and ReportInflateRatio. Inflating stops
// at the bound, never after it: at most the bound plus one octet is ever inflated, and what is read
// grows by doubling, so a bomb costs at most about twice the bound in memory. An attachment past either
// bound is refused whole, never parsed in part.

package smtpedgeservice

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"strings"
)

// How an attachment is packed.
const (
	smtpPackingNone = "none"
	smtpPackingGzip = "gzip"
	smtpPackingZip  = "zip"
)

// The read size while inflating.
const smtpInflateChunkByteCount = 32 * 1024

// An aggregate's attachment and how it is packed.
type smtpAggregateAttachment struct {
	part    *SmtpReportPart
	packing string
}

// The first leaf that is an aggregate's attachment, by its type, or by its file name when its type
// says only octets. nil when there is none.
func smtpFindAggregateAttachment(parts *SmtpReportParts) *smtpAggregateAttachment {
	byName := func(name string) string {
		name = strings.ToLower(name)
		switch {
		case strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".gzip"):
			return smtpPackingGzip
		case strings.HasSuffix(name, ".zip"):
			return smtpPackingZip
		case strings.HasSuffix(name, ".xml") || strings.HasSuffix(name, ".json"):
			return smtpPackingNone
		}
		return ""
	}
	for _, part := range parts.Parts {
		packing := ""
		switch part.MediaType {
		case "application/gzip", "application/x-gzip", "application/tlsrpt+gzip":
			packing = smtpPackingGzip
		case "application/zip", "application/x-zip", "application/x-zip-compressed":
			packing = smtpPackingZip
		case "text/xml", "application/xml", "application/tlsrpt+json", "application/json":
			packing = smtpPackingNone
		case "application/octet-stream":
			packing = byName(part.FileName)
		}
		if packing != "" {
			return &smtpAggregateAttachment{part: part, packing: packing}
		}
	}
	return nil
}

// A part's octets with its transfer encoding undone. Decoding never outgrows the part.
func smtpDecodeTransfer(part *SmtpReportPart) ([]byte, error) {
	switch part.TransferEncoding {
	case "", "7bit", "8bit", "binary":
		return part.Body, nil
	case "base64":
		// the decoder skips CR and LF, as a MIME body's lines need
		decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(part.Body)))
		if err != nil {
			return nil, fmt.Errorf("%w: an attachment that does not decode", ErrSmtpReportRefused)
		}
		return decoded, nil
	case "quoted-printable":
		decoded, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(part.Body)))
		if err != nil {
			return nil, fmt.Errorf("%w: an attachment that does not decode", ErrSmtpReportRefused)
		}
		return decoded, nil
	}
	return nil, fmt.Errorf("%w: an attachment in an unknown transfer encoding", ErrSmtpReportRefused)
}

// Everything reader gives, refused once it passes limit. The buffer doubles, capped at the limit and
// one octet, so what a read allocates in all stays under about twice the limit; append alone grows a
// large slice by a quarter, which would allocate about five times it.
func smtpReadBounded(reader io.Reader, limit int) ([]byte, error) {
	out := make([]byte, 0, min(limit+1, smtpInflateChunkByteCount))
	for {
		if len(out) == cap(out) {
			grown := make([]byte, len(out), min(2*cap(out), limit+1))
			copy(grown, out)
			out = grown
		}
		// read straight into the buffer, never past one octet over the limit
		n, err := reader.Read(out[len(out):cap(out)])
		out = out[:len(out)+n]
		if limit < len(out) {
			return nil, fmt.Errorf("%w: an attachment inflating past its bound", ErrSmtpReportRefused)
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: an attachment that does not inflate", ErrSmtpReportRefused)
		}
	}
}

// The attachment's report, inflated within the bounds: ReportInflateByteCount in all, and
// ReportInflateRatio octets per packed octet.
func inflateSmtpReport(packed []byte, packing string, settings *SmtpEdgeSettings) ([]byte, error) {
	limit := settings.ReportInflateByteCount
	if packing != smtpPackingNone {
		limit = min(limit, settings.ReportInflateRatio*len(packed))
	}
	switch packing {
	case smtpPackingNone:
		if limit < len(packed) {
			return nil, fmt.Errorf("%w: an attachment past its bound", ErrSmtpReportRefused)
		}
		return packed, nil
	case smtpPackingGzip:
		reader, err := gzip.NewReader(bytes.NewReader(packed))
		if err != nil {
			return nil, fmt.Errorf("%w: an attachment that is not gzip", ErrSmtpReportRefused)
		}
		defer reader.Close()
		return smtpReadBounded(reader, limit)
	case smtpPackingZip:
		archive, err := zip.NewReader(bytes.NewReader(packed), int64(len(packed)))
		if err != nil {
			return nil, fmt.Errorf("%w: an attachment that is not zip", ErrSmtpReportRefused)
		}
		if len(archive.File) != 1 || archive.File[0].FileInfo().IsDir() {
			return nil, fmt.Errorf("%w: a zip of other than one file", ErrSmtpReportRefused)
		}
		entry, err := archive.File[0].Open()
		if err != nil {
			return nil, fmt.Errorf("%w: a zip entry that does not open", ErrSmtpReportRefused)
		}
		defer entry.Close()
		return smtpReadBounded(entry, limit)
	}
	return nil, fmt.Errorf("%w: an unknown packing", ErrSmtpReportRefused)
}

// The aggregate a report attaches, parsed. nil and no error when it attaches none. The kind is the
// content's: XML is DMARC (RFC 9990), JSON is TLS-RPT (RFC 8460).
func parseSmtpAggregate(parts *SmtpReportParts, settings *SmtpEdgeSettings) (*SmtpAggregateRows, error) {
	attachment := smtpFindAggregateAttachment(parts)
	if attachment == nil {
		return nil, nil
	}
	packed, err := smtpDecodeTransfer(attachment.part)
	if err != nil {
		return nil, err
	}
	data, err := inflateSmtpReport(packed, attachment.packing, settings)
	if err != nil {
		return nil, err
	}
	content := bytes.TrimLeft(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), " \t\r\n")
	switch {
	case bytes.HasPrefix(content, []byte("<")):
		return parseSmtpDmarcXml(data, settings)
	case bytes.HasPrefix(content, []byte("{")):
		return parseSmtpTlsRptJson(data, settings)
	}
	return nil, fmt.Errorf("%w: an attachment that is neither XML nor JSON", ErrSmtpReportRefused)
}
