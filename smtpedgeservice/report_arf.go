// ARF's header-only parse (§14.8, D-SMTP-12, RFC 5965). Of a feedback report it reads two parts and no
// more: the message/feedback-report part, for its Feedback-Type, and, to the first CRLF CRLF and at
// most ReportHeaderByteCount, the enclosed message/rfc822 or text/rfc822-headers part's header block.
// Nothing past that CRLF CRLF is read, whatever the part's type claims, and no enclosed body or
// attachment is decoded or copied (owner decision 78). Encoded words and unknown charsets stay as
// written, never expanded.
//
// Of the header block it keeps six things, each checked against its shape so no report text rides in a
// field: DKIM-Signature's d= and s=, Message-ID, X-UR-Ref, Feedback-ID, the From domain, and the
// Received hop that names one of the sending addresses, with its time. That hop's IP is one of
// URnetwork's own, and lives in the returned value for the join only (§2.8 smtp-5); a Received that
// names any other address is skipped, so no third-party address leaves this file.
//
// ParseHeaderBlock is the same parse for the abuse form's pasted header blocks (C-20).

package smtpedgeservice

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net/mail"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

const (
	// RFC 5322 §2.1.1's longest line, which bounds a Message-ID kept.
	smtpMessageIdMaxByteCount = 998
	// The longest Feedback-Type token kept. RFC 5965's registry's longest is twelve.
	smtpFeedbackTypeMaxByteCount = 32
)

var (
	// plan-SMTP-small-readings#3: 1. and 34 lowercase base32 characters.
	smtpXUrRefPattern = regexp.MustCompile(`^1\.[a-z2-7]{34}$`)
	// plan-SMTP-small-readings#4: class, tier, the 26-character network token, urnetwork.
	smtpFeedbackIdPattern   = regexp.MustCompile(`^[nb]:[cpt]:[a-z2-7]{26}:urnetwork$`)
	smtpFeedbackTypePattern = regexp.MustCompile(`^[a-z0-9-]+$`)
)

// One DKIM-Signature's signer, as written in the reported headers: whether it verifies is
// VerifyHeaders' to say.
type SmtpReportSignature struct {
	// d=, lowercased.
	Domain string
	// s=, lowercased.
	Selector string
}

// What a reported header block says, each field empty when absent or not of its shape.
type SmtpReportHeaders struct {
	// At most ReportDkimSignatureCount, in order.
	DkimSignatures []SmtpReportSignature
	// As written, between and including its angle brackets.
	MessageId  string
	XUrRef     string
	FeedbackId string
	// The domain of From's first address, lowercased, when it is an LDH name.
	FromDomain string
	// The topmost Received hop whose from clause names a sending address, for the join only and never
	// stored. Invalid when none does.
	ReceivedAddress netip.Addr
	// That hop's time. Zero when it has none that parses.
	ReceivedTime time.Time
}

// One ARF report, or a role mail, after the header-only parse.
type SmtpArfReport struct {
	// RFC 5965's Feedback-Type, lowercased: abuse, fraud, virus, other, not-spam (RFC 6430, kept as a
	// cancel) and so on. Empty when the report has no feedback-report part, as role mail may not.
	FeedbackType string
	// The enclosed header block's fields. nil when the report encloses none.
	Headers *SmtpReportHeaders
	// The enclosed header block itself, through its blank line or cut at the bound, for VerifyHeaders
	// and the join only: in memory, never stored or logged.
	headerBlock []byte
}

// The enclosed header block, for VerifyHeaders and the join.
func (self *SmtpArfReport) HeaderBlock() []byte {
	return self.headerBlock
}

// The ARF report in parts. A report with neither a feedback-report part nor an enclosed header block
// is refused. A feedback-report part with no Feedback-Type is refused, as RFC 5965 requires one.
func parseSmtpArf(parts *SmtpReportParts, settings *SmtpEdgeSettings) (*SmtpArfReport, error) {
	report := &SmtpArfReport{}
	feedbackFound := false
	enclosedFound := false
	for _, part := range parts.Parts {
		switch part.MediaType {
		case "message/feedback-report":
			if feedbackFound {
				continue
			}
			feedbackFound = true
			block, err := smtpDecodedHeaderBlock(part, settings.ReportHeaderByteCount)
			if err != nil {
				return nil, err
			}
			fields, err := smtpHeaderFields(block, false)
			if err != nil {
				return nil, err
			}
			feedbackType := strings.ToLower(strings.TrimSpace(smtpHeaderValue(fields, "Feedback-Type")))
			if feedbackType == "" || smtpFeedbackTypeMaxByteCount < len(feedbackType) || !smtpFeedbackTypePattern.MatchString(feedbackType) {
				return nil, fmt.Errorf("%w: a feedback report with no Feedback-Type", ErrSmtpReportRefused)
			}
			report.FeedbackType = feedbackType
		case "message/rfc822", "message/global", "text/rfc822-headers", "message/rfc822-headers", "message/global-headers":
			if enclosedFound {
				continue
			}
			enclosedFound = true
			block, err := smtpDecodedHeaderBlock(part, settings.ReportHeaderByteCount)
			if err != nil {
				return nil, err
			}
			headers, err := parseSmtpReportHeaders(block, settings)
			if err != nil {
				return nil, err
			}
			report.headerBlock = block
			report.Headers = headers
		}
	}
	if !feedbackFound && !enclosedFound {
		return nil, fmt.Errorf("%w: no feedback report and no enclosed header block", ErrSmtpReportRefused)
	}
	return report, nil
}

// The fields of a header block pasted into the abuse form (C-20), by the same parse ARF's enclosed
// blocks get. A block past ReportHeaderByteCount is cut there.
func ParseHeaderBlock(block []byte, settings *SmtpEdgeSettings) (*SmtpReportHeaders, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	block = smtpCutHeaderBlock(block, settings.ReportHeaderByteCount)
	return parseSmtpReportHeaders(block, settings)
}

// data's header block: through its first CRLF CRLF when that comes within maxByteCount, else cut at
// the last CRLF before the bound, so a field is never cut mid-line.
func smtpCutHeaderBlock(data []byte, maxByteCount int) []byte {
	window := data
	if maxByteCount < len(window) {
		window = window[:maxByteCount]
	}
	if bytes.HasPrefix(window, smtpCrlf) {
		return window[:2]
	}
	if end := bytes.Index(window, smtpCrlfCrlf); 0 <= end {
		return window[:end+4]
	}
	if len(window) < len(data) {
		if lastLine := bytes.LastIndex(window, smtpCrlf); 0 <= lastLine {
			return window[:lastLine+2]
		}
		return nil
	}
	return window
}

// A part's header block, decoded by its transfer encoding only as far as the first CRLF CRLF, and cut
// at maxByteCount when that comes later. Base64 and quoted-printable are read a few octets at a time,
// so decoding stops within one quantum of the block's end, and what it decoded past the end is
// dropped at once. Any other encoding is refused.
func smtpDecodedHeaderBlock(part *SmtpReportPart, maxByteCount int) ([]byte, error) {
	var decoder io.Reader
	switch part.TransferEncoding {
	case "", "7bit", "8bit", "binary":
		return smtpCutHeaderBlock(part.Body, maxByteCount), nil
	case "base64":
		decoder = base64.NewDecoder(base64.StdEncoding, bytes.NewReader(part.Body))
	case "quoted-printable":
		decoder = quotedprintable.NewReader(bytes.NewReader(part.Body))
	default:
		return nil, fmt.Errorf("%w: a header part in an unknown transfer encoding", ErrSmtpReportRefused)
	}
	// one base64 quantum, so at most two octets past the block's end are ever decoded
	quantum := make([]byte, 3)
	decoded := make([]byte, 0, min(maxByteCount, 4*1024))
	for len(decoded) < maxByteCount+len(smtpCrlfCrlf) {
		n, err := decoder.Read(quantum)
		decoded = append(decoded, quantum[:n]...)
		// the block ends in what this read added, or straddles the last read
		searchFrom := max(0, len(decoded)-n-len(smtpCrlfCrlf)+1)
		if bytes.HasPrefix(decoded, smtpCrlf) {
			return decoded[:2], nil
		}
		if end := bytes.Index(decoded[searchFrom:], smtpCrlfCrlf); 0 <= end {
			return smtpCutHeaderBlock(decoded[:searchFrom+end+4], maxByteCount), nil
		}
		if err == io.EOF {
			return smtpCutHeaderBlock(decoded, maxByteCount), nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: a header part that does not decode", ErrSmtpReportRefused)
		}
	}
	return smtpCutHeaderBlock(decoded, maxByteCount), nil
}

// The six things a reported header block says.
func parseSmtpReportHeaders(block []byte, settings *SmtpEdgeSettings) (*SmtpReportHeaders, error) {
	fields, err := smtpHeaderFields(block, false)
	if err != nil {
		return nil, err
	}
	headers := &SmtpReportHeaders{}
	receivedFound := false
	for _, field := range fields {
		switch strings.ToLower(field.name) {
		case "dkim-signature":
			if settings.ReportDkimSignatureCount <= len(headers.DkimSignatures) {
				continue
			}
			tags, ok := smtpDkimTagList(smtpUnfold(field.value))
			if !ok {
				continue
			}
			domain := strings.ToLower(tags["d"])
			selector := strings.ToLower(tags["s"])
			if smtpLdhName(domain) && smtpDkimSelectorValid(selector) {
				headers.DkimSignatures = append(headers.DkimSignatures, SmtpReportSignature{Domain: domain, Selector: selector})
			}
		case "message-id":
			if headers.MessageId != "" {
				continue
			}
			messageId := strings.TrimSpace(smtpUnfold(field.value))
			if strings.HasPrefix(messageId, "<") && strings.HasSuffix(messageId, ">") && strings.Contains(messageId, "@") &&
				len(messageId) <= smtpMessageIdMaxByteCount && smtpPrintableAscii(messageId) {
				headers.MessageId = messageId
			}
		case "x-ur-ref":
			if value := strings.TrimSpace(smtpUnfold(field.value)); headers.XUrRef == "" && smtpXUrRefPattern.MatchString(value) {
				headers.XUrRef = value
			}
		case "feedback-id":
			if value := strings.TrimSpace(smtpUnfold(field.value)); headers.FeedbackId == "" && smtpFeedbackIdPattern.MatchString(value) {
				headers.FeedbackId = value
			}
		case "from":
			if headers.FromDomain == "" {
				headers.FromDomain = smtpAddressDomain(smtpUnfold(field.value))
			}
		case "received":
			if receivedFound {
				continue
			}
			address, receivedTime, ok := smtpReceivedHop(smtpUnfold(field.value))
			if ok && settings.isSendingAddress(address) {
				headers.ReceivedAddress = address
				headers.ReceivedTime = receivedTime
				receivedFound = true
			}
		}
	}
	return headers, nil
}

// Whether value is printable ASCII with no space.
func smtpPrintableAscii(value string) bool {
	for i := range len(value) {
		if value[i] <= ' ' || 0x7f <= value[i] {
			return false
		}
	}
	return true
}

// value with only its ASCII capitals lowered, byte for byte, so its length and every index into it are
// value's.
func smtpAsciiLower(value string) string {
	lowered := []byte(value)
	for i, c := range lowered {
		if 'A' <= c && c <= 'Z' {
			lowered[i] = c + ('a' - 'A')
		}
	}
	return string(lowered)
}

// The domain of a From field's first address, lowercased, when it is an LDH name, else empty. The
// display name is never decoded: only the addr-spec is read, inside the first angle brackets when there
// are any.
func smtpAddressDomain(value string) string {
	address := value
	if open := strings.IndexByte(value, '<'); 0 <= open {
		if close := strings.IndexByte(value[open:], '>'); 0 <= close {
			address = value[open+1 : open+close]
		}
	} else if comma := strings.IndexByte(value, ','); 0 <= comma {
		address = value[:comma]
	}
	at := strings.LastIndexByte(address, '@')
	if at < 0 {
		return ""
	}
	domain := address[at+1:]
	if end := strings.IndexAny(domain, " \t()>;,"); 0 <= end {
		domain = domain[:end]
	}
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if !smtpLdhName(domain) {
		return ""
	}
	return domain
}

// A Received field's from-clause address and its time: the first address literal in brackets before
// the by clause (RFC 5321 §4.4's TCP-info), and the date after the last semicolon.
func smtpReceivedHop(value string) (netip.Addr, time.Time, bool) {
	fromClause := value
	// searched in an ASCII-lowered copy, which keeps every byte where it was: strings.ToLower rewrites
	// invalid UTF-8, so an index into its result need not be an index into value
	if by := strings.Index(smtpAsciiLower(value), " by "); 0 <= by {
		fromClause = value[:by]
	}
	open := strings.IndexByte(fromClause, '[')
	if open < 0 {
		return netip.Addr{}, time.Time{}, false
	}
	close := strings.IndexByte(fromClause[open:], ']')
	if close < 0 {
		return netip.Addr{}, time.Time{}, false
	}
	literal := fromClause[open+1 : open+close]
	literal = strings.TrimPrefix(strings.TrimPrefix(literal, "IPv6:"), "ipv6:")
	address, err := netip.ParseAddr(literal)
	if err != nil {
		return netip.Addr{}, time.Time{}, false
	}
	var receivedTime time.Time
	if semicolon := strings.LastIndexByte(value, ';'); 0 <= semicolon {
		date := strings.TrimSpace(value[semicolon+1:])
		// a trailing comment, as "(PDT)", which ParseDate need not take
		if strings.HasSuffix(date, ")") {
			if open := strings.LastIndexByte(date, '('); 0 <= open {
				date = strings.TrimSpace(date[:open])
			}
		}
		if parsed, err := mail.ParseDate(date); err == nil {
			receivedTime = parsed
		}
	}
	return address.Unmap(), receivedTime, true
}
