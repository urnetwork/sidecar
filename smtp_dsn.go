//go:build !sidecar_http && !ios_extension

// RFC 3464 delivery status notifications for the sender's own failures (§14.4, §14.5, D-SMTP-20; SMTP-M9-08): a
// recipient domain's send that ends without delivery, refused, tls_refused, too_large or failed, gives the
// composing member one DSN naming the domain, its recipients and why, deposited to the sending mailbox through
// SmtpMailbox.DepositDsn as received mail is (§15.10's last line). A held send makes none: deferred and queued
// are not ends.
//
// The copy rule (§14.5's Copy): only too_large cites the DATA cap, naming that domain, the size and the cap;
// every other DSN names no cap; and no DSN points to an inbound indexer, receiver or coverage setting, which are
// inbound matters (§18.5). TestSmtpDsnCopy scans each kind's text for those words.
//
// The DSN is multipart/report (RFC 6522) with three parts: a plain text account, the message/delivery-status
// fields (RFC 3464 §2.2, §2.3) with one block a recipient, and the original's header block as
// text/rfc822-headers, Bcc already gone from it, so no body leaves the mailbox again.
//
// Off the sidecar_http leg: a page Worker sends no mail (§18.10).

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"
)

var errSmtpDsn = errors.New("smtp dsn: nothing to report")

// One recipient a DSN reports.
type SmtpDsnRecipient struct {
	// The addr-spec, lowercase.
	Address string
	// RFC 3463's enhanced status, a 5.x.x: 5.0.0 for the MX's own refusal, 5.7.10 for TLS that could not be
	// authenticated (SmtpTlsRefusalStatus), 5.7.30 for a missing REQUIRETLS extension, 5.3.4 for a message
	// too large, 4.4.7 for one that timed out.
	Status string
	// The MX's reply code, when it refused the recipient; 0 otherwise.
	ReplyCode uint32
}

// One DSN's facts, and its bytes by Encode.
type SmtpDsn struct {
	// b.<net>.<root>, the envelope sender's domain: the DSN's Reporting-MTA and its From's domain.
	ReportingDomain string
	// Who the DSN tells: the original's sender.
	To string
	// The recipient domain the DSN is for, which every recipient below is at.
	RecipientDomain string
	// refused, tls_refused, too_large or failed.
	Outcome    SmtpOutcomeKind
	Recipients []*SmtpDsnRecipient
	// Why, in words, beside the outcome's own sentence: a TLS refusal's Reason, or the sender's.
	Reason string
	// too_large alone: the message's encoded bytes, and the DATA cap they passed.
	ByteCount    uint64
	CapByteCount uint64
	// The original's header block, with its final CRLF CRLF or without it.
	OriginalHeaders []byte
	ArrivalTime     time.Time
	Now             time.Time
	// The DSN's own Message-ID and MIME boundary, which the caller draws.
	MessageId string
	Boundary  string
}

// The outcome's own sentence, the first of the account. Only too_large's names the cap.
func (self *SmtpDsn) summary() string {
	switch self.Outcome {
	case SmtpOutcomeRefused:
		return fmt.Sprintf("The mail server for %s refused the message.", self.RecipientDomain)
	case SmtpOutcomeTlsRefused:
		return fmt.Sprintf("The message was not sent to %s: its mail server could not be authenticated well enough.", self.RecipientDomain)
	case SmtpOutcomeTooLarge:
		return fmt.Sprintf("The message is %d bytes, over the %d bytes this device can prove to the mail server for %s, "+
			"which takes mail only by DATA, so it was not sent there. Recipients at other domains are not affected.",
			self.ByteCount, self.CapByteCount, self.RecipientDomain)
	}
	return fmt.Sprintf("The message could not be sent to %s.", self.RecipientDomain)
}

// The DSN's RFC 5322 bytes. Refuses a DSN with no recipient or of an outcome that is no end.
func (self *SmtpDsn) Encode() ([]byte, error) {
	switch self.Outcome {
	case SmtpOutcomeRefused, SmtpOutcomeTlsRefused, SmtpOutcomeTooLarge, SmtpOutcomeFailed:
	default:
		return nil, fmt.Errorf("%w: outcome %d is no end", errSmtpDsn, self.Outcome)
	}
	if len(self.Recipients) == 0 || self.ReportingDomain == "" || self.To == "" || self.Boundary == "" {
		return nil, errSmtpDsn
	}
	clean := func(value string) string {
		// a header value never carries a line break, whatever the caller handed in
		return strings.Map(func(r rune) rune {
			if r == '\r' || r == '\n' {
				return ' '
			}
			return r
		}, value)
	}
	var out bytes.Buffer
	line := func(text string) {
		out.WriteString(text)
		out.WriteString("\r\n")
	}
	line("From: Mail Delivery System <mailer-daemon@" + clean(self.ReportingDomain) + ">")
	line("To: <" + clean(self.To) + ">")
	line("Subject: Undelivered mail to " + clean(self.RecipientDomain))
	line("Date: " + self.Now.UTC().Format(time.RFC1123Z))
	if self.MessageId != "" {
		line("Message-ID: <" + clean(self.MessageId) + ">")
	}
	line("Auto-Submitted: auto-replied")
	line("MIME-Version: 1.0")
	line("Content-Type: multipart/report; report-type=delivery-status; boundary=\"" + clean(self.Boundary) + "\"")
	line("")

	// the account
	line("--" + self.Boundary)
	line("Content-Type: text/plain; charset=us-ascii")
	line("")
	line(self.summary())
	if self.Reason != "" {
		line("")
		line(clean(self.Reason))
	}
	line("")
	line("Recipients:")
	for _, recipient := range self.Recipients {
		line("  " + clean(recipient.Address))
	}
	line("")

	// the fields
	line("--" + self.Boundary)
	line("Content-Type: message/delivery-status")
	line("")
	line("Reporting-MTA: dns; " + clean(self.ReportingDomain))
	if !self.ArrivalTime.IsZero() {
		line("Arrival-Date: " + self.ArrivalTime.UTC().Format(time.RFC1123Z))
	}
	for _, recipient := range self.Recipients {
		line("")
		line("Final-Recipient: rfc822; " + clean(recipient.Address))
		line("Action: failed")
		line("Status: " + clean(recipient.Status))
		if recipient.ReplyCode != 0 {
			line(fmt.Sprintf("Diagnostic-Code: smtp; %d", recipient.ReplyCode))
		}
	}
	line("")

	// the original's header block
	line("--" + self.Boundary)
	line("Content-Type: text/rfc822-headers")
	line("")
	headers := bytes.TrimRight(self.OriginalHeaders, "\r\n")
	out.Write(headers)
	out.WriteString("\r\n")
	line("")
	line("--" + self.Boundary + "--")
	return out.Bytes(), nil
}

// RFC 3463's status for a recipient the MX refused with code: its class, 5.0.0 or 4.0.0.
func smtpDsnStatusOfReply(code uint32) string {
	if 400 <= code && code < 500 {
		return "4.0.0"
	}
	return "5.0.0"
}

// RFC 3463's statuses the sender's own ends give.
const (
	// RFC 8689: the MX did not advertise REQUIRETLS after STARTTLS.
	smtpDsnStatusRequireTlsMissing = "5.7.30"
	// A message too large for the system: too_large.
	smtpDsnStatusTooLarge = "5.3.4"
	// Delivery time expired: given up at 5 days.
	smtpDsnStatusExpired = "4.4.7"
	// Other or undefined status: a send that ended for a reason of its own.
	smtpDsnStatusOther = "5.0.0"
)
