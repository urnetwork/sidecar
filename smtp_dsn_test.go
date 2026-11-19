//go:build !sidecar_http && !ios_extension

// RFC 3464 DSNs (SMTP-M9-08): each end's text holds its reason and recipients, only too_large's cites the DATA cap,
// naming its domain, the size and the cap, no DSN names an inbound indexer, receiver or coverage setting, and a held
// outcome makes none.

package sidecar_test

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A DSN of outcome for bob and carol at mail.example.
func testSmtpDsn(outcome sidecar.SmtpOutcomeKind, reason string) *sidecar.SmtpDsn {
	return &sidecar.SmtpDsn{
		ReportingDomain: "b.n1.root.example",
		To:              "alice@n1.root.example",
		RecipientDomain: testTlsDomain,
		Outcome:         outcome,
		Recipients: []*sidecar.SmtpDsnRecipient{
			{Address: "bob@" + testTlsDomain, Status: "5.0.0", ReplyCode: 550},
			{Address: "carol@" + testTlsDomain, Status: "5.0.0", ReplyCode: 550},
		},
		Reason:          reason,
		ByteCount:       5120,
		CapByteCount:    4096,
		OriginalHeaders: []byte("From: alice@n1.root.example\r\nSubject: hello\r\n\r\n"),
		ArrivalTime:     time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC),
		Now:             time.Date(2026, time.November, 8, 12, 5, 0, 0, time.UTC),
		MessageId:       "aaaaaaaaaaaaaaaaaaaaaaaaaa@b.n1.root.example",
		Boundary:        "dsn-boundary",
	}
}

// The copy rule (§14.5): every DSN holds its reason and its recipients; only too_large's names the cap; none names
// an indexer, a receiver or a coverage setting.
func TestSmtpDsnCopy(t *testing.T) {
	inbound := regexp.MustCompile(`(?i)\b(indexers?|receivers?|coverage)\b`)
	refusal := &sidecar.SmtpTlsRefusal{Kind: sidecar.SmtpTlsRefusalUnauthenticated, Level: sidecar.SmtpTlsLevelUnauthenticated}
	for _, c := range []struct {
		outcome sidecar.SmtpOutcomeKind
		reason  string
	}{
		{outcome: sidecar.SmtpOutcomeRefused},
		{outcome: sidecar.SmtpOutcomeTlsRefused, reason: refusal.Reason()},
		{outcome: sidecar.SmtpOutcomeTooLarge},
		{outcome: sidecar.SmtpOutcomeFailed, reason: "The recipient domain has no mail server that takes mail."},
	} {
		dsn, err := testSmtpDsn(c.outcome, c.reason).Encode()
		if err != nil {
			t.Fatalf("outcome %d: %v", c.outcome, err)
		}
		text := string(dsn)
		for _, want := range []string{"bob@" + testTlsDomain, "carol@" + testTlsDomain, "Final-Recipient: rfc822; bob@" + testTlsDomain, testTlsDomain,
			"report-type=delivery-status", "Reporting-MTA: dns; b.n1.root.example", "Content-Type: text/rfc822-headers", "Subject: hello"} {
			if !strings.Contains(text, want) {
				t.Errorf("outcome %d: no %q in %s", c.outcome, want, text)
			}
		}
		if c.reason != "" && !strings.Contains(text, c.reason) {
			t.Errorf("outcome %d: no reason", c.outcome)
		}
		citesCap := strings.Contains(text, "4096") || strings.Contains(text, "5120")
		if citesCap != (c.outcome == sidecar.SmtpOutcomeTooLarge) {
			t.Errorf("outcome %d: cites the cap %v", c.outcome, citesCap)
		}
		if match := inbound.FindString(text); match != "" {
			t.Errorf("outcome %d names %q", c.outcome, match)
		}
		if !bytes.HasSuffix(dsn, []byte("--dsn-boundary--\r\n")) {
			t.Errorf("outcome %d: the report does not close", c.outcome)
		}
	}
}

// Deferred and queued are no ends, so they make no DSN; nor does one with no recipient.
func TestSmtpDsnRefusesWhatIsNoEnd(t *testing.T) {
	for _, outcome := range []sidecar.SmtpOutcomeKind{sidecar.SmtpOutcomeDeferred, sidecar.SmtpOutcomeQueued, sidecar.SmtpOutcomeSent, sidecar.SmtpOutcomeUnspecified} {
		if _, err := testSmtpDsn(outcome, "").Encode(); err == nil {
			t.Errorf("outcome %d made a DSN", outcome)
		}
	}
	dsn := testSmtpDsn(sidecar.SmtpOutcomeRefused, "")
	dsn.Recipients = nil
	if _, err := dsn.Encode(); err == nil {
		t.Error("a DSN with no recipient")
	}
}

// A value carrying a line break is flattened, so no caller can add a header to the DSN.
func TestSmtpDsnHoldsHeaderValuesToOneLine(t *testing.T) {
	dsn := testSmtpDsn(sidecar.SmtpOutcomeRefused, "")
	dsn.To = "alice@n1.root.example>\r\nBcc: <mallory@" + testTlsOtherZone
	encoded, err := dsn.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("\r\nBcc:")) {
		t.Errorf("a header was added: %s", encoded)
	}
}
