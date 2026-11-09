// MAIL-M7-11's ingest headers: the rendering of sealed evidence byte for byte, the deposits that get none or a bare
// none, incomplete checks, and hostile values that can neither split a field nor pass a line's 998 bytes. Every name
// is synthetic.

package sidecar

import (
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Why rendered breaks RFC 5322's shape for added fields, or empty: every line a field's first, named
// Authentication-Results or Received, or a folded continuation; no bare CR or LF; at most 998 bytes a line; and the
// whole ending CRLF.
func checkMailIngestHeaderLines(rendered []byte) string {
	if len(rendered) == 0 {
		return ""
	}
	text := string(rendered)
	if !strings.HasSuffix(text, "\r\n") {
		return "the fields do not end CRLF"
	}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\r\n"), "\r\n") {
		if strings.ContainsAny(line, "\r\n") {
			return "a bare line break"
		}
		if 998 < len(line) {
			return "a line past 998 bytes"
		}
		if !strings.HasPrefix(line, "Authentication-Results: ") && !strings.HasPrefix(line, "Received: ") && !strings.HasPrefix(line, "\t") {
			return "a line that opens a field of its own: " + line
		}
	}
	return ""
}

// A receiver's deposit with full evidence, byte for byte: each method's clause, then Received from the sealed
// ingress, the TLS session and the sealed time.
func TestMailIngestHeadersRenderSealedEvidence(t *testing.T) {
	rendered := MailIngestHeaders(testMailReceiverDeposit(), Id{0x01, 0x9a}, "sender.example")
	want := "Authentication-Results: mx.k3j4h5g6f7.root.example;\r\n" +
		"\tspf=pass smtp.mailfrom=sender.example;\r\n" +
		"\tdkim=temperror header.d=other.example header.s=s2;\r\n" +
		"\tdkim=pass header.d=sender.example header.s=s1;\r\n" +
		"\tdmarc=pass header.from=sender.example;\r\n" +
		"\tarc=none;\r\n" +
		"\tiprev=pass policy.iprev=192.0.2.25 (mail.sender.example)\r\n" +
		"Received: from mail.sender.example (mail.sender.example [192.0.2.25])\r\n" +
		"\tby mx.k3j4h5g6f7.root.example with ESMTPS (TLS1.3 TLS_AES_128_GCM_SHA256)\r\n" +
		"\tid agnaaaaaaaaaaaaaaaaaaaaaaa;\r\n" +
		"\tFri, 06 Nov 2026 00:00:00 +0000\r\n"
	if string(rendered) != want {
		t.Errorf("got\n%s\nwant\n%s", rendered, want)
	}
	if failure := checkMailIngestHeaderLines(rendered); failure != "" {
		t.Error(failure)
	}
	// a pure function of the deposit: rendering again, as a second reader would, gives the same bytes
	if string(MailIngestHeaders(testMailReceiverDeposit(), Id{0x01, 0x9a}, "sender.example")) != want {
		t.Error("a second rendering differs")
	}
}

// A same-network deposit gets no field; a receiver's with no evidence gets none (evidence unavailable); a null
// sender's SPF names the HELO identity; incomplete checks read as such; IPv6 senders get IPv6 literals.
func TestMailIngestHeadersCases(t *testing.T) {
	if rendered := MailIngestHeaders(testMailSameNetworkDeposit(), Id{1}, "sender.example"); rendered != nil {
		t.Errorf("a same-network deposit: %q", rendered)
	}

	noEvidence := testMailReceiverDeposit()
	noEvidence.Evidence = nil
	rendered := string(MailIngestHeaders(noEvidence, Id{1}, "sender.example"))
	if !strings.HasPrefix(rendered, "Authentication-Results: mx.k3j4h5g6f7.root.example; none (evidence unavailable)\r\nReceived: from mail.sender.example (unknown [192.0.2.25])\r\n") {
		t.Errorf("no evidence:\n%s", rendered)
	}
	// with neither ingress nor evidence, a receiver's deposit names no host
	noEvidence.Ingress = nil
	if rendered := string(MailIngestHeaders(noEvidence, Id{1}, "")); rendered != "Authentication-Results: unknown.invalid; none (evidence unavailable)\r\n" {
		t.Errorf("nothing sealed: %q", rendered)
	}

	incomplete := testMailReceiverDeposit()
	incomplete.MailFrom = nil
	incomplete.Evidence.Spf.Result = protocol.SpfVerdict_SPF_INCOMPLETE
	incomplete.Evidence.Dkim = []*protocol.DkimResult{{Domain: "sender.example", Selector: "s1", Result: protocol.DkimVerdict_DKIM_INCOMPLETE}}
	incomplete.Evidence.Dmarc.Result = protocol.DmarcVerdict_DMARC_TEMPERROR
	incomplete.Evidence.Arc.Cv = protocol.ArcVerdict_ARC_INCOMPLETE
	incomplete.Evidence.Limits = &protocol.AuthLimits{Reason: 2}
	incomplete.Evidence.PtrName = ""
	incomplete.Ingress.SenderIp = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x25}
	rendered = string(MailIngestHeaders(incomplete, Id{1}, ""))
	for _, part := range []string{
		"\tspf=temperror reason=\"incomplete\" smtp.helo=sender.example;\r\n",
		"\tdkim=temperror reason=\"incomplete\" header.d=sender.example header.s=s1;\r\n",
		"\tdmarc=temperror;\r\n",
		"\tarc=none reason=\"incomplete\"\r\n\t(checks incomplete)\r\n",
		"Received: from mail.sender.example (unknown [IPv6:2001:db8::25])\r\n",
	} {
		if !strings.Contains(rendered, part) {
			t.Errorf("no %q in\n%s", part, rendered)
		}
	}
	if strings.Contains(rendered, "iprev") || strings.Contains(rendered, "header.from") {
		t.Errorf("a result nothing sealed:\n%s", rendered)
	}

	// verdicts left unspecified are left out, and a deposit with nothing else reads none
	empty := testMailReceiverDeposit()
	empty.Evidence = &protocol.MailAuthEvidence{Version: 1}
	if rendered := string(MailIngestHeaders(empty, Id{1}, "")); !strings.HasPrefix(rendered, "Authentication-Results: mx.k3j4h5g6f7.root.example; none\r\nReceived: ") {
		t.Errorf("no verdicts:\n%s", rendered)
	}
}

// Every value a sender sets, with CR, LF, quotes, parentheses and backslashes, and at every length: the fields
// never split and no line passes 998 bytes.
func TestMailIngestHeadersHoldHostileValues(t *testing.T) {
	hostiles := []string{
		"evil.example\r\nBcc: victim@x.example",
		"a\nb\rc",
		`q"uo"te\back(paren)`,
		strings.Repeat("\"", 400),
		strings.Repeat("\\", 400),
		strings.Repeat("(", 400),
		strings.Repeat("x", 4000),
		strings.Repeat("é", 2000),
		"\xff\xfe\r\n\x00",
	}
	for _, hostile := range hostiles {
		deposit := testMailReceiverDeposit()
		deposit.Ingress.EhloName = hostile
		deposit.Ingress.Sni = hostile
		deposit.Evidence.Spf.Domain = hostile
		deposit.Evidence.PtrName = hostile
		for _, dkim := range deposit.Evidence.Dkim {
			dkim.Domain = hostile
			dkim.Selector = hostile
		}
		deposit.Evidence.Dkim = append(deposit.Evidence.Dkim, deposit.Evidence.Dkim...)
		deposit.TlsSuite = 0xffffffff
		rendered := MailIngestHeaders(deposit, Id{1}, hostile)
		if failure := checkMailIngestHeaderLines(rendered); failure != "" {
			t.Errorf("%q: %s", hostile[:min(len(hostile), 20)], failure)
		}
		if strings.Contains(string(rendered), "Bcc:") && !strings.Contains(string(rendered), "\"evil.example Bcc: victim@x.example\"") {
			t.Errorf("%q: Bcc outside a quoted value:\n%s", hostile[:min(len(hostile), 20)], rendered)
		}
		if strings.Contains(string(rendered), "evil.example") && !strings.Contains(string(rendered), "unknown.invalid") {
			t.Errorf("a hostile SNI became the authserv-id")
		}
	}
}
