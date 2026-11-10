//go:build !sidecar_http && !js

// MAIL-M7-08's checks on FakeMailZone, the kit's signers and a fake clock: a message that passes everything, SPF's
// identities and verdicts, the PTR forward-confirmed by the receiver itself, the SNI host's TLSA compared by SPKI,
// and the header view's cut at 256 KiB. Every name, key and address is synthetic.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The session's names and the receiver's key the checks test against.
const (
	testMailAuthSni    = "mx.k3j4h5g6f7.root.example"
	testMailAuthSender = "192.0.2.25"
)

var testMailAuthSpki = sha256.Sum256([]byte("a synthetic receiver's SubjectPublicKeyInfo"))

// A zone, a clock and a receiver's checker over its own stub.
type mailAuthCheckWorld struct {
	clock    *sidecartest.FakeClock
	zone     *sidecartest.FakeMailZone
	settings *sidecar.MailAuthSettings
	stub     *sidecar.MailDnsStub
	checker  *sidecar.MailAuthChecker
	corpus   *sidecartest.MailCorpus
}

func newMailAuthCheckWorld(t *testing.T) *mailAuthCheckWorld {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	zone := sidecartest.NewFakeMailZone(clock)
	settings := sidecar.DefaultMailAuthSettings()
	stub := sidecar.NewMailDnsStub(zone, clock, settings)
	return &mailAuthCheckWorld{
		clock: clock, zone: zone, settings: settings, stub: stub,
		checker: sidecar.NewMailAuthChecker(stub, clock, settings),
		corpus:  sidecartest.NewMailCorpus(zone, clock.Now()),
	}
}

// The session around message: from 192.0.2.25, MAIL FROM bounce@<mailFromDomain>, EHLO mail.sender.example, to the
// network's mx host.
func testMailAuthInput(message []byte, mailFromDomain string) *sidecar.MailAuthInput {
	input := &sidecar.MailAuthInput{
		Message:            bytes.NewReader(message),
		Size:               int64(len(message)),
		SenderIp:           netip.MustParseAddr(testMailAuthSender),
		EhloName:           "mail.sender.example",
		SniHost:            testMailAuthSni,
		ReceiverSpkiSha256: testMailAuthSpki[:],
	}
	if mailFromDomain != "" {
		input.MailFrom = []byte("bounce@" + mailFromDomain)
	}
	return input
}

// A plain message from fromDomain.
func testMailAuthMessage(fromDomain string, subject string) []byte {
	return []byte(strings.Join([]string{
		"From: Sender <sender@" + fromDomain + ">",
		"To: Receiver <id@k3j4h5g6f7.root.example>",
		"Subject: " + subject,
		"Date: Sun, 08 Nov 2026 12:00:00 +0000",
		"Message-ID: <" + subject + "@" + fromDomain + ">",
		"",
		"A synthetic body.",
		"",
	}, "\r\n"))
}

// Runs a check that needs no clock moved.
func (self *mailAuthCheckWorld) check(t *testing.T, input *sidecar.MailAuthInput) *sidecar.MailAuthOutcome {
	t.Helper()
	outcome, err := self.checker.Check(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	return outcome
}

// Publishes what a well-run sending domain does: SPF for its addresses, DMARC p=reject, a PTR that resolves back,
// and the receiver's TLSA under the SNI host.
func (self *mailAuthCheckWorld) publishSender(domain string) {
	self.zone.AddTxt(domain, "v=spf1 ip4:192.0.2.0/24 -all")
	self.zone.AddTxt("_dmarc."+domain, "v=DMARC1; p=reject")
	self.zone.AddPtr(netip.MustParseAddr(testMailAuthSender), "mail."+domain)
	self.zone.AddAddress("mail."+domain, netip.MustParseAddr(testMailAuthSender))
	self.zone.AddAddress("mail."+domain, netip.MustParseAddr("2001:db8::25"))
	self.zone.AddTlsa("_25._tcp."+testMailAuthSni, 3, 1, 1, testMailAuthSpki[:])
}

// A message every check passes: SPF pass, an aligned DKIM pass with the key relied on, DMARC pass under p=reject,
// the PTR forward-confirmed, the TLSA live, and no limits.
func TestMailAuthCheckPassesEverything(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	world.publishSender("sender.example")
	signer, err := sidecartest.NewMailDkimSigner("sender.example", "s1", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(2048))
	if err != nil {
		t.Fatal(err)
	}
	world.zone.AddTxt(sidecartest.MailDkimKeyName("s1", "sender.example"), signer.KeyRecord())
	message, err := signer.Sign(testMailAuthMessage("sender.example", "all-pass"))
	if err != nil {
		t.Fatal(err)
	}
	outcome := world.check(t, testMailAuthInput(message, "sender.example"))
	if outcome.Spf.GetResult() != protocol.SpfVerdict_SPF_PASS || outcome.Spf.GetDomain() != "sender.example" || len(outcome.Spf.GetRecords()) != 1 || len(outcome.Spf.GetIp()) != 4 {
		t.Errorf("spf %v", outcome.Spf)
	}
	if len(outcome.Dkim) != 1 || outcome.Dkim[0].GetResult() != protocol.DkimVerdict_DKIM_PASS || outcome.Dkim[0].GetDomain() != "sender.example" || outcome.Dkim[0].GetSelector() != "s1" || len(outcome.Dkim[0].GetPublicKey()) == 0 {
		t.Errorf("dkim %v", outcome.Dkim)
	}
	if outcome.Dmarc.GetResult() != protocol.DmarcVerdict_DMARC_PASS || outcome.Dmarc.GetP() != "reject" || outcome.Dmarc.GetAlignment() != sidecar.MailDmarcAlignedSpf|sidecar.MailDmarcAlignedDkim {
		t.Errorf("dmarc %v", outcome.Dmarc)
	}
	if outcome.PtrName != "mail.sender.example" || !outcome.SniTlsaLive || outcome.Limits != nil || outcome.DkimVerifiedCount != 1 {
		t.Errorf("ptr %q, tlsa %t, limits %v, verified %d", outcome.PtrName, outcome.SniTlsaLive, outcome.Limits, outcome.DkimVerifiedCount)
	}
}

// SPF's identity is MAIL FROM's domain, or with a null reverse path the post-TLS EHLO's; and each verdict as RFC 7208
// gives it, a failed lookup temperror.
func TestMailAuthCheckSpf(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	world.zone.AddTxt("pass.example", "v=spf1 ip4:192.0.2.25 -all")
	world.zone.AddTxt("fail.example", "v=spf1 -all")
	world.zone.AddTxt("soft.example", "v=spf1 ~all")
	world.zone.AddTxt("mail.sender.example", "v=spf1 ip4:192.0.2.25 -all")
	world.zone.AddTxt("down.example", "v=spf1 -all")
	world.zone.Fail("down.example", dnsmessage.TypeTXT, sidecartest.FakeMailZoneServFail)
	for _, c := range []struct {
		mailFrom string
		want     protocol.SpfVerdict
		domain   string
	}{
		{mailFrom: "pass.example", want: protocol.SpfVerdict_SPF_PASS, domain: "pass.example"},
		{mailFrom: "fail.example", want: protocol.SpfVerdict_SPF_FAIL, domain: "fail.example"},
		{mailFrom: "soft.example", want: protocol.SpfVerdict_SPF_SOFTFAIL, domain: "soft.example"},
		{mailFrom: "none.example", want: protocol.SpfVerdict_SPF_NONE, domain: "none.example"},
		{mailFrom: "down.example", want: protocol.SpfVerdict_SPF_TEMPERROR, domain: "down.example"},
		// a null reverse path takes the EHLO, mail.sender.example
		{mailFrom: "", want: protocol.SpfVerdict_SPF_PASS, domain: "mail.sender.example"},
	} {
		outcome := world.check(t, testMailAuthInput(testMailAuthMessage("from.example", "spf"), c.mailFrom))
		if outcome.Spf.GetResult() != c.want || outcome.Spf.GetDomain() != c.domain {
			t.Errorf("%q: %v", c.mailFrom, outcome.Spf)
		}
	}
}

// The PTR is the receiver's own forward-confirmed one: a name that does not resolve back to sender_ip is none, and
// the TLSA counts only with this receiver's SPKI.
func TestMailAuthCheckPtrAndTlsa(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	world.zone.AddPtr(netip.MustParseAddr(testMailAuthSender), "liar.sender.example")
	world.zone.AddAddress("liar.sender.example", netip.MustParseAddr("198.51.100.7"))
	world.zone.AddTlsa("_25._tcp."+testMailAuthSni, 3, 1, 1, bytes.Repeat([]byte{0x01}, 32))
	outcome := world.check(t, testMailAuthInput(testMailAuthMessage("from.example", "ptr"), "from.example"))
	if outcome.PtrName != "" || outcome.SniTlsaLive {
		t.Errorf("ptr %q, tlsa %t", outcome.PtrName, outcome.SniTlsaLive)
	}
}

// A header section past 256 KiB is cut at its last whole field within: fields past the cut are only counted, the
// cut sets limits' count bit, and a signature that fails under the cut view is incomplete, not fail.
func TestMailAuthHeaderViewCutsAt256KiB(t *testing.T) {
	world := newMailAuthCheckWorld(t)
	world.publishSender("sender.example")
	signer, err := sidecartest.NewMailDkimSigner("sender.example", "s1", sidecartest.MailDkimRsaSha256, sidecartest.MailDkimRsaKey(1024))
	if err != nil {
		t.Fatal(err)
	}
	signer.SignedHeaders = []string{"from", "subject", "x-filler"}
	world.zone.AddTxt(sidecartest.MailDkimKeyName("s1", "sender.example"), signer.KeyRecord())
	base := testMailAuthMessage("sender.example", "cut")
	// 300 KiB of filler fields below From, the last of which the signature covers
	header, body, _ := bytes.Cut(base, []byte("\r\n\r\n"))
	var filler strings.Builder
	for index := range 300 {
		fmt.Fprintf(&filler, "X-Filler: %04d %s\r\n", index, strings.Repeat("f", 985))
	}
	message := append(append(append([]byte{}, header...), []byte("\r\n"+filler.String())...), append([]byte("\r\n"), body...)...)
	message, err = signer.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	outcome := world.check(t, testMailAuthInput(message, "sender.example"))
	if !outcome.View.Cut || outcome.View.Size() >= int64(len(message)) {
		t.Fatalf("view cut %t at %d of %d", outcome.View.Cut, outcome.View.Size(), len(message))
	}
	if len(outcome.Dkim) != 1 || outcome.Dkim[0].GetResult() != protocol.DkimVerdict_DKIM_INCOMPLETE {
		t.Errorf("dkim %v", outcome.Dkim)
	}
	if outcome.Limits.GetReason()&sidecar.MailAuthLimitCount == 0 {
		t.Errorf("limits %v", outcome.Limits)
	}
	// the view itself: its header ends within the bound and then an empty line, and the body follows as received
	viewBytes := make([]byte, outcome.View.Size())
	if _, err := outcome.View.ReadAt(viewBytes, 0); err != nil {
		t.Fatal(err)
	}
	viewHeader, viewBody, found := bytes.Cut(viewBytes, []byte("\r\n\r\n"))
	if !found || 256*1024 < len(viewHeader)+2 || !bytes.Equal(viewBody, body) {
		t.Errorf("a header of %d bytes, body kept %t", len(viewHeader), bytes.Equal(viewBody, body))
	}
}
