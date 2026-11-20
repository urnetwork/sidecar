// §14.6's Team custom domains at the gate (SMTP-M9-34, D-SMTP-15): a verified domain sends From on the team tier and
// an unverified one is DENIED, a domain past §20.7's 14 days off the team tier is withheld, a strict-mode domain's
// envelope is b.<domain>, and each through the real engine and the sidecar's own sender, whose signature is under
// the From's domain. Every name is synthetic.

package smtpedgeservice_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// The world's custom domains: one verified, and one the network added but has not proven.
const (
	testCustomDomain   = "brand.example"
	testUnprovenDomain = "pending.example"
)

// Pro's numbers on the team tier, as Quota.Limits names a Team network.
func teamLimits() *sidecar.QuotaLimits {
	limits := proLimits()
	limits.Tier = "team"
	return limits
}

// The gate world's network on the team tier.
func newCustomDomainGateWorld(t *testing.T) *gateWorld {
	g := newGateWorld(t)
	g.facts.Limits = teamLimits()
	g.reload()
	return g
}

func TestSmtpGateCustomDomainSendsOnTheTeamTier(t *testing.T) {
	g := newCustomDomainGateWorld(t)
	decision := g.expect(testCustomDomain, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	// not strict: the network's own envelope, which the sender's bounce address is at
	if decision.EnvelopeDomain != "b.n1.root.example" || decision.Burner || decision.Label != "" || decision.Tier != "team" {
		t.Fatalf("decision %+v", decision)
	}
	// a name the network spelled with a final dot, or in capitals, is the same verified domain
	g.facts.VerifiedDomains = []string{"Brand.Example."}
	g.reload()
	g.expect(testCustomDomain, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
}

func TestSmtpGateCustomDomainUnverifiedIsDenied(t *testing.T) {
	g := newCustomDomainGateWorld(t)
	// added and not yet proven, so not among the verified domains the feed loads
	g.expect(testUnprovenDomain, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
	// a subdomain of a verified domain is not that domain
	g.expect("mail."+testCustomDomain, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
	// the daily recheck dropped it: the feed's next load names it no more
	g.facts.VerifiedDomains = nil
	g.reload()
	g.expect(testCustomDomain, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
}

// Another network's verified domain is in no fact of this one's, whatever its tier.
func TestSmtpGateCustomDomainOfAnotherNetworkIsDenied(t *testing.T) {
	g := newCustomDomainGateWorld(t)
	otherNetworkId := sidecar.NewId()
	g.gate.SetFacts(otherNetworkId, &smtpedgeservice.SmtpGateFacts{
		MailEnableTime:  g.now.Add(-48 * time.Hour),
		Label:           "n2",
		VerifiedDomains: []string{"other-brand.example"},
		Limits:          teamLimits(),
	})
	g.expect("other-brand.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
}

// A verified name at or below <root> is no custom domain: the zone row answers the network's own names.
func TestSmtpGateCustomDomainUnderTheRootIsNoCustomDomain(t *testing.T) {
	g := newCustomDomainGateWorld(t)
	g.facts.VerifiedDomains = []string{"n2.root.example", "sub.n1.root.example", "root.example"}
	g.reload()
	for _, from := range g.facts.VerifiedDomains {
		g.expect(from, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
	}
}

// §20.7's custom domains row: off the team tier a domain's mail From is withheld 14 days after the downgrade, its
// web hosts beside it, and a renewal sends again at the next preamble; the network's own zone sends throughout.
func TestSmtpGateCustomDomainWithheldAfterTheDowngradesGrace(t *testing.T) {
	g := newGateWorld(t)
	// left team 13 days ago: the withholding is a day off
	g.facts.CustomDomainWithholdTime = g.now.Add(24 * time.Hour)
	g.reload()
	g.expect(testCustomDomain, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	// the 14 days are up
	g.facts.CustomDomainWithholdTime = g.now
	g.reload()
	g.expect(testCustomDomain, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "custom_domain_withheld")
	g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
	// a network that left no tier, off the team tier, sends From none
	g.facts.CustomDomainWithholdTime = time.Time{}
	g.reload()
	g.expect(testCustomDomain, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "custom_domain_withheld")
	// an unverified domain is refused as unverified first, whatever the tier
	g.expect(testUnprovenDomain, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
	// a renewal puts the tier back
	g.facts.Limits = teamLimits()
	g.reload()
	g.expect(testCustomDomain, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
}

func TestSmtpCustomDomainSendable(t *testing.T) {
	now := time.Date(2026, time.November, 20, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		tier         string
		withholdTime time.Time
		sendable     bool
	}{
		{tier: "team", sendable: true},
		{tier: "team", withholdTime: now.Add(-time.Hour), sendable: true},
		{tier: "pro", withholdTime: now.Add(time.Nanosecond), sendable: true},
		{tier: "pro", withholdTime: now, sendable: false},
		{tier: "pro", sendable: false},
		{tier: "free", withholdTime: now.Add(time.Hour), sendable: true},
		{tier: "free", sendable: false},
		{tier: "", sendable: false},
	}
	for _, c := range cases {
		if got := smtpedgeservice.SmtpCustomDomainSendable(c.tier, c.withholdTime, now); got != c.sendable {
			t.Errorf("%q until %v: %t, want %t", c.tier, c.withholdTime, got, c.sendable)
		}
	}
}

// Strict mode (§15.4) moves a custom domain's envelope to b.<domain>: only that domain's, only while it is verified
// and sendable, and never from anything the sidecar declares.
func TestSmtpGateStrictCustomDomainTakesItsOwnEnvelope(t *testing.T) {
	g := newCustomDomainGateWorld(t)
	g.facts.VerifiedDomains = []string{testCustomDomain, "plain.example"}
	g.facts.StrictDomains = []string{testCustomDomain, testUnprovenDomain}
	g.reload()
	if decision := g.expect(testCustomDomain, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, ""); decision.EnvelopeDomain != "b."+testCustomDomain {
		t.Fatalf("strict: envelope %s", decision.EnvelopeDomain)
	}
	if decision := g.expect("plain.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, ""); decision.EnvelopeDomain != "b.n1.root.example" {
		t.Fatalf("not strict: envelope %s", decision.EnvelopeDomain)
	}
	// strict mode concerns custom domains alone: the network's own zones keep its envelope
	if decision := g.expect("n1.root.example", 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, ""); decision.EnvelopeDomain != "b.n1.root.example" {
		t.Fatalf("the network's zone: envelope %s", decision.EnvelopeDomain)
	}
	// strict names no domain into sending
	g.expect(testUnprovenDomain, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
	// a withheld strict domain is withheld
	g.facts.Limits = proLimits()
	g.reload()
	g.expect(testCustomDomain, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "custom_domain_withheld")
}

// A burner lives under the network's zones alone: a burner's From under a custom domain is no burner of the network.
func TestSmtpGateBurnerUnderACustomDomainIsDenied(t *testing.T) {
	g := newCustomDomainGateWorld(t)
	g.expect("otter-4821."+testCustomDomain, sidecar.SmtpFlagBurner, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
	g.expect(testCustomDomain, sidecar.SmtpFlagBurner, protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, "from_domain")
}

// The engine world's network on the team tier with testCustomDomain verified, strict as asked.
func newCustomDomainEngineWorld(t *testing.T, strict bool, limits *sidecar.QuotaLimits, withholdTime func(now time.Time) time.Time) *edgeWorld {
	t.Helper()
	return newTestEngineWorld(t, func(world *edgeWorld) {
		facts := &smtpedgeservice.SmtpGateFacts{
			MailEnableTime:  world.clock.Now().Add(-48 * time.Hour),
			Label:           testLabel,
			VerifiedDomains: []string{testCustomDomain},
			ReportToken:     strings.Repeat("a", 26),
			Limits:          limits,
		}
		if strict {
			facts.StrictDomains = []string{testCustomDomain}
		}
		if withholdTime != nil {
			facts.CustomDomainWithholdTime = withholdTime(world.clock.Now())
		}
		world.gate.SetFacts(world.networkId, facts)
	})
}

// One message from fromDomain to bob at dest.example, its envelope sender at envelopeDomain.
func testCustomDomainMessage(w *edgeWorld, effectKey byte, fromDomain string, envelopeDomain string) *sidecar.SmtpOutboundMessage {
	message := testEngineMessage(w, effectKey)
	message.Sender = "bounce-1@" + envelopeDomain
	message.Message = []byte("From: Alice <alice@" + fromDomain + ">\r\nTo: bob@" + testRecipientDomain + "\r\nSubject: from the brand\r\n" +
		"Message-ID: <qvsc2zbwd5c3m5rbnvzxjzpnay@" + fromDomain + ">\r\n\r\nA body line.\r\n")
	return message
}

// The selector a DKIM-Signature header in message names under d=domain, "" for none.
func testDkimSelectorUnder(message []byte, domain string) string {
	for _, line := range bytes.Split(message, []byte("\r\n")) {
		_, rest, ok := bytes.Cut(line, []byte("; d="+domain+"; s="))
		if ok && bytes.HasPrefix(line, []byte("DKIM-Signature: ")) {
			selector, _, _ := bytes.Cut(rest, []byte(";"))
			return string(selector)
		}
	}
	return ""
}

// A verified domain sends through the engine on the team tier: the sidecar signs under a selector of the From's own
// domain (Z5's d=), the preamble declares that selector, and MAIL FROM stays at the network's envelope.
func TestSmtpSenderSendsFromATeamCustomDomainThroughTheEngine(t *testing.T) {
	w := newCustomDomainEngineWorld(t, false, teamLimits(), nil)
	dialer := &testEngineDialer{w: w}
	sender, prover, senderLog := newTestEngineSender(t, w, dialer)
	result, err := sender.Send(context.Background(), testCustomDomainMessage(w, 0x51, testCustomDomain, "b."+testLabel+"."+testRoot))
	if err != nil {
		t.Fatal(err)
	}
	if outcome := result.Domains[0]; outcome.Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("outcome %+v; the sender logged %q; the prover saw %+v", outcome, senderLog.Lines(), prover.Sends())
	}
	dialer.serving.Wait()
	transactions := w.mx.Transactions()
	if len(transactions) != 1 || transactions[0].Sender != "<bounce-1@b."+testLabel+"."+testRoot+">" {
		t.Fatalf("transactions %+v", transactions)
	}
	selector := testDkimSelectorUnder(transactions[0].Message, testCustomDomain)
	if selector == "" || testDkimSelectorUnder(transactions[0].Message, testLabel+"."+testRoot) != "" {
		t.Fatalf("the message as taken signs under no selector of %s alone: %s", testCustomDomain, transactions[0].Message)
	}
	sessions := w.verifier.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("%d sessions", len(sessions))
	}
	preamble := sessions[0].Preamble()
	if preamble.HeaderFromDomain != testCustomDomain || preamble.DkimSelector != selector || preamble.EnvelopeDomain != "b."+testLabel+"."+testRoot {
		t.Fatalf("the session's preamble %+v", preamble)
	}
	// Feedback-ID names the team tier
	if !bytes.Contains(transactions[0].Message, []byte("Feedback-ID: n:t:")) {
		t.Errorf("the message as taken: %s", transactions[0].Message)
	}
}

// Strict mode's envelope: the edge derives b.<domain> from the network's facts, the session holds Z4 to it, and the
// MX takes MAIL FROM there.
func TestSmtpSenderStrictCustomDomainEnvelopeThroughTheEngine(t *testing.T) {
	w := newCustomDomainEngineWorld(t, true, teamLimits(), nil)
	dialer := &testEngineDialer{w: w}
	sender, prover, senderLog := newTestEngineSender(t, w, dialer)
	result, err := sender.Send(context.Background(), testCustomDomainMessage(w, 0x52, testCustomDomain, "b."+testCustomDomain))
	if err != nil {
		t.Fatal(err)
	}
	if outcome := result.Domains[0]; outcome.Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("outcome %+v; the sender logged %q; the prover saw %+v", outcome, senderLog.Lines(), prover.Sends())
	}
	dialer.serving.Wait()
	sessions := w.verifier.Sessions()
	if len(sessions) != 1 || sessions[0].Preamble().EnvelopeDomain != "b."+testCustomDomain {
		t.Fatalf("the session's envelope: %d sessions", len(sessions))
	}
	transactions := w.mx.Transactions()
	if len(transactions) != 1 || transactions[0].Sender != "<bounce-1@b."+testCustomDomain+">" {
		t.Fatalf("transactions %+v", transactions)
	}
}

// An unverified domain and a withheld one are DENIED before any MX is dialed, and the sender fails the message with
// a DSN rather than holding it.
func TestSmtpSenderCustomDomainRefusalsReachNoMx(t *testing.T) {
	cases := []struct {
		name         string
		fromDomain   string
		limits       *sidecar.QuotaLimits
		withholdTime func(now time.Time) time.Time
		reason       string
	}{
		{name: "unverified", fromDomain: testUnprovenDomain, limits: teamLimits(), reason: "from_domain"},
		{name: "withheld", fromDomain: testCustomDomain, limits: proLimits(), withholdTime: func(now time.Time) time.Time { return now.Add(-time.Minute) }, reason: "custom_domain_withheld"},
	}
	for _, c := range cases {
		w := newCustomDomainEngineWorld(t, false, c.limits, c.withholdTime)
		sender, _, _ := newTestEngineSender(t, w, &testEngineDialer{w: w})
		result, err := sender.Send(context.Background(), testCustomDomainMessage(w, 0x53, c.fromDomain, "b."+testLabel+"."+testRoot))
		if err != nil {
			t.Fatal(err)
		}
		if outcome := result.Domains[0]; outcome.Outcome != sidecar.SmtpOutcomeFailed {
			t.Errorf("%s: outcome %+v", c.name, outcome)
		}
		if dials := w.world.Dials(); len(dials) != 0 {
			t.Errorf("%s: dialed %v", c.name, dials)
		}
		if len(w.verifier.Sessions()) != 0 {
			t.Errorf("%s: a session opened", c.name)
		}
		// the gate's own row answered, as one preamble shows
		preamble := w.preamble()
		preamble.HeaderFromDomain = c.fromDomain
		if outcome, result := w.send(preamble); result.GetCode() != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED) || outcome.Reason != c.reason {
			t.Errorf("%s: answered %d (%s)", c.name, result.GetCode(), outcome.Reason)
		}
	}
}
