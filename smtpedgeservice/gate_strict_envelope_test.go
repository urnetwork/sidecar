// Strict mode's envelope as the edge and the sender each reach it (QD-1129; §14.6, §15.4, Z4, §14.7's cut): the gate
// derives envelope_domain from the network's strict domains in its facts, and MAIL's bounce address picks the sender's
// MAIL FROM from the same set as GET /mail/status names it, by the one rule (sidecar.SmtpStrictCustomDomain), so the
// two agree for a strict domain, a custom domain that is not strict, a subdomain under a strict domain, and a domain
// whose MX host is unmapped between two reads of the set. Through the real engine, the sender's per-attempt envelope
// (SmtpSenderArgs.Envelope) moves a message queued under one read to the envelope the edge derives at the next, where
// the queued envelope alone would put MAIL FROM away from the session's, which Z4 fails and the edge cuts. Every name
// is synthetic.

package smtpedgeservice_test

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// The local part the sender's bounce address takes in these tests: MAIL draws its token, and only the domain moves.
const testStrictEnvelopeLocal = "bounces+abc123"

// The network's zone the gate and engine worlds send from.
const testStrictEnvelopeNetworkZone = testLabel + "." + testRoot

// MAIL FROM's domain as the sender's bounce address picks it from GET /mail/status's strict domains
// (MailClient.BounceSender's rule).
func testStrictEnvelopeSenderDomain(fromDomain string, strictDomains []string) string {
	return sidecar.SmtpEnvelopeDomain(testStrictEnvelopeNetworkZone, sidecar.SmtpStrictCustomDomain(fromDomain, strictDomains, testRoot))
}

// The gate's envelope_domain and the sender's MAIL FROM agree at every read of the set, which the server serves the edge
// and the sender alike (model.GetSmtpStrictCustomDomains), whatever the read finds.
func TestSmtpStrictEnvelopeGateAndSenderAgree(t *testing.T) {
	g := newCustomDomainGateWorld(t)
	subdomain := "mail." + testCustomDomain
	g.facts.VerifiedDomains = []string{testCustomDomain, "plain.example", subdomain}
	networkEnvelope := "b." + testStrictEnvelopeNetworkZone
	reads := []struct {
		name   string
		strict []string
		from   string
		want   string
	}{
		{name: "a strict domain", strict: []string{testCustomDomain}, from: testCustomDomain, want: "b." + testCustomDomain},
		{name: "a custom domain that is not strict", strict: []string{testCustomDomain}, from: "plain.example", want: networkEnvelope},
		// the MX host at mx.brand.example makes brand.example strict and not mail.brand.example
		{name: "a subdomain under a strict domain", strict: []string{testCustomDomain}, from: subdomain, want: networkEnvelope},
		// one at mx.mail.brand.example makes both strict, and the set names both
		{name: "a subdomain the set names too", strict: []string{testCustomDomain, subdomain}, from: subdomain, want: "b." + subdomain},
		{name: "the network's own zone", strict: []string{testCustomDomain}, from: testStrictEnvelopeNetworkZone, want: networkEnvelope},
		// the MX host unmapped between two reads: each read agrees on its own set
		{name: "before the unmapping", strict: []string{testCustomDomain}, from: testCustomDomain, want: "b." + testCustomDomain},
		{name: "after the unmapping", strict: []string{}, from: testCustomDomain, want: networkEnvelope},
		{name: "mapped again", strict: []string{testCustomDomain}, from: testCustomDomain, want: "b." + testCustomDomain},
	}
	for _, read := range reads {
		g.facts.StrictDomains = slices.Clone(read.strict)
		g.reload()
		decision := g.expect(read.from, 0, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK, "")
		sender := testStrictEnvelopeSenderDomain(read.from, read.strict)
		if decision.EnvelopeDomain != read.want || sender != decision.EnvelopeDomain {
			t.Errorf("%s: the edge derives %s and the sender sends at %s, want %s", read.name, decision.EnvelopeDomain, sender, read.want)
		}
	}
}

// GET /mail/status as a sending host reads it in these tests: the strict domains the next read names.
type testStrictEnvelopeStatus struct {
	stateLock     sync.Mutex
	strictDomains []string
}

func (self *testStrictEnvelopeStatus) set(strictDomains ...string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.strictDomains = strictDomains
}

// MailClient.BounceSender's answer over this status: the bounce address at the envelope the rule picks now.
func (self *testStrictEnvelopeStatus) envelope(ctx context.Context, headerFromDomain string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return testStrictEnvelopeLocal + "@" + testStrictEnvelopeSenderDomain(headerFromDomain, self.strictDomains), nil
}

// newTestEngineSender's sender with envelope as its SmtpSenderArgs.Envelope, nil for none.
func newTestStrictEnvelopeSender(t *testing.T, w *edgeWorld, dialer sidecar.SmtpEdgeDialer, envelope func(ctx context.Context, headerFromDomain string) (string, error)) (*sidecar.SmtpSender, *captureLogger) {
	t.Helper()
	settings := sidecar.DefaultSmtpSenderSettings()
	store := sidecartest.NewFakeStore()
	anchors, err := sidecar.NewSmtpDnssecAnchors(w.world.TrustAnchorDs())
	if err != nil {
		t.Fatal(err)
	}
	zone := sidecartest.NewFakeMailZone(w.clock)
	pins := sidecar.NewSmtpPinStore(store.Root(), settings, w.clock, nil)
	policy := sidecar.NewSmtpTlsPolicy(sidecar.NewSmtpDane(anchors, w.clock, nil),
		sidecar.NewSmtpMtaSts(zone, w.world.MtaStsTransport(), store.Root(), settings, w.clock), pins,
		sidecar.NewSmtpTlsAllowanceStore(store.Root(), settings, w.clock), nil, zone, nil, settings, w.clock)
	senderLog := &captureLogger{}
	sender, err := sidecar.NewSmtpSender(&sidecar.SmtpSenderArgs{
		Dialer: dialer, Prover: sidecartest.NewFakeSmtpProver(nil), Policy: policy, Pins: pins,
		Dkim:     sidecar.NewSmtpDkimKeys(&testEngineSecrets{values: map[string][]byte{}}, testEnginePublisher{}, settings, w.clock, nil),
		Mailbox:  sidecartest.NewFakeSmtpMailbox(nil),
		Envelope: envelope,
		Settings: settings, Clock: w.clock, Log: senderLog,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.Close)
	return sender, senderLog
}

// The engine world's facts with strictDomains, the gate's next load after a strict-mode MX host's change.
func testStrictEnvelopeFacts(w *edgeWorld, strictDomains ...string) {
	w.gate.SetFacts(w.networkId, &smtpedgeservice.SmtpGateFacts{
		MailEnableTime:  w.clock.Now().Add(-48 * time.Hour),
		Label:           testLabel,
		VerifiedDomains: []string{testCustomDomain},
		StrictDomains:   strictDomains,
		ReportToken:     strings.Repeat("a", 26),
		Limits:          teamLimits(),
	})
}

// A message From the custom domain queued with its envelope sender at envelopeDomain, as MAIL queued it under the
// read of the set then.
func testStrictEnvelopeMessage(w *edgeWorld, effectKey byte, envelopeDomain string) *sidecar.SmtpOutboundMessage {
	message := testCustomDomainMessage(w, effectKey, testCustomDomain, envelopeDomain)
	message.Sender = testStrictEnvelopeLocal + "@" + envelopeDomain
	return message
}

// One send of message through the engine: the session's envelope_domain, which the edge derived, and the MAIL FROM
// the MX took.
func testStrictEnvelopeSend(t *testing.T, w *edgeWorld, dialer *testEngineDialer, sender *sidecar.SmtpSender, log *captureLogger, message *sidecar.SmtpOutboundMessage) (envelopeDomain string, mailFrom string) {
	t.Helper()
	sessionCount, transactionCount := len(w.verifier.Sessions()), len(w.mx.Transactions())
	result, err := sender.Send(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := result.Domains[0]; outcome.Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("outcome %+v; the sender logged %q", outcome, log.Lines())
	}
	dialer.serving.Wait()
	sessions, transactions := w.verifier.Sessions(), w.mx.Transactions()
	if len(sessions) != sessionCount+1 || len(transactions) != transactionCount+1 {
		t.Fatalf("%d sessions and %d transactions after %d and %d", len(sessions), len(transactions), sessionCount, transactionCount)
	}
	return sessions[sessionCount].Preamble().EnvelopeDomain, transactions[transactionCount].Sender
}

// A message queued while the domain was strict, its envelope sender at b.<domain>, is sent after the domain's MX host
// was unmapped: the sender asks for the envelope at the attempt, so MAIL FROM is where the edge now derives it, the
// network's own. A sender that took the queued envelope as it stood would send MAIL FROM at b.<domain> into a session
// whose envelope is the network's, the disagreement a real verifier fails (Z4) and the edge cuts (§14.7), two of which
// in 24 h halt the network (§14.8).
func TestSmtpSenderEnvelopeFollowsTheStrictSetThroughTheEngine(t *testing.T) {
	w := newTestEngineWorld(t, func(world *edgeWorld) {
		testStrictEnvelopeFacts(world, testCustomDomain)
	})
	status := &testStrictEnvelopeStatus{}
	status.set(testCustomDomain)
	dialer := &testEngineDialer{w: w}
	sender, senderLog := newTestStrictEnvelopeSender(t, w, dialer, status.envelope)
	queued := testStrictEnvelopeLocal + "@b." + testCustomDomain

	// the first read: the domain is strict, at the edge and at the sender
	envelopeDomain, mailFrom := testStrictEnvelopeSend(t, w, dialer, sender, senderLog, testStrictEnvelopeMessage(w, 0x61, "b."+testCustomDomain))
	if envelopeDomain != "b."+testCustomDomain || mailFrom != "<"+queued+">" {
		t.Fatalf("while strict: the edge derived %s and MAIL FROM was %s", envelopeDomain, mailFrom)
	}

	// the MX host unmapped: the gate's next load and the next read of GET /mail/status both name no strict domain
	testStrictEnvelopeFacts(w)
	status.set()
	message := testStrictEnvelopeMessage(w, 0x62, "b."+testCustomDomain)
	if message.Sender != queued {
		t.Fatalf("the queued envelope %s", message.Sender)
	}
	envelopeDomain, mailFrom = testStrictEnvelopeSend(t, w, dialer, sender, senderLog, message)
	if envelopeDomain != "b."+testStrictEnvelopeNetworkZone || mailFrom != "<"+testStrictEnvelopeLocal+"@b."+testStrictEnvelopeNetworkZone+">" {
		t.Fatalf("after the unmapping: the edge derived %s and MAIL FROM was %s", envelopeDomain, mailFrom)
	}

	// mapped again: back at b.<domain> on both ends
	testStrictEnvelopeFacts(w, testCustomDomain)
	status.set(testCustomDomain)
	envelopeDomain, mailFrom = testStrictEnvelopeSend(t, w, dialer, sender, senderLog, testStrictEnvelopeMessage(w, 0x63, "b."+testStrictEnvelopeNetworkZone))
	if envelopeDomain != "b."+testCustomDomain || mailFrom != "<"+queued+">" {
		t.Fatalf("mapped again: the edge derived %s and MAIL FROM was %s", envelopeDomain, mailFrom)
	}

	// the queued envelope alone: what the per-attempt envelope keeps from happening
	testStrictEnvelopeFacts(w)
	staleSender, staleLog := newTestStrictEnvelopeSender(t, w, dialer, nil)
	envelopeDomain, mailFrom = testStrictEnvelopeSend(t, w, dialer, staleSender, staleLog, testStrictEnvelopeMessage(w, 0x64, "b."+testCustomDomain))
	if envelopeDomain != "b."+testStrictEnvelopeNetworkZone || mailFrom != "<"+queued+">" {
		t.Fatalf("the queued envelope: the edge derived %s and MAIL FROM was %s", envelopeDomain, mailFrom)
	}
}

// An envelope that cannot be read holds the domain's send for its next retry, dialing nothing.
func TestSmtpSenderEnvelopeNotReadHoldsTheSend(t *testing.T) {
	w := newTestEngineWorld(t, func(world *edgeWorld) {
		testStrictEnvelopeFacts(world, testCustomDomain)
	})
	dialer := &testEngineDialer{w: w}
	refused := func(ctx context.Context, headerFromDomain string) (string, error) {
		return "", context.DeadlineExceeded
	}
	sender, _ := newTestStrictEnvelopeSender(t, w, dialer, refused)
	result, err := sender.Send(context.Background(), testStrictEnvelopeMessage(w, 0x65, "b."+testCustomDomain))
	if err != nil {
		t.Fatal(err)
	}
	if outcome := result.Domains[0]; outcome.Outcome != sidecar.SmtpOutcomeDeferred || outcome.RetryAfter <= 0 {
		t.Fatalf("outcome %+v", outcome)
	}
	dialer.serving.Wait()
	if len(w.verifier.Sessions()) != 0 || len(w.mx.Transactions()) != 0 {
		t.Fatalf("%d sessions and %d transactions", len(w.verifier.Sessions()), len(w.mx.Transactions()))
	}
}
