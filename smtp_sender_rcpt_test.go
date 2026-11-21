//go:build !sidecar_http && !ios_extension

package sidecar_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A non-pipelining MX stops at the first refusal. Another host must still send to the untried address.
func TestSmtpSenderRetriesAnUnansweredRecipientAfterRestart(t *testing.T) {
	script := sidecartest.DefaultMxScript()
	script.Keywords = []string{"CHUNKING"}
	script.RcptReplies["bad"] = "550 no such recipient"
	world := newTestSenderWorld(t, &testSenderOptions{script: script})
	bad, untried := "bad@"+testTlsDomain, "later@"+testTlsDomain
	message := world.message([]string{bad, untried}, nil, "body\r\n")
	outcome := testDomainOutcome(t, world.send(message), testTlsDomain)
	if outcome.Outcome != sidecar.SmtpOutcomeDeferred {
		t.Fatalf("first outcome: %+v", outcome)
	}
	dsns := world.mailbox.Dsns()
	if len(dsns) != 1 || !bytes.Contains(dsns[0].Dsn, []byte("Final-Recipient: rfc822; "+bad)) || bytes.Contains(dsns[0].Dsn, []byte("Final-Recipient: rfc822; "+untried)) {
		t.Fatalf("DSNs: %s", testDsnText(dsns))
	}
	other := newTestSenderWorld(t, nil)
	earlier, err := world.mailbox.ReadOutcomes(t.Context(), message.EffectKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.mailbox.WriteOutcomes(t.Context(), message.EffectKey, earlier); err != nil {
		t.Fatal(err)
	}
	other.tls.clock.Advance(outcome.RetryAfter)
	if got := testDomainOutcome(t, other.send(message), testTlsDomain); got.Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("retry: %+v", got)
	}
	transactions := other.mx.Transactions()
	if len(transactions) != 1 || !slices.Equal(transactions[0].Recipients, []string{"<" + untried + ">"}) || len(other.mailbox.Dsns()) != 0 {
		t.Fatalf("retry sent to %+v, DSNs %v", transactions, other.mailbox.Dsns())
	}
}

// A temporary refusal remains pending after another recipient received the message and a third permanently failed.
func TestSmtpSenderRetriesOnlyTheTemporaryRecipient(t *testing.T) {
	script := sidecartest.DefaultMxScript()
	script.RcptReplies["defer"] = "450 mailbox temporarily unavailable"
	script.RcptReplies["bad"] = "550 no such mailbox"
	world := newTestSenderWorld(t, &testSenderOptions{script: script})
	deferred := "defer@" + testTlsDomain
	message := world.message([]string{deferred, "bad@" + testTlsDomain, "ok@" + testTlsDomain}, nil, "body\r\n")
	outcome := testDomainOutcome(t, world.send(message), testTlsDomain)
	if outcome.Outcome != sidecar.SmtpOutcomeDeferred || len(world.mx.Transactions()) != 1 || len(world.mailbox.Dsns()) != 1 {
		t.Fatalf("first result: %+v, deliveries %v, DSNs %s", outcome, world.mx.Transactions(), testDsnText(world.mailbox.Dsns()))
	}
	other := newTestSenderWorld(t, nil)
	records, err := world.mailbox.ReadOutcomes(t.Context(), message.EffectKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.mailbox.WriteOutcomes(t.Context(), message.EffectKey, records); err != nil {
		t.Fatal(err)
	}
	other.tls.clock.Advance(outcome.RetryAfter)
	if got := testDomainOutcome(t, other.send(message), testTlsDomain); got.Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("retry: %+v", got)
	}
	tx := other.mx.Transactions()
	if len(tx) != 1 || !slices.Equal(tx[0].Recipients, []string{"<" + deferred + ">"}) {
		t.Fatalf("retry deliveries: %+v", tx)
	}
}
