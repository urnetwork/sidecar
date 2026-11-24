//go:build !sidecar_http && !ios_extension && !js

package sidecar

import (
	"context"
	"testing"
)

// An idle-only prover with no ready keys. An empty mailbox must never start a connection.
type mailComponentIdleProver struct {
	SmtpProver
	entered chan struct{}
}

func (self *mailComponentIdleProver) KeySet() []byte { return nil }

func (self *mailComponentIdleProver) PrepareKeys(ctx context.Context) (*SmtpProverReadiness, error) {
	select {
	case self.entered <- struct{}{}:
	default:
	}
	return &SmtpProverReadiness{Done: true}, nil
}

// Exercise the stock sender's lifecycle with an enrolled memory instance and the member's verified state, its lookups
// on a resolver the test names (newTestMailSenderRun), since this test binary refuses the default public ones.
func TestMailComponentSmtpUsesLocalEnableAndTheMembersMailbox(t *testing.T) {
	prover := &mailComponentIdleProver{entered: make(chan struct{}, 1)}
	resolvers := &testMailSenderResolvers{}
	sender := newTestMailSenderRun(t, prover, resolvers.factory)
	world, client, run, binding := sender.world, sender.client, sender.run, sender.binding
	client.passSmtp(run, binding)
	if run.smtp != nil {
		t.Fatal("network enable alone started the local prover")
	}
	client.enabledLocally = true
	client.passSmtp(run, binding)
	smtp := run.smtp
	if smtp == nil || smtp.mailboxId != world.mailboxId || smtp.memberId != world.member {
		t.Fatalf("the enabled prover host did not attach the member's mailbox: %v", world.log.snapshot())
	}
	binding, _, err := client.bound()
	if err != nil || binding.Sender != smtp.sender || binding.BurnerSelectors != smtp.dkim || smtp.dkim.domainAnswers() == nil || smtp.dkim.domainAnswers().Root != testMailIngestRoot {
		t.Fatal("the active sender or its DKIM domain answers are missing")
	}
	testAwait(t, prover.entered, "the member's prover host")
	client.passSmtp(run, binding)
	if run.smtp != smtp {
		t.Fatal("another pass replaced an active sender")
	}
	client.replaceSmtp(run, nil)
	binding, _, err = client.bound()
	if err != nil || binding.Sender != nil || binding.BurnerSelectors != nil {
		t.Fatal("the stopped sender remained bound")
	}
	if built, releases := resolvers.snapshot(); len(built) != 1 || releases[0] != 1 {
		t.Errorf("one sender built %d resolvers, released %v", len(built), releases)
	}
}
