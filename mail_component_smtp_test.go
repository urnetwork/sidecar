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

// Exercise the stock sender's lifecycle with an enrolled memory instance and the member's verified state.
func TestMailComponentSmtpUsesLocalEnableAndTheMembersMailbox(t *testing.T) {
	world := newMailSendResultTestWorld(t)
	client := world.client
	instance, _, _ := enrolledInstance(t)
	prover := &mailComponentIdleProver{entered: make(chan struct{}, 1)}
	settings := DefaultSidecarSettings()
	settings.Connect.SmtpProver = prover
	client.sidecar = &Sidecar{instance: instance, networkId: &testNetworkId, settings: settings}
	client.setNetworkRow(testMailIngestNetwork())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	run := &mailComponentRun{ctx: ctx, cancel: cancel, env: &SidecarEnv{
		Ctx: ctx, SidecarApi: &SidecarApi{}, Subprotocol: newTestSubprotocol(t, nil).subprotocol,
	}}
	client.componentRun = run
	defer client.replaceSmtp(run, nil)
	binding, _, err := client.bound()
	if err != nil {
		t.Fatal(err)
	}
	client.enabledLocally = false
	client.setNetworkEnabled(true)
	client.passSmtp(run, binding)
	if run.smtp != nil {
		t.Fatal("network enable alone started the local prover")
	}
	client.enabledLocally = true
	client.passSmtp(run, binding)
	smtp := run.smtp
	if smtp == nil || smtp.mailboxId != world.mailboxId || smtp.memberId != world.member {
		t.Fatal("the enabled prover host did not attach the member's mailbox")
	}
	binding, _, err = client.bound()
	if err != nil || binding.Sender != smtp.sender || binding.BurnerSelectors != smtp.dkim || smtp.dkim.domainAnswers() == nil || smtp.dkim.domainAnswers().Root != testMailIngestRoot {
		t.Fatal("the active sender or its DKIM domain answers are missing")
	}
	select {
	case <-prover.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	client.passSmtp(run, binding)
	if run.smtp != smtp {
		t.Fatal("another pass replaced an active sender")
	}
	client.replaceSmtp(run, nil)
	binding, _, err = client.bound()
	if err != nil || binding.Sender != nil || binding.BurnerSelectors != nil {
		t.Fatal("the stopped sender remained bound")
	}
}
