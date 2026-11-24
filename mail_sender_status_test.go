//go:build !sidecar_http && !ios_extension && !js

// The sender's part of MailClient.Status (MailClientSenderStatus), from inside: the mail component's pass keeps why no
// sender runs on this device where none does, as it keeps the receiver's Problem, so a sender the test binary's guard
// refuses, or whose composition fails for any other reason, shows in Status, and through it in `ur mail status`,
// `ur status` and the e2e world's status, where it showed only in a V(1) log. A running sender says nothing is wrong;
// each gate a device does not pass says which; a refusal clears at the pass that composes the sender; and a generation
// another has replaced says nothing over the one that runs, while one Close ended has the last word, its stop's. The
// senders here ask resolvers the tests name (mail_sender_doh_seam_test.go's), and nothing dials.

package sidecar

import (
	"context"
	"errors"
	"testing"
)

// The sender part of client's status, as Status answers it.
func testMailSenderStatus(t *testing.T, client *MailClient) MailClientSenderStatus {
	t.Helper()
	status, err := client.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return status.Sender
}

// In a test binary, a prover host whose send settings name no resolver runs no sender, and its status says why: the
// guard's refusal, which the pass logged at V(1) alone before.
func TestMailSenderStatusReportsTheGuardsRefusal(t *testing.T) {
	prover := &mailComponentIdleProver{entered: make(chan struct{}, 1)}
	sender := newTestMailSenderRun(t, prover, nil)
	sender.client.enabledLocally = true
	sender.client.passSmtp(sender.run, sender.binding)
	if sender.run.smtp != nil {
		t.Fatal("a prover host on the default resolvers composed a sender in a test")
	}
	if status := testMailSenderStatus(t, sender.client); status.Running || status.Problem != ErrMailSenderPublicResolver.Error() {
		t.Fatalf("the refused sender's status %+v", status)
	}
}

// Every other failure of the composition says why as well: the resolver its settings name answering an error, and a
// part built after the resolver refusing, here the sender over settings out of range.
func TestMailSenderStatusReportsEveryCompositionFailure(t *testing.T) {
	prover := &mailComponentIdleProver{entered: make(chan struct{}, 1)}
	refused := errors.New("the test's DNS is not up")
	sender := newTestMailSenderRun(t, prover, func() (*MailSenderResolver, error) {
		return nil, refused
	})
	sender.client.enabledLocally = true
	sender.client.passSmtp(sender.run, sender.binding)
	if status := testMailSenderStatus(t, sender.client); sender.run.smtp != nil || status.Running || status.Problem != refused.Error() {
		t.Fatalf("with its resolver refused, a sender %t and the status %+v", sender.run.smtp != nil, status)
	}
	resolvers := &testMailSenderResolvers{}
	sender.client.settings.Send.ResolverFactory = resolvers.factory
	sender.client.sidecar.settings.Connect.SmtpSender = &SmtpSenderSettings{}
	outOfRange := (&SmtpSenderSettings{}).validate()
	if outOfRange == nil {
		t.Fatal("empty sender settings validate")
	}
	sender.client.passSmtp(sender.run, sender.binding)
	if status := testMailSenderStatus(t, sender.client); sender.run.smtp != nil || status.Running || status.Problem != outOfRange.Error() {
		t.Fatalf("with settings out of range, a sender %t and the status %+v, not %q", sender.run.smtp != nil, status, outOfRange)
	}
	if built, releases := resolvers.snapshot(); len(built) != 1 || releases[0] != 1 {
		t.Errorf("the failed composition built %d resolvers, released %v", len(built), releases)
	}
}

// A refused sender's problem clears at the pass that composes it, once the device names its own DNS, and a running
// sender says nothing is wrong, at that pass and at each later one that keeps it.
func TestMailSenderStatusReportsNoProblemWhileRunning(t *testing.T) {
	prover := &mailComponentIdleProver{entered: make(chan struct{}, 1)}
	sender := newTestMailSenderRun(t, prover, nil)
	sender.client.enabledLocally = true
	sender.client.passSmtp(sender.run, sender.binding)
	if status := testMailSenderStatus(t, sender.client); status.Problem != ErrMailSenderPublicResolver.Error() {
		t.Fatalf("the refused sender's status %+v", status)
	}
	resolvers := &testMailSenderResolvers{}
	sender.client.settings.Send.ResolverFactory = resolvers.factory
	sender.client.passSmtp(sender.run, sender.binding)
	smtp := sender.run.smtp
	if smtp == nil {
		t.Fatalf("no sender on a named resolver: %v", sender.world.log.snapshot())
	}
	if status := testMailSenderStatus(t, sender.client); status != (MailClientSenderStatus{Running: true}) {
		t.Fatalf("the running sender's status %+v", status)
	}
	sender.client.passSmtp(sender.run, sender.binding)
	if status := testMailSenderStatus(t, sender.client); sender.run.smtp != smtp || status != (MailClientSenderStatus{Running: true}) {
		t.Fatalf("at a later pass the same sender %t, the status %+v", sender.run.smtp == smtp, status)
	}
}

// Each gate this device does not pass says which, and a sender a gate closes stops, its status saying why: mail on for
// the network but enabled on another device alone, then mail off, then a host with no prover, whose internet mail
// waits in the member's outbox for one.
func TestMailSenderStatusNamesTheGateNotPassed(t *testing.T) {
	prover := &mailComponentIdleProver{entered: make(chan struct{}, 1)}
	resolvers := &testMailSenderResolvers{}
	sender := newTestMailSenderRun(t, prover, resolvers.factory)
	client, run := sender.client, sender.run
	client.passSmtp(run, sender.binding)
	if status := testMailSenderStatus(t, client); run.smtp != nil || status.Running ||
		status.Problem != "mail was enabled on another device: ur mail enable on this one sends from it" {
		t.Fatalf("enabled on another device, a sender %t and the status %+v", run.smtp != nil, status)
	}
	client.enabledLocally = true
	client.passSmtp(run, sender.binding)
	if status := testMailSenderStatus(t, client); run.smtp == nil || !status.Running {
		t.Fatalf("enabled here, a sender %t and the status %+v", run.smtp != nil, status)
	}
	// mail off for the network, as GET /mail/status reads it, and this device's enable gone
	func() {
		sender.world.api.stateLock.Lock()
		defer sender.world.api.stateLock.Unlock()
		sender.world.api.status = &MailNetworkStatus{}
	}()
	client.setNetworkEnabled(false)
	client.enabledLocally = false
	client.passSmtp(run, sender.binding)
	if status := testMailSenderStatus(t, client); run.smtp != nil || status.Running || status.Problem != "mail is off" {
		t.Fatalf("with mail off, a sender %t and the status %+v", run.smtp != nil, status)
	}
	if built, releases := resolvers.snapshot(); len(built) != 1 || releases[0] != 1 {
		t.Errorf("the stopped sender built %d resolvers, released %v", len(built), releases)
	}
	client.enabledLocally = true
	client.sidecar.settings.Connect.SmtpProver = nil
	client.passSmtp(run, sender.binding)
	if status := testMailSenderStatus(t, client); run.smtp != nil || status.Running ||
		status.Problem != "this device is no prover host: its internet mail waits in the member's outbox for one" {
		t.Fatalf("with no prover, a sender %t and the status %+v", run.smtp != nil, status)
	}
}

// A generation another has replaced says nothing over the one that runs: the new generation's first pass composes its
// sender, and the old generation's stop, which joins its own sender's workers and so can end after that pass, leaves
// the new generation's status standing.
func TestMailSenderStatusOfAReplacedGenerationDoesNotStand(t *testing.T) {
	prover := &mailComponentIdleProver{entered: make(chan struct{}, 1)}
	resolvers := &testMailSenderResolvers{}
	sender := newTestMailSenderRun(t, prover, resolvers.factory)
	client, previous := sender.client, sender.run
	client.enabledLocally = true
	client.passSmtp(previous, sender.binding)
	if previous.smtp == nil {
		t.Fatalf("no sender on a named resolver: %v", sender.world.log.snapshot())
	}
	// the next generation, installed as Attach installs it, and its first pass
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	next := &mailComponentRun{ctx: ctx, cancel: cancel, env: previous.env}
	func() {
		client.stateLock.Lock()
		defer client.stateLock.Unlock()
		client.componentRun = next
	}()
	t.Cleanup(func() { client.replaceSmtp(next, nil) })
	client.passSmtp(next, sender.binding)
	if next.smtp == nil || next.smtp == previous.smtp {
		t.Fatalf("the next generation composed no sender of its own: %v", sender.world.log.snapshot())
	}
	client.stopRun(previous)
	if status := testMailSenderStatus(t, client); previous.smtp != nil || status != (MailClientSenderStatus{Running: true}) {
		t.Fatalf("after the replaced generation's stop, its sender %t and the status %+v", previous.smtp != nil, status)
	}
}

// With no generation running, as after Close, the generation that ran has the last word: the stop its goroutine runs
// as Close ends it says no sender runs.
func TestMailSenderStatusAfterCloseSaysNoSenderRuns(t *testing.T) {
	prover := &mailComponentIdleProver{entered: make(chan struct{}, 1)}
	resolvers := &testMailSenderResolvers{}
	sender := newTestMailSenderRun(t, prover, resolvers.factory)
	client, run := sender.client, sender.run
	client.enabledLocally = true
	client.passSmtp(run, sender.binding)
	if status := testMailSenderStatus(t, client); run.smtp == nil || !status.Running {
		t.Fatalf("a sender %t and the status %+v", run.smtp != nil, status)
	}
	client.Close()
	// what runGeneration's deferred stop runs once Close has cancelled the generation
	client.stopRun(run)
	if status := testMailSenderStatus(t, client); run.smtp != nil || status != (MailClientSenderStatus{}) {
		t.Fatalf("after Close, a sender %t and the status %+v", run.smtp != nil, status)
	}
}
