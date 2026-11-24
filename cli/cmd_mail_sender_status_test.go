// The sender part of mail.status against a fake daemon: ur mail status, and ur status's mail lines, print why this
// device's sender does not run where it does not, a test binary's refusal of the public resolvers included, and that it
// sends where it runs; a reply from a daemon that says nothing of a sender prints no sender line.

package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// Sets the status the fake daemon's mail client answers.
func (self *testUrMailClient) setStatus(status *sidecar.MailClientStatus) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.status = status
}

// A sender's problem reaches ur mail status and ur status, and a running sender prints as sending with no problem.
func TestUrMailStatusPrintsTheSender(t *testing.T) {
	refused := &sidecar.MailClientStatus{
		Enabled: true,
		Network: &sidecar.MailNetworkStatus{Enabled: true},
		Sender:  sidecar.MailClientSenderStatus{Problem: sidecar.ErrMailSenderPublicResolver.Error()},
	}
	client := &testUrMailClient{status: refused}
	daemon := startTestControlDaemon(t, &testUrMailTarget{client: client}, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	ctx := context.Background()
	if code := cli.main(ctx, []string{"ur", "mail", "status"}); code != urExitOk {
		t.Fatalf("status: exit %d", code)
	}
	want := "sender:     not sending: " + sidecar.ErrMailSenderPublicResolver.Error() + "\n"
	if out := stdout.String(); !strings.Contains(out, want) {
		t.Fatalf("ur mail status printed %q", out)
	}
	stdout.Reset()
	printUrStatusMail(ctx, cli)
	if out := stdout.String(); !strings.Contains(out, want) {
		t.Fatalf("ur status's mail lines %q", out)
	}
	running := *refused
	running.Sender = sidecar.MailClientSenderStatus{Running: true}
	client.setStatus(&running)
	stdout.Reset()
	if code := cli.main(ctx, []string{"ur", "mail", "status"}); code != urExitOk {
		t.Fatalf("status: exit %d", code)
	}
	if out := stdout.String(); !strings.Contains(out, "sender:     sending\n") {
		t.Fatalf("with the sender running, ur mail status printed %q", out)
	}
}

// The daemon's reply carries the sender's part as Status gave it, and a reply with none, a daemon's from before the
// part, prints no sender line rather than a sender that does not run.
func TestUrMailStatusReplyCarriesTheSender(t *testing.T) {
	reply := urMailStatusReplyOf(&sidecar.MailClientStatus{Sender: sidecar.MailClientSenderStatus{Problem: "this host composes no sender"}})
	if reply.Sender == nil || reply.Sender.Running || reply.Sender.Problem != "this host composes no sender" {
		t.Fatalf("the reply's sender %+v", reply.Sender)
	}
	if lines := formatUrMailStatus(reply); !slices.Contains(lines, "sender:     not sending: this host composes no sender") {
		t.Errorf("the lines %q", lines)
	}
	for _, line := range formatUrMailStatus(&urMailStatusReply{Enabled: true, NetworkKnown: true}) {
		if strings.HasPrefix(line, "sender:") {
			t.Errorf("a reply with no sender part printed %q", line)
		}
	}
}
