package main

import (
	"context"
	"strings"
	"testing"
)

// A daemon target whose hosted network keeps one approved recipient.
type testUrMailRecipientsTarget struct {
	testUrDaemonTarget
	// the pairs that stand, as "<alias> <recipient>"
	approved map[string]bool
	networks []string
}

func (self *testUrMailRecipientsTarget) removeMailRecipient(ctx context.Context, network string, alias string, recipient string) (bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networks = append(self.networks, network)
	pair := alias + " " + recipient
	stood := self.approved[pair]
	delete(self.approved, pair)
	return stood, nil
}

func (self *testUrMailRecipientsTarget) stands(alias string, recipient string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.approved[alias+" "+recipient]
}

// A yes on the terminal removes the pair's record through the daemon, --network reaching the target; a pair with no
// record changes nothing and says so.
func TestUrMailRecipientsRemoveTakesAYesOnTheTerminal(t *testing.T) {
	alias, recipient := "ann@acme.root.example", "someone@outside.example"
	target := &testUrMailRecipientsTarget{approved: map[string]bool{alias + " " + recipient: true}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	tty := &testTty{lines: []string{"y", "y"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "mail", "recipients", "rm", alias, recipient, "--network=acme"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if target.stands(alias, recipient) || !strings.Contains(stdout.String(), "removed") {
		t.Fatalf("the record stands, or nothing said so: %q", stdout.String())
	}
	if !strings.Contains(tty.written.String(), alias) || !strings.Contains(tty.written.String(), recipient) {
		t.Fatalf("the terminal's question names no pair: %q", tty.written.String())
	}
	if len(target.networks) != 1 || target.networks[0] != "acme" {
		t.Fatalf("networks %v", target.networks)
	}
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "mail", "recipients", "rm", alias, recipient}); code != urExitOk || !strings.Contains(stdout.String(), "no approval stood") {
		t.Fatalf("a pair with no record: exit %d: %q", code, stdout.String())
	}
}

// Without a yes on the terminal, or without a terminal, nothing is removed; and mail.recipients.rm is a Confirm
// method, so a call that does not say a person confirmed is refused before it removes anything.
func TestUrMailRecipientsRemoveTakesNothingWithoutAPerson(t *testing.T) {
	alias, recipient := "ann@acme.root.example", "someone@outside.example"
	target := &testUrMailRecipientsTarget{approved: map[string]bool{alias + " " + recipient: true}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "mail", "recipients", "rm", alias, recipient}); code != urExitFailed {
		t.Fatalf("no terminal: exit %d", code)
	}
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "mail", "recipients", "rm", alias, recipient}); code != urExitOk || !strings.Contains(stdout.String(), "nothing changed") {
		t.Fatalf("a no: exit %d: %q", code, stdout.String())
	}
	reply := &urMailRecipientsRemoveReply{}
	params := &urMailRecipientsRemoveParams{Alias: alias, Recipient: recipient}
	if err := cli.callDaemon(context.Background(), urMethodMailRecipientsRemove, params, false, reply); err == nil {
		t.Fatal("an unconfirmed mail.recipients.rm removed a record")
	}
	if err := cli.callDaemon(context.Background(), urMethodMailRecipientsRemove, &urMailRecipientsRemoveParams{Alias: alias}, true, reply); err == nil {
		t.Fatal("mail.recipients.rm took a call naming no recipient")
	}
	if !target.stands(alias, recipient) || len(target.networks) != 0 {
		t.Fatalf("the record was touched: networks %v", target.networks)
	}
}
