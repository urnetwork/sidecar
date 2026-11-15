package main

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A keychain namespace in memory.
type testUrMailSecrets struct {
	stateLock sync.Mutex
	values    map[string][]byte
}

func (self *testUrMailSecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.values[name]
	if !ok {
		return nil, sidecar.ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *testUrMailSecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.values == nil {
		self.values = map[string][]byte{}
	}
	self.values[name] = bytes.Clone(value)
	return nil
}

func (self *testUrMailSecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.values, name)
	return nil
}

func (self *testUrMailSecrets) List(prefix string) ([]string, error) {
	return nil, nil
}

// A daemon target whose hosted network keeps a credential, with IMAP listening on loopback.
type testUrMailCredentialTarget struct {
	testUrDaemonTarget
	secrets    *testUrMailSecrets
	credential *sidecar.MailLocalCredential
	networks   []string
	starts     int
}

func newTestUrMailCredentialTarget(t *testing.T) *testUrMailCredentialTarget {
	t.Helper()
	secrets := &testUrMailSecrets{}
	credential, err := sidecar.NewMailLocalCredential(secrets)
	if err != nil {
		t.Fatal(err)
	}
	return &testUrMailCredentialTarget{secrets: secrets, credential: credential}
}

func (self *testUrMailCredentialTarget) mailCredential(network string) (*sidecar.MailLocalCredential, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networks = append(self.networks, network)
	return self.credential, nil
}

func (self *testUrMailCredentialTarget) startMailImap() (*sidecar.DaemonLocalListenerStatus, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.starts += 1
	return &sidecar.DaemonLocalListenerStatus{Service: sidecar.DaemonLocalImap, Addresses: []string{"127.0.0.1:17003"}}, nil
}

// The password line ur wrote to the terminal.
func testUrMailCredentialPassword(t *testing.T, written string) string {
	t.Helper()
	for _, line := range strings.Split(written, "\n") {
		if password, ok := strings.CutPrefix(strings.TrimSpace(line), "password"); ok {
			return strings.TrimSpace(password)
		}
	}
	t.Fatalf("no password on the terminal: %q", written)
	return ""
}

// The secret reaches the terminal alone, never stdout, and opens the network's mailbox through the verifier the
// daemon kept; IMAP opens, and --network reaches the target.
func TestUrMailCredentialShowsTheSecretOnTheTerminalAlone(t *testing.T) {
	target := newTestUrMailCredentialTarget(t)
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	tty := &testTty{lines: []string{"y"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "mail", "credential", "--network=acme"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	password := testUrMailCredentialPassword(t, tty.written.String())
	if strings.Contains(stdout.String(), password) || strings.Contains(stderr.String(), password) {
		t.Fatal("the secret reached stdout or stderr")
	}
	if !strings.Contains(stdout.String(), "mail credential made") || !strings.Contains(tty.written.String(), "127.0.0.1:17003") {
		t.Fatalf("stdout %q, terminal %q", stdout.String(), tty.written.String())
	}
	for name, value := range target.secrets.values {
		if bytes.Contains(value, []byte(password)) {
			t.Errorf("the keychain's %s holds the secret", name)
		}
	}
	login, err := sidecar.NewMailLocalLogin(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if login.Check(context.Background(), netip.MustParseAddr("127.0.0.1"), sidecar.MailLocalCredentialUser, password, []*sidecar.MailLocalCredential{target.credential}) != 0 {
		t.Fatal("the secret shown does not open the credential the daemon kept")
	}
	if len(target.networks) != 1 || target.networks[0] != "acme" || target.starts != 1 {
		t.Fatalf("networks %v, IMAP starts %d", target.networks, target.starts)
	}
}

// Without a yes on the terminal, or without a terminal, nothing is made; and mail.credential is a Confirm method, so a
// call that does not say a person confirmed is refused before it keeps anything.
func TestUrMailCredentialMakesNothingWithoutAPerson(t *testing.T) {
	target := newTestUrMailCredentialTarget(t)
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "mail", "credential"}); code != urExitFailed {
		t.Fatalf("no terminal: exit %d", code)
	}
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "mail", "credential"}); code != urExitOk || !strings.Contains(stdout.String(), "nothing changed") {
		t.Fatalf("a no: exit %d: %q", code, stdout.String())
	}
	secret, err := sidecar.NewMailLocalCredentialSecret(nil)
	if err != nil {
		t.Fatal(err)
	}
	reply := &urMailCredentialReply{}
	if err := cli.callDaemon(context.Background(), urMethodMailCredential, &urMailCredentialParams{Verifier: secret.Verifier}, false, reply); err == nil {
		t.Fatal("an unconfirmed mail.credential was kept")
	}
	if configured, err := target.credential.Configured(); err != nil || configured {
		t.Fatalf("a credential was made: %v %v", configured, err)
	}
}
