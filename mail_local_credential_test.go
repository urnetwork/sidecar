//go:build !ios_extension

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

// A secrets namespace in memory.
type testMailSecrets struct {
	stateLock sync.Mutex
	values    map[string][]byte
}

func (self *testMailSecrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.values[name]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *testMailSecrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.values == nil {
		self.values = map[string][]byte{}
	}
	self.values[name] = bytes.Clone(value)
	return nil
}

func (self *testMailSecrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.values, name)
	return nil
}

func (self *testMailSecrets) List(prefix string) ([]string, error) {
	return nil, nil
}

// A clock a credential test moves: its waits fire only when Advance passes them.
type testMailCredentialClock struct {
	stateLock sync.Mutex
	now       time.Time
	waits     []*testMailCredentialWait
	added     chan struct{}
}

type testMailCredentialWait struct {
	at      time.Time
	channel chan time.Time
}

func newTestMailCredentialClock(now time.Time) *testMailCredentialClock {
	return &testMailCredentialClock{now: now, added: make(chan struct{}, 64)}
}

func (self *testMailCredentialClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *testMailCredentialClock) After(timeout time.Duration) <-chan time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	wait := &testMailCredentialWait{at: self.now.Add(timeout), channel: make(chan time.Time, 1)}
	self.waits = append(self.waits, wait)
	select {
	case self.added <- struct{}{}:
	default:
	}
	return wait.channel
}

func (self *testMailCredentialClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return true }
}

// Moves the clock by timeout, firing every wait it passes.
func (self *testMailCredentialClock) Advance(timeout time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(timeout)
	kept := []*testMailCredentialWait{}
	for _, wait := range self.waits {
		if !wait.at.After(self.now) {
			wait.channel <- wait.at
			continue
		}
		kept = append(kept, wait)
	}
	self.waits = kept
}

// How far off each pending wait is.
func (self *testMailCredentialClock) pending() []time.Duration {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	durations := []time.Duration{}
	for _, wait := range self.waits {
		durations = append(durations, wait.at.Sub(self.now))
	}
	return durations
}

// A wrong credential is refused at a bounded rate: each refusal from a client waits on the clock, doubling up to
// the bound, a wrong user name costing what a wrong secret does; a success clears the count; a new credential stops
// the old one opening anything at once.
func TestMailLocalCredentialRefusesAtABoundedRate(t *testing.T) {
	clock := newTestMailCredentialClock(time.UnixMilli(1793923200000))
	settings := DefaultMailLocalCredentialSettings()
	settings.FailureDelayMax = 4 * settings.FailureDelay
	login, err := NewMailLocalLogin(clock, settings)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := NewMailLocalCredential(&testMailSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	credentials := []*MailLocalCredential{credential}
	client := netip.MustParseAddr("192.0.2.40")
	check := func(user string, password string, wait time.Duration) {
		t.Helper()
		answered := make(chan int, 1)
		go func() { answered <- login.Check(context.Background(), client, user, password, credentials) }()
		for !slices.Contains(clock.pending(), wait) {
			<-clock.added
		}
		select {
		case <-answered:
			t.Fatal("a refusal answered before its wait")
		default:
		}
		clock.Advance(wait)
		if index := <-answered; index != -1 {
			t.Fatalf("a wrong credential opened %d", index)
		}
	}
	// with no credential made, every pair refuses
	check(MailLocalCredentialUser, "x", settings.FailureDelay)
	if configured, err := credential.Configured(); err != nil || configured {
		t.Fatalf("configured before any credential: %v %v", configured, err)
	}
	secret, err := NewMailLocalCredentialSecret(settings)
	if err != nil || len(secret.Text) < 40 {
		t.Fatalf("a secret of %d characters: %v", len(secret.Text), err)
	}
	if err := credential.Install(secret.Verifier); err != nil {
		t.Fatal(err)
	}
	check(MailLocalCredentialUser, "wrong", 2*settings.FailureDelay)
	check("someone", secret.Text, 4*settings.FailureDelay)
	check(MailLocalCredentialUser, secret.Text+"x", settings.FailureDelayMax)
	if login.Check(context.Background(), client, MailLocalCredentialUser, secret.Text, credentials) != 0 {
		t.Fatal("the credential did not open")
	}
	check(MailLocalCredentialUser, "wrong", settings.FailureDelay)
	replaced, err := NewMailLocalCredentialSecret(settings)
	if err != nil || replaced.Text == secret.Text {
		t.Fatalf("a second secret: %v", err)
	}
	if err := credential.Install(replaced.Verifier); err != nil {
		t.Fatal(err)
	}
	check(MailLocalCredentialUser, secret.Text, 2*settings.FailureDelay)
	if login.Check(context.Background(), client, MailLocalCredentialUser, replaced.Text, credentials) != 0 {
		t.Fatal("the new credential did not open")
	}
}

// The keychain holds the verifier alone: neither the secret's text nor anything that opens a session sits there,
// so no reply or store can give a credential out (I-7). The secret names its own network among several.
func TestMailLocalCredentialKeepsOnlyAVerifier(t *testing.T) {
	secrets := []*testMailSecrets{{}, {}}
	credentials := []*MailLocalCredential{}
	texts := []string{}
	for _, keychain := range secrets {
		credential, err := NewMailLocalCredential(keychain)
		if err != nil {
			t.Fatal(err)
		}
		secret, err := NewMailLocalCredentialSecret(nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := credential.Install(secret.Verifier); err != nil {
			t.Fatal(err)
		}
		credentials = append(credentials, credential)
		texts = append(texts, secret.Text)
	}
	for index, keychain := range secrets {
		if len(keychain.values) != 1 {
			t.Errorf("network %d's keychain holds %d entries", index, len(keychain.values))
		}
		for name, value := range keychain.values {
			if len(value) != 32 {
				t.Errorf("%s holds %d bytes, not a verifier", name, len(value))
			}
			for _, text := range texts {
				if bytes.Contains(value, []byte(text)) {
					t.Errorf("%s holds a secret's text", name)
				}
			}
		}
		login, err := NewMailLocalLogin(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := login.Check(context.Background(), netip.MustParseAddr("127.0.0.1"), MailLocalCredentialUser, texts[index], credentials); got != index {
			t.Errorf("network %d's secret opened %d", index, got)
		}
	}
}

// A keychain that cannot answer makes no credential, settings out of range make no login or secret, and a verifier
// of the wrong size is refused.
func TestMailLocalCredentialFailsClosed(t *testing.T) {
	if _, err := NewMailLocalCredential(nil); !errors.Is(err, ErrMailLocalCredential) {
		t.Errorf("no keychain: %v", err)
	}
	settings := DefaultMailLocalCredentialSettings()
	settings.CredentialByteCount = 8
	if _, err := NewMailLocalLogin(nil, settings); !errors.Is(err, ErrMailLocalCredential) {
		t.Errorf("an 8-byte secret's login: %v", err)
	}
	if _, err := NewMailLocalCredentialSecret(settings); !errors.Is(err, ErrMailLocalCredential) {
		t.Errorf("an 8-byte secret: %v", err)
	}
	credential, err := NewMailLocalCredential(&testMailSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.Install(make([]byte, 16)); !errors.Is(err, ErrMailLocalCredential) {
		t.Errorf("a 16-byte verifier: %v", err)
	}
}
