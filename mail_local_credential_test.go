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
// the bound, a wrong user name costing what a wrong secret does; a success clears the count; a rotated secret stops
// checking the old one at once.
func TestMailLocalCredentialRefusesAtABoundedRate(t *testing.T) {
	clock := newTestMailCredentialClock(time.UnixMilli(1793923200000))
	settings := DefaultMailLocalCredentialSettings()
	settings.FailureDelayMax = 4 * settings.FailureDelay
	credential, err := NewMailLocalCredential(&testMailSecrets{}, clock, settings)
	if err != nil {
		t.Fatal(err)
	}
	client := netip.MustParseAddr("192.0.2.40")
	// with no credential made, every pair refuses
	answered := make(chan bool, 1)
	go func() { answered <- credential.Check(context.Background(), client, MailLocalCredentialUser, "x") }()
	for !slices.Contains(clock.pending(), settings.FailureDelay) {
		<-clock.added
	}
	clock.Advance(settings.FailureDelay)
	if <-answered {
		t.Fatal("a pair checked before any credential was made")
	}
	secret, err := credential.Ensure()
	if err != nil || len(secret) < 40 {
		t.Fatalf("ensure %d %v", len(secret), err)
	}
	if again, _ := credential.Ensure(); again != secret {
		t.Fatal("ensure made a second secret")
	}
	check := func(user string, password string, wait time.Duration) {
		t.Helper()
		answered := make(chan bool, 1)
		go func() { answered <- credential.Check(context.Background(), client, user, password) }()
		for !slices.Contains(clock.pending(), wait) {
			<-clock.added
		}
		select {
		case <-answered:
			t.Fatal("a refusal answered before its wait")
		default:
		}
		clock.Advance(wait)
		if <-answered {
			t.Fatal("a wrong credential checked")
		}
	}
	check(MailLocalCredentialUser, "wrong", 2*settings.FailureDelay)
	check("someone", secret, 4*settings.FailureDelay)
	check(MailLocalCredentialUser, secret+"x", settings.FailureDelayMax)
	if !credential.Check(context.Background(), client, MailLocalCredentialUser, secret) {
		t.Fatal("the credential did not check")
	}
	check(MailLocalCredentialUser, "wrong", settings.FailureDelay)
	rotated, err := credential.Rotate()
	if err != nil || rotated == secret {
		t.Fatalf("rotate %v", err)
	}
	check(MailLocalCredentialUser, secret, 2*settings.FailureDelay)
	if !credential.Check(context.Background(), client, MailLocalCredentialUser, rotated) {
		t.Fatal("the rotated credential did not check")
	}
}

// A keychain that cannot answer leaves no credential to show, and settings out of range make none.
func TestMailLocalCredentialFailsClosed(t *testing.T) {
	if _, err := NewMailLocalCredential(nil, nil, nil); !errors.Is(err, ErrMailLocalCredential) {
		t.Errorf("no keychain: %v", err)
	}
	settings := DefaultMailLocalCredentialSettings()
	settings.CredentialByteCount = 8
	if _, err := NewMailLocalCredential(&testMailSecrets{}, nil, settings); !errors.Is(err, ErrMailLocalCredential) {
		t.Errorf("an 8-byte secret: %v", err)
	}
}
