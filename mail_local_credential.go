//go:build !ios_extension

// The local mail credential (§15.16, D-MAIL-11, I-7, I-17, owner decision 47; MAIL-M8-07): the one secret IMAP's
// LOGIN takes, and SMTP submission's AUTH with it (MAIL-M9-01), per daemon instance. It lives in this network's
// keychain (§5.9) under the mail component's names, is made at random the first time it is asked for, and grants
// only what the daemon grants its OS user: the member's own mail, read and flagged, never an agent's credential, an
// admin right or a login (I-6).
//
//	user      MailLocalCredentialUser, the same for every instance: the secret alone authenticates, so a
//	          name says nothing about who exists
//	secret    CredentialByteCount random bytes, base64url, shown to the person by `ur mail credential` and
//	          nowhere else: never in an agent's environment, output or log (I-7), never in a log line here
//	check     constant time over the whole presented pair, so a wrong name and a wrong secret are one refusal
//	          and take one time
//	cost      each refusal from a client address waits FailureDelay, doubling with every further refusal from
//	          it in FailureWindow up to FailureDelayMax, before it answers, so a LAN host that guesses
//	          (§15.16) gets a bounded rate whatever it sends; a success clears the address's count
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// The user name every instance's credential goes with.
const MailLocalCredentialUser = "ur"

// The credential's name in the mail component's keychain namespace.
const mailLocalCredentialSecretName = "mail/local-credential"

// The keychain holds no credential and none could be made, or the credential would not check.
var ErrMailLocalCredential = errors.New("mail local credential: unavailable")

// The credential's tunables.
type MailLocalCredentialSettings struct {
	// The secret's random bytes: 32.
	CredentialByteCount int
	// What a client address's first refusal waits: 1 s.
	FailureDelay time.Duration
	// The most one refusal waits: 30 s.
	FailureDelayMax time.Duration
	// How long a client address's refusals are counted from its last: 15 min.
	FailureWindow time.Duration
	// Client addresses whose refusals are counted at most, the oldest forgotten first: 4,096.
	FailureAddressCount int
}

// The defaults, a fresh value each call.
func DefaultMailLocalCredentialSettings() *MailLocalCredentialSettings {
	return &MailLocalCredentialSettings{
		CredentialByteCount: 32,
		FailureDelay:        time.Second,
		FailureDelayMax:     30 * time.Second,
		FailureWindow:       15 * time.Minute,
		FailureAddressCount: 4096,
	}
}

// One client address's refusals.
type mailCredentialFailures struct {
	count    int
	lastTime time.Time
}

// See the file header.
type MailLocalCredential struct {
	secrets  SidecarSecrets
	clock    Clock
	settings *MailLocalCredentialSettings

	stateLock sync.Mutex
	failures  map[netip.Addr]*mailCredentialFailures
	order     []netip.Addr
}

// The credential over secrets, the mail component's keychain namespace.
func NewMailLocalCredential(secrets SidecarSecrets, clock Clock, settings *MailLocalCredentialSettings) (*MailLocalCredential, error) {
	if secrets == nil {
		return nil, ErrMailLocalCredential
	}
	if settings == nil {
		settings = DefaultMailLocalCredentialSettings()
	}
	if settings.CredentialByteCount < 16 || settings.FailureDelay <= 0 || settings.FailureDelayMax < settings.FailureDelay ||
		settings.FailureWindow <= 0 || settings.FailureAddressCount <= 0 {
		return nil, ErrMailLocalCredential
	}
	return &MailLocalCredential{secrets: secrets, clock: clockOrReal(clock), settings: settings, failures: map[netip.Addr]*mailCredentialFailures{}}, nil
}

// The secret as the person reads it, made the first time. For `ur mail credential` alone.
func (self *MailLocalCredential) Ensure() (string, error) {
	secret, err := self.secrets.Get(mailLocalCredentialSecretName)
	if err == nil && len(secret) == self.settings.CredentialByteCount {
		return base64.RawURLEncoding.EncodeToString(secret), nil
	}
	if err != nil && !errors.Is(err, ErrSidecarStoreAbsent) {
		return "", err
	}
	return self.Rotate()
}

// A new secret in place of the old, which stops checking at once. For `ur mail credential --rotate`.
func (self *MailLocalCredential) Rotate() (string, error) {
	secret := make([]byte, self.settings.CredentialByteCount)
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	rand.Read(secret)
	testHookSecret("mail_local_credential", secret)
	if err := self.secrets.Put(mailLocalCredentialSecretName, secret); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(secret), nil
}

// Whether user and password are the credential, in constant time over both. A refusal from client waits its
// cost on the clock before it answers, inside ctx; a success clears client's count. With no credential made yet
// every pair refuses.
func (self *MailLocalCredential) Check(ctx context.Context, client netip.Addr, user string, password string) bool {
	secret, err := self.secrets.Get(mailLocalCredentialSecretName)
	matched := false
	if err == nil && len(secret) == self.settings.CredentialByteCount {
		testHookSecret("mail_local_credential", secret)
		want := []byte(MailLocalCredentialUser + "\x00" + base64.RawURLEncoding.EncodeToString(secret))
		got := []byte(user + "\x00" + password)
		matched = subtle.ConstantTimeEq(int32(len(want)), int32(len(got))) == 1 && subtle.ConstantTimeCompare(want, got) == 1
	}
	client = client.Unmap().WithZone("")
	if matched {
		self.stateLock.Lock()
		delete(self.failures, client)
		self.stateLock.Unlock()
		return true
	}
	delay := self.refused(client)
	select {
	case <-self.clock.After(delay):
	case <-ctx.Done():
	}
	return false
}

// Counts a refusal from client and answers what it waits.
func (self *MailLocalCredential) refused(client netip.Addr) time.Duration {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	failures, ok := self.failures[client]
	if !ok || self.settings.FailureWindow < now.Sub(failures.lastTime) {
		if !ok {
			for self.settings.FailureAddressCount <= len(self.failures) && 0 < len(self.order) {
				delete(self.failures, self.order[0])
				self.order = self.order[1:]
			}
			self.order = append(self.order, client)
		}
		failures = &mailCredentialFailures{}
		self.failures[client] = failures
	}
	failures.count += 1
	failures.lastTime = now
	delay := self.settings.FailureDelay
	for range failures.count - 1 {
		delay *= 2
		if self.settings.FailureDelayMax <= delay {
			return self.settings.FailureDelayMax
		}
	}
	return delay
}
