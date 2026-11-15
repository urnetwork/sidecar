//go:build !ios_extension

// The local mail credential (§15.10, §15.16, D-MAIL-11, I-7, I-17, owner decision 47; MAIL-M8-07): the one secret
// IMAP's LOGIN takes, and SMTP submission's AUTH with it (MAIL-M9-01), per daemon instance and network. It grants
// only what the daemon grants its OS user: the member's own mail, read and flagged, never an agent's credential, an
// admin right or a login (I-6).
//
//	secret    drawn by `ur mail credential` in its own process (NewMailLocalCredentialSecret) and shown on the
//	          terminal once, as app passwords are. It never reaches the daemon: no control reply or keychain entry
//	          holds a credential to give out (§5.8's replies carry no token, key, pass or recovery code; I-7), and a
//	          person who lost it makes another
//	verifier  SHA-256 over the user name, a NUL and the secret's text, kept in the network's keychain.ur under the
//	          mail component's names (MailLocalCredential). The secret's 256 random bits make a plain hash enough,
//	          and the verifier opens nothing
//	user      MailLocalCredentialUser for every network and instance: the secret alone authenticates, so a name says
//	          nothing about who exists
//	match     the presented pair hashed the same way and compared with every network's verifier in constant time,
//	          so a wrong name and a wrong secret are one refusal, and the one that matches names the network
//	cost      MailLocalLogin: each refusal from a client address waits FailureDelay, doubling with every further
//	          refusal from it in FailureWindow up to FailureDelayMax, before it answers, so a LAN host that guesses
//	          (§15.16) gets a bounded rate whatever it sends; a success clears the address's count. A daemon holds
//	          one for IMAP and submission alike, so alternating the two buys a guesser nothing
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// The user name every network's credential goes with.
const MailLocalCredentialUser = "ur"

// The verifier's name in the mail component's keychain namespace.
const mailLocalCredentialVerifierName = "mail/local-credential-verifier"

// The keychain cannot keep or read the verifier, or what was given is out of shape.
var ErrMailLocalCredential = errors.New("mail local credential: unavailable")

// The credential's tunables.
type MailLocalCredentialSettings struct {
	// The secret's random bytes: 32, so a plain hash is a verifier no guess reaches.
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

// Whether the settings can run: a secret of at least 16 bytes and positive, ordered waits.
func (self *MailLocalCredentialSettings) valid() bool {
	return 16 <= self.CredentialByteCount && 0 < self.FailureDelay && self.FailureDelay <= self.FailureDelayMax &&
		0 < self.FailureWindow && 0 < self.FailureAddressCount
}

// The verifier of a presented pair: SHA-256 over the user, a NUL and the password.
func mailLocalCredentialVerifier(user string, password string) []byte {
	hash := sha256.New()
	hash.Write([]byte(user))
	hash.Write([]byte{0})
	hash.Write([]byte(password))
	return hash.Sum(nil)
}

// A credential drawn for the person: the text they give their mail client, and the verifier the daemon keeps.
type MailLocalCredentialSecret struct {
	// CredentialByteCount random bytes, base64url: shown on the terminal once, never sent or kept.
	Text string
	// What MailLocalCredential.Install keeps.
	Verifier []byte
}

// A new credential at settings' size, nil taking the defaults: what `ur mail credential` draws in its own process.
func NewMailLocalCredentialSecret(settings *MailLocalCredentialSettings) (*MailLocalCredentialSecret, error) {
	if settings == nil {
		settings = DefaultMailLocalCredentialSettings()
	}
	if !settings.valid() {
		return nil, ErrMailLocalCredential
	}
	secret := make([]byte, settings.CredentialByteCount)
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	rand.Read(secret)
	testHookSecret("mail_local_credential", secret)
	text := base64.RawURLEncoding.EncodeToString(secret)
	clear(secret)
	// the text is what a client sends and a log could carry, so the harness scans for it too
	testHookSecret("mail_local_credential", []byte(text))
	return &MailLocalCredentialSecret{Text: text, Verifier: mailLocalCredentialVerifier(MailLocalCredentialUser, text)}, nil
}

// One network's credential: its verifier in the mail component's keychain namespace. Safe for concurrent use.
type MailLocalCredential struct {
	secrets SidecarSecrets
}

// The credential over secrets, the mail component's keychain namespace of one network.
func NewMailLocalCredential(secrets SidecarSecrets) (*MailLocalCredential, error) {
	if secrets == nil {
		return nil, ErrMailLocalCredential
	}
	return &MailLocalCredential{secrets: secrets}, nil
}

// Keeps verifier in place of any earlier one, which stops opening anything at once. On the disk when it returns.
func (self *MailLocalCredential) Install(verifier []byte) error {
	if len(verifier) != sha256.Size {
		return ErrMailLocalCredential
	}
	return self.secrets.Put(mailLocalCredentialVerifierName, verifier)
}

// Whether a credential was made for this network.
func (self *MailLocalCredential) Configured() (bool, error) {
	verifier, err := self.secrets.Get(mailLocalCredentialVerifierName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return len(verifier) == sha256.Size, nil
}

// Whether presented, a pair's verifier, is this credential's: constant time, and false with none made or none
// readable.
func (self *MailLocalCredential) matches(presented []byte) bool {
	verifier, err := self.secrets.Get(mailLocalCredentialVerifierName)
	if err != nil || len(verifier) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(verifier, presented) == 1
}

// One client address's refusals.
type mailCredentialFailures struct {
	count    int
	lastTime time.Time
}

// The check and its cost: see the file header. One per daemon. Safe for concurrent use.
type MailLocalLogin struct {
	clock    Clock
	settings *MailLocalCredentialSettings

	stateLock sync.Mutex
	failures  map[netip.Addr]*mailCredentialFailures
	order     []netip.Addr
}

// A login on clock, nil reading real time, and settings, nil taking the defaults.
func NewMailLocalLogin(clock Clock, settings *MailLocalCredentialSettings) (*MailLocalLogin, error) {
	if settings == nil {
		settings = DefaultMailLocalCredentialSettings()
	}
	if !settings.valid() {
		return nil, ErrMailLocalCredential
	}
	return &MailLocalLogin{clock: clockOrReal(clock), settings: settings, failures: map[netip.Addr]*mailCredentialFailures{}}, nil
}

// Which of credentials user and password open: every one compared whole, in constant time, so neither the answer
// nor its time tells a wrong name from a wrong secret. -1 for none, answered only after client's refusal cost has
// passed on the clock, or ctx ended; a match clears client's count.
func (self *MailLocalLogin) Check(ctx context.Context, client netip.Addr, user string, password string, credentials []*MailLocalCredential) int {
	presented := mailLocalCredentialVerifier(user, password)
	matched := -1
	for index, credential := range credentials {
		if credential != nil && credential.matches(presented) && matched < 0 {
			matched = index
		}
	}
	client = client.Unmap().WithZone("")
	if 0 <= matched {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if _, ok := self.failures[client]; ok {
				delete(self.failures, client)
				self.order = slices.DeleteFunc(self.order, func(address netip.Addr) bool { return address == client })
			}
		}()
		return matched
	}
	delay := self.refused(client)
	select {
	case <-self.clock.After(delay):
	case <-ctx.Done():
	}
	return -1
}

// Counts a refusal from client and answers what it waits.
func (self *MailLocalLogin) refused(client netip.Addr) time.Duration {
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

// This network's local credential, over the mail component's keychain namespace: ErrMailLocalCredential for a client
// made without one.
func (self *MailClient) LocalCredential() (*MailLocalCredential, error) {
	return NewMailLocalCredential(self.secrets)
}
