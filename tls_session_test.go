//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// A session for memberId on the fixture's front, as its callback would set it, live for SessionLifetime.
func (self *tlsFrontFixture) sealSession(t *testing.T, memberId Id) string {
	t.Helper()
	now := self.clock.Now()
	value, err := self.front.sessions.sealSession(tlsFrontTestServerName, &tlsSession{
		memberId:   memberId,
		issueTime:  now,
		expireTime: now.Add(self.settings.SessionLifetime),
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// Sessions survive a restart: a sealer made again from the same keychain opens what the first sealed, and the root is
// made once and kept.
func TestTlsSessionSurvivesRestart(t *testing.T) {
	secrets := newTlsFrontTestSecrets()
	networkId := NewId()
	first, err := newTlsSessionSealer(secrets, networkId)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.November, 11, 9, 0, 0, 0, time.UTC)
	session := &tlsSession{memberId: NewId(), issueTime: now, expireTime: now.Add(12 * time.Hour)}
	session.sessionId[0] = 7
	value, err := first.sealSession(tlsFrontTestServerName, session)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := secrets.Get(tlsFrontSessionRootRecordName)
	restarted, err := newTlsSessionSealer(secrets, networkId)
	if err != nil {
		t.Fatal(err)
	}
	opened := restarted.openSession(value, tlsFrontTestServerName, now.Add(time.Hour))
	if opened == nil || opened.memberId != session.memberId || opened.sessionId != session.sessionId ||
		!opened.expireTime.Equal(session.expireTime) || !opened.issueTime.Equal(session.issueTime) {
		t.Fatalf("after a restart: %+v", opened)
	}
	if again, _ := secrets.Get(tlsFrontSessionRootRecordName); string(again) != string(root) {
		t.Error("the root was made again")
	}
}

// A session opens on its own host, network and cookie name alone, and not past its expiry or once changed.
func TestTlsSessionRefusesAnotherHostNetworkOrCookie(t *testing.T) {
	secrets := newTlsFrontTestSecrets()
	sealer, err := newTlsSessionSealer(secrets, NewId())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.November, 11, 9, 0, 0, 0, time.UTC)
	value, err := sealer.sealSession(tlsFrontTestServerName, &tlsSession{memberId: NewId(), issueTime: now, expireTime: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if sealer.openSession(value, tlsFrontTestServerName, now) == nil {
		t.Fatal("its own host refused")
	}
	if sealer.openSession(value, tlsFrontTestOtherName, now) != nil {
		t.Error("another host opened it")
	}
	if sealer.openSession(value, tlsFrontTestServerName, now.Add(time.Hour)) != nil {
		t.Error("opened at its expiry")
	}
	otherNetwork, err := newTlsSessionSealer(secrets, NewId())
	if err != nil {
		t.Fatal(err)
	}
	if otherNetwork.openSession(value, tlsFrontTestServerName, now) != nil {
		t.Error("another network opened it")
	}
	if sealer.openPreLogin(value, tlsFrontTestServerName, now) != nil {
		t.Error("it opened as a pending login")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 1
	if sealer.openSession(base64.RawURLEncoding.EncodeToString(sealed), tlsFrontTestServerName, now) != nil {
		t.Error("a changed cookie opened")
	}
	for _, malformed := range []string{"", "!", strings.Repeat("A", 10)} {
		if sealer.openSession(malformed, tlsFrontTestServerName, now) != nil {
			t.Errorf("%q opened", malformed)
		}
	}
}

// A pending login round-trips its state, nonce, verifier and return path, and ends at its expiry.
func TestTlsPreLoginRoundTrip(t *testing.T) {
	sealer, err := newTlsSessionSealer(newTlsFrontTestSecrets(), NewId())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.November, 11, 9, 0, 0, 0, time.UTC)
	preLogin := &tlsPreLogin{expireTime: now.Add(10 * time.Minute), returnPath: "/page?x=1"}
	preLogin.state[0], preLogin.nonce[1], preLogin.verifier[2] = 1, 2, 3
	value, err := sealer.sealPreLogin(tlsFrontTestServerName, preLogin)
	if err != nil {
		t.Fatal(err)
	}
	opened := sealer.openPreLogin(value, tlsFrontTestServerName, now)
	if opened == nil || opened.state != preLogin.state || opened.nonce != preLogin.nonce || opened.verifier != preLogin.verifier ||
		opened.returnPath != preLogin.returnPath {
		t.Fatalf("opened %+v", opened)
	}
	if sealer.openPreLogin(value, tlsFrontTestServerName, now.Add(10*time.Minute)) != nil {
		t.Error("opened at its expiry")
	}
	if sealer.openSession(value, tlsFrontTestServerName, now) != nil {
		t.Error("it opened as a session")
	}
}

// A locked or failed keychain refuses the sealer and writes nothing over what may be there (D-CORE-15).
func TestTlsSessionSealerNeedsTheKeychain(t *testing.T) {
	for _, getErr := range []error{ErrSidecarStoreLocked, ErrSidecarStoreFailed} {
		secrets := newTlsFrontTestSecrets()
		secrets.getErr = getErr
		if _, err := newTlsSessionSealer(secrets, NewId()); !errors.Is(err, getErr) {
			t.Errorf("%v: %v", getErr, err)
		}
		if len(secrets.values) != 0 {
			t.Errorf("%v: wrote %d records", getErr, len(secrets.values))
		}
	}
	secrets := newTlsFrontTestSecrets()
	secrets.values[tlsFrontSessionRootRecordName] = []byte("short")
	if _, err := newTlsSessionSealer(secrets, NewId()); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Errorf("a root that does not decode: %v", err)
	}
}
