//go:build !sidecar_http && !js && !ios_extension

// Sidecar.SecretMatcher (I-7) on a sidecar whose keychain holds an enrollment: its identity and client keys, raw and
// as private keys, and its bearer token match; its public key does not; and Locked and unenrolled sidecars refuse to
// build a matcher. The enrolled instance is sidecar_core_test.go's, off the page Worker's leg.

package sidecar

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
)

// A sidecar's matcher holds its identity and client keys, raw and as private keys, and its bearer token; Locked and
// unenrolled sidecars refuse to build one.
func TestSidecarSecretMatcherHoldsItsCredentials(t *testing.T) {
	_, enrollment := newTestEnrolledInstance(t)
	sidecar := newTestSidecar(t)
	func() {
		sidecar.stateLock.Lock()
		defer sidecar.stateLock.Unlock()
		sidecar.lifecycle.state = SidecarStateUnenrolled
	}()
	if _, err := sidecar.SecretMatcher(); !errors.Is(err, ErrSidecarNoIdentity) {
		t.Errorf("unenrolled: %v", err)
	}
	func() {
		sidecar.stateLock.Lock()
		defer sidecar.stateLock.Unlock()
		sidecar.coreSecrets = enrollment.secrets
	}()
	matcher, err := sidecar.SecretMatcher()
	if err != nil {
		t.Fatal(err)
	}
	identityKey := ed25519.NewKeyFromSeed(enrollment.keys.identitySeed)
	for name, text := range map[string][]byte{
		"the identity seed":        []byte(hex.EncodeToString(enrollment.keys.identitySeed)),
		"the identity private key": []byte(base64.StdEncoding.EncodeToString(identityKey)),
		"the client key seed":      enrollment.keys.clientKeySeed,
		"the bearer token":         []byte("Authorization: Bearer " + enrollment.byJwt),
	} {
		if match := matcher.Match(text); match == nil || match.Class != SecretMatchCredential && match.Class != "jwt" {
			t.Errorf("%s: %+v", name, match)
		}
	}
	if matcher.Matches([]byte(hex.EncodeToString(identityKey.Public().(ed25519.PublicKey)))) {
		t.Error("the identity public key matched as a credential")
	}

	func() {
		sidecar.stateLock.Lock()
		defer sidecar.stateLock.Unlock()
		sidecar.lifecycle.state = SidecarStateLocked
	}()
	if _, err := sidecar.SecretMatcher(); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("locked: %v", err)
	}
}
