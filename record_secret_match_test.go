//go:build !ios_extension

// Sidecar.SecretMatcher (I-7): each credential matches raw, as hex in either case and as base64 in both alphabets,
// padded and not; a value under the settings' bound and ordinary text match nothing; the redactor's token forms match
// with no credential; a match names its class and offset, never the bytes; and a sidecar's own matcher holds its keys
// and token from the keychain, refusing while Locked and before enrollment.

package sidecar

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// A GitHub token shape the redactor's github-pat rule finds: synthetic, mixed characters for its entropy bound.
const testSecretMatchToken = "ghp_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"

// Each encoding of a credential matches inside ordinary text, at its offset.
func TestSecretMatcherMatchesEveryEncoding(t *testing.T) {
	credential := []byte("a synthetic credential of forty bytes!!!")
	matcher := NewSecretMatcher([][]byte{credential}, nil)
	forms := map[string]string{
		"raw":            string(credential),
		"hex":            hex.EncodeToString(credential),
		"upper hex":      strings.ToUpper(hex.EncodeToString(credential)),
		"base64":         base64.StdEncoding.EncodeToString(credential),
		"raw base64":     base64.RawStdEncoding.EncodeToString(credential),
		"url base64":     base64.URLEncoding.EncodeToString(credential),
		"raw url base64": base64.RawURLEncoding.EncodeToString(credential),
	}
	for name, form := range forms {
		text := []byte("prefix " + form + " suffix")
		match := matcher.Match(text)
		if match == nil || match.Class != SecretMatchCredential || match.Offset != len("prefix ") {
			t.Errorf("%s: %+v", name, match)
		}
	}
	if matcher.Matches([]byte("nothing secret here, just words and 1234567890abcdef")) {
		t.Error("ordinary text matched")
	}
}

// A credential under CredentialMinByteCount is skipped, so a short value never matches everything.
func TestSecretMatcherSkipsShortCredentials(t *testing.T) {
	settings := DefaultSecretMatchSettings()
	short := []byte("abc")
	matcher := NewSecretMatcher([][]byte{short, nil}, settings)
	if matcher.FormCount() != 0 || matcher.Matches([]byte("abcabcabc")) {
		t.Errorf("a short credential matched, %d forms", matcher.FormCount())
	}
	settings.CredentialMinByteCount = 2
	if !NewSecretMatcher([][]byte{short}, settings).Matches([]byte("xabcx")) {
		t.Error("a credential at the bound did not match")
	}
}

// The redactor's token forms match with no credential at all, and name their rule; PII is no credential.
func TestSecretMatcherFindsTokenForms(t *testing.T) {
	var none *SecretMatcher
	match := none.Match([]byte("token=" + testSecretMatchToken))
	if match == nil || match.Class != "github-pat" || match.Offset != len("token=") {
		t.Errorf("the token: %+v", match)
	}
	if NewSecretMatcher(nil, nil).Matches([]byte("mail alice@example.com about it")) {
		t.Error("an address matched as a credential")
	}
}

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
