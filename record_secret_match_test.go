//go:build !ios_extension

// Sidecar.SecretMatcher (I-7): each credential matches raw, as hex in either case and as base64 in both alphabets,
// padded and not; a value under the settings' bound and ordinary text match nothing; the redactor's token forms match
// with no credential; a match names its class and offset, never the bytes; and on every leg the connect identity seed
// a keychain keeps is a credential. record_secret_match_sidecar_test.go holds a sidecar's own matcher, and
// record_secret_match_connect_test.go a connect leg's connect identity.

package sidecar

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
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

// The connect identity seed a keychain keeps is a credential on every leg, matched in each encoding once kept; a
// keychain keeping none lists nothing.
func TestConnectIdentityCredentialsHoldTheKeptSeed(t *testing.T) {
	_, secrets := newIdentityTestSecrets(t, NewId())
	if credentials, err := loadSidecarConnectIdentityCredentials(secrets); err != nil || len(credentials) != 0 {
		t.Fatalf("a keychain keeping no connect identity listed %d credentials, %v", len(credentials), err)
	}
	seed, err := newSidecarConnectIdentitySeed(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := &SidecarIdentity{NetworkId: NewId(), SidecarId: NewId(), ClientId: NewId(), Generation: 1}
	if err := persistSidecarConnectIdentitySeed(secrets, identity, seed); err != nil {
		t.Fatal(err)
	}
	credentials, err := loadSidecarConnectIdentityCredentials(secrets)
	if err != nil {
		t.Fatal(err)
	}
	matcher := NewSecretMatcher(credentials, nil)
	for name, form := range map[string]string{
		"raw":            string(seed),
		"upper hex":      strings.ToUpper(hex.EncodeToString(seed)),
		"base64":         base64.StdEncoding.EncodeToString(seed),
		"raw url base64": base64.RawURLEncoding.EncodeToString(seed),
	} {
		text := []byte("the seed " + form + " here")
		if match := matcher.Match(text); match == nil || match.Class != SecretMatchCredential || match.Offset != len("the seed ") {
			t.Errorf("the seed, %s: %+v", name, match)
		}
	}
}
