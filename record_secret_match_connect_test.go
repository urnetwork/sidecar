//go:build !sidecar_http && !js && !ios_extension

// Sidecar.SecretMatcher (I-7) on the connect identity a generation keeps (identity_connect.go): a running sidecar's
// matcher holds the seed its keychain keeps and every key its client was opened with, in each encoding, where a matcher
// built before the generation's first start holds none of them, and holds nothing public; a predecessor's record still
// counts; and a record that does not decode builds no matcher. The enrolled instance and the platform are
// sidecar_core_test.go's.

package sidecar

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// A base sidecar's matcher over secrets at Unenrolled, as an MCP call builds one.
func connectSecretMatcherOf(t *testing.T, secrets SidecarSecrets) (*SecretMatcher, error) {
	t.Helper()
	sidecar := newTestSidecar(t)
	func() {
		sidecar.stateLock.Lock()
		defer sidecar.stateLock.Unlock()
		sidecar.lifecycle.state = SidecarStateUnenrolled
		sidecar.coreSecrets = secrets
	}()
	return sidecar.SecretMatcher()
}

// The sequence certificate's key in a client's PEM, and its PKCS #8 bytes.
func connectSecretTlsKeyOf(t *testing.T, tlsPrivateKeyPem []byte) (ed25519.PrivateKey, []byte) {
	t.Helper()
	block, rest := pem.Decode(tlsPrivateKeyPem)
	if block == nil || len(rest) != 0 {
		t.Fatal("the certificate's key is not one PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	tlsKey, ok := key.(ed25519.PrivateKey)
	if err != nil || !ok {
		t.Fatalf("the certificate's key is not an Ed25519 key: %v", err)
	}
	return tlsKey, block.Bytes
}

// Each form, between ordinary words, must match as a credential at its offset.
func connectSecretTestMatches(t *testing.T, matcher *SecretMatcher, forms map[string][]byte) {
	t.Helper()
	prefix := "a tool result with "
	for name, form := range forms {
		text := append(append([]byte(prefix), form...), " in it"...)
		if match := matcher.Match(text); match == nil || match.Class != SecretMatchCredential || match.Offset != len(prefix) {
			t.Errorf("%s: %+v", name, match)
		}
	}
}

// The matcher of a running sidecar holds its generation's connect identity: the seed its keychain keeps, the sequence
// certificate's key as its seed, private key, PKCS #8 bytes and PEM, and each provide key, the bytes its client was
// opened with, in hex and base64 as well as raw; a matcher built from the same keychain before the generation's first
// start drew the identity matches none of them as a credential. The certificate and the public keys are no credential.
func TestSidecarSecretMatcherHoldsItsConnectIdentity(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	before, err := connectSecretMatcherOf(t, enrollment.secrets)
	if err != nil {
		t.Fatal(err)
	}
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))
	opened := connectIdentityTestOpened(t, platform.awaitOpened(t, 1))
	seed, err := loadSidecarConnectIdentitySeed(enrollment.secrets, &SidecarIdentity{ClientId: enrollment.clientId, Generation: 1})
	if err != nil || seed == nil {
		t.Fatalf("the keychain keeps no seed for generation 1: %v", err)
	}
	tlsKey, tlsKeyDer := connectSecretTlsKeyOf(t, opened.tlsPrivateKeyPem)
	forms := map[string][]byte{
		"the seed":           seed,
		"the seed in hex":    []byte(hex.EncodeToString(seed)),
		"the seed in base64": []byte(base64.StdEncoding.EncodeToString(seed)),
		"the certificate key's seed in upper hex":      []byte(strings.ToUpper(hex.EncodeToString(tlsKey.Seed()))),
		"the certificate key's seed in raw url base64": []byte(base64.RawURLEncoding.EncodeToString(tlsKey.Seed())),
		"the certificate's private key in base64":      []byte(base64.StdEncoding.EncodeToString(tlsKey)),
		"the certificate key's pkcs8 in url base64":    []byte(base64.URLEncoding.EncodeToString(tlsKeyDer)),
		"the certificate key's pem":                    opened.tlsPrivateKeyPem,
		// as a JSON of the client's settings carries it
		"the certificate key's pem in base64": []byte(base64.StdEncoding.EncodeToString(opened.tlsPrivateKeyPem)),
	}
	for mode, key := range opened.provideSecretKeys {
		forms[fmt.Sprintf("the %s provide key", mode)] = key
		forms[fmt.Sprintf("the %s provide key in hex", mode)] = []byte(hex.EncodeToString(key))
		forms[fmt.Sprintf("the %s provide key in raw base64", mode)] = []byte(base64.RawStdEncoding.EncodeToString(key))
	}
	matcher, err := sidecar.SecretMatcher()
	if err != nil {
		t.Fatal(err)
	}
	connectSecretTestMatches(t, matcher, forms)
	for name, form := range forms {
		text := append(append([]byte("a tool result with "), form...), " in it"...)
		if match := before.Match(text); match != nil && match.Class == SecretMatchCredential {
			t.Errorf("%s matched as a credential before the generation kept a connect identity", name)
		}
	}

	certificateBlock, _ := pem.Decode(opened.tlsCertificatePem)
	if certificateBlock == nil {
		t.Fatal("the certificate is not a PEM block")
	}
	for name, text := range map[string][]byte{
		"the certificate":                        opened.tlsCertificatePem,
		"the certificate in base64":              []byte(base64.StdEncoding.EncodeToString(certificateBlock.Bytes)),
		"the certificate's public key in hex":    []byte(hex.EncodeToString(tlsKey.Public().(ed25519.PublicKey))),
		"the certificate's public key in base64": []byte(base64.StdEncoding.EncodeToString(tlsKey.Public().(ed25519.PublicKey))),
	} {
		if matcher.Matches(text) {
			t.Errorf("%s matched", name)
		}
	}
}

// A predecessor's connect identity record, which generation 2's first start has yet to replace, still counts, its seed
// and its keys alike, though the core's own read answers generation 2 no seed.
func TestSidecarSecretMatcherHoldsAPredecessorsConnectIdentity(t *testing.T) {
	_, enrollment := newTestEnrolledInstance(t)
	seed := connectIdentityTestSeed(t)
	predecessor := &SidecarIdentity{
		NetworkId: enrollment.networkId, SidecarId: enrollment.sidecarId, ClientId: enrollment.clientId, Generation: 1,
	}
	if err := persistSidecarConnectIdentitySeed(enrollment.secrets, predecessor, seed); err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.keys.withNewClientKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollment.bind(t, 2, keys)
	current := &SidecarIdentity{ClientId: enrollment.clientId, Generation: 2}
	if kept, err := loadSidecarConnectIdentitySeed(enrollment.secrets, current); err != nil || kept != nil {
		t.Fatalf("generation 2 was answered a seed, %v", err)
	}
	matcher, err := connectSecretMatcherOf(t, enrollment.secrets)
	if err != nil {
		t.Fatal(err)
	}
	identity := connectIdentityTestDerive(t, seed)
	tlsKey, _ := connectSecretTlsKeyOf(t, identity.tlsPrivateKeyPem)
	forms := map[string][]byte{
		"the seed in hex":                         []byte(hex.EncodeToString(seed)),
		"the certificate key's seed in base64":    []byte(base64.StdEncoding.EncodeToString(tlsKey.Seed())),
		"the certificate key's pem in url base64": []byte(base64.URLEncoding.EncodeToString(identity.tlsPrivateKeyPem)),
	}
	for mode, key := range identity.provideSecretKeys {
		forms[fmt.Sprintf("the %s provide key in url base64", mode)] = []byte(base64.URLEncoding.EncodeToString(key))
	}
	connectSecretTestMatches(t, matcher, forms)
}

// A connect identity record that does not decode is Failed (D-CORE-15): no matcher is built, so a caller refuses rather
// than answers unchecked, and the error repeats none of the record.
func TestSidecarSecretMatcherRefusesAConnectIdentityThatDoesNotDecode(t *testing.T) {
	_, enrollment := newTestEnrolledInstance(t)
	damaged := []byte("synthetic damage, no connect identity record")
	if err := enrollment.secrets.Put(sidecarConnectIdentityRecordName, damaged); err != nil {
		t.Fatal(err)
	}
	matcher, err := connectSecretMatcherOf(t, enrollment.secrets)
	if matcher != nil || !errors.Is(err, ErrSidecarStoreFailed) || !errors.Is(err, errSidecarConnectIdentityFormat) {
		t.Fatalf("a matcher over a record that does not decode: %v", err)
	}
	if strings.Contains(err.Error(), string(damaged)) {
		t.Error("the error repeats the record")
	}
}
