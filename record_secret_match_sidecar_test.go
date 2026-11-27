//go:build !sidecar_http && !js && !ios_extension

// Sidecar.SecretMatcher (I-7) on a sidecar whose keychain holds an enrollment: its identity and client keys, raw and
// as private keys, its bearer token and the reader keys its keychain keeps (QD-1444) match; its public keys and signed
// ReaderKeys do not; a reader key the keychain cannot give, and Locked and unenrolled sidecars, refuse to build a
// matcher. The enrolled instance is sidecar_core_test.go's, off the page Worker's leg, and the reader keys are
// record_secret_match_test.go's.

package sidecar

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

// A base sidecar at Unenrolled over secrets, the core's namespace of its network's keychain, as an MCP call finds one.
func newTestSecretMatchSidecar(t *testing.T, secrets SidecarSecrets) *Sidecar {
	t.Helper()
	sidecar := newTestSidecar(t)
	func() {
		sidecar.stateLock.Lock()
		defer sidecar.stateLock.Unlock()
		sidecar.lifecycle.state = SidecarStateUnenrolled
		sidecar.coreSecrets = secrets
	}()
	return sidecar
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

// A sidecar's matcher holds every reader key its keychain keeps (QD-1444): enrollment's first ReaderKey, a Delegation's
// reader seed, and the current generation gkm's upkeep keeps beside a replaced one and a lapsed one, each its private
// key's bytes, caught in every encoding in a tool result, in a result's json and in an error; no public key or signed
// ReaderKey matches as a credential; and once upkeep erases a generation, 30 days past its not_after, the next matcher
// holds it no longer and holds the rest.
func TestSidecarSecretMatcherHoldsItsReaderKeys(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	keys := newTestSecretMatchReaderKeys(t, instance, enrollment.networkId, enrollment.secrets)
	seeds := map[string][]byte{
		"enrollment's first ReaderKey": keys.firstSeed,
		"a Delegation's reader seed":   keys.delegationSeed,
	}
	publics := map[string][]byte{}
	// generations on days 0, 6 and 12: on day 12 the first has lapsed, the second is replaced, the third is current
	for i, advance := range []time.Duration{0, 6 * 24 * time.Hour, 6 * 24 * time.Hour} {
		keys.keep(t, advance)
		seed, publicKey, signed := keys.newest(t)
		seeds[fmt.Sprintf("generation %d", i)] = seed
		publics[fmt.Sprintf("generation %d's public key", i)] = publicKey
		signedBytes, err := proto.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		publics[fmt.Sprintf("generation %d's signed ReaderKey", i)] = signedBytes
	}
	sidecar := newTestSecretMatchSidecar(t, enrollment.secrets)
	matcher, err := sidecar.SecretMatcher()
	if err != nil {
		t.Fatal(err)
	}
	for name, seed := range seeds {
		testSecretMatchCaught(t, matcher, name, seed)
	}
	for name, public := range publics {
		testSecretMatchNotCaught(t, matcher, name, public)
	}

	// day 37 is 30 days past generation 0's not_after: upkeep erases it as it keeps generation 3
	keys.keep(t, 25*24*time.Hour)
	seeds["generation 3"], _, _ = keys.newest(t)
	matcher, err = sidecar.SecretMatcher()
	if err != nil {
		t.Fatal(err)
	}
	testSecretMatchNotCaught(t, matcher, "erased generation 0", seeds["generation 0"])
	delete(seeds, "generation 0")
	for name, seed := range seeds {
		testSecretMatchCaught(t, matcher, name, seed)
	}
}

// A reader key the sidecar's keychain keeps but cannot give builds no matcher, so a caller refuses rather than answers
// unchecked: a generation's record that does not decode, repeating none of the record; a read the keychain fails, of
// the first ReaderKey or of gkm's list; and a keychain view reaching no gkm namespace.
func TestSidecarSecretMatcherRefusesAReaderKeyItCannotRead(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	keys := newTestSecretMatchReaderKeys(t, instance, enrollment.networkId, enrollment.secrets)
	keys.keep(t, 0)
	for _, c := range []struct {
		name    string
		secrets SidecarSecrets
		err     error
	}{
		{
			name:    "the first ReaderKey's read failing",
			secrets: &testSecretMatchFailingSecrets{SidecarSecrets: enrollment.secrets, failName: sidecarReaderKeyRecordName, err: ErrSidecarStoreFailed},
			err:     ErrSidecarStoreFailed,
		},
		{
			name:    "gkm's list failing",
			secrets: &testSecretMatchFailingSecrets{SidecarSecrets: enrollment.secrets, failList: true, err: ErrSidecarStoreLocked},
			err:     ErrSidecarStoreLocked,
		},
		{
			name:    "a view reaching no gkm namespace",
			secrets: &testSecretMatchOneNamespace{SidecarSecrets: enrollment.secrets},
			err:     errSidecarKeychainUnreachable,
		},
	} {
		matcher, err := newTestSecretMatchSidecar(t, c.secrets).SecretMatcher()
		if matcher != nil || !errors.Is(err, c.err) {
			t.Errorf("%s: a matcher, %v", c.name, err)
		}
	}

	damaged := []byte("synthetic damage, no ReaderKey record of upkeep's")
	gkmSecrets := instance.secrets(enrollment.networkId, gkmUpkeepSecretsNamespace)
	if err := gkmSecrets.Put(gkmReaderKeyRecordName(make([]byte, 32)), damaged); err != nil {
		t.Fatal(err)
	}
	matcher, err := newTestSecretMatchSidecar(t, enrollment.secrets).SecretMatcher()
	if matcher != nil || !errors.Is(err, ErrSidecarStoreFailed) || !errors.Is(err, errSidecarReaderKeyRecordFormat) {
		t.Fatalf("a matcher over a record that does not decode: %v", err)
	}
	if strings.Contains(err.Error(), string(damaged)) || strings.Contains(err.Error(), hex.EncodeToString(damaged)) {
		t.Error("the error repeats the record")
	}
}

// A sidecar's matcher holds its live agent subkeys (QD-1449), each seed and Ed25519 private key, minted as the daemon
// mints them, and its components' keys, the tls device key and its pending successor, the front's session root and the
// DKIM key, each made by its own component, all caught in every encoding in a tool result, a result's json and an
// error; no agent certificate, public key or published DKIM key matches; and once the agent is revoked the next matcher
// holds its subkey no longer and holds the rest.
func TestSidecarSecretMatcherHoldsItsAgentAndComponentKeys(t *testing.T) {
	sidecar, instance, _ := newIdentityTestSidecar(t)
	networkId := sidecar.currentIdentity().NetworkId
	secrets := instance.secrets(networkId, sidecarCoreSecretsNamespace)
	agentId := NewId()
	agentSeed, cert := testSecretMatchAgentSubkey(t, sidecar, secrets, agentId)
	keys := newTestSecretMatchComponentKeys(t, instance, networkId)
	matcher, err := sidecar.SecretMatcher()
	if err != nil {
		t.Fatal(err)
	}
	testSecretMatchCaught(t, matcher, "the agent subkey's seed", agentSeed)
	testSecretMatchCaught(t, matcher, "the agent subkey's private key", []byte(ed25519.NewKeyFromSeed(agentSeed)))
	for name, secret := range keys.secretForms {
		testSecretMatchCaught(t, matcher, name, secret)
	}
	testSecretMatchNotCaught(t, matcher, "the agent subkey's public key", cert.PublicKey)
	testSecretMatchNotCaught(t, matcher, "the agent subkey's certificate", cert.Cert)
	for name, public := range keys.publicForms {
		testSecretMatchNotCaught(t, matcher, name, public)
	}

	if err := sidecar.AgentRevoke(agentId); err != nil {
		t.Fatal(err)
	}
	matcher, err = sidecar.SecretMatcher()
	if err != nil {
		t.Fatal(err)
	}
	testSecretMatchNotCaught(t, matcher, "the revoked agent's subkey seed", agentSeed)
	for name, secret := range keys.secretForms {
		testSecretMatchCaught(t, matcher, name, secret)
	}
}

// A key the sidecar's keychain keeps but cannot give builds no matcher, so a caller refuses rather than answers
// unchecked: an agent subkey record or a DKIM key record that does not decode, each repeating none of the record.
func TestSidecarSecretMatcherRefusesAnAgentOrComponentKeyItCannotRead(t *testing.T) {
	sidecar, instance, _ := newIdentityTestSidecar(t)
	networkId := sidecar.currentIdentity().NetworkId
	keys := newTestSecretMatchComponentKeys(t, instance, networkId)
	damaged := []byte("synthetic damage, no key record")
	for _, c := range []struct {
		name    string
		secrets SidecarSecrets
		record  string
		err     error
	}{
		{name: "an agent subkey", secrets: instance.secrets(networkId, sidecarCoreSecretsNamespace), record: sidecarAgentRecordName(NewId()), err: errSidecarAgentRecordFormat},
		{name: "a dkim key", secrets: instance.secrets(networkId, SmtpDkimSecretsNamespace), record: keys.dkimKeyRecordName, err: errSidecarDkimKeyFormat},
	} {
		if err := c.secrets.Put(c.record, damaged); err != nil {
			t.Fatal(err)
		}
		matcher, err := sidecar.SecretMatcher()
		if matcher != nil || !errors.Is(err, c.err) || !errors.Is(err, ErrSidecarStoreFailed) {
			t.Errorf("%s that does not decode: a matcher, %v", c.name, err)
		} else if strings.Contains(err.Error(), string(damaged)) || strings.Contains(err.Error(), hex.EncodeToString(damaged)) {
			t.Errorf("%s: the error repeats the record", c.name)
		}
		if err := c.secrets.Delete(c.record); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := sidecar.SecretMatcher(); err != nil {
		t.Errorf("with the damage gone: %v", err)
	}
}
