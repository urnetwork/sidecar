//go:build !sidecar_http && !js

// A generation's kept connect identity (identity_connect.go, sidecar_new_connect.go): one seed derives one sequence
// certificate and one provide key per mode, byte for byte, another seed others; the keychain's record holds a
// generation's seed under its client id and number, gives way to a new one for a new generation and is Failed when it
// does not decode; and a Sidecar opens each start of a generation's client on the identity its record keeps, a new
// generation's on a new one, and none on a record that fails, which locks it and stays as it was.
// TestRestartedSidecarIsReachedAtOnceUnderItsKeptGeneration (sidecartest) runs a restart on the Net.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/connect"
)

// A context a broken test's wait ends with.
func connectIdentityTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), sidecarTestTimeout)
}

func connectIdentityTestSeed(t testing.TB) []byte {
	t.Helper()
	seed, err := newSidecarConnectIdentitySeed(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return seed
}

func connectIdentityTestDerive(t testing.TB, seed []byte) *sidecarConnectIdentity {
	t.Helper()
	identity, err := newSidecarConnectIdentity(seed)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

// Whether two identities are the same, field for field.
func connectIdentityTestSame(a *sidecarConnectIdentity, b *sidecarConnectIdentity) bool {
	if !bytes.Equal(a.tlsCertificatePem, b.tlsCertificatePem) || !bytes.Equal(a.tlsPrivateKeyPem, b.tlsPrivateKeyPem) ||
		len(a.provideSecretKeys) != len(b.provideSecretKeys) {
		return false
	}
	for mode, key := range a.provideSecretKeys {
		if !bytes.Equal(key, b.provideSecretKeys[mode]) {
			return false
		}
	}
	return true
}

// One seed derives one identity: the same bytes at every derivation, a certificate on an Ed25519 key with connect's
// sequence name that loads with its key, and a 32-byte provide key for each mode a sidecar's client provides, no two of
// them alike and none the seed or the certificate's key.
func TestConnectIdentityIsTheSameForTheSameSeed(t *testing.T) {
	seed := connectIdentityTestSeed(t)
	first := connectIdentityTestDerive(t, seed)
	second := connectIdentityTestDerive(t, bytes.Clone(seed))
	if !connectIdentityTestSame(first, second) {
		t.Fatal("one seed derived two identities")
	}
	keyPair, err := tls.X509KeyPair(first.tlsCertificatePem, first.tlsPrivateKeyPem)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(first.tlsCertificatePem)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("the certificate is not one PEM block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	tlsKey, ok := keyPair.PrivateKey.(ed25519.PrivateKey)
	publicKey, publicOk := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || !publicOk || !publicKey.Equal(tlsKey.Public()) {
		t.Fatal("the certificate is not on its own Ed25519 key")
	}
	if certificate.Subject.CommonName != sidecarConnectIdentityTlsName || len(certificate.DNSNames) != 1 ||
		certificate.DNSNames[0] != sidecarConnectIdentityTlsName {
		t.Errorf("the certificate names %q, %v", certificate.Subject.CommonName, certificate.DNSNames)
	}
	if certificate.SerialNumber.Sign() <= 0 || certificate.NotAfter.Year() != 9999 {
		t.Errorf("serial %v, not after %v", certificate.SerialNumber, certificate.NotAfter)
	}
	// self-signed under its own key, which is no CA's, so the signature is checked under the key alone
	if err := certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
		t.Errorf("the certificate does not verify: %v", err)
	}
	modes := sidecarConnectIdentityProvideModes()
	if len(first.provideSecretKeys) != len(modes) {
		t.Fatalf("%d provide keys for %d modes", len(first.provideSecretKeys), len(modes))
	}
	seen := [][]byte{seed, tlsKey.Seed()}
	for _, mode := range modes {
		key := first.provideSecretKeys[mode]
		if len(key) != sha256.Size {
			t.Errorf("%s's key is %d bytes", mode, len(key))
		}
		for _, other := range seen {
			if bytes.Equal(key, other) {
				t.Errorf("%s's key is another key or the seed", mode)
			}
		}
		seen = append(seen, key)
	}
}

// Another seed derives another identity: no certificate, certificate key or provide key in common.
func TestConnectIdentityDiffersForAnotherSeed(t *testing.T) {
	first := connectIdentityTestDerive(t, connectIdentityTestSeed(t))
	second := connectIdentityTestDerive(t, connectIdentityTestSeed(t))
	if bytes.Equal(first.tlsCertificatePem, second.tlsCertificatePem) || bytes.Equal(first.tlsPrivateKeyPem, second.tlsPrivateKeyPem) {
		t.Error("two seeds derived one certificate")
	}
	for mode, key := range first.provideSecretKeys {
		if bytes.Equal(key, second.provideSecretKeys[mode]) {
			t.Errorf("two seeds derived one %s key", mode)
		}
	}
}

// A seed that is not one, none included, derives nothing, so no client opens on an identity no keychain keeps.
func TestConnectIdentityRefusesASeedThatIsNotOne(t *testing.T) {
	for _, seed := range [][]byte{nil, make([]byte, sidecarConnectIdentitySeedByteCount-1), make([]byte, sidecarConnectIdentitySeedByteCount+1)} {
		if identity, err := newSidecarConnectIdentity(seed); !errors.Is(err, errSidecarNoConnectIdentity) || identity != nil {
			t.Errorf("a seed of %d bytes: %v", len(seed), err)
		}
	}
}

// The record answers the seed it was kept with to its own generation alone: to a later generation of the same sidecar,
// or another client, it answers none, and a seed kept for that generation then takes its place.
func TestConnectIdentityRecordKeepsItsGenerationsSeed(t *testing.T) {
	_, secrets := newIdentityTestSecrets(t, NewId())
	identity := &SidecarIdentity{NetworkId: NewId(), SidecarId: NewId(), ClientId: NewId(), Generation: 3}
	if seed, err := loadSidecarConnectIdentitySeed(secrets, identity); err != nil || seed != nil {
		t.Fatalf("an empty keychain answered %x, %v", seed, err)
	}
	seed := connectIdentityTestSeed(t)
	if err := persistSidecarConnectIdentitySeed(secrets, identity, seed); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadSidecarConnectIdentitySeed(secrets, identity)
	if err != nil || !bytes.Equal(loaded, seed) {
		t.Fatalf("the kept seed came back as %x, %v", loaded, err)
	}
	next := identity.clone()
	next.Generation++
	next.ClientId = NewId()
	otherClient := identity.clone()
	otherClient.ClientId = NewId()
	for _, other := range []*SidecarIdentity{next, otherClient} {
		if seed, err := loadSidecarConnectIdentitySeed(secrets, other); err != nil || seed != nil {
			t.Errorf("generation %d of client %s was answered %x, %v", other.Generation, other.ClientId, seed, err)
		}
	}
	nextSeed := connectIdentityTestSeed(t)
	if err := persistSidecarConnectIdentitySeed(secrets, next, nextSeed); err != nil {
		t.Fatal(err)
	}
	if loaded, err := loadSidecarConnectIdentitySeed(secrets, next); err != nil || !bytes.Equal(loaded, nextSeed) {
		t.Errorf("the next generation's seed came back as %x, %v", loaded, err)
	}
	if loaded, err := loadSidecarConnectIdentitySeed(secrets, identity); err != nil || loaded != nil {
		t.Errorf("the replaced generation was still answered %x, %v", loaded, err)
	}
}

// A record that does not decode is §5.9's Failed, never absent (D-CORE-15), and its error repeats none of its bytes.
func TestConnectIdentityRecordThatDoesNotDecodeIsFailed(t *testing.T) {
	identity := &SidecarIdentity{NetworkId: NewId(), SidecarId: NewId(), ClientId: NewId(), Generation: 1}
	good := (&sidecarConnectIdentityRecord{clientId: identity.ClientId, generation: 1, seed: connectIdentityTestSeed(t)}).encode()
	damaged := func(edit func(encoded []byte) []byte) []byte {
		return edit(bytes.Clone(good))
	}
	for _, encoded := range [][]byte{
		{},
		[]byte("synthetic damage, no record"),
		good[:len(good)-1],
		append(bytes.Clone(good), 0x00),
		damaged(func(encoded []byte) []byte { encoded[0] ^= 0x01; return encoded }),
		damaged(func(encoded []byte) []byte { encoded[len(sidecarConnectIdentityRecordMagic)] = 2; return encoded }),
		(&sidecarConnectIdentityRecord{clientId: Id{}, generation: 1, seed: make([]byte, sidecarConnectIdentitySeedByteCount)}).encode(),
		(&sidecarConnectIdentityRecord{clientId: identity.ClientId, generation: 0, seed: make([]byte, sidecarConnectIdentitySeedByteCount)}).encode(),
		(&sidecarConnectIdentityRecord{clientId: identity.ClientId, generation: -1, seed: make([]byte, sidecarConnectIdentitySeedByteCount)}).encode(),
	} {
		_, secrets := newIdentityTestSecrets(t, identity.NetworkId)
		if err := secrets.Put(sidecarConnectIdentityRecordName, encoded); err != nil {
			t.Fatal(err)
		}
		seed, err := loadSidecarConnectIdentitySeed(secrets, identity)
		if !errors.Is(err, errSidecarConnectIdentityFormat) || !errors.Is(err, ErrSidecarStoreFailed) || seed != nil {
			t.Errorf("%d bytes: %x, %v", len(encoded), seed, err)
		}
		if err != nil && 0 < len(encoded) && strings.Contains(err.Error(), string(encoded)) {
			t.Error("the error repeats the record")
		}
	}
}

// The provide keys and the sequence certificate a platform client was opened with, which the platform loads into its
// contract manager and its encryption.
func connectIdentityTestOpened(t *testing.T, client *testPlatformClient) *sidecarConnectIdentity {
	t.Helper()
	encryption := client.args.ClientSettings.EncryptionSettings
	if encryption == nil || len(encryption.ProvideTlsCertificatePem) == 0 || len(encryption.ProvideTlsPrivateKeyPem) == 0 {
		t.Fatal("the client was opened with no sequence certificate")
	}
	if len(client.args.ProvideSecretKeys) != len(sidecarConnectIdentityProvideModes()) {
		t.Fatalf("the client was opened with %d provide keys", len(client.args.ProvideSecretKeys))
	}
	return &sidecarConnectIdentity{
		tlsCertificatePem: bytes.Clone(encryption.ProvideTlsCertificatePem),
		tlsPrivateKeyPem:  bytes.Clone(encryption.ProvideTlsPrivateKeyPem),
		provideSecretKeys: client.args.ProvideSecretKeys,
	}
}

// A generation's client, opened again at a later start of the same generation, as a restarted daemon opens it, comes
// up on the connect identity the first start drew and kept: the same provide keys in the platform's args and in the
// client's contract manager, the same certificate in its settings and its encryption, under the same client id.
func TestRestartedGenerationOpensItsClientOnTheKeptConnectIdentity(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	firstPlatform := newTestSidecarPlatform()
	first, err := NewSidecar(t.Context(), &testSidecarHost{store: instance.Store(&enrollment.networkId)}, nil, testSidecarSettings(firstPlatform))
	if err != nil {
		t.Fatal(err)
	}
	firstClient := firstPlatform.awaitOpened(t, 1)
	firstIdentity := connectIdentityTestOpened(t, firstClient)
	closeCtx, cancelClose := connectIdentityTestContext()
	defer cancelClose()
	if err := first.CloseAndWait(closeCtx); err != nil {
		t.Fatal(err)
	}

	secondPlatform := newTestSidecarPlatform()
	newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(secondPlatform))
	secondClient := secondPlatform.awaitOpened(t, 1)
	secondIdentity := connectIdentityTestOpened(t, secondClient)
	if secondClient.args.ClientId != firstClient.args.ClientId || !connectIdentityTestSame(firstIdentity, secondIdentity) {
		t.Fatal("the restarted generation's client was opened on another connect identity")
	}
	// the platform here loads no keys as it builds a client, so these are the leg's own, before any mode is provided
	held := secondClient.client.ContractManager().GetProvideSecretKeys()
	for mode, key := range firstIdentity.provideSecretKeys {
		if !bytes.Equal(held[mode], key) {
			t.Errorf("the restarted client holds another %s key", mode)
		}
	}
	if presented := secondClient.client.EncryptionSessionManager().ProvideTlsCertificatePem(); !bytes.Equal(presented, firstIdentity.tlsCertificatePem) {
		t.Error("the restarted client presents another sequence certificate")
	}
	seed, err := loadSidecarConnectIdentitySeed(enrollment.secrets, &SidecarIdentity{ClientId: enrollment.clientId, Generation: 1})
	if err != nil || seed == nil {
		t.Fatalf("the keychain keeps no seed for generation 1: %v", err)
	}
	if !connectIdentityTestSame(connectIdentityTestDerive(t, seed), firstIdentity) {
		t.Error("the clients' identity is not the one the kept seed derives")
	}
}

// A new generation, a new client, comes up on a connect identity of its own: nothing of generation 1's.
func TestNewGenerationOpensItsClientOnAFreshConnectIdentity(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))
	firstIdentity := connectIdentityTestOpened(t, platform.awaitOpened(t, 1))

	keys, err := enrollment.keys.withNewClientKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollment.bind(t, 2, keys)
	enrollment.commitReplacement(t, sidecar)
	secondClient := platform.awaitOpened(t, 2)
	secondIdentity := connectIdentityTestOpened(t, secondClient)
	if secondClient.args.ClientId != connect.Id(enrollment.clientId) {
		t.Fatal("the second client is not generation 2's")
	}
	if bytes.Equal(firstIdentity.tlsCertificatePem, secondIdentity.tlsCertificatePem) ||
		bytes.Equal(firstIdentity.tlsPrivateKeyPem, secondIdentity.tlsPrivateKeyPem) {
		t.Error("generation 2's client presents generation 1's certificate")
	}
	for mode, key := range firstIdentity.provideSecretKeys {
		if bytes.Equal(key, secondIdentity.provideSecretKeys[mode]) {
			t.Errorf("generation 2's client holds generation 1's %s key", mode)
		}
	}
	if seed, err := loadSidecarConnectIdentitySeed(enrollment.secrets, &SidecarIdentity{ClientId: enrollment.clientId, Generation: 2}); err != nil || seed == nil {
		t.Errorf("the keychain keeps no seed for generation 2: %v", err)
	}
}

// A connect identity record that does not decode is Failed (D-CORE-15): the sidecar opens no client, enters Locked and
// raises refused, a wake tries again and opens none, and the record stays as it was, so nothing overwrites a value
// that failed.
func TestFailedConnectIdentityRecordLocksAndIsKept(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	damaged := []byte("synthetic damage, no connect identity record")
	if err := enrollment.secrets.Put(sidecarConnectIdentityRecordName, damaged); err != nil {
		t.Fatal(err)
	}
	platform := newTestSidecarPlatform()
	events := &alarmTestEvents{}
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))
	sidecar.AddEventCallback(events.add)
	refusedCount := func() int {
		return len(events.of(SidecarEventRefused))
	}
	// each wake is a pass after the callback, whatever the first pass raised before it; each raises refused again,
	// as a failed identity record's pass does
	for range 2 {
		before := refusedCount()
		sidecar.wake()
		awaitSidecarStatus(t, sidecar, func(status SidecarStatus) bool {
			return status.State == SidecarStateLocked && before < refusedCount()
		})
	}
	if opened := len(platform.openedClients()); opened != 0 {
		t.Errorf("%d clients opened on a failed connect identity record", opened)
	}
	for _, event := range events.of(SidecarEventState) {
		if event.State != SidecarStateLocked {
			t.Errorf("the sidecar moved to %s on a failed connect identity record", event.State)
		}
	}
	kept, err := enrollment.secrets.Get(sidecarConnectIdentityRecordName)
	if err != nil || !bytes.Equal(kept, damaged) {
		t.Errorf("the failed record was overwritten: %q, %v", kept, err)
	}
	if sidecar.runningGeneration() != nil {
		t.Error("a generation runs on a failed connect identity record")
	}
}

// The connect leg opens no client for a generation that came with no connect identity: a client on fresh material
// would cost its peers their contracts at the next start, so none opens on material the keychain does not keep.
func TestConnectLegOpensNoClientWithoutAConnectIdentity(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))
	platform.awaitOpened(t, 1)
	leg, ok := sidecar.leg.(*sidecarConnectLeg)
	if !ok {
		t.Fatal("no connect leg")
	}
	identity := sidecar.currentIdentity()
	if identity == nil {
		t.Fatal("no identity")
	}
	ctx, cancel := connectIdentityTestContext()
	defer cancel()
	generation := &sidecarGeneration{
		sidecar: sidecar, generation: identity.Generation, identity: identity, networkId: enrollment.networkId,
		byJwt: enrollment.byJwt, clientKeySeed: enrollment.keys.clientKeySeedCopy(), ctx: ctx, cancel: cancel,
	}
	defer clear(generation.clientKeySeed)
	if started, err := leg.startGeneration(generation); !errors.Is(err, errSidecarNoConnectIdentity) || started != nil {
		t.Fatalf("a generation with no connect identity started: %v", err)
	}
	if opened := len(platform.openedClients()); opened != 1 {
		t.Errorf("%d clients opened, the running generation's alone wanted", opened)
	}
	if !leg.keepsConnectIdentity() {
		t.Error("the connect leg keeps no connect identity")
	}
}
