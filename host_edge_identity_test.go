//go:build !sidecar_http && !ios_extension

// An edge client's derived connect identity (host_edge_identity.go): the same seed derives the same client key, sequence
// certificate and Service provide key, byte for byte, another seed others, and a seed that is not one nothing; the pool
// gives each client the identity its seed derives, and a pool made again on the same source the same, and fails closed
// on a seed it cannot use. TestEdgeClientPoolRestartedInPlaceReachesItsListenerAgain runs a restart on the Net.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"
)

// A source of synthetic credentials that answers each index's identity seed, or an error or a seed of the wrong size
// where a test sets one.
type edgePoolTestIdentitySource struct {
	*edgePoolTestSource
	seeds    map[int][]byte
	seedErrs map[int]error
}

func newEdgePoolTestIdentitySource(t testing.TB, count int) *edgePoolTestIdentitySource {
	source := &edgePoolTestIdentitySource{edgePoolTestSource: newEdgePoolTestSource(count), seeds: map[int][]byte{}, seedErrs: map[int]error{}}
	for index := range count {
		source.seeds[index] = edgeIdentityTestSeed(t)
	}
	return source
}

func (self *edgePoolTestIdentitySource) EdgeClientIdentitySeed(ctx context.Context, index int, clientId Id) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.seedErrs[index]; err != nil {
		return nil, err
	}
	if Id(self.clientIds[index]) != clientId {
		return nil, errors.New("another client's seed")
	}
	return bytes.Clone(self.seeds[index]), nil
}

func edgeIdentityTestSeed(t testing.TB) []byte {
	seed := make([]byte, EdgeClientIdentitySeedByteCount)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	return seed
}

func edgeIdentityTestDerive(t testing.TB, seed []byte) *edgeClientIdentity {
	t.Helper()
	identity, err := newEdgeClientIdentity(seed)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

// One seed derives one identity: every field the same bytes at every derivation, a certificate on an Ed25519 key with
// connect's sequence name that loads with its key, and three keys that are not each other.
func TestEdgeClientIdentityIsTheSameForTheSameSeed(t *testing.T) {
	seed := edgeIdentityTestSeed(t)
	first := edgeIdentityTestDerive(t, seed)
	second := edgeIdentityTestDerive(t, bytes.Clone(seed))
	if !bytes.Equal(first.clientKeySeed, second.clientKeySeed) || !bytes.Equal(first.tlsCertificatePem, second.tlsCertificatePem) ||
		!bytes.Equal(first.tlsPrivateKeyPem, second.tlsPrivateKeyPem) || !bytes.Equal(first.serviceProvideSecretKey, second.serviceProvideSecretKey) {
		t.Fatal("one seed derived two identities")
	}
	if len(first.clientKeySeed) != ed25519.SeedSize || len(first.serviceProvideSecretKey) != 32 {
		t.Errorf("a client key seed of %d bytes and a provide key of %d", len(first.clientKeySeed), len(first.serviceProvideSecretKey))
	}
	if bytes.Equal(first.clientKeySeed, first.serviceProvideSecretKey) || bytes.Equal(first.clientKeySeed, seed) || bytes.Equal(first.serviceProvideSecretKey, seed) {
		t.Error("two of the derived keys, or one and the seed, are the same")
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
	publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || !publicKey.Equal(keyPair.PrivateKey.(ed25519.PrivateKey).Public()) {
		t.Error("the certificate is not on its own Ed25519 key")
	}
	if certificate.Subject.CommonName != edgeClientIdentityTlsName || len(certificate.DNSNames) != 1 || certificate.DNSNames[0] != edgeClientIdentityTlsName {
		t.Errorf("the certificate names %q, %v", certificate.Subject.CommonName, certificate.DNSNames)
	}
	if certificate.SerialNumber.Sign() <= 0 || !certificate.NotAfter.Equal(edgeClientIdentityTlsNotAfter) {
		t.Errorf("serial %v, not after %v", certificate.SerialNumber, certificate.NotAfter)
	}
	// self-signed under its own key, which is no CA's, so the signature is checked under the key alone
	if err := certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature); err != nil {
		t.Errorf("the certificate does not verify: %v", err)
	}
	// the TLS key is none of the other keys
	if bytes.Equal(keyPair.PrivateKey.(ed25519.PrivateKey).Seed(), first.clientKeySeed) {
		t.Error("the certificate's key is the client key")
	}
}

func TestEdgeClientIdentityDiffersForAnotherSeed(t *testing.T) {
	first := edgeIdentityTestDerive(t, edgeIdentityTestSeed(t))
	second := edgeIdentityTestDerive(t, edgeIdentityTestSeed(t))
	if bytes.Equal(first.clientKeySeed, second.clientKeySeed) || bytes.Equal(first.tlsCertificatePem, second.tlsCertificatePem) ||
		bytes.Equal(first.tlsPrivateKeyPem, second.tlsPrivateKeyPem) || bytes.Equal(first.serviceProvideSecretKey, second.serviceProvideSecretKey) {
		t.Error("two seeds share part of an identity")
	}
}

func TestEdgeClientIdentityRefusesASeedThatIsNotOne(t *testing.T) {
	for _, byteCount := range []int{0, EdgeClientIdentitySeedByteCount - 1, EdgeClientIdentitySeedByteCount + 1} {
		if identity, err := newEdgeClientIdentity(make([]byte, byteCount)); !errors.Is(err, ErrEdgeClientIdentity) || identity != nil {
			t.Errorf("a %d-byte seed: %v", byteCount, err)
		}
	}
}

// Each client opens with the identity its seed derives: the client key connect publishes, the sequence certificate it
// presents and commits to, and the Service key it provides, which the platform is handed to load before the client can
// receive. A pool made again on the same source, as a restarted process is, presents the same three.
func TestEdgeClientPoolGivesEachClientItsSlotsIdentity(t *testing.T) {
	source := newEdgePoolTestIdentitySource(t, 2)
	presented := func(platform *edgePoolTestPlatform) [][3][]byte {
		pool, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: source, Platform: platform, Settings: newEdgePoolTestSettings(2)})
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		opened := platform.openedArgs()
		identities := [][3][]byte{}
		for index, client := range pool.Clients() {
			want := edgeIdentityTestDerive(t, bytes.Clone(source.seeds[index]))
			connectClient := client.Subprotocol.client
			publicKey := connectClient.ClientKeyManager().PublicKey()
			if !bytes.Equal(publicKey, ed25519.NewKeyFromSeed(want.clientKeySeed).Public().(ed25519.PublicKey)) {
				t.Errorf("client %d's client key is not its seed's", index)
			}
			certificatePem := connectClient.EncryptionSessionManager().ProvideTlsCertificatePem()
			if !bytes.Equal(certificatePem, want.tlsCertificatePem) {
				t.Errorf("client %d's sequence certificate is not its seed's", index)
			}
			serviceKey, ok := connectClient.ContractManager().GetProvideSecretKey(connectprotocol.ProvideMode_Service)
			if !ok || !bytes.Equal(serviceKey, want.serviceProvideSecretKey) {
				t.Errorf("client %d's Service key is not its seed's", index)
			}
			provideSecretKeys := opened[index].ProvideSecretKeys
			if len(provideSecretKeys) != 1 || !bytes.Equal(provideSecretKeys[connectprotocol.ProvideMode_Service], want.serviceProvideSecretKey) {
				t.Errorf("client %d's platform was handed keys %v", index, len(provideSecretKeys))
			}
			identities = append(identities, [3][]byte{publicKey, certificatePem, serviceKey})
		}
		return identities
	}
	first := presented(newEdgePoolTestPlatform())
	restarted := presented(newEdgePoolTestPlatform())
	for index := range first {
		for part := range first[index] {
			if !bytes.Equal(first[index][part], restarted[index][part]) {
				t.Errorf("client %d's identity part %d changed across the restart", index, part)
			}
		}
	}
	if bytes.Equal(first[0][0], first[1][0]) || bytes.Equal(first[0][2], first[1][2]) {
		t.Error("two clients share an identity")
	}
}

// A source that answers no seeds leaves each client to draw its own, as connect does: two pools on it present two
// client keys.
func TestEdgeClientPoolDrawsFreshIdentitiesWithoutASeed(t *testing.T) {
	source := newEdgePoolTestSource(1)
	publicKey := func() []byte {
		platform := newEdgePoolTestPlatform()
		pool, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: source, Platform: platform, Settings: newEdgePoolTestSettings(1)})
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		if keys := platform.openedArgs()[0].ProvideSecretKeys; keys != nil {
			t.Errorf("a source with no seed handed the platform %d keys", len(keys))
		}
		return pool.Clients()[0].Subprotocol.client.ClientKeyManager().PublicKey()
	}
	if bytes.Equal(publicKey(), publicKey()) {
		t.Error("two processes with no seed drew one client key")
	}
}

// A source that answers an error, or a seed that is not one, fails the pool: no client comes up as another identity
// under its id, and the clients opened before it are closed.
func TestEdgeClientPoolFailsClosedOnAnIdentityItCannotUse(t *testing.T) {
	failing := newEdgePoolTestIdentitySource(t, 2)
	failing.seedErrs[1] = errors.New("synthetic seed failure")
	platform := newEdgePoolTestPlatform()
	if _, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: failing, Platform: platform, Settings: newEdgePoolTestSettings(2)}); !errors.Is(err, ErrEdgeClientPool) {
		t.Errorf("a seed the source could not answer: %v", err)
	}
	if len(platform.openedArgs()) != 1 || platform.closedCount() != 1 {
		t.Errorf("%d opened and %d closed after a failed seed", len(platform.openedArgs()), platform.closedCount())
	}
	short := newEdgePoolTestIdentitySource(t, 1)
	short.seeds[0] = short.seeds[0][:EdgeClientIdentitySeedByteCount-1]
	platform = newEdgePoolTestPlatform()
	if _, err := NewEdgeClientPool(t.Context(), &EdgeClientPoolArgs{Source: short, Platform: platform, Settings: newEdgePoolTestSettings(1)}); !errors.Is(err, ErrEdgeClientPool) || !errors.Is(err, ErrEdgeClientIdentity) {
		t.Errorf("a short seed: %v", err)
	}
	if len(platform.openedArgs()) != 0 {
		t.Errorf("%d clients opened on a short seed", len(platform.openedArgs()))
	}
	// the seed is asked for the id the source answered, never another
	other := newEdgePoolTestIdentitySource(t, 1)
	if _, err := other.EdgeClientIdentitySeed(t.Context(), 0, Id(connect.NewId())); err == nil {
		t.Error("the test source answered another client's seed")
	}
}
