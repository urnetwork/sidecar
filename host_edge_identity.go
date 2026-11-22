//go:build !sidecar_http && !ios_extension

// An edge client's connect identity, as stable as its client id (§13.6; QD tlsedge-restart-contracts-edge-identity).
// api derives an edge client's id from its environment, host, block, slot and index, so a restart, or a deploy into a
// slot an earlier process held, comes back under the same id while the edge keeps no state. A connect client's identity
// material is drawn fresh each process unless its owner keeps it: the Service provide secret key that every contract
// to it is HMAC'd with, the sequence TLS certificate that every contract to it commits to, and the Ed25519 client key
// its peers verify its identity proof against. A listener that served the earlier process holds its send sequence to
// the id and its queued contracts, all under the earlier material, and a client that drew new material refuses every
// one of them, so the listener's answers wait on its AckTimeout. The sdk keeps the three across an app's restarts for
// this reason; the edge derives them instead.
//
// The block's credential source answers a 32-byte seed per client (EdgeClientIdentitySource), which only the block
// can make (server's PlatformClientSource derives it from the edge bearer, which api holds only as a hash). From it
// the pool derives, each by HKDF-SHA256 under its own label:
//
//   - the client key seed (connect.ClientSettings.ClientKeySeed), so the client key is the one the platform already
//     publishes for the id;
//   - the sequence certificate's Ed25519 key, and the certificate itself on a fixed template whose serial comes from
//     the seed: Ed25519 signs deterministically, so the certificate's bytes are the same at every start, and a
//     contract's commitment to them still matches (EncryptionSettings.ProvideTlsCertificatePem and ...PrivateKeyPem);
//   - the Service provide secret key, which the platform loads before the client can receive
//     (SidecarPlatformClientArgs.ProvideSecretKeys), so a contract signed for the earlier process verifies from the
//     first frame.
//
// The seed and the keys derived from it are secrets: they stay in the process, reach the test hooks' privacy harness
// as they are made, and are never logged (I-7). The provide key alone goes to the platform, as every client's does,
// since the platform signs contracts to the client with it.

package sidecar

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// The seed a source answers: 32 bytes, HKDF-SHA256's output length.
const EdgeClientIdentitySeedByteCount = 32

// The derivation's labels, each a version of its own: a change to one is a new identity for every edge client.
const (
	edgeClientIdentityClientKeyLabel = "urnetwork-edge-client-identity-v1/client-key"
	edgeClientIdentityTlsKeyLabel    = "urnetwork-edge-client-identity-v1/sequence-tls-key"
	edgeClientIdentityTlsSerialLabel = "urnetwork-edge-client-identity-v1/sequence-tls-serial"
	edgeClientIdentityServiceLabel   = "urnetwork-edge-client-identity-v1/provide-service"
)

// The derived certificate's fixed template: the name connect's own sequence certificates carry, and RFC 5280
// §4.1.2.5's validity for a certificate with no well-defined expiration, since peers check the certificate against a
// contract's commitment to its bytes and never its dates (connect's DefaultSequenceServerTlsConfig).
const edgeClientIdentityTlsName = "urnetwork-sequence"

var (
	edgeClientIdentityTlsNotBefore = time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)
	edgeClientIdentityTlsNotAfter  = time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
)

// The serial's bytes from the seed, under a leading 0x01 so the serial is positive and 17 bytes, within RFC 5280's 20.
const edgeClientIdentityTlsSerialByteCount = 16

// A source's seed that is not one.
var ErrEdgeClientIdentity = errors.New("the edge client's identity seed is not one")

// A credential source that can answer each client's identity seed: the same 32 bytes for clientId at every start of
// the block, secret, and for no other client. An edge's source implements it beside ServiceClientSource; a source that
// does not leaves each client to draw fresh material, which costs its listeners their contracts at every restart.
type EdgeClientIdentitySource interface {
	// The seed of index's client, whose id the source answered as clientId. A fresh slice, which the caller clears.
	EdgeClientIdentitySeed(ctx context.Context, index int, clientId Id) ([]byte, error)
}

// One client's derived material, borrowed by its settings for the client's life.
type edgeClientIdentity struct {
	clientKeySeed           []byte
	tlsCertificatePem       []byte
	tlsPrivateKeyPem        []byte
	serviceProvideSecretKey []byte
}

// Derives a client's identity from its seed. The same seed answers the same bytes, field for field.
func newEdgeClientIdentity(seed []byte) (*edgeClientIdentity, error) {
	if len(seed) != EdgeClientIdentitySeedByteCount {
		return nil, fmt.Errorf("%w: %d bytes", ErrEdgeClientIdentity, len(seed))
	}
	testHookSecret("edge_client_identity_seed", seed)
	derive := func(label string, byteCount int) ([]byte, error) {
		return hkdf.Key(sha256.New, seed, nil, label, byteCount)
	}
	clientKeySeed, err := derive(edgeClientIdentityClientKeyLabel, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	testHookSecret("edge_client_key_seed", clientKeySeed)
	tlsKeySeed, err := derive(edgeClientIdentityTlsKeyLabel, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	testHookSecret("edge_client_sequence_tls_key", tlsKeySeed)
	tlsKey := ed25519.NewKeyFromSeed(tlsKeySeed)
	clear(tlsKeySeed)
	serialBytes, err := derive(edgeClientIdentityTlsSerialLabel, edgeClientIdentityTlsSerialByteCount)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(append([]byte{0x01}, serialBytes...)),
		Subject:      pkix.Name{CommonName: edgeClientIdentityTlsName},
		NotBefore:    edgeClientIdentityTlsNotBefore,
		NotAfter:     edgeClientIdentityTlsNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{edgeClientIdentityTlsName},
	}
	// Ed25519 ignores the reader, so the certificate's bytes follow from the seed alone
	certificateDer, err := x509.CreateCertificate(rand.Reader, template, template, tlsKey.Public(), tlsKey)
	if err != nil {
		return nil, err
	}
	privateKeyDer, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	clear(tlsKey)
	if err != nil {
		return nil, err
	}
	tlsPrivateKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDer})
	clear(privateKeyDer)
	serviceProvideSecretKey, err := derive(edgeClientIdentityServiceLabel, sha256.Size)
	if err != nil {
		return nil, err
	}
	return &edgeClientIdentity{
		clientKeySeed:           clientKeySeed,
		tlsCertificatePem:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDer}),
		tlsPrivateKeyPem:        tlsPrivateKeyPem,
		serviceProvideSecretKey: serviceProvideSecretKey,
	}, nil
}
