//go:build !ios_extension && !sidecar_http

// The connect identity's credentials on connect legs (I-7; §5.9's connect_identity): what a generation's client holds
// of the identity its kept seed derives, made by the client's own derivation (sidecar_new_connect.go), so a matcher
// holds the bytes the client keeps rather than a second reading of the labels. Beside each key go the encodings a
// leaked one is likely to take: the sequence certificate's key as its Ed25519 seed, its private key, its PKCS #8 bytes,
// whose base64 is a PEM's body, and the PEM the client's settings carry, whose own base64 a JSON of those settings
// holds. The certificate is public, as every client's is, and is not listed. record_secret_match_http.go is the page
// Worker's twin.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// The derivation's sequence certificate key did not read back as one Ed25519 key in PKCS #8. Never expected, since
// newSidecarConnectIdentity encodes the key it made; were it to happen, no matcher is built rather than one that
// misses the key.
var errSidecarConnectIdentityTlsKeyFormat = errors.New("the connect identity's sequence certificate key does not read back")

// The seed and each key it derives that grants something, each a copy the caller clears: the sequence certificate's
// key in its four forms and each provide mode's secret key. The derivation reports the seed and the certificate's key
// to testHookSecret, as it does at the client's start.
func sidecarConnectIdentityCredentials(seed []byte) ([][]byte, error) {
	identity, err := newSidecarConnectIdentity(seed)
	if err != nil {
		return nil, err
	}
	credentials := [][]byte{bytes.Clone(seed), identity.tlsPrivateKeyPem}
	for _, provideSecretKey := range identity.provideSecretKeys {
		credentials = append(credentials, provideSecretKey)
	}
	refuse := func() ([][]byte, error) {
		for _, credential := range credentials {
			clear(credential)
		}
		return nil, errSidecarConnectIdentityTlsKeyFormat
	}
	block, rest := pem.Decode(identity.tlsPrivateKeyPem)
	if block == nil || len(rest) != 0 {
		return refuse()
	}
	credentials = append(credentials, block.Bytes)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	tlsKey, ok := key.(ed25519.PrivateKey)
	if err != nil || !ok {
		return refuse()
	}
	return append(credentials, tlsKey.Seed(), []byte(tlsKey)), nil
}
