// §17.9's ShareCert (D-BRIDGE-17; DESIGN-DETAILS 12.2.8): what a share's ShareKey signs to certify one ShareSigner of
// one generation of the accepting network's config, and a host's check of it before it reads a share link's
// delegation. ShareCertSigned writes one and VerifyShareCert is the host's admit row's first half, both here, std and
// protobuf only, so the keyless device role that verifies and the root's keyring share one definition (§4.4).
//
// A ShareCert is a Signed of type 0x1909 under purpose window-delegation: signer_id is the share_id, key_id the
// SHA-256 of the ShareKey's public key, and the body names the share, the generation g, g's ShareSigner's public key
// and a not_after_ms at most Lifetime ahead. A verifier resolves key_id to the ShareKey its own network's approving
// admin pinned for that share (BridgeShareKey), never to a key the cert or the delegation carries.
//
// The admit row's checks, in order: the bytes' bound; the type; signer_id the share the check names; key_id the pinned
// key's digest; the signature over the body as received; then the body, whose share_id must be the check's, whose
// not_after_ms must be ahead and at most Lifetime and Skew away, and whose generation must be at least the share's
// ratchet, the newest generation the host has verified and kept. Raising the ratchet is the caller's, committed before
// the contract that carried the cert is admitted (QD-671).
//
// Errors name the check that failed, never a value (I-13). Package-level functions are safe for concurrent use.

package bridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
)

// The format's limits, which the ShareKey's holder and every host share, so their default lives here and each side's
// settings carry it.
type ShareCertSettings struct {
	// The most bytes a Signed ShareCert takes: 1 KiB, where one is about 150 B. A longer one is refused unread.
	// Positive.
	MaxByteCount int
	// The longest a cert runs from its signing, and so the furthest ahead of a verifier's time its not_after_ms may
	// lie, beside Skew: 168 h, §17.9's 7 days. Positive.
	Lifetime time.Duration
	// What a verifier allows between its clock and a signer's (§8.6): 60 s.
	Skew time.Duration
}

// §17.9's values.
func DefaultShareCertSettings() *ShareCertSettings {
	return &ShareCertSettings{
		MaxByteCount: 1024,
		Lifetime:     168 * time.Hour,
		Skew:         60 * time.Second,
	}
}

var (
	// The bytes are no Signed ShareCert: past the bound, not decoding, holding a field this verifier does not know, or
	// an id or key of the wrong length.
	ErrShareCertMalformed = errors.New("share certificate malformed")
	// Not signed by the share's pinned ShareKey, or for another share.
	ErrShareCertSigner = errors.New("share certificate signer refused")
	// not_after_ms is not ahead of the verifier's time.
	ErrShareCertExpired = errors.New("share certificate expired")
	// not_after_ms lies further ahead than a cert may run.
	ErrShareCertLifetime = errors.New("share certificate runs past its lifetime")
	// The cert's generation is below the newest this host verified for the share.
	ErrShareCertGeneration = errors.New("share certificate below the share's newest generation")
)

// What a host holds a ShareCert to (§17.9's admit row). Each value is one the host established itself.
type ShareCertCheck struct {
	// The share the delegation names, which this host's state compiled.
	ShareId []byte
	// That share's pinned ShareKey, Ed25519 (BridgeShareKey.public_key).
	SharePublicKey []byte
	// The verifier's time in ms since the epoch.
	NowMs int64
	// The share's ratchet: the newest generation this host verified and kept; 0 before any.
	Generation uint64
	// The format's limits; nil is DefaultShareCertSettings.
	Settings *ShareCertSettings
}

// Verifies a ShareCert as a share link's delegation carried it, and returns it only when every check passes (the
// file's comment).
func VerifyShareCert(signedBytes []byte, check *ShareCertCheck) (*ShareCert, error) {
	if check == nil || len(check.ShareId) != windowDelegationIdByteCount || !windowDelegationNonZero(check.ShareId) ||
		len(check.SharePublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: no share to hold the certificate to", ErrShareCertSigner)
	}
	settings := check.Settings
	if settings == nil {
		settings = DefaultShareCertSettings()
	}
	if len(signedBytes) == 0 || settings.MaxByteCount < len(signedBytes) {
		return nil, fmt.Errorf("%w: %d bytes", ErrShareCertMalformed, len(signedBytes))
	}
	signed := &Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return nil, fmt.Errorf("%w: the Signed does not decode", ErrShareCertMalformed)
	}
	if signed.GetType() != uint32(SignedType_SIGNED_SHARE_CERT) {
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrSignedTypeMismatch, signed.GetType(), int32(SignedType_SIGNED_SHARE_CERT))
	}
	if !bytes.Equal(signed.GetSignerId(), check.ShareId) {
		return nil, fmt.Errorf("%w: signed for another share", ErrShareCertSigner)
	}
	if keyDigest := sha256.Sum256(check.SharePublicKey); !bytes.Equal(signed.GetKeyId(), keyDigest[:]) {
		return nil, fmt.Errorf("%w: a key_id that is not the pinned ShareKey's", ErrShareCertSigner)
	}
	if err := VerifySigned(signed, SignedPurposeWindowDelegation, SignedType_SIGNED_SHARE_CERT, SignedKeyAlgEd25519, check.SharePublicKey); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrShareCertSigner, err)
	}
	cert := &ShareCert{}
	if err := proto.Unmarshal(signed.GetBody(), cert); err != nil {
		return nil, fmt.Errorf("%w: the body does not decode", ErrShareCertMalformed)
	}
	if 0 < len(cert.ProtoReflect().GetUnknown()) {
		return nil, fmt.Errorf("%w: a field this verifier does not know", ErrShareCertMalformed)
	}
	if !bytes.Equal(cert.GetShareId(), check.ShareId) {
		return nil, fmt.Errorf("%w: a body for another share", ErrShareCertSigner)
	}
	if len(cert.GetSignerPublicKey()) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: a signer key of %d bytes", ErrShareCertMalformed, len(cert.GetSignerPublicKey()))
	}
	if cert.GetNotAfterMs() <= check.NowMs {
		return nil, ErrShareCertExpired
	}
	if check.NowMs+(settings.Lifetime+settings.Skew).Milliseconds() < cert.GetNotAfterMs() {
		return nil, ErrShareCertLifetime
	}
	if cert.GetConfigGeneration() < check.Generation {
		return nil, ErrShareCertGeneration
	}
	return cert, nil
}

// The bytes a BridgeShareSigner file and a share link's delegation carry (§17.9's keys row): cert encoded
// deterministically, signed by the ShareKey whose seed is shareSeed under purpose window-delegation and type 0x1909,
// with signer_id the share_id and key_id the SHA-256 of the ShareKey's public key. Nil settings are
// DefaultShareCertSettings.
func ShareCertSigned(cert *ShareCert, shareSeed []byte, settings *ShareCertSettings) ([]byte, error) {
	if settings == nil {
		settings = DefaultShareCertSettings()
	}
	switch {
	case cert == nil || len(cert.GetShareId()) != windowDelegationIdByteCount || !windowDelegationNonZero(cert.GetShareId()):
		return nil, fmt.Errorf("%w: no share", ErrShareCertMalformed)
	case len(cert.GetSignerPublicKey()) != ed25519.PublicKeySize:
		return nil, fmt.Errorf("%w: a signer key of %d bytes", ErrShareCertMalformed, len(cert.GetSignerPublicKey()))
	case cert.GetNotAfterMs() <= 0:
		return nil, fmt.Errorf("%w: no not_after_ms", ErrShareCertMalformed)
	case len(shareSeed) != ed25519.SeedSize:
		return nil, fmt.Errorf("%w: a ShareKey seed of %d bytes", ErrShareCertMalformed, len(shareSeed))
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(cert)
	if err != nil {
		return nil, fmt.Errorf("%w: the body does not encode", ErrShareCertMalformed)
	}
	shareKey := ed25519.NewKeyFromSeed(shareSeed)
	keyDigest := sha256.Sum256(shareKey.Public().(ed25519.PublicKey))
	signed := &Signed{
		Body:      body,
		SignerId:  bytes.Clone(cert.GetShareId()),
		KeyId:     keyDigest[:],
		Signature: ed25519.Sign(shareKey, SignedBytes(SignedPurposeWindowDelegation, SignedType_SIGNED_SHARE_CERT, body)),
		Type:      uint32(SignedType_SIGNED_SHARE_CERT),
	}
	signedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		return nil, fmt.Errorf("%w: the Signed does not encode", ErrShareCertMalformed)
	}
	if settings.MaxByteCount < len(signedBytes) {
		return nil, fmt.Errorf("%w: %d bytes", ErrShareCertMalformed, len(signedBytes))
	}
	return signedBytes, nil
}

// A share link's delegation signed by a ShareSigner (§17.9's keys and sign rows): the Signed a ShareSigner whose seed
// is signerSeed makes over body under purpose window-delegation and type 0x1908, with signer_id the share_id and
// key_id the SHA-256 of the ShareSigner's public key. WindowDelegationSigned takes it as its sign function's answer.
func ShareSignerSign(shareId []byte, signerSeed []byte, body []byte) (*Signed, error) {
	if len(shareId) != windowDelegationIdByteCount || len(signerSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: no share signer", ErrWindowDelegationMalformed)
	}
	signer := ed25519.NewKeyFromSeed(signerSeed)
	keyDigest := sha256.Sum256(signer.Public().(ed25519.PublicKey))
	return &Signed{
		Body:      body,
		SignerId:  bytes.Clone(shareId),
		KeyId:     keyDigest[:],
		Signature: ed25519.Sign(signer, SignedBytes(SignedPurposeWindowDelegation, SignedType_SIGNED_WINDOW_DELEGATION, body)),
		Type:      uint32(SignedType_SIGNED_WINDOW_DELEGATION),
	}, nil
}
