// §13.8's key attestation: a device's identity key saying this P-256 key, for these names, is its own. It binds the
// SPKI and the identifier set together, so a chain for another key or for other names never verifies, and it is what
// the CT watch reads a certificate back against (D-TLS-8), so an operator that can pass DNS-01 still cannot attest.
//
// Signing goes through a function value in Sidecar.Sign's shape (CORE-M1-05), and no key is created, derived or
// unwrapped here, so nothing calls testHookSecret. Package-level functions are safe for concurrent use.
//
// Errors name fields, never their values (I-13).

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The purpose SIGNED_TLS_KEY_ATTESTATION signs under (§6.11, §13.8). Protocol, not policy: it is in the signed bytes.
const TlsKeyAttestationPurpose = "tls-key"

var (
	// The bytes are no Signed, its body is no TlsKeyAttestation, or a field is not the size or value it must be.
	ErrTlsKeyAttestationMalformed = errors.New("tls key attestation malformed")
	// It verifies and says something else: another network, sidecar, key or identifier set.
	ErrTlsKeyAttestationMismatch = errors.New("tls key attestation mismatch")
)

// Signs a statement with the device's identity key and answers §6.9's Signed, signer_id the sidecar_id, in the shape
// of Sidecar.Sign (CORE-M1-05), so a Sidecar's method value is one. agentId is a label there and selects no key, and an
// attestation passes nil, since only the identity key attests. May be called from any goroutine.
type TlsKeyAttestationSignFunction func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error)

// Refuses an attestation whose fields cannot be one, on both sides of the signature.
func checkTlsKeyAttestation(attestation *protocol.TlsKeyAttestation) error {
	if len(attestation.GetNetworkId()) != len(Id{}) || len(attestation.GetSidecarId()) != len(Id{}) {
		return fmt.Errorf("%w: id size", ErrTlsKeyAttestationMalformed)
	}
	if len(attestation.GetSpkiSha256()) != sha256.Size || len(attestation.GetIdentifierSetSha256()) != sha256.Size {
		return fmt.Errorf("%w: hash size", ErrTlsKeyAttestationMalformed)
	}
	if attestation.GetIssueTimeMillis() == 0 {
		return fmt.Errorf("%w: no issue time", ErrTlsKeyAttestationMalformed)
	}
	return nil
}

// Signs attestation through sign and answers the Signed's encoded bytes, as TlsCertOrderArgs.Attestation carries them.
// The caller sets every field, the time from its own clock, and the set's hash from verified config, never a server's
// answer.
func SignTlsKeyAttestation(attestation *protocol.TlsKeyAttestation, sign TlsKeyAttestationSignFunction) ([]byte, error) {
	if err := checkTlsKeyAttestation(attestation); err != nil {
		return nil, err
	}
	signedType := bridge.SignedType_SIGNED_TLS_KEY_ATTESTATION
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(attestation)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTlsKeyAttestationMalformed, err)
	}
	signed, err := sign(TlsKeyAttestationPurpose, signedType, body, nil)
	if err != nil {
		return nil, err
	}
	// a nil, another statement or another signer from sign would otherwise reach certs as an attestation that only
	// fails there
	if signed.GetType() != uint32(signedType) || !bytes.Equal(signed.GetBody(), body) ||
		!bytes.Equal(signed.GetSignerId(), attestation.GetSidecarId()) {
		return nil, fmt.Errorf("%w: sign answered another statement", ErrTlsKeyAttestationMalformed)
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(signed)
}

// Checks attestation, a Signed's encoded bytes, as the attestation of this network's sidecarId under its identity key,
// for this key and identifier set, and answers its body, whose issue time the CT watch reads. Nil answers only for a
// statement of that type and purpose verifying under identityPublicKey, whose body parses only after that (§6.9).
//
// identityPublicKey is the caller's to resolve from sidecarId in state it trusts: certs from the gate, a device from
// its own config, never from the Signed around this. spkiSha256 and identifierSetSha256 come from what the attestation
// is said to cover, the CSR or the certificate, so a mismatch is a refusal.
//
// A signature covers no signer_id, so this refuses one other than sidecarId rather than leave a caller that resolved
// its key from there holding a statement by another sidecar.
func VerifyTlsKeyAttestation(
	attestation []byte,
	identityPublicKey []byte,
	networkId Id,
	sidecarId Id,
	spkiSha256 [sha256.Size]byte,
	identifierSetSha256 [sha256.Size]byte,
) (*protocol.TlsKeyAttestation, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(attestation, signed); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTlsKeyAttestationMalformed, err)
	}
	err := bridge.VerifySigned(
		signed,
		TlsKeyAttestationPurpose,
		bridge.SignedType_SIGNED_TLS_KEY_ATTESTATION,
		bridge.SignedKeyAlgEd25519,
		identityPublicKey,
	)
	if err != nil {
		return nil, err
	}
	body := &protocol.TlsKeyAttestation{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTlsKeyAttestationMalformed, err)
	}
	if err := checkTlsKeyAttestation(body); err != nil {
		return nil, err
	}
	switch {
	case !bytes.Equal(body.GetNetworkId(), networkId[:]):
		return nil, fmt.Errorf("%w: network", ErrTlsKeyAttestationMismatch)
	case !bytes.Equal(body.GetSidecarId(), sidecarId[:]) || !bytes.Equal(signed.GetSignerId(), sidecarId[:]):
		return nil, fmt.Errorf("%w: sidecar", ErrTlsKeyAttestationMismatch)
	case !bytes.Equal(body.GetSpkiSha256(), spkiSha256[:]):
		return nil, fmt.Errorf("%w: key", ErrTlsKeyAttestationMismatch)
	case !bytes.Equal(body.GetIdentifierSetSha256(), identifierSetSha256[:]):
		return nil, fmt.Errorf("%w: identifier set", ErrTlsKeyAttestationMismatch)
	}
	return body, nil
}
