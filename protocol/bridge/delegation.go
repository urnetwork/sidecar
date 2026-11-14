// §17.9's WindowDelegation at both of its ends (D-BRIDGE-17): WindowDelegationSigned writes what a link's window client
// carries in CreateContract, and VerifyWindowDelegation is a host's check of those bytes, once per contract, before
// the contract's first flow dials. Both live here, std and protobuf only, so the keyless device role that verifies and
// the root's signer share one definition (§4.4).
//
// A delegation is a Signed of type 0x1908 under purpose window-delegation, by one of two keys of its subject, told
// apart by signer_id's length and never by trying keys (QD-093; DESIGN-DETAILS 4.2.2):
//
//	16 bytes  the subject's sidecar_id: its identity key signed, and key_id is empty, as §6.9's Signers row has an
//	          identity key sign. A daemon's sidecar role signs so.
//	32 bytes  a delegation_id: the key of the subject's forwarding Delegation signed (owner decision 197), and key_id is
//	          the SHA-256 of that key. It verifies only under the forwarding key the verifier's state lists for that id,
//	          live, and only for the sidecar the state lists it under. An app's VPN component signs so.
//
// The signature covers the body as received, never a re-marshal, and nothing parses the body until it verifies. C13's
// seal is the operator's statement, a consistency check only (D-BRIDGE-17), so every value a delegation is held to here
// comes from what the verifier established itself, passed in WindowDelegationCheck.
//
// A share link's delegation, signed by a ShareSigner its share_cert names, is §17.9's share signers row, which lands
// with shares (BRIDGE-M6-04, BRIDGE-M6-05); until then one that carries a share or a key_id is refused.
//
// Errors name the check that failed, never a value (I-13). Package-level functions are safe for concurrent use.

package bridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
)

const (
	// §6.9's purpose for window delegations and share certificates (§17.9, §6.11).
	SignedPurposeWindowDelegation = "window-delegation"
	// The length of the ids a delegation names: sidecar, client and network ids (§5).
	windowDelegationIdByteCount = 16
	// The length of a delegation_id, the SHA-256 of a Signed Delegation (§10.5), and of a key_id that is a key's SHA-256.
	windowDelegationDigestByteCount = sha256.Size
)

// The format's limits, which a signer and a verifier share, so their default lives here and each side's settings
// carry it.
type WindowDelegationSettings struct {
	// The most bytes a Signed WindowDelegation takes: 2 KiB, where one is about 200 B, about 280 B under a forwarding
	// key and about 350 B with a ShareCert (§17.9's cost row), with room for the encoding's overhead. A longer one is
	// refused unread. Positive.
	MaxByteCount int
}

// The format's own values.
func DefaultWindowDelegationSettings() *WindowDelegationSettings {
	return &WindowDelegationSettings{
		MaxByteCount: 2 * 1024,
	}
}

var (
	// The bytes are no Signed WindowDelegation: past the bound, not decoding, holding a field this verifier does not
	// know, or an id or key of the wrong length.
	ErrWindowDelegationMalformed = errors.New("window delegation malformed")
	// The signer is not one the check admits: no identity key at the verifier's state, revoked or suspended included,
	// no live forwarding Delegation of the signer's id, a key_id that is not that key's, or not the delegation's own
	// subject.
	ErrWindowDelegationSigner = errors.New("window delegation signer refused")
	// A value the delegation names is not the one the verifier holds: the network, the window client, its key or the
	// target. Also a check value that is none, such as an unsealed network.
	ErrWindowDelegationMismatch = errors.New("window delegation mismatch")
	// not_after_ms is not ahead of the verifier's time.
	ErrWindowDelegationExpired = errors.New("window delegation expired")
	// A share link's delegation, which shares verify (BRIDGE-M6-05); refused until they land.
	ErrWindowDelegationShare = errors.New("window delegation for a share refused")
)

// What a host holds a delegation to (§17.9's verify row). Each value is one the host established itself, never one
// the delegation or a seal says.
type WindowDelegationCheck struct {
	// C13's sealed source network, which the delegation's network_id must equal.
	NetworkId []byte
	// The contract's source client: the window client.
	WindowClientId []byte
	// The sealed session's verified peer key (C15), Ed25519.
	WindowClientPublicKey []byte
	// The host verifying, by its sidecar_id.
	TargetSidecarId []byte
	// The verifier's time in ms since the epoch: not_after_ms must be past it.
	NowMs int64
	// The pinned identity key of the subject a sidecar_id names, through its SidecarAdmit, and false for a subject that
	// is unknown, revoked or suspended at the verifier's state. Called at most once, before the signature is checked.
	IdentityKey func(sidecarId []byte) (publicKey []byte, ok bool)
	// The forwarding Delegation a delegation_id names at the verifier's state: the sidecar whose identity lists it and
	// its Ed25519 key, and false for an id no admitted subject's identity lists live, a superseded or revoked one
	// included. Nil admits no forwarding key. Called at most once, before the signature is checked.
	ForwardingKey func(delegationId []byte) (sidecarId []byte, publicKey []byte, ok bool)
	// The format's limits; nil is DefaultWindowDelegationSettings.
	Settings *WindowDelegationSettings
}

// A delegation that verified, and which of its subject's keys signed it.
type WindowDelegationAdmission struct {
	Delegation *WindowDelegation
	// The forwarding Delegation whose key signed it, 32 bytes; empty where the subject's identity key did. A host
	// keeps it with the principal, since a revocation or supersession of that Delegation ends what its key admitted and
	// nothing the identity key admitted.
	ForwardDelegationId []byte
}

// VerifyWindowDelegationAdmission's delegation alone, for a caller that does not keep which key signed.
func VerifyWindowDelegation(signedBytes []byte, check *WindowDelegationCheck) (*WindowDelegation, error) {
	admission, err := VerifyWindowDelegationAdmission(signedBytes, check)
	if err != nil {
		return nil, err
	}
	return admission.Delegation, nil
}

// Verifies a window client's delegation as its contract carried it, and returns it only when every check passes: a
// Signed of type 0x1908 under purpose window-delegation; its signer by signer_id's length (the file's comment), a
// sidecar_id the check's IdentityKey admits with no key_id, or a delegation_id the check's ForwardingKey admits with
// key_id the SHA-256 of that key; the signature over the body as received; then the body, whose subject_sidecar_id
// must be the signer, or the sidecar the forwarding Delegation is listed under, whose network_id, window_client_id,
// window_client_public_key and target_sidecar_id must equal the check's, and whose not_after_ms must be ahead of the
// check's time. A delegation carrying a share is refused (the file's comment).
func VerifyWindowDelegationAdmission(signedBytes []byte, check *WindowDelegationCheck) (*WindowDelegationAdmission, error) {
	if check == nil || check.IdentityKey == nil {
		return nil, fmt.Errorf("%w: no check to hold the delegation to", ErrWindowDelegationMismatch)
	}
	settings := check.Settings
	if settings == nil {
		settings = DefaultWindowDelegationSettings()
	}
	if len(signedBytes) == 0 || settings.MaxByteCount < len(signedBytes) {
		return nil, fmt.Errorf("%w: %d bytes", ErrWindowDelegationMalformed, len(signedBytes))
	}
	signed := &Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return nil, fmt.Errorf("%w: the Signed does not decode", ErrWindowDelegationMalformed)
	}
	// the type before the signer is looked up, so a share certificate or any other statement goes no further
	if signed.GetType() != uint32(SignedType_SIGNED_WINDOW_DELEGATION) {
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrSignedTypeMismatch, signed.GetType(),
			int32(SignedType_SIGNED_WINDOW_DELEGATION))
	}
	// the path by the signer's length alone: no key is tried under an id of the other kind
	signerId := signed.GetSignerId()
	var publicKey []byte
	// the sidecar the body must name as its subject
	var subjectId []byte
	var forwardDelegationId []byte
	switch len(signerId) {
	case windowDelegationIdByteCount:
		if 0 < len(signed.GetKeyId()) {
			return nil, fmt.Errorf("%w: a key_id, which only a share signer's delegation carries", ErrWindowDelegationShare)
		}
		identityKey, ok := check.IdentityKey(signerId)
		if !ok {
			return nil, fmt.Errorf("%w: a subject with no admitted identity key", ErrWindowDelegationSigner)
		}
		publicKey, subjectId = identityKey, signerId
	case windowDelegationDigestByteCount:
		keyId := signed.GetKeyId()
		if len(keyId) != windowDelegationDigestByteCount {
			return nil, fmt.Errorf("%w: a forwarding signer with a key_id of %d bytes", ErrWindowDelegationMalformed, len(keyId))
		}
		if check.ForwardingKey == nil {
			return nil, fmt.Errorf("%w: no forwarding key is admitted here", ErrWindowDelegationSigner)
		}
		forwardSidecarId, forwardKey, ok := check.ForwardingKey(signerId)
		if !ok || len(forwardSidecarId) != windowDelegationIdByteCount || len(forwardKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: no live forwarding Delegation of that id", ErrWindowDelegationSigner)
		}
		if keyDigest := sha256.Sum256(forwardKey); !bytes.Equal(keyId, keyDigest[:]) {
			return nil, fmt.Errorf("%w: a key_id that is not the forwarding key's", ErrWindowDelegationSigner)
		}
		publicKey, subjectId, forwardDelegationId = forwardKey, forwardSidecarId, bytes.Clone(signerId)
	default:
		return nil, fmt.Errorf("%w: a signer_id of %d bytes", ErrWindowDelegationMalformed, len(signerId))
	}
	if err := VerifySigned(signed, SignedPurposeWindowDelegation, SignedType_SIGNED_WINDOW_DELEGATION, SignedKeyAlgEd25519, publicKey); err != nil {
		return nil, fmt.Errorf("window delegation: %w", err)
	}

	delegation := &WindowDelegation{}
	if err := proto.Unmarshal(signed.GetBody(), delegation); err != nil {
		return nil, fmt.Errorf("%w: the body does not decode", ErrWindowDelegationMalformed)
	}
	// a field this verifier does not know may narrow what the delegation grants, so it is never skipped
	if 0 < len(delegation.ProtoReflect().GetUnknown()) {
		return nil, fmt.Errorf("%w: a field this verifier does not know", ErrWindowDelegationMalformed)
	}
	if 0 < len(delegation.GetShareId()) || 0 < len(delegation.GetShareCert()) {
		return nil, fmt.Errorf("%w: a delegation that carries a share", ErrWindowDelegationShare)
	}
	if !bytes.Equal(delegation.GetSubjectSidecarId(), subjectId) {
		return nil, fmt.Errorf("%w: signed by another than its subject", ErrWindowDelegationSigner)
	}
	matches := []struct {
		name      string
		got       []byte
		want      []byte
		byteCount int
	}{
		{name: "network_id", got: delegation.GetNetworkId(), want: check.NetworkId, byteCount: windowDelegationIdByteCount},
		{name: "window_client_id", got: delegation.GetWindowClientId(), want: check.WindowClientId, byteCount: windowDelegationIdByteCount},
		{name: "window_client_public_key", got: delegation.GetWindowClientPublicKey(), want: check.WindowClientPublicKey, byteCount: ed25519.PublicKeySize},
		{name: "target_sidecar_id", got: delegation.GetTargetSidecarId(), want: check.TargetSidecarId, byteCount: windowDelegationIdByteCount},
	}
	for _, match := range matches {
		// a check value of the wrong length or all zero is none, which nothing matches: an unsealed network among them
		if len(match.want) != match.byteCount || !windowDelegationNonZero(match.want) {
			return nil, fmt.Errorf("%w: no %s to hold the delegation to", ErrWindowDelegationMismatch, match.name)
		}
		if len(match.got) != match.byteCount {
			return nil, fmt.Errorf("%w: a %s of %d bytes", ErrWindowDelegationMalformed, match.name, len(match.got))
		}
		if !bytes.Equal(match.got, match.want) {
			return nil, fmt.Errorf("%w: %s", ErrWindowDelegationMismatch, match.name)
		}
	}
	if delegation.GetNotAfterMs() <= check.NowMs {
		return nil, ErrWindowDelegationExpired
	}
	return &WindowDelegationAdmission{Delegation: delegation, ForwardDelegationId: forwardDelegationId}, nil
}

// Whether any byte is set.
func windowDelegationNonZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return true
		}
	}
	return false
}

// The bytes a window client's contract carries (§17.9's sign row): delegation encoded deterministically, signed by sign
// under purpose window-delegation and type 0x1908, and that Signed encoded as CreateContract.window_delegation holds
// it. sign is the signer's own, such as the root's Sidecar.Sign by the identity key, or a VPN component's forwarding
// signer. This holds the delegation to the lengths VerifyWindowDelegation reads and to no share, and what sign returns
// to a Signed of that type over that body whose signer_id and key_id take one of the two shapes a verifier reads, so a
// signer never hands a link another statement. Nil settings are DefaultWindowDelegationSettings.
func WindowDelegationSigned(
	delegation *WindowDelegation,
	sign func(purpose string, signedType SignedType, body []byte) (*Signed, error),
	settings *WindowDelegationSettings,
) ([]byte, error) {
	if delegation == nil {
		return nil, fmt.Errorf("%w: no delegation", ErrWindowDelegationMalformed)
	}
	if settings == nil {
		settings = DefaultWindowDelegationSettings()
	}
	lengths := []struct {
		name      string
		value     []byte
		byteCount int
	}{
		{name: "network_id", value: delegation.GetNetworkId(), byteCount: windowDelegationIdByteCount},
		{name: "subject_sidecar_id", value: delegation.GetSubjectSidecarId(), byteCount: windowDelegationIdByteCount},
		{name: "window_client_id", value: delegation.GetWindowClientId(), byteCount: windowDelegationIdByteCount},
		{name: "window_client_public_key", value: delegation.GetWindowClientPublicKey(), byteCount: ed25519.PublicKeySize},
		{name: "target_sidecar_id", value: delegation.GetTargetSidecarId(), byteCount: windowDelegationIdByteCount},
	}
	for _, length := range lengths {
		if len(length.value) != length.byteCount {
			return nil, fmt.Errorf("%w: a %s of %d bytes", ErrWindowDelegationMalformed, length.name, len(length.value))
		}
	}
	if delegation.GetNotAfterMs() <= 0 {
		return nil, fmt.Errorf("%w: no not_after_ms", ErrWindowDelegationMalformed)
	}
	if 0 < len(delegation.GetShareId()) || 0 < len(delegation.GetShareCert()) {
		return nil, fmt.Errorf("%w: a delegation that carries a share", ErrWindowDelegationShare)
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(delegation)
	if err != nil {
		return nil, fmt.Errorf("%w: the body does not encode", ErrWindowDelegationMalformed)
	}
	signed, err := sign(SignedPurposeWindowDelegation, SignedType_SIGNED_WINDOW_DELEGATION, body)
	if err != nil {
		return nil, err
	}
	if signed == nil || signed.GetType() != uint32(SignedType_SIGNED_WINDOW_DELEGATION) || !bytes.Equal(signed.GetBody(), body) {
		return nil, fmt.Errorf("%w: the signer returned another statement", ErrWindowDelegationMalformed)
	}
	identitySigned := len(signed.GetSignerId()) == windowDelegationIdByteCount && len(signed.GetKeyId()) == 0
	forwardSigned := len(signed.GetSignerId()) == windowDelegationDigestByteCount && len(signed.GetKeyId()) == windowDelegationDigestByteCount
	if !identitySigned && !forwardSigned {
		return nil, fmt.Errorf("%w: a signer no verifier reads", ErrWindowDelegationMalformed)
	}
	signedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		return nil, fmt.Errorf("%w: the Signed does not encode", ErrWindowDelegationMalformed)
	}
	if settings.MaxByteCount < len(signedBytes) {
		return nil, fmt.Errorf("%w: %d bytes", ErrWindowDelegationMalformed, len(signedBytes))
	}
	return signedBytes, nil
}
