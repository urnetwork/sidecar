// Checks a typed Signed (§6.9, D-PROTO-7). Every statement a client acts on passes through VerifySigned
// (I-4), and it lives here so the keyless device role verifies without linking protocol (§4.4).
//
// Signatures cover the bytes as received, never a re-marshal (§22.6): VerifySigned reads Signed.body and
// parses nothing inside it, and a caller parses that body only after it returns nil, only as the
// message its type registers. They cover purpose, type and body and nothing else of a Signed, so what
// names a statement comes from those three (SignedBytesSha256), never from the Signed around them.
//
// No key is created, derived or unwrapped here, since these checks take public keys only, so nothing
// calls testHookSecret. Package-level functions are safe for concurrent use.

package bridge

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Starts every signed bytes (§6.9).
const signedBytesPrefix = "urnetwork-sidecar-v1/"

// Names the countersigned bytes' domain and is no §6.11 purpose, so signed bytes never reach it.
const presenceActPurpose = "presence-act"

// §16.6's webauthn-es256 per-use profile. The authenticator data is the rp id's SHA-256, a flags byte,
// then a 4-byte counter (WebAuthn §6.1).
const (
	webAuthnRpId                          = "ur.io"
	webAuthnClientDataTypeGet             = "webauthn.get"
	webAuthnFlagsOffset                   = sha256.Size
	webAuthnFlagUserPresent          byte = 0x01
	webAuthnFlagUserVerified         byte = 0x04
	webAuthnAuthenticatorDataMinSize      = sha256.Size + 1 + 4
)

var (
	// No Signed was given.
	ErrSignedMissing = errors.New("no signed statement")
	// The expected type is 0 or outside SignedType (§6.11).
	ErrSignedTypeUnknown = errors.New("signed type unknown")
	// The purpose is empty, holds a 0x00, which would make the signed bytes ambiguous, or is
	// "presence-act", which would reach the countersigned bytes' domain (§6.9).
	ErrSignedPurpose = errors.New("signed purpose refused")
	// Signed.type is not the expected type.
	ErrSignedTypeMismatch = errors.New("signed type mismatch")
	// The evidence does not fit the signer, or for webauthn-es256 does not pass (§6.9, §16.6).
	ErrSignedEvidence = errors.New("signed evidence refused")
	// The key algorithm is unknown, the public key is malformed for it, or a key the statement carries is
	// not the one its row binds.
	ErrSignedKey = errors.New("signed key refused")
	// The signature does not verify.
	ErrSignedSignature = errors.New("signed signature refused")
)

// The algorithm of the key record that Signed.key_id names. That record fixes it, never the message
// (§6.9). Zero is no algorithm, so an unset value fails closed.
type SignedKeyAlg int

const (
	// An Ed25519 public key of 32 bytes: identity keys, agent subkeys and share keys.
	SignedKeyAlgEd25519 SignedKeyAlg = iota + 1
	// A P-256 public key as a SEC 1 uncompressed point of 65 bytes, with a DER signature over the signed
	// bytes (§16.6's ecdsa-p256-sha256).
	SignedKeyAlgEcdsaP256
	// A P-256 public key as for SignedKeyAlgEcdsaP256, with a DER signature over authenticator data and
	// client data (§16.6's webauthn-es256).
	SignedKeyAlgWebAuthnEs256
)

// What a signature covers (§6.9): "urnetwork-sidecar-v1/" || purpose || 0x00 || u32be(type) || body.
// Signers call this too, so one definition serves both ends. VerifySigned refuses a purpose this
// encoding cannot keep apart.
func SignedBytes(purpose string, signedType SignedType, body []byte) []byte {
	signedBytes := make([]byte, 0, len(signedBytesPrefix)+len(purpose)+1+4+len(body))
	signedBytes = append(signedBytes, signedBytesPrefix...)
	signedBytes = append(signedBytes, purpose...)
	signedBytes = append(signedBytes, 0x00)
	signedBytes = binary.BigEndian.AppendUint32(signedBytes, uint32(signedType))
	return append(signedBytes, body...)
}

// The signed bytes' SHA-256: ECDSA's digest, WebAuthn's challenge and an act's leaf (§7.9), and the one hash of a
// statement that its signature fixes, so what refuses a repeat keys on this.
//
// A hash of the Signed is no identity. No signature covers its signer_id, key_id, webauthn or unknown fields, or
// the way it is encoded, §7.9 ignores a countersignature it does not require, and ECDSA takes (r, n - s) as well as
// (r, s), so a relay can write one statement as any number of Signeds that all verify and all hash apart. §7.9's
// replay row, keyed on such a hash, would pass each as new.
func SignedBytesSha256(purpose string, signedType SignedType, body []byte) [sha256.Size]byte {
	return sha256.Sum256(SignedBytes(purpose, signedType, body))
}

// Refuses a type other than expectedType, then checks the signature over the signed bytes. Returns nil
// only when signed verifies under publicKey as that type. A nil says that of the purpose, type and body,
// and nothing of the rest of signed (SignedBytesSha256).
//
// Callers resolve Signed.key_id to its key record for keyAlg and publicKey, and pass the purpose and
// type their position expects, or for a recovery key, which has no such record, call VerifyRecoverySigned.
// A purpose and type that were not signed together fail the signature, since both are in the signed bytes.
// A heterogeneous list (deltas) maps each Signed.type to its purpose and parser before calling this (§6.11).
//
// Evidence must fit: without its key_id only for a webauthn-es256 signer, and with it, a countersignature,
// only beside an Ed25519 signature, which is as near as this comes to knowing an identity key. A
// countersignature is never checked here: nil says nothing about one, so a caller holding a statement
// §7.9's presence row covers must check it apart, and any other caller ignores it.
//
// For webauthn-es256 this checks everything in §16.6's per-use profile that needs no state: the rp id
// hash, UP and UV, the client data's type and challenge, and the signature. Two checks stay with the
// caller: the signCount against the stored one, and the origin against the profile's per-platform list.
func VerifySigned(signed *Signed, purpose string, expectedType SignedType, keyAlg SignedKeyAlg, publicKey []byte) error {
	if signed == nil {
		return ErrSignedMissing
	}
	if _, ok := SignedType_name[int32(expectedType)]; !ok || expectedType == SignedType_SIGNED_TYPE_NONE {
		return fmt.Errorf("%w: %d", ErrSignedTypeUnknown, int32(expectedType))
	}
	if purpose == "" || purpose == presenceActPurpose || strings.IndexByte(purpose, 0x00) >= 0 {
		return fmt.Errorf("%w: %q", ErrSignedPurpose, purpose)
	}
	if signed.GetType() != uint32(expectedType) {
		return fmt.Errorf("%w: got %d, expected %d", ErrSignedTypeMismatch, signed.GetType(), int32(expectedType))
	}

	evidence := signed.GetWebauthn()

	switch keyAlg {
	case SignedKeyAlgEd25519:
		if evidence != nil && len(evidence.GetKeyId()) == 0 {
			return fmt.Errorf("%w: webauthn evidence beside an ed25519 signature", ErrSignedEvidence)
		}
		// ed25519.Verify panics on any other length, and this length comes from a key record.
		if len(publicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: ed25519 public key of %d bytes", ErrSignedKey, len(publicKey))
		}
		if !ed25519.Verify(publicKey, SignedBytes(purpose, expectedType, signed.GetBody()), signed.GetSignature()) {
			return ErrSignedSignature
		}
		return nil

	case SignedKeyAlgEcdsaP256:
		if evidence != nil {
			return fmt.Errorf("%w: evidence beside an ecdsa-p256-sha256 signature", ErrSignedEvidence)
		}
		ecdsaKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), publicKey)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSignedKey, err)
		}
		digest := SignedBytesSha256(purpose, expectedType, signed.GetBody())
		if !ecdsa.VerifyASN1(ecdsaKey, digest[:], signed.GetSignature()) {
			return ErrSignedSignature
		}
		return nil

	case SignedKeyAlgWebAuthnEs256:
		if evidence == nil {
			return fmt.Errorf("%w: a webauthn-es256 signature without evidence", ErrSignedEvidence)
		}
		if len(evidence.GetKeyId()) != 0 {
			return fmt.Errorf("%w: a countersignature beside a webauthn-es256 signature", ErrSignedEvidence)
		}
		// Only a countersignature uses these, and no signature here covers them.
		if len(evidence.GetSignature()) != 0 || evidence.GetActSize() != 0 || evidence.GetActIndex() != 0 ||
			len(evidence.GetActPath()) != 0 {
			return fmt.Errorf("%w: countersignature fields without a key_id", ErrSignedEvidence)
		}

		authenticatorData := evidence.GetAuthenticatorData()
		if len(authenticatorData) < webAuthnAuthenticatorDataMinSize {
			return fmt.Errorf("%w: authenticator data of %d bytes", ErrSignedEvidence, len(authenticatorData))
		}
		rpIdHash := sha256.Sum256([]byte(webAuthnRpId))
		if !bytes.Equal(authenticatorData[:sha256.Size], rpIdHash[:]) {
			return fmt.Errorf("%w: rp id hash", ErrSignedEvidence)
		}
		requiredFlags := webAuthnFlagUserPresent | webAuthnFlagUserVerified
		if authenticatorData[webAuthnFlagsOffset]&requiredFlags != requiredFlags {
			return fmt.Errorf("%w: UP or UV unset", ErrSignedEvidence)
		}

		var clientData struct {
			Type      string `json:"type"`
			Challenge string `json:"challenge"`
		}
		if err := json.Unmarshal(evidence.GetClientDataJson(), &clientData); err != nil {
			return fmt.Errorf("%w: client data: %w", ErrSignedEvidence, err)
		}
		if clientData.Type != webAuthnClientDataTypeGet {
			return fmt.Errorf("%w: client data type", ErrSignedEvidence)
		}
		// The challenge is the SHA-256 of the signed bytes, so it covers the type.
		challenge := SignedBytesSha256(purpose, expectedType, signed.GetBody())
		if clientData.Challenge != base64.RawURLEncoding.EncodeToString(challenge[:]) {
			return fmt.Errorf("%w: challenge", ErrSignedEvidence)
		}

		ecdsaKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), publicKey)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSignedKey, err)
		}
		clientDataHash := sha256.Sum256(evidence.GetClientDataJson())
		digest := sha256.New()
		digest.Write(authenticatorData)
		digest.Write(clientDataHash[:])
		if !ecdsa.VerifyASN1(ecdsaKey, digest.Sum(nil), signed.GetSignature()) {
			return ErrSignedSignature
		}
		return nil

	default:
		return fmt.Errorf("%w: algorithm %d", ErrSignedKey, int(keyAlg))
	}
}

// Checks a statement a member's recovery key signed (§7.9's Recovery), before or after its device is admitted. The
// key has no record to resolve: a RecoveryBind seals it and rows keep only its hash, so the statement carries it in
// Signed.key_id, and recoveryKeySha256 is the MemberRow.recovery_key_sha256 of the member its signer_id names. That
// match is what vouches for the key, so nothing parses the body first, and VerifySigned then holds it to every rule
// as an Ed25519 signer. An empty recoveryKeySha256, a member with no binding, refuses.
//
// Which statements a recovery key may sign, and whether the binding may still act, are the caller's, as a signer's
// role is for VerifySigned. Its statements need no presence countersignature, so a nil says nothing of one.
func VerifyRecoverySigned(signed *Signed, purpose string, expectedType SignedType, recoveryKeySha256 []byte) error {
	if signed == nil {
		return ErrSignedMissing
	}
	publicKeySha256 := sha256.Sum256(signed.GetKeyId())
	if !bytes.Equal(publicKeySha256[:], recoveryKeySha256) {
		return fmt.Errorf("%w: not the member's recovery key", ErrSignedKey)
	}
	return VerifySigned(signed, purpose, expectedType, SignedKeyAlgEd25519, signed.GetKeyId())
}
