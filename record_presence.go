// §16.6's presence profiles at every verifier, from a key's row (D-MCP-19, I-8; FS-124): a presence key's per-use
// signature, its countersignature over an act (§7.9's presence row) and its own signature over the KeyRegister that
// registers it (protos-bridge-presence-gaps #3, QD-086). api, evs, gkm and every member device run these alike, so they
// refuse alike, and the spend check and the gates run VerifyPresenceUse on a presence decision.
//
// protocol/bridge holds the checks that need no state, the rp id, flags, client data, origin table and signatures,
// because the keyless device role verifies there; this file adds what a key's row and a verifier's own state give: the
// algorithm from the KeyRow and never from the message (§6.9's algorithm), so an ES256 assertion presented to an
// ecdsa-p256-sha256 key fails; and the signCount of a webauthn-es256 key against the one a spending verifier stored. A
// gate or a reader of one statement holds no counter and passes none, which is D-MCP-19's reason the countersign check
// never compares one.
//
// What a key's row cannot say stays with the caller: that the key is its signer's or approver's, registered through an
// I-8 channel, not void and within its not_after at the verifying state (TEAM-M2-06's LiveKeys); that a statement needs
// a countersignature at all (§7.9's presence row); and that an ecdsa-p256-sha256 key was created with
// kSecAccessControlUserPresence, a creation rule no verifier can see, which MCP-M3-09's prompts keep. Labels, attested or
// asserted, are record_presence_attest.go's.
//
// No key is created, derived or unwrapped here, since these checks take public keys only, so nothing calls
// testHookSecret. Package-level functions are safe for concurrent use; a PresenceCounter's safety is its own. On every
// leg: nothing here names a connect type.

package sidecar

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The purpose of a presence key's own signature over the KeyRegister that registers it (QD-086). No §6.11 type is
// signed under it but SIGNED_KEY_REGISTER, by that KeyRegister's new key, and the identity key never signs it
// (identity_sign.go), so its signed bytes meet no statement's.
const PresenceKeyProofPurpose = "key-proof"

// KeyRegister's fields that carry the new key's own proof (QD-086), written last, in this order.
const (
	presenceKeySignatureNumber protowire.Number = 9
	presenceKeyWebAuthnNumber  protowire.Number = 10
)

// The signCount in WebAuthn's authenticator data: after the rp id hash and the flags byte, 4 bytes big-endian
// (WebAuthn §6.1). bridge.VerifySigned has checked the data is at least this long before anything reads it.
const (
	presenceSignCountOffset = 32 + 1
	presenceSignCountSize   = 4
)

var (
	// The row is no presence key's: missing, of purpose other than presence, revoked, or of an algorithm no §16.6
	// profile has, ssh-ed25519 among them.
	ErrPresenceKey = errors.New("presence key refused")
	// A webauthn-es256 assertion's signCount is not above the one stored for its key, when either is non-zero
	// (§16.6's per use): a replay, or a cloned authenticator.
	ErrPresenceCounter = errors.New("presence counter regression")
	// A KeyRegister's own proof is missing, misplaced, followed by anything, carried by a key that is no presence key,
	// or does not verify (QD-086).
	ErrPresenceRegistration = errors.New("presence registration refused")
)

// Where a verifier that spends presence decisions keeps each webauthn-es256 key's newest signCount (§16.6's per use):
// a daemon spending a decision passes its store. A gate, or a reader of one statement, holds none and passes nil.
type PresenceCounter interface {
	// Runs update with the count stored for keyId, 0 when none is, under the store's own lock, and stores what update
	// returns before returning nil. An error from update stores nothing and is returned as it is. A store that
	// outlives the process writes the count durably before it returns, so a crash cannot roll a key's count back and
	// let a replayed assertion pass. update calls nothing that takes the store's lock.
	UpdatePresenceCount(keyId []byte, update func(storedCount uint32) (uint32, error)) error
}

// §6.9's SignedKeyAlg for a presence key's row, which the row's alg fixes, never the message: webauthn-es256 or
// ecdsa-p256-sha256. Refuses a row that is missing, of another purpose, revoked at the state it was read from, or of
// any other algorithm. A row's not_after and void are the caller's, at the verifying state.
func PresenceKeyAlg(key *bridge.KeyRow) (bridge.SignedKeyAlg, error) {
	if key == nil {
		return 0, fmt.Errorf("%w: no key row", ErrPresenceKey)
	}
	if key.GetPurpose() != bridge.KeyPurpose_KEY_PURPOSE_PRESENCE {
		return 0, fmt.Errorf("%w: purpose %s", ErrPresenceKey, key.GetPurpose())
	}
	if key.GetRevokedAt() != 0 {
		return 0, fmt.Errorf("%w: revoked at %d", ErrPresenceKey, key.GetRevokedAt())
	}
	return presenceSignedKeyAlg(key.GetAlg())
}

// The SignedKeyAlg of a presence key's KeyAlg, and a refusal for any other.
func presenceSignedKeyAlg(keyAlg bridge.KeyAlg) (bridge.SignedKeyAlg, error) {
	switch keyAlg {
	case bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256:
		return bridge.SignedKeyAlgWebAuthnEs256, nil
	case bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256:
		return bridge.SignedKeyAlgEcdsaP256, nil
	}
	return 0, fmt.Errorf("%w: algorithm %s", ErrPresenceKey, keyAlg)
}

// §16.6's per-use check of a statement a presence key signed itself, a presence decision (channel presence) among them,
// as signedType under purpose: bridge.VerifySigned under the row's algorithm and public key, which for webauthn-es256
// checks the rp id hash, UP and UV, the client data's type, challenge and origin, and the signature, and for
// ecdsa-p256-sha256 a DER signature over the signed bytes with no evidence beside it, presence being what the registering
// device asserted. Then, for webauthn-es256 and a non-nil counter, the signCount: above the stored one when either is
// non-zero, and stored as the key's newest. A nil counter compares none (above).
//
// The caller resolves which key signed and that it may (above); the signature binds the key it names, so a statement
// verified under another key's row fails. A countersignature beside the signature is refused, since a presence key's own
// statement carries none.
func VerifyPresenceUse(
	signed *bridge.Signed,
	purpose string,
	signedType bridge.SignedType,
	key *bridge.KeyRow,
	counter PresenceCounter,
) error {
	keyAlg, err := PresenceKeyAlg(key)
	if err != nil {
		return err
	}
	if err := bridge.VerifySigned(signed, purpose, signedType, keyAlg, key.GetPublicKey()); err != nil {
		return err
	}
	if keyAlg != bridge.SignedKeyAlgWebAuthnEs256 || counter == nil {
		return nil
	}

	authenticatorData := signed.GetWebauthn().GetAuthenticatorData()
	signCount := binary.BigEndian.Uint32(
		authenticatorData[presenceSignCountOffset : presenceSignCountOffset+presenceSignCountSize],
	)
	// the store's update is the linearization point, and runs under its lock, so the barriers sit either side of it
	barrierKey := hex.EncodeToString(key.GetKeyId())
	testHookBarrier("record.presence_count.before", barrierKey)
	err = counter.UpdatePresenceCount(key.GetKeyId(), func(storedCount uint32) (uint32, error) {
		if storedCount == 0 && signCount == 0 {
			// an authenticator that keeps no counter, such as a synced passkey (WebAuthn §6.1.1)
			return 0, nil
		}
		if signCount <= storedCount {
			return storedCount, fmt.Errorf("%w: %d after %d", ErrPresenceCounter, signCount, storedCount)
		}
		return signCount, nil
	})
	testHookBarrier("record.presence_count.after", barrierKey)
	return err
}

// §16.6's countersign check from the row of the key that signed.webauthn.key_id names: bridge.VerifyPresenceCountersign
// under the row's algorithm and public key, which walks the statement's leaf to its act's root and checks the
// countersigned bytes with UV set, the signCount never compared (D-MCP-19). The evidence must name this row's key_id.
//
// A nil says this key countersigned purpose, type and body in an act of signed.signer_id, and nothing more: the caller
// also runs VerifySigned for the identity signature and decides, from §7.9's presence row, whether a countersignature is
// required at all, ignoring one it does not require (TEAM-M2-06).
func VerifyPresenceCountersignature(signed *bridge.Signed, purpose string, key *bridge.KeyRow) error {
	keyAlg, err := PresenceKeyAlg(key)
	if err != nil {
		return err
	}
	if signed != nil && !bytes.Equal(signed.GetWebauthn().GetKeyId(), key.GetKeyId()) {
		return fmt.Errorf("%w: the countersignature names another key", bridge.ErrSignedEvidence)
	}
	return bridge.VerifyPresenceCountersign(signed, purpose, keyAlg, key.GetPublicKey())
}

// Checks a presence key's own signature over the KeyRegister that registers it (§16.6's register row; QD-086). register
// is signed's body as ParseConfigStatement parsed it, and signed the statement as received, whose identity signature
// and rule are the caller's (TEAM-M2-06).
//
// The proof is KeyRegister's fields 9 and 10, written last: the body is sliced at field 9's first byte, never
// re-marshaled or emptied, and the new key's signature covers §6.9's signed bytes over what comes before, purpose
// key-proof and type SIGNED_KEY_REGISTER. Field 9 holds a DER signature for both profiles; webauthn-es256 adds field 10,
// its authenticator data and client data, whose challenge is those signed bytes' SHA-256, with UP and UV set and an
// origin on the release table, checked by bridge.VerifySigned like any webauthn-es256 statement. ecdsa-p256-sha256 has
// no field 10. Anything after the proof, a repeat of either field or field 10 first is refused.
//
// The key's algorithm and public key are register's, which must be what the sliced bytes give, so a register parsed
// from other bytes is refused. A KeyRegister of purpose sshsig carries no proof and is refused here: its rule checks
// that fields 9 and 10 are empty instead.
func VerifyPresenceRegistration(register *protocol.KeyRegister, signed *bridge.Signed) error {
	if register == nil || signed == nil {
		return fmt.Errorf("%w: no KeyRegister", ErrPresenceRegistration)
	}
	if signed.GetType() != uint32(bridge.SignedType_SIGNED_KEY_REGISTER) {
		return fmt.Errorf("%w: type %d", ErrPresenceRegistration, signed.GetType())
	}
	if register.GetPurpose() != bridge.KeyPurpose_KEY_PURPOSE_PRESENCE {
		return fmt.Errorf("%w: purpose %s carries no proof", ErrPresenceRegistration, register.GetPurpose())
	}
	keyAlg, err := presenceSignedKeyAlg(register.GetAlg())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPresenceRegistration, err)
	}

	body := signed.GetBody()
	prefixSize, keySignature, keyWebAuthn, err := presenceRegistrationProof(body)
	if err != nil {
		return err
	}
	// what the key signed is the prefix, so the key it names must be the prefix's
	prefix := &protocol.KeyRegister{}
	if err := proto.Unmarshal(body[:prefixSize], prefix); err != nil {
		return fmt.Errorf("%w: %w", ErrPresenceRegistration, err)
	}
	if prefix.GetAlg() != register.GetAlg() || prefix.GetPurpose() != register.GetPurpose() ||
		!bytes.Equal(prefix.GetPublicKey(), register.GetPublicKey()) || !bytes.Equal(prefix.GetKeyId(), register.GetKeyId()) {
		return fmt.Errorf("%w: register is not the statement's body", ErrPresenceRegistration)
	}

	proofSigned := &bridge.Signed{
		Body:      body[:prefixSize],
		Signature: keySignature,
		Type:      uint32(bridge.SignedType_SIGNED_KEY_REGISTER),
	}
	switch keyAlg {
	case bridge.SignedKeyAlgEcdsaP256:
		if keyWebAuthn != nil {
			return fmt.Errorf("%w: webauthn evidence beside an ecdsa-p256-sha256 key's proof", ErrPresenceRegistration)
		}
	case bridge.SignedKeyAlgWebAuthnEs256:
		if keyWebAuthn == nil {
			return fmt.Errorf("%w: a webauthn-es256 key's proof without its evidence", ErrPresenceRegistration)
		}
		evidence := &bridge.WebAuthnEvidence{}
		if err := proto.Unmarshal(keyWebAuthn, evidence); err != nil {
			return fmt.Errorf("%w: evidence: %w", ErrPresenceRegistration, err)
		}
		proofSigned.Webauthn = evidence
	}
	err = bridge.VerifySigned(
		proofSigned,
		PresenceKeyProofPurpose,
		bridge.SignedType_SIGNED_KEY_REGISTER,
		keyAlg,
		register.GetPublicKey(),
	)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPresenceRegistration, err)
	}
	return nil
}

// Where a KeyRegister body's proof starts, with the proof's two values: field 9's bytes, and field 10's bytes or nil
// when it is absent. The proof is field 9 then, optionally, field 10, each once and length-delimited, at the end of the
// body; field 10 alone, either one first after the other, or any field after them is refused.
func presenceRegistrationProof(body []byte) (int, []byte, []byte, error) {
	offset := 0
	for offset < len(body) {
		number, wireType, tagSize := protowire.ConsumeTag(body[offset:])
		if tagSize < 0 {
			return 0, nil, nil, fmt.Errorf("%w: %w", ErrPresenceRegistration, protowire.ParseError(tagSize))
		}
		if number == presenceKeySignatureNumber || number == presenceKeyWebAuthnNumber {
			break
		}
		valueSize := protowire.ConsumeFieldValue(number, wireType, body[offset+tagSize:])
		if valueSize < 0 {
			return 0, nil, nil, fmt.Errorf("%w: %w", ErrPresenceRegistration, protowire.ParseError(valueSize))
		}
		offset += tagSize + valueSize
	}
	prefixSize := offset

	// One length-delimited field of number, or false where the next field is another or the body ends.
	consumeProofField := func(number protowire.Number) ([]byte, bool, error) {
		if offset == len(body) {
			return nil, false, nil
		}
		fieldNumber, wireType, tagSize := protowire.ConsumeTag(body[offset:])
		if tagSize < 0 {
			return nil, false, fmt.Errorf("%w: %w", ErrPresenceRegistration, protowire.ParseError(tagSize))
		}
		if fieldNumber != number {
			return nil, false, nil
		}
		if wireType != protowire.BytesType {
			return nil, false, fmt.Errorf("%w: field %d of wire type %d", ErrPresenceRegistration, number, wireType)
		}
		value, valueSize := protowire.ConsumeBytes(body[offset+tagSize:])
		if valueSize < 0 {
			return nil, false, fmt.Errorf("%w: %w", ErrPresenceRegistration, protowire.ParseError(valueSize))
		}
		offset += tagSize + valueSize
		return value, true, nil
	}

	keySignature, ok, err := consumeProofField(presenceKeySignatureNumber)
	if err != nil {
		return 0, nil, nil, err
	}
	if !ok || len(keySignature) == 0 {
		return 0, nil, nil, fmt.Errorf("%w: no key_signature first in the proof", ErrPresenceRegistration)
	}
	keyWebAuthn, ok, err := consumeProofField(presenceKeyWebAuthnNumber)
	if err != nil {
		return 0, nil, nil, err
	}
	if !ok {
		keyWebAuthn = nil
	} else if keyWebAuthn == nil {
		// present but empty is still present, so it cannot read as absent
		keyWebAuthn = []byte{}
	}
	if offset != len(body) {
		return 0, nil, nil, fmt.Errorf("%w: %d bytes after the proof", ErrPresenceRegistration, len(body)-offset)
	}
	return prefixSize, keySignature, keyWebAuthn, nil
}
