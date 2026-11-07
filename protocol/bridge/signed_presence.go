// §7.9's presence countersignature: one presence check over an act of statements, which each statement carries and
// verifies alone, in any landing order (owner decisions 185, 187, 189 and 192; D-TEAM-32). api, evs, gkm and every
// member device run VerifyPresenceCountersign, so they refuse alike, and an act's tree is defined here, once, for
// TEAM-M2-06's BuildPresenceAct to build on.
//
// §16.6's webauthn-es256 profile lives here too, because protocol/bridge imports nothing upward: the MCP area extends
// this file's table rather than supplying a function. The table is values, so a release changes it and nothing
// registers into it.
//
// An act's tree is RFC 9162's over d_0..d_{m-1}, each d_i the SHA-256 of statement i's signed bytes, so a leaf hash is
// SHA-256(0x00 || d_i) and each statement still covers its own purpose and type. No key is created, derived or
// unwrapped here, so nothing calls testHookSecret. Package-level functions are safe for concurrent use.

package bridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/bits"
	"slices"
)

// §16.6's webauthn-es256 profile. The authenticator data is the rp id's SHA-256, a flags byte, then a 4-byte counter
// (WebAuthn §6.1).
const (
	webAuthnRpId                          = "ur.io"
	webAuthnClientDataTypeGet             = "webauthn.get"
	webAuthnFlagsOffset                   = sha256.Size
	webAuthnFlagUserPresent          byte = 0x01
	webAuthnFlagUserVerified         byte = 0x04
	webAuthnAuthenticatorDataMinSize      = sha256.Size + 1 + 4
)

// §16.6's "profile's per-platform list", which a countersignature's origin must be on. It holds one origin until
// plan-MCP-presence-origins.md is answered, so any other, an Android passkey's among them, is refused.
var webAuthnOrigins = [...]string{"https://ur.io"}

// §7.9's act: m is 1 to 65,535, so its deepest leaf has 16 hashes to the root.
const (
	presenceActMaxSize     = 65535
	presenceActPathMaxSize = 16
)

// RFC 9162 §2.1.1's prefixes, which keep a leaf from being read as a node.
const (
	presenceActLeafPrefix byte = 0x00
	presenceActNodePrefix byte = 0x01
)

// What a presence key signs for an act (§7.9): "urnetwork-sidecar-v1/presence-act" || 0x00 || signer_id ||
// u32be(act_size) || root. signer_id is the only field that varies in length, so the last 36 bytes split it from the
// rest. Signers call this too, so one definition serves both ends.
func PresenceActBytes(signerId []byte, actSize uint32, root [sha256.Size]byte) []byte {
	actBytes := make([]byte, 0, len(signedBytesPrefix)+len(presenceActPurpose)+1+len(signerId)+4+sha256.Size)
	actBytes = append(actBytes, signedBytesPrefix...)
	actBytes = append(actBytes, presenceActPurpose...)
	actBytes = append(actBytes, 0x00)
	actBytes = append(actBytes, signerId...)
	actBytes = binary.BigEndian.AppendUint32(actBytes, actSize)
	return append(actBytes, root[:]...)
}

// RFC 9162's MTH over an act's statements in act order, each given as SignedBytesSha256 returns it. Refuses an act
// with no statement or over 65,535, which no verifier would take.
func PresenceActRoot(statementDigests [][sha256.Size]byte) ([sha256.Size]byte, error) {
	leafHashes, err := presenceActLeafHashes(statementDigests)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return presenceActTreeHash(leafHashes), nil
}

// RFC 9162 §2.1.3.1's inclusion path of the statement at actIndex, as WebAuthnEvidence.act_path carries it: empty for
// an act of one. Each call hashes the whole act, so a builder that paths all m statements does about m² hashes, which
// is nothing at the few statements an act signs and minutes near the cap.
func PresenceActPath(statementDigests [][sha256.Size]byte, actIndex uint32) ([][]byte, error) {
	leafHashes, err := presenceActLeafHashes(statementDigests)
	if err != nil {
		return nil, err
	}
	if uint64(actIndex) >= uint64(len(leafHashes)) {
		return nil, fmt.Errorf("%w: index %d of %d statements", ErrSignedAct, actIndex, len(leafHashes))
	}
	return presenceActTreePath(leafHashes, int(actIndex)), nil
}

// Checks signed.webauthn as §7.9's presence countersignature by the key its key_id names, keyAlg and publicKey being
// that key's: hashes signed's own signed bytes as its leaf, walks its inclusion path to the act's root, and runs
// §16.6's countersign check over the countersigned bytes they give, UV set and the signCount not compared: the
// statement's nonce and §7.9's replay row refuse a reuse, and a verifier of one statement holds no counter.
//
// A nil says this key countersigned this purpose, type and body in an act of this signer_id, and nothing more. So a
// caller also runs VerifySigned, for the type its position expects and the identity signature; resolves key_id to a
// presence key the signer registered, live at the verifying state; and decides that a countersignature is required at
// all, ignoring it where §7.9's presence row does not (TEAM-M2-06).
//
// A presence key is P-256, so SignedKeyAlgEd25519 refuses. For SignedKeyAlgEcdsaP256 the user verification is the
// access control the key was created with, which no verifier can see (§16.6). For SignedKeyAlgWebAuthnEs256 the rp id
// hash, client data type and origin come from this file's table.
func VerifyPresenceCountersign(signed *Signed, purpose string, keyAlg SignedKeyAlg, publicKey []byte) error {
	if signed == nil {
		return ErrSignedMissing
	}
	// Signed.type is the leaf's, so an unregistered value stops here as VerifySigned stops one. It is not compared with
	// an expected type, which is VerifySigned's: the leaf covers it, so a rewritten value walks to another root.
	signedType := SignedType(signed.GetType())
	if !signedTypeRegistered(signedType) {
		return fmt.Errorf("%w: %d", ErrSignedTypeUnknown, signed.GetType())
	}
	if !signedPurposeUsable(purpose) {
		return fmt.Errorf("%w: %q", ErrSignedPurpose, purpose)
	}

	evidence := signed.GetWebauthn()
	if len(evidence.GetKeyId()) == 0 {
		return fmt.Errorf("%w: no countersignature", ErrSignedEvidence)
	}
	// An act is one signer's, and an empty id would leave the bytes naming nobody.
	if len(signed.GetSignerId()) == 0 {
		return fmt.Errorf("%w: a countersignature with no signer_id", ErrSignedEvidence)
	}

	statementDigest := SignedBytesSha256(purpose, signedType, signed.GetBody())
	root, err := presenceActPathRoot(
		presenceActLeafHash(statementDigest),
		evidence.GetActIndex(),
		evidence.GetActSize(),
		evidence.GetActPath(),
	)
	if err != nil {
		return err
	}
	countersignedBytes := PresenceActBytes(signed.GetSignerId(), evidence.GetActSize(), root)

	switch keyAlg {
	case SignedKeyAlgEcdsaP256:
		if len(evidence.GetAuthenticatorData()) != 0 || len(evidence.GetClientDataJson()) != 0 {
			return fmt.Errorf("%w: an assertion beside an ecdsa-p256-sha256 countersignature", ErrSignedEvidence)
		}
		digest := sha256.Sum256(countersignedBytes)
		return verifyP256Signature(publicKey, digest[:], evidence.GetSignature())

	case SignedKeyAlgWebAuthnEs256:
		origin, err := checkWebAuthnAssertion(evidence, countersignedBytes)
		if err != nil {
			return err
		}
		if !slices.Contains(webAuthnOrigins[:], origin) {
			return fmt.Errorf("%w: origin %q", ErrSignedEvidence, origin)
		}
		return verifyWebAuthnSignature(evidence, evidence.GetSignature(), publicKey)

	default:
		return fmt.Errorf("%w: algorithm %d is no presence key's", ErrSignedKey, int(keyAlg))
	}
}

// §16.6's webauthn-es256 checks that come before the signature, over message, a statement's signed bytes or an act's
// countersigned bytes: the rp id hash, UP and UV, the client data's type, and a challenge that is message's SHA-256.
// Returns the client data's origin, for a caller holding the list it must be on.
func checkWebAuthnAssertion(evidence *WebAuthnEvidence, message []byte) (string, error) {
	authenticatorData := evidence.GetAuthenticatorData()
	if len(authenticatorData) < webAuthnAuthenticatorDataMinSize {
		return "", fmt.Errorf("%w: authenticator data of %d bytes", ErrSignedEvidence, len(authenticatorData))
	}
	rpIdHash := sha256.Sum256([]byte(webAuthnRpId))
	if !bytes.Equal(authenticatorData[:sha256.Size], rpIdHash[:]) {
		return "", fmt.Errorf("%w: rp id hash", ErrSignedEvidence)
	}
	requiredFlags := webAuthnFlagUserPresent | webAuthnFlagUserVerified
	if authenticatorData[webAuthnFlagsOffset]&requiredFlags != requiredFlags {
		return "", fmt.Errorf("%w: UP or UV unset", ErrSignedEvidence)
	}

	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(evidence.GetClientDataJson(), &clientData); err != nil {
		return "", fmt.Errorf("%w: client data: %w", ErrSignedEvidence, err)
	}
	if clientData.Type != webAuthnClientDataTypeGet {
		return "", fmt.Errorf("%w: client data type", ErrSignedEvidence)
	}
	challenge := sha256.Sum256(message)
	if clientData.Challenge != base64.RawURLEncoding.EncodeToString(challenge[:]) {
		return "", fmt.Errorf("%w: challenge", ErrSignedEvidence)
	}
	return clientData.Origin, nil
}

// Checks §16.6's DER ECDSA P-256 signature over authenticatorData || SHA-256(clientDataJSON), which is Signed.signature
// for a webauthn-es256 signer and the evidence's own for a countersignature.
func verifyWebAuthnSignature(evidence *WebAuthnEvidence, signature []byte, publicKey []byte) error {
	clientDataHash := sha256.Sum256(evidence.GetClientDataJson())
	digest := sha256.New()
	digest.Write(evidence.GetAuthenticatorData())
	digest.Write(clientDataHash[:])
	return verifyP256Signature(publicKey, digest.Sum(nil), signature)
}

// Each statement's leaf hash, or a refusal of a size no act has.
func presenceActLeafHashes(statementDigests [][sha256.Size]byte) ([][sha256.Size]byte, error) {
	if len(statementDigests) == 0 || len(statementDigests) > presenceActMaxSize {
		return nil, fmt.Errorf("%w: %d statements", ErrSignedAct, len(statementDigests))
	}
	leafHashes := make([][sha256.Size]byte, len(statementDigests))
	for i, statementDigest := range statementDigests {
		leafHashes[i] = presenceActLeafHash(statementDigest)
	}
	return leafHashes, nil
}

// RFC 9162 §2.1.1's MTH({d}) = HASH(0x00 || d).
func presenceActLeafHash(statementDigest [sha256.Size]byte) [sha256.Size]byte {
	var input [1 + sha256.Size]byte
	input[0] = presenceActLeafPrefix
	copy(input[1:], statementDigest[:])
	return sha256.Sum256(input[:])
}

// RFC 9162 §2.1.1's HASH(0x01 || left || right). Both sides are 32 bytes, which the path's walk checks of what it reads.
func presenceActNodeHash(left []byte, right []byte) [sha256.Size]byte {
	var input [1 + 2*sha256.Size]byte
	input[0] = presenceActNodePrefix
	copy(input[1:], left)
	copy(input[1+sha256.Size:], right)
	return sha256.Sum256(input[:])
}

// RFC 9162 §2.1.1's k: the largest power of two smaller than a size of at least 2.
func presenceActSplit(size int) int {
	return 1 << (bits.Len(uint(size-1)) - 1)
}

// MTH over at least one leaf hash, by §2.1.1's recursion.
func presenceActTreeHash(leafHashes [][sha256.Size]byte) [sha256.Size]byte {
	if len(leafHashes) == 1 {
		return leafHashes[0]
	}
	split := presenceActSplit(len(leafHashes))
	left := presenceActTreeHash(leafHashes[:split])
	right := presenceActTreeHash(leafHashes[split:])
	return presenceActNodeHash(left[:], right[:])
}

// PATH(actIndex, leaves) by §2.1.3.1's recursion, nearest the leaf first.
func presenceActTreePath(leafHashes [][sha256.Size]byte, actIndex int) [][]byte {
	if len(leafHashes) == 1 {
		return [][]byte{}
	}
	split := presenceActSplit(len(leafHashes))
	if actIndex < split {
		sibling := presenceActTreeHash(leafHashes[split:])
		return append(presenceActTreePath(leafHashes[:split], actIndex), sibling[:])
	}
	sibling := presenceActTreeHash(leafHashes[:split])
	return append(presenceActTreePath(leafHashes[split:], actIndex-split), sibling[:])
}

// RFC 9162 §2.1.3.2 from a leaf hash to the root its path proves, the bounds first. The root is not compared with
// anything, because an act's is known only as what its key signed: a path that misses its leaf gives another root, and
// the signature over the bytes that name it fails.
func presenceActPathRoot(
	leafHash [sha256.Size]byte,
	actIndex uint32,
	actSize uint32,
	actPath [][]byte,
) ([sha256.Size]byte, error) {
	noRoot := [sha256.Size]byte{}
	if actSize == 0 || actSize > presenceActMaxSize {
		return noRoot, fmt.Errorf("%w: size %d", ErrSignedAct, actSize)
	}
	if actIndex >= actSize {
		return noRoot, fmt.Errorf("%w: index %d of %d", ErrSignedAct, actIndex, actSize)
	}
	if len(actPath) > presenceActPathMaxSize {
		return noRoot, fmt.Errorf("%w: a path of %d hashes", ErrSignedAct, len(actPath))
	}

	// §2.1.3.2's fn, sn and r.
	index := actIndex
	lastIndex := actSize - 1
	root := leafHash
	for _, sibling := range actPath {
		if len(sibling) != sha256.Size {
			return noRoot, fmt.Errorf("%w: a path hash of %d bytes", ErrSignedAct, len(sibling))
		}
		if lastIndex == 0 {
			return noRoot, fmt.Errorf("%w: a path longer than index %d of %d", ErrSignedAct, actIndex, actSize)
		}
		if index&1 == 1 || index == lastIndex {
			root = presenceActNodeHash(sibling, root[:])
			for index&1 == 0 && index != 0 {
				index >>= 1
				lastIndex >>= 1
			}
		} else {
			root = presenceActNodeHash(root[:], sibling)
		}
		index >>= 1
		lastIndex >>= 1
	}
	if lastIndex != 0 {
		return noRoot, fmt.Errorf("%w: a path shorter than index %d of %d", ErrSignedAct, actIndex, actSize)
	}
	return root, nil
}
