// §5.6's admission on the device (CORE-M2-01): the one gate, Admitted, that §6's Hello check, §10's upkeep and §8's
// grants ask before a sidecar gets a peer, a group, a wrap or a grant; the safety number a `ur login` device with no
// anchor shows for its admitter to compare (plan-CORE-safety-number); and a pre-approved key's self-admission, a
// SidecarAdmit signed by the Delegation's key from the bundle, carrying exactly its tags (§5.6, §7.8, C-03).
//
// Admission is the config repo's, never api's: Admitted reads only the installed SidecarAuthority, and a sidecar with
// none installed, or whose state does not name it, is not admitted. A revoked admission, or an agent's whose not_after
// has passed, is not admitted either; a parked one is (§7.9's cascade parks owner-bound reads, which §8's gates ask
// Consented about, not admission).
//
// A bundle's two seeds are a credential every other copy of the auth key string still holds (§7.8): the signing seed
// is used once, here, and erased, and only the reader seed is kept, never logged, persisted raw elsewhere or passed to
// MCP. Each reaches testHookSecret as it is used, so the privacy harness finds either one leaked.
//
// On every leg: root Id, no connect type.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The safety number's format values (plan-CORE-safety-number): its domain, its 60 digits, and its groups.
const (
	sidecarSafetyNumberDomain      = "urnetwork-sidecar-v1/safety-number"
	sidecarSafetyNumberDigitCount  = 60
	sidecarSafetyNumberGroupDigits = 5
	sidecarSafetyNumberLineGroups  = 4
)

// The keychain record of the core's namespace that keeps a Delegation-admitted sidecar's reader seed (§10.5's d
// wrap path): the one seed of a bundle this device keeps.
const sidecarDelegationReaderKeyRecordName = "delegation_reader_key"

var (
	// A safety number's input is not two 32-byte values.
	ErrSidecarSafetyNumber = errors.New("a safety number needs a 32-byte genesis hash and a 32-byte identity key")
	// A self-admission that the bundle, the Delegation's row or this sidecar's identity cannot make: refused,
	// nothing signed.
	ErrSidecarDelegationAdmit = errors.New("the Delegation cannot admit this sidecar")
)

// Whether this sidecar is admitted (§5.6): the installed authority's state names it in a SidecarAdmit, not revoked,
// and, for an agent, before its not_after. False with no authority, no identity, or a state that does not name it.
// Everything §5.6 lists asks this one place: no peer (§6's Hello check), MLS group or wrap (§10's upkeep, KEYS-M2-18),
// or grant (§8) before it is true.
func (self *Sidecar) Admitted() bool {
	authority := self.authority()
	identity := self.currentIdentity()
	if authority == nil || identity == nil {
		return false
	}
	admission := authority.Admission(identity.SidecarId)
	if admission == nil || admission.Row == nil || !bytes.Equal(admission.Row.GetSidecarId(), identity.SidecarId.Bytes()) {
		return false
	}
	if admission.Row.GetRevokedAt() != 0 {
		return false
	}
	// an admission's not_after binds agents only (§7.9); an expired one admits nothing
	if notAfter := admission.Row.GetNotAfter(); notAfter != 0 && notAfter <= self.clock.Now().UnixMilli() {
		return false
	}
	return true
}

// The safety number of a device's identity key in a network (plan-CORE-safety-number): digest =
// SHA-256("urnetwork-sidecar-v1/safety-number" || 0x00 || genesis_sha256 || identity_public_key), N the digest read
// big-endian, and the number N mod 10^60, 60 decimal digits zero-padded. genesisSha256 is SHA-256(Signed Genesis), A_0.
// ur and SidecarApprovals show it alike (FormatSafetyNumber), so an admitter compares the same digits the device shows.
func SafetyNumber(genesisSha256 []byte, identityPublicKey []byte) (string, error) {
	if len(genesisSha256) != sha256.Size || len(identityPublicKey) != ed25519.PublicKeySize {
		return "", ErrSidecarSafetyNumber
	}
	hash := sha256.New()
	hash.Write([]byte(sidecarSafetyNumberDomain))
	hash.Write([]byte{0x00})
	hash.Write(genesisSha256)
	hash.Write(identityPublicKey)
	number := new(big.Int).SetBytes(hash.Sum(nil))
	modulus := new(big.Int).Exp(big.NewInt(10), big.NewInt(sidecarSafetyNumberDigitCount), nil)
	number.Mod(number, modulus)
	digits := number.String()
	return strings.Repeat("0", sidecarSafetyNumberDigitCount-len(digits)) + digits, nil
}

// A safety number as ur and the apps show it: 12 groups of 5 digits, in three lines of 4 groups. Anything but 60
// digits is answered as given, which no comparison matches.
func FormatSafetyNumber(number string) string {
	if len(number) != sidecarSafetyNumberDigitCount {
		return number
	}
	lines := []string{}
	lineDigits := sidecarSafetyNumberGroupDigits * sidecarSafetyNumberLineGroups
	for lineStart := 0; lineStart < len(number); lineStart += lineDigits {
		groups := []string{}
		for groupStart := lineStart; groupStart < lineStart+lineDigits; groupStart += sidecarSafetyNumberGroupDigits {
			groups = append(groups, number[groupStart:groupStart+sidecarSafetyNumberGroupDigits])
		}
		lines = append(lines, strings.Join(groups, " "))
	}
	return strings.Join(lines, "\n")
}

// This sidecar's own safety number, over the genesis its anchor holds and its identity key: what `ur login` shows a
// device with no invite's or auth key's anchor, and what its admitter must see before signing its admission (§5.6's
// genesis row). ErrSidecarStoreAbsent before an anchor is recorded, ErrSidecarNoIdentity before enrollment.
func (self *Sidecar) SafetyNumber() (string, error) {
	identity := self.currentIdentity()
	if identity == nil {
		return "", ErrSidecarNoIdentity
	}
	anchor, err := self.Anchor()
	if err != nil {
		return "", err
	}
	return SafetyNumber(anchor.GenesisSha256, identity.IdentityPublicKey)
}

// What a pre-approved key's self-admission is made from: the bundle, the Delegation's row as the verified log holds
// it, and this sidecar's identity.
type sidecarDelegationAdmitArgs struct {
	networkId Id
	identity  *SidecarIdentity
	bundle    *AuthKeyBundle
	// the Delegation's row at the state the statement is signed at, whose not_after an admission may not undercut
	delegation *bridge.DelegationRow
	// the state the statement is signed at
	at *bridge.AuthPin
	// --ephemeral: no not_after is carried
	ephemeral bool
	// the statement's own not_after, at most 7 days after signing (§7.9)
	statementNotAfterMs int64
	random              io.Reader
}

// The SidecarAdmit a pre-approved key's Delegation signs for this sidecar (§5.6, §7.8, C-03): exactly the bundle's
// tag_ids and, unless ephemeral, the Delegation's not_after, which is no earlier than its own; signed_id the
// delegation_id and key_id SHA-256 of the Delegation's public key (§6.9's Signers). Refuses a bundle whose Delegation
// the row does not name, a Delegation that has ended, a bundle with no tags, a signing seed whose key is not the
// Delegation's, and a row with no not_after. The signing seed is erased whatever the outcome; the caller keeps the
// reader seed (keepDelegationReaderKey) and erases the bundle.
func newDelegationSidecarAdmit(args *sidecarDelegationAdmitArgs) (*bridge.Signed, error) {
	bundle := args.bundle
	if bundle == nil || args.identity == nil || args.delegation == nil || args.at == nil {
		return nil, ErrSidecarDelegationAdmit
	}
	defer clear(bundle.DelegationSigningSeed)
	if len(bundle.DelegationSigningSeed) != ed25519.SeedSize {
		return nil, ErrSidecarDelegationAdmit
	}
	testHookSecret("delegation_signing_seed", bundle.DelegationSigningSeed)
	// a delegation_id is SHA-256(Signed Delegation), 32 bytes (§10.5's d); a bundle naming another id, the 16-byte form
	// TEAM-M1-05's parser reads today included (questions/core-m2-01-bundle-delegation-id-width.md), matches no row
	if !bytes.Equal(args.delegation.GetDelegationId(), bundle.DelegationId.Bytes()) || args.delegation.GetEndedAt() != 0 {
		return nil, fmt.Errorf("%w: the Delegation is not this bundle's, or has ended", ErrSidecarDelegationAdmit)
	}
	if len(bundle.TagIds) == 0 {
		return nil, fmt.Errorf("%w: a Delegation admits tagged sidecars only", ErrSidecarDelegationAdmit)
	}
	delegationNotAfter := args.delegation.GetNotAfter()
	if delegationNotAfter <= 0 {
		return nil, fmt.Errorf("%w: the Delegation has no not_after", ErrSidecarDelegationAdmit)
	}
	privateKey := ed25519.NewKeyFromSeed(bundle.DelegationSigningSeed)
	defer clear(privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyId := sha256.Sum256(publicKey)
	nonce := make([]byte, configNonceByteCount)
	if _, err := io.ReadFull(args.random, nonce); err != nil {
		return nil, fmt.Errorf("no randomness for a nonce: %w", err)
	}
	admit := &protocol.SidecarAdmit{
		Header: &bridge.StatementHeader{
			NetworkId:  args.networkId.Bytes(),
			At:         &bridge.AuthPin{Version: args.at.GetVersion(), Chain: bytes.Clone(args.at.GetChain())},
			Nonce:      nonce,
			NotAfterMs: args.statementNotAfterMs,
		},
		NetworkId:         args.networkId.Bytes(),
		SidecarId:         args.identity.SidecarId.Bytes(),
		IdentityPublicKey: bytes.Clone(args.identity.IdentityPublicKey),
		IdentityAlg:       configIdentityAlgEd25519,
		Ephemeral:         args.ephemeral,
	}
	for _, tagId := range bundle.TagIds {
		admit.TagIds = append(admit.TagIds, bytes.Clone(tagId))
	}
	if !args.ephemeral {
		// no earlier than the Delegation's own, which is its not_after exactly
		admit.NotAfter = delegationNotAfter
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(admit)
	if err != nil {
		return nil, err
	}
	signedType := bridge.SignedType_SIGNED_SIDECAR_ADMIT
	signature := ed25519.Sign(privateKey, bridge.SignedBytes(bridge.SignedPurposeAuthority, signedType, body))
	return &bridge.Signed{
		Type:      uint32(signedType),
		SignerId:  bundle.DelegationId.Bytes(),
		KeyId:     keyId[:],
		Body:      body,
		Signature: signature,
	}, nil
}

// Keeps the bundle's reader seed in the core's namespace (§10.5's d wrap path), the one seed this device keeps, then
// erases it from the bundle. Refuses a seed that is not 32 bytes.
func keepDelegationReaderKey(secrets SidecarSecrets, bundle *AuthKeyBundle) error {
	defer clear(bundle.DelegationReaderSeed)
	if len(bundle.DelegationReaderSeed) != authKeySeedByteCount {
		return ErrSidecarDelegationAdmit
	}
	testHookSecret("delegation_reader_seed", bundle.DelegationReaderSeed)
	return secrets.Put(sidecarDelegationReaderKeyRecordName, bundle.DelegationReaderSeed)
}
