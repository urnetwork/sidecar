// §7.9's KeyRegister and KeyRevoke as rules of the log, and the keys they leave (owner decisions 185, 187; D-TEAM-32;
// §16.6):
//
//	KeyRegister  the member's consented, approval-capable device: a key_id no key held before; a presence key
//	               webauthn-es256 or ecdsa-p256-sha256, a 65-byte SEC 1 point (protos-bridge-presence-gaps #1),
//	               carrying its own signature over the body before field 9 (#3, VerifyPresenceRegistration); an sshsig
//	               key ssh-ed25519, 32 bytes, with no such proof; a not_after after the entry's time
//	KeyRevoke    a consented, approval-capable device of the key's member; a revoked key takes it again as nothing
//
// A presence key is live for its signer, the device whose KeyRegister it is, while it is not revoked, not void (a
// cascade's P held that device when it registered it, config_cascade.go) and before its not_after: what the presence
// row reads (config_presence.go). That a device registers after a device or presence decision, never on a harness's
// word, and its first key only after a /dev/tty-confirmed command or in ur login, is what it asks of its person
// (CORE's), which no verifier sees.
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret. On every leg.

package sidecar

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A registered key's key_id is at most this long: the hash or credential id its device names it by.
const configKeyIdMaxByteCount = 64

// Registers KeyRegister's and KeyRevoke's rules.
func init() {
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_KEY_REGISTER,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckKeyRegister,
		apply:      configApplyKeyRegister,
	})
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_KEY_REVOKE,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckKeyRevoke,
		apply:      configApplyKeyRevoke,
	})
}

// Whether one device signer is a consented, approval-capable device of the member (§16.6): consented for it, untagged,
// not ephemeral, read_only or suspended, and standing.
func (self *ConfigState) approvalCapableSigner(signers []ConfigSigner, memberId Id, timeMs int64) bool {
	if len(signers) != 1 || signers[0].Kind != ConfigSignerSidecar {
		return false
	}
	acl, err := self.Acl()
	if err != nil {
		return false
	}
	_, ok := self.anyMemberDevice(signers, timeMs, func(signerId Id, signerMemberId Id, role bridge.MemberRole) bool {
		return signerMemberId == memberId && acl.ApprovalCapable(signerId) && acl.ConsentedFor(signerId, memberId)
	})
	return ok
}

// A KeyRegister: a member of this state; a key_id of 1 to 64 bytes no key held before; the purpose's algorithm and key
// form, a presence key's own proof and an sshsig key's lack of one; a not_after after the entry's time; and its
// member's consented, approval-capable device as its one signer.
func configCheckKeyRegister(state *ConfigState, statement *configStatement) error {
	register := statement.body.(*protocol.KeyRegister)
	memberId, err := IdFromBytes(register.GetMemberId())
	if err != nil {
		return fmt.Errorf("%w: a member_id of %d bytes", ErrConfigRule, len(register.GetMemberId()))
	}
	keyId := register.GetKeyId()
	switch {
	case state.members[memberId] == nil:
		return fmt.Errorf("%w: no such member", ErrConfigRule)
	case len(keyId) == 0 || configKeyIdMaxByteCount < len(keyId):
		return fmt.Errorf("%w: a key_id of %d bytes", ErrConfigRule, len(keyId))
	case state.keys[string(keyId)] != nil:
		return fmt.Errorf("%w: a key_id registered before", ErrConfigRule)
	case register.GetNotAfter() <= statement.timeMs:
		return fmt.Errorf("%w: a key needs a not_after to come", ErrConfigRule)
	}
	switch register.GetPurpose() {
	case bridge.KeyPurpose_KEY_PURPOSE_PRESENCE:
		switch register.GetAlg() {
		case bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256, bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256:
		default:
			return fmt.Errorf("%w: a presence key of algorithm %s", ErrConfigRule, register.GetAlg())
		}
		if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), register.GetPublicKey()); err != nil {
			return fmt.Errorf("%w: a presence key's point: %w", ErrConfigRule, err)
		}
		if statement.signed == nil {
			return fmt.Errorf("%w: a presence key's registration rides no proposal", ErrConfigRule)
		}
		if err := VerifyPresenceRegistration(register, statement.signed); err != nil {
			return fmt.Errorf("%w: %w", ErrConfigRule, err)
		}
	case bridge.KeyPurpose_KEY_PURPOSE_SSHSIG:
		switch {
		case register.GetAlg() != bridge.KeyAlg_KEY_ALG_SSH_ED25519:
			return fmt.Errorf("%w: an sshsig key of algorithm %s", ErrConfigRule, register.GetAlg())
		case len(register.GetPublicKey()) != ed25519.PublicKeySize:
			return fmt.Errorf("%w: an ssh-ed25519 key of %d bytes", ErrConfigRule, len(register.GetPublicKey()))
		case len(register.GetKeySignature()) != 0 || register.GetKeyWebauthn() != nil:
			return fmt.Errorf("%w: an sshsig key carries no proof", ErrConfigRule)
		}
	default:
		return fmt.Errorf("%w: purpose %s", ErrConfigRule, register.GetPurpose())
	}
	if !state.approvalCapableSigner(statement.signers, memberId, statement.timeMs) {
		return fmt.Errorf("%w: a key registers only by its member's consented, approval-capable device", ErrConfigAuthority)
	}
	return nil
}

// A KeyRegister's effect: the key's row, with its signer and position for the presence row and the cascade.
func configApplyKeyRegister(next *configStateBuilder, statement *configStatement) error {
	register := statement.body.(*protocol.KeyRegister)
	if next.state.keys[string(register.GetKeyId())] != nil {
		return fmt.Errorf("%w: a key_id registered before", ErrConfigRule)
	}
	if len(statement.signers) == 0 {
		return fmt.Errorf("%w: a KeyRegister with no signer", ErrConfigRule)
	}
	next.putKey(&bridge.KeyRow{
		KeyId:     bytes.Clone(register.GetKeyId()),
		MemberId:  bytes.Clone(register.GetMemberId()),
		Alg:       register.GetAlg(),
		PublicKey: bytes.Clone(register.GetPublicKey()),
		Purpose:   register.GetPurpose(),
		Signer:    statement.signers[0].RowsSigner(),
		At:        statement.n,
		NotAfter:  register.GetNotAfter(),
	})
	return nil
}

// A KeyRevoke: a key this state holds, by a consented, approval-capable device of its member. A revoked key takes it
// again as nothing.
func configCheckKeyRevoke(state *ConfigState, statement *configStatement) error {
	key := state.keys[string(statement.body.(*protocol.KeyRevoke).GetKeyId())]
	if key == nil {
		return fmt.Errorf("%w: no such key", ErrConfigRule)
	}
	memberId, err := IdFromBytes(key.GetMemberId())
	if err != nil {
		return fmt.Errorf("%w: the key names no member", ErrConfigRule)
	}
	if !state.approvalCapableSigner(statement.signers, memberId, statement.timeMs) {
		return fmt.Errorf("%w: a key revokes only by its member's consented, approval-capable device", ErrConfigAuthority)
	}
	return nil
}

// A KeyRevoke's effect: the key revoked here unless it was already.
func configApplyKeyRevoke(next *configStateBuilder, statement *configStatement) error {
	key := next.keyForWrite(statement.body.(*protocol.KeyRevoke).GetKeyId())
	if key == nil {
		return fmt.Errorf("%w: no such key", ErrConfigRule)
	}
	if key.GetRevokedAt() == 0 {
		key.RevokedAt = statement.n
	}
	return nil
}

// The presence keys the sidecar registered that are live at timeMs, by key_id: not revoked, not void and before their
// not_after (§7.9's presence row).
func (self *ConfigState) livePresenceKeysAt(sidecarId Id, timeMs int64) []*bridge.KeyRow {
	live := []*bridge.KeyRow{}
	for _, key := range self.keys {
		if key.GetPurpose() != bridge.KeyPurpose_KEY_PURPOSE_PRESENCE || !bytes.Equal(key.GetSigner(), sidecarId.Bytes()) ||
			key.GetRevokedAt() != 0 || key.GetNotAfter() <= timeMs || self.CascadeVoids(key.GetSigner(), key.GetAt()) {
			continue
		}
		live = append(live, key)
	}
	slices.SortFunc(live, func(a *bridge.KeyRow, b *bridge.KeyRow) int {
		return bytes.Compare(a.GetKeyId(), b.GetKeyId())
	})
	return live
}

// The presence keys the sidecar registered that are live at this state, by key_id: what a device's act countersigns
// with, and what SidecarAuthority.LiveKeys answers. The caller must not change them.
func (self *ConfigState) LiveKeys(sidecarId Id) []*bridge.KeyRow {
	return self.livePresenceKeysAt(sidecarId, self.timeMs)
}
