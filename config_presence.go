// §7.9's presence row (owner decisions 185, 187, 189, 192; D-TEAM-32): a statement the row covers, signed by a sidecar
// that registered a live presence key, carries that key's countersignature in §6.9's Signed.webauthn, and api, evs,
// gkm and every member device run this one function, so they refuse alike:
//
//	covers    a SidecarRevoke{reason: compromise}, and every other SidecarRevoke of another sidecar; a presence key's
//	            KeyRegister or KeyRevoke; every Suspend of another sidecar and every RecoveryVeto; a DelegationRevoke
//	            with since_n (owner decision 192); a SidecarAdmit, AdmissionConfirm or OwnerConfirm of an untagged
//	            sidecar; an AdminSet, a MemberRevoke, a RecoveryBind and a RecoveryRebind; and an AuthorityProposal
//	            carrying one of these, or a cosign of such a proposal, by its own signer's key
//	required  of a signer with a live presence key (config_keys.go's livePresenceKeysAt at the carrying entry's time)
//	verify    the countersignature names one of the signer's live keys and passes §16.6's countersign check from that
//	            key's row (VerifyPresenceCountersignature): its leaf through its act's path to the root, the
//	            countersigned bytes naming the signer, UV set, signCount not compared; the statement's nonce and the
//	            replay row refuse a reuse
//
// A countersignature the row does not require is ignored; a device's own sign-out and a recovery key's statements need
// none, and a Delegation's key registers none. What cannot be told apart counts as covered. The act itself, its root,
// bytes and paths, is CORE-M2-02's sidecarAct over PROTO's bridge functions (C-02); this is the rule acts are judged by.
// The keyless device role parses no KeyRegister, so it applies a covered SidecarRevoke, MemberRevoke or Suspend on its
// identity signature as a denial its sidecar role's next state confirms or reverses (device/, §17).
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret. On every leg.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The presence row at state for a statement carried at its entry: each device signer with a live presence key at the
// entry's time, signing what the row covers, must have countersigned it with one of those keys. A proposal's statement
// carries no Signed of its own: its proposal and each cosign met the row on their own entries.
func configPresenceCheck(state *ConfigState, statement *configStatement) error {
	if statement.signed == nil {
		return nil
	}
	for _, signer := range statement.signers {
		if signer.Kind != ConfigSignerSidecar {
			continue
		}
		live := state.livePresenceKeysAt(signer.SidecarId, statement.timeMs)
		if len(live) == 0 || !configPresenceCovers(state, statement.signedType, statement.body, signer.SidecarId) {
			continue
		}
		keyId := statement.signed.GetWebauthn().GetKeyId()
		var key *bridge.KeyRow
		for _, candidate := range live {
			if bytes.Equal(candidate.GetKeyId(), keyId) {
				key = candidate
				break
			}
		}
		if key == nil {
			return fmt.Errorf("%w: %s needs a countersignature by a live presence key of its signer", ErrConfigPresence, statement.signedType)
		}
		if err := VerifyPresenceCountersignature(statement.signed, statement.purpose, key); err != nil {
			return fmt.Errorf("%w: %w", ErrConfigPresence, err)
		}
	}
	return nil
}

// Whether §7.9's presence row covers a statement by signer (D-TEAM-32's list). What cannot be told apart counts as
// covered.
func configPresenceCovers(state *ConfigState, signedType bridge.SignedType, body proto.Message, signerId Id) bool {
	untaggedRow := func(sidecarBytes []byte) bool {
		sidecarId, err := IdFromBytes(sidecarBytes)
		if err != nil {
			return true
		}
		row := state.sidecars[sidecarId]
		return row == nil || len(row.GetTagIds()) == 0
	}
	switch message := body.(type) {
	case *bridge.SidecarRevoke:
		return message.GetReason() == bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE ||
			!bytes.Equal(message.GetSidecarId(), signerId.Bytes())
	case *protocol.KeyRegister:
		return message.GetPurpose() == bridge.KeyPurpose_KEY_PURPOSE_PRESENCE
	case *protocol.KeyRevoke:
		key := state.keys[string(message.GetKeyId())]
		return key == nil || key.GetPurpose() == bridge.KeyPurpose_KEY_PURPOSE_PRESENCE
	case *bridge.Suspend:
		return !bytes.Equal(message.GetSubject(), signerId.Bytes())
	case *protocol.RecoveryVeto, *protocol.AdminSet, *bridge.MemberRevoke, *protocol.RecoveryBind, *protocol.RecoveryRebind:
		return true
	case *protocol.DelegationRevoke:
		return message.GetSinceN() != 0
	case *protocol.SidecarAdmit:
		return len(message.GetTagIds()) == 0
	case *protocol.AdmissionConfirm:
		return untaggedRow(message.GetSidecarId())
	case *protocol.OwnerConfirm:
		return untaggedRow(message.GetSidecarId())
	case *protocol.AuthorityProposal:
		proposed, err := configProposedStatement(message, nil, 0, 0)
		return err != nil || configPresenceCovers(state, proposed.signedType, proposed.body, signerId)
	case *protocol.AuthorityCosign:
		if len(message.GetProposalId()) != sha256.Size {
			return true
		}
		proposal := state.proposals[[sha256.Size]byte(message.GetProposalId())]
		return proposal == nil || configPresenceCovers(state, proposal.statement.signedType, proposal.statement.body, signerId)
	}
	return false
}

// Whether §7.9's presence row asks a countersignature of a statement as its signer would sign it now: the row covers it
// and the signer holds a live presence key at this state, read from the log, never from a caller (C-10's
// SidecarAuthority.PresenceRequired). A type the log does not carry is no statement the row reads; a body that does
// not parse counts as covered.
func (self *ConfigState) PresenceRequired(statement *SidecarStatement) bool {
	if statement == nil {
		return false
	}
	purpose, ok := ConfigStatementPurpose(statement.Type)
	if !ok || len(self.livePresenceKeysAt(statement.SignerId, self.timeMs)) == 0 {
		return false
	}
	body, err := ParseConfigStatement(purpose, statement.Type, statement.Body)
	if err != nil {
		return true
	}
	return configPresenceCovers(self, statement.Type, body, statement.SignerId)
}
