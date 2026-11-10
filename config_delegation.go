// §7.9's Delegation and DelegationRevoke as rules of the log, the scoped row a Delegation's key admits by, and its
// end (D-TEAM-30, §7.8, §10.5):
//
//	Delegation        an Owner's, Admin's or Network admin's member device that may apply each of its tags (§8's
//	                    tagOwners), never another Delegation: it never re-delegates; at least one tag, max_admits at
//	                    least 1, a not_after after the entry's time and at most 90 days on (7.8), an Ed25519 signing
//	                    key and an X-Wing reader key (§10.5)
//	DelegationRevoke  an admin's device, the device that signed the Delegation, or a Network admin's that may apply
//	                    each of its tags; since_n 0, or for a leaked bundle a position before the entry, from which
//	                    each agent the Delegation admitted parks; a repeat ends nothing twice and parks again
//	by its key        a SidecarAdmit of an agent carrying exactly its tags and, unless ephemeral, a not_after no
//	                    earlier than its own, up to max_admits counted in log order for its life; and an
//	                    AdmissionConfirm of an agent it admitted, which lifts a park; each refused once it ended or
//	                    passed its not_after
//
// A Delegation with forward set is a forwarding Delegation, §7.9's forwarding row, which config_forwarding.go judges:
// none of the rules above apply to it, its key signs no statement of the log, and its revocation takes since_n 0 alone.
//
// A Delegation ends at the first of its DelegationRevoke, its void (a cascade's P held its signer when it signed it)
// and a compromise revocation of a sidecar it admitted (config_cascade.go); its key drops then too, and before, at a
// lost or removed revocation or a Suspend of one of its agents, which leaves it admitting, each later agent uncovered.
//
// A Delegation signs as §6.9's Signers and protos-bridge-recovery-key-carrier fix it: signer_id its delegation_id and
// key_id the SHA-256 of its pubkey. Every effect here reads only the statement's body and the state it applies to, so a
// base's re-application gives every reader the same rows. Nothing here creates, derives or unwraps a key, so nothing
// calls testHookSecret. On every leg.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §7.8's and §10.5's sizes and bounds, which every reader holds alike.
const (
	// A Delegation's not_after is at most this long after the entry that carries it (7.8).
	configDelegationMaxLifetimeMs = int64(90 * 24 * 60 * 60 * 1000)
	// An X-Wing public key, Delegation.reader_xwing_public_key's size (§10.5).
	configXwingPublicKeyByteCount = 1216
)

// Registers Delegation's and DelegationRevoke's rules.
func init() {
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_DELEGATION,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckDelegation,
		apply:      configApplyDelegation,
	})
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_DELEGATION_REVOKE,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckDelegationRevoke,
		apply:      configApplyDelegationRevoke,
	})
}

// Verifies a statement a Delegation's key signed: signer_id names a Delegation this state holds and key_id is its
// pubkey's SHA-256. Only a SidecarAdmit and an AdmissionConfirm take such a signer; whether the Delegation may still
// sign is the type's rule. A forwarding Delegation's key is no signer of the log at all: it admits nothing
// (D-TEAM-33), so a statement whose signer resolves to one is refused here, at api and at every reader.
func (self *ConfigState) verifyDelegationSigner(signed *bridge.Signed, purpose string, signedType bridge.SignedType) (ConfigSigner, error) {
	switch signedType {
	case bridge.SignedType_SIGNED_SIDECAR_ADMIT, bridge.SignedType_SIGNED_ADMISSION_CONFIRM:
	default:
		return ConfigSigner{}, fmt.Errorf("%w: a Delegation's key signs no %s", ErrConfigSigner, signedType)
	}
	delegation := self.delegations[string(signed.GetSignerId())]
	if delegation == nil {
		return ConfigSigner{}, fmt.Errorf("%w: no Delegation with this id", ErrConfigSigner)
	}
	if ConfigDelegationRowForwards(delegation) {
		return ConfigSigner{}, fmt.Errorf("%w: a forwarding Delegation's key signs no %s: it admits nothing", ErrConfigSigner, signedType)
	}
	pubkey := delegation.GetPubkey()
	pubkeySha256 := sha256.Sum256(pubkey)
	if len(pubkey) != ed25519.PublicKeySize || !bytes.Equal(pubkeySha256[:], signed.GetKeyId()) {
		return ConfigSigner{}, fmt.Errorf("%w: key_id is not the Delegation's key", ErrConfigSigner)
	}
	if err := bridge.VerifySigned(signed, purpose, signedType, bridge.SignedKeyAlgEd25519, pubkey); err != nil {
		return ConfigSigner{}, fmt.Errorf("%w: %w", ErrConfigSigner, err)
	}
	return ConfigSigner{Kind: ConfigSignerDelegation, DelegationId: bytes.Clone(signed.GetSignerId())}, nil
}

// The Delegation's tag ids, refusing a malformed or repeated one.
func configDelegationTagIds(tagBytes [][]byte) ([]Id, error) {
	tagIds := make([]Id, 0, len(tagBytes))
	for _, tag := range tagBytes {
		tagId, err := IdFromBytes(tag)
		if err != nil || slices.Contains(tagIds, tagId) {
			return nil, fmt.Errorf("%w: a malformed or repeated tag id", ErrConfigRule)
		}
		tagIds = append(tagIds, tagId)
	}
	return tagIds, nil
}

// A Delegation: its fields' forms and bounds, a delegation_id no state held before, and one standing member device of
// an Owner, Admin or Network admin, not read_only, that may apply each of its tags (§8's tagOwners). One with forward
// set is judged by §7.9's forwarding row instead, and by none of this (D-TEAM-33).
func configCheckDelegation(state *ConfigState, statement *configStatement) error {
	delegation := statement.body.(*protocol.Delegation)
	if ConfigDelegationForwards(delegation) {
		return configCheckForwardingDelegation(state, statement)
	}
	if len(statement.signers) != 1 || statement.signers[0].Kind != ConfigSignerSidecar {
		return fmt.Errorf("%w: a Delegation takes one device's signature, never a Delegation's or a recovery key's", ErrConfigSigner)
	}
	tagIds, err := configDelegationTagIds(delegation.GetTagIds())
	if err != nil {
		return err
	}
	notAfter := delegation.GetNotAfter()
	switch {
	case len(tagIds) == 0:
		return fmt.Errorf("%w: a Delegation names no tag", ErrConfigRule)
	case len(delegation.GetPubkey()) != ed25519.PublicKeySize:
		return fmt.Errorf("%w: a signing key of %d bytes", ErrConfigRule, len(delegation.GetPubkey()))
	case len(delegation.GetReaderXwingPublicKey()) != configXwingPublicKeyByteCount:
		return fmt.Errorf("%w: a reader key of %d bytes", ErrConfigRule, len(delegation.GetReaderXwingPublicKey()))
	case delegation.GetMaxAdmits() == 0:
		return fmt.Errorf("%w: a Delegation that admits nothing", ErrConfigRule)
	case notAfter <= statement.timeMs:
		return fmt.Errorf("%w: a Delegation needs a not_after to come", ErrConfigRule)
	case statement.timeMs+configDelegationMaxLifetimeMs < notAfter:
		return fmt.Errorf("%w: a Delegation's not_after more than 90 days on", ErrConfigRule)
	case state.delegations[string(statement.id[:])] != nil:
		return fmt.Errorf("%w: a delegation_id declared before", ErrConfigRule)
	}
	acl, err := state.Acl()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	if _, ok := state.anyMemberDevice(statement.signers, statement.timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
		switch role {
		case bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_ADMIN, bridge.MemberRole_MEMBER_ROLE_NETWORK_ADMIN:
		default:
			return false
		}
		for _, tagId := range tagIds {
			if !acl.CanApplyTag(signerId, tagId) {
				return false
			}
		}
		return true
	}); !ok {
		return fmt.Errorf("%w: a Delegation needs an Owner's, Admin's or Network admin's device that owns each of its tags", ErrConfigAuthority)
	}
	return nil
}

// A Delegation's effect: its row, keyed by its delegation_id, with its signer and position for the cascade.
func configApplyDelegation(next *configStateBuilder, statement *configStatement) error {
	delegation := statement.body.(*protocol.Delegation)
	if ConfigDelegationForwards(delegation) {
		return configApplyForwardingDelegation(next, statement)
	}
	if next.state.delegations[string(statement.id[:])] != nil {
		return fmt.Errorf("%w: a delegation_id declared before", ErrConfigRule)
	}
	if len(statement.signers) == 0 {
		return fmt.Errorf("%w: a Delegation with no signer", ErrConfigRule)
	}
	row := &bridge.DelegationRow{
		DelegationId:         bytes.Clone(statement.id[:]),
		Signer:               statement.signers[0].RowsSigner(),
		At:                   statement.n,
		NotAfter:             delegation.GetNotAfter(),
		Pubkey:               bytes.Clone(delegation.GetPubkey()),
		ReaderXwingPublicKey: bytes.Clone(delegation.GetReaderXwingPublicKey()),
		MaxAdmits:            delegation.GetMaxAdmits(),
	}
	for _, tagId := range delegation.GetTagIds() {
		row.TagAtoms = append(row.TagAtoms, bytes.Clone(tagId))
	}
	next.putDelegation(row)
	return nil
}

// Whether the signer may revoke the Delegation: an admin's device, the device that signed it, or a Network admin's
// that may apply each of its tags; each a standing member device, not read_only.
func (self *ConfigState) delegationRevokeSigner(signers []ConfigSigner, delegation *bridge.DelegationRow, timeMs int64) bool {
	acl, err := self.Acl()
	if err != nil {
		return false
	}
	_, ok := self.anyMemberDevice(signers, timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
		switch {
		case role == bridge.MemberRole_MEMBER_ROLE_OWNER || role == bridge.MemberRole_MEMBER_ROLE_ADMIN:
			return true
		case bytes.Equal(delegation.GetSigner(), signerId.Bytes()):
			return true
		case role == bridge.MemberRole_MEMBER_ROLE_NETWORK_ADMIN:
			for _, tagBytes := range delegation.GetTagAtoms() {
				tagId, err := IdFromBytes(tagBytes)
				if err != nil || !acl.CanApplyTag(signerId, tagId) {
					return false
				}
			}
			return 0 < len(delegation.GetTagAtoms())
		}
		return false
	})
	return ok
}

// A DelegationRevoke: a Delegation this state holds, since_n 0 or a position before the entry, and one device's
// signature that may revoke it. Revoking an ended Delegation is no refusal: it ends nothing again, and a since_n parks.
func configCheckDelegationRevoke(state *ConfigState, statement *configStatement) error {
	revoke := statement.body.(*protocol.DelegationRevoke)
	if len(statement.signers) != 1 || statement.signers[0].Kind != ConfigSignerSidecar {
		return fmt.Errorf("%w: a DelegationRevoke takes one device's signature", ErrConfigSigner)
	}
	delegation := state.delegations[string(revoke.GetDelegationId())]
	if delegation == nil {
		return fmt.Errorf("%w: no such Delegation", ErrConfigRule)
	}
	if ConfigDelegationRowForwards(delegation) {
		return configCheckForwardingRevoke(state, statement, delegation)
	}
	if sinceN := revoke.GetSinceN(); sinceN != 0 && statement.n <= sinceN {
		return fmt.Errorf("%w: since_n %d is not before the entry", ErrConfigRule, sinceN)
	}
	if !state.delegationRevokeSigner(statement.signers, delegation, statement.timeMs) {
		return fmt.Errorf("%w: no signer may revoke this Delegation", ErrConfigAuthority)
	}
	return nil
}

// A DelegationRevoke's effect: the Delegation ends here and its key drops, unless either happened before; with since_n,
// each agent it admitted from since_n on, not revoked, parks here, held in a cascade's P from its admission, since a
// leaked bundle's thief may have admitted it (D-TEAM-30).
func configApplyDelegationRevoke(next *configStateBuilder, statement *configStatement) error {
	revoke := statement.body.(*protocol.DelegationRevoke)
	delegationId := revoke.GetDelegationId()
	delegation := next.delegationForWrite(delegationId)
	if delegation == nil {
		return fmt.Errorf("%w: no such Delegation", ErrConfigRule)
	}
	configEndDelegation(delegation, statement.n)
	if ConfigDelegationRowForwards(delegation) {
		// it admitted nothing, so there is nothing to park
		return nil
	}
	if sinceN := revoke.GetSinceN(); sinceN != 0 {
		for _, sidecarId := range next.state.SidecarIds() {
			row := next.sidecar(sidecarId)
			if !bytes.Equal(row.GetDelegationId(), delegationId) || row.GetAdmittedAt() < sinceN {
				continue
			}
			configParkSidecar(next, sidecarId, row.GetAdmittedAt(), statement.n)
		}
	}
	return nil
}

// Ends a Delegation at n and drops its key there, keeping an earlier position of either.
func configEndDelegation(delegation *bridge.DelegationRow, n uint64) {
	if delegation.GetEndedAt() == 0 {
		delegation.EndedAt = n
	}
	if delegation.GetKeyDroppedAt() == 0 {
		delegation.KeyDroppedAt = n
	}
}

// The Delegation that signs a statement, nil when no signer is one.
func (self *ConfigState) signingDelegation(signers []ConfigSigner) *bridge.DelegationRow {
	for _, signer := range signers {
		if signer.Kind == ConfigSignerDelegation {
			return self.delegations[string(signer.DelegationId)]
		}
	}
	return nil
}

// Whether the Delegation may still sign at timeMs: not ended and before its not_after (D-TEAM-30). Its key's drop
// leaves it admitting, so a copy of its auth key admits on (7.10's agents row).
func configDelegationSigns(delegation *bridge.DelegationRow, timeMs int64) error {
	switch {
	case delegation == nil:
		return fmt.Errorf("%w: no such Delegation", ErrConfigSigner)
	case ConfigDelegationRowForwards(delegation):
		return fmt.Errorf("%w: a forwarding Delegation admits nothing", ErrConfigAuthority)
	case delegation.GetEndedAt() != 0:
		return fmt.Errorf("%w: the Delegation ended at %d", ErrConfigAuthority, delegation.GetEndedAt())
	case delegation.GetNotAfter() <= timeMs:
		return fmt.Errorf("%w: the Delegation passed its not_after", ErrConfigAuthority)
	}
	return nil
}

// §7.9's scoped row for a Delegation's SidecarAdmit: the Delegation's key alone, the Delegation still signing and
// under max_admits, the admission tagged with exactly its tags and, unless ephemeral, carrying a not_after no earlier
// than the Delegation's.
func (self *ConfigState) checkDelegationAdmission(statement *configStatement, admit *protocol.SidecarAdmit, admission *configAdmission) error {
	if len(statement.signers) != 1 {
		return fmt.Errorf("%w: a Delegation's admission carries its key's signature alone", ErrConfigSigner)
	}
	delegation := self.signingDelegation(statement.signers)
	if err := configDelegationSigns(delegation, statement.timeMs); err != nil {
		return err
	}
	if delegation.GetMaxAdmits() <= delegation.GetAdmissions() {
		return fmt.Errorf("%w: the Delegation made its %d admissions", ErrConfigAuthority, delegation.GetMaxAdmits())
	}
	if !admission.tagged || len(admission.tagIds) != len(delegation.GetTagAtoms()) {
		return fmt.Errorf("%w: a Delegation's admission carries exactly its tags", ErrConfigRule)
	}
	for _, tagBytes := range delegation.GetTagAtoms() {
		tagId, err := IdFromBytes(tagBytes)
		if err != nil || !slices.Contains(admission.tagIds, tagId) {
			return fmt.Errorf("%w: a Delegation's admission carries exactly its tags", ErrConfigRule)
		}
	}
	if !admission.ephemeral && admit.GetNotAfter() < delegation.GetNotAfter() {
		return fmt.Errorf("%w: an agent's not_after before its Delegation's", ErrConfigRule)
	}
	return nil
}

// A Delegation's AdmissionConfirm: of an agent it admitted, while it still signs.
func (self *ConfigState) checkDelegationConfirm(statement *configStatement, row *bridge.SidecarRow) error {
	if len(statement.signers) != 1 {
		return fmt.Errorf("%w: a Delegation's confirmation carries its key's signature alone", ErrConfigSigner)
	}
	delegation := self.signingDelegation(statement.signers)
	if err := configDelegationSigns(delegation, statement.timeMs); err != nil {
		return err
	}
	if !bytes.Equal(row.GetDelegationId(), delegation.GetDelegationId()) {
		return fmt.Errorf("%w: a Delegation confirms only an agent it admitted", ErrConfigAuthority)
	}
	return nil
}

// Whether the Delegation ended, and the position it ended at: its DelegationRevoke, its void or a compromise
// revocation of an agent it admitted (D-TEAM-30). False for one that has not ended or that this state does not hold.
func (self *ConfigState) DelegationEnded(delegationId []byte) (uint64, bool) {
	delegation := self.delegations[string(delegationId)]
	if delegation == nil || delegation.GetEndedAt() == 0 {
		return 0, false
	}
	return delegation.GetEndedAt(), true
}

// Whether the Delegation's shared reader key dropped (§10.5), and the position it dropped at: its end, a Suspend of one
// of its agents, or a lost or removed revocation of one. A dropped key leaves a live Delegation admitting.
func (self *ConfigState) DelegationKeyDropped(delegationId []byte) (uint64, bool) {
	delegation := self.delegations[string(delegationId)]
	if delegation == nil || delegation.GetKeyDroppedAt() == 0 {
		return 0, false
	}
	return delegation.GetKeyDroppedAt(), true
}
