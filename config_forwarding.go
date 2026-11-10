// §7.9's forwarding row as a rule of the log (D-TEAM-33; owner decision 197; DESIGN-DETAILS 4.2.6): a Delegation with
// forward set is its sidecar S's forwarding Delegation, which S signs for the keys its app's VPN component generated.
//
//	Delegation        by forward_sidecar_id's own identity key alone, S standing: admitted, not revoked, not parked and
//	                    not read_only; no tag_ids, max_admits 0 and not_after 0; an Ed25519 pubkey and a 1,216-byte
//	                    X-Wing reader key; host_client_id and host_client_public_key both set or both empty. None of
//	                    D-TEAM-30's agent rules judge it: no tag owner, no Owner's or Admin's device, no 90 days
//	its key           signs no log statement: api and every reader refuse a SidecarAdmit or AdmissionConfirm whose
//	                    signer resolves to one; it signs only S's WindowDelegations, which hosts verify (§17.9)
//	DelegationRevoke  since_n 0 only, from S, a device allowed to revoke S (§5.6) or an Owner's or Admin's device; one
//	                    naming an ended or superseded Delegation takes effect and changes nothing live
//	supersession      a newer forwarding Delegation of S supersedes the one live before it at the newer one's position,
//	                    superseded_at: no end for §10.5, so no shrink, and one live a sidecar
//	ends              its DelegationRevoke; S's revocation for any reason, a member's removal and an ephemeral reap
//	                    included; its void, S in a compromise cascade's P when it signed it (config_cascade.go)
//	key drops         while S is parked or suspended, key_dropped_at the position that dropped it, and 0 again when S
//	                    is neither: it returns with S
//
// Its row leaves reader_xwing_public_key empty and carries the key's SHA-256 in reader_key_sha256: the key is gkm's
// object, since 1,216 B a device would pass §8.8's 4 MiB of rows at about 2,600 app devices (DESIGN-DETAILS 4.2.2).
// What a host may read of it is the config alone (§10.5), which KEYS's holders decide from the row.
//
// Every effect here reads only the statement's body and the state being built, never what the check found, so a
// base's re-application gives every reader the same rows (DESIGN-DETAILS 5.2.3): the row's signer is the body's
// forward_sidecar_id, which the check held equal to the signer. Nothing here creates, derives or unwraps a key, so
// nothing calls testHookSecret. On every leg.

package sidecar

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// ForwardScope.host_client_public_key's size: a ClientKey, Ed25519 (C15).
const configHostClientPublicKeyByteCount = ed25519.PublicKeySize

// Whether a row is a forwarding Delegation's: it names the sidecar it forwards for.
func ConfigDelegationRowForwards(row *bridge.DelegationRow) bool {
	return len(row.GetForwardSidecarId()) != 0
}

// The sidecar a forwarding Delegation's row is of, false for any other row or a malformed id.
func configRowForwardSidecar(row *bridge.DelegationRow) (Id, bool) {
	if !ConfigDelegationRowForwards(row) {
		return Id{}, false
	}
	sidecarId, err := IdFromBytes(row.GetForwardSidecarId())
	return sidecarId, err == nil
}

// A forwarding Delegation: its own sidecar's signature alone, that sidecar standing and not read_only; its fields'
// forms, with no tag, max_admits or not_after; and a delegation_id no state held before. The host client, where set,
// is api's to check against its own tables: a reader holds no client rows.
func configCheckForwardingDelegation(state *ConfigState, statement *configStatement) error {
	delegation := statement.body.(*protocol.Delegation)
	forward := delegation.GetForward()
	if len(statement.signers) != 1 || statement.signers[0].Kind != ConfigSignerSidecar {
		return fmt.Errorf("%w: a forwarding Delegation takes its own sidecar's signature alone", ErrConfigSigner)
	}
	sidecarId, err := IdFromBytes(forward.GetForwardSidecarId())
	if err != nil {
		return fmt.Errorf("%w: a forward_sidecar_id of %d bytes", ErrConfigRule, len(forward.GetForwardSidecarId()))
	}
	hostIdSize, hostKeySize := len(forward.GetHostClientId()), len(forward.GetHostClientPublicKey())
	switch {
	case len(delegation.GetTagIds()) != 0:
		return fmt.Errorf("%w: a forwarding Delegation naming tags", ErrConfigRule)
	case delegation.GetMaxAdmits() != 0:
		return fmt.Errorf("%w: a forwarding Delegation with max_admits, which admits nothing", ErrConfigRule)
	case delegation.GetNotAfter() != 0:
		return fmt.Errorf("%w: a forwarding Delegation with a not_after", ErrConfigRule)
	case len(delegation.GetPubkey()) != ed25519.PublicKeySize:
		return fmt.Errorf("%w: a forwarding key of %d bytes", ErrConfigRule, len(delegation.GetPubkey()))
	case len(delegation.GetReaderXwingPublicKey()) != configXwingPublicKeyByteCount:
		return fmt.Errorf("%w: a reader key of %d bytes", ErrConfigRule, len(delegation.GetReaderXwingPublicKey()))
	case hostIdSize != 0 && hostIdSize != len(Id{}):
		return fmt.Errorf("%w: a host_client_id of %d bytes", ErrConfigRule, hostIdSize)
	case hostIdSize == 0 && hostKeySize != 0:
		return fmt.Errorf("%w: a host client key with no host client", ErrConfigRule)
	case hostIdSize != 0 && hostKeySize != configHostClientPublicKeyByteCount:
		return fmt.Errorf("%w: a host client key of %d bytes", ErrConfigRule, hostKeySize)
	case state.delegations[string(statement.id[:])] != nil:
		return fmt.Errorf("%w: a delegation_id declared before", ErrConfigRule)
	}
	if statement.signers[0].SidecarId != sidecarId {
		return fmt.Errorf("%w: a forwarding Delegation is signed only by the sidecar it names", ErrConfigAuthority)
	}
	row, standing := state.standingSidecar(sidecarId, statement.timeMs)
	if !standing {
		return fmt.Errorf("%w: a forwarding Delegation's sidecar is not admitted, or is revoked or parked", ErrConfigAuthority)
	}
	if configRowReadOnly(row) {
		return fmt.Errorf("%w: a forwarding Delegation from a read_only device", ErrConfigReadOnly)
	}
	return nil
}

// A forwarding Delegation's effect: its row, keyed by its delegation_id, its signer the sidecar its body names, its
// reader key as a digest; each forwarding Delegation of that sidecar live before it superseded here; and its key
// dropped from the start where the sidecar is suspended on the state being built.
func configApplyForwardingDelegation(next *configStateBuilder, statement *configStatement) error {
	delegation := statement.body.(*protocol.Delegation)
	forward := delegation.GetForward()
	sidecarId, err := IdFromBytes(forward.GetForwardSidecarId())
	if err != nil {
		return fmt.Errorf("%w: a forward_sidecar_id of %d bytes", ErrConfigRule, len(forward.GetForwardSidecarId()))
	}
	if next.state.delegations[string(statement.id[:])] != nil {
		return fmt.Errorf("%w: a delegation_id declared before", ErrConfigRule)
	}
	sidecarRow := next.sidecar(sidecarId)
	if sidecarRow == nil || sidecarRow.GetRevokedAt() != 0 {
		// the rebuilt rows no longer hold its sidecar standing, so it has nothing to forward for
		return fmt.Errorf("%w: a forwarding Delegation's sidecar is not admitted here", ErrConfigRule)
	}
	for _, delegationId := range configForwardingIds(next.state, sidecarId, configForwardingLive) {
		next.delegationForWrite(delegationId).SupersededAt = statement.n
	}
	readerKeySha256 := DelegationReaderKeySha256(delegation.GetReaderXwingPublicKey())
	row := &bridge.DelegationRow{
		DelegationId:        bytes.Clone(statement.id[:]),
		Signer:              sidecarId.Bytes(),
		At:                  statement.n,
		Pubkey:              bytes.Clone(delegation.GetPubkey()),
		ForwardSidecarId:    sidecarId.Bytes(),
		HostClientId:        bytes.Clone(forward.GetHostClientId()),
		HostClientPublicKey: bytes.Clone(forward.GetHostClientPublicKey()),
		ReaderKeySha256:     readerKeySha256[:],
	}
	if sidecarRow.GetParkedAt() != 0 || aclRowsSuspends(next.state.aclRows, sidecarId) {
		row.KeyDroppedAt = statement.n
	}
	next.putDelegation(row)
	return nil
}

// A forwarding Delegation's DelegationRevoke: since_n 0, the only form one takes, since it admitted nothing to park;
// from its sidecar itself, as a device signs itself out, from whoever may revoke that sidecar, or from an Owner's or
// Admin's device. Revoking an ended or superseded one is no refusal.
func configCheckForwardingRevoke(state *ConfigState, statement *configStatement, delegation *bridge.DelegationRow) error {
	revoke := statement.body.(*protocol.DelegationRevoke)
	if revoke.GetSinceN() != 0 {
		return fmt.Errorf("%w: a forwarding Delegation's revocation carries since_n 0", ErrConfigRule)
	}
	sidecarId, ok := configRowForwardSidecar(delegation)
	if !ok {
		return fmt.Errorf("%w: a forwarding Delegation's row names no sidecar", ErrConfigRule)
	}
	if len(statement.signers) == 1 && statement.signers[0].Kind == ConfigSignerSidecar && statement.signers[0].SidecarId == sidecarId {
		return nil
	}
	if _, admin := state.anyMemberDevice(statement.signers, statement.timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
		return role == bridge.MemberRole_MEMBER_ROLE_OWNER || role == bridge.MemberRole_MEMBER_ROLE_ADMIN
	}); admin {
		return nil
	}
	if row := state.sidecars[sidecarId]; row != nil {
		if err := state.revokeSigners(statement.signers, configRowAdmission(sidecarId, row), statement.timeMs); err == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: no signer may revoke this forwarding Delegation", ErrConfigAuthority)
}

// Which of a sidecar's forwarding Delegations a change reaches.
type configForwardingSet int

const (
	// not ended and not superseded: the one that is live
	configForwardingLive configForwardingSet = iota + 1
	// not ended, superseded ones included
	configForwardingUnended
)

// The ids of the sidecar's forwarding Delegations in set, in id order.
func configForwardingIds(state *ConfigState, sidecarId Id, set configForwardingSet) [][]byte {
	delegationIds := [][]byte{}
	for _, row := range state.delegations {
		rowSidecarId, forwards := configRowForwardSidecar(row)
		if !forwards || rowSidecarId != sidecarId || row.GetEndedAt() != 0 {
			continue
		}
		if set == configForwardingLive && row.GetSupersededAt() != 0 {
			continue
		}
		delegationIds = append(delegationIds, row.GetDelegationId())
	}
	slices.SortFunc(delegationIds, bytes.Compare)
	return delegationIds
}

// Ends every forwarding Delegation of a sidecar at n, its revocation for any reason: superseded ones too, which
// changes nothing live.
func configEndForwarding(next *configStateBuilder, sidecarId Id, n uint64) {
	for _, delegationId := range configForwardingIds(next.state, sidecarId, configForwardingUnended) {
		configEndDelegation(next.delegationForWrite(delegationId), n)
	}
}

// A park's effect on a sidecar's forwarding Delegations, its span in P being [from, n): one it signed at or after
// from rests on what P signed, is void and ends at n, as config_cascade.go ends every Delegation P signed; the key of
// the live one it signed before drops at n.
func configParkForwarding(next *configStateBuilder, sidecarId Id, from uint64, n uint64) {
	for _, delegationId := range configForwardingIds(next.state, sidecarId, configForwardingUnended) {
		if from <= next.state.delegations[string(delegationId)].GetAt() {
			configEndDelegation(next.delegationForWrite(delegationId), n)
		}
	}
	if row := next.sidecar(sidecarId); row != nil && row.GetParkedAt() != 0 {
		configDropForwardingKey(next, sidecarId, n)
	}
}

// Drops the key of a sidecar's live forwarding Delegation at n, as the sidecar parks or is suspended, keeping an
// earlier drop's position.
func configDropForwardingKey(next *configStateBuilder, sidecarId Id, n uint64) {
	for _, delegationId := range configForwardingIds(next.state, sidecarId, configForwardingLive) {
		if next.state.delegations[string(delegationId)].GetKeyDroppedAt() == 0 {
			next.delegationForWrite(delegationId).KeyDroppedAt = n
		}
	}
}

// Returns the key of a sidecar's live forwarding Delegation once the sidecar is neither parked nor suspended, nor
// revoked, on the state being built: it returns with its sidecar. Called after a lift and after an Unsuspend.
func configReturnForwardingKey(next *configStateBuilder, sidecarId Id) {
	row := next.sidecar(sidecarId)
	if row == nil || row.GetRevokedAt() != 0 || row.GetParkedAt() != 0 || aclRowsSuspends(next.state.aclRows, sidecarId) {
		return
	}
	for _, delegationId := range configForwardingIds(next.state, sidecarId, configForwardingLive) {
		if next.state.delegations[string(delegationId)].GetKeyDroppedAt() != 0 {
			next.delegationForWrite(delegationId).KeyDroppedAt = 0
		}
	}
}

// Each sidecar's live forwarding Delegation, built once.
func (self *ConfigState) forwarding() map[Id]*bridge.DelegationRow {
	self.forwardingOnce.Do(func() {
		live := map[Id]*bridge.DelegationRow{}
		for _, row := range self.delegations {
			sidecarId, forwards := configRowForwardSidecar(row)
			if !forwards || row.GetEndedAt() != 0 || row.GetSupersededAt() != 0 {
				continue
			}
			// the rule keeps one live a sidecar; rows that held two would give the newest, then the higher id
			if held := live[sidecarId]; held != nil {
				if c := cmp.Compare(held.GetAt(), row.GetAt()); 0 < c || (c == 0 && 0 <= bytes.Compare(held.GetDelegationId(), row.GetDelegationId())) {
					continue
				}
			}
			live[sidecarId] = row
		}
		self.forwardingCache = live
	})
	return self.forwardingCache
}

// The sidecar's live forwarding Delegation at this state (§7.9's forwarding row): the one neither ended nor
// superseded, nil for none. Whether its key is in force is ForwardingKey's: a live Delegation's key is dropped while
// its sidecar is parked or suspended. The row is the state's own and must not be changed.
func (self *ConfigState) ForwardingDelegation(sidecarId Id) *bridge.DelegationRow {
	return self.forwarding()[sidecarId]
}

// The forwarding key in force for the sidecar at this state: its live forwarding Delegation's id and Ed25519 key,
// false when it has none live, its key is dropped, or the sidecar does not stand at the state's time. What a host
// admits the sidecar's WindowDelegations under (§17.9's verify), and what a compile puts in BridgeIdentity's
// forward_delegation_id and forward_public_key.
func (self *ConfigState) ForwardingKey(sidecarId Id) (delegationId []byte, publicKey []byte, ok bool) {
	row := self.forwarding()[sidecarId]
	if row == nil || row.GetKeyDroppedAt() != 0 {
		return nil, nil, false
	}
	if _, standing := self.standingSidecar(sidecarId, self.timeMs); !standing {
		return nil, nil, false
	}
	return bytes.Clone(row.GetDelegationId()), bytes.Clone(row.GetPubkey()), true
}
