// §8.5's one consent predicate, consented(d, M), which §5.6, §7.9, §10.9, §11.14 and §16.6 all call and none
// re-derives (D-ACL-22), with §16.6's approval capability and §7.9's tag right.
//
// d is consented for M when its admission names M, it is neither ephemeral nor parked, and one clause holds
// on a signature by neither a sidecar then in a compromise cascade's set P nor a recovery key whose binding
// one signed:
//
//	scoped     M's consented device or M's recovery key signed d's SidecarAdmit, alone or as one of k
//	invited    d's SidecarAdmit carries SIDECAR_CAPABILITY_INVITED and d is M's first admission, revoked
//	           ones included, that is neither ephemeral nor read_only (plan-ACL-invited-consent-evidence)
//	genesis    d signed the network's Genesis
//	confirmed  M's consented device signed OwnerConfirm{d}, or the AdmissionConfirm{d} rows keep
//
// Consent rests on what M's consented devices signed when they signed it, so the build replays every
// clause in log order: a signer counts at position p only if it was consented for M before p, is not
// read_only (read-only devices are never consent signers), and the view's cascade does not void what it
// signed at p. A consent resting on what P signed therefore returns only through M's own OwnerConfirm or
// AdmissionConfirm from a consented device outside P, and an admin's AdmissionConfirm restores all but
// owner-bound reads (§7.9's lift).
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"bytes"
	"cmp"
	"slices"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a replayed consent event is.
type aclConsentClause int

const (
	aclConsentGenesis aclConsentClause = iota + 1
	aclConsentInvited
	aclConsentScoped
	aclConsentOwnerConfirm
	aclConsentAdmissionConfirm
)

// One clause that may consent a sidecar, at the position of the entry that carried it.
type aclConsentEvent struct {
	sidecarIndex int32
	position     uint64
	clause       aclConsentClause
}

// Whether a sidecar_id signer was M's consented device, not read_only, before position, with what it
// signed there outside every cascade.
func (self *AclState) consentSignerCounts(signer []byte, memberId Id, position uint64) bool {
	signerId, err := IdFromBytes(signer)
	if err != nil {
		return false
	}
	signerState := self.sidecarState(signerId)
	if signerState == nil || !signerState.valid || signerState.tagged || signerState.memberId != memberId ||
		signerState.ephemeral || signerState.readOnly || !signerState.hasConsent || position <= signerState.consentedAt {
		return false
	}
	return !self.view.CascadeVoids(signer, position)
}

// Whether a 32-byte signer was M's recovery key at position, the binding then current, with what it
// signed there outside every cascade.
func (self *AclState) recoverySignerCounts(signer []byte, memberId Id, position uint64) bool {
	member := self.view.Member(memberId)
	if member == nil || len(signer) == len(Id{}) {
		return false
	}
	// bindings run newest first: the one in force at position is the first carried before it, and with no
	// binding rows the row's own key is the one in effect
	current := member.GetRecoveryKeySha256()
	if 0 < len(member.GetBindings()) {
		current = nil
		for _, binding := range member.GetBindings() {
			if binding.GetAt() < position {
				current = binding.GetKeySha256()
				break
			}
		}
	}
	if len(current) == 0 || !bytes.Equal(current, signer) {
		return false
	}
	return !self.view.CascadeVoids(signer, position)
}

// Whether one event consents its sidecar, given the consents replayed before it.
func (self *AclState) consentEventHolds(event aclConsentEvent) bool {
	sidecar := &self.sidecars[event.sidecarIndex]
	row := sidecar.facts.Row
	switch event.clause {
	case aclConsentGenesis:
		return true
	case aclConsentInvited:
		// the admitting device's signature must stand outside every cascade
		for _, signer := range row.GetAdmissionSigners() {
			if !self.view.CascadeVoids(signer, event.position) {
				return true
			}
		}
		return false
	case aclConsentScoped:
		for _, signer := range row.GetAdmissionSigners() {
			if self.consentSignerCounts(signer, sidecar.memberId, event.position) ||
				self.recoverySignerCounts(signer, sidecar.memberId, event.position) {
				return true
			}
		}
		return false
	case aclConsentOwnerConfirm:
		return self.consentSignerCounts(row.GetOwnerConfirmSigner(), sidecar.memberId, event.position)
	case aclConsentAdmissionConfirm:
		return self.consentSignerCounts(row.GetConfirmSigner(), sidecar.memberId, event.position)
	}
	return false
}

// Replays every consent clause in log order, recording where each sidecar was first consented.
func (self *AclState) replayConsent() {
	genesis := self.view.Genesis()
	// each member's first admission that is neither ephemeral nor read_only, revoked ones included
	firstDevices := map[Id]int32{}
	for i := range self.sidecars {
		sidecar := &self.sidecars[i]
		if !sidecar.valid || sidecar.tagged || sidecar.ephemeral || sidecar.readOnly {
			continue
		}
		first, found := firstDevices[sidecar.memberId]
		if !found {
			firstDevices[sidecar.memberId] = int32(i)
			continue
		}
		firstRow := self.sidecars[first].facts.Row
		if sidecar.facts.Row.GetAdmittedAt() < firstRow.GetAdmittedAt() {
			firstDevices[sidecar.memberId] = int32(i)
		}
	}

	events := []aclConsentEvent{}
	for i := range self.sidecars {
		sidecar := &self.sidecars[i]
		if !sidecar.valid || sidecar.tagged || sidecar.ephemeral {
			continue
		}
		row := sidecar.facts.Row
		index := int32(i)
		admittedAt := row.GetAdmittedAt()
		if genesis != nil && Id(genesis.GetOwnerSidecarId()) == sidecar.id && Id(genesis.GetOwnerMemberId()) == sidecar.memberId {
			events = append(events, aclConsentEvent{sidecarIndex: index, position: admittedAt, clause: aclConsentGenesis})
		}
		if sidecar.facts.hasCapability(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED) && !sidecar.readOnly &&
			firstDevices[sidecar.memberId] == index {
			events = append(events, aclConsentEvent{sidecarIndex: index, position: admittedAt, clause: aclConsentInvited})
		}
		if 0 < len(row.GetAdmissionSigners()) {
			events = append(events, aclConsentEvent{sidecarIndex: index, position: admittedAt, clause: aclConsentScoped})
		}
		if 0 < len(row.GetOwnerConfirmSigner()) {
			events = append(events, aclConsentEvent{sidecarIndex: index, position: row.GetOwnerConfirmedAt(), clause: aclConsentOwnerConfirm})
		}
		if 0 < len(row.GetConfirmSigner()) {
			events = append(events, aclConsentEvent{sidecarIndex: index, position: row.GetConfirmedAt(), clause: aclConsentAdmissionConfirm})
		}
	}
	slices.SortStableFunc(events, func(a aclConsentEvent, b aclConsentEvent) int {
		return cmp.Compare(a.position, b.position)
	})
	for _, event := range events {
		sidecar := &self.sidecars[event.sidecarIndex]
		if sidecar.hasConsent {
			continue
		}
		if self.consentEventHolds(event) {
			sidecar.hasConsent = true
			sidecar.consentedAt = event.position
		}
	}
}

// Judges each EvsShare once: its signer a consented device of the repo's owner, not read_only, when it
// signed, and what it signed outside every cascade, which voids a share signed in P (§7.9). Every reader
// refuses an admin's share of an owner-bound repo, so one the rows hold anyway opens nothing.
func (self *AclState) judgeShares() {
	for _, repo := range self.repos {
		for i := range repo.shares {
			share := &repo.shares[i]
			share.valid = aclRepoKindOwnerBound(repo.kind) && repo.ownerId != (Id{}) &&
				self.consentSignerCounts(share.row.GetSigner(), repo.ownerId, share.row.GetAt())
		}
	}
}

// §8.5's consented(d, M) now, M being the member d's admission names: the replayed consent, d admitted and
// neither revoked, ephemeral nor parked, and its member still a member.
func (self *AclState) sidecarConsented(sidecar *aclSidecarState) bool {
	return sidecar.hasConsent && sidecar.valid && !sidecar.tagged && !sidecar.ephemeral && !sidecar.parked &&
		!sidecar.revoked && !sidecar.memberGone
}

// §8.5's consented(d, M) for the member d's admission names, the one predicate every caller uses (D-ACL-22).
func (self *AclState) Consented(sidecarId Id) bool {
	sidecar := self.sidecarState(sidecarId)
	return sidecar != nil && self.sidecarConsented(sidecar)
}

// Whether d is consented for this member: Consented, with d's admission naming memberId.
func (self *AclState) ConsentedFor(sidecarId Id, memberId Id) bool {
	sidecar := self.sidecarState(sidecarId)
	return sidecar != nil && sidecar.memberId == memberId && self.sidecarConsented(sidecar)
}

// §16.6's approval-capable device: consented, untagged, not ephemeral and not read_only. A suspended one
// approves nothing either, since a Suspend removes its activations (§8.6).
func (self *AclState) ApprovalCapable(sidecarId Id) bool {
	sidecar := self.sidecarState(sidecarId)
	return sidecar != nil && self.sidecarConsented(sidecar) && !sidecar.readOnly && !sidecar.suspended
}

// Whether the signing sidecar may apply a tag, for §7.9's scoped row: a member device, not read_only and
// standing (not revoked, parked or suspended), of a member the tag atom's tagOwners name, as the rows
// carry them expanded to member_ids (plan-ACL-atom-and-rule-ids #4). A tag no row holds has no owner.
func (self *AclState) CanApplyTag(signerSidecarId Id, tagId Id) bool {
	signer := self.sidecarState(signerSidecarId)
	if signer == nil || signer.class != AclSubjectClassMemberDevice || signer.readOnly ||
		!signer.valid || signer.revoked || signer.parked || signer.suspended || signer.memberGone {
		return false
	}
	atomIndex, found := self.atomIndexes[tagId]
	if !found {
		return false
	}
	atomRow := self.atomRow(atomIndex)
	if atomRow == nil {
		return false
	}
	for _, ownerBytes := range atomRow.GetTagOwnerMemberIds() {
		if Id(ownerBytes) == signer.memberId {
			return true
		}
	}
	return false
}
