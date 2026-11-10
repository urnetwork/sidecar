// §7.9's compromise cascade (D-TEAM-26): a SidecarRevoke{reason: compromise, since_n} parks a closure P, voids what
// P signed, ends the Delegations P signed and the one that admitted the revoked sidecar, and is lifted device by device
// by a confirmation from outside P. Rows keep what every reader needs to build P alike (DESIGN-DETAILS 5.2.3): each
// admission's signers and position, every confirmation with whether it lifted a park, each recovery binding's and
// Delegation's signer and position, and each sidecar's spans in earlier cascades' P (question
// team-m2-04-cascade-spans), so api, evs, gkm, a new device and a long-running reader reach one P from rows alone.
//
// P, in position order from since_n, each record counting from the entry that carried it, never its signer's at:
//
//	revoked     the revoked sidecar, from since_n
//	admitted    a sidecar whose admission, at or after since_n, a sidecar then in P signed
//	recovery    one a recovery key admitted, alone or in a proposal, under a binding a sidecar then in P signed
//	delegation  one admitted under a Delegation a sidecar then in P signed, which is void; and where a Delegation
//	              admitted the revoked sidecar, each sidecar that Delegation admitted from since_n on
//	lifted      one whose park a sidecar then in P lifted, by an AdmissionConfirm or OwnerConfirm
//	consent     one consented (§8.5) now that is not once what P signed counts for nothing: a confirmation of a
//	              device consented on other signatures adds none
//
// The revocation is refused when P would hold one of its signers. Its effect: the revoked sidecar revoked and every
// other in P parked at the entry, each holding a span [from, entry) in rows; what each signed inside its span void
// until a signer outside P signs it again (CascadeVoids): its recovery bindings, so a member's binding in effect falls
// back to its newest one not void, its registered keys, its EvsShares (ACL's VoidEvsShares) and its Delegations, which
// end; while grants, approvals, suspensions, access-log statements, SponsorSets, IndexerSets, MemberAdmits and config
// heads it signed stand.
//
// A lift: an AdmissionConfirm by one allowed to admit the sidecar, or its member's OwnerConfirm, from a standing
// signer, so one outside P, unparks it there, the device live again from that position; what it signed in P stays
// void. Every confirmation that takes effect joins its row's history.
//
// A cascade's P is a pure function of the state it is computed at, so the effect recomputes it on the state being
// built, which a base's re-application rebuilds alike at every reader. Nothing here creates, derives or unwraps a key,
// so nothing calls testHookSecret. On every leg.

package sidecar

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// ConfirmationRow.kind's values.
const (
	configConfirmAdmission uint32 = 1
	configConfirmOwner     uint32 = 2
)

// Why a cascade's P holds a sidecar.
type ConfigCascadeReason int

const (
	// the revoked sidecar, from since_n
	ConfigCascadeRevoked ConfigCascadeReason = iota + 1
	// a sidecar then in P signed its admission
	ConfigCascadeAdmitted
	// admitted under a Delegation a sidecar then in P signed, or by the Delegation that admitted the revoked sidecar
	ConfigCascadeDelegation
	// a recovery key admitted it under a binding a sidecar then in P signed
	ConfigCascadeRecovery
	// a sidecar then in P lifted its park
	ConfigCascadeLifted
	// its consent rests only on what P signed
	ConfigCascadeConsent
)

// One sidecar a cascade's P holds.
type ConfigCascadeMember struct {
	SidecarId Id
	// The position from which it is in P: since_n for the revoked sidecar, else the entry that pulled it in.
	From   uint64
	Reason ConfigCascadeReason
}

// §7.9's P for a compromise revocation of TargetId from SinceN, at the state it was computed at.
type ConfigCascadeClosure struct {
	TargetId Id
	SinceN   uint64
	// Every sidecar P holds: the revoked one first, then by From and id.
	Members []ConfigCascadeMember

	from map[Id]uint64
}

// Whether P holds the sidecar, and from which position.
func (self *ConfigCascadeClosure) From(sidecarId Id) (uint64, bool) {
	from, held := self.from[sidecarId]
	return from, held
}

// Whether P held the sidecar at position at.
func (self *ConfigCascadeClosure) holdsAt(sidecarId Id, at uint64) bool {
	from, held := self.from[sidecarId]
	return held && from <= at
}

// Whether a record signed by signer (a sidecar_id, a recovery key's hash or a delegation_id) and carried at position at
// rests on what this P signed: a sidecar then in P, a Delegation one signed, or a recovery key whose binding one
// signed.
func (self *ConfigCascadeClosure) voidsRecord(state *ConfigState, signer []byte, at uint64) bool {
	switch len(signer) {
	case len(Id{}):
		return self.holdsAt(Id(signer), at)
	case sha256.Size:
		if delegation := state.delegations[string(signer)]; delegation != nil {
			return len(delegation.GetSigner()) == len(Id{}) && self.holdsAt(Id(delegation.GetSigner()), delegation.GetAt())
		}
		for _, binding := range state.bindingsOfKeyAt(signer, at) {
			if len(binding.GetSigner()) == len(Id{}) && self.holdsAt(Id(binding.GetSigner()), binding.GetAt()) {
				return true
			}
		}
	}
	return false
}

// Adds the sidecar at from, or lowers its position; false when nothing changed.
func (self *ConfigCascadeClosure) lower(sidecarId Id, from uint64, reason ConfigCascadeReason) bool {
	if current, held := self.from[sidecarId]; held && current <= from {
		return false
	}
	self.from[sidecarId] = from
	for i := range self.Members {
		if self.Members[i].SidecarId == sidecarId {
			self.Members[i].From, self.Members[i].Reason = from, reason
			return true
		}
	}
	self.Members = append(self.Members, ConfigCascadeMember{SidecarId: sidecarId, From: from, Reason: reason})
	return true
}

// The state's view with what this P signed voided too, which §8.5's consent is judged by for the consent clause.
type configCascadeView struct {
	*ConfigState
	closure *ConfigCascadeClosure
}

// The state's voids, and this P's.
func (self configCascadeView) CascadeVoids(signer []byte, at uint64) bool {
	return self.ConfigState.CascadeVoids(signer, at) || self.closure.voidsRecord(self.ConfigState, signer, at)
}

// §7.9's P for a compromise revocation of targetId from sinceN at this state. An error for a sidecar this state never
// admitted or a since_n of 0, which has no default.
func (self *ConfigState) CascadeClosure(targetId Id, sinceN uint64) (*ConfigCascadeClosure, error) {
	target := self.sidecars[targetId]
	if target == nil {
		return nil, fmt.Errorf("%w: no such sidecar", ErrConfigRule)
	}
	if sinceN == 0 {
		return nil, fmt.Errorf("%w: a compromise revocation needs since_n", ErrConfigRule)
	}
	closure := &ConfigCascadeClosure{
		TargetId: targetId,
		SinceN:   sinceN,
		Members:  []ConfigCascadeMember{{SidecarId: targetId, From: sinceN, Reason: ConfigCascadeRevoked}},
		from:     map[Id]uint64{targetId: sinceN},
	}
	acl, err := self.Acl()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	sidecarIds := self.SidecarIds()
	// the least fixed point: positions only fall and members only join, so this ends
	for {
		changed := false
		for _, sidecarId := range sidecarIds {
			if sidecarId == targetId {
				continue
			}
			if from, reason, found := closure.recordEntry(self, self.sidecars[sidecarId], target.GetDelegationId()); found {
				changed = closure.lower(sidecarId, from, reason) || changed
			}
		}
		consentChanged, err := closure.consentEntries(self, acl, sidecarIds)
		if err != nil {
			return nil, err
		}
		if !changed && !consentChanged {
			break
		}
	}
	slices.SortStableFunc(closure.Members[1:], func(a ConfigCascadeMember, b ConfigCascadeMember) int {
		if c := cmp.Compare(a.From, b.From); c != 0 {
			return c
		}
		return a.SidecarId.Cmp(b.SidecarId)
	})
	return closure, nil
}

// The earliest position at which one of the row's own records pulls it into this P, and why: its admission or a
// confirmation that lifted its park.
func (self *ConfigCascadeClosure) recordEntry(state *ConfigState, row *bridge.SidecarRow, targetDelegationId []byte) (uint64, ConfigCascadeReason, bool) {
	best, reason, found := uint64(0), ConfigCascadeReason(0), false
	consider := func(position uint64, why ConfigCascadeReason) {
		if !found || position < best {
			best, reason, found = position, why, true
		}
	}
	admittedAt := row.GetAdmittedAt()
	if self.SinceN <= admittedAt {
		for _, signer := range row.GetAdmissionSigners() {
			if !self.voidsRecord(state, signer, admittedAt) {
				continue
			}
			switch {
			case len(signer) == len(Id{}):
				consider(admittedAt, ConfigCascadeAdmitted)
			case state.delegations[string(signer)] != nil:
				consider(admittedAt, ConfigCascadeDelegation)
			default:
				consider(admittedAt, ConfigCascadeRecovery)
			}
		}
		if len(targetDelegationId) != 0 && bytes.Equal(row.GetDelegationId(), targetDelegationId) {
			consider(admittedAt, ConfigCascadeDelegation)
		}
	}
	for _, confirmation := range row.GetConfirmations() {
		if confirmation.GetLiftedPark() && self.SinceN <= confirmation.GetAt() &&
			self.voidsRecord(state, confirmation.GetSigner(), confirmation.GetAt()) {
			consider(confirmation.GetAt(), ConfigCascadeLifted)
		}
	}
	return best, reason, found
}

// §8.5's clause: each untagged member device consented now that is not once what this P signed counts for nothing
// joins P, from the earliest of its consent records P signed. One whose loss runs through another device's consent
// waits until that device has joined, so its position is that device's record's. Whether any joined.
func (self *ConfigCascadeClosure) consentEntries(state *ConfigState, acl *AclState, sidecarIds []Id) (bool, error) {
	rows := state.aclRows
	if rows == nil {
		rows = &protocol.AclRows{}
	}
	hypothetical, err := NewAclState(rows, configCascadeView{ConfigState: state, closure: self})
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	changed := false
	deferred := []Id{}
	for _, sidecarId := range sidecarIds {
		if _, held := self.from[sidecarId]; held || !acl.Consented(sidecarId) || hypothetical.Consented(sidecarId) {
			continue
		}
		row := state.sidecars[sidecarId]
		best, found := uint64(0), false
		if self.SinceN <= row.GetAdmittedAt() {
			for _, signer := range row.GetAdmissionSigners() {
				if self.voidsRecord(state, signer, row.GetAdmittedAt()) {
					best, found = row.GetAdmittedAt(), true
				}
			}
		}
		for _, confirmation := range row.GetConfirmations() {
			at := confirmation.GetAt()
			if self.SinceN <= at && self.voidsRecord(state, confirmation.GetSigner(), at) && (!found || at < best) {
				best, found = at, true
			}
		}
		if !found {
			deferred = append(deferred, sidecarId)
			continue
		}
		changed = self.lower(sidecarId, best, ConfigCascadeConsent) || changed
	}
	if changed {
		return true, nil
	}
	// nothing else joins, so what still rests on P rests on it from since_n
	for _, sidecarId := range deferred {
		changed = self.lower(sidecarId, self.SinceN, ConfigCascadeConsent) || changed
	}
	return changed, nil
}

// The recovery bindings in force at position at whose key's hash is keySha256, one per member that bound it: each
// member's newest binding carried before at.
func (self *ConfigState) bindingsOfKeyAt(keySha256 []byte, at uint64) []*bridge.RecoveryBindingRow {
	bindings := []*bridge.RecoveryBindingRow{}
	for _, memberId := range self.MemberIds() {
		for _, binding := range self.members[memberId].GetBindings() {
			if binding.GetAt() < at {
				if bytes.Equal(binding.GetKeySha256(), keySha256) {
					bindings = append(bindings, binding)
				}
				break
			}
		}
	}
	return bindings
}

// Whether the sidecar was in an earlier compromise cascade's P at position at, by the spans its row keeps.
func (self *ConfigState) heldInCascadeAt(signer []byte, at uint64) bool {
	sidecarId, err := IdFromBytes(signer)
	if err != nil {
		return false
	}
	for _, span := range self.sidecars[sidecarId].GetCascades() {
		if span.GetFrom() <= at && at < span.GetUntil() {
			return true
		}
	}
	return false
}

// Whether a record signed by signer (a sidecar_id, a recovery key's hash or a delegation_id) and carried at position
// at rests on what a compromise cascade voids (§7.9's cascade, D-TEAM-26): a sidecar then in a cascade's P, a
// Delegation one signed, or a recovery key whose binding in force at at one signed. Read from rows alone, so every
// reader answers alike.
func (self *ConfigState) CascadeVoids(signer []byte, at uint64) bool {
	switch len(signer) {
	case len(Id{}):
		return self.heldInCascadeAt(signer, at)
	case sha256.Size:
		if delegation := self.delegations[string(signer)]; delegation != nil {
			return self.heldInCascadeAt(delegation.GetSigner(), delegation.GetAt())
		}
		for _, binding := range self.bindingsOfKeyAt(signer, at) {
			if self.heldInCascadeAt(binding.GetSigner(), binding.GetAt()) {
				return true
			}
		}
	}
	return false
}

// Every sidecar parked now, by a compromise cascade or a leaked bundle's DelegationRevoke, in id order.
func (self *ConfigState) ParkedSet() []Id {
	parked := []Id{}
	for _, sidecarId := range self.SidecarIds() {
		if self.sidecars[sidecarId].GetParkedAt() != 0 {
			parked = append(parked, sidecarId)
		}
	}
	return parked
}

// A compromise revocation: since_n a position before the entry; never by the device itself; by whoever may revoke
// the device; and refused when its P would hold one of its signers, a recovery key whose binding P voids included.
func configCheckCompromise(state *ConfigState, statement *configStatement, sidecarId Id, row *bridge.SidecarRow) error {
	revoke := statement.body.(*bridge.SidecarRevoke)
	sinceN := revoke.GetSinceN()
	if sinceN == 0 || statement.n <= sinceN {
		return fmt.Errorf("%w: a compromise revocation needs a since_n before its entry", ErrConfigRule)
	}
	for _, signer := range statement.signers {
		if signer.Kind == ConfigSignerSidecar && signer.SidecarId == sidecarId {
			return fmt.Errorf("%w: a device revokes itself only for lost", ErrConfigAuthority)
		}
	}
	if err := state.revokeSigners(statement.signers, configRowAdmission(sidecarId, row), statement.timeMs); err != nil {
		return err
	}
	closure, err := state.CascadeClosure(sidecarId, sinceN)
	if err != nil {
		return err
	}
	for _, signer := range statement.signers {
		if closure.voidsRecord(state, signer.RowsSigner(), statement.n) {
			return fmt.Errorf("%w: the cascade's P would hold one of its signers", ErrConfigAuthority)
		}
	}
	return nil
}

// A compromise revocation's effect, P computed on the state being built: the target revoked and each other sidecar of
// P parked here, every one holding its span; the Delegations P signed and the target's own ended, their keys dropped;
// each member's binding in effect its newest one P left standing; and the recovery proposals a voided binding's key
// signed closed.
func configApplyCompromise(next *configStateBuilder, statement *configStatement, sidecarId Id) error {
	revoke := statement.body.(*bridge.SidecarRevoke)
	closure, err := next.snapshot().CascadeClosure(sidecarId, revoke.GetSinceN())
	if err != nil {
		return err
	}
	target := next.sidecarForWrite(sidecarId)
	if target.GetRevokedAt() == 0 {
		target.RevokedAt = statement.n
	}
	target.Cascades = append(target.Cascades, &bridge.CascadeSpanRow{From: revoke.GetSinceN(), Until: statement.n})
	// the revoked sidecar's forwarding Delegations end with it, those from before since_n too (D-TEAM-33)
	configEndForwarding(next, sidecarId, statement.n)
	for _, member := range closure.Members[1:] {
		configParkSidecar(next, member.SidecarId, member.From, statement.n)
	}
	for _, delegation := range next.state.Delegations() {
		void := closure.voidsRecord(next.state, delegation.GetSigner(), delegation.GetAt())
		if void || bytes.Equal(delegation.GetDelegationId(), target.GetDelegationId()) {
			configEndDelegation(next.delegationForWrite(delegation.GetDelegationId()), statement.n)
		}
	}
	configRestoreBindings(next)
	configCloseVoidedProposals(next, statement.n)
	return nil
}

// Parks a sidecar at n, unless it is revoked or parked already, and keeps its span [from, n) in P. Its forwarding
// Delegations follow it (D-TEAM-33): one it signed inside the span is void and ends here, and the key of one it signed
// before drops here until a lift returns it.
func configParkSidecar(next *configStateBuilder, sidecarId Id, from uint64, n uint64) {
	row := next.sidecarForWrite(sidecarId)
	if row == nil {
		return
	}
	if row.GetRevokedAt() == 0 && row.GetParkedAt() == 0 {
		row.ParkedAt = n
	}
	row.Cascades = append(row.Cascades, &bridge.CascadeSpanRow{From: from, Until: n})
	configParkForwarding(next, sidecarId, from, n)
}

// Sets each member's binding in effect to its newest binding no cascade voids, none when every one is void (§7.9: a
// void restores the newest earlier binding not void).
func configRestoreBindings(next *configStateBuilder) {
	for _, memberId := range next.state.MemberIds() {
		member := next.member(memberId)
		var inEffect []byte
		for _, binding := range member.GetBindings() {
			if !next.state.heldInCascadeAt(binding.GetSigner(), binding.GetAt()) {
				inEffect = binding.GetKeySha256()
				break
			}
		}
		if !bytes.Equal(inEffect, member.GetRecoveryKeySha256()) {
			next.memberForWrite(memberId).RecoveryKeySha256 = bytes.Clone(inEffect)
		}
	}
}

// Records a confirmation that took effect at n on the sidecar's row: the newest of its kind, a ConfirmationRow in its
// history, and, for a parked sidecar, the lift (§7.9's lift row): unparked here, and a member device standing again
// live from here (§7.9's leaves row).
func configConfirmSidecar(next *configStateBuilder, n uint64, kind uint32, signer []byte, sidecarId Id) {
	row := next.sidecarForWrite(sidecarId)
	if row == nil {
		return
	}
	lifted := row.GetParkedAt() != 0
	switch kind {
	case configConfirmAdmission:
		row.ConfirmSigner, row.ConfirmedAt = bytes.Clone(signer), n
	case configConfirmOwner:
		row.OwnerConfirmSigner, row.OwnerConfirmedAt = bytes.Clone(signer), n
	}
	row.Confirmations = append(row.Confirmations, &bridge.ConfirmationRow{Kind: kind, Signer: bytes.Clone(signer), At: n, LiftedPark: lifted})
	if !lifted || row.GetRevokedAt() != 0 {
		return
	}
	row.ParkedAt = 0
	// its forwarding key returns with it, unless a Suspend still holds it (D-TEAM-33)
	configReturnForwardingKey(next, sidecarId)
	if !configRowMemberDevice(row) || aclRowsSuspends(next.state.aclRows, sidecarId) {
		return
	}
	if memberId, _ := configRowMember(row); next.member(memberId) != nil {
		row.LiveSince = n
	}
}

// One recovery binding a cascade voids.
type ConfigCascadeBinding struct {
	MemberId  Id
	KeySha256 []byte
	// The sidecar in P that signed it, and its entry.
	Signer Id
	At     uint64
}

// One record a cascade leaves standing though a sidecar then in P signed it (§7.9's cascade row).
type ConfigCascadeStanding struct {
	// suspension, repo_admin, repo_grant or repo_revoke
	Kind string
	// The suspension's subject or the repo the row is of.
	Id     Id
	Signer Id
	At     uint64
}

// One device that sealed keychain.wrap to a binding the cascade voids: its member's devices live while that binding
// was current (§7.9's cascade row, §5.9's backup rule).
type ConfigCascadeReseal struct {
	MemberId  Id
	SidecarId Id
	KeySha256 []byte
}

// What a compromise revocation of a sidecar from since_n would do at this state (§7.9's cascade row): what P parks,
// voids and ends, what stands, and who sealed to a voided binding. Derived from rows, never stored, so CORE's
// PreviewDeviceRevoke reads what api and every reader will apply (SidecarAuthority.Cascade).
type ConfigCascadePlan struct {
	Closure *ConfigCascadeClosure
	// P but the revoked sidecar and any revoked already: what parks.
	Parks []Id
	// Each member's binding P voids, in member then position order.
	VoidedBindings []ConfigCascadeBinding
	// The registered keys P voids, by key_id.
	VoidedKeys []*bridge.KeyRow
	// The EvsShares P voids, ACL's VoidEvsShares.
	VoidedShares []AclVoidedShare
	// The Delegations the revocation ends: each P signed, and the one that admitted the revoked sidecar.
	EndedDelegationIds [][]byte
	// What P signed that stands.
	Stands []ConfigCascadeStanding
	// The devices that sealed to a voided binding.
	Reseals []ConfigCascadeReseal
}

// The plan of a compromise revocation of targetId from sinceN at this state.
func (self *ConfigState) CascadePlan(targetId Id, sinceN uint64) (*ConfigCascadePlan, error) {
	closure, err := self.CascadeClosure(targetId, sinceN)
	if err != nil {
		return nil, err
	}
	plan := &ConfigCascadePlan{Closure: closure}
	for _, member := range closure.Members[1:] {
		if self.sidecars[member.SidecarId].GetRevokedAt() == 0 {
			plan.Parks = append(plan.Parks, member.SidecarId)
		}
	}
	slices.SortFunc(plan.Parks, Id.Cmp)

	for _, memberId := range self.MemberIds() {
		bindings := self.members[memberId].GetBindings()
		for i, binding := range bindings {
			if !closure.voidsRecord(self, binding.GetSigner(), binding.GetAt()) {
				continue
			}
			plan.VoidedBindings = append(plan.VoidedBindings, ConfigCascadeBinding{
				MemberId: memberId, KeySha256: bytes.Clone(binding.GetKeySha256()), Signer: Id(binding.GetSigner()), At: binding.GetAt(),
			})
			// the member's devices live while it was current, from its entry to the next binding's
			until := uint64(0)
			if 0 < i {
				until = bindings[i-1].GetAt()
			}
			for _, sidecarId := range self.SidecarIds() {
				row := self.sidecars[sidecarId]
				rowMemberId, untagged := configRowMember(row)
				if !untagged || rowMemberId != memberId || row.GetEphemeral() {
					continue
				}
				revokedAt := row.GetRevokedAt()
				if (revokedAt != 0 && revokedAt <= binding.GetAt()) || (until != 0 && until <= row.GetAdmittedAt()) {
					continue
				}
				plan.Reseals = append(plan.Reseals, ConfigCascadeReseal{MemberId: memberId, SidecarId: sidecarId, KeySha256: bytes.Clone(binding.GetKeySha256())})
			}
		}
	}

	keyIds := make([]string, 0, len(self.keys))
	for keyId := range self.keys {
		keyIds = append(keyIds, keyId)
	}
	slices.Sort(keyIds)
	for _, keyId := range keyIds {
		key := self.keys[keyId]
		if closure.voidsRecord(self, key.GetSigner(), key.GetAt()) {
			plan.VoidedKeys = append(plan.VoidedKeys, key)
		}
	}

	if acl, err := self.Acl(); err == nil {
		parkedFrom := map[Id]uint64{}
		for _, member := range closure.Members {
			parkedFrom[member.SidecarId] = member.From
		}
		plan.VoidedShares = acl.VoidEvsShares(parkedFrom)
	}

	target := self.sidecars[targetId]
	for _, delegation := range self.Delegations() {
		// the revoked sidecar's own forwarding Delegations end with it, whenever it signed them
		forwardSidecarId, forwards := configRowForwardSidecar(delegation)
		if closure.voidsRecord(self, delegation.GetSigner(), delegation.GetAt()) ||
			bytes.Equal(delegation.GetDelegationId(), target.GetDelegationId()) ||
			(forwards && forwardSidecarId == targetId && delegation.GetEndedAt() == 0) {
			plan.EndedDelegationIds = append(plan.EndedDelegationIds, bytes.Clone(delegation.GetDelegationId()))
		}
	}

	plan.Stands = configCascadeStands(self.aclRows, closure)
	return plan, nil
}

// The suspensions and access-log rows a sidecar then in P signed, which stand until revoked.
func configCascadeStands(rows *protocol.AclRows, closure *ConfigCascadeClosure) []ConfigCascadeStanding {
	stands := []ConfigCascadeStanding{}
	add := func(kind string, id []byte, signer []byte, at uint64) {
		if len(signer) != len(Id{}) || len(id) != len(Id{}) || !closure.holdsAt(Id(signer), at) {
			return
		}
		stands = append(stands, ConfigCascadeStanding{Kind: kind, Id: Id(id), Signer: Id(signer), At: at})
	}
	for _, suspension := range rows.GetSuspensions() {
		add("suspension", suspension.GetSubject(), suspension.GetSigner(), suspension.GetAt())
	}
	for _, repo := range rows.GetRepos() {
		for _, admin := range repo.GetAdmins() {
			add("repo_admin", repo.GetRepoId(), admin.GetSigner(), admin.GetAt())
		}
		for _, grant := range repo.GetGrants() {
			add("repo_grant", repo.GetRepoId(), grant.GetSigner(), grant.GetAt())
		}
		for _, revoke := range repo.GetRevokes() {
			add("repo_revoke", repo.GetRepoId(), revoke.GetSigner(), revoke.GetAt())
		}
	}
	slices.SortStableFunc(stands, func(a ConfigCascadeStanding, b ConfigCascadeStanding) int {
		return cmp.Compare(a.At, b.At)
	})
	return stands
}

// The plan as DeviceRevokePlan's items (§5.6): park, void, stands and reseal, each with what it names and the entry
// that carries it. A device's name is the config head's, which rows do not hold, so it is left to the caller.
func (self *ConfigCascadePlan) Items() []DeviceRevokeItem {
	items := []DeviceRevokeItem{}
	for _, sidecarId := range self.Parks {
		from, _ := self.Closure.From(sidecarId)
		items = append(items, DeviceRevokeItem{Effect: "park", Kind: "device", Id: sidecarId.Bytes(), Position: from})
	}
	for _, binding := range self.VoidedBindings {
		items = append(items, DeviceRevokeItem{Effect: "void", Kind: "recovery_binding", Id: bytes.Clone(binding.KeySha256), Position: binding.At})
	}
	for _, key := range self.VoidedKeys {
		items = append(items, DeviceRevokeItem{Effect: "void", Kind: "key", Id: bytes.Clone(key.GetKeyId()), Position: key.GetAt()})
	}
	for _, share := range self.VoidedShares {
		items = append(items, DeviceRevokeItem{Effect: "void", Kind: "evs_share", Id: share.RepoId.Bytes(), Position: share.At})
	}
	for _, delegationId := range self.EndedDelegationIds {
		items = append(items, DeviceRevokeItem{Effect: "void", Kind: "delegation", Id: bytes.Clone(delegationId)})
	}
	for _, standing := range self.Stands {
		items = append(items, DeviceRevokeItem{Effect: "stands", Kind: standing.Kind, Id: standing.Id.Bytes(), Position: standing.At})
	}
	for _, reseal := range self.Reseals {
		items = append(items, DeviceRevokeItem{Effect: "reseal", Kind: "device", Id: reseal.SidecarId.Bytes()})
	}
	return items
}

// Closes, as voided, each open proposal a recovery key signed under a binding a cascade now voids (§7.9's cascade and
// Recovery voiding): what that key signed rests on P.
func configCloseVoidedProposals(next *configStateBuilder, n uint64) {
	configVoidProposals(next, n, func(proposal *configProposal) bool {
		for _, signer := range proposal.row.GetSigners() {
			if len(signer.GetSigner()) == sha256.Size && next.state.CascadeVoids(signer.GetSigner(), signer.GetAt()) {
				return true
			}
		}
		return false
	})
}
