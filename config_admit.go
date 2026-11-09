// §7.9's admission and removal records as rules of the log: AdminSet, MemberAdmit, MemberRevoke, SidecarAdmit,
// SidecarRevoke (lost, removed, reaped) and AdmissionConfirm, each with its signer row.
//
//	AdminSet          authority, its changed members never counting
//	MemberAdmit,      an Owner's or Admin's device; authority, the member never counting, if the member is in
//	  MemberRevoke      the AdminSet
//	SidecarAdmit      for a device of a member outside the AdminSet, one admin's device (an Owner, Admin or IT
//	                    admin) or, while self_admit is on, the member's consented device (§8.5); for an AdminSet
//	                    member's device, authority, its existing device counting as one; for a tagged one, a
//	                    device of a member who owns each of its tags (§8's tagOwners)
//	SidecarRevoke     the device itself (sign-out), or whoever may admit it but that the member's consented device
//	                    revokes whatever self_admit says (§7.10)
//	AdmissionConfirm  any signer allowed to admit the device, never the device itself
//
// A sidecar_id is admitted once and its row stays a tombstone; tagged and ephemeral admissions carry a not_after and a
// member device's admission carrying one is refused, so leaves' rank depends on the log alone; revocations are
// idempotent. A Delegation's admissions are TEAM-M2-04's and a recovery key's TEAM-M2-05's, refused at the signer
// until each lands, as a compromise revocation is; lifting a park is TEAM-M2-04's too, so a confirmation of a parked
// device records its signer and leaves the park.
//
// admission_sha256 is the SidecarAdmit's signed bytes' hash, whether it rides its own entry or a proposal's statement
// (protos-bridge-statement-id-wrapper, team-records-admission-sha256-under-proposal).
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The capability bits a SidecarAdmit may carry; any other is refused, so a bit an older reader cannot read grants
// nothing it would miss.
const configKnownCapabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) |
	uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED)

// Registers the admission and removal rules.
func init() {
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_ADMIN_SET,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckAdminSet,
		apply:      configApplyAdminSet,
		targets:    configAdminSetTargets,
	})
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_MEMBER_ADMIT,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckMemberAdmit,
		apply:      configApplyMemberAdmit,
		targets:    configMemberAdmitTargets,
	})
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_MEMBER_REVOKE,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckMemberRevoke,
		apply:      configApplyMemberRevoke,
		targets:    configMemberRevokeTargets,
	})
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckSidecarAdmit,
		apply:      configApplySidecarAdmit,
		targets:    configSidecarAdmitTargets,
	})
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckSidecarRevoke,
		apply:      configApplySidecarRevoke,
		targets:    configSidecarRevokeTargets,
	})
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_ADMISSION_CONFIRM,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckAdmissionConfirm,
		apply:      configApplyAdmissionConfirm,
		targets:    configAdmissionConfirmTargets,
	})
}

// An AdminSet's role for each member it lists, refusing an id that is not 16 bytes or a member listed twice, since a
// member holds one role (§7.5).
func configAdminSetRoles(adminSet *protocol.AdminSet) (map[Id]bridge.MemberRole, error) {
	roles := map[Id]bridge.MemberRole{}
	lists := []struct {
		memberIds [][]byte
		role      bridge.MemberRole
	}{
		{memberIds: adminSet.GetOwners(), role: bridge.MemberRole_MEMBER_ROLE_OWNER},
		{memberIds: adminSet.GetAdmins(), role: bridge.MemberRole_MEMBER_ROLE_ADMIN},
		{memberIds: adminSet.GetNetworkAdmins(), role: bridge.MemberRole_MEMBER_ROLE_NETWORK_ADMIN},
		{memberIds: adminSet.GetItAdmins(), role: bridge.MemberRole_MEMBER_ROLE_IT_ADMIN},
	}
	for _, list := range lists {
		for _, memberBytes := range list.memberIds {
			memberId, err := IdFromBytes(memberBytes)
			if err != nil {
				return nil, fmt.Errorf("%w: an AdminSet member_id of %d bytes", ErrConfigRule, len(memberBytes))
			}
			if _, found := roles[memberId]; found {
				return nil, fmt.Errorf("%w: an AdminSet lists a member twice", ErrConfigRule)
			}
			roles[memberId] = list.role
		}
	}
	return roles, nil
}

// The members whose role an AdminSet changes at state: those it adds or moves, and those it drops.
func configAdminSetTargets(state *ConfigState, statement *configStatement) ConfigTargets {
	roles, err := configAdminSetRoles(statement.body.(*protocol.AdminSet))
	if err != nil {
		return ConfigTargets{}
	}
	targets := ConfigTargets{}
	for memberId, role := range roles {
		if state.members[memberId].GetRole() != role {
			targets.MemberIds = append(targets.MemberIds, memberId)
		}
	}
	for memberId, member := range state.members {
		if _, listed := roles[memberId]; !listed && configRoleInAdminSet(member.GetRole()) {
			targets.MemberIds = append(targets.MemberIds, memberId)
		}
	}
	slices.SortFunc(targets.MemberIds, Id.Cmp)
	return targets
}

// An AdminSet: every member it names a member, at least one Owner or Admin, a threshold k with 2 <= k <= n when n >=
// 3 (0 for the default 2) and 0 or 1 when n <= 2, and authority at the current AdminSet, its changed members never
// counting.
func configCheckAdminSet(state *ConfigState, statement *configStatement) error {
	adminSet := statement.body.(*protocol.AdminSet)
	roles, err := configAdminSetRoles(adminSet)
	if err != nil {
		return err
	}
	counted := 0
	for memberId, role := range roles {
		if state.members[memberId] == nil {
			return fmt.Errorf("%w: an AdminSet names one who is no member", ErrConfigRule)
		}
		if role == bridge.MemberRole_MEMBER_ROLE_OWNER || role == bridge.MemberRole_MEMBER_ROLE_ADMIN {
			counted += 1
		}
	}
	threshold := int(adminSet.GetThreshold())
	switch {
	case counted == 0:
		return fmt.Errorf("%w: an AdminSet with no Owner or Admin", ErrConfigRule)
	case counted <= 2 && 1 < threshold:
		return fmt.Errorf("%w: threshold %d with %d Owners and Admins, which forces 1", ErrConfigRule, threshold, counted)
	case 2 < counted && threshold != 0 && (threshold < 2 || counted < threshold):
		return fmt.Errorf("%w: threshold %d with %d Owners and Admins", ErrConfigRule, threshold, counted)
	}
	if !state.authorityAt(statement.signers, configAdminSetTargets(state, statement), statement.timeMs) {
		return fmt.Errorf("%w: an AdminSet without authority", ErrConfigAuthority)
	}
	return nil
}

// An AdminSet's effect: each member it names takes its role, each it drops falls to member, and its threshold holds.
func configApplyAdminSet(next *configStateBuilder, statement *configStatement) error {
	adminSet := statement.body.(*protocol.AdminSet)
	roles, err := configAdminSetRoles(adminSet)
	if err != nil {
		return err
	}
	for memberId, member := range next.state.members {
		if _, listed := roles[memberId]; !listed && configRoleInAdminSet(member.GetRole()) {
			next.memberForWrite(memberId).Role = bridge.MemberRole_MEMBER_ROLE_MEMBER
		}
	}
	for memberId, role := range roles {
		if member := next.memberForWrite(memberId); member != nil {
			member.Role = role
		}
	}
	next.state.threshold = adminSet.GetThreshold()
	return nil
}

// A MemberAdmit's member, which never counts toward it.
func configMemberAdmitTargets(state *ConfigState, statement *configStatement) ConfigTargets {
	memberId, err := IdFromBytes(statement.body.(*protocol.MemberAdmit).GetMemberId())
	if err != nil {
		return ConfigTargets{}
	}
	return ConfigTargets{MemberIds: []Id{memberId}}
}

// A MemberAdmit: a role outside the AdminSet's four (billing_admin, auditor or member), signed by an Owner's or
// Admin's device, or with authority when it moves a member out of the AdminSet.
func configCheckMemberAdmit(state *ConfigState, statement *configStatement) error {
	admit := statement.body.(*protocol.MemberAdmit)
	memberId, err := IdFromBytes(admit.GetMemberId())
	if err != nil {
		return fmt.Errorf("%w: a member_id of %d bytes", ErrConfigRule, len(admit.GetMemberId()))
	}
	switch admit.GetRole() {
	case bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN, bridge.MemberRole_MEMBER_ROLE_AUDITOR, bridge.MemberRole_MEMBER_ROLE_MEMBER:
	default:
		return fmt.Errorf("%w: a MemberAdmit of role %s, which only an AdminSet signs", ErrConfigRule, admit.GetRole())
	}
	if member := state.members[memberId]; member != nil && configRoleInAdminSet(member.GetRole()) {
		if !state.authorityAt(statement.signers, ConfigTargets{MemberIds: []Id{memberId}}, statement.timeMs) {
			return fmt.Errorf("%w: a MemberAdmit of an AdminSet member without authority", ErrConfigAuthority)
		}
		return nil
	}
	if _, ok := state.anyMemberDevice(statement.signers, statement.timeMs, func(signerId Id, signerMemberId Id, role bridge.MemberRole) bool {
		return configRoleAdmitsMembers(role) && signerMemberId != memberId
	}); !ok {
		return fmt.Errorf("%w: a MemberAdmit needs an Owner's or Admin's device", ErrConfigAuthority)
	}
	return nil
}

// A MemberAdmit's effect: the member, with its role.
func configApplyMemberAdmit(next *configStateBuilder, statement *configStatement) error {
	admit := statement.body.(*protocol.MemberAdmit)
	memberId, err := IdFromBytes(admit.GetMemberId())
	if err != nil {
		return err
	}
	if member := next.memberForWrite(memberId); member != nil {
		member.Role = admit.GetRole()
		return nil
	}
	next.putMember(memberId, &bridge.MemberRow{MemberId: memberId.Bytes(), Role: admit.GetRole()})
	return nil
}

// A MemberRevoke's member, which never counts toward it.
func configMemberRevokeTargets(state *ConfigState, statement *configStatement) ConfigTargets {
	memberId, err := IdFromBytes(statement.body.(*bridge.MemberRevoke).GetMemberId())
	if err != nil {
		return ConfigTargets{}
	}
	return ConfigTargets{MemberIds: []Id{memberId}}
}

// A MemberRevoke: a member of this state, by an Owner's or Admin's device, or with authority for an AdminSet member.
func configCheckMemberRevoke(state *ConfigState, statement *configStatement) error {
	revoke := statement.body.(*bridge.MemberRevoke)
	memberId, err := IdFromBytes(revoke.GetMemberId())
	if err != nil {
		return fmt.Errorf("%w: a member_id of %d bytes", ErrConfigRule, len(revoke.GetMemberId()))
	}
	member := state.members[memberId]
	if member == nil {
		return fmt.Errorf("%w: no such member", ErrConfigRule)
	}
	if configRoleInAdminSet(member.GetRole()) {
		if !state.authorityAt(statement.signers, ConfigTargets{MemberIds: []Id{memberId}}, statement.timeMs) {
			return fmt.Errorf("%w: a MemberRevoke of an AdminSet member without authority", ErrConfigAuthority)
		}
		return nil
	}
	if _, ok := state.anyMemberDevice(statement.signers, statement.timeMs, func(signerId Id, signerMemberId Id, role bridge.MemberRole) bool {
		return configRoleAdmitsMembers(role) && signerMemberId != memberId
	}); !ok {
		return fmt.Errorf("%w: a MemberRevoke needs an Owner's or Admin's device", ErrConfigAuthority)
	}
	return nil
}

// A MemberRevoke's effect: the member's row goes, and each of its untagged devices is revoked at this position, its
// tagged agents keeping their tags with autogroup:admin as their sponsor (§7.10's Sponsors).
func configApplyMemberRevoke(next *configStateBuilder, statement *configStatement) error {
	memberId, err := IdFromBytes(statement.body.(*bridge.MemberRevoke).GetMemberId())
	if err != nil {
		return err
	}
	if next.member(memberId) == nil {
		return fmt.Errorf("%w: no such member", ErrConfigRule)
	}
	next.deleteMember(memberId)
	for sidecarId, row := range next.state.sidecars {
		if rowMemberId, untagged := configRowMember(row); untagged && rowMemberId == memberId && row.GetRevokedAt() == 0 {
			next.sidecarForWrite(sidecarId).RevokedAt = statement.n
		}
	}
	return nil
}

// What an admission names, from a SidecarAdmit or a row: the device, its member or tags, and whether it is
// ephemeral.
type configAdmission struct {
	sidecarId Id
	memberId  Id
	tagged    bool
	tagIds    []Id
	ephemeral bool
}

// The targets of a statement acting on one admitted or admitting device.
func (self *configAdmission) targets() ConfigTargets {
	targets := ConfigTargets{SidecarId: self.sidecarId, HasSidecar: true}
	if !self.tagged {
		targets.SidecarMemberId, targets.HasSidecarMember = self.memberId, true
	}
	return targets
}

// A SidecarAdmit's admission, refusing malformed ids, an admission naming both a member and tags or neither, and a
// tag named twice.
func configSidecarAdmission(admit *protocol.SidecarAdmit) (*configAdmission, error) {
	sidecarId, err := IdFromBytes(admit.GetSidecarId())
	if err != nil {
		return nil, fmt.Errorf("%w: a sidecar_id of %d bytes", ErrConfigRule, len(admit.GetSidecarId()))
	}
	admission := &configAdmission{sidecarId: sidecarId, ephemeral: admit.GetEphemeral()}
	switch {
	case len(admit.GetMemberId()) != 0 && len(admit.GetTagIds()) != 0:
		return nil, fmt.Errorf("%w: an admission naming a member and tags", ErrConfigRule)
	case len(admit.GetMemberId()) != 0:
		if admission.memberId, err = IdFromBytes(admit.GetMemberId()); err != nil {
			return nil, fmt.Errorf("%w: a member_id of %d bytes", ErrConfigRule, len(admit.GetMemberId()))
		}
	case len(admit.GetTagIds()) != 0:
		admission.tagged = true
		for _, tagBytes := range admit.GetTagIds() {
			tagId, err := IdFromBytes(tagBytes)
			if err != nil || slices.Contains(admission.tagIds, tagId) {
				return nil, fmt.Errorf("%w: a malformed or repeated tag id", ErrConfigRule)
			}
			admission.tagIds = append(admission.tagIds, tagId)
		}
	default:
		return nil, fmt.Errorf("%w: an admission naming neither a member nor tags", ErrConfigRule)
	}
	return admission, nil
}

// A row's admission.
func configRowAdmission(sidecarId Id, row *bridge.SidecarRow) *configAdmission {
	admission := &configAdmission{sidecarId: sidecarId, ephemeral: row.GetEphemeral()}
	if memberId, untagged := configRowMember(row); untagged {
		admission.memberId = memberId
		return admission
	}
	admission.tagged = true
	for _, tagBytes := range row.GetTagIds() {
		if tagId, err := IdFromBytes(tagBytes); err == nil {
			admission.tagIds = append(admission.tagIds, tagId)
		}
	}
	return admission
}

// Whether the network's self_admit is on (owner decision 112): unset or on. An error when this reader could not open
// the config head that holds it, so a scoped self-admission fails closed there (question
// team-m2-02-self-admit-at-rows-only-readers).
func (self *ConfigState) selfAdmit() (bool, error) {
	settings, known := self.Settings()
	if !known {
		return false, fmt.Errorf("%w: self_admit", ErrConfigSettingsUnknown)
	}
	return settings.GetSelfAdmit() != protocol.SelfAdmitMode_SELF_ADMIT_MODE_OFF, nil
}

// Whether signers may admit the device admission names at state (§7.9's SidecarAdmit signers and scoped row), and
// the first signer the row keeps as the one that did. The device itself never signs its own admission.
func (self *ConfigState) admitSigners(signers []ConfigSigner, admission *configAdmission, timeMs int64) (ConfigSigner, error) {
	notTarget := func(signerId Id) bool {
		return signerId != admission.sidecarId
	}
	if admission.tagged {
		acl, err := self.Acl()
		if err != nil {
			return ConfigSigner{}, fmt.Errorf("%w: %w", ErrConfigRule, err)
		}
		signer, ok := self.anyMemberDevice(signers, timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
			if !notTarget(signerId) {
				return false
			}
			for _, tagId := range admission.tagIds {
				if !acl.CanApplyTag(signerId, tagId) {
					return false
				}
			}
			return true
		})
		if !ok {
			return ConfigSigner{}, fmt.Errorf("%w: a tagged admission needs a device of an owner of each of its tags", ErrConfigAuthority)
		}
		return signer, nil
	}

	member := self.members[admission.memberId]
	if member == nil {
		return ConfigSigner{}, fmt.Errorf("%w: an admission naming one who is no member", ErrConfigRule)
	}
	if configRoleInAdminSet(member.GetRole()) {
		targets := admission.targets()
		if !self.authorityAt(signers, targets, timeMs) {
			return ConfigSigner{}, fmt.Errorf("%w: an AdminSet member's device without authority", ErrConfigAuthority)
		}
		signer, _ := self.anyMemberDevice(signers, timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
			_, counted := self.countedMember(ConfigSigner{Kind: ConfigSignerSidecar, SidecarId: signerId}, targets, timeMs)
			return counted
		})
		return signer, nil
	}
	if signer, ok := self.anyMemberDevice(signers, timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
		return notTarget(signerId) && configRoleAdmits(role)
	}); ok {
		return signer, nil
	}
	acl, err := self.Acl()
	if err != nil {
		return ConfigSigner{}, fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	signer, ok := self.anyMemberDevice(signers, timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
		return notTarget(signerId) && memberId == admission.memberId && acl.ConsentedFor(signerId, memberId)
	})
	if !ok {
		return ConfigSigner{}, fmt.Errorf("%w: a device of a member outside the AdminSet needs an admin's device or the member's consented one", ErrConfigAuthority)
	}
	selfAdmit, err := self.selfAdmit()
	if err != nil {
		return ConfigSigner{}, err
	}
	if !selfAdmit {
		return ConfigSigner{}, fmt.Errorf("%w: self_admit is off", ErrConfigAuthority)
	}
	return signer, nil
}

// A SidecarAdmit's device and its member's AdminSet standing.
func configSidecarAdmitTargets(state *ConfigState, statement *configStatement) ConfigTargets {
	admission, err := configSidecarAdmission(statement.body.(*protocol.SidecarAdmit))
	if err != nil {
		return ConfigTargets{}
	}
	return admission.targets()
}

// A SidecarAdmit: this network; a sidecar_id never admitted, the Genesis's included; an Ed25519 identity key; a
// member of this state or tags; a not_after above the entry's time for a tagged or ephemeral admission and none for a
// member device; only known capability bits; and its signers' row.
func configCheckSidecarAdmit(state *ConfigState, statement *configStatement) error {
	admit := statement.body.(*protocol.SidecarAdmit)
	if !bytes.Equal(admit.GetNetworkId(), state.networkId.Bytes()) {
		return fmt.Errorf("%w: another network's admission", ErrConfigRule)
	}
	admission, err := configSidecarAdmission(admit)
	if err != nil {
		return err
	}
	if state.sidecars[admission.sidecarId] != nil || bytes.Equal(state.genesis.GetOwnerSidecarId(), admission.sidecarId.Bytes()) {
		return fmt.Errorf("%w: a sidecar_id admitted before", ErrConfigRule)
	}
	if !configIdentityKeyValid(admit.GetIdentityPublicKey(), admit.GetIdentityAlg()) || admit.GetIdentityAlg() != configIdentityAlgEd25519 {
		return fmt.Errorf("%w: the identity key", ErrConfigRule)
	}
	memberDevice := !admission.tagged && !admission.ephemeral
	switch {
	case memberDevice && admit.GetNotAfter() != 0:
		return fmt.Errorf("%w: a member device's admission carrying not_after", ErrConfigRule)
	case !memberDevice && admit.GetNotAfter() <= statement.timeMs:
		return fmt.Errorf("%w: a tagged or ephemeral admission needs a not_after to come", ErrConfigRule)
	case admit.GetCapabilities()&^configKnownCapabilities != 0:
		return fmt.Errorf("%w: unknown capability bits %#x", ErrConfigRule, admit.GetCapabilities()&^configKnownCapabilities)
	}
	statement.rowSigner, err = state.admitSigners(statement.signers, admission, statement.timeMs)
	return err
}

// A SidecarAdmit's effect: the device's row, admitted here, its signers kept for the cascade, a tagged one's
// admitting member its sponsor, and a member device live from here (§7.9's leaves row).
func configApplySidecarAdmit(next *configStateBuilder, statement *configStatement) error {
	admit := statement.body.(*protocol.SidecarAdmit)
	admission, err := configSidecarAdmission(admit)
	if err != nil {
		return err
	}
	if next.sidecar(admission.sidecarId) != nil {
		return fmt.Errorf("%w: a sidecar_id admitted before", ErrConfigRule)
	}
	row := &bridge.SidecarRow{
		SidecarId:         admission.sidecarId.Bytes(),
		AdmissionSha256:   bytes.Clone(statement.id[:]),
		AdmittedAt:        statement.n,
		Capabilities:      admit.GetCapabilities(),
		NotAfter:          admit.GetNotAfter(),
		IdentityPublicKey: bytes.Clone(admit.GetIdentityPublicKey()),
		IdentityAlg:       admit.GetIdentityAlg(),
		Ephemeral:         admission.ephemeral,
	}
	for _, signer := range statement.signers {
		rowsSigner := signer.RowsSigner()
		if !slices.ContainsFunc(row.AdmissionSigners, func(other []byte) bool { return bytes.Equal(other, rowsSigner) }) {
			row.AdmissionSigners = append(row.AdmissionSigners, rowsSigner)
		}
	}
	if admission.tagged {
		for _, tagId := range admission.tagIds {
			row.TagIds = append(row.TagIds, tagId.Bytes())
		}
		if statement.rowSigner.Kind == ConfigSignerSidecar {
			if memberId, untagged := configRowMember(next.sidecar(statement.rowSigner.SidecarId)); untagged {
				row.Sponsor = memberId.Bytes()
			}
		}
	} else {
		row.MemberId = admission.memberId.Bytes()
		if !admission.ephemeral {
			row.LiveSince = statement.n
		}
	}
	next.putSidecar(admission.sidecarId, row)
	return nil
}

// A SidecarRevoke's device and its member.
func configSidecarRevokeTargets(state *ConfigState, statement *configStatement) ConfigTargets {
	sidecarId, err := IdFromBytes(statement.body.(*bridge.SidecarRevoke).GetSidecarId())
	if err != nil {
		return ConfigTargets{}
	}
	row := state.sidecars[sidecarId]
	if row == nil {
		return ConfigTargets{SidecarId: sidecarId, HasSidecar: true}
	}
	return configRowAdmission(sidecarId, row).targets()
}

// A SidecarRevoke: a device this state admitted, for lost, removed or reaped (reaped only for an ephemeral one) with
// no since_n, by the device itself or by whoever may admit it, the member's consented device included whatever
// self_admit says (§7.10). A compromise revocation is TEAM-M2-04's cascade, refused until it lands. A device revoked
// already takes it again as nothing (§7.9's replay row: revocations are idempotent).
func configCheckSidecarRevoke(state *ConfigState, statement *configStatement) error {
	revoke := statement.body.(*bridge.SidecarRevoke)
	sidecarId, err := IdFromBytes(revoke.GetSidecarId())
	if err != nil {
		return fmt.Errorf("%w: a sidecar_id of %d bytes", ErrConfigRule, len(revoke.GetSidecarId()))
	}
	row := state.sidecars[sidecarId]
	if row == nil {
		return fmt.Errorf("%w: no such sidecar", ErrConfigRule)
	}
	switch revoke.GetReason() {
	case bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED:
	case bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REAPED:
		if !row.GetEphemeral() {
			return fmt.Errorf("%w: reaped names no ephemeral admission", ErrConfigRule)
		}
	case bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE:
		return fmt.Errorf("%w: a compromise revocation waits on TEAM-M2-04's cascade", ErrConfigRuleMissing)
	default:
		return fmt.Errorf("%w: reason %d", ErrConfigRule, revoke.GetReason())
	}
	if revoke.GetSinceN() != 0 {
		return fmt.Errorf("%w: since_n outside a compromise revocation", ErrConfigRule)
	}
	if len(statement.signers) == 1 && statement.signers[0].Kind == ConfigSignerSidecar && statement.signers[0].SidecarId == sidecarId {
		return nil
	}
	return state.revokeSigners(statement.signers, configRowAdmission(sidecarId, row), statement.timeMs)
}

// Whether signers may revoke the device admission names: authority for an AdminSet member's device; else an admin's
// device, the member's consented device whatever self_admit says, or for a tagged one a device of an owner of each
// of its tags.
func (self *ConfigState) revokeSigners(signers []ConfigSigner, admission *configAdmission, timeMs int64) error {
	member := self.members[admission.memberId]
	if !admission.tagged && member != nil && configRoleInAdminSet(member.GetRole()) {
		if !self.authorityAt(signers, admission.targets(), timeMs) {
			return fmt.Errorf("%w: revoking an AdminSet member's device without authority", ErrConfigAuthority)
		}
		return nil
	}
	notTarget := func(signerId Id) bool {
		return signerId != admission.sidecarId
	}
	if _, ok := self.anyMemberDevice(signers, timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
		return notTarget(signerId) && configRoleAdmits(role)
	}); ok {
		return nil
	}
	acl, err := self.Acl()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	if _, ok := self.anyMemberDevice(signers, timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
		if !notTarget(signerId) {
			return false
		}
		if admission.tagged {
			for _, tagId := range admission.tagIds {
				if !acl.CanApplyTag(signerId, tagId) {
					return false
				}
			}
			return 0 < len(admission.tagIds)
		}
		return member != nil && memberId == admission.memberId && acl.ConsentedFor(signerId, memberId)
	}); ok {
		return nil
	}
	return fmt.Errorf("%w: no signer may revoke this device", ErrConfigAuthority)
}

// A SidecarRevoke's effect: the device revoked here unless it was already; and for lost or removed, a Delegation
// that admitted it drops its key here, the Delegation admitting on (§10.5, D-TEAM-30).
func configApplySidecarRevoke(next *configStateBuilder, statement *configStatement) error {
	revoke := statement.body.(*bridge.SidecarRevoke)
	sidecarId, err := IdFromBytes(revoke.GetSidecarId())
	if err != nil {
		return err
	}
	row := next.sidecar(sidecarId)
	if row == nil {
		return fmt.Errorf("%w: no such sidecar", ErrConfigRule)
	}
	if row.GetRevokedAt() == 0 {
		next.sidecarForWrite(sidecarId).RevokedAt = statement.n
	}
	switch revoke.GetReason() {
	case bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED:
		if delegationId := row.GetDelegationId(); len(delegationId) != 0 {
			if delegation := next.delegationForWrite(delegationId); delegation != nil && delegation.GetKeyDroppedAt() == 0 {
				delegation.KeyDroppedAt = statement.n
			}
		}
	}
	return nil
}

// An AdmissionConfirm's device and its member.
func configAdmissionConfirmTargets(state *ConfigState, statement *configStatement) ConfigTargets {
	sidecarId, err := IdFromBytes(statement.body.(*protocol.AdmissionConfirm).GetSidecarId())
	if err != nil {
		return ConfigTargets{}
	}
	row := state.sidecars[sidecarId]
	if row == nil {
		return ConfigTargets{SidecarId: sidecarId, HasSidecar: true}
	}
	return configRowAdmission(sidecarId, row).targets()
}

// An AdmissionConfirm: a device this state admitted and has not revoked, by any signer allowed to admit it, never the
// device itself.
func configCheckAdmissionConfirm(state *ConfigState, statement *configStatement) error {
	confirm := statement.body.(*protocol.AdmissionConfirm)
	sidecarId, err := IdFromBytes(confirm.GetSidecarId())
	if err != nil {
		return fmt.Errorf("%w: a sidecar_id of %d bytes", ErrConfigRule, len(confirm.GetSidecarId()))
	}
	row := state.sidecars[sidecarId]
	if row == nil || row.GetRevokedAt() != 0 {
		return fmt.Errorf("%w: no admitted sidecar to confirm", ErrConfigRule)
	}
	statement.rowSigner, err = state.admitSigners(statement.signers, configRowAdmission(sidecarId, row), statement.timeMs)
	return err
}

// An AdmissionConfirm's effect: its signer and position, the newest AdmissionConfirm the row keeps. Lifting a park
// through it is TEAM-M2-04's.
func configApplyAdmissionConfirm(next *configStateBuilder, statement *configStatement) error {
	sidecarId, err := IdFromBytes(statement.body.(*protocol.AdmissionConfirm).GetSidecarId())
	if err != nil {
		return err
	}
	if next.sidecar(sidecarId) == nil {
		return fmt.Errorf("%w: no such sidecar", ErrConfigRule)
	}
	signer := statement.rowSigner
	if signer.Kind == 0 && 0 < len(statement.signers) {
		signer = statement.signers[0]
	}
	write := next.sidecarForWrite(sidecarId)
	write.ConfirmSigner = signer.RowsSigner()
	write.ConfirmedAt = statement.n
	return nil
}
