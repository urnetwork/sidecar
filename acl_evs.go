// §8.12's evs readers over one AclState: the rights a sidecar holds on a repo, which the token exchange maps
// to repo:<id>:deposit|r|rw|admin scopes (§7.8) and evs and gkm honor only while the subject still holds
// them (D-ACL-21), and the reader and writer sets that §10.5's key holders and §11.8's gate read.
//
// Kind defaults are the binary's, §8.5's table, and come ahead of every document; no document narrows one
// (plan-ACL-small-readings #2). A rule's * and evs:* (the wildcard repo target) reach only general and
// record repos. A rule naming a repo outright adds readers only to team_record and mailcfg, besides general
// and record; one naming a vault or mailbox adds only deposit, the form the compile gives a kind default's
// tag:mail mail indexers, whose atom only the config head knows (acl-m2-02-state-readings #3); and rules
// add nothing to config, directory or secret repos (D-ACL-13, D-ACL-24).
//
// §8.6's ceiling holds an ephemeral sidecar to the config's read, the directory's read and own-path writes,
// kind-default deposits, and the rules, RepoGrants and EvsShares that name it: its sidecar atom, a tag it
// carries, or autogroup:ephemeral. A parked sidecar gets nothing, and no ephemeral one writes a config head.
// Deposit implies no read, subscription, key or place in RepoReaders. admin implies write, and write read,
// within the ceiling (plan-ACL-small-readings #3). A read_only sidecar gets only r, plus the receipt deposit
// with it (D-TEAM-24), and a reader of an owner-bound repo that does not write gets the receipt deposit too
// (§16.8).
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"bytes"
	"math/bits"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The rights a sidecar holds on one repo, as bits.
type AclEvsRights uint32

const (
	// deposit only: no read, subscription, key or place among the readers
	AclEvsDeposit AclEvsRights = 1 << iota
	// r
	AclEvsRead
	// rw
	AclEvsWrite
	// admin: lifecycle, drops, and in the directory ERASE, CUT and CLOSURE (§8.10)
	AclEvsAdmin
)

// Whether every right of rights is held.
func (self AclEvsRights) Has(rights AclEvsRights) bool {
	return self&rights == rights
}

// Which service a token is for. Only the config tells them apart: member devices but read_only ones get
// gkm rw on its group, while evs rw stays with config writers (§7.9's commit row, §10.6).
type AclTokenAudience int

const (
	AclTokenAudienceEvs AclTokenAudience = iota + 1
	AclTokenAudienceGkm
)

// One EvsAccess answer: the rights, and what gave the strongest of them or why there are none.
type AclEvsAccess struct {
	Rights AclEvsRights
	AclDecision
}

// The owner-bound kinds, whose readers only the owner's consent adds (§8.5, owner decision 126).
func aclRepoKindOwnerBound(kind protocol.RepoKind) bool {
	switch kind {
	case protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_SECRET:
		return true
	}
	return false
}

// The kinds * and evs:* reach.
func aclRepoKindGeneral(kind protocol.RepoKind) bool {
	return kind == protocol.RepoKind_REPO_KIND_GENERAL || kind == protocol.RepoKind_REPO_KIND_RECORD
}

// The kinds whose access log adds admins and RepoGrants: every kind but the config, the directory, whose
// RepoAdmin adds and RepoGrants every reader refuses (§8.8), and the owner-bound ones, which take EvsShares.
func aclRepoKindTakesGrants(kind protocol.RepoKind) bool {
	switch kind {
	case protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_RECORD,
		protocol.RepoKind_REPO_KIND_TEAM_RECORD, protocol.RepoKind_REPO_KIND_MAILCFG:
		return true
	}
	return false
}

// Rights as they accumulate across sources, keeping the decision of the strongest.
type aclEvsAccumulator struct {
	rights   AclEvsRights
	decision AclDecision
}

// The rank of a right set: the strongest right it holds.
func aclEvsRank(rights AclEvsRights) int {
	return bits.Len32(uint32(rights))
}

// Adds rights from one source.
func (self *aclEvsAccumulator) add(rights AclEvsRights, decision AclDecision) {
	if rights == 0 {
		return
	}
	if aclEvsRank(self.rights) < aclEvsRank(rights) {
		self.decision = decision
		self.decision.Allowed = true
	}
	self.rights |= rights
}

// A rule's evs actions as rights.
func aclRuleEvsRights(rule *aclRule) AclEvsRights {
	rights := AclEvsRights(0)
	if rule.allows(protocol.AclAction_ACL_ACTION_DEPOSIT) {
		rights |= AclEvsDeposit
	}
	if rule.allows(protocol.AclAction_ACL_ACTION_READ) {
		rights |= AclEvsRead
	}
	if rule.allows(protocol.AclAction_ACL_ACTION_WRITE) {
		rights |= AclEvsWrite
	}
	if rule.allows(protocol.AclAction_ACL_ACTION_ADMIN) {
		rights |= AclEvsAdmin
	}
	return rights
}

// A RepoGrant role as rights.
func aclGrantRoleRights(role protocol.RepoGrantRole) AclEvsRights {
	switch role {
	case protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT:
		return AclEvsDeposit
	case protocol.RepoGrantRole_REPO_GRANT_ROLE_READER:
		return AclEvsRead
	case protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER:
		return AclEvsWrite
	}
	return 0
}

// The rights a sidecar holds on a repo at now, for a token of the audience. Only a sidecar holds evs
// scopes; any other subject gets none.
func (self *AclState) EvsAccess(subject AclSubject, repoId Id, audience AclTokenAudience, now time.Time) AclEvsAccess {
	nowMs := now.UnixMilli()
	resolved := self.resolve(&subject, nowMs)
	if resolved.deny != 0 {
		return AclEvsAccess{AclDecision: aclDeny(resolved.deny)}
	}
	if resolved.sidecar == nil {
		return AclEvsAccess{AclDecision: aclDeny(AclReasonNoGrant)}
	}
	return self.sidecarEvsAccess(resolved.sidecar, repoId, audience, nowMs)
}

// EvsAccess for an indexed sidecar the caller has resolved and found not hard denied.
func (self *AclState) sidecarEvsAccess(sidecar *aclSidecarState, repoId Id, audience AclTokenAudience, nowMs int64) AclEvsAccess {
	repo := self.repos[repoId]
	if repo == nil {
		return AclEvsAccess{AclDecision: aclDeny(AclReasonNoRepo)}
	}
	if repo.deleted {
		return AclEvsAccess{AclDecision: aclDeny(AclReasonRepoDeleted)}
	}
	accumulator := aclEvsAccumulator{}
	kindDefault := AclDecision{Reason: AclReasonKindDefault}
	memberDevice := sidecar.class == AclSubjectClassMemberDevice
	consented := self.sidecarConsented(sidecar)

	switch repo.kind {
	case protocol.RepoKind_REPO_KIND_CONFIG:
		// every admitted sidecar reads it, ephemeral ones too (owner decision 6); config writers write its
		// heads at evs, and member devices but read_only ones commit its group at gkm
		accumulator.add(AclEvsRead, kindDefault)
		switch audience {
		case AclTokenAudienceEvs:
			if sidecar.configWriter && memberDevice && !sidecar.readOnly {
				accumulator.add(AclEvsWrite, kindDefault)
			}
		case AclTokenAudienceGkm:
			if memberDevice && !sidecar.readOnly {
				accumulator.add(AclEvsWrite, kindDefault)
			}
		}
	case protocol.RepoKind_REPO_KIND_DIRECTORY:
		// every admitted sidecar of the team reads it and every one not read_only writes its own paths;
		// admin is its creator's and every config writer's, each while consented and not read_only
		// (D-ACL-24, §8.8)
		accumulator.add(AclEvsRead, kindDefault)
		if !sidecar.readOnly {
			accumulator.add(AclEvsWrite, kindDefault)
		}
		if (repo.admins[sidecar.id] || sidecar.configWriter) && consented && !sidecar.readOnly {
			accumulator.add(AclEvsAdmin, AclDecision{Reason: AclReasonRepoAdmin})
		}
	case protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_SECRET:
		self.addOwnerBoundRights(&accumulator, sidecar, repoId, repo, consented, nowMs)
	case protocol.RepoKind_REPO_KIND_TEAM_RECORD:
		// autogroup:admin and :auditor read; autogroup:member and tagged subjects deposit (§8.5). The read
		// is no row §8.6's ceiling counts, so an ephemeral sidecar only deposits.
		readers := aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN) | aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_AUDITOR)
		if sidecar.autogroups&readers != 0 && !sidecar.ephemeral {
			accumulator.add(AclEvsRead, kindDefault)
		}
		accumulator.add(AclEvsDeposit, kindDefault)
	case protocol.RepoKind_REPO_KIND_MAILCFG:
		// members write the records they sign, so member devices are its writers; a Team scope's is read
		// only by its member's consented devices (§15.8). tag:mail's read comes as a rule.
		if repo.ownerId == (Id{}) && memberDevice {
			accumulator.add(AclEvsWrite, kindDefault)
		} else if repo.ownerId != (Id{}) && sidecar.memberId == repo.ownerId && consented {
			accumulator.add(AclEvsWrite, kindDefault)
		}
	case protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_RECORD:
	default:
		// a kind this code does not know grants nothing
		return AclEvsAccess{AclDecision: aclDeny(AclReasonNoGrant)}
	}

	self.addRuleRights(&accumulator, sidecar, repoId, repo, nowMs)
	if aclRepoKindTakesGrants(repo.kind) {
		self.addAccessLogRights(&accumulator, sidecar, repo, nowMs)
	}
	self.addAuditRights(&accumulator, sidecar, repoId, repo, nowMs)

	rights := accumulator.rights
	if rights.Has(AclEvsAdmin) {
		rights |= AclEvsWrite
	}
	if rights.Has(AclEvsWrite) {
		rights |= AclEvsRead
	}
	if aclRepoKindOwnerBound(repo.kind) && rights.Has(AclEvsRead) && !rights.Has(AclEvsWrite) {
		rights |= AclEvsDeposit
	}
	if sidecar.readOnly {
		if rights.Has(AclEvsRead) {
			rights = AclEvsRead | AclEvsDeposit
		} else {
			rights = 0
		}
	}
	if rights == 0 {
		return AclEvsAccess{AclDecision: aclDeny(AclReasonNoGrant)}
	}
	accumulator.decision.Allowed = true
	return AclEvsAccess{Rights: rights, AclDecision: accumulator.decision}
}

// An owner-bound repo's rights: its owner's consented devices read and write, and those of them in its
// admins administer; its EvsShares' subjects read; in a vault or mailbox the owner's other untagged
// subjects and the tagged subjects it sponsors deposit (§8.5).
func (self *AclState) addOwnerBoundRights(accumulator *aclEvsAccumulator, sidecar *aclSidecarState, repoId Id, repo *aclRepoState, consented bool, nowMs int64) {
	kindDefault := AclDecision{Reason: AclReasonKindDefault}
	ownerDevice := consented && sidecar.memberId == repo.ownerId && repo.consents[sidecar.id]
	if ownerDevice {
		accumulator.add(AclEvsRead|AclEvsWrite, kindDefault)
		if repo.admins[sidecar.id] && !sidecar.readOnly {
			accumulator.add(AclEvsAdmin, AclDecision{Reason: AclReasonRepoAdmin})
		}
	}
	for i := range repo.shares {
		share := &repo.shares[i]
		if !share.valid || (share.expiresMs != 0 && share.expiresMs <= nowMs) {
			continue
		}
		if self.namesSidecar(sidecar, share.subject, sidecar.ephemeral) {
			accumulator.add(AclEvsRead, AclDecision{Reason: AclReasonEvsShare, At: share.row.GetAt()})
		}
	}
	if repo.kind == protocol.RepoKind_REPO_KIND_VAULT || repo.kind == protocol.RepoKind_REPO_KIND_MAILBOX {
		otherOwnerSubject := !sidecar.tagged && sidecar.memberId == repo.ownerId && !ownerDevice
		sponsored := sidecar.tagged && sidecar.hasOwner && sidecar.owner == repo.ownerId
		if otherOwnerSubject || sponsored {
			accumulator.add(AclEvsDeposit, kindDefault)
		}
	}
}

// The rights the rows' rules give the sidecar on the repo, by kind as the file's header says, within the
// ceiling.
func (self *AclState) addRuleRights(accumulator *aclEvsAccumulator, sidecar *aclSidecarState, repoId Id, repo *aclRepoState, nowMs int64) {
	explicit := self.repoRules[repoId]
	wildcard := aclRepoKindGeneral(repo.kind)
	allowed := AclEvsRights(0)
	switch {
	case aclRepoKindGeneral(repo.kind), repo.kind == protocol.RepoKind_REPO_KIND_TEAM_RECORD,
		repo.kind == protocol.RepoKind_REPO_KIND_MAILCFG:
		allowed = AclEvsDeposit | AclEvsRead | AclEvsWrite | AclEvsAdmin
	case repo.kind == protocol.RepoKind_REPO_KIND_VAULT, repo.kind == protocol.RepoKind_REPO_KIND_MAILBOX:
		allowed = AclEvsDeposit
	}
	if allowed == 0 || (explicit == nil && !wildcard) {
		return
	}
	ceiling := sidecar.ceilingRules
	for w := 0; w < self.ruleWordCount; w += 1 {
		var word uint64
		if explicit != nil {
			word = explicit[w]
		}
		if wildcard {
			word |= self.wildcardRepoRules[w]
		}
		word &= sidecar.srcRules[w]
		if ceiling != nil {
			word &= ceiling[w]
		}
		for word != 0 {
			bit := bits.TrailingZeros64(word)
			word &= word - 1
			rule := &self.rules[w*64+bit]
			if rule.activeAt(nowMs) {
				accumulator.add(aclRuleEvsRights(rule)&allowed, aclAllowRule(rule))
			}
		}
	}
}

// Whether an atom names the sidecar as §8.6's ceiling counts naming: autogroup:ephemeral, or an atom whose
// sidecar_ids list it, which is its sidecar:<id> atom or a tag atom, or a tag its admission carries.
func (self *AclState) namesSidecarDirectly(sidecar *aclSidecarState, atomIndex int32) bool {
	if atomIndex <= int32(aclAutogroupMax) {
		return atomIndex == int32(protocol.AclAutogroup_ACL_AUTOGROUP_EPHEMERAL)
	}
	for _, tagId := range sidecar.facts.TagIds {
		if index, found := self.atomIndexes[tagId]; found && index == atomIndex {
			return true
		}
	}
	atomRow := self.atomRow(atomIndex)
	if atomRow == nil {
		return false
	}
	for _, listed := range atomRow.GetSidecarIds() {
		if Id(listed) == sidecar.id {
			return true
		}
	}
	return false
}

// The rows' AclAtom at an index, or nil for an autogroup or an atom only a rule or admission names.
func (self *AclState) atomRow(atomIndex int32) *protocol.AclAtom {
	rowIndex := int(atomIndex) - int(aclAutogroupMax) - 1
	if rowIndex < 0 || len(self.rows.GetAtoms()) <= rowIndex {
		return nil
	}
	return self.rows.GetAtoms()[rowIndex]
}

// Whether a RepoGrant's or EvsShare's subject names the sidecar: its sidecar_id, its member for an
// untagged one, or an atom it holds. Within the ceiling only its sidecar_id, a tag it carries or
// autogroup:ephemeral counts (acl-m2-02-state-readings #4).
func (self *AclState) namesSidecar(sidecar *aclSidecarState, subject Id, withinCeiling bool) bool {
	if subject == sidecar.id {
		return true
	}
	if !withinCeiling && !sidecar.tagged && subject == sidecar.memberId {
		return true
	}
	atomIndex, found := self.atomIndexes[subject]
	if !found {
		return false
	}
	if _, holds := slices.BinarySearch(sidecar.atoms, atomIndex); !holds {
		return false
	}
	return !withinCeiling || self.namesSidecarDirectly(sidecar, atomIndex)
}

// The rights the repo's folded access log gives: its admins, and its RepoGrants in force that no config
// writer's standing RepoRevoke overrides (§8.8).
func (self *AclState) addAccessLogRights(accumulator *aclEvsAccumulator, sidecar *aclSidecarState, repo *aclRepoState, nowMs int64) {
	if repo.admins[sidecar.id] {
		var at uint64
		for _, admin := range repo.row.GetAdmins() {
			if Id(admin.GetSidecarId()) == sidecar.id {
				at = admin.GetAt()
			}
		}
		accumulator.add(AclEvsAdmin, AclDecision{Reason: AclReasonRepoAdmin, At: at})
	}
	if repo.revoked[sidecar.id] {
		return
	}
	for i := range repo.grants {
		grant := &repo.grants[i]
		if (grant.expiresMs != 0 && grant.expiresMs <= nowMs) || repo.revoked[grant.subject] {
			continue
		}
		if self.namesSidecar(sidecar, grant.subject, sidecar.ephemeral) {
			accumulator.add(aclGrantRoleRights(grant.row.GetRole()), AclDecision{Reason: AclReasonRepoGrant, At: grant.row.GetAt()})
		}
	}
}

// The audit block's read and receipt deposit, while its AuditOptIn stands at nowMs, for a sidecar holding a
// reader atom, on the kinds and repos the block names (owner decision 63). Rows hold a block only with a verified
// opt-in's record (acl_audit.go), and past its not_after the reader drops as an expiry (§7.9).
func (self *AclState) addAuditRights(accumulator *aclEvsAccumulator, sidecar *aclSidecarState, repoId Id, repo *aclRepoState, nowMs int64) {
	audit := self.rows.GetAudit()
	if audit == nil || !self.auditStands(nowMs) {
		return
	}
	named := slices.Contains(audit.GetRepoKinds(), uint32(repo.kind)) ||
		slices.ContainsFunc(audit.GetRepoIds(), func(idBytes []byte) bool { return bytes.Equal(idBytes, repoId.Bytes()) })
	if !named {
		return
	}
	for _, readerBytes := range audit.GetReaderAtoms() {
		reader, err := IdFromBytes(readerBytes)
		if err != nil {
			continue
		}
		atomIndex, found := self.atomIndexes[reader]
		if !found {
			continue
		}
		if _, holds := slices.BinarySearch(sidecar.atoms, atomIndex); !holds {
			continue
		}
		if sidecar.ephemeral && !self.namesSidecarDirectly(sidecar, atomIndex) {
			continue
		}
		accumulator.add(AclEvsRead|AclEvsDeposit, AclDecision{Reason: AclReasonAudit})
		return
	}
}

// The sidecars that hold a right on the repo at now, at evs, sorted.
func (self *AclState) repoHolders(repoId Id, right AclEvsRights, now time.Time) []Id {
	nowMs := now.UnixMilli()
	holders := []Id{}
	for i := range self.sidecars {
		sidecar := &self.sidecars[i]
		if sidecar.hardDeny(nowMs) != 0 {
			continue
		}
		if self.sidecarEvsAccess(sidecar, repoId, AclTokenAudienceEvs, nowMs).Rights.Has(right) {
			holders = append(holders, sidecar.id)
		}
	}
	return holders
}

// RepoReaders(repo) (§8.12): the sidecars §8.6 gives read on evs:<repo> at now, sorted. Depositors are
// not among them.
func (self *AclState) RepoReaders(repoId Id, now time.Time) []Id {
	return self.repoHolders(repoId, AclEvsRead, now)
}

// The sidecars whose heads readers accept on the repo at now (owner decision 7), sorted.
func (self *AclState) RepoWriters(repoId Id, now time.Time) []Id {
	return self.repoHolders(repoId, AclEvsWrite, now)
}

// The repos a read, write or admin grant naming one of the atoms reads at now, sorted: rules whose src
// names an atom, and RepoGrants of reader or writer whose subject is one. This is the part of §10.5's
// reach(d) the rows decide for a Delegation's tags; the config and a team's directory are §10.5's own.
func (self *AclState) ReposGrantedToAtoms(atoms []Id, now time.Time) []Id {
	nowMs := now.UnixMilli()
	atomIndexes := []int32{}
	for _, atom := range atoms {
		if index, found := self.atomIndexes[atom]; found {
			atomIndexes = append(atomIndexes, index)
		}
	}
	readable := func(repoId Id) bool {
		repo := self.repos[repoId]
		return repo != nil && !repo.deleted && aclRepoKindTakesGrants(repo.kind)
	}
	granted := map[Id]bool{}
	readActions := uint32(1)<<uint32(protocol.AclAction_ACL_ACTION_READ) | uint32(1)<<uint32(protocol.AclAction_ACL_ACTION_WRITE) |
		uint32(1)<<uint32(protocol.AclAction_ACL_ACTION_ADMIN)
	for i := range self.rules {
		rule := &self.rules[i]
		if rule.actions&readActions == 0 || !rule.activeAt(nowMs) {
			continue
		}
		if !slices.ContainsFunc(atomIndexes, rule.hasSrcAtom) {
			continue
		}
		for _, repoId := range rule.repoTargets {
			if readable(repoId) {
				granted[repoId] = true
			}
		}
		if rule.repoWildcard {
			for repoId, repo := range self.repos {
				if !repo.deleted && aclRepoKindGeneral(repo.kind) {
					granted[repoId] = true
				}
			}
		}
	}
	for repoId, repo := range self.repos {
		if !readable(repoId) {
			continue
		}
		for i := range repo.grants {
			grant := &repo.grants[i]
			if aclGrantRoleRights(grant.row.GetRole()) < AclEvsRead || repo.revoked[grant.subject] ||
				(grant.expiresMs != 0 && grant.expiresMs <= nowMs) {
				continue
			}
			if slices.Contains(atoms, grant.subject) {
				granted[repoId] = true
			}
		}
	}
	repoIds := make([]Id, 0, len(granted))
	for repoId := range granted {
		repoIds = append(repoIds, repoId)
	}
	slices.SortFunc(repoIds, Id.Cmp)
	return repoIds
}
