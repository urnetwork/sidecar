// §8.8's access log of one repo_id (owner decision 8): RepoCreate, RepoAdmin, RepoGrant, RepoRevoke, RepoDelete,
// RepoRestore, RepoVersioning and RepoPrefixRules, each checked at its position here and folded by acl_access_log.go.
//
//	RepoCreate      general or record: a member device that is not read_only, or a tagged or ephemeral sidecar
//	                under a rule giving it admin on evs:* or that repo, within §8.6's ceiling; team_record and
//	                mailcfg: a config writer; vault, mailbox and secret: a consented device of the owner, its
//	                member; directory: a config writer, once per network, and at api alone the team tier
//	                (AclStatementNeedsTeamTier); config: none, since §7.9's bootstrap creates it
//	                (plan-ACL-small-readings #4)
//	RepoAdmin       a repo admin or a config writer; in an owner-bound repo an add only by a consented device of its
//	                owner, of a consented device of its owner (§15.7); never an add in the directory
//	RepoGrant       a repo admin or a config writer, in general, record, team_record and mailcfg repos only: never
//	                owner-bound (EvsShare there), the directory or the config
//	RepoRevoke      a repo admin or a config writer, never in the directory or the config; in an owner-bound repo
//	                never of its owner or one of its owner's consented devices (plan-ACL-owner-bound-standing-revoke)
//	RepoDelete      a repo admin; a RepoDelete{now} may follow one without now, nothing a RepoDelete{now}
//	RepoRestore     a repo admin, of the newest RepoDelete without now, within 7 days of its entry
//	RepoVersioning  a repo admin or a config writer, in an owner-bound repo a consented device of its owner; never
//	                the directory or the config; format 1 folds the lock and skips its rules (D-PHASE-9)
//	RepoPrefixRules a repo admin or a config writer, by RepoVersioning's test, only in a general repo that is not
//	                deleted; sealed_rules 48 B and a positive multiple of 256 B, at most SealedMaxByteCount, read by
//	                its length alone; fewer than SetMaxCount sets in the repo's rows (DESIGN-DETAILS 16.2.2). Code
//	                from M2 checks it and folds its row, and nothing enforces a rule until M6 (D-PHASE-9; QD-212)
//
// A repo admin counts while it stands, and in an owner-bound repo while it is a consented device of the owner, in
// the directory while it is consented, either way not read_only. The config takes no access-log statement: no rows
// give it an admin and policy never widens its writers (D-ACL-13; acl-m2-02-state-readings #10). Statements on a
// deleted repo are refused but for RepoRevoke, RepoAdmin's remove, RepoDelete{now} and RepoRestore.
//
// RepoRestore's window runs from its RepoDelete's entry time, which the deletion row carries (QD-743), so every reader
// judges it from rows alone on any day of the window, whether or not its log still keeps that entry. A row with no
// time, which no fold writes, is refused as a restore that cannot be dated.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"fmt"
	"math/bits"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §8.8's access-log limits, which every reader and api hold alike (QD-702): the protocol's values, so changing one is a
// protocol change no deployment makes on one side alone. The statement rules read DefaultAclAccessLogSettings();
// threading each side's own instance through them is the review phase's settings sweep (QD-706).
type AclAccessLogSettings struct {
	// How long after its RepoDelete's entry a RepoRestore is taken: 7 days (§8.8, owner decision 82). §11.12's shred
	// starts no earlier than this past the entry, so a restore every reader takes always finds the repo unshredded.
	// Positive.
	RepoRestoreWindow time.Duration
}

// §8.8's values. A fresh value each call.
func DefaultAclAccessLogSettings() *AclAccessLogSettings {
	return &AclAccessLogSettings{
		RepoRestoreWindow: 7 * 24 * time.Hour,
	}
}

// Whether a RepoRestore sequenced at restoreTimeMs lies within the window of a RepoDelete whose entry was sequenced at
// deletedTimeMs, both ms since the epoch: at most RepoRestoreWindow after it, the window's last ms included.
func (self *AclAccessLogSettings) RepoRestoreWithinWindow(deletedTimeMs int64, restoreTimeMs int64) bool {
	return restoreTimeMs-deletedTimeMs <= self.RepoRestoreWindow.Milliseconds()
}

// A time from ms since the epoch.
func aclTime(timeMs int64) time.Time {
	return time.UnixMilli(timeMs)
}

// The repo a statement names, refusing an id of the wrong size, the wildcard's zero form, a repo the rows do not
// hold, and the config, which takes no access-log statement.
func (self *AclState) statementRepo(repoIdBytes []byte) (*aclRepoState, error) {
	repoId, err := IdFromBytes(repoIdBytes)
	if err != nil || repoId == (Id{}) {
		return nil, fmt.Errorf("%w: a repo_id of %d bytes", ErrConfigRule, len(repoIdBytes))
	}
	repo := self.repos[repoId]
	if repo == nil {
		return nil, fmt.Errorf("%w: a repo the rows do not hold", ErrConfigRule)
	}
	if repo.kind == protocol.RepoKind_REPO_KIND_CONFIG {
		return nil, fmt.Errorf("%w: the config takes no access-log statement", ErrConfigRule)
	}
	return repo, nil
}

// Whether the signer counts as the repo's admin at position: in its admins and standing, and in the directory, where
// every config writer is one too, consented; in an owner-bound repo a consented device of the owner (§8.8).
func (self *AclState) repoAdminSigner(repo *aclRepoState, signer *aclSidecarState, position uint64) bool {
	switch {
	case repo.kind == protocol.RepoKind_REPO_KIND_DIRECTORY:
		return (repo.admins[signer.id] || signer.configWriter) && self.consentedSignerAt(signer, signer.memberId, position)
	case aclRepoKindOwnerBound(repo.kind):
		return repo.admins[signer.id] && self.consentedSignerAt(signer, repo.ownerId, position)
	case repo.kind == protocol.RepoKind_REPO_KIND_CONFIG:
		return false
	}
	return repo.admins[signer.id] && !signer.readOnly
}

// Whether a rule in force gives the sidecar admin on the repo or on evs:*, within §8.6's ceiling: what lets a tagged
// or ephemeral sidecar create a general or record repo (plan-ACL-small-readings #4).
func (self *AclState) ruleGrantsRepoAdmin(sidecar *aclSidecarState, repoId Id, nowMs int64) bool {
	explicit := self.repoRules[repoId]
	for w := 0; w < self.ruleWordCount; w += 1 {
		word := self.wildcardRepoRules[w]
		if explicit != nil {
			word |= explicit[w]
		}
		word &= sidecar.srcRules[w]
		if sidecar.ceilingRules != nil {
			word &= sidecar.ceilingRules[w]
		}
		for word != 0 {
			bit := bits.TrailingZeros64(word)
			word &= word - 1
			rule := &self.rules[w*64+bit]
			if rule.activeAt(nowMs) && rule.allows(protocol.AclAction_ACL_ACTION_ADMIN) {
				return true
			}
		}
	}
	return false
}

// The sidecars consented for a member now, in id order: an owner-bound repo's consented_sidecar_ids at its creation.
func (self *AclState) consentedSidecarIds(memberId Id) []Id {
	sidecarIds := []Id{}
	for i := range self.sidecars {
		sidecar := &self.sidecars[i]
		if sidecar.memberId == memberId && self.sidecarConsented(sidecar) {
			sidecarIds = append(sidecarIds, sidecar.id)
		}
	}
	return sidecarIds
}

// Whether api alone must refuse a statement outside the team tier (§8.8; §20.5's NetworkTierOf): a RepoCreate of the
// directory, one per team network, which readers, who know no tier, do not judge. signed is the Signed as received;
// anything else, a malformed one included, is false, and the log's own check judges it.
func AclStatementNeedsTeamTier(signed []byte) bool {
	message := &bridge.Signed{}
	if err := proto.Unmarshal(signed, message); err != nil || bridge.SignedType(message.GetType()) != bridge.SignedType_SIGNED_REPO_CREATE {
		return false
	}
	body, err := ParseConfigStatement(bridge.SignedPurposeAcl, bridge.SignedType_SIGNED_REPO_CREATE, message.GetBody())
	if err != nil {
		return false
	}
	return body.(*protocol.RepoCreate).GetKind() == protocol.RepoKind_REPO_KIND_DIRECTORY
}

// RepoCreate{repo_id, kind}: who the kind lets create it, which becomes its admin.
func (self *AclState) checkRepoCreate(statement *AclStatement, create *protocol.RepoCreate) (*AclStatementVerdict, error) {
	signer, err := self.statementSigner(statement)
	if err != nil {
		return nil, err
	}
	repoId, err := IdFromBytes(create.GetRepoId())
	if err != nil || repoId == (Id{}) {
		return nil, fmt.Errorf("%w: a repo_id of %d bytes", ErrConfigRule, len(create.GetRepoId()))
	}
	if self.repos[repoId] != nil {
		return nil, fmt.Errorf("%w: a second RepoCreate of one repo", ErrConfigRule)
	}
	verdict := &AclStatementVerdict{Signer: signer.id}
	switch kind := create.GetKind(); kind {
	case protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_RECORD:
		if signer.class != AclSubjectClassMemberDevice && !self.ruleGrantsRepoAdmin(signer, repoId, statement.TimeMs) {
			return nil, fmt.Errorf("%w: a tagged or ephemeral sidecar creates a repo only under an admin rule", ErrConfigAuthority)
		}
	case protocol.RepoKind_REPO_KIND_TEAM_RECORD, protocol.RepoKind_REPO_KIND_MAILCFG:
		if !signer.configWriter {
			return nil, fmt.Errorf("%w: only a config writer creates a %s repo", ErrConfigAuthority, kind)
		}
	case protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_SECRET:
		if signer.class != AclSubjectClassMemberDevice || !self.consentedSignerAt(signer, signer.memberId, statement.N) {
			return nil, fmt.Errorf("%w: only a consented device of its owner creates a %s repo", ErrConfigAuthority, kind)
		}
		verdict.MemberId = signer.memberId
		verdict.ConsentedSidecarIds = self.consentedSidecarIds(signer.memberId)
	case protocol.RepoKind_REPO_KIND_DIRECTORY:
		if !signer.configWriter {
			return nil, fmt.Errorf("%w: only a config writer creates the directory", ErrConfigAuthority)
		}
		for _, repo := range self.repos {
			if repo.kind == protocol.RepoKind_REPO_KIND_DIRECTORY {
				return nil, fmt.Errorf("%w: a second directory in one network", ErrConfigRule)
			}
		}
	case protocol.RepoKind_REPO_KIND_CONFIG:
		return nil, fmt.Errorf("%w: the config repo comes from the network's bootstrap, never a RepoCreate", ErrConfigRule)
	default:
		return nil, fmt.Errorf("%w: a RepoCreate of kind %d", ErrConfigRule, kind)
	}
	return verdict, nil
}

// RepoAdmin{repo_id, sidecar_id, add | remove}.
func (self *AclState) checkRepoAdmin(statement *AclStatement, admin *protocol.RepoAdmin) (*AclStatementVerdict, error) {
	signer, err := self.statementSigner(statement)
	if err != nil {
		return nil, err
	}
	repo, err := self.statementRepo(admin.GetRepoId())
	if err != nil {
		return nil, err
	}
	sidecarId, err := IdFromBytes(admin.GetSidecarId())
	if err != nil {
		return nil, fmt.Errorf("%w: a sidecar_id of %d bytes", ErrConfigRule, len(admin.GetSidecarId()))
	}
	switch admin.GetChange() {
	case protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD:
		if repo.kind == protocol.RepoKind_REPO_KIND_DIRECTORY {
			return nil, fmt.Errorf("%w: the directory takes no RepoAdmin add", ErrConfigRule)
		}
		if repo.deleted {
			return nil, fmt.Errorf("%w: a RepoAdmin add on a deleted repo", ErrConfigRule)
		}
		added := self.sidecarState(sidecarId)
		if added == nil || added.hardDeny(statement.TimeMs) != 0 {
			return nil, fmt.Errorf("%w: a RepoAdmin add of a sidecar that does not stand", ErrConfigRule)
		}
		if aclRepoKindOwnerBound(repo.kind) {
			if !self.consentedSignerAt(signer, repo.ownerId, statement.N) {
				return nil, fmt.Errorf("%w: only a consented device of its owner adds an admin to an owner-bound repo", ErrConfigAuthority)
			}
			if added.memberId != repo.ownerId || !self.sidecarConsented(added) || added.readOnly {
				return nil, fmt.Errorf("%w: an owner-bound repo's admin is a consented device of its owner", ErrConfigRule)
			}
			return &AclStatementVerdict{Signer: signer.id}, nil
		}
	case protocol.RepoAdminChange_REPO_ADMIN_CHANGE_REMOVE:
	default:
		return nil, fmt.Errorf("%w: a RepoAdmin change %d", ErrConfigRule, admin.GetChange())
	}
	if !self.repoAdminSigner(repo, signer, statement.N) && !signer.configWriter {
		return nil, fmt.Errorf("%w: neither a repo admin nor a config writer", ErrConfigAuthority)
	}
	return &AclStatementVerdict{Signer: signer.id, ConfigWriter: signer.configWriter}, nil
}

// RepoGrant{repo_id, subject, role, expires}.
func (self *AclState) checkRepoGrant(statement *AclStatement, grant *protocol.RepoGrant) (*AclStatementVerdict, error) {
	signer, err := self.statementSigner(statement)
	if err != nil {
		return nil, err
	}
	repo, err := self.statementRepo(grant.GetRepoId())
	if err != nil {
		return nil, err
	}
	if !aclRepoKindTakesGrants(repo.kind) {
		return nil, fmt.Errorf("%w: a %s repo takes no RepoGrant", ErrConfigRule, repo.kind)
	}
	if repo.deleted {
		return nil, fmt.Errorf("%w: a RepoGrant on a deleted repo", ErrConfigRule)
	}
	if _, err := aclStatementSubject(grant.GetSubject()); err != nil {
		return nil, err
	}
	switch grant.GetRole() {
	case protocol.RepoGrantRole_REPO_GRANT_ROLE_DEPOSIT, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER:
	default:
		return nil, fmt.Errorf("%w: a RepoGrant role %d", ErrConfigRule, grant.GetRole())
	}
	if expires := grant.GetExpires(); expires != 0 && expires <= statement.TimeMs {
		return nil, fmt.Errorf("%w: a RepoGrant expired when it landed", ErrConfigRule)
	}
	if !self.repoAdminSigner(repo, signer, statement.N) && !signer.configWriter {
		return nil, fmt.Errorf("%w: neither a repo admin nor a config writer", ErrConfigAuthority)
	}
	return &AclStatementVerdict{Signer: signer.id, ConfigWriter: signer.configWriter}, nil
}

// RepoRevoke{repo_id, subject}.
func (self *AclState) checkRepoRevoke(statement *AclStatement, revoke *protocol.RepoRevoke) (*AclStatementVerdict, error) {
	signer, err := self.statementSigner(statement)
	if err != nil {
		return nil, err
	}
	repo, err := self.statementRepo(revoke.GetRepoId())
	if err != nil {
		return nil, err
	}
	if repo.kind == protocol.RepoKind_REPO_KIND_DIRECTORY {
		return nil, fmt.Errorf("%w: the directory takes no RepoRevoke", ErrConfigRule)
	}
	subjectId, err := aclStatementSubject(revoke.GetSubject())
	if err != nil {
		return nil, err
	}
	if aclRepoKindOwnerBound(repo.kind) {
		// SidecarRevoke and Suspend remove an owner's device; a RepoRevoke never locks the owner out
		// (plan-ACL-owner-bound-standing-revoke)
		if subjectId == repo.ownerId {
			return nil, fmt.Errorf("%w: a RepoRevoke of an owner-bound repo's owner", ErrConfigRule)
		}
		if subject := self.sidecarState(subjectId); subject != nil && subject.memberId == repo.ownerId && self.sidecarConsented(subject) {
			return nil, fmt.Errorf("%w: a RepoRevoke of a consented device of an owner-bound repo's owner", ErrConfigRule)
		}
	}
	if !self.repoAdminSigner(repo, signer, statement.N) && !signer.configWriter {
		return nil, fmt.Errorf("%w: neither a repo admin nor a config writer", ErrConfigAuthority)
	}
	return &AclStatementVerdict{Signer: signer.id, ConfigWriter: signer.configWriter}, nil
}

// RepoDelete{repo_id, deletion_id, now}: a repo admin, before §11.12's DELETE.
func (self *AclState) checkRepoDelete(statement *AclStatement, deletion *protocol.RepoDelete) (*AclStatementVerdict, error) {
	signer, err := self.statementSigner(statement)
	if err != nil {
		return nil, err
	}
	repo, err := self.statementRepo(deletion.GetRepoId())
	if err != nil {
		return nil, err
	}
	if deletionId, err := IdFromBytes(deletion.GetDeletionId()); err != nil || deletionId == (Id{}) {
		return nil, fmt.Errorf("%w: a deletion_id of %d bytes", ErrConfigRule, len(deletion.GetDeletionId()))
	}
	if newest := repo.row.GetDeletion(); newest != nil && newest.GetDeletedAt() != 0 && newest.GetRestoredAt() == 0 {
		if newest.GetNow() || !deletion.GetNow() {
			return nil, fmt.Errorf("%w: a RepoDelete of a deleted repo", ErrConfigRule)
		}
	}
	if !self.repoAdminSigner(repo, signer, statement.N) {
		return nil, fmt.Errorf("%w: only a repo admin deletes a repo", ErrConfigAuthority)
	}
	return &AclStatementVerdict{Signer: signer.id}, nil
}

// RepoRestore{repo_id, deletion_id}: a repo admin, of the newest RepoDelete without now, within 7 days of its entry.
func (self *AclState) checkRepoRestore(statement *AclStatement, restore *protocol.RepoRestore) (*AclStatementVerdict, error) {
	signer, err := self.statementSigner(statement)
	if err != nil {
		return nil, err
	}
	repo, err := self.statementRepo(restore.GetRepoId())
	if err != nil {
		return nil, err
	}
	deletion := repo.row.GetDeletion()
	switch {
	case deletion == nil || deletion.GetDeletedAt() == 0:
		return nil, fmt.Errorf("%w: a RepoRestore of a repo with no RepoDelete", ErrConfigRule)
	case string(deletion.GetDeletionId()) != string(restore.GetDeletionId()):
		return nil, fmt.Errorf("%w: a RepoRestore of another deletion_id", ErrConfigRule)
	case deletion.GetNow():
		return nil, fmt.Errorf("%w: a RepoDelete with now is never restored", ErrConfigRule)
	case deletion.GetRestoredAt() != 0:
		return nil, fmt.Errorf("%w: a deletion already restored", ErrConfigRule)
	}
	// the row's own time, never the log's copy of the entry, so the verdict is the same at every reader on every day
	deletedTimeMs := deletion.GetDeletedTimeMs()
	if deletedTimeMs == 0 {
		return nil, fmt.Errorf("%w: a deletion row with no entry time", ErrConfigRuleMissing)
	}
	if !DefaultAclAccessLogSettings().RepoRestoreWithinWindow(deletedTimeMs, statement.TimeMs) {
		return nil, fmt.Errorf("%w: a RepoRestore more than 7 days after its RepoDelete", ErrConfigRule)
	}
	if !self.repoAdminSigner(repo, signer, statement.N) {
		return nil, fmt.Errorf("%w: only a repo admin restores a repo", ErrConfigAuthority)
	}
	return &AclStatementVerdict{Signer: signer.id}, nil
}

// RepoVersioning{repo_id, lock, rules}: format 1 verifies the signer, folds the lock and skips the sealed rules,
// enforcing nothing (D-PHASE-9; FS-95).
func (self *AclState) checkRepoVersioning(statement *AclStatement, versioning *protocol.RepoVersioning) (*AclStatementVerdict, error) {
	signer, err := self.statementSigner(statement)
	if err != nil {
		return nil, err
	}
	repo, err := self.statementRepo(versioning.GetRepoId())
	if err != nil {
		return nil, err
	}
	if repo.kind == protocol.RepoKind_REPO_KIND_DIRECTORY {
		return nil, fmt.Errorf("%w: the directory takes no RepoVersioning", ErrConfigRule)
	}
	if repo.deleted {
		return nil, fmt.Errorf("%w: a RepoVersioning on a deleted repo", ErrConfigRule)
	}
	switch versioning.GetLock() {
	case protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED, protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_UNLOCKED:
	default:
		return nil, fmt.Errorf("%w: a lock of %d", ErrConfigRule, versioning.GetLock())
	}
	if aclRepoKindOwnerBound(repo.kind) {
		if !self.consentedSignerAt(signer, repo.ownerId, statement.N) {
			return nil, fmt.Errorf("%w: only a consented device of its owner sets an owner-bound repo's versioning", ErrConfigAuthority)
		}
	} else if !self.repoAdminSigner(repo, signer, statement.N) && !signer.configWriter {
		return nil, fmt.Errorf("%w: neither a repo admin nor a config writer", ErrConfigAuthority)
	}
	return &AclStatementVerdict{Signer: signer.id}, nil
}

// RepoPrefixRules{repo_id, sealed_rules}: DESIGN-DETAILS 16.2.2's id-level rule, which api, the gates and every device
// judge alike with no key. The body is never opened: its length is read, and what it holds is the reader's from M6
// (ACL-M6-04), a set no reader can open leaving the one below it in force.
func (self *AclState) checkRepoPrefixRules(statement *AclStatement, prefixRules *protocol.RepoPrefixRules) (*AclStatementVerdict, error) {
	signer, err := self.statementSigner(statement)
	if err != nil {
		return nil, err
	}
	repo, err := self.statementRepo(prefixRules.GetRepoId())
	if err != nil {
		return nil, err
	}
	// every other kind is written by fixed sets or only by its owner's devices (16.9, small reading 1; QD-795)
	if repo.kind != protocol.RepoKind_REPO_KIND_GENERAL {
		return nil, fmt.Errorf("%w: a %s repo takes no RepoPrefixRules", ErrConfigRule, repo.kind)
	}
	if repo.deleted {
		return nil, fmt.Errorf("%w: a RepoPrefixRules on a deleted repo", ErrConfigRule)
	}
	settings := DefaultAclPrefixSettings()
	if byteCount := len(prefixRules.GetSealedRules()); !settings.SealedByteCountFits(byteCount) {
		return nil, fmt.Errorf("%w: sealed rules of %d bytes, not 48 B and a positive multiple of 256 B within %d", ErrConfigRule, byteCount, settings.SealedMaxByteCount)
	}
	if setCount := len(repo.row.GetPrefixRules()); !settings.SetFits(setCount) {
		return nil, fmt.Errorf("%w: the repo holds %d rule sets, SetMaxCount's limit of %d", ErrConfigRule, setCount, settings.SetMaxCount)
	}
	// checkRepoVersioning's test for a repo that is not owner-bound: an admin standing at S(n-1), or a config writer
	if !self.repoAdminSigner(repo, signer, statement.N) && !signer.configWriter {
		return nil, fmt.Errorf("%w: neither a repo admin nor a config writer", ErrConfigAuthority)
	}
	return &AclStatementVerdict{Signer: signer.id}, nil
}
