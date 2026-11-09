// §8.8's statements, 0x11xx: one rule per type, which api's verifier and every reader run alike through TEAM's
// ConfigLog (configAclRules, wired here from init), so both reach one verdict for one entry. CheckStatement gives the
// verdict at S(n-1), the state the entry lands on, with what it found there; ApplyStatement folds a statement that
// took effect into the next state's AclRows and names its effect on §7's rows (owner_confirm_signer and
// owner_confirmed_at, live_since, key_dropped_at), which TEAM's rows take; ReapplyStatement folds it again over a new
// base, keeping the verdict it got at its own position, so a later authority change never undoes an earlier
// revocation, while an effect the new rows no longer allow drops.
//
// Signers (§8.8's signer column, §7.9's read_only and authority rows):
//
//	GrantActivate   any admitted sidecar; authority only from its decisions (acl_grant.go)
//	GrantRevoke     the grant's subject, an approver its requests rule names at the revoke, or an admin; an id no
//	                active grant carries, an admin alone
//	Suspend         owner or sponsor (class 1) < admin (2) < k of n (3), and for an AdminSet member's device no admin
//	                class; a suspend_id already in force refused
//	Unsuspend       the class that suspended it or a higher one, never the subject; a stale id a no-op
//	EvsShare        a consented device of the owner-bound repo's owner, consented before the share's position
//	OwnerConfirm    a consented device of the confirmed sidecar's member
//	the access log  acl_statement_repo.go
//
// Every signer is a sidecar the state admits, standing at the entry's time (not revoked, expired, parked or
// suspended, an untagged one's member still a member) and not read_only (D-TEAM-24). A k-of-n statement, a completed
// AuthorityProposal, comes with its signers counted by TEAM's authority rows, and only Suspend and Unsuspend take one.
// AuditOptIn and AuditOptOut are the audit reader's (ACL-M6-02), refused until it lands.
//
// Pure functions of the state and the statement: no clock, no I/O. On every leg, the sidecar_http page Worker's
// included: root Id, no connect type. Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A Suspend's signer class, as AclSuspension.signer_class keeps it (plan-ACL-folded-grant-state #1): an Unsuspend
// lifts it only from the same class or a higher one.
const (
	// the subject's owner, or a tagged subject's sponsor
	AclSuspendClassOwner uint32 = 1
	// an admin, which an AdminSet member's device has none of
	AclSuspendClassAdmin uint32 = 2
	// k of n (§7.9's authority)
	AclSuspendClassAuthority uint32 = 3
)

// One §8.8 statement as its rule judges it.
type AclStatement struct {
	// The 0x11xx type.
	Type bridge.SignedType
	// The body as its type: *protocol.GrantActivate, *bridge.GrantRevoke, *bridge.Suspend, *protocol.RepoGrant and
	// so on, as ParseConfigStatement gives it.
	Body proto.Message
	// Who signed: one sidecar, or for a k-of-n statement the proposal's and its cosigns' signers, the proposer first.
	Signers []ConfigSigner
	// Whether it took effect by k of n: a completed AuthorityProposal, whose signers TEAM's authority rows counted.
	Authority bool
	// The carrying entry's position and time, ms since the epoch.
	N      uint64
	TimeMs int64
}

// What CheckStatement found at a statement's own position, which ApplyStatement folds and ReapplyStatement keeps over
// a new base, so neither judges the signer again.
type AclStatementVerdict struct {
	// The sidecar the rows keep as the one that signed it: the signer, or a k-of-n statement's proposer.
	Signer Id
	// A Suspend's or Unsuspend's class, AclSuspendClass*.
	Class uint32
	// Whether the signer wrote config heads at the statement's position, so its RepoRevoke stands and its RepoGrant
	// lifts a standing one (§8.8).
	ConfigWriter bool
	// RepoCreate of an owner-bound kind: the owner, the signer's member, and the owner's devices consented there,
	// AclRepo.consented_sidecar_ids. OwnerConfirm: the confirmed sidecar's member.
	MemberId            Id
	ConsentedSidecarIds []Id
	// OwnerConfirm: the sidecar it confirms.
	TargetId Id
	// Unsuspend: whether it lifts a Suspend in force; a stale id lifts nothing.
	Lifts bool
	// GrantRevoke: the retain_until_ms its AclSpentGrant row keeps (plan-ACL-folded-grant-state #3).
	RetainUntilMs int64
	// GrantActivate: what it folds to (acl_grant.go).
	grant *aclGrantFold
}

// What a statement that took effect does to §7's rows, which the AclRows do not hold: TEAM's rows take it.
type AclStatementEffect struct {
	// An OwnerConfirm's: the sidecar whose row's owner_confirm_signer becomes Signer and owner_confirmed_at the
	// statement's position. Nil for every other statement.
	OwnerConfirmed *AclOwnerConfirmed
	// Subjects an Unsuspend lifted a Suspend of: a member device that stands again, with no Suspend left in force,
	// becomes live at this position (§7.9's leaves row's live_since).
	UnsuspendedSubjectIds []Id
	// Subjects a Suspend names: an agent of a live Delegation drops that Delegation's shared reader key at this
	// position (§8.6's one switch, §10.5).
	SuspendedSubjectIds []Id
}

// One OwnerConfirm's effect on its sidecar's row.
type AclOwnerConfirmed struct {
	SidecarId Id
	Signer    Id
}

// The verdict at this state, S(n-1), for a statement carried at position statement.N: nil and what the check found
// when it takes effect, else why not, wrapping ErrConfigRefused's classes. spendCheck runs §16.6's spend check on a
// GrantActivate's decisions; nil refuses every decision (AclSpendCheckUnbuilt).
func (self *AclState) CheckStatement(statement *AclStatement, spendCheck AclSpendCheck) (*AclStatementVerdict, error) {
	if statement == nil || statement.Body == nil || len(statement.Signers) == 0 {
		return nil, fmt.Errorf("%w: no statement", ErrConfigRule)
	}
	if statement.Authority && statement.Type != bridge.SignedType_SIGNED_SUSPEND && statement.Type != bridge.SignedType_SIGNED_UNSUSPEND {
		return nil, fmt.Errorf("%w: %s takes no k-of-n signers", ErrConfigRule, statement.Type)
	}
	switch body := statement.Body.(type) {
	case *protocol.GrantActivate:
		if statement.Type == bridge.SignedType_SIGNED_GRANT_ACTIVATE {
			return self.CheckGrantActivate(statement, spendCheck)
		}
	case *bridge.GrantRevoke:
		if statement.Type == bridge.SignedType_SIGNED_GRANT_REVOKE {
			return self.checkGrantRevoke(statement, body)
		}
	case *bridge.Suspend:
		if statement.Type == bridge.SignedType_SIGNED_SUSPEND {
			return self.checkSuspend(statement, body)
		}
	case *bridge.Unsuspend:
		if statement.Type == bridge.SignedType_SIGNED_UNSUSPEND {
			return self.checkUnsuspend(statement, body)
		}
	case *protocol.EvsShare:
		if statement.Type == bridge.SignedType_SIGNED_EVS_SHARE {
			return self.checkEvsShare(statement, body)
		}
	case *protocol.OwnerConfirm:
		if statement.Type == bridge.SignedType_SIGNED_OWNER_CONFIRM {
			return self.checkOwnerConfirm(statement, body)
		}
	case *protocol.RepoCreate:
		if statement.Type == bridge.SignedType_SIGNED_REPO_CREATE {
			return self.checkRepoCreate(statement, body)
		}
	case *protocol.RepoAdmin:
		if statement.Type == bridge.SignedType_SIGNED_REPO_ADMIN {
			return self.checkRepoAdmin(statement, body)
		}
	case *protocol.RepoGrant:
		if statement.Type == bridge.SignedType_SIGNED_REPO_GRANT {
			return self.checkRepoGrant(statement, body)
		}
	case *protocol.RepoRevoke:
		if statement.Type == bridge.SignedType_SIGNED_REPO_REVOKE {
			return self.checkRepoRevoke(statement, body)
		}
	case *protocol.RepoDelete:
		if statement.Type == bridge.SignedType_SIGNED_REPO_DELETE {
			return self.checkRepoDelete(statement, body)
		}
	case *protocol.RepoRestore:
		if statement.Type == bridge.SignedType_SIGNED_REPO_RESTORE {
			return self.checkRepoRestore(statement, body)
		}
	case *protocol.RepoVersioning:
		if statement.Type == bridge.SignedType_SIGNED_REPO_VERSIONING {
			return self.checkRepoVersioning(statement, body)
		}
	case *protocol.AuditOptIn, *protocol.AuditOptOut:
		return nil, fmt.Errorf("%w: %s waits on the audit reader (ACL-M6-02)", ErrConfigRuleMissing, statement.Type)
	}
	return nil, fmt.Errorf("%w: %s with a body of another type", ErrConfigRule, statement.Type)
}

// The AclRows a statement that took effect leaves on this state's rows, and its effect on §7's rows. verdict is what
// CheckStatement found at the statement's own position. The state's rows are not changed.
func (self *AclState) ApplyStatement(statement *AclStatement, verdict *AclStatementVerdict) (*protocol.AclRows, AclStatementEffect, error) {
	return aclFoldStatement(self.rows, statement, verdict, false)
}

// ApplyStatement over a new base: this state's rows are the base's with the tail before the statement re-applied. The
// verdict is kept, never judged again, so a revocation stays one whatever authority changed since; an effect the new
// rows no longer allow, such as a grant on a repo they do not hold, is an error, and the statement's effect ends at
// this base (§7.9's base row).
func (self *AclState) ReapplyStatement(statement *AclStatement, verdict *AclStatementVerdict) (*protocol.AclRows, AclStatementEffect, error) {
	return aclFoldStatement(self.rows, statement, verdict, true)
}

// One statement's fold into rows, which are not changed: ApplyStatement's and ReapplyStatement's, and TEAM's apply
// path's, which folds on the rows of the state being built without indexing them.
func aclFoldStatement(rows *protocol.AclRows, statement *AclStatement, verdict *AclStatementVerdict, reapply bool) (*protocol.AclRows, AclStatementEffect, error) {
	effect := AclStatementEffect{}
	if rows == nil {
		rows = &protocol.AclRows{}
	}
	if statement == nil || verdict == nil {
		return nil, effect, fmt.Errorf("%w: a statement folded without its verdict", ErrConfigRule)
	}
	switch body := statement.Body.(type) {
	case *protocol.GrantActivate:
		next, err := aclFoldGrantActivate(rows, verdict, reapply)
		return next, effect, err
	case *bridge.GrantRevoke:
		return aclFoldGrantRevoke(rows, body, verdict), effect, nil
	case *bridge.Suspend:
		subjectId, err := aclSuspendIds(body.GetSubject(), body.GetSuspendId())
		if err != nil {
			return nil, effect, err
		}
		next := aclFoldSuspend(rows, statement, body, verdict)
		effect.SuspendedSubjectIds = []Id{subjectId}
		return next, effect, nil
	case *bridge.Unsuspend:
		subjectId, err := aclSuspendIds(body.GetSubject(), body.GetSuspendId())
		if err != nil {
			return nil, effect, err
		}
		next, lifted := aclFoldUnsuspend(rows, body)
		if lifted {
			effect.UnsuspendedSubjectIds = []Id{subjectId}
		}
		return next, effect, nil
	case *protocol.OwnerConfirm:
		effect.OwnerConfirmed = &AclOwnerConfirmed{SidecarId: verdict.TargetId, Signer: verdict.Signer}
	case *protocol.EvsShare, *protocol.RepoCreate, *protocol.RepoAdmin, *protocol.RepoGrant, *protocol.RepoRevoke,
		*protocol.RepoDelete, *protocol.RepoRestore, *protocol.RepoVersioning:
	default:
		return nil, effect, fmt.Errorf("%w: %s folds nothing", ErrConfigRule, statement.Type)
	}
	repos, err := FoldAclRepos(rows.GetRepos(), []AclAccessLogEntry{{Statement: statement, Verdict: verdict}})
	if err != nil {
		if reapply {
			return nil, effect, fmt.Errorf("%w: %w", ErrConfigRule, err)
		}
		return nil, effect, err
	}
	next := aclRowsCopy(rows)
	next.Repos = repos
	return next, effect, nil
}

// A new AclRows sharing every list of rows, unknown fields included, so a fold replaces only what it changes and the
// rows an earlier state holds never change.
func aclRowsCopy(rows *protocol.AclRows) *protocol.AclRows {
	next := &protocol.AclRows{
		HasDocument: rows.GetHasDocument(),
		Atoms:       rows.GetAtoms(),
		Rules:       rows.GetRules(),
		Requests:    rows.GetRequests(),
		Repos:       rows.GetRepos(),
		Bridge:      rows.GetBridge(),
		Audit:       rows.GetAudit(),
		Suspensions: rows.GetSuspensions(),
		SpentGrants: rows.GetSpentGrants(),
	}
	if unknown := rows.ProtoReflect().GetUnknown(); len(unknown) != 0 {
		next.ProtoReflect().SetUnknown(unknown)
	}
	return next
}

// The one signer of a statement that takes no k-of-n signers: a sidecar this state admits, standing at the entry's
// time and not read_only.
func (self *AclState) statementSigner(statement *AclStatement) (*aclSidecarState, error) {
	if len(statement.Signers) != 1 {
		return nil, fmt.Errorf("%w: %s takes one signer", ErrConfigRule, statement.Type)
	}
	signer := statement.Signers[0]
	if signer.Kind != ConfigSignerSidecar {
		return nil, fmt.Errorf("%w: %s takes a sidecar's signature", ErrConfigSigner, statement.Type)
	}
	sidecar := self.sidecarState(signer.SidecarId)
	if sidecar == nil {
		return nil, fmt.Errorf("%w: a sidecar this state does not admit", ErrConfigSigner)
	}
	if sidecar.readOnly {
		return nil, fmt.Errorf("%w: %s from a read_only device", ErrConfigReadOnly, statement.Type)
	}
	if reason := sidecar.hardDeny(statement.TimeMs); reason != 0 {
		return nil, fmt.Errorf("%w: the signer is %s", ErrConfigAuthority, reason)
	}
	return sidecar, nil
}

// Whether the sidecar acts as an admin: a member device, not read_only, of an Owner or Admin, autogroup:admin's two
// roles (acl-m2-02-state-readings #1).
func aclSignerAdmin(sidecar *aclSidecarState) bool {
	return sidecar.class == AclSubjectClassMemberDevice && !sidecar.readOnly &&
		sidecar.autogroups&aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN) != 0
}

// Whether a sidecar is a member device of an AdminSet member: an Owner's, Admin's, network admin's or IT admin's
// (§7.5), which only its owner or k of n suspends (§8.8).
func (self *AclState) adminSetDevice(sidecar *aclSidecarState) bool {
	if sidecar == nil || sidecar.class != AclSubjectClassMemberDevice {
		return false
	}
	member := self.view.Member(sidecar.memberId)
	return member != nil && configRoleInAdminSet(member.GetRole())
}

// Whether the signer counts as a consented device of the member at position: consented for it before the position,
// not read_only, standing now, and what it signs there outside every cascade (§8.5).
func (self *AclState) consentedSignerAt(signer *aclSidecarState, memberId Id, position uint64) bool {
	return self.sidecarConsented(signer) && !signer.suspended &&
		self.consentSignerCounts(signer.id.Bytes(), memberId, position)
}

// The view this state was built over, which a spend check reads.
func (self *AclState) View() AclAuthView {
	return self.view
}

// TEAM's configAclRules, implemented by ACL's rules (C-05): each 0x11xx entry checked at S(n-1), the verdict kept on
// the statement so a base's re-application keeps it, the fold written to the state being built and its effect to
// TEAM's rows there.
type configAclStatementRules struct{}

// Replaces TEAM's unwired rules, which refuse every acl statement.
func init() {
	configAcl = configAclStatementRules{}
}

// The statement as ACL's rules take it. A proposal's statement, which a completing AuthorityProposal or
// AuthorityCosign carries, has no Signed of its own and took effect by k of n.
func configAclStatement(statement *configStatement) *AclStatement {
	return &AclStatement{
		Type:      statement.signedType,
		Body:      statement.body,
		Signers:   statement.signers,
		Authority: statement.signed == nil,
		N:         statement.n,
		TimeMs:    statement.timeMs,
	}
}

// CheckStatement at state, keeping the verdict on the statement.
func (self configAclStatementRules) check(state *ConfigState, statement *configStatement) error {
	acl, err := state.Acl()
	if err != nil {
		return fmt.Errorf("%w: the state's acl rows do not build", ErrConfigRule)
	}
	verdict, err := acl.CheckStatement(configAclStatement(statement), state.aclSpendCheck())
	if err != nil {
		return err
	}
	statement.aclVerdict = verdict
	return nil
}

// The fold and its effect on the state being built.
func (self configAclStatementRules) apply(next *configStateBuilder, statement *configStatement) error {
	return self.fold(next, statement, false)
}

// The fold and its effect over a new base, the verdict kept.
func (self configAclStatementRules) reapply(next *configStateBuilder, statement *configStatement) error {
	return self.fold(next, statement, true)
}

// Writes a statement's fold to next's AclRows and its effect to next's rows.
func (self configAclStatementRules) fold(next *configStateBuilder, statement *configStatement, reapply bool) error {
	if statement.aclVerdict == nil {
		return fmt.Errorf("%w: %s applied without its check", ErrConfigRule, statement.signedType)
	}
	rows, effect, err := aclFoldStatement(next.state.aclRows, configAclStatement(statement), statement.aclVerdict, reapply)
	if err != nil {
		return err
	}
	next.setAclRows(rows)
	configApplyAclEffect(next, statement.n, effect)
	return nil
}

// What a k-of-n proposal of an acl statement acts on, which never counts toward its own authority: a Suspend's or
// Unsuspend's subject. False for every other acl type, which no proposal carries: AuditOptIn and AuditOptOut wait on
// ACL-M6-02.
func (self configAclStatementRules) targets(state *ConfigState, statement *configStatement) (ConfigTargets, bool) {
	var subject []byte
	switch body := statement.body.(type) {
	case *bridge.Suspend:
		subject = body.GetSubject()
	case *bridge.Unsuspend:
		subject = body.GetSubject()
	default:
		return ConfigTargets{}, false
	}
	targets := ConfigTargets{}
	if subjectId, err := IdFromBytes(subject); err == nil {
		targets.SidecarId, targets.HasSidecar = subjectId, true
	}
	return targets, true
}

// An acl statement's effect on TEAM's rows at position n: an OwnerConfirm's signer and position on its sidecar's
// row; live_since for a member device an Unsuspend left standing with no Suspend in force (§7.9's leaves row); and
// key_dropped_at for the live Delegation that admitted a suspended agent (§10.5).
func configApplyAclEffect(next *configStateBuilder, n uint64, effect AclStatementEffect) {
	if confirmed := effect.OwnerConfirmed; confirmed != nil {
		if row := next.sidecarForWrite(confirmed.SidecarId); row != nil {
			row.OwnerConfirmSigner = confirmed.Signer.Bytes()
			row.OwnerConfirmedAt = n
		}
	}
	for _, subjectId := range effect.UnsuspendedSubjectIds {
		row := next.sidecar(subjectId)
		if row == nil || !configRowMemberDevice(row) || row.GetRevokedAt() != 0 || row.GetParkedAt() != 0 {
			continue
		}
		if memberId, _ := configRowMember(row); next.member(memberId) == nil {
			continue
		}
		if aclRowsSuspends(next.state.aclRows, subjectId) {
			continue
		}
		next.sidecarForWrite(subjectId).LiveSince = n
	}
	for _, subjectId := range effect.SuspendedSubjectIds {
		row := next.sidecar(subjectId)
		if row == nil || len(row.GetDelegationId()) == 0 {
			continue
		}
		delegation := next.state.delegations[string(row.GetDelegationId())]
		if delegation == nil || delegation.GetKeyDroppedAt() != 0 || delegation.GetEndedAt() != 0 {
			continue
		}
		next.delegationForWrite(row.GetDelegationId()).KeyDroppedAt = n
	}
}

// The spend check this state's log runs on GrantActivate's decisions: its settings', else none, which refuses.
func (self *ConfigState) aclSpendCheck() AclSpendCheck {
	if self.history == nil || self.history.settings == nil || self.history.settings.AclSpendCheck == nil {
		return AclSpendCheckUnbuilt{}
	}
	return self.history.settings.AclSpendCheck
}

// The time entry k was sequenced at, from the states this state's log keeps, false when k is above this state or
// outside what the log retains. RepoRestore's 7 days run from it.
func (self *ConfigState) aclTimeAt(k uint64) (int64, bool) {
	if k == self.n {
		return self.timeMs, true
	}
	chain, ok := self.chainAt(k)
	if !ok {
		return 0, false
	}
	state, err := self.StateAt(&bridge.AuthPin{Version: k, Chain: chain[:]})
	if err != nil {
		return 0, false
	}
	return state.TimeMs(), true
}
