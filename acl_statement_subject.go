// §8.8's statements about subjects and grants: GrantRevoke, Suspend, Unsuspend, EvsShare and OwnerConfirm, each a
// check at its position and, but for EvsShare and OwnerConfirm, which the access log's fold takes (acl_access_log.go),
// a fold into AclRows. acl_statement.go says who may sign each.
//
// A Suspend's subject is 16 bytes, a sidecar_id or a client_id (§8.4's subjects); its suspend_id is 16 random bytes,
// and an active Suspend keeps one AclSuspension row per (subject, suspend_id) until an Unsuspend naming both lands
// (plan-ACL-folded-grant-state #1). Only a sidecar's owner and class can be read from the state, so a client subject
// takes an admin's or k of n.
//
// A GrantRevoke spends its grant_id for good: the active rule that carries it leaves the rows, and AclSpentGrant keeps
// the id, with its activation's retain_until_ms, or 0, the network's life, for an id no activation carried
// (plan-ACL-folded-grant-state #3), so no later GrantActivate of it takes effect (§8.8's refuse row).
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A Suspend's suspend_id: 16 random bytes, an Id's size.
const aclSuspendIdByteCount = 16

// A derived atom's kinds (plan-ACL-nonsidecar-subjects): the byte its id hashes.
const (
	AclDerivedAtomMember    byte = 1
	AclDerivedAtomSidecar   byte = 2
	AclDerivedAtomClient    byte = 3
	AclDerivedAtomNetwork   byte = 4
	AclDerivedAtomRole      byte = 5
	AclDerivedAtomPrincipal byte = 6
)

// A selector with no table name compiled to an atom: the first 16 bytes of
// SHA-256("urnetwork-sidecar-v1/acl-atom" || 0x00 || kind || 0x00 || value), value an id's 16 bytes or a role's or
// principal's name (plan-ACL-nonsidecar-subjects). An activated grant's src is its subject's sidecar atom
// (plan-ACL-folded-grant-state #2). A writer redraws a table atom that would take an autogroup's form; a derived one
// that did would read as that autogroup, which SHA-256 makes a 2^-120 event.
func AclDerivedAtom(kind byte, value []byte) Id {
	hash := sha256.New()
	hash.Write([]byte("urnetwork-sidecar-v1/acl-atom"))
	hash.Write([]byte{0, kind, 0})
	hash.Write(value)
	var digest [sha256.Size]byte
	hash.Sum(digest[:0])
	return Id(digest[:aclAtomByteCount])
}

// The active rule a grant_id names, an activated grant's, or nil.
func (self *AclState) grantRule(grantId []byte) *aclRule {
	for i := range self.rules {
		if bytes.Equal(self.rules[i].row.GetRuleId(), grantId) {
			return &self.rules[i]
		}
	}
	return nil
}

// The AclSpentGrant row of a grant_id, or nil.
func (self *AclState) spentGrant(grantId []byte) *protocol.AclSpentGrant {
	for _, spent := range self.rows.GetSpentGrants() {
		if bytes.Equal(spent.GetGrantId(), grantId) {
			return spent
		}
	}
	return nil
}

// Whether an activated grant's src, its subject's sidecar atom, lists the sidecar.
func (self *AclState) grantSubjectIs(rule *aclRule, sidecarId Id) bool {
	sidecar := self.sidecarState(sidecarId)
	if sidecar == nil {
		return false
	}
	for _, atomIndex := range rule.srcAtoms {
		atomRow := self.atomRow(atomIndex)
		if atomRow == nil {
			continue
		}
		for _, listed := range atomRow.GetSidecarIds() {
			if Id(listed) == sidecarId {
				return true
			}
		}
	}
	return false
}

// The sidecar an activated grant's src names: the one sidecar its subject atom lists. False when there is not
// exactly one.
func (self *AclState) grantSubject(rule *aclRule) (Id, bool) {
	subjectIds := []Id{}
	for _, atomIndex := range rule.srcAtoms {
		if atomRow := self.atomRow(atomIndex); atomRow != nil {
			for _, listed := range atomRow.GetSidecarIds() {
				subjectIds = append(subjectIds, Id(listed))
			}
		}
	}
	slices.SortFunc(subjectIds, Id.Cmp)
	subjectIds = slices.Compact(subjectIds)
	if len(subjectIds) != 1 {
		return Id{}, false
	}
	return subjectIds[0], true
}

// Whether the signer may approve the grant under its requests rule at timeMs: an approval-capable device of a member
// the rule's approvers name for the grant's subject and destinations at this state (§8.6). A grant whose requests
// rule this head deleted has no approver.
func (self *AclState) grantApprover(rule *aclRule, signer *aclSidecarState, timeMs int64) bool {
	if !self.ApprovalCapable(signer.id) || len(rule.row.GetSourceRuleId()) == 0 {
		return false
	}
	subjectId, ok := self.grantSubject(rule)
	if !ok {
		return false
	}
	for _, request := range self.rows.GetRequests() {
		if !bytes.Equal(request.GetRuleId(), rule.row.GetSourceRuleId()) {
			continue
		}
		approvers := self.ResolveApprovers(request.GetApproverAtoms(), AclSidecarSubject(subjectId), rule.row.GetTargets(), aclTime(timeMs))
		return self.Approves(approvers, signer.memberId)
	}
	return false
}

// GrantRevoke{grant_id}: the subject, an approver, or an admin, for a grant an active rule carries; an admin alone for
// an id no active rule carries, spent or never activated (§8.8). A revocation repeats harmlessly.
func (self *AclState) checkGrantRevoke(statement *AclStatement, revoke *bridge.GrantRevoke) (*AclStatementVerdict, error) {
	signer, err := self.statementSigner(statement)
	if err != nil {
		return nil, err
	}
	grantId := revoke.GetGrantId()
	if len(grantId) != sha256.Size {
		return nil, fmt.Errorf("%w: a grant_id of %d bytes", ErrConfigRule, len(grantId))
	}
	verdict := &AclStatementVerdict{Signer: signer.id}
	if spent := self.spentGrant(grantId); spent != nil {
		verdict.RetainUntilMs = spent.GetRetainUntilMs()
	}
	admin := aclSignerAdmin(signer)
	if rule := self.grantRule(grantId); rule != nil {
		if !admin && !self.grantSubjectIs(rule, signer.id) && !self.grantApprover(rule, signer, statement.TimeMs) {
			return nil, fmt.Errorf("%w: neither the grant's subject, an approver nor an admin", ErrConfigAuthority)
		}
		return verdict, nil
	}
	if !admin {
		return nil, fmt.Errorf("%w: only an admin revokes a grant_id no active grant carries", ErrConfigAuthority)
	}
	return verdict, nil
}

// The class the signer holds over a subject, 0 for none: an admin's, unless the subject is an AdminSet member's
// device, else its owner's or sponsor's (owner decision 83).
func (self *AclState) suspendClass(signer *aclSidecarState, subjectId Id) uint32 {
	subject := self.sidecarState(subjectId)
	if aclSignerAdmin(signer) && !self.adminSetDevice(subject) {
		return AclSuspendClassAdmin
	}
	if subject != nil && subject.valid && subject.hasOwner && signer.class == AclSubjectClassMemberDevice &&
		!signer.readOnly && signer.memberId == subject.owner {
		return AclSuspendClassOwner
	}
	return 0
}

// The active Suspend of a subject under a suspend_id, or nil.
func aclRowsSuspension(rows *protocol.AclRows, subject []byte, suspendId []byte) *protocol.AclSuspension {
	for _, suspension := range rows.GetSuspensions() {
		if bytes.Equal(suspension.GetSubject(), subject) && bytes.Equal(suspension.GetSuspendId(), suspendId) {
			return suspension
		}
	}
	return nil
}

// Whether any active Suspend names the subject.
func aclRowsSuspends(rows *protocol.AclRows, subjectId Id) bool {
	for _, suspension := range rows.GetSuspensions() {
		if bytes.Equal(suspension.GetSubject(), subjectId.Bytes()) {
			return true
		}
	}
	return false
}

// Checks a Suspend's or Unsuspend's ids and returns the subject.
func aclSuspendIds(subject []byte, suspendId []byte) (Id, error) {
	subjectId, err := IdFromBytes(subject)
	if err != nil {
		return Id{}, fmt.Errorf("%w: a subject of %d bytes", ErrConfigRule, len(subject))
	}
	if len(suspendId) != aclSuspendIdByteCount {
		return Id{}, fmt.Errorf("%w: a suspend_id of %d bytes", ErrConfigRule, len(suspendId))
	}
	return subjectId, nil
}

// The class a Suspend or Unsuspend acts in: k of n for a completed proposal, whose signers TEAM counted, else the one
// signer's over the subject, and the signer the rows keep.
func (self *AclState) suspendSigner(statement *AclStatement, subjectId Id) (uint32, Id, error) {
	if statement.Authority {
		for _, signer := range statement.Signers {
			if signer.Kind == ConfigSignerSidecar && signer.SidecarId == subjectId {
				return 0, Id{}, fmt.Errorf("%w: the subject signs no %s of itself", ErrConfigAuthority, statement.Type)
			}
		}
		return AclSuspendClassAuthority, statement.Signers[0].SidecarId, nil
	}
	signer, err := self.statementSigner(statement)
	if err != nil {
		return 0, Id{}, err
	}
	class := self.suspendClass(signer, subjectId)
	if class == 0 {
		return 0, Id{}, fmt.Errorf("%w: neither the subject's owner or sponsor nor an admin over it", ErrConfigAuthority)
	}
	return class, signer.id, nil
}

// Suspend{subject, suspend_id}: an admin, or the subject's owner or sponsor; for an AdminSet member's device its
// owner or k of n (§8.8, §7.9). A suspend_id already in force for the subject is refused, since one Unsuspend names
// one Suspend.
func (self *AclState) checkSuspend(statement *AclStatement, suspend *bridge.Suspend) (*AclStatementVerdict, error) {
	subjectId, err := aclSuspendIds(suspend.GetSubject(), suspend.GetSuspendId())
	if err != nil {
		return nil, err
	}
	if aclRowsSuspension(self.rows, suspend.GetSubject(), suspend.GetSuspendId()) != nil {
		return nil, fmt.Errorf("%w: a suspend_id already in force", ErrConfigRule)
	}
	class, signerId, err := self.suspendSigner(statement, subjectId)
	if err != nil {
		return nil, err
	}
	return &AclStatementVerdict{Signer: signerId, Class: class}, nil
}

// Unsuspend{subject, suspend_id}: the class that suspended it or a higher one (owner or sponsor < admin < k of n),
// never the subject itself; it lifts only that suspend_id, and a stale one lifts nothing (§8.8).
func (self *AclState) checkUnsuspend(statement *AclStatement, unsuspend *bridge.Unsuspend) (*AclStatementVerdict, error) {
	subjectId, err := aclSuspendIds(unsuspend.GetSubject(), unsuspend.GetSuspendId())
	if err != nil {
		return nil, err
	}
	if !statement.Authority && len(statement.Signers) == 1 && statement.Signers[0].SidecarId == subjectId {
		return nil, fmt.Errorf("%w: the subject never lifts its own Suspend", ErrConfigAuthority)
	}
	class, signerId, err := self.suspendSigner(statement, subjectId)
	if err != nil {
		return nil, err
	}
	verdict := &AclStatementVerdict{Signer: signerId, Class: class}
	suspension := aclRowsSuspension(self.rows, unsuspend.GetSubject(), unsuspend.GetSuspendId())
	if suspension == nil {
		return verdict, nil
	}
	if class < suspension.GetSignerClass() {
		return nil, fmt.Errorf("%w: class %d lifts no Suspend of class %d", ErrConfigAuthority, class, suspension.GetSignerClass())
	}
	verdict.Lifts = true
	return verdict, nil
}

// EvsShare{repo_id, subject, expires}: a consented device of the owner-bound repo's owner, consented before the
// share's position (§8.5), so every reader refuses an admin's (owner decision 126). An expires at or before the entry's
// time shares nothing and is refused.
func (self *AclState) checkEvsShare(statement *AclStatement, share *protocol.EvsShare) (*AclStatementVerdict, error) {
	signer, err := self.statementSigner(statement)
	if err != nil {
		return nil, err
	}
	repo, err := self.statementRepo(share.GetRepoId())
	if err != nil {
		return nil, err
	}
	if !aclRepoKindOwnerBound(repo.kind) || repo.ownerId == (Id{}) {
		return nil, fmt.Errorf("%w: an EvsShare of a repo of kind %s", ErrConfigRule, repo.kind)
	}
	if repo.deleted {
		return nil, fmt.Errorf("%w: an EvsShare of a deleted repo", ErrConfigRule)
	}
	if _, err := aclStatementSubject(share.GetSubject()); err != nil {
		return nil, err
	}
	if expires := share.GetExpires(); expires != 0 && expires <= statement.TimeMs {
		return nil, fmt.Errorf("%w: an EvsShare expired when it landed", ErrConfigRule)
	}
	if !self.consentedSignerAt(signer, repo.ownerId, statement.N) {
		return nil, fmt.Errorf("%w: only a consented device of the repo's owner shares it", ErrConfigAuthority)
	}
	return &AclStatementVerdict{Signer: signer.id}, nil
}

// OwnerConfirm{sidecar_id}: a consented device of the sidecar's member confirms another untagged, standing device of
// that member (§8.5's confirmed clause; owner decision 126).
func (self *AclState) checkOwnerConfirm(statement *AclStatement, confirm *protocol.OwnerConfirm) (*AclStatementVerdict, error) {
	signer, err := self.statementSigner(statement)
	if err != nil {
		return nil, err
	}
	targetId, err := IdFromBytes(confirm.GetSidecarId())
	if err != nil {
		return nil, fmt.Errorf("%w: a sidecar_id of %d bytes", ErrConfigRule, len(confirm.GetSidecarId()))
	}
	target := self.sidecarState(targetId)
	switch {
	case target == nil || !target.valid:
		return nil, fmt.Errorf("%w: an OwnerConfirm of a sidecar this state does not admit", ErrConfigRule)
	case target.tagged || target.ephemeral:
		return nil, fmt.Errorf("%w: an OwnerConfirm of a tagged or ephemeral sidecar, which consent never names", ErrConfigRule)
	case target.revoked:
		return nil, fmt.Errorf("%w: an OwnerConfirm of a revoked sidecar", ErrConfigRule)
	case targetId == signer.id:
		return nil, fmt.Errorf("%w: a device confirms no admission of its own", ErrConfigRule)
	}
	if !self.consentedSignerAt(signer, target.memberId, statement.N) {
		return nil, fmt.Errorf("%w: only a consented device of the sidecar's member confirms it", ErrConfigAuthority)
	}
	return &AclStatementVerdict{Signer: signer.id, TargetId: targetId, MemberId: target.memberId}, nil
}

// A subject a statement names: 16 bytes, never the wildcard repo's zero form.
func aclStatementSubject(subject []byte) (Id, error) {
	subjectId, err := IdFromBytes(subject)
	if err != nil || subjectId == (Id{}) {
		return Id{}, fmt.Errorf("%w: a subject of %d bytes", ErrConfigRule, len(subject))
	}
	return subjectId, nil
}

// GrantRevoke's fold: the rule carrying the grant_id leaves the rows, and the id stays spent, keeping the retain time
// its activation set.
func aclFoldGrantRevoke(rows *protocol.AclRows, revoke *bridge.GrantRevoke, verdict *AclStatementVerdict) *protocol.AclRows {
	next := aclRowsCopy(rows)
	grantId := revoke.GetGrantId()
	if slices.ContainsFunc(rows.GetRules(), func(rule *protocol.AclRule) bool { return bytes.Equal(rule.GetRuleId(), grantId) }) {
		next.Rules = slices.DeleteFunc(slices.Clone(rows.GetRules()), func(rule *protocol.AclRule) bool {
			return bytes.Equal(rule.GetRuleId(), grantId)
		})
	}
	next.SpentGrants = aclSpendGrant(rows.GetSpentGrants(), grantId, verdict.RetainUntilMs)
	return next
}

// The spent rows with grantId spent until retainUntilMs: a row it already has keeps the later of the two, and 0, the
// network's life, wins over any time.
func aclSpendGrant(spentGrants []*protocol.AclSpentGrant, grantId []byte, retainUntilMs int64) []*protocol.AclSpentGrant {
	next := slices.Clone(spentGrants)
	for i, spent := range next {
		if !bytes.Equal(spent.GetGrantId(), grantId) {
			continue
		}
		retain := spent.GetRetainUntilMs()
		if retain != 0 && (retainUntilMs == 0 || retain < retainUntilMs) {
			retain = retainUntilMs
		}
		next[i] = &protocol.AclSpentGrant{GrantId: bytes.Clone(grantId), RetainUntilMs: retain}
		return next
	}
	return append(next, &protocol.AclSpentGrant{GrantId: bytes.Clone(grantId), RetainUntilMs: retainUntilMs})
}

// Suspend's fold: one AclSuspension row with its class, signer and position; one already there for the same
// (subject, suspend_id), as a re-application finds, stays.
func aclFoldSuspend(rows *protocol.AclRows, statement *AclStatement, suspend *bridge.Suspend, verdict *AclStatementVerdict) *protocol.AclRows {
	if aclRowsSuspension(rows, suspend.GetSubject(), suspend.GetSuspendId()) != nil {
		return rows
	}
	next := aclRowsCopy(rows)
	next.Suspensions = append(slices.Clone(rows.GetSuspensions()), &protocol.AclSuspension{
		Subject:     bytes.Clone(suspend.GetSubject()),
		SuspendId:   bytes.Clone(suspend.GetSuspendId()),
		SignerClass: verdict.Class,
		Signer:      verdict.Signer.Bytes(),
		At:          statement.N,
	})
	return next
}

// Unsuspend's fold: the Suspend it names leaves the rows, and whether there was one.
func aclFoldUnsuspend(rows *protocol.AclRows, unsuspend *bridge.Unsuspend) (*protocol.AclRows, bool) {
	if aclRowsSuspension(rows, unsuspend.GetSubject(), unsuspend.GetSuspendId()) == nil {
		return rows, false
	}
	next := aclRowsCopy(rows)
	next.Suspensions = slices.DeleteFunc(slices.Clone(rows.GetSuspensions()), func(suspension *protocol.AclSuspension) bool {
		return bytes.Equal(suspension.GetSubject(), unsuspend.GetSubject()) && bytes.Equal(suspension.GetSuspendId(), unsuspend.GetSuspendId())
	})
	return next, true
}
