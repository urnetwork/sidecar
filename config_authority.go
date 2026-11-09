// §7.9's authority: k distinct counted signers among the newest AdminSet's n Owners and Admins, and the proposals
// that gather them (§7.9's several, proposal, counted, completion and k = 1 rows; D-TEAM-12, D-TEAM-21).
//
// k is the AdminSet's threshold, 2 by default when n >= 3, and 1 whenever n <= 2, so no lone signer mints or removes
// a config-signing key but where a network has two or fewer such members (7.18). A signer counts as its member: a
// member's devices count once; read_only devices never count; neither the device a statement acts on nor a member an
// AdminSet change or MemberRevoke acts on counts; but an AdminSet member's existing device counts as one for its own
// new device and for revoking another of its own devices (owner decision 112, §5.6).
//
// A statement that needs more than one signer is an AuthorityProposal by the first counted signer, then an
// AuthorityCosign from each further one, each under its own header. Signatures count at the completing entry's
// state, and the proposed statement takes effect at the entry holding the k-th, its causal identity. A recovery key's
// signature is TEAM-M2-05's, a Delegation never counts, and presence is TEAM-M2-06's, each refused until it lands.
//
// Rows carry no open proposal, so one a base folds before it completes closes there (question
// team-m2-02-open-proposals-across-bases), on every reader alike.
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"crypto/sha256"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a statement acts on, which never counts toward its own authority (§7.9's counted row).
type ConfigTargets struct {
	// The device a SidecarAdmit, SidecarRevoke or AdmissionConfirm acts on, which never counts.
	SidecarId  Id
	HasSidecar bool
	// The member an untagged target device names, whose other devices count as one for it, though that member be
	// a network or IT admin (owner decision 112).
	SidecarMemberId  Id
	HasSidecarMember bool
	// The members a MemberAdmit, a MemberRevoke or an AdminSet change acts on: none of their devices count.
	MemberIds []Id
}

// The effective threshold k and the number n of Owners and Admins in the newest AdminSet (§7.9's authority row).
func (self *ConfigState) Threshold() (k int, n int) {
	for _, member := range self.members {
		switch member.GetRole() {
		case bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_ADMIN:
			n += 1
		}
	}
	switch {
	case n <= 2:
		k = 1
	case self.threshold == 0:
		k = 2
	default:
		k = int(self.threshold)
	}
	return k, n
}

// The distinct members signers count as for a statement acting on targets, judged at this state's time (§7.9's
// counted row).
func (self *ConfigState) Counted(signers []ConfigSigner, targets ConfigTargets) []Id {
	return self.countedAt(signers, targets, self.timeMs)
}

// Whether signers hold authority for a statement acting on targets at this state: at least k counted.
func (self *ConfigState) Authority(signers []ConfigSigner, targets ConfigTargets) bool {
	return self.authorityAt(signers, targets, self.timeMs)
}

// Counted, judging each signer's standing at timeMs, the carrying entry's time.
func (self *ConfigState) countedAt(signers []ConfigSigner, targets ConfigTargets, timeMs int64) []Id {
	memberIds := []Id{}
	for _, signer := range signers {
		memberId, ok := self.countedMember(signer, targets, timeMs)
		if ok && !slices.Contains(memberIds, memberId) {
			memberIds = append(memberIds, memberId)
		}
	}
	return memberIds
}

// Authority, judging standing at timeMs.
func (self *ConfigState) authorityAt(signers []ConfigSigner, targets ConfigTargets, timeMs int64) bool {
	k, _ := self.Threshold()
	return k <= len(self.countedAt(signers, targets, timeMs))
}

// The member one signer counts as, false when it counts for none: only a standing member device, not read_only,
// of an Owner or Admin, or of the target device's own AdminSet member, and never the target or a target member.
// A recovery key counts under Recovery's window, which TEAM-M2-05 judges; a Delegation never counts.
func (self *ConfigState) countedMember(signer ConfigSigner, targets ConfigTargets, timeMs int64) (Id, bool) {
	if signer.Kind != ConfigSignerSidecar || (targets.HasSidecar && signer.SidecarId == targets.SidecarId) {
		return Id{}, false
	}
	row, standing := self.standingSidecar(signer.SidecarId, timeMs)
	if !standing || !configRowMemberDevice(row) || configRowReadOnly(row) {
		return Id{}, false
	}
	memberId, _ := configRowMember(row)
	if slices.Contains(targets.MemberIds, memberId) {
		return Id{}, false
	}
	role := self.members[memberId].GetRole()
	switch {
	case role == bridge.MemberRole_MEMBER_ROLE_OWNER || role == bridge.MemberRole_MEMBER_ROLE_ADMIN:
		return memberId, true
	case targets.HasSidecarMember && memberId == targets.SidecarMemberId && configRoleInAdminSet(role):
		return memberId, true
	}
	return Id{}, false
}

// A statement's targets, by its type's rule, or for an acl statement by ACL's rules.
func configStatementTargets(state *ConfigState, statement *configStatement) (ConfigTargets, bool) {
	if statement.signedType>>8 == 0x11 {
		return configAcl.targets(state, statement)
	}
	rule := configStatementRules[statement.signedType]
	if rule == nil || rule.targets == nil {
		return ConfigTargets{}, false
	}
	return rule.targets(state, statement), true
}

// Registers AuthorityProposal's and AuthorityCosign's rules.
func init() {
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckProposal,
		apply:      configApplyProposal,
	})
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_AUTHORITY_COSIGN,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckCosign,
		apply:      configApplyCosign,
	})
}

// The statement an AuthorityProposal carries, signed by signers so far: its type's body as signed (QD-498), whose
// own header §7.9 does not judge, only the proposal's.
func configProposedStatement(proposal *protocol.AuthorityProposal, signers []ConfigSigner, n uint64, timeMs int64) (*configStatement, error) {
	proposedType := bridge.SignedType(proposal.GetStatementType())
	var purpose string
	var body proto.Message
	var err error
	if proposedType>>8 == 0x11 {
		// an acl statement, which ACL's rules take; they name the targets of the types a proposal may carry
		var ok bool
		if purpose, ok = ConfigStatementPurpose(proposedType); !ok {
			return nil, fmt.Errorf("%w: a proposal of %s, which no proposal carries yet", ErrConfigRuleMissing, proposedType)
		}
		body, err = ParseConfigStatement(purpose, proposedType, proposal.GetStatement())
	} else {
		rule := configStatementRules[proposedType]
		if rule == nil || rule.targets == nil {
			return nil, fmt.Errorf("%w: a proposal of %s, which no proposal carries yet", ErrConfigRuleMissing, proposedType)
		}
		purpose = rule.purpose
		body, err = rule.decode(proposal.GetStatement())
	}
	if err != nil {
		return nil, fmt.Errorf("%w: the proposed statement: %w", ErrConfigRule, err)
	}
	proposed := &configStatement{
		signedType: proposedType,
		purpose:    purpose,
		body:       body,
		bodyBytes:  proposal.GetStatement(),
		id:         bridge.SignedBytesSha256(purpose, proposedType, proposal.GetStatement()),
		signers:    slices.Clone(signers),
		n:          n,
		timeMs:     timeMs,
	}
	if headerMessage, ok := body.(configHeaderMessage); ok {
		proposed.header = headerMessage.GetHeader()
	}
	if proposedType>>8 == 0x11 {
		if _, ok := configAcl.targets(nil, proposed); !ok {
			return nil, fmt.Errorf("%w: a proposal of %s, which no proposal carries yet", ErrConfigRuleMissing, proposedType)
		}
	}
	return proposed, nil
}

// An AuthorityProposal at state: its proposer counts for the proposed statement, and at k = 1 the proposal completes
// at its own entry, where the proposed statement's rule must hold.
func configCheckProposal(state *ConfigState, statement *configStatement) error {
	proposal := statement.body.(*protocol.AuthorityProposal)
	proposed, err := configProposedStatement(proposal, statement.signers, statement.n, statement.timeMs)
	if err != nil {
		return err
	}
	targets, _ := configStatementTargets(state, proposed)
	if len(state.countedAt(statement.signers, targets, statement.timeMs)) != 1 {
		return fmt.Errorf("%w: the proposer is no counted signer for %s", ErrConfigAuthority, proposed.signedType)
	}
	if state.authorityAt(proposed.signers, targets, statement.timeMs) {
		if err := configCheckStatement(state, proposed); err != nil {
			return err
		}
		statement.completes = proposed
		return nil
	}
	statement.proposed = proposed
	return nil
}

// An AuthorityProposal's effect: the proposed statement's at completion, else an open proposal.
func configApplyProposal(next *configStateBuilder, statement *configStatement) error {
	if statement.completes != nil {
		return configApplyStatement(next, statement.completes, false)
	}
	if statement.proposed == nil {
		return fmt.Errorf("%w: a proposal neither complete nor open", ErrConfigRule)
	}
	next.putProposal(&configProposal{
		id:         statement.id,
		n:          statement.n,
		notAfterMs: statement.header.GetNotAfterMs(),
		statement:  statement.proposed,
	})
	return nil
}

// An AuthorityCosign at state: its proposal is open and unexpired, and its signer is a further counted one; the
// k-th counted signature completes the proposal, where the proposed statement's rule must hold at this state.
func configCheckCosign(state *ConfigState, statement *configStatement) error {
	cosign := statement.body.(*protocol.AuthorityCosign)
	if len(cosign.GetProposalId()) != sha256.Size {
		return fmt.Errorf("%w: a proposal_id of %d bytes", ErrConfigRule, len(cosign.GetProposalId()))
	}
	proposal := state.proposals[[sha256.Size]byte(cosign.GetProposalId())]
	if proposal == nil {
		return fmt.Errorf("%w: no open proposal with this id", ErrConfigRule)
	}
	if proposal.notAfterMs < statement.timeMs {
		return fmt.Errorf("%w: the proposal expired", ErrConfigRule)
	}
	targets, _ := configStatementTargets(state, proposal.statement)
	cosigner, counted := state.countedMember(statement.signers[0], targets, statement.timeMs)
	if !counted {
		return fmt.Errorf("%w: the cosigner is no counted signer for %s", ErrConfigAuthority, proposal.statement.signedType)
	}
	if slices.Contains(state.countedAt(proposal.statement.signers, targets, statement.timeMs), cosigner) {
		return fmt.Errorf("%w: the cosigner's member already counts", ErrConfigAuthority)
	}
	proposed := *proposal.statement
	proposed.signers = append(slices.Clone(proposal.statement.signers), statement.signers[0])
	proposed.n, proposed.timeMs = statement.n, statement.timeMs
	if state.authorityAt(proposed.signers, targets, statement.timeMs) {
		if err := configCheckStatement(state, &proposed); err != nil {
			return err
		}
		statement.completes = &proposed
		return nil
	}
	statement.proposed = &proposed
	return nil
}

// An AuthorityCosign's effect: the proposed statement's and the proposal's close at completion, else the proposal
// with one more signer. On a base's re-application a proposal the base folded is gone, and an incomplete cosign of it
// writes nothing.
func configApplyCosign(next *configStateBuilder, statement *configStatement) error {
	proposalId := [sha256.Size]byte(statement.body.(*protocol.AuthorityCosign).GetProposalId())
	if statement.completes != nil {
		next.deleteProposal(proposalId)
		return configApplyStatement(next, statement.completes, false)
	}
	proposal := next.proposal(proposalId)
	if proposal == nil || statement.proposed == nil {
		return fmt.Errorf("%w: the proposal is not open here", ErrConfigRule)
	}
	next.putProposal(&configProposal{
		id:         proposal.id,
		n:          proposal.n,
		notAfterMs: proposal.notAfterMs,
		statement:  statement.proposed,
	})
	return nil
}

// Whether any signer is a standing member device, not read_only, at timeMs, that also passes accept, which sees its
// row, member and role. The first such signer comes back for the rows that keep one.
func (self *ConfigState) anyMemberDevice(signers []ConfigSigner, timeMs int64, accept func(signerId Id, memberId Id, role bridge.MemberRole) bool) (ConfigSigner, bool) {
	for _, signer := range signers {
		if signer.Kind != ConfigSignerSidecar {
			continue
		}
		row, standing := self.standingSidecar(signer.SidecarId, timeMs)
		if !standing || !configRowMemberDevice(row) || configRowReadOnly(row) {
			continue
		}
		memberId, _ := configRowMember(row)
		if accept(signer.SidecarId, memberId, self.members[memberId].GetRole()) {
			return signer, true
		}
	}
	return ConfigSigner{}, false
}

// Whether a role may admit and revoke devices with one signature: an Owner's, Admin's or IT admin's (§7.5).
func configRoleAdmits(role bridge.MemberRole) bool {
	switch role {
	case bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_ADMIN, bridge.MemberRole_MEMBER_ROLE_IT_ADMIN:
		return true
	}
	return false
}

// Whether a role signs MemberAdmit and MemberRevoke alone: an Owner's or an Admin's (§7.9's records).
func configRoleAdmitsMembers(role bridge.MemberRole) bool {
	return role == bridge.MemberRole_MEMBER_ROLE_OWNER || role == bridge.MemberRole_MEMBER_ROLE_ADMIN
}
