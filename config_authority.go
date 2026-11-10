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
// key counts as its member under Recovery's window (config_recovery.go), a Delegation never counts, and presence is
// TEAM-M2-06's.
//
// Rows carry every open proposal as a ProposalRow, with its signers, its window and its kind fixed at its entry
// (DESIGN-DETAILS 5.2.2), so a cosign, veto, void or activation after a fold finds it at every reader alike.
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"bytes"
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

// The member one signer counts as, false when it counts for none: a standing member device, not read_only, or a
// recovery key under its binding in effect that no void restored (config_recovery.go), of an Owner or Admin, or of the
// target device's own AdminSet member; never the target device or a target member. A Delegation never counts.
func (self *ConfigState) countedMember(signer ConfigSigner, targets ConfigTargets, timeMs int64) (Id, bool) {
	var memberId Id
	switch signer.Kind {
	case ConfigSignerSidecar:
		if targets.HasSidecar && signer.SidecarId == targets.SidecarId {
			return Id{}, false
		}
		row, standing := self.standingSidecar(signer.SidecarId, timeMs)
		if !standing || !configRowMemberDevice(row) || configRowReadOnly(row) {
			return Id{}, false
		}
		memberId, _ = configRowMember(row)
	case ConfigSignerRecovery:
		if !self.recoveryKeyCurrent(signer) {
			return Id{}, false
		}
		memberId = signer.MemberId
	default:
		return Id{}, false
	}
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

// The statement a ProposalRow proposes, as rows carry it to a reader that holds no entry of it: its signers rebuilt
// from the row, a 16-byte one a sidecar and a 32-byte one a recovery key, whose member is the one whose bindings hold
// it, or none, so that it counts for none, where that is not one member.
func (self *ConfigState) proposalRowStatement(row *bridge.ProposalRow) (*configStatement, error) {
	signers := make([]ConfigSigner, 0, len(row.GetSigners()))
	for _, signer := range row.GetSigners() {
		switch len(signer.GetSigner()) {
		case len(Id{}):
			signers = append(signers, ConfigSigner{Kind: ConfigSignerSidecar, SidecarId: Id(signer.GetSigner())})
		case sha256.Size:
			memberId, _ := self.recoveryKeyMember(signer.GetSigner())
			signers = append(signers, ConfigSigner{Kind: ConfigSignerRecovery, MemberId: memberId, RecoveryKeySha256: bytes.Clone(signer.GetSigner())})
		default:
			return nil, fmt.Errorf("a signer of %d bytes", len(signer.GetSigner()))
		}
	}
	switch kind := bridge.ProposalKind(row.GetKind()); {
	case len(signers) == 0:
		return nil, fmt.Errorf("no signer")
	case kind < bridge.ProposalKind_PROPOSAL_KIND_AUTHORITY || bridge.ProposalKind_PROPOSAL_KIND_RESTORED < kind:
		return nil, fmt.Errorf("kind %d", kind)
	}
	last := row.GetSigners()[len(row.GetSigners())-1].GetAt()
	return configProposedStatement(&protocol.AuthorityProposal{StatementType: row.GetStatementType(), Statement: row.GetStatement()}, signers, last, 0)
}

// An AuthorityProposal at state: a device proposer counts for the proposed statement, and at k = 1 the proposal
// completes at its own entry, where the proposed statement's rule must hold. A recovery key's proposal takes the kind
// §7.9's Recovery table gives it and never completes at its own entry: Recovery's window holds it, or for a
// recovery-scoped admission one admission signer's cosign completes it.
func configCheckProposal(state *ConfigState, statement *configStatement) error {
	proposal := statement.body.(*protocol.AuthorityProposal)
	proposed, err := configProposedStatement(proposal, statement.signers, statement.n, statement.timeMs)
	if err != nil {
		return err
	}
	targets, _ := configStatementTargets(state, proposed)
	proposer := statement.signers[0]
	statement.proposalKind = bridge.ProposalKind_PROPOSAL_KIND_AUTHORITY
	if proposer.Kind == ConfigSignerRecovery {
		kind, err := state.recoveryProposalKind(proposer, proposed)
		if err != nil {
			return err
		}
		if kind == bridge.ProposalKind_PROPOSAL_KIND_AUTHORITY && len(state.countedAt(statement.signers, targets, statement.timeMs)) != 1 {
			return fmt.Errorf("%w: the recovery key counts for no k of %s", ErrConfigAuthority, proposed.signedType)
		}
		statement.proposalKind = kind
		statement.proposed = proposed
		return nil
	}
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

// An AuthorityProposal's effect: the proposed statement's at completion, else an open proposal, its row holding its
// kind and, for a recovery key's, its window from this entry.
func configApplyProposal(next *configStateBuilder, statement *configStatement) error {
	if statement.completes != nil {
		return configApplyStatement(next, statement.completes, false)
	}
	if statement.proposed == nil {
		return fmt.Errorf("%w: a proposal neither complete nor open", ErrConfigRule)
	}
	proposal := statement.body.(*protocol.AuthorityProposal)
	proposer := statement.signers[0]
	kind := statement.proposalKind
	if kind == bridge.ProposalKind_PROPOSAL_KIND_UNSPECIFIED {
		kind = bridge.ProposalKind_PROPOSAL_KIND_AUTHORITY
	}
	row := &bridge.ProposalRow{
		ProposalId:    bytes.Clone(statement.id[:]),
		StatementType: proposal.GetStatementType(),
		Statement:     bytes.Clone(proposal.GetStatement()),
		ProposedAt:    statement.n,
		NotAfterMs:    statement.header.GetNotAfterMs(),
		Signers:       []*bridge.ProposalSigner{{Signer: proposer.RowsSigner(), At: statement.n}},
		Kind:          uint32(kind),
	}
	if proposer.Kind == ConfigSignerRecovery {
		row.WindowEntry, row.WindowTimeMs = statement.n, statement.timeMs
	}
	next.putProposal(&configProposal{id: statement.id, row: row, statement: statement.proposed})
	return nil
}

// An AuthorityCosign at state: its proposal open and unexpired, and by kind: for k of n a further counted signer, the
// k-th completing it unless Recovery's window holds it, where the proposed statement's rule must hold at this state; for
// a recovery-scoped admission one admission signer's device, which completes it; for a restored binding's admission an
// admission signer's device, which the activation counts when self_admit is off.
func configCheckCosign(state *ConfigState, statement *configStatement) error {
	cosign := statement.body.(*protocol.AuthorityCosign)
	if len(cosign.GetProposalId()) != sha256.Size {
		return fmt.Errorf("%w: a proposal_id of %d bytes", ErrConfigRule, len(cosign.GetProposalId()))
	}
	proposal := state.proposals[[sha256.Size]byte(cosign.GetProposalId())]
	if proposal == nil || !proposal.open(statement.timeMs) {
		return fmt.Errorf("%w: no open proposal with this id", ErrConfigRule)
	}
	cosigner := statement.signers[0]
	targets, _ := configStatementTargets(state, proposal.statement)
	proposed := *proposal.statement
	proposed.signers = append(slices.Clone(proposal.statement.signers), cosigner)
	proposed.n, proposed.timeMs = statement.n, statement.timeMs
	admissionSigner := func() bool {
		_, ok := state.anyMemberDevice([]ConfigSigner{cosigner}, statement.timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
			return !(targets.HasSidecar && signerId == targets.SidecarId) && configRoleAdmits(role)
		})
		return ok
	}
	switch bridge.ProposalKind(proposal.row.GetKind()) {
	case bridge.ProposalKind_PROPOSAL_KIND_RECOVERY_SCOPED:
		if !admissionSigner() {
			return fmt.Errorf("%w: a recovery-scoped admission takes an admission signer's cosign", ErrConfigAuthority)
		}
		if err := configCheckStatement(state, &proposed); err != nil {
			return err
		}
		statement.completes = &proposed
		return nil
	case bridge.ProposalKind_PROPOSAL_KIND_RESTORED:
		if !admissionSigner() {
			return fmt.Errorf("%w: a restored binding's admission takes only an admission signer's cosign", ErrConfigAuthority)
		}
		statement.proposed = &proposed
		return nil
	}
	member, counted := state.countedMember(cosigner, targets, statement.timeMs)
	if !counted {
		return fmt.Errorf("%w: the cosigner is no counted signer for %s", ErrConfigAuthority, proposal.statement.signedType)
	}
	if slices.Contains(state.countedAt(proposal.statement.signers, targets, statement.timeMs), member) {
		return fmt.Errorf("%w: the cosigner's member already counts", ErrConfigAuthority)
	}
	if !proposal.windowed() && cosigner.Kind != ConfigSignerRecovery && state.authorityAt(proposed.signers, targets, statement.timeMs) {
		if err := configCheckStatement(state, &proposed); err != nil {
			return err
		}
		statement.completes = &proposed
		return nil
	}
	statement.proposed = &proposed
	return nil
}

// An AuthorityCosign's effect: one more signer in its proposal's row, a recovery key's restarting its window; at
// completion the proposal closes and the proposed statement takes effect here. A proposal not open on the state being
// built, as a base's new rows may leave it, takes no cosign and the effect ends there.
func configApplyCosign(next *configStateBuilder, statement *configStatement) error {
	proposalId := [sha256.Size]byte(statement.body.(*protocol.AuthorityCosign).GetProposalId())
	proposal := next.proposal(proposalId)
	if proposal == nil || proposal.closedAt != 0 {
		return fmt.Errorf("%w: the proposal is not open here", ErrConfigRule)
	}
	proposed := statement.proposed
	if statement.completes != nil {
		proposed = statement.completes
	}
	if proposed == nil {
		return fmt.Errorf("%w: a cosign neither complete nor open", ErrConfigRule)
	}
	cosigner := statement.signers[0]
	row := proto.Clone(proposal.row).(*bridge.ProposalRow)
	row.Signers = append(row.Signers, &bridge.ProposalSigner{Signer: cosigner.RowsSigner(), At: statement.n})
	if cosigner.Kind == ConfigSignerRecovery {
		row.WindowEntry, row.WindowTimeMs = statement.n, statement.timeMs
	}
	updated := &configProposal{id: proposalId, row: row, statement: proposed}
	if statement.completes != nil {
		updated.closedAt, updated.closed = statement.n, ConfigProposalCompleted
		next.putProposal(updated)
		return configApplyStatement(next, statement.completes, false)
	}
	next.putProposal(updated)
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
