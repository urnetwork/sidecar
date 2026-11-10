// §7.9's Recovery in the verifier (owner decisions 3, 62, 112, 126-128, 149; D-TEAM-21): a member's recovery key, its
// bindings, the proposals it signs and the window that holds them, judged alike at api and every reader. A member M's
// recovery key admits M's new untagged device:
//
//	outside the AdminSet, self_admit on   a plain SidecarAdmit by the key, at its position (scoped)
//	outside the AdminSet, self_admit off  an AuthorityProposal by the key, completing at one cosign by an Owner's,
//	                                        Admin's or IT admin's device (PROPOSAL_KIND_RECOVERY_SCOPED)
//	under a binding a void restored       an AuthorityProposal, activating at an ApiTick 72 h after its entry with no
//	                                        counted cosign, and with self_admit off one such cosign; a plain
//	                                        SidecarAdmit by the key refused (PROPOSAL_KIND_RESTORED; owner decision 149)
//	in the AdminSet                       an AuthorityProposal plus k-1 cosigns, the key counting as one of k,
//	                                        activating at an ApiTick 72 h after the entry of its newest recovery-key
//	                                        signature (PROPOSAL_KIND_AUTHORITY, windowed)
//
// Any authority statement a recovery key signs, in its proposal or a cosign, is pending until such an activation, a
// later recovery cosign restarting the window; a RecoveryVeto between the proposal and the activation closes it
// (config_recovery_veto.go), and so do, as voids, a RecoveryRebind of its subject or of a member whose key signed it,
// an AdminSet change, its subject's removal and a compromise cascade that voids the binding of a key that signed it.
// Rows carry every open proposal with its signers, window and kind (DESIGN-DETAILS 5.2.2), so all of this holds across
// a fold at every reader.
//
// RecoveryBind and RecoveryRebind show in the log only member_id, reason, prev_sha256 and the Ed25519 key's hash; the
// rest is sealed (plan-TEAM-sealed-field-format), so api and readers match bindings by hash, and the anchor that opens
// the sealed genesis_sig is CORE-M2-06's. A recovery key signs as §6.9's Signers fix it: signer_id its member_id and
// key_id the raw Ed25519 key, whose hash must be the member's binding in effect. Its statements need no presence
// countersignature.
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret. On every leg.

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

// §7.9's Recovery window, a protocol constant every reader holds alike: an activation needs a tick at least this long
// after the entry of the proposal's newest recovery-key signature.
const configRecoveryWindowMs = int64(72 * 60 * 60 * 1000)

// Why a proposal closed.
type ConfigProposalClose int

const (
	// its k-th counted signature, or for a recovery-scoped admission its one admission signer's cosign
	ConfigProposalCompleted ConfigProposalClose = iota + 1
	// an ApiTick's activation once Recovery's window ran
	ConfigProposalActivated
	// a RecoveryVeto
	ConfigProposalVetoed
	// a RecoveryRebind of its subject or of a member whose key signed it, an AdminSet change, its subject's removal,
	// or a cascade that voided the binding of a key that signed it
	ConfigProposalVoided
)

// Registers RecoveryBind's and RecoveryRebind's rules.
func init() {
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_RECOVERY_BIND,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckRecoveryBinding,
		apply:      configApplyRecoveryBinding,
		targets:    configRecoveryBindingTargets,
	})
	registerConfigStatementRule(configStatementRule{
		signedType: bridge.SignedType_SIGNED_RECOVERY_REBIND,
		purpose:    bridge.SignedPurposeAuthority,
		check:      configCheckRecoveryBinding,
		apply:      configApplyRecoveryBinding,
		targets:    configRecoveryBindingTargets,
	})
}

// Verifies a statement a member's recovery key signed: signer_id names a member whose binding in effect is the hash of
// key_id, the raw Ed25519 key (bridge.VerifyRecoverySigned). A recovery key signs only a SidecarAdmit, an
// AuthorityProposal and an AuthorityCosign; what each may do is its rule's.
func (self *ConfigState) verifyRecoverySigner(signed *bridge.Signed, purpose string, signedType bridge.SignedType) (ConfigSigner, error) {
	switch signedType {
	case bridge.SignedType_SIGNED_SIDECAR_ADMIT, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, bridge.SignedType_SIGNED_AUTHORITY_COSIGN:
	default:
		return ConfigSigner{}, fmt.Errorf("%w: a recovery key signs no %s", ErrConfigSigner, signedType)
	}
	memberId, err := IdFromBytes(signed.GetSignerId())
	if err != nil {
		return ConfigSigner{}, fmt.Errorf("%w: a recovery signer_id of %d bytes", ErrConfigSigner, len(signed.GetSignerId()))
	}
	member := self.members[memberId]
	if member == nil || len(member.GetRecoveryKeySha256()) != sha256.Size {
		return ConfigSigner{}, fmt.Errorf("%w: no member with a recovery binding", ErrConfigSigner)
	}
	if err := bridge.VerifyRecoverySigned(signed, purpose, signedType, member.GetRecoveryKeySha256()); err != nil {
		return ConfigSigner{}, fmt.Errorf("%w: %w", ErrConfigSigner, err)
	}
	return ConfigSigner{Kind: ConfigSignerRecovery, MemberId: memberId, RecoveryKeySha256: bytes.Clone(member.GetRecoveryKeySha256())}, nil
}

// The member a recovery key's hash is bound to, false when no member's bindings hold it, or more than one's, which
// RecoveryBind refuses: a signer rows name by its key's hash alone.
func (self *ConfigState) recoveryKeyMember(keySha256 []byte) (Id, bool) {
	found, memberId := false, Id{}
	for _, candidateId := range self.MemberIds() {
		for _, binding := range self.members[candidateId].GetBindings() {
			if bytes.Equal(binding.GetKeySha256(), keySha256) {
				if found && memberId != candidateId {
					return Id{}, false
				}
				found, memberId = true, candidateId
				break
			}
		}
	}
	return memberId, found
}

// The member's binding in effect (§7.9's MemberRow.recovery_key_sha256), nil for none: its newest binding no cascade
// voids, which is a restored one while a newer binding is void. The caller must not change it.
func (self *ConfigState) CurrentBinding(memberId Id) *bridge.RecoveryBindingRow {
	member := self.members[memberId]
	if member == nil || len(member.GetRecoveryKeySha256()) == 0 {
		return nil
	}
	for _, binding := range member.GetBindings() {
		if bytes.Equal(binding.GetKeySha256(), member.GetRecoveryKeySha256()) {
			return binding
		}
	}
	return nil
}

// Whether the member's binding in effect is one a void restored (§7.9's cascade): its newest binding is void, so it
// takes no wrap and its admissions activate only by Recovery's window until a signer outside P signs it again.
func (self *ConfigState) BindingRestored(memberId Id) bool {
	member := self.members[memberId]
	bindings := member.GetBindings()
	if len(member.GetRecoveryKeySha256()) == 0 || len(bindings) == 0 {
		return false
	}
	return self.heldInCascadeAt(bindings[0].GetSigner(), bindings[0].GetAt())
}

// Whether a recovery signer's key counts as its member at this state: the member's binding in effect, not one a void
// restored, which counts for no k (owner decision 149).
func (self *ConfigState) recoveryKeyCurrent(signer ConfigSigner) bool {
	member := self.members[signer.MemberId]
	return member != nil && len(signer.RecoveryKeySha256) == sha256.Size &&
		bytes.Equal(member.GetRecoveryKeySha256(), signer.RecoveryKeySha256) && !self.BindingRestored(signer.MemberId)
}

// A binding's member, never counted out: the member's own consented device signs its binding.
func configRecoveryBindingTargets(state *ConfigState, statement *configStatement) ConfigTargets {
	return ConfigTargets{}
}

// A RecoveryBind or RecoveryRebind's fields: the member, the new key's hash, the replaced binding's hash and, for a
// rebind, its reason.
func configRecoveryBindingFields(body proto.Message) (memberBytes []byte, prevSha256 []byte, keySha256 []byte, reason bridge.RecoveryRebindReason, rebind bool) {
	switch binding := body.(type) {
	case *protocol.RecoveryBind:
		return binding.GetMemberId(), binding.GetPrevSha256(), binding.GetEd25519PublicKeySha256(), bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_UNSPECIFIED, false
	case *protocol.RecoveryRebind:
		return binding.GetMemberId(), binding.GetPrevSha256(), binding.GetEd25519PublicKeySha256(), binding.GetReason(), true
	}
	return nil, nil, nil, 0, false
}

// A RecoveryBind or RecoveryRebind: a member of this state; a 32-byte key hash no other member ever bound; prev_sha256
// the binding in effect, empty for a first binding; for a rebind a binding to replace and a reason; signed by the
// member's consented device (§8.5), with authority for an AdminSet member.
func configCheckRecoveryBinding(state *ConfigState, statement *configStatement) error {
	memberBytes, prevSha256, keySha256, reason, rebind := configRecoveryBindingFields(statement.body)
	memberId, err := IdFromBytes(memberBytes)
	if err != nil {
		return fmt.Errorf("%w: a member_id of %d bytes", ErrConfigRule, len(memberBytes))
	}
	member := state.members[memberId]
	switch {
	case member == nil:
		return fmt.Errorf("%w: no such member", ErrConfigRule)
	case len(keySha256) != sha256.Size:
		return fmt.Errorf("%w: a key hash of %d bytes", ErrConfigRule, len(keySha256))
	case !bytes.Equal(prevSha256, member.GetRecoveryKeySha256()):
		return fmt.Errorf("%w: prev_sha256 is not the binding in effect", ErrConfigRule)
	case rebind && len(member.GetRecoveryKeySha256()) == 0:
		return fmt.Errorf("%w: a rebind with no binding to replace", ErrConfigRule)
	case rebind && (reason < bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_ROUTINE || bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_COMPROMISE < reason):
		return fmt.Errorf("%w: a rebind's reason %d", ErrConfigRule, reason)
	}
	if boundTo, bound := state.recoveryKeyMember(keySha256); bound && boundTo != memberId {
		return fmt.Errorf("%w: another member's recovery key", ErrConfigRule)
	}
	acl, err := state.Acl()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrConfigRule, err)
	}
	signer, ok := state.anyMemberDevice(statement.signers, statement.timeMs, func(signerId Id, signerMemberId Id, role bridge.MemberRole) bool {
		return signerMemberId == memberId && acl.ConsentedFor(signerId, memberId)
	})
	if !ok {
		return fmt.Errorf("%w: a recovery binding needs its member's consented device", ErrConfigAuthority)
	}
	if configRoleInAdminSet(member.GetRole()) && !state.authorityAt(statement.signers, ConfigTargets{}, statement.timeMs) {
		return fmt.Errorf("%w: an AdminSet member's recovery binding without authority", ErrConfigAuthority)
	}
	statement.rowSigner = signer
	return nil
}

// A RecoveryBind or RecoveryRebind's effect: the binding, newest first, with its signer and position, in effect from
// here; and each recovery window a rebind voids closes: those of proposals whose subject is the member or that the
// member's key signed.
func configApplyRecoveryBinding(next *configStateBuilder, statement *configStatement) error {
	memberBytes, _, keySha256, reason, _ := configRecoveryBindingFields(statement.body)
	memberId, err := IdFromBytes(memberBytes)
	if err != nil {
		return err
	}
	member := next.memberForWrite(memberId)
	if member == nil {
		return fmt.Errorf("%w: no such member", ErrConfigRule)
	}
	signer := statement.rowSigner
	if signer.Kind == 0 && 0 < len(statement.signers) {
		signer = statement.signers[0]
	}
	binding := &bridge.RecoveryBindingRow{KeySha256: bytes.Clone(keySha256), Signer: signer.RowsSigner(), At: statement.n, Reason: reason}
	member.Bindings = append([]*bridge.RecoveryBindingRow{binding}, member.Bindings...)
	member.RecoveryKeySha256 = bytes.Clone(keySha256)
	configVoidProposals(next, statement.n, func(proposal *configProposal) bool {
		if slices.Contains(configProposalSubjects(next.state, proposal), memberId) {
			return true
		}
		return slices.ContainsFunc(proposal.statement.signers, func(signer ConfigSigner) bool {
			return signer.Kind == ConfigSignerRecovery && signer.MemberId == memberId
		})
	})
	return nil
}

// The members a proposal concerns, whose rebind or removal voids its window: an admission's member, a member record's
// member, and the members an AdminSet changes.
func configProposalSubjects(state *ConfigState, proposal *configProposal) []Id {
	switch body := proposal.statement.body.(type) {
	case *protocol.SidecarAdmit:
		if memberId, err := IdFromBytes(body.GetMemberId()); err == nil {
			return []Id{memberId}
		}
	case *protocol.MemberAdmit:
		if memberId, err := IdFromBytes(body.GetMemberId()); err == nil {
			return []Id{memberId}
		}
	case *bridge.MemberRevoke:
		if memberId, err := IdFromBytes(body.GetMemberId()); err == nil {
			return []Id{memberId}
		}
	}
	targets, _ := configStatementTargets(state, proposal.statement)
	subjects := slices.Clone(targets.MemberIds)
	if targets.HasSidecarMember {
		subjects = append(subjects, targets.SidecarMemberId)
	}
	return subjects
}

// Closes, as voided at n, each open proposal Recovery's window holds that void says.
func configVoidProposals(next *configStateBuilder, n uint64, void func(proposal *configProposal) bool) {
	for _, proposalId := range next.state.proposalIds() {
		proposal := next.proposal(proposalId)
		if proposal.closedAt == 0 && proposal.windowed() && void(proposal) {
			next.closeProposal(proposalId, n, ConfigProposalVoided)
		}
	}
}

// The kind a recovery key's AuthorityProposal takes (§7.9's Recovery table), fixed at its entry: an AdminSet member's
// key, its binding current, proposes as one of k under the window; outside the AdminSet a key proposes only its own
// member's untagged device, restored under a binding a void restored and else recovery-scoped while self_admit is off.
func (self *ConfigState) recoveryProposalKind(signer ConfigSigner, proposed *configStatement) (bridge.ProposalKind, error) {
	member := self.members[signer.MemberId]
	if member == nil {
		return 0, fmt.Errorf("%w: no such member", ErrConfigSigner)
	}
	restored := self.BindingRestored(signer.MemberId)
	if configRoleInAdminSet(member.GetRole()) {
		if restored {
			return 0, fmt.Errorf("%w: an AdminSet member's key under a restored binding counts for no k", ErrConfigAuthority)
		}
		return bridge.ProposalKind_PROPOSAL_KIND_AUTHORITY, nil
	}
	admit, ok := proposed.body.(*protocol.SidecarAdmit)
	if !ok {
		return 0, fmt.Errorf("%w: a recovery key outside the AdminSet proposes only its member's device", ErrConfigAuthority)
	}
	admission, err := configSidecarAdmission(admit)
	if err != nil {
		return 0, err
	}
	if admission.tagged || admission.ephemeral || admission.memberId != signer.MemberId {
		return 0, fmt.Errorf("%w: a recovery key proposes only its member's untagged device", ErrConfigAuthority)
	}
	switch {
	case restored:
		return bridge.ProposalKind_PROPOSAL_KIND_RESTORED, nil
	case !self.SelfAdmit():
		return bridge.ProposalKind_PROPOSAL_KIND_RECOVERY_SCOPED, nil
	}
	return 0, fmt.Errorf("%w: with self_admit on the key admits by a plain SidecarAdmit", ErrConfigRule)
}

// §7.9's Recovery row for a SidecarAdmit a recovery key signs or helps sign: the admission names the key's member and an
// untagged member device. Outside the AdminSet, a plain one takes effect while self_admit is on and the binding is
// current; one completing a recovery-scoped proposal needs an admission signer's device among its signers; one an
// activation carries stands on the window. In the AdminSet only an activation admits, with k counted, the key one of
// them.
func (self *ConfigState) checkRecoveryAdmission(statement *configStatement, admission *configAdmission) (ConfigSigner, error) {
	var recovery ConfigSigner
	for _, signer := range statement.signers {
		if signer.Kind == ConfigSignerRecovery {
			recovery = signer
			break
		}
	}
	if admission.tagged || admission.ephemeral || admission.memberId != recovery.MemberId {
		return ConfigSigner{}, fmt.Errorf("%w: a recovery key admits only its member's untagged device", ErrConfigAuthority)
	}
	member := self.members[recovery.MemberId]
	if member == nil {
		return ConfigSigner{}, fmt.Errorf("%w: no such member", ErrConfigRule)
	}
	if configRoleInAdminSet(member.GetRole()) {
		if !statement.activated {
			return ConfigSigner{}, fmt.Errorf("%w: an AdminSet member's recovery admission waits on Recovery's window", ErrConfigAuthority)
		}
		if !self.authorityAt(statement.signers, admission.targets(), statement.timeMs) {
			return ConfigSigner{}, fmt.Errorf("%w: an AdminSet member's recovery admission without authority", ErrConfigAuthority)
		}
		return recovery, nil
	}
	switch {
	case statement.activated:
		return recovery, nil
	case statement.signed != nil:
		if self.BindingRestored(recovery.MemberId) {
			return ConfigSigner{}, fmt.Errorf("%w: a restored binding's key admits only through Recovery's window", ErrConfigAuthority)
		}
		if !self.SelfAdmit() {
			return ConfigSigner{}, fmt.Errorf("%w: self_admit is off", ErrConfigAuthority)
		}
		return recovery, nil
	}
	signer, ok := self.anyMemberDevice(statement.signers, statement.timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
		return signerId != admission.sidecarId && configRoleAdmits(role)
	})
	if !ok {
		return ConfigSigner{}, fmt.Errorf("%w: a recovery-scoped admission needs an admission signer's cosign", ErrConfigAuthority)
	}
	return signer, nil
}

// An open proposal Recovery's window holds, as a device's recovery_window alarm and veto read it.
type ConfigRecoveryWindow struct {
	// The proposal's row: its kind, signers and window (window_entry, p, and window_time_ms, T_p).
	Row *bridge.ProposalRow
	// The member whose recovery key signed it, or whose restored binding admits.
	MemberId Id
	// The device it admits, nil for another authority statement.
	SidecarId *Id
	// The position it closed at, 0 while open, and why.
	ClosedAt uint64
	Closed   ConfigProposalClose
	// Whether it passed its not_after unactivated, by this state's time.
	Expired bool
}

// The recovery window of a proposal this state holds, open or closed, false for one it does not hold or that no window
// holds. Closed ones leave at the next base, which carries only open proposals.
func (self *ConfigState) RecoveryWindow(proposalId []byte) (*ConfigRecoveryWindow, bool) {
	if len(proposalId) != sha256.Size {
		return nil, false
	}
	proposal := self.proposals[[sha256.Size]byte(proposalId)]
	if proposal == nil || !proposal.windowed() {
		return nil, false
	}
	window := &ConfigRecoveryWindow{
		Row:      proposal.row,
		ClosedAt: proposal.closedAt,
		Closed:   proposal.closed,
		Expired:  proposal.closedAt == 0 && proposal.row.GetNotAfterMs() < self.timeMs,
	}
	for _, signer := range proposal.statement.signers {
		if signer.Kind == ConfigSignerRecovery {
			window.MemberId = signer.MemberId
			break
		}
	}
	if admit, ok := proposal.statement.body.(*protocol.SidecarAdmit); ok {
		if admission, err := configSidecarAdmission(admit); err == nil {
			sidecarId := admission.sidecarId
			window.SidecarId = &sidecarId
			if window.MemberId == (Id{}) {
				window.MemberId = admission.memberId
			}
		}
	}
	return window, true
}

// Every open proposal Recovery's window holds at this state, by proposal_id: what admins' devices show as
// recovery_window and may veto. The caller must not change them.
func (self *ConfigState) PendingProposals() []*bridge.ProposalRow {
	pending := []*bridge.ProposalRow{}
	for _, proposalId := range self.proposalIds() {
		proposal := self.proposals[proposalId]
		if proposal.open(self.timeMs) && proposal.windowed() {
			pending = append(pending, proposal.row)
		}
	}
	return pending
}

// An ApiTick's activation of a proposal (§7.9's activation row) at the tick's state: open and unexpired at the tick's
// time, held by Recovery's window, the tick at least 72 h after its newest recovery-key signature, k counted for an
// authority one or, for a restored binding's admission with self_admit off, one admission signer's cosign, and its
// statement's rule holding at the tick. Returns the statement as it takes effect there.
func (self *ConfigState) checkActivation(proposalId []byte, n uint64, timeMs int64) (*configStatement, error) {
	if len(proposalId) != sha256.Size {
		return nil, fmt.Errorf("%w: an activated id of %d bytes", ErrConfigRule, len(proposalId))
	}
	proposal := self.proposals[[sha256.Size]byte(proposalId)]
	switch {
	case proposal == nil || !proposal.open(timeMs):
		return nil, fmt.Errorf("%w: an activation of no open proposal", ErrConfigRule)
	case !proposal.windowed():
		return nil, fmt.Errorf("%w: an activation of a proposal no window holds", ErrConfigRule)
	case timeMs < proposal.row.GetWindowTimeMs()+configRecoveryWindowMs:
		return nil, fmt.Errorf("%w: an activation before the window ran", ErrConfigRule)
	}
	statement := *proposal.statement
	statement.n, statement.timeMs, statement.activated = n, timeMs, true
	targets, _ := configStatementTargets(self, &statement)
	switch bridge.ProposalKind(proposal.row.GetKind()) {
	case bridge.ProposalKind_PROPOSAL_KIND_AUTHORITY:
		if !self.authorityAt(statement.signers, targets, timeMs) {
			return nil, fmt.Errorf("%w: an activation short of k", ErrConfigAuthority)
		}
	case bridge.ProposalKind_PROPOSAL_KIND_RESTORED:
		if !self.SelfAdmit() {
			if _, ok := self.anyMemberDevice(statement.signers, timeMs, func(signerId Id, memberId Id, role bridge.MemberRole) bool {
				return configRoleAdmits(role)
			}); !ok {
				return nil, fmt.Errorf("%w: a restored binding's admission with self_admit off needs an admission signer's cosign", ErrConfigAuthority)
			}
		}
	default:
		return nil, fmt.Errorf("%w: an activation of kind %d", ErrConfigRule, proposal.row.GetKind())
	}
	if err := configCheckStatement(self, &statement); err != nil {
		return nil, err
	}
	return &statement, nil
}
