// §7.9's authority on the test network: k of n with its default and its forced 1, who counts, and proposals with
// their cosigns, §22.7's admission suite's authority rows at k = 2 among them.

package sidecar

import (
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A team: the owner and two admins, b and c, so k = 2 of n = 3, each with one admitted device.
type testConfigTeam struct {
	*testConfigNet
	adminB testConfigDevice
	adminC testConfigDevice
}

// The team, built at k = 1 before its AdminSet grows to three, each admin's device its member's first admission from an
// invite, so consented (§8.5's invited clause).
func newTestConfigTeam(t testing.TB) *testConfigTeam {
	net := newTestConfigNet(t)
	team := &testConfigTeam{testConfigNet: net}
	memberB, memberC := testConfigId("admin b"), testConfigId("admin c")
	net.admitMember(net.owner, memberB, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	net.admitMember(net.owner, memberC, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	team.adminB = net.device("admin b laptop", memberB)
	team.adminC = net.device("admin c laptop", memberC)
	net.admitDevice(net.owner, team.adminB, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	net.admitDevice(net.owner, team.adminC, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, team.adminSet(0))
	if k, n := net.log.State().Threshold(); k != 2 || n != 3 {
		t.Fatalf("k %d of n %d", k, n)
	}
	return team
}

// An AdminSet of the owner, b and c, plus extra admins.
func (self *testConfigTeam) adminSet(threshold uint32, extraAdmins ...Id) *protocol.AdminSet {
	adminSet := &protocol.AdminSet{
		Header:    self.header(),
		Owners:    [][]byte{self.ownerMemberId.Bytes()},
		Admins:    [][]byte{self.adminB.memberId.Bytes(), self.adminC.memberId.Bytes()},
		Threshold: threshold,
	}
	for _, admin := range extraAdmins {
		adminSet.Admins = append(adminSet.Admins, admin.Bytes())
	}
	return adminSet
}

// Signs and sequences an AuthorityProposal of body, returning its verdict and its proposal_id.
func (self *testConfigNet) propose(signer testConfigDevice, signedType bridge.SignedType, body proto.Message) (ConfigVerdict, []byte) {
	self.t.Helper()
	proposal := &protocol.AuthorityProposal{
		Header:        self.header(),
		StatementType: uint32(signedType),
		Statement:     testConfigMarshal(self.t, body),
	}
	verdict := self.post(signer, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, proposal)
	return verdict, verdict.StatementId[:]
}

// Signs and sequences an AuthorityCosign of a proposal.
func (self *testConfigNet) cosign(signer testConfigDevice, proposalId []byte) ConfigVerdict {
	self.t.Helper()
	return self.post(signer, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, &protocol.AuthorityCosign{Header: self.header(), ProposalId: proposalId})
}

// k is 1 whenever n <= 2, 2 by default from n = 3, and the AdminSet's threshold when set.
func TestThresholdDefaultsAndTheForcedOne(t *testing.T) {
	net := newTestConfigNet(t)
	if k, n := net.log.State().Threshold(); k != 1 || n != 1 {
		t.Errorf("one owner: k %d of n %d", k, n)
	}
	memberB, memberC, memberD := testConfigId("b"), testConfigId("c"), testConfigId("d")
	for _, member := range []Id{memberB, memberC, memberD} {
		net.admitMember(net.owner, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	}
	adminSet := func(threshold uint32, admins ...Id) *protocol.AdminSet {
		adminSet := &protocol.AdminSet{Header: net.header(), Owners: [][]byte{net.ownerMemberId.Bytes()}, Threshold: threshold}
		for _, admin := range admins {
			adminSet.Admins = append(adminSet.Admins, admin.Bytes())
		}
		return adminSet
	}
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, adminSet(2, memberB), ErrConfigRule)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, adminSet(0, memberB))
	if k, n := net.log.State().Threshold(); k != 1 || n != 2 {
		t.Errorf("two: k %d of n %d", k, n)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, adminSet(1, memberB))
	if k, n := net.log.State().Threshold(); k != 1 || n != 2 {
		t.Errorf("two, threshold 1: k %d of n %d", k, n)
	}
	// at k = 1 the owner adds two admins alone, which neither of them counts toward
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, adminSet(1, memberB, memberC, memberD), ErrConfigRule)
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, adminSet(5, memberB, memberC, memberD), ErrConfigRule)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, adminSet(3, memberB, memberC, memberD))
	if k, n := net.log.State().Threshold(); k != 3 || n != 4 {
		t.Errorf("four, threshold 3: k %d of n %d", k, n)
	}
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_ADMIN_SET, adminSet(0, memberB), ErrConfigAuthority)
}

// §22.7: at k = 2 one signer's authority statement is refused, whichever kind it is.
func TestOneSignersAuthorityStatementIsRefusedAtTwo(t *testing.T) {
	team := newTestConfigTeam(t)
	team.mustRefuse(team.owner, bridge.SignedType_SIGNED_ADMIN_SET, team.adminSet(0), ErrConfigAuthority)
	team.mustRefuse(team.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{
		Header: team.header(), MemberId: team.adminB.memberId.Bytes(),
	}, ErrConfigAuthority)
	phone := team.device("owner phone", team.ownerMemberId)
	team.mustRefuse(team.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(phone, nil, false, 0, 0), ErrConfigAuthority)
	team.mustRefuse(team.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, &bridge.SidecarRevoke{
		Header: team.header(), SidecarId: team.adminB.sidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED,
	}, ErrConfigAuthority)
	team.mustRefuse(team.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
		Header: team.header(), MemberId: team.adminC.memberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER,
	}, ErrConfigAuthority)
}

// §22.7: AdminSet changes both ways, each a proposal and one cosign at k = 2, the change taking effect at the cosign.
func TestAdminSetChangesBothWaysOnAProposalAndACosign(t *testing.T) {
	team := newTestConfigTeam(t)
	memberX := testConfigId("x")
	team.admitMember(team.owner, memberX, bridge.MemberRole_MEMBER_ROLE_MEMBER)

	proposal, proposalId := team.propose(team.owner, bridge.SignedType_SIGNED_ADMIN_SET, team.adminSet(0, memberX))
	if !proposal.Accepted() || proposal.CompletedProposalId != nil {
		t.Fatalf("the proposal: %v, completed %x", proposal.Refusal, proposal.CompletedProposalId)
	}
	if team.log.State().Member(memberX).GetRole() != bridge.MemberRole_MEMBER_ROLE_MEMBER {
		t.Fatal("a proposal took effect alone")
	}
	cosign := team.cosign(team.adminB, proposalId)
	if !cosign.Accepted() || !slices.Equal(cosign.CompletedProposalId, proposalId) {
		t.Fatalf("the cosign: %v", cosign.Refusal)
	}
	if role := team.log.State().Member(memberX).GetRole(); role != bridge.MemberRole_MEMBER_ROLE_ADMIN {
		t.Errorf("x is %s", role)
	}
	if k, n := team.log.State().Threshold(); k != 2 || n != 4 {
		t.Errorf("k %d of n %d", k, n)
	}
	if len(team.log.State().OpenProposalIds()) != 0 {
		t.Error("a completed proposal stays open")
	}

	_, removalId := team.propose(team.owner, bridge.SignedType_SIGNED_ADMIN_SET, team.adminSet(0))
	if verdict := team.cosign(team.adminC, removalId); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	if role := team.log.State().Member(memberX).GetRole(); role != bridge.MemberRole_MEMBER_ROLE_MEMBER {
		t.Errorf("x is %s after the removal", role)
	}
}

// §22.7: a target never counts: an AdminSet change's target member's cosign, a MemberRevoke's target's, nor the
// target device proposing its own revocation.
func TestATargetNeverCounts(t *testing.T) {
	team := newTestConfigTeam(t)
	withoutB := &protocol.AdminSet{
		Header: team.header(), Owners: [][]byte{team.ownerMemberId.Bytes()}, Admins: [][]byte{team.adminC.memberId.Bytes()},
	}
	_, proposalId := team.propose(team.owner, bridge.SignedType_SIGNED_ADMIN_SET, withoutB)
	if verdict := team.cosign(team.adminB, proposalId); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigAuthority) {
		t.Errorf("the target's cosign: %v", verdict.Refusal)
	}

	_, revokeId := team.propose(team.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{
		Header: team.header(), MemberId: team.adminC.memberId.Bytes(),
	})
	if verdict := team.cosign(team.adminC, revokeId); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigAuthority) {
		t.Errorf("a MemberRevoke's target's cosign: %v", verdict.Refusal)
	}

	selfProposal, _ := team.propose(team.adminB, bridge.SignedType_SIGNED_SIDECAR_REVOKE, &bridge.SidecarRevoke{
		Header: team.header(), SidecarId: team.adminB.sidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST,
	})
	if selfProposal.Accepted() || !errors.Is(selfProposal.Refusal, ErrConfigAuthority) {
		t.Errorf("the target device's own proposal: %v", selfProposal.Refusal)
	}

	if verdict := team.cosign(team.adminB, revokeId); !verdict.Accepted() {
		t.Errorf("another admin's cosign: %v", verdict.Refusal)
	}
	if team.log.State().Member(team.adminC.memberId) != nil {
		t.Error("c survived its revocation")
	}
}

// §22.7: an AdminSet member's existing device counts as one for its own new device, and its phone revokes its laptop
// on one other admin's cosign.
func TestAnAdminSetMembersOwnDeviceCountsAsOne(t *testing.T) {
	team := newTestConfigTeam(t)
	phone := team.device("owner phone", team.ownerMemberId)
	_, admitId := team.propose(team.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(phone, nil, false, 0, 0))
	if team.log.State().SidecarRow(phone.sidecarId) != nil {
		t.Fatal("an open proposal admitted")
	}
	if verdict := team.cosign(team.adminB, admitId); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	row := team.log.State().SidecarRow(phone.sidecarId)
	if row == nil || row.GetAdmittedAt() != team.n {
		t.Fatal("the phone was not admitted at the cosign")
	}
	if len(row.GetAdmissionSigners()) != 2 {
		t.Errorf("admission signers %x", row.GetAdmissionSigners())
	}
	if !team.log.State().IsConfigWriter(phone.sidecarId) {
		t.Error("the owner's new device writes no config")
	}

	_, revokeId := team.propose(phone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, &bridge.SidecarRevoke{
		Header: team.header(), SidecarId: team.owner.sidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST,
	})
	if verdict := team.cosign(team.adminC, revokeId); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	if team.log.State().SidecarRow(team.owner.sidecarId).GetRevokedAt() != team.n {
		t.Error("the laptop is not revoked at the cosign")
	}
}

// An IT admin is in the AdminSet but counts toward nothing but its own devices: its device counts as one for its new
// device, and alone it cannot propose another's.
func TestAnItAdminsDeviceCountsOnlyForItsOwnDevices(t *testing.T) {
	team := newTestConfigTeam(t)
	itAdmin := testConfigId("it admin")
	team.admitMember(team.owner, itAdmin, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	itLaptop := team.device("it laptop", itAdmin)
	team.admitDevice(team.owner, itLaptop, 0)
	withIt := team.adminSet(0)
	withIt.ItAdmins = [][]byte{itAdmin.Bytes()}
	_, setId := team.propose(team.owner, bridge.SignedType_SIGNED_ADMIN_SET, withIt)
	if verdict := team.cosign(team.adminB, setId); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}

	itPhone := team.device("it phone", itAdmin)
	_, admitId := team.propose(itLaptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(itPhone, nil, false, 0, 0))
	if verdict := team.cosign(team.adminC, admitId); !verdict.Accepted() {
		t.Fatalf("the IT admin's own new device: %v", verdict.Refusal)
	}
	other := team.device("owner tablet", team.ownerMemberId)
	proposal, _ := team.propose(itLaptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(other, nil, false, 0, 0))
	if proposal.Accepted() || !errors.Is(proposal.Refusal, ErrConfigAuthority) {
		t.Errorf("an IT admin proposing an owner's device: %v", proposal.Refusal)
	}
}

// A member's second device adds nothing its first already counted, and an expired proposal takes no cosign.
func TestACosignMustBeAFurtherCountedSignerBeforeExpiry(t *testing.T) {
	team := newTestConfigTeam(t)
	phone := team.device("owner phone", team.ownerMemberId)
	_, admitId := team.propose(team.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(phone, nil, false, 0, 0))
	team.cosign(team.adminB, admitId)

	memberX := testConfigId("x")
	team.admitMember(team.owner, memberX, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	_, proposalId := team.propose(team.owner, bridge.SignedType_SIGNED_ADMIN_SET, team.adminSet(0, memberX))
	if verdict := team.cosign(phone, proposalId); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigAuthority) {
		t.Errorf("the proposer's member again: %v", verdict.Refusal)
	}

	team.timeMs += 2 * 60 * 60 * 1000
	if verdict := team.cosign(team.adminC, proposalId); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigRule) {
		t.Errorf("an expired proposal: %v", verdict.Refusal)
	}
	if verdict := team.cosign(team.adminC, make([]byte, sha256.Size)); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigRule) {
		t.Errorf("no such proposal: %v", verdict.Refusal)
	}
}

// At k = 1 a proposal completes at its own entry, and its id is the completed one; a proposal of a type no
// proposal carries yet, or of a proposal, is refused.
func TestAProposalAtOneCompletesAtItsOwnEntry(t *testing.T) {
	net := newTestConfigNet(t)
	verdict, proposalId := net.propose(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("proposed"))
	if !verdict.Accepted() || !slices.Equal(verdict.CompletedProposalId, proposalId) {
		t.Fatalf("got %v, completed %x", verdict.Refusal, verdict.CompletedProposalId)
	}
	if net.log.State().Member(testConfigId("proposed")) == nil {
		t.Error("the proposed statement did not take effect")
	}
	keyRegister, _ := net.propose(net.owner, bridge.SignedType_SIGNED_KEY_REGISTER, &protocol.KeyRegister{Header: net.header()})
	if keyRegister.Accepted() || !errors.Is(keyRegister.Refusal, ErrConfigRuleMissing) {
		t.Errorf("a KeyRegister proposal: %v", keyRegister.Refusal)
	}
	nested, _ := net.propose(net.owner, bridge.SignedType_SIGNED_AUTHORITY_COSIGN, &protocol.AuthorityCosign{Header: net.header()})
	if nested.Accepted() {
		t.Error("a proposal of a cosign")
	}
}

// Rows carry every open proposal (DESIGN-DETAILS 5.2.2), so one a base folds stays open on every reader alike, as does
// one in the base's tail, and a cosign completes either.
func TestAProposalABaseFoldsStaysOpen(t *testing.T) {
	team := newTestConfigTeam(t)
	memberX, memberY := testConfigId("x"), testConfigId("y")
	team.admitMember(team.owner, memberX, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	team.admitMember(team.owner, memberY, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	_, foldedId := team.propose(team.owner, bridge.SignedType_SIGNED_ADMIN_SET, team.adminSet(0, memberX))
	foldPoint := team.n
	_, tailId := team.propose(team.owner, bridge.SignedType_SIGNED_ADMIN_SET, team.adminSet(0, memberY))
	team.fold(team.owner, foldPoint, 2)

	open := team.log.State().OpenProposalIds()
	if len(open) != 2 || !slices.ContainsFunc(open, func(id []byte) bool { return slices.Equal(id, tailId) }) ||
		!slices.ContainsFunc(open, func(id []byte) bool { return slices.Equal(id, foldedId) }) {
		t.Fatalf("open after the base: %x", open)
	}
	testConfigStatesEqual(t, team.newReader().State(), team.log.State())
	if verdict := team.cosign(team.adminB, foldedId); !verdict.Accepted() {
		t.Errorf("the folded proposal: %v", verdict.Refusal)
	}
	if team.log.State().Member(memberX).GetRole() != bridge.MemberRole_MEMBER_ROLE_ADMIN {
		t.Error("x is no admin")
	}
	if verdict := team.cosign(team.adminB, tailId); !verdict.Accepted() {
		t.Errorf("the tail's proposal: %v", verdict.Refusal)
	}
	if team.log.State().Member(memberY).GetRole() != bridge.MemberRole_MEMBER_ROLE_ADMIN {
		t.Error("y is no admin")
	}
}

// A completion re-applied in a base's tail keeps its verdict: the proposed statement stands on the new rows, and a
// new device starting at that base reaches the same state.
func TestACompletionInABasesTailStands(t *testing.T) {
	team := newTestConfigTeam(t)
	foldPoint := team.n
	phone := team.device("owner phone", team.ownerMemberId)
	_, admitId := team.propose(team.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(phone, nil, false, 0, 0))
	team.cosign(team.adminB, admitId)
	team.fold(team.owner, foldPoint, 2)
	if team.log.State().SidecarRow(phone.sidecarId) == nil {
		t.Fatal("the completion did not re-apply")
	}
	restored, err := RestoreConfigLog(testConfigLogSettings(), team.log.Retained(), team.source)
	if err != nil {
		t.Fatal(err)
	}
	testConfigStatesEqual(t, restored.State(), team.log.State())
}

// Counted on a state: each member once, never a revoked device or a target, never a member outside the Owners and
// Admins.
func TestCountedCountsEachMemberOnce(t *testing.T) {
	team := newTestConfigTeam(t)
	phone := team.device("owner phone", team.ownerMemberId)
	_, admitId := team.propose(team.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, team.admission(phone, nil, false, 0, 0))
	team.cosign(team.adminB, admitId)
	state := team.log.State()
	sidecar := func(device testConfigDevice) ConfigSigner {
		return ConfigSigner{Kind: ConfigSignerSidecar, SidecarId: device.sidecarId}
	}
	signers := []ConfigSigner{sidecar(team.owner), sidecar(phone), sidecar(team.adminB)}
	if counted := state.Counted(signers, ConfigTargets{}); len(counted) != 2 {
		t.Errorf("counted %v", counted)
	}
	if counted := state.Counted(signers, ConfigTargets{MemberIds: []Id{team.adminB.memberId}}); len(counted) != 1 {
		t.Errorf("with b a target: %v", counted)
	}
	if !state.Authority(signers, ConfigTargets{}) || state.Authority(signers[:2], ConfigTargets{}) {
		t.Error("authority")
	}
	recovery := ConfigSigner{Kind: ConfigSignerRecovery, MemberId: team.adminC.memberId, RecoveryKeySha256: make([]byte, sha256.Size)}
	if counted := state.Counted([]ConfigSigner{recovery}, ConfigTargets{}); len(counted) != 0 {
		t.Error("a recovery key counted before TEAM-M2-05")
	}
}
