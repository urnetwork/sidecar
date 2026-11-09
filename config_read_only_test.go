// D-TEAM-24 on the test network: a read_only device signs itself out and nothing else, at k = 1 and at k = 2, and is
// never a counted signer or a config writer; and the one list every verifier asks.

package sidecar

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Only its own upkeep, reads, receipts and HeadCheck replies; anything else, and anything this list does not know,
// is refused.
func TestReadOnlyAllowsOnlyItsOwnUpkeep(t *testing.T) {
	allowed := []ReadOnlyAct{
		ReadOnlyActSignOut, ReadOnlyActReaderKey, ReadOnlyActKeyPackage, ReadOnlyActPathCommit, ReadOnlyActResync,
		ReadOnlyActAck, ReadOnlyActLeave, ReadOnlyActReadEntry, ReadOnlyActReceiptDeposit, ReadOnlyActHeadCheckReply,
	}
	refused := []ReadOnlyAct{
		ReadOnlyActStatement, ReadOnlyActApprovalDecision, ReadOnlyActWrap, ReadOnlyActGenRotate, ReadOnlyActWelcome,
		ReadOnlyActGroupInfoWrite, ReadOnlyActAddOrRemove, ReadOnlyActEvsHead, ReadOnlyActSocketRegistration,
		ReadOnlyActServiceWrite, 0, ReadOnlyActServiceWrite + 1,
	}
	for _, act := range allowed {
		if !ReadOnlyAllows(act) {
			t.Errorf("act %d refused", act)
		}
	}
	for _, act := range refused {
		if ReadOnlyAllows(act) {
			t.Errorf("act %d allowed", act)
		}
	}
}

// What a read_only device of the owner tries at net, each refused, and then its own sign-out, which lands. proposalId
// names an open proposal it would cosign, nil for none.
func testReadOnlyDeviceSignsOutAndNothingElse(t *testing.T, net *testConfigNet, readOnly testConfigDevice, proposalId []byte) {
	member := testConfigId("m")
	net.admitMember(net.owner, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	memberDevice := net.device("m device", member)
	net.admitDevice(net.owner, memberDevice, 0)
	statements := []struct {
		signedType bridge.SignedType
		body       proto.Message
	}{
		{signedType: bridge.SignedType_SIGNED_ADMIN_SET, body: &protocol.AdminSet{Header: net.header(), Owners: [][]byte{net.ownerMemberId.Bytes()}}},
		{signedType: bridge.SignedType_SIGNED_MEMBER_ADMIT, body: net.memberAdmitStatement("by a page Worker")},
		{signedType: bridge.SignedType_SIGNED_MEMBER_REVOKE, body: &bridge.MemberRevoke{Header: net.header(), MemberId: member.Bytes()}},
		{signedType: bridge.SignedType_SIGNED_SIDECAR_ADMIT, body: net.admission(net.device("m worker", member), nil, false, 0, 0)},
		{signedType: bridge.SignedType_SIGNED_SIDECAR_REVOKE, body: net.revocation(memberDevice, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)},
		{signedType: bridge.SignedType_SIGNED_ADMISSION_CONFIRM, body: &protocol.AdmissionConfirm{Header: net.header(), SidecarId: memberDevice.sidecarId.Bytes()}},
		{signedType: bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, body: &protocol.AuthorityProposal{
			Header: net.header(), StatementType: uint32(bridge.SignedType_SIGNED_MEMBER_ADMIT),
			Statement: testConfigMarshal(t, net.memberAdmitStatement("proposed by a page Worker")),
		}},
		{signedType: bridge.SignedType_SIGNED_OWNER_CONFIRM, body: &protocol.OwnerConfirm{Header: net.header(), SidecarId: memberDevice.sidecarId.Bytes()}},
	}
	if proposalId != nil {
		statements = append(statements, struct {
			signedType bridge.SignedType
			body       proto.Message
		}{signedType: bridge.SignedType_SIGNED_AUTHORITY_COSIGN, body: &protocol.AuthorityCosign{Header: net.header(), ProposalId: proposalId}})
	}
	for _, statement := range statements {
		verdict := net.post(readOnly, statement.signedType, statement.body)
		if verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigReadOnly) {
			t.Errorf("%s: %v", statement.signedType, verdict.Refusal)
		}
	}
	state := net.log.State()
	if state.IsConfigWriter(readOnly.sidecarId) {
		t.Error("a read_only device writes config")
	}
	if counted := state.Counted([]ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: readOnly.sidecarId}}, ConfigTargets{}); len(counted) != 0 {
		t.Error("a read_only device counts")
	}
	net.mustPost(readOnly, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(readOnly, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	if net.log.State().SidecarRow(readOnly.sidecarId).GetRevokedAt() == 0 {
		t.Error("the sign-out did not land")
	}
}

// At k = 1, a personal network's owner admits its page Worker alone, and the Worker signs only its own sign-out.
func TestAReadOnlyDeviceSignsOutAndNothingElseAtOne(t *testing.T) {
	net := newTestConfigNet(t)
	worker := net.device("owner page worker", net.ownerMemberId)
	net.admitDevice(net.owner, worker, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	if !net.log.State().ReadOnly(worker.sidecarId) {
		t.Fatal("not read_only")
	}
	testReadOnlyDeviceSignsOutAndNothingElse(t, net, worker, nil)
}

// At k = 2, an admin's page Worker is admitted on a proposal and a cosign, and its cosign of another proposal is
// refused like everything else but its sign-out.
func TestAReadOnlyDeviceSignsOutAndNothingElseAtTwo(t *testing.T) {
	team := newTestConfigTeam(t)
	worker := team.device("owner page worker", team.ownerMemberId)
	_, admitId := team.propose(team.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		team.admission(worker, nil, false, 0, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)))
	if verdict := team.cosign(team.adminB, admitId); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	memberX := testConfigId("x")
	team.admitMember(team.owner, memberX, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	_, openId := team.propose(team.adminC, bridge.SignedType_SIGNED_ADMIN_SET, team.adminSet(0, memberX))
	testReadOnlyDeviceSignsOutAndNothingElse(t, team.testConfigNet, worker, openId)
}
