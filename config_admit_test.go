// §7.9's admission and removal rules on the test network: §22.7's admission suite's rows outside the AdminSet, tagged
// admissions within tagOwners, each record's shape, replays of admitted ids, idempotent revocations, and the hooks a
// compromise revocation and a park's lift wait on.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A member outside the AdminSet with one consented device, its first, admitted by the owner from an invite.
func (self *testConfigNet) consentedMember(label string) (Id, testConfigDevice) {
	self.t.Helper()
	member := testConfigId(label)
	self.admitMember(self.owner, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	first := self.device(label+" first device", member)
	self.admitDevice(self.owner, first, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	acl, err := self.log.State().Acl()
	if err != nil {
		self.t.Fatal(err)
	}
	if !acl.ConsentedFor(first.sidecarId, member) {
		self.t.Fatal("the invited first device is not consented")
	}
	return member, first
}

// A SidecarRevoke at the tip.
func (self *testConfigNet) revocation(device testConfigDevice, reason bridge.SidecarRevokeReason) *bridge.SidecarRevoke {
	return &bridge.SidecarRevoke{Header: self.header(), SidecarId: device.sidecarId.Bytes(), Reason: reason}
}

// §22.7: outside the AdminSet, M's consented device admits M's device unless self_admit is off, and revokes one
// either way; an admin's device admits whatever self_admit says.
func TestOutsideTheAdminSetAMembersDeviceAdmitsUnlessSelfAdmitIsOff(t *testing.T) {
	net := newTestConfigNet(t)
	member, first := net.consentedMember("m")
	second := net.device("m second", member)
	net.admitDevice(first, second, 0)
	row := net.log.State().SidecarRow(second.sidecarId)
	if row.GetLiveSince() != net.n || !bytes.Equal(row.GetAdmissionSigners()[0], first.sidecarId.Bytes()) || len(row.GetSponsor()) != 0 {
		t.Errorf("the row: %v", row)
	}

	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(2))] = &protocol.ServiceSettings{SelfAdmit: protocol.SelfAdmitMode_SELF_ADMIT_MODE_OFF}
	net.fold(net.owner, net.n, 2)
	third := net.device("m third", member)
	net.mustRefuse(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(third, nil, false, 0, 0), ErrConfigAuthority)
	net.mustPost(first, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(second, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	net.admitDevice(net.owner, third, 0)
}

// A rows-only reader cannot open the head that holds self_admit, so a member's own admission fails closed there
// (question team-m2-02-self-admit-at-rows-only-readers), while an admin's still lands.
func TestASelfAdmissionFailsClosedWhereSettingsAreUnknown(t *testing.T) {
	net := newTestConfigNet(t)
	member, first := net.consentedMember("m")
	net.log.rowsOnly = true
	net.fold(net.owner, net.n, 2)
	if _, known := net.log.State().Settings(); known {
		t.Fatal("a rows-only reader knows the settings")
	}
	second := net.device("m second", member)
	net.mustRefuse(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(second, nil, false, 0, 0), ErrConfigSettingsUnknown)
	net.admitDevice(net.owner, second, 0)
}

// A member's device that nothing consented admits nothing, nor does a device of another member, and no device admits
// itself.
func TestOnlyAConsentedDeviceOfTheMemberAdmitsAlone(t *testing.T) {
	net := newTestConfigNet(t)
	member, _ := net.consentedMember("m")
	unconsented := net.device("m unconsented", member)
	net.admitDevice(net.owner, unconsented, 0)
	newDevice := net.device("m new", member)
	net.mustRefuse(unconsented, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(newDevice, nil, false, 0, 0), ErrConfigAuthority)

	_, otherFirst := net.consentedMember("other")
	net.mustRefuse(otherFirst, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(newDevice, nil, false, 0, 0), ErrConfigAuthority)
	net.mustRefuse(otherFirst, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(unconsented, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST), ErrConfigAuthority)
}

// A tagged admission needs a device of a member who owns each of its tags (§8's tagOwners), whose member then
// sponsors it; that member's device revokes it, and an admin's does too.
func TestATaggedAdmissionNeedsAnOwnerOfEachTag(t *testing.T) {
	net := newTestConfigNet(t)
	member, first := net.consentedMember("tag owner")
	tagCi, tagDeploy := testConfigId("tag ci"), testConfigId("tag deploy")
	net.withTagOwner(tagCi, member)
	expiry := net.timeMs + 24*60*60*1000

	agent := net.device("ci agent", Id{})
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{tagCi}, false, expiry, 0), ErrConfigAuthority)
	net.mustRefuse(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{tagCi, tagDeploy}, false, expiry, 0), ErrConfigAuthority)
	net.mustPost(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{tagCi}, false, expiry, 0))
	row := net.log.State().SidecarRow(agent.sidecarId)
	if !bytes.Equal(row.GetSponsor(), member.Bytes()) || row.GetLiveSince() != 0 || row.GetNotAfter() != expiry {
		t.Errorf("the agent's row: %v", row)
	}

	second := net.device("ci agent two", Id{})
	net.mustPost(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(second, []Id{tagCi}, false, expiry, 0))
	net.mustPost(first, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(second, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
}

// Each shape §7.9's SidecarAdmit row and replay row refuse.
func TestSidecarAdmitShapesAreRefused(t *testing.T) {
	net := newTestConfigNet(t)
	member := testConfigId("m")
	net.admitMember(net.owner, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	expiry := net.timeMs + 24*60*60*1000
	device := net.device("m device", member)
	tagId := testConfigId("tag")
	cases := []struct {
		name   string
		mutate func(admit *protocol.SidecarAdmit)
	}{
		{name: "a member and tags", mutate: func(admit *protocol.SidecarAdmit) { admit.TagIds = [][]byte{tagId.Bytes()} }},
		{name: "neither", mutate: func(admit *protocol.SidecarAdmit) { admit.MemberId = nil }},
		{name: "no such member", mutate: func(admit *protocol.SidecarAdmit) { admit.MemberId = testConfigId("nobody").Bytes() }},
		{name: "a member device with not_after", mutate: func(admit *protocol.SidecarAdmit) { admit.NotAfter = expiry }},
		{name: "an ephemeral one without", mutate: func(admit *protocol.SidecarAdmit) { admit.Ephemeral = true }},
		{name: "an ephemeral one already expired", mutate: func(admit *protocol.SidecarAdmit) {
			admit.Ephemeral, admit.NotAfter = true, net.timeMs
		}},
		{name: "an unknown capability", mutate: func(admit *protocol.SidecarAdmit) { admit.Capabilities = 8 }},
		{name: "another network", mutate: func(admit *protocol.SidecarAdmit) { admit.NetworkId = testConfigId("other").Bytes() }},
		{name: "a short identity key", mutate: func(admit *protocol.SidecarAdmit) { admit.IdentityPublicKey = admit.IdentityPublicKey[:16] }},
		{name: "another algorithm", mutate: func(admit *protocol.SidecarAdmit) { admit.IdentityAlg = "rsa" }},
		{name: "the genesis device's id", mutate: func(admit *protocol.SidecarAdmit) { admit.SidecarId = net.owner.sidecarId.Bytes() }},
		{name: "a short sidecar_id", mutate: func(admit *protocol.SidecarAdmit) { admit.SidecarId = admit.SidecarId[:8] }},
	}
	for _, c := range cases {
		admit := net.admission(device, nil, false, 0, 0)
		c.mutate(admit)
		verdict := net.post(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, admit)
		if verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigRule) {
			t.Errorf("%s: %v", c.name, verdict.Refusal)
		}
	}
	tagged := net.admission(net.device("tagged twice", Id{}), []Id{tagId, tagId}, false, expiry, 0)
	if verdict := net.post(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, tagged); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigRule) {
		t.Errorf("a tag twice: %v", verdict.Refusal)
	}
}

// §22.7: replays of admitted ids are refused: the same statement again as a repeat, a new admission of the same
// sidecar_id as admitted before, live or revoked.
func TestReplaysOfAdmittedIdsAreRefused(t *testing.T) {
	net := newTestConfigNet(t)
	member := testConfigId("m")
	net.admitMember(net.owner, member, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	device := net.device("m device", member)
	net.admitDevice(net.owner, device, 0)
	admitted := net.entries[len(net.entries)-1]
	admittedEntry := net.statementOf(admitted)

	if verdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, admittedEntry)); verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigReplay) {
		t.Errorf("the same statement again: %v", verdict.Refusal)
	}
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(device, nil, false, 0, 0), ErrConfigRule)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(device, nil, false, 0, 0), ErrConfigRule)
	if verdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, admittedEntry)); verdict.Accepted() {
		t.Error("the first admission again after the revocation")
	}
}

// The Signed an entry carries.
func (self *testConfigNet) statementOf(entryBytes []byte) []byte {
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		self.t.Fatal(err)
	}
	return entry.GetBody()
}

// Revocations are idempotent: a second takes effect as nothing and keeps the first position; reaped names only an
// ephemeral admission; since_n rides only a compromise revocation, which waits on TEAM-M2-04's cascade; and a device
// signs itself out.
func TestSidecarRevokeReasonsAndRepeats(t *testing.T) {
	net := newTestConfigNet(t)
	member, first := net.consentedMember("m")
	laptop := net.device("m laptop", member)
	net.admitDevice(first, laptop, 0)
	worker := net.device("m worker", member)
	net.mustPost(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(worker, nil, true, net.timeMs+60*60*1000, 0))

	net.mustRefuse(first, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REAPED), ErrConfigRule)
	compromise := net.revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE)
	compromise.SinceN = 3
	net.mustRefuse(first, bridge.SignedType_SIGNED_SIDECAR_REVOKE, compromise, ErrConfigRuleMissing)
	withSince := net.revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	withSince.SinceN = 3
	net.mustRefuse(first, bridge.SignedType_SIGNED_SIDECAR_REVOKE, withSince, ErrConfigRule)
	net.mustRefuse(first, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_UNSPECIFIED), ErrConfigRule)

	revoked := net.mustPost(first, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	if at := net.log.State().SidecarRow(laptop.sidecarId).GetRevokedAt(); at != revoked.Pin.GetVersion() {
		t.Errorf("revoked at %d, first at %d", at, revoked.Pin.GetVersion())
	}
	net.mustPost(first, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(worker, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REAPED))
	net.mustPost(first, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(first, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	if net.log.State().SidecarRow(first.sidecarId).GetRevokedAt() == 0 {
		t.Error("the device did not sign itself out")
	}
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(net.device("never admitted", member), bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST), ErrConfigRule)
}

// A lost or removed revocation of a Delegation's agent drops that Delegation's key and leaves it admitting; a reap
// drops nothing (§10.5, D-TEAM-30).
func TestALostRevocationDropsTheDelegationsKey(t *testing.T) {
	net := newTestConfigNet(t)
	tagId := testConfigId("tag ci")
	delegationId := sha256.Sum256([]byte("a delegation"))
	expiry := net.timeMs + 24*60*60*1000
	state := net.log.State()
	rows := state.Rows()
	rows.Delegations = append(rows.Delegations, &bridge.DelegationRow{
		DelegationId: delegationId[:], Signer: net.owner.sidecarId.Bytes(), At: 1, TagAtoms: [][]byte{tagId.Bytes()}, NotAfter: expiry,
	})
	agents := []testConfigDevice{net.device("agent one", Id{}), net.device("agent two", Id{})}
	for i, agent := range agents {
		rows.Sidecars = append(rows.Sidecars, &bridge.SidecarRow{
			SidecarId: agent.sidecarId.Bytes(), AdmittedAt: 1, DelegationId: delegationId[:], NotAfter: expiry,
			IdentityPublicKey: agent.publicKey(), IdentityAlg: configIdentityAlgEd25519, TagIds: [][]byte{tagId.Bytes()},
			Ephemeral: i == 1,
		})
	}
	net.pushBase(net.owner, rows, net.n, 2, 0)

	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(agents[1], bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REAPED))
	if net.log.State().Delegation(delegationId[:]).GetKeyDroppedAt() != 0 {
		t.Error("a reap dropped the key")
	}
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(agents[0], bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	delegation := net.log.State().Delegation(delegationId[:])
	if delegation.GetKeyDroppedAt() != revoked.Pin.GetVersion() || delegation.GetEndedAt() != 0 {
		t.Errorf("the Delegation: %v", delegation)
	}
}

// MemberAdmit: only the roles outside the AdminSet, by an Owner's or Admin's device; MemberRevoke revokes the member's
// untagged devices and leaves its tagged agents, with autogroup:admin standing in as their sponsor.
func TestMemberAdmitAndRevoke(t *testing.T) {
	net := newTestConfigNet(t)
	member, first := net.consentedMember("m")
	tagId := testConfigId("tag")
	net.withTagOwner(tagId, member)
	agent := net.device("m agent", Id{})
	net.mustPost(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{tagId}, false, net.timeMs+24*60*60*1000, 0))

	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
		Header: net.header(), MemberId: testConfigId("would be admin").Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_ADMIN,
	}, ErrConfigRule)
	net.mustRefuse(first, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("by a member"), ErrConfigAuthority)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, &protocol.MemberAdmit{
		Header: net.header(), MemberId: member.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_AUDITOR,
	})
	if net.log.State().Member(member).GetRole() != bridge.MemberRole_MEMBER_ROLE_AUDITOR {
		t.Error("the role did not change")
	}

	net.mustRefuse(first, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: member.Bytes()}, ErrConfigAuthority)
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: member.Bytes()})
	state := net.log.State()
	if state.Member(member) != nil || state.SidecarRow(first.sidecarId).GetRevokedAt() != revoked.Pin.GetVersion() {
		t.Error("the member or its device stands")
	}
	if state.SidecarRow(agent.sidecarId).GetRevokedAt() != 0 {
		t.Error("the member's tagged agent was revoked")
	}
	if _, ok := state.Sponsor(agent.sidecarId); ok {
		t.Error("a removed member sponsors")
	}
	net.mustRefuse(net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: member.Bytes()}, ErrConfigRule)
}

// AdmissionConfirm: any signer allowed to admit the device, never the device itself, and never of a revoked one; it
// keeps its signer and position, and leaves a park for TEAM-M2-04 to lift.
func TestAdmissionConfirmBySomeoneAllowedToAdmit(t *testing.T) {
	net := newTestConfigNet(t)
	member, first := net.consentedMember("m")
	second := net.device("m second", member)
	net.admitDevice(net.owner, second, 0)
	confirm := func(device testConfigDevice) *protocol.AdmissionConfirm {
		return &protocol.AdmissionConfirm{Header: net.header(), SidecarId: device.sidecarId.Bytes()}
	}
	net.mustRefuse(second, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, confirm(second), ErrConfigAuthority)
	confirmed := net.mustPost(first, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, confirm(second))
	row := net.log.State().SidecarRow(second.sidecarId)
	if !bytes.Equal(row.GetConfirmSigner(), first.sidecarId.Bytes()) || row.GetConfirmedAt() != confirmed.Pin.GetVersion() {
		t.Errorf("the row: %v", row)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(second, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	net.mustRefuse(first, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, confirm(second), ErrConfigRule)
}
