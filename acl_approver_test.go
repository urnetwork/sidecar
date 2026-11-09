// §8.6's approvers resolved from a requests rule's atoms: autogroup:self, autogroup:sponsor and
// autogroup:dst-owner with their fallbacks to autogroup:admin (owner decisions 83, 180), and members named
// outright or by role. Pure, on every leg.

package sidecar

import (
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The bytes of approver atoms.
func aclApproverAtoms(atoms ...Id) [][]byte {
	atomBytes := [][]byte{}
	for _, atom := range atoms {
		atomBytes = append(atomBytes, atom.Bytes())
	}
	return atomBytes
}

// Whether an approver set is exactly these members and these autogroups.
func aclApproversAre(approvers *AclApprovers, memberIds []Id, autogroups ...protocol.AclAutogroup) bool {
	bits := uint32(0)
	for _, autogroup := range autogroups {
		bits |= aclAutogroupBit(autogroup)
	}
	return slices.Equal(approvers.MemberIds, aclSortedIds(memberIds...)) && approvers.Autogroups == bits
}

// autogroup:self names the requester's owner or a tagged requester's sponsor, and autogroup:sponsor a
// tagged requester's sponsor; with no sponsor, or for an untagged requester's sponsor, autogroup:admin
// stands in.
func TestAclSelfAndSponsorApprovers(t *testing.T) {
	fixture := newAclTestFixture()
	alice := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	tagId := fixture.tag(alice)
	laptop := fixture.device(alice)
	agent := fixture.agent(alice, tagId)
	orphan := fixture.agent(alice, tagId)
	delete(fixture.view.sponsors, orphan)
	app := NewId()
	state := fixture.state(t)
	self := aclApproverAtoms(AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF))
	sponsor := aclApproverAtoms(AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SPONSOR))
	admin := protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN
	cases := []struct {
		name       string
		atoms      [][]byte
		requester  AclSubject
		memberIds  []Id
		autogroups []protocol.AclAutogroup
	}{
		{name: "self of a member device", atoms: self, requester: AclSidecarSubject(laptop), memberIds: []Id{alice}},
		{name: "self of a tagged sidecar", atoms: self, requester: AclSidecarSubject(agent), memberIds: []Id{alice}},
		{name: "self of an orphan", atoms: self, requester: AclSidecarSubject(orphan), autogroups: []protocol.AclAutogroup{admin}},
		{name: "self of an app device", atoms: self, requester: AclClientSubject(app, alice, nil, ""), memberIds: []Id{alice}},
		{name: "self of a legacy client", atoms: self, requester: AclClientSubject(app, Id{}, nil, ""), autogroups: []protocol.AclAutogroup{admin}},
		{name: "sponsor of a tagged sidecar", atoms: sponsor, requester: AclSidecarSubject(agent), memberIds: []Id{alice}},
		{name: "sponsor of an orphan", atoms: sponsor, requester: AclSidecarSubject(orphan), autogroups: []protocol.AclAutogroup{admin}},
		{name: "sponsor of a member device", atoms: sponsor, requester: AclSidecarSubject(laptop), autogroups: []protocol.AclAutogroup{admin}},
	}
	for _, c := range cases {
		approvers := state.ResolveApprovers(c.atoms, c.requester, nil, aclTestNow)
		if !aclApproversAre(approvers, c.memberIds, c.autogroups...) {
			t.Errorf("%s: %+v", c.name, approvers)
		}
	}
}

// autogroup:dst-owner: one destination's owner, a tagged one's sponsor, a socket's one owner or sponsor
// across the subjects that hold listen on it, and autogroup:admin for a sponsor gone, mixed listeners, no
// listener, or a destination with no subject owner (owner decision 180, plan-ACL-small-readings #5).
func TestAclDstOwnerApprover(t *testing.T) {
	fixture := newAclTestFixture()
	alice := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	bob := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	workerTag := fixture.tag(alice)
	aliceLaptop := fixture.device(alice)
	aliceWorker := fixture.agent(alice, workerTag)
	bobWorker := fixture.agent(bob, workerTag)
	orphanWorker := fixture.agent(bob, fixture.tag(bob))
	delete(fixture.view.sponsors, orphanWorker)
	aliceOnly := aclTestTokenPath(1)
	mixed := aclTestTokenPath(2)
	expiring := aclTestTokenPath(3)
	fixture.rule([]Id{fixture.sidecarAtom(aliceWorker)}, []*protocol.AclTarget{aclSocketRowTarget(false, aliceOnly), aclSocketRowTarget(false, mixed)},
		protocol.AclAction_ACL_ACTION_LISTEN)
	fixture.rule([]Id{fixture.sidecarAtom(bobWorker)}, []*protocol.AclTarget{aclSocketRowTarget(false, mixed)}, protocol.AclAction_ACL_ACTION_LISTEN)
	listen := fixture.rule([]Id{fixture.sidecarAtom(aliceLaptop)}, []*protocol.AclTarget{aclSocketRowTarget(false, expiring)}, protocol.AclAction_ACL_ACTION_LISTEN)
	listen.Expires = aclTestNow.Add(time.Minute).UnixMilli()
	state := fixture.state(t)
	dstOwner := aclApproverAtoms(AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER))
	admin := []protocol.AclAutogroup{protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN}
	requester := AclSidecarSubject(fixture.device(bob))
	cases := []struct {
		name       string
		grantDst   []*protocol.AclTarget
		now        time.Time
		memberIds  []Id
		autogroups []protocol.AclAutogroup
	}{
		{name: "a member device", grantDst: []*protocol.AclTarget{aclSidecarTarget(aliceLaptop)}, memberIds: []Id{alice}},
		{name: "a tagged sidecar", grantDst: []*protocol.AclTarget{aclSidecarTarget(aliceWorker)}, memberIds: []Id{alice}},
		{name: "a sponsor gone", grantDst: []*protocol.AclTarget{aclSidecarTarget(orphanWorker)}, autogroups: admin},
		{name: "one owner of two", grantDst: []*protocol.AclTarget{aclSidecarTarget(aliceLaptop), aclSidecarTarget(aliceWorker)}, memberIds: []Id{alice}},
		{name: "two owners", grantDst: []*protocol.AclTarget{aclSidecarTarget(aliceLaptop), aclSidecarTarget(bobWorker)}, autogroups: admin},
		{name: "a tag of two owners", grantDst: []*protocol.AclTarget{aclAtomTarget(workerTag)}, autogroups: admin},
		{name: "one owner's listeners", grantDst: []*protocol.AclTarget{aclSocketRowTarget(false, aliceOnly)}, memberIds: []Id{alice}},
		{name: "mixed listeners", grantDst: []*protocol.AclTarget{aclSocketRowTarget(false, mixed)}, autogroups: admin},
		{name: "a listen grant in force", grantDst: []*protocol.AclTarget{aclSocketRowTarget(false, expiring)}, memberIds: []Id{alice}},
		{name: "a listen grant expired", grantDst: []*protocol.AclTarget{aclSocketRowTarget(false, expiring)}, now: aclTestNow.Add(time.Minute), autogroups: admin},
		{name: "no listener", grantDst: []*protocol.AclTarget{aclSocketRowTarget(false, aclTestTokenPath(9))}, autogroups: admin},
		{name: "a repo", grantDst: []*protocol.AclTarget{aclRepoTarget(NewId())}, autogroups: admin},
		{name: "no destination", grantDst: nil, autogroups: admin},
	}
	for _, c := range cases {
		now := c.now
		if now.IsZero() {
			now = aclTestNow
		}
		approvers := state.ResolveApprovers(dstOwner, requester, c.grantDst, now)
		if !aclApproversAre(approvers, c.memberIds, c.autogroups...) {
			t.Errorf("%s: %+v", c.name, approvers)
		}
	}
}

// Members named by user and group atoms approve, members by a role autogroup approve by their role, every
// member holding autogroup:member, and someone no longer a member approves nothing.
func TestAclNamedAndRoleApprovers(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	admin := fixture.member(bridge.MemberRole_MEMBER_ROLE_ADMIN)
	auditor := fixture.member(bridge.MemberRole_MEMBER_ROLE_AUDITOR)
	member := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	departed := NewId()
	group := fixture.group(member, departed)
	state := fixture.state(t)
	requester := AclSidecarSubject(fixture.device(member))

	named := state.ResolveApprovers(aclApproverAtoms(group, NewId()), requester, nil, aclTestNow)
	if !aclApproversAre(named, []Id{member, departed}) || !state.Approves(named, member) || state.Approves(named, departed) || state.Approves(named, owner) {
		t.Errorf("named: %+v", named)
	}

	byRole := state.ResolveApprovers(aclApproverAtoms(AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN)), requester, nil, aclTestNow)
	cases := []struct {
		memberId Id
		approves bool
	}{
		{memberId: owner, approves: true},
		{memberId: admin, approves: true},
		{memberId: auditor, approves: false},
		{memberId: member, approves: false},
		{memberId: departed, approves: false},
	}
	for i, c := range cases {
		if approves := state.Approves(byRole, c.memberId); approves != c.approves {
			t.Errorf("admin case %d: %t", i, approves)
		}
	}
	anyMember := state.ResolveApprovers(aclApproverAtoms(AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER),
		AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED)), requester, nil, aclTestNow)
	if !anyMember.HasAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER) || anyMember.HasAutogroup(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED) ||
		!state.Approves(anyMember, auditor) || state.Approves(anyMember, departed) {
		t.Errorf("autogroup:member: %+v", anyMember)
	}
}
