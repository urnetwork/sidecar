// §10.9's member check and §8.12's non-readers on hand-made rows: a server-forged Add or wrap refused for a non-reader,
// an unconsented device in an owner-bound repo, a parked, revoked, suspended or expired device and one past its
// grant's expiry; a leaf only for a member device, in the config and directory groups only for one §7.9's leaves rule
// entitles, and never past 1,000; and the holders a writer must not seal to. Pure, on every leg.

package sidecar

import (
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A leaf in a group of 1,000 leaves at most, as a commit within the bound presents it.
func aclTestLeaf(sidecarId Id) AclRepoMember {
	return AclRepoMember{SidecarId: sidecarId, Form: AclRepoMemberLeaf, LeafCount: 2}
}

// A ReaderWrap's recipient.
func aclTestWrap(sidecarId Id) AclRepoMember {
	return AclRepoMember{SidecarId: sidecarId, Form: AclRepoMemberWrap}
}

// A server that forges an Add or a ReaderWrap for a sidecar that does not read the repo gets it refused, whatever the
// sidecar is: a member device no rule names, a depositor, a sidecar the log never admitted, and a repo the rows do not
// hold or that is deleted (R-ACL-7).
func TestCheckRepoMemberRefusesAForgedAddOfANonReader(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	member := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	other := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	tagId := fixture.tag(owner)
	eng := fixture.group(member)
	reader := fixture.invitedDevice(member)
	outsider := fixture.invitedDevice(other)
	depositor := fixture.agent(owner, tagId)
	repoId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	deletedId, deleted := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	deleted.Deletion = &protocol.AclRepoDeletionRow{DeletionId: NewId().Bytes(), DeletedAt: fixture.next()}
	rule := fixture.rule([]Id{eng}, []*protocol.AclTarget{aclRepoTarget(repoId), aclRepoTarget(deletedId)}, protocol.AclAction_ACL_ACTION_READ)
	fixture.rule([]Id{tagId}, []*protocol.AclTarget{aclRepoTarget(repoId)}, protocol.AclAction_ACL_ACTION_DEPOSIT)
	state := fixture.state(t)

	for _, member := range []AclRepoMember{aclTestLeaf(reader), aclTestWrap(reader)} {
		decision := state.CheckRepoMember(repoId, member, aclTestNow)
		if !decision.Allowed || decision.Reason != AclReasonRule || decision.Rule != rule {
			t.Errorf("the reader's form %d: %+v", member.Form, decision)
		}
	}
	cases := []struct {
		name   string
		repoId Id
		member AclRepoMember
		reason AclReason
	}{
		{name: "a member device no rule names, as a leaf", repoId: repoId, member: aclTestLeaf(outsider), reason: AclReasonNoGrant},
		{name: "a member device no rule names, wrapped", repoId: repoId, member: aclTestWrap(outsider), reason: AclReasonNoGrant},
		{name: "a depositor, wrapped", repoId: repoId, member: aclTestWrap(depositor), reason: AclReasonNoGrant},
		{name: "a ghost, as a leaf", repoId: repoId, member: aclTestLeaf(NewId()), reason: AclReasonUnadmitted},
		{name: "a ghost, wrapped", repoId: repoId, member: aclTestWrap(NewId()), reason: AclReasonUnadmitted},
		{name: "a repo the rows do not hold", repoId: NewId(), member: aclTestLeaf(reader), reason: AclReasonNoRepo},
		{name: "a deleted repo", repoId: deletedId, member: aclTestWrap(reader), reason: AclReasonRepoDeleted},
		{name: "a form this code does not know", repoId: repoId, member: AclRepoMember{SidecarId: reader, Form: 3, LeafCount: 2}, reason: AclReasonNoGrant},
	}
	for _, c := range cases {
		if decision := state.CheckRepoMember(c.repoId, c.member, aclTestNow); decision.Allowed || decision.Reason != c.reason {
			t.Errorf("%s: %+v, want %s", c.name, decision, c.reason)
		}
	}
}

// In an owner-bound repo only the owner's consented devices and their EvsShares' subjects pass: an admin-admitted
// device of the owner is refused as unconsented, leaf and wrap alike, until the owner confirms it; an admin's share
// opens nothing; a sponsored agent only deposits (owner decision 126, §22.7's owner consent row).
func TestCheckRepoMemberOwnerBoundTakesOnlyConsentedDevicesAndShares(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	admin := fixture.member(bridge.MemberRole_MEMBER_ROLE_ADMIN)
	friendMember := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	tagId := fixture.tag(owner)
	adminDevice := fixture.invitedDevice(admin)
	laptop := fixture.invitedDevice(owner)
	phone := fixture.device(owner, laptop.Bytes())
	adminAdmitted := fixture.device(owner, adminDevice.Bytes())
	friend := fixture.invitedDevice(friendMember)
	adminShared := fixture.device(admin, adminDevice.Bytes())
	sponsored := fixture.agent(owner, tagId)
	vaultId, vault := fixture.repo(protocol.RepoKind_REPO_KIND_VAULT, owner)
	vault.ConsentedSidecarIds = [][]byte{laptop.Bytes(), phone.Bytes()}
	shareAt := fixture.next()
	vault.Shares = []*protocol.AclRepoShareRow{
		{Subject: friend.Bytes(), Signer: laptop.Bytes(), At: shareAt},
		{Subject: adminShared.Bytes(), Signer: adminDevice.Bytes(), At: fixture.next()},
	}
	state := fixture.state(t)

	cases := []struct {
		name   string
		member AclRepoMember
		reason AclReason
		at     uint64
	}{
		{name: "the owner's invited device", member: aclTestLeaf(laptop), reason: AclReasonKindDefault},
		{name: "the owner's scoped device", member: aclTestLeaf(phone), reason: AclReasonKindDefault},
		{name: "the owner's share, as a leaf", member: aclTestLeaf(friend), reason: AclReasonEvsShare, at: shareAt},
		{name: "the owner's share, wrapped", member: aclTestWrap(friend), reason: AclReasonEvsShare, at: shareAt},
	}
	for _, c := range cases {
		decision := state.CheckRepoMember(vaultId, c.member, aclTestNow)
		if !decision.Allowed || decision.Reason != c.reason || decision.At != c.at {
			t.Errorf("%s: %+v", c.name, decision)
		}
	}
	refusals := []struct {
		name   string
		member AclRepoMember
		reason AclReason
	}{
		{name: "an admin-admitted device of the owner, as a leaf", member: aclTestLeaf(adminAdmitted), reason: AclReasonUnconsented},
		{name: "an admin-admitted device of the owner, wrapped", member: aclTestWrap(adminAdmitted), reason: AclReasonUnconsented},
		{name: "an admin's share", member: aclTestLeaf(adminShared), reason: AclReasonNoGrant},
		{name: "the admin's own device", member: aclTestWrap(adminDevice), reason: AclReasonNoGrant},
		{name: "a sponsored agent, which deposits", member: aclTestWrap(sponsored), reason: AclReasonNoGrant},
	}
	for _, c := range refusals {
		if decision := state.CheckRepoMember(vaultId, c.member, aclTestNow); decision.Allowed || decision.Reason != c.reason {
			t.Errorf("%s: %+v, want %s", c.name, decision, c.reason)
		}
	}

	// the owner's OwnerConfirm, which the next base's compile lists among the consented devices, admits it
	fixture.admission(adminAdmitted).Row.OwnerConfirmSigner = laptop.Bytes()
	fixture.admission(adminAdmitted).Row.OwnerConfirmedAt = fixture.next()
	vault.ConsentedSidecarIds = append(vault.ConsentedSidecarIds, adminAdmitted.Bytes())
	if decision := fixture.state(t).CheckRepoMember(vaultId, aclTestLeaf(adminAdmitted), aclTestNow); !decision.Allowed {
		t.Errorf("the confirmed device: %+v", decision)
	}
}

// A parked, revoked, suspended or expired device, or one whose member left, is refused as either form, and so is
// every device in a cascade's park whatever its grants (§10.9's Add row: admitted, unrevoked, unparked).
func TestCheckRepoMemberRefusesAParkedOrRevokedDevice(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(fixture *aclTestFixture, deviceId Id, memberId Id)
		reason AclReason
	}{
		{name: "parked", edit: func(fixture *aclTestFixture, deviceId Id, memberId Id) {
			fixture.view.parked[deviceId] = true
		}, reason: AclReasonParked},
		{name: "revoked", edit: func(fixture *aclTestFixture, deviceId Id, memberId Id) {
			fixture.admission(deviceId).Row.RevokedAt = fixture.next()
		}, reason: AclReasonRevoked},
		{name: "suspended", edit: func(fixture *aclTestFixture, deviceId Id, memberId Id) {
			fixture.rows.Suspensions = append(fixture.rows.Suspensions, &protocol.AclSuspension{
				Subject: deviceId.Bytes(), SuspendId: NewId().Bytes(), SignerClass: AclSuspendClassAdmin, At: fixture.next(),
			})
		}, reason: AclReasonSuspended},
		{name: "past its not_after", edit: func(fixture *aclTestFixture, deviceId Id, memberId Id) {
			fixture.admission(deviceId).Row.NotAfter = aclTestNow.UnixMilli()
		}, reason: AclReasonExpired},
		{name: "its member gone", edit: func(fixture *aclTestFixture, deviceId Id, memberId Id) {
			delete(fixture.view.members, memberId)
		}, reason: AclReasonUnadmitted},
	}
	for _, c := range cases {
		fixture := newAclTestFixture()
		member := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
		deviceId := fixture.invitedDevice(member)
		repoId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
		fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), []*protocol.AclTarget{aclRepoTarget(repoId)},
			protocol.AclAction_ACL_ACTION_READ, protocol.AclAction_ACL_ACTION_WRITE)
		if decision := fixture.state(t).CheckRepoMember(repoId, aclTestLeaf(deviceId), aclTestNow); !decision.Allowed {
			t.Fatalf("%s: before, %+v", c.name, decision)
		}
		c.edit(fixture, deviceId, member)
		state := fixture.state(t)
		for _, member := range []AclRepoMember{aclTestLeaf(deviceId), aclTestWrap(deviceId)} {
			if decision := state.CheckRepoMember(repoId, member, aclTestNow); decision.Allowed || decision.Reason != c.reason {
				t.Errorf("%s, form %d: %+v, want %s", c.name, member.Form, decision, c.reason)
			}
		}
	}
}

// A RepoGrant's reader passes before its expiry and is refused at exactly it, and a config writer's standing RepoRevoke
// refuses it however long the grant runs (§8.8, §7.9's coverage).
func TestCheckRepoMemberEndsAtAGrantsExpiry(t *testing.T) {
	fixture := newAclTestFixture()
	member := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	other := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	admin := fixture.invitedDevice(member)
	granted := fixture.invitedDevice(other)
	revoked := fixture.device(other, granted.Bytes())
	expires := aclTestNow.Add(time.Hour)
	repoId, repo := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: admin.Bytes(), Signer: admin.Bytes(), At: fixture.next()}}
	grantAt := fixture.next()
	repo.Grants = []*protocol.AclRepoGrantRow{
		{Subject: granted.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, Expires: expires.UnixMilli(), Signer: admin.Bytes(), At: grantAt},
		{Subject: revoked.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER, Signer: admin.Bytes(), At: fixture.next()},
	}
	repo.Revokes = []*protocol.AclRepoRevokeRow{{Subject: revoked.Bytes(), Signer: NewId().Bytes(), At: fixture.next()}}
	state := fixture.state(t)

	decision := state.CheckRepoMember(repoId, aclTestLeaf(granted), expires.Add(-time.Millisecond))
	if !decision.Allowed || decision.Reason != AclReasonRepoGrant || decision.At != grantAt {
		t.Errorf("before the expiry: %+v", decision)
	}
	for _, member := range []AclRepoMember{aclTestLeaf(granted), aclTestWrap(granted)} {
		if decision := state.CheckRepoMember(repoId, member, expires); decision.Allowed || decision.Reason != AclReasonNoGrant {
			t.Errorf("at the expiry, form %d: %+v", member.Form, decision)
		}
	}
	if decision := state.CheckRepoMember(repoId, aclTestWrap(revoked), aclTestNow); decision.Allowed {
		t.Errorf("a standing RepoRevoke's subject: %+v", decision)
	}
}

// A leaf needs a member device: a tagged or ephemeral reader takes a wrap and never a seat (D-KEYS-11); and no group
// takes a leaf past 1,000 (D-KEYS-2), a count below one being no tree.
func TestCheckRepoMemberLeafNeedsAMemberDeviceAndASeat(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	tagId := fixture.tag(owner)
	laptop := fixture.invitedDevice(owner)
	pageWorker := fixture.device(owner, laptop.Bytes())
	fixture.admission(pageWorker).Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	agent := fixture.agent(owner, tagId)
	ephemeral := fixture.device(owner, laptop.Bytes())
	fixture.admission(ephemeral).Ephemeral = true
	repoId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	fixture.rule([]Id{tagId, fixture.sidecarAtom(ephemeral)}, []*protocol.AclTarget{aclRepoTarget(repoId)}, protocol.AclAction_ACL_ACTION_READ)
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), []*protocol.AclTarget{aclRepoTarget(repoId)}, protocol.AclAction_ACL_ACTION_READ)
	state := fixture.state(t)

	for _, sidecarId := range []Id{agent, ephemeral} {
		if decision := state.CheckRepoMember(repoId, aclTestWrap(sidecarId), aclTestNow); !decision.Allowed {
			t.Errorf("%s's wrap: %+v", sidecarId, decision)
		}
		if decision := state.CheckRepoMember(repoId, aclTestLeaf(sidecarId), aclTestNow); decision.Allowed || decision.Reason != AclReasonNotMemberDevice {
			t.Errorf("%s's leaf: %+v", sidecarId, decision)
		}
	}
	// a read_only member device is a leaf of what it reads
	if decision := state.CheckRepoMember(repoId, aclTestLeaf(pageWorker), aclTestNow); !decision.Allowed {
		t.Errorf("the page Worker's leaf: %+v", decision)
	}
	counts := []struct {
		leafCount int
		allowed   bool
	}{
		{leafCount: 1, allowed: true},
		{leafCount: aclRepoSeatCount, allowed: true},
		{leafCount: aclRepoSeatCount + 1},
		{leafCount: 0},
		{leafCount: -1},
	}
	for _, c := range counts {
		decision := state.CheckRepoMember(repoId, AclRepoMember{SidecarId: laptop, Form: AclRepoMemberLeaf, LeafCount: c.leafCount}, aclTestNow)
		if decision.Allowed != c.allowed || (!c.allowed && decision.Reason != AclReasonSeatsFull) {
			t.Errorf("%d leaves: %+v", c.leafCount, decision)
		}
	}
	// a wrap takes no seat, so its count is never read
	if decision := state.CheckRepoMember(repoId, AclRepoMember{SidecarId: agent, Form: AclRepoMemberWrap, LeafCount: aclRepoSeatCount + 1}, aclTestNow); !decision.Allowed {
		t.Errorf("a wrap with a count: %+v", decision)
	}
}

// The config group and a team directory's seat by §7.9's leaves rule alone: a member device the rule does not entitle
// is refused a leaf there and takes a wrap, while in a data repo the same device takes a leaf (owner decisions 144,
// 182; §22.7's seats row).
func TestCheckRepoMemberConfigLeafFollowsTheLeavesRule(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	tagId := fixture.tag(owner)
	entitled := fixture.invitedDevice(owner)
	wrapped := fixture.device(owner, entitled.Bytes())
	agent := fixture.agent(owner, tagId)
	fixture.view.leafEntitled = map[Id]bool{entitled: true}
	configId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_CONFIG, Id{})
	directoryId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_DIRECTORY, Id{})
	dataId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), []*protocol.AclTarget{aclRepoTarget(dataId)}, protocol.AclAction_ACL_ACTION_READ)
	state := fixture.state(t)

	for _, repoId := range []Id{configId, directoryId} {
		if decision := state.CheckRepoMember(repoId, aclTestLeaf(entitled), aclTestNow); !decision.Allowed || decision.Reason != AclReasonKindDefault {
			t.Errorf("%s: the entitled leaf: %+v", repoId, decision)
		}
		if decision := state.CheckRepoMember(repoId, aclTestLeaf(wrapped), aclTestNow); decision.Allowed || decision.Reason != AclReasonNotLeafEntitled {
			t.Errorf("%s: the wrapped device's leaf: %+v", repoId, decision)
		}
		if decision := state.CheckRepoMember(repoId, aclTestLeaf(agent), aclTestNow); decision.Allowed || decision.Reason != AclReasonNotMemberDevice {
			t.Errorf("%s: the agent's leaf: %+v", repoId, decision)
		}
		for _, sidecarId := range []Id{entitled, wrapped, agent} {
			if decision := state.CheckRepoMember(repoId, aclTestWrap(sidecarId), aclTestNow); !decision.Allowed {
				t.Errorf("%s: %s's wrap: %+v", repoId, sidecarId, decision)
			}
		}
	}
	if decision := state.CheckRepoMember(dataId, aclTestLeaf(wrapped), aclTestNow); !decision.Allowed {
		t.Errorf("the data repo: the wrapped device's leaf: %+v", decision)
	}
}

// Owner decision 63's audit assignment: once the rows carry the audit block with its AuditOptIn, which ACL-M6-02's
// compile writes only after verifying it, the audit reader takes a wrap of each repo the block names, an owner-bound
// one included, and no leaf, being tagged; without the opt-in it takes neither.
func TestCheckRepoMemberTakesTheAuditReaderOnlyWithItsOptIn(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	admin := fixture.member(bridge.MemberRole_MEMBER_ROLE_ADMIN)
	auditTag := fixture.tag(admin)
	auditor := fixture.agent(admin, auditTag)
	vaultId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_VAULT, owner)
	mailboxId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_MAILBOX, owner)
	fixture.rows.Audit = &protocol.AclAudit{
		ReaderAtoms: [][]byte{auditTag.Bytes()},
		RepoKinds:   []uint32{uint32(protocol.RepoKind_REPO_KIND_VAULT)},
	}
	if decision := fixture.state(t).CheckRepoMember(vaultId, aclTestWrap(auditor), aclTestNow); decision.Allowed {
		t.Errorf("without its opt-in: %+v", decision)
	}
	fixture.rows.Audit.AuditOptIn = []byte("a k-of-n AuditOptIn the compile verified")
	state := fixture.state(t)
	if decision := state.CheckRepoMember(vaultId, aclTestWrap(auditor), aclTestNow); !decision.Allowed || decision.Reason != AclReasonAudit {
		t.Errorf("the audit reader's wrap: %+v", decision)
	}
	if decision := state.CheckRepoMember(vaultId, aclTestLeaf(auditor), aclTestNow); decision.Allowed || decision.Reason != AclReasonNotMemberDevice {
		t.Errorf("the audit reader's leaf: %+v", decision)
	}
	if decision := state.CheckRepoMember(mailboxId, aclTestWrap(auditor), aclTestNow); decision.Allowed {
		t.Errorf("a kind the block does not name: %+v", decision)
	}
}

// A view that answers AclAuthView alone, as fakes outside this package do.
type aclTestUnrankedView struct {
	AclAuthView
}

// A view that does not answer §7.9's leaves rule entitles no device: the config and directory groups take no leaf
// through it, the closed direction, while their wraps and a data repo's leaves pass as before.
func TestCheckRepoMemberWithoutTheLeavesRuleTakesNoConfigLeaf(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	device := fixture.invitedDevice(owner)
	fixture.view.leafEntitled = map[Id]bool{device: true}
	configId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_CONFIG, Id{})
	directoryId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_DIRECTORY, Id{})
	dataId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), []*protocol.AclTarget{aclRepoTarget(dataId)}, protocol.AclAction_ACL_ACTION_READ)
	if decision := fixture.state(t).CheckRepoMember(configId, aclTestLeaf(device), aclTestNow); !decision.Allowed {
		t.Fatalf("the ranked view's leaf: %+v", decision)
	}
	state, err := NewAclState(fixture.rows, aclTestUnrankedView{AclAuthView: fixture.view})
	if err != nil {
		t.Fatal(err)
	}
	for _, repoId := range []Id{configId, directoryId} {
		if decision := state.CheckRepoMember(repoId, aclTestLeaf(device), aclTestNow); decision.Allowed || decision.Reason != AclReasonNotLeafEntitled {
			t.Errorf("%s: the leaf: %+v", repoId, decision)
		}
		if decision := state.CheckRepoMember(repoId, aclTestWrap(device), aclTestNow); !decision.Allowed {
			t.Errorf("%s: the wrap: %+v", repoId, decision)
		}
	}
	if decision := state.CheckRepoMember(dataId, aclTestLeaf(device), aclTestNow); !decision.Allowed {
		t.Errorf("the data repo's leaf: %+v", decision)
	}
}

// NonReaders names each holder of a key that does not read the repo, with its reason, sorted and once each: a revoked
// device, a parked one, a ghost, a depositor and a reader past its grant's expiry; a reader and a config leaf that only
// lost its entitlement are not named, and a holder set that reads in full names no one (§8.12's invariant).
func TestAclNonReaders(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	member := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	tagId := fixture.tag(owner)
	reader := fixture.invitedDevice(owner)
	revoked := fixture.device(owner, reader.Bytes())
	fixture.admission(revoked).Row.RevokedAt = fixture.next()
	parked := fixture.device(owner, reader.Bytes())
	fixture.view.parked[parked] = true
	depositor := fixture.agent(owner, tagId)
	granted := fixture.invitedDevice(member)
	ghost := NewId()
	expires := aclTestNow.Add(-time.Millisecond)
	repoId, repo := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	repo.Grants = []*protocol.AclRepoGrantRow{{
		Subject: granted.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, Expires: expires.UnixMilli(), Signer: reader.Bytes(), At: fixture.next(),
	}}
	configId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_CONFIG, Id{})
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_OWNER), []*protocol.AclTarget{aclRepoTarget(repoId)}, protocol.AclAction_ACL_ACTION_READ)
	fixture.rule([]Id{tagId}, []*protocol.AclTarget{aclRepoTarget(repoId)}, protocol.AclAction_ACL_ACTION_DEPOSIT)
	state := fixture.state(t)

	holders := []Id{reader, revoked, parked, depositor, granted, ghost, revoked}
	want := []AclNonReader{
		{SidecarId: revoked, Reason: AclReasonRevoked},
		{SidecarId: parked, Reason: AclReasonParked},
		{SidecarId: depositor, Reason: AclReasonNoGrant},
		{SidecarId: granted, Reason: AclReasonNoGrant},
		{SidecarId: ghost, Reason: AclReasonUnadmitted},
	}
	slices.SortFunc(want, func(a AclNonReader, b AclNonReader) int { return a.SidecarId.Cmp(b.SidecarId) })
	if got := state.NonReaders(repoId, holders, aclTestNow); !slices.Equal(got, want) {
		t.Errorf("non-readers %+v, want %+v", got, want)
	}
	if got := state.NonReaders(repoId, []Id{reader}, aclTestNow); len(got) != 0 {
		t.Errorf("a reader named: %+v", got)
	}
	// before its expiry the granted device reads
	if got := state.NonReaders(repoId, []Id{granted}, expires.Add(-time.Millisecond)); len(got) != 0 {
		t.Errorf("before the expiry: %+v", got)
	}
	// every admitted sidecar reads the config, leaf-entitled or not, and a deleted repo has no reader
	if got := state.NonReaders(configId, []Id{reader, depositor}, aclTestNow); len(got) != 0 {
		t.Errorf("the config: %+v", got)
	}
	repo.Deletion = &protocol.AclRepoDeletionRow{DeletionId: NewId().Bytes(), DeletedAt: fixture.next()}
	if got := fixture.state(t).NonReaders(repoId, []Id{reader}, aclTestNow); len(got) != 1 || got[0].Reason != AclReasonRepoDeleted {
		t.Errorf("a deleted repo: %+v", got)
	}
}

// The check is a gate's and a member's per-commit work: it allocates nothing, allowed or refused, on a state of §8.8's
// atom bound.
func TestCheckRepoMemberDoesNotAllocate(t *testing.T) {
	bench := newAclBenchState(t)
	state := bench.state
	checks := map[string]func(){
		"leaf":            func() { state.CheckRepoMember(bench.repos[0], aclTestLeaf(bench.devices[0]), aclTestNow) },
		"wrap":            func() { state.CheckRepoMember(bench.repos[1], aclTestWrap(bench.agents[0]), aclTestNow) },
		"agent's leaf":    func() { state.CheckRepoMember(bench.repos[2], aclTestLeaf(bench.agents[1]), aclTestNow) },
		"a ghost":         func() { state.CheckRepoMember(bench.repos[3], aclTestLeaf(Id{}), aclTestNow) },
		"an unknown repo": func() { state.CheckRepoMember(Id{}, aclTestWrap(bench.devices[1]), aclTestNow) },
	}
	for name, check := range checks {
		if allocs := testing.AllocsPerRun(50, check); allocs != 0 {
			t.Errorf("%s: %.1f allocations", name, allocs)
		}
	}
}
