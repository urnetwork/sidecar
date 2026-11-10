// §8.12's data seats and the writer's preview on hand-made rows, then through the config log's own state: §22.7's
// seats row (a data repo's 1,001st reading member device waits keyless and is named in the preview; the
// earliest-admitted waiting device with a KeyPackage fills a freed seat; a seated device is never displaced; agents
// take no seat), the config and directory groups left to §7.9's leaves rule, and the preview from the trees a writer
// holds. Pure, on every leg.

package sidecar

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network whose one member's devices, admitted in order, all read and write one general repo.
type aclSeatsFixture struct {
	*aclTestFixture
	memberId Id
	repoId   Id
	devices  []Id
}

func newAclSeatsFixture(deviceCount int) *aclSeatsFixture {
	fixture := newAclTestFixture()
	seats := &aclSeatsFixture{aclTestFixture: fixture, memberId: fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)}
	seats.repoId, _ = fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), []*protocol.AclTarget{aclRepoTarget(seats.repoId)},
		protocol.AclAction_ACL_ACTION_READ, protocol.AclAction_ACL_ACTION_WRITE)
	for range deviceCount {
		seats.devices = append(seats.devices, fixture.device(seats.memberId))
	}
	return seats
}

// A set of sidecars, as gkm's KeyPackage listing gives a committer one.
func aclTestSet(sidecarIds ...Id) map[Id]bool {
	set := map[Id]bool{}
	for _, sidecarId := range sidecarIds {
		set[sidecarId] = true
	}
	return set
}

// Ids sorted, as a plan lists its seated leaves.
func aclTestSorted(sidecarIds []Id) []Id {
	sorted := slices.Clone(sidecarIds)
	slices.SortFunc(sorted, Id.Cmp)
	return sorted
}

// §22.7's seats row: with every reading member device holding a KeyPackage, the first 1,000 by admission take the
// seats and the 1,001st waits keyless; with the 1,000 seated it waits all the same, and the preview names the repo
// and that device.
func TestAclDataSeatsTheThousandAndFirstReaderWaitsKeyless(t *testing.T) {
	seats := newAclSeatsFixture(aclRepoSeatCount + 1)
	state := seats.state(t)
	first, last := seats.devices[:aclRepoSeatCount], seats.devices[aclRepoSeatCount]

	plan, err := AclDataSeats(state, seats.repoId, nil, aclTestSet(seats.devices...), aclTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Adds, first) || !slices.Equal(plan.Waiting, []Id{last}) || plan.FreeSeats != 0 ||
		len(plan.Seated) != 0 || len(plan.Removes) != 0 {
		t.Errorf("an empty tree: %d adds, waiting %v, %d free, %d seated, removes %v", len(plan.Adds), plan.Waiting, plan.FreeSeats, len(plan.Seated), plan.Removes)
	}
	plan, err = AclDataSeats(state, seats.repoId, first, aclTestSet(seats.devices...), aclTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Seated, aclTestSorted(first)) || len(plan.Adds) != 0 || !slices.Equal(plan.Waiting, []Id{last}) || plan.FreeSeats != 0 {
		t.Errorf("a full tree: %d seated, adds %v, waiting %v, %d free", len(plan.Seated), plan.Adds, plan.Waiting, plan.FreeSeats)
	}
	// a commit that seats it anyway passes the bound for no one
	if decision := state.CheckRepoMember(seats.repoId, AclRepoMember{SidecarId: last, Form: AclRepoMemberLeaf, LeafCount: aclRepoSeatCount + 1}, aclTestNow); decision.Allowed || decision.Reason != AclReasonSeatsFull {
		t.Errorf("the 1,001st leaf: %+v", decision)
	}

	unseated := AclUnseated(state, nil, aclTestNow)
	want := []AclUnseatedRepo{{RepoId: seats.repoId, ReaderCount: aclRepoSeatCount + 1, SidecarIds: []Id{last}}}
	if !slices.EqualFunc(unseated, want, aclTestUnseatedEqual) {
		t.Errorf("the preview: %+v", unseated)
	}
}

// Whether two preview rows are equal.
func aclTestUnseatedEqual(a AclUnseatedRepo, b AclUnseatedRepo) bool {
	return a.RepoId == b.RepoId && a.ReaderCount == b.ReaderCount && slices.Equal(a.SidecarIds, b.SidecarIds)
}

// A seated device that stops reading is due a Remove, and its seat goes to the earliest-admitted waiting device that
// has a KeyPackage: one without waits, and the rest wait behind the seat taken (§8.12, KF2).
func TestAclDataSeatsEarliestAdmittedFillsAFreedSeat(t *testing.T) {
	seats := newAclSeatsFixture(aclRepoSeatCount + 3)
	leaves := seats.devices[:aclRepoSeatCount]
	w1, w2, w3 := seats.devices[aclRepoSeatCount], seats.devices[aclRepoSeatCount+1], seats.devices[aclRepoSeatCount+2]
	revoked := leaves[10]
	seats.admission(revoked).Row.RevokedAt = seats.next()
	state := seats.state(t)

	cases := []struct {
		keyPackages map[Id]bool
		adds        []Id
		waiting     []Id
	}{
		{keyPackages: aclTestSet(w1, w2, w3), adds: []Id{w1}, waiting: []Id{w2, w3}},
		{keyPackages: aclTestSet(w2, w3), adds: []Id{w2}, waiting: []Id{w1, w3}},
		{keyPackages: aclTestSet(w3), adds: []Id{w3}, waiting: []Id{w1, w2}},
		{keyPackages: aclTestSet(), adds: []Id{}, waiting: []Id{w1, w2, w3}},
	}
	for i, c := range cases {
		plan, err := AclDataSeats(state, seats.repoId, leaves, c.keyPackages, aclTestNow)
		if err != nil {
			t.Fatal(err)
		}
		wantRemoves := []AclNonReader{{SidecarId: revoked, Reason: AclReasonRevoked}}
		wantFree := 1 - len(c.adds)
		if !slices.Equal(plan.Removes, wantRemoves) || len(plan.Seated) != aclRepoSeatCount-1 || slices.Contains(plan.Seated, revoked) ||
			!slices.Equal(plan.Adds, c.adds) || !slices.Equal(plan.Waiting, c.waiting) || plan.FreeSeats != wantFree {
			t.Errorf("case %d: removes %v, %d seated, adds %v, waiting %v, %d free", i, plan.Removes, len(plan.Seated), plan.Adds, plan.Waiting, plan.FreeSeats)
		}
	}
}

// Seated devices keep their leaves however many earlier-admitted devices wait: a seat frees only by a Remove, and the
// waiting device admitted first takes it then (§8.12: a seated device keeps its leaf until a Remove).
func TestAclDataSeatsNeverDisplacesASeatedDevice(t *testing.T) {
	seats := newAclSeatsFixture(aclRepoSeatCount + 2)
	early, earlier := seats.devices[0], seats.devices[1]
	// the later-admitted 1,000 hold the seats, as when the early two had no KeyPackage while they filled
	leaves := seats.devices[2:]
	state := seats.state(t)
	plan, err := AclDataSeats(state, seats.repoId, leaves, aclTestSet(seats.devices...), aclTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Adds) != 0 || len(plan.Removes) != 0 || len(plan.Seated) != aclRepoSeatCount || !slices.Equal(plan.Waiting, []Id{early, earlier}) {
		t.Errorf("a full tree: adds %v, removes %v, %d seated, waiting %v", plan.Adds, plan.Removes, len(plan.Seated), plan.Waiting)
	}

	// a seated device parked by a cascade frees its seat to the first admitted
	parked := leaves[len(leaves)-1]
	seats.view.parked[parked] = true
	plan, err = AclDataSeats(seats.state(t), seats.repoId, leaves, aclTestSet(seats.devices...), aclTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Removes, []AclNonReader{{SidecarId: parked, Reason: AclReasonParked}}) || !slices.Equal(plan.Adds, []Id{early}) ||
		!slices.Equal(plan.Waiting, []Id{earlier}) {
		t.Errorf("a freed seat: removes %v, adds %v, waiting %v", plan.Removes, plan.Adds, plan.Waiting)
	}
}

// Agents take no seat: a tagged or ephemeral reader with a KeyPackage is neither added nor waiting, and one found in
// the tree is due a Remove; a read_only member device takes a seat as any member device does; and a leaf whose member
// left, or that no longer reads, frees its seat (D-KEYS-11, §10.9's Remove row).
func TestAclDataSeatsAgentsTakeNoSeat(t *testing.T) {
	seats := newAclSeatsFixture(2)
	owner := seats.memberId
	tagId := seats.tag(owner)
	agent := seats.agent(owner, tagId)
	ephemeral := seats.device(owner)
	seats.admission(ephemeral).Ephemeral = true
	pageWorker := seats.device(owner)
	seats.admission(pageWorker).Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	other := seats.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	gone := seats.device(other)
	seats.rule([]Id{tagId, seats.sidecarAtom(ephemeral)}, []*protocol.AclTarget{aclRepoTarget(seats.repoId)}, protocol.AclAction_ACL_ACTION_READ)
	delete(seats.view.members, other)
	state := seats.state(t)
	for _, sidecarId := range []Id{agent, ephemeral} {
		if decision := state.CheckRepoMember(seats.repoId, aclTestWrap(sidecarId), aclTestNow); !decision.Allowed {
			t.Fatalf("%s does not read: %+v", sidecarId, decision)
		}
	}

	plan, err := AclDataSeats(state, seats.repoId, []Id{seats.devices[0], agent, gone}, aclTestSet(agent, ephemeral, pageWorker, seats.devices[1]), aclTestNow)
	if err != nil {
		t.Fatal(err)
	}
	wantRemoves := []AclNonReader{{SidecarId: agent, Reason: AclReasonNotMemberDevice}, {SidecarId: gone, Reason: AclReasonUnadmitted}}
	slices.SortFunc(wantRemoves, func(a AclNonReader, b AclNonReader) int { return a.SidecarId.Cmp(b.SidecarId) })
	if !slices.Equal(plan.Seated, []Id{seats.devices[0]}) || !slices.Equal(plan.Removes, wantRemoves) ||
		!slices.Equal(plan.Adds, []Id{seats.devices[1], pageWorker}) || len(plan.Waiting) != 0 || plan.FreeSeats != aclRepoSeatCount-3 {
		t.Errorf("seated %v, removes %v, adds %v, waiting %v, %d free", plan.Seated, plan.Removes, plan.Adds, plan.Waiting, plan.FreeSeats)
	}
	// a leaf twice in the caller's list is one leaf
	plan, err = AclDataSeats(state, seats.repoId, []Id{seats.devices[0], seats.devices[0]}, aclTestSet(), aclTestNow)
	if err != nil || !slices.Equal(plan.Seated, []Id{seats.devices[0]}) || plan.FreeSeats != aclRepoSeatCount-1 {
		t.Errorf("a repeated leaf: %v, %+v", err, plan)
	}
}

// The config group and a team directory's seat by §7.9's leaves rule, so AclDataSeats has no plan for them, nor for a
// repo the rows do not hold, nor for a deleted one, whose leaves no plan removes while its readers may return
// (owner decision 182, §10.8).
func TestAclDataSeatsRefusesTheConfigAndADirectory(t *testing.T) {
	seats := newAclSeatsFixture(1)
	configId, _ := seats.repo(protocol.RepoKind_REPO_KIND_CONFIG, Id{})
	directoryId, _ := seats.repo(protocol.RepoKind_REPO_KIND_DIRECTORY, Id{})
	deletedId, deleted := seats.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	deleted.Deletion = &protocol.AclRepoDeletionRow{DeletionId: NewId().Bytes(), DeletedAt: seats.next()}
	restoredId, restored := seats.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	restored.Deletion = &protocol.AclRepoDeletionRow{DeletionId: NewId().Bytes(), DeletedAt: seats.next(), RestoredAt: seats.next()}
	state := seats.state(t)
	if _, err := AclDataSeats(state, restoredId, seats.devices, nil, aclTestNow); err != nil {
		t.Errorf("a restored repo: %v", err)
	}
	for _, repoId := range []Id{configId, directoryId, deletedId, NewId()} {
		if _, err := AclDataSeats(state, repoId, nil, aclTestSet(seats.devices...), aclTestNow); !errors.Is(err, ErrAclNoDataSeats) {
			t.Errorf("%s: %v", repoId, err)
		}
	}
	if _, err := AclDataSeats(nil, seats.repoId, nil, nil, aclTestNow); !errors.Is(err, ErrAclNoDataSeats) {
		t.Errorf("no state: %v", err)
	}
	for _, kind := range []protocol.RepoKind{protocol.RepoKind_REPO_KIND_RECORD, protocol.RepoKind_REPO_KIND_TEAM_RECORD,
		protocol.RepoKind_REPO_KIND_MAILCFG, protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_SECRET} {
		fixture := newAclTestFixture()
		repoId, _ := fixture.repo(kind, fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER))
		if _, err := AclDataSeats(fixture.state(t), repoId, nil, nil, aclTestNow); err != nil {
			t.Errorf("%s is a data repo: %v", kind, err)
		}
	}
}

// The preview follows the trees the writer holds: a seated later-admitted device keeps its seat and an earlier one is
// named; with no tree it names the repo's steady state, the earliest-admitted 1,000 seated; a repo of 1,000 readers, a
// deleted one and the config are never named, nor anything in a network of 1,000 member devices or fewer.
func TestAclUnseatedFollowsTheTreesItKnows(t *testing.T) {
	seats := newAclSeatsFixture(aclRepoSeatCount + 1)
	early, last := seats.devices[0], seats.devices[aclRepoSeatCount]
	exactId, _ := seats.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	deletedId, deleted := seats.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	deleted.Deletion = &protocol.AclRepoDeletionRow{DeletionId: NewId().Bytes(), DeletedAt: seats.next()}
	configId, _ := seats.repo(protocol.RepoKind_REPO_KIND_CONFIG, Id{})
	seats.rule([]Id{seats.group(seats.memberId)}, []*protocol.AclTarget{aclRepoTarget(deletedId)}, protocol.AclAction_ACL_ACTION_READ)
	// exactly 1,000 read the second repo
	for _, sidecarId := range seats.devices[1:] {
		seats.rule([]Id{seats.sidecarAtom(sidecarId)}, []*protocol.AclTarget{aclRepoTarget(exactId)}, protocol.AclAction_ACL_ACTION_READ)
	}
	state := seats.state(t)

	want := []AclUnseatedRepo{{RepoId: seats.repoId, ReaderCount: aclRepoSeatCount + 1, SidecarIds: []Id{last}}}
	if got := AclUnseated(state, nil, aclTestNow); !slices.EqualFunc(got, want, aclTestUnseatedEqual) {
		t.Errorf("no trees: %+v", got)
	}
	trees := map[Id][]Id{seats.repoId: seats.devices[1:], configId: seats.devices}
	want[0].SidecarIds = []Id{early}
	if got := AclUnseated(state, trees, aclTestNow); !slices.EqualFunc(got, want, aclTestUnseatedEqual) {
		t.Errorf("the writer's trees: %+v", got)
	}
	// a tree with a free seat names one fewer: the earliest waiting device takes it
	trees[seats.repoId] = seats.devices[2:]
	want[0].SidecarIds = []Id{seats.devices[1]}
	if got := AclUnseated(state, trees, aclTestNow); !slices.EqualFunc(got, want, aclTestUnseatedEqual) {
		t.Errorf("a tree with a free seat: %+v", got)
	}

	seats.admission(last).Row.RevokedAt = seats.next()
	if got := AclUnseated(seats.state(t), nil, aclTestNow); len(got) != 0 {
		t.Errorf("1,000 member devices: %+v", got)
	}
}

// Through the config log's own state, the view every reader holds: §7.9's leaves rule seats the config group, so the
// 1,001st live member device takes a wrap there and no leaf, while a data repo it reads names it in the preview; once
// an entitled device is revoked, it is entitled to the config leaf, and the data repo's freed seat is its.
func TestAclSeatsOnTheConfigLogsState(t *testing.T) {
	net := newTestConfigNet(t)
	member := testConfigId("seated member")
	configId, repoId := testConfigId("seats config repo"), testConfigId("seats data repo")
	rows := net.log.State().Rows()
	rows.Members = append(rows.Members, &bridge.MemberRow{MemberId: member.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER})
	seated := []Id{net.owner.sidecarId}
	for i := range aclRepoSeatCount - 1 {
		device := testConfigId(fmt.Sprintf("seats device %d", i))
		rows.Sidecars = append(rows.Sidecars, &bridge.SidecarRow{
			SidecarId: device.Bytes(), AdmissionSigners: [][]byte{net.owner.sidecarId.Bytes()}, AdmittedAt: 1, LiveSince: 1,
			IdentityPublicKey: testConfigDeviceKey("seats").Public().(ed25519.PublicKey), IdentityAlg: configIdentityAlgEd25519,
			MemberId: member.Bytes(),
		})
		seated = append(seated, device)
	}
	rows.Acl = testConfigMarshal(t, &protocol.AclRows{
		HasDocument: true,
		Rules: []*protocol.AclRule{{
			RuleId:   testConfigId("seats rule").Bytes(),
			SrcAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:  []*protocol.AclTarget{{RepoId: repoId.Bytes()}},
			Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_READ), uint32(protocol.AclAction_ACL_ACTION_WRITE)},
		}},
		Repos: []*protocol.AclRepo{
			{RepoId: configId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_CONFIG},
			{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
		},
	})
	if verdict := net.pushBase(net.owner, rows, net.n, 2, 0); !verdict.Accepted() {
		t.Fatalf("the base: %v", verdict.Refusal)
	}
	extra := net.device("seats the 1,001st", member)
	net.admitDevice(net.owner, extra, 0)

	state := net.log.State()
	acl, err := state.Acl()
	if err != nil {
		t.Fatal(err)
	}
	now := time.UnixMilli(state.TimeMs())
	if decision := acl.CheckRepoMember(configId, aclTestLeaf(seated[1]), now); !decision.Allowed {
		t.Errorf("an entitled device's config leaf: %+v", decision)
	}
	if decision := acl.CheckRepoMember(configId, aclTestLeaf(extra.sidecarId), now); decision.Allowed || decision.Reason != AclReasonNotLeafEntitled {
		t.Errorf("the 1,001st's config leaf: %+v", decision)
	}
	if decision := acl.CheckRepoMember(configId, aclTestWrap(extra.sidecarId), now); !decision.Allowed {
		t.Errorf("the 1,001st's config wrap: %+v", decision)
	}
	plan, err := AclDataSeats(acl, repoId, seated, aclTestSet(extra.sidecarId), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Seated) != aclRepoSeatCount || len(plan.Adds) != 0 || !slices.Equal(plan.Waiting, []Id{extra.sidecarId}) {
		t.Errorf("the data repo: %d seated, adds %v, waiting %v", len(plan.Seated), plan.Adds, plan.Waiting)
	}
	want := []AclUnseatedRepo{{RepoId: repoId, ReaderCount: aclRepoSeatCount + 1, SidecarIds: []Id{extra.sidecarId}}}
	if got := AclUnseated(acl, map[Id][]Id{repoId: seated}, now); !slices.EqualFunc(got, want, aclTestUnseatedEqual) {
		t.Errorf("the preview: %+v", got)
	}

	revoked := seated[5]
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, &bridge.SidecarRevoke{
		Header: net.header(), SidecarId: revoked.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED,
	})
	state = net.log.State()
	if acl, err = state.Acl(); err != nil {
		t.Fatal(err)
	}
	now = time.UnixMilli(state.TimeMs())
	if decision := acl.CheckRepoMember(configId, aclTestLeaf(extra.sidecarId), now); !decision.Allowed {
		t.Errorf("the promoted device's config leaf: %+v", decision)
	}
	if got := acl.NonReaders(repoId, seated, now); !slices.Equal(got, []AclNonReader{{SidecarId: revoked, Reason: AclReasonRevoked}}) {
		t.Errorf("non-readers after the revocation: %+v", got)
	}
	plan, err = AclDataSeats(acl, repoId, seated, aclTestSet(extra.sidecarId), now)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Removes, []AclNonReader{{SidecarId: revoked, Reason: AclReasonRevoked}}) || !slices.Equal(plan.Adds, []Id{extra.sidecarId}) ||
		len(plan.Waiting) != 0 {
		t.Errorf("the freed seat: removes %v, adds %v, waiting %v", plan.Removes, plan.Adds, plan.Waiting)
	}
	if got := AclUnseated(acl, nil, now); len(got) != 0 {
		t.Errorf("the preview after the revocation: %+v", got)
	}
}
