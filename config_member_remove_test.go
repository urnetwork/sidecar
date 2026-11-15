// TEAM-M6-11's member removal on the device, on the test network and the act harness: the plan names the member's
// devices, its tagged agents and the repos that rotate; an AdminSet member's MemberRevoke is k of n; from its position
// every reader masks the member's devices in the directory and never its tagged agents, which keep their grants under
// autogroup:admin until a SponsorSet, and the config's holders shrink there so a write needs a covering generation
// (FS-87's M6 masking and gate cases, Q-TEAM-8); the server's denials owed a signature; and the act: confirmed only,
// one MemberRevoke posted, its effects committing each revoked device and tracking the position, a k = 2 proposal's
// effects waiting for the completing entry.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network with a member, its consented device and a tagged agent it admitted, sponsored by it.
func newTestConfigMemberRemoveNet(t *testing.T) (*testConfigNet, Id, testConfigDevice, testConfigDevice) {
	t.Helper()
	net := newTestConfigNet(t)
	member, first := net.consentedMember("leaving")
	tagId := testConfigId("leaving tag")
	net.withTagOwner(tagId, member)
	agent := net.device("leaving agent", Id{})
	net.mustPost(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(agent, []Id{tagId}, false, net.timeMs+24*60*60*1000, 0))
	if sponsor, ok := net.log.State().Sponsor(agent.sidecarId); !ok || sponsor != member {
		t.Fatalf("the agent's sponsor: %v %v", sponsor, ok)
	}
	return net, member, first, agent
}

// The plan of a removal outside the AdminSet: one Owner's or Admin's signature, the member's device revoked, its agent
// kept, and the config among the repos whose holders shrink.
func TestAMemberRevokePlanNamesDevicesAgentsAndRepos(t *testing.T) {
	net, member, first, agent := newTestConfigMemberRemoveNet(t)
	plan, err := net.log.State().MemberRevokePlan(member)
	if err != nil {
		t.Fatal(err)
	}
	if plan.AdminSet || plan.Signatures != 1 || plan.MemberId != member || !proto.Equal(plan.Pin, net.log.State().Pin()) {
		t.Errorf("the plan: admin set %v, %d signatures", plan.AdminSet, plan.Signatures)
	}
	if !slices.Equal(plan.DeviceIds, []Id{first.sidecarId}) || !slices.Equal(plan.AgentIds, []Id{agent.sidecarId}) {
		t.Errorf("devices %v, agents %v", plan.DeviceIds, plan.AgentIds)
	}
	if !slices.Contains(plan.ReposRotating, net.configRepoId()) {
		t.Errorf("the config is not among the repos that rotate: %v", plan.ReposRotating)
	}
	if _, err := net.log.State().MemberRevokePlan(testConfigId("nobody")); !errors.Is(err, ErrMemberPlanNoMember) {
		t.Errorf("an unknown member: %v", err)
	}
}

// An AdminSet member's MemberRevoke is an authority statement: k of n, here 2 of 3.
func TestAMemberRevokePlanOfAnAdminSetMemberNeedsKOfN(t *testing.T) {
	team := newTestConfigTeam(t)
	plan, err := team.log.State().MemberRevokePlan(team.adminC.memberId)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.AdminSet || plan.Signatures != 2 || !slices.Equal(plan.DeviceIds, []Id{team.adminC.sidecarId}) {
		t.Errorf("the plan: admin set %v, %d signatures, devices %v", plan.AdminSet, plan.Signatures, plan.DeviceIds)
	}
}

// FS-87's M6 masking: before the MemberRevoke's position no reader masks the member's device, from it every reader
// does, a second reader alike, and the tagged agent never; the agent keeps its grants with autogroup:admin as its
// sponsor until a SponsorSet; and the config's holders shrink at that position, so a write needs a generation covering
// it (§7.10's gate).
func TestAMemberRevokeMasksItsDevicesFromItsPosition(t *testing.T) {
	net, member, first, agent := newTestConfigMemberRemoveNet(t)
	before := net.log.State()
	if before.MaskedInDirectory(first.sidecarId) || before.MaskedInDirectory(agent.sidecarId) {
		t.Fatal("masked before the removal")
	}
	revoked := net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: member.Bytes()})
	position := revoked.Pin.GetVersion()
	for name, state := range map[string]*ConfigState{"the reader": net.log.State(), "a second reader": net.newReader().State()} {
		if !state.MaskedInDirectory(first.sidecarId) {
			t.Errorf("%s does not mask the removed member's device", name)
		}
		if state.MaskedInDirectory(agent.sidecarId) {
			t.Errorf("%s masks the removed member's tagged agent", name)
		}
	}
	if net.statesAt[position-1].MaskedInDirectory(first.sidecarId) {
		t.Error("the state before the removal masks the device")
	}
	state := net.log.State()
	if _, ok := state.Sponsor(agent.sidecarId); ok {
		t.Error("a removed member still sponsors its agent")
	}
	if row := state.SidecarRow(agent.sidecarId); row.GetRevokedAt() != 0 || len(row.GetTagIds()) == 0 {
		t.Error("the agent lost its admission or its tags")
	}
	if shrunkAt := state.ShrunkAt(net.configRepoId()); shrunkAt != position {
		t.Errorf("the config's holders shrank at %d, the removal is at %d", shrunkAt, position)
	}
	// the directory's own view asks the same
	view := &configDirectoryAuth{state: state}
	if !view.Masked(first.sidecarId) || view.Masked(agent.sidecarId) {
		t.Error("the directory's view disagrees with the state's mask")
	}
	// a never-admitted sidecar is the standing rule's, not the mask's
	if state.MaskedInDirectory(testConfigId("a stranger")) {
		t.Error("a sidecar never admitted is masked")
	}
}

// The members the config holds that api no longer lists are the removals api denied and no device signed.
func TestUnsignedMemberRemovalsAreTheConfigsMembersApiDropped(t *testing.T) {
	net, member, _, _ := newTestConfigMemberRemoveNet(t)
	other, _ := net.consentedMember("staying")
	state := net.log.State()
	if owed := state.UnsignedMemberRemovals([]Id{net.ownerMemberId, member, other}); len(owed) != 0 {
		t.Errorf("owed with every member listed: %v", owed)
	}
	if owed := state.UnsignedMemberRemovals([]Id{net.ownerMemberId, other}); !slices.Equal(owed, []Id{member}) {
		t.Errorf("owed: %v", owed)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: member.Bytes()})
	if owed := net.log.State().UnsignedMemberRemovals([]Id{net.ownerMemberId, other}); len(owed) != 0 {
		t.Errorf("owed once signed: %v", owed)
	}
}

// An act authority that holds the test network's state, which the member's removal plans from, and says whether a
// proposal pends.
type testMemberRemoveAuthority struct {
	*testActAuthority
	stateLock sync.Mutex
	state     *ConfigState
	pending   map[string]bool
}

func (self *testMemberRemoveAuthority) State() *ConfigState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state
}

func (self *testMemberRemoveAuthority) setState(state *ConfigState) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.state = state
}

// Changes the act authority's state under its lock.
func (self *testMemberRemoveAuthority) edit(change func()) {
	self.testActAuthority.stateLock.Lock()
	defer self.testActAuthority.stateLock.Unlock()
	change()
}

func (self *testMemberRemoveAuthority) PendingProposal(proposalId []byte) *bridge.ProposalRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.pending[string(proposalId)] {
		return &bridge.ProposalRow{}
	}
	return nil
}

func (self *testMemberRemoveAuthority) Settings() *bridge.ProjectionSettings {
	return self.State().Settings()
}

// The act harness's sidecar with the member-removal authority over the test network, and its effects installed.
func newTestMemberRemoveSidecar(t *testing.T, net *testConfigNet) (*Sidecar, *testMemberRemoveAuthority, *testDeltaApi, *revokeTestEffects) {
	t.Helper()
	sidecar, actAuthority, deltaApi := newActTestSidecar(t)
	authority := &testMemberRemoveAuthority{testActAuthority: actAuthority, state: net.log.State(), pending: map[string]bool{}}
	t.Cleanup(sidecar.InstallAuthority(authority))
	effects := newRevokeTestEffects()
	t.Cleanup(sidecar.InstallRevokeEffects(effects))
	return sidecar, authority, deltaApi, effects
}

// The act: never through MCP, a hook or an unconfirmed call; on a person's confirmation one MemberRevoke of the
// member, which lands and is tracked at its position; and its effects at a landed entry commit each device the entry
// revoked, then track the position.
func TestSignMemberRevokePostsOneMemberRevoke(t *testing.T) {
	net, member, first, _ := newTestConfigMemberRemoveNet(t)
	sidecar, authority, deltaApi, effects := newTestMemberRemoveSidecar(t, net)
	ctx := context.Background()
	for _, origin := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		if _, err := sidecar.SignMemberRevoke(ctx, member, origin, nil); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("origin %d: %v", origin, err)
		}
	}
	if posts := deltaApi.postsSoFar(); len(posts) != 0 {
		t.Fatalf("%d statements posted before the confirmed call", len(posts))
	}
	revocation, err := sidecar.SignMemberRevoke(ctx, member, SidecarActConfirmed, nil)
	if err != nil {
		t.Fatal(err)
	}
	posts := deltaApi.postsSoFar()
	if len(posts) != 1 {
		t.Fatalf("posted %d statements", len(posts))
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(posts[0], signed); err != nil || bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_MEMBER_REVOKE {
		t.Fatalf("the posted statement: %v %v", signed.GetType(), err)
	}
	revoke := &bridge.MemberRevoke{}
	postedBody(t, signed, revoke)
	if !bytes.Equal(revoke.GetMemberId(), member.Bytes()) || revocation.Entry == nil || revocation.ProposalId != nil || revocation.Pending {
		t.Fatalf("the revocation: %+v, %+v", revoke, revocation)
	}
	if !slices.Equal(revocation.Plan.DeviceIds, []Id{first.sidecarId}) {
		t.Errorf("the plan signed: %v", revocation.Plan.DeviceIds)
	}
	// the harness's api lands it at a position the test network never held, where no device is revoked: tracked
	// alone
	calls, positions := effects.snapshot()
	if !slices.Equal(calls, []string{"track"}) || positions[0] != revocation.Entry.GetVersion() {
		t.Errorf("the effects: %v at %v", calls, positions)
	}

	// at the entry where the network's log applied it, the device that entry revoked is committed first
	landed := net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_REVOKE, &bridge.MemberRevoke{Header: net.header(), MemberId: member.Bytes()})
	authority.setState(net.log.State())
	sidecar.runMemberRevokeEffects(ctx, member, landed.Pin)
	calls, positions = effects.snapshot()
	if !slices.Equal(calls, []string{"track", "commit", "track"}) || positions[1] != landed.Pin.GetVersion() {
		t.Errorf("the effects: %v at %v", calls, positions)
	}
	if !slices.Equal(effects.sidecars, []Id{first.sidecarId}) {
		t.Errorf("committed %v", effects.sidecars)
	}
}

// At k = 2, an AdminSet member's removal, the act posts an AuthorityProposal of the MemberRevoke and runs no effect; a MemberRevoke of the member that
// lands while the proposal still pends runs none either; the entry where it completes runs them.
func TestSignMemberRevokeAtK2WaitsForItsCompletion(t *testing.T) {
	team := newTestConfigTeam(t)
	member := team.adminC.memberId
	sidecar, authority, deltaApi, effects := newTestMemberRemoveSidecar(t, team.testConfigNet)
	ctx := context.Background()
	revocation, err := sidecar.SignMemberRevoke(ctx, member, SidecarActConfirmed, nil)
	if err != nil {
		t.Fatal(err)
	}
	posts := deltaApi.postsSoFar()
	signed := &bridge.Signed{}
	if len(posts) != 1 || proto.Unmarshal(posts[0], signed) != nil || bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL {
		t.Fatalf("posted %d statements", len(posts))
	}
	proposal := &protocol.AuthorityProposal{}
	postedBody(t, signed, proposal)
	if bridge.SignedType(proposal.GetStatementType()) != bridge.SignedType_SIGNED_MEMBER_REVOKE || revocation.Entry != nil || len(revocation.ProposalId) != 32 {
		t.Fatalf("the proposal: type %d, entry %v, id %x", proposal.GetStatementType(), revocation.Entry, revocation.ProposalId)
	}
	if calls, _ := effects.snapshot(); len(calls) != 0 {
		t.Fatalf("effects before the completion: %v", calls)
	}
	body, _ := proto.Marshal(&bridge.MemberRevoke{MemberId: member.Bytes()})
	entry := func(n uint64) *SidecarAuthorityEntry {
		return &SidecarAuthorityEntry{
			Pin:     &bridge.AuthPin{Version: n, Chain: countingBytes(byte(n), 32)},
			TimeMs:  sidecar.clock.Now().UnixMilli(),
			Applied: true,
			Effects: []*SidecarAuthorityEffect{{Type: bridge.SignedType_SIGNED_MEMBER_REVOKE, Body: body}},
		}
	}
	func() {
		authority.stateLock.Lock()
		defer authority.stateLock.Unlock()
		authority.pending[string(revocation.ProposalId)] = true
	}()
	authority.apply(entry(50))
	if calls, _ := effects.snapshot(); len(calls) != 0 {
		t.Fatalf("effects while the proposal pends: %v", calls)
	}
	func() {
		authority.stateLock.Lock()
		defer authority.stateLock.Unlock()
		delete(authority.pending, string(revocation.ProposalId))
	}()
	authority.apply(entry(51))
	select {
	case <-effects.done:
	case <-time.After(10 * time.Second):
		t.Fatal("no effects at the completing entry")
	}
	if calls, positions := effects.snapshot(); !slices.Equal(calls, []string{"track"}) || positions[0] != 51 {
		t.Errorf("the effects: %v at %v", calls, positions)
	}
	// the watch ended there: a later entry runs nothing
	authority.apply(entry(52))
	if calls, _ := effects.snapshot(); len(calls) != 1 {
		t.Errorf("a second run: %v", calls)
	}
}
