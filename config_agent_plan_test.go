// TEAM-M2-18's AgentRevokePlan on the test network: for a Delegation's agent each act names the agent, the Delegation's
// shared reader key with the agents that then read by their own ReaderWraps and the repos that rotate, and its
// admission authority apart; only --compromise ends the authority, any other act offering `ur admin delegations
// revoke`; FS-102 part 2's plan names D's key as retired and D as still admitting; and the acts' statements.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network whose owner delegated tag ci to a Delegation that admitted two agents, and a repo a grant to ci reads.
func newTestConfigAgentNet(t *testing.T) (*testConfigNet, *testConfigDelegation, testConfigDevice, testConfigDevice, Id) {
	net, ci, _ := newTestConfigTagNet(t)
	day := int64(24 * 60 * 60 * 1000)
	delegation := net.delegate(net.owner, "ci", []Id{ci}, 5, net.timeMs+30*day)
	first, second := net.device("agent one", Id{}), net.device("agent two", Id{})
	for _, agent := range []testConfigDevice{first, second} {
		if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, agent, false, delegation.notAfter)); !verdict.Accepted() {
			t.Fatal(verdict.Refusal)
		}
	}
	repoId := testConfigId("ci repo")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
		Header: net.header(), RepoId: repoId.Bytes(), Subject: ci.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
	})
	return net, delegation, first, second, repoId
}

// FS-102 part 2: a Suspend of a Delegation's agent retires its shared key, the other agent then reading by its own
// ReaderWrap and the repo the Delegation reaches rotating, and leaves the Delegation admitting, which the plan offers
// to end; the plan's statement is the Suspend.
func TestAnAgentPlanNamesItsThreeCapabilitiesApart(t *testing.T) {
	net, delegation, first, second, repoId := newTestConfigAgentNet(t)
	plan, err := net.log.State().AgentRevokePlan(first.sidecarId, AgentActSuspend, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	part := plan.Delegation
	if part == nil || !bytes.Equal(part.DelegationId, delegation.id) {
		t.Fatalf("the plan names no Delegation: %+v", plan)
	}
	if !part.KeyRetires || !slices.Equal(part.AgentsOnOwnWraps, []Id{second.sidecarId}) || !slices.Contains(part.ReposRotating, repoId) {
		t.Errorf("the shared key: retires %v, own wraps %v, rotating %v", part.KeyRetires, part.AgentsOnOwnWraps, part.ReposRotating)
	}
	if part.AuthorityEnds || part.AdmissionsLeft != 3 || part.NotAfter.UnixMilli() != delegation.notAfter {
		t.Errorf("the authority: ends %v, %d left, until %v", part.AuthorityEnds, part.AdmissionsLeft, part.NotAfter)
	}
	if !strings.Contains(plan.Offer, "ur admin delegations revoke") {
		t.Errorf("no offer to end the Delegation: %q", plan.Offer)
	}
	if len(plan.statements) != 1 || plan.statements[0].signedType != bridge.SignedType_SIGNED_SUSPEND {
		t.Errorf("the statements: %v", plan.statements)
	}

	// only --compromise ends the authority, and then nothing is offered
	compromise, err := net.log.State().AgentRevokePlan(first.sidecarId, AgentActRevoke, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !compromise.Delegation.AuthorityEnds || compromise.Offer != "" || compromise.SinceN == 0 {
		t.Errorf("a compromise revocation: ends %v, offer %q, since %d", compromise.Delegation.AuthorityEnds, compromise.Offer, compromise.SinceN)
	}
	revoke := compromise.statements[0].statement.(*bridge.SidecarRevoke)
	if revoke.GetReason() != bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE || revoke.GetSinceN() != compromise.SinceN {
		t.Errorf("the revocation: %v", revoke)
	}
	plain, err := net.log.State().AgentRevokePlan(first.sidecarId, AgentActRevoke, false, 0)
	if err != nil || plain.Delegation.AuthorityEnds || plain.Offer == "" {
		t.Errorf("a plain revocation ends the authority: %v", err)
	}
}

// What the acts refuse: a member's own device, an Unsuspend of an agent no Suspend names, --compromise on a Suspend; and
// after the Suspend lands, an Unsuspend names its suspend_id and leaves the key as it is.
func TestAnAgentPlanRefusesWhatChangesNothing(t *testing.T) {
	net, _, first, _, _ := newTestConfigAgentNet(t)
	state := net.log.State()
	if _, err := state.AgentRevokePlan(net.owner.sidecarId, AgentActRevoke, false, 0); !errors.Is(err, ErrAgentPlanNoAgent) {
		t.Errorf("a member's device: %v", err)
	}
	if _, err := state.AgentRevokePlan(first.sidecarId, AgentActUnsuspend, false, 0); !errors.Is(err, ErrAgentPlanNothing) {
		t.Errorf("an Unsuspend of no Suspend: %v", err)
	}
	if _, err := state.AgentRevokePlan(first.sidecarId, AgentActSuspend, true, 0); err == nil {
		t.Error("a Suspend for compromise")
	}
	suspendId := aclTestSuspendId("agent one")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: first.sidecarId.Bytes(), SuspendId: suspendId})
	plan, err := net.log.State().AgentRevokePlan(first.sidecarId, AgentActUnsuspend, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	unsuspend := plan.statements[0].statement.(*bridge.Unsuspend)
	if !bytes.Equal(unsuspend.GetSuspendId(), suspendId) || plan.Delegation.KeyRetires {
		t.Errorf("the Unsuspend: %v, key retires %v", unsuspend, plan.Delegation.KeyRetires)
	}
}

// `ur admin delegations` lists each Delegation's key and admission state, and a leaked bundle's DelegationRevoke parks
// from since_n, never before the Delegation's own entry.
func TestDelegationStatesAndRevokeStatement(t *testing.T) {
	net, delegation, first, second, _ := newTestConfigAgentNet(t)
	states := net.log.State().DelegationStates()
	if len(states) != 1 || !bytes.Equal(states[0].DelegationId, delegation.id) || states[0].AdmissionsLeft != 3 ||
		!slices.Contains(states[0].AgentIds, first.sidecarId) || !slices.Contains(states[0].AgentIds, second.sidecarId) {
		t.Fatalf("the Delegations: %+v", states)
	}
	revoke, err := net.log.State().DelegationRevokeStatement(delegation.id, true, 1)
	if err != nil || revoke.GetSinceN() != states[0].At {
		t.Errorf("a leaked bundle's revoke: %v %v", revoke, err)
	}
	plain, err := net.log.State().DelegationRevokeStatement(delegation.id, false, 7)
	if err != nil || plain.GetSinceN() != 0 {
		t.Errorf("a plain revoke: %v %v", plain, err)
	}
}
