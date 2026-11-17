//go:build !js && !ios && !android && !sdk_mobile_bind

package sidecar

// A remote-mode app's request methods (MCP-M8-01; §16.6's host table, D-SDK-9) on the dispatcher with no socket, over
// the approver tests' world: the list shows another sidecar's request on channel device with approve and deny and the
// daemon's own with no decision; a confirmed decision on another's request signs it by the identity key and files it;
// the daemon's own is refused whatever is sent; an unconfirmed call, or one from mcp or a hook, runs nothing; and params
// the method does not take are refused.

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The approver world's sidecar on a daemon serving the app methods, its approver log the world's.
func newTestApprovalsAppDaemon(t *testing.T, world *testApproverWorld) *Daemon {
	t.Helper()
	t.Cleanup(world.sidecar.InstallApproverLog(world.log))
	daemon := newDispatchTestDaemon(t)
	if err := daemon.AddSidecar(NewId(), world.sidecar); err != nil {
		t.Fatal(err)
	}
	for _, method := range DaemonApprovalsAppMethods() {
		if err := daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	return daemon
}

// One call in mode: its reply decoded into reply, or the rpc's error.
func testApprovalsAppCall(t *testing.T, daemon *Daemon, mode string, method string, params any, confirmed bool, reply any) *DaemonRpcError {
	t.Helper()
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(&daemonRpcRequest{JsonRpc: "2.0", Id: json.RawMessage("1"), Method: method, Params: encoded, UrConfirmed: confirmed})
	if err != nil {
		t.Fatal(err)
	}
	response := dispatchTest(daemon, mode, string(line))
	if response.Error != nil {
		return response.Error
	}
	if reply != nil {
		if err := json.Unmarshal(response.Result, reply); err != nil {
			t.Fatal(err)
		}
	}
	return nil
}

// The list and the decisions as the remote-mode row gives them.
func TestApprovalsAppMethodsDecideAsTheRemoteRow(t *testing.T) {
	world := newTestApproverWorld(t)
	daemon := newTestApprovalsAppDaemon(t, world)
	identity := world.sidecar.currentIdentity()
	own := world.put(identity.SidecarId, testApproverDnsSet(t, "198.51.100.7"), "agent words")
	other := world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.8"), "")

	reply := &DaemonApprovalsAppReply{}
	if refusal := testApprovalsAppCall(t, daemon, DaemonModeControl, DaemonMethodApprovalsAppRequests, &DaemonApprovalsAppParams{}, false, reply); refusal != nil {
		t.Fatal(refusal)
	}
	if len(reply.Items) != 2 {
		t.Fatalf("%d items", len(reply.Items))
	}
	for _, item := range reply.Items {
		if item.ApprovalId == nil || item.SidecarId == nil || item.Kind != "dns_set" || item.Text == "" {
			t.Fatalf("an item: %+v", item)
		}
		switch *item.ApprovalId {
		case own.ApprovalId():
			if *item.SidecarId != identity.SidecarId || item.Channel != "" || len(item.Decisions) != 0 || !strings.Contains(item.Text, "agent words") {
				t.Errorf("the daemon's own request: %+v", item)
			}
		case other.ApprovalId():
			if *item.SidecarId != world.requesterId || item.Channel != "device" || !slices.Equal(item.Decisions, []string{SidecarDecisionApprove, SidecarDecisionDeny}) {
				t.Errorf("another sidecar's request: %+v", item)
			}
		}
	}

	decide := func(mode string, confirmed bool, params any) *DaemonRpcError {
		return testApprovalsAppCall(t, daemon, mode, DaemonMethodApprovalsAppRequest, params, confirmed, nil)
	}
	approveOther := &DaemonApprovalsAppDecideParams{ApprovalId: other.ApprovalId(), Decision: SidecarDecisionApprove}
	for _, call := range []struct {
		mode      string
		confirmed bool
	}{{mode: DaemonModeControl, confirmed: false}, {mode: DaemonModeMcp, confirmed: true}, {mode: DaemonModeHook, confirmed: true}} {
		if refusal := decide(call.mode, call.confirmed, approveOther); refusal == nil || refusal.Code != DaemonRpcConfirmationRequired {
			t.Errorf("mode %s, confirmed %t: %+v", call.mode, call.confirmed, refusal)
		}
	}
	for _, params := range []any{
		map[string]any{"approval_id": other.ApprovalId(), "decision": "approve", "uses": 2},
		&DaemonApprovalsAppDecideParams{ApprovalId: other.ApprovalId(), Decision: SidecarDecisionRevoke},
		&DaemonApprovalsAppDecideParams{Decision: SidecarDecisionApprove},
	} {
		if refusal := decide(DaemonModeControl, true, params); refusal == nil || refusal.Code != DaemonRpcFailed {
			t.Errorf("params %+v: %+v", params, refusal)
		}
	}
	for _, decision := range []string{SidecarDecisionApprove, SidecarDecisionDeny} {
		refusal := decide(DaemonModeControl, true, &DaemonApprovalsAppDecideParams{ApprovalId: own.ApprovalId(), Decision: decision})
		if refusal == nil || !strings.Contains(refusal.Message, ErrSidecarApprovalNotEligible.Error()) {
			t.Errorf("the app's %s of the daemon's own request: %+v", decision, refusal)
		}
	}
	if world.decisionCount() != 0 {
		t.Fatalf("%d decisions filed", world.decisionCount())
	}
	if refusal := decide(DaemonModeControl, true, approveOther); refusal != nil {
		t.Fatal(refusal)
	}
	decision := world.lastDecision()
	if decision.Decision.GetChannel() != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE) || !decision.Binds(other) || world.decisionCount() != 1 {
		t.Errorf("the app's decision: %+v", decision.Decision)
	}
}
