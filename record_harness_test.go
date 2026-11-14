//go:build !ios_extension

// MCP-M3-10's harness_ok, its state half, on a real config log (§16.6, D-MCP-9, D-MCP-14, Q-MCP-6, FS-28): a member
// with one approval-capable device may approve its own request by harness evidence; a Worker beside it keeps that, a
// second CLI or a presence key clears it; a tainted run counts it only where the requests rule's own list names it,
// never through evidenceDefault; only an O tool's own kinds take one; and the decision it signs spends.

package sidecar

import (
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A harness_ok world: the spend network, and a member with one device whose request is judged.
type testHarnessWorld struct {
	t      *testing.T
	net    *testSpendNet
	solo   Id
	device testConfigDevice
}

func newTestHarnessWorld(t *testing.T) *testHarnessWorld {
	t.Helper()
	net := newTestSpendNet(t)
	solo, device := net.consentedMember("harness solo")
	return &testHarnessWorld{t: t, net: net, solo: solo, device: device}
}

// The tip's approval states, compiled with no document.
func (self *testHarnessWorld) states() *ConfigApprovalStates {
	self.t.Helper()
	states, err := NewConfigApprovalStates(self.net.log.State(), false, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return states
}

// The world's device's request for action, tainted or not, naming approvers.
func (self *testHarnessWorld) request(action *StoredCanonicalAction, tainted bool, approvers ...Id) *StoredApprovalRequest {
	self.t.Helper()
	approvalId := NewId()
	actionId := action.ActionId(approvalId)
	payloadSha256 := action.PayloadSha256()
	approverBytes := [][]byte{}
	for _, approver := range approvers {
		approverBytes = append(approverBytes, approver.Bytes())
	}
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ApprovalRequest{
		ApprovalId: approvalId.Bytes(), ActionId: actionId[:], RunId: NewId().Bytes(), CanonicalAction: action.Bytes,
		PayloadSha256: payloadSha256[:], Risk: uint32(SidecarRiskNormal), Tainted: tainted,
		RequesterSidecarId: self.device.sidecarId.Bytes(), Approvers: approverBytes,
		NotAfterMillis: self.net.timeMs + time.Hour.Milliseconds(), Version: 1,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	request, err := ParseStoredApprovalRequest(stored)
	if err != nil {
		self.t.Fatal(err)
	}
	return request
}

// harness_ok's answer on request, at the tip, the run tainted now or not.
func (self *testHarnessWorld) ok(states HarnessStates, request *StoredApprovalRequest, runTainted bool) (Id, error) {
	return HarnessOk(states, &HarnessOkArgs{
		Request: request, Requester: self.device.sidecarId, RunTainted: runTainted, Now: time.UnixMilli(self.net.timeMs),
	})
}

// A member whose only approval-capable device is the requester, with no presence key, approves its own untainted
// request by harness evidence; a member with a second device, as the spend network's M is, does not.
func TestHarnessOkForALoneDevice(t *testing.T) {
	world := newTestHarnessWorld(t)
	request := world.request(testSpendDnsAction(t, "192.0.2.1"), false, world.solo)
	memberId, err := world.ok(world.states(), request, false)
	if err != nil || memberId != world.solo {
		t.Fatalf("a lone device: %s %v", memberId, err)
	}
	// another sidecar's request, and a request naming another approver, are not this daemon's to approve
	if _, err := HarnessOk(world.states(), &HarnessOkArgs{Request: request, Requester: world.net.laptop.sidecarId, Now: time.UnixMilli(world.net.timeMs)}); !errors.Is(err, ErrHarnessNotOk) {
		t.Errorf("another sidecar's request: %v", err)
	}
	if _, err := world.ok(world.states(), world.request(testSpendDnsAction(t, "192.0.2.1"), false, world.net.other), false); !errors.Is(err, ErrHarnessNotOk) {
		t.Errorf("a request naming another approver: %v", err)
	}
}

// A read_only Worker beside the requester keeps harness_ok, since it is no approval-capable device; a second CLI,
// which is, clears it (D-MCP-14).
func TestWorkerKeepsHarnessOkSecondCliClearsIt(t *testing.T) {
	world := newTestHarnessWorld(t)
	worker := world.net.device("harness solo worker", world.solo)
	world.net.admitDevice(world.device, worker, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	request := world.request(testSpendDnsAction(t, "192.0.2.2"), false, world.solo)
	if _, err := world.ok(world.states(), request, false); err != nil {
		t.Errorf("with a Worker beside it: %v", err)
	}
	second := world.net.device("harness solo second cli", world.solo)
	world.net.admitDevice(world.device, second, 0)
	if !world.states().ApprovalCapable(second.sidecarId, world.solo) {
		t.Fatal("the second CLI is not approval-capable")
	}
	if _, err := world.ok(world.states(), request, false); !errors.Is(err, ErrHarnessNotOk) {
		t.Errorf("with a second CLI: %v", err)
	}
}

// A presence key of the member clears harness_ok: the daemon prompts for it instead.
func TestPresenceKeyClearsHarnessOk(t *testing.T) {
	world := newTestHarnessWorld(t)
	world.net.registerPresenceKey(world.device, newTestPresenceKey(t, "harness solo key", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256))
	request := world.request(testSpendDnsAction(t, "192.0.2.3"), false, world.solo)
	if _, err := world.ok(world.states(), request, false); !errors.Is(err, ErrHarnessNotOk) {
		t.Errorf("with a presence key: %v", err)
	}
}

// A governing evidence list without harness refuses it: here evidenceDefault narrowed to device.
func TestEvidenceListWithoutHarnessRefused(t *testing.T) {
	world := newTestHarnessWorld(t)
	world.net.withAclRows(func(rows *protocol.AclRows) {
		rows.EvidenceDefault = []uint32{uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)}
	})
	request := world.request(testSpendDnsAction(t, "192.0.2.4"), false, world.solo)
	if _, err := world.ok(world.states(), request, false); !errors.Is(err, ErrHarnessNotOk) {
		t.Errorf("evidenceDefault without harness: %v", err)
	}
}

// The states with the requests rule's own list naming harness, as a compiled document's would.
type testHarnessRuleStates struct {
	*ConfigApprovalStates
}

func (self *testHarnessRuleStates) RuleNamesHarness(action *StoredCanonicalAction) bool {
	return true
}

// §22.5's §16 row: in a tainted run harness evidence counts only where a requests rule names it, never through
// evidenceDefault; a run tainted since its untainted request counts as tainted.
func TestTaintedRunCountsHarnessOnlyWhereARuleNamesIt(t *testing.T) {
	world := newTestHarnessWorld(t)
	action := testSpendDnsAction(t, "192.0.2.5")
	tainted := world.request(action, true, world.solo)
	if _, err := world.ok(world.states(), tainted, false); !errors.Is(err, ErrHarnessNotOk) {
		t.Errorf("a tainted request under evidenceDefault: %v", err)
	}
	untainted := world.request(action, false, world.solo)
	if _, err := world.ok(world.states(), untainted, true); !errors.Is(err, ErrHarnessNotOk) {
		t.Errorf("an untainted request of a run tainted since: %v", err)
	}
	named := &testHarnessRuleStates{ConfigApprovalStates: world.states()}
	if _, err := world.ok(named, tainted, true); err != nil {
		t.Errorf("a tainted request whose rule names harness: %v", err)
	}
}

// Only an O tool's own kinds take a harness decision; every other kind, and a template, is a person's to sign.
func TestHarnessKindsClosedList(t *testing.T) {
	outward := []SidecarActionKind{
		SidecarActionPublish, SidecarActionListen, SidecarActionForward, SidecarActionExpose,
		SidecarActionAliasCreate, SidecarActionAliasDelete, SidecarActionAgentConfigWrite, SidecarActionAgentConfigDelete,
		SidecarActionDnsSet, SidecarActionDnsDelete, SidecarActionMail, SidecarActionAccessRequest, SidecarActionRestore,
	}
	for kind := SidecarActionUnspecified; kind <= SidecarActionMailTlsUnauthenticated+1; kind += 1 {
		if HarnessDecisionKind(kind) != slices.Contains(outward, kind) {
			t.Errorf("kind %d: %t", kind, HarnessDecisionKind(kind))
		}
	}
	world := newTestHarnessWorld(t)
	for _, kind := range []SidecarActionKind{SidecarActionInvite, SidecarActionShare, SidecarActionEgressChange, SidecarActionPayment} {
		action := &StoredCanonicalAction{Action: &protocol.CanonicalAction{Kind: uint32(kind)}}
		request := &StoredApprovalRequest{
			Request: &protocol.ApprovalRequest{RequesterSidecarId: world.device.sidecarId.Bytes(), Approvers: [][]byte{world.solo.Bytes()}},
			Action:  action,
		}
		if _, err := world.ok(world.states(), request, false); !errors.Is(err, ErrHarnessNotOk) {
			t.Errorf("kind %d: %v", kind, err)
		}
	}
	template := &StoredCanonicalAction{Action: &protocol.CanonicalAction{Kind: uint32(SidecarActionDnsSet), Scope: true}}
	request := &StoredApprovalRequest{
		Request: &protocol.ApprovalRequest{RequesterSidecarId: world.device.sidecarId.Bytes(), Approvers: [][]byte{world.solo.Bytes()}},
		Action:  template,
	}
	if _, err := world.ok(world.states(), request, false); !errors.Is(err, ErrHarnessNotOk) {
		t.Errorf("a template: %v", err)
	}
}

// The decision harness_ok lets the daemon sign spends: channel harness, one use, its signer the requester itself, at
// the tip's pin. One citing no leaf is refused before anything is signed.
func TestHarnessDecisionSpends(t *testing.T) {
	world := newTestHarnessWorld(t)
	action := testSpendDnsAction(t, "192.0.2.6")
	request := world.request(action, false, world.solo)
	states := world.states()
	memberId, err := world.ok(states, request, false)
	if err != nil {
		t.Fatal(err)
	}
	leaf := make([]byte, 32)
	leaf[0] = 1
	body, err := HarnessDecisionBody(request, memberId, states.Pin(), leaf, time.UnixMilli(world.net.timeMs).Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	parsed := &protocol.ApprovalDecision{}
	if err := proto.Unmarshal(body, parsed); err != nil {
		t.Fatal(err)
	}
	signed := testSpendSignedBy(t, world.device.sidecarId, world.device.key, parsed)
	decision := testSpendParse(t, signed)
	input := &SpendInput{Action: action, Spender: world.device.sidecarId, Now: time.UnixMilli(world.net.timeMs)}
	if err := Spendable(decision, input, states.ConfigSpendState, nil); err != nil {
		t.Errorf("the harness decision does not spend: %v", err)
	}
	if decision.Decision.GetChannel() != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS) || decision.Decision.GetUses() != 1 {
		t.Errorf("decision %+v", decision.Decision)
	}
	if _, err := HarnessDecisionBody(request, memberId, states.Pin(), nil, time.UnixMilli(world.net.timeMs)); !errors.Is(err, ErrHarnessNotOk) {
		t.Errorf("a decision citing no leaf: %v", err)
	}
}
