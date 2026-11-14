package sidecar

// CORE-M3-01: §5.4's gate. With no gate, or a nil one, every action is refused; every kind of §5.4's list reaches the
// installed gate, and record.proto's enum holds no kind the list lacks; risk only rises; a pending answer raises
// approval_pending; the decision and the run binding pass through unchanged; and a malformed action is refused before
// any gate.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A gate that records what reaches it and answers what the test sets.
type testRecordingGate struct {
	stateLock sync.Mutex
	actions   []*SidecarAction
	decisions []*bridge.Signed
	answer    error
}

func (self *testRecordingGate) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.actions = append(self.actions, action)
	self.decisions = append(self.decisions, decision)
	return self.answer
}

// A well-formed action of kind.
func testSidecarAction(t *testing.T, kind SidecarActionKind) *SidecarAction {
	t.Helper()
	canonical, err := proto.Marshal(&protocol.CanonicalAction{Kind: uint32(kind), Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	return &SidecarAction{Kind: kind, Canonical: canonical, Risk: SidecarRiskNormal}
}

// I-8: with no gate installed, with nil installed, and once the installed one is removed, every action is refused.
func TestNilGateRefuses(t *testing.T) {
	sidecar, _, _ := newIdentityTestSidecar(t)
	action := testSidecarAction(t, SidecarActionMail)
	if err := sidecar.Authorize(t.Context(), action, nil); !errors.Is(err, ErrSidecarGateDenied) {
		t.Errorf("no gate: %v", err)
	}
	remove := sidecar.InstallGate(nil)
	if err := sidecar.Authorize(t.Context(), action, nil); !errors.Is(err, ErrSidecarGateDenied) {
		t.Errorf("a nil gate: %v", err)
	}
	remove()
	gate := &testRecordingGate{}
	remove = sidecar.InstallGate(gate)
	if err := sidecar.Authorize(t.Context(), action, nil); err != nil {
		t.Errorf("an installed gate that passes: %v", err)
	}
	remove()
	if err := sidecar.Authorize(t.Context(), action, nil); !errors.Is(err, ErrSidecarGateDenied) {
		t.Errorf("a removed gate: %v", err)
	}
}

// Every kind of record.proto's SidecarActionKind but unspecified is one of §5.4's list and reaches the installed
// gate as it was asked; unspecified and a value past the list are refused before any gate.
func TestEveryKindReachesGate(t *testing.T) {
	sidecar, _, _ := newIdentityTestSidecar(t)
	gate := &testRecordingGate{}
	defer sidecar.InstallGate(gate)()
	if len(protocol.SidecarActionKind_name)-1 != len(sidecarGateKinds) {
		t.Fatalf("record.proto has %d kinds, the gate's list %d", len(protocol.SidecarActionKind_name)-1, len(sidecarGateKinds))
	}
	for number := range protocol.SidecarActionKind_name {
		if number == 0 {
			continue
		}
		kind := SidecarActionKind(number)
		if err := sidecar.Authorize(t.Context(), testSidecarAction(t, kind), nil); err != nil {
			t.Errorf("kind %d: %v", kind, err)
		}
	}
	if len(gate.actions) != len(sidecarGateKinds) {
		t.Errorf("%d actions reached the gate", len(gate.actions))
	}
	for _, kind := range []SidecarActionKind{SidecarActionUnspecified, SidecarActionMailTlsUnauthenticated + 1} {
		if err := sidecar.Authorize(t.Context(), testSidecarAction(t, kind), nil); !errors.Is(err, ErrSidecarActionInvalid) {
			t.Errorf("kind %d: %v", kind, err)
		}
	}
	for name, action := range map[string]*SidecarAction{
		"nil":          nil,
		"no canonical": {Kind: SidecarActionMail, Risk: SidecarRiskNormal},
		"no risk":      {Kind: SidecarActionMail, Canonical: []byte{0x08, 0x0e}},
	} {
		if err := sidecar.Authorize(t.Context(), action, nil); !errors.Is(err, ErrSidecarActionInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// §5.4: risk is max(policy, the daemon classifier), which an agent may only raise: an agent asking low gets the floor,
// asking high gets high, and a policy's high stands whatever the agent asks.
func TestRiskOnlyRaises(t *testing.T) {
	stored := &StoredCanonicalAction{Action: &protocol.CanonicalAction{Kind: uint32(SidecarActionMail), Version: 1}}
	stored.Bytes, _ = proto.Marshal(stored.Action)
	for _, row := range []struct {
		policy, asked, want SidecarRisk
	}{
		{policy: SidecarRiskNormal, asked: SidecarRiskUnspecified, want: SidecarRiskNormal},
		{policy: SidecarRiskNormal, asked: SidecarRiskHigh, want: SidecarRiskHigh},
		{policy: SidecarRiskHigh, asked: SidecarRiskNormal, want: SidecarRiskHigh},
		{policy: SidecarRiskUnspecified, asked: SidecarRisk(9), want: SidecarRiskNormal},
	} {
		runId := NewId()
		action, err := NewSidecarAction(stored, row.policy, row.asked, &runId, nil)
		if err != nil {
			t.Fatal(err)
		}
		if action.Risk != row.want || action.RunId == nil || *action.RunId != runId {
			t.Errorf("policy %d, asked %d: %+v", row.policy, row.asked, action)
		}
	}
	if _, err := NewSidecarAction(&StoredCanonicalAction{Action: &protocol.CanonicalAction{}, Bytes: []byte{1}}, SidecarRiskNormal, SidecarRiskNormal, nil, nil); !errors.Is(err, ErrSidecarActionInvalid) {
		t.Errorf("an unspecified kind: %v", err)
	}
}

// A gate's pending answer raises approval_pending with the request's id, and reaches the caller as it was.
func TestApprovalPendingEmitsEvent(t *testing.T) {
	sidecar, _, _ := newIdentityTestSidecar(t)
	approvalId := NewId()
	defer sidecar.InstallGate(&testRecordingGate{answer: &ApprovalPendingError{ApprovalId: approvalId}})()
	events := &alarmTestEvents{}
	defer sidecar.AddEventCallback(events.add)()
	err := sidecar.Authorize(t.Context(), testSidecarAction(t, SidecarActionPublish), nil)
	pending := &ApprovalPendingError{}
	if !errors.As(err, &pending) || pending.ApprovalId != approvalId {
		t.Fatalf("%v", err)
	}
	raised := events.of(SidecarEventApprovalPending)
	if len(raised) != 1 || raised[0].ApprovalId == nil || *raised[0].ApprovalId != approvalId {
		t.Errorf("%+v", raised)
	}
}

// The decision and the run binding reach the gate unchanged, which §16's gate judges a tainted run's fresh decision
// and harness evidence by (TS1, owner decision 142).
func TestAuthorizePassesTheRunBindingThrough(t *testing.T) {
	sidecar, _, _ := newIdentityTestSidecar(t)
	gate := &testRecordingGate{}
	defer sidecar.InstallGate(gate)()
	action := testSidecarAction(t, SidecarActionForward)
	runId := NewId()
	agentId := NewId()
	action.RunId = &runId
	action.AgentId = &agentId
	decision := &bridge.Signed{Type: uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION), Body: []byte("a decision")}
	if err := sidecar.Authorize(t.Context(), action, decision); err != nil {
		t.Fatal(err)
	}
	if gate.actions[0] != action || *gate.actions[0].RunId != runId || *gate.actions[0].AgentId != agentId || gate.decisions[0] != decision {
		t.Errorf("%+v %+v", gate.actions[0], gate.decisions[0])
	}
}
