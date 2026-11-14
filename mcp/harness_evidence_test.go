//go:build !js && !ios && !android && !sdk_mobile_bind

// MCP-M3-10's event half of harness_ok: the store keeps the events that asked about a call of ur's, a decision is
// signed only on one of the same run, tool and arguments, unused, under ten minutes old, in a prompting mode, and the
// event serves one decision. harness_ok's state half runs on a real config log in the root's record_harness_test.go;
// here a fake states answers it.

package mcp

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A states that answers harness_ok's state half as a test sets it.
type fakeHarnessStates struct {
	member           sidecar.Id
	requester        sidecar.Id
	otherCapable     bool
	presenceKey      bool
	evidence         []protocol.ApprovalChannel
	ruleNamesHarness bool
}

func (self *fakeHarnessStates) Pin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: 7, Chain: make([]byte, 32)}
}
func (self *fakeHarnessStates) ChainAt(version uint64) ([32]byte, bool) { return [32]byte{}, false }
func (self *fakeHarnessStates) Forked() bool                            { return false }
func (self *fakeHarnessStates) IdentityKey(sidecarId sidecar.Id) []byte {
	return nil
}
func (self *fakeHarnessStates) ApprovalCapable(sidecarId sidecar.Id, memberId sidecar.Id) bool {
	return sidecarId == self.requester && memberId == self.member
}
func (self *fakeHarnessStates) PresenceKey(keyId []byte, memberId sidecar.Id) *bridge.KeyRow {
	return nil
}
func (self *fakeHarnessStates) Govern(action *sidecar.StoredCanonicalAction, spender sidecar.Id, now time.Time) (sidecar.SpendRule, error) {
	return &fakeHarnessRule{states: self}, nil
}
func (self *fakeHarnessStates) Approvers(action *sidecar.StoredCanonicalAction, requester sidecar.Id, now time.Time) ([]sidecar.Id, error) {
	return []sidecar.Id{self.member}, nil
}
func (self *fakeHarnessStates) RuleNamesHarness(action *sidecar.StoredCanonicalAction) bool {
	return self.ruleNamesHarness
}
func (self *fakeHarnessStates) DeviceMember(sidecarId sidecar.Id) (sidecar.Id, bool) {
	return self.member, sidecarId == self.requester
}
func (self *fakeHarnessStates) OtherApprovalCapable(memberId sidecar.Id, except sidecar.Id) bool {
	return self.otherCapable
}
func (self *fakeHarnessStates) HoldsPresenceKey(memberId sidecar.Id) bool {
	return self.presenceKey
}

// The fake states' one rule.
type fakeHarnessRule struct {
	states *fakeHarnessStates
}

func (self *fakeHarnessRule) Evidence() []protocol.ApprovalChannel { return self.states.evidence }
func (self *fakeHarnessRule) ApproverCount() int                   { return 1 }
func (self *fakeHarnessRule) Eligible(memberId sidecar.Id) bool {
	return memberId == self.states.member
}
func (self *fakeHarnessRule) AdminClauseMet(memberIds []sidecar.Id) bool {
	return true
}

// A signer that records what it signed.
type fakeHarnessSigner struct {
	identity *sidecar.SidecarIdentity

	stateLock sync.Mutex
	signed    []fakeHarnessSigned
}

// One signature asked for.
type fakeHarnessSigned struct {
	memberId sidecar.Id
	leaf     []byte
	notAfter time.Time
}

func (self *fakeHarnessSigner) Identity() *sidecar.SidecarIdentity {
	return self.identity
}

func (self *fakeHarnessSigner) SignHarnessDecision(request *sidecar.StoredApprovalRequest, memberId sidecar.Id, pin *bridge.AuthPin, evidenceSha256 []byte, notAfter time.Time) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.signed = append(self.signed, fakeHarnessSigned{memberId: memberId, leaf: append([]byte(nil), evidenceSha256...), notAfter: notAfter})
	return []byte("a signed harness decision"), nil
}

// Each run's taint, as a test sets it.
type fakeRunView struct {
	stateLock sync.Mutex
	tainted   map[sidecar.Id]bool
}

func (self *fakeRunView) RunTainted(runId sidecar.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.tainted[runId]
}

// A record writer that seals every draft at once, its leaf a hash of its order.
type fakeEvidenceRecord struct {
	stateLock sync.Mutex
	drafts    []*sidecar.RecordDraft
}

func (self *fakeEvidenceRecord) Append(draft *sidecar.RecordDraft) ([]*sidecar.RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.drafts = append(self.drafts, draft)
	return []*sidecar.RecordEntryRef{{Seq: uint64(len(self.drafts)), Leaf: sha256.Sum256([]byte{byte(len(self.drafts))})}}, nil
}

// A world of one network's harness evidence: its store, a run, a request for dns_set by this sidecar, and the call that
// asks.
type testHarnessEvidenceWorld struct {
	t         *testing.T
	clock     *sidecartest.FakeClock
	networkId sidecar.Id
	runId     sidecar.Id
	store     *HarnessEvidenceStore
	states    *fakeHarnessStates
	signer    *fakeHarnessSigner
	runs      *fakeRunView
	record    *fakeEvidenceRecord
	evidence  *HarnessEvidence
	action    *sidecar.SidecarAction
	request   *sidecar.StoredApprovalRequest
	arguments []byte
}

func newTestHarnessEvidenceWorld(t *testing.T) *testHarnessEvidenceWorld {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	world := &testHarnessEvidenceWorld{
		t:         t,
		clock:     clock,
		networkId: sidecar.NewId(),
		runId:     sidecar.NewId(),
		store:     NewHarnessEvidenceStore(sidecar.DefaultSidecarSettings().Ingest, clock),
		runs:      &fakeRunView{tainted: map[sidecar.Id]bool{}},
		record:    &fakeEvidenceRecord{},
		arguments: []byte(`{"name":"www","type":"A","value":"192.0.2.7"}`),
	}
	identity := &sidecar.SidecarIdentity{NetworkId: world.networkId, SidecarId: sidecar.NewId()}
	world.signer = &fakeHarnessSigner{identity: identity}
	world.states = &fakeHarnessStates{
		member:    sidecar.NewId(),
		requester: identity.SidecarId,
		evidence: []protocol.ApprovalChannel{protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
			protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE, protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS},
	}
	world.evidence = NewHarnessEvidence(&HarnessEvidenceArgs{
		Store:     world.store,
		NetworkId: world.networkId,
		Signer:    world.signer,
		States:    func() (sidecar.HarnessStates, error) { return world.states, nil },
		Runs:      world.runs,
		Record:    world.record,
	})
	stored, err := sidecar.NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(sidecar.SidecarActionDnsSet), DnsName: "www", DnsType: "A", DnsValue: "192.0.2.7", DnsTtl: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	runId := world.runId
	world.action, err = sidecar.NewSidecarAction(stored, sidecar.SidecarRiskNormal, sidecar.SidecarRiskNormal, &runId, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.request = world.newRequest(false)
	return world
}

// The request this sidecar filed for the world's action, tainted or not.
func (self *testHarnessEvidenceWorld) newRequest(tainted bool) *sidecar.StoredApprovalRequest {
	self.t.Helper()
	approvalId := sidecar.NewId()
	action := self.action
	stored, err := sidecar.ParseStoredCanonicalAction(action.Canonical)
	if err != nil {
		self.t.Fatal(err)
	}
	actionId := stored.ActionId(approvalId)
	payloadSha256 := stored.PayloadSha256()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ApprovalRequest{
		ApprovalId: approvalId.Bytes(), ActionId: actionId[:], RunId: self.runId.Bytes(), CanonicalAction: stored.Bytes,
		PayloadSha256: payloadSha256[:], Risk: uint32(sidecar.SidecarRiskNormal), Tainted: tainted,
		RequesterSidecarId: self.signer.identity.SidecarId.Bytes(), Approvers: [][]byte{self.states.member.Bytes()},
		NotAfterMillis: self.clock.Now().Add(24 * time.Hour).UnixMilli(), Version: 1,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	request, err := sidecar.ParseStoredApprovalRequest(encoded)
	if err != nil {
		self.t.Fatal(err)
	}
	return request
}

// A PermissionRequest of Claude Code for the world's call, in mode, with the given arguments' hash.
func (self *testHarnessEvidenceWorld) permissionRequest(mode string, sessionId string) *HookEvent {
	return &HookEvent{
		Harness:         claudeHookHarness,
		HarnessEvent:    "PermissionRequest",
		Kind:            HookEventPermissionRequest,
		SessionId:       sessionId,
		PermissionMode:  mode,
		ToolKind:        HookToolMcp,
		ToolServer:      urMcpServerName,
		ToolName:        "dns_set",
		ToolInputSha256: hookToolInputSha256(self.arguments),
	}
}

// Notes event as captured in the world's run, with a leaf.
func (self *testHarnessEvidenceWorld) note(event *HookEvent) []byte {
	leaf := sha256.Sum256([]byte(event.SessionId + event.PermissionMode + self.clock.Now().String()))
	self.store.Note(&HookCaptured{NetworkId: self.networkId, RunId: self.runId, Event: event, EventLeaf: leaf[:]})
	return leaf[:]
}

// The context of the O call: its call in the world's run, its tool and its arguments.
func (self *testHarnessEvidenceWorld) callContext(arguments []byte) context.Context {
	ctx := context.WithValue(context.Background(), mcpCallContextKey{}, &McpCall{NetworkId: self.networkId, RunId: self.runId})
	return withMcpToolArguments(ctx, "dns_set", arguments)
}

// The decision's answer for the world's call.
func (self *testHarnessEvidenceWorld) decide(ctx context.Context) ([]byte, error) {
	return self.evidence.HarnessDecision(ctx, self.action, self.request)
}

// A PermissionRequest in a prompting mode signs one decision, bound to the event: its leaf, and ten minutes past it.
func TestHarnessEvidenceSignsOnTheEvent(t *testing.T) {
	world := newTestHarnessEvidenceWorld(t)
	leaf := world.note(world.permissionRequest("default", "s1"))
	at := world.clock.Now()
	world.clock.Advance(time.Minute)
	if _, err := world.decide(world.callContext(world.arguments)); err != nil {
		t.Fatal(err)
	}
	if len(world.signer.signed) != 1 {
		t.Fatalf("signed %d", len(world.signer.signed))
	}
	signed := world.signer.signed[0]
	if signed.memberId != world.states.member || string(signed.leaf) != string(leaf) || !signed.notAfter.Equal(at.Add(10*time.Minute)) {
		t.Errorf("signed %+v", signed)
	}
}

// Every prompt-skipping mode voids the event, and so does a later event of its session reporting one.
func TestEachSkippingModeVoidsEvidence(t *testing.T) {
	for _, mode := range sidecar.DefaultSidecarSettings().Ingest.BypassPermissionModes {
		world := newTestHarnessEvidenceWorld(t)
		world.note(world.permissionRequest(mode, "s1"))
		if _, err := world.decide(world.callContext(world.arguments)); !errors.Is(err, ErrHarnessNoEvidence) {
			t.Errorf("%s: %v", mode, err)
		}
	}
	world := newTestHarnessEvidenceWorld(t)
	world.note(world.permissionRequest("default", "s1"))
	later := world.permissionRequest("bypassPermissions", "s1")
	later.Kind, later.HarnessEvent = HookEventPreToolUse, "PreToolUse"
	world.note(later)
	if _, err := world.decide(world.callContext(world.arguments)); !errors.Is(err, ErrHarnessNoEvidence) {
		t.Errorf("a session that turned to bypass: %v", err)
	}
}

// A mode the list does not name, a missing one included, is no evidence.
func TestUnknownModeVoidsEvidence(t *testing.T) {
	for _, mode := range []string{"", "yolo", "Default"} {
		world := newTestHarnessEvidenceWorld(t)
		world.note(world.permissionRequest(mode, "s1"))
		if _, err := world.decide(world.callContext(world.arguments)); !errors.Is(err, ErrHarnessNoEvidence) {
			t.Errorf("mode %q: %v", mode, err)
		}
	}
}

// One event serves one decision.
func TestEventUsedOnce(t *testing.T) {
	world := newTestHarnessEvidenceWorld(t)
	world.note(world.permissionRequest("default", "s1"))
	if _, err := world.decide(world.callContext(world.arguments)); err != nil {
		t.Fatal(err)
	}
	world.request = world.newRequest(false)
	if _, err := world.decide(world.callContext(world.arguments)); !errors.Is(err, ErrHarnessNoEvidence) {
		t.Errorf("a second decision on one event: %v", err)
	}
}

// An event ten minutes old or more is no evidence.
func TestEventOlderThanTenMinutesRefused(t *testing.T) {
	world := newTestHarnessEvidenceWorld(t)
	world.note(world.permissionRequest("default", "s1"))
	world.clock.Advance(10 * time.Minute)
	if _, err := world.decide(world.callContext(world.arguments)); !errors.Is(err, ErrHarnessNoEvidence) {
		t.Errorf("an event ten minutes old: %v", err)
	}
	world = newTestHarnessEvidenceWorld(t)
	world.note(world.permissionRequest("default", "s1"))
	world.clock.Advance(10*time.Minute - time.Millisecond)
	if _, err := world.decide(world.callContext(world.arguments)); err != nil {
		t.Errorf("an event just under ten minutes old: %v", err)
	}
}

// The hook's tool_input and the MCP call's arguments match by their RFC 8785 form, whatever their keys' order; other
// arguments or another tool do not.
func TestArgumentKeyOrderMatches(t *testing.T) {
	payload := []byte(`{"session_id":"s1","hook_event_name":"PermissionRequest","permission_mode":"default",` +
		`"tool_name":"mcp__ur__dns_set","tool_input":{"value":"192.0.2.7","type":"A","name":"www"}}`)
	event, err := (&claudeHookAdapter{}).Parse(payload, sidecar.DefaultSidecarSettings().Ingest)
	if err != nil {
		t.Fatal(err)
	}
	world := newTestHarnessEvidenceWorld(t)
	world.note(event)
	if _, err := world.decide(world.callContext([]byte(`{"name":"www","type":"A","value":"192.0.2.7"}`))); err != nil {
		t.Errorf("reordered keys: %v", err)
	}
	world = newTestHarnessEvidenceWorld(t)
	world.note(event)
	if _, err := world.decide(world.callContext([]byte(`{"name":"www","type":"A","value":"192.0.2.8"}`))); !errors.Is(err, ErrHarnessNoEvidence) {
		t.Errorf("other arguments: %v", err)
	}
	world = newTestHarnessEvidenceWorld(t)
	world.note(event)
	ctx := withMcpToolArguments(world.callContext(nil), "dns_delete", world.arguments)
	if _, err := world.decide(ctx); !errors.Is(err, ErrHarnessNoEvidence) {
		t.Errorf("another tool: %v", err)
	}
}

// Cursor's beforeMCPExecution that ur hook answered ask counts; its other events do not.
func TestCursorAskedEventCounts(t *testing.T) {
	world := newTestHarnessEvidenceWorld(t)
	event := &HookEvent{
		Harness: cursorHookHarness, HarnessEvent: "beforeMCPExecution", Kind: HookEventPreToolUse, SessionId: "c1",
		ToolKind: HookToolMcp, ToolServer: urMcpServerName, ToolName: "dns_set", ToolInputSha256: hookToolInputSha256(world.arguments),
	}
	world.note(event)
	if _, err := world.decide(world.callContext(world.arguments)); err != nil {
		t.Errorf("an asked beforeMCPExecution: %v", err)
	}
	world = newTestHarnessEvidenceWorld(t)
	after := *event
	after.HarnessEvent, after.Kind = "afterMCPExecution", HookEventPostToolUse
	world.note(&after)
	if _, err := world.decide(world.callContext(world.arguments)); !errors.Is(err, ErrHarnessNoEvidence) {
		t.Errorf("an afterMCPExecution: %v", err)
	}
}

// A refusal of harness_ok's state half signs nothing and leaves the event for a decision that may stand.
func TestStateRefusalKeepsTheEvent(t *testing.T) {
	world := newTestHarnessEvidenceWorld(t)
	world.note(world.permissionRequest("default", "s1"))
	world.states.otherCapable = true
	if _, err := world.decide(world.callContext(world.arguments)); !errors.Is(err, sidecar.ErrHarnessNotOk) {
		t.Fatalf("a second approval-capable device: %v", err)
	}
	world.states.otherCapable = false
	if _, err := world.decide(world.callContext(world.arguments)); err != nil {
		t.Errorf("the event was spent by a refusal: %v", err)
	}
	if len(world.signer.signed) != 1 {
		t.Errorf("signed %d", len(world.signer.signed))
	}
}

// In a tainted run harness evidence counts only where the requests rule names it, never through evidenceDefault
// (owner decision 142): a run tainted since its request was filed counts as tainted.
func TestTaintedRunNeedsARuleNamingHarness(t *testing.T) {
	world := newTestHarnessEvidenceWorld(t)
	world.note(world.permissionRequest("default", "s1"))
	world.runs.tainted[world.runId] = true
	if _, err := world.decide(world.callContext(world.arguments)); !errors.Is(err, sidecar.ErrHarnessNotOk) {
		t.Errorf("a tainted run under evidenceDefault: %v", err)
	}
	world.states.ruleNamesHarness = true
	world.request = world.newRequest(true)
	if _, err := world.decide(world.callContext(world.arguments)); err != nil {
		t.Errorf("a tainted run whose rule names harness: %v", err)
	}
}

// A typed command confirmed on /dev/tty: the daemon seals a hook_event entry of ur-tty-confirm, source observed,
// holding the arguments' hash, and cites its leaf.
func TestTtyConfirmationSealsItsEntry(t *testing.T) {
	world := newTestHarnessEvidenceWorld(t)
	argumentsSha256 := hookToolInputSha256(world.arguments)
	ctx := WithHarnessTtyConfirmation(context.Background(), argumentsSha256)
	if _, err := world.decide(ctx); err != nil {
		t.Fatal(err)
	}
	if len(world.record.drafts) != 1 {
		t.Fatalf("drafts %d", len(world.record.drafts))
	}
	draft := world.record.drafts[0]
	body, ok := draft.Body.(*protocol.HookEventBody)
	if !ok || draft.Kind != sidecar.RecordKindHookEvent || draft.Source != sidecar.RecordSourceObserved ||
		body.GetEvent() != "ur-tty-confirm" || string(body.GetArgumentsSha256()) != string(argumentsSha256) {
		t.Errorf("the confirmation's entry: %+v", draft)
	}
	leaf := sha256.Sum256([]byte{1})
	if string(world.signer.signed[0].leaf) != string(leaf[:]) {
		t.Error("the decision does not cite the confirmation's leaf")
	}
}

// The store sits on the hook path after the capture, which gives it each event's leaf; an event with no leaf, whose
// entry waited in the spool, is no evidence.
func TestStoreKeepsTheCapturedLeaf(t *testing.T) {
	world := newTestHarnessEvidenceWorld(t)
	server := newTestMcpServer(newFakeMcpDaemon(), world.clock)
	leaf := sha256.Sum256([]byte("captured"))
	server.SetHookCapture(func(ctx context.Context, captured *HookCaptured) error {
		captured.EventLeaf = leaf[:]
		return nil
	})
	world.store.Install(server)
	event := world.permissionRequest("default", "s1")
	if err := server.hookCapture()(context.Background(), &HookCaptured{NetworkId: world.networkId, RunId: world.runId, Event: event}); err != nil {
		t.Fatal(err)
	}
	if _, err := world.decide(world.callContext(world.arguments)); err != nil {
		t.Fatal(err)
	}
	if string(world.signer.signed[0].leaf) != string(leaf[:]) {
		t.Error("the decision does not cite the captured leaf")
	}
	world.store.Note(&HookCaptured{NetworkId: world.networkId, RunId: world.runId, Event: event})
	world.request = world.newRequest(false)
	if _, err := world.decide(world.callContext(world.arguments)); !errors.Is(err, ErrHarnessNoEvidence) {
		t.Errorf("an event with no leaf: %v", err)
	}
}
