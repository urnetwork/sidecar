//go:build !ios_extension

// QD-740 on the approval path, end to end: a request's local_port, weight and alpn are its kind's alone (the kind
// table's request column), are rendered by name, and bind the spend; a version-4 grant is rendered with its sealed
// detail opened, approved, spent with its request's local port, and folds port-limited at a GrantActivate; a device
// that cannot open a detail approves nothing; and a request with a field this build cannot name is still refused
// (D-MCP-17). On the approver world of record_approval_decide_test.go, the approval world of
// record_approval_state_test.go and ACL's statement cast. Synthetic values only.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A request of action by requester carrying detail as its local_port, weight and alpn, waiting in the vault. Not
// parsed, so a test may put one the parse refuses.
func (self *testApproverWorld) storedRequest(requester Id, action *StoredCanonicalAction, detail *SidecarActionDetail) []byte {
	self.t.Helper()
	approvalId := NewId()
	actionId := action.ActionId(approvalId)
	payloadSha256 := action.PayloadSha256()
	runId := NewId()
	request := &protocol.ApprovalRequest{
		ApprovalId: approvalId.Bytes(), ActionId: actionId[:], RunId: runId.Bytes(), CanonicalAction: action.Bytes,
		PayloadSha256: payloadSha256[:], Risk: uint32(SidecarRiskNormal),
		RequesterSidecarId: requester.Bytes(), Approvers: [][]byte{self.memberId.Bytes()},
		NotAfterMillis: self.sidecar.clock.Now().Add(time.Hour).UnixMilli(), Version: 1,
	}
	if detail != nil {
		request.LocalPort, request.Weight, request.Alpn = detail.LocalPort, detail.Weight, detail.Alpn
	}
	return testRecordStored(self.t, request)
}

// storedRequest, parsed and put in the vault.
func (self *testApproverWorld) putDetail(requester Id, action *StoredCanonicalAction, detail *SidecarActionDetail) *StoredApprovalRequest {
	self.t.Helper()
	request, err := ParseStoredApprovalRequest(self.storedRequest(requester, action, detail))
	if err != nil {
		self.t.Fatal(err)
	}
	self.log.stateLock.Lock()
	defer self.log.stateLock.Unlock()
	self.log.pending = append(self.log.pending, &RecordPendingApproval{LogId: self.vaultId, EntryId: NewId(), Request: request})
	return request
}

// A render's value of name, false when it shows none.
func testRenderField(render *ApprovalRender, name string) (string, bool) {
	for _, field := range render.Fields {
		if field.Name == name {
			return field.Value, true
		}
	}
	return "", false
}

// A version-4 grant on an approver's device that holds the key: the render shows the clear fields, the request's
// local port and what the sealed detail holds, never its ciphertext, and an approval signs the request.
func TestSealedGrantRenderedOpenedAndApproved(t *testing.T) {
	world := newTestApproverWorld(t)
	world.approver = world.approver.WithDetailOpener(newTestActionDetailOpener(testActionDetailGeneration))
	forward := testSealedForward(t)
	request := world.putDetail(world.requesterId, forward, &SidecarActionDetail{LocalPort: 18443})
	item := world.item(request.ApprovalId())
	if item.Refused != "" || len(item.Decisions) != 2 {
		t.Fatalf("the item: %+v", item)
	}
	render := item.Render
	if !render.Sealed || !render.Opened {
		t.Errorf("sealed %t, opened %t", render.Sealed, render.Opened)
	}
	for name, want := range map[string]string{
		"grant_dst":                 testActionTargetDst,
		"grant_allow":               "dial",
		"local_port":                "18443",
		"sealed_detail.target_port": "8443",
		"sealed_detail.grant_dst":   testActionTargetDst + ":tcp:8443",
	} {
		if value, ok := testRenderField(render, name); !ok || value != want {
			t.Errorf("%s renders %q (%t), want %q", name, value, ok, want)
		}
	}
	if _, ok := testRenderField(render, "sealed_detail"); ok {
		t.Error("the ciphertext is rendered as a field")
	}
	text := render.Text()
	if !strings.Contains(text, "sealed_detail.target_port: 8443") || !strings.Contains(text, "local_port: 18443") ||
		strings.Contains(text, "did not open") {
		t.Errorf("the text:\n%s", text)
	}
	if err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if decision := world.lastDecision(); !decision.Binds(request) ||
		decision.Decision.GetDecision() != uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE) {
		t.Errorf("the decision: %+v", decision.Decision)
	}
}

// A device that cannot open a grant's sealed detail, with no opener, without the key's generation, or holding a
// detail that is not the action's, shows the rest, says the detail stayed sealed, lists deny alone, and signs no
// approval: a prefix or a port is never approved unseen (D-MCP-17). A denial is still signed.
func TestSealedGrantNotOpenedTakesNoApproval(t *testing.T) {
	forward := testSealedForward(t)
	stray := proto.Clone(testBuildableActions()["bridge_forward"]).(*protocol.CanonicalAction)
	stray.SealedDetail = testSealActionDetail(&protocol.CanonicalActionDetail{GrantDst: []string{"sidecar:6162636465666768696a6b6c6d6e6f70:tcp:22"}})
	for name, c := range map[string]struct {
		opener CanonicalActionDetailOpener
		action *StoredCanonicalAction
	}{
		"no opener":            {action: forward},
		"no generation":        {opener: newTestActionDetailOpener(1, 2), action: forward},
		"another action's":     {opener: newTestActionDetailOpener(testActionDetailGeneration), action: buildTestAction(t, stray)},
		"an opener of nothing": {opener: testActionDetailOpenerOfNothing{}, action: forward},
	} {
		world := newTestApproverWorld(t)
		if c.opener != nil {
			world.approver = world.approver.WithDetailOpener(c.opener)
		}
		request := world.putDetail(world.requesterId, c.action, &SidecarActionDetail{LocalPort: 18443})
		item := world.item(request.ApprovalId())
		if !slices.Equal(item.Decisions, []string{SidecarDecisionDeny}) {
			t.Errorf("%s: decisions %v", name, item.Decisions)
		}
		if !item.Render.Sealed || item.Render.Opened || !strings.Contains(item.Render.Text(), "did not open") {
			t.Errorf("%s: the render:\n%s", name, item.Render.Text())
		}
		for _, field := range item.Render.Fields {
			if strings.HasPrefix(field.Name, "sealed_detail") {
				t.Errorf("%s: rendered %s", name, field.Name)
			}
		}
		err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil)
		if !errors.Is(err, ErrApprovalDetailSealed) || world.decisionCount() != 0 {
			t.Errorf("%s: an approval answered %v, %d filed", name, err, world.decisionCount())
		}
		if err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionDeny}, SidecarActConfirmed, nil); err != nil {
			t.Errorf("%s: a denial: %v", name, err)
		} else if denial := world.lastDecision(); denial.Decision.GetDecision() != uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY) {
			t.Errorf("%s: the denial: %+v", name, denial.Decision)
		}
	}
}

// An opener that answers no detail and no error for an action that carries one.
type testActionDetailOpenerOfNothing struct{}

func (self testActionDetailOpenerOfNothing) OpenActionDetail(action *StoredCanonicalAction) (*protocol.CanonicalActionDetail, error) {
	return nil, nil
}

// A request's local_port, weight and alpn are its action's kind's alone (the kind table's request column): a publish
// binds its local port and ALPNs, a listen its local port and weight, a forward and an expose their local port, and
// every other field on every other kind is refused by the parse, as are a port past 65535 and an empty ALPN. What
// parses is rendered by name after the action's fields.
func TestRequestDetailIsItsKindsAlone(t *testing.T) {
	world := newTestApproverWorld(t)
	actions := testBuildableActions()
	details := map[protoreflect.FieldNumber]*SidecarActionDetail{
		approvalRequestFieldLocalPort: {LocalPort: 8080},
		approvalRequestFieldWeight:    {Weight: 10},
		approvalRequestFieldAlpn:      {Alpn: []string{"h2", "http/1.1"}},
	}
	for name, action := range actions {
		stored := buildTestAction(t, action)
		row, _ := CanonicalActionFields(SidecarActionKind(action.GetKind()))
		for number, detail := range details {
			_, err := ParseStoredApprovalRequest(world.storedRequest(world.requesterId, stored, detail))
			if row.requestAllows(number) {
				if err != nil {
					t.Errorf("%s with request field %d: %v", name, number, err)
				}
			} else if !errors.Is(err, ErrRecordStoredInvalid) {
				t.Errorf("%s with request field %d answered %v", name, number, err)
			}
		}
	}
	wants := map[string][]protoreflect.FieldNumber{
		"tls_publish": {14, 16}, "socket_listen": {14, 15}, "bridge_forward": {14}, "bridge_expose": {14},
	}
	for name := range actions {
		row, _ := CanonicalActionFields(SidecarActionKind(actions[name].GetKind()))
		if !slices.Equal(row.Request, wants[name]) {
			t.Errorf("%s binds request fields %v, want %v", name, row.Request, wants[name])
		}
	}
	publish := buildTestAction(t, actions["tls_publish"])
	for name, detail := range map[string]*SidecarActionDetail{
		"a port past 65535": {LocalPort: 65536},
		"an empty alpn":     {LocalPort: 8080, Alpn: []string{"h2", ""}},
	} {
		if _, err := ParseStoredApprovalRequest(world.storedRequest(world.requesterId, publish, detail)); !errors.Is(err, ErrRecordStoredInvalid) {
			t.Errorf("%s answered %v", name, err)
		}
	}
	// a request field this build cannot name is still refused
	unknown := &protocol.ApprovalRequest{}
	if err := proto.Unmarshal(world.storedRequest(world.requesterId, publish, nil), unknown); err != nil {
		t.Fatal(err)
	}
	unknown.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 17, protowire.VarintType), 1))
	if _, err := ParseStoredApprovalRequest(testRecordStored(t, unknown)); !errors.Is(err, ErrRecordStoredInvalid) {
		t.Errorf("a request with an unknown field answered %v", err)
	}

	request := world.putDetail(world.requesterId, publish, &SidecarActionDetail{LocalPort: 8080, Alpn: []string{"h2", "http/1.1\x1b[2J"}})
	render := world.item(request.ApprovalId()).Render
	if value, ok := testRenderField(render, "local_port"); !ok || value != "8080" {
		t.Errorf("local_port renders %q (%t)", value, ok)
	}
	if value, ok := testRenderField(render, "alpn"); !ok || !strings.HasPrefix(value, "h2, http/1.1") || strings.ContainsRune(value, 0x1b) {
		t.Errorf("alpn renders %q (%t)", value, ok)
	}
	if render.Sealed || render.Opened {
		t.Error("a publish reads as sealed")
	}
	if detail := request.Detail(); !detail.Equal(&SidecarActionDetail{LocalPort: 8080, Alpn: []string{"h2", "http/1.1\x1b[2J"}}) {
		t.Errorf("the request's detail: %+v", detail)
	}
	listen := world.putDetail(world.requesterId, buildTestAction(t, actions["socket_listen"]), &SidecarActionDetail{LocalPort: 8443, Weight: -3})
	if value, ok := testRenderField(world.item(listen.ApprovalId()).Render, "weight"); !ok || value != "-3" {
		t.Errorf("weight renders %q (%t)", value, ok)
	}
	// a request with no detail has none, and nil equals it
	bare := world.putDetail(world.requesterId, publish, nil)
	if bare.Detail() != nil || !bare.Detail().Equal(&SidecarActionDetail{}) || bare.Detail().Equal(&SidecarActionDetail{LocalPort: 1}) {
		t.Errorf("a request with no detail: %+v", bare.Detail())
	}
}

// A version-4 grant approved and spent: the daemon files its request with the local port the forward binds, a
// decision on it spends once for that action and port, the effect sees the port the approver saw, and the same
// grant asked on another local port finds no approval and files its own request.
func TestSealedGrantApprovedAndSpent(t *testing.T) {
	world := newTestApprovalWorld(t)
	world.lookups[SidecarActionForward] = world.effect.lookup
	forward := testSealedForwardExpiring(t, world.clock.Now().Add(24*time.Hour).UnixMilli())
	asked := func(localPort uint32) *SidecarAction {
		action := world.action(forward)
		action.Detail = &SidecarActionDetail{LocalPort: localPort}
		return action
	}
	request := world.pendingRequest(world.gate.Authorize(t.Context(), asked(18443), nil))
	if request.Request.GetLocalPort() != 18443 || request.Action.Action.GetVersion() != canonicalActionVersionSealedGrant ||
		!bytes.Equal(request.Action.Bytes, forward.Bytes) {
		t.Fatalf("the request: %+v", request.Request)
	}
	// the same ask again finds its request; another port's does not
	if again := world.pendingRequest(world.gate.Authorize(t.Context(), asked(18443), nil)); again.ApprovalId() != request.ApprovalId() {
		t.Error("the same forward filed a second request")
	}
	otherPort := world.pendingRequest(world.gate.Authorize(t.Context(), asked(18444), nil))
	if otherPort.ApprovalId() == request.ApprovalId() || otherPort.Request.GetLocalPort() != 18444 {
		t.Error("another local port found the first request")
	}
	decision := world.approve(request)
	world.log.putDecision(request.ApprovalId(), decision)
	if err := world.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	// the decision in hand on another local port, or on none, spends nothing
	for _, localPort := range []uint32{18444, 0} {
		if err := world.gate.Authorize(t.Context(), asked(localPort), testGateSigned(t, decision)); !errors.Is(err, ErrApprovalRefused) {
			t.Errorf("the decision on local port %d: %v", localPort, err)
		}
	}
	if runCount, _ := world.effect.counts(); runCount != 0 {
		t.Fatalf("an effect ran %d times before its spend", runCount)
	}
	spent := asked(18443)
	testGateExpectOutcome(t, "the approved forward", world.gate.Authorize(t.Context(), spent, nil), spent, ApprovalOutcomeDone)
	spend, ok := world.effect.spendSeen()
	if !ok || spend.ApprovalId != request.ApprovalId() || !bytes.Equal(spend.Action, forward.Bytes) ||
		!spend.Detail.Equal(&SidecarActionDetail{LocalPort: 18443}) {
		t.Errorf("the spend the effect saw: %+v", spend)
	}
	if got := world.status(request.ApprovalId()); got != ApprovalStatusSpent {
		t.Errorf("status %s", got)
	}
	if _, effectCount := world.effect.counts(); effectCount != 1 {
		t.Errorf("%d effects for one use", effectCount)
	}
	// the other port's request still waits, unspent
	if got := world.status(otherPort.ApprovalId()); got != ApprovalStatusPending {
		t.Errorf("the other port's request: %s", got)
	}
	// a detail the kind does not bind files nothing: a forward has no weight and no ALPN
	filed := world.log.filedCount()
	for name, detail := range map[string]*SidecarActionDetail{
		"a weight": {LocalPort: 18445, Weight: 5}, "an alpn": {LocalPort: 18445, Alpn: []string{"h2"}}, "a port past 65535": {LocalPort: 65536},
	} {
		action := world.action(forward)
		action.Detail = detail
		err := world.gate.Authorize(t.Context(), action, nil)
		pending := &ApprovalPendingError{}
		if err == nil || errors.As(err, &pending) || !errors.Is(err, ErrRecordStoredInvalid) {
			t.Errorf("a forward binding %s answered %v", name, err)
		}
	}
	if world.log.filedCount() != filed {
		t.Error("a request with a detail its kind does not bind was filed")
	}
}

// A version-4 grant at a GrantActivate: every reader's check takes it by its clear fields, and it folds to a rule
// that is port-limited by its sealed detail, so a device opens no port the detail does not name.
func TestSealedGrantActivatesPortLimited(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	selfRule := fixture.requestRule([]Id{member}, []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, 0)
	state := fixture.state(t)
	phoneDst := aclTestDst(cast.phone)
	stored, err := NewSealedCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionForward), RuleId: selfRule, Subject: cast.laptop.Bytes(),
		GrantDst: []string{phoneDst}, GrantAllow: []string{"dial"},
	}, &protocol.CanonicalActionDetail{TargetPort: 22, GrantDst: []string{phoneDst + ":tcp:22"}},
		testConfigSealKey(testActionDetailGeneration), testActionDetailContext(), nil)
	if err != nil {
		t.Fatal(err)
	}
	grant := newAclTestGrant(t, selfRule, cast.laptop, []string{phoneDst}, []string{"dial"}, 0)
	grant.actionBytes = stored.Bytes
	grant.approve(t, cast.member, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, aclTestDecisionNotAfter)
	activate := grant.activate()
	statement := fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate, cast.laptop)
	verdict, err := state.CheckStatement(statement, &aclTestSpendCheck{})
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := state.ApplyStatement(statement, verdict)
	if err != nil {
		t.Fatal(err)
	}
	fixture.rows = rows
	reach := fixture.state(t).Reach(AclSidecarSubject(cast.laptop), AclSidecarSubject(cast.phone), aclTestNow)
	if !reach.Allowed || !bytes.Equal(reach.Rule.GetRuleId(), activate.GetGrantId()) {
		t.Fatalf("the activated grant: %+v", reach)
	}
	if !reach.Rule.GetPortsLimited() {
		t.Error("a grant with sealed ports folded to one with every port")
	}
	// the rule's row holds no port
	if encoded := testConfigMarshal(t, reach.Rule); bytes.Contains(encoded, []byte(":tcp:")) {
		t.Error("the folded rule holds port text")
	}
}
