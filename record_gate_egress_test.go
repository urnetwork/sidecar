//go:build !ios_extension

// QD-1060 at §16.6's real gate, on the approval world (record_approval_state_test.go): an egress change's requirement
// of default egress (QD-1053) is a field of its action, require_default_egress = 41, so the same exits filed with it
// and without it are two actions and the gate spends neither's decision on the other; a template binds the requirement
// whether it sets it or not (TemplateBound), so a template whose approver saw no requirement spends on no filing that
// carries one; and an approver renders the requirement as its own clause. The filer's side, BridgeFiler.SetEgress
// filing the requirement through the gate's seam, is TestBridgeSetEgressFilesUnderTheGate's.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The clause an approver's render adds for the requirement of default egress (QD-1060).
const testEgressRequirementClause = ", and require its devices to keep default egress on"

// The egress spec the tests file: one subject's exits through one sidecar, with the requirement of default egress or
// without it.
func testEgressRequest(requireDefaultEgress bool) *BridgeEgressRequest {
	return &BridgeEgressRequest{
		Subject:              testConfigId("egress subject"),
		Mode:                 bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS,
		ExitSidecarIds:       []Id{testConfigId("egress exit")},
		RequireDefaultEgress: requireDefaultEgress,
	}
}

// The action BridgeFiler.SetEgress builds for the test's spec.
func testEgressAction(t *testing.T, requireDefaultEgress bool) *StoredCanonicalAction {
	t.Helper()
	stored, err := bridgeEgressAction(testEgressRequest(requireDefaultEgress))
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// A template of the test's exits for its subject, with the requirement of default egress or without it.
func testEgressTemplate(t *testing.T, requireDefaultEgress bool) *StoredCanonicalAction {
	t.Helper()
	request := testEgressRequest(requireDefaultEgress)
	template, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind:                 uint32(SidecarActionEgressChange),
		Scope:                true,
		Subject:              request.Subject.Bytes(),
		EgressMode:           uint32(request.Mode),
		GrantDst:             []string{"sidecar:" + hex.EncodeToString(request.ExitSidecarIds[0].Bytes())},
		RequireDefaultEgress: requireDefaultEgress,
	})
	if err != nil {
		t.Fatal(err)
	}
	return template
}

// An egress change as a person's confirmed command hands it to Authorize (BridgeFiler.SetEgress): no run and no agent,
// with the world's effect, and uses for a template.
func (self *testApprovalWorld) egressAction(stored *StoredCanonicalAction, uses uint32) *SidecarAction {
	return &SidecarAction{
		Kind:      SidecarActionEgressChange,
		Canonical: stored.Bytes,
		Risk:      SidecarRiskNormal,
		Summary:   "ur bridge egress",
		Effect:    self.effect,
		Uses:      uses,
	}
}

// Files stored's request as a person's command does, for uses (0 for an action that is no template), and keeps the
// phone's approval of it for as many: the request and the decision as stored.
func (self *testApprovalWorld) approvedEgress(stored *StoredCanonicalAction, uses uint32) (*StoredApprovalRequest, []byte) {
	self.t.Helper()
	request := self.pendingRequest(self.gate.Authorize(self.t.Context(), self.egressAction(stored, uses), nil))
	decision := self.decision(request, self.spend.phone, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, max(1, uses))
	if _, err := self.inbox.Receive(self.t.Context(), decision); err != nil {
		self.t.Fatal(err)
	}
	return request, decision
}

// The approval the world's effect last ran under.
func (self *testApprovalWorld) lastSpentApprovalId() Id {
	self.t.Helper()
	spend, ok := self.lastSpend()
	if !ok {
		self.t.Fatal("no effect ran under a spend")
	}
	return spend.ApprovalId
}

// The same exits filed with the requirement of default egress and without it are two actions (QD-1060): a decision on
// the exits alone leaves the requirement's filing waiting on a request of its own, which shows the requirement, and
// that decision passed in hand with it is refused as one on another action; the requirement's own approval then spends
// under another effect key; and each retry answers its own outcome without running the effect again (AU4). The other
// direction too: the requirement's decision passed with the exits alone is refused.
func TestEgressChangeRequirementTakesItsOwnDecision(t *testing.T) {
	world := newTestApprovalWorld(t)
	world.lookups[SidecarActionEgressChange] = world.effect.lookup
	plain := testEgressAction(t, false)
	required := testEgressAction(t, true)
	if bytes.Equal(plain.Bytes, required.Bytes) || !required.Action.GetRequireDefaultEgress() {
		t.Fatal("the requirement left the action as it was")
	}

	// the exits alone, approved and spent
	plainRequest, plainDecision := world.approvedEgress(plain, 0)
	plainUse := world.egressAction(plain, 0)
	testGateExpectOutcome(t, "the exits alone", world.gate.Authorize(t.Context(), plainUse, nil), plainUse, ApprovalOutcomeDone)
	if world.lastSpentApprovalId() != plainRequest.ApprovalId() {
		t.Fatal("the exits alone spent another approval")
	}

	// the requirement's filing takes no use of that decision: it waits on a request of its own, whose action is its own
	requiredRequest := world.pendingRequest(world.gate.Authorize(t.Context(), world.egressAction(required, 0), nil))
	if requiredRequest.ApprovalId() == plainRequest.ApprovalId() || !bytes.Equal(requiredRequest.Action.Bytes, required.Bytes) {
		t.Fatalf("the requirement's filing waits on approval %s", requiredRequest.ApprovalId())
	}
	if runCount, _ := world.effect.counts(); runCount != 1 {
		t.Fatalf("the requirement's filing ran the effect: %d runs", runCount)
	}
	if render := RenderApprovalRequest(requiredRequest); !strings.HasSuffix(render.Meaning, testEgressRequirementClause) {
		t.Errorf("the requirement's request renders as %q", render.Meaning)
	}
	// nor does the decision on the exits alone spend on it when passed in hand
	err := world.gate.Authorize(t.Context(), world.egressAction(required, 0), testGateSigned(t, plainDecision))
	if !errors.Is(err, ErrApprovalRefused) {
		t.Fatalf("the exits' decision passed with the requirement's filing: %v", err)
	}
	if runCount, _ := world.effect.counts(); runCount != 1 {
		t.Fatalf("a refused decision ran the effect: %d runs", runCount)
	}

	// the requirement's own approval spends, under another effect key
	requiredDecision := world.decision(requiredRequest, world.spend.phone, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, 1)
	if _, err := world.inbox.Receive(t.Context(), requiredDecision); err != nil {
		t.Fatal(err)
	}
	requiredUse := world.egressAction(required, 0)
	testGateExpectOutcome(t, "the requirement", world.gate.Authorize(t.Context(), requiredUse, nil), requiredUse, ApprovalOutcomeDone)
	if world.lastSpentApprovalId() != requiredRequest.ApprovalId() || bytes.Equal(requiredUse.Outcome.EffectRef, plainUse.Outcome.EffectRef) {
		t.Fatalf("the requirement spent approval %s, effect %q", world.lastSpentApprovalId(), requiredUse.Outcome.EffectRef)
	}
	plainKey := ApprovalEffectKey(plainRequest.ApprovalId(), plain.ActionId(plainRequest.ApprovalId()))
	requiredKey := ApprovalEffectKey(requiredRequest.ApprovalId(), required.ActionId(requiredRequest.ApprovalId()))
	if plainKey == requiredKey {
		t.Fatal("the two filings share an effect key")
	}

	// each retry answers its own outcome, the effect not run again
	for _, retry := range []struct {
		name   string
		stored *StoredCanonicalAction
		want   []byte
	}{
		{name: "the exits alone again", stored: plain, want: plainUse.Outcome.EffectRef},
		{name: "the requirement again", stored: required, want: requiredUse.Outcome.EffectRef},
	} {
		use := world.egressAction(retry.stored, 0)
		testGateExpectOutcome(t, retry.name, world.gate.Authorize(t.Context(), use, nil), use, ApprovalOutcomeDone)
		if !bytes.Equal(use.Outcome.EffectRef, retry.want) {
			t.Errorf("%s: effect %q, want %q", retry.name, use.Outcome.EffectRef, retry.want)
		}
	}
	if runCount, effectCount := world.effect.counts(); runCount != 2 || effectCount != 2 {
		t.Errorf("%d runs, %d effects", runCount, effectCount)
	}

	// the other direction: the requirement's decision passed with the exits alone is refused
	err = world.gate.Authorize(t.Context(), world.egressAction(plain, 0), testGateSigned(t, requiredDecision))
	if !errors.Is(err, ErrApprovalRefused) {
		t.Errorf("the requirement's decision passed with the exits alone: %v", err)
	}
}

// A template binds the requirement of default egress whether it sets it or not (TemplateBound; question
// egress-lock-action-field-template-requirement): a template of two uses of the exits without the requirement, whose
// approver saw none, spends on those exits but not on the same exits with the requirement, which waits on a request of
// its own and refuses that template's decision passed in hand; a template that requires it spends on the requirement's
// filing.
func TestEgressChangeTemplateBindsTheRequirementAtTheGate(t *testing.T) {
	world := newTestApprovalWorld(t)
	world.lookups[SidecarActionEgressChange] = world.effect.lookup
	plain := testEgressAction(t, false)
	required := testEgressAction(t, true)

	template := testEgressTemplate(t, false)
	templateRequest, templateDecision := world.approvedEgress(template, 2)
	if render := RenderApprovalRequest(templateRequest); !render.Template || strings.Contains(render.Meaning, testEgressRequirementClause) {
		t.Fatalf("the template renders as %+v", render)
	}
	plainUse := world.egressAction(plain, 0)
	testGateExpectOutcome(t, "the exits under the template", world.gate.Authorize(t.Context(), plainUse, nil), plainUse, ApprovalOutcomeDone)
	if world.lastSpentApprovalId() != templateRequest.ApprovalId() {
		t.Fatal("the exits spent another approval than the template's")
	}

	// the template's second use is no use for the requirement's filing, which its approver never saw
	requiredRequest := world.pendingRequest(world.gate.Authorize(t.Context(), world.egressAction(required, 0), nil))
	if requiredRequest.ApprovalId() == templateRequest.ApprovalId() || !bytes.Equal(requiredRequest.Action.Bytes, required.Bytes) {
		t.Fatalf("the requirement's filing waits on approval %s", requiredRequest.ApprovalId())
	}
	err := world.gate.Authorize(t.Context(), world.egressAction(required, 0), testGateSigned(t, templateDecision))
	if !errors.Is(err, ErrApprovalRefused) {
		t.Fatalf("the template's decision passed with the requirement's filing: %v", err)
	}
	if runCount, _ := world.effect.counts(); runCount != 1 {
		t.Fatalf("the requirement's filing ran the effect under the template: %d runs", runCount)
	}

	// a template that requires it, whose approver saw the clause, covers the requirement's filing
	requiring := testEgressTemplate(t, true)
	requiringRequest, _ := world.approvedEgress(requiring, 2)
	if render := RenderApprovalRequest(requiringRequest); !strings.HasSuffix(render.Meaning, testEgressRequirementClause) {
		t.Fatalf("the requiring template renders as %q", render.Meaning)
	}
	requiredUse := world.egressAction(required, 0)
	testGateExpectOutcome(t, "the requirement under its template", world.gate.Authorize(t.Context(), requiredUse, nil), requiredUse, ApprovalOutcomeDone)
	if world.lastSpentApprovalId() != requiringRequest.ApprovalId() {
		t.Fatal("the requirement spent another approval than its template's")
	}
	if runCount, effectCount := world.effect.counts(); runCount != 2 || effectCount != 2 {
		t.Errorf("%d runs, %d effects", runCount, effectCount)
	}
}

// An approver's render of an egress change that requires default egress (QD-1060): the meaning says what the route
// becomes and then the requirement as its own clause, the field shows by its record.proto name, and the text a person
// reads carries both; the same exits without it show neither.
func TestEgressChangeRequirementRendersItsClause(t *testing.T) {
	world := newTestApprovalWorld(t)
	world.lookups[SidecarActionEgressChange] = world.effect.lookup
	request := testEgressRequest(true)
	exit := "sidecar:" + hex.EncodeToString(request.ExitSidecarIds[0].Bytes())
	wantPlain := "Send sidecar " + hex.EncodeToString(request.Subject.Bytes()) + "'s internet traffic only through " + exit +
		", and refuse it public egress"
	for _, c := range []struct {
		name     string
		stored   *StoredCanonicalAction
		meaning  string
		required bool
	}{
		{name: "the exits alone", stored: testEgressAction(t, false), meaning: wantPlain},
		{name: "the requirement", stored: testEgressAction(t, true), meaning: wantPlain + testEgressRequirementClause, required: true},
	} {
		filed := world.pendingRequest(world.gate.Authorize(t.Context(), world.egressAction(c.stored, 0), nil))
		render := RenderApprovalRequest(filed)
		fields := map[string]string{}
		for _, field := range render.Fields {
			fields[field.Name] = field.Value
		}
		value, shown := fields["require_default_egress"]
		if render.Meaning != c.meaning || shown != c.required || (c.required && value != "true") {
			t.Errorf("%s: meaning %q, require_default_egress %q (shown %t)", c.name, render.Meaning, value, shown)
		}
		text := render.Text()
		if !strings.Contains(text, c.meaning+".") || strings.Contains(text, "require_default_egress: true") != c.required ||
			strings.Contains(text, "default egress on") != c.required {
			t.Errorf("%s: the text\n%s", c.name, text)
		}
	}
}
