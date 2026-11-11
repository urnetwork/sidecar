//go:build !ios_extension

// MCP-M3-06: §16.6's gate on the approval world (record_approval_state_test.go), a test effect and a fake clock, each
// a top-level test: one effect for two callers of one action; spent for a further action; a kill after the Reserve,
// after the effect and before the Outcome, each then a retry and a restart's reconcile; an uncertain use never taken by
// another action; the stale rule filing a tainted request; a use reserved before the taint completing; a tainted run
// refusing a standing grant; expiry at not_after - 1 s and + 11 min; a gate kind refused past not_after - 60 s; a cancel
// with a reservation in flight; harness evidence in a tainted run only where its rule names harness; and every kind of
// §5.4's list reaching the real gate, which passes none without a decision (CORE-M3-01's TestEveryKindReachesGate).

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A mail template the world's agent may spend uses times: recipients among those listed, from alias me.
func (self *testApprovalWorld) mailTemplate(recipients ...string) *StoredCanonicalAction {
	self.t.Helper()
	template, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionMail), Scope: true, Recipients: recipients, Alias: "me",
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return template
}

// Files template's request and keeps the phone's approval of it for uses, answering the request and the decision as
// stored.
func (self *testApprovalWorld) approvedTemplate(template *StoredCanonicalAction, uses uint32) (*StoredApprovalRequest, []byte) {
	self.t.Helper()
	request, err := self.router.FindOrFile(self.t.Context(), self.action(template))
	if err != nil {
		self.t.Fatal(err)
	}
	decision := self.decision(request, self.spend.phone, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, uses)
	if _, err := self.inbox.Receive(self.t.Context(), decision); err != nil {
		self.t.Fatal(err)
	}
	return request, decision
}

// A stored decision as the Signed Authorize takes.
func testGateSigned(t *testing.T, stored []byte) *bridge.Signed {
	t.Helper()
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(stored, signed); err != nil {
		t.Fatal(err)
	}
	return signed
}

// Reserves stored's use of request directly in the ledger, as a process killed after spend step 4 left it, and
// answers its effect key.
func (self *testApprovalWorld) reserveDirect(request *StoredApprovalRequest, stored *StoredCanonicalAction) []byte {
	self.t.Helper()
	approvalId := request.ApprovalId()
	actionId := stored.ActionId(approvalId)
	effectKey := ApprovalEffectKey(approvalId, actionId)
	payloadSha256 := stored.PayloadSha256()
	hold := self.ledger.Hold(approvalId)
	defer hold.Release()
	if _, _, err := hold.ReserveUse(stored.Bytes, actionId[:], payloadSha256[:], effectKey[:], 1); err != nil {
		self.t.Fatal(err)
	}
	return effectKey[:]
}

// The outcome a call answered, which must be nil with an outcome of want.
func testGateExpectOutcome(t *testing.T, name string, err error, action *SidecarAction, want ApprovalOutcomeState) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if action.Outcome == nil || action.Outcome.State != want {
		t.Fatalf("%s: outcome %+v, want %s", name, action.Outcome, want)
	}
}

// Two callers of one approved action at once join one flight: one effect, both answered with it.
func TestOneEffectForTwoCallers(t *testing.T) {
	world := newTestApprovalWorld(t)
	stored := world.mailAction("someone@example.com")
	world.approved(stored)
	world.effect.running = make(chan struct{})
	world.effect.release = make(chan struct{})
	joined := make(chan struct{}, 1)
	world.gate.flights.onJoin = func(key string) {
		joined <- struct{}{}
	}
	first, second := world.action(stored), world.action(stored)
	errs := make(chan error, 2)
	go func() {
		errs <- world.gate.Authorize(context.Background(), first, nil)
	}()
	<-world.effect.running
	go func() {
		errs <- world.gate.Authorize(context.Background(), second, nil)
	}()
	<-joined
	close(world.effect.release)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if runCount, effectCount := world.effect.counts(); runCount != 1 || effectCount != 1 {
		t.Errorf("%d runs, %d effects", runCount, effectCount)
	}
	if first.Outcome.State != ApprovalOutcomeDone || !bytes.Equal(first.Outcome.EffectRef, second.Outcome.EffectRef) {
		t.Errorf("outcomes %+v and %+v", first.Outcome, second.Outcome)
	}
	// AU4: a later retry answers the original outcome without running the effect
	world.effect.running, world.effect.release = nil, nil
	third := world.action(stored)
	testGateExpectOutcome(t, "a retry", world.gate.Authorize(t.Context(), third, nil), third, ApprovalOutcomeDone)
	if runCount, _ := world.effect.counts(); runCount != 1 || !bytes.Equal(third.Outcome.EffectRef, first.Outcome.EffectRef) {
		t.Errorf("the retry ran the effect again, or answered another reference: %d runs", runCount)
	}
}

// A template approved for two uses spends on two different actions, and a third is refused spent, never taking a used
// one; without the decision in hand the third files a request of its own.
func TestSpentForAFurtherAction(t *testing.T) {
	world := newTestApprovalWorld(t)
	template := world.mailTemplate("a@example.com", "b@example.com", "c@example.com")
	request, decision := world.approvedTemplate(template, 2)
	for _, recipient := range []string{"a@example.com", "b@example.com"} {
		action := world.action(world.mailAction(recipient))
		testGateExpectOutcome(t, recipient, world.gate.Authorize(t.Context(), action, nil), action, ApprovalOutcomeDone)
	}
	third := world.action(world.mailAction("c@example.com"))
	if err := world.gate.Authorize(t.Context(), third, testGateSigned(t, decision)); !errors.Is(err, ErrApprovalSpent) {
		t.Errorf("a third action with the decision: %v", err)
	}
	if fresh := world.pendingRequest(world.gate.Authorize(t.Context(), third, nil)); fresh.ApprovalId() == request.ApprovalId() {
		t.Error("the third action found the spent approval")
	}
	if _, effectCount := world.effect.counts(); effectCount != 2 {
		t.Errorf("%d effects for two uses", effectCount)
	}
	if got := world.status(request.ApprovalId()); got != ApprovalStatusSpent {
		t.Errorf("status %s", got)
	}
}

// A kill after the Reserve, after the effect, and before the Outcome: a restart's reconcile settles what its Lookup
// proves and leaves the rest uncertain, and a retry of the same action answers the original or completes the use.
func TestRetryAfterKillAtEachStep(t *testing.T) {
	cases := []struct {
		name string
		// whether the effect happened before the kill
		effectDone bool
		// what the component answers on the retry, nil to do the effect
		retryAnswer error
		// the outcome the restart's reconcile records, empty for none
		reconciled ApprovalOutcomeState
		want       ApprovalOutcomeState
	}{
		{name: "after the reserve", effectDone: false, reconciled: ApprovalOutcomeUncertain, want: ApprovalOutcomeDone},
		{name: "after the effect", effectDone: true, reconciled: ApprovalOutcomeDone, want: ApprovalOutcomeDone},
		{name: "before the outcome", effectDone: false, retryAnswer: errors.New("the answer was lost"), reconciled: ApprovalOutcomeUncertain, want: ApprovalOutcomeUncertain},
	}
	for _, c := range cases {
		world := newTestApprovalWorld(t)
		stored := world.mailAction("someone@example.com")
		request := world.approved(stored)
		effectKey := world.reserveDirect(request, stored)
		if c.effectDone {
			world.effect.doneUnder(effectKey)
		}
		// the restart: a gate built afresh reconciles before it serves
		world.open()
		recordedCount, err := world.gate.Reconcile(t.Context())
		if err != nil || recordedCount != 1 {
			t.Fatalf("%s: reconcile recorded %d, %v", c.name, recordedCount, err)
		}
		actionId := stored.ActionId(request.ApprovalId())
		if outcome := world.state(request.ApprovalId()).Outcome(actionId[:]); outcome == nil || outcome.State != c.reconciled {
			t.Fatalf("%s: reconciled %+v", c.name, outcome)
		}
		world.effect.setAnswer(c.retryAnswer)
		action := world.action(stored)
		testGateExpectOutcome(t, c.name, world.gate.Authorize(t.Context(), action, nil), action, c.want)
		if _, effectCount := world.effect.counts(); c.want == ApprovalOutcomeDone && effectCount != 1 {
			t.Errorf("%s: %d effects", c.name, effectCount)
		}
		if uses := world.state(request.ApprovalId()).Reserves; len(uses) != 1 {
			t.Errorf("%s: %d reserves", c.name, len(uses))
		}
	}
}

// AU3: a use whose outcome is uncertain stays consumed, so a further action takes none of it and the uncertain one
// completes under its own key.
func TestUncertainNeverSpentByAnotherAction(t *testing.T) {
	world := newTestApprovalWorld(t)
	template := world.mailTemplate("a@example.com", "b@example.com", "c@example.com")
	_, decision := world.approvedTemplate(template, 2)
	first := world.mailAction("a@example.com")
	world.effect.setAnswer(errors.New("the connection dropped"))
	action := world.action(first)
	testGateExpectOutcome(t, "the uncertain use", world.gate.Authorize(t.Context(), action, nil), action, ApprovalOutcomeUncertain)
	world.effect.setAnswer(nil)
	second := world.action(world.mailAction("b@example.com"))
	testGateExpectOutcome(t, "the second use", world.gate.Authorize(t.Context(), second, nil), second, ApprovalOutcomeDone)
	third := world.action(world.mailAction("c@example.com"))
	if err := world.gate.Authorize(t.Context(), third, testGateSigned(t, decision)); !errors.Is(err, ErrApprovalSpent) {
		t.Errorf("a further action took the uncertain use: %v", err)
	}
	retry := world.action(first)
	testGateExpectOutcome(t, "the retry", world.gate.Authorize(t.Context(), retry, nil), retry, ApprovalOutcomeDone)
}

// TS1's stale rule: a run tainted after its request was filed untainted spends nothing on that decision, files a
// tainted request, and answers pending with it; the effect does not run.
func TestStaleFilesTaintedRequest(t *testing.T) {
	world := newTestApprovalWorld(t)
	stored := world.mailAction("someone@example.com")
	clean := world.approved(stored)
	if err := world.runs.Taint(t.Context(), world.runId, RunTaintUntrustedData); err != nil {
		t.Fatal(err)
	}
	fresh := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(stored), nil))
	if fresh.ApprovalId() == clean.ApprovalId() || !fresh.Request.GetTainted() {
		t.Errorf("the stale answer named %s, tainted %v", fresh.ApprovalId(), fresh.Request.GetTainted())
	}
	if runCount, _ := world.effect.counts(); runCount != 0 {
		t.Errorf("the effect ran %d times", runCount)
	}
	// the decision on the untainted request, handed in, is stale too
	if err := world.gate.Authorize(t.Context(), world.action(stored), testGateSigned(t, world.approve(clean))); err == nil {
		t.Error("an untainted request's decision spent in a tainted run")
	}
	// the tainted request's own approval spends
	world.log.putDecision(fresh.ApprovalId(), world.approve(fresh))
	if err := world.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	action := world.action(stored)
	testGateExpectOutcome(t, "the tainted request's approval", world.gate.Authorize(t.Context(), action, nil), action, ApprovalOutcomeDone)
}

// TS1: a use reserved before the taint only completes, the stale rule not applying to it.
func TestReservedBeforeTaintCompletes(t *testing.T) {
	world := newTestApprovalWorld(t)
	stored := world.mailAction("someone@example.com")
	world.approved(stored)
	world.effect.setAnswer(errors.New("the connection dropped"))
	action := world.action(stored)
	testGateExpectOutcome(t, "before the taint", world.gate.Authorize(t.Context(), action, nil), action, ApprovalOutcomeUncertain)
	if err := world.runs.Taint(t.Context(), world.runId, RunTaintWebTool); err != nil {
		t.Fatal(err)
	}
	world.effect.setAnswer(nil)
	retry := world.action(stored)
	testGateExpectOutcome(t, "after the taint", world.gate.Authorize(t.Context(), retry, nil), retry, ApprovalOutcomeDone)
}

// A standing grant passes an untainted run's action with no ledger row and an empty key; once the run is tainted no
// standing grant passes, and the action files a request (TS1).
func TestTaintedRunRefusesStandingGrant(t *testing.T) {
	world := newTestApprovalWorld(t)
	world.grants.covers = true
	stored := world.mailAction("someone@example.com")
	action := world.action(stored)
	testGateExpectOutcome(t, "untainted", world.gate.Authorize(t.Context(), action, nil), action, ApprovalOutcomeDone)
	approvalIds, err := world.ledger.approvalIds()
	if err != nil || len(approvalIds) != 0 {
		t.Errorf("a standing grant wrote %d approvals, %v", len(approvalIds), err)
	}
	if err := world.runs.Taint(t.Context(), world.runId, RunTaintCoverageLapse); err != nil {
		t.Fatal(err)
	}
	request := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(stored), nil))
	if !request.Request.GetTainted() {
		t.Error("the tainted run's request reads untainted")
	}
	if runCount, _ := world.effect.counts(); runCount != 1 {
		t.Errorf("the effect ran %d times", runCount)
	}
}

// A local use reserves until not_after: at not_after - 1 s it spends; a first use at not_after + 30 s is refused
// expired; and a use left uncertain only reconciles at not_after + 11 min, its effect not run again.
func TestExpiryAtNotAfter(t *testing.T) {
	world := newTestApprovalWorld(t)
	early := world.mailAction("early@example.com")
	earlyRequest := world.approved(early)
	late := world.mailAction("late@example.com")
	lateRequest := world.approved(late)
	uncertain := world.mailAction("uncertain@example.com")
	uncertainRequest := world.approved(uncertain)
	notAfter := time.UnixMilli(earlyRequest.Request.GetNotAfterMillis())
	if !notAfter.Equal(time.UnixMilli(lateRequest.Request.GetNotAfterMillis())) {
		t.Fatal("the requests expire apart")
	}
	world.clock.advance(notAfter.Add(-time.Second).Sub(world.clock.Now()))
	action := world.action(early)
	testGateExpectOutcome(t, "at not_after - 1 s", world.gate.Authorize(t.Context(), action, nil), action, ApprovalOutcomeDone)
	world.effect.setAnswer(errors.New("the connection dropped"))
	pending := world.action(uncertain)
	testGateExpectOutcome(t, "an uncertain use", world.gate.Authorize(t.Context(), pending, nil), pending, ApprovalOutcomeUncertain)
	world.effect.setAnswer(nil)

	world.clock.advance(31 * time.Second)
	if err := world.gate.Authorize(t.Context(), world.action(late), testGateSigned(t, world.approve(lateRequest))); !errors.Is(err, ErrApprovalExpired) {
		t.Errorf("a first use past not_after: %v", err)
	}

	runCount, _ := world.effect.counts()
	world.clock.advance(11 * time.Minute)
	retry := world.action(uncertain)
	if err := world.gate.Authorize(t.Context(), retry, nil); err != nil || retry.Outcome.State != ApprovalOutcomeUncertain || !errors.Is(retry.Outcome.Err, ErrApprovalExpired) {
		t.Errorf("a retry past the completion window: %v, %+v", err, retry.Outcome)
	}
	if after, _ := world.effect.counts(); after != runCount {
		t.Errorf("the retry ran the effect past its window: %d runs, %d before", after, runCount)
	}
	// a Lookup that finds the effect settles it, still without running it
	actionId := uncertain.ActionId(uncertainRequest.ApprovalId())
	effectKey := ApprovalEffectKey(uncertainRequest.ApprovalId(), actionId)
	world.effect.doneUnder(effectKey[:])
	settled := world.action(uncertain)
	if err := world.gate.Authorize(t.Context(), settled, nil); err != nil || settled.Outcome.State != ApprovalOutcomeDone {
		t.Errorf("a reconciling retry: %v, %+v", err, settled.Outcome)
	}
	if after, _ := world.effect.counts(); after != runCount {
		t.Errorf("the reconciling retry ran the effect: %d runs", after)
	}
}

// A gate kind's use reserves until not_after - 60 s, §8.6's skew, so a prompt presentation meets the gate's clock: at
// not_after - 61 s it spends, at not_after - 59 s it is refused.
func TestServerGatedRefusedPastSkew(t *testing.T) {
	world := newTestApprovalWorld(t)
	first := testSpendDnsAction(t, "192.0.2.10")
	firstRequest := world.approved(first)
	second := testSpendDnsAction(t, "192.0.2.11")
	world.approved(second)
	notAfter := time.UnixMilli(firstRequest.Request.GetNotAfterMillis())
	world.clock.advance(notAfter.Add(-61 * time.Second).Sub(world.clock.Now()))
	action := world.action(first)
	testGateExpectOutcome(t, "at not_after - 61 s", world.gate.Authorize(t.Context(), action, nil), action, ApprovalOutcomeDone)
	spend, ok := world.lastSpend()
	if !ok || spend.ApprovalId != firstRequest.ApprovalId() || len(spend.Decisions) != 1 || !bytes.Equal(spend.Action, first.Bytes) {
		t.Errorf("the gate kind's effect saw spend %+v", spend)
	}
	world.clock.advance(2 * time.Second)
	if err := world.gate.Authorize(t.Context(), world.action(second), nil); !errors.Is(err, ErrApprovalExpired) {
		t.Errorf("at not_after - 59 s: %v", err)
	}
}

// The spend the world's effect last ran under, read through a probe effect.
func (self *testApprovalWorld) lastSpend() (*ApprovalSpend, bool) {
	return self.effect.spendSeen()
}

// A cancel that lands while a use's effect runs leaves that use to complete, and a further use is refused cancelled.
func TestCancelWithReservationInFlight(t *testing.T) {
	world := newTestApprovalWorld(t)
	template := world.mailTemplate("a@example.com", "b@example.com")
	request, decision := world.approvedTemplate(template, 2)
	world.effect.running = make(chan struct{})
	world.effect.release = make(chan struct{})
	inFlight := world.action(world.mailAction("a@example.com"))
	errs := make(chan error, 1)
	go func() {
		errs <- world.gate.Authorize(context.Background(), inFlight, nil)
	}()
	<-world.effect.running
	cancel, err := proto.Marshal(world.signedCancel(world.spend.phone, request.ApprovalId()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.inbox.ReceiveCancel(t.Context(), cancel); err != nil {
		t.Fatal(err)
	}
	close(world.effect.release)
	testGateExpectOutcome(t, "the use in flight", <-errs, inFlight, ApprovalOutcomeDone)
	world.effect.running, world.effect.release = nil, nil
	further := world.action(world.mailAction("b@example.com"))
	if err := world.gate.Authorize(t.Context(), further, testGateSigned(t, decision)); !errors.Is(err, ErrApprovalCancelled) {
		t.Errorf("a further use after the cancel: %v", err)
	}
	if got := world.status(request.ApprovalId()); got != ApprovalStatusCancelled {
		t.Errorf("status %s", got)
	}
	// a cancel signed by a device that is not its approver's is not kept
	other := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(world.mailAction("other@example.com")), nil))
	world.log.putDecision(other.ApprovalId(), world.approve(other))
	if err := world.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	forged, err := proto.Marshal(world.signedCancel(world.spend.otherDevice, other.ApprovalId()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.inbox.ReceiveCancel(t.Context(), forged); err == nil {
		t.Error("another member's device cancelled the approval")
	}
}

// An ApprovalCancel of approvalId signed by signerId's identity key.
func (self *testApprovalWorld) signedCancel(signerId Id, approvalId Id) *bridge.Signed {
	body, err := proto.Marshal(&protocol.ApprovalCancel{ApprovalId: approvalId.Bytes()})
	if err != nil {
		self.t.Fatal(err)
	}
	return &bridge.Signed{
		Body:      body,
		SignerId:  signerId.Bytes(),
		Signature: ed25519.Sign(self.spend.keys[signerId], bridge.SignedBytes(ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_CANCEL, body)),
		Type:      uint32(bridge.SignedType_SIGNED_APPROVAL_CANCEL),
	}
}

// Owner decision 142: in a tainted run a harness decision spends only where the governing rule's own list names
// harness, never through evidenceDefault.
func TestTaintedHarnessDecisionNeedsRuleNamingHarness(t *testing.T) {
	world := newTestApprovalWorld(t)
	if err := world.runs.Taint(t.Context(), world.runId, RunTaintWebTool); err != nil {
		t.Fatal(err)
	}
	world.harness = approvalHarnessFunc(func(ctx context.Context, action *SidecarAction, request *StoredApprovalRequest) ([]byte, error) {
		return world.decision(request, world.spend.laptop, protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS,
			protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, 1), nil
	})
	stored := world.mailAction("someone@example.com")
	if err := world.gate.Authorize(t.Context(), world.action(stored), nil); SpendRefusalCodeOf(err) != SpendRefusalEvidence {
		t.Errorf("a harness decision in a tainted run under evidenceDefault: %v", err)
	}
	world.states.namesHarness = true
	action := world.action(stored)
	testGateExpectOutcome(t, "the rule names harness", world.gate.Authorize(t.Context(), action, nil), action, ApprovalOutcomeDone)
}

// A denial refuses the action rather than filing it again, and an action whose kind registers no Lookup is refused
// before its Reserve.
func TestDeniedAndNoLookupRefuse(t *testing.T) {
	world := newTestApprovalWorld(t)
	stored := world.mailAction("someone@example.com")
	request := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(stored), nil))
	world.log.putDecision(request.ApprovalId(), world.decision(request, world.spend.phone, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY, 0))
	if err := world.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := world.gate.Authorize(t.Context(), world.action(stored), nil); !errors.Is(err, ErrApprovalDenied) {
		t.Errorf("a denied action: %v", err)
	}
	if world.log.filedCount() != 1 {
		t.Errorf("%d requests filed after a denial", world.log.filedCount())
	}

	delete(world.lookups, SidecarActionMail)
	unlooked := world.mailAction("another@example.com")
	unlookedRequest := world.approved(unlooked)
	if err := world.gate.Authorize(t.Context(), world.action(unlooked), nil); !errors.Is(err, ErrApprovalNoLookup) {
		t.Errorf("a kind with no lookup: %v", err)
	}
	if reserves := world.state(unlookedRequest.ApprovalId()).Reserves; len(reserves) != 0 {
		t.Errorf("%d reserves for a kind with no lookup", len(reserves))
	}
}

// CORE-M3-01's TestEveryKindReachesGate on the real gate: every kind of §5.4's list reaches it through
// Sidecar.Authorize, and none passes without a decision. A kind with a row in the kind table files its request and
// waits; one with none is refused as the action it cannot parse.
func TestEveryKindReachesRealGate(t *testing.T) {
	world := newTestApprovalWorld(t)
	sidecar, _, _ := newIdentityTestSidecar(t)
	defer sidecar.InstallGate(world.gate)()
	for _, kind := range sidecarGateKinds {
		canonical, err := proto.Marshal(&protocol.CanonicalAction{Kind: uint32(kind), Version: 1, Scope: true})
		if err != nil {
			t.Fatal(err)
		}
		action := world.action(&StoredCanonicalAction{Action: &protocol.CanonicalAction{Kind: uint32(kind)}, Bytes: canonical})
		err = sidecar.Authorize(t.Context(), action, nil)
		pending := &ApprovalPendingError{}
		switch {
		case err == nil:
			t.Errorf("kind %d passed without a decision", kind)
		case errors.As(err, &pending):
		case errors.Is(err, ErrSidecarActionInvalid):
			if _, ok := CanonicalActionFields(kind); ok {
				if _, parseErr := ParseStoredCanonicalAction(canonical); parseErr == nil {
					t.Errorf("kind %d has a row and was refused as malformed: %v", kind, err)
				}
			}
		default:
			t.Errorf("kind %d: %v", kind, err)
		}
	}
	if runCount, _ := world.effect.counts(); runCount != 0 {
		t.Errorf("an effect ran %d times", runCount)
	}
	if world.log.filedCount() == 0 {
		t.Error("no kind filed a request")
	}
	if !slices.Contains(sidecarGateKinds[:], SidecarActionRestore) {
		t.Error("restore is not on the gate's list")
	}
}
