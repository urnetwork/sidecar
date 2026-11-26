//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Retries run only on a retryable code, RetryCount times from RetryBase doubling on the Harness's clock, always on the
// same model; a code no retry cures goes to the failure choice, which an unattached run cannot ask, so it stops.
func TestHarnessRetryOnlyRetryableNeverOtherModel(t *testing.T) {
	other := testInferRemoteEntry("chutes", "qwen4-max", ComputeLabelAp, InferEffortHigh)
	router := newHarnessScriptedRouter(t, testInferRemoteEntry("engy", "glm-5.2", ComputeLabelA1, InferEffortHigh), other)
	world := newHarnessTestWorld(t, router, nil, nil)
	capacity := &InferError{Code: InferErrorCapacity, Model: harnessTestModel, Message: "at capacity"}
	router.script(&harnessScriptedCall{refuse: capacity}, &harnessScriptedCall{refuse: capacity}, harnessTextCall("finally"))
	agent := world.agent(t, nil)
	log := harnessCollect(t, agent)
	agent.Prompt(context.Background(), "go", nil)
	waits := []time.Duration{}
	for attempt := 0; attempt < 2; attempt += 1 {
		<-router.called
		if err := world.clock.AwaitTimers(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
		wait := 2 * time.Second << attempt
		waits = append(waits, wait)
		world.clock.Advance(wait)
	}
	events := log.until(t, HarnessEventAgentSettled)
	retryStarts := []int64{}
	for _, event := range events {
		if event.Type == HarnessEventAutoRetryStart {
			delay := int64(0)
			event.Decode("delayMs", &delay)
			retryStarts = append(retryStarts, delay)
		}
	}
	if !slices.Equal(retryStarts, []int64{2000, 4000}) || harnessStopReason(events[len(events)-1]) != HarnessStopEnded {
		t.Fatalf("retries waited %v, stop %q", retryStarts, harnessStopReason(events[len(events)-1]))
	}
	for _, request := range router.made() {
		if request.Model != harnessTestModel {
			t.Fatalf("a retry went to %s", request.Model)
		}
	}

	// model_refused is no retry's to cure: no retry, and with no person attached the run stops naming the code
	router.script(&harnessScriptedCall{refuse: &InferError{Code: InferErrorModelRefused, Model: harnessTestModel, Message: "below the floor"}})
	before := len(router.made())
	harnessPromptIdle(t, agent, "again")
	events = log.until(t, HarnessEventAgentSettled)
	errorMessage := ""
	events[len(events)-1].Decode("errorMessage", &errorMessage)
	if len(router.made())-before != 1 || harnessStopReason(events[len(events)-1]) != HarnessStopError ||
		!strings.Contains(errorMessage, "model_refused") {
		t.Fatalf("a refused model: %d calls, stop %q, %q", len(router.made())-before, harnessStopReason(events[len(events)-1]), errorMessage)
	}
}

// The person attached to a run answers the failure choice: add credit is offered only to a person who may buy, else
// the question names who may; raise the budget files compute_budget_raise (kind 21) through the run's gate and calls
// again once it is approved; a held answer retries at the broker's time, offering nothing, then reports.
func TestHarnessFailureChoiceOffers(t *testing.T) {
	balance := &InferError{Code: InferErrorInsufficientQuota, Reason: InferQuotaReasonBalance, Model: harnessTestModel, Message: "the balance ran out."}
	asked := func(world *harnessTestWorld, agent HarnessAgent, log *harnessEventLog) *HarnessUiRequest {
		t.Helper()
		for _, event := range log.until(t, HarnessEventUiRequest) {
			if request := event.UiRequest(); request != nil {
				return request
			}
		}
		return nil
	}

	// a buyer is offered add credit
	router := newHarnessScriptedRouter(t)
	purchases := &harnessTestPurchases{mayBuy: true}
	world := newHarnessTestWorld(t, router, nil, &HarnessArgs{Purchases: purchases})
	agent := world.agent(t, nil)
	defer world.harness.UiBroker().AttachPerson(agent.Run().Id())()
	log := harnessCollect(t, agent)
	router.script(&harnessScriptedCall{refuse: balance}, harnessTextCall("bought and done"))
	agent.Prompt(context.Background(), "go", nil)
	request := asked(world, agent, log)
	if !slices.Contains(request.Options, HarnessFailureAddCredit) || !strings.Contains(request.Title, "insufficient_quota") ||
		!strings.Contains(request.Title, harnessTestModel) {
		t.Fatalf("a buyer's choice: %+v", request)
	}
	retry := HarnessFailureRetry
	if err := world.harness.UiBroker().Respond(&HarnessUiResponse{Id: request.Id, Value: &retry}); err != nil {
		t.Fatal(err)
	}
	if events := log.until(t, HarnessEventAgentSettled); harnessStopReason(events[len(events)-1]) != HarnessStopEnded {
		t.Fatalf("a retry after buying: %q", harnessStopReason(events[len(events)-1]))
	}

	// a person who may not buy is told who may, and offered no add credit
	router = newHarnessScriptedRouter(t)
	world = newHarnessTestWorld(t, router, nil, &HarnessArgs{Purchases: &harnessTestPurchases{who: "The network's admins"}})
	agent = world.agent(t, nil)
	defer world.harness.UiBroker().AttachPerson(agent.Run().Id())()
	log = harnessCollect(t, agent)
	router.script(&harnessScriptedCall{refuse: balance})
	agent.Prompt(context.Background(), "go", nil)
	request = asked(world, agent, log)
	if slices.Contains(request.Options, HarnessFailureAddCredit) || !strings.Contains(request.Message, "The network's admins may add credit") {
		t.Fatalf("a non-buyer's choice: %+v", request)
	}
	world.harness.UiBroker().Respond(&HarnessUiResponse{Id: request.Id, Cancelled: true})
	log.until(t, HarnessEventAgentSettled)

	// raise the budget files kind 21 and calls again once approved
	router = newHarnessScriptedRouter(t)
	approvals := newHarnessTestApprovals()
	gate := &harnessTestGate{approvals: approvals, approvalId: NewId(), presented: make(chan struct{}, 16)}
	raiser := &harnessTestRaiser{}
	world = newHarnessTestWorld(t, router, nil, &HarnessArgs{BudgetRaiser: raiser, Approvals: approvals})
	gate.runs = world.runs
	world.harness.gate = gate
	budget := &HarnessBudget{Id: NewId(), DayNanoUsd: 5 * 1000 * 1000 * 1000}
	agent = world.agent(t, &HarnessAgentSpec{Budget: budget})
	defer world.harness.UiBroker().AttachPerson(agent.Run().Id())()
	log = harnessCollect(t, agent)
	router.script(&harnessScriptedCall{refuse: &InferError{Code: InferErrorInsufficientQuota, Reason: InferQuotaReasonBudget,
		Budget: budget.Id.String(), Period: "day", Model: harnessTestModel, Message: "the day's budget ran out"}},
		harnessTextCall("raised and done"))
	agent.Prompt(context.Background(), "go", nil)
	request = asked(world, agent, log)
	if !slices.Contains(request.Options, HarnessFailureRaiseBudget) || slices.Contains(request.Options, HarnessFailureAddCredit) {
		t.Fatalf("a budget's choice: %+v", request)
	}
	raise := HarnessFailureRaiseBudget
	world.harness.UiBroker().Respond(&HarnessUiResponse{Id: request.Id, Value: &raise})
	pending := log.until(t, HarnessEventApprovalPending)
	kind := ""
	pending[len(pending)-1].Decode("kind", &kind)
	if kind != "alias_create" || raiser.count() != 1 || raiser.last().Period != "day" || raiser.last().Budget != budget {
		t.Fatalf("the raise: kind %q, %d raises", kind, raiser.count())
	}
	approvals.decide(gate.approvalId, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, ApprovalStatusApproved)
	if events := log.until(t, HarnessEventAgentSettled); harnessStopReason(events[len(events)-1]) != HarnessStopEnded {
		t.Fatalf("after the raise: %q", harnessStopReason(events[len(events)-1]))
	}

	// held: retried at the broker's time, HeldRetryCount times, offering nothing, then reported
	router = newHarnessScriptedRouter(t)
	world = newHarnessTestWorld(t, router, nil, nil)
	agent = world.agent(t, nil)
	defer world.harness.UiBroker().AttachPerson(agent.Run().Id())()
	log = harnessCollect(t, agent)
	start := world.clock.Now()
	for i := 1; i <= 4; i += 1 {
		// each answer names the broker's time a further 90 seconds on
		router.script(&harnessScriptedCall{refuse: &InferError{Code: InferErrorInsufficientQuota, Reason: InferQuotaReasonHeld,
			RetryAtMs: start.Add(time.Duration(i) * 90 * time.Second).UnixMilli(), Model: harnessTestModel,
			Message: "holds stand in the way"}})
	}
	agent.Prompt(context.Background(), "go", nil)
	for i := 0; i < 3; i += 1 {
		<-router.called
		if err := world.clock.AwaitTimers(context.Background(), 1); err != nil {
			t.Fatal(err)
		}
		// nothing is retried before the broker's time
		world.clock.Advance(89 * time.Second)
		select {
		case <-router.called:
			t.Fatal("a held call retried before the broker's time")
		default:
		}
		world.clock.Advance(time.Second)
	}
	events := log.until(t, HarnessEventAgentSettled)
	for _, event := range events {
		if event.Type == HarnessEventUiRequest {
			t.Fatal("a held answer offered a choice")
		}
	}
	if calls := len(router.made()); calls != 4 || harnessStopReason(events[len(events)-1]) != HarnessStopError {
		t.Fatalf("held: %d calls, stop %q", calls, harnessStopReason(events[len(events)-1]))
	}
}

// BAL's purchase rights as a test fixes them.
type harnessTestPurchases struct {
	mayBuy bool
	who    string
}

func (self *harnessTestPurchases) MayBuy(ctx context.Context) (bool, string, error) {
	return self.mayBuy, self.who, nil
}

// Kind 21's builder as a test stands it in: an action its fake gate takes, as kind 21 for the run's check.
type harnessTestRaiser struct {
	stateLock sync.Mutex
	raises    []*HarnessBudgetRaise
}

func (self *harnessTestRaiser) BudgetRaise(ctx context.Context, raise *HarnessBudgetRaise) (*HarnessAuthorizeRequest, error) {
	self.stateLock.Lock()
	self.raises = append(self.raises, raise)
	self.stateLock.Unlock()
	stored, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionAliasCreate), Alias: "budget"})
	if err != nil {
		return nil, err
	}
	// the fake gate reads the action's bytes alone; the run holds the kind it asked to the action it was given
	stored.Action.Kind = uint32(SidecarActionComputeBudgetRaise)
	return &HarnessAuthorizeRequest{Kind: SidecarActionComputeBudgetRaise, Action: stored, PolicyRisk: SidecarRiskNormal,
		AgentAskedRisk: SidecarRiskNormal, Effect: &harnessTestEffect{}}, nil
}

func (self *harnessTestRaiser) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.raises)
}

func (self *harnessTestRaiser) last() *HarnessBudgetRaise {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.raises[len(self.raises)-1]
}

// A none model's disclosure, in a run a person is attached to: the run raises the disclosure request, waits for the
// acknowledgment and calls again; a "Not now" takes it to the failure choice.
func TestHarnessDisclosureAttachedAsksThenCalls(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	acks := newHarnessTestAcks()
	world := newHarnessTestWorld(t, router, nil, &HarnessArgs{Acks: acks})
	agent := world.agent(t, nil)
	defer world.harness.UiBroker().AttachPerson(agent.Run().Id())()
	log := harnessCollect(t, agent)
	required := &InferError{Code: InferErrorDisclosureRequired, Reason: InferDisclosureReasonUnacknowledged, Model: harnessTestModel,
		DisclosureId: "inference:none", DisclosureVersion: 2, Message: "acknowledge first"}
	router.script(&harnessScriptedCall{refuse: required}, harnessTextCall("now answered"))
	agent.Prompt(context.Background(), "go", nil)
	events := log.until(t, HarnessEventUiRequest)
	request := events[len(events)-1].UiRequest()
	if request.Method != HarnessUiDisclosure || request.DisclosureId != "inference:none" || request.DisclosureVersion != 2 ||
		request.Title != "" || request.Message != "" {
		t.Fatalf("the disclosure request: %+v", request)
	}
	acks.acknowledge("inference:none", 2)
	events = log.until(t, HarnessEventAgentSettled)
	if harnessStopReason(events[len(events)-1]) != HarnessStopEnded || len(router.made()) != 2 {
		t.Fatalf("after the acknowledgment: %q, %d calls", harnessStopReason(events[len(events)-1]), len(router.made()))
	}

	// "Not now" fails the call with the failure choice: a new version the store does not cover
	router.script(&harnessScriptedCall{refuse: &InferError{Code: InferErrorDisclosureRequired, Reason: InferDisclosureReasonUnacknowledged,
		Model: harnessTestModel, DisclosureId: "inference:none", DisclosureVersion: 3, Message: "acknowledge the new version"}})
	harnessPromptIdle(t, agent, "again")
	events = log.until(t, HarnessEventUiRequest)
	request = events[len(events)-1].UiRequest()
	notNow := HarnessUiDisclosureDecline
	world.harness.UiBroker().Respond(&HarnessUiResponse{Id: request.Id, Value: &notNow})
	events = log.until(t, HarnessEventUiRequest)
	choice := events[len(events)-1].UiRequest()
	if choice.Method != HarnessUiSelect || !slices.Contains(choice.Options, HarnessFailureAnotherModel) ||
		!strings.Contains(choice.Title, "disclosure_required") {
		t.Fatalf("after Not now: %+v", choice)
	}
	world.harness.UiBroker().Respond(&HarnessUiResponse{Id: choice.Id, Cancelled: true})
	log.until(t, HarnessEventAgentSettled)
}

// A none model's disclosure in a run no person is attached to stops the run, its stop reason naming the disclosure,
// and nothing is raised.
func TestHarnessDisclosureUnattachedStopsNamingIt(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	world := newHarnessTestWorld(t, router, nil, &HarnessArgs{Acks: newHarnessTestAcks()})
	agent := world.agent(t, nil)
	log := harnessCollect(t, agent)
	router.script(&harnessScriptedCall{refuse: &InferError{Code: InferErrorDisclosureRequired, Reason: InferDisclosureReasonUnacknowledged,
		Model: harnessTestModel, DisclosureId: "inference:none", DisclosureVersion: 2, Message: "acknowledge first"}})
	agent.Prompt(context.Background(), "go", nil)
	events := log.until(t, HarnessEventAgentSettled)
	errorMessage := ""
	events[len(events)-1].Decode("errorMessage", &errorMessage)
	if harnessStopReason(events[len(events)-1]) != HarnessStopDisclosureRequired || !strings.Contains(errorMessage, "inference:none") {
		t.Fatalf("stop %q: %q", harnessStopReason(events[len(events)-1]), errorMessage)
	}
	for _, event := range events {
		if event.Type == HarnessEventUiRequest {
			t.Fatal("an unattached run raised a request")
		}
	}
}
