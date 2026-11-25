//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The instant the tests' engy disclosure version 2 took effect.
var testInferDisclosureSince = time.Date(2027, time.March, 1, 12, 0, 0, 0, time.UTC)

// A policy covering Chutes' TEE model at AP, Tinfoil's at A1, and two of engy's direct models, one of them on the
// limited_use line; engy's disclosure at version 2 with 14 days' grace from testInferDisclosureSince.
func testInferCheckPolicy() *ComputePolicy {
	return &ComputePolicy{
		Version:    3,
		NotAfterMs: testInferDisclosureSince.Add(90 * 24 * time.Hour).UnixMilli(),
		Providers: []*ComputePolicyProvider{
			{Id: "chutes", Label: ComputeLabelAp, Models: []*ComputePolicyModel{{Model: "qwen3.8-27b-tee", ProviderModelId: "chute-qwen"}}},
			{Id: "tinfoil", Label: ComputeLabelA1, Models: []*ComputePolicyModel{{Model: "gpt-oss-120b", ProviderModelId: "gpt-oss"}}},
		},
		Direct: ComputePolicyDirectLine{
			Providers: []*ComputePolicyDirect{{
				Slug: "engy",
				Models: []*ComputePolicyDirectModel{
					{Model: "glm-5.2", ProviderModelId: "glm-5.2"},
					{Model: "deepseek-v4.1-flash", ProviderModelId: "deepseek-v4.1-flash-1017"},
				},
			}},
			LimitedUse: []string{"engy-deepseek-v4.1-flash"},
		},
		Disclosures: []*ComputePolicyDisclosure{
			{Id: "inference:local", Version: 1},
			{Id: "inference:chutes", Version: 1},
			{Id: "inference:engy", Version: 2, GraceDays: 14, SinceMs: testInferDisclosureSince.UnixMilli()},
		},
	}
}

// The newest policy, the remote-work gate and its clock, each settable.
type testInferPolicySource struct {
	stateLock  sync.Mutex
	policy     *ComputePolicy
	policyErr  error
	remoteErr  error
	now        time.Time
	operations []ComputeRemoteOperation
}

// See InferPolicySource.
func (self *testInferPolicySource) PolicyCurrent() (*ComputePolicy, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.policy, self.policyErr
}

// See InferPolicySource.
func (self *testInferPolicySource) RemoteWork(ctx context.Context, operation ComputeRemoteOperation) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.operations = append(self.operations, operation)
	return self.remoteErr
}

// See InferPolicySource.
func (self *testInferPolicySource) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

// Sets the gate's time.
func (self *testInferPolicySource) setNow(now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = now
}

// The person's models key as read.
type testInferModelsKey struct {
	read *HarnessModelsKeyRead
	err  error
}

// See InferModelsKeySource.
func (self *testInferModelsKey) ModelsKey(ctx context.Context) (*HarnessModelsKeyRead, error) {
	return self.read, self.err
}

// The network's floor and providers.
type testInferComputeBlock struct {
	network *ComputeNetworkModels
	err     error
}

// See InferComputeBlockSource.
func (self *testInferComputeBlock) ComputeNetworkModels(ctx context.Context) (*ComputeNetworkModels, error) {
	return self.network, self.err
}

// Device budgets that answer err, counting their asks.
type testInferBudgets struct {
	stateLock sync.Mutex
	err       error
	asked     int
}

// See InferBudgetGate.
func (self *testInferBudgets) Admit(ctx context.Context, call *InferCall) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.asked += 1
	return self.err
}

// The acknowledgments covering this sidecar, changeable.
type testInferAcknowledgments struct {
	stateLock sync.Mutex
	scope     InferAcknowledgmentScope
	versions  map[string]uint32
	err       error
}

// See InferAcknowledgments.
func (self *testInferAcknowledgments) Covering(ctx context.Context) (*InferAcknowledgmentSet, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return nil, self.err
	}
	versions := map[string]uint32{}
	for id, version := range self.versions {
		versions[id] = version
	}
	return &InferAcknowledgmentSet{Scope: self.scope, Versions: versions}, nil
}

// Records an acknowledgment of id at version.
func (self *testInferAcknowledgments) acknowledge(id string, version uint32) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.versions[id] = version
}

// Runs' and bindings' marks.
type testInferMarks struct {
	stateLock sync.Mutex
	runs      map[Id][]string
	bindings  map[string][]string
	err       error
}

// See InferMarkSource.
func (self *testInferMarks) RunMarks(ctx context.Context, runId Id) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.runs[runId]), self.err
}

// See InferMarkSource.
func (self *testInferMarks) BindingMarks(ctx context.Context, binding *InferBinding) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.bindings[binding.Handle]), self.err
}

// Marks run with mark.
func (self *testInferMarks) mark(runId Id, mark string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.runs[runId] = append(self.runs[runId], mark)
}

// The person attached to some runs, answering each ask with answer.
type testInferAsker struct {
	stateLock sync.Mutex
	attached  map[Id]bool
	answer    func(ask *InferDisclosureAsk) (bool, error)
	asks      []*InferDisclosureAsk
}

// See InferDisclosureAsker.
func (self *testInferAsker) Attached(runId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.attached[runId]
}

// See InferDisclosureAsker.
func (self *testInferAsker) Ask(ctx context.Context, ask *InferDisclosureAsk) (bool, error) {
	answer := func() func(ask *InferDisclosureAsk) (bool, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.asks = append(self.asks, ask)
		return self.answer
	}()
	return answer(ask)
}

// The asks made so far.
func (self *testInferAsker) asked() []*InferDisclosureAsk {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.asks)
}

// A router world whose checks are the real ones over fakes of every source: CO-18's defaults for the network, the
// person's defaults for the key, budgets with room, no acknowledgment, no mark and no one attached.
type testInferCheckWorld struct {
	*testInferRouterWorld
	policy  *testInferPolicySource
	key     *testInferModelsKey
	block   *testInferComputeBlock
	budgets *testInferBudgets
	acks    *testInferAcknowledgments
	marks   *testInferMarks
	asker   *testInferAsker
	sources *InferCheckSources
}

// The check world, with change made to its fakes and sources before the router is built.
func newTestInferCheckWorld(t *testing.T, change func(world *testInferCheckWorld)) *testInferCheckWorld {
	t.Helper()
	world := &testInferCheckWorld{
		policy: &testInferPolicySource{
			policy: testInferCheckPolicy(),
			now:    testInferDisclosureSince.Add(time.Hour),
		},
		key:     &testInferModelsKey{read: &HarnessModelsKeyRead{Key: &HarnessModelsKey{}}},
		block:   &testInferComputeBlock{network: DefaultComputeNetworkModels()},
		budgets: &testInferBudgets{},
		acks:    &testInferAcknowledgments{scope: InferAcknowledgmentPerson, versions: map[string]uint32{}},
		marks:   &testInferMarks{runs: map[Id][]string{}, bindings: map[string][]string{}},
		asker:   &testInferAsker{attached: map[Id]bool{}},
	}
	world.sources = &InferCheckSources{
		Policy:          world.policy,
		ModelsKey:       world.key,
		ComputeBlock:    world.block,
		Budgets:         world.budgets,
		Acknowledgments: world.acks,
		Marks:           world.marks,
		Asker:           world.asker,
	}
	if change != nil {
		change(world)
	}
	world.testInferRouterWorld = newTestInferRouterWorld(t, func(routerWorld *testInferRouterWorld) {
		routerWorld.remote = []*InferCatalogEntry{
			testInferRemoteEntry("chutes", "qwen3.8-27b-tee", ComputeLabelAp, InferEffortLow, InferEffortHigh),
			testInferRemoteEntry("tinfoil", "gpt-oss-120b", ComputeLabelA1, InferEffortLow, InferEffortHigh),
			testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortOff, InferEffortHigh),
			testInferRemoteEntry("engy", "deepseek-v4.1-flash", ComputeLabelNone, InferEffortOff),
			testInferRemoteEntry("chutes", "kimi-k3-tee", ComputeLabelAp, InferEffortHigh),
		}
		routerWorld.checker = newInferSourceChecker(routerWorld.settings, world.sources, nil)
	})
	return world
}

// How many calls reached a path or the engine.
func (self *testInferCheckWorld) dispatched() int {
	return len(self.engine.called()) + len(self.tee.called()) + len(self.direct.called())
}

// Infers model for run, draining the stream, and answers the refusal or the stream's terminal error, nil for end.
func (self *testInferCheckWorld) infer(t *testing.T, request *InferRequest) error {
	t.Helper()
	events, err := self.router.Infer(context.Background(), request)
	if err != nil {
		return err
	}
	all := testInferDrain(t, events)
	if last := all[len(all)-1]; last.Kind == InferEventError {
		return last.Error
	}
	return nil
}

// A request for model in run.
func testInferRunRequest(model string, runId Id) *InferRequest {
	request := testInferRequest(model, "")
	request.RunId = &runId
	return request
}

// A local model runs under every floor, tee_only and providers list, past every budget in every state of the balance,
// on a run carrying limited_use, with no acknowledgment, no current policy and the remote-work gate lapsed: the
// person's allow alone decides (CO-9, IC-5).
func TestCheckLocalPassesEveryFloorAndBudget(t *testing.T) {
	quotas := []*InferError{
		{Code: InferErrorInsufficientQuota, Reason: InferQuotaReasonBalance, Message: "the network cannot pay"},
		{Code: InferErrorInsufficientQuota, Reason: InferQuotaReasonBudget, Budget: "agent", Period: "day", Message: "the agent's day is spent"},
		{Code: InferErrorInsufficientQuota, Reason: InferQuotaReasonHeld, RetryAtMs: 1, Message: "held"},
	}
	for _, quota := range quotas {
		runId := NewId()
		world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
			world.block.network = &ComputeNetworkModels{Floor: ComputeLabelA2, Providers: []string{}}
			world.key.read.Key.TeeOnly = true
			world.budgets.err = quota
			world.policy.policyErr = errors.New("no policy held")
			world.policy.remoteErr = &ComputeRemoteLapsedError{Reason: ComputeRemoteLapseTicketExpired}
			world.marks.runs[runId] = []string{inferMarkLimitedUse}
		})
		if err := world.infer(t, testInferRunRequest("local-gemma-4-e4b-off", runId)); err != nil {
			t.Errorf("with %s: %v", quota.Reason, err)
		}
		if world.budgets.asked != 0 || len(world.policy.operations) != 0 {
			t.Errorf("a local call asked the budgets %d times and the gate %v", world.budgets.asked, world.policy.operations)
		}
	}

	unwired := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.sources.Policy, world.sources.ComputeBlock, world.sources.Budgets = nil, nil, nil
		world.sources.Acknowledgments, world.sources.Marks, world.sources.ModelsKey = nil, nil, nil
	})
	if err := unwired.infer(t, testInferRequest("local-gemma-4-e4b-off", "")); err != nil {
		t.Errorf("with no source wired: %v", err)
	}

	narrowed := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.key.read.Key.Allow = []string{"chutes-*"}
	})
	refused := testInferErrorOf(t, narrowed.infer(t, testInferRequest("local-gemma-4-e4b-off", "")), InferErrorModelRefused)
	if refused.Reason != string(ComputeModelRuleAllow) {
		t.Errorf("a local model off allow: %+v", refused)
	}
	unreadable := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.key.read = &HarnessModelsKeyRead{Key: &HarnessModelsKey{}, Unreadable: true}
	})
	testInferErrorOf(t, unreadable.infer(t, testInferRequest("local-gemma-4-e4b-off", "")), InferErrorModelRefused)
	if narrowed.dispatched()+unreadable.dispatched() != 0 {
		t.Error("a refused local call ran")
	}
}

// Fails unless model is refused model_refused by rule in world, before any path or engine ran.
func testInferCheckRefusedBy(t *testing.T, world *testInferCheckWorld, model string, rule string) *InferError {
	t.Helper()
	err := world.infer(t, testInferRequest(model, ""))
	refused := testInferErrorOf(t, err, InferErrorModelRefused)
	if refused.Reason != rule || refused.Model != model {
		t.Errorf("%s refused as %+v, want rule %s", model, refused, rule)
	}
	testInferErrorOf(t, world.router.Check(context.Background(), testInferRequest(model, "")), InferErrorModelRefused)
	if world.dispatched() != 0 {
		t.Errorf("%s was refused and still dispatched", model)
	}
	return refused
}

// A remote model below the network's assurance_floor is refused, rule floor, and so is one below the person's
// tee_only, rule tee_only; one at or above both runs.
func TestCheckRemoteBelowFloorRefused(t *testing.T) {
	world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.block.network = &ComputeNetworkModels{Floor: ComputeLabelA1, Providers: []string{"*"}}
	})
	testInferCheckRefusedBy(t, world, "chutes-qwen3.8-27b-tee-high", string(ComputeModelRuleFloor))
	testInferCheckRefusedBy(t, world, "engy-glm-5.2-off", string(ComputeModelRuleFloor))
	if err := world.infer(t, testInferRequest("tinfoil-gpt-oss-120b-high", "")); err != nil {
		t.Errorf("an A1 model under an A1 floor: %v", err)
	}
	teeOnly := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.key.read.Key.TeeOnly = true
	})
	testInferCheckRefusedBy(t, teeOnly, "engy-glm-5.2-off", string(ComputeModelRuleTeeOnly))
	if err := teeOnly.infer(t, testInferRequest("chutes-qwen3.8-27b-tee-high", "")); err != nil {
		t.Errorf("an AP model under tee_only: %v", err)
	}
}

// A remote model whose provider the network's providers list leaves out is refused, rule provider.
func TestCheckRemoteOffProviderListRefused(t *testing.T) {
	world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.block.network = &ComputeNetworkModels{Floor: ComputeLabelNone, Providers: []string{"tinfoil"}}
	})
	testInferCheckRefusedBy(t, world, "chutes-qwen3.8-27b-tee-high", string(ComputeModelRuleProvider))
	if err := world.infer(t, testInferRequest("tinfoil-gpt-oss-120b-low", "")); err != nil {
		t.Errorf("a listed provider: %v", err)
	}
}

// A remote model no glob of the person's allow matches is refused, rule allow, the name matched being the canonical
// name the call runs, the alias resolved first.
func TestCheckRemoteOffAllowRefused(t *testing.T) {
	world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.key.read.Key.Allow = []string{"local-*", "chutes-*-high"}
	})
	testInferCheckRefusedBy(t, world, "chutes-qwen3.8-27b-tee-low", string(ComputeModelRuleAllow))
	testInferCheckRefusedBy(t, world, "tinfoil-gpt-oss-120b-high", string(ComputeModelRuleAllow))
	request := testInferRequest("chutes-qwen3.8-27b-tee", "max")
	if err := world.infer(t, request); err != nil {
		t.Errorf("an alias resolving to an allowed name: %v", err)
	}
}

// A remote model the newest verified policy does not cover is unusable, rule policy, whatever the catalog lists, and so
// is every remote model while no policy is current; the policy's label is the one checked, never the catalog's.
func TestCheckRemoteUncoveredByPolicyRefused(t *testing.T) {
	world := newTestInferCheckWorld(t, nil)
	testInferCheckRefusedBy(t, world, "chutes-kimi-k3-tee-high", InferRefusedRulePolicy)
	none := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.policy.policyErr = ErrComputePolicyNotCurrent
	})
	testInferCheckRefusedBy(t, none, "tinfoil-gpt-oss-120b-high", InferRefusedRulePolicy)

	// the catalog says A1 of Chutes' model, the policy AP: an A1 floor refuses it
	lying := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.block.network = &ComputeNetworkModels{Floor: ComputeLabelA1, Providers: []string{"*"}}
	})
	lying.router.remoteCatalog = &testInferRemoteCatalog{entries: []*InferCatalogEntry{
		testInferRemoteEntry("chutes", "qwen3.8-27b-tee", ComputeLabelA1, InferEffortHigh),
	}}
	testInferCheckRefusedBy(t, lying, "chutes-qwen3.8-27b-tee-high", string(ComputeModelRuleFloor))

	// a TEE provider listed as a direct one is not covered either way
	switched := newTestInferCheckWorld(t, nil)
	switched.router.remoteCatalog = &testInferRemoteCatalog{entries: []*InferCatalogEntry{
		testInferRemoteEntry("chutes", "qwen3.8-27b", ComputeLabelNone, InferEffortHigh),
	}}
	testInferCheckRefusedBy(t, switched, "chutes-qwen3.8-27b-high", InferRefusedRulePolicy)
}

// An A1 provider whose chips the policy's custody registry vouches for reaches an A2 floor, the call carrying the floor
// for the TEE path to hold each instance to; without the registry it does not.
func TestCheckCustodyReachesA2Floor(t *testing.T) {
	world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.block.network = &ComputeNetworkModels{Floor: ComputeLabelA2, Providers: []string{"*"}}
	})
	testInferCheckRefusedBy(t, world, "tinfoil-gpt-oss-120b-high", string(ComputeModelRuleFloor))
	vouched := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.block.network = &ComputeNetworkModels{Floor: ComputeLabelA2, Providers: []string{"*"}}
		world.policy.policy.Custody = []*ComputePolicyCustody{{Provider: "tinfoil", Registry: "registry.example"}}
	})
	if err := vouched.infer(t, testInferRequest("tinfoil-gpt-oss-120b-high", "")); err != nil {
		t.Fatal(err)
	}
	if call := vouched.tee.called()[0]; call.Floor != ComputeLabelA2 || call.Policy == nil {
		t.Errorf("the call's floor %s, policy %v", call.Floor, call.Policy)
	}
}

// A remote model past a device-side budget is refused insufficient_quota, reason budget, naming the budget and period,
// before any path runs (§16.4).
func TestCheckRemotePastDeviceBudgetRefused(t *testing.T) {
	world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.budgets.err = &InferError{Code: InferErrorInsufficientQuota, Reason: InferQuotaReasonBudget, Budget: "agent", Period: "day", Message: "the agent's day budget is spent"}
	})
	err := world.infer(t, testInferRequest("chutes-qwen3.8-27b-tee-high", ""))
	refused := testInferErrorOf(t, err, InferErrorInsufficientQuota)
	if refused.Reason != InferQuotaReasonBudget || refused.Budget != "agent" || refused.Period != "day" || refused.Model != "chutes-qwen3.8-27b-tee-high" {
		t.Errorf("refused as %+v", refused)
	}
	unreadable := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.budgets.err = errors.New("the counters do not read")
	})
	refused = testInferErrorOf(t, unreadable.infer(t, testInferRequest("chutes-qwen3.8-27b-tee-high", "")), InferErrorInsufficientQuota)
	if refused.Reason != InferQuotaReasonBudget {
		t.Errorf("budgets that do not read: %+v", refused)
	}
	if world.dispatched()+unreadable.dispatched() != 0 {
		t.Error("a call past a budget ran")
	}
}

// The policy's remote-work gate lapsed refuses every remote call, rule policy, the gate asked for the call's own
// operation.
func TestCheckPolicyGateLapseRefuses(t *testing.T) {
	world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.policy.remoteErr = &ComputeRemoteLapsedError{Operation: ComputeRemoteModelCallTee, Reason: ComputeRemoteLapseTicketExpired}
	})
	refused := testInferCheckRefusedBy(t, world, "chutes-qwen3.8-27b-tee-high", InferRefusedRulePolicy)
	if !strings.Contains(refused.Message, "lapsed") {
		t.Errorf("refused as %+v", refused)
	}
	testInferCheckRefusedBy(t, world, "engy-glm-5.2-off", InferRefusedRulePolicy)
	if want := []ComputeRemoteOperation{ComputeRemoteModelCallTee, ComputeRemoteModelCallTee, ComputeRemoteModelCallDirect, ComputeRemoteModelCallDirect}; !slices.Equal(world.policy.operations, want) {
		t.Errorf("the gate was asked for %v", world.policy.operations)
	}
}

// Every source not wired refuses every remote call, naming what is missing, and no local one; installers that fail or
// set one source twice leave the checks refusing every remote call.
func TestCheckSourcesUnwiredRefuseRemoteNeverLocal(t *testing.T) {
	clear := []func(sources *InferCheckSources){
		func(sources *InferCheckSources) { sources.Policy = nil },
		func(sources *InferCheckSources) { sources.ModelsKey = nil },
		func(sources *InferCheckSources) { sources.ComputeBlock = nil },
		func(sources *InferCheckSources) { sources.Budgets = nil },
		func(sources *InferCheckSources) { sources.Acknowledgments = nil },
		func(sources *InferCheckSources) { sources.Marks = nil },
	}
	for _, unwire := range clear {
		world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
			unwire(world.sources)
		})
		refused := testInferCheckRefusedBy(t, world, "chutes-qwen3.8-27b-tee-high", InferRefusedRuleSource)
		if !strings.Contains(refused.Message, "does not wire") {
			t.Errorf("refused as %+v", refused)
		}
		if err := world.infer(t, testInferRequest("local-gemma-4-e4b-off", "")); err != nil {
			t.Errorf("a local call with a source unwired: %v", err)
		}
	}

	budgets := &testInferBudgets{}
	twice := []*inferCheckSourcesRegistration{
		{name: "first", install: func(sidecar *Sidecar, sources *InferCheckSources) error {
			sources.Budgets = budgets
			return nil
		}},
		{name: "second", install: func(sidecar *Sidecar, sources *InferCheckSources) error {
			sources.Budgets = &testInferBudgets{}
			return nil
		}},
	}
	if err := installInferCheckSources(nil, &InferCheckSources{}, twice); err == nil || !strings.Contains(err.Error(), "Budgets") {
		t.Errorf("two installers of one source: %v", err)
	}
	failing := []*inferCheckSourcesRegistration{
		{name: "failing", install: func(sidecar *Sidecar, sources *InferCheckSources) error {
			return errors.New("planted")
		}},
	}
	err := installInferCheckSources(nil, &InferCheckSources{}, failing)
	if err == nil {
		t.Fatal("a failing installer passed")
	}
	world := newTestInferCheckWorld(t, nil)
	world.router.checker = newInferSourceChecker(world.settings, world.sources, err)
	testInferCheckRefusedBy(t, world, "chutes-qwen3.8-27b-tee-high", InferRefusedRuleSource)
	if err := world.infer(t, testInferRequest("local-gemma-4-e4b-off", "")); err != nil {
		t.Errorf("a local call with the sources refused: %v", err)
	}
}

// An installer registers once, by name, with an installer.
func TestRegisterInferCheckSourcesRefusesABadRegistration(t *testing.T) {
	registrations := inferCheckSourcesRegistrations
	t.Cleanup(func() {
		inferCheckSourcesRegistrations = registrations
	})
	inferCheckSourcesRegistrations = []*inferCheckSourcesRegistration{}
	install := func(sidecar *Sidecar, sources *InferCheckSources) error {
		return nil
	}
	testInferPanics(t, "an empty name", func() { registerInferCheckSources("", install) })
	testInferPanics(t, "a nil installer", func() { registerInferCheckSources("budgets", nil) })
	registerInferCheckSources("budgets", install)
	testInferPanics(t, "a second registration", func() { registerInferCheckSources("budgets", install) })
}

// The catalog lists each model the static checks refuse unavailable with why, and says why no remote model is offered
// where none stays usable; a model only a call can refuse stays listed.
func TestCheckCatalogListsRefusedModelsUnavailable(t *testing.T) {
	world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.block.network = &ComputeNetworkModels{Floor: ComputeLabelA1, Providers: []string{"*"}}
		world.budgets.err = newInferError(InferErrorInsufficientQuota, "spent")
	})
	catalog, err := world.router.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	unavailable := map[string]string{}
	for _, entry := range catalog.Entries() {
		unavailable[entry.Provider+"-"+entry.Model] = entry.Unavailable
	}
	for model, wantUsable := range map[string]bool{
		"tinfoil-gpt-oss-120b":     true,
		"chutes-qwen3.8-27b-tee":   false,
		"engy-glm-5.2":             false,
		"chutes-kimi-k3-tee":       false,
		"local-gemma-4-e4b":        true,
		"engy-deepseek-v4.1-flash": false,
	} {
		if (unavailable[model] == "") != wantUsable {
			t.Errorf("%s listed %q", model, unavailable[model])
		}
	}
	unwired := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.sources.Marks = nil
	})
	catalog, err = unwired.router.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(catalog.RemoteUnavailable(), "run marks") {
		t.Errorf("why no remote model: %q", catalog.RemoteUnavailable())
	}
}
