//go:build !ios_extension

// §16.6's step 2 for a bridge exposure (record_gate_standing.go) on the approval world (record_approval_state_test.go),
// its gate built again with a standing-grants source that judges an exposure's rule, each a top-level test: an exposure
// whose effect names a rule the source covers passes under an empty key with nothing filed, where before the gate held
// it for a person since ActiveGrant reads no exposure; a tainted run asks a person (TS1) while the same exposure from no
// run passes; a rule its action does not describe stands for nothing and is never asked about; and a source that judges
// no rule, an effect that names none, no source, and a source that answers no each leave the exposure to a decision.
// The real filer, gate and engine run it in record_gate_standing_bridge_test.go.

package sidecar

import (
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Standing grants that cover no action by its grant fields and an exposure's rule where covers says, keeping each rule
// asked about.
type testStandingRules struct {
	stateLock  sync.Mutex
	covers     bool
	askedRules []*BridgeLedgerRule
}

func (self *testStandingRules) ActiveGrant(action *StoredCanonicalAction, spender Id, now time.Time) bool {
	return false
}

func (self *testStandingRules) StandingRule(rule *BridgeLedgerRule, spender Id, now time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.askedRules = append(self.askedRules, rule)
	return self.covers
}

// The rules asked about so far.
func (self *testStandingRules) asked() []*BridgeLedgerRule {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*BridgeLedgerRule{}, self.askedRules...)
}

// The world's effect, naming rule as the one it files under an empty key.
type testStandingRuleEffect struct {
	*testGateEffect
	rule *BridgeLedgerRule
}

func (self *testStandingRuleEffect) StandingRule() *BridgeLedgerRule {
	return self.rule
}

// The world's gate built again over its args, inbox and router, with grants as its standing grants.
func (self *testApprovalWorld) gateWithGrants(grants ApprovalStandingGrants) {
	self.t.Helper()
	gate, err := NewApprovalGate(self.args, self.inbox, self.router, &ApprovalGateArgs{
		Grants: grants,
		Lookups: func(kind SidecarActionKind) SidecarEffectLookup {
			return self.lookups[kind]
		},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.gate = gate
}

// A route of the laptop's subnet as the filer asks for it (bridgeRouteAction), and the rule it files with no approval.
func (self *testApprovalWorld) routeExposure(prefix *bridge.BridgeIpv4Prefix) (*StoredCanonicalAction, *BridgeLedgerRule) {
	self.t.Helper()
	route := &bridge.BridgeRouteBody{Prefixes: []*bridge.BridgeIpv4Prefix{prefix}, Kind: bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET, Weight: 1}
	stored, err := bridgeRouteAction(self.spend.laptop, route)
	if err != nil {
		self.t.Fatal(err)
	}
	return stored, &BridgeLedgerRule{SignedType: bridge.SignedType_SIGNED_BRIDGE_ROUTE, Owner: self.spend.laptop, Route: route, Standing: true}
}

// A map of one TCP port of the laptop's address onto its loopback, ending at expiresMs, as the filer asks for it
// (bridgeMapAction), and the rule it files with no approval.
func (self *testApprovalWorld) mapExposure(port uint32, expiresMs int64) (*StoredCanonicalAction, *BridgeLedgerRule) {
	self.t.Helper()
	plan := &bridgeMapPlan{
		protocol: bridgeProtocolTcp, ports: []*bridge.BridgePortRange{{First: port, Last: port}}, target: []byte{127, 0, 0, 1},
		targetPort: port, expiresMs: expiresMs,
	}
	stored, err := bridgeMapAction(self.spend.laptop, plan)
	if err != nil {
		self.t.Fatal(err)
	}
	return stored, &BridgeLedgerRule{
		SignedType: bridge.SignedType_SIGNED_BRIDGE_MAP, Owner: self.spend.laptop, Map: plan.body(0x64500007), Expires: expiresMs, Standing: true,
	}
}

// stored as the O tool hands it to Authorize in the world's run, its effect the world's naming rule.
func (self *testApprovalWorld) exposureAction(stored *StoredCanonicalAction, rule *BridgeLedgerRule) *SidecarAction {
	action := self.action(stored)
	action.Effect = &testStandingRuleEffect{testGateEffect: self.effect, rule: rule}
	return action
}

// Whether the ledger and the approval family's log hold nothing: no approval file, no request filed.
func (self *testApprovalWorld) nothingFiled() bool {
	self.t.Helper()
	approvalIds, err := self.ledger.approvalIds()
	if err != nil {
		self.t.Fatal(err)
	}
	return len(approvalIds) == 0 && self.log.filedCount() == 0
}

// The it bridge case's finding (approval-gate-standing-exposures): a route and a map whose rules a standing grant covers
// pass under an empty key, no spend on the effect's context and no ledger row, with no request filed for a person, the
// source asked once about the very rule each effect names.
func TestStandingExposurePassesWithNothingFiled(t *testing.T) {
	world := newTestApprovalWorld(t)
	rules := &testStandingRules{covers: true}
	world.gateWithGrants(rules)
	route, routeRule := world.routeExposure(testBridgePrefix(192, 0, 2, 0, 24))
	mapped, mapRule := world.mapExposure(8443, world.clock.Now().Add(time.Hour).UnixMilli())
	cases := []struct {
		name   string
		stored *StoredCanonicalAction
		rule   *BridgeLedgerRule
	}{
		{name: "a route", stored: route, rule: routeRule},
		{name: "a map", stored: mapped, rule: mapRule},
	}
	for _, c := range cases {
		action := world.exposureAction(c.stored, c.rule)
		testGateExpectOutcome(t, c.name, world.gate.Authorize(t.Context(), action, nil), action, ApprovalOutcomeDone)
		if len(action.Outcome.effectKey) != 0 {
			t.Errorf("%s ran under a use's key", c.name)
		}
	}
	if spend, seen := world.effect.spendSeen(); seen {
		t.Errorf("a standing exposure ran under a spend: %+v", spend)
	}
	if runCount, effectCount := world.effect.counts(); runCount != 2 || effectCount != 2 {
		t.Errorf("%d runs, %d effects for two exposures", runCount, effectCount)
	}
	if !world.nothingFiled() {
		t.Error("a standing exposure filed a request or kept a ledger row")
	}
	if asked := rules.asked(); len(asked) != 2 || asked[0] != routeRule || asked[1] != mapRule {
		t.Errorf("the source was asked about %+v", asked)
	}
}

// TS1: once the run is tainted no standing grant passes an exposure, which files a tainted request for a person, the
// effect not run and the source never asked; the same exposure from no run, a person's typed command, passes.
func TestStandingExposureInATaintedRunAsksAPerson(t *testing.T) {
	world := newTestApprovalWorld(t)
	rules := &testStandingRules{covers: true}
	world.gateWithGrants(rules)
	if err := world.runs.Taint(t.Context(), world.runId, RunTaintWebTool); err != nil {
		t.Fatal(err)
	}
	stored, rule := world.routeExposure(testBridgePrefix(198, 51, 100, 0, 24))
	request := world.pendingRequest(world.gate.Authorize(t.Context(), world.exposureAction(stored, rule), nil))
	if !request.Request.GetTainted() || SidecarActionKind(request.Action.Action.GetKind()) != SidecarActionExpose {
		t.Errorf("the tainted run's request: %v", request.Request)
	}
	if runCount, _ := world.effect.counts(); runCount != 0 || len(rules.asked()) != 0 {
		t.Fatalf("the tainted run ran the effect %d times and asked the source %d times", runCount, len(rules.asked()))
	}
	typed := world.exposureAction(stored, rule)
	typed.RunId, typed.AgentId = nil, nil
	testGateExpectOutcome(t, "a typed command", world.gate.Authorize(t.Context(), typed, nil), typed, ApprovalOutcomeDone)
	if world.log.filedCount() != 1 {
		t.Errorf("%d requests filed", world.log.filedCount())
	}
}

// A rule its action does not describe stands for nothing, as every reader holds a rule to the action its approval names:
// each files a request, the source is never asked and no effect runs. The template is held at step 2 itself.
func TestStandingExposureNeedsTheRuleOfItsAction(t *testing.T) {
	world := newTestApprovalWorld(t)
	rules := &testStandingRules{covers: true}
	world.gateWithGrants(rules)
	notAfterMs := world.clock.Now().Add(time.Hour).UnixMilli()
	route, routeRule := world.routeExposure(testBridgePrefix(192, 0, 2, 0, 24))
	mapped, mapRule := world.mapExposure(8443, notAfterMs)
	// a variant of base, edited
	variant := func(base *BridgeLedgerRule, edit func(rule *BridgeLedgerRule)) *BridgeLedgerRule {
		rule := *base
		if base.Route != nil {
			rule.Route = proto.Clone(base.Route).(*bridge.BridgeRouteBody)
		}
		if base.Map != nil {
			rule.Map = proto.Clone(base.Map).(*bridge.BridgeMapBody)
		}
		edit(&rule)
		return &rule
	}
	otherTarget, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionExpose), TargetSidecarId: world.spend.phone.Bytes(), Cidrs: []string{"192.0.2.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	template, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionExpose), TargetSidecarId: world.spend.laptop.Bytes(), Cidrs: []string{"192.0.2.0/24"}, Scope: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		stored *StoredCanonicalAction
		rule   *BridgeLedgerRule
		// the uses the action asks, 0 for one; a template asks 2 or more
		uses uint32
	}{
		{name: "another owner's", stored: route, rule: variant(routeRule, func(rule *BridgeLedgerRule) { rule.Owner = world.spend.phone })},
		{name: "a prefix outside the action's", stored: route, rule: variant(routeRule, func(rule *BridgeLedgerRule) {
			rule.Route.Prefixes = []*bridge.BridgeIpv4Prefix{testBridgePrefix(198, 51, 100, 0, 24)}
		})},
		{name: "a wider prefix than the action's", stored: route, rule: variant(routeRule, func(rule *BridgeLedgerRule) {
			rule.Route.Prefixes = []*bridge.BridgeIpv4Prefix{testBridgePrefix(192, 0, 0, 0, 16)}
		})},
		{name: "an exit for a subnet's action", stored: route, rule: variant(routeRule, func(rule *BridgeLedgerRule) {
			rule.Route.Prefixes, rule.Route.Kind = nil, bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT
		})},
		{name: "a map for a route's action", stored: route, rule: mapRule},
		{name: "a route for a map's action", stored: mapped, rule: routeRule},
		{name: "a map onto another port", stored: mapped, rule: variant(mapRule, func(rule *BridgeLedgerRule) { rule.Map.TargetPort = 8444 })},
		{name: "a map outliving its action", stored: mapped, rule: variant(mapRule, func(rule *BridgeLedgerRule) { rule.Expires = notAfterMs + 1 })},
		{name: "a rule carrying an approval", stored: route, rule: variant(routeRule, func(rule *BridgeLedgerRule) {
			rule.Route.Approval = &bridge.BridgeApproval{CanonicalAction: route.Bytes}
		})},
		{name: "a rule with no body", stored: route, rule: variant(routeRule, func(rule *BridgeLedgerRule) { rule.Route = nil })},
		{name: "an action for another sidecar", stored: otherTarget, rule: routeRule},
		{name: "a template", stored: template, rule: routeRule, uses: 2},
	}
	for _, c := range cases {
		action := world.exposureAction(c.stored, c.rule)
		action.Uses = c.uses
		err := world.gate.Authorize(t.Context(), action, nil)
		pending := &ApprovalPendingError{}
		if !errors.As(err, &pending) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if runCount, _ := world.effect.counts(); runCount != 0 || len(rules.asked()) != 0 {
		t.Errorf("%d runs, the source asked %d times", runCount, len(rules.asked()))
	}
}

// Only a source that judges rules and an effect that names one pass an exposure: grants that read grant fields alone, an
// effect naming no rule, an effect that is no standing-rule effect and no source each leave it to a decision without
// asking, and a source that answers no is asked once and leaves it too. No effect runs.
func TestStandingExposureNeedsASourceAndAnEffectThatJudgeIt(t *testing.T) {
	world := newTestApprovalWorld(t)
	stored, rule := world.routeExposure(testBridgePrefix(203, 0, 113, 0, 24))
	refusing := &testStandingRules{covers: false}
	judging := &testStandingRules{covers: true}
	plain := world.action(stored)
	cases := []struct {
		name   string
		grants ApprovalStandingGrants
		action *SidecarAction
	}{
		{name: "grants that read grant fields alone", grants: &testStandingGrants{}, action: world.exposureAction(stored, rule)},
		{name: "an effect naming no rule", grants: judging, action: world.exposureAction(stored, nil)},
		{name: "an effect that is no standing-rule effect", grants: judging, action: plain},
		{name: "no source", grants: nil, action: world.exposureAction(stored, rule)},
		{name: "a source that answers no", grants: refusing, action: world.exposureAction(stored, rule)},
	}
	for _, c := range cases {
		world.gateWithGrants(c.grants)
		pending := &ApprovalPendingError{}
		if err := world.gate.Authorize(t.Context(), c.action, nil); !errors.As(err, &pending) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if runCount, _ := world.effect.counts(); runCount != 0 {
		t.Errorf("the effect ran %d times", runCount)
	}
	if len(judging.asked()) != 0 || len(refusing.asked()) != 1 || refusing.asked()[0] != rule {
		t.Errorf("the judging source was asked %d times, the refusing one %+v", len(judging.asked()), refusing.asked())
	}
}
