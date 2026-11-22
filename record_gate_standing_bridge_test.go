//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http && !ios_extension

// The it bridge case's finding at §16.6's stock gate (approval-gate-standing-exposures; server's sidecare2e it bridge
// tests, whose worldDeviceGate stood in for a person): bridge_expose through DaemonBridges over the real BridgeFiler,
// with the real gate installed and the filer's AclEngine as its standing grants, as ur daemon composes them
// (cli/bridge_filing_config.go). A route and a map a standing grant covers file their rules with no approval and no
// request for a person, where before the gate held every exposure for a decision since AclEngine.ActiveGrant reads no
// exposure; asked again, after a restart too, they file nothing more; a tainted run still asks a person (TS1). Under a
// document the gate holds an exposure to its standing route and dial rules: inside them nothing is asked, outside them
// a request is filed. Each a top-level test.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A document whose standing rules cover part of what the tests expose: a route of 10.40.0.0/16 through any advertiser
// that names it, and a dial of TCP 8000 to 8010 on a member's own devices, which names the filing host.
const testStandingExposurePolicy = `{
  "grants": [
    { "src": ["autogroup:member"], "dst": ["ip:10.40.0.0/16"], "allow": ["route"] },
    { "src": ["autogroup:member"], "dst": ["autogroup:self"], "allow": ["dial"], "ip": ["tcp:8000-8010"] },
  ],
}`

// A filing reply that must have passed on a standing grant: a rule id, no approval spent and none waited for. Answers
// the rule the ledger holds under it, which must be this host's, active, filed with no approval.
func (self *testBridgeEffectWorld) standingFiling(name string, reply *DaemonBridgeFilingReply, err error) *BridgeLedgerRule {
	self.t.Helper()
	if err != nil {
		self.t.Fatalf("%s: %v", name, err)
	}
	if reply.ApprovalPendingId != nil || reply.ApprovalId != nil || reply.RuleId == "" {
		self.t.Fatalf("%s did not pass on a standing grant: %+v", name, reply)
	}
	ruleId, err := hex.DecodeString(reply.RuleId)
	if err != nil {
		self.t.Fatal(err)
	}
	rule := self.ledger().Rule(ruleId)
	if rule == nil || !rule.Active() || !rule.Standing || rule.Owner != self.hostId || rule.ApprovalId != (Id{}) {
		self.t.Fatalf("%s's rule: %+v", name, rule)
	}
	return rule
}

// Whether the requester's approval state holds nothing: no approval file, no request in the approval family's log.
func (self *testBridgeEffectWorld) nothingAsked() bool {
	self.t.Helper()
	approvalIds, err := self.ledgerRows.approvalIds()
	if err != nil {
		self.t.Fatal(err)
	}
	return len(approvalIds) == 0 && self.approvals.filedCount() == 0
}

// With no document an untagged owner's rules stand (owner decision 120): an agent's route passes the stock gate with
// nothing asked and lands as a standing rule, its route entry opened with no approval; the call again answers that rule
// and posts nothing; the host's first map files its address and then the map, both with no approval; after a restart
// both calls again answer their rules and post nothing; and once the run is tainted an exposure files a tainted request
// and posts nothing (TS1). The restart comes after both filings since the world's filer draws its random rule ids from
// one seed at every open, where a daemon's draws from crypto/rand.
func TestStockGatePassesAStandingExposureWithNothingAsked(t *testing.T) {
	world := newTestBridgeEffectWorld(t)
	world.grants = world.engine
	world.open()

	params := &DaemonBridgeExposeParams{Prefixes: []string{"192.168.7.0/24"}}
	filed, err := world.expose(params)
	rule := world.standingFiling("the route", filed, err)
	if rule.Route == nil || len(rule.Route.GetPrefixes()) != 1 || rule.Route.GetApproval() != nil {
		t.Fatalf("the route's body: %+v", rule.Route)
	}
	if posted := world.api.postedTypes(t); len(posted) != 1 || posted[0] != bridge.SignedType_SIGNED_BRIDGE_ROUTE {
		t.Fatalf("posted %v", posted)
	}
	routes := world.records.routes(t)
	if len(routes) != 1 {
		t.Fatalf("%d route entries", len(routes))
	}
	if body := routes[0].Body.(*protocol.RouteBody); body.GetEvent() != bridgeRouteRecordOpened || !bytes.Equal(body.GetRuleId(), rule.RuleId) ||
		len(body.GetApprovalId()) != 0 {
		t.Fatalf("the route entry: %v", body)
	}
	if !world.nothingAsked() {
		t.Fatal("a standing route asked a person")
	}

	again, err := world.expose(params)
	if err != nil || again.RuleId != filed.RuleId || again.ApprovalPendingId != nil || world.api.postCount() != 1 {
		t.Fatalf("the same route again: %+v %v, %d posts", again, err, world.api.postCount())
	}

	mapParams := &DaemonBridgeExposeParams{Port: 8443, TargetPort: 443, Target: "192.168.9.20"}
	mapped, err := world.expose(mapParams)
	mapRule := world.standingFiling("the first map", mapped, err)
	if !mapped.AddressFiled || mapRule.Map == nil || mapRule.Map.GetTargetPort() != 443 || mapRule.Map.GetApproval() != nil {
		t.Fatalf("the first map: %+v, %+v", mapped, mapRule.Map)
	}
	posted := world.api.postedTypes(t)
	if len(posted) != 3 || posted[1] != bridge.SignedType_SIGNED_BRIDGE_ADDRESS || posted[2] != bridge.SignedType_SIGNED_BRIDGE_MAP {
		t.Fatalf("posted %v", posted)
	}
	if !world.nothingAsked() {
		t.Fatal("a standing map asked a person")
	}

	world.open()
	for _, c := range []struct {
		params *DaemonBridgeExposeParams
		ruleId string
	}{{params: params, ruleId: filed.RuleId}, {params: mapParams, ruleId: mapped.RuleId}} {
		restarted, err := world.expose(c.params)
		if err != nil || restarted.RuleId != c.ruleId || restarted.AddressFiled || world.api.postCount() != 3 {
			t.Fatalf("an exposure again after a restart: %+v %v, %d posts", restarted, err, world.api.postCount())
		}
	}

	if err := world.runs.Taint(t.Context(), world.runId, RunTaintWebTool); err != nil {
		t.Fatal(err)
	}
	request := world.pendingRequest(world.expose(&DaemonBridgeExposeParams{Prefixes: []string{"192.168.8.0/24"}}))
	if !request.Request.GetTainted() || world.api.postCount() != 3 || world.approvals.filedCount() != 1 {
		t.Fatalf("the tainted run's exposure: %v, %d posts, %d requests", request.Request, world.api.postCount(), world.approvals.filedCount())
	}
}

// Under a document the stock gate passes what its standing rules cover and asks a person for the rest: a route inside
// the route rule's prefix lands standing, naming that rule; a route outside it and an exit file requests; the host's
// first map on a port the dial rule covers lands standing after its address, and maps on a port outside it or of
// another protocol file requests. Nothing is posted for what waits.
func TestStockGateHoldsAnExposureToTheDocumentsStandingRules(t *testing.T) {
	world := newTestBridgeEffectWorld(t)
	policy := testBridgeCompilePolicy(t, world.net.log.State(), world.net.networkId, testStandingExposurePolicy, nil)
	world.net.withAclRows(func(rows *protocol.AclRows) {
		rows.HasDocument = true
		rows.Rules = append(rows.Rules, policy.rows.GetRules()...)
		slices.SortFunc(rows.Rules, func(a *protocol.AclRule, b *protocol.AclRule) int { return bytes.Compare(a.GetRuleId(), b.GetRuleId()) })
	})
	world.heads.reader = newTestConfigHeadReader(world.net)
	acl, err := world.net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	if err := world.engine.Install(acl, policy.local); err != nil {
		t.Fatal(err)
	}
	world.grants = world.engine
	world.aclLocal = func() *AclLocalPolicy { return policy.local }
	world.open()

	inside, err := world.expose(&DaemonBridgeExposeParams{Prefixes: []string{"10.40.7.0/24"}})
	rule := world.standingFiling("a route inside the rule", inside, err)
	if len(rule.RouteRuleIds) != 1 || !bytes.Equal(rule.RouteRuleIds[0], policy.grantId(0).Bytes()) {
		t.Fatalf("the standing route names rules %x, the route rule %x", rule.RouteRuleIds, policy.grantId(0).Bytes())
	}
	mapped, err := world.expose(&DaemonBridgeExposeParams{Port: 8005})
	if mapRule := world.standingFiling("a map the dial rule covers", mapped, err); !mapped.AddressFiled || mapRule.Map == nil {
		t.Fatalf("the map: %+v", mapped)
	}
	posts := world.api.postCount()
	if posts != 3 || !world.nothingAsked() {
		t.Fatalf("%d posts, asked a person %t", posts, !world.nothingAsked())
	}

	waiting := []struct {
		name   string
		params *DaemonBridgeExposeParams
	}{
		{name: "a route outside the rule", params: &DaemonBridgeExposeParams{Prefixes: []string{"172.16.9.0/24"}}},
		{name: "a route wider than the rule", params: &DaemonBridgeExposeParams{Prefixes: []string{"10.0.0.0/8"}}},
		{name: "an exit", params: &DaemonBridgeExposeParams{Exit: true}},
		{name: "a map on a port outside the rule", params: &DaemonBridgeExposeParams{Port: 9000}},
		{name: "a map of another protocol", params: &DaemonBridgeExposeParams{Port: 8006, Protocol: "udp"}},
	}
	for _, c := range waiting {
		request := world.pendingRequest(world.expose(c.params))
		if SidecarActionKind(request.Action.Action.GetKind()) != SidecarActionExpose || Id(request.Request.GetRequesterSidecarId()) != world.hostId {
			t.Errorf("%s: the request %v", c.name, request.Request)
		}
	}
	if world.api.postCount() != posts || world.approvals.filedCount() != len(waiting) {
		t.Errorf("%d posts after %d, %d requests for %d waiting exposures", world.api.postCount(), posts, world.approvals.filedCount(), len(waiting))
	}
}
