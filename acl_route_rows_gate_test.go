//go:build !sidecar_http && !ios_extension

// QD-764 at the contract gate and in AclEngine: a no-via route rule's reach is exactly its advertisers, an
// autogroup:internet rule that names a via is refused through any other at both, and a legacy client is reached by no
// route rule's via (D-ACL-5).

package sidecar

import (
	"net/netip"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A contract gate over one network whose state is state.
func aclRouteRowsTestGate(t *testing.T, state *AclState) (*AclContractGate, func(sidecarId Id) AclContractEnd) {
	t.Helper()
	networkId := NewId()
	states, heads := newAclContractTestStates(), &aclContractTestHeads{}
	heads.set(map[Id]uint64{networkId: 1}, nil)
	states.install(networkId, state)
	gate, _, _ := newAclContractTestGate(t, states, heads)
	end := func(sidecarId Id) AclContractEnd {
		return AclContractEnd{Known: true, NetworkId: networkId, SubjectClientId: NewId(), SidecarId: sidecarId, SidecarHeld: true}
	}
	return gate, end
}

// Whether the gate allows a data contract from a to b by reach, as a route's flows need.
func aclRouteRowsTestReaches(gate *AclContractGate, a AclContractEnd, b AclContractEnd) bool {
	verdict := aclContractDecide(gate, a, b, false)
	return verdict.Outcome == AclContractAllow && verdict.Class == AclContractClassData && verdict.Reason == AclContractReasonReach
}

// An engine of the source's with a state and its local policy installed.
func aclRouteRowsTestEngine(t *testing.T, sourceId Id, world *aclCompileWorld) *AclEngine {
	t.Helper()
	local, err := CompileAclLocal(world.input())
	if err != nil {
		t.Fatal(err)
	}
	engine := NewAclEngine(sourceId, nil, nil, nil)
	if err := engine.Install(world.state(t), local); err != nil {
		t.Fatal(err)
	}
	return engine
}

// The question's rule at the gate and in AclEngine: before an approved route names it nothing reaches through either
// sidecar, and then the advertiser alone, the engine holding the route to the rule's 10.0.0.0/8.
func TestANoViaRouteRuleReachesItsAdvertisersAtTheGateAndTheEngine(t *testing.T) {
	world := newAclCompileWorld("no via gate")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	dana := world.member("dana@acme.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	laptop := world.device("dana laptop", dana)
	router := world.device("router", owner)
	nas := world.device("nas", owner)
	world.group("eng")
	world.setPolicy(t, `{
  "groups": { "group:eng": ["dana@acme.example"] },
  "grants": [ { "src": ["group:eng"], "dst": ["ip:10.0.0.0/8"], "allow": ["route"] } ],
}`)
	ruleId := world.documentRuleId(t, "grant", 0)
	inside, outside := netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("192.0.2.9")

	gate, end := aclRouteRowsTestGate(t, world.state(t))
	engine := aclRouteRowsTestEngine(t, laptop, world)
	for _, via := range []Id{router, nas} {
		if aclRouteRowsTestReaches(gate, end(laptop), end(via)) {
			t.Errorf("the gate let the laptop reach %v before any route", via)
		}
		if decision := engine.AllowRoute(AclSidecarSubject(laptop), inside, aclIpProtocolTcp, 22, AclSidecarSubject(via), aclTestNow); decision.Allowed {
			t.Errorf("the engine routed through %v before any route: %+v", via, decision)
		}
	}

	world.ledgerRoute("approved", router, true, ruleId)
	gate, end = aclRouteRowsTestGate(t, world.state(t))
	engine = aclRouteRowsTestEngine(t, laptop, world)
	if !aclRouteRowsTestReaches(gate, end(laptop), end(router)) {
		t.Error("the gate refused the laptop its advertiser")
	}
	if aclRouteRowsTestReaches(gate, end(laptop), end(nas)) {
		t.Error("the gate let the laptop reach a sidecar no route names")
	}
	if decision := engine.AllowRoute(AclSidecarSubject(laptop), inside, aclIpProtocolTcp, 22, AclSidecarSubject(router), aclTestNow); !decision.Allowed {
		t.Errorf("the engine refused the advertiser: %s", decision.Reason)
	}
	if decision := engine.AllowRoute(AclSidecarSubject(laptop), outside, aclIpProtocolTcp, 22, AclSidecarSubject(router), aclTestNow); decision.Allowed {
		t.Errorf("the engine routed outside the rule's prefix: %+v", decision)
	}
	if decision := engine.AllowRoute(AclSidecarSubject(laptop), inside, aclIpProtocolTcp, 22, AclSidecarSubject(nas), aclTestNow); decision.Allowed {
		t.Errorf("the engine routed through a sidecar no route names: %+v", decision)
	}
}

// An internet rule with via tag:exit-us is refused through tag:exit-eu at the gate and in AclEngine, even once the eu
// exit files an exit route naming the rule; through its via the engine takes a public address and no private one, the
// rule holding no prefix.
func TestAnInternetRuleWithAViaIsRefusedThroughAnotherAtTheGateAndTheEngine(t *testing.T) {
	world := newAclInternetWorld(t)
	public, private := netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("10.1.2.3")
	check := func() {
		t.Helper()
		gate, end := aclRouteRowsTestGate(t, world.world.state(t))
		engine := aclRouteRowsTestEngine(t, world.laptop, world.world)
		if !aclRouteRowsTestReaches(gate, end(world.laptop), end(world.exitUs)) {
			t.Error("the gate refused the rule's via")
		}
		if aclRouteRowsTestReaches(gate, end(world.laptop), end(world.exitEu)) {
			t.Error("the gate let the rule through another exit")
		}
		source := AclSidecarSubject(world.laptop)
		if decision := engine.AllowRoute(source, public, aclIpProtocolTcp, 443, AclSidecarSubject(world.exitUs), aclTestNow); !decision.Allowed {
			t.Errorf("the engine refused its via: %s", decision.Reason)
		}
		if decision := engine.AllowRoute(source, public, aclIpProtocolTcp, 443, AclSidecarSubject(world.exitEu), aclTestNow); decision.Allowed {
			t.Errorf("the engine took another exit: %+v", decision)
		}
		if decision := engine.AllowRoute(source, private, aclIpProtocolTcp, 443, AclSidecarSubject(world.exitUs), aclTestNow); decision.Allowed {
			t.Errorf("the engine took a private address through an internet rule: %+v", decision)
		}
	}
	check()
	world.world.ledgerRoute("eu exit", world.exitEu, true, world.ruleId)
	check()
}

// D-ACL-5 at the gate: a legacy client is reached only by a dial rule with no ports and no via, so neither a route rule
// whose via names it nor a dial rule that also names a via reaches it, while an unrestricted dial does.
func TestALegacyClientIsReachedByNoVia(t *testing.T) {
	net := newAclContractTestNet()
	a := net.fixture.device(net.owner)
	legacy, viaLegacy, dialWithVia := NewId(), NewId(), NewId()
	net.fixture.rule([]Id{net.sidecarAtom(a)}, []*protocol.AclTarget{{ClientId: legacy.Bytes()}}, protocol.AclAction_ACL_ACTION_DIAL)
	route := net.fixture.rule([]Id{net.sidecarAtom(a)}, nil, protocol.AclAction_ACL_ACTION_ROUTE)
	route.Via = []*protocol.AclTarget{{ClientId: viaLegacy.Bytes()}}
	both := net.fixture.rule([]Id{net.sidecarAtom(a)}, []*protocol.AclTarget{{ClientId: dialWithVia.Bytes()}},
		protocol.AclAction_ACL_ACTION_DIAL, protocol.AclAction_ACL_ACTION_ROUTE)
	both.Via = []*protocol.AclTarget{aclAtomTarget(net.sidecarAtom(a))}
	gate := net.gate(t)
	for _, c := range []struct {
		name    string
		client  Id
		reached bool
	}{
		{name: "an unrestricted dial", client: legacy, reached: true},
		{name: "a route's via", client: viaLegacy, reached: false},
		{name: "a dial beside a via", client: dialWithVia, reached: false},
	} {
		verdict := aclContractDecide(gate, net.sidecarEnd(a), net.clientEnd(c.client, Id{}, false), false)
		if (verdict.Outcome == AclContractAllow && verdict.Reason == AclContractReasonReach) != c.reached {
			t.Errorf("%s: %+v", c.name, verdict)
		}
		// an enforcing client is reached by the same rules wherever their reach names it
		enforcing := aclContractDecide(gate, net.sidecarEnd(a), net.clientEnd(c.client, Id{}, true), false)
		if enforcing.Outcome != AclContractAllow || enforcing.Reason != AclContractReasonReach {
			t.Errorf("%s, enforcing: %+v", c.name, enforcing)
		}
	}
}
