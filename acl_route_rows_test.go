// QD-764 at the acl side (acl-m2-17-no-via-route-advertisers): a rule's via subjects ride AclRule.via apart from its
// targets, and BridgeRows' route rows name the advertisers a route rule with no via takes as its via subjects. A no-via
// rule reaches nothing before an approved route names it and then exactly its advertisers; an autogroup:internet rule
// that names a via takes no advertiser; the enumerators agree with MayRoute on both; and CompileAcl writes the routes the
// head's ledger holds in force, in one encoding, which testdata/acl/vectors/route_rows.hex holds. Pure, on every leg.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"math/rand/v2"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Adds an approved route's row to the fixture's BridgeRows as a BridgeRoute's filing writes it: its id, its advertiser
// and the rules it serves (QD-764).
func (self *aclTestFixture) routeRow(t testing.TB, routeId []byte, advertiser Id, ruleIds ...[]byte) {
	t.Helper()
	statement := &BridgeLogStatement{SignedType: bridge.SignedType_SIGNED_BRIDGE_ROUTE, RuleId: routeId, Subject: advertiser, RouteRuleIds: ruleIds}
	data, err := bridgeRowsWithRoute(self.rows.Bridge, statement)
	if err != nil {
		t.Fatal(err)
	}
	self.rows.Bridge = data
}

// The route rows rows hold, each as advertiser and rule ids.
func aclTestRouteRows(t testing.TB, rows *protocol.AclRows) []*bridge.BridgeRouteRow {
	t.Helper()
	bridgeRows, err := ParseBridgeRows(rows.GetBridge())
	if err != nil {
		t.Fatal(err)
	}
	return bridgeRows.GetRoutes()
}

// The question's own rule (QD-764): {"src": ["group:eng"], "dst": ["ip:10.0.0.0/8"], "allow": ["route"]} opens nothing
// before an approved route names it, a route filed with no approval that no standing grant covers being none, and then
// exactly its advertisers: at MayRoute, at reach, and in RouteRules and ExitRules, which agree with MayRoute.
func TestANoViaRouteRuleReachesExactlyItsAdvertisers(t *testing.T) {
	world := newAclCompileWorld("no via")
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
	source, address := AclSidecarSubject(laptop), netip.MustParseAddr("10.1.2.3")
	// what the state lets the laptop reach through each of the router and the nas, by every read
	reaches := func(state *AclState) []bool {
		t.Helper()
		reached := []bool{}
		for _, via := range []Id{router, nas} {
			viaSubject := AclSidecarSubject(via)
			mayRoute := state.MayRoute(source, address, viaSubject, aclTestNow).Allowed
			reach := state.Reach(source, viaSubject, aclTestNow).Allowed
			routeRules := state.RouteRules(source, viaSubject, aclTestNow)
			exitRules := state.ExitRules(source, viaSubject, aclTestNow)
			if reach != mayRoute || (0 < len(routeRules)) != mayRoute || (0 < len(exitRules)) != mayRoute {
				t.Fatalf("through %v the reads disagree: MayRoute %t, reach %t, %d route rules, %d exit rules", via, mayRoute, reach, len(routeRules), len(exitRules))
			}
			if mayRoute && (len(routeRules) != 1 || !bytes.Equal(routeRules[0].RuleId, ruleId.Bytes()) || routeRules[0].Internet) {
				t.Fatalf("through %v: %+v", via, routeRules)
			}
			reached = append(reached, mayRoute)
		}
		return reached
	}

	state := world.state(t)
	if rule := state.rules[slices.IndexFunc(state.rules, func(rule aclRule) bool { return Id(rule.row.GetRuleId()) == ruleId })]; rule.viaNamed ||
		len(rule.row.GetTargets()) != 0 || len(rule.row.GetVia()) != 0 {
		t.Fatalf("the rule's row: %v", rule.row)
	}
	if got := reaches(state); !slices.Equal(got, []bool{false, false}) {
		t.Fatalf("before any route: %v", got)
	}
	// filed with no approval, and 192.0.2.0/24 lies outside the rule's prefix, so no standing grant covers it: no
	// approved route, and the fold writes no row for it
	uncovered := world.ledgerRoute("uncovered", router, false, ruleId)
	uncovered.Route.Prefixes = []*bridge.BridgeIpv4Prefix{testBridgePrefix(192, 0, 2, 0, 24)}
	rows := world.compile(t)
	if routes := aclTestRouteRows(t, rows); len(routes) != 0 {
		t.Fatalf("an uncovered route's row: %v", routes)
	}
	if got := reaches(world.state(t)); !slices.Equal(got, []bool{false, false}) {
		t.Fatalf("with an uncovered route: %v", got)
	}

	world.ledgerRoute("approved", router, true, ruleId)
	if got := reaches(world.state(t)); !slices.Equal(got, []bool{true, false}) {
		t.Fatalf("with the router's approved route: %v", got)
	}
	// a standing route the rule covers is in force too, and makes its advertiser a via of the rule
	world.ledgerRoute("standing", nas, false, ruleId)
	if got := reaches(world.state(t)); !slices.Equal(got, []bool{true, true}) {
		t.Fatalf("with the nas's covered route: %v", got)
	}
	// a sidecar outside group:eng reaches nothing through either
	state = world.state(t)
	for _, via := range []Id{router, nas} {
		if decision := state.MayRoute(AclSidecarSubject(router), address, AclSidecarSubject(via), aclTestNow); decision.Allowed {
			t.Errorf("a source outside the rule through %v: %+v", via, decision)
		}
	}
}

// An autogroup:internet rule that names a via takes public addresses through it alone (QD-764): through another exit it
// is refused at MayRoute and reach, an exit route the other exit files naming the rule adds it no advertiser, since a
// rule that names a via takes none, and rows show the via apart from the targets.
func TestAnInternetRuleWithAViaHoldsToIt(t *testing.T) {
	world := newAclInternetWorld(t)
	state := world.world.state(t)
	public := netip.MustParseAddr("198.51.100.9")
	row := state.rules[slices.IndexFunc(state.rules, func(rule aclRule) bool { return Id(rule.row.GetRuleId()) == world.ruleId })].row
	if len(row.GetTargets()) != 1 || !bytes.Equal(row.GetTargets()[0].GetAtom(), AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_INTERNET).Bytes()) ||
		len(row.GetVia()) != 1 || !bytes.Equal(row.GetVia()[0].GetAtom(), world.world.tag("exit-us").Bytes()) {
		t.Fatalf("the internet rule's row: %v", row)
	}
	check := func(state *AclState) {
		t.Helper()
		source := AclSidecarSubject(world.laptop)
		if decision := state.MayRoute(source, public, AclSidecarSubject(world.exitUs), aclTestNow); !decision.Allowed {
			t.Errorf("through its via: %s", decision.Reason)
		}
		if decision := state.Reach(source, AclSidecarSubject(world.exitUs), aclTestNow); !decision.Allowed {
			t.Errorf("reach to its via: %s", decision.Reason)
		}
		if decision := state.MayRoute(source, public, AclSidecarSubject(world.exitEu), aclTestNow); decision.Allowed {
			t.Errorf("through another exit: %+v", decision)
		}
		if decision := state.Reach(source, AclSidecarSubject(world.exitEu), aclTestNow); decision.Allowed {
			t.Errorf("reach to another exit: %+v", decision)
		}
		if exits := state.ExitRules(source, AclSidecarSubject(world.exitEu), aclTestNow); len(exits) != 0 {
			t.Errorf("exit rules through another exit: %+v", exits)
		}
		if exits := state.ExitRules(source, AclSidecarSubject(world.exitUs), aclTestNow); len(exits) != 1 || !exits[0].Internet {
			t.Errorf("exit rules through its via: %+v", exits)
		}
	}
	check(state)
	world.world.ledgerRoute("eu exit", world.exitEu, true, world.ruleId)
	rows := world.world.compile(t)
	if routes := aclTestRouteRows(t, rows); len(routes) != 1 || Id(routes[0].GetAdvertiser()) != world.exitEu {
		t.Fatalf("the eu exit's row: %v", routes)
	}
	check(world.world.state(t))
}

// A world of a member's laptop and two exits tagged exit-us and exit-eu, whose one rule takes the internet through
// tag:exit-us.
type aclInternetWorld struct {
	world  *aclCompileWorld
	laptop Id
	exitUs Id
	exitEu Id
	ruleId Id
}

func newAclInternetWorld(t testing.TB) *aclInternetWorld {
	world := newAclCompileWorld("internet via")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	self := &aclInternetWorld{world: world}
	self.laptop = world.device("laptop", owner)
	self.exitUs = world.agent("exit us", owner, "exit-us")
	self.exitEu = world.agent("exit eu", owner, "exit-eu")
	world.setPolicy(t, `{
  "tagOwners": { "tag:exit-us": ["autogroup:admin"], "tag:exit-eu": ["autogroup:admin"] },
  "grants": [ { "src": ["autogroup:member"], "dst": ["autogroup:internet"], "via": ["tag:exit-us"], "allow": ["route"] } ],
}`)
	self.ruleId = world.documentRuleId(t, "grant", 0)
	return self
}

// NewAclState refuses a via no writer writes: two kinds, a kind that names no subject, and autogroup:internet, a
// destination and no via; and reads one of no kind it knows, a later format's, as a via that matches nothing, so the
// rule takes no advertiser.
func TestAclStateReadsAViaAsASubjectOnly(t *testing.T) {
	for name, via := range map[string]*protocol.AclTarget{
		"two kinds":          {Atom: NewId().Bytes(), SidecarId: NewId().Bytes()},
		"a repo":             {RepoId: NewId().Bytes()},
		"a socket":           {SocketPrefix: true},
		"a public name":      {PublicName: "tls/443/app"},
		"mail":               {MailSend: true},
		"autogroup:internet": aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_INTERNET),
		"a short sidecar id": {SidecarId: NewId().Bytes()[:8]},
	} {
		fixture := newAclTestFixture()
		rule := fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), nil, protocol.AclAction_ACL_ACTION_ROUTE)
		rule.Via = []*protocol.AclTarget{via}
		if _, err := NewAclState(fixture.rows, fixture.view); err == nil {
			t.Errorf("%s: built", name)
		}
	}

	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	source, advertiser := fixture.device(owner), fixture.device(owner)
	rule := fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), nil, protocol.AclAction_ACL_ACTION_ROUTE)
	rule.Via = []*protocol.AclTarget{{}}
	fixture.routeRow(t, testBridgeRuleId("route"), advertiser, rule.GetRuleId())
	state := fixture.state(t)
	if decision := state.MayRoute(AclSidecarSubject(source), netip.MustParseAddr("10.0.0.1"), AclSidecarSubject(advertiser), aclTestNow); decision.Allowed {
		t.Errorf("a via of no kind took an advertiser: %+v", decision)
	}
	// bytes no verifier folded add no advertiser, the closed direction, and the state still builds
	fixture.rows.Bridge = []byte{0xff}
	rule.Via = nil
	state = fixture.state(t)
	if decision := state.MayRoute(AclSidecarSubject(source), netip.MustParseAddr("10.0.0.1"), AclSidecarSubject(advertiser), aclTestNow); decision.Allowed {
		t.Errorf("malformed bridge rows gave an advertiser: %+v", decision)
	}
}

// A dial reaches what a rule's targets name and a route what its via names: a rule allowing both, its destinations and
// its via apart (QD-764), dials only its destinations and routes only through its via.
func TestADialAndRouteRuleKeepsItsDestinationsAndViaApart(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	serverTag, routerTag := fixture.tag(owner), fixture.tag(owner)
	source := fixture.device(owner)
	server := fixture.agent(owner, serverTag)
	router := fixture.agent(owner, routerTag)
	rule := fixture.rule([]Id{fixture.sidecarAtom(source)}, []*protocol.AclTarget{aclAtomTarget(serverTag)},
		protocol.AclAction_ACL_ACTION_DIAL, protocol.AclAction_ACL_ACTION_ROUTE)
	rule.Via = []*protocol.AclTarget{aclAtomTarget(routerTag)}
	state := fixture.state(t)
	address := netip.MustParseAddr("10.0.0.1")
	if !state.MayDial(AclSidecarSubject(source), AclSidecarSubject(server), aclTestNow).Allowed {
		t.Error("the destination refused a dial")
	}
	if state.MayDial(AclSidecarSubject(source), AclSidecarSubject(router), aclTestNow).Allowed {
		t.Error("the via dialled")
	}
	if !state.MayRoute(AclSidecarSubject(source), address, AclSidecarSubject(router), aclTestNow).Allowed {
		t.Error("the via refused a route")
	}
	if state.MayRoute(AclSidecarSubject(source), address, AclSidecarSubject(server), aclTestNow).Allowed {
		t.Error("the destination routed")
	}
	for _, destination := range []Id{server, router} {
		if !state.Reach(AclSidecarSubject(source), AclSidecarSubject(destination), aclTestNow).Allowed {
			t.Errorf("reach to %v refused", destination)
		}
	}
}

// The fold's rows (CompileAcl at a base, QD-764): the log's egress modes at the fold, its id-level route rows dropped,
// and a row for each route the head's ledger holds in force, filed under a decision or covered by a standing grant of
// the head's own policy: a no-via rule's covering prefix, a via rule's advertiser among its via. A route outside its
// rule's prefix, one by an advertiser the rule's via does not hold, a withdrawn one and a void one have none. The bytes
// are one encoding whatever order the ledger hands its routes in, and testdata/acl/vectors/route_rows.hex holds them.
// SIDECAR_REGENERATE_ACL_ROUTE_ROWS=1 rewrites it.
func TestCompileAclWritesTheRoutesInForceInOneEncoding(t *testing.T) {
	world := newAclCompileWorld("route rows")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	laptop := world.device("laptop", owner)
	router := world.agent("router", owner, "router")
	world.setPolicy(t, `{
  "tagOwners": { "tag:router": ["autogroup:admin"] },
  "grants": [
    { "src": ["autogroup:member"], "dst": ["ip:10.0.0.0/8"], "allow": ["route"] },
    { "src": ["autogroup:member"], "dst": ["ip:192.168.0.0/16"], "via": ["tag:router"], "allow": ["route"] },
  ],
}`)
	noVia, viaRouter := world.documentRuleId(t, "grant", 0), world.documentRuleId(t, "grant", 1)
	// the log at the fold: the laptop in exits, and an id-level row of a route the ledger holds void
	logRows, err := bridgeRowsWithEgress(nil, laptop, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS)
	if err != nil {
		t.Fatal(err)
	}
	logRows, err = bridgeRowsWithRoute(logRows, &BridgeLogStatement{SignedType: bridge.SignedType_SIGNED_BRIDGE_ROUTE,
		RuleId: testBridgeRuleId("void at the fold"), Subject: laptop, RouteRuleIds: [][]byte{noVia.Bytes()}})
	if err != nil {
		t.Fatal(err)
	}
	world.statements.Bridge = logRows

	approved := world.ledgerRoute("approved", router, true, noVia, viaRouter)
	covered := world.ledgerRoute("covered", laptop, false, noVia)
	covered.Route.Prefixes = []*bridge.BridgeIpv4Prefix{testBridgePrefix(10, 1, 0, 0, 16)}
	outside := world.ledgerRoute("outside its prefix", laptop, false, noVia)
	outside.Route.Prefixes = []*bridge.BridgeIpv4Prefix{testBridgePrefix(172, 16, 0, 0, 12)}
	viaHeld := world.ledgerRoute("its via's", router, false, viaRouter)
	viaHeld.Route.Prefixes = []*bridge.BridgeIpv4Prefix{testBridgePrefix(192, 168, 7, 0, 24)}
	viaNotHeld := world.ledgerRoute("not its via's", laptop, false, viaRouter)
	viaNotHeld.Route.Prefixes = []*bridge.BridgeIpv4Prefix{testBridgePrefix(192, 168, 8, 0, 24)}
	withdrawn := world.ledgerRoute("withdrawn", router, true, noVia)
	withdrawn.Withdrawn = &BridgeLedgerWithdrawal{At: 9, TimeMs: aclTestNow.UnixMilli(), Mode: bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET, Signer: router}
	void := world.ledgerRoute("void", router, true, noVia)
	void.Void, void.Route = true, nil

	rows := world.compile(t)
	bridgeRows, err := ParseBridgeRows(rows.GetBridge())
	if err != nil {
		t.Fatal(err)
	}
	if len(bridgeRows.GetEgress()) != 1 || Id(bridgeRows.GetEgress()[0].GetSubject()) != laptop {
		t.Fatalf("the egress modes at the fold: %v", bridgeRows.GetEgress())
	}
	want := []*BridgeLedgerRule{approved, covered, viaHeld}
	slices.SortFunc(want, func(a *BridgeLedgerRule, b *BridgeLedgerRule) int { return bytes.Compare(a.RuleId, b.RuleId) })
	if len(bridgeRows.GetRoutes()) != len(want) {
		t.Fatalf("%d routes in force, want %d: %v", len(bridgeRows.GetRoutes()), len(want), bridgeRows.GetRoutes())
	}
	for i, rule := range want {
		row := bridgeRows.GetRoutes()[i]
		wantRuleIds := slices.Clone(rule.RouteRuleIds)
		slices.SortFunc(wantRuleIds, bytes.Compare)
		if !bytes.Equal(row.GetRouteId(), rule.RuleId) || Id(row.GetAdvertiser()) != rule.Owner || !slices.EqualFunc(row.GetRouteRuleIds(), wantRuleIds, bytes.Equal) {
			t.Errorf("route %d: %v, want %x by %v", i, row, rule.RuleId, rule.Owner)
		}
	}

	encoded := aclEncodeRows(t, rows)
	random := rand.New(rand.NewPCG(7, 64))
	for range 8 {
		random.Shuffle(len(world.routes), func(i int, j int) { world.routes[i], world.routes[j] = world.routes[j], world.routes[i] })
		if again := aclEncodeRows(t, world.compile(t)); !bytes.Equal(again, encoded) {
			t.Fatal("the routes in another order compile to other bytes")
		}
	}
	const vectorPath = "testdata/acl/vectors/route_rows.hex"
	if os.Getenv("SIDECAR_REGENERATE_ACL_ROUTE_ROWS") != "" {
		if err := os.WriteFile(vectorPath, []byte(hex.EncodeToString(encoded)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	golden, err := testAclVectorFiles.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(encoded); got != strings.TrimSpace(string(golden)) {
		t.Fatalf("the rows compile to other bytes:\n%s", got)
	}
}
