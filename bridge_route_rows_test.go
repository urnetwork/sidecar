// QD-764 at the bridge side (acl-m2-17-no-via-route-advertisers): BridgeRows' route rows on the test network. Every
// verifier applies a BridgeRoute's ids and a binding BridgeWithdraw in log order, the keyless gate's included; a base's
// rows carry each route the head's ledger holds in force at the fold, so a void body's id-level row leaves them there;
// a verifier started at the base holds the long-running verifier's rows; the section's bytes are one encoding; and the
// compile emits a no-via rule's subject rows from the rows' advertisers, an exit's rows only for a rule that reaches
// public destinations.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The route rows a log's state holds, each its route id and advertiser.
func testBridgeRouteRowsOf(t testing.TB, log *ConfigLog) []*bridge.BridgeRouteRow {
	t.Helper()
	rows, err := log.State().BridgeRows()
	if err != nil {
		t.Fatal(err)
	}
	return rows.GetRoutes()
}

// Fails unless the log holds route rows of exactly these ids, in route_id order, each by its advertiser.
func testBridgeRouteRowsAre(t testing.TB, log *ConfigLog, want ...*bridge.BridgeRouteRow) {
	t.Helper()
	got := testBridgeRouteRowsOf(t, log)
	slices.SortFunc(want, func(a *bridge.BridgeRouteRow, b *bridge.BridgeRouteRow) int {
		return bytes.Compare(a.GetRouteId(), b.GetRouteId())
	})
	if len(got) != len(want) {
		t.Fatalf("%d route rows, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if !bytes.Equal(got[i].GetRouteId(), want[i].GetRouteId()) || !bytes.Equal(got[i].GetAdvertiser(), want[i].GetAdvertiser()) ||
			!slices.EqualFunc(got[i].GetRouteRuleIds(), want[i].GetRouteRuleIds(), bytes.Equal) {
			t.Fatalf("route row %d: %v, want %v", i, got[i], want[i])
		}
	}
}

// A BridgeRoute's row as the rows carry it.
func testBridgeRouteRow(routeId []byte, advertiser testConfigDevice, ruleIds ...[]byte) *bridge.BridgeRouteRow {
	return bridgeRouteRowOf(routeId, advertiser.sidecarId, ruleIds)
}

// A filing's ids join the rows in log order, its route_rule_ids in their one order, a policy rule's 16 bytes beside a
// requested grant's 32; a filing of the held id leaves the row as it was; a withdrawal removes the row where it binds,
// its advertiser's own or an admin's, and a withdrawal of an id no route row holds changes nothing. Every reader, the
// keyless gate's included, holds the same rows.
func TestARouteRowFollowsItsFilingAndBindingWithdrawals(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop, desktop := testBridgeCast(net)
	route, withdraw := bridge.SignedType_SIGNED_BRIDGE_ROUTE, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW
	policyRule, grant := testConfigId("policy rule").Bytes(), testBridgeRuleId("a requested grant")
	laptopId, desktopId := testBridgeRuleId("laptop's"), testBridgeRuleId("desktop's")

	filing := net.bridgeRoute(laptop, laptopId, testBridgeSubnet(testBridgePrefix(10, 1, 0, 0, 16), "a"))
	filing.RouteRuleIds = [][]byte{grant, policyRule}
	net.mustPost(laptop, route, filing)
	testBridgeRouteRowsAre(t, net.log, testBridgeRouteRow(laptopId, laptop, policyRule, grant))
	if row := testBridgeRouteRowsOf(t, net.log)[0]; len(row.GetRouteRuleIds()) != 2 || !slices.IsSortedFunc(row.GetRouteRuleIds(), bytes.Compare) {
		t.Fatalf("the rule ids out of their order: %v", row)
	}

	// the held id, filed again with other rules, activates nothing
	again := net.bridgeRoute(laptop, laptopId, testBridgeSubnet(testBridgePrefix(10, 1, 0, 0, 16), "a"))
	again.RouteRuleIds = [][]byte{testConfigId("another rule").Bytes()}
	net.mustPost(laptop, route, again)
	net.mustPost(desktop, route, net.bridgeRoute(desktop, desktopId, testBridgeSubnet(testBridgePrefix(10, 2, 0, 0, 16), "b")))
	testBridgeRouteRowsAre(t, net.log, testBridgeRouteRow(laptopId, laptop, policyRule, grant), testBridgeRouteRow(desktopId, desktop))
	net.everyReaderAgrees()

	// a withdrawal of a map's id, which no route row holds, changes no row
	net.mustPost(desktop, withdraw, net.bridgeWithdraw(testBridgeRuleId("no route's"), bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET))
	testBridgeRouteRowsAre(t, net.log, testBridgeRouteRow(laptopId, laptop, policyRule, grant), testBridgeRouteRow(desktopId, desktop))
	// an admin's withdrawal binds any filer's route, and the advertiser's own binds its own
	net.mustPost(net.owner, withdraw, net.bridgeWithdraw(desktopId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN))
	testBridgeRouteRowsAre(t, net.log, testBridgeRouteRow(laptopId, laptop, policyRule, grant))
	net.mustPost(laptop, withdraw, net.bridgeWithdraw(laptopId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET))
	testBridgeRouteRowsAre(t, net.log)
	net.everyReaderAgrees()

	// past a fold the rows hold a route the unfolded log does not: a withdrawal by neither its advertiser nor an admin
	// is taken at id level, binding only its signer's filings, and leaves the row, which the advertiser's then removes
	foldedId := testBridgeRuleId("folded")
	net.mustPost(laptop, route, net.bridgeRoute(laptop, foldedId, testBridgeSubnet(testBridgePrefix(10, 3, 0, 0, 16), "c")))
	net.fold(net.owner, net.n, 2)
	if net.log.State().Bridge().Len() != 0 {
		t.Fatal("the fold left a bridge statement unfolded")
	}
	net.mustPost(desktop, withdraw, net.bridgeWithdraw(foldedId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET))
	testBridgeRouteRowsAre(t, net.log, testBridgeRouteRow(foldedId, laptop))
	net.mustPost(laptop, withdraw, net.bridgeWithdraw(foldedId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET))
	testBridgeRouteRowsAre(t, net.log)
	net.everyReaderAgrees()
}

// "a verifier from a base agreeing with one that folded from the start": a no-via rule's covered route and a route whose
// body is void each show their ids at every verifier from their filings; the base that folds them carries the covered
// one alone, as CompileBridgeRows writes it from the head's ledger and the head's policy, so the void one leaves every
// verifier's rows there; a reader present since the bootstrap, one restored at the base and the keyless gate hold the
// writer's rows, and a withdrawal past the base applies at each alike.
func TestRouteRowsAreEqualFromABaseAndFromTheStart(t *testing.T) {
	net := newTestBridgeLedgerNet(t)
	_, laptop, desktop := testBridgeCast(net.testConfigNet)
	ruleId := testConfigId("no via rule")
	net.foldLedger(net.n, func(rows *protocol.AclRows) {
		rows.HasDocument = true
		rows.Rules = append(rows.Rules, &protocol.AclRule{
			RuleId: ruleId.Bytes(), SrcAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Actions: []uint32{uint32(protocol.AclAction_ACL_ACTION_ROUTE)},
		})
	})
	local := &AclLocalPolicy{HasDocument: true, Rules: []AclLocalRule{{RuleId: ruleId, Cidrs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}}}

	route := bridge.SignedType_SIGNED_BRIDGE_ROUTE
	coveredId, voidId := testBridgeRuleId("covered"), testBridgeRuleId("void")
	covered := net.bridgeRoute(laptop, coveredId, testBridgeSubnet(testBridgePrefix(10, 1, 0, 0, 16), "a"))
	covered.RouteRuleIds = [][]byte{ruleId.Bytes()}
	net.mustPost(laptop, route, covered)
	voidBody := testBridgeSubnet(testBridgePrefix(10, 2, 0, 0, 16), "b")
	voidBody.Kind = bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_UNSPECIFIED
	void := net.bridgeRoute(desktop, voidId, voidBody)
	void.RouteRuleIds = [][]byte{ruleId.Bytes()}
	voided := net.mustPost(desktop, route, void)
	if verdict := testBridgeVerdictAt(net.log, voided.Pin.GetVersion()); verdict == nil || verdict.Kind != BridgeBodyStanding {
		t.Fatalf("the void body's verdict: %+v", verdict)
	}
	coveredRow, voidRow := testBridgeRouteRow(coveredId, laptop, ruleId.Bytes()), testBridgeRouteRow(voidId, desktop, ruleId.Bytes())
	for _, log := range append(net.everyReader(), net.log, net.presentReader()) {
		testBridgeRouteRowsAre(t, log, coveredRow, voidRow)
	}

	// the writer's base: the head's ledger, folded, holds the covered route active and the other void; its rows carry
	// the routes in force, by the head's policy
	version := net.log.State().Base().GetConfigVersion() + 1
	folded := net.log.State()
	reached := net.foldLedger(net.n, func(rows *protocol.AclRows) {
		routes, err := BridgeHeadRoutes(net.heads[version])
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) != 1 || !bytes.Equal(routes[0].RuleId, coveredId) {
			t.Fatalf("the head's routes that may be in force: %v", routes)
		}
		state, err := NewAclState(rows, folded)
		if err != nil {
			t.Fatal(err)
		}
		now := time.UnixMilli(folded.TimeMs())
		if rows.Bridge, err = CompileBridgeRows(rows.Bridge, routes, func(rule *BridgeLedgerRule) bool {
			return local.StandingCovers(state, rule, now)
		}); err != nil {
			t.Fatal(err)
		}
	})
	if reached != folded.n {
		t.Fatalf("the fold reached %d, want %d", reached, folded.n)
	}
	if rule := net.ledgerOf(net.log).Rule(voidId); rule == nil || !rule.Void {
		t.Fatalf("the void body's rule at the fold: %+v", rule)
	}
	for _, log := range append(net.everyReader(), net.log, net.presentReader(), net.restoredReader()) {
		testBridgeRouteRowsAre(t, log, coveredRow)
	}
	net.everyReaderAgrees()

	// past the base, the advertiser's withdrawal removes its row at every verifier
	net.mustPost(laptop, bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, net.bridgeWithdraw(coveredId, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN))
	for _, log := range append(net.everyReader(), net.log, net.presentReader(), net.restoredReader()) {
		testBridgeRouteRowsAre(t, log)
	}
	net.everyReaderAgrees()
}

// The section's one encoding, golden: egress rows in subject order and route rows in route_id order, each row's
// route_rule_ids in byte order, whatever order the entries came in; and what a parser refuses of a route row.
func TestBridgeRouteRowsEncodeOnce(t *testing.T) {
	a, b := Id{0x01}, Id{0x02}
	ruleA, ruleB, grant := Id{0x0a}.Bytes(), Id{0x0b}.Bytes(), make([]byte, 32)
	grant[0] = 0x0c
	routeX, routeY := make([]byte, 32), make([]byte, 32)
	routeX[0], routeY[0] = 0x58, 0x59
	statement := func(routeId []byte, advertiser Id, ruleIds ...[]byte) *BridgeLogStatement {
		return &BridgeLogStatement{SignedType: bridge.SignedType_SIGNED_BRIDGE_ROUTE, RuleId: routeId, Subject: advertiser, RouteRuleIds: ruleIds}
	}
	build := func(steps ...func(data []byte) ([]byte, error)) []byte {
		t.Helper()
		var data []byte
		for _, step := range steps {
			var err error
			if data, err = step(data); err != nil {
				t.Fatal(err)
			}
		}
		return data
	}
	egress := func(subject Id) func(data []byte) ([]byte, error) {
		return func(data []byte) ([]byte, error) {
			return bridgeRowsWithEgress(data, subject, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS)
		}
	}
	routed := func(s *BridgeLogStatement) func(data []byte) ([]byte, error) {
		return func(data []byte) ([]byte, error) { return bridgeRowsWithRoute(data, s) }
	}
	forward := build(egress(a), routed(statement(routeX, a, grant, ruleB, ruleA)), routed(statement(routeY, b)), egress(b))
	backward := build(routed(statement(routeY, b)), egress(b), routed(statement(routeX, a, ruleA, grant, ruleB)), egress(a))
	if !bytes.Equal(forward, backward) {
		t.Fatalf("two orders of the same entries encode apart: %x and %x", forward, backward)
	}
	// two egress rows of 20 bytes; a route row of 122: its 32-byte id, 16-byte advertiser and rule ids 0x0a.., 0x0b..
	// and the 32-byte 0x0c.., in byte order; one of 52 with no rule
	const golden = "0a140a100100000000000000000000000000000010020a140a10020000000000000000000000000000001002" +
		"127a0a205800000000000000000000000000000000000000000000000000000000000000121001000000000000000000000000000000" +
		"1a100a0000000000000000000000000000001a100b0000000000000000000000000000001a200c00000000000000000000000000000000" +
		"00000000000000000000000000000012340a2059000000000000000000000000000000000000000000000000000000000000001210020000" +
		"00000000000000000000000000"
	if got := hex.EncodeToString(forward); got != golden {
		t.Fatalf("the section encodes to %s", got)
	}
	compiled, err := CompileBridgeRows(forward, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := ParseBridgeRows(compiled); err != nil || len(rows.GetRoutes()) != 0 || len(rows.GetEgress()) != 2 {
		t.Fatalf("a fold with no ledger route keeps the modes and drops the log's routes: %v, %v", rows, err)
	}

	for name, row := range map[string]*bridge.BridgeRouteRow{
		"a short route id":          {RouteId: routeX[:16], Advertiser: a.Bytes()},
		"a short advertiser":        {RouteId: routeX, Advertiser: a.Bytes()[:8]},
		"a rule id of 20 bytes":     {RouteId: routeX, Advertiser: a.Bytes(), RouteRuleIds: [][]byte{make([]byte, 20)}},
		"rule ids out of order":     {RouteId: routeX, Advertiser: a.Bytes(), RouteRuleIds: [][]byte{ruleB, ruleA}},
		"a rule id twice":           {RouteId: routeX, Advertiser: a.Bytes(), RouteRuleIds: [][]byte{ruleA, ruleA}},
		"routes out of their order": nil,
	} {
		rows := &bridge.BridgeRows{Routes: []*bridge.BridgeRouteRow{row}}
		if row == nil {
			rows.Routes = []*bridge.BridgeRouteRow{{RouteId: routeY, Advertiser: b.Bytes()}, {RouteId: routeX, Advertiser: a.Bytes()}}
		}
		data := testConfigMarshal(t, rows)
		if _, err := ParseBridgeRows(data); !errors.Is(err, ErrBridgeRowsMalformed) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := bridgeRowsWithRoute(data, statement(routeY, b)); !errors.Is(err, ErrBridgeRowsMalformed) {
			t.Errorf("%s, a route applied over it: %v", name, err)
		}
	}
}

// BRIDGE-M4-16's subject rows for a no-via rule, from the same source as every gate, the rows' route rows (QD-764):
// before S serves a route naming the rule no peer holds a row at S, and once it does each source of the rule holds a
// route row of what S serves inside the rule's prefix. An exit's rows come only of a rule that reaches public
// destinations: an internet rule whose via is S gives them, the no-via rule of 192.0.2.0/24 none.
func TestCompileEmitsSubjectRowsForANoViaRule(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	noVia, internet := testConfigId("no via rule"), testConfigId("internet rule")
	prefix := testBridgePrefix(192, 0, 2, 0, 24)
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()
	view := func(withInternet bool) *testBridgeCompileView {
		t.Helper()
		view := net.view()
		rows := &protocol.AclRows{HasDocument: true, Bridge: view.state.aclRows.GetBridge()}
		rows.Rules = append(rows.Rules, &protocol.AclRule{RuleId: noVia.Bytes(), SrcAtoms: [][]byte{member}, Actions: []uint32{uint32(protocol.AclAction_ACL_ACTION_ROUTE)}})
		local := &AclLocalPolicy{HasDocument: true, Rules: []AclLocalRule{{RuleId: noVia, Cidrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}}}
		if withInternet {
			rows.Rules = append(rows.Rules, &protocol.AclRule{
				RuleId: internet.Bytes(), SrcAtoms: [][]byte{member}, Actions: []uint32{uint32(protocol.AclAction_ACL_ACTION_ROUTE)},
				Targets: []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_INTERNET)},
				Via:     []*protocol.AclTarget{{SidecarId: net.host.sidecarId.Bytes()}},
			})
			local.Rules = append(local.Rules, AclLocalRule{RuleId: internet})
		}
		slices.SortFunc(rows.Rules, func(a *protocol.AclRule, b *protocol.AclRule) int { return bytes.Compare(a.GetRuleId(), b.GetRuleId()) })
		slices.SortFunc(local.Rules, func(a AclLocalRule, b AclLocalRule) int { return a.RuleId.Cmp(b.RuleId) })
		acl, err := NewAclState(rows, view.state)
		if err != nil {
			t.Fatal(err)
		}
		view.acl, view.aclLocal = acl, local
		return view
	}
	peers := []testConfigDevice{net.peer, net.other, net.owner}

	_, rules := testBridgeCompile(t, view(false), net.local())
	for _, peer := range peers {
		if subject := testBridgeCompileSubject(rules, peer.sidecarId); subject != nil {
			t.Errorf("before S serves a route, %v holds rows: %v", peer.sidecarId, subject)
		}
	}

	routeId := net.standingRoute(net.host, "served", prefix, noVia.Bytes())
	if rows, err := net.log.State().BridgeRows(); err != nil || BridgeRowsRoute(rows, routeId) == nil {
		t.Fatalf("the state's route rows: %v, %v", rows, err)
	}
	compiled, rules := testBridgeCompile(t, view(false), net.local())
	if served := rules.GetServed(); len(served) != 1 || !bytes.Equal(served[0].GetRouteId(), routeId) {
		t.Fatalf("S serves %v", served)
	}
	for _, peer := range peers {
		subject := testBridgeCompileSubject(rules, peer.sidecarId)
		if subject == nil || len(subject.GetRoute()) != 1 || !proto.Equal(subject.GetRoute()[0].GetPrefix(), prefix) || subject.GetRoute()[0].GetProtocol() != 0 ||
			len(subject.GetExit()) != 0 || len(subject.GetDial()) != 0 {
			t.Errorf("%v's rows at S: %v", peer.sidecarId, subject)
		}
	}
	if len(compiled.State.GetIdentities()) != len(peers) {
		t.Errorf("%d identities for %d subjects", len(compiled.State.GetIdentities()), len(peers))
	}

	_, rules = testBridgeCompile(t, view(true), net.local())
	for _, peer := range peers {
		subject := testBridgeCompileSubject(rules, peer.sidecarId)
		if subject == nil || len(subject.GetExit()) != 1 || subject.GetExit()[0].GetProtocol() != 0 || len(subject.GetRoute()) != 1 {
			t.Errorf("%v's rows at S with the internet rule: %v", peer.sidecarId, subject)
		}
	}
}
