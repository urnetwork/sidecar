//go:build !ios_extension

// The readers of a port-limited activated dial grant read its ports alike, through acl_grant_route.go's dial reader
// (aclGrantDialPortsOf; owner decisions 220 and 804; QD-740, QD-1428):
//
//	compile      the bridge compile's host dial rows open its sealed detail once a compile with its route reading, and
//	             wait or alarm for a detail that does not open here as the route rows do
//	check        AclEngine.Check's dial or route to a subject reads a document rule by its local detail as AllowInbound
//	             and AllowRoute read it, at some port or address, as it reads an activated grant by its sealed detail:
//	             a rule limiting ports only where this device holds them, at no client (question
//	             acl-grant-port-consistency-check-client-ports), and a route rule only by its prefixes, its
//	             autogroup:internet or the routes in force its destinations name
//	active grant AclEngine.ActiveGrant covers a forward at the ports its own sealed detail names by a rule whose ports
//	             take them, a document rule's local ones or an activated grant's sealed ones, so a forward asked again
//	             passes as standing on its own grant, and BridgeFiler.ForwardRoute serves a forward the gate passed as
//	             standing on any rule in force that opens its port (bridge_forward_standing_test.go, on the legs that
//	             file forwards)
//
// Each test that accepts fails before this change, but for the guards that say they held before. Synthetic values only.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The compile's grant net with the bridge approvers' requests rule taking a member's dial to its own devices beside
// its route, so a dial grant of the laptop's to the desktop activates through the log.
func newTestPortConsistencyNet(t *testing.T) *testBridgeGrantNet {
	net := newTestBridgeGrantNet(t)
	net.foldLedger(net.n, func(rows *protocol.AclRows) {
		for _, request := range rows.GetRequests() {
			if bytes.Equal(request.GetRuleId(), testBridgeRequestRuleId) {
				request.Actions = append(request.Actions, uint32(protocol.AclAction_ACL_ACTION_DIAL))
			}
		}
	})
	return net
}

// A version-4 grant of the laptop's to the desktop asking allow, the desktop by id alone in its clear grant_dst, its
// detail sealed as a daemon seals one (testWithSealedDetail) or by seal where set, ending an hour from the net's time.
func testPortConsistencyGrantAction(net *testBridgeGrantNet, allow []string, detail *protocol.CanonicalActionDetail,
	seal func(action *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail)) []byte {
	action := &protocol.CanonicalAction{
		Kind: uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD), Version: canonicalActionVersionSealedGrant,
		RuleId: testBridgeRequestRuleId, Subject: net.host.sidecarId.Bytes(),
		GrantDst: []string{aclTestDst(net.peer.sidecarId)}, GrantAllow: allow, ExpiresMillis: net.timeMs + 60*60*1000,
	}
	if seal == nil {
		testWithSealedDetail(action, detail)
	} else {
		seal(action, detail)
	}
	return testConfigMarshal(net.t, action)
}

// A seal of detail for action under another network's context, so it does not open under the key the net's devices
// hold in the net's own network.
func testPortConsistencySealElsewhere(t *testing.T) func(action *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail) {
	return func(action *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail) {
		clearBytes, err := canonicalActionClearBytes(action)
		if err != nil {
			t.Fatal(err)
		}
		sealContext, err := CanonicalActionDetailSealContext(testConfigId("another network"), clearBytes)
		if err != nil {
			t.Fatal(err)
		}
		if action.SealedDetail, err = SealConfigBody(testConfigSealKey(testActionDetailGeneration), sealContext, detail, testActionDetailRandom()); err != nil {
			t.Fatal(err)
		}
	}
}

// The desktop's compile at the reader's tip, holding generation 3's key where withKey, and the laptop's subject there,
// nil for none.
func testPortConsistencyDesktop(t *testing.T, net *testBridgeGrantNet, withKey bool) (*BridgeCompiled, *bridge.BridgeRuleSubject) {
	t.Helper()
	compiled, rules := testBridgeCompile(t, net.grantViewOf(net.log, withKey), net.localOf(net.peer))
	return compiled, testBridgeCompileSubject(rules, net.host.sidecarId)
}

// The state_unverified alarms a compile raised.
func testPortConsistencyUnverified(compiled *BridgeCompiled) []BridgeAlarm {
	alarms := []BridgeAlarm{}
	for _, alarm := range compiled.Alarms {
		if alarm.Reason == SidecarBridgeAlarmStateUnverified {
			alarms = append(alarms, alarm)
		}
	}
	return alarms
}

// A dial grant sealed to a generation this device does not hold gives the laptop no dial row at the desktop and waits
// for that generation, alarming nothing, as a route grant's detail does; with the key the same compile gives the rows
// its detail names, tcp 22 and udp 53, under its id and expiry, and waits for nothing. Before this change the compile
// gave no row and named no wait, so the component never fetched the key the rows waited on.
func TestCompileWaitsForAnActivatedDialGrantsKeyGeneration(t *testing.T) {
	net := newTestPortConsistencyNet(t)
	desktopDst := aclTestDst(net.peer.sidecarId)
	expiresMs := net.timeMs + 60*60*1000
	grantId := net.activate("dial key", testPortConsistencyGrantAction(net, []string{"dial"}, &protocol.CanonicalActionDetail{
		GrantDst: []string{desktopDst + ":tcp:22", desktopDst + ":udp:53"},
	}, nil))

	compiled, subject := testPortConsistencyDesktop(t, net, false)
	if subject != nil && 0 < len(subject.GetDial()) {
		t.Errorf("with its generation's key not held the grant gave dial rows %v", subject.GetDial())
	}
	wait := BridgeCompileWait{Kind: BridgeCompileWaitGeneration, Generation: testActionDetailGeneration}
	if !slices.Contains(compiled.Waits, wait) {
		t.Errorf("a dial grant's generation not held names no wait: %v", compiled.Waits)
	}
	if alarms := testPortConsistencyUnverified(compiled); len(alarms) != 0 {
		t.Errorf("a generation not held alarmed %v", alarms)
	}

	compiled, subject = testPortConsistencyDesktop(t, net, true)
	want := testBridgeGrantRowsSorted(
		testBridgeGrantRow(grantId, nil, aclIpProtocolTcp, 22, expiresMs), testBridgeGrantRow(grantId, nil, aclIpProtocolUdp, 53, expiresMs),
	)
	if subject == nil || !testBridgeReachRowsAre(subject.GetDial(), want...) {
		t.Fatalf("with the key, the laptop's dial rows at the desktop: %v", subject)
	}
	if len(compiled.Waits) != 0 || len(testPortConsistencyUnverified(compiled)) != 0 {
		t.Errorf("an opened dial grant waited for %v and alarmed %v", compiled.Waits, compiled.Alarms)
	}
}

// A dial grant whose detail does not open under the key held, sealed in another network, gives no dial row and alarms
// state_unverified once, naming the grant and why and no port, as a route grant's does; so does a port-limited dial
// grant whose action the state does not hold, while the same rule limiting no ports, an action sealing no detail, stands
// at every port and alarms nothing. Before this change neither alarmed.
func TestCompileAlarmsForAnActivatedDialGrantWhoseDetailDoesNotOpen(t *testing.T) {
	net := newTestPortConsistencyNet(t)
	desktopDst := aclTestDst(net.peer.sidecarId)
	grantId := net.activate("dial elsewhere", testPortConsistencyGrantAction(net, []string{"dial"}, &protocol.CanonicalActionDetail{
		GrantDst: []string{desktopDst + ":tcp:2222"},
	}, testPortConsistencySealElsewhere(t)))
	compiled, subject := testPortConsistencyDesktop(t, net, true)
	if subject != nil && 0 < len(subject.GetDial()) {
		t.Errorf("a detail that does not open gave dial rows %v", subject.GetDial())
	}
	alarms := testPortConsistencyUnverified(compiled)
	if len(alarms) != 1 {
		t.Fatalf("state_unverified alarms %v, want one", compiled.Alarms)
	}
	if alarm := alarms[0]; alarm.SidecarId != net.host.sidecarId || !strings.Contains(alarm.Detail, "grant "+hex.EncodeToString(grantId)) ||
		!strings.Contains(alarm.Detail, aclGrantRouteUnreadNotOpened.String()) || strings.Contains(alarm.Detail, "2222") {
		t.Errorf("the alarm %+v", alarm)
	}

	// a port-limited dial grant whose action the state does not hold, as rows a base carries name it
	for _, portsLimited := range []bool{true, false} {
		held := newTestPortConsistencyNet(t)
		missingId := sha256.Sum256([]byte("dial grant whose action is not held"))
		view := held.grantViewOf(held.log, true)
		rows := testPortConsistencyRowsWith(t, view.state.aclRows, &protocol.AclRule{
			RuleId:       missingId[:],
			SrcAtoms:     [][]byte{AclDerivedAtom(AclDerivedAtomSidecar, held.host.sidecarId.Bytes()).Bytes()},
			Targets:      []*protocol.AclTarget{{SidecarId: held.peer.sidecarId.Bytes()}},
			Actions:      []uint32{uint32(protocol.AclAction_ACL_ACTION_DIAL)},
			PortsLimited: portsLimited,
			Expires:      held.timeMs + 60*60*1000,
			SourceRuleId: testBridgeRequestRuleId,
		}, held.host.sidecarId)
		acl, err := NewAclState(rows, view.state)
		if err != nil {
			t.Fatal(err)
		}
		view.acl = acl
		compiled, rules := testBridgeCompile(t, view, held.localOf(held.peer))
		subject := testBridgeCompileSubject(rules, held.host.sidecarId)
		alarmed := len(testPortConsistencyUnverified(compiled)) != 0
		switch {
		case portsLimited && (!alarmed || (subject != nil && 0 < len(subject.GetDial()))):
			t.Errorf("an action not held: alarmed %t, the laptop %v", alarmed, subject)
		case !portsLimited && (alarmed || subject == nil || !testBridgeReachRowsAre(subject.GetDial(),
			&bridge.BridgeRuleReach{GrantId: missingId[:], Expires: held.timeMs + 60*60*1000})):
			t.Errorf("a rule limiting no ports: alarmed %t, the laptop %v", alarmed, subject)
		}
	}
}

// The rows with rule added, its source sidecar's derived atom beside it.
func testPortConsistencyRowsWith(t *testing.T, base *protocol.AclRows, rule *protocol.AclRule, source Id) *protocol.AclRows {
	t.Helper()
	rows := proto.Clone(base).(*protocol.AclRows)
	sourceAtom := AclDerivedAtom(AclDerivedAtomSidecar, source.Bytes())
	rows.Atoms = append(rows.Atoms, &protocol.AclAtom{Atom: sourceAtom.Bytes(), SidecarIds: [][]byte{source.Bytes()}})
	rows.Rules = append(rows.Rules, rule)
	return rows
}

// A grant allowing dial and route whose detail does not open opens it once a compile, for its dial rows and its route
// rows both, and so alarms once, where the dial rows' own alarm would otherwise give it a second; with its detail open
// it gives the desktop's dial rows at its port and route rows of its prefix, at the same port, a route grant's ports
// being every port its sidecar destinations name. A guard of the shared opening: before this change the dial rows
// alarmed nothing, so this held then too.
func TestCompileOpensAGrantAllowingDialAndRouteOnce(t *testing.T) {
	desktopDetail := func(net *testBridgeGrantNet) *protocol.CanonicalActionDetail {
		return &protocol.CanonicalActionDetail{Cidrs: []string{"192.168.7.0/25"}, GrantDst: []string{aclTestDst(net.peer.sidecarId) + ":tcp:22"}}
	}
	both := []string{"dial", "route"}

	net := newTestPortConsistencyNet(t)
	net.activate("both elsewhere", testPortConsistencyGrantAction(net, both, desktopDetail(net), testPortConsistencySealElsewhere(t)))
	compiled, subject := testPortConsistencyDesktop(t, net, true)
	if alarms := testPortConsistencyUnverified(compiled); len(alarms) != 1 {
		t.Errorf("a grant allowing both alarmed %d times a compile: %v", len(alarms), alarms)
	}
	if subject != nil && 0 < len(subject.GetDial())+len(subject.GetRoute()) {
		t.Errorf("a detail that does not open gave dial rows %v and route rows %v", subject.GetDial(), subject.GetRoute())
	}

	opened := newTestPortConsistencyNet(t)
	expiresMs := opened.timeMs + 60*60*1000
	grantId := opened.activate("both", testPortConsistencyGrantAction(opened, both, desktopDetail(opened), nil))
	compiled, subject = testPortConsistencyDesktop(t, opened, true)
	if subject == nil || !testBridgeReachRowsAre(subject.GetDial(), testBridgeGrantRow(grantId, nil, aclIpProtocolTcp, 22, expiresMs)) {
		t.Fatalf("the laptop's dial rows at the desktop: %v", subject)
	}
	if !testBridgeReachRowsAre(subject.GetRoute(), testBridgeGrantRow(grantId, testBridgePrefix(192, 168, 7, 0, 25), aclIpProtocolTcp, 22, expiresMs)) {
		t.Errorf("the laptop's route rows at the desktop: %v", subject.GetRoute())
	}
	if len(compiled.Waits) != 0 || len(testPortConsistencyUnverified(compiled)) != 0 {
		t.Errorf("an opened grant waited for %v and alarmed %v", compiled.Waits, compiled.Alarms)
	}
}

// One Check of a dial or a route to a sidecar.
func testPortConsistencyCheck(engine *AclEngine, source Id, action protocol.AclAction, kind AclSelectorKind, destination Id) AclCheck {
	return engine.Check(AclSidecarSubject(source), action, AclResource{Kind: AclResourceSubject, Subject: AclSelector{Kind: kind, Id: destination}}, aclTestNow)
}

// An engine of a sidecar's over state with local, nil holding no local detail.
func testPortConsistencyEngine(t *testing.T, sidecarId Id, state *AclState, local *AclLocalPolicy, opener AclGrantDetails) *AclEngine {
	t.Helper()
	engine := NewAclEngine(sidecarId, nil, nil, &AclEngineSettings{ClockSkew: 0})
	if err := engine.InstallWithGrants(state, local, opener); err != nil {
		t.Fatal(err)
	}
	return engine
}

// Check's dial to a sidecar reads a document rule limiting ports as AllowInbound does: where this device holds the
// rule's ports, its local detail, the dial stands, naming the rule; where it holds none, the rule opens no port here,
// so the dial is refused though the rows take it, as AllowInbound refuses every port. Before this change the rows alone
// allowed it.
func TestAclEngineCheckDialsASubjectByADocumentRulesPorts(t *testing.T) {
	world := newAclEngineWorld(t)
	state, local := world.install(t, aclTestEnginePin(1, "check dial ports"))
	phone := AclSidecarSubject(world.phone)
	if !state.MayDial(phone, AclSidecarSubject(world.laptop), aclTestNow).Allowed {
		t.Fatal("the rows do not take the phone's dial to the laptop: the refusal below would prove nothing")
	}
	ruleId := world.world.documentRuleId(t, "grant", 0)
	held := testPortConsistencyEngine(t, world.laptop, state, local, nil)
	if result := testPortConsistencyCheck(held, world.phone, protocol.AclAction_ACL_ACTION_DIAL, AclSelectorSidecar, world.laptop); !result.Allowed ||
		!bytes.Equal(result.GrantId, ruleId.Bytes()) {
		t.Errorf("with the rule's ports held: %+v", result)
	}
	bare := testPortConsistencyEngine(t, world.laptop, state, nil, nil)
	if result := testPortConsistencyCheck(bare, world.phone, protocol.AclAction_ACL_ACTION_DIAL, AclSelectorSidecar, world.laptop); result.Allowed ||
		result.Reason != AclReasonNoGrant {
		t.Errorf("with no local detail: %+v", result)
	}
	if decision := bare.AllowInbound(&AclInbound{Source: phone, IpProtocol: aclIpProtocolTcp, Port: 22}, aclTestNow); decision.Allowed {
		t.Errorf("with no local detail AllowInbound opened tcp 22: %+v", decision)
	}
}

// A world whose document reaches two clients no binding names from the members' devices, one through a rule limiting
// ports and one through a rule limiting none, and routes the members through three sidecars: an exit by
// autogroup:internet, a desk by its own routes in force (a rule naming no prefix whose destination is its via), and a
// router by a prefix.
type testPortConsistencyCheckWorld struct {
	world     *aclCompileWorld
	phone     Id
	exit      Id
	desk      Id
	router    Id
	limited   Id
	unlimited Id
}

func newTestPortConsistencyCheckWorld(t *testing.T) *testPortConsistencyCheckWorld {
	world := newAclCompileWorld("check narrowing")
	owner := world.member("owner@narrowing.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	self := &testPortConsistencyCheckWorld{world: world}
	self.phone = world.device("narrowing phone", owner)
	self.exit = world.device("narrowing exit", owner)
	self.desk = world.device("narrowing desk", owner)
	self.router = world.device("narrowing router", owner)
	self.limited = world.id("narrowing limited client")
	self.unlimited = world.id("narrowing unlimited client")
	for _, clientId := range []Id{self.limited, self.unlimited} {
		world.resolve.Clients = append(world.resolve.Clients, &protocol.ConfigClientResolution{ClientId: clientId.Bytes()})
	}
	world.setPolicy(t, `{
  "grants": [
    { "src": ["autogroup:member"], "dst": ["client:`+self.limited.String()+`"], "allow": ["dial"], "ip": ["tcp:22"] },
    { "src": ["autogroup:member"], "dst": ["client:`+self.unlimited.String()+`"], "allow": ["dial"] },
    { "src": ["autogroup:member"], "dst": ["autogroup:internet"], "via": ["sidecar:`+self.exit.String()+`"], "allow": ["route"] },
    { "src": ["autogroup:member"], "dst": ["sidecar:`+self.desk.String()+`"], "via": ["sidecar:`+self.desk.String()+`"], "allow": ["route"] },
    { "src": ["autogroup:member"], "dst": ["ip:198.51.100.0/24"], "via": ["sidecar:`+self.router.String()+`"], "allow": ["route"] },
  ],
}`)
	return self
}

// The state and local policy.
func (self *testPortConsistencyCheckWorld) install(t *testing.T) (*AclState, *AclLocalPolicy) {
	t.Helper()
	view := self.world.view()
	view.pin = aclTestEnginePin(1, "check narrowing")
	state, err := NewAclState(self.world.compile(t), view)
	if err != nil {
		t.Fatal(err)
	}
	local, err := CompileAclLocal(self.world.input())
	if err != nil {
		t.Fatal(err)
	}
	return state, local
}

// Check's dial to a client no binding names counts a rule limiting no ports and not one limiting ports, whose ports the
// client's own device checks and which §8.10 reaches no legacy client by, the closed direction, as an activated grant's
// detail names no port at a client. Before this change the rows alone allowed both.
func TestAclEngineCheckDialsAClientOnlyByARuleLimitingNoPorts(t *testing.T) {
	world := newTestPortConsistencyCheckWorld(t)
	state, local := world.install(t)
	engine := testPortConsistencyEngine(t, world.phone, state, local, nil)
	phone := AclSidecarSubject(world.phone)
	for _, clientId := range []Id{world.limited, world.unlimited} {
		if !state.MayDial(phone, AclClientSubject(clientId, Id{}, nil, ""), aclTestNow).Allowed {
			t.Fatalf("the rows do not take the phone's dial to client %s: the refusal below would prove nothing", clientId)
		}
	}
	if result := testPortConsistencyCheck(engine, world.phone, protocol.AclAction_ACL_ACTION_DIAL, AclSelectorClient, world.unlimited); !result.Allowed ||
		!bytes.Equal(result.GrantId, world.world.documentRuleId(t, "grant", 1).Bytes()) {
		t.Errorf("a rule limiting no ports: %+v", result)
	}
	if result := testPortConsistencyCheck(engine, world.phone, protocol.AclAction_ACL_ACTION_DIAL, AclSelectorClient, world.limited); result.Allowed {
		t.Errorf("a rule limiting ports at a client: %+v", result)
	}
}

// Check's route through a sidecar reads a document rule as AllowRoute does at any address: an autogroup:internet rule
// takes its exit with or without the rule's local detail, since rows carry it; a rule naming a prefix takes its router
// only where this device holds the prefix; and a rule naming no prefix takes the desk only where the desk, a
// destination of the rule, serves a route in force, by the routes InstallRoutes last took and none before. The rows
// take every one of these. Before this change the rows alone allowed each.
func TestAclEngineCheckRoutesThroughASubjectByADocumentRulesDetail(t *testing.T) {
	world := newTestPortConsistencyCheckWorld(t)
	state, local := world.install(t)
	phone := AclSidecarSubject(world.phone)
	for _, via := range []Id{world.exit, world.desk, world.router} {
		if !state.MayRoute(phone, netip.Addr{}, AclSidecarSubject(via), aclTestNow).Allowed {
			t.Fatalf("the rows do not route the phone through %s: the refusals below would prove nothing", via)
		}
	}
	route := func(engine *AclEngine, via Id) AclCheck {
		return testPortConsistencyCheck(engine, world.phone, protocol.AclAction_ACL_ACTION_ROUTE, AclSelectorSidecar, via)
	}
	held := testPortConsistencyEngine(t, world.phone, state, local, nil)
	bare := testPortConsistencyEngine(t, world.phone, state, nil, nil)
	cases := []struct {
		name    string
		engine  *AclEngine
		via     Id
		allowed bool
	}{
		{name: "the exit with the detail", engine: held, via: world.exit, allowed: true},
		{name: "the exit without it", engine: bare, via: world.exit, allowed: true},
		{name: "the router with the detail", engine: held, via: world.router, allowed: true},
		{name: "the router without it", engine: bare, via: world.router},
		{name: "the desk before any routes", engine: held, via: world.desk},
		{name: "the desk without the detail", engine: bare, via: world.desk},
	}
	for _, c := range cases {
		if result := route(c.engine, c.via); result.Allowed != c.allowed {
			t.Errorf("%s: %+v", c.name, result)
		}
	}
	// the desk once it serves a route in force, and the router's routes reaching nothing of the desk's
	held.InstallRoutes(NewAclServedRoutes([]AclServedRoute{{Advertiser: world.router, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}}))
	if result := route(held, world.desk); result.Allowed {
		t.Errorf("the desk while only the router serves a route: %+v", result)
	}
	held.InstallRoutes(NewAclServedRoutes([]AclServedRoute{{Advertiser: world.desk, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}}))
	if result := route(held, world.desk); !result.Allowed || !bytes.Equal(result.GrantId, world.world.documentRuleId(t, "grant", 3).Bytes()) {
		t.Errorf("the desk serving a route in force: %+v", result)
	}
}

// Check's route through a sidecar under a document rule limiting ports stands only where this device holds the rule's
// ports, as AllowRoute refuses every port of such a rule whose detail it does not hold.
func TestAclEngineCheckRoutesThroughASubjectOnlyAtPortsTheDeviceHolds(t *testing.T) {
	world := newAclEngineWorld(t)
	state, local := world.install(t, aclTestEnginePin(1, "check route ports"))
	phone := AclSidecarSubject(world.phone)
	if !state.MayRoute(phone, netip.Addr{}, AclSidecarSubject(world.router), aclTestNow).Allowed {
		t.Fatal("the rows do not route the phone through the router: the refusal below would prove nothing")
	}
	held := testPortConsistencyEngine(t, world.phone, state, local, nil)
	if result := testPortConsistencyCheck(held, world.phone, protocol.AclAction_ACL_ACTION_ROUTE, AclSelectorSidecar, world.router); !result.Allowed {
		t.Errorf("with the rule's detail: %+v", result)
	}
	bare := testPortConsistencyEngine(t, world.phone, state, nil, nil)
	if result := testPortConsistencyCheck(bare, world.phone, protocol.AclAction_ACL_ACTION_ROUTE, AclSelectorSidecar, world.router); result.Allowed {
		t.Errorf("with no local detail: %+v", result)
	}
}

// A forward's action of the laptop's to the desktop at one port, as a daemon builds it: version 4, the desktop by id
// alone in its clear grant_dst, its target port and the port's text sealed in its detail (testWithSealedDetail),
// under the bridge approvers' requests rule, ending half an hour from the net's time; as stored.
func testPortConsistencyForward(t *testing.T, net *testBridgeGrantNet, subject Id, protocolName string, port uint32) *StoredCanonicalAction {
	t.Helper()
	target := aclTestDst(net.peer.sidecarId)
	action := testWithSealedDetail(&protocol.CanonicalAction{
		Kind: uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD), Version: canonicalActionVersionSealedGrant,
		RuleId: testBridgeRequestRuleId, Subject: subject.Bytes(),
		GrantDst: []string{target}, GrantAllow: []string{"dial"}, ExpiresMillis: net.timeMs + 30*60*1000,
	}, &protocol.CanonicalActionDetail{TargetPort: port, GrantDst: []string{target + ":" + protocolName + ":" + strconv.FormatUint(uint64(port), 10)}})
	stored, err := ParseStoredCanonicalAction(testConfigMarshal(t, action))
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// ActiveGrant covers a forward by a port-limited activated dial grant at the ports the grant's sealed detail names
// there, the forward's own ports read from its own sealed detail: the laptop's forwards to the desktop's tcp 22 and udp
// 53 pass, and its forwards to tcp 23 and udp 22 do not; nor does any where this device holds neither detail's key,
// where its opener opens no action, so the forward asks every port, for another spender, or within the clock skew of the
// grant's end. Before this change a port-limited grant covered no forward at all.
func TestAclActiveGrantCoversAForwardAtItsDialGrantsPorts(t *testing.T) {
	net := newTestPortConsistencyNet(t)
	desktopDst := aclTestDst(net.peer.sidecarId)
	expiresMs := net.timeMs + 60*60*1000
	net.activate("standing dial", testPortConsistencyGrantAction(net, []string{"dial"}, &protocol.CanonicalActionDetail{
		GrantDst: []string{desktopDst + ":tcp:22", desktopDst + ":udp:53"},
	}, nil))
	now := time.UnixMilli(net.log.State().TimeMs())
	laptop := net.host.sidecarId
	engine := net.grantEngine(net.log, true, nil)
	cases := []struct {
		protocolName string
		port         uint32
		covered      bool
	}{
		{protocolName: "tcp", port: 22, covered: true},
		{protocolName: "udp", port: 53, covered: true},
		{protocolName: "tcp", port: 23},
		{protocolName: "udp", port: 22},
	}
	for _, c := range cases {
		if covered := engine.ActiveGrant(testPortConsistencyForward(t, net, laptop, c.protocolName, c.port), laptop, now); covered != c.covered {
			t.Errorf("a forward to the desktop's %s %d: covered %t", c.protocolName, c.port, covered)
		}
	}
	forward := testPortConsistencyForward(t, net, laptop, "tcp", 22)
	view := net.grantViewOf(net.log, true)
	actionless := &testAclGrantDetailsCount{opener: newAclStateGrantDetails(view.state, view.head, view.RepoKeyAt)}
	skew := DefaultAclEngineSettings().ClockSkew
	for name, covered := range map[string]bool{
		"without the key":                net.grantEngine(net.log, false, nil).ActiveGrant(forward, laptop, now),
		"an opener that opens no action": net.grantEngine(net.log, true, actionless).ActiveGrant(forward, laptop, now),
		"another spender":                engine.ActiveGrant(forward, net.peer.sidecarId, now),
		"within the skew of its end":     engine.ActiveGrant(forward, laptop, time.UnixMilli(expiresMs).Add(-skew)),
	} {
		if covered {
			t.Errorf("%s: the forward is covered", name)
		}
	}
	if !engine.ActiveGrant(forward, laptop, time.UnixMilli(expiresMs).Add(-skew-time.Millisecond)) {
		t.Error("just before the skew of the grant's end the forward is not covered")
	}
	if 0 == actionless.count() {
		t.Error("the opener that opens no action was never asked for the grant's detail: the engine read nothing")
	}
}

// An opener of a test's forwards' own details, sealed in the test's network under generation 3's key
// (testWithSealedDetail), which opens no activated grant.
type testPortConsistencyActionOpener struct{}

func (self testPortConsistencyActionOpener) GrantDetail(grantId []byte) (*protocol.CanonicalActionDetail, error) {
	return nil, ErrAclGrantActionNotHeld
}

func (self testPortConsistencyActionOpener) actionDetail(action *StoredCanonicalAction) (*protocol.CanonicalActionDetail, error) {
	return OpenCanonicalActionDetail(action, testActionDetailNetworkId(), testConfigSealKeyAt(testConfigSealKey(testActionDetailGeneration)))
}

// ActiveGrant covers a forward by a document rule limiting ports at the ports the rule's local detail names: the
// members' dial rule, tcp 22 and udp 5000 to 5010, covers the phone's forwards to the laptop's tcp 22 and udp 5005 and
// not its tcp 23; with no local detail held, or an opener that opens no action, no forward. Before this change a rule
// limiting ports covered no forward.
func TestAclActiveGrantCoversAForwardByADocumentRulesPorts(t *testing.T) {
	world := newAclEngineWorld(t)
	state, local := world.install(t, aclTestEnginePin(1, "active grant ports"))
	ruleId := world.world.id("forward requests rule").Bytes()
	forward := func(dst string) *StoredCanonicalAction {
		action := aclTestGrantAction(ruleId, world.phone, []string{dst}, []string{"dial"}, aclTestNow.Add(time.Hour).UnixMilli())
		// the target's port is the forward's own, as BridgeFiler.Forward seals it
		_, ports, err := ParseAclGrantDst(dst)
		if err != nil {
			t.Fatal(err)
		}
		action.SealedDetail = nil
		testWithSealedDetail(action, &protocol.CanonicalActionDetail{TargetPort: ports.GetFirst(), GrantDst: []string{dst}})
		stored, err := ParseStoredCanonicalAction(testConfigMarshal(t, action))
		if err != nil {
			t.Fatal(err)
		}
		return stored
	}
	laptop := aclTestDst(world.laptop)
	held := testPortConsistencyEngine(t, world.phone, state, local, testPortConsistencyActionOpener{})
	cases := []struct {
		dst     string
		covered bool
	}{
		{dst: laptop + ":tcp:22", covered: true},
		{dst: laptop + ":udp:5005", covered: true},
		{dst: laptop + ":tcp:23"},
	}
	for _, c := range cases {
		if covered := held.ActiveGrant(forward(c.dst), world.phone, aclTestNow); covered != c.covered {
			t.Errorf("a forward to %s: covered %t", c.dst, covered)
		}
	}
	bare := testPortConsistencyEngine(t, world.phone, state, nil, testPortConsistencyActionOpener{})
	if bare.ActiveGrant(forward(laptop+":tcp:22"), world.phone, aclTestNow) {
		t.Error("with no local detail a forward is covered")
	}
	noActions := testPortConsistencyEngine(t, world.phone, state, local, newTestAclFollowupsDetails())
	if noActions.ActiveGrant(forward(laptop+":tcp:22"), world.phone, aclTestNow) {
		t.Error("with an opener that opens no action a forward is covered")
	}
}
