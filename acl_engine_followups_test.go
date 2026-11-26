//go:build !ios_extension

// AclEngine's activated grants past acl-engine-route-grants (acl_engine.go; owner decisions 220 and 679; QD-003, QD-740,
// QD-1164): AllowInbound opens a port-limited activated dial grant's ports by its sealed detail, the ports it names at
// this sidecar, as the host's compile serves them (grantPortRule), and nothing where the detail does not read; Check's
// dial or route to a sidecar counts an activated grant only where its detail reaches that sidecar; and a grant whose
// detail waited on a config key generation is read again when the key arrives, by ReadWaitingGrants, which the acl
// follower runs on the keychain's signal, armed before its read. Each test that accepts fails before this change.
// Synthetic values only.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An opener over details by grant id, which answers a grant's error where errs holds one, counts what it is asked, and
// at the next ask runs onAsk once, outside its lock, before it answers. Safe for concurrent use.
type testAclFollowupsDetails struct {
	stateLock sync.Mutex
	details   map[string]*protocol.CanonicalActionDetail
	errs      map[string]error
	asked     map[string]int
	onAsk     func()
}

func newTestAclFollowupsDetails() *testAclFollowupsDetails {
	return &testAclFollowupsDetails{details: map[string]*protocol.CanonicalActionDetail{}, errs: map[string]error{}, asked: map[string]int{}}
}

func (self *testAclFollowupsDetails) GrantDetail(grantId []byte) (*protocol.CanonicalActionDetail, error) {
	onAsk := func() func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.asked[string(grantId)] += 1
		onAsk := self.onAsk
		self.onAsk = nil
		return onAsk
	}()
	if onAsk != nil {
		onAsk()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.errs[string(grantId)]; err != nil {
		return nil, err
	}
	detail, found := self.details[string(grantId)]
	if !found {
		return nil, ErrAclGrantActionNotHeld
	}
	return proto.Clone(detail).(*protocol.CanonicalActionDetail), nil
}

// What the next ask runs first, once.
func (self *testAclFollowupsDetails) setOnAsk(onAsk func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.onAsk = onAsk
}

// Sets a grant's detail, or with detail nil its error.
func (self *testAclFollowupsDetails) set(grantId []byte, detail *protocol.CanonicalActionDetail, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err != nil {
		self.errs[string(grantId)] = err
		delete(self.details, string(grantId))
		return
	}
	delete(self.errs, string(grantId))
	self.details[string(grantId)] = detail
}

// How many times a grant's detail was asked.
func (self *testAclFollowupsDetails) count(grantId []byte) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.asked[string(grantId)]
}

// A network whose document gives no rule of its own and whose one requests rule takes a member's dial and route to
// another member: the phone, the owner's laptop and desk, and the grants activated for the phone.
type testAclFollowupsWorld struct {
	world  *aclCompileWorld
	laptop Id
	phone  Id
	desk   Id
}

func newTestAclFollowupsWorld(t *testing.T) *testAclFollowupsWorld {
	world := newAclCompileWorld("engine followups")
	owner := world.member("owner@followups.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	member := world.member("member@followups.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	self := &testAclFollowupsWorld{world: world}
	self.laptop = world.device("followups laptop", owner)
	self.desk = world.device("followups desk", owner)
	self.phone = world.device("followups phone", member)
	world.setPolicy(t, `{
  "requests": [
    { "src": ["autogroup:member"], "dst": ["autogroup:member"], "allow": ["dial", "route"], "approver": ["autogroup:admin"] },
  ],
}`)
	phoneAtom := AclDerivedAtom(AclDerivedAtomSidecar, self.phone.Bytes())
	world.statements.Atoms = append(world.statements.Atoms, &protocol.AclAtom{Atom: phoneAtom.Bytes(), SidecarIds: [][]byte{self.phone.Bytes()}})
	return self
}

// Activates a grant of the phone's on targets for actions, an hour from the head's time, port-limited where sealed, as
// a GrantActivate carrying a sealed_detail folds; a route grant's targets are its via too (QD-764). Answers its id.
func (self *testAclFollowupsWorld) grant(t *testing.T, label string, targets []*protocol.AclTarget, actions []protocol.AclAction, sealed bool) []byte {
	t.Helper()
	grantId := self.world.key("followups grant " + label)
	rule := &protocol.AclRule{
		RuleId:       bytes.Clone(grantId),
		SrcAtoms:     [][]byte{AclDerivedAtom(AclDerivedAtomSidecar, self.phone.Bytes()).Bytes()},
		Targets:      targets,
		PortsLimited: sealed,
		Expires:      self.world.headTimeMs + 60*60*1000,
		SourceRuleId: self.world.documentRuleId(t, "request", 0).Bytes(),
	}
	for _, action := range actions {
		rule.Actions = append(rule.Actions, uint32(action))
		if action == protocol.AclAction_ACL_ACTION_ROUTE {
			for _, target := range targets {
				rule.Via = append(rule.Via, proto.Clone(target).(*protocol.AclTarget))
			}
		}
	}
	self.world.statements.Rules = append(self.world.statements.Rules, rule)
	return grantId
}

// The state at a pin.
func (self *testAclFollowupsWorld) state(t *testing.T, pin *bridge.AuthPin) *AclState {
	t.Helper()
	view := self.world.view()
	view.pin = pin
	state, err := NewAclState(self.world.compile(t), view)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// An engine of a sidecar's over the world's state at pin 1, its grants opened through opener, nil opening none.
func (self *testAclFollowupsWorld) engine(t *testing.T, sidecarId Id, opener AclGrantDetails) *AclEngine {
	t.Helper()
	engine := NewAclEngine(sidecarId, nil, nil, &AclEngineSettings{ClockSkew: 0})
	if err := engine.InstallWithGrants(self.state(t, aclTestEnginePin(1, "followups")), nil, opener); err != nil {
		t.Fatal(err)
	}
	return engine
}

// A sidecar's text in a grant_dst or a detail's.
func testAclFollowupsDst(sidecarId Id) string {
	return "sidecar:" + hex.EncodeToString(sidecarId.Bytes())
}

// One inbound dial of the phone's.
type testAclFollowupsDial struct {
	ipProtocol uint32
	port       uint32
	allowed    bool
}

// A port-limited dial grant opens at each sidecar exactly the ports its detail names there, as grantPortRule reads them:
// the laptop its tcp 22 and udp 53 and the desk its tcp 80, no other port or protocol, the decision naming the grant; a
// target_port keeps only its own port; and the grant opens nothing with no opener, with its generation's key missing,
// where its action is not held, where its detail does not open, or past its expiry. Before this change the grant opened
// no port at all.
func TestAclEngineAllowInboundOpensAnActivatedDialGrantsPortsByItsDetail(t *testing.T) {
	world := newTestAclFollowupsWorld(t)
	grantId := world.grant(t, "dial", []*protocol.AclTarget{{SidecarId: world.laptop.Bytes()}, {SidecarId: world.desk.Bytes()}},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, true)
	details := newTestAclFollowupsDetails()
	details.set(grantId, &protocol.CanonicalActionDetail{GrantDst: []string{
		testAclFollowupsDst(world.laptop) + ":tcp:22", testAclFollowupsDst(world.laptop) + ":udp:53", testAclFollowupsDst(world.desk) + ":tcp:80",
	}}, nil)
	phone := AclSidecarSubject(world.phone)
	check := func(name string, engine *AclEngine, dials []testAclFollowupsDial, at time.Time) {
		t.Helper()
		for _, dial := range dials {
			decision := engine.AllowInbound(&AclInbound{Source: phone, IpProtocol: dial.ipProtocol, Port: dial.port}, at)
			if decision.Allowed != dial.allowed || (dial.allowed && !bytes.Equal(decision.Rule.GetRuleId(), grantId)) {
				t.Errorf("%s: protocol %d port %d allowed %t (%s)", name, dial.ipProtocol, dial.port, decision.Allowed, decision.Reason)
			}
		}
	}
	laptopDials := []testAclFollowupsDial{
		{ipProtocol: aclIpProtocolTcp, port: 22, allowed: true},
		{ipProtocol: aclIpProtocolUdp, port: 53, allowed: true},
		{ipProtocol: aclIpProtocolTcp, port: 80},
		{ipProtocol: aclIpProtocolTcp, port: 23},
		{ipProtocol: aclIpProtocolUdp, port: 22},
		{ipProtocol: aclIpProtocolTcp, port: 53},
	}
	check("the laptop", world.engine(t, world.laptop, details), laptopDials, aclTestNow)
	check("the desk", world.engine(t, world.desk, details), []testAclFollowupsDial{
		{ipProtocol: aclIpProtocolTcp, port: 80, allowed: true},
		{ipProtocol: aclIpProtocolTcp, port: 22},
		{ipProtocol: aclIpProtocolUdp, port: 53},
	}, aclTestNow)
	expiresAt := time.UnixMilli(world.world.headTimeMs + 60*60*1000)
	check("the laptop at the grant's end", world.engine(t, world.laptop, details), []testAclFollowupsDial{
		{ipProtocol: aclIpProtocolTcp, port: 22},
	}, expiresAt)

	closed := make([]testAclFollowupsDial, len(laptopDials))
	for i, dial := range laptopDials {
		closed[i] = testAclFollowupsDial{ipProtocol: dial.ipProtocol, port: dial.port}
	}
	check("no opener", world.engine(t, world.laptop, nil), closed, aclTestNow)
	for _, err := range []error{ErrConfigSealGenerationMissing, ErrAclGrantActionNotHeld, ErrConfigSealInvalid} {
		unread := newTestAclFollowupsDetails()
		unread.set(grantId, nil, err)
		check(err.Error(), world.engine(t, world.laptop, unread), closed, aclTestNow)
	}

	// a target_port keeps only the destinations whose port it is
	targeted := newTestAclFollowupsDetails()
	targeted.set(grantId, &protocol.CanonicalActionDetail{TargetPort: 22, GrantDst: []string{
		testAclFollowupsDst(world.laptop) + ":tcp:22", testAclFollowupsDst(world.laptop) + ":tcp:2222",
	}}, nil)
	check("a target_port", world.engine(t, world.laptop, targeted), []testAclFollowupsDial{
		{ipProtocol: aclIpProtocolTcp, port: 22, allowed: true},
		{ipProtocol: aclIpProtocolTcp, port: 2222},
	}, aclTestNow)
}

// A dial grant whose action seals no detail limits no ports, as its rows say and the compile serves it, at every port of
// every sidecar its rows name, and its opener is never asked.
func TestAclEngineAllowInboundOpensAnUnsealedDialGrantAtEveryPort(t *testing.T) {
	world := newTestAclFollowupsWorld(t)
	grantId := world.grant(t, "unsealed dial", []*protocol.AclTarget{{SidecarId: world.laptop.Bytes()}},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, false)
	details := newTestAclFollowupsDetails()
	engine := world.engine(t, world.laptop, details)
	for _, dial := range []testAclFollowupsDial{{ipProtocol: aclIpProtocolTcp, port: 22}, {ipProtocol: aclIpProtocolUdp, port: 5353}} {
		decision := engine.AllowInbound(&AclInbound{Source: AclSidecarSubject(world.phone), IpProtocol: dial.ipProtocol, Port: dial.port}, aclTestNow)
		if !decision.Allowed || !bytes.Equal(decision.Rule.GetRuleId(), grantId) {
			t.Errorf("protocol %d port %d: %+v", dial.ipProtocol, dial.port, decision)
		}
	}
	if count := details.count(grantId); count != 0 {
		t.Errorf("the opener was asked %d times for a grant sealing no detail", count)
	}
}

// Flow by flow, the desktop's engine admits exactly what the desktop's compile gives the laptop dial rows for, under a
// dial grant activated through the log with its ports sealed (tcp 22 and udp 53 at the desktop): with the key of the
// detail's generation some flows pass and some do not, and without it neither the compile nor the engine opens any.
func TestAclEngineAgreesWithTheCompileOnAnActivatedDialGrantsPorts(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	// the bridge approvers' requests rule takes the member's dial to its own devices too
	net.foldLedger(net.n, func(rows *protocol.AclRows) {
		for _, request := range rows.GetRequests() {
			if bytes.Equal(request.GetRuleId(), testBridgeRequestRuleId) {
				request.Actions = append(request.Actions, uint32(protocol.AclAction_ACL_ACTION_DIAL))
			}
		}
	})
	desktopDst := aclTestDst(net.peer.sidecarId)
	action := &protocol.CanonicalAction{
		Kind: uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD), Version: canonicalActionVersionSealedGrant,
		RuleId: testBridgeRequestRuleId, Subject: net.host.sidecarId.Bytes(),
		GrantDst: []string{desktopDst}, GrantAllow: []string{"dial"}, ExpiresMillis: net.timeMs + 60*60*1000,
	}
	testWithSealedDetail(action, &protocol.CanonicalActionDetail{GrantDst: []string{desktopDst + ":tcp:22", desktopDst + ":udp:53"}})
	grantId := net.activate("dial", testConfigMarshal(t, action))
	laptop := AclSidecarSubject(net.host.sidecarId)
	now := time.UnixMilli(net.log.State().TimeMs())
	for _, withKey := range []bool{true, false} {
		view := net.grantViewOf(net.log, withKey)
		_, rules := testBridgeCompile(t, view, net.localOf(net.peer))
		rows := []*bridge.BridgeRuleReach{}
		if subject := testBridgeCompileSubject(rules, net.host.sidecarId); subject != nil {
			rows = subject.GetDial()
		}
		admits := func(ipProtocol uint32, port uint32) bool {
			for _, row := range rows {
				if row.GetProtocol() != 0 && row.GetProtocol() != ipProtocol {
					continue
				}
				if len(row.GetPorts()) == 0 {
					return true
				}
				for _, ports := range row.GetPorts() {
					if ports.GetFirst() <= port && port <= ports.GetLast() {
						return true
					}
				}
			}
			return false
		}
		desktop := NewAclEngine(net.peer.sidecarId, nil, nil, nil)
		if err := desktop.InstallWithGrants(view.acl, view.aclLocal, newAclStateGrantDetails(view.state, view.head, view.RepoKeyAt)); err != nil {
			t.Fatal(err)
		}
		admitted, refused := 0, 0
		for _, ipProtocol := range []uint32{aclIpProtocolTcp, aclIpProtocolUdp} {
			for _, port := range []uint32{21, 22, 23, 53, 80} {
				compiled := admits(ipProtocol, port)
				decision := desktop.AllowInbound(&AclInbound{Source: laptop, IpProtocol: ipProtocol, Port: port}, now)
				allowed := decision.Allowed
				if compiled != allowed || (allowed && !bytes.Equal(decision.Rule.GetRuleId(), grantId)) {
					t.Errorf("with the key %t, protocol %d port %d: the compile admits %t, the engine allows %t", withKey, ipProtocol, port, compiled, allowed)
				}
				if allowed {
					admitted += 1
				} else {
					refused += 1
				}
			}
		}
		if withKey && (admitted == 0 || refused == 0) {
			t.Errorf("with the key the engine admitted %d flows and refused %d: they tell nothing apart", admitted, refused)
		}
		if !withKey && admitted != 0 {
			t.Errorf("without the key the engine admitted %d flows", admitted)
		}
	}
}

// Check's dial to a sidecar counts a port-limited dial grant only at a sidecar its detail names a port at, and none with
// no opener or at a client, where no detail can name a port; one sealing no detail stands at every sidecar its rows
// name, as its rows say. Before this change every check here took the rows' reach alone and allowed.
func TestAclEngineCheckDialsASubjectByAnActivatedGrantsDetail(t *testing.T) {
	world := newTestAclFollowupsWorld(t)
	clientId := world.world.id("followups legacy client")
	sealedId := world.grant(t, "sealed dial", []*protocol.AclTarget{
		{SidecarId: world.laptop.Bytes()}, {SidecarId: world.desk.Bytes()}, {ClientId: clientId.Bytes()},
	}, []protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, true)
	details := newTestAclFollowupsDetails()
	details.set(sealedId, &protocol.CanonicalActionDetail{GrantDst: []string{testAclFollowupsDst(world.laptop) + ":tcp:22"}}, nil)
	phone := AclSidecarSubject(world.phone)
	dial := func(engine *AclEngine, selector AclSelector) AclCheck {
		return engine.Check(phone, protocol.AclAction_ACL_ACTION_DIAL, AclResource{Kind: AclResourceSubject, Subject: selector}, aclTestNow)
	}
	laptop := AclSelector{Kind: AclSelectorSidecar, Id: world.laptop}
	desk := AclSelector{Kind: AclSelectorSidecar, Id: world.desk}
	client := AclSelector{Kind: AclSelectorClient, Id: clientId}

	engine := world.engine(t, world.laptop, details)
	state := engine.State()
	for _, destination := range []AclSubject{AclSidecarSubject(world.laptop), AclSidecarSubject(world.desk), AclClientSubject(clientId, Id{}, nil, "")} {
		if !state.MayDial(phone, destination, aclTestNow).Allowed {
			t.Fatalf("the rows do not take the phone's dial to %v: the refusals below would prove nothing", destination)
		}
	}
	if result := dial(engine, laptop); !result.Allowed || !bytes.Equal(result.GrantId, sealedId) {
		t.Errorf("the laptop, whose port the detail names: %+v", result)
	}
	for name, selector := range map[string]AclSelector{"the desk, named at no port": desk, "a client": client} {
		if result := dial(engine, selector); result.Allowed || result.Reason != AclReasonNoGrant {
			t.Errorf("%s: %+v", name, result)
		}
	}
	if result := dial(world.engine(t, world.laptop, nil), laptop); result.Allowed {
		t.Errorf("no opener: %+v", result)
	}

	unsealedId := world.grant(t, "unsealed dial", []*protocol.AclTarget{{SidecarId: world.desk.Bytes()}},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, false)
	if result := dial(world.engine(t, world.laptop, details), desk); !result.Allowed || !bytes.Equal(result.GrantId, unsealedId) {
		t.Errorf("a grant sealing no detail: %+v", result)
	}
}

// Check's route to a sidecar counts an activated route grant only where its detail reads, as AllowRoute and the ip
// ranges do: through the desktop with the key of its generation, and not without it, with no opener, where its action
// seals no detail, or through a sidecar its grant_dst does not name. Before this change the rows' via alone allowed.
func TestAclEngineCheckRoutesThroughASubjectByAnActivatedGrantsDetail(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	grantId := net.portedGrant("subject route", net.timeMs+60*60*1000)
	laptop := AclSidecarSubject(net.host.sidecarId)
	now := time.UnixMilli(net.log.State().TimeMs())
	route := func(engine *AclEngine, via Id) AclCheck {
		return engine.Check(laptop, protocol.AclAction_ACL_ACTION_ROUTE,
			AclResource{Kind: AclResourceSubject, Subject: AclSelector{Kind: AclSelectorSidecar, Id: via}}, now)
	}
	if result := route(net.grantEngine(net.log, true, nil), net.peer.sidecarId); !result.Allowed || !bytes.Equal(result.GrantId, grantId) {
		t.Fatalf("through the desktop with the key: %+v", result)
	}
	if result := route(net.grantEngine(net.log, true, nil), net.other.sidecarId); result.Allowed {
		t.Errorf("through a sidecar the grant does not name: %+v", result)
	}
	view := net.grantViewOf(net.log, true)
	if !view.acl.MayRoute(laptop, netip.Addr{}, AclSidecarSubject(net.peer.sidecarId), now).Allowed {
		t.Fatal("the rows do not route the laptop through the desktop: the refusals below would prove nothing")
	}
	if result := route(net.grantEngine(net.log, false, nil), net.peer.sidecarId); result.Allowed {
		t.Errorf("without the key: %+v", result)
	}
	bare := NewAclEngine(net.host.sidecarId, nil, nil, nil)
	if err := bare.Install(view.acl, nil); err != nil {
		t.Fatal(err)
	}
	if result := route(bare, net.peer.sidecarId); result.Allowed {
		t.Errorf("no opener: %+v", result)
	}

	// the same grant's rule, its action sealing no detail, as rows a base carries name it
	rows := proto.Clone(view.state.aclRows).(*protocol.AclRows)
	for _, rule := range rows.GetRules() {
		if bytes.Equal(rule.GetRuleId(), grantId) {
			rule.PortsLimited = false
		}
	}
	acl, err := NewAclState(rows, view.state)
	if err != nil {
		t.Fatal(err)
	}
	unsealed := NewAclEngine(net.host.sidecarId, nil, nil, nil)
	if err := unsealed.InstallWithGrants(acl, nil, newAclStateGrantDetails(view.state, view.head, view.RepoKeyAt)); err != nil {
		t.Fatal(err)
	}
	if result := route(unsealed, net.peer.sidecarId); result.Allowed {
		t.Errorf("a grant sealing no detail: %+v", result)
	}
}

// A grant whose detail waits on its generation's key reaches nothing until the key arrives, and then
// ReadWaitingGrants reads it, and it alone, at the same pin, state and local policy, where before this change it stayed
// closed until the next install: a route grant and a dial grant, each sealed to a generation not held, while a grant
// whose detail read at the install is kept and not opened again. A read with the key still missing changes nothing
// and says the grants still wait; one with nothing waiting reads nothing.
func TestAclEngineReadsWaitingGrantsWhenTheirKeyArrives(t *testing.T) {
	world := newTestAclFollowupsWorld(t)
	routeId := world.grant(t, "waiting route", []*protocol.AclTarget{{SidecarId: world.desk.Bytes()}},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_ROUTE}, true)
	dialId := world.grant(t, "waiting dial", []*protocol.AclTarget{{SidecarId: world.laptop.Bytes()}},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, true)
	keptId := world.grant(t, "kept route", []*protocol.AclTarget{{SidecarId: world.desk.Bytes()}},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_ROUTE}, true)
	details := newTestAclFollowupsDetails()
	details.set(routeId, nil, ErrConfigSealGenerationMissing)
	details.set(dialId, nil, ErrConfigSealGenerationMissing)
	details.set(keptId, &protocol.CanonicalActionDetail{Cidrs: []string{"198.51.100.0/24"}}, nil)
	engine := world.engine(t, world.laptop, details)
	pin, state := engine.Pin(), engine.State()
	phone := AclSidecarSubject(world.phone)
	routes := func() (bool, bool) {
		waiting := engine.Check(phone, protocol.AclAction_ACL_ACTION_ROUTE, AclResource{Kind: AclResourceIp, Cidr: netip.MustParsePrefix("203.0.113.0/28")}, aclTestNow)
		kept := engine.Check(phone, protocol.AclAction_ACL_ACTION_ROUTE, AclResource{Kind: AclResourceIp, Cidr: netip.MustParsePrefix("198.51.100.0/28")}, aclTestNow)
		return waiting.Allowed && bytes.Equal(waiting.GrantId, routeId), kept.Allowed && bytes.Equal(kept.GrantId, keptId)
	}
	dials := func() bool {
		return engine.AllowInbound(&AclInbound{Source: phone, IpProtocol: aclIpProtocolTcp, Port: 22}, aclTestNow).Allowed
	}
	if waiting, kept := routes(); waiting || !kept || dials() || !engine.grantsWaitForKey() {
		t.Fatalf("at the install: the waiting route %t, the kept one %t, the dial %t, waits %t", waiting, kept, dials(), engine.grantsWaitForKey())
	}

	// the key still missing: nothing reads, and the grants still wait
	if !engine.ReadWaitingGrants() {
		t.Error("a read without the key says nothing waits")
	}
	if waiting, _ := routes(); waiting || dials() {
		t.Error("a grant stands without its key")
	}

	// the key arrives: before the read nothing changes, after it both grants stand
	details.set(routeId, &protocol.CanonicalActionDetail{Cidrs: []string{"203.0.113.0/28"}}, nil)
	details.set(dialId, &protocol.CanonicalActionDetail{GrantDst: []string{testAclFollowupsDst(world.laptop) + ":tcp:22"}}, nil)
	if waiting, _ := routes(); waiting || dials() {
		t.Fatal("a grant stood before the read: the engine reads details at a check")
	}
	if engine.ReadWaitingGrants() {
		t.Error("the read says a grant still waits")
	}
	if waiting, kept := routes(); !waiting || !kept || !dials() {
		t.Errorf("after the read: the waiting route %t, the kept one %t, the dial %t", waiting, kept, dials())
	}
	if engine.Pin() != pin || engine.State() != state || engine.grantsWaitForKey() {
		t.Error("the read changed the installed pin or state, or still waits")
	}
	if details.count(routeId) != 3 || details.count(dialId) != 3 || details.count(keptId) != 1 {
		t.Errorf("the opener was asked %d, %d and %d times, want 3, 3 and 1", details.count(routeId), details.count(dialId), details.count(keptId))
	}
	if engine.ReadWaitingGrants() || details.count(routeId) != 3 {
		t.Error("a read with nothing waiting read again")
	}
}

// An install landing while ReadWaitingGrants reads is never undone: the read goes round again on the newer install,
// which read its grants before the key arrived, and the grant stands there, at the newer pin.
func TestAclEngineReadWaitingGrantsYieldsToAConcurrentInstall(t *testing.T) {
	world := newTestAclFollowupsWorld(t)
	grantId := world.grant(t, "raced dial", []*protocol.AclTarget{{SidecarId: world.laptop.Bytes()}},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, true)
	details := newTestAclFollowupsDetails()
	details.set(grantId, nil, ErrConfigSealGenerationMissing)
	engine := world.engine(t, world.laptop, details)
	newer := world.state(t, aclTestEnginePin(2, "followups"))
	details.setOnAsk(func() {
		// the read's ask: an install lands first, reading the grant while its key is missing, and then the key arrives
		if err := engine.InstallWithGrants(newer, nil, details); err != nil {
			t.Error(err)
		}
		details.set(grantId, &protocol.CanonicalActionDetail{GrantDst: []string{testAclFollowupsDst(world.laptop) + ":tcp:22"}}, nil)
	})
	if engine.ReadWaitingGrants() {
		t.Error("the read says the grant still waits")
	}
	if engine.Pin().GetVersion() != 2 || engine.State() != newer {
		t.Fatalf("the installed pin is %d: the read undid the newer install", engine.Pin().GetVersion())
	}
	if decision := engine.AllowInbound(&AclInbound{Source: AclSidecarSubject(world.phone), IpProtocol: aclIpProtocolTcp, Port: 22}, aclTestNow); !decision.Allowed {
		t.Errorf("the grant does not stand at the newer install: %+v", decision)
	}
}

// A grant allowing dial and route opens its detail once an install, and not again at the next install of a state
// holding it.
func TestAclEngineOpensAGrantAllowingDialAndRouteOnce(t *testing.T) {
	world := newTestAclFollowupsWorld(t)
	grantId := world.grant(t, "dial and route", []*protocol.AclTarget{{SidecarId: world.laptop.Bytes()}},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL, protocol.AclAction_ACL_ACTION_ROUTE}, true)
	details := newTestAclFollowupsDetails()
	details.set(grantId, &protocol.CanonicalActionDetail{
		Cidrs: []string{"198.51.100.0/24"}, GrantDst: []string{testAclFollowupsDst(world.laptop) + ":tcp:22"},
	}, nil)
	engine := world.engine(t, world.laptop, details)
	phone := AclSidecarSubject(world.phone)
	if !engine.AllowInbound(&AclInbound{Source: phone, IpProtocol: aclIpProtocolTcp, Port: 22}, aclTestNow).Allowed ||
		!engine.AllowRoute(phone, netip.MustParseAddr("198.51.100.7"), aclIpProtocolTcp, 22, AclSidecarSubject(world.laptop), aclTestNow).Allowed {
		t.Fatal("the grant does not stand for both")
	}
	if err := engine.InstallWithGrants(world.state(t, aclTestEnginePin(2, "followups")), nil, details); err != nil {
		t.Fatal(err)
	}
	if count := details.count(grantId); count != 1 {
		t.Errorf("the detail was opened %d times over two installs", count)
	}
}

// AllowInbound through an activated dial grant allocates nothing: its detail was read at the install.
func TestAclEngineAllowInboundThroughAnActivatedDialGrantWithoutAllocating(t *testing.T) {
	world := newTestAclFollowupsWorld(t)
	grantId := world.grant(t, "allocations", []*protocol.AclTarget{{SidecarId: world.laptop.Bytes()}},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, true)
	details := newTestAclFollowupsDetails()
	details.set(grantId, &protocol.CanonicalActionDetail{GrantDst: []string{testAclFollowupsDst(world.laptop) + ":tcp:22"}}, nil)
	engine := world.engine(t, world.laptop, details)
	allowed := &AclInbound{Source: AclSidecarSubject(world.phone), IpProtocol: aclIpProtocolTcp, Port: 22}
	refused := &AclInbound{Source: AclSidecarSubject(world.phone), IpProtocol: aclIpProtocolTcp, Port: 23}
	if !engine.AllowInbound(allowed, aclTestNow).Allowed {
		t.Fatal("the grant does not stand")
	}
	for _, inbound := range []*AclInbound{allowed, refused} {
		if allocs := testing.AllocsPerRun(100, func() { engine.AllowInbound(inbound, aclTestNow) }); allocs != 0 {
			t.Errorf("port %d: %v allocations", inbound.Port, allocs)
		}
	}
}

// A keychain of the config repo's generation keys that signals each generation it takes, as GkmGroupClient's
// RepoKeyHeld does: one channel armed at a time, made at an arm and closed at the next generation taken. onArm runs once,
// at the next arm, before the channel is made. Safe for concurrent use.
type testAclFollowupsKeychain struct {
	stateLock    sync.Mutex
	configRepoId Id
	keys         []*EvsRepoKey
	armed        chan struct{}
	onArm        func()
	// the repos asked for, by RepoKeyHeld and held alike
	askedRepoIds []Id
}

func (self *testAclFollowupsKeychain) held(repoId Id, generation uint64) *EvsRepoKey {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.askedRepoIds = append(self.askedRepoIds, repoId)
	if repoId != self.configRepoId {
		return nil
	}
	return testConfigSealKeyAt(self.keys...)(generation)
}

func (self *testAclFollowupsKeychain) repoKeyHeld(repoId Id) (bool, <-chan struct{}) {
	onArm := func() func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		onArm := self.onArm
		self.onArm = nil
		return onArm
	}()
	if onArm != nil {
		onArm()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.askedRepoIds = append(self.askedRepoIds, repoId)
	if self.armed == nil {
		self.armed = make(chan struct{})
	}
	return len(self.keys) != 0, self.armed
}

// Takes a key, closing the armed channel if one is armed.
func (self *testAclFollowupsKeychain) take(key *EvsRepoKey) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.keys = append(self.keys, key)
	if self.armed != nil {
		close(self.armed)
		self.armed = nil
	}
}

// Whether every repo asked for was the config repo.
func (self *testAclFollowupsKeychain) askedConfigRepoAlone() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return 0 < len(self.askedRepoIds) && !slices.ContainsFunc(self.askedRepoIds, func(repoId Id) bool { return repoId != self.configRepoId })
}

// A follower of the net's tip on the laptop's engine over the keychain, waking on its signal where watch says.
func testAclFollowupsFollower(t *testing.T, net *testBridgeGrantNet, source *aclTestFollowSource, keychain *testAclFollowupsKeychain, watch bool) (*AclFollower, *AclEngine) {
	t.Helper()
	settings := DefaultAclSettings()
	settings.Clock = newTestConfigClock()
	settings.Log = NewNoopLogger()
	engine := NewAclEngine(net.host.sidecarId, nil, nil, nil)
	args := &AclFollowerArgs{Source: source, Engine: engine, HeldRepoKey: keychain.held, Settings: settings}
	if watch {
		args.RepoKeyHeld = keychain.repoKeyHeld
	}
	follower, err := NewAclFollower(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(follower.Close)
	return follower, engine
}

// Waits until the follower's state holds no grant waiting on a key, failing the test after a minute of none.
func testAclFollowupsWaitKeys(t *testing.T, follower *AclFollower) {
	t.Helper()
	for {
		waits, changed := follower.keyWaits.Get()
		if !waits {
			return
		}
		select {
		case <-changed:
		case <-time.After(time.Minute):
			t.Fatal("the follower's grants still wait on a key a minute on")
		}
	}
}

// The acl follower reads a grant that waited on its generation's key again when the keychain takes the key, with no
// entry, base or install: before, the grant stayed closed at the engine until the next one, as a follower with no
// keychain signal still leaves it, even when its source calls back with the same state.
func TestAclFollowerReadsWaitingGrantsWhenTheKeychainTakesAGeneration(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	grantId := net.portedGrant("follower key", net.timeMs+60*60*1000)
	state := net.log.State()
	configRepoId, ok := aclFollowerConfigRepoId(state)
	if !ok {
		t.Fatal("the net's genesis names no config repo")
	}
	laptop := AclSidecarSubject(net.host.sidecarId)
	now := time.UnixMilli(state.TimeMs())
	routes := func(engine *AclEngine) bool {
		result := engine.Check(laptop, protocol.AclAction_ACL_ACTION_ROUTE, AclResource{Kind: AclResourceIp, Cidr: netip.MustParsePrefix("192.168.7.0/26")}, now)
		return result.Allowed && bytes.Equal(result.GrantId, grantId)
	}

	keychain := &testAclFollowupsKeychain{configRepoId: configRepoId}
	source := &aclTestFollowSource{state: state}
	follower, engine := testAclFollowupsFollower(t, net, source, keychain, true)
	if routes(engine) || !follower.keyWaits.Value() {
		t.Fatalf("before the key: the grant stands %t, the follower sees it wait %t", routes(engine), follower.keyWaits.Value())
	}
	keychain.take(testConfigSealKey(testActionDetailGeneration))
	testAclFollowupsWaitKeys(t, follower)
	if !routes(engine) {
		t.Error("the grant does not stand once its key is taken")
	}
	if stats := follower.Stats(); stats.InstallCount != 1 {
		t.Errorf("%d installs: the key's read is no install", stats.InstallCount)
	}
	if !keychain.askedConfigRepoAlone() {
		t.Error("the follower asked the keychain for another repo than the config repo")
	}

	// with no keychain signal the grant stays closed after the key arrives, the same state called back included
	unwatched := &testAclFollowupsKeychain{configRepoId: configRepoId}
	unwatchedSource := &aclTestFollowSource{state: state}
	_, unwatchedEngine := testAclFollowupsFollower(t, net, unwatchedSource, unwatched, false)
	unwatched.take(testConfigSealKey(testActionDetailGeneration))
	unwatchedSource.applied(state)
	if routes(unwatchedEngine) {
		t.Error("a follower with no keychain signal read the grant again")
	}
}

// The key watch arms the keychain's signal before it reads: a key taken just before the arm, when no channel is armed to
// close, is in the read that follows it, so the grant stands with no further signal.
func TestAclFollowerReadsAKeyTakenBeforeItsWatchArms(t *testing.T) {
	net := newTestBridgeGrantNet(t)
	grantId := net.portedGrant("follower arm", net.timeMs+60*60*1000)
	state := net.log.State()
	configRepoId, ok := aclFollowerConfigRepoId(state)
	if !ok {
		t.Fatal("the net's genesis names no config repo")
	}
	keychain := &testAclFollowupsKeychain{configRepoId: configRepoId}
	keychain.onArm = func() {
		keychain.take(testConfigSealKey(testActionDetailGeneration))
	}
	follower, engine := testAclFollowupsFollower(t, net, &aclTestFollowSource{state: state}, keychain, true)
	testAclFollowupsWaitKeys(t, follower)
	result := engine.Check(AclSidecarSubject(net.host.sidecarId), protocol.AclAction_ACL_ACTION_ROUTE,
		AclResource{Kind: AclResourceIp, Cidr: netip.MustParsePrefix("192.168.7.0/26")}, time.UnixMilli(state.TimeMs()))
	if !result.Allowed || !bytes.Equal(result.GrantId, grantId) {
		t.Errorf("the grant does not stand: %+v", result)
	}
}
