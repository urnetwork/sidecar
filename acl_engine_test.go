// AclEngine: lock-free checks across an Install, a lower pin and a fork refused with the old state kept, the client's
// narrowing of ports, prefixes, socket globs and aliases from AclLocalPolicy, and the Verify checks at a pin. Pure, on
// every leg.

package sidecar

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A fake of the log's states, by version.
type aclTestEngineStates struct {
	states map[uint64]*AclState
	tip    uint64
	// below this the log retains nothing
	floor uint64
}

func (self *aclTestEngineStates) AclStateAt(pin *bridge.AuthPin) (*AclState, error) {
	switch {
	case self.tip < pin.GetVersion():
		return nil, ErrConfigPinAhead
	case pin.GetVersion() < self.floor:
		return nil, ErrConfigPinNotRetained
	}
	state := self.states[pin.GetVersion()]
	if state == nil || string(state.Pin().GetChain()) != string(pin.GetChain()) {
		return nil, ErrConfigPinOffChain
	}
	return state, nil
}

// A pin at n with a chain fixed by a label.
func aclTestEnginePin(n uint64, label string) *bridge.AuthPin {
	chain := make([]byte, 32)
	copy(chain, fmt.Sprintf("%d %s", n, label))
	return &bridge.AuthPin{Version: n, Chain: chain}
}

// The engine world: a member's laptop that receives, a phone that dials, a router, and a document that limits ports,
// routes a prefix through the router, dials a socket glob and sends to an alias glob.
type aclEngineWorld struct {
	world  *aclCompileWorld
	laptop Id
	phone  Id
	router Id
	agent  Id
}

func newAclEngineWorld(t testing.TB) *aclEngineWorld {
	world := newAclCompileWorld("engine")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	engine := &aclEngineWorld{world: world}
	engine.laptop = world.device("laptop", owner)
	engine.phone = world.device("phone", owner)
	engine.router = world.agent("router", owner, "router")
	engine.agent = world.agent("agent", owner, "worker")
	world.setPolicy(t, `{
  "tagOwners": { "tag:router": ["autogroup:admin"], "tag:worker": ["autogroup:admin"] },
  "grants": [
    { "src": ["autogroup:member"], "dst": ["autogroup:member"], "allow": ["dial"], "ip": ["tcp:22", "udp:5000-5010"] },
    { "src": ["autogroup:member"], "dst": ["ip:192.0.2.0/24"], "via": ["tag:router"], "allow": ["route"], "ip": ["tcp:443"] },
    { "src": ["tag:worker"], "dst": ["sock:app/db*"], "allow": ["dial"] },
    { "src": ["tag:worker"], "dst": ["mail:ops-*"], "allow": ["send"] },
  ],
}`)
	return engine
}

// The state and local policy at a pin.
func (self *aclEngineWorld) install(t testing.TB, pin *bridge.AuthPin) (*AclState, *AclLocalPolicy) {
	t.Helper()
	view := self.world.view()
	view.pin = pin
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

// Nothing is allowed before an Install.
func TestAclEngineRefusesWithNothingInstalled(t *testing.T) {
	engine := NewAclEngine(NewId(), nil, nil, nil)
	if decision := engine.AllowInbound(&AclInbound{Source: AclSidecarSubject(NewId()), IpProtocol: 6, Port: 22}, aclTestNow); decision.Allowed || decision.Reason != AclReasonNoState {
		t.Fatalf("%+v", decision)
	}
	if engine.Pin() != nil {
		t.Fatal("a pin before an Install")
	}
}

// A dial's ports come from the rule's local detail, which rows lack (plan-BRIDGE-gate-row-prefixes #1): the receiver
// opens exactly the ports its rule names.
func TestAclEngineAllowInboundChecksPortsLocally(t *testing.T) {
	world := newAclEngineWorld(t)
	state, local := world.install(t, aclTestEnginePin(1, "a"))
	engine := NewAclEngine(world.laptop, nil, nil, nil)
	if err := engine.Install(state, local); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ipProtocol uint32
		port       uint32
		allowed    bool
	}{
		{ipProtocol: aclIpProtocolTcp, port: 22, allowed: true},
		{ipProtocol: aclIpProtocolUdp, port: 22, allowed: false},
		{ipProtocol: aclIpProtocolUdp, port: 5005, allowed: true},
		{ipProtocol: aclIpProtocolTcp, port: 5005, allowed: false},
		{ipProtocol: aclIpProtocolTcp, port: 80, allowed: false},
	}
	for i, c := range cases {
		inbound := &AclInbound{Source: AclSidecarSubject(world.phone), IpProtocol: c.ipProtocol, Port: c.port}
		if decision := engine.AllowInbound(inbound, aclTestNow); decision.Allowed != c.allowed {
			t.Errorf("case %d: allowed %t (%s)", i, decision.Allowed, decision.Reason)
		}
	}
	// without local detail a port-limited rule opens no port
	bare := NewAclEngine(world.laptop, nil, nil, nil)
	if err := bare.Install(state, nil); err != nil {
		t.Fatal(err)
	}
	if decision := bare.AllowInbound(&AclInbound{Source: AclSidecarSubject(world.phone), IpProtocol: aclIpProtocolTcp, Port: 22}, aclTestNow); decision.Allowed {
		t.Error("a port-limited rule opened a port with no detail")
	}
}

// A route rule's prefix and ports are the client's: the router's engine takes 192.0.2.0/24 on tcp:443 only.
func TestAclEngineAllowRouteChecksPrefixesLocally(t *testing.T) {
	world := newAclEngineWorld(t)
	state, local := world.install(t, aclTestEnginePin(1, "a"))
	engine := NewAclEngine(world.router, nil, nil, nil)
	if err := engine.Install(state, local); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		address string
		port    uint32
		via     Id
		allowed bool
	}{
		{address: "192.0.2.7", port: 443, via: world.router, allowed: true},
		{address: "192.0.2.7", port: 80, via: world.router, allowed: false},
		{address: "198.51.100.7", port: 443, via: world.router, allowed: false},
		{address: "192.0.2.7", port: 443, via: world.agent, allowed: false},
	}
	for i, c := range cases {
		decision := engine.AllowRoute(AclSidecarSubject(world.phone), netip.MustParseAddr(c.address), aclIpProtocolTcp, c.port, AclSidecarSubject(c.via), aclTestNow)
		if decision.Allowed != c.allowed {
			t.Errorf("case %d: allowed %t (%s)", i, decision.Allowed, decision.Reason)
		}
	}
}

// A socket's exact glob and an alias are the client's: rows carry the glob's literal prefix and mail_send alone.
func TestAclEngineChecksSocketGlobsAndAliases(t *testing.T) {
	world := newAclEngineWorld(t)
	state, local := world.install(t, aclTestEnginePin(1, "a"))
	engine := NewAclEngine(world.laptop, nil, nil, nil)
	if err := engine.Install(state, local); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name    string
		allowed bool
	}{
		{name: "app/db1", allowed: true},
		{name: "app/web", allowed: false},
	} {
		inbound := &AclInbound{Source: AclSidecarSubject(world.agent), SocketName: c.name, NameToken: world.world.tokenPath(t, c.name)}
		if decision := engine.AllowInbound(inbound, aclTestNow); decision.Allowed != c.allowed {
			t.Errorf("socket %s: allowed %t (%s)", c.name, decision.Allowed, decision.Reason)
		}
	}
	for _, c := range []struct {
		alias   string
		allowed bool
	}{
		{alias: "ops-pager", allowed: true},
		{alias: "billing", allowed: false},
	} {
		if decision := engine.AllowAlias(AclSidecarSubject(world.agent), protocol.AclAction_ACL_ACTION_SEND, c.alias, aclTestNow); decision.Allowed != c.allowed {
			t.Errorf("alias %s: allowed %t (%s)", c.alias, decision.Allowed, decision.Reason)
		}
	}
	if check := engine.Check(AclSidecarSubject(world.agent), protocol.AclAction_ACL_ACTION_DIAL, AclResource{Kind: AclResourceSocket, Name: "app/db2"}, aclTestNow); !check.Allowed || len(check.GrantId) == 0 {
		t.Errorf("Check of a socket: %+v", check)
	}
	if check := engine.Check(AclSidecarSubject(world.agent), protocol.AclAction_ACL_ACTION_DIAL, AclResource{Kind: AclResourceSocket, Name: "app/web"}, aclTestNow); check.Allowed {
		t.Errorf("Check of another socket: %+v", check)
	}
}

// A lower pin and a second A_n at one n are refused with an alarm, and the installed state stays (I-16).
func TestAclEngineInstallRefusesLowerAndForkedPins(t *testing.T) {
	world := newAclEngineWorld(t)
	alarms := []AclEngineAlarm{}
	engine := NewAclEngine(world.laptop, nil, func(alarm AclEngineAlarm) { alarms = append(alarms, alarm) }, nil)
	state5, local := world.install(t, aclTestEnginePin(5, "a"))
	if err := engine.Install(state5, local); err != nil {
		t.Fatal(err)
	}
	state4, _ := world.install(t, aclTestEnginePin(4, "a"))
	if err := engine.Install(state4, local); !errors.Is(err, ErrAclEnginePinLower) {
		t.Fatalf("a lower pin: %v", err)
	}
	fork, _ := world.install(t, aclTestEnginePin(5, "b"))
	if err := engine.Install(fork, local); !errors.Is(err, ErrAclEngineFork) {
		t.Fatalf("a fork: %v", err)
	}
	if engine.State() != state5 || len(alarms) != 2 || alarms[0].Kind != AclEngineAlarmPinLower || alarms[1].Kind != AclEngineAlarmFork {
		t.Fatalf("state %v, alarms %+v", engine.Pin(), alarms)
	}
	state6, _ := world.install(t, aclTestEnginePin(6, "a"))
	if err := engine.Install(state6, local); err != nil || engine.Pin().GetVersion() != 6 {
		t.Fatalf("a higher pin: %v", err)
	}
}

// Checks run while Installs swap states, under -race: each answer is one whole state's.
func TestAclEngineChecksDuringInstall(t *testing.T) {
	world := newAclEngineWorld(t)
	engine := NewAclEngine(world.laptop, nil, nil, nil)
	states := []*AclState{}
	locals := []*AclLocalPolicy{}
	for n := uint64(1); n <= 64; n += 1 {
		state, local := world.install(t, aclTestEnginePin(n, "a"))
		states = append(states, state)
		locals = append(locals, local)
	}
	if err := engine.Install(states[0], locals[0]); err != nil {
		t.Fatal(err)
	}
	inbound := &AclInbound{Source: AclSidecarSubject(world.phone), IpProtocol: aclIpProtocolTcp, Port: 22}
	wait := sync.WaitGroup{}
	refused := make(chan string, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 256 {
				if decision := engine.AllowInbound(inbound, aclTestNow); !decision.Allowed {
					refused <- decision.Reason.String()
					return
				}
			}
		}()
	}
	for i := 1; i < len(states); i += 1 {
		if err := engine.Install(states[i], locals[i]); err != nil {
			t.Fatal(err)
		}
	}
	wait.Wait()
	close(refused)
	for reason := range refused {
		t.Errorf("a check during an Install refused: %s", reason)
	}
}

// The checks a packet or stream path runs allocate nothing.
func TestAclEngineChecksDoNotAllocate(t *testing.T) {
	world := newAclEngineWorld(t)
	state, local := world.install(t, aclTestEnginePin(1, "a"))
	engine := NewAclEngine(world.router, nil, nil, nil)
	if err := engine.Install(state, local); err != nil {
		t.Fatal(err)
	}
	inbound := &AclInbound{Source: AclSidecarSubject(world.phone), IpProtocol: aclIpProtocolTcp, Port: 22}
	address := netip.MustParseAddr("192.0.2.7")
	checks := map[string]func(){
		"AllowInbound": func() { engine.AllowInbound(inbound, aclTestNow) },
		"AllowRoute": func() {
			engine.AllowRoute(AclSidecarSubject(world.phone), address, aclIpProtocolTcp, 443, AclSidecarSubject(world.router), aclTestNow)
		},
	}
	for name, check := range checks {
		if allocs := testing.AllocsPerRun(100, check); allocs != 0 {
			t.Errorf("%s: %v allocations", name, allocs)
		}
	}
}

// VerifyHeadSigner judges at the push's pin: a writer before its removal passes there and fails after it; a pin above
// the tip waits, one before what the log retains is unjudged, and one off the chain alarms.
func TestAclEngineVerifyHeadSignerAtThePushsPin(t *testing.T) {
	world := newAclCompileWorld("head signer")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	writer := world.device("writer", owner)
	repoId := world.repo("notes", protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	world.policy = nil
	before := world.view()
	before.pin = aclTestEnginePin(5, "a")
	stateBefore, err := NewAclState(world.compile(t), before)
	if err != nil {
		t.Fatal(err)
	}
	// the writer's member leaves at 6
	after := world.view()
	after.pin = aclTestEnginePin(6, "a")
	delete(after.members, owner)
	stateAfter, err := NewAclState(world.compile(t), after)
	if err != nil {
		t.Fatal(err)
	}
	states := &aclTestEngineStates{states: map[uint64]*AclState{5: stateBefore, 6: stateAfter}, tip: 6, floor: 3}
	alarms := []AclEngineAlarm{}
	engine := NewAclEngine(writer, states, func(alarm AclEngineAlarm) { alarms = append(alarms, alarm) }, nil)
	if err := engine.Install(stateAfter, nil); err != nil {
		t.Fatal(err)
	}
	if err := engine.VerifyHeadSigner(repoId, writer, aclTestEnginePin(5, "a"), aclTestNow); err != nil {
		t.Errorf("before the removal: %v", err)
	}
	if err := engine.VerifyHeadSigner(repoId, writer, aclTestEnginePin(6, "a"), aclTestNow); err == nil {
		t.Error("after the removal the writer passed")
	}
	if err := engine.VerifyHeadSigner(repoId, writer, aclTestEnginePin(7, "a"), aclTestNow); !errors.Is(err, ErrConfigPinAhead) {
		t.Errorf("a pin above the tip: %v", err)
	}
	if err := engine.VerifyHeadSigner(repoId, writer, aclTestEnginePin(2, "a"), aclTestNow); !errors.Is(err, ErrConfigPinNotRetained) {
		t.Errorf("a pin before the previous base: %v", err)
	}
	if err := engine.VerifyHeadSigner(repoId, writer, aclTestEnginePin(5, "b"), aclTestNow); !errors.Is(err, ErrConfigPinOffChain) || len(alarms) != 1 || alarms[0].Kind != AclEngineAlarmPinOffChain {
		t.Errorf("an off-chain pin: %v, alarms %+v", err, alarms)
	}
}

func BenchmarkAclEngineAllowInbound(b *testing.B) {
	world := newAclEngineWorld(b)
	state, local := world.install(b, aclTestEnginePin(1, "a"))
	engine := NewAclEngine(world.laptop, nil, nil, nil)
	if err := engine.Install(state, local); err != nil {
		b.Fatal(err)
	}
	inbound := &AclInbound{Source: AclSidecarSubject(world.phone), IpProtocol: aclIpProtocolTcp, Port: 22}
	b.ReportAllocs()
	for b.Loop() {
		engine.AllowInbound(inbound, aclTestNow)
	}
}

func BenchmarkAclEngineAllowRoute(b *testing.B) {
	world := newAclEngineWorld(b)
	state, local := world.install(b, aclTestEnginePin(1, "a"))
	engine := NewAclEngine(world.router, nil, nil, nil)
	if err := engine.Install(state, local); err != nil {
		b.Fatal(err)
	}
	address := netip.MustParseAddr("192.0.2.7")
	b.ReportAllocs()
	for b.Loop() {
		engine.AllowRoute(AclSidecarSubject(world.phone), address, aclIpProtocolTcp, 443, AclSidecarSubject(world.router), aclTestNow)
	}
}
