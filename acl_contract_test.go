//go:build !sidecar_http && !ios_extension

// The contract gate on hand-made rows and a fake view (T2's shape, no sleeps): the forward rule, a companion checked
// reversed, a reply waiting on its origin, the witness exception and each peer it refuses, every NoPermission refusal,
// D-ACL-5's legacy rule, the head-row miss, a cold network refused, the heads snapshot and its loads, a decision that
// allocates nothing, and the gate over a real AclGateCache. The server's TestCreateContractAcl* run the same rule
// through CreateContract.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	_ AclContractStateSource = (*AclGateCache)(nil)
	_ AclGateSource          = (*AclGateApiSource)(nil)
)

// A state source over hand-made states, counting the loads it is asked for.
type aclContractTestStates struct {
	stateLock sync.Mutex
	snapshots map[Id]*AclGateSnapshot
	reads     int
	changed   []Id
}

func newAclContractTestStates() *aclContractTestStates {
	return &aclContractTestStates{snapshots: map[Id]*AclGateSnapshot{}}
}

func (self *aclContractTestStates) State(networkId Id) (*AclGateSnapshot, AclGateStatus) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reads += 1
	snapshot := self.snapshots[networkId]
	if snapshot == nil {
		return nil, AclGateUnknown
	}
	return snapshot, AclGateLoaded
}

func (self *aclContractTestStates) Changed(networkId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.changed = append(self.changed, networkId)
}

// Installs a network's state.
func (self *aclContractTestStates) install(networkId Id, state *AclState) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.snapshots[networkId] = &AclGateSnapshot{Pin: state.Pin(), Acl: state}
}

// What the source was asked: its reads and the networks it was asked to load.
func (self *aclContractTestStates) asked() (int, []Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.reads, slices.Clone(self.changed)
}

// A heads source a test rewrites, whose loads may fail or be held.
type aclContractTestHeads struct {
	stateLock sync.Mutex
	heads     map[Id]uint64
	err       error
	hold      chan struct{}
}

func (self *aclContractTestHeads) Heads(ctx context.Context) (map[Id]uint64, error) {
	hold := func() chan struct{} {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.hold
	}()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return nil, self.err
	}
	heads := map[Id]uint64{}
	for networkId, version := range self.heads {
		heads[networkId] = version
	}
	return heads, nil
}

// Sets what the next loads answer.
func (self *aclContractTestHeads) set(heads map[Id]uint64, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.heads, self.err = heads, err
}

// A gate over states and heads on a test clock whose loads report on the returned channel. The first load has finished
// when it returns, unless heads holds it.
func newAclContractTestGate(t *testing.T, states AclContractStateSource, heads *aclContractTestHeads) (*AclContractGate, *aclGateTestClock, chan error) {
	t.Helper()
	clock := newAclGateTestClock()
	loads := make(chan error, 64)
	settings := DefaultAclContractGateSettings()
	settings.Log = NewNoopLogger()
	settings.OnHeads = func(networkCount int, err error) {
		loads <- err
	}
	gate := NewAclContractGate(context.Background(), states, heads, clock, settings)
	t.Cleanup(gate.Close)
	if heads.hold == nil {
		aclContractTestNextLoad(t, loads)
		<-clock.armed
	}
	return gate, clock, loads
}

// Waits for the next heads load to finish, failing after a real-time bound only a broken gate reaches.
func aclContractTestNextLoad(t *testing.T, loads chan error) error {
	t.Helper()
	select {
	case err := <-loads:
		return err
	case <-time.After(30 * time.Second):
		t.Fatal("no heads load finished")
	}
	return nil
}

// One network with a head row and its state, for the rule's cases.
type aclContractTestNet struct {
	fixture   *aclTestFixture
	networkId Id
	owner     Id
	states    *aclContractTestStates
	heads     *aclContractTestHeads
}

func newAclContractTestNet() *aclContractTestNet {
	fixture := newAclTestFixture()
	self := &aclContractTestNet{
		fixture:   fixture,
		networkId: NewId(),
		owner:     fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER),
		states:    newAclContractTestStates(),
		heads:     &aclContractTestHeads{},
	}
	self.heads.set(map[Id]uint64{self.networkId: 1}, nil)
	return self
}

// The gate with the fixture's rows installed as the network's state.
func (self *aclContractTestNet) gate(t *testing.T) *AclContractGate {
	t.Helper()
	self.states.install(self.networkId, self.fixture.state(t))
	gate, _, _ := newAclContractTestGate(t, self.states, self.heads)
	return gate
}

// A sidecar end of the network.
func (self *aclContractTestNet) sidecarEnd(sidecarId Id) AclContractEnd {
	return AclContractEnd{Known: true, NetworkId: self.networkId, SubjectClientId: NewId(), SidecarId: sidecarId, SidecarHeld: true}
}

// A client end of the network that is no sidecar: an app device of memberId, or with no member a legacy client.
func (self *aclContractTestNet) clientEnd(clientId Id, memberId Id, aclEnforcing bool) AclContractEnd {
	return AclContractEnd{Known: true, NetworkId: self.networkId, SubjectClientId: clientId, MemberId: memberId, AclEnforcing: aclEnforcing}
}

// A sidecar subject's derived atom, named in a rule's src or dst.
func (self *aclContractTestNet) sidecarAtom(sidecarId Id) Id {
	return self.fixture.sidecarAtom(sidecarId)
}

// A rule letting src's sidecar dial dst's.
func (self *aclContractTestNet) dial(src Id, dst Id) *protocol.AclRule {
	return self.fixture.rule([]Id{self.sidecarAtom(src)}, []*protocol.AclTarget{aclSidecarTarget(dst)}, protocol.AclAction_ACL_ACTION_DIAL)
}

func aclContractDecide(gate *AclContractGate, source AclContractEnd, destination AclContractEnd, companion bool) AclContractVerdict {
	return gate.Decide(&AclContractRequest{Source: source, Destination: destination, Companion: companion}, aclTestNow)
}

// Non-companion a→b needs reach(a,b), and allows it as data under the rule that grants it.
func TestAclContractGateForwardNeedsReach(t *testing.T) {
	net := newAclContractTestNet()
	a, b := net.fixture.device(net.owner), net.fixture.device(net.owner)
	rule := net.dial(a, b)
	gate := net.gate(t)

	verdict := aclContractDecide(gate, net.sidecarEnd(a), net.sidecarEnd(b), false)
	if verdict.Outcome != AclContractAllow || verdict.Class != AclContractClassData || verdict.Reason != AclContractReasonReach ||
		verdict.Decision.Rule != rule || verdict.NetworkId != net.networkId {
		t.Fatalf("forward: %+v", verdict)
	}
	// reach(a,b) is no reach(b,a): b's non-companion request to a is a reply, data once a's origin stands
	reply := aclContractDecide(gate, net.sidecarEnd(b), net.sidecarEnd(a), false)
	if reply.Outcome != AclContractReply || reply.Decision.Rule != rule || reply.Allowed() {
		t.Fatalf("reply: %+v", reply)
	}
	if withOrigin := reply.Origin(true); withOrigin.Outcome != AclContractAllow || withOrigin.Class != AclContractClassData || withOrigin.Reason != AclContractReasonReply {
		t.Errorf("reply with its origin: %+v", withOrigin)
	}
	// with no origin, two admitted sidecars still witness each other
	if withoutOrigin := reply.Origin(false); withoutOrigin.Outcome != AclContractAllow || withoutOrigin.Class != AclContractClassControl || withoutOrigin.Reason != AclContractReasonWitness {
		t.Errorf("reply with no origin: %+v", withoutOrigin)
	}
	if forward := verdict.Origin(false); forward != verdict {
		t.Errorf("Origin changed a verdict that is no reply: %+v", forward)
	}
}

// A companion a→b answers b, so it needs reach(b,a), the reverse of what the request names (D-ACL-4).
func TestAclContractGateChecksACompanionReversed(t *testing.T) {
	net := newAclContractTestNet()
	a := net.fixture.device(net.owner)
	appDevice := NewId()
	// a may dial the app device; the app device may dial nothing
	rule := net.fixture.rule([]Id{net.sidecarAtom(a)}, []*protocol.AclTarget{{ClientId: appDevice.Bytes()}}, protocol.AclAction_ACL_ACTION_DIAL)
	gate := net.gate(t)
	sidecar, app := net.sidecarEnd(a), net.clientEnd(appDevice, net.owner, true)

	if verdict := aclContractDecide(gate, app, sidecar, true); verdict.Outcome != AclContractAllow || verdict.Decision.Rule != rule {
		t.Errorf("the app device's companion to a, which a reaches: %+v", verdict)
	}
	// a's companion to the app device needs the app device's reach to a, and nothing grants it; no witness, since
	// one end is no sidecar
	if verdict := aclContractDecide(gate, sidecar, app, true); verdict.Outcome != AclContractRefuse || verdict.Reason != AclContractReasonNoReach {
		t.Errorf("a's companion to the app device: %+v", verdict)
	}
	// the same pair as non-companions: a reaches it, and the app device's request is only a reply
	if verdict := aclContractDecide(gate, sidecar, app, false); verdict.Outcome != AclContractAllow {
		t.Errorf("a's forward: %+v", verdict)
	}
	reply := aclContractDecide(gate, app, sidecar, false)
	if reply.Outcome != AclContractReply {
		t.Fatalf("the app device's non-companion: %+v", reply)
	}
	if withoutOrigin := reply.Origin(false); withoutOrigin.Outcome != AclContractRefuse || withoutOrigin.Reason != AclContractReasonNoReach || withoutOrigin.Class != 0 {
		t.Errorf("its reply with no origin: %+v", withoutOrigin)
	}
}

// Two admitted sidecars of one network get control with no reach grant, and each peer the exception does not cover
// is refused.
func TestAclContractGateWitnessException(t *testing.T) {
	cases := []struct {
		name string
		edit func(net *aclContractTestNet, b Id)
		// what b's end carries
		end   func(net *aclContractTestNet, b Id) AclContractEnd
		allow bool
	}{
		{name: "admitted", allow: true},
		{name: "revoked", edit: func(net *aclContractTestNet, b Id) {
			net.fixture.admission(b).Row.RevokedAt = net.fixture.next()
		}},
		{name: "parked", edit: func(net *aclContractTestNet, b Id) {
			net.fixture.view.parked[b] = true
		}},
		{name: "suspended", edit: func(net *aclContractTestNet, b Id) {
			net.fixture.rows.Suspensions = append(net.fixture.rows.Suspensions, &protocol.AclSuspension{Subject: b.Bytes(), SuspendId: NewId().Bytes()})
		}},
		{name: "past its not_after", edit: func(net *aclContractTestNet, b Id) {
			net.fixture.admission(b).Row.NotAfter = aclTestNow.UnixMilli()
		}},
		{name: "unadmitted", end: func(net *aclContractTestNet, b Id) AclContractEnd {
			return net.sidecarEnd(NewId())
		}},
		{name: "halted by the caller", end: func(net *aclContractTestNet, b Id) AclContractEnd {
			end := net.sidecarEnd(b)
			end.Deny = AclReasonAbuseHalt
			return end
		}},
		{name: "an app device", end: func(net *aclContractTestNet, b Id) AclContractEnd {
			return net.clientEnd(NewId(), net.owner, true)
		}},
	}
	for _, c := range cases {
		net := newAclContractTestNet()
		a, b := net.fixture.device(net.owner), net.fixture.device(net.owner)
		if c.edit != nil {
			c.edit(net, b)
		}
		gate := net.gate(t)
		end := net.sidecarEnd(b)
		if c.end != nil {
			end = c.end(net, b)
		}
		for _, companion := range []bool{false, true} {
			verdict := aclContractDecide(gate, net.sidecarEnd(a), end, companion)
			switch {
			case c.allow && (verdict.Outcome != AclContractAllow || verdict.Class != AclContractClassControl || verdict.Reason != AclContractReasonWitness):
				t.Errorf("%s, companion %t: %+v", c.name, companion, verdict)
			case !c.allow && (verdict.Outcome != AclContractRefuse || verdict.Class != 0):
				t.Errorf("%s, companion %t: %+v", c.name, companion, verdict)
			}
		}
	}
}

// Every NoPermission refusal the rule names, each against a pair the rule would otherwise allow.
func TestAclContractGateRefusesWithNoPermission(t *testing.T) {
	net := newAclContractTestNet()
	tag := net.fixture.tag(net.owner)
	a, b := net.fixture.device(net.owner), net.fixture.device(net.owner)
	agent := net.fixture.agent(net.owner, tag)
	net.dial(a, b)
	net.dial(b, a)
	revoked := net.fixture.device(net.owner)
	net.fixture.admission(revoked).Row.RevokedAt = net.fixture.next()
	egressRows, err := proto.Marshal(&bridge.BridgeRows{Egress: []*bridge.BridgeEgressRow{
		{Subject: tag.Bytes(), Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS},
		{Subject: b.Bytes(), Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE},
	}})
	if err != nil {
		t.Fatal(err)
	}
	net.fixture.rows.Bridge = egressRows
	gate := net.gate(t)
	provider := AclContractEnd{Known: true, NetworkId: NewId(), SubjectClientId: NewId()}

	hosted := net.sidecarEnd(a)
	hosted.Hosted = true
	declared := net.sidecarEnd(a)
	declared.DeclaresNoEgress = true
	unbound := net.sidecarEnd(Id{})
	unresolved := net.clientEnd(Id{}, net.owner, true)
	cases := []struct {
		name        string
		source      AclContractEnd
		destination AclContractEnd
		reason      AclContractReason
	}{
		{name: "a hosted device's Network contract", source: hosted, destination: net.sidecarEnd(b), reason: AclContractReasonHosted},
		{name: "a declared client's Public contract", source: declared, destination: provider, reason: AclContractReasonDeclaredNoEgress},
		{name: "a tag in exits", source: net.sidecarEnd(agent), destination: provider, reason: AclContractReasonEgress},
		{name: "a sidecar in none", source: net.sidecarEnd(b), destination: provider, reason: AclContractReasonEgress},
		{name: "a revoked sidecar's Public contract", source: net.sidecarEnd(revoked), destination: provider, reason: AclContractReasonDenied},
		{name: "a sidecar's client with no binding", source: unbound, destination: net.sidecarEnd(b), reason: AclContractReasonSubjectUnknown},
		{name: "a child whose subject is unresolved", source: unresolved, destination: net.sidecarEnd(b), reason: AclContractReasonSubjectUnknown},
		{name: "a client the server does not have", source: net.sidecarEnd(a), destination: AclContractEnd{}, reason: AclContractReasonSubjectUnknown},
		{name: "a revoked sidecar's dial", source: net.sidecarEnd(revoked), destination: net.sidecarEnd(a), reason: AclContractReasonNoReach},
	}
	for _, c := range cases {
		verdict := aclContractDecide(gate, c.source, c.destination, false)
		if verdict.Outcome != AclContractRefuse || verdict.Reason != c.reason || verdict.Allowed() {
			t.Errorf("%s: %+v, want %s", c.name, verdict, c.reason)
		}
	}
	// a's own Public contract passes: its egress is auto
	if verdict := aclContractDecide(gate, net.sidecarEnd(a), provider, false); verdict.Outcome != AclContractAllow || verdict.Reason != AclContractReasonPublic {
		t.Errorf("a's Public contract: %+v", verdict)
	}
	// a companion's source answers another's contract, which is none of its egress
	if verdict := aclContractDecide(gate, net.sidecarEnd(b), provider, true); verdict.Outcome != AclContractAllow {
		t.Errorf("b's Public companion: %+v", verdict)
	}
}

// Rows' egress section as a gate reads it in place: a suspended client is refused its Public contracts, an app
// device whose member the log does not hold keeps them, and bytes no verifier folded refuse.
func TestAclContractGatePublicEgressRows(t *testing.T) {
	net := newAclContractTestNet()
	appDevice, suspendedDevice := NewId(), NewId()
	net.fixture.rows.Suspensions = append(net.fixture.rows.Suspensions, &protocol.AclSuspension{Subject: suspendedDevice.Bytes(), SuspendId: NewId().Bytes()})
	group := net.fixture.group(net.owner)
	rows, err := proto.Marshal(&bridge.BridgeRows{Egress: []*bridge.BridgeEgressRow{{Subject: group.Bytes(), Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS}}})
	if err != nil {
		t.Fatal(err)
	}
	net.fixture.rows.Bridge = rows
	gate := net.gate(t)
	provider := AclContractEnd{Known: true, NetworkId: NewId(), SubjectClientId: NewId()}

	if verdict := aclContractDecide(gate, net.clientEnd(appDevice, net.owner, true), provider, false); verdict.Reason != AclContractReasonEgress {
		t.Errorf("an app device of a group in exits: %+v", verdict)
	}
	if verdict := aclContractDecide(gate, net.clientEnd(suspendedDevice, Id{}, false), provider, false); verdict.Reason != AclContractReasonDenied {
		t.Errorf("a suspended client: %+v", verdict)
	}
	if verdict := aclContractDecide(gate, net.clientEnd(NewId(), NewId(), true), provider, false); verdict.Outcome != AclContractAllow {
		t.Errorf("an app device whose member the log does not hold: %+v", verdict)
	}

	for _, malformed := range [][]byte{{0xff}, {0x10, 0x01}, {0x0a, 0x02, 0x12, 0x00}} {
		bad := newAclContractTestNet()
		bad.fixture.rows.Bridge = malformed
		badGate := bad.gate(t)
		if verdict := aclContractDecide(badGate, bad.clientEnd(NewId(), Id{}, false), provider, false); verdict.Reason != AclContractReasonEgress {
			t.Errorf("rows %x: %+v", malformed, verdict)
		}
	}
}

// D-ACL-5: a client with no acl_enforcing is reached only through a rule whose ports_limited is false, and is a
// source otherwise; an enforcing client is reached through either.
func TestAclContractGateLegacyRule(t *testing.T) {
	net := newAclContractTestNet()
	a, d := net.fixture.device(net.owner), net.fixture.device(net.owner)
	legacy, enforcing, unrestricted := NewId(), NewId(), NewId()
	limited := net.fixture.rule([]Id{net.sidecarAtom(a)}, []*protocol.AclTarget{{ClientId: legacy.Bytes()}, {ClientId: enforcing.Bytes()}}, protocol.AclAction_ACL_ACTION_DIAL)
	limited.PortsLimited = true
	open := net.fixture.rule([]Id{net.sidecarAtom(a)}, []*protocol.AclTarget{{ClientId: unrestricted.Bytes()}}, protocol.AclAction_ACL_ACTION_DIAL)
	// every untagged non-sidecar may dial d
	net.fixture.rule(autogroupAtoms(protocol.AclAutogroup_ACL_AUTOGROUP_UNTAGGED), []*protocol.AclTarget{aclSidecarTarget(d)}, protocol.AclAction_ACL_ACTION_DIAL)
	gate := net.gate(t)
	sidecar := net.sidecarEnd(a)

	if verdict := aclContractDecide(gate, sidecar, net.clientEnd(legacy, Id{}, false), false); verdict.Outcome != AclContractRefuse || verdict.Reason != AclContractReasonNoReach {
		t.Errorf("a legacy client under a ports-limited rule: %+v", verdict)
	}
	if verdict := aclContractDecide(gate, sidecar, net.clientEnd(enforcing, Id{}, true), false); verdict.Outcome != AclContractAllow || verdict.Decision.Rule != limited {
		t.Errorf("an enforcing client under the same rule: %+v", verdict)
	}
	if verdict := aclContractDecide(gate, sidecar, net.clientEnd(unrestricted, Id{}, false), false); verdict.Outcome != AclContractAllow || verdict.Decision.Rule != open {
		t.Errorf("a legacy client under an unrestricted rule: %+v", verdict)
	}
	// source-only: the legacy client still dials d
	if verdict := aclContractDecide(gate, net.clientEnd(legacy, Id{}, false), net.sidecarEnd(d), false); verdict.Outcome != AclContractAllow {
		t.Errorf("the legacy client as a source: %+v", verdict)
	}
	// and d's companion to it answers it, which takes the legacy client's reach to d
	if verdict := aclContractDecide(gate, net.sidecarEnd(d), net.clientEnd(legacy, Id{}, false), true); verdict.Outcome != AclContractAllow {
		t.Errorf("d's companion to the legacy client: %+v", verdict)
	}
}

// A subject reaches itself: two clients acting as one sidecar contract with no rule, unless it is hard-denied.
func TestAclContractGateOneSubject(t *testing.T) {
	net := newAclContractTestNet()
	a, suspended := net.fixture.device(net.owner), net.fixture.device(net.owner)
	net.fixture.rows.Suspensions = append(net.fixture.rows.Suspensions, &protocol.AclSuspension{Subject: suspended.Bytes(), SuspendId: NewId().Bytes()})
	gate := net.gate(t)
	if verdict := aclContractDecide(gate, net.sidecarEnd(a), net.sidecarEnd(a), false); verdict.Outcome != AclContractAllow || verdict.Reason != AclContractReasonSelf {
		t.Errorf("one sidecar's clients: %+v", verdict)
	}
	if verdict := aclContractDecide(gate, net.sidecarEnd(suspended), net.sidecarEnd(suspended), false); verdict.Reason != AclContractReasonDenied {
		t.Errorf("a suspended sidecar's clients: %+v", verdict)
	}
}

// A network with no head row costs one map miss and reads no state: today's path (R-ACL-8). Platform ends skip
// whatever the heads say.
func TestAclContractGateSkipsANetworkWithNoHead(t *testing.T) {
	net := newAclContractTestNet()
	a, b := net.fixture.device(net.owner), net.fixture.device(net.owner)
	gate := net.gate(t)
	other := NewId()
	source := net.sidecarEnd(a)
	source.NetworkId = other
	destination := net.sidecarEnd(b)
	destination.NetworkId = other
	before, _ := net.states.asked()
	for _, companion := range []bool{false, true} {
		if verdict := aclContractDecide(gate, source, destination, companion); verdict.Outcome != AclContractSkip || verdict.Class != AclContractClassData || verdict.Reason != AclContractReasonNoHead {
			t.Errorf("no head, companion %t: %+v", companion, verdict)
		}
	}
	platform := net.sidecarEnd(b)
	platform.Platform = true
	if verdict := aclContractDecide(gate, net.sidecarEnd(a), platform, false); verdict.Outcome != AclContractSkip || verdict.Reason != AclContractReasonPlatform {
		t.Errorf("a platform end: %+v", verdict)
	}
	if reads, changed := net.states.asked(); reads != before || len(changed) != 1 {
		t.Errorf("skips read the state: %d reads, %v loads asked", reads-before, changed)
	}
	if !gate.HasHead(net.networkId) || gate.HasHead(other) {
		t.Error("HasHead disagrees with the snapshot")
	}
}

// A network with a head row and no verified state refuses and asks for a load; before any heads snapshot, the gate
// refuses everything it does not skip.
func TestAclContractGateRefusesWithNoLoadedState(t *testing.T) {
	net := newAclContractTestNet()
	a, b := net.fixture.device(net.owner), net.fixture.device(net.owner)
	net.dial(a, b)
	net.heads.hold = make(chan struct{})
	gate, clock, loads := newAclContractTestGate(t, net.states, net.heads)
	if verdict := aclContractDecide(gate, net.sidecarEnd(a), net.sidecarEnd(b), false); verdict.Reason != AclContractReasonHeadsUnknown || gate.Ready() {
		t.Fatalf("before any heads: %+v", verdict)
	}
	close(net.heads.hold)
	if err := aclContractTestNextLoad(t, loads); err != nil || !gate.Ready() {
		t.Fatalf("the first load: %v", err)
	}
	<-clock.armed
	_, asked := net.states.asked()
	if !slices.Equal(asked, []Id{net.networkId}) {
		t.Fatalf("the first load asked for %v", asked)
	}
	for range 2 {
		if verdict := aclContractDecide(gate, net.sidecarEnd(a), net.sidecarEnd(b), false); verdict.Outcome != AclContractRefuse || verdict.Reason != AclContractReasonNotLoaded {
			t.Fatalf("not loaded: %+v", verdict)
		}
	}
	if _, asked := net.states.asked(); len(asked) != 3 {
		t.Errorf("each refusal asks for a load: %v", asked)
	}
	net.states.install(net.networkId, net.fixture.state(t))
	if verdict := aclContractDecide(gate, net.sidecarEnd(a), net.sidecarEnd(b), false); verdict.Outcome != AclContractAllow {
		t.Errorf("once loaded: %+v", verdict)
	}
}

// The heads reload every HeadsInterval: a new or moved head asks the cache for a load, an unchanged one asks nothing,
// and a failed load keeps the last snapshot.
func TestAclContractGateReloadsItsHeads(t *testing.T) {
	states := newAclContractTestStates()
	first, second := NewId(), NewId()
	heads := &aclContractTestHeads{}
	heads.set(map[Id]uint64{first: 3}, nil)
	gate, clock, loads := newAclContractTestGate(t, states, heads)
	tick := func() error {
		clock.fire <- clock.Now()
		err := aclContractTestNextLoad(t, loads)
		if armed := <-clock.armed; armed != DefaultAclContractGateSettings().HeadsInterval {
			t.Fatalf("armed %v", armed)
		}
		return err
	}
	if _, asked := states.asked(); !slices.Equal(asked, []Id{first}) {
		t.Fatalf("the first load asked for %v", asked)
	}
	if err := tick(); err != nil {
		t.Fatal(err)
	}
	if _, asked := states.asked(); len(asked) != 1 {
		t.Errorf("an unchanged head asked for a load: %v", asked)
	}
	heads.set(map[Id]uint64{first: 4, second: 1}, nil)
	if err := tick(); err != nil {
		t.Fatal(err)
	}
	_, asked := states.asked()
	slices.SortFunc(asked[1:], Id.Cmp)
	want := []Id{first, first, second}
	slices.SortFunc(want[1:], Id.Cmp)
	if !slices.Equal(asked, want) {
		t.Errorf("moved and new heads asked for %v", asked)
	}
	heads.set(nil, errors.New("store down"))
	if err := tick(); err == nil {
		t.Fatal("a failed load reported none")
	}
	if !gate.HasHead(second) || gate.Stats().HeadsFailureCount != 1 || gate.Stats().HeadsLoadCount != 3 {
		t.Errorf("a failed load dropped the snapshot: %+v", gate.Stats())
	}
}

// A heads load asks for at most LoadAskCount loads, the rest at the loads after it, so a cold start spreads them.
func TestAclContractGateBoundsTheLoadsItAsks(t *testing.T) {
	states := newAclContractTestStates()
	heads := &aclContractTestHeads{}
	networkIds := []Id{NewId(), NewId(), NewId()}
	heads.set(map[Id]uint64{networkIds[0]: 1, networkIds[1]: 1, networkIds[2]: 1}, nil)
	clock := newAclGateTestClock()
	loads := make(chan error, 64)
	settings := DefaultAclContractGateSettings()
	settings.Log = NewNoopLogger()
	settings.LoadAskCount = 1
	settings.OnHeads = func(networkCount int, err error) {
		loads <- err
	}
	gate := NewAclContractGate(context.Background(), states, heads, clock, settings)
	t.Cleanup(gate.Close)
	for i := range len(networkIds) + 1 {
		if i != 0 {
			clock.fire <- clock.Now()
		}
		if err := aclContractTestNextLoad(t, loads); err != nil {
			t.Fatal(err)
		}
		<-clock.armed
		if _, asked := states.asked(); len(asked) != min(i+1, len(networkIds)) {
			t.Fatalf("load %d asked for %v", i, asked)
		}
	}
	_, asked := states.asked()
	slices.SortFunc(asked, Id.Cmp)
	slices.SortFunc(networkIds, Id.Cmp)
	if !slices.Equal(asked, networkIds) || !gate.HasHead(networkIds[2]) {
		t.Errorf("asked for %v", asked)
	}
}

// The decision allocates nothing on any path a warm state answers (§22.5's gate).
func TestAclContractGateDecideAllocatesNothing(t *testing.T) {
	net := newAclContractTestNet()
	a, b, c := net.fixture.device(net.owner), net.fixture.device(net.owner), net.fixture.device(net.owner)
	net.dial(a, b)
	gate := net.gate(t)
	other := net.sidecarEnd(b)
	other.NetworkId = NewId()
	cases := []AclContractRequest{
		{Source: net.sidecarEnd(a), Destination: net.sidecarEnd(b)},
		{Source: net.sidecarEnd(b), Destination: net.sidecarEnd(a)},
		{Source: net.sidecarEnd(a), Destination: net.sidecarEnd(c)},
		{Source: net.sidecarEnd(a), Destination: net.sidecarEnd(b), Companion: true},
		{Source: net.sidecarEnd(a), Destination: other},
		{Source: other, Destination: other},
	}
	for i := range cases {
		if allocations := testing.AllocsPerRun(100, func() { gate.Decide(&cases[i], aclTestNow) }); 0 < allocations {
			t.Errorf("case %d allocates %v", i, allocations)
		}
	}
}

// The gate over a real AclGateCache and a log: a network its heads name loads, two admitted sidecars witness each
// other, and a revocation the cache loads refuses them.
func TestAclContractGateOverAGateCache(t *testing.T) {
	net := newTestConfigNet(t)
	peer := net.admitMemberDevice("contract peer")
	source := newAclGateTestSource()
	source.publish(net)
	cache, cacheLoads := newAclGateTestCache(t, source, newAclGateTestClock(), nil)
	heads := &aclContractTestHeads{}
	heads.set(map[Id]uint64{net.networkId: net.n}, nil)
	gate, _, _ := newAclContractTestGate(t, cache, heads)
	aclGateTestNextLoad(t, cacheLoads)

	end := func(sidecarId Id) AclContractEnd {
		return AclContractEnd{Known: true, NetworkId: net.networkId, SubjectClientId: NewId(), SidecarId: sidecarId, SidecarHeld: true}
	}
	now := time.UnixMilli(net.timeMs)
	verdict := gate.Decide(&AclContractRequest{Source: end(net.owner.sidecarId), Destination: end(peer.sidecarId)}, now)
	if verdict.Outcome != AclContractAllow || verdict.Class != AclContractClassControl {
		t.Fatalf("two admitted sidecars: %+v", verdict)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(peer, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED))
	source.publish(net)
	cache.Changed(net.networkId)
	aclGateTestNextLoad(t, cacheLoads)
	verdict = gate.Decide(&AclContractRequest{Source: end(net.owner.sidecarId), Destination: end(peer.sidecarId)}, time.UnixMilli(net.timeMs))
	if verdict.Outcome != AclContractRefuse || verdict.Reason != AclContractReasonNoReach || verdict.Decision.Reason != AclReasonRevoked {
		t.Errorf("after the revocation: %+v", verdict)
	}
}
