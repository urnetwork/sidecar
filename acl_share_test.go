//go:build !sidecar_http && !ios_extension

// §8.11's share half of the contract gate on hand-made rows of two networks (T2's shape): both halves cover a pair,
// either missing leaves it to the Public rule, only a bound sidecar is a share's destination, both networks need a
// head row and a loaded state, a hard deny at either state uncovers it, a share is read before the Public rule's
// declared and egress refusals, and a covered decision allocates nothing. Server's TestCreateContractAclShare* run the
// same rule through CreateContract, with FriendsAndFamily and its escrow.

package sidecar

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Two networks for a share: x shares its sidecar b with y, whose sidecar a dials it.
type aclShareTestWorld struct {
	x, y       *aclTestFixture
	xId, yId   Id
	a, b       Id
	xOwner     Id
	yOwner     Id
	states     *aclContractTestStates
	heads      *aclContractTestHeads
	yRule      *protocol.AclRule
	xRule      *protocol.AclRule
	xNetworkOf Id
}

// The world with both halves granted: y's a may dial network:x, and x's network:y atom may dial b.
func newAclShareTestWorld() *aclShareTestWorld {
	self := &aclShareTestWorld{
		x:      newAclTestFixture(),
		y:      newAclTestFixture(),
		xId:    NewId(),
		yId:    NewId(),
		states: newAclContractTestStates(),
		heads:  &aclContractTestHeads{},
	}
	self.xOwner = self.x.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	self.yOwner = self.y.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	self.a = self.y.device(self.yOwner)
	self.b = self.x.device(self.xOwner)
	self.yRule = self.grantOutbound()
	self.xRule = self.grantInbound()
	self.heads.set(map[Id]uint64{self.xId: 1, self.yId: 1}, nil)
	return self
}

// y's half: a dials network:x.
func (self *aclShareTestWorld) grantOutbound() *protocol.AclRule {
	return self.y.rule([]Id{self.y.sidecarAtom(self.a)}, []*protocol.AclTarget{{NetworkId: self.xId.Bytes()}}, protocol.AclAction_ACL_ACTION_DIAL)
}

// x's half: network:y dials b.
func (self *aclShareTestWorld) grantInbound() *protocol.AclRule {
	self.xNetworkOf = self.x.atom(&protocol.AclAtom{NetworkIds: [][]byte{self.yId.Bytes()}})
	return self.x.rule([]Id{self.xNetworkOf}, []*protocol.AclTarget{aclSidecarTarget(self.b)}, protocol.AclAction_ACL_ACTION_DIAL)
}

// The gate with both states installed as they now stand.
func (self *aclShareTestWorld) gate(t *testing.T) *AclContractGate {
	t.Helper()
	self.states.install(self.xId, self.x.state(t))
	self.states.install(self.yId, self.y.state(t))
	gate, _, _ := newAclContractTestGate(t, self.states, self.heads)
	return gate
}

// a's end in y, and b's in x.
func (self *aclShareTestWorld) source() AclContractEnd {
	return AclContractEnd{Known: true, NetworkId: self.yId, SubjectClientId: NewId(), SidecarId: self.a, SidecarHeld: true}
}

func (self *aclShareTestWorld) destination() AclContractEnd {
	return AclContractEnd{Known: true, NetworkId: self.xId, SubjectClientId: NewId(), SidecarId: self.b, SidecarHeld: true}
}

// A non-companion from y's a to x's b is covered by both halves: data, Reason share, each half naming its rule.
func TestAclShareCoversAPairWithBothHalves(t *testing.T) {
	world := newAclShareTestWorld()
	gate := world.gate(t)

	verdict := aclContractDecide(gate, world.source(), world.destination(), false)
	if !verdict.Shared() || verdict.Outcome != AclContractAllow || verdict.Class != AclContractClassData || verdict.Reason != AclContractReasonShare {
		t.Fatalf("the share: %+v", verdict)
	}
	if verdict.NetworkId != world.yId || verdict.Decision.Rule != world.yRule || verdict.ShareDecision.Rule != world.xRule {
		t.Errorf("the halves: network %s, %+v and %+v", verdict.NetworkId, verdict.Decision, verdict.ShareDecision)
	}
	if verdict.Reason.String() != "share" {
		t.Errorf("reason %q", verdict.Reason)
	}
	// the share is directed: x's b dialing y's a is covered by no half, and the Public rule decides it
	reverse := aclContractDecide(gate, world.destination(), AclContractEnd{Known: true, NetworkId: world.yId, SubjectClientId: NewId(), SidecarId: world.a, SidecarHeld: true}, false)
	if reverse.Shared() || reverse.Reason != AclContractReasonPublic {
		t.Errorf("the reverse: %+v", reverse)
	}

	// the helper over two states answers the same halves
	outbound, inbound := AclShareReach(world.y.state(t), world.yId, AclSidecarSubject(world.a), world.x.state(t), world.xId, AclSidecarSubject(world.b), aclTestNow)
	if !outbound.Allowed || !inbound.Allowed {
		t.Errorf("AclShareReach: %+v, %+v", outbound, inbound)
	}
}

// Either half alone covers nothing: the Public rule decides the pair, which here passes it as Public data.
func TestAclShareNeedsBothHalves(t *testing.T) {
	for _, missing := range []string{"y's", "x's"} {
		world := newAclShareTestWorld()
		switch missing {
		case "y's":
			world.y.rows.Rules = slices.DeleteFunc(world.y.rows.Rules, func(rule *protocol.AclRule) bool { return rule == world.yRule })
		case "x's":
			world.x.rows.Rules = slices.DeleteFunc(world.x.rows.Rules, func(rule *protocol.AclRule) bool { return rule == world.xRule })
		}
		gate := world.gate(t)
		verdict := aclContractDecide(gate, world.source(), world.destination(), false)
		if verdict.Shared() || verdict.Outcome != AclContractAllow || verdict.Reason != AclContractReasonPublic {
			t.Errorf("without %s half: %+v", missing, verdict)
		}
		if missing == "x's" {
			outbound, inbound := AclShareReach(world.y.state(t), world.yId, AclSidecarSubject(world.a), world.x.state(t), world.xId, AclSidecarSubject(world.b), aclTestNow)
			if !outbound.Allowed || inbound.Allowed || inbound.Reason != AclReasonNoGrant {
				t.Errorf("AclShareReach without x's half: %+v, %+v", outbound, inbound)
			}
		}
	}

	// a rule of y's naming another network, or of x's naming another network's atom, is no half of this share
	world := newAclShareTestWorld()
	world.y.rows.Rules = slices.DeleteFunc(world.y.rows.Rules, func(rule *protocol.AclRule) bool { return rule == world.yRule })
	world.y.rule([]Id{world.y.sidecarAtom(world.a)}, []*protocol.AclTarget{{NetworkId: NewId().Bytes()}}, protocol.AclAction_ACL_ACTION_DIAL)
	world.x.rows.Atoms = append(world.x.rows.Atoms, &protocol.AclAtom{Atom: NewId().Bytes(), NetworkIds: [][]byte{NewId().Bytes()}})
	gate := world.gate(t)
	if verdict := aclContractDecide(gate, world.source(), world.destination(), false); verdict.Shared() {
		t.Errorf("another network's rule: %+v", verdict)
	}
}

// Only a non-companion toward a bound sidecar is a share's: an app device or an sdk client, a client marked by no
// owner row, and a companion are left to the Public rule.
func TestAclShareOnlyTowardABoundSidecar(t *testing.T) {
	world := newAclShareTestWorld()
	appDevice := NewId()
	world.x.rule([]Id{world.xNetworkOf}, []*protocol.AclTarget{{ClientId: appDevice.Bytes()}}, protocol.AclAction_ACL_ACTION_DIAL)
	gate := world.gate(t)

	unbound := world.destination()
	unbound.SidecarId = Id{}
	unmarked := world.destination()
	unmarked.SidecarHeld = false
	app := AclContractEnd{Known: true, NetworkId: world.xId, SubjectClientId: appDevice, MemberId: world.xOwner, AclEnforcing: true}
	for name, destination := range map[string]AclContractEnd{"an unbound client": unbound, "an unmarked client": unmarked, "an app device x's half names": app} {
		if verdict := aclContractDecide(gate, world.source(), destination, false); verdict.Shared() || verdict.Reason != AclContractReasonPublic {
			t.Errorf("%s: %+v", name, verdict)
		}
	}
	// a share's reply rides its forward contract's companion, which the Public rule passes as a companion
	if verdict := aclContractDecide(gate, world.source(), world.destination(), true); verdict.Shared() || verdict.Reason != AclContractReasonPublic {
		t.Errorf("a companion: %+v", verdict)
	}
	// and within one network nothing is a share
	same := world.destination()
	same.NetworkId = world.yId
	if verdict := aclContractDecide(gate, world.source(), same, false); verdict.Shared() {
		t.Errorf("one network: %+v", verdict)
	}
}

// Both networks need a projection: a destination network with no head row covers nothing, and one with a head row
// and no loaded state covers nothing and is asked to load.
func TestAclShareNeedsBothProjections(t *testing.T) {
	world := newAclShareTestWorld()
	world.heads.set(map[Id]uint64{world.yId: 1}, nil)
	gate := world.gate(t)
	if verdict := aclContractDecide(gate, world.source(), world.destination(), false); verdict.Shared() || verdict.Reason != AclContractReasonPublic {
		t.Errorf("x with no head row: %+v", verdict)
	}
	if _, changed := world.states.asked(); slices.Contains(changed, world.xId) {
		t.Error("a network with no head row was asked to load")
	}

	cold := newAclShareTestWorld()
	cold.states.install(cold.yId, cold.y.state(t))
	coldGate, _, _ := newAclContractTestGate(t, cold.states, cold.heads)
	if verdict := aclContractDecide(coldGate, cold.source(), cold.destination(), false); verdict.Shared() || verdict.Reason != AclContractReasonPublic {
		t.Errorf("x not loaded: %+v", verdict)
	}
	if _, changed := cold.states.asked(); !slices.Contains(changed, cold.xId) {
		t.Errorf("x was not asked to load: %v", changed)
	}
}

// A hard deny at either state uncovers the pair: a suspended source in y, a revoked destination in x, a source the
// caller halts.
func TestAclShareRefusesAHardDeniedEnd(t *testing.T) {
	cases := []struct {
		name string
		edit func(world *aclShareTestWorld)
		end  func(world *aclShareTestWorld, source *AclContractEnd)
		want AclContractReason
	}{
		{name: "a suspended source", edit: func(world *aclShareTestWorld) {
			world.y.rows.Suspensions = append(world.y.rows.Suspensions, &protocol.AclSuspension{Subject: world.a.Bytes(), SuspendId: NewId().Bytes()})
		}, want: AclContractReasonDenied},
		{name: "a revoked destination", edit: func(world *aclShareTestWorld) {
			world.x.admission(world.b).Row.RevokedAt = world.x.next()
		}, want: AclContractReasonPublic},
		{name: "a parked destination", edit: func(world *aclShareTestWorld) {
			world.x.view.parked[world.b] = true
		}, want: AclContractReasonPublic},
		{name: "a halted source", end: func(world *aclShareTestWorld, source *AclContractEnd) {
			source.Deny = AclReasonAbuseHalt
		}, want: AclContractReasonDenied},
	}
	for _, c := range cases {
		world := newAclShareTestWorld()
		if c.edit != nil {
			c.edit(world)
		}
		gate := world.gate(t)
		source := world.source()
		if c.end != nil {
			c.end(world, &source)
		}
		if verdict := aclContractDecide(gate, source, world.destination(), false); verdict.Shared() || verdict.Reason != c.want {
			t.Errorf("%s: %+v, want %s", c.name, verdict, c.want)
		}
	}
}

// A share is no Public contract: a declared no-egress source and a source in egress none, which the Public rule
// refuses, are covered by a share, and refused without one.
func TestAclShareIsReadBeforeThePublicRefusals(t *testing.T) {
	world := newAclShareTestWorld()
	egress, err := proto.Marshal(&bridge.BridgeRows{Egress: []*bridge.BridgeEgressRow{{Subject: world.a.Bytes(), Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE}}})
	if err != nil {
		t.Fatal(err)
	}
	world.y.rows.Bridge = egress
	gate := world.gate(t)
	declared := world.source()
	declared.DeclaresNoEgress = true
	if verdict := aclContractDecide(gate, declared, world.destination(), false); !verdict.Shared() {
		t.Errorf("a declared source with a share: %+v", verdict)
	}
	if verdict := aclContractDecide(gate, world.source(), world.destination(), false); !verdict.Shared() {
		t.Errorf("a source in none with a share: %+v", verdict)
	}
	provider := AclContractEnd{Known: true, NetworkId: NewId(), SubjectClientId: NewId()}
	if verdict := aclContractDecide(gate, declared, provider, false); verdict.Reason != AclContractReasonDeclaredNoEgress {
		t.Errorf("a declared source with no share: %+v", verdict)
	}
	if verdict := aclContractDecide(gate, world.source(), provider, false); verdict.Reason != AclContractReasonEgress {
		t.Errorf("a source in none with no share: %+v", verdict)
	}
}

// A covered decision, and one each half refuses, allocate nothing (§22.5's gate).
func TestAclShareDecideAllocatesNothing(t *testing.T) {
	world := newAclShareTestWorld()
	stranger := world.y.device(world.yOwner)
	gate := world.gate(t)
	strangerEnd := world.source()
	strangerEnd.SidecarId = stranger
	cases := []AclContractRequest{
		{Source: world.source(), Destination: world.destination()},
		{Source: strangerEnd, Destination: world.destination()},
		{Source: world.source(), Destination: world.destination(), Companion: true},
	}
	if !gate.Decide(&cases[0], aclTestNow).Shared() || gate.Decide(&cases[1], aclTestNow).Shared() {
		t.Fatal("the cases are not what they say")
	}
	for i := range cases {
		if allocations := testing.AllocsPerRun(100, func() { gate.Decide(&cases[i], aclTestNow) }); 0 < allocations {
			t.Errorf("case %d allocates %v", i, allocations)
		}
	}
}
