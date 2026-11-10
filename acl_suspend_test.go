// §8.6's one switch on a client: a Suspend in the next state refuses the subject at every check from the install on,
// then resets its streams, drops its aliases and closes its flows, in that order; a retry does nothing; a parked
// sidecar takes the same switch. Pure, on every leg.

package sidecar

import (
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The components a test watches, which record each call and what the engine said of the subject at that moment.
type aclTestSuspendHooks struct {
	engine *AclEngine
	calls  []string
	// whether the subject was refused at each call, which the policy swap must precede
	refusedAtCall []bool
	probe         func() bool
}

func (self *aclTestSuspendHooks) record(call string) int {
	self.calls = append(self.calls, call)
	self.refusedAtCall = append(self.refusedAtCall, self.probe())
	return 1
}

func (self *aclTestSuspendHooks) ResetStreams(subjectId Id) int {
	return self.record("streams " + subjectId.String())
}
func (self *aclTestSuspendHooks) DropAliases(subjectId Id) int {
	return self.record("aliases " + subjectId.String())
}
func (self *aclTestSuspendHooks) CloseFlows(subjectId Id) int {
	return self.record("flows " + subjectId.String())
}

// A network where a member's phone dials its laptop, and the states before and after the phone's Suspend.
func newAclSuspendWorld(t *testing.T) (*aclEngineWorld, *AclState, *AclState, *AclLocalPolicy) {
	world := newAclEngineWorld(t)
	before, local := world.install(t, aclTestEnginePin(1, "a"))
	world.world.statements.Suspensions = []*protocol.AclSuspension{{
		Subject: world.phone.Bytes(), SuspendId: world.world.id("suspend phone").Bytes(), SignerClass: AclSuspendClassOwner,
		Signer: world.laptop.Bytes(), At: 2,
	}}
	after, _ := world.install(t, aclTestEnginePin(2, "a"))
	return world, before, after, local
}

// The switch: the policy goes in before any component acts, so each acts with the subject already refused, and every
// gate check of the new state refuses it: reach, sockets and evs (§22.5's suspension, one epoch).
func TestAclSuspendEffectsSwapThePolicyFirst(t *testing.T) {
	world, before, after, local := newAclSuspendWorld(t)
	engine := NewAclEngine(world.laptop, nil, nil, nil)
	if err := engine.Install(before, local); err != nil {
		t.Fatal(err)
	}
	inbound := &AclInbound{Source: AclSidecarSubject(world.phone), IpProtocol: aclIpProtocolTcp, Port: 22}
	if !engine.AllowInbound(inbound, aclTestNow).Allowed {
		t.Fatal("the phone is refused before its Suspend")
	}
	hooks := &aclTestSuspendHooks{engine: engine, probe: func() bool { return !engine.AllowInbound(inbound, aclTestNow).Allowed }}
	report, err := NewAclSuspendEffects(engine, hooks).Apply(after, local, aclTestNow)
	if err != nil {
		t.Fatal(err)
	}
	phone := world.phone.String()
	if !slices.Equal(report.DeniedSidecarIds, []Id{world.phone}) ||
		!slices.Equal(hooks.calls, []string{"streams " + phone, "aliases " + phone, "flows " + phone}) {
		t.Fatalf("report %+v, calls %v", report, hooks.calls)
	}
	for i, refused := range hooks.refusedAtCall {
		if !refused {
			t.Errorf("%s ran before the policy refused the phone", hooks.calls[i])
		}
	}
	subject := AclSidecarSubject(world.phone)
	for name, decision := range map[string]AclDecision{
		"reach":  after.Reach(subject, AclSidecarSubject(world.laptop), aclTestNow),
		"socket": after.MayDialSocket(subject, world.world.tokenPath(t, "app/db1"), aclTestNow),
		"evs":    after.EvsAccess(subject, world.world.id("repo notes"), AclTokenAudienceEvs, aclTestNow).AclDecision,
	} {
		if decision.Allowed || decision.Reason != AclReasonSuspended {
			t.Errorf("%s after the Suspend: %+v", name, decision)
		}
	}
}

// A retried Apply of the state already installed finds nothing newly denied and calls nothing.
func TestAclSuspendEffectsRetryIsANoOp(t *testing.T) {
	world, before, after, local := newAclSuspendWorld(t)
	engine := NewAclEngine(world.laptop, nil, nil, nil)
	if err := engine.Install(before, local); err != nil {
		t.Fatal(err)
	}
	hooks := &aclTestSuspendHooks{engine: engine, probe: func() bool { return true }}
	effects := NewAclSuspendEffects(engine, hooks)
	if _, err := effects.Apply(after, local, aclTestNow); err != nil {
		t.Fatal(err)
	}
	calls := len(hooks.calls)
	report, err := effects.Apply(after, local, aclTestNow)
	if err != nil || len(report.DeniedSidecarIds) != 0 || len(hooks.calls) != calls {
		t.Fatalf("a retry: %+v, %v, %d calls", report, err, len(hooks.calls)-calls)
	}
}

// A parked sidecar takes the same switch as a suspended one (§8.6: suspensions, revocations and cascade parks alike),
// and hard deny wins over the grants it still holds.
func TestAclSuspendEffectsParkedAsSuspended(t *testing.T) {
	world := newAclEngineWorld(t)
	before, local := world.install(t, aclTestEnginePin(1, "a"))
	view := world.world.view()
	view.pin = aclTestEnginePin(2, "a")
	view.parked[world.phone] = true
	after, err := NewAclState(world.world.compile(t), view)
	if err != nil {
		t.Fatal(err)
	}
	if denied := AclNewlyDenied(before, after, aclTestNow); !slices.Equal(denied, []Id{world.phone}) {
		t.Fatalf("newly denied %v", denied)
	}
	if decision := after.Reach(AclSidecarSubject(world.phone), AclSidecarSubject(world.laptop), aclTestNow); decision.Allowed || decision.Reason != AclReasonParked {
		t.Errorf("a parked phone's reach: %+v", decision)
	}
	engine := NewAclEngine(world.laptop, nil, nil, nil)
	if err := engine.Install(before, local); err != nil {
		t.Fatal(err)
	}
	hooks := &aclTestSuspendHooks{engine: engine, probe: func() bool { return true }}
	if report, err := NewAclSuspendEffects(engine, hooks).Apply(after, local, aclTestNow); err != nil || report.Flows != 1 {
		t.Fatalf("report %+v, %v", report, err)
	}
}
