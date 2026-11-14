//go:build !ios_extension

// The device's requested grants (ACL-M4-02) over grants the log activated: ActiveGrant passes its subject's action
// and refuses another spender's, one past not_after less the skew and one it does not cover; Grants lists what rows
// hold of it; the grant component's Lookup finds its grant_id once the log holds it and a revocation's spent id after;
// the effect files nothing under a standing grant or for a grant the log holds; and the request half builds a
// forward's action at version 4 and seals its request's detail once the grant's fields are filled (QD-771), and
// refuses one with no detail, one its caller sealed already, a port or a prefix in the grant_dst it is asked, and a
// grant no rule takes.
//
// A forward's grant is a dial grant, so its action is version 4 and its activation folds port-limited (QD-740): until
// a device reads a grant's ports from its sealed_detail (ACL-M4-02's), no activated forward stands for a later one,
// which is the closed direction, and only a rule that limits no ports covers a forward. A publish's grant seals
// nothing, so it carries what an activated grant covers.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The host the world's laptop publishes, and its tls/ socket.
const (
	aclGrantFileHost   = "blog.example"
	aclGrantFileSocket = "tls/443/blog.example"
)

// A cast whose laptop holds two activated grants, and an engine over that state: a forward's dial grant to its phone,
// at version 4 with its port sealed, and a publish's grant, publish on a host and listen on its tls/ socket.
type aclGrantFileWorld struct {
	cast     *aclStatementCast
	grant    *aclTestGrant
	activate *protocol.GrantActivate
	// the publish's action as its daemon built it, and its activation
	publish         *StoredCanonicalAction
	publishActivate *protocol.GrantActivate
	engine          *AclEngine
	selfRule        []byte
	publishRule     []byte
}

func newAclGrantFileWorld(t *testing.T) *aclGrantFileWorld {
	cast := newAclStatementCast()
	fixture := cast.fixture
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	ownApprovers := []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}
	selfRule := fixture.requestRule([]Id{member}, []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, ownApprovers, 0)
	publishRule := fixture.requestRule([]Id{member}, []*protocol.AclTarget{{PublicName: aclGrantFileHost}, {PublicName: aclGrantFileSocket}},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_PUBLISH, protocol.AclAction_ACL_ACTION_LISTEN}, ownApprovers, 0)
	world := &aclGrantFileWorld{cast: cast, selfRule: selfRule, publishRule: publishRule}
	device := protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE

	world.grant = newAclTestGrant(t, selfRule, cast.laptop, []string{aclTestDst(cast.phone)}, []string{"dial"}, 0).
		approve(t, cast.member, device, aclTestDecisionNotAfter).approve(t, cast.owner, device, aclTestDecisionNotAfter)
	world.activate = world.grant.activate()
	world.publish = buildTestAction(t, world.publishAction(cast.laptop, aclGrantFileHost, aclGrantFileSocket, "publish", "listen"))
	world.publishActivate = newAclTestGrantOf(world.publish.Bytes, cast.laptop).approve(t, cast.member, device, aclTestDecisionNotAfter).activate()
	for _, activate := range []*protocol.GrantActivate{world.activate, world.publishActivate} {
		statement := fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate, cast.laptop)
		state := fixture.state(t)
		verdict, err := state.CheckStatement(statement, &aclTestSpendCheck{})
		if err != nil {
			t.Fatal(err)
		}
		rows, _, err := state.ApplyStatement(statement, verdict)
		if err != nil {
			t.Fatal(err)
		}
		fixture.rows = rows
	}
	world.engine = NewAclEngine(cast.laptop, nil, nil, nil)
	world.install(t)
	return world
}

// Installs the fixture's rows in the engine.
func (self *aclGrantFileWorld) install(t *testing.T) {
	if err := self.engine.Install(self.cast.fixture.state(t), nil); err != nil {
		t.Fatal(err)
	}
}

// A publish of host on socket for subject, asking allow of both under the world's publish rule, as its daemon fills it.
func (self *aclGrantFileWorld) publishAction(subject Id, host string, socket string, allow ...string) *protocol.CanonicalAction {
	return &protocol.CanonicalAction{
		Kind: uint32(SidecarActionPublish), Host: host, Port: 443,
		Audience: uint32(protocol.AclAudience_ACL_AUDIENCE_MEMBERS), AppMode: uint32(protocol.AclAppMode_ACL_APP_MODE_HTTP),
		RuleId: self.publishRule, Subject: subject.Bytes(), GrantDst: []string{"dns:" + host, "sock:" + socket}, GrantAllow: allow,
	}
}

// A verifier's reading of an action's stored bytes, which must parse.
func aclGrantFileParse(t *testing.T, stored []byte) *StoredCanonicalAction {
	t.Helper()
	action, err := ParseStoredCanonicalAction(stored)
	if err != nil {
		t.Fatal(err)
	}
	return action
}

// An action asking grant_dst and grant_allow for subject under the world's dial rule, as stored: a forward's at
// version 4 for a dial or a route, another kind's otherwise (aclTestGrantAction).
func (self *aclGrantFileWorld) action(t *testing.T, subject Id, dst []string, allow []string) *StoredCanonicalAction {
	t.Helper()
	return aclGrantFileParse(t, testConfigMarshal(t, aclTestGrantAction(self.selfRule, subject, dst, allow, 0)))
}

// The publish's grant covers its subject's action at once, and no other spender's, no host or action it does not
// take, and no use past its not_after less §8.6's skew. The forward's grant, sealed, covers no forward, its own
// included, and a rule that limits no ports covers one.
func TestAclActiveGrantCoversItsSubjectAlone(t *testing.T) {
	world := newAclGrantFileWorld(t)
	laptop, phone := world.cast.laptop, world.cast.phone
	publish := func(subject Id, host string, socket string, allow ...string) *StoredCanonicalAction {
		return buildTestAction(t, world.publishAction(subject, host, socket, allow...))
	}
	expiresAt := aclTestNow.Add(time.Duration(aclRequestDefaultExpiryMs) * time.Millisecond)
	skew := DefaultAclEngineSettings().ClockSkew
	cases := []struct {
		name    string
		action  *StoredCanonicalAction
		spender Id
		now     time.Time
		active  bool
	}{
		{name: "its subject's publish", action: world.publish, spender: laptop, now: aclTestNow, active: true},
		{name: "another spender presenting it", action: world.publish, spender: phone, now: aclTestNow},
		{name: "another subject's action", action: publish(phone, aclGrantFileHost, aclGrantFileSocket, "publish", "listen"), spender: phone, now: aclTestNow},
		{name: "a host it does not name", action: publish(laptop, "other.example", "tls/443/other.example", "publish", "listen"), spender: laptop, now: aclTestNow},
		{name: "an action it does not allow", action: publish(laptop, aclGrantFileHost, aclGrantFileSocket, "admin", "listen"), spender: laptop, now: aclTestNow},
		{name: "just inside the skew", action: world.publish, spender: laptop, now: expiresAt.Add(-skew - time.Millisecond), active: true},
		{name: "within the skew of its end", action: world.publish, spender: laptop, now: expiresAt.Add(-skew)},
		{name: "past its end", action: world.publish, spender: laptop, now: expiresAt.Add(time.Second)},
		{name: "no action", spender: laptop, now: aclTestNow},
		// the forward's grant folded port-limited, and a forward's clear fields name no port
		{name: "the sealed grant's own forward", action: aclGrantFileParse(t, world.grant.actionBytes), spender: laptop, now: aclTestNow},
		{name: "a forward to the sealed grant's target", action: world.action(t, laptop, []string{aclTestDst(phone)}, []string{"dial"}), spender: laptop, now: aclTestNow},
		{name: "a forward naming a port, sealed", action: world.action(t, laptop, []string{aclTestDst(phone) + ":tcp:22"}, []string{"dial"}), spender: laptop, now: aclTestNow},
	}
	for _, c := range cases {
		if active := world.engine.ActiveGrant(c.action, c.spender, c.now); active != c.active {
			t.Errorf("%s: active %t", c.name, active)
		}
	}
	if NewAclEngine(laptop, nil, nil, nil).ActiveGrant(world.publish, laptop, aclTestNow) {
		t.Error("an engine with no state covered an action")
	}

	// a standing rule that limits no ports covers a forward, for its subject and its target alone
	fixture := world.cast.fixture
	fixture.rule([]Id{fixture.sidecarAtom(laptop)}, []*protocol.AclTarget{aclSidecarTarget(phone)}, protocol.AclAction_ACL_ACTION_DIAL)
	world.install(t)
	if !world.engine.ActiveGrant(world.action(t, laptop, []string{aclTestDst(phone)}, []string{"dial"}), laptop, aclTestNow) {
		t.Error("a rule to every port did not cover a forward")
	}
	if world.engine.ActiveGrant(world.action(t, laptop, []string{aclTestDst(world.cast.stranger)}, []string{"dial"}), laptop, aclTestNow) {
		t.Error("the rule covered a forward to another target")
	}
	if world.engine.ActiveGrant(world.action(t, laptop, []string{aclTestDst(phone)}, []string{"route"}), laptop, aclTestNow) {
		t.Error("the rule covered a route")
	}
}

// Grants lists the activated grant, its requests rule beside it, for its subject alone.
func TestAclGrantsListsWhatRowsHold(t *testing.T) {
	world := newAclGrantFileWorld(t)
	grants := world.engine.Grants(AclSidecarSubject(world.cast.laptop), aclTestNow)
	found := false
	for _, grant := range grants {
		if bytes.Equal(grant.GrantId, world.activate.GetGrantId()) {
			found = true
			// a sealed grant lists as port-limited, its ports in no row
			if !bytes.Equal(grant.SourceRuleId, world.selfRule) || len(grant.Actions) != 1 || grant.Actions[0] != protocol.AclAction_ACL_ACTION_DIAL ||
				len(grant.Targets) != 1 || !bytes.Equal(grant.Targets[0].GetSidecarId(), world.cast.phone.Bytes()) || !grant.PortsLimited {
				t.Errorf("the grant as listed: %+v", grant)
			}
		}
		if bytes.Equal(grant.GrantId, world.publishActivate.GetGrantId()) && (grant.PortsLimited || !bytes.Equal(grant.SourceRuleId, world.publishRule)) {
			t.Errorf("the publish's grant as listed: %+v", grant)
		}
	}
	if !found {
		t.Fatalf("the activated grant is not listed: %d grants", len(grants))
	}
	for _, grant := range world.engine.Grants(AclSidecarSubject(world.cast.phone), aclTestNow) {
		if bytes.Equal(grant.GrantId, world.activate.GetGrantId()) {
			t.Error("the phone lists the laptop's grant")
		}
	}
}

// The grant component's Lookup answers done with the grant_id the spend fixes once the log holds it, an active rule or,
// after its revocation, a spent id, and uncertain with no spend or for a grant the log does not hold; the effect files
// nothing under a standing grant, answers a grant the log holds with no filing, and with no spend proves nothing done.
func TestAclGrantComponentLooksUpItsGrantId(t *testing.T) {
	world := newAclGrantFileWorld(t)
	filer := NewAclGrantFiler(nil, world.engine)
	decisions := [][]byte{}
	for _, decision := range world.grant.decisions {
		decisions = append(decisions, testConfigMarshal(t, decision))
	}
	spend := &ApprovalSpend{ApprovalId: world.grant.approvalId, Decisions: decisions, Action: world.grant.actionBytes}
	ctx := withApprovalSpend(context.Background(), spend)
	effectKey := bytes.Repeat([]byte{0x11}, sha256.Size)
	outcome, err := filer.Lookup(ctx, world.grant.actionBytes, effectKey)
	if err != nil || outcome.State != ApprovalOutcomeDone || !bytes.Equal(outcome.EffectRef, world.activate.GetGrantId()) {
		t.Fatalf("the held grant: %+v %v", outcome, err)
	}
	if outcome, _ := filer.Lookup(context.Background(), world.grant.actionBytes, effectKey); outcome.State != ApprovalOutcomeUncertain {
		t.Errorf("no spend: %+v", outcome)
	}
	other := &ApprovalSpend{ApprovalId: NewId(), Decisions: decisions, Action: world.grant.actionBytes}
	if outcome, _ := filer.Lookup(withApprovalSpend(context.Background(), other), world.grant.actionBytes, effectKey); outcome.State != ApprovalOutcomeUncertain {
		t.Errorf("a grant the log does not hold: %+v", outcome)
	}

	effect := filer.Effect(&StoredCanonicalAction{Bytes: world.grant.actionBytes})
	if ref, err := effect.Run(ctx, nil); ref != nil || err != nil {
		t.Errorf("under a standing grant: %x %v", ref, err)
	}
	if ref, err := effect.Run(ctx, effectKey); err != nil || !bytes.Equal(ref, world.activate.GetGrantId()) {
		t.Errorf("a grant the log holds: %x %v", ref, err)
	}
	if _, err := effect.Run(context.Background(), effectKey); !errors.Is(err, ErrSidecarEffectNotDone) {
		t.Errorf("no spend: %v", err)
	}

	revoke := world.cast.fixture.statement(bridge.SignedType_SIGNED_GRANT_REVOKE, &bridge.GrantRevoke{GrantId: world.activate.GetGrantId()}, world.cast.laptop)
	world.cast.fixture.apply(t, world.cast.fixture.state(t), revoke)
	world.install(t)
	for _, grant := range world.engine.Grants(AclSidecarSubject(world.cast.laptop), aclTestNow) {
		if bytes.Equal(grant.GrantId, world.activate.GetGrantId()) {
			t.Error("the revoked grant is still listed")
		}
	}
	if outcome, _ := filer.Lookup(ctx, world.grant.actionBytes, effectKey); outcome.State != ApprovalOutcomeDone {
		t.Errorf("the revoked grant's spent id: %+v", outcome)
	}
}

// The request half: a forward's action builds at version 4 with the rule MatchAclRequest finds and the rule's default
// lifetime, and only then seals the detail its request carries, beside those final fields (QD-771), so the detail
// opens beside the action as built, and the action shows a server its grant fields and the ciphertext alone. A forward
// with no detail, one at version 1, a base its caller sealed before the grant's fields were filled, a filer whose
// device seals nothing and a grant_dst naming a port or a prefix are refused, and a grant no requests rule takes is
// refused before any action is built.
func TestAclGrantFilerActionSealsOnceFilledAndFailsClosed(t *testing.T) {
	world := newAclGrantFileWorld(t)
	ctx := context.Background()
	filer := NewAclGrantFiler(nil, world.engine)
	filer.details = testActionDetailSealer{}
	phone := aclTestDst(world.cast.phone)
	detail := &protocol.CanonicalActionDetail{TargetPort: aclTestForwardPort, GrantDst: []string{phone + ":tcp:22"}}
	base := &protocol.CanonicalAction{Kind: uint32(SidecarActionForward)}
	request := &AclGrantRequest{Subject: world.cast.laptop, GrantDst: []string{phone}, GrantAllow: []string{"dial"}, Detail: detail}
	action, err := filer.Action(ctx, base, request, aclTestNow)
	if err != nil {
		t.Fatal(err)
	}
	built := action.Action
	if built.GetVersion() != canonicalActionVersionSealedGrant || !bytes.Equal(built.GetRuleId(), world.selfRule) || len(built.GetSealedDetail()) == 0 ||
		built.GetExpiresMillis() != aclTestNow.UnixMilli()+aclRequestDefaultExpiryMs || len(built.GetGrantDst()) != 1 || built.GetGrantDst()[0] != phone {
		t.Errorf("the forward as built: %+v", built)
	}
	// sealed beside the rule and the expiry the filer filled, so it opens beside the action as built
	opened, err := OpenCanonicalActionDetail(action, testActionDetailNetworkId(), testConfigSealKeyAt(testConfigSealKey(testActionDetailGeneration)))
	if err != nil || !proto.Equal(opened, detail) {
		t.Errorf("the forward's detail opened to %+v: %v", opened, err)
	}
	if err := CheckCanonicalActionForServer(action); err != nil {
		t.Errorf("the forward on a server path: %v", err)
	}
	if bytes.Contains(action.Bytes, []byte(":tcp:")) {
		t.Error("the forward's stored bytes show a port")
	}

	// a seal its caller made before the rule and expiry were filled binds neither, so the filer takes none
	early := testWithSealedDetail(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionForward), GrantDst: []string{phone}, GrantAllow: []string{"dial"}, Subject: world.cast.laptop.Bytes(),
	}, detail)
	if _, err := filer.Action(ctx, early, request, aclTestNow); !errors.Is(err, ErrAclGrantFile) || !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a base sealed before its grant's fields: %v", err)
	}
	noDetail := &AclGrantRequest{Subject: world.cast.laptop, GrantDst: []string{phone}, GrantAllow: []string{"dial"}}
	if _, err := filer.Action(ctx, base, noDetail, aclTestNow); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a forward that seals nothing: %v", err)
	}
	version1 := &protocol.CanonicalAction{Kind: uint32(SidecarActionForward), Version: 1}
	if _, err := filer.Action(ctx, version1, request, aclTestNow); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a forward at version 1: %v", err)
	}
	if _, err := NewAclGrantFiler(nil, world.engine).Action(ctx, base, request, aclTestNow); !errors.Is(err, ErrAclGrantFile) {
		t.Errorf("a filer whose device seals nothing: %v", err)
	}
	ported := &AclGrantRequest{Subject: world.cast.laptop, GrantDst: []string{phone + ":tcp:22"}, GrantAllow: []string{"dial"}, Detail: detail}
	if _, err := filer.Action(ctx, base, ported, aclTestNow); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a grant_dst naming a port: %v", err)
	}
	prefixed := &AclGrantRequest{Subject: world.cast.laptop, GrantDst: []string{"ip:192.0.2.0/24"}, GrantAllow: []string{"route"}, Detail: detail}
	if _, err := filer.Action(ctx, base, prefixed, aclTestNow); !errors.Is(err, ErrAclGrantFieldInvalid) {
		t.Errorf("a grant_dst naming a prefix: %v", err)
	}
	stranger := &AclGrantRequest{Subject: world.cast.laptop, GrantDst: []string{aclTestDst(world.cast.stranger)}, GrantAllow: []string{"dial"}, Detail: detail}
	if _, err := filer.Action(ctx, base, stranger, aclTestNow); !errors.Is(err, ErrAclRequestNoMatch) {
		t.Errorf("a grant no rule takes: %v", err)
	}
	if _, err := NewAclGrantFiler(nil, NewAclEngine(world.cast.laptop, nil, nil, nil)).Action(ctx, base, request, aclTestNow); !errors.Is(err, ErrAclGrantFile) {
		t.Errorf("no state: %v", err)
	}
	if err := filer.Revoke(context.Background(), []byte{1}, SidecarActConfirmed, nil); !errors.Is(err, ErrAclGrantFile) {
		t.Errorf("a malformed grant id: %v", err)
	}
}

// Each asked action is held to the destinations it applies to: one publish's grant asks publish on the dns host and
// listen on its tls/ socket, and is covered; a destination no asked action applies to, or an action that applies to no
// destination, is not.
func TestAclActiveGrantHoldsEachActionToItsDestinations(t *testing.T) {
	world := newAclGrantFileWorld(t)
	fixture := world.cast.fixture
	fixture.rule([]Id{fixture.sidecarAtom(world.cast.laptop)}, []*protocol.AclTarget{{PublicName: "app"}, {PublicName: "tls/443/app"}},
		protocol.AclAction_ACL_ACTION_PUBLISH, protocol.AclAction_ACL_ACTION_LISTEN)
	world.install(t)
	laptop := world.cast.laptop
	cases := []struct {
		name   string
		dst    []string
		allow  []string
		active bool
	}{
		{name: "a publish's host and socket", dst: []string{"dns:app", "sock:tls/443/app"}, allow: []string{"publish", "listen"}, active: true},
		{name: "the socket alone", dst: []string{"sock:tls/443/app"}, allow: []string{"listen"}, active: true},
		{name: "a listen on the host", dst: []string{"dns:app"}, allow: []string{"listen"}},
		{name: "a socket no asked action applies to", dst: []string{"dns:app", "sock:tls/443/app"}, allow: []string{"publish"}},
		{name: "another host", dst: []string{"dns:other", "sock:tls/443/other"}, allow: []string{"publish", "listen"}},
	}
	for _, c := range cases {
		if active := world.engine.ActiveGrant(world.action(t, laptop, c.dst, c.allow), laptop, aclTestNow); active != c.active {
			t.Errorf("%s: active %t", c.name, active)
		}
	}
}
