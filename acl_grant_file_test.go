//go:build !ios_extension

// The device's requested grants (ACL-M4-02) over a grant the log activated: ActiveGrant passes its subject's action
// and refuses another spender's, one past not_after less the skew and one it does not cover; Grants lists what rows
// hold of it; the grant component's Lookup finds its grant_id once the log holds it and a revocation's spent id after;
// the effect files nothing under a standing grant or for a grant the log holds; and the request half refuses a kind
// its question still holds and a grant no rule takes.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A cast whose laptop holds an activated dial grant to its phone, with no port, and an engine over that state.
type aclGrantFileWorld struct {
	cast     *aclStatementCast
	grant    *aclTestGrant
	activate *protocol.GrantActivate
	engine   *AclEngine
	selfRule []byte
}

func newAclGrantFileWorld(t *testing.T) *aclGrantFileWorld {
	cast := newAclStatementCast()
	fixture := cast.fixture
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	selfRule := fixture.requestRule([]Id{member}, []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, 0)
	state := fixture.state(t)
	device := protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE
	grant := newAclTestGrant(t, selfRule, cast.laptop, []string{aclTestDst(cast.phone)}, []string{"dial"}, 0).
		approve(t, cast.member, device, aclTestDecisionNotAfter).approve(t, cast.owner, device, aclTestDecisionNotAfter)
	activate := grant.activate()
	statement := fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate, cast.laptop)
	verdict, err := state.CheckStatement(statement, &aclTestSpendCheck{})
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := state.ApplyStatement(statement, verdict)
	if err != nil {
		t.Fatal(err)
	}
	fixture.rows = rows
	world := &aclGrantFileWorld{cast: cast, grant: grant, activate: activate, selfRule: selfRule}
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

// A forward's action asking grant_dst and grant_allow for subject, as stored.
func (self *aclGrantFileWorld) action(t *testing.T, subject Id, dst []string, allow []string) *StoredCanonicalAction {
	action := &protocol.CanonicalAction{
		Kind: uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD), Version: 1,
		RuleId: self.selfRule, Subject: subject.Bytes(), GrantDst: dst, GrantAllow: allow,
	}
	return &StoredCanonicalAction{Action: action, Bytes: testConfigMarshal(t, action)}
}

// The grant covers its subject's action at once, and no other spender's, no action it does not take, and no use past
// its not_after less §8.6's skew.
func TestAclActiveGrantCoversItsSubjectAlone(t *testing.T) {
	world := newAclGrantFileWorld(t)
	laptop, phone := world.cast.laptop, world.cast.phone
	dial := []string{"dial"}
	expiresAt := aclTestNow.Add(time.Duration(aclRequestDefaultExpiryMs) * time.Millisecond)
	skew := DefaultAclEngineSettings().ClockSkew
	cases := []struct {
		name    string
		action  *StoredCanonicalAction
		spender Id
		now     time.Time
		active  bool
	}{
		{name: "its subject's dial", action: world.action(t, laptop, []string{aclTestDst(phone)}, dial), spender: laptop, now: aclTestNow, active: true},
		{name: "a port of the target", action: world.action(t, laptop, []string{aclTestDst(phone) + ":tcp:22"}, dial), spender: laptop, now: aclTestNow, active: true},
		{name: "another spender presenting it", action: world.action(t, laptop, []string{aclTestDst(phone)}, dial), spender: phone, now: aclTestNow},
		{name: "another subject's action", action: world.action(t, phone, []string{aclTestDst(laptop)}, dial), spender: phone, now: aclTestNow},
		{name: "a destination it does not name", action: world.action(t, laptop, []string{aclTestDst(world.cast.stranger)}, dial), spender: laptop, now: aclTestNow},
		{name: "an action it does not allow", action: world.action(t, laptop, []string{aclTestDst(phone)}, []string{"listen"}), spender: laptop, now: aclTestNow},
		{name: "just inside the skew", action: world.action(t, laptop, []string{aclTestDst(phone)}, dial), spender: laptop, now: expiresAt.Add(-skew - time.Millisecond), active: true},
		{name: "within the skew of its end", action: world.action(t, laptop, []string{aclTestDst(phone)}, dial), spender: laptop, now: expiresAt.Add(-skew)},
		{name: "past its end", action: world.action(t, laptop, []string{aclTestDst(phone)}, dial), spender: laptop, now: expiresAt.Add(time.Second)},
		{name: "no action", spender: laptop, now: aclTestNow},
	}
	for _, c := range cases {
		if active := world.engine.ActiveGrant(c.action, c.spender, c.now); active != c.active {
			t.Errorf("%s: active %t", c.name, active)
		}
	}
	if NewAclEngine(laptop, nil, nil, nil).ActiveGrant(world.action(t, laptop, []string{aclTestDst(phone)}, dial), laptop, aclTestNow) {
		t.Error("an engine with no state covered an action")
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
			if !bytes.Equal(grant.SourceRuleId, world.selfRule) || len(grant.Actions) != 1 || grant.Actions[0] != protocol.AclAction_ACL_ACTION_DIAL ||
				len(grant.Targets) != 1 || !bytes.Equal(grant.Targets[0].GetSidecarId(), world.cast.phone.Bytes()) {
				t.Errorf("the grant as listed: %+v", grant)
			}
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
	if world.engine.ActiveGrant(world.action(t, world.cast.laptop, []string{aclTestDst(world.cast.phone)}, []string{"dial"}), world.cast.laptop, aclTestNow) {
		t.Error("the revoked grant still covers its action")
	}
	if outcome, _ := filer.Lookup(ctx, world.grant.actionBytes, effectKey); outcome.State != ApprovalOutcomeDone {
		t.Errorf("the revoked grant's spent id: %+v", outcome)
	}
}

// The request half: a kind whose question still holds its fields is refused by the builder, and a grant no requests
// rule takes is refused before any action is built.
func TestAclGrantFilerActionFailsClosed(t *testing.T) {
	world := newAclGrantFileWorld(t)
	filer := NewAclGrantFiler(nil, world.engine)
	base := &protocol.CanonicalAction{Kind: uint32(protocol.SidecarActionKind_SIDECAR_ACTION_KIND_FORWARD), Version: 1}
	request := &AclGrantRequest{Subject: world.cast.laptop, GrantDst: []string{aclTestDst(world.cast.phone)}, GrantAllow: []string{"dial"}}
	if _, err := filer.Action(base, request, aclTestNow); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a held kind: %v", err)
	}
	stranger := &AclGrantRequest{Subject: world.cast.laptop, GrantDst: []string{aclTestDst(world.cast.stranger)}, GrantAllow: []string{"dial"}}
	if _, err := filer.Action(base, stranger, aclTestNow); !errors.Is(err, ErrAclRequestNoMatch) {
		t.Errorf("a grant no rule takes: %v", err)
	}
	if _, err := NewAclGrantFiler(nil, NewAclEngine(world.cast.laptop, nil, nil, nil)).Action(base, request, aclTestNow); !errors.Is(err, ErrAclGrantFile) {
		t.Errorf("no state: %v", err)
	}
	if err := filer.Revoke(context.Background(), []byte{1}, SidecarActConfirmed, nil); !errors.Is(err, ErrAclGrantFile) {
		t.Errorf("a malformed grant id: %v", err)
	}
}
