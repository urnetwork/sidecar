//go:build !sidecar_http && !ios_extension

// The edge gates' view on T2's hand-made rows (ACL-M5-01): each publish check with its refusal (a publish without
// listen, a raw publish under members, a raw link with no pin, a mismatched app_mode, a system publish ended by its
// listen grant's revocation), a halted network denied, an unloaded network never allowed, an over-limit one refused, an
// edge Find allowed under any audience's publish, the front judging it, and refused with none (QD-852), dns admin, and
// the view's checks allocating nothing.

package sidecar

import (
	"bytes"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An over-limit list a test sets.
type aclGateViewTestQuota struct {
	over   map[Id]bool
	loaded bool
}

func (self *aclGateViewTestQuota) OverLimit(networkId Id) (bool, bool) {
	return self.over[networkId], self.loaded
}

// One network's rows for the view: a listener's publishes in each form, a receiver's smtp/25/mx listen, and a zone
// admin's grant.
type aclGateViewWorld struct {
	fixture   *aclTestFixture
	networkId Id
	listener  Id
	receiver  Id
	stranger  Id
	mxListen  *protocol.AclRule
	pin       []byte
	states    *aclContractTestStates
	quota     *aclGateViewTestQuota
	view      *AclGateView
}

// A publish rule of the listener's for a host and its tls/443 socket, publish and listen unless only is given.
func (self *aclGateViewWorld) publish(host string, audience protocol.AclAudience, appMode protocol.AclAppMode, pin []byte, only ...protocol.AclAction) *protocol.AclRule {
	actions := []protocol.AclAction{protocol.AclAction_ACL_ACTION_PUBLISH, protocol.AclAction_ACL_ACTION_LISTEN}
	targets := []*protocol.AclTarget{{PublicName: host}, {PublicName: "tls/443/" + host}}
	if 0 < len(only) {
		actions = only
		targets = targets[:1]
	}
	rule := self.fixture.rule([]Id{self.fixture.sidecarAtom(self.listener)}, targets, actions...)
	rule.Audience, rule.AppMode, rule.LinkSpkiSha256 = audience, appMode, pin
	return rule
}

func newAclGateViewWorld(t testing.TB) *aclGateViewWorld {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	world := &aclGateViewWorld{
		fixture:   fixture,
		networkId: NewId(),
		listener:  fixture.device(owner),
		receiver:  fixture.device(owner),
		stranger:  fixture.device(owner),
		pin:       bytes.Repeat([]byte{0x5a}, 32),
		states:    newAclContractTestStates(),
		quota:     &aclGateViewTestQuota{over: map[Id]bool{}, loaded: true},
	}
	members, link, public := protocol.AclAudience_ACL_AUDIENCE_MEMBERS, protocol.AclAudience_ACL_AUDIENCE_LINK, protocol.AclAudience_ACL_AUDIENCE_PUBLIC
	http, raw := protocol.AclAppMode_ACL_APP_MODE_HTTP, protocol.AclAppMode_ACL_APP_MODE_RAW
	world.publish("app-preview", members, http, nil)
	world.publish("device-only", protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE, http, nil)
	world.publish("shared-link", link, http, nil)
	world.publish("unset-audience", protocol.AclAudience_ACL_AUDIENCE_UNSPECIFIED, http, nil)
	world.publish("raw-members", members, raw, nil)
	world.publish("raw-link", link, raw, nil)
	world.publish("raw-pinned", link, raw, world.pin)
	world.publish("public-site", public, http, nil)
	world.publish("no-listen", public, http, nil, protocol.AclAction_ACL_ACTION_PUBLISH)
	world.publish("split", public, http, nil, protocol.AclAction_ACL_ACTION_PUBLISH)
	fixture.rule([]Id{fixture.sidecarAtom(world.listener)}, []*protocol.AclTarget{{PublicName: "tls/443/split"}}, protocol.AclAction_ACL_ACTION_LISTEN)
	world.publish("zone-host", members, http, nil, protocol.AclAction_ACL_ACTION_ADMIN)
	world.mxListen = fixture.rule([]Id{fixture.sidecarAtom(world.receiver)}, []*protocol.AclTarget{{PublicName: "smtp/25/mx"}}, protocol.AclAction_ACL_ACTION_LISTEN)
	world.mxListen.Expires = aclTestNow.UnixMilli() + 60*60*1000
	world.install(t)
	world.view = NewAclGateView(world.states, hostAbuseGate{networkId: connect.Id(world.networkId), standing: AbuseStandingStandard, verified: true}, world.quota)
	return world
}

// Installs the fixture's rows as the network's loaded state.
func (self *aclGateViewWorld) install(t testing.TB) {
	self.states.install(self.networkId, self.fixture.state(t))
}

// Each publish check and its refusal, on the gate's own evaluation.
func TestAclGateViewPublishChecks(t *testing.T) {
	world := newAclGateViewWorld(t)
	listener, stranger := AclSidecarSubject(world.listener), AclSidecarSubject(world.stranger)
	http, raw := protocol.AclAppMode_ACL_APP_MODE_HTTP, protocol.AclAppMode_ACL_APP_MODE_RAW
	cases := []struct {
		name    string
		subject AclSubject
		socket  string
		appMode protocol.AclAppMode
		allowed bool
	}{
		{name: "a members http publish", subject: listener, socket: "tls/443/app-preview", appMode: http, allowed: true},
		{name: "an unspecified mode reads as http", subject: listener, socket: "tls/443/app-preview", allowed: true},
		{name: "a mismatched app_mode", subject: listener, socket: "tls/443/app-preview", appMode: raw},
		{name: "another port's socket", subject: listener, socket: "tls/8443/app-preview", appMode: http},
		{name: "a raw publish under members", subject: listener, socket: "tls/443/raw-members", appMode: raw},
		{name: "a raw link with no pin", subject: listener, socket: "tls/443/raw-link", appMode: raw},
		{name: "a raw link with its pin", subject: listener, socket: "tls/443/raw-pinned", appMode: raw, allowed: true},
		{name: "a publish without listen", subject: listener, socket: "tls/443/no-listen", appMode: http},
		{name: "a publish with listen from a rule of its own", subject: listener, socket: "tls/443/split", appMode: http, allowed: true},
		{name: "another subject's host", subject: stranger, socket: "tls/443/app-preview", appMode: http},
		{name: "no publish grant", subject: listener, socket: "tls/443/elsewhere", appMode: http},
		{name: "no tls/ name", subject: listener, socket: "smtp/25/app-preview", appMode: http},
		{name: "the system publish on the receiver's listen", subject: AclSidecarSubject(world.receiver), socket: "tls/443/mta-sts", appMode: http, allowed: true},
		{name: "the system publish raw", subject: AclSidecarSubject(world.receiver), socket: "tls/443/mta-sts", appMode: raw},
		{name: "the system publish with no listen", subject: listener, socket: "tls/443/mta-sts", appMode: http},
	}
	for _, c := range cases {
		if decision := world.view.MayPublish(world.networkId, c.subject, c.socket, c.appMode, aclTestNow); decision.Allowed != c.allowed {
			t.Errorf("%s: allowed %t (%s)", c.name, decision.Allowed, decision.Reason)
		}
	}

	grant, decision := world.view.PublishGrant(world.networkId, listener, "tls/443/raw-pinned", raw, aclTestNow)
	if !decision.Allowed || grant == nil || grant.Audience != protocol.AclAudience_ACL_AUDIENCE_LINK || grant.AppMode != raw ||
		!bytes.Equal(grant.LinkSpkiSha256, world.pin) || len(grant.GrantIds) != 1 {
		t.Fatalf("the pinned grant: %+v %+v", grant, decision)
	}
	system, decision := world.view.PublishGrant(world.networkId, AclSidecarSubject(world.receiver), "tls/443/mta-sts", http, aclTestNow)
	if !decision.Allowed || system.Audience != protocol.AclAudience_ACL_AUDIENCE_PUBLIC || system.ExpiresMs != world.mxListen.Expires ||
		!bytes.Equal(system.GrantIds[0], world.mxListen.RuleId) {
		t.Fatalf("the system publish: %+v", system)
	}

	// the receiver's listen grant revoked, as a GrantRevoke's fold drops it, ends the system publish
	world.fixture.rows.Rules = slicesDeleteRule(world.fixture.rows.Rules, world.mxListen)
	world.install(t)
	if decision := world.view.MayPublish(world.networkId, AclSidecarSubject(world.receiver), "tls/443/mta-sts", http, aclTestNow); decision.Allowed {
		t.Error("the system publish outlived its listen grant")
	}
}

// The rules without one.
func slicesDeleteRule(rules []*protocol.AclRule, gone *protocol.AclRule) []*protocol.AclRule {
	kept := []*protocol.AclRule{}
	for _, rule := range rules {
		if rule != gone {
			kept = append(kept, rule)
		}
	}
	return kept
}

// An edge Find runs as autogroup:public with no listener picked yet, and goes on under any audience's publish of the
// name (QD-852): the audience and a raw link's pin are the listener's front's to judge, so the gate reads neither.
func TestAclGateViewEdgeFindPassesUnderAnyAudiencesPublish(t *testing.T) {
	world := newAclGateViewWorld(t)
	cases := []struct {
		name   string
		socket string
	}{
		{name: "a members publish", socket: "tls/443/app-preview"},
		{name: "an audience left unset, which reads as members", socket: "tls/443/unset-audience"},
		{name: "a members-device publish", socket: "tls/443/device-only"},
		{name: "a link publish", socket: "tls/443/shared-link"},
		{name: "a public publish", socket: "tls/443/public-site"},
		{name: "a raw link with its pin", socket: "tls/443/raw-pinned"},
		{name: "a publish with listen from a rule of its own", socket: "tls/443/split"},
		{name: "the system publish on a receiver's listen", socket: "tls/443/mta-sts"},
	}
	for _, c := range cases {
		decision := world.view.MayEdgeFind(world.networkId, c.socket, aclTestNow)
		if !decision.Allowed || decision.Rule == nil {
			t.Errorf("%s: refused (%s)", c.name, decision.Reason)
		}
	}
	// the decision carries the grant the name stands on, and judges no audience
	decision := world.view.MayEdgeFind(world.networkId, "tls/443/device-only", aclTestNow)
	grant, _ := world.view.PublishGrant(world.networkId, AclSidecarSubject(world.listener), "tls/443/device-only", protocol.AclAppMode_ACL_APP_MODE_HTTP, aclTestNow)
	if grant == nil || grant.Audience != protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE || len(grant.GrantIds) != 1 ||
		!bytes.Equal(decision.Rule.GetRuleId(), grant.GrantIds[0]) {
		t.Errorf("the edge Find's rule %x, the listener's grant %+v", decision.Rule.GetRuleId(), grant)
	}
}

// An edge Find is refused where no publish grant names the host, and where the name's only grants are ones no
// registration could take.
func TestAclGateViewEdgeFindNeedsAPublishGrant(t *testing.T) {
	world := newAclGateViewWorld(t)
	cases := []struct {
		name   string
		socket string
	}{
		{name: "no publish grant", socket: "tls/443/elsewhere"},
		{name: "another port's socket", socket: "tls/8443/app-preview"},
		{name: "a publish without listen", socket: "tls/443/no-listen"},
		{name: "a raw publish under members", socket: "tls/443/raw-members"},
		{name: "a raw link with no pin", socket: "tls/443/raw-link"},
		{name: "admin of the zone alone", socket: "tls/443/zone-host"},
		{name: "no tls/ name", socket: "smtp/25/app-preview"},
		{name: "a name of more segments", socket: "tls/443/app-preview/more"},
		{name: "a port that is no number", socket: "tls/https/app-preview"},
		{name: "an empty name", socket: ""},
	}
	for _, c := range cases {
		if decision := world.view.MayEdgeFind(world.networkId, c.socket, aclTestNow); decision.Allowed || decision.Reason != AclReasonNoGrant {
			t.Errorf("%s: %+v", c.name, decision)
		}
	}
}

// A grant stands for an edge Find only while a sidecar holding it is under no hard deny, and only while it is in
// force: a parked listener's publish, an expired rule and a receiver whose listen grant is gone each refuse.
func TestAclGateViewEdgeFindEndsWithItsGrant(t *testing.T) {
	world := newAclGateViewWorld(t)
	expiring := world.publish("short-lived", protocol.AclAudience_ACL_AUDIENCE_MEMBERS, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
	expiring.Expires = aclTestNow.UnixMilli() + 1000
	world.install(t)
	if decision := world.view.MayEdgeFind(world.networkId, "tls/443/short-lived", aclTestNow); !decision.Allowed {
		t.Fatalf("a grant in force: %s", decision.Reason)
	}
	if decision := world.view.MayEdgeFind(world.networkId, "tls/443/short-lived", aclTestNow.Add(time.Second)); decision.Allowed {
		t.Error("an edge Find passed under an expired publish")
	}

	world.fixture.rows.Rules = slicesDeleteRule(world.fixture.rows.Rules, world.mxListen)
	world.fixture.view.parked[world.listener] = true
	world.install(t)
	for _, socket := range []string{"tls/443/app-preview", "tls/443/public-site", "tls/443/mta-sts"} {
		if decision := world.view.MayEdgeFind(world.networkId, socket, aclTestNow); decision.Allowed || decision.Reason != AclReasonNoGrant {
			t.Errorf("%s with no standing holder: %+v", socket, decision)
		}
	}
}

// The edge Find sits behind the view's refusals as every check does: a halted network, an unloaded one and a nil view.
func TestAclGateViewEdgeFindFoldsInTheServersHardDenies(t *testing.T) {
	world := newAclGateViewWorld(t)
	halted := NewAclGateView(world.states, hostAbuseGate{networkId: connect.Id(world.networkId), standing: AbuseStandingSuspended}, nil)
	if decision := halted.MayEdgeFind(world.networkId, "tls/443/public-site", aclTestNow); decision.Allowed || decision.Reason != AclReasonAbuseHalt {
		t.Errorf("a halted network: %+v", decision)
	}
	world.quota.over[world.networkId] = true
	if decision := world.view.MayEdgeFind(world.networkId, "tls/443/public-site", aclTestNow); decision.Allowed || decision.Reason != AclReasonQuota {
		t.Errorf("over its limit: %+v", decision)
	}
	if decision := world.view.MayEdgeFind(NewId(), "tls/443/public-site", aclTestNow); decision.Allowed || decision.Reason != AclReasonNoState {
		t.Errorf("an unloaded network: %+v", decision)
	}
	var none *AclGateView
	if decision := none.MayEdgeFind(world.networkId, "tls/443/public-site", aclTestNow); decision.Allowed {
		t.Error("a nil view allowed")
	}
}

// A member scope's host stands for an edge Find only on a grant of that member's consented devices; a tag scope's on
// any sidecar's.
func TestAclStateEdgeFindInScopeHoldsAMemberScopeToItsMember(t *testing.T) {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	other := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	laptop := fixture.invitedDevice(owner)
	// a device of the other member with no consent clause
	unconsented := fixture.device(other)
	publish := func(sidecarId Id, host string) {
		fixture.rule([]Id{fixture.sidecarAtom(sidecarId)}, []*protocol.AclTarget{{PublicName: host}, {PublicName: "tls/443/" + host}},
			protocol.AclAction_ACL_ACTION_PUBLISH, protocol.AclAction_ACL_ACTION_LISTEN)
	}
	publish(laptop, "notes.owner")
	publish(unconsented, "notes.other")
	state := fixture.state(t)
	if !state.ConsentedFor(laptop, owner) || state.ConsentedFor(unconsented, other) {
		t.Fatal("the fixture's consent")
	}
	cases := []struct {
		name    string
		socket  string
		scope   AclScope
		allowed bool
	}{
		{name: "the member's consented device in its own scope", socket: "tls/443/notes.owner", scope: AclScope{Label: "owner", MemberId: owner}, allowed: true},
		{name: "another member's scope", socket: "tls/443/notes.owner", scope: AclScope{Label: "owner", MemberId: other}},
		{name: "a device with no consent in its member's scope", socket: "tls/443/notes.other", scope: AclScope{Label: "other", MemberId: other}},
		{name: "a tag scope takes any sidecar's grant", socket: "tls/443/notes.other", scope: AclScope{Label: "other"}, allowed: true},
		{name: "no grant in the scope", socket: "tls/443/absent.owner", scope: AclScope{Label: "owner", MemberId: owner}},
	}
	for _, c := range cases {
		if decision := state.MayEdgeFindInScope(c.socket, c.scope, aclTestNow); decision.Allowed != c.allowed {
			t.Errorf("%s: allowed %t (%s)", c.name, decision.Allowed, decision.Reason)
		}
	}
}

// dns:<host>'s admin covers the host's zone records; publish alone does not.
func TestAclGateViewDnsAdmin(t *testing.T) {
	world := newAclGateViewWorld(t)
	listener := AclSidecarSubject(world.listener)
	if decision := world.view.MayAdminDns(world.networkId, listener, "zone-host", aclTestNow); !decision.Allowed {
		t.Errorf("the zone's admin: %s", decision.Reason)
	}
	for _, host := range []string{"app-preview", "zone-host"} {
		if decision := world.view.MayViewDns(world.networkId, listener, host, aclTestNow); !decision.Allowed {
			t.Errorf("view of %s: %s", host, decision.Reason)
		}
	}
	if decision := world.view.MayViewDns(world.networkId, AclSidecarSubject(world.stranger), "app-preview", aclTestNow); decision.Allowed {
		t.Error("another sidecar viewed the publisher's records")
	}
	if decision := world.view.MayAdminDns(world.networkId, listener, "app-preview", aclTestNow); decision.Allowed {
		t.Error("a publish grant administered a zone")
	}
}

// The hard denies only servers know: a halted network, a standing this build does not know, one the host has not
// loaded, a network over its limit, and a network the cache has not loaded, which the view asks the cache to load.
func TestAclGateViewFoldsInTheServersHardDenies(t *testing.T) {
	world := newAclGateViewWorld(t)
	listener := AclSidecarSubject(world.listener)
	socket := AclSocketName{PublicName: "tls/443/app-preview"}
	if decision := world.view.MayListen(world.networkId, listener, socket, aclTestNow); !decision.Allowed {
		t.Fatalf("the listen: %s", decision.Reason)
	}
	cases := []struct {
		name   string
		view   *AclGateView
		reason AclReason
	}{
		{name: "halted", view: NewAclGateView(world.states, hostAbuseGate{networkId: connect.Id(world.networkId), standing: AbuseStandingSuspended}, nil), reason: AclReasonAbuseHalt},
		{name: "a standing this build does not know", view: NewAclGateView(world.states, hostAbuseGate{networkId: connect.Id(world.networkId), standing: "later"}, nil), reason: AclReasonAbuseHalt},
		{name: "no standing loaded", view: NewAclGateView(world.states, nil, nil), reason: AclReasonNoState},
		{name: "another network's standing", view: NewAclGateView(world.states, hostAbuseGate{networkId: connect.NewId(), standing: AbuseStandingStandard}, nil), reason: AclReasonNoState},
	}
	for _, c := range cases {
		decisions := []AclDecision{
			c.view.MayListen(world.networkId, listener, socket, aclTestNow),
			c.view.MayPublish(world.networkId, listener, "tls/443/app-preview", protocol.AclAppMode_ACL_APP_MODE_HTTP, aclTestNow),
			c.view.MayDialSocket(world.networkId, listener, aclTestTokenPath(1), aclTestNow),
			c.view.MayViewDns(world.networkId, listener, "app-preview", aclTestNow),
		}
		for _, decision := range decisions {
			if decision.Allowed || decision.Reason != c.reason {
				t.Errorf("%s: %+v", c.name, decision)
			}
		}
	}
	world.quota.over[world.networkId] = true
	if decision := world.view.MayListen(world.networkId, listener, socket, aclTestNow); decision.Allowed || decision.Reason != AclReasonQuota {
		t.Errorf("over its limit: %+v", decision)
	}
	world.quota.loaded = false
	if decision := world.view.MayListen(world.networkId, listener, socket, aclTestNow); decision.Allowed || decision.Reason != AclReasonNoState {
		t.Errorf("no over-limit list loaded: %+v", decision)
	}
	unloaded := NewId()
	if decision := world.view.MayListen(unloaded, listener, socket, aclTestNow); decision.Allowed || decision.Reason != AclReasonNoState {
		t.Errorf("an unloaded network: %+v", decision)
	}
	if _, asked := world.states.asked(); len(asked) != 1 || asked[0] != unloaded {
		t.Errorf("the cache was asked to load %v", asked)
	}
	var none *AclGateView
	if decision := none.MayListen(world.networkId, listener, socket, aclTestNow); decision.Allowed {
		t.Error("a nil view allowed")
	}
}

// A check through the view allocates nothing.
func TestAclGateViewAllocatesNothing(t *testing.T) {
	world := newAclGateViewWorld(t)
	listener := AclSidecarSubject(world.listener)
	socket := AclSocketName{PublicName: "tls/443/app-preview"}
	allocs := testing.AllocsPerRun(100, func() {
		world.view.MayListen(world.networkId, listener, socket, aclTestNow)
		world.view.MayPublish(world.networkId, listener, "tls/443/app-preview", protocol.AclAppMode_ACL_APP_MODE_HTTP, aclTestNow)
		world.view.MayEdgeFind(world.networkId, "tls/443/app-preview", aclTestNow)
		world.view.MayEdgeFind(world.networkId, "tls/443/elsewhere", aclTestNow)
	})
	if allocs != 0 {
		t.Errorf("%v allocations a check", allocs)
	}
}

func BenchmarkAclGateView(b *testing.B) {
	world := newAclGateViewWorld(b)
	listener := AclSidecarSubject(world.listener)
	b.ReportAllocs()
	for b.Loop() {
		world.view.MayPublish(world.networkId, listener, "tls/443/app-preview", protocol.AclAppMode_ACL_APP_MODE_HTTP, aclTestNow)
	}
}
