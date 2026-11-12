//go:build !sidecar_http && !ios_extension

// D-ACL-12's split (ACL-M7-01): a receiver without the listen grant refused at the gate and a scope's listener refused
// for another scope or outside its member scope; MaySendMail only with mail_send; AllowAlias for allowed and refused
// aliases and globs; a mailcfg record from a creator without the grant ignored; and an alias canary absent from rows
// and from every gate view's input.

package sidecar

import (
	"bytes"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network's receivers: the network's own, a Team scope's, and a sender, on hand-made rows behind a gate view.
type aclMailWorld struct {
	fixture       *aclTestFixture
	networkId     Id
	scopeMember   Id
	receiver      Id
	scopeReceiver Id
	sender        Id
	other         Id
	view          *AclGateView
}

func newAclMailWorld(t *testing.T) *aclMailWorld {
	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	scopeMember := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world := &aclMailWorld{
		fixture:       fixture,
		networkId:     NewId(),
		scopeMember:   scopeMember,
		receiver:      fixture.invitedDevice(owner),
		scopeReceiver: fixture.invitedDevice(scopeMember),
		sender:        fixture.invitedDevice(owner),
		other:         fixture.invitedDevice(owner),
	}
	listen, send := protocol.AclAction_ACL_ACTION_LISTEN, protocol.AclAction_ACL_ACTION_SEND
	fixture.rule([]Id{fixture.sidecarAtom(world.receiver)}, []*protocol.AclTarget{{PublicName: "smtp/25/mx"}}, listen)
	fixture.rule([]Id{fixture.sidecarAtom(world.scopeReceiver)}, []*protocol.AclTarget{{PublicName: "smtp/25/mx.sales"}}, listen)
	fixture.rule([]Id{fixture.sidecarAtom(world.sender)}, []*protocol.AclTarget{{MailSend: true}}, send)
	// a grant of send with no mail_send target sends nothing
	fixture.rule([]Id{fixture.sidecarAtom(world.other)}, []*protocol.AclTarget{{PublicName: "smtp/25/elsewhere"}}, send)
	states := newAclContractTestStates()
	states.install(world.networkId, fixture.state(t))
	world.view = NewAclGateView(states, hostAbuseGate{networkId: connect.Id(world.networkId), standing: AbuseStandingStandard, verified: true}, nil)
	return world
}

// mxedge and /dns/key-record: the receiver's listen grant on its own name, a scope's on the scope's alone, and a member
// scope's only from that member's consented devices.
func TestAclMailReceiveGate(t *testing.T) {
	world := newAclMailWorld(t)
	sales := AclScope{Label: "sales"}
	cases := []struct {
		name     string
		receiver Id
		scope    AclScope
		allowed  bool
		reason   AclReason
	}{
		{name: "the network's receiver", receiver: world.receiver, allowed: true},
		{name: "a receiver with no listen grant", receiver: world.other, reason: AclReasonNoGrant},
		{name: "the scope's receiver in its scope", receiver: world.scopeReceiver, scope: sales, allowed: true},
		{name: "the scope's receiver for another scope", receiver: world.scopeReceiver, scope: AclScope{Label: "support"}, reason: AclReasonNoGrant},
		{name: "the network's receiver for a scope", receiver: world.receiver, scope: sales, reason: AclReasonNoGrant},
		{name: "the member scope's own device", receiver: world.scopeReceiver, scope: AclScope{Label: "sales", MemberId: world.scopeMember}, allowed: true},
		{name: "another member's device in a member scope", receiver: world.scopeReceiver, scope: AclScope{Label: "sales", MemberId: NewId()}, reason: AclReasonUnconsented},
	}
	for _, c := range cases {
		decision := world.view.MayReceive(world.networkId, AclSidecarSubject(c.receiver), c.scope, aclTestNow)
		if decision.Allowed != c.allowed || (!c.allowed && decision.Reason != c.reason) {
			t.Errorf("%s: %+v", c.name, decision)
		}
	}
	halted := NewAclGateView(newAclContractTestStates(), nil, nil)
	if decision := halted.MayReceive(world.networkId, AclSidecarSubject(world.receiver), AclScope{}, aclTestNow); decision.Allowed {
		t.Error("an unloaded network received")
	}
}

// smtpedge: mail_send alone sends; a send grant on anything else does not.
func TestAclMailSendGate(t *testing.T) {
	world := newAclMailWorld(t)
	if decision := world.view.MaySendMail(world.networkId, AclSidecarSubject(world.sender), aclTestNow); !decision.Allowed {
		t.Errorf("the sender: %s", decision.Reason)
	}
	for _, subject := range []Id{world.receiver, world.other} {
		if decision := world.view.MaySendMail(world.networkId, AclSidecarSubject(subject), aclTestNow); decision.Allowed {
			t.Errorf("%s sends with no mail_send", subject)
		}
	}
}

// A document's aliases: the client checks them exactly, a mailcfg record stands only on its creator's listen grant,
// and no alias reaches the rows any gate reads.
func TestAclMailAliasesStayOnTheDevice(t *testing.T) {
	world := newAclCompileWorld("mail aliases")
	owner := world.member("owner@acme.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	creator := world.device("creator", owner)
	agent := world.agent("agent", owner, "worker")
	world.setPolicy(t, `{
  "grants": [
    { "src": ["autogroup:member"], "dst": ["mail:ops-*", "mail:canary-alias-7f3a"], "allow": ["send", "listen"] },
  ],
}`)
	rows := world.compile(t)
	local, err := CompileAclLocal(world.input())
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewAclState(rows, world.view())
	if err != nil {
		t.Fatal(err)
	}
	engine := NewAclEngine(creator, nil, nil, nil)
	if err := engine.Install(state, local); err != nil {
		t.Fatal(err)
	}
	send, listen := protocol.AclAction_ACL_ACTION_SEND, protocol.AclAction_ACL_ACTION_LISTEN
	cases := []struct {
		subject Id
		action  protocol.AclAction
		alias   string
		allowed bool
	}{
		{subject: creator, action: send, alias: "ops-alerts", allowed: true},
		{subject: creator, action: listen, alias: "ops-pager", allowed: true},
		{subject: creator, action: send, alias: "canary-alias-7f3a", allowed: true},
		{subject: creator, action: send, alias: "sales", allowed: false},
		{subject: creator, action: send, alias: "ops", allowed: false},
		{subject: creator, action: protocol.AclAction_ACL_ACTION_DIAL, alias: "ops-alerts", allowed: false},
		{subject: agent, action: send, alias: "ops-alerts", allowed: false},
	}
	for i, c := range cases {
		if decision := engine.AllowAlias(AclSidecarSubject(c.subject), c.action, c.alias, aclTestNow); decision.Allowed != c.allowed {
			t.Errorf("case %d (%s): allowed %t (%s)", i, c.alias, decision.Allowed, decision.Reason)
		}
	}
	if !engine.HonorsMailcfgRecord(creator, "ops-alerts", aclTestNow) {
		t.Error("a creator holding the listen grant is not honored")
	}
	if engine.HonorsMailcfgRecord(agent, "ops-alerts", aclTestNow) {
		t.Error("a mailcfg record from a creator without the grant was honored")
	}
	if engine.HonorsMailcfgRecord(creator, "sales", aclTestNow) {
		t.Error("a record for an alias outside the creator's grant was honored")
	}

	// the rows hold mail_send, and of the aliases nothing
	encoded := aclEncodeRows(t, rows)
	for _, canary := range []string{"canary-alias-7f3a", "canary-alias", "ops-"} {
		if bytes.Contains(encoded, []byte(canary)) {
			t.Errorf("the rows hold %q", canary)
		}
	}
	mailSend := false
	for _, rule := range rows.GetRules() {
		for _, target := range rule.GetTargets() {
			mailSend = mailSend || target.GetMailSend()
		}
	}
	if !mailSend {
		t.Error("the rows hold no mail_send")
	}
}
