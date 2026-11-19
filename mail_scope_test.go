//go:build !sidecar_http && !js && !ios_extension

package sidecar

// A Team scope's mail on a device (MAIL-M8-09; §22.7's scope rows): a device receives for a member scope only under
// team_mail: member scopes and only as a consented device of the scope's member, a tag scope taking none; a reader
// alarms on a scope deposit from any other receiver and on one whose scope it cannot resolve; the network's mailcfg is
// never a scope's, and a scope's is its member's; and a scope's addresses are spelled and parsed under its own zone.

import (
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Under member scopes a member's consented device receives for its member's scope alone, where policy grants the listen
// there, never for another member's scope or a tag scope; under team_mail: indexers, or with no state, no scope
// receives. The mode is the config's, the consent and the grant the acl state's.
func TestMailScopeReceiverHostsOnlyForTheMembersConsentedDevices(t *testing.T) {
	net := newTestConfigNet(t)
	net.setTeamMail(protocol.TeamMailMode_TEAM_MAIL_MODE_MEMBER_SCOPES)
	memberScopes := net.log.State()
	net.setTeamMail(protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS)
	indexers := net.log.State()

	fixture := newAclTestFixture()
	owner := fixture.member(bridge.MemberRole_MEMBER_ROLE_OWNER)
	member := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	other := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	memberDevice := fixture.invitedDevice(member)
	otherDevice := fixture.invitedDevice(other)
	ungranted := fixture.invitedDevice(member)
	ownerDevice := fixture.invitedDevice(owner)
	listen := protocol.AclAction_ACL_ACTION_LISTEN
	for _, device := range []Id{memberDevice, otherDevice, ownerDevice} {
		fixture.rule([]Id{fixture.sidecarAtom(device)}, []*protocol.AclTarget{
			{PublicName: "smtp/25/mx.eng"}, {PublicName: "smtp/25/mx.ops"}, {PublicName: "smtp/25/mx.sales"},
		}, listen)
	}
	acl := fixture.state(t)
	scopes := []AclScope{{Label: "eng", MemberId: member}, {Label: "ops"}, {Label: "sales", MemberId: other}}
	now := aclTestNow
	if hosts := MailScopeReceiverHosts(memberScopes, acl, scopes, memberDevice, now); !slices.Equal(hosts, []string{"mx.eng"}) {
		t.Errorf("the member's device receives for %v", hosts)
	}
	if hosts := MailScopeReceiverHosts(memberScopes, acl, scopes, otherDevice, now); !slices.Equal(hosts, []string{"mx.sales"}) {
		t.Errorf("the other member's device receives for %v", hosts)
	}
	if hosts := MailScopeReceiverHosts(memberScopes, acl, scopes, ownerDevice, now); len(hosts) != 0 {
		t.Errorf("a device of neither member, an owner's, receives for %v", hosts)
	}
	if hosts := MailScopeReceiverHosts(memberScopes, acl, scopes, ungranted, now); len(hosts) != 0 {
		t.Errorf("a consented device policy grants no listen receives for %v", hosts)
	}
	if hosts := MailScopeReceiverHosts(nil, acl, scopes, memberDevice, now); len(hosts) != 0 {
		t.Errorf("with no config: %v", hosts)
	}
	if hosts := MailScopeReceiverHosts(indexers, acl, scopes, memberDevice, now); len(hosts) != 0 {
		t.Errorf("under team_mail: indexers: %v", hosts)
	}
}

// A scope deposit from the scope member's own device raises nothing; one from another member's device alarms, as does
// one whose scope the source does not list, and every scope deposit while no source can tell the member. Each alarm
// names the receiver and the repo.
func TestMailScopeDepositFromAnotherReceiverAlarms(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	_, otherLaptop := net.consentedMember("other")
	acl, err := net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	world := newMailClientTestWorld(t)
	world.client.setNetworkRow(testMailIngestNetwork())
	engine := NewAclEngine(laptop.sidecarId, nil, nil, nil)
	if err := engine.Install(acl, nil); err != nil {
		t.Fatal(err)
	}
	var eventLock sync.Mutex
	events := []SidecarEvent{}
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	bound := *binding
	bound.Engine = engine
	bound.Scopes = func(state *AclState) ([]AclScope, bool) {
		return []AclScope{{Label: "eng", MemberId: member}}, true
	}
	bound.Event = func(event SidecarEvent) {
		eventLock.Lock()
		defer eventLock.Unlock()
		events = append(events, event)
	}
	world.client.Bind(&bound)
	repoId := NewId()
	deposit := func(depositorId Id, sni string) {
		world.client.judgeReceiver(&bound, &MailMessage{RepoId: repoId, Id: NewId(), DepositorId: depositorId, ReceiverDeposit: true, Sni: sni})
	}
	alarms := func() []SidecarEvent {
		eventLock.Lock()
		defer eventLock.Unlock()
		return slices.Clone(events)
	}
	deposit(laptop.sidecarId, "mx.eng.acme.root.example")
	if got := alarms(); len(got) != 0 {
		t.Fatalf("the member's own receiver alarmed: %+v", got)
	}
	deposit(otherLaptop.sidecarId, "mx.eng.acme.root.example")
	deposit(laptop.sidecarId, "mx.unlisted.acme.root.example")
	got := alarms()
	if len(got) != 2 || got[0].MailReceiverAlarm != SidecarMailReceiverAlarmScope || *got[0].SidecarId != otherLaptop.sidecarId ||
		*got[0].RepoId != repoId || got[1].MailReceiverAlarm != SidecarMailReceiverAlarmScope || *got[1].SidecarId != laptop.sidecarId {
		t.Fatalf("alarms %+v", got)
	}

	// no source: no scope's member can be told, so every scope deposit alarms
	bound.Scopes = nil
	world.client.Bind(&bound)
	deposit(laptop.sidecarId, "mx.eng.acme.root.example")
	if got := alarms(); len(got) != 3 {
		t.Fatalf("with no scope source: %+v", got)
	}
	for _, line := range world.log.snapshot() {
		if strings.Contains(line, "eng") || strings.Contains(line, "@") {
			t.Errorf("a line names a scope or an address: %q", line)
		}
	}
}

// The network's mailcfg is the one whose row names no owner, even where a scope's was created first, and a scope's is
// the one whose row names the scope's member: a scope's directory is never read as the network's, nor another member's.
func TestMailReposTellTheNetworksMailcfgFromAScopes(t *testing.T) {
	world := newMailReposTestWorld(t)
	_, ownerDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	member, memberDevice := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	other, _ := world.fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	scopeConfigId, networkConfigId := NewId(), NewId()
	world.fixture.rows.Repos = append(world.fixture.rows.Repos,
		&protocol.AclRepo{
			RepoId: scopeConfigId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILCFG, OwnerMemberId: member.Bytes(),
			Admins: []*protocol.AclRepoAdminRow{{SidecarId: memberDevice.Bytes(), Signer: memberDevice.Bytes(), At: 1}},
		},
		&protocol.AclRepo{
			RepoId: networkConfigId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILCFG,
			Admins: []*protocol.AclRepoAdminRow{{SidecarId: ownerDevice.Bytes(), Signer: ownerDevice.Bytes(), At: 2}},
		},
	)
	world.rebuild()
	repos := world.repos(ownerDevice)
	if repoId, ok := repos.MailConfigRepo(); !ok || repoId != networkConfigId {
		t.Errorf("the network's mailcfg: %s %t", repoId, ok)
	}
	if repoId, ok := repos.ScopeMailConfigRepo(member); !ok || repoId != scopeConfigId {
		t.Errorf("the member's scope mailcfg: %s %t", repoId, ok)
	}
	if _, ok := repos.ScopeMailConfigRepo(other); ok {
		t.Error("another member reads the member's scope mailcfg as its own")
	}
	if _, ok := repos.ScopeMailConfigRepo(Id{}); ok {
		t.Error("no member names a scope mailcfg")
	}
}

// A scope's addresses are spelled under <scope>.<net>.<root>, and a parse of one gives back its scope; a name deeper
// than a scope is none.
func TestMailScopeAddressesSpellUnderTheScope(t *testing.T) {
	zone := MailScopeZone("root.example", "acme", "eng")
	if zone.Domain() != "eng.acme.root.example" || MailScopeHost("eng") != "mx.eng" {
		t.Fatalf("zone %s, host %s", zone.Domain(), MailScopeHost("eng"))
	}
	recipient, err := ParseMailRecipient("root.example", "bo@eng.acme.root.example")
	if err != nil || recipient.Zone.Scope != "eng" || recipient.Zone.Net != "acme" {
		t.Fatalf("parsed %+v, %v", recipient, err)
	}
	if _, err := ParseMailRecipient("root.example", "bo@deep.eng.acme.root.example"); err == nil {
		t.Error("a name deeper than a scope parsed")
	}
}
