//go:build !sidecar_http && !js && !ios_extension

package sidecar

// A Team scope's mail on a device (MAIL-M8-09; §22.7's scope rows): a device receives for a member scope only under
// team_mail: member scopes and only as a consented device of the scope's member, a tag scope taking none; a reader
// alarms on a scope deposit from any other receiver and on one whose scope it cannot resolve; the network's mailcfg is
// never a scope's, and a scope's is its member's; a scope member's device creates its scope's mailcfg and its receiver
// starts on it, where a device outside the scope reads none of it (QD-1093); and a scope's addresses are spelled and
// parsed under its own zone.

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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

// A scope's receiver starts on its scope's own mailcfg (QD-1093): with none in the log the member's device plans no
// receiver, though it may listen; its setup creates the mailcfg, which the log binds to the member; the receiver is then
// planned with that mailcfg and starts on smtp/25/mx.<scope>, publishing its key under mx.<scope>. A device outside the
// scope plans none, creates none and reads none of it, a config writer's included, and a scope whose member's devices
// write config heads stays unplanned, nothing filed.
func TestMailScopeReceiverStartsOnItsScopesOwnMailcfg(t *testing.T) {
	net := newTestConfigNet(t)
	net.setTeamMail(protocol.TeamMailMode_TEAM_MAIL_MODE_MEMBER_SCOPES)
	memberScopes := net.log.State()

	world := newMailReposTestWorld(t)
	fixture := world.fixture
	owner, ownerDevice := fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_OWNER)
	member, memberDevice := fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	other, otherDevice := fixture.memberWithDevice(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	listen := protocol.AclAction_ACL_ACTION_LISTEN
	for _, device := range []Id{memberDevice, otherDevice, ownerDevice} {
		fixture.rule([]Id{fixture.sidecarAtom(device)}, []*protocol.AclTarget{
			{PublicName: "smtp/25/mx.eng"}, {PublicName: "smtp/25/mx.sales"}, {PublicName: "smtp/25/mx.adm"},
		}, listen)
	}
	world.rebuild()
	scopes := []AclScope{{Label: "eng", MemberId: member}, {Label: "adm", MemberId: owner}}
	now := aclTestNow
	ctx := context.Background()

	// no mailcfg yet: the device may listen for its scope, and plans no receiver
	if hosts := MailScopeReceiverHosts(memberScopes, world.state(), scopes, memberDevice, now); !slices.Equal(hosts, []string{"mx.eng"}) {
		t.Fatalf("the member's device receives for %v", hosts)
	}
	if plans := MailScopeReceiverPlans(memberScopes, world.state(), scopes, memberDevice, now); len(plans) != 0 {
		t.Fatalf("a receiver planned with no scope mailcfg: %+v", plans)
	}

	// a device outside the scope creates nothing for it and plans nothing
	plans, err := world.repos(otherDevice).EnsureScopeReceivers(ctx, memberScopes, scopes, now)
	if err != nil || len(plans) != 0 || world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE) != 0 {
		t.Fatalf("another member's device set the scope up: %+v, %v", plans, err)
	}
	// a scope whose member's devices write config heads gets no mailcfg this way: nothing is filed, since the log would
	// read it as the network's
	plans, err = world.repos(ownerDevice).EnsureScopeReceivers(ctx, memberScopes, scopes, now)
	if !errors.Is(err, ErrMailReposConfigWriter) || len(plans) != 0 || world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE) != 0 {
		t.Fatalf("a config writer's scope: %+v, %v", plans, err)
	}

	// the member's device sets its scope up
	plans, err = world.repos(memberDevice).EnsureScopeReceivers(ctx, memberScopes, scopes, now)
	if err != nil || len(plans) != 1 {
		t.Fatalf("the member's device's setup: %+v, %v", plans, err)
	}
	plan := plans[0]
	scopeConfigId, found := world.repos(memberDevice).ScopeMailConfigRepo(member)
	if !found || plan.MailConfigRepoId != scopeConfigId || plan.Host != "mx.eng" || plan.Scope.Label != "eng" || plan.ListenName() != "smtp/25/mx.eng" {
		t.Fatalf("the plan %+v, the scope's mailcfg %s %t", plan, scopeConfigId, found)
	}
	if row := world.state().Repo(scopeConfigId); row.GetKind() != protocol.RepoKind_REPO_KIND_MAILCFG || Id(row.GetOwnerMemberId()) != member {
		t.Fatalf("the scope mailcfg's row: %+v", row)
	}
	// a second pass finds it and files nothing more
	again, err := world.repos(memberDevice).EnsureScopeReceivers(ctx, memberScopes, scopes, now)
	if err != nil || len(again) != 1 || again[0] != plan || world.filedCount(bridge.SignedType_SIGNED_REPO_CREATE) != 1 {
		t.Fatalf("a second setup: %+v, %v", again, err)
	}
	// under team_mail: indexers nothing is planned or created, the mailcfg standing or not
	net.setTeamMail(protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS)
	if plans, err := world.repos(memberDevice).EnsureScopeReceivers(ctx, net.log.State(), scopes, now); err != nil || len(plans) != 0 {
		t.Fatalf("under team_mail: indexers: %+v, %v", plans, err)
	}

	// the receiver starts on the plan: its listen is the scope host's, and its key goes out under mx.<scope>
	receiverWorld := newMailReceiverTestWorld(t, nil)
	listened := make(chan string, 4)
	receiverWorld.newReceiver(func(args *MailReceiverArgs) {
		args.Host = plan.Host
		args.Listen = func(ctx context.Context, address string, settings *SocketListenSettings) (MailReceiverListener, error) {
			listened <- address
			return receiverWorld.listener, nil
		}
	})
	start := receiverWorld.clock.Now()
	if err := receiverWorld.start(); err != nil {
		t.Fatal(err)
	}
	if address := <-listened; address != plan.ListenName() {
		t.Fatalf("the scope receiver listens on %q", address)
	}
	receiverWorld.clock.awaitWaitAt(start.Add(600 * time.Second))
	armed := receiverWorld.clock.armed()
	receiverWorld.clock.Advance(600 * time.Second)
	receiverWorld.listener.awaitServing(true)
	receiverWorld.clock.awaitArmedPast(armed)
	if publishes := receiverWorld.publisher.publishes(); len(publishes) != 1 || publishes[0].host != "mx.eng" {
		t.Fatalf("the scope receiver's key records: %+v", publishes)
	}
	if status := receiverWorld.receiver.Status(); !status.Listening || !status.Serving {
		t.Fatalf("the scope receiver's status %+v", status)
	}

	// a device outside the scope reads none of the scope's mailcfg: another member's, and a config writer's
	state := world.state()
	for name, device := range map[string]Id{"another member's device": otherDevice, "a config writer": ownerDevice} {
		if rights := state.EvsAccess(AclSidecarSubject(device), scopeConfigId, AclTokenAudienceEvs, now).Rights; rights != 0 {
			t.Errorf("%s holds %b on the scope's mailcfg", name, rights)
		}
		if rights := state.EvsAccess(AclSidecarSubject(device), scopeConfigId, AclTokenAudienceGkm, now).Rights; rights != 0 {
			t.Errorf("%s holds %b on the scope mailcfg's group", name, rights)
		}
		if plans := MailScopeReceiverPlans(memberScopes, state, scopes, device, now); len(plans) != 0 {
			t.Errorf("%s plans %+v", name, plans)
		}
	}
	if readers := state.RepoReaders(scopeConfigId, now); !slices.Equal(readers, []Id{memberDevice}) {
		t.Errorf("the scope mailcfg's readers %v", readers)
	}
	if rights := state.EvsAccess(AclSidecarSubject(memberDevice), scopeConfigId, AclTokenAudienceEvs, now).Rights; !rights.Has(AclEvsRead | AclEvsWrite) {
		t.Errorf("the member's device holds %b on its scope's mailcfg", rights)
	}
	if _, found := world.repos(otherDevice).ScopeMailConfigRepo(other); found {
		t.Error("another member was answered a scope mailcfg")
	}
}

// EvsClient.CreateRepo makes a scope's own mailcfg (QD-1093): the RepoCreate it files carries the kind alone, the log's
// fold binding the owner, and the repo's group carries the owner member in its ur_group, as a mailbox's does. The
// network's mailcfg is made with no owner, and any other kind that takes none is refused with one, nothing filed.
func TestEvsCreateRepoTakesAnOwnerForAScopesMailcfg(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	})
	test := newEvsTestClient(t, handler, newEvsTestStore(t))
	ctx := context.Background()
	member := NewId()
	scopeRepo, err := test.client.CreateRepo(ctx, &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_MAILCFG, OwnerMemberId: &member})
	if err != nil {
		t.Fatal(err)
	}
	created := test.poster.bodies[0].(*protocol.RepoCreate)
	if Id(created.GetRepoId()) != scopeRepo.RepoId() || created.GetKind() != protocol.RepoKind_REPO_KIND_MAILCFG {
		t.Errorf("RepoCreate %v", created)
	}
	if len(test.gkm.created) != 1 || test.gkm.created[0].RepoId != scopeRepo.RepoId() || test.gkm.created[0].Kind != protocol.RepoKind_REPO_KIND_MAILCFG ||
		test.gkm.created[0].OwnerMemberId == nil || *test.gkm.created[0].OwnerMemberId != member {
		t.Errorf("the scope mailcfg's group %+v", test.gkm.created)
	}
	if _, err := test.client.CreateRepo(ctx, &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_MAILCFG}); err != nil {
		t.Fatalf("the network's mailcfg: %v", err)
	}
	if len(test.gkm.created) != 2 || test.gkm.created[1].OwnerMemberId != nil {
		t.Errorf("the network mailcfg's group %+v", test.gkm.created)
	}
	for _, kind := range []protocol.RepoKind{protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_RECORD, protocol.RepoKind_REPO_KIND_TEAM_RECORD, protocol.RepoKind_REPO_KIND_DIRECTORY} {
		if _, err := test.client.CreateRepo(ctx, &EvsCreateRepoArgs{Kind: kind, OwnerMemberId: &member}); !errors.Is(err, errInvalidSettings) {
			t.Errorf("%s with an owner: %v", kind, err)
		}
	}
	if len(test.poster.filed) != 2 {
		t.Errorf("%d statements filed", len(test.poster.filed))
	}
}
