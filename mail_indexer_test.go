//go:build !sidecar_http && !js && !ios_extension

// MAIL-M7-25's mail indexers on §7.9's test network, FS-82's M7 cases: under team_mail: indexers an undesignated
// tag:mail device registers no listener while a designated one does; internet mail naming an undesignated receiver
// alarms readers; with no mail indexer an online receiver still takes mail and nothing alarms; a designation the
// reader cannot open leaves the list unknown, gating and alarming on nothing; a personal network's designations work
// at network scope; a scope deposit from another member's device alarms; and the component raises the alarm as an
// event and keeps an undesignated tag:mail device's receiver off.

package sidecar

import (
	"context"
	"crypto/sha256"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Sets the head's team_mail at the next config version and folds the tip into a base carrying it.
func (self *testConfigNet) setTeamMail(mode protocol.TeamMailMode) {
	self.t.Helper()
	configVersion := self.log.State().Base().GetConfigVersion() + 1
	self.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = &protocol.ServiceSettings{TeamMail: mode}
	if verdict := self.fold(self.owner, self.n, configVersion); !verdict.Accepted() {
		self.t.Fatalf("the base naming team_mail: %v", verdict.Refusal)
	}
}

// Opens each designation as offering services[subject], and nothing for a subject not in the map.
func testMailIndexerServices(services map[Id][]protocol.IndexerService) MailIndexerServices {
	return func(indexer ConfigIndexer) ([]protocol.IndexerService, bool) {
		offered, ok := services[indexer.SidecarId]
		return offered, ok
	}
}

// A Team with a member's laptop and two tag:mail devices, one of them designated for mail at network scope.
type testMailIndexerTeam struct {
	net        *testConfigNet
	member     Id
	laptop     testConfigDevice
	designated testConfigDevice
	other      testConfigDevice
	services   MailIndexerServices
}

func newTestMailIndexerTeam(t *testing.T, mode protocol.TeamMailMode) *testMailIndexerTeam {
	t.Helper()
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	tagId := testConfigId("tag mail")
	net.withTagOwner(tagId, member)
	designated := net.device("mail indexer", Id{})
	other := net.device("mail other", Id{})
	for _, device := range []testConfigDevice{designated, other} {
		net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(device, []Id{tagId}, false, net.timeMs+30*24*testConfigHourMs, 0))
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(designated, protocol.IndexerScope_INDEXER_SCOPE_NETWORK, false))
	if mode != protocol.TeamMailMode_TEAM_MAIL_MODE_UNSPECIFIED {
		net.setTeamMail(mode)
	}
	return &testMailIndexerTeam{
		net: net, member: member, laptop: laptop, designated: designated, other: other,
		services: testMailIndexerServices(map[Id][]protocol.IndexerService{
			designated.sidecarId: {protocol.IndexerService_INDEXER_SERVICE_MAIL, protocol.IndexerService_INDEXER_SERVICE_SEARCH},
		}),
	}
}

// FS-82: under team_mail: indexers an undesignated tag:mail device registers no listener, a designated one does, and
// an untagged member device receives as its grant says; under member scopes a tag:mail device is not gated.
func TestMailIndexerAnUndesignatedTagMailDeviceRegistersNoListener(t *testing.T) {
	team := newTestMailIndexerTeam(t, protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS)
	state := team.net.log.State()
	if MailReceiverEligible(state, team.other.sidecarId, team.services) {
		t.Error("an undesignated tag:mail device registers")
	}
	if !MailReceiverEligible(state, team.designated.sidecarId, team.services) {
		t.Error("a designated tag:mail device does not register")
	}
	if !MailReceiverEligible(state, team.laptop.sidecarId, team.services) {
		t.Error("an untagged member device is gated")
	}
	// a designation that names search alone is no mail indexer, and one the reader cannot open designates nothing
	searchOnly := testMailIndexerServices(map[Id][]protocol.IndexerService{team.designated.sidecarId: {protocol.IndexerService_INDEXER_SERVICE_SEARCH}})
	if MailReceiverEligible(state, team.designated.sidecarId, searchOnly) || MailReceiverEligible(state, team.designated.sidecarId, nil) {
		t.Error("a designation that names no mail, or does not open, lets a tag:mail device register")
	}
	scopes := newTestMailIndexerTeam(t, protocol.TeamMailMode_TEAM_MAIL_MODE_MEMBER_SCOPES)
	if !MailReceiverEligible(scopes.net.log.State(), scopes.other.sidecarId, scopes.services) {
		t.Error("a tag:mail device gated outside team_mail: indexers")
	}
}

// FS-82: internet mail an undesignated receiver took alarms readers under team_mail: indexers; the designated one's
// does not; and a list the reader cannot open alarms on nothing.
func TestMailIndexerInternetMailFromAnUndesignatedReceiverAlarms(t *testing.T) {
	team := newTestMailIndexerTeam(t, protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS)
	state := team.net.log.State()
	if reason := MailUndesignatedReceiver(state, team.other.sidecarId, team.services); reason != SidecarMailReceiverAlarmUndesignated {
		t.Errorf("the undesignated receiver: %q", reason)
	}
	if reason := MailUndesignatedReceiver(state, team.laptop.sidecarId, team.services); reason != SidecarMailReceiverAlarmUndesignated {
		t.Errorf("an untagged receiver outside the list: %q", reason)
	}
	if reason := MailUndesignatedReceiver(state, team.designated.sidecarId, team.services); reason != "" {
		t.Errorf("the designated receiver: %q", reason)
	}
	if reason := MailUndesignatedReceiver(state, team.other.sidecarId, nil); reason != "" {
		t.Errorf("an unknown list alarms: %q", reason)
	}
	receivers, known := MailDesignatedReceivers(state, team.services)
	if !known || len(receivers) != 1 || receivers[0].SidecarId != team.designated.sidecarId || receivers[0].Scope != protocol.IndexerScope_INDEXER_SCOPE_NETWORK {
		t.Fatalf("the designations %+v, known %t", receivers, known)
	}
	// outside team_mail: indexers nothing alarms
	unspecified := newTestMailIndexerTeam(t, protocol.TeamMailMode_TEAM_MAIL_MODE_UNSPECIFIED)
	if reason := MailUndesignatedReceiver(unspecified.net.log.State(), unspecified.other.sidecarId, unspecified.services); reason != "" {
		t.Errorf("an alarm with no team_mail chosen: %q", reason)
	}
}

// FS-82: with no mail indexer designated, any online receiver still takes mail: an untagged one registers and nothing
// alarms.
func TestMailIndexerWithNoMailIndexerAnOnlineReceiverStillTakesMail(t *testing.T) {
	net := newTestConfigNet(t)
	_, laptop := net.consentedMember("m")
	net.setTeamMail(protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS)
	state := net.log.State()
	services := testMailIndexerServices(map[Id][]protocol.IndexerService{})
	if !MailReceiverEligible(state, laptop.sidecarId, services) {
		t.Error("an untagged receiver gated with no mail indexer")
	}
	if reason := MailUndesignatedReceiver(state, laptop.sidecarId, services); reason != "" {
		t.Errorf("an alarm with no mail indexer: %q", reason)
	}
	if covers, err := mailIndexerCovers(state, laptop.sidecarId, services); covers || err != nil {
		t.Errorf("a mail indexer covers with none designated: %t, %v", covers, err)
	}
}

// A personal network's designation, at network or member scope, makes a mail indexer that covers its mail.
func TestMailIndexerAPersonalNetworksDesignationsWorkAtNetworkScope(t *testing.T) {
	for _, scope := range []protocol.IndexerScope{protocol.IndexerScope_INDEXER_SCOPE_NETWORK, protocol.IndexerScope_INDEXER_SCOPE_MEMBER} {
		net := newTestConfigNet(t)
		desktop := net.device("owner desktop", net.ownerMemberId)
		net.admitDevice(net.owner, desktop, 0)
		net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(desktop, scope, false))
		state := net.log.State()
		services := testMailIndexerServices(map[Id][]protocol.IndexerService{desktop.sidecarId: {protocol.IndexerService_INDEXER_SERVICE_MAIL}})
		receivers, known := MailDesignatedReceivers(state, services)
		if !known || !slices.Equal(mailNetworkIndexers(state, receivers), []Id{desktop.sidecarId}) {
			t.Errorf("scope %s: the network's indexers %+v", scope, receivers)
		}
		if covers, err := mailIndexerCovers(state, net.owner.sidecarId, services); !covers || err != nil {
			t.Errorf("scope %s: no indexer covers the owner's mail: %v", scope, err)
		}
	}
}

// A member-scope designation covers its own member's mail and no other's in a Team; a designation the reader cannot
// open leaves coverage unknown.
func TestMailIndexerAMemberScopeCoversItsOwnMember(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	desktop := net.device("m desktop", member)
	net.admitDevice(laptop, desktop, 0)
	_, otherLaptop := net.consentedMember("other")
	net.mustPost(laptop, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(desktop, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, false))
	state := net.log.State()
	services := testMailIndexerServices(map[Id][]protocol.IndexerService{desktop.sidecarId: {protocol.IndexerService_INDEXER_SERVICE_MAIL}})
	if covers, err := mailIndexerCovers(state, laptop.sidecarId, services); !covers || err != nil {
		t.Errorf("the member's own designation does not cover it: %v", err)
	}
	if covers, err := mailIndexerCovers(state, otherLaptop.sidecarId, services); covers || err != nil {
		t.Errorf("another member's designation covers: %t, %v", covers, err)
	}
	if _, err := mailIndexerCovers(state, otherLaptop.sidecarId, nil); err == nil {
		t.Error("an unopened designation reads as no designation")
	}
}

// A member scope's deposit from a receiver that is no consented device of the scope's member alarms (reading 8), and
// a scope the reader cannot resolve to a member alarms too.
func TestMailIndexerAScopeDepositFromAnotherMembersDeviceAlarms(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	_, otherLaptop := net.consentedMember("other")
	acl, err := net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	if reason := MailScopeReceiver(acl, member, laptop.sidecarId); reason != "" {
		t.Errorf("the member's own device: %q", reason)
	}
	if reason := MailScopeReceiver(acl, member, otherLaptop.sidecarId); reason != SidecarMailReceiverAlarmScope {
		t.Errorf("another member's device: %q", reason)
	}
	if reason := MailScopeReceiver(acl, Id{}, laptop.sidecarId); reason != SidecarMailReceiverAlarmScope {
		t.Errorf("an unresolved scope: %q", reason)
	}
	for sni, want := range map[string]string{
		"mx.sales.acme.root.example": "sales", "MX.Sales.Acme.Root.Example.": "sales", "mx.acme.root.example": "",
		"mx.custom.example": "", "mail.sales.acme.root.example": "",
	} {
		if scope, ok := mailSniScope("root.example", sni); scope != want || ok != (want != "") {
			t.Errorf("%s: %q %t", sni, scope, ok)
		}
	}
}

// The component raises mail_receiver_alarm as an event naming the receiver and the repo, never an address, for
// internet mail an undesignated receiver took, and raises nothing for the designated one's or same-network mail.
func TestMailIndexerComponentRaisesTheAlarmAsAnEvent(t *testing.T) {
	team := newTestMailIndexerTeam(t, protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS)
	world := newMailClientTestWorld(t)
	var eventLock sync.Mutex
	events := []SidecarEvent{}
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	bound := *binding
	bound.Config = func() (*ConfigState, error) { return team.net.log.State(), nil }
	bound.IndexerServices = team.services
	bound.Event = func(event SidecarEvent) {
		eventLock.Lock()
		defer eventLock.Unlock()
		events = append(events, event)
	}
	world.client.Bind(&bound)
	repoId := NewId()
	message := func(depositorId Id, receiver bool) *MailMessage {
		return &MailMessage{RepoId: repoId, Id: NewId(), DepositorId: depositorId, ReceiverDeposit: receiver, Sni: "mx.acme.root.example"}
	}
	world.client.judgeReceiver(&bound, message(team.designated.sidecarId, true))
	world.client.judgeReceiver(&bound, message(team.other.sidecarId, false))
	world.client.judgeReceiver(&bound, message(team.other.sidecarId, true))
	eventLock.Lock()
	defer eventLock.Unlock()
	if len(events) != 1 || events[0].Kind != SidecarEventMailReceiverAlarm || events[0].MailReceiverAlarm != SidecarMailReceiverAlarmUndesignated ||
		*events[0].SidecarId != team.other.sidecarId || *events[0].RepoId != repoId {
		t.Fatalf("events %+v", events)
	}
	for _, line := range world.log.snapshot() {
		if strings.Contains(line, "@") {
			t.Errorf("a line names an address: %q", line)
		}
	}
}

// The component keeps an undesignated tag:mail device's receiver off, saying why, even where policy grants the listen.
func TestMailIndexerComponentKeepsAnUndesignatedReceiverOff(t *testing.T) {
	world := newMailClientTestWorld(t)
	eligible := false
	world.client.componentSeams = &mailComponentSeams{
		mayReceive: func() bool { return true },
		eligible:   func() bool { return eligible },
		factory: func(args *mailReceiverFactoryArgs) (*MailReceiver, func(), error) {
			t.Fatal("a receiver was built for an undesignated device")
			return nil, nil, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &mailComponentRun{ctx: ctx, cancel: cancel}
	world.enable()
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	world.client.passReceive(run, binding)
	if status := world.client.receiverStatus; status.Running || !strings.Contains(status.Problem, "team_mail: indexers") {
		t.Fatalf("an undesignated device's receiver %+v", status)
	}
}
