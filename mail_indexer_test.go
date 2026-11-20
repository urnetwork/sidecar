//go:build !sidecar_http && !js && !ios_extension

// MAIL-M7-25's mail indexers on §7.9's test network, FS-82's M7 cases: under team_mail: indexers an undesignated
// tag:mail device registers no listener while a designated one does; internet mail naming an undesignated receiver
// alarms readers; with no mail indexer an online receiver still takes mail and nothing alarms; a designation the
// reader cannot open leaves the list unknown, gating and alarming on nothing; a personal network's designations work
// at network scope; a scope deposit from another member's device alarms; and the component raises the alarm as an
// event and keeps an undesignated tag:mail device's receiver off.
//
// QD-1096's M8 cases (owner decision 634), the designation's services sealed for real: folded past every reader, it
// opens at a new device and a gate with the row's nonce, so coverage reads indexer, the designated tag:mail device
// registers and mail an undesignated receiver took alarms; a tampered nonce opens nothing; the component's opener asks
// its key client for the config repo's key, bounded; and the component binds that opener over its evs component's key
// client, binding none without one.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
	// the designation's entry
	at uint64
	// newTestMailIndexerSealedTeam's: the config key its services are sealed to, and the key client holding it that
	// services opens them through
	key *EvsRepoKey
	gkm *testMailIndexerGkm
}

func newTestMailIndexerTeam(t *testing.T, mode protocol.TeamMailMode) *testMailIndexerTeam {
	t.Helper()
	team := newTestMailIndexerTeamOf(t, mode, func(net *testConfigNet, designated testConfigDevice) *protocol.IndexerSet {
		return net.indexerSet(designated, protocol.IndexerScope_INDEXER_SCOPE_NETWORK, false)
	})
	team.services = testMailIndexerServices(map[Id][]protocol.IndexerService{
		team.designated.sidecarId: {protocol.IndexerService_INDEXER_SERVICE_MAIL, protocol.IndexerService_INDEXER_SERVICE_SEARCH},
	})
	return team
}

// The Team with the designation designate files, at network scope, then team_mail set to mode unless unspecified.
func newTestMailIndexerTeamOf(t *testing.T, mode protocol.TeamMailMode, designate func(net *testConfigNet, designated testConfigDevice) *protocol.IndexerSet) *testMailIndexerTeam {
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
	at := net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, designate(net, designated)).Pin.GetVersion()
	if mode != protocol.TeamMailMode_TEAM_MAIL_MODE_UNSPECIFIED {
		net.setTeamMail(mode)
	}
	return &testMailIndexerTeam{net: net, member: member, laptop: laptop, designated: designated, other: other, at: at}
}

// The Team with the designation's services, mail and search, sealed to the config's generation-3 key under the
// IndexerSet's own header as Sidecar.DesignateIndexer seals them, and services the component's opener over a key
// client holding that key, reading the net's newest state (mailIndexerServicesOver).
func newTestMailIndexerSealedTeam(t *testing.T, mode protocol.TeamMailMode) *testMailIndexerTeam {
	t.Helper()
	key := testConfigSealKey(3)
	team := newTestMailIndexerTeamOf(t, mode, func(net *testConfigNet, designated testConfigDevice) *protocol.IndexerSet {
		return net.sealedIndexerSet(designated, protocol.IndexerScope_INDEXER_SCOPE_NETWORK, key,
			protocol.IndexerService_INDEXER_SERVICE_MAIL, protocol.IndexerService_INDEXER_SERVICE_SEARCH)
	})
	team.key = key
	team.gkm = newTestMailIndexerGkm(key)
	team.services = team.servicesAt(func() (*ConfigState, error) { return team.net.log.State(), nil })
	return team
}

// The component's opener over the team's key client, the config read from config.
func (self *testMailIndexerTeam) servicesAt(config func() (*ConfigState, error)) MailIndexerServices {
	return mailIndexerServicesOver(context.Background(), self.gkm, config, DefaultMailSettings().IndexerKeyTimeout)
}

// A key client holding the config repo's key of one generation, which records each RepoKey asked of it; every other
// call refuses.
type testMailIndexerGkm struct {
	gkmRefusingClient
	key *EvsRepoKey

	stateLock sync.Mutex
	asks      []testMailIndexerGkmAsk
}

// One RepoKey a key client was asked, and whether the ask carried a deadline.
type testMailIndexerGkmAsk struct {
	repoId     Id
	generation uint64
	deadline   bool
}

func newTestMailIndexerGkm(key *EvsRepoKey) *testMailIndexerGkm {
	return &testMailIndexerGkm{key: key}
}

// The key of its generation of its repo; ErrGkmKeyMissing for any other.
func (self *testMailIndexerGkm) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	_, deadline := ctx.Deadline()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.asks = append(self.asks, testMailIndexerGkmAsk{repoId: repoId, generation: generation, deadline: deadline})
	if repoId != self.key.RepoId() || generation != self.key.Generation() {
		return nil, ErrGkmKeyMissing
	}
	return self.key, nil
}

// What it was asked so far.
func (self *testMailIndexerGkm) asked() []testMailIndexerGkmAsk {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.asks)
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

// QD-1096's M8 case: with the designation's IndexerSet folded past every reader, a device that starts now holds only
// its row, and opens its services with the row's nonce as the long-running reader does: coverage reads indexer for
// the receiver it covers, the designated tag:mail device registers under team_mail: indexers while the other does
// not, and internet mail the other took raises the undesignated-receiver alarm while the designated one's raises none.
// A rows-only gate, which runs no mail, opens them alike.
func TestMailIndexerAFoldedDesignationOpensAtANewDevice(t *testing.T) {
	team := newTestMailIndexerSealedTeam(t, protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS)
	net := team.net
	net.foldPast(team.at)
	restored, gate := net.startedReaders()
	now := time.UnixMilli(net.timeMs)
	readers := []struct {
		label string
		state *ConfigState
	}{
		{label: "the long-running reader", state: net.log.State()},
		{label: "a new device", state: restored.State()},
	}
	for _, reader := range readers {
		state := reader.state
		services := team.servicesAt(func() (*ConfigState, error) { return state, nil })
		receivers, known := MailDesignatedReceivers(state, services)
		if !known || len(receivers) != 1 || receivers[0].SidecarId != team.designated.sidecarId {
			t.Errorf("%s: the designations %+v, known %t", reader.label, receivers, known)
		}
		if covers, err := mailIndexerCovers(state, team.laptop.sidecarId, services); !covers || err != nil {
			t.Errorf("%s: no mail indexer covers the laptop: %t, %v", reader.label, covers, err)
		}
		acl, err := state.Acl()
		if err != nil {
			t.Fatal(err)
		}
		if coverage := mailCoverageOf(acl, state, team.laptop.sidecarId, services, now); coverage != MailCoverageIndexer {
			t.Errorf("%s: the laptop's coverage %s", reader.label, coverage)
		}
		if !MailReceiverEligible(state, team.designated.sidecarId, services) {
			t.Errorf("%s: the designated tag:mail device registers no listener", reader.label)
		}
		if MailReceiverEligible(state, team.other.sidecarId, services) {
			t.Errorf("%s: an undesignated tag:mail device registers", reader.label)
		}
		if reason := MailUndesignatedReceiver(state, team.other.sidecarId, services); reason != SidecarMailReceiverAlarmUndesignated {
			t.Errorf("%s: mail the undesignated receiver took: %q", reader.label, reason)
		}
		if reason := MailUndesignatedReceiver(state, team.designated.sidecarId, services); reason != "" {
			t.Errorf("%s: mail the designated receiver took: %q", reader.label, reason)
		}
	}
	indexers := gate.State().Indexers()
	if len(indexers) != 1 {
		t.Fatalf("the gate's designations %+v", indexers)
	}
	offered, opened := team.servicesAt(func() (*ConfigState, error) { return gate.State(), nil })(indexers[0])
	if !opened || !slices.Contains(offered, protocol.IndexerService_INDEXER_SERVICE_MAIL) {
		t.Errorf("the gate's services %v, opened %t", offered, opened)
	}
}

// A designation whose row carries a nonce its services were not sealed under opens nothing: the list reads unknown, so
// the designated tag:mail device registers no listener, mail the other took raises no alarm, coverage never reads
// indexer, and whether a mail indexer covers cannot be told.
func TestMailIndexerATamperedNonceOpensNothing(t *testing.T) {
	team := newTestMailIndexerSealedTeam(t, protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS)
	net := team.net
	state := net.log.State()
	folded := state.Indexers()
	if len(folded) != 1 {
		t.Fatalf("the designations %+v", folded)
	}
	if _, opened := team.services(folded[0]); !opened {
		t.Fatal("the designation as folded does not open")
	}
	// a base whose rows carry the designation with one bit of its nonce flipped
	rows := state.Rows()
	rows.Indexers[0].Nonce[0] ^= 0x01
	if verdict := net.pushBase(net.owner, rows, net.n, state.Base().GetConfigVersion(), state.threshold); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	tampered := net.log.State()
	indexers := tampered.Indexers()
	if len(indexers) != 1 || bytes.Equal(indexers[0].Nonce, folded[0].Nonce) {
		t.Fatalf("the tampered designations %+v", indexers)
	}
	if offered, opened := team.services(indexers[0]); opened {
		t.Fatalf("a tampered nonce opens: %v", offered)
	}
	if _, known := MailDesignatedReceivers(tampered, team.services); known {
		t.Error("the list reads known")
	}
	if MailReceiverEligible(tampered, team.designated.sidecarId, team.services) {
		t.Error("the tag:mail device registers on a designation that does not open")
	}
	if reason := MailUndesignatedReceiver(tampered, team.other.sidecarId, team.services); reason != "" {
		t.Errorf("an unknown list alarms: %q", reason)
	}
	if covers, err := mailIndexerCovers(tampered, team.laptop.sidecarId, team.services); covers || !errors.Is(err, errMailIndexerServicesSealed) {
		t.Errorf("coverage by a designation that does not open: %t, %v", covers, err)
	}
	acl, err := tampered.Acl()
	if err != nil {
		t.Fatal(err)
	}
	if coverage := mailCoverageOf(acl, tampered, team.laptop.sidecarId, team.services, time.UnixMilli(net.timeMs)); coverage == MailCoverageIndexer {
		t.Error("coverage reads indexer over a designation that does not open")
	}
}

// The component's opener asks its key client for the config repo the state's genesis names at the generation the seal
// names, each ask bounded by IndexerKeyTimeout; a key client that holds no key of that generation, or a config that
// gives no state, opens nothing; and with no key client or no config there is no opener, so every designation reads
// unknown.
func TestMailIndexerServicesOverTheKeyClientAskTheConfigRepo(t *testing.T) {
	team := newTestMailIndexerSealedTeam(t, protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS)
	state := team.net.log.State()
	indexers := state.Indexers()
	if len(indexers) != 1 {
		t.Fatalf("the designations %+v", indexers)
	}
	offered, opened := team.services(indexers[0])
	want := []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_MAIL, protocol.IndexerService_INDEXER_SERVICE_SEARCH}
	if !opened || !slices.Equal(offered, want) {
		t.Fatalf("the services %v, opened %t", offered, opened)
	}
	configRepoId := Id(state.Genesis().GetConfigRepoId())
	if asks := team.gkm.asked(); len(asks) != 1 || asks[0] != (testMailIndexerGkmAsk{repoId: configRepoId, generation: 3, deadline: true}) {
		t.Errorf("the key client was asked %+v", asks)
	}

	config := func() (*ConfigState, error) { return state, nil }
	timeout := DefaultMailSettings().IndexerKeyTimeout
	otherGeneration := mailIndexerServicesOver(context.Background(), newTestMailIndexerGkm(testConfigSealKey(2)), config, timeout)
	if _, opened := otherGeneration(indexers[0]); opened {
		t.Error("services open with another generation's key")
	}
	refusing := mailIndexerServicesOver(context.Background(), gkmRefusingClient{}, config, timeout)
	if _, opened := refusing(indexers[0]); opened {
		t.Error("services open through a refusing key client")
	}
	noState := mailIndexerServicesOver(context.Background(), team.gkm, func() (*ConfigState, error) { return nil, ErrMailUnbound }, timeout)
	if _, opened := noState(indexers[0]); opened {
		t.Error("services open with no config state")
	}
	if mailIndexerServicesOver(context.Background(), nil, config, timeout) != nil || mailIndexerServicesOver(context.Background(), team.gkm, nil, timeout) != nil {
		t.Error("an opener with no key client or no config")
	}
}

// The component binds its opener over the evs component's key client (owner decision 634), the config read from the
// Sidecar's verified state: with the designation folded past, a covered device's MailIndexer stands and its Status
// carries no prompt, the designated tag:mail device's client registers and the undesignated one's does not. A Sidecar
// with no evs component binds none, so the designation reads unknown and the tag:mail device registers nothing.
func TestMailIndexerTheComponentBindsTheOpenerOverItsKeyClient(t *testing.T) {
	team := newTestMailIndexerSealedTeam(t, protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS)
	team.net.foldPast(team.at)
	sidecar := newTestSidecar(t)
	leg := &sidecarConnectLeg{sidecar: sidecar, tls: newTlsDeviceState(sidecar.settings.Tls)}
	sidecar.leg = leg
	configClient := &ConfigClient{}
	configClient.configLog.Store(team.net.log)
	func() {
		sidecar.authorities.stateLock.Lock()
		defer sidecar.authorities.stateLock.Unlock()
		sidecar.authorities.authority = configClient.Authority()
	}()
	bind := func(device testConfigDevice) (*MailClient, *MailBinding) {
		t.Helper()
		client, err := NewMailClient(&MailClientArgs{NetworkId: team.net.networkId, SidecarId: device.sidecarId, Store: newTestMemoryStore()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(client.Close)
		client.sidecar = sidecar
		client.bindFromSidecar(context.Background(), nil)
		binding := func() *MailBinding {
			client.stateLock.Lock()
			defer client.stateLock.Unlock()
			return client.binding
		}()
		if binding == nil {
			t.Fatal("nothing bound")
		}
		return client, binding
	}

	// no evs component, so no key client: nothing opens
	laptop, binding := bind(team.laptop)
	if binding.IndexerServices != nil {
		t.Error("an opener with no key client")
	}
	if _, err := binding.MailIndexer(); !errors.Is(err, errMailIndexerServicesSealed) {
		t.Errorf("a designation that cannot open reads %v", err)
	}
	if status, err := laptop.Status(context.Background()); err != nil || status.MailIndexerKnown {
		t.Errorf("the status with no key client %+v, %v", status, err)
	}
	designated, designatedBinding := bind(team.designated)
	if designated.receiverEligible(designatedBinding) {
		t.Error("a tag:mail device registers while its designation cannot open")
	}

	leg.components = append(leg.components, &EvsComponent{client: &EvsClient{args: &EvsClientArgs{Gkm: team.gkm}}})
	laptop, binding = bind(team.laptop)
	if standing, err := binding.MailIndexer(); !standing || err != nil {
		t.Errorf("no mail indexer stands: %t, %v", standing, err)
	}
	if status, err := laptop.Status(context.Background()); err != nil || !status.MailIndexerKnown || !status.MailIndexer || status.Prompt != "" {
		t.Errorf("the status with the key client %+v, %v", status, err)
	}
	designated, designatedBinding = bind(team.designated)
	if !designated.receiverEligible(designatedBinding) {
		t.Error("the designated tag:mail device registers no listener")
	}
	other, otherBinding := bind(team.other)
	if other.receiverEligible(otherBinding) {
		t.Error("an undesignated tag:mail device registers")
	}
	configRepoId := Id(team.net.log.State().Genesis().GetConfigRepoId())
	for _, ask := range team.gkm.asked() {
		if ask.repoId != configRepoId || ask.generation != team.key.Generation() || !ask.deadline {
			t.Errorf("the key client was asked %+v", ask)
		}
	}
}
