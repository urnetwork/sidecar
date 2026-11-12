// The production gate (SOCK-M5-07; DESIGN-DETAILS 13.2.3, 13.6) on a network's real authorization log: the admission
// world with ACL's own compile, on a Net whose first metadata cluster holds proj/ and projrows/, read through the
// direct source with a wrapper a test can fail, hold or rewrite, standing for api's internal surface (QD-055). On it,
// the route fixture's processes, each an engine on a production gate of its own over one FakeSocketStore, on the
// Net's clock. Nothing sleeps: loads are awaited by count, and the grace, reloads and polls move on the fake clock.
// The processes' cache waits no backoff after a failed load and reloads behind networks only when a test asks, so a
// load happens exactly when a test triggers one.

package socketsservice_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// The projection source a process reads: the direct source on the Net's first metadata cluster, which a test fails
// for some networks, holds, or rewrites.
type testGateSource struct {
	inner sidecar.AclGateSource

	stateLock sync.Mutex
	// A network's reads fail while it is here.
	failNetworkIds map[connect.Id]bool
	// While set, Entries waits on it, after reporting on started.
	hold    chan struct{}
	started chan struct{}
	// Rewrites what one Entries answers.
	rewrite func(entries [][]byte) [][]byte
}

var errTestGateSourceDown = errors.New("the projection source is down")

func (self *testGateSource) failing(networkId sidecar.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.failNetworkIds[connect.Id(networkId)]
}

// Fails or answers networkId's reads.
func (self *testGateSource) setFailing(networkId connect.Id, failing bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if failing {
		self.failNetworkIds[networkId] = true
	} else {
		delete(self.failNetworkIds, networkId)
	}
}

// Holds every Entries until the returned release is called.
func (self *testGateSource) holdEntries() func() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	hold := make(chan struct{})
	self.hold = hold
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.hold = nil
		close(hold)
	}
}

// Rewrites what Entries answers, nil for none.
func (self *testGateSource) setRewrite(rewrite func(entries [][]byte) [][]byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rewrite = rewrite
}

func (self *testGateSource) Genesis(ctx context.Context, networkId sidecar.Id) ([]byte, error) {
	if self.failing(networkId) {
		return nil, errTestGateSourceDown
	}
	return self.inner.Genesis(ctx, networkId)
}

func (self *testGateSource) Entries(ctx context.Context, networkId sidecar.Id, after *bridge.AuthPin) ([][]byte, error) {
	hold, rewrite := func() (chan struct{}, func([][]byte) [][]byte) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.hold, self.rewrite
	}()
	if hold != nil {
		self.started <- struct{}{}
		select {
		case <-hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if self.failing(networkId) {
		return nil, errTestGateSourceDown
	}
	entries, err := self.inner.Entries(ctx, networkId, after)
	if err == nil && rewrite != nil {
		entries = rewrite(entries)
	}
	return entries, err
}

func (self *testGateSource) Rows(ctx context.Context, networkId sidecar.Id, rowsSha256 []byte) ([]byte, error) {
	if self.failing(networkId) {
		return nil, errTestGateSourceDown
	}
	return self.inner.Rows(ctx, networkId, rowsSha256)
}

// One network's log: its admission world, its member's two devices, K_sock and app/db's token path under it.
type testGateNetwork struct {
	t         *testing.T
	admission *sidecartest.AdmissionNet
	networkId connect.Id
	memberId  sidecar.Id
	listener  *sidecartest.AdmissionDevice
	dialer    *sidecartest.AdmissionDevice
	tokenPath []byte
}

// What the tests share: the Net, its source, and the networks on its tier.
type testGateLog struct {
	t      *testing.T
	net    *sidecartest.Net
	tier   *sidecartest.AdmissionTier
	source *testGateSource
}

// A Net whose first metadata cluster the source reads.
func newTestGateLog(t *testing.T) *testGateLog {
	t.Helper()
	net := sidecartest.NewNet(context.Background(), nil)
	t.Cleanup(net.Close)
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	tier.AclCompile = sidecartest.AclAdmissionCompile
	return &testGateLog{
		t:    t,
		net:  net,
		tier: tier,
		source: &testGateSource{
			inner:          sidecar.NewAclGateDirectSource(nil, net.Host().Blobs, nil),
			failNetworkIds: map[connect.Id]bool{},
			started:        make(chan struct{}, 64),
		},
	}
}

// A network on the tier whose member m has two devices, the listener its invited first, and whose head holds K_sock
// and a policy giving every member device listen and dial on app/db.
func (self *testGateLog) newNetwork() *testGateNetwork {
	self.t.Helper()
	admission := sidecartest.NewAdmissionNet(self.t, self.tier)
	self.t.Cleanup(admission.Close)
	memberId, listener := admission.ConsentedMember("m")
	dialer := admission.Device("m second device", memberId)
	admission.AdmitDevice(admission.Owner(), dialer, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	socketKey := bytes.Repeat([]byte{0x5a}, 32)
	keyFileBytes, err := proto.Marshal(&protocol.SocketKeyFile{CurrentKey: socketKey})
	if err != nil {
		self.t.Fatal(err)
	}
	admission.SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadSocketKeyPath, keyFileBytes)
	})
	socketKeys, err := sidecar.NewSocketKeys(admission.NetworkId(), socketKey)
	if err != nil {
		self.t.Fatal(err)
	}
	tokenPath, err := socketKeys.TokenPath("app/db")
	if err != nil {
		self.t.Fatal(err)
	}
	network := &testGateNetwork{
		t:         self.t,
		admission: admission,
		networkId: connect.Id(admission.NetworkId()),
		memberId:  memberId,
		listener:  listener,
		dialer:    dialer,
		tokenPath: tokenPath,
	}
	network.savePolicy(true)
	return network
}

// Saves the members' grant on app/db: listen and dial, or dial alone, which revokes the listen. The base's pin.
func (self *testGateNetwork) savePolicy(listen bool) *bridge.AuthPin {
	self.t.Helper()
	allow := `"dial"`
	if listen {
		allow = `"listen", "dial"`
	}
	source := fmt.Sprintf(`{
		"grants": [
			{ "src": ["autogroup:member"], "dst": ["sock:app/db"], "allow": [%s] },
		],
	}`, allow)
	_, pin := self.admission.SaveAclPolicy([]byte(source), sidecartest.AclSaveMembers{})
	return pin
}

// The tip's position.
func (self *testGateNetwork) tip() uint64 {
	return self.admission.Tip().GetVersion()
}

// A sidecar of the route fixture for device: its own client, the device's sidecar id and identity key, and a token.
func (self *testGateNetwork) sidecarOf(world *testSocketWorld, device *sidecartest.AdmissionDevice) *testSocketSidecar {
	self.t.Helper()
	sidecarId := connect.Id(device.SidecarId)
	socketSidecar := &testSocketSidecar{
		networkId:   self.networkId,
		clientId:    testSocketId(),
		sidecarId:   sidecarId,
		identityKey: device.Key,
	}
	socketSidecar.token = world.authenticator.Issue(&sidecar.Principal{
		NetworkId: self.networkId,
		ClientId:  socketSidecar.clientId,
		SidecarId: &sidecarId,
		Audience:  socketsservice.SocketsAudience,
		IssuedAt:  world.clock.Now(),
		ExpiresAt: world.clock.Now().Add(24 * time.Hour),
	})
	return socketSidecar
}

// A process on the production gate over the log's source, with settings changed by mutate. Its cache waits no
// backoff after a failed load, and its gate reloads a behind network once an hour, so loads come when a test asks.
func (self *testGateLog) newProcess(world *testSocketWorld, mutate func(settings *socketsservice.SocketsSettings)) *testSocketProcess {
	self.t.Helper()
	host := sidecartest.NewFakeHost(world.ctx, world.clock, nil, nil, nil)
	gates := "sidecar:\n  sockets: {enabled: true, percent: 100}\n  urnetwork_edge: " + world.edgeNetworkId.String() + "\n"
	if err := host.Gates.Set(gates); err != nil {
		self.t.Fatal(err)
	}
	serviceHost := host.ServiceHost()
	serviceHost.Authenticator = world.authenticator
	settings := socketsservice.DefaultSocketsSettings()
	settings.Gate.Cache.PollJitter = 0
	settings.Gate.Cache.FailureBackoff = 0
	settings.Gate.BehindReloadInterval = time.Hour
	if mutate != nil {
		mutate(settings)
	}
	gate, err := socketsservice.NewSocketProjectionGate(world.ctx, serviceHost, self.source, settings.Gate)
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(gate.Close)
	service, err := socketsservice.NewSocketsService(world.ctx, serviceHost, world.store, gate, settings)
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(service.Close)
	service.SetTicketKeys(world.ticketKeys)
	// before its first over-limit answer every network reads as spent
	if err := gate.AwaitOverLimitReads(world.ctx, 1); err != nil {
		self.t.Fatal(err)
	}
	return &testSocketProcess{world: world, host: host, projection: gate, service: service}
}

// Asks the process's gate for networkId until a load lands, failing the test unless the network is then served.
func (self *testSocketProcess) awaitLoaded(networkId connect.Id) socketsservice.SocketGateView {
	self.world.t.Helper()
	count := self.projection.LoadCount()
	if view, err := self.projection.View(networkId); err == nil {
		return view
	}
	if err := self.projection.AwaitLoads(self.world.ctx, count+1); err != nil {
		self.world.t.Fatal(err)
	}
	view, err := self.projection.View(networkId)
	if err != nil {
		self.world.t.Fatalf("after its load the network answers %v", err)
	}
	return view
}

// The {acl_<N>}v event, and the load it starts awaited.
func (self *testSocketProcess) changed(networkId connect.Id) {
	self.world.t.Helper()
	count := self.projection.LoadCount()
	self.service.ProjectionChanged(networkId)
	if err := self.projection.AwaitLoads(self.world.ctx, count+1); err != nil {
		self.world.t.Fatal(err)
	}
}

// One Find of app/db by dialer: the refusal's code, or "" with the primary ticket verified.
func (self *testSocketProcess) findAppDb(network *testGateNetwork, dialer *testSocketSidecar) (sidecar.SocketErrorCode, *protocol.SocketTicket) {
	self.world.t.Helper()
	networkId := network.networkId
	code, result := self.find(dialer.token, &sidecar.SocketFindArgs{NameToken: network.tokenPath, NetworkId: &networkId})
	if code != http.StatusOK {
		self.world.t.Fatalf("a Find answered %d", code)
	}
	if result.Error != nil {
		return result.Error.Code, nil
	}
	return "", self.world.verifyTicket(result.Primary)
}

// A Find of a network the gate holds nothing of answers unavailable and starts its load; once loaded, a page at the
// tip's position writes the lease, the claim verifying under the identity key the log admits, and a Find signs at
// the tip.
func TestGateLoadsOnFirstAskAndServesTheVerifiedState(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	listener := network.sidecarOf(world, network.listener)
	dialer := network.sidecarOf(world, network.dialer)

	networkId := network.networkId
	code, result := process.find(dialer.token, &sidecar.SocketFindArgs{NameToken: network.tokenPath, NetworkId: &networkId})
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable || result.Error.RetryAfterMs != 250 {
		t.Fatalf("a Find of an unloaded network answered %d, %+v", code, result)
	}
	if process.service.SignedTicketCount() != 0 {
		t.Fatal("an unloaded network got a ticket")
	}
	view := process.awaitLoaded(networkId)
	if view.Position() != network.tip() {
		t.Fatalf("the view stands at %d, the tip %d", view.Position(), network.tip())
	}
	if publicKey, found := view.IdentityKey(listener.sidecarId); !found || !bytes.Equal(publicKey, network.listener.PublicKey()) {
		t.Fatal("the listener's identity key is not the one the log admits")
	}
	if _, found := view.IdentityKey(testSocketId()); found {
		t.Fatal("a sidecar the log never admitted has an identity key")
	}

	process.registerOk(listener, 1, listener.blindedRegistration(t, network.tokenPath))
	errorCode, ticket := process.findAppDb(network, dialer)
	if errorCode != "" {
		t.Fatalf("the Find answered %s", errorCode)
	}
	if ticket.GetPolicyVersion() != network.tip() {
		t.Fatalf("the ticket stands at %d, the tip %d", ticket.GetPolicyVersion(), network.tip())
	}

	// a sidecar the grant does not name may not listen
	stranger := world.newSidecar(networkId)
	if verdict := view.MayListen(&socketsservice.SocketGateRequest{NetworkId: networkId, SidecarId: &stranger.sidecarId, NameToken: network.tokenPath}, world.clock.Now()); verdict.Allowed {
		t.Fatal("a sidecar outside the grant may listen")
	}
	if verdict := view.MayListen(&socketsservice.SocketGateRequest{NetworkId: networkId, NameToken: network.tokenPath}, world.clock.Now()); verdict.Allowed {
		t.Fatal("a request naming no sidecar may listen")
	}
}

// 13.6's TestBehindProcessAdmitsNothing (SockReg.tla's BehindAllows twin): a process whose evidence says the log
// passed what it holds, and that cannot load the new entries, judges no page, makes no pick and signs no ticket once
// the grace has passed; when the source answers again the next load covers the evidence and the revoked listener's
// page is refused.
func TestBehindProcessAdmitsNothing(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	listener := network.sidecarOf(world, network.listener)
	dialer := network.sidecarOf(world, network.dialer)
	process.awaitLoaded(network.networkId)
	registration := listener.blindedRegistration(t, network.tokenPath)
	process.registerOk(listener, 1, registration)

	log.source.setFailing(network.networkId, true)
	network.savePolicy(false)
	process.changed(network.networkId)
	world.clock.Advance(socketsservice.DefaultSocketGateSettings().BehindGrace)
	if _, err := process.projection.View(network.networkId); !errors.Is(err, socketsservice.ErrSocketGateBehind) {
		t.Fatalf("past the grace the network answers %v", err)
	}

	pages, picks, signed := world.fakeStore.OpCount("ApplyPage"), world.fakeStore.OpCount("Pick"), process.service.SignedTicketCount()
	code, result := process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 2, Registrations: []*sidecar.SocketRegistration{registration}})
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable {
		t.Fatalf("a page while behind answered %d, %+v", code, result)
	}
	if errorCode, _ := process.findAppDb(network, dialer); errorCode != sidecar.SocketErrorCodeUnavailable {
		t.Fatalf("a Find while behind answered %s", errorCode)
	}
	if world.fakeStore.OpCount("ApplyPage") != pages || world.fakeStore.OpCount("Pick") != picks || process.service.SignedTicketCount() != signed {
		t.Fatal("a behind process reached the store or signed")
	}

	log.source.setFailing(network.networkId, false)
	process.changed(network.networkId)
	if view, err := process.projection.View(network.networkId); err != nil || view.Position() != network.tip() {
		t.Fatalf("once the source answers the network answers %v", err)
	}
	code, result = process.register(listener.token, &sidecar.SocketRegistrationsArgs{SetVersion: 3, Registrations: []*sidecar.SocketRegistration{registration}})
	if code != http.StatusOK || result.Error != nil || (result.Statuses[0] != sidecar.SocketRegistrationStatusRevoked && result.Statuses[0] != sidecar.SocketRegistrationStatusDenied) {
		t.Fatalf("the revoked listener's page answered %d, %+v", code, result)
	}
	if errorCode, _ := process.findAppDb(network, dialer); errorCode != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("a Find of the revoked name answered %s", errorCode)
	}
}

// A revocation reaches Find within the grace (13.2.3's bounds): while its load is held, the process serves its last
// state for at most BehindGrace after the event, then answers unavailable; once the load lands, the revoked
// listener gets no ticket, its lease ends for cause and its client is hinted once.
func TestGateRevocationReachesFindWithinTheGrace(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	listener := network.sidecarOf(world, network.listener)
	dialer := network.sidecarOf(world, network.dialer)
	process.awaitLoaded(network.networkId)
	process.registerOk(listener, 1, listener.blindedRegistration(t, network.tokenPath))
	if errorCode, _ := process.findAppDb(network, dialer); errorCode != "" {
		t.Fatalf("before the revocation the Find answered %s", errorCode)
	}

	release := log.source.holdEntries()
	network.savePolicy(false)
	count := process.projection.LoadCount()
	process.service.ProjectionChanged(network.networkId)
	<-log.source.started
	world.clock.Advance(socketsservice.DefaultSocketGateSettings().BehindGrace - time.Millisecond)
	if _, err := process.projection.View(network.networkId); err != nil {
		t.Fatalf("inside the grace the network answers %v", err)
	}
	world.clock.Advance(time.Millisecond)
	signed := process.service.SignedTicketCount()
	if errorCode, _ := process.findAppDb(network, dialer); errorCode != sidecar.SocketErrorCodeUnavailable {
		t.Fatalf("past the grace with its load held the Find answered %s", errorCode)
	}
	release()
	if err := process.projection.AwaitLoads(world.ctx, count+1); err != nil {
		t.Fatal(err)
	}
	if errorCode, _ := process.findAppDb(network, dialer); errorCode != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("after the load the Find answered %s", errorCode)
	}
	if process.service.SignedTicketCount() != signed {
		t.Fatal("a ticket was signed for the revoked listener")
	}
	if listeners, err := world.fakeStore.ListListeners(world.ctx, network.networkId, network.tokenPath); err != nil || len(listeners) != 0 {
		t.Fatalf("the revoked lease stands: %d, %v", len(listeners), err)
	}
	// the base queued a sweep, which may have removed the lease before the Find: whichever removed it hinted
	if err := process.service.AwaitSweeps(world.ctx, 1); err != nil {
		t.Fatal(err)
	}
	revoked := 0
	for _, hint := range process.host.Push.Hints(listener.clientId) {
		message := &protocol.SocketHint{}
		if hint.Topic == sidecar.PushTopicSock && proto.Unmarshal(hint.Body, message) == nil && message.GetKind() == protocol.SocketHintKind_SOCKET_HINT_REVOKED {
			revoked += 1
		}
	}
	if revoked != 1 {
		t.Fatalf("%d revocation hints", revoked)
	}
}

// With no evidence a process serves its last verified state through a source outage, the cache's poll included; with
// evidence it cannot follow, the network alone answers unavailable after the grace, another network served on, and
// the source's return makes it fresh again.
func TestGateSourceOutageRefusesOnlyANetworkWithEvidence(t *testing.T) {
	log := newTestGateLog(t)
	first := log.newNetwork()
	second := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	process.awaitLoaded(first.networkId)
	process.awaitLoaded(second.networkId)

	log.source.setFailing(first.networkId, true)
	log.source.setFailing(second.networkId, true)
	count := process.projection.LoadCount()
	world.clock.Advance(socketsservice.DefaultSocketGateSettings().Cache.PollInterval)
	if err := process.projection.AwaitLoads(world.ctx, count+2); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(time.Minute)
	for _, network := range []*testGateNetwork{first, second} {
		if view, err := process.projection.View(network.networkId); err != nil || view.Position() != network.tip() {
			t.Fatalf("with no evidence, through a failed poll, the network answers %v", err)
		}
	}

	process.changed(first.networkId)
	world.clock.Advance(socketsservice.DefaultSocketGateSettings().BehindGrace)
	if _, err := process.projection.View(first.networkId); !errors.Is(err, socketsservice.ErrSocketGateBehind) {
		t.Fatalf("the network with evidence answers %v", err)
	}
	if _, err := process.projection.View(second.networkId); err != nil {
		t.Fatalf("the other network answers %v", err)
	}

	log.source.setFailing(first.networkId, false)
	process.changed(first.networkId)
	if _, err := process.projection.View(first.networkId); err != nil {
		t.Fatalf("once its source answers the network answers %v", err)
	}
}

// A network whose evidence stays uncovered asks for another load each BehindReloadInterval, so it is fresh again
// once the source answers, with no further event.
func TestGateBehindNetworkReloadsOnItsInterval(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, func(settings *socketsservice.SocketsSettings) {
		settings.Gate.BehindReloadInterval = 5 * time.Second
	})
	process.awaitLoaded(network.networkId)
	log.source.setFailing(network.networkId, true)
	network.admission.AdmitMember(network.admission.Owner(), "after the outage", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	process.changed(network.networkId)
	log.source.setFailing(network.networkId, false)
	count := process.projection.LoadCount()
	world.clock.Advance(5 * time.Second)
	if err := process.projection.AwaitLoads(world.ctx, count+1); err != nil {
		t.Fatal(err)
	}
	if view, err := process.projection.View(network.networkId); err != nil || view.Position() != network.tip() {
		t.Fatalf("after its reload the network answers %v", err)
	}
}

// 13.6: a process whose event is withheld serves its last state, which nothing contradicts, until the resubscription
// check finds {acl_}v moved; a check that finds it unmoved loads nothing.
func TestGateWithheldEventServesUntilTheResubscriptionCheck(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	listener := network.sidecarOf(world, network.listener)
	dialer := network.sidecarOf(world, network.dialer)
	held := process.awaitLoaded(network.networkId).Position()
	process.registerOk(listener, 1, listener.blindedRegistration(t, network.tokenPath))

	network.savePolicy(false)
	if _, err := process.host.Redis.Increment(world.ctx, sidecar.AclVersionKey(sidecar.Id(network.networkId)), time.Hour); err != nil {
		t.Fatal(err)
	}
	// past any grace, inside the lease
	world.clock.Advance(4 * socketsservice.DefaultSocketGateSettings().BehindGrace)
	errorCode, ticket := process.findAppDb(network, dialer)
	if errorCode != "" || ticket.GetPolicyVersion() != held {
		t.Fatalf("with its event withheld the Find answered %s at %d", errorCode, ticket.GetPolicyVersion())
	}

	count := process.projection.LoadCount()
	process.service.ProjectionsResync()
	if err := process.projection.AwaitResyncs(world.ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := process.projection.AwaitLoads(world.ctx, count+1); err != nil {
		t.Fatal(err)
	}
	if view, err := process.projection.View(network.networkId); err != nil || view.Position() != network.tip() {
		t.Fatalf("after the check the network answers %v", err)
	}
	if errorCode, _ := process.findAppDb(network, dialer); errorCode != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("after the check the Find answered %s", errorCode)
	}

	count = process.projection.LoadCount()
	process.service.ProjectionsResync()
	if err := process.projection.AwaitResyncs(world.ctx, 2); err != nil {
		t.Fatal(err)
	}
	if process.projection.LoadCount() != count {
		t.Fatal("a check that found {acl_}v unmoved loaded the network")
	}
}

// A run the cache refuses covers nothing (section 5's checks, 13.2.3): a forked A_n at a held position, refused with
// an alarm, and a run with a gap leave the network behind past the grace, while its last state served inside it; an
// honest run covers it again.
func TestGateRefusedRunsCoverNothing(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	held := process.awaitLoaded(network.networkId).Position()

	forked := network.admission.ForkEntryAt(held, network.admission.Sign(network.listener, bridge.SignedType_SIGNED_MEMBER_ADMIT,
		network.admission.MemberAdmit(network.admission.Id("a member api never sequenced"), bridge.MemberRole_MEMBER_ROLE_MEMBER)))
	log.source.setRewrite(func(entries [][]byte) [][]byte { return [][]byte{forked} })
	alarms := process.projection.Stats().AlarmCount
	process.changed(network.networkId)
	if process.projection.Stats().AlarmCount != alarms+1 {
		t.Fatal("a second A_n raised no alarm")
	}
	if view, err := process.projection.View(network.networkId); err != nil || view.Position() != held {
		t.Fatalf("inside the grace the network answers %v", err)
	}
	world.clock.Advance(socketsservice.DefaultSocketGateSettings().BehindGrace)
	if _, err := process.projection.View(network.networkId); !errors.Is(err, socketsservice.ErrSocketGateBehind) {
		t.Fatalf("after a refused fork the network answers %v", err)
	}
	log.source.setRewrite(nil)
	process.changed(network.networkId)
	if view, err := process.projection.View(network.networkId); err != nil || view.Position() != held {
		t.Fatalf("after an honest run the network answers %v", err)
	}

	network.admission.AdmitMember(network.admission.Owner(), "gap one", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	network.admission.AdmitMember(network.admission.Owner(), "gap two", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	log.source.setRewrite(func(entries [][]byte) [][]byte {
		if len(entries) < 2 {
			return entries
		}
		return entries[1:]
	})
	failures := process.projection.Stats().LoadFailureCount
	process.changed(network.networkId)
	if process.projection.Stats().LoadFailureCount <= failures {
		t.Fatal("a run with a gap was not refused")
	}
	world.clock.Advance(socketsservice.DefaultSocketGateSettings().BehindGrace)
	if _, err := process.projection.View(network.networkId); !errors.Is(err, socketsservice.ErrSocketGateBehind) {
		t.Fatalf("after a run with a gap the network answers %v", err)
	}
	log.source.setRewrite(nil)
	process.changed(network.networkId)
	if view, err := process.projection.View(network.networkId); err != nil || view.Position() != network.tip() {
		t.Fatalf("after the whole run the network answers %v", err)
	}
}

// A store answer naming a position above the state is evidence, covered only by a load that reaches it; a position at
// or below the state's, and a client removal's fence, are none.
func TestGateObservedPositionIsEvidenceUntilALoadReachesIt(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	held := process.awaitLoaded(network.networkId).Position()

	count := process.projection.LoadCount()
	process.projection.Observe(network.networkId, held)
	process.projection.Observe(network.networkId, socketsservice.SocketRemovedClientPosition)
	world.clock.Advance(socketsservice.DefaultSocketGateSettings().BehindGrace)
	if _, err := process.projection.View(network.networkId); err != nil || process.projection.LoadCount() != count {
		t.Fatalf("no evidence at all made the network answer %v", err)
	}

	// a fresher process admitted a lease at the next position, which this process's source does not yet serve
	process.projection.Observe(network.networkId, held+1)
	if err := process.projection.AwaitLoads(world.ctx, count+1); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(socketsservice.DefaultSocketGateSettings().BehindGrace)
	if _, err := process.projection.View(network.networkId); !errors.Is(err, socketsservice.ErrSocketGateBehind) {
		t.Fatalf("a load short of the observed position left the network answering %v", err)
	}
	network.admission.AdmitMember(network.admission.Owner(), "the observed position", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	process.changed(network.networkId)
	if view, err := process.projection.View(network.networkId); err != nil || view.Position() < held+1 {
		t.Fatalf("a load reaching the observed position left the network answering %v", err)
	}
}

// The sweep's queue (13.2.3): a network's first load queues nothing, a run of widening entries queues nothing, and a
// base, which may narrow, queues the network at its new position.
func TestGateQueuesASweepForANarrowingRunAlone(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	var stateLock sync.Mutex
	narrowed := []uint64{}
	process.projection.OnNarrowed(func(networkId connect.Id, position uint64) {
		stateLock.Lock()
		defer stateLock.Unlock()
		narrowed = append(narrowed, position)
	})
	process.awaitLoaded(network.networkId)
	network.admission.AdmitMember(network.admission.Owner(), "widening", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	process.changed(network.networkId)
	network.savePolicy(false)
	process.changed(network.networkId)
	stateLock.Lock()
	defer stateLock.Unlock()
	if !slices.Equal(narrowed, []uint64{network.tip()}) {
		t.Fatalf("queued %v, the base at %d", narrowed, network.tip())
	}
}

// 13.2.3's kind table: the widening statements and the repo statements no socket check reads queue no sweep; a base,
// a tick, every other statement, an unknown type and a body that does not parse do.
func TestSocketEntryMayNarrowErrsTowardSweeping(t *testing.T) {
	statement := func(signedType bridge.SignedType) *bridge.AuthEntry {
		body, err := proto.Marshal(&bridge.Signed{Type: uint32(signedType), Body: []byte("statement")})
		if err != nil {
			t.Fatal(err)
		}
		return &bridge.AuthEntry{Kind: bridge.AuthEntryKindStatement, Body: body}
	}
	widening := []bridge.SignedType{
		bridge.SignedType_SIGNED_GRANT_ACTIVATE, bridge.SignedType_SIGNED_UNSUSPEND, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		bridge.SignedType_SIGNED_MEMBER_ADMIT, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, bridge.SignedType_SIGNED_OWNER_CONFIRM,
		bridge.SignedType_SIGNED_KEY_REGISTER, bridge.SignedType_SIGNED_EVS_SHARE,
	}
	for signedType := bridge.SignedType_SIGNED_REPO_CREATE; signedType <= bridge.SignedType_SIGNED_AUDIT_OPT_OUT; signedType += 1 {
		widening = append(widening, signedType)
	}
	for _, signedType := range widening {
		if socketsservice.SocketEntryMayNarrowForTest(statement(signedType)) {
			t.Errorf("%v may narrow", signedType)
		}
	}
	narrowing := []*bridge.AuthEntry{
		statement(bridge.SignedType_SIGNED_GRANT_REVOKE), statement(bridge.SignedType_SIGNED_SUSPEND),
		statement(bridge.SignedType_SIGNED_SIDECAR_REVOKE), statement(bridge.SignedType_SIGNED_MEMBER_REVOKE),
		statement(bridge.SignedType_SIGNED_DELEGATION_REVOKE), statement(bridge.SignedType_SIGNED_KEY_REVOKE),
		statement(bridge.SignedType(0x12FF)),
		{Kind: bridge.AuthEntryKindStatement, Body: []byte{0xff, 0xff}},
		{Kind: bridge.AuthEntryKindBase},
		{Kind: bridge.AuthEntryKindTick},
		{Kind: 9},
	}
	for index, entry := range narrowing {
		if !socketsservice.SocketEntryMayNarrowForTest(entry) {
			t.Errorf("entry %d may not narrow", index)
		}
	}
}

// urnetwork-edge holds no log: its view refuses every check, and the gate loads nothing for it.
func TestGatePlatformNetworkRefusesEveryCheck(t *testing.T) {
	log := newTestGateLog(t)
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	view, err := process.projection.View(world.edgeNetworkId)
	if err != nil || view.Position() != 0 {
		t.Fatalf("the platform network answers %v", err)
	}
	sidecarId := testSocketId()
	request := &socketsservice.SocketGateRequest{NetworkId: world.edgeNetworkId, SidecarId: &sidecarId, Name: "ur/smtpedge"}
	if view.MayListen(request, world.clock.Now()).Allowed || view.MayDial(request, world.clock.Now()).Allowed || view.MayPublish(request, world.clock.Now()).Allowed {
		t.Fatal("the platform network allowed a check")
	}
	if process.projection.LoadCount() != 0 {
		t.Fatal("the gate loaded the platform network")
	}
}
