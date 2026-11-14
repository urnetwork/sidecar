// §13.9's system publish at T2 (SOCK-M8-01; §9.10, §15.5), on FakeSocketStore and FakeSocketGate: a receiver, a
// sidecar whose only grant is its approved smtp/25/mx listen, registers tls/443/mta-sts and an edge finds it, with no
// tls/ grant in the network, its ticket and pair resting on that listen grant; a non-receiver is refused whatever tls/
// grants it holds, at registration and at Find's listener check; the listen grant's revocation ends the publish at the
// heartbeat, at Find and by the sweep, and its expiry at Find and in the ticket; and no other name takes the path.
// The listener's half is socket_admission_test.go's. Feeds §22.5's §13 row: mta-sts served only as a receiver's system
// publish.

package socketsservice_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// tls/'s hooks for the scene: they allow, record what they were asked, and follow the transitions.
type testSocketSystemPublishHooks struct {
	testSocketRecordingHooks
	checks []*socketsservice.SocketListenCheck
}

func (self *testSocketSystemPublishHooks) ValidateListen(ctx context.Context, check *socketsservice.SocketListenCheck) error {
	self.checks = append(self.checks, check)
	return self.testSocketRecordingHooks.ValidateListen(ctx, check)
}

// A process with tls/ open over recording hooks; a network whose receiver holds smtp/25/mx's listen grant, 2 h long,
// and no tls/ grant, as nothing in it does; and an edge with three clients.
type testSocketSystemPublishScene struct {
	world        *testSocketWorld
	process      *testSocketProcess
	hooks        *testSocketSystemPublishHooks
	networkId    connect.Id
	receiver     *testSocketSidecar
	expireMillis uint64
	edge         *testSocketEdge
}

func newTestSocketSystemPublishScene(t *testing.T) *testSocketSystemPublishScene {
	world := newTestSocketWorld(t)
	scene := &testSocketSystemPublishScene{
		world:     world,
		process:   world.newProcess(nil),
		hooks:     &testSocketSystemPublishHooks{},
		networkId: testSocketId(),
		edge:      world.newEdge(3),
	}
	if err := scene.process.service.RegisterNamespace(sidecar.SocketNamespaceTls, scene.hooks); err != nil {
		t.Fatal(err)
	}
	scene.receiver = world.newSidecar(scene.networkId)
	scene.expireMillis = uint64(world.clock.Now().Add(2 * time.Hour).UnixMilli())
	scene.process.gate.SetIdentityKey(scene.networkId, scene.receiver.sidecarId, scene.receiver.publicKey())
	scene.process.gate.AllowListen(scene.networkId, scene.receiver.sidecarId, []byte(sidecar.SocketSystemPublishListenName), sidecartest.FakeSocketGrant{
		GrantId:      []byte("receiver-smtp-listen"),
		ExpireMillis: scene.expireMillis,
	})
	scene.process.gate.Load(scene.networkId)
	return scene
}

// listener's registration of the system publish, app mode as given.
func testSocketSystemPublishRegistration(t *testing.T, listener *testSocketSidecar, appMode string) *sidecar.SocketRegistration {
	return listener.edgeRegistration(t, sidecar.SocketSystemPublishName, "tls", appMode)
}

// The edge's Find of name in the scene's network.
func (self *testSocketSystemPublishScene) find(name string) (int, *sidecar.SocketFindResult) {
	networkId := self.networkId
	return self.process.find(self.edge.token, &sidecar.SocketFindArgs{Name: name, NetworkId: &networkId, ClientIds: self.edge.clientIdArgs()})
}

// One page of listener's registrations under setVersion: the status of each, in name key order.
func (self *testSocketSystemPublishScene) statuses(t *testing.T, listener *testSocketSidecar, setVersion uint64, registrations ...*sidecar.SocketRegistration) []sidecar.SocketRegistrationStatus {
	t.Helper()
	code, result := self.process.register(listener.token, &sidecar.SocketRegistrationsArgs{
		SetVersion:    setVersion,
		Registrations: testSocketSortRegistrations(registrations),
	})
	if code != http.StatusOK || result.Error != nil {
		t.Fatalf("the page answered %d, %+v", code, result)
	}
	return result.Statuses
}

// The leases of the system publish in the scene's network.
func (self *testSocketSystemPublishScene) leases(t *testing.T) []*socketsservice.SocketStoreListener {
	t.Helper()
	listeners, err := self.world.fakeStore.ListListeners(self.world.ctx, self.networkId, []byte(sidecar.SocketSystemPublishName))
	if err != nil {
		t.Fatal(err)
	}
	return listeners
}

// A receiver registers the system publish and an edge finds it, with no tls/ grant anywhere in the network: the entry
// reaches tls/'s ValidateListen with the receiver's smtp/25/mx listen as its verdict, and the edge's ticket and pair
// rest on that grant, its id and its expiry.
func TestSocketSystemPublishReceiverRegistersAndIsFound(t *testing.T) {
	scene := newTestSocketSystemPublishScene(t)
	world := scene.world
	receiver := scene.receiver
	scene.process.registerOk(receiver, 1, testSocketSystemPublishRegistration(t, receiver, "http"))
	if len(scene.hooks.checks) != 1 {
		t.Fatalf("tls/'s ValidateListen was asked %d times", len(scene.hooks.checks))
	}
	check := scene.hooks.checks[0]
	switch {
	case check.Name != sidecar.SocketSystemPublishName, check.Namespace != sidecar.SocketNamespaceTls,
		check.SidecarId == nil || *check.SidecarId != receiver.sidecarId, check.Registration.AppMode != "http":
		t.Fatalf("ValidateListen saw %+v", check)
	case check.Listen == nil || !check.Listen.Allowed || !bytes.Equal(check.Listen.GrantId, []byte("receiver-smtp-listen")) ||
		check.Listen.GrantExpireMillis != scene.expireMillis:
		t.Fatalf("the entry rests on %+v, not the receiver's listen", check.Listen)
	}
	if !slices.Equal(scene.hooks.firstListens, []string{sidecar.SocketSystemPublishName}) {
		t.Fatalf("FirstListen %v", scene.hooks.firstListens)
	}

	code, result := scene.find(sidecar.SocketSystemPublishName)
	if code != http.StatusOK || result.Error != nil || result.Primary == nil || result.Backup != nil {
		t.Fatalf("the edge's Find answered %d, %+v", code, result)
	}
	ticket := world.verifyTicket(result.Primary)
	switch {
	case ticket.GetName() != sidecar.SocketSystemPublishName, len(ticket.GetNameToken()) != 0,
		!bytes.Equal(ticket.GetListenerClientId(), receiver.clientId.Bytes()),
		!bytes.Equal(ticket.GetDialerNetworkId(), world.edgeNetworkId.Bytes()):
		t.Fatalf("the ticket names %v", ticket)
	case !bytes.Equal(ticket.GetGrantId(), []byte("receiver-smtp-listen")), ticket.GetGrantExpireTimeMillis() != scene.expireMillis:
		t.Fatalf("the ticket rests on %v", ticket)
	}
	dialerClientId, err := connect.IdFromBytes(ticket.GetDialerClientId())
	if err != nil || !slices.Contains(scene.edge.clientIds, dialerClientId) {
		t.Fatal("the ticket names a client the edge does not hold")
	}
	if pairExpireMillis, found, err := world.fakeStore.GetServicePair(world.ctx, receiver.clientId, dialerClientId); err != nil || !found || pairExpireMillis != scene.expireMillis {
		t.Fatalf("the pair: %d, %v, %v", pairExpireMillis, found, err)
	}
}

// A non-receiver is refused: a sidecar holding every tls/ grant the publish could have, listen, publish and a public
// dial, and no smtp/25/mx listen, is denied at registration, and tls/'s ValidateListen never sees it; a lease it
// holds from a process that judged it before its listen grant went is refused at the listener check, removed with a
// SOCKET_HINT_REVOKED, and takes no ticket.
func TestSocketSystemPublishRefusesANonReceiver(t *testing.T) {
	scene := newTestSocketSystemPublishScene(t)
	world := scene.world
	process := scene.process
	stranger := world.newSidecar(scene.networkId)
	name := []byte(sidecar.SocketSystemPublishName)
	process.gate.SetIdentityKey(scene.networkId, stranger.sidecarId, stranger.publicKey())
	process.gate.AllowListen(scene.networkId, stranger.sidecarId, name, testSocketGrant("tls-listen"))
	process.gate.AllowPublish(scene.networkId, name, testSocketGrant("tls-publish"))
	process.gate.AllowPublicDial(scene.networkId, name, testSocketGrant("tls-public"))
	process.gate.Load(scene.networkId)
	statuses := scene.statuses(t, stranger, 1, testSocketSystemPublishRegistration(t, stranger, "http"))
	if statuses[0] != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("a non-receiver's registration answered %s", statuses[0])
	}
	if len(scene.hooks.checks) != 0 {
		t.Fatal("tls/'s ValidateListen saw a non-receiver")
	}

	// a process at an older position that still held the stranger's smtp/25/mx listen wrote its lease
	stale := world.newProcess(nil)
	if err := stale.service.RegisterNamespace(sidecar.SocketNamespaceTls, &testSocketRecordingHooks{}); err != nil {
		t.Fatal(err)
	}
	stale.gate.SetIdentityKey(scene.networkId, stranger.sidecarId, stranger.publicKey())
	stale.gate.AllowListen(scene.networkId, stranger.sidecarId, []byte(sidecar.SocketSystemPublishListenName), testSocketGrant("old-smtp-listen"))
	stale.gate.LoadAt(scene.networkId, 1)
	process.gate.LoadAt(scene.networkId, 3)
	registration := testSocketSystemPublishRegistration(t, stranger, "http")
	stale.registerOk(stranger, 2, registration)
	if leases := scene.leases(t); len(leases) != 1 {
		t.Fatalf("%d leases before the Find", len(leases))
	}

	code, result := scene.find(sidecar.SocketSystemPublishName)
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("a Find of a non-receiver's lease answered %d, %+v", code, result)
	}
	if count := process.service.SignedTicketCount(); count != 0 {
		t.Fatalf("%d tickets signed for a non-receiver", count)
	}
	if leases := scene.leases(t); len(leases) != 0 {
		t.Fatal("the non-receiver's lease stands")
	}
	if hints := testSocketRevokedHints(t, process.host, stranger.clientId); len(hints) != 1 || !bytes.Equal(hints[0], registration.ListenId.Bytes()) {
		t.Fatalf("the non-receiver's hints name %x", hints)
	}
}

// The listen grant's revocation ends the publish at the heartbeat: the receiver's next page answers revoked, and the
// lease and its last listener go.
func TestSocketSystemPublishRevocationEndsItAtTheHeartbeat(t *testing.T) {
	scene := newTestSocketSystemPublishScene(t)
	receiver := scene.receiver
	registration := testSocketSystemPublishRegistration(t, receiver, "http")
	scene.process.registerOk(receiver, 1, registration)
	scene.process.gate.RevokeListen(scene.networkId, receiver.sidecarId, []byte(sidecar.SocketSystemPublishListenName))
	scene.process.gate.Load(scene.networkId)
	if statuses := scene.statuses(t, receiver, 2, registration); statuses[0] != sidecar.SocketRegistrationStatusRevoked {
		t.Fatalf("the heartbeat after the revocation answered %s", statuses[0])
	}
	if leases := scene.leases(t); len(leases) != 0 {
		t.Fatal("the revoked receiver's lease stands")
	}
	if !slices.Equal(scene.hooks.lastUnlistens, []string{sidecar.SocketSystemPublishName}) {
		t.Fatalf("LastUnlisten %v", scene.hooks.lastUnlistens)
	}
}

// The listen grant's revocation ends the publish at Find: before the next heartbeat, a Find's listener check refuses
// the receiver, removes its lease and pairs and hints it, and signs nothing.
func TestSocketSystemPublishRevocationEndsItAtFind(t *testing.T) {
	scene := newTestSocketSystemPublishScene(t)
	world := scene.world
	receiver := scene.receiver
	registration := testSocketSystemPublishRegistration(t, receiver, "http")
	scene.process.registerOk(receiver, 1, registration)
	code, result := scene.find(sidecar.SocketSystemPublishName)
	if code != http.StatusOK || result.Error != nil {
		t.Fatalf("the Find before the revocation answered %d, %+v", code, result)
	}
	dialerClientId, _ := connect.IdFromBytes(world.verifyTicket(result.Primary).GetDialerClientId())
	signed := scene.process.service.SignedTicketCount()

	scene.process.gate.RevokeListen(scene.networkId, receiver.sidecarId, []byte(sidecar.SocketSystemPublishListenName))
	scene.process.gate.Load(scene.networkId)
	code, result = scene.find(sidecar.SocketSystemPublishName)
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("the Find after the revocation answered %d, %+v", code, result)
	}
	if count := scene.process.service.SignedTicketCount(); count != signed {
		t.Fatalf("%d tickets signed after the revocation", count-signed)
	}
	if leases := scene.leases(t); len(leases) != 0 {
		t.Fatal("the revoked receiver's lease stands")
	}
	if _, found, _ := world.fakeStore.GetServicePair(world.ctx, receiver.clientId, dialerClientId); found {
		t.Fatal("the revoked receiver's pair outlived its last edge name")
	}
	if hints := testSocketRevokedHints(t, scene.process.host, receiver.clientId); len(hints) != 1 || !bytes.Equal(hints[0], registration.ListenId.Bytes()) {
		t.Fatalf("the revoked receiver's hints name %x", hints)
	}
}

// The listen grant's revocation ends the publish by the sweep its load queues, with no Find or heartbeat.
func TestSocketSystemPublishRevocationEndsItBySweep(t *testing.T) {
	scene := newTestSocketSystemPublishScene(t)
	receiver := scene.receiver
	registration := testSocketSystemPublishRegistration(t, receiver, "http")
	scene.process.registerOk(receiver, 1, registration)
	scene.process.gate.RevokeListen(scene.networkId, receiver.sidecarId, []byte(sidecar.SocketSystemPublishListenName))
	position := scene.process.gate.Load(scene.networkId)
	scene.process.service.QueueSweepForTest(scene.networkId, position)
	if err := scene.process.service.AwaitSweeps(scene.world.ctx, 1); err != nil {
		t.Fatal(err)
	}
	if leases := scene.leases(t); len(leases) != 0 {
		t.Fatal("the sweep left the revoked receiver's lease")
	}
	if hints := testSocketRevokedHints(t, scene.process.host, receiver.clientId); len(hints) != 1 || !bytes.Equal(hints[0], registration.ListenId.Bytes()) {
		t.Fatalf("the revoked receiver's hints name %x", hints)
	}
}

// The listen grant's expiry ends the publish: the ticket's grant ends with it, so the listener resets its stream
// there; a heartbeat 10 s before it keeps the lease, and 11 s on, the grant run out and the lease not, a Find refuses
// and removes the lease at its listener check, and the next heartbeat is refused.
func TestSocketSystemPublishEndsAtItsGrantsExpiry(t *testing.T) {
	scene := newTestSocketSystemPublishScene(t)
	world := scene.world
	receiver := scene.receiver
	registration := testSocketSystemPublishRegistration(t, receiver, "http")
	scene.process.registerOk(receiver, 1, registration)
	code, result := scene.find(sidecar.SocketSystemPublishName)
	if code != http.StatusOK || result.Error != nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if ticket := world.verifyTicket(result.Primary); ticket.GetGrantExpireTimeMillis() != scene.expireMillis {
		t.Fatalf("the ticket's grant ends at %d, not the listen grant's %d", ticket.GetGrantExpireTimeMillis(), scene.expireMillis)
	}

	world.clock.Advance(2*time.Hour - 10*time.Second)
	scene.process.registerOk(receiver, 2, registration)
	world.clock.Advance(11 * time.Second)
	if leases := scene.leases(t); len(leases) != 1 {
		t.Fatalf("%d leases before the Find past the grant's expiry", len(leases))
	}
	code, result = scene.find(sidecar.SocketSystemPublishName)
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("a Find past the grant's expiry answered %d, %+v", code, result)
	}
	if leases := scene.leases(t); len(leases) != 0 {
		t.Fatal("the lease outlived its grant at Find")
	}
	if statuses := scene.statuses(t, receiver, 3, registration); statuses[0] != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("a heartbeat past the grant's expiry answered %s", statuses[0])
	}
}

// No other name takes the path: a receiver holding only its smtp/25/mx listen is denied tls/443/other, tls/8443/mta-sts
// and the system publish in app mode raw, in one page beside its accepted system publish; and an edge's Find of
// tls/443/other runs the dial check the system publish skips, so it is denied before any group is read.
func TestSocketSystemPublishTakesNoOtherName(t *testing.T) {
	scene := newTestSocketSystemPublishScene(t)
	receiver := scene.receiver
	accepted := testSocketSystemPublishRegistration(t, receiver, "http")
	scene.process.registerOk(receiver, 1, accepted)
	other := receiver.edgeRegistration(t, "tls/443/other", "tls", "http")
	otherPort := receiver.edgeRegistration(t, "tls/8443/mta-sts", "tls", "http")
	statuses := scene.statuses(t, receiver, 2, accepted, other, otherPort)
	sorted := testSocketSortRegistrations([]*sidecar.SocketRegistration{accepted, other, otherPort})
	for index, registration := range sorted {
		want := sidecar.SocketRegistrationStatusDenied
		if registration == accepted {
			want = sidecar.SocketRegistrationStatusOk
		}
		if statuses[index] != want {
			t.Errorf("%s answered %s", registration.Name, statuses[index])
		}
	}

	raw := testSocketSystemPublishRegistration(t, receiver, "raw")
	if statuses := scene.statuses(t, receiver, 3, raw); statuses[0] != sidecar.SocketRegistrationStatusRevoked {
		t.Fatalf("the system publish in app mode raw answered %s", statuses[0])
	}

	code, result := scene.find("tls/443/other")
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeDenied {
		t.Fatalf("an edge's Find of tls/443/other answered %d, %+v", code, result)
	}
	if count := scene.process.service.SignedTicketCount(); count != 0 {
		t.Fatalf("%d tickets signed", count)
	}
}

// The stand-in on the production gate, over a network's real authorization log and §8's own evaluator (SOCK-M5-07's
// world): a member device whose policy grants listen on sock:smtp/25/mx and nothing on tls/ registers the system
// publish and an edge finds it at the tip, the ticket resting on that rule; a policy that drops the listen and grants
// the name's own tls/ listen instead ends the receiver's publish, at its next heartbeat or by the sweep the policy's
// load queues, and the next Find finds no listener.
func TestSocketSystemPublishOnTheProductionGate(t *testing.T) {
	log := newTestGateLog(t)
	network := log.newNetwork()
	world := newTestSocketWorldOn(t, log.net.Clock())
	process := log.newProcess(world, nil)
	if err := process.service.RegisterNamespace(sidecar.SocketNamespaceTls, &testSocketSystemPublishHooks{}); err != nil {
		t.Fatal(err)
	}
	receiver := network.sidecarOf(world, network.listener)
	saveListen := func(dst string) {
		source := fmt.Sprintf(`{
			"grants": [
				{ "src": ["autogroup:member"], "dst": [%q], "allow": ["listen"] },
			],
		}`, dst)
		network.admission.SaveAclPolicy([]byte(source), sidecartest.AclSaveMembers{})
	}
	saveListen("sock:" + sidecar.SocketSystemPublishListenName)
	view := process.awaitLoaded(network.networkId)
	listen := view.MayListen(&socketsservice.SocketGateRequest{
		NetworkId: network.networkId,
		SidecarId: &receiver.sidecarId,
		Name:      sidecar.SocketSystemPublishListenName,
	}, world.clock.Now())
	if !listen.Allowed || len(listen.GrantId) == 0 {
		t.Fatalf("the policy's smtp/25/mx listen: %+v", listen)
	}

	registration := testSocketSystemPublishRegistration(t, receiver, "http")
	process.registerOk(receiver, 1, registration)
	edge := world.newEdge(2)
	networkId := network.networkId
	findArgs := &sidecar.SocketFindArgs{Name: sidecar.SocketSystemPublishName, NetworkId: &networkId, ClientIds: edge.clientIdArgs()}
	code, result := process.find(edge.token, findArgs)
	if code != http.StatusOK || result.Error != nil || result.Primary == nil {
		t.Fatalf("the edge's Find answered %d, %+v", code, result)
	}
	ticket := world.verifyTicket(result.Primary)
	if !bytes.Equal(ticket.GetListenerClientId(), receiver.clientId.Bytes()) || ticket.GetPolicyVersion() != network.tip() ||
		!bytes.Equal(ticket.GetGrantId(), listen.GrantId) {
		t.Fatalf("the ticket %v rests elsewhere than the receiver's listen at the tip", ticket)
	}

	saveListen("sock:" + sidecar.SocketSystemPublishName)
	process.changed(network.networkId)
	code, page := process.register(receiver.token, &sidecar.SocketRegistrationsArgs{SetVersion: 2, Registrations: []*sidecar.SocketRegistration{registration}})
	// the policy's load queued a sweep, which may have removed the lease before the heartbeat
	if code != http.StatusOK || page.Error != nil ||
		(page.Statuses[0] != sidecar.SocketRegistrationStatusRevoked && page.Statuses[0] != sidecar.SocketRegistrationStatusDenied) {
		t.Fatalf("the heartbeat after the listen went answered %d, %+v", code, page)
	}
	code, result = process.find(edge.token, findArgs)
	if code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("a Find after the listen went answered %d, %+v", code, result)
	}
}
