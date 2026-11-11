// smtp/ at T2 (SOCK-M7-01): the namespace opens only with §15's check; a receiver's smtp/25/mx is found by an
// mxedge-style edge Find on the receiver's own listen grant; a receiver with no listen grant is denied, one not
// serving takes no ticket, a member scope takes only consented devices, and a dead receiver falls to the backup.

package socketsservice_test

import (
	"bytes"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/socketsservice"
)

// A scope source that consents the sidecars a test lists, scope by scope, and answers undecided for one scope.
type testSocketScopeConsent struct {
	consented map[string][]connect.Id
	undecided string
}

func (self *testSocketScopeConsent) ConsentListen(networkId connect.Id, scope string, sidecarId *connect.Id) error {
	if scope == self.undecided {
		return socketsservice.ErrSocketListenUnavailable
	}
	if sidecarId != nil && slices.Contains(self.consented[scope], *sidecarId) {
		return nil
	}
	return socketsservice.ErrSocketListenRefused
}

// A process with smtp/ open over mail, a network with receiverCount receivers allowed to listen on name, each
// with its listen grant, and an edge with three clients.
type testSocketSmtpScene struct {
	world     *testSocketWorld
	process   *testSocketProcess
	mail      *testSocketRecordingHooks
	networkId connect.Id
	receivers []*testSocketSidecar
	edge      *testSocketEdge
}

func newTestSocketSmtpScene(t *testing.T, name string, receiverCount int, scopes socketsservice.SocketScopeConsent) *testSocketSmtpScene {
	world := newTestSocketWorld(t)
	scene := &testSocketSmtpScene{
		world:     world,
		process:   world.newProcess(nil),
		mail:      &testSocketRecordingHooks{},
		networkId: testSocketId(),
		edge:      world.newEdge(3),
	}
	if err := scene.process.service.RegisterSmtpNamespace(scene.mail, scopes); err != nil {
		t.Fatal(err)
	}
	for index := range receiverCount {
		receiver := world.newSidecar(scene.networkId)
		scene.process.gate.SetIdentityKey(scene.networkId, receiver.sidecarId, receiver.publicKey())
		scene.process.gate.AllowListen(scene.networkId, receiver.sidecarId, []byte(name), sidecartest.FakeSocketGrant{
			GrantId:      []byte{'r', byte('a' + index)},
			ExpireMillis: uint64(world.clock.Now().Add(time.Duration(index+1) * time.Hour).UnixMilli()),
		})
		scene.receivers = append(scene.receivers, receiver)
	}
	scene.process.gate.Load(scene.networkId)
	return scene
}

// A receiver's registration of name, serving or not, at max_streams 16 (§15.5).
func testSocketReceiverRegistration(t *testing.T, receiver *testSocketSidecar, name string, serving bool) *sidecar.SocketRegistration {
	registration := receiver.edgeRegistration(t, name, "smtp-starttls", "")
	registration.MaxStreams = 16
	registration.Serving = serving
	return registration
}

// The edge's Find of name in the scene's network.
func (self *testSocketSmtpScene) find(name string, failedTickets []*sidecar.SocketFailedTicket) (int, *sidecar.SocketFindResult) {
	networkId := self.networkId
	return self.process.find(self.edge.token, &sidecar.SocketFindArgs{
		Name:          name,
		NetworkId:     &networkId,
		ClientIds:     self.edge.clientIdArgs(),
		FailedTickets: failedTickets,
	})
}

// smtp/ opens only over §15's check: before it, and with none, a receiver is denied.
func TestSocketSmtpNamespaceOpensOnlyWithMailsCheck(t *testing.T) {
	world := newTestSocketWorld(t)
	process := world.newProcess(nil)
	receiver := testSocketEnrolledListener(world, process)
	args := &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{testSocketReceiverRegistration(t, receiver, "smtp/25/mx", true)}}
	if code, result := process.register(receiver.token, args); code != http.StatusOK || result.Statuses[0] != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("smtp/ unopened answered %d, %+v", code, result)
	}
	if err := process.service.RegisterSmtpNamespace(nil, nil); err == nil {
		t.Fatal("smtp/ opened with no §15 check")
	}
	if _, registered := process.service.LookupNamespace(sidecar.SocketNamespaceSmtp); registered {
		t.Fatal("a refused opening registered hooks")
	}
	mail := &testSocketRecordingHooks{}
	if err := process.service.RegisterSmtpNamespace(mail, nil); err != nil {
		t.Fatal(err)
	}
	args.SetVersion = 2
	if code, result := process.register(receiver.token, args); code != http.StatusOK || result.Statuses[0] != sidecar.SocketRegistrationStatusOk {
		t.Fatalf("smtp/ opened answered %d, %+v", code, result)
	}
	if mail.validateCount != 1 || !slices.Equal(mail.firstListens, []string{"smtp/25/mx"}) {
		t.Fatalf("§15's hooks saw %d checks and %v", mail.validateCount, mail.firstListens)
	}
	mail.validateErr = socketsservice.ErrSocketListenRefused
	args.SetVersion = 3
	if code, result := process.register(receiver.token, args); code != http.StatusOK || result.Statuses[0] != sidecar.SocketRegistrationStatusRevoked {
		t.Fatalf("§15's refusal answered %d, %+v", code, result)
	}
	if !slices.Equal(mail.lastUnlistens, []string{"smtp/25/mx"}) {
		t.Fatalf("§15's hooks saw %v", mail.lastUnlistens)
	}
}

// An mxedge-style edge Find reaches a receiver: its ticket names the receiver, one of the edge's clients, and the
// receiver's own listen grant, with no dial or publish grant in the network, and the {svc_} pair stands for that
// client with the grant's expiry.
func TestSocketSmtpEdgeFindReachesAReceiver(t *testing.T) {
	scene := newTestSocketSmtpScene(t, "smtp/25/mx", 1, nil)
	world := scene.world
	receiver := scene.receivers[0]
	scene.process.registerOk(receiver, 1, testSocketReceiverRegistration(t, receiver, "smtp/25/mx", true))
	code, result := scene.find("smtp/25/mx", nil)
	if code != http.StatusOK || result.Error != nil || result.Primary == nil || result.Backup != nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	ticket := world.verifyTicket(result.Primary)
	expireMillis := uint64(world.clock.Now().Add(time.Hour).UnixMilli())
	switch {
	case ticket.GetName() != "smtp/25/mx", len(ticket.GetNameToken()) != 0,
		!bytes.Equal(ticket.GetListenerClientId(), receiver.clientId.Bytes()),
		!bytes.Equal(ticket.GetDialerNetworkId(), world.edgeNetworkId.Bytes()):
		t.Fatalf("the ticket names %v", ticket)
	case !bytes.Equal(ticket.GetGrantId(), []byte("ra")), ticket.GetGrantExpireTimeMillis() != expireMillis:
		t.Fatalf("the ticket rests on %v", ticket)
	}
	dialerClientId, _ := connect.IdFromBytes(ticket.GetDialerClientId())
	if !slices.Contains(scene.edge.clientIds, dialerClientId) {
		t.Fatal("the ticket names a client the edge does not hold")
	}
	if pairExpireMillis, found, err := world.fakeStore.GetServicePair(world.ctx, receiver.clientId, dialerClientId); err != nil || !found || pairExpireMillis != expireMillis {
		t.Fatalf("the pair: %d, %v, %v", pairExpireMillis, found, err)
	}
}

// A receiver with no listen grant is denied at registration, and so is never found.
func TestSocketSmtpReceiverWithNoListenGrantIsDenied(t *testing.T) {
	scene := newTestSocketSmtpScene(t, "smtp/25/mx", 0, nil)
	stranger := scene.world.newSidecar(scene.networkId)
	scene.process.gate.SetIdentityKey(scene.networkId, stranger.sidecarId, stranger.publicKey())
	scene.process.gate.Load(scene.networkId)
	args := &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{testSocketReceiverRegistration(t, stranger, "smtp/25/mx", true)}}
	if code, result := scene.process.register(stranger.token, args); code != http.StatusOK || result.Statuses[0] != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if code, result := scene.find("smtp/25/mx", nil); code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("a Find answered %d, %+v", code, result)
	}
}

// A receiver registered not serving keeps its lease and takes no ticket until it serves (§9.5, §15.5).
func TestSocketSmtpReceiverNotServingTakesNoTickets(t *testing.T) {
	scene := newTestSocketSmtpScene(t, "smtp/25/mx", 1, nil)
	receiver := scene.receivers[0]
	scene.process.registerOk(receiver, 1, testSocketReceiverRegistration(t, receiver, "smtp/25/mx", false))
	if code, result := scene.find("smtp/25/mx", nil); code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("a receiver not serving answered %d, %+v", code, result)
	}
	if count := scene.process.service.SignedTicketCount(); count != 0 {
		t.Fatalf("%d tickets signed", count)
	}
	scene.process.registerOk(receiver, 2, testSocketReceiverRegistration(t, receiver, "smtp/25/mx", true))
	if code, result := scene.find("smtp/25/mx", nil); code != http.StatusOK || result.Error != nil {
		t.Fatalf("a serving receiver answered %d, %+v", code, result)
	}
}

// Only a receiver's host and protocol register: smtp/25/@, another label, and a protocol other than
// smtp-starttls are each denied.
func TestSocketSmtpRefusesOtherHostsAndProtocols(t *testing.T) {
	for _, name := range []string{"smtp/25/@", "smtp/25/www"} {
		scene := newTestSocketSmtpScene(t, name, 1, nil)
		receiver := scene.receivers[0]
		args := &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{testSocketReceiverRegistration(t, receiver, name, true)}}
		if code, result := scene.process.register(receiver.token, args); code != http.StatusOK || result.Statuses[0] != sidecar.SocketRegistrationStatusDenied {
			t.Errorf("%s answered %d, %+v", name, code, result)
		}
	}
	scene := newTestSocketSmtpScene(t, "smtp/25/mx", 1, nil)
	receiver := scene.receivers[0]
	registration := receiver.edgeRegistration(t, "smtp/25/mx", "tcp", "")
	args := &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{registration}}
	if code, result := scene.process.register(receiver.token, args); code != http.StatusOK || result.Statuses[0] != sidecar.SocketRegistrationStatusDenied {
		t.Errorf("a tcp receiver answered %d, %+v", code, result)
	}
}

// A member scope's mx.<scope> takes only that member's consented devices, through the scope source; with no
// source every scope host is refused, and an undecided source makes the page unavailable.
func TestSocketSmtpScopeTakesOnlyConsentedDevices(t *testing.T) {
	unscoped := newTestSocketSmtpScene(t, "smtp/25/mx.team", 1, nil)
	receiver := unscoped.receivers[0]
	args := &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{testSocketReceiverRegistration(t, receiver, "smtp/25/mx.team", true)}}
	if code, result := unscoped.process.register(receiver.token, args); code != http.StatusOK || result.Statuses[0] != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("a scope host with no scope source answered %d, %+v", code, result)
	}

	consent := &testSocketScopeConsent{consented: map[string][]connect.Id{}, undecided: "later"}
	scene := newTestSocketSmtpScene(t, "smtp/25/mx.team", 2, consent)
	consented, unconsented := scene.receivers[0], scene.receivers[1]
	consent.consented["team"] = []connect.Id{consented.sidecarId}
	scene.process.registerOk(consented, 1, testSocketReceiverRegistration(t, consented, "smtp/25/mx.team", true))
	args = &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{testSocketReceiverRegistration(t, unconsented, "smtp/25/mx.team", true)}}
	if code, result := scene.process.register(unconsented.token, args); code != http.StatusOK || result.Statuses[0] != sidecar.SocketRegistrationStatusDenied {
		t.Fatalf("an unconsented device answered %d, %+v", code, result)
	}

	later := newTestSocketSmtpScene(t, "smtp/25/mx.later", 1, consent)
	receiver = later.receivers[0]
	args = &sidecar.SocketRegistrationsArgs{SetVersion: 1, Registrations: []*sidecar.SocketRegistration{testSocketReceiverRegistration(t, receiver, "smtp/25/mx.later", true)}}
	if code, result := later.process.register(receiver.token, args); code != http.StatusOK || result.Error == nil || result.Error.Code != sidecar.SocketErrorCodeUnavailable {
		t.Fatalf("an undecided scope answered %d, %+v", code, result)
	}
}

// A dead receiver falls to the backup: a Find answers a primary and a backup, and once the edge reports the
// primary's accept timeout, the next Find's primary is the other receiver.
func TestSocketSmtpDeadReceiverFallsToTheBackup(t *testing.T) {
	scene := newTestSocketSmtpScene(t, "smtp/25/mx", 2, nil)
	world := scene.world
	for _, receiver := range scene.receivers {
		scene.process.registerOk(receiver, 1, testSocketReceiverRegistration(t, receiver, "smtp/25/mx", true))
	}
	code, result := scene.find("smtp/25/mx", nil)
	if code != http.StatusOK || result.Error != nil || result.Backup == nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	dead := world.verifyTicket(result.Primary).GetListenerClientId()
	backup := world.verifyTicket(result.Backup).GetListenerClientId()
	if bytes.Equal(dead, backup) {
		t.Fatal("the backup is the primary's receiver")
	}
	failed := []*sidecar.SocketFailedTicket{{Ticket: result.Primary.Ticket, Reason: sidecar.SocketFailedReasonTimeout}}
	for round := range 3 {
		code, result = scene.find("smtp/25/mx", failed)
		if code != http.StatusOK || result.Error != nil {
			t.Fatalf("round %d answered %d, %+v", round, code, result)
		}
		if primary := world.verifyTicket(result.Primary).GetListenerClientId(); !bytes.Equal(primary, backup) {
			t.Fatalf("round %d's primary is the dead receiver", round)
		}
		failed = nil
	}
	// an edge reports only accept timeouts: a refused report is dropped
	if dropped := scene.process.host.Metrics.Value("urnetwork_sockets_failure_reports_total", "dropped"); dropped != 0 {
		t.Fatalf("%v reports dropped", dropped)
	}
	refused := []*sidecar.SocketFailedTicket{{Ticket: result.Primary.Ticket, Reason: sidecar.SocketFailedReasonRefused}}
	if code, result := scene.find("smtp/25/mx", refused); code != http.StatusOK || result.Error != nil {
		t.Fatalf("answered %d, %+v", code, result)
	}
	if dropped := scene.process.host.Metrics.Value("urnetwork_sockets_failure_reports_total", "dropped"); dropped != 1 {
		t.Fatalf("an edge's refused report was not dropped: %v", dropped)
	}
}
