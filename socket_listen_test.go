//go:build !sidecar_http && !js

// §9.9's listener on its component (SOCK-M5-11), with a scripted registrations service, a fake policy, the pipe seam and
// the test clock: an admitted stream reaches AcceptSocket and nothing refused does (FS-34's listener side, FI-11); a
// replayed ticket, an unused edge ticket from another source and an edge-marked ticket for an application name are
// refused while a valid edge splice is accepted; max_streams answers busy; drain with and without streams in flight;
// a stream ends at its grant's expiry and at a revocation; Close unlistens and keeps accepted conns; tls/ goes through
// Authorize, whose pending answer reaches the caller, and the production action is refused on its held question.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A registrations service that takes every entry, giving the test key, the service's clock and urnetwork-edge, and
// records each page.
type testListenService struct {
	urnetworkEdge Id
	pages         chan *SocketRegistrationsArgs
	stateLock     sync.Mutex
	status        SocketRegistrationStatus
}

func (self *testListenService) registrations(ctx context.Context, args *SocketRegistrationsArgs) (*SocketRegistrationsResult, error) {
	self.stateLock.Lock()
	status := self.status
	self.stateLock.Unlock()
	select {
	case self.pages <- args:
	default:
	}
	statuses := make([]SocketRegistrationStatus, len(args.Registrations))
	for i := range statuses {
		statuses[i] = status
	}
	urnetworkEdge := connect.Id(self.urnetworkEdge)
	return &SocketRegistrationsResult{
		Statuses:         statuses,
		SetVersion:       args.SetVersion,
		ServerTimeMillis: uint64(testSocketNow.UnixMilli()),
		TicketKeys: []*SocketTicketKey{{
			KeyId:            testAdmissionKeyId,
			PublicKey:        testAdmissionKey.Public().(ed25519.PublicKey),
			ExpireTimeMillis: uint64(testSocketNow.Add(24 * time.Hour).UnixMilli()),
		}},
		UrnetworkEdge: &urnetworkEdge,
	}, nil
}

// A component attached to a generation of the test network, its registrar on the scripted service.
type testListenFixture struct {
	clock      *testArmedClock
	ring       *SocketKeyRing
	policy     *testSocketPolicy
	service    *testListenService
	component  *SocketComponent
	generation *socketGeneration
	dialer     *SubprotocolPeerIdentity
	dialerId   Id
	ticketSeq  int
	authorized []*SidecarAction
}

func newTestListenFixture(t testing.TB) *testListenFixture {
	t.Helper()
	fixture := &testListenFixture{
		clock:    newTestArmedClock(),
		ring:     newTestSocketRing(t, "listen", "", 0),
		policy:   newTestSocketPolicy(5),
		service:  &testListenService{urnetworkEdge: testSocketId("urnetwork-edge"), pages: make(chan *SocketRegistrationsArgs, 64), status: SocketRegistrationStatusOk},
		dialer:   &SubprotocolPeerIdentity{SidecarId: testSocketId("dialer sidecar")},
		dialerId: testSocketId("dialer client"),
	}
	signer := newTestSocketSigner("listener")
	component, err := NewSocketComponent(t.Context(), &SocketComponentArgs{
		NetworkId: testRegistrarNetworkId,
		Settings:  DefaultSidecarSocketSettings(),
		Sign:      signer.sign,
		Clock:     fixture.clock,
		Log:       NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(component.Close)
	fixture.component = component
	if err := component.SetKeyRing(fixture.ring); err != nil {
		t.Fatal(err)
	}
	if err := component.SetNetworkLabels(&SocketNetworkLabels{Label: "abcdefghij"}); err != nil {
		t.Fatal(err)
	}
	fixture.policy.inbound[fixture.dialer.SidecarId] = true
	component.SetPolicy(fixture.policy)
	fixture.generation = &socketGeneration{
		ctx: t.Context(),
		seq: 1,
		identity: &SidecarIdentity{
			NetworkId:         testRegistrarNetworkId,
			SidecarId:         signer.sidecarId,
			ClientId:          testSocketId("listener client"),
			IdentityPublicKey: signer.publicKey(),
		},
		authorize: func(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
			fixture.authorized = append(fixture.authorized, action)
			return nil
		},
	}
	fixture.policy.listen[signer.sidecarId] = true
	fixture.policy.publish[signer.sidecarId] = true
	component.registrar.attach(t.Context(), fixture.service.registrations, signer.publicKey())
	func() {
		component.stateLock.Lock()
		defer component.stateLock.Unlock()
		component.generation = fixture.generation
	}()
	return fixture
}

// A listener on address, after the service's first verdict.
func (self *testListenFixture) listen(t testing.TB, address string, settings *SocketListenSettings) *SocketListener {
	t.Helper()
	parsed, err := ParseSocketAddress(address)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := self.component.listen(t.Context(), parsed, settings, false)
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

// A ticket for listener from the fixture's dialer, changed by mutate.
func (self *testListenFixture) ticket(t testing.TB, listener *SocketListener, mutate func(ticket *protocol.SocketTicket)) []byte {
	t.Helper()
	self.ticketSeq += 1
	nowMillis := uint64(self.clock.Now().UnixMilli())
	ticket := &protocol.SocketTicket{
		TicketId:         testSocketId("listen ticket " + string(rune('a'+self.ticketSeq))).Bytes(),
		NetworkId:        testRegistrarNetworkId.Bytes(),
		ListenerClientId: self.generation.identity.ClientId.Bytes(),
		ListenId:         listener.listenId.Bytes(),
		DialerClientId:   self.dialerId.Bytes(),
		DialerNetworkId:  testRegistrarNetworkId.Bytes(),
		IssueTimeMillis:  nowMillis,
		ExpireTimeMillis: nowMillis + 30_000,
		PolicyVersion:    5,
	}
	if listener.namespace.blinded() {
		ticket.NameToken = listener.nameTokens()[0]
	} else {
		ticket.Name = listener.name
	}
	if mutate != nil {
		mutate(ticket)
	}
	signed, err := SignSocketTicket(testAdmissionKeyId, testAdmissionKey, ticket)
	if err != nil {
		t.Fatal(err)
	}
	ticketBytes, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return ticketBytes
}

// Presents ticketBytes as a sidecar dialer's open, the stream's far end given back on an accept.
func (self *testListenFixture) open(listener *SocketListener, request *socketAdmissionRequest) (*socketPipeEnd, error) {
	dialerEnd, listenerEnd := newSocketStreamPipe(1024)
	err := listener.acceptStream(context.Background(), self.generation, request, func() socketStream { return listenerEnd }, nil)
	if err != nil {
		return nil, err
	}
	return dialerEnd, nil
}

func (self *testListenFixture) request(ticketBytes []byte) *socketAdmissionRequest {
	return &socketAdmissionRequest{ticketBytes: ticketBytes, sourceId: self.dialerId, peer: self.dialer}
}

// The code a refusal carries.
func testRejectCode(err error) protocol.StreamRejectCode {
	var rejectErr *StreamRejectError
	if errors.As(err, &rejectErr) {
		return rejectErr.Code
	}
	return protocol.StreamRejectCode(99)
}

// Whether a conn waits to be taken.
func testListenerQueued(listener *SocketListener) int {
	return len(listener.accepted)
}

func TestSocketListenAdmitsBeforeAnyByte(t *testing.T) {
	fixture := newTestListenFixture(t)
	listener := fixture.listen(t, "db/primary", nil)
	defer listener.Close()
	first := testSocketAwait(t, fixture.service.pages, "the first page")
	if len(first.Registrations) != 1 || len(first.Registrations[0].NameToken) == 0 || first.Registrations[0].Name != "" {
		t.Fatalf("the page %+v", first.Registrations)
	}

	// refused opens reach nothing
	edgeMarked := fixture.ticket(t, listener, func(ticket *protocol.SocketTicket) {
		ticket.DialerNetworkId = fixture.service.urnetworkEdge.Bytes()
	})
	if _, err := fixture.open(listener, &socketAdmissionRequest{ticketBytes: edgeMarked, sourceId: fixture.dialerId, edge: true}); testRejectCode(err) != protocol.StreamRejectCode_SR_INVALID {
		t.Errorf("an edge-marked ticket for an application name: %v", err)
	}
	otherSource := fixture.request(fixture.ticket(t, listener, nil))
	otherSource.sourceId = testSocketId("another source")
	if _, err := fixture.open(listener, otherSource); testRejectCode(err) != protocol.StreamRejectCode_SR_INVALID {
		t.Errorf("a ticket from another source: %v", err)
	}
	if queued := testListenerQueued(listener); queued != 0 || listener.inflightCount() != 0 {
		t.Fatalf("refusals reached the queue: %d queued, %d in flight", queued, listener.inflightCount())
	}

	// an admitted one carries its bytes once taken, its ticket kept
	ticketBytes := fixture.ticket(t, listener, nil)
	dialerEnd, err := fixture.open(listener, fixture.request(ticketBytes))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialerEnd.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptSocket(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	read := make([]byte, 5)
	if _, err := io.ReadFull(conn, read); err != nil || string(read) != "hello" {
		t.Fatalf("read %q %v", read, err)
	}
	if !bytes.Equal(conn.SignedTicket(), ticketBytes) || !bytes.Equal(conn.Ticket().GetListenId(), listener.listenId.Bytes()) {
		t.Error("the conn kept another ticket")
	}
	if remote := conn.RemoteAddr().(*SocketAddr); Id(remote.ClientId) != fixture.dialerId || Id(remote.NetworkId) != testRegistrarNetworkId {
		t.Errorf("remote %v", remote)
	}
	if listener.inflightCount() != 1 {
		t.Errorf("%d in flight", listener.inflightCount())
	}
	// the same ticket again is a replay
	if _, err := fixture.open(listener, fixture.request(ticketBytes)); testRejectCode(err) != protocol.StreamRejectCode_SR_INVALID {
		t.Errorf("a replay: %v", err)
	}
	conn.Close()
	if listener.inflightCount() != 0 {
		t.Errorf("%d in flight after the close", listener.inflightCount())
	}
}

func TestSocketListenHoldsMaxStreams(t *testing.T) {
	fixture := newTestListenFixture(t)
	listener := fixture.listen(t, "db/primary", &SocketListenSettings{MaxStreams: 1})
	defer listener.Close()
	if _, err := fixture.open(listener, fixture.request(fixture.ticket(t, listener, nil))); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.open(listener, fixture.request(fixture.ticket(t, listener, nil))); testRejectCode(err) != protocol.StreamRejectCode_SR_BUSY {
		t.Errorf("past max_streams: %v", err)
	}
	listener.SetServing(false)
	conn, err := listener.AcceptSocket(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if _, err := fixture.open(listener, fixture.request(fixture.ticket(t, listener, nil))); testRejectCode(err) != protocol.StreamRejectCode_SR_BUSY {
		t.Errorf("not serving: %v", err)
	}
}

// A valid edge splice on a tls/ listener: Authorize first, an edge's open with no Hello admitted.
func TestSocketListenTakesAnEdgeSplice(t *testing.T) {
	fixture := newTestListenFixture(t)
	fixture.component.listenAction = func(name string, settings *SocketListenSettings) (*SidecarAction, error) {
		return &SidecarAction{Kind: SidecarActionListen, Canonical: []byte(name), Risk: SidecarRiskNormal}, nil
	}
	listener := fixture.listen(t, "tls/443/blog", nil)
	defer listener.Close()
	if len(fixture.authorized) != 1 || fixture.authorized[0].Kind != SidecarActionListen {
		t.Fatalf("authorized %+v", fixture.authorized)
	}
	page := testSocketAwait(t, fixture.service.pages, "the page")
	if registration := page.Registrations[0]; registration.Name != "tls/443/blog" || registration.Protocol != "tls" || registration.AppMode != "http" {
		t.Errorf("the registration %+v", registration)
	}
	edgeTicket := fixture.ticket(t, listener, func(ticket *protocol.SocketTicket) {
		ticket.DialerNetworkId = fixture.service.urnetworkEdge.Bytes()
	})
	// an edge's unused ticket presented by another source is refused, and spends nothing for its holder
	unused := fixture.ticket(t, listener, func(ticket *protocol.SocketTicket) {
		ticket.DialerNetworkId = fixture.service.urnetworkEdge.Bytes()
	})
	if _, err := fixture.open(listener, &socketAdmissionRequest{ticketBytes: unused, sourceId: testSocketId("another edge client"), edge: true}); testRejectCode(err) != protocol.StreamRejectCode_SR_INVALID {
		t.Errorf("an edge ticket from another source: %v", err)
	}
	if _, err := fixture.open(listener, &socketAdmissionRequest{ticketBytes: edgeTicket, sourceId: fixture.dialerId, edge: true}); err != nil {
		t.Fatalf("a valid edge splice: %v", err)
	}
	// a sidecar may not dial an edge name
	if _, err := fixture.open(listener, fixture.request(fixture.ticket(t, listener, nil))); testRejectCode(err) != protocol.StreamRejectCode_SR_INVALID {
		t.Errorf("a sidecar's ticket for tls/: %v", err)
	}
}

// tls/ and smtp/ go through Authorize: its pending answer reaches the caller with nothing registered, and the
// production action, whose row waits on a question, refuses the Listen before any gate.
func TestSocketListenAuthorizesOutwardNames(t *testing.T) {
	fixture := newTestListenFixture(t)
	parsed, _ := ParseSocketAddress("tls/443/blog")
	if _, err := fixture.component.listen(t.Context(), parsed, nil, false); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("the held action: %v", err)
	}
	if len(fixture.authorized) != 0 {
		t.Error("a gate saw an action it could not render")
	}
	approvalId := testSocketId("approval")
	fixture.component.listenAction = func(name string, settings *SocketListenSettings) (*SidecarAction, error) {
		return &SidecarAction{Kind: SidecarActionListen, Canonical: []byte(name), Risk: SidecarRiskNormal}, nil
	}
	fixture.generation.authorize = func(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
		return &ApprovalPendingError{ApprovalId: approvalId}
	}
	for _, address := range []string{"tls/443/shop", "smtp/25/mx"} {
		parsed, _ = ParseSocketAddress(address)
		_, err := fixture.component.listen(t.Context(), parsed, nil, false)
		var pending *ApprovalPendingError
		if !errors.As(err, &pending) || pending.ApprovalId != approvalId {
			t.Fatalf("%s: a pending approval: %v", address, err)
		}
	}
	select {
	case page := <-fixture.service.pages:
		t.Errorf("a pending listen registered %+v", page.Registrations)
	default:
	}
}

// Names a sidecar does not listen on, and a network not its own.
func TestSocketListenRefusesNames(t *testing.T) {
	fixture := newTestListenFixture(t)
	for _, address := range []string{"share/abcdefghijklmnopqrstuvwxyz", "ur/smtpedge", "sys/x", "x/y", "othernetwk:db/primary"} {
		parsed, err := ParseSocketAddress(address)
		if err != nil {
			continue
		}
		if _, err := fixture.component.listen(t.Context(), parsed, nil, false); err == nil {
			t.Errorf("%s listened", address)
		}
	}
	parsed, _ := ParseSocketAddress("db/primary")
	for _, settings := range []*SocketListenSettings{{Weight: 1001}, {MaxStreams: -1}, {AppMode: "raw"}, {Alpn: []string{"h2"}}} {
		if _, err := fixture.component.listen(t.Context(), parsed, settings, false); err == nil {
			t.Errorf("settings %+v listened", settings)
		}
	}
}

// Drain with nothing in flight closes at once; with a stream in flight it waits for it to end, and past
// ListenDrainTimeout resets it with RST_DRAINING.
func TestSocketListenDrains(t *testing.T) {
	fixture := newTestListenFixture(t)
	idle := fixture.listen(t, "db/idle", nil)
	if err := idle.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := idle.AcceptSocket(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a drained listener accepts: %v", err)
	}
	// SOCKET_HINT_DRAIN forces the same drain
	hinted := fixture.listen(t, "db/hinted", nil)
	hinted.drainHinted()
	testSocketAwait(t, hinted.closed, "the hinted drain's close")

	for _, ending := range []string{"closes", "times out"} {
		listener := fixture.listen(t, "db/busy", nil)
		dialerEnd, err := fixture.open(listener, fixture.request(fixture.ticket(t, listener, nil)))
		if err != nil {
			t.Fatal(err)
		}
		conn, err := listener.AcceptSocket(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		drained := make(chan error, 1)
		// what earlier drains armed is no sign of this one
		fixture.clock.flushArmed()
		go func() {
			drained <- listener.Drain(context.Background())
		}()
		// an issued ticket is still admitted while draining, which has armed its time
		fixture.clock.awaitArmed(t, DefaultSidecarSocketSettings().ListenDrainTimeout)
		lateEnd, err := fixture.open(listener, fixture.request(fixture.ticket(t, listener, nil)))
		if err != nil {
			t.Fatalf("an issued ticket while draining: %v", err)
		}
		late, err := listener.AcceptSocket(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		switch ending {
		case "closes":
			conn.Close()
			late.Close()
			if err := testSocketAwait(t, drained, "the drain"); err != nil {
				t.Fatal(err)
			}
		case "times out":
			fixture.clock.advance(DefaultSidecarSocketSettings().ListenDrainTimeout)
			if err := testSocketAwait(t, drained, "the drain"); err != nil {
				t.Fatal(err)
			}
			for _, end := range []*socketPipeEnd{dialerEnd, lateEnd} {
				_, err := end.Read(make([]byte, 1))
				var resetErr *socketStreamResetError
				if !errors.As(err, &resetErr) || resetErr.Code != protocol.StreamResetCode_RST_DRAINING {
					t.Errorf("a stream past the drain: %v", err)
				}
			}
		}
		if listener.inflightCount() != 0 {
			t.Errorf("%s: %d in flight", ending, listener.inflightCount())
		}
	}
}

// A stream ends at its ticket's grant expiry, and at a revocation the next PolicyChanged finds.
func TestSocketListenEndsStreamsWithTheirGrant(t *testing.T) {
	fixture := newTestListenFixture(t)
	listener := fixture.listen(t, "db/primary", nil)
	defer listener.Close()
	expiring, err := fixture.open(listener, fixture.request(fixture.ticket(t, listener, func(ticket *protocol.SocketTicket) {
		ticket.GrantExpireTimeMillis = uint64(fixture.clock.Now().Add(10 * time.Second).UnixMilli())
	})))
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := fixture.open(listener, fixture.request(fixture.ticket(t, listener, nil)))
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.advance(10 * time.Second)
	readReset := func(end *socketPipeEnd) protocol.StreamResetCode {
		_, err := end.Read(make([]byte, 1))
		var resetErr *socketStreamResetError
		if !errors.As(err, &resetErr) {
			return protocol.StreamResetCode_RST_UNSPECIFIED
		}
		return resetErr.Code
	}
	if code := readReset(expiring); code != protocol.StreamResetCode_RST_REVOKED {
		t.Errorf("at its grant's expiry: %s", code)
	}
	if listener.inflightCount() != 1 {
		t.Fatalf("%d in flight", listener.inflightCount())
	}
	fixture.policy.set(func(policy *testSocketPolicy) { policy.inbound = map[Id]bool{} })
	fixture.component.PolicyChanged()
	if code := readReset(revoked); code != protocol.StreamResetCode_RST_REVOKED {
		t.Errorf("at a revocation: %s", code)
	}
	if listener.inflightCount() != 0 {
		t.Errorf("%d in flight", listener.inflightCount())
	}
}

// Close unlistens at once: the next page lacks the entry, a pending AcceptSocket answers net.ErrClosed, a taken conn
// stays open, and one admitted but never taken is reset.
func TestSocketListenCloseUnlistens(t *testing.T) {
	fixture := newTestListenFixture(t)
	listener := fixture.listen(t, "db/primary", nil)
	testSocketAwait(t, fixture.service.pages, "the first page")
	second := fixture.listen(t, "db/secondary", nil)
	defer second.Close()
	testSocketAwait(t, fixture.service.pages, "the second listener's page")
	takenEnd, err := fixture.open(listener, fixture.request(fixture.ticket(t, listener, nil)))
	if err != nil {
		t.Fatal(err)
	}
	taken, err := listener.AcceptSocket(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	queuedEnd, err := fixture.open(listener, fixture.request(fixture.ticket(t, listener, nil)))
	if err != nil {
		t.Fatal(err)
	}
	pending := make(chan error, 1)
	go func() {
		_, err := second.AcceptSocket(context.Background())
		pending <- err
	}()
	listener.Close()
	unlisten := testSocketAwait(t, fixture.service.pages, "the unlisten's page")
	for _, registration := range unlisten.Registrations {
		for _, tokenPath := range listener.nameTokens() {
			if bytes.Equal(registration.NameToken, tokenPath) {
				t.Error("a closed listener stayed in the set")
			}
		}
	}
	if _, err := queuedEnd.Read(make([]byte, 1)); err == nil {
		t.Error("a conn never taken stayed open")
	}
	if _, err := takenEnd.Write([]byte("x")); err != nil {
		t.Errorf("a taken conn closed with its listener: %v", err)
	}
	if _, err := io.ReadFull(taken, make([]byte, 1)); err != nil {
		t.Errorf("a taken conn reads: %v", err)
	}
	if _, err := listener.AcceptSocket(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("accept after close: %v", err)
	}
	if _, err := fixture.open(listener, fixture.request(fixture.ticket(t, listener, nil))); testRejectCode(err) != protocol.StreamRejectCode_SR_RETRY {
		t.Errorf("a racing ticket after close: %v", err)
	}
	second.Close()
	if err := testSocketAwait(t, pending, "the pending accept"); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a pending accept: %v", err)
	}
}
