//go:build !sidecar_http && !ios_extension

// SOCK-M9-01's client side (T1 on the pipe seam): a platform listener's admission is §9.6's steps 1 to 5 and 7, with no
// config, and a sidecar dials a ur/ name with no Hello, claim or listen grant, holding only a ticket the service
// signed for urnetwork-edge.

package sidecar

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// The admission fixture as a platform listener on ur/smtpedge in urnetwork-edge.
func newTestPlatformAdmission(t testing.TB) *testAdmissionFixture {
	t.Helper()
	fixture := newTestAdmissionFixture(t, "ur/smtpedge")
	fixture.admission = newSocketAdmission(DefaultSidecarSocketSettings(), fixture.clock, fixture.urnetworkEdge, fixture.listenId, SocketNamespacePlatform, "ur/smtpedge", nil, 4)
	return fixture
}

// A sidecar's ticket for the platform listener, as the service signs a ur/ Find's: urnetwork-edge's, no §8 grant.
func (self *testAdmissionFixture) platformTicket(t testing.TB, mutate func(ticket *protocol.SocketTicket)) []byte {
	t.Helper()
	return self.ticket(t, func(ticket *protocol.SocketTicket) {
		ticket.NetworkId = self.urnetworkEdge.Bytes()
		ticket.GrantId = nil
		ticket.PolicyVersion = 0
		if mutate != nil {
			mutate(ticket)
		}
	})
}

// A sidecar's open at an edge's dispatcher, which marks every open an edge stream; a sidecar sends an edge no Hello.
func (self *testAdmissionFixture) platformRequest(ticketBytes []byte) *socketAdmissionRequest {
	return &socketAdmissionRequest{ticketBytes: ticketBytes, sourceId: self.dialerClientId, edge: true}
}

// The platform inputs: no config, serving.
func (self *testAdmissionFixture) platformInputs() *socketAdmissionInputs {
	inputs := self.inputs()
	inputs.policy = nil
	return inputs
}

// §9.6's steps 1 to 5 and 7 on a platform listener, each refusal exact, and no step 6: no config is read, and none
// is needed.
func TestPlatformAdmissionRunsEveryStepButTheConfigs(t *testing.T) {
	otherKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	cases := []struct {
		name string
		run  func(fixture *testAdmissionFixture) protocol.StreamRejectCode
		want protocol.StreamRejectCode
	}{
		{name: "a sidecar's ticket", want: testAccepted, run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
			return fixture.admit(fixture.platformRequest(fixture.platformTicket(t, nil)), fixture.platformInputs())
		}},
		{name: "another key's signature", want: protocol.StreamRejectCode_SR_INVALID, run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
			ticketBytes := fixture.ticketBy(t, otherKey, testAdmissionKeyId, func(ticket *protocol.SocketTicket) {
				ticket.NetworkId = fixture.urnetworkEdge.Bytes()
			})
			return fixture.admit(fixture.platformRequest(ticketBytes), fixture.platformInputs())
		}},
		{name: "another listener", want: protocol.StreamRejectCode_SR_INVALID, run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
			return fixture.admit(fixture.platformRequest(fixture.platformTicket(t, func(ticket *protocol.SocketTicket) {
				ticket.ListenerClientId = testSocketId("another edge client").Bytes()
			})), fixture.platformInputs())
		}},
		{name: "a ticket for another network's group", want: protocol.StreamRejectCode_SR_INVALID, run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
			return fixture.admit(fixture.platformRequest(fixture.platformTicket(t, func(ticket *protocol.SocketTicket) {
				ticket.NetworkId = testRegistrarNetworkId.Bytes()
			})), fixture.platformInputs())
		}},
		{name: "another service", want: protocol.StreamRejectCode_SR_INVALID, run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
			return fixture.admit(fixture.platformRequest(fixture.platformTicket(t, func(ticket *protocol.SocketTicket) {
				ticket.Name = "ur/otherservice"
			})), fixture.platformInputs())
		}},
		{name: "an earlier listen", want: protocol.StreamRejectCode_SR_RETRY, run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
			return fixture.admit(fixture.platformRequest(fixture.platformTicket(t, func(ticket *protocol.SocketTicket) {
				ticket.ListenId = testSocketId("an earlier listen").Bytes()
			})), fixture.platformInputs())
		}},
		{name: "a source the ticket does not name", want: protocol.StreamRejectCode_SR_INVALID, run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
			request := fixture.platformRequest(fixture.platformTicket(t, nil))
			request.sourceId = testSocketId("another source")
			return fixture.admit(request, fixture.platformInputs())
		}},
		{name: "an edge's ticket", want: protocol.StreamRejectCode_SR_INVALID, run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
			return fixture.admit(fixture.platformRequest(fixture.platformTicket(t, func(ticket *protocol.SocketTicket) {
				ticket.DialerNetworkId = fixture.urnetworkEdge.Bytes()
			})), fixture.platformInputs())
		}},
		{name: "a Hello", want: protocol.StreamRejectCode_SR_INVALID, run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
			request := fixture.platformRequest(fixture.platformTicket(t, nil))
			request.peer = fixture.dialerPeer
			return fixture.admit(request, fixture.platformInputs())
		}},
		{name: "an expired ticket", want: protocol.StreamRejectCode_SR_INVALID, run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
			return fixture.admit(fixture.platformRequest(fixture.platformTicket(t, func(ticket *protocol.SocketTicket) {
				ticket.IssueTimeMillis -= 60_000
				ticket.ExpireTimeMillis = ticket.IssueTimeMillis + 30_000
			})), fixture.platformInputs())
		}},
		{name: "a replay", want: protocol.StreamRejectCode_SR_INVALID, run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
			ticketBytes := fixture.platformTicket(t, nil)
			if code := fixture.admit(fixture.platformRequest(ticketBytes), fixture.platformInputs()); code != testAccepted {
				return code
			}
			return fixture.admit(fixture.platformRequest(ticketBytes), fixture.platformInputs())
		}},
		{name: "a full listener", want: protocol.StreamRejectCode_SR_BUSY, run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
			inputs := fixture.platformInputs()
			inputs.inflight = 4
			return fixture.admit(fixture.platformRequest(fixture.platformTicket(t, nil)), inputs)
		}},
		{name: "a listener not serving", want: protocol.StreamRejectCode_SR_BUSY, run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
			inputs := fixture.platformInputs()
			inputs.serving = false
			return fixture.admit(fixture.platformRequest(fixture.platformTicket(t, nil)), inputs)
		}},
		{name: "urnetwork-edge's own §20 stop, which is no dialer's", want: testAccepted, run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
			fixture.state.streamsStopped = true
			return fixture.admit(fixture.platformRequest(fixture.platformTicket(t, nil)), fixture.platformInputs())
		}},
	}
	for _, c := range cases {
		if got := c.run(newTestPlatformAdmission(t)); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// An application or edge listener's admission still runs step 6: a ticket in the platform's form gets nothing there.
func TestPlatformTicketOpensNoOtherListener(t *testing.T) {
	fixture := newTestAdmissionFixture(t, "db/primary")
	ticketBytes := fixture.ticket(t, func(ticket *protocol.SocketTicket) {
		ticket.GrantId = nil
		ticket.PolicyVersion = 0
	})
	inputs := fixture.inputs()
	inputs.policy = nil
	if code := fixture.admit(fixture.request(ticketBytes), inputs); code != protocol.StreamRejectCode_SR_DENIED {
		t.Fatalf("an application listener with no config admitted: %v", code)
	}
}

// What the platform dial tests open: the request each open carried.
type testPlatformOpener struct {
	*testDialOpener
	stateLock sync.Mutex
	requests  []*StreamOpenRequest
}

func (self *testPlatformOpener) open(ctx context.Context, clientId Id, request *StreamOpenRequest) (socketStream, error) {
	self.stateLock.Lock()
	self.requests = append(self.requests, request)
	self.stateLock.Unlock()
	return self.testDialOpener.open(ctx, clientId, request)
}

// A dialer of ur/smtpedge: the registrar's answer named urnetwork-edge and the service's key, and the scripted service
// answers each Find with tickets for listeners, each changed by mutate.
func newTestPlatformDial(t *testing.T, mutate func(ticket *protocol.SocketTicket), listeners ...*testDialListener) (*testDialFixture, *testPlatformOpener, Id) {
	t.Helper()
	fixture := newTestDialFixture(t, listeners...)
	edge := testSocketId("urnetwork-edge")
	fixture.dialer.urnetworkEdge = &edge
	fixture.dialer.admission = &socketAdmissionState{
		known: true,
		ticketKeys: []*SocketTicketKey{{
			KeyId:            testAdmissionKeyId,
			PublicKey:        testAdmissionKey.Public().(ed25519.PublicKey),
			ExpireTimeMillis: uint64(testSocketNow.UnixMilli()) + 24*3600*1000,
		}},
		urnetworkEdge: &edge,
	}
	opener := &testPlatformOpener{testDialOpener: fixture.opener}
	fixture.dialer.opener = opener
	ticketCount := 0
	fixture.dialer.find = newSocketFindClient(func(ctx context.Context, args *SocketFindArgs) (*SocketFindResult, error) {
		fixture.service.stateLock.Lock()
		copied := *args
		fixture.service.finds = append(fixture.service.finds, &copied)
		fixture.service.stateLock.Unlock()
		result := &SocketFindResult{}
		for position, listener := range listeners {
			ticketCount += 1
			nowMillis := uint64(fixture.clock.Now().UnixMilli())
			ticket := &protocol.SocketTicket{
				TicketId:         testSocketId("platform ticket " + string(rune('a'+ticketCount))).Bytes(),
				NetworkId:        edge.Bytes(),
				Name:             "ur/smtpedge",
				ListenerClientId: listener.clientId.Bytes(),
				ListenId:         testSocketId("edge listen").Bytes(),
				DialerClientId:   fixture.clientId.Bytes(),
				DialerNetworkId:  testRegistrarNetworkId.Bytes(),
				IssueTimeMillis:  nowMillis,
				ExpireTimeMillis: nowMillis + 30_000,
				Backup:           position == 1,
			}
			if mutate != nil {
				mutate(ticket)
			}
			signedTicket, err := SignSocketTicket(testAdmissionKeyId, testAdmissionKey, ticket)
			if err != nil {
				return nil, err
			}
			ticketBytes, err := proto.Marshal(signedTicket)
			if err != nil {
				return nil, err
			}
			findTicket := &SocketFindTicket{Ticket: ticketBytes}
			if position == 0 {
				result.Primary = findTicket
			} else {
				result.Backup = findTicket
			}
		}
		return result, nil
	})
	return fixture, opener, edge
}

// A sidecar dials ur/smtpedge: one Find for the service in the clear in urnetwork-edge, no Hello, no claim and no listen
// grant asked, and the open an edge stream to the ticket's listener with the name as its target.
func TestPlatformDialOpensWithNoHelloOrClaim(t *testing.T) {
	listener := newTestDialListener("smtpedge")
	fixture, opener, edge := newTestPlatformDial(t, nil, listener)
	// no listener holds a listen grant in this device's config, which a ur/ dial never asks
	fixture.policy.listen = map[Id]bool{}
	conn, err := fixture.dial("ur/smtpedge")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	finds := fixture.service.findArgs()
	if len(finds) != 1 || finds[0].Name != "ur/smtpedge" || len(finds[0].NameToken) != 0 || *finds[0].NetworkId != connect.Id(edge) {
		t.Fatalf("the Find: %+v", finds)
	}
	if len(fixture.opener.verified) != 0 {
		t.Fatal("a ur/ dial ran a Hello")
	}
	if len(opener.requests) != 1 || !opener.requests[0].Edge || opener.requests[0].Target != "ur/smtpedge" {
		t.Fatalf("the open: %+v", opener.requests)
	}
	if opened := fixture.opener.openedIds(); len(opened) != 1 || opened[0] != listener.clientId {
		t.Fatalf("opened %v", opened)
	}
}

// A sidecar refuses before any open a ur/ ticket naming a listener outside urnetwork-edge, one the service did not sign,
// or one naming another dialer or service.
func TestPlatformDialRefusesWhatIsNoPlatformTicket(t *testing.T) {
	otherKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	cases := []struct {
		name   string
		mutate func(ticket *protocol.SocketTicket)
		resign bool
	}{
		{name: "a listener in another network", mutate: func(ticket *protocol.SocketTicket) { ticket.NetworkId = testRegistrarNetworkId.Bytes() }},
		{name: "another dialer", mutate: func(ticket *protocol.SocketTicket) { ticket.DialerClientId = testSocketId("someone else").Bytes() }},
		{name: "another service", mutate: func(ticket *protocol.SocketTicket) { ticket.Name = "ur/otherservice" }},
		{name: "another key", resign: true},
	}
	for _, c := range cases {
		listener := newTestDialListener("smtpedge " + c.name)
		fixture, _, _ := newTestPlatformDial(t, c.mutate, listener)
		if c.resign {
			fixture.dialer.admission.ticketKeys[0].PublicKey = otherKey.Public().(ed25519.PublicKey)
		}
		_, err := fixture.dial("ur/smtpedge")
		if !errors.Is(err, ErrSocketNoListener) {
			t.Errorf("%s: %v", c.name, err)
		}
		if opened := fixture.opener.openedIds(); len(opened) != 0 {
			t.Errorf("%s: opened %v", c.name, opened)
		}
	}
}

// A dead edge's ticket goes to the backup (§14's failure row): the primary's open fails, and the backup's edge opens.
func TestPlatformDialFallsToTheBackupEdge(t *testing.T) {
	dead := newTestDialListener("dead edge").rejecting(protocol.StreamRejectCode_SR_RETRY)
	alive := newTestDialListener("live edge")
	fixture, _, _ := newTestPlatformDial(t, nil, dead, alive)
	conn, err := fixture.dial("ur/smtpedge")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if opened := fixture.opener.openedIds(); len(opened) != 2 || opened[1] != alive.clientId {
		t.Fatalf("opened %v", opened)
	}
}

// Before any registration answer names urnetwork-edge, a ur/ dial is unavailable, and a ur/ address naming a network
// is no address.
func TestPlatformDialNeedsTheEdgeNetwork(t *testing.T) {
	fixture, _, _ := newTestPlatformDial(t, nil, newTestDialListener("smtpedge"))
	fixture.dialer.admission = &socketAdmissionState{}
	fixture.dialer.urnetworkEdge = nil
	if _, err := fixture.dial("ur/smtpedge"); !errors.Is(err, ErrSocketUnavailable) {
		t.Fatalf("with no urnetwork-edge: %v", err)
	}
	if _, err := fixture.dial("abcdefghij:ur/smtpedge"); err == nil {
		t.Fatal("a ur/ address with a network dialed")
	}
}
