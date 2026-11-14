//go:build !sidecar_http && !js

// §22.5's admission table (SOCK-M5-11): one case per step and refusal of §9.6's listener admission, on a fixed clock,
// a fake policy and tickets the test's service key signs, plus the replay set's bound, the position wait on the clock,
// and ±10 min of clock offset still admitting inside the ticket's window.
//
// §13.9's system publish on the listener (SOCK-M8-01): tls/443/mta-sts admitted and registered on a receiver's own
// smtp/25/mx listen grant alone, with no tls/ grant and no call to §5.4's gate; a non-receiver refused whatever tls/
// grants it holds; the grant's expiry and revocation ending the publish's streams; and no other name taking the path.
// The service's half is socketsservice's system_publish_test.go.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A service key admission trusts, apart from the ticket tests' fixed one.
var testAdmissionKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))

const testAdmissionKeyId = "admission-key"

// A SocketPolicy whose answers a test sets.
type testSocketPolicy struct {
	stateLock sync.Mutex
	position  uint64
	// what WaitPosition's fetch reaches, and a channel closed once it waits
	catchUpTo uint64
	block     bool
	waiting   chan struct{}
	// by subject id; absent denies
	inbound  map[Id]bool
	listen   map[Id]bool
	publish  map[Id]bool
	inbounds []*AclInbound
	// when set, listen on a name in the clear is allowed only on the names it holds, beside listen's subjects
	listenNames map[string]bool
	// the names in the clear MayListen was asked of, in order, and how often MayPublish was asked
	listenAsked  []string
	publishAsked int
}

func newTestSocketPolicy(position uint64) *testSocketPolicy {
	return &testSocketPolicy{
		position: position,
		waiting:  make(chan struct{}),
		inbound:  map[Id]bool{},
		listen:   map[Id]bool{},
		publish:  map[Id]bool{},
	}
}

func (self *testSocketPolicy) Position() uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.position
}

func (self *testSocketPolicy) WaitPosition(ctx context.Context, position uint64) bool {
	self.stateLock.Lock()
	block := self.block
	waiting := self.waiting
	self.stateLock.Unlock()
	if block {
		close(waiting)
		<-ctx.Done()
		return false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.position = max(self.position, self.catchUpTo)
	return position <= self.position
}

func (self *testSocketPolicy) decision(allowed bool) AclDecision {
	if allowed {
		return AclDecision{Allowed: true, Reason: AclReasonRule}
	}
	return aclDeny(AclReasonNoGrant)
}

func (self *testSocketPolicy) AllowInbound(inbound *AclInbound, now time.Time) AclDecision {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.inbounds = append(self.inbounds, inbound)
	return self.decision(self.inbound[inbound.Source.Id])
}

func (self *testSocketPolicy) MayListen(subject AclSubject, socket AclSocketName, now time.Time) AclDecision {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	allowed := self.listen[subject.Id]
	if socket.PublicName != "" {
		self.listenAsked = append(self.listenAsked, socket.PublicName)
		if self.listenNames != nil {
			allowed = allowed && self.listenNames[socket.PublicName]
		}
	}
	return self.decision(allowed)
}

func (self *testSocketPolicy) MayPublish(subject AclSubject, host string, now time.Time) AclDecision {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.publishAsked += 1
	return self.decision(self.publish[subject.Id])
}

// The names MayListen was asked of so far, and how often MayPublish was asked.
func (self *testSocketPolicy) asked() ([]string, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.listenAsked), self.publishAsked
}

func (self *testSocketPolicy) set(change func(policy *testSocketPolicy)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	change(self)
}

// One listener's admission and what it judges against.
type testAdmissionFixture struct {
	clock     *testSocketClock
	ring      *SocketKeyRing
	admission *socketAdmission
	state     *socketAdmissionState
	policy    *testSocketPolicy
	clientId  Id
	sidecarId Id
	listenId  Id
	name      string
	nameToken []byte
	// the dialer's sidecar, its client and its Hello
	dialerClientId Id
	dialerPeer     *SubprotocolPeerIdentity
	urnetworkEdge  Id
	ticketCount    int
}

// A listener on name in the test network, its policy allowing the dialer's sidecar, every edge name's own listen and
// publish, at position 5.
func newTestAdmissionFixture(t testing.TB, name string) *testAdmissionFixture {
	t.Helper()
	fixture := &testAdmissionFixture{
		clock:          newTestSocketClock(),
		ring:           newTestSocketRing(t, "admission", "", 0),
		clientId:       testSocketId("listener client"),
		sidecarId:      testSocketId("listener sidecar"),
		listenId:       testSocketId("listen " + name),
		name:           name,
		dialerClientId: testSocketId("dialer client"),
		urnetworkEdge:  testSocketId("urnetwork-edge"),
	}
	fixture.dialerPeer = &SubprotocolPeerIdentity{SidecarId: testSocketId("dialer sidecar")}
	_, namespace, err := ParseSocketName(name)
	if err != nil {
		t.Fatal(err)
	}
	if namespace.blinded() {
		if fixture.nameToken, err = fixture.ring.Current().TokenPath(name); err != nil {
			t.Fatal(err)
		}
	}
	fixture.policy = newTestSocketPolicy(5)
	fixture.policy.inbound[fixture.dialerPeer.SidecarId] = true
	fixture.policy.listen[fixture.sidecarId] = true
	fixture.policy.publish[fixture.sidecarId] = true
	fixture.state = &socketAdmissionState{
		known: true,
		ticketKeys: []*SocketTicketKey{{
			KeyId:            testAdmissionKeyId,
			PublicKey:        testAdmissionKey.Public().(ed25519.PublicKey),
			ExpireTimeMillis: uint64(testSocketNow.Add(24 * time.Hour).UnixMilli()),
		}},
		urnetworkEdge: &fixture.urnetworkEdge,
	}
	settings := DefaultSidecarSocketSettings()
	fixture.admission = newSocketAdmission(settings, fixture.clock, testRegistrarNetworkId, fixture.listenId, namespace, name, func() [][]byte {
		if fixture.nameToken == nil {
			return nil
		}
		return [][]byte{fixture.nameToken}
	}, 4)
	return fixture
}

// A ticket for this listener from the fixture's dialer at the service's now, changed by mutate, signed by key.
func (self *testAdmissionFixture) ticketBy(t testing.TB, key ed25519.PrivateKey, keyId string, mutate func(ticket *protocol.SocketTicket)) []byte {
	t.Helper()
	self.ticketCount += 1
	nowMillis := self.state.serverNowMillis(self.clock.Now())
	ticket := &protocol.SocketTicket{
		TicketId:         testSocketId("ticket " + string(rune('a'+self.ticketCount))).Bytes(),
		NetworkId:        testRegistrarNetworkId.Bytes(),
		NameToken:        self.nameToken,
		ListenerClientId: self.clientId.Bytes(),
		ListenId:         self.listenId.Bytes(),
		DialerClientId:   self.dialerClientId.Bytes(),
		DialerNetworkId:  testRegistrarNetworkId.Bytes(),
		IssueTimeMillis:  nowMillis,
		ExpireTimeMillis: nowMillis + 30_000,
		PolicyVersion:    5,
		GrantId:          bytes.Repeat([]byte{0x07}, 32),
	}
	if self.nameToken == nil {
		ticket.Name = self.name
	}
	if mutate != nil {
		mutate(ticket)
	}
	signed, err := SignSocketTicket(keyId, key, ticket)
	if err != nil {
		t.Fatal(err)
	}
	ticketBytes, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return ticketBytes
}

func (self *testAdmissionFixture) ticket(t testing.TB, mutate func(ticket *protocol.SocketTicket)) []byte {
	return self.ticketBy(t, testAdmissionKey, testAdmissionKeyId, mutate)
}

// A sidecar dialer's open of ticketBytes.
func (self *testAdmissionFixture) request(ticketBytes []byte) *socketAdmissionRequest {
	return &socketAdmissionRequest{ticketBytes: ticketBytes, sourceId: self.dialerClientId, peer: self.dialerPeer}
}

// An edge's open of ticketBytes: no Hello, a Service-mode source.
func (self *testAdmissionFixture) edgeRequest(ticketBytes []byte) *socketAdmissionRequest {
	return &socketAdmissionRequest{ticketBytes: ticketBytes, sourceId: self.dialerClientId, edge: true}
}

func (self *testAdmissionFixture) inputs() *socketAdmissionInputs {
	return &socketAdmissionInputs{
		admission: self.state,
		clientId:  self.clientId,
		sidecarId: self.sidecarId,
		policy:    self.policy,
		serving:   true,
	}
}

func (self *testAdmissionFixture) admit(request *socketAdmissionRequest, inputs *socketAdmissionInputs) protocol.StreamRejectCode {
	return self.admission.admit(context.Background(), request, inputs).code
}

const testAccepted = protocol.StreamRejectCode_SR_UNSPECIFIED

func TestSocketAdmissionTable(t *testing.T) {
	type admissionCase struct {
		name string
		// on a tls/ listener rather than an application one
		edgeName bool
		run      func(fixture *testAdmissionFixture) protocol.StreamRejectCode
		want     protocol.StreamRejectCode
	}
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	cases := []admissionCase{
		{name: "1: a ticket signed by another key", want: protocol.StreamRejectCode_SR_INVALID,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				return fixture.admit(fixture.request(fixture.ticketBy(t, otherKey, testAdmissionKeyId, nil)), fixture.inputs())
			}},
		{name: "1: a ticket under a key no answer gave", want: protocol.StreamRejectCode_SR_INVALID,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				return fixture.admit(fixture.request(fixture.ticketBy(t, otherKey, "unknown-key", nil)), fixture.inputs())
			}},
		{name: "1: no registration answer yet", want: protocol.StreamRejectCode_SR_INVALID,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				inputs := fixture.inputs()
				inputs.admission = &socketAdmissionState{}
				return fixture.admit(fixture.request(fixture.ticket(t, nil)), inputs)
			}},
		{name: "2: another listener client", want: protocol.StreamRejectCode_SR_INVALID,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				return fixture.admit(fixture.request(fixture.ticket(t, func(ticket *protocol.SocketTicket) {
					ticket.ListenerClientId = testSocketId("another listener").Bytes()
				})), fixture.inputs())
			}},
		{name: "2: another name", want: protocol.StreamRejectCode_SR_INVALID,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				return fixture.admit(fixture.request(fixture.ticket(t, func(ticket *protocol.SocketTicket) {
					ticket.NameToken = bytes.Repeat([]byte{0x09}, socketTokenByteCount)
				})), fixture.inputs())
			}},
		{name: "2: a listen that ended answers retry", want: protocol.StreamRejectCode_SR_RETRY,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				return fixture.admit(fixture.request(fixture.ticket(t, func(ticket *protocol.SocketTicket) {
					ticket.ListenId = testSocketId("an earlier listen").Bytes()
				})), fixture.inputs())
			}},
		{name: "3: a dialer that is not the session's source", want: protocol.StreamRejectCode_SR_INVALID,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				request := fixture.request(fixture.ticket(t, nil))
				request.sourceId = testSocketId("another source")
				return fixture.admit(request, fixture.inputs())
			}},
		{name: "3: a sidecar dialer with no Hello", want: protocol.StreamRejectCode_SR_INVALID,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				request := fixture.request(fixture.ticket(t, nil))
				request.peer = nil
				return fixture.admit(request, fixture.inputs())
			}},
		{name: "3: a sidecar dialer from another network", want: protocol.StreamRejectCode_SR_INVALID,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				return fixture.admit(fixture.request(fixture.ticket(t, func(ticket *protocol.SocketTicket) {
					ticket.DialerNetworkId = testSocketId("another network").Bytes()
				})), fixture.inputs())
			}},
		{name: "3: an edge-marked ticket for an application name", want: protocol.StreamRejectCode_SR_INVALID,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				return fixture.admit(fixture.edgeRequest(fixture.ticket(t, func(ticket *protocol.SocketTicket) {
					ticket.DialerNetworkId = fixture.urnetworkEdge.Bytes()
				})), fixture.inputs())
			}},
		{name: "3: an edge ticket from a source that sent a Hello", edgeName: true, want: protocol.StreamRejectCode_SR_INVALID,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				return fixture.admit(fixture.request(fixture.ticket(t, func(ticket *protocol.SocketTicket) {
					ticket.DialerNetworkId = fixture.urnetworkEdge.Bytes()
				})), fixture.inputs())
			}},
		{name: "3: a sidecar's ticket for an edge name", edgeName: true, want: protocol.StreamRejectCode_SR_INVALID,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				return fixture.admit(fixture.request(fixture.ticket(t, nil)), fixture.inputs())
			}},
		{name: "4: an expired ticket", want: protocol.StreamRejectCode_SR_INVALID,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				ticketBytes := fixture.ticket(t, nil)
				fixture.clock.advance(30 * time.Second)
				return fixture.admit(fixture.request(ticketBytes), fixture.inputs())
			}},
		{name: "4: a ticket presented twice", want: protocol.StreamRejectCode_SR_INVALID,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				ticketBytes := fixture.ticket(t, nil)
				if code := fixture.admit(fixture.request(ticketBytes), fixture.inputs()); code != testAccepted {
					return protocol.StreamRejectCode(99)
				}
				return fixture.admit(fixture.request(ticketBytes), fixture.inputs())
			}},
		{name: "5: max_streams in flight", want: protocol.StreamRejectCode_SR_BUSY,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				inputs := fixture.inputs()
				inputs.inflight = 4
				return fixture.admit(fixture.request(fixture.ticket(t, nil)), inputs)
			}},
		{name: "5: not serving", want: protocol.StreamRejectCode_SR_BUSY,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				inputs := fixture.inputs()
				inputs.serving = false
				return fixture.admit(fixture.request(fixture.ticket(t, nil)), inputs)
			}},
		{name: "5: §20 stopped new streams", want: protocol.StreamRejectCode_SR_QUOTA,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				fixture.state.streamsStopped = true
				return fixture.admit(fixture.request(fixture.ticket(t, nil)), fixture.inputs())
			}},
		{name: "6: the dialer holds no dial grant here", want: protocol.StreamRejectCode_SR_DENIED,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				fixture.policy.set(func(policy *testSocketPolicy) { policy.inbound = map[Id]bool{} })
				return fixture.admit(fixture.request(fixture.ticket(t, nil)), fixture.inputs())
			}},
		{name: "6: no evaluation of the config yet", want: protocol.StreamRejectCode_SR_DENIED,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				inputs := fixture.inputs()
				inputs.policy = nil
				return fixture.admit(fixture.request(fixture.ticket(t, nil)), inputs)
			}},
		{name: "6: behind the ticket's position, and the fetch stays behind", want: protocol.StreamRejectCode_SR_RETRY,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				fixture.policy.set(func(policy *testSocketPolicy) { policy.catchUpTo = 6 })
				return fixture.admit(fixture.request(fixture.ticket(t, func(ticket *protocol.SocketTicket) { ticket.PolicyVersion = 7 })), fixture.inputs())
			}},
		{name: "6: behind the ticket's position, and the fetch reaches it", want: testAccepted,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				fixture.policy.set(func(policy *testSocketPolicy) { policy.catchUpTo = 7 })
				return fixture.admit(fixture.request(fixture.ticket(t, func(ticket *protocol.SocketTicket) { ticket.PolicyVersion = 7 })), fixture.inputs())
			}},
		{name: "6: an edge's dial of a tls/ name whose listener holds no publish", edgeName: true, want: protocol.StreamRejectCode_SR_DENIED,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				fixture.policy.set(func(policy *testSocketPolicy) { policy.publish = map[Id]bool{} })
				return fixture.admit(fixture.edgeRequest(fixture.ticket(t, func(ticket *protocol.SocketTicket) {
					ticket.DialerNetworkId = fixture.urnetworkEdge.Bytes()
				})), fixture.inputs())
			}},
		{name: "7: a sidecar's dial within the network", want: testAccepted,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				return fixture.admit(fixture.request(fixture.ticket(t, nil)), fixture.inputs())
			}},
		{name: "7: an edge's dial of a tls/ name", edgeName: true, want: testAccepted,
			run: func(fixture *testAdmissionFixture) protocol.StreamRejectCode {
				return fixture.admit(fixture.edgeRequest(fixture.ticket(t, func(ticket *protocol.SocketTicket) {
					ticket.DialerNetworkId = fixture.urnetworkEdge.Bytes()
				})), fixture.inputs())
			}},
	}
	for _, admissionCase := range cases {
		name := "db/primary"
		if admissionCase.edgeName {
			name = "tls/443/blog"
		}
		fixture := newTestAdmissionFixture(t, name)
		if code := admissionCase.run(fixture); code != admissionCase.want {
			t.Errorf("%s: %s, want %s", admissionCase.name, code, admissionCase.want)
		}
	}
}

// Step 6 judges the dialer's sidecar on the listener's own name and token path, never the ticket's grant.
func TestSocketAdmissionJudgesTheDialerLocally(t *testing.T) {
	fixture := newTestAdmissionFixture(t, "db/primary")
	ticketBytes := fixture.ticket(t, func(ticket *protocol.SocketTicket) {
		ticket.GrantId = bytes.Repeat([]byte{0xee}, 32)
	})
	if code := fixture.admit(fixture.request(ticketBytes), fixture.inputs()); code != testAccepted {
		t.Fatalf("%s", code)
	}
	if len(fixture.policy.inbounds) != 1 {
		t.Fatalf("%d evaluations", len(fixture.policy.inbounds))
	}
	inbound := fixture.policy.inbounds[0]
	if inbound.Source.Kind != AclSubjectSidecar || inbound.Source.Id != fixture.dialerPeer.SidecarId || inbound.SocketName != "db/primary" || !bytes.Equal(inbound.NameToken, fixture.nameToken) {
		t.Errorf("evaluated %+v", inbound)
	}
}

// The replay set keeps a ticket_id until its ticket expires and drops it then, so it holds at most what could still be
// presented.
func TestSocketAdmissionReplaySetIsBoundedByTicketLife(t *testing.T) {
	fixture := newTestAdmissionFixture(t, "db/primary")
	for range 3 {
		if code := fixture.admit(fixture.request(fixture.ticket(t, nil)), fixture.inputs()); code != testAccepted {
			t.Fatalf("%s", code)
		}
	}
	if count := fixture.admission.seenCount(); count != 3 {
		t.Fatalf("%d held", count)
	}
	fixture.clock.advance(30 * time.Second)
	if code := fixture.admit(fixture.request(fixture.ticket(t, nil)), fixture.inputs()); code != testAccepted {
		t.Fatalf("%s", code)
	}
	if count := fixture.admission.seenCount(); count != 1 {
		t.Fatalf("%d held past their tickets' expiry", count)
	}
}

// A fetch that does not answer is bounded by ListenPositionWait on the listener's clock, then retry.
func TestSocketAdmissionPositionWaitIsBounded(t *testing.T) {
	fixture := newTestAdmissionFixture(t, "db/primary")
	fixture.policy.set(func(policy *testSocketPolicy) { policy.block = true })
	ticketBytes := fixture.ticket(t, func(ticket *protocol.SocketTicket) { ticket.PolicyVersion = 9 })
	codes := make(chan protocol.StreamRejectCode, 1)
	go func() {
		codes <- fixture.admit(fixture.request(ticketBytes), fixture.inputs())
	}()
	testSocketAwait(t, fixture.policy.waiting, "the fetch's wait")
	select {
	case code := <-codes:
		t.Fatalf("answered %s before its wait ran out", code)
	default:
	}
	fixture.clock.advance(DefaultSidecarSocketSettings().ListenPositionWait)
	if code := testSocketAwait(t, codes, "the verdict"); code != protocol.StreamRejectCode_SR_RETRY {
		t.Fatalf("%s", code)
	}
}

// A listener whose clock is 10 min off the service's admits a ticket inside its window once the registration answer's
// offset is applied, and refuses it past the window.
func TestSocketAdmissionHoldsTheServiceOffset(t *testing.T) {
	for _, offset := range []time.Duration{10 * time.Minute, -10 * time.Minute} {
		fixture := newTestAdmissionFixture(t, "db/primary")
		fixture.state.serverTimeOffsetMillis = offset.Milliseconds()
		ticketBytes := fixture.ticket(t, nil)
		fixture.clock.advance(29 * time.Second)
		if code := fixture.admit(fixture.request(ticketBytes), fixture.inputs()); code != testAccepted {
			t.Errorf("offset %v inside the window: %s", offset, code)
		}
		late := fixture.ticket(t, nil)
		fixture.clock.advance(30 * time.Second)
		if code := fixture.admit(fixture.request(late), fixture.inputs()); code != protocol.StreamRejectCode_SR_INVALID {
			t.Errorf("offset %v past the window: %s", offset, code)
		}
	}
}

// An edge's open of a ticket for fixture's listener, changed by mutate.
func (self *testAdmissionFixture) edgeAdmit(t testing.TB, mutate func(ticket *protocol.SocketTicket)) protocol.StreamRejectCode {
	t.Helper()
	return self.admit(self.edgeRequest(self.ticket(t, func(ticket *protocol.SocketTicket) {
		ticket.DialerNetworkId = self.urnetworkEdge.Bytes()
		if mutate != nil {
			mutate(ticket)
		}
	})), self.inputs())
}

// §13.9's system publish at step 6 (SOCK-M8-01): a receiver whose only grant is its smtp/25/mx listen admits an edge's
// ticket for tls/443/mta-sts, step 6 asking that listen alone and no publish; a non-receiver holding the name's own
// tls/ listen and every publish is denied, since those count for nothing there; and tls/443/other takes no such path.
func TestSocketAdmissionSystemPublishStandsOnTheReceiversListen(t *testing.T) {
	receiver := newTestAdmissionFixture(t, SocketSystemPublishName)
	receiver.policy.set(func(policy *testSocketPolicy) {
		policy.listenNames = map[string]bool{SocketSystemPublishListenName: true}
		policy.publish = map[Id]bool{}
	})
	if code := receiver.edgeAdmit(t, nil); code != testAccepted {
		t.Fatalf("a receiver's system publish: %s", code)
	}
	if listenAsked, publishAsked := receiver.policy.asked(); !slices.Equal(listenAsked, []string{SocketSystemPublishListenName}) || publishAsked != 0 {
		t.Fatalf("step 6 asked listen on %v and publish %d times", listenAsked, publishAsked)
	}

	stranger := newTestAdmissionFixture(t, SocketSystemPublishName)
	stranger.policy.set(func(policy *testSocketPolicy) {
		policy.listenNames = map[string]bool{SocketSystemPublishName: true}
	})
	if code := stranger.edgeAdmit(t, nil); code != protocol.StreamRejectCode_SR_DENIED {
		t.Fatalf("a non-receiver holding the name's tls/ grants: %s", code)
	}

	other := newTestAdmissionFixture(t, "tls/443/other")
	other.policy.set(func(policy *testSocketPolicy) {
		policy.listenNames = map[string]bool{SocketSystemPublishListenName: true}
	})
	if code := other.edgeAdmit(t, nil); code != protocol.StreamRejectCode_SR_DENIED {
		t.Fatalf("tls/443/other on a receiver's smtp/25/mx listen: %s", code)
	}
}

// The system publish's listener (SOCK-M8-01): its own entry on a receiver registers tls/443/mta-sts in app mode http
// with no call to §5.4's gate and no tls/ grant, and edges' splices are admitted; a stream ends at its ticket's grant
// expiry, which the service signs from the receiver's listen grant; once that grant is revoked, PolicyChanged resets the
// live stream and the next open is denied.
func TestSocketListenSystemPublishStandsOnTheReceiversListen(t *testing.T) {
	fixture := newTestListenFixture(t)
	fixture.policy.set(func(policy *testSocketPolicy) {
		policy.listenNames = map[string]bool{SocketSystemPublishListenName: true}
		policy.publish = map[Id]bool{}
	})
	listener, err := fixture.component.listenSystemPublish(t.Context(), nil)
	if err != nil {
		t.Fatalf("a receiver's system publish: %v", err)
	}
	defer listener.Close()
	if len(fixture.authorized) != 0 {
		t.Fatalf("the system publish went through §5.4's gate: %+v", fixture.authorized)
	}
	page := testSocketAwait(t, fixture.service.pages, "the page")
	if registration := page.Registrations[0]; registration.Name != SocketSystemPublishName || registration.Protocol != "tls" || registration.AppMode != "http" {
		t.Fatalf("the registration %+v", registration)
	}
	edgeOpen := func(mutate func(ticket *protocol.SocketTicket)) (*socketPipeEnd, error) {
		ticketBytes := fixture.ticket(t, listener, func(ticket *protocol.SocketTicket) {
			ticket.DialerNetworkId = fixture.service.urnetworkEdge.Bytes()
			if mutate != nil {
				mutate(ticket)
			}
		})
		return fixture.open(listener, &socketAdmissionRequest{ticketBytes: ticketBytes, sourceId: fixture.dialerId, edge: true})
	}
	readReset := func(end *socketPipeEnd) protocol.StreamResetCode {
		_, err := end.Read(make([]byte, 1))
		var resetErr *socketStreamResetError
		if !errors.As(err, &resetErr) {
			return protocol.StreamResetCode_RST_UNSPECIFIED
		}
		return resetErr.Code
	}
	expiring, err := edgeOpen(func(ticket *protocol.SocketTicket) {
		ticket.GrantExpireTimeMillis = uint64(fixture.clock.Now().Add(10 * time.Second).UnixMilli())
	})
	if err != nil {
		t.Fatalf("a receiver refused an edge splice of its system publish: %v", err)
	}
	live, err := edgeOpen(nil)
	if err != nil {
		t.Fatalf("a receiver refused an edge splice of its system publish: %v", err)
	}
	fixture.clock.advance(10 * time.Second)
	if code := readReset(expiring); code != protocol.StreamResetCode_RST_REVOKED {
		t.Errorf("at its grant's expiry: %s", code)
	}

	fixture.policy.set(func(policy *testSocketPolicy) { policy.listenNames = map[string]bool{} })
	fixture.component.PolicyChanged()
	if code := readReset(live); code != protocol.StreamResetCode_RST_REVOKED {
		t.Errorf("at the listen grant's revocation: %s", code)
	}
	if listener.inflightCount() != 0 {
		t.Errorf("%d in flight", listener.inflightCount())
	}
	if _, err := edgeOpen(nil); testRejectCode(err) != protocol.StreamRejectCode_SR_DENIED {
		t.Errorf("an open after the revocation: %v", err)
	}
}

// The system publish's entry denies a non-receiver, with no approval filed and nothing registered, whatever tls/
// grants it holds, and refuses app mode raw as invalid; an ordinary Listen of tls/443/mta-sts, the daemon's included,
// is denied on a receiver too, the name being the entry's alone; and a receiver's Listen of tls/443/other goes through
// §5.4's gate as any tls/ name does.
func TestSocketListenSystemPublishRefusesANonReceiver(t *testing.T) {
	fixture := newTestListenFixture(t)
	fixture.component.listenAction = func(name string, settings *SocketListenSettings) (*SidecarAction, error) {
		return &SidecarAction{Kind: SidecarActionListen, Canonical: []byte(name), Risk: SidecarRiskNormal}, nil
	}
	refused := errors.New("the test's gate refuses")
	fixture.generation.authorize = func(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
		fixture.authorized = append(fixture.authorized, action)
		return refused
	}
	fixture.policy.set(func(policy *testSocketPolicy) {
		policy.listenNames = map[string]bool{SocketSystemPublishName: true}
	})
	if _, err := fixture.component.listenSystemPublish(t.Context(), nil); !errors.Is(err, ErrSocketDenied) {
		t.Fatalf("a non-receiver's system publish: %v", err)
	}
	fixture.policy.set(func(policy *testSocketPolicy) {
		policy.listenNames = map[string]bool{SocketSystemPublishListenName: true}
	})
	if _, err := fixture.component.listenSystemPublish(t.Context(), &SocketListenSettings{AppMode: "raw"}); !errors.Is(err, errSocketRegistrationInvalid) {
		t.Fatalf("the system publish in app mode raw: %v", err)
	}
	for _, address := range []string{SocketSystemPublishName, "abcdefghij:" + SocketSystemPublishName, "TLS/443/MTA-STS"} {
		parsed, err := ParseSocketAddress(address)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.component.listen(t.Context(), parsed, nil, false); !errors.Is(err, ErrSocketDenied) {
			t.Fatalf("an ordinary Listen of %s on a receiver: %v", address, err)
		}
	}
	if len(fixture.authorized) != 0 {
		t.Fatalf("the system publish went through §5.4's gate: %+v", fixture.authorized)
	}
	select {
	case page := <-fixture.service.pages:
		t.Fatalf("a refused system publish registered %+v", page.Registrations)
	default:
	}

	other, err := ParseSocketAddress("tls/443/other")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.component.listen(t.Context(), other, nil, false); !errors.Is(err, refused) || len(fixture.authorized) != 1 {
		t.Fatalf("tls/443/other on a receiver: %v, %d actions gated", err, len(fixture.authorized))
	}
}
