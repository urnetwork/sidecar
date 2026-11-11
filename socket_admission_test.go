//go:build !sidecar_http && !js

// §22.5's admission table (SOCK-M5-11): one case per step and refusal of §9.6's listener admission, on a fixed clock,
// a fake policy and tickets the test's service key signs, plus the replay set's bound, the position wait on the clock,
// and ±10 min of clock offset still admitting inside the ticket's window.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
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
	return self.decision(self.listen[subject.Id])
}

func (self *testSocketPolicy) MayPublish(subject AclSubject, host string, now time.Time) AclDecision {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.decision(self.publish[subject.Id])
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
