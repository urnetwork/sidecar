//go:build !sidecar_http && !js

// SocketEdgeDialer on the pipe seam and a scripted Find (SOCK-M5-13): a dead primary falls to the backup at the accept
// timeout, only accept timeouts reach failed_tickets, the ticket's named client opens the stream with the caller's
// metadata and early data, a ticket naming a client this process does not hold is never opened, the visitor's own
// departure reports nothing, and a dial takes at most three Finds.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// One scripted edge listener: how it answers an open.
type testEdgeListener struct {
	clientId   Id
	reject     bool
	code       protocol.StreamRejectCode
	timeout    bool
	dialerFrom Id
}

// An open as the edge dialer made it.
type testEdgeOpen struct {
	from     Id
	listener Id
	request  *StreamOpenRequest
}

// The edge dialer's world: its K clients, the listeners' answers, and a scripted Find.
type testEdgeFixture struct {
	clock     *testArmedClock
	clientIds []Id
	listeners map[Id]*testEdgeListener
	answers   [][]*testEdgeListener
	waiting   chan Id
	dialer    *SocketEdgeDialer

	stateLock sync.Mutex
	finds     []*SocketFindArgs
	opens     []*testEdgeOpen
	count     int
}

func newTestEdgeFixture(t testing.TB, listeners ...*testEdgeListener) *testEdgeFixture {
	t.Helper()
	fixture := &testEdgeFixture{
		clock:     newTestArmedClock(),
		clientIds: []Id{testSocketId("edge client 0"), testSocketId("edge client 1"), testSocketId("edge client 2")},
		listeners: map[Id]*testEdgeListener{},
		waiting:   make(chan Id, 16),
	}
	for index, listener := range listeners {
		fixture.listeners[listener.clientId] = listener
		if listener.dialerFrom == (Id{}) {
			listener.dialerFrom = fixture.clientIds[index%len(fixture.clientIds)]
		}
	}
	dialer, err := newSocketEdgeDialer(nil, fixture.clock, fixture.clientIds, newSocketFindClient(fixture.find), fixture.open)
	if err != nil {
		t.Fatal(err)
	}
	fixture.dialer = dialer
	return fixture
}

func (self *testEdgeFixture) ticket(listener *testEdgeListener, backup bool) *SocketFindTicket {
	self.count += 1
	ticket := &protocol.SocketTicket{
		TicketId:              testSocketId("edge ticket " + string(rune('a'+self.count))).Bytes(),
		NetworkId:             testRegistrarNetworkId.Bytes(),
		Name:                  "tls/443/blog",
		ListenerClientId:      listener.clientId.Bytes(),
		ListenId:              testSocketId("edge listen").Bytes(),
		DialerClientId:        listener.dialerFrom.Bytes(),
		DialerNetworkId:       testSocketId("urnetwork-edge").Bytes(),
		IssueTimeMillis:       1,
		ExpireTimeMillis:      30_001,
		PolicyVersion:         5,
		Backup:                backup,
		GrantExpireTimeMillis: 77_000,
	}
	signed, err := SignSocketTicket(testAdmissionKeyId, testAdmissionKey, ticket)
	if err != nil {
		panic(err)
	}
	ticketBytes, err := proto.Marshal(signed)
	if err != nil {
		panic(err)
	}
	return &SocketFindTicket{Ticket: ticketBytes}
}

func (self *testEdgeFixture) find(ctx context.Context, args *SocketFindArgs) (*SocketFindResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	copied := *args
	copied.FailedTickets = append([]*SocketFailedTicket(nil), args.FailedTickets...)
	self.finds = append(self.finds, &copied)
	listeners := self.answers[min(len(self.finds)-1, len(self.answers)-1)]
	result := &SocketFindResult{}
	for position, listener := range listeners {
		if position == 0 {
			result.Primary = self.ticket(listener, false)
		} else {
			result.Backup = self.ticket(listener, true)
		}
	}
	return result, nil
}

func (self *testEdgeFixture) open(ctx context.Context, clientId Id, listenerClientId Id, request *StreamOpenRequest) (socketStream, error) {
	self.stateLock.Lock()
	self.opens = append(self.opens, &testEdgeOpen{from: clientId, listener: listenerClientId, request: request})
	self.stateLock.Unlock()
	listener := self.listeners[listenerClientId]
	switch {
	case listener.timeout:
		self.waiting <- listenerClientId
		<-ctx.Done()
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED}
	case listener.reject:
		return nil, &StreamRejectError{Code: listener.code}
	}
	edge, _ := newSocketStreamPipe(1024)
	return edge, nil
}

func (self *testEdgeFixture) recorded() ([]*SocketFindArgs, []*testEdgeOpen) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*SocketFindArgs(nil), self.finds...), append([]*testEdgeOpen(nil), self.opens...)
}

func testEdgeRequest() *SocketEdgeDialRequest {
	return &SocketEdgeDialRequest{
		NetworkId:    testRegistrarNetworkId,
		NetworkLabel: "abcdefghij",
		Name:         "tls/443/blog",
		Protocol:     "tls",
		Metadata: func(grantExpireTimeMillis uint64) ([]byte, error) {
			return []byte{byte(grantExpireTimeMillis / 1000)}, nil
		},
		EarlyData: bytes.Repeat([]byte{0x16}, 3000),
	}
}

func TestSocketEdgeDialFallsToTheBackupAtTheAcceptTimeout(t *testing.T) {
	primary := &testEdgeListener{clientId: testSocketId("edge listener primary"), timeout: true}
	backup := &testEdgeListener{clientId: testSocketId("edge listener backup")}
	fixture := newTestEdgeFixture(t, primary, backup)
	fixture.answers = [][]*testEdgeListener{{primary, backup}}
	type result struct {
		stream *SocketEdgeStream
		err    error
	}
	results := make(chan result, 1)
	go func() {
		stream, err := fixture.dialer.Dial(context.Background(), testEdgeRequest())
		results <- result{stream: stream, err: err}
	}()
	testSocketAwait(t, fixture.waiting, "the dead primary's open")
	fixture.clock.advance(DefaultSocketEdgeDialSettings().AcceptTimeout)
	got := testSocketAwait(t, results, "the dial")
	if got.err != nil {
		t.Fatal(got.err)
	}
	// the stream opened from the client the backup's ticket named, with the caller's metadata and first bytes
	if got.stream.ClientId() != backup.dialerFrom || !bytes.Equal(got.stream.Ticket().GetListenerClientId(), backup.clientId.Bytes()) {
		t.Errorf("opened from %v to %x", got.stream.ClientId(), got.stream.Ticket().GetListenerClientId())
	}
	finds, opens := fixture.recorded()
	if len(finds) != 1 || len(opens) != 2 {
		t.Fatalf("%d finds, %d opens", len(finds), len(opens))
	}
	for index, open := range opens {
		want := []*testEdgeListener{primary, backup}[index]
		if open.from != want.dialerFrom || open.listener != want.clientId || !open.request.Edge ||
			open.request.Target != "abcdefghij:tls/443/blog" || !bytes.Equal(open.request.Metadata, []byte{77}) ||
			len(open.request.EarlyData) != 3000 || len(open.request.Ticket) == 0 {
			t.Errorf("open %d: %+v", index, open)
		}
	}
	if len(finds[0].ClientIds) != 3 || finds[0].Name != "tls/443/blog" || *finds[0].NetworkId != connect.Id(testRegistrarNetworkId) {
		t.Errorf("find %+v", finds[0])
	}
}

// Only an accept timeout is reported; a refusal, a ticket for a client this process lacks, and a reset are not.
func TestSocketEdgeDialReportsOnlyAcceptTimeouts(t *testing.T) {
	dead := &testEdgeListener{clientId: testSocketId("edge listener dead"), timeout: true}
	busy := &testEdgeListener{clientId: testSocketId("edge listener busy"), reject: true, code: protocol.StreamRejectCode_SR_BUSY}
	stranger := &testEdgeListener{clientId: testSocketId("edge listener stranger"), dialerFrom: testSocketId("not this process's client")}
	retry := &testEdgeListener{clientId: testSocketId("edge listener retry"), reject: true, code: protocol.StreamRejectCode_SR_RETRY}
	fixture := newTestEdgeFixture(t, dead, busy, stranger, retry)
	fixture.answers = [][]*testEdgeListener{{dead, busy}, {stranger, retry}}
	results := make(chan error, 1)
	go func() {
		_, err := fixture.dialer.Dial(context.Background(), testEdgeRequest())
		results <- err
	}()
	testSocketAwait(t, fixture.waiting, "the dead listener's open")
	fixture.clock.advance(DefaultSocketEdgeDialSettings().AcceptTimeout)
	if err := testSocketAwait(t, results, "the dial"); !errors.Is(err, ErrSocketNoListener) {
		t.Fatalf("%v", err)
	}
	finds, opens := fixture.recorded()
	if len(finds) != 3 {
		t.Fatalf("%d finds", len(finds))
	}
	if len(finds[1].FailedTickets) != 1 || finds[1].FailedTickets[0].Reason != SocketFailedReasonTimeout {
		t.Errorf("the second find carried %+v", finds[1].FailedTickets)
	}
	if len(finds[2].FailedTickets) != 0 {
		t.Errorf("the third find carried %+v", finds[2].FailedTickets)
	}
	for _, open := range opens {
		if open.listener == stranger.clientId {
			t.Error("a ticket naming another process's client opened")
		}
	}
}

// The visitor leaving mid-dial ends it with nothing reported, and denied and quota stop at once.
func TestSocketEdgeDialStops(t *testing.T) {
	dead := &testEdgeListener{clientId: testSocketId("edge listener dead"), timeout: true}
	fixture := newTestEdgeFixture(t, dead)
	fixture.answers = [][]*testEdgeListener{{dead}}
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan error, 1)
	go func() {
		_, err := fixture.dialer.Dial(ctx, testEdgeRequest())
		results <- err
	}()
	testSocketAwait(t, fixture.waiting, "the dead listener's open")
	cancel()
	if err := testSocketAwait(t, results, "the dial"); err == nil {
		t.Fatal("a departed visitor's dial answered")
	}
	if finds, _ := fixture.recorded(); len(finds) != 1 {
		t.Errorf("%d finds after the visitor left", len(finds))
	}

	for _, stop := range []struct {
		code protocol.StreamRejectCode
		want error
	}{
		{code: protocol.StreamRejectCode_SR_DENIED, want: ErrSocketDenied},
		{code: protocol.StreamRejectCode_SR_QUOTA, want: ErrSocketQuota},
	} {
		refusing := &testEdgeListener{clientId: testSocketId("edge listener refusing"), reject: true, code: stop.code}
		backup := &testEdgeListener{clientId: testSocketId("edge listener backup")}
		fixture := newTestEdgeFixture(t, refusing, backup)
		fixture.answers = [][]*testEdgeListener{{refusing, backup}}
		if _, err := fixture.dialer.Dial(context.Background(), testEdgeRequest()); !errors.Is(err, stop.want) {
			t.Errorf("%s: %v", stop.code, err)
		}
		if _, opens := fixture.recorded(); len(opens) != 1 {
			t.Errorf("%s: %d opens", stop.code, len(opens))
		}
	}
}

// An edge dials only tls/ and smtp/ names, on a label, and a dialer needs a client of its own in the edge role.
func TestSocketEdgeDialRefusesWhatIsNotAnEdge(t *testing.T) {
	fixture := newTestEdgeFixture(t)
	for _, name := range []string{"db/primary", "ur/smtpedge", "share/abcdefghijklmnopqrstuvwxyz"} {
		request := testEdgeRequest()
		request.Name = name
		if _, err := fixture.dialer.Dial(context.Background(), request); err == nil {
			t.Errorf("%s dialed", name)
		}
	}
	request := testEdgeRequest()
	request.NetworkLabel = ""
	if _, err := fixture.dialer.Dial(context.Background(), request); err == nil {
		t.Error("a dial with no label")
	}
	if _, err := NewSocketEdgeDialer(&SocketEdgeDialerArgs{}); err == nil {
		t.Error("a dialer with no clients")
	}
	if _, err := NewSocketEdgeDialer(&SocketEdgeDialerArgs{Clients: []*SocketEdgeClient{{ClientId: testSocketId("edge"), Subprotocol: &Subprotocol{}}}}); err == nil {
		t.Error("a dialer on a sidecar's dispatcher")
	}
}
