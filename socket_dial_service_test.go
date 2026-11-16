//go:build !sidecar_http && !js

// The Service hold of a ur/ dial (QD-849; §6.10.1 item 2 and §13.6 as it reads them), in two parts.
//
// On the pipe seam: a ur/ ticket's open holds Service from before the open until its stream has ended at §6, each way
// a stream ends, this end's Close alone ending nothing; an open that fails holds nothing afterwards; a ticket that
// fails its checks, and any other namespace's dial, holds nothing at all.
//
// On real dispatchers (rpc_hello_test.go's pair: a sidecar and an edge, each on a connect client of its own): the
// dialer's hold is the dispatcher's, Subprotocol.HoldProvideMode, so the tests read the sidecar's client for what it
// provides and tap what it sends the platform. The pair delivers frames without connect's contracts, so
// testServiceContracts stands where CreateContract and the receiving client do for an edge's frames to the sidecar:
// each is carried only on a contract signed with the sidecar client's own Service provide key, which that client's
// ContractManager verifies, the two calls the platform's issuer and connect's receive make. With no key nothing is
// issued and the frame is dropped, as a refused CreateContract leaves it unsent. It asks a contract of every frame,
// where connect checks one a contract, so it is the stricter of the two.
//
// A stream's end releases its hold on a goroutine of the stream's own, so each test waits for the release it means
// (the openers signal each one) and never sleeps.

package sidecar

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol"
)

// The fixture's holds as the test opener counted them.
func testPlatformHolds(t testing.TB, fixture *testDialFixture, wantHoldCount int, wantHeldCount int, wantEvents ...string) {
	t.Helper()
	holdCount, heldCount, events := fixture.opener.holds()
	if holdCount != wantHoldCount || heldCount != wantHeldCount {
		t.Errorf("%d holds taken and %d held, want %d and %d", holdCount, heldCount, wantHoldCount, wantHeldCount)
	}
	if wantEvents != nil && !slices.Equal(events, wantEvents) {
		t.Errorf("events %v, want %v", events, wantEvents)
	}
}

// Waits for one Service hold of the fixture's to be released.
func testPlatformReleased(t testing.TB, fixture *testDialFixture, what string) {
	t.Helper()
	testSocketAwait(t, fixture.opener.released, what)
}

// A ur/ dial holds Service from before its open until its stream has ended, whichever way it ends, and releases it
// once. This end's Close alone ends nothing: the edge's own close is still to come.
func TestPlatformDialHoldsServiceUntilItsStreamEnds(t *testing.T) {
	cases := []struct {
		name string
		end  func(t *testing.T, fixture *testDialFixture, conn *SocketConn, farEnd *socketPipeEnd)
	}{
		{name: "Close, then the edge's close", end: func(t *testing.T, fixture *testDialFixture, conn *SocketConn, farEnd *socketPipeEnd) {
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
			// the edge's last bytes and its StreamClose still need their contracts
			testPlatformHolds(t, fixture, 1, 1)
			if _, err := farEnd.Write([]byte("an outcome no one reads")); err != nil {
				t.Error(err)
			}
			testPlatformHolds(t, fixture, 1, 1)
			farEnd.CloseWrite()
		}},
		{name: "the edge's close, then Close", end: func(t *testing.T, fixture *testDialFixture, conn *SocketConn, farEnd *socketPipeEnd) {
			farEnd.Close()
			testPlatformHolds(t, fixture, 1, 1)
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
		}},
		{name: "Abort", end: func(t *testing.T, fixture *testDialFixture, conn *SocketConn, farEnd *socketPipeEnd) {
			if err := conn.Abort(); err != nil {
				t.Error(err)
			}
		}},
		{name: "the edge's reset, which no one has read", end: func(t *testing.T, fixture *testDialFixture, conn *SocketConn, farEnd *socketPipeEnd) {
			farEnd.Reset(protocol.StreamResetCode_RST_REVOKED)
		}},
		{name: "both directions closed", end: func(t *testing.T, fixture *testDialFixture, conn *SocketConn, farEnd *socketPipeEnd) {
			// one direction closed ends nothing: the edge's answer is still to come
			if err := conn.CloseWrite(); err != nil {
				t.Error(err)
			}
			testPlatformHolds(t, fixture, 1, 1)
			farEnd.CloseWrite()
		}},
		{name: "both directions closed, the edge's bytes read through", end: func(t *testing.T, fixture *testDialFixture, conn *SocketConn, farEnd *socketPipeEnd) {
			if _, err := farEnd.Write([]byte("outcome")); err != nil {
				t.Error(err)
			}
			farEnd.CloseWrite()
			if err := conn.CloseWrite(); err != nil {
				t.Error(err)
			}
			// both sent their close, and the edge's bytes are not read yet
			testPlatformHolds(t, fixture, 1, 1)
			outcome := make([]byte, 7)
			if _, err := io.ReadFull(conn, outcome); err != nil || string(outcome) != "outcome" {
				t.Errorf("read %q, %v", outcome, err)
			}
		}},
	}
	for _, c := range cases {
		fixture, _, _ := newTestPlatformDial(t, nil, newTestDialListener("smtpedge "+c.name))
		conn, err := fixture.dial("ur/smtpedge")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		// held before the open left, and through the stream's life
		testPlatformHolds(t, fixture, 1, 1, "hold", "open")
		// a deadline that passes ends no stream
		conn.SetReadDeadline(time.Unix(1, 0))
		if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("%s: a read past its deadline: %v", c.name, err)
		}
		conn.SetReadDeadline(time.Time{})
		testPlatformHolds(t, fixture, 1, 1)
		c.end(t, fixture, conn, fixture.opener.farEnd(0))
		testPlatformReleased(t, fixture, c.name+": the ended stream's release")
		testPlatformHolds(t, fixture, 1, 0, "hold", "open", "release")
		// whatever ends it again releases nothing more
		conn.Close()
		conn.Abort()
		testPlatformHolds(t, fixture, 1, 0, "hold", "open", "release")
	}
}

// A ur/ open that fails holds nothing afterwards, whatever the edge answered, and each further ticket holds for its
// own open alone.
func TestPlatformDialReleasesServiceWhenTheOpenFails(t *testing.T) {
	rejects := []struct {
		code      protocol.StreamRejectCode
		wantErr   error
		wantHolds int
	}{
		// retry is the ticket's alone: each of the three Finds answers the same edge again
		{code: protocol.StreamRejectCode_SR_RETRY, wantErr: ErrSocketNoListener, wantHolds: 3},
		{code: protocol.StreamRejectCode_SR_QUOTA, wantErr: ErrSocketQuota, wantHolds: 3},
		{code: protocol.StreamRejectCode_SR_DENIED, wantErr: ErrSocketDenied, wantHolds: 1},
		{code: protocol.StreamRejectCode_SR_INVALID, wantErr: ErrSocketNoListener, wantHolds: 3},
	}
	for _, c := range rejects {
		fixture, _, _ := newTestPlatformDial(t, nil, newTestDialListener("smtpedge").rejecting(c.code))
		if _, err := fixture.dial("ur/smtpedge"); !errors.Is(err, c.wantErr) {
			t.Errorf("%v: %v", c.code, err)
		}
		holdCount, heldCount, events := fixture.opener.holds()
		if holdCount != c.wantHolds || heldCount != 0 {
			t.Errorf("%v: %d holds taken and %d held", c.code, holdCount, heldCount)
		}
		// no two holds overlap: every failed open released before the next ticket's hold
		for index, event := range events {
			if want := []string{"hold", "open", "release"}[index%3]; event != want {
				t.Fatalf("%v: events %v", c.code, events)
			}
		}
	}

	// an edge that never answers holds Service only until its accept timeout, and the backup's stream holds its own
	dead := newTestDialListener("dead edge")
	dead.timeout = true
	alive := newTestDialListener("live edge")
	fixture, _, _ := newTestPlatformDial(t, nil, dead, alive)
	type dialResult struct {
		conn *SocketConn
		err  error
	}
	results := make(chan dialResult, 1)
	go func() {
		conn, err := fixture.dial("ur/smtpedge")
		results <- dialResult{conn: conn, err: err}
	}()
	testSocketAwait(t, fixture.opener.waiting, "the dead edge's open")
	testPlatformHolds(t, fixture, 1, 1, "hold", "open")
	fixture.clock.advance(DefaultSidecarSocketSettings().DialAcceptTimeout)
	result := testSocketAwait(t, results, "the dial")
	if result.err != nil {
		t.Fatal(result.err)
	}
	testPlatformHolds(t, fixture, 2, 1, "hold", "open", "release", "hold", "open")
	result.conn.Close()
	fixture.opener.farEnd(0).Close()
	// the timed-out open's release came before the backup's hold; this is the backup's stream's
	testPlatformReleased(t, fixture, "the dead edge's release")
	testPlatformReleased(t, fixture, "the backup's stream's release")
	testPlatformHolds(t, fixture, 2, 0)
}

// A ur/ ticket that fails its checks is refused before any hold, a dispatcher that refuses the hold refuses the
// ticket before any open, and a dial of an application name holds nothing.
func TestPlatformDialHoldsNothingItDoesNotOpen(t *testing.T) {
	mutations := []func(ticket *protocol.SocketTicket){
		func(ticket *protocol.SocketTicket) { ticket.NetworkId = testRegistrarNetworkId.Bytes() },
		func(ticket *protocol.SocketTicket) { ticket.DialerClientId = testSocketId("someone else").Bytes() },
		func(ticket *protocol.SocketTicket) { ticket.Name = "ur/otherservice" },
	}
	for index, mutate := range mutations {
		fixture, _, _ := newTestPlatformDial(t, mutate, newTestDialListener("smtpedge"))
		if _, err := fixture.dial("ur/smtpedge"); !errors.Is(err, ErrSocketNoListener) {
			t.Errorf("ticket %d: %v", index, err)
		}
		testPlatformHolds(t, fixture, 0, 0)
	}

	fixture, _, _ := newTestPlatformDial(t, nil, newTestDialListener("smtpedge"))
	fixture.opener.holdErr = errSubprotocolClosed
	if _, err := fixture.dial("ur/smtpedge"); !errors.Is(err, ErrSocketNoListener) {
		t.Errorf("a refused hold: %v", err)
	}
	if opened := fixture.opener.openedIds(); len(opened) != 0 {
		t.Errorf("opened %v with no Service", opened)
	}

	// a sidecar's own names ride Network contracts, which a sidecar always provides
	listener := newTestDialListener("an application listener")
	application := newTestDialFixture(t, listener)
	application.service.answers = [][]*testDialListener{{listener}}
	conn, err := application.dial(testDialName)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	testPlatformHolds(t, application, 0, 0)
}

// A stream with no end to wait on would hold Service for good, so a ur/ dial refuses it: reset, released, never a
// conn.
func TestPlatformDialRefusesAStreamWithNoEnd(t *testing.T) {
	fixture, opener, _ := newTestPlatformDial(t, nil, newTestDialListener("smtpedge"))
	endless := &testEndlessOpener{testPlatformOpener: opener}
	fixture.dialer.opener = endless
	if _, err := fixture.dial("ur/smtpedge"); !errors.Is(err, ErrSocketNoListener) {
		t.Fatalf("a stream with no end dialed: %v", err)
	}
	if len(endless.streams) == 0 {
		t.Fatal("no stream opened")
	}
	for index := range endless.streams {
		var resetErr *socketStreamResetError
		if _, err := fixture.opener.farEnd(index).Read(make([]byte, 1)); !errors.As(err, &resetErr) {
			t.Errorf("stream %d: the edge's end reads %v", index, err)
		}
	}
	holdCount, heldCount, _ := fixture.opener.holds()
	if holdCount != len(endless.streams) || heldCount != 0 {
		t.Errorf("%d holds taken for %d streams, %d held", holdCount, len(endless.streams), heldCount)
	}
}

// A socketStream and no more: it cannot say when it has ended.
type testEndlessStream struct {
	socketStream
}

// An opener whose accepted streams are testEndlessStreams.
type testEndlessOpener struct {
	*testPlatformOpener
	streams []*testEndlessStream
}

func (self *testEndlessOpener) open(ctx context.Context, clientId Id, request *StreamOpenRequest) (socketStream, error) {
	stream, err := self.testPlatformOpener.open(ctx, clientId, request)
	if err != nil {
		return nil, err
	}
	endless := &testEndlessStream{socketStream: stream}
	self.streams = append(self.streams, endless)
	return endless, nil
}

// A stream accepted as its Dial ended is no one's to close: the Dial resets it and releases its hold.
func TestPlatformDialEndsAStreamAcceptedAsTheDialEnded(t *testing.T) {
	fixture, _, _ := newTestPlatformDial(t, nil, newTestDialListener("smtpedge"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// the Dial's ctx ends inside the open, which the edge accepts all the same
	fixture.opener.onOpen = cancel
	parsed, err := ParseSocketAddress("ur/smtpedge")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := fixture.dialer.dial(ctx, parsed, nil, false)
	if conn != nil || !errors.Is(err, ErrSocketUnavailable) {
		t.Fatalf("the ended dial answered %v, %v", conn, err)
	}
	var resetErr *socketStreamResetError
	if _, err := fixture.opener.farEnd(0).Read(make([]byte, 1)); !errors.As(err, &resetErr) || resetErr.Code != protocol.StreamResetCode_RST_CANCELLED {
		t.Errorf("the edge's end reads %v", err)
	}
	testPlatformReleased(t, fixture, "the reset stream's release")
	testPlatformHolds(t, fixture, 1, 0, "hold", "open", "release")
}

// CreateContract's part, and the receiving client's, for an edge's frames to a sidecar: see the file header.
//
// A refused StreamWindow is counted apart. An edge's stream sender carries its windows on a goroutine of its own, so
// the last one of a stream, acking the sidecar's final bytes, can leave after the edge's StreamClose has ended the
// stream at the sidecar and the hold with it. It is then a frame of no stream, which the sidecar would drop had it
// come (on connect it rides the stream's standing contract, or is lost with nothing waiting on it). A window refused
// while its stream lived would stall the stream, which the tests' byte exchanges and their other frames would show.
type testServiceContracts struct {
	stateLock          sync.Mutex
	issuedCount        int
	refusedCount       int
	refusedWindowCount int
	// one signal for each frame refused a contract
	refused chan struct{}
}

func newTestServiceContracts() *testServiceContracts {
	return &testServiceContracts{refused: make(chan struct{}, 1024)}
}

// The pair's delivery: an edge's frame to a sidecar goes only on a contract under the sidecar's Service key.
func (self *testServiceContracts) deliver(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
	if !from.edge || to.edge {
		// a sidecar's frames to an edge ride the edge's own Service key, which an edge always holds (§6.10.1 item 2)
		return envelope
	}
	manager := to.subprotocol.client.ContractManager()
	issued := func() bool {
		secretKey, ok := manager.GetProvideSecretKey(connectprotocol.ProvideMode_Service)
		if !ok {
			return false
		}
		storedContractBytes, err := connect.ProtoMarshal(&connectprotocol.StoredContract{
			ContractId:        connect.NewId().Bytes(),
			TransferByteCount: 1024 * 1024,
			SourceId:          from.clientId.Bytes(),
			DestinationId:     to.clientId.Bytes(),
		})
		if err != nil {
			return false
		}
		defer connect.MessagePoolReturn(storedContractBytes)
		storedContractHmac := connect.SignStoredContract(connect.DefaultContractManagerSettings(), secretKey, storedContractBytes)
		return manager.Verify(storedContractHmac, storedContractBytes, connectprotocol.ProvideMode_Service)
	}()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !issued {
		if protocol.MessageType(envelope.Type) == protocol.MessageType_STREAM_WINDOW {
			self.refusedWindowCount += 1
			return nil
		}
		self.refusedCount += 1
		self.refused <- struct{}{}
		return nil
	}
	self.issuedCount += 1
	return envelope
}

// How many of the edge's frames got a contract, and how many were refused one.
func (self *testServiceContracts) counts() (issuedCount int, refusedCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.issuedCount, self.refusedCount
}

// The dispatcher's opener, signalling each Service hold released.
type testServiceOpener struct {
	*subprotocolSocketOpener
	released chan struct{}
}

func (self *testServiceOpener) holdService() (func(), error) {
	release, err := self.subprotocolSocketOpener.holdService()
	if err != nil {
		return nil, err
	}
	return func() {
		release()
		self.released <- struct{}{}
	}, nil
}

// A sidecar's real dispatcher dialing ur/smtpedge at an edge's, under testServiceContracts.
type testServiceDial struct {
	pair      *testRpcPair
	sidecar   *testRpcSide
	edge      *testRpcSide
	contracts *testServiceContracts
	fixture   *testDialFixture
	opener    *testServiceOpener
	// the edge's ur/smtpedge listener's opens
	incomings chan *StreamIncoming
}

func newTestServiceDial(t *testing.T) *testServiceDial {
	t.Helper()
	pair := newTestRpcPair(t)
	contracts := newTestServiceContracts()
	pair.deliver = contracts.deliver
	sidecarSide := pair.add(nil, nil)
	edge := pair.addEdge(nil)
	listener := newTestDialListener("smtpedge")
	listener.clientId = Id(edge.clientId)
	fixture, _, _ := newTestPlatformDial(t, nil, listener)
	// the tickets name the sidecar's client as their dialer, and the opens go through its dispatcher
	fixture.clientId = Id(sidecarSide.clientId)
	fixture.dialer.clientId = Id(sidecarSide.clientId)
	opener := &testServiceOpener{
		subprotocolSocketOpener: &subprotocolSocketOpener{subprotocol: sidecarSide.subprotocol},
		released:                make(chan struct{}, 1024),
	}
	fixture.dialer.opener = opener
	return &testServiceDial{
		pair:      pair,
		sidecar:   sidecarSide,
		edge:      edge,
		contracts: contracts,
		fixture:   fixture,
		opener:    opener,
		incomings: testStreamAccepting(t, edge, "ur/smtpedge"),
	}
}

// Waits for one ended stream's Service hold to be released.
func (self *testServiceDial) awaitReleased(t *testing.T, what string) {
	t.Helper()
	testAwait(t, self.opener.released, what)
}

// Whether the sidecar's client provides Service now: the mode and its key.
func (self *testServiceDial) providesService() bool {
	manager := self.sidecar.subprotocol.client.ContractManager()
	_, hasKey := manager.GetProvideSecretKey(connectprotocol.ProvideMode_Service)
	return hasKey && manager.GetProvideModes()[connectprotocol.ProvideMode_Service]
}

// How many holds the sidecar's dispatcher counts on Service.
func (self *testServiceDial) serviceHoldCount() int {
	provideModes := &self.sidecar.subprotocol.provideModes
	provideModes.stateLock.Lock()
	defer provideModes.stateLock.Unlock()
	return provideModes.heldModeCounts[connectprotocol.ProvideMode_Service]
}

// One ur/smtpedge stream: the sidecar's conn and the edge's end of it.
func (self *testServiceDial) dial(t *testing.T) (*SocketConn, *SubprotocolStream) {
	t.Helper()
	conn, err := self.fixture.dial("ur/smtpedge")
	if err != nil {
		t.Fatal(err)
	}
	incoming := testAwait(t, self.incomings, "the edge's accept")
	if !incoming.Edge || incoming.SourceId != Id(self.sidecar.clientId) {
		t.Fatalf("the edge's incoming %+v", incoming)
	}
	return conn, incoming.Stream
}

// §14's exchange in small: the sidecar's preamble to the edge and the edge's result back, each read whole.
func (self *testServiceDial) exchange(t *testing.T, conn *SocketConn, edgeStream *SubprotocolStream) {
	t.Helper()
	if _, err := conn.Write([]byte("smtp preamble")); err != nil {
		t.Fatal(err)
	}
	if got := testStreamReadFull(t, edgeStream, 13); string(got) != "smtp preamble" {
		t.Errorf("the edge read %q", got)
	}
	if _, err := edgeStream.Write([]byte("smtp outcome")); err != nil {
		t.Fatal(err)
	}
	outcome := make([]byte, 12)
	if _, err := io.ReadFull(conn, outcome); err != nil || string(outcome) != "smtp outcome" {
		t.Errorf("the sidecar read %q, %v", outcome, err)
	}
}

// A sidecar with no tls/ or smtp/ registration opens a ur/ stream to smtpedge, and the edge's replies come under
// contracts signed with its Service key, which it holds for the stream alone: the stream completes, and Service goes
// when it ends. The twin opens the same stream with no hold, as the dialer did before QD-849: the edge accepts, its
// StreamAccept gets no contract, and the open never completes.
func TestPlatformDialStreamCompletesUnderItsServiceKey(t *testing.T) {
	world := newTestServiceDial(t)
	if world.providesService() {
		t.Fatal("a sidecar with no registration provides Service")
	}

	// the twin: no hold, so the edge's reply has no key to be signed with
	twinCtx, twinCancel := context.WithCancel(t.Context())
	twinErr := make(chan error, 1)
	go func() {
		_, err := world.sidecar.subprotocol.OpenStream(twinCtx, Id(world.edge.clientId), &StreamOpenRequest{Target: "ur/smtpedge", Edge: true})
		twinErr <- err
	}()
	twinIncoming := testAwait(t, world.incomings, "the edge's accept of the twin")
	testAwait(t, world.contracts.refused, "the refused reply contract")
	twinCancel()
	if err := testAwait(t, twinErr, "the twin's open"); err == nil {
		t.Fatal("a ur/ stream opened with no Service key for the edge's replies")
	}
	// the opener's reset reaches the edge on the sidecar's stream sender, and ends the edge's half of the twin
	var twinResetErr *StreamResetError
	if _, err := twinIncoming.Stream.Read(make([]byte, 1)); !errors.As(err, &twinResetErr) {
		t.Fatalf("the edge's end of the twin reads %v", err)
	}
	if issuedCount, _ := world.contracts.counts(); issuedCount != 0 {
		t.Fatalf("%d reply contracts issued with no Service key", issuedCount)
	}
	_, refusedBefore := world.contracts.counts()

	conn, edgeStream := world.dial(t)
	if !world.providesService() || world.serviceHoldCount() != 1 {
		t.Errorf("the open stream holds Service %d times, provided %t", world.serviceHoldCount(), world.providesService())
	}
	world.exchange(t, conn, edgeStream)
	issuedCount, refusedCount := world.contracts.counts()
	if issuedCount == 0 || refusedCount != refusedBefore {
		t.Errorf("%d reply contracts issued and %d refused on the held stream", issuedCount, refusedCount-refusedBefore)
	}
	// the stream completes: each side's close reaches the other
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := edgeStream.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("the edge read %v", err)
	}
	if err := edgeStream.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("the sidecar read %v", err)
	}
	// both directions closed: the last ur/ stream ended, and Service with it
	world.awaitReleased(t, "the ended stream's release")
	if world.providesService() || world.serviceHoldCount() != 0 {
		t.Errorf("the ended stream holds Service %d times, provided %t", world.serviceHoldCount(), world.providesService())
	}
	conn.Close()
	if _, refusedCount := world.contracts.counts(); refusedCount != refusedBefore {
		t.Errorf("%d of the edge's frames refused a contract on the held stream", refusedCount-refusedBefore)
	}
	testStreamsSettled(t, world.sidecar)
	testStreamsSettled(t, world.edge)
}

// The sidecar's Close does not end its ur/ stream: the edge's last bytes and its own StreamClose come after it, each
// under the Service key the stream still holds, and the hold goes once the edge's close has arrived.
func TestPlatformDialKeepsServiceForTheEdgesClose(t *testing.T) {
	world := newTestServiceDial(t)
	conn, edgeStream := world.dial(t)
	world.exchange(t, conn, edgeStream)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if !world.providesService() || world.serviceHoldCount() != 1 {
		t.Errorf("after the sidecar's Close: Service held %d times, provided %t", world.serviceHoldCount(), world.providesService())
	}
	issuedBefore, _ := world.contracts.counts()
	if _, err := edgeStream.Write([]byte("a late outcome")); err != nil {
		t.Fatal(err)
	}
	if err := edgeStream.Close(); err != nil {
		t.Fatal(err)
	}
	world.awaitReleased(t, "the ended stream's release")
	issuedCount, refusedCount := world.contracts.counts()
	if issuedCount <= issuedBefore || refusedCount != 0 {
		t.Errorf("the edge's frames after the sidecar's Close: %d got a contract, %d were refused one", issuedCount-issuedBefore, refusedCount)
	}
	if world.providesService() || world.serviceHoldCount() != 0 {
		t.Errorf("the ended stream holds Service %d times, provided %t", world.serviceHoldCount(), world.providesService())
	}
	testStreamsSettled(t, world.sidecar)
	testStreamsSettled(t, world.edge)
}

// A dispatcher that closes ends its streams, and each ended stream's wait with it: no hold's goroutine outlives it.
func TestPlatformDialReleasesWhenItsDispatcherCloses(t *testing.T) {
	world := newTestServiceDial(t)
	conn, edgeStream := world.dial(t)
	defer edgeStream.Close()
	world.sidecar.subprotocol.Close()
	world.awaitReleased(t, "the closed dispatcher's stream's release")
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, ErrSocketReset) {
		t.Errorf("a closed dispatcher's conn reads %v", err)
	}
	// a closed dispatcher holds nothing more, so its next ur/ ticket is refused before any open
	if _, err := world.fixture.dial("ur/smtpedge"); !errors.Is(err, ErrSocketNoListener) {
		t.Errorf("a dial on a closed dispatcher: %v", err)
	}
}

// A send transport for ControlId alone, as sidecartest's Net gives a client: what the client sends the platform.
type testControlTransport struct {
	transportId connect.Id
}

func (self *testControlTransport) TransportId() connect.Id {
	return self.transportId
}

func (self *testControlTransport) Priority() int {
	return connect.TransportMaxPriority
}

func (self *testControlTransport) Weight() float32 {
	return 0
}

func (self *testControlTransport) CanEvalRouteWeight(stats *connect.RouteStats, remainingStats map[connect.Transport]*connect.RouteStats) bool {
	return true
}

func (self *testControlTransport) RouteWeight(stats *connect.RouteStats, remainingStats map[connect.Transport]*connect.RouteStats) float32 {
	return 1
}

func (self *testControlTransport) MatchesSend(destination connect.TransferPath) bool {
	return destination.DestinationId == connect.ControlId
}

func (self *testControlTransport) MatchesReceive(destination connect.TransferPath) bool {
	return false
}

func (self *testControlTransport) Downgrade(source connect.TransferPath) {
}

// Taps what client sends the platform and answers each provide frame once, as whether it names Service: a resend
// carries its first send's message id and is not counted again. Nothing acks, as with a platform that is slow.
func testTapProvides(t *testing.T, client *connect.Client) chan bool {
	t.Helper()
	route := make(connect.Route)
	client.RouteManager().UpdateTransport(&testControlTransport{transportId: connect.NewId()}, []connect.Route{route})
	provides := make(chan bool, 1024)
	ctx := t.Context()
	done := make(chan struct{})
	t.Cleanup(func() {
		// the client is cancelled first, so nothing sends on the route once the tap is gone
		client.Cancel()
		<-done
	})
	go func() {
		defer close(done)
		seenMessageIds := map[connect.Id]bool{}
		for {
			var frameBytes []byte
			select {
			case <-ctx.Done():
				return
			case <-client.Done():
				return
			case frameBytes = <-route:
			}
			transferFrame := &connectprotocol.TransferFrame{}
			err := proto.Unmarshal(frameBytes, transferFrame)
			connect.MessagePoolReturn(frameBytes)
			if err != nil || transferFrame.Pack == nil {
				continue
			}
			messageId, err := connect.IdFromBytes(transferFrame.Pack.MessageId)
			if err != nil || seenMessageIds[messageId] {
				continue
			}
			seenMessageIds[messageId] = true
			for _, frame := range transferFrame.Pack.Frames {
				if frame.MessageType != connectprotocol.MessageType_TransferProvide {
					continue
				}
				provide := &connectprotocol.Provide{}
				if err := proto.Unmarshal(frame.MessageBytes, provide); err != nil {
					continue
				}
				provides <- slices.ContainsFunc(provide.Keys, func(key *connectprotocol.ProvideKey) bool {
					return key.Mode == connectprotocol.ProvideMode_Service
				})
			}
		}
	}()
	return provides
}

// Overlapping ur/ streams share one hold: the client sends the platform one provide frame at the first hold, naming
// Service, and one at the last release, naming it no more, and nothing between.
func TestPlatformDialOverlappingStreamsShareOneProvideFrame(t *testing.T) {
	world := newTestServiceDial(t)
	provides := testTapProvides(t, world.sidecar.subprotocol.client)

	first, firstEdgeStream := world.dial(t)
	if !testAwait(t, provides, "the first hold's provide frame") {
		t.Fatal("the first hold's provide frame names no Service")
	}
	second, secondEdgeStream := world.dial(t)
	if world.serviceHoldCount() != 2 || !world.providesService() {
		t.Errorf("two streams hold Service %d times, provided %t", world.serviceHoldCount(), world.providesService())
	}
	world.exchange(t, first, firstEdgeStream)
	world.exchange(t, second, secondEdgeStream)

	// the first to end leaves the other its Service
	first.Close()
	firstEdgeStream.Close()
	world.awaitReleased(t, "the first stream's release")
	if world.serviceHoldCount() != 1 || !world.providesService() {
		t.Errorf("one stream of two ended: Service held %d times, provided %t", world.serviceHoldCount(), world.providesService())
	}
	world.exchange(t, second, secondEdgeStream)

	second.Close()
	secondEdgeStream.Close()
	world.awaitReleased(t, "the second stream's release")
	if world.serviceHoldCount() != 0 || world.providesService() {
		t.Errorf("both streams ended: Service held %d times, provided %t", world.serviceHoldCount(), world.providesService())
	}
	// the client's sends to the platform are in order, so a frame the second hold or the first release had sent
	// would be read here, ahead of the last release's
	if testAwait(t, provides, "the last release's provide frame") {
		t.Fatal("a second provide frame names Service: a hold or a release between the first and the last sent one")
	}
	select {
	case named := <-provides:
		t.Errorf("a third provide frame, naming Service %t", named)
	default:
	}
	if _, refusedCount := world.contracts.counts(); refusedCount != 0 {
		t.Errorf("%d of the edge's frames refused a contract", refusedCount)
	}
}

// A sidecar holding smtp/ keeps Service after its ur/ stream ends, and a ur/ stream keeps it after the smtp/ lease
// goes: the dispatcher counts both holds, and Service goes only when both have ended.
func TestPlatformDialSharesServiceWithAnSmtpListener(t *testing.T) {
	for _, listenerEndsFirst := range []bool{false, true} {
		world := newTestServiceDial(t)
		// the listener's component on the sidecar's own dispatcher, as one generation carries both
		listen := newTestListenFixture(t)
		listen.generation.subprotocol = world.sidecar.subprotocol
		listener := listen.listen(t, "smtp/25/mx", nil)
		if world.serviceHoldCount() != 1 || !world.providesService() {
			t.Fatalf("an smtp/ lease holds Service %d times, provided %t", world.serviceHoldCount(), world.providesService())
		}
		conn, edgeStream := world.dial(t)
		if world.serviceHoldCount() != 2 {
			t.Errorf("an smtp/ lease and a ur/ stream hold Service %d times", world.serviceHoldCount())
		}
		world.exchange(t, conn, edgeStream)

		endStream := func() {
			conn.Close()
			edgeStream.Close()
			world.awaitReleased(t, "the ur/ stream's release")
		}
		ends := []func(){endStream, func() { listener.Close() }}
		if listenerEndsFirst {
			slices.Reverse(ends)
		}
		ends[0]()
		if world.serviceHoldCount() != 1 || !world.providesService() {
			t.Errorf("listener first %t: one of the two ended, and Service is held %d times, provided %t", listenerEndsFirst, world.serviceHoldCount(), world.providesService())
		}
		if listenerEndsFirst {
			// the stream outlives the lease on its own hold
			world.exchange(t, conn, edgeStream)
		}
		ends[1]()
		if world.serviceHoldCount() != 0 || world.providesService() {
			t.Errorf("listener first %t: both ended, and Service is held %d times, provided %t", listenerEndsFirst, world.serviceHoldCount(), world.providesService())
		}
		if _, refusedCount := world.contracts.counts(); refusedCount != 0 {
			t.Errorf("listener first %t: %d of the edge's frames refused a contract", listenerEndsFirst, refusedCount)
		}
	}
}

// The hold admits nothing new from a Service source. While a ur/ stream holds Service, an edge's request reaches no
// handler, its Hello nothing, and its StreamOpen only a listener the sidecar has: one to a name it does not listen
// on is rejected, the ur/ name it dialed included.
func TestPlatformDialHoldAdmitsNothingNewFromAService(t *testing.T) {
	world := newTestServiceDial(t)
	runs := make(chan struct{}, 16)
	if _, err := world.sidecar.subprotocol.Handle(testCallType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		runs <- struct{}{}
		return nil, nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	conn, edgeStream := world.dial(t)
	defer conn.Close()
	defer edgeStream.Close()
	if !world.providesService() {
		t.Fatal("the open stream holds no Service")
	}
	sidecarId := world.sidecar.clientId

	// an edge's request and an edge's Hello, each carried on a contract under the held key: dropped at the mode check
	for _, messageType := range []protocol.MessageType{testCallType, protocol.MessageType_HELLO, protocol.MessageType_HEAD_CHECK, protocol.MessageType_SEARCH} {
		droppedBefore := world.sidecar.subprotocol.Stats().ProvideModeDroppedCount
		issuedBefore, _ := world.contracts.counts()
		envelope := &protocol.Envelope{Version: WireVersionMajor, Type: uint32(messageType), RequestId: 7, Body: []byte("an edge asks")}
		if sent, err := world.edge.send(sidecarId, envelope, nil, 0); !sent || err != nil {
			t.Fatalf("%v: %t, %v", messageType, sent, err)
		}
		// the frame went under the held key, as the stream's own frames beside it may have
		if issuedCount, _ := world.contracts.counts(); issuedCount <= issuedBefore {
			t.Errorf("%v: the edge's frame got no contract", messageType)
		}
		if dropped := world.sidecar.subprotocol.Stats().ProvideModeDroppedCount; dropped != droppedBefore+1 {
			t.Errorf("%v from a Service source: %d dropped, before %d", messageType, dropped, droppedBefore)
		}
	}
	select {
	case <-runs:
		t.Error("a handler ran for an edge's request")
	default:
	}
	if _, ok := world.sidecar.subprotocol.PeerIdentity(Id(world.edge.clientId)); ok {
		t.Error("the sidecar holds an identity for an edge")
	}

	// an edge's open reaches only a listener the sidecar has: it has none on these
	for _, target := range []string{"ur/smtpedge", "abcdefghij:smtp/25/mx", "abcdefghij:db/primary"} {
		_, err := world.edge.subprotocol.OpenStream(t.Context(), Id(sidecarId), &StreamOpenRequest{Target: target, Ticket: []byte("an edge ticket")})
		var rejectErr *StreamRejectError
		if !errors.As(err, &rejectErr) {
			t.Errorf("an edge's open of %s: %v", target, err)
		}
	}
	// and the held stream still runs
	world.exchange(t, conn, edgeStream)
}
