//go:build !sidecar_http && !js

// §6.7's streams over two dispatchers (PROTO-M5-02): the open and its answers, early data and the data
// behind it before the accept, a long PQ ClientHello among them, the reject codes one to one with §9's,
// half-close each way, the identity rules (no stream before a verified Hello, a key change resetting with
// IDENTITY), an edge's open with no Hello, an edge's credit growing with its streams, and Close joining
// with bytes held. A pair delivers each side's sends to the other's inline handler as connect would.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
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

// The target the tests listen on.
const testStreamTarget = "examplenet:ur/agent"

// Two sidecars of one network, their Hello not yet run.
func newTestStreamSides(t *testing.T, adjust func(settings *SidecarProtocolSettings)) (*testRpcPair, *testRpcSide, *testRpcSide) {
	t.Helper()
	pair := newTestRpcPair(t)
	return pair, pair.add(nil, adjust), pair.add(nil, adjust)
}

// Listens on target at side, accepting each open and handing it on.
func testStreamAccepting(t *testing.T, side *testRpcSide, target string) chan *StreamIncoming {
	t.Helper()
	incomings := make(chan *StreamIncoming, 16)
	if _, err := side.subprotocol.Listen(target, func(ctx context.Context, incoming *StreamIncoming) error {
		incomings <- incoming
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return incomings
}

// Opens a stream from opener to acceptor, which a test listens on, and answers both ends.
func testStreamOpen(t *testing.T, opener *testRpcSide, acceptor *testRpcSide, incomings chan *StreamIncoming, request *StreamOpenRequest) (*SubprotocolStream, *SubprotocolStream) {
	t.Helper()
	if request == nil {
		request = &StreamOpenRequest{Target: testStreamTarget}
	}
	stream, err := opener.subprotocol.OpenStream(t.Context(), Id(acceptor.clientId), request)
	if err != nil {
		t.Fatal(err)
	}
	incoming := testAwait(t, incomings, "the accept")
	return stream, incoming.Stream
}

// Reads exactly n bytes from stream.
func testStreamReadFull(t *testing.T, stream *SubprotocolStream, n int) []byte {
	t.Helper()
	data := make([]byte, n)
	if _, err := io.ReadFull(stream, data); err != nil {
		t.Fatalf("read %d B: %v", n, err)
	}
	return data
}

// The types of what side sent, in order.
func testSentTypes(side *testRpcSide) []protocol.MessageType {
	types := []protocol.MessageType{}
	for _, envelope := range side.sent() {
		types = append(types, protocol.MessageType(envelope.Type))
	}
	return types
}

// Every stream with a peer gone from side's table and its credit back: what a finished or ended stream
// leaves. The table's empty peers stay, holding their ids.
func testStreamsSettled(t *testing.T, side *testRpcSide) {
	t.Helper()
	streams := &side.subprotocol.streams
	streams.stateLock.Lock()
	defer streams.stateLock.Unlock()
	for peerId, peer := range streams.peers {
		if len(peer.streams) != 0 || peer.pendingAcceptCount != 0 || peer.credit.committed() != 0 {
			t.Errorf("peer %s: %d streams, %d pending, %d B committed", peerId, len(peer.streams), peer.pendingAcceptCount, peer.credit.committed())
		}
	}
	if usage := side.subprotocol.budget.currentUsage(); usage.creditByteCount != 0 {
		t.Errorf("the budget holds %d B of credit", usage.creditByteCount)
	}
}

// The open's whole path: Hello first, the acceptor told the target, metadata, ticket and the peer's
// verified identity, early data read first, then bytes both ways; both Closes finish the stream and give
// every byte of credit back.
func TestStreamOpenAcceptAndTalk(t *testing.T) {
	_, a, b := newTestStreamSides(t, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	request := &StreamOpenRequest{
		Target:    testStreamTarget,
		Metadata:  []byte("open metadata"),
		Ticket:    []byte("a ticket"),
		EarlyData: []byte("hello"),
	}
	opened, err := b.subprotocol.OpenStream(t.Context(), Id(a.clientId), request)
	if err != nil {
		t.Fatal(err)
	}
	incoming := testAwait(t, incomings, "the accept")
	if incoming.Edge || incoming.Peer == nil || incoming.Peer.SidecarId != b.sidecarId || incoming.SourceId != Id(b.clientId) ||
		incoming.Target != testStreamTarget || !bytes.Equal(incoming.Metadata, request.Metadata) || !bytes.Equal(incoming.Ticket, request.Ticket) {
		t.Errorf("incoming %+v", incoming)
	}
	accepted := incoming.Stream
	if peer, ok := accepted.Peer(); !ok || peer.SidecarId != b.sidecarId {
		t.Errorf("the accepted stream's peer: %v %t", peer, ok)
	}
	if types := testSentTypes(b); !slices.Contains(types, protocol.MessageType_HELLO) ||
		slices.Index(types, protocol.MessageType_HELLO) > slices.Index(types, protocol.MessageType_STREAM_OPEN) {
		t.Errorf("no Hello before the open: %v", types)
	}
	if got := testStreamReadFull(t, accepted, 5); string(got) != "hello" {
		t.Errorf("early data %q", got)
	}
	if _, err := opened.Write([]byte(" there")); err != nil {
		t.Fatal(err)
	}
	if got := testStreamReadFull(t, accepted, 6); string(got) != " there" {
		t.Errorf("data %q", got)
	}
	if _, err := accepted.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	if got := testStreamReadFull(t, opened, 5); string(got) != "world" {
		t.Errorf("reply %q", got)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := accepted.Read(make([]byte, 8)); n != 0 || err != io.EOF {
		t.Errorf("after the opener's close: %d %v", n, err)
	}
	if err := accepted.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.Read(make([]byte, 8)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a read after Close: %v", err)
	}
	if err := opened.Close(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a second Close: %v", err)
	}
	testStreamsSettled(t, a)
	testStreamsSettled(t, b)
	if stats := b.subprotocol.StreamStats(); stats.OpenedCount != 1 {
		t.Errorf("opener stats %+v", stats)
	}
	if stats := a.subprotocol.StreamStats(); stats.AcceptedCount != 1 {
		t.Errorf("acceptor stats %+v", stats)
	}
}

// Early data, then StreamData behind it before any answer: a 3,000 B ClientHello, as a PQ key share makes
// one, goes as StreamOpen's 2,048 B and one StreamData of the rest, in one flight; the accept function
// reads nothing before it answers (FI-11), and the acceptor then reads all of it in order.
func TestStreamEarlyDataThenDataBeforeAccept(t *testing.T) {
	_, a, b := newTestStreamSides(t, nil)
	if err := b.subprotocol.EnsureHello(t.Context(), Id(a.clientId)); err != nil {
		t.Fatal(err)
	}
	clientHello := make([]byte, 3000)
	rand.Read(clientHello)
	answer := make(chan struct{})
	readBeforeAccept := make(chan error, 1)
	incomings := make(chan *StreamIncoming, 1)
	if _, err := a.subprotocol.Listen(testStreamTarget, func(ctx context.Context, incoming *StreamIncoming) error {
		// no byte reaches a reader before the accept: a read at a deadline already passed times out
		incoming.Stream.SetReadDeadline(a.clock.Now())
		_, err := incoming.Stream.Read(make([]byte, 16))
		incoming.Stream.SetReadDeadline(time.Time{})
		readBeforeAccept <- err
		incomings <- incoming
		<-answer
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	opened := make(chan *SubprotocolStream, 1)
	go func() {
		stream, err := b.subprotocol.OpenStream(t.Context(), Id(a.clientId), &StreamOpenRequest{Target: testStreamTarget, EarlyData: clientHello})
		if err != nil {
			t.Error(err)
		}
		opened <- stream
	}()
	if err := testAwait(t, readBeforeAccept, "the read before the accept"); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("a read before the accept: %v", err)
	}
	incoming := testAwait(t, incomings, "the open")
	// the open and the rest of the ClientHello both went before any answer
	sent := testAwaitSent(t, b, func(sent []*protocol.Envelope) bool {
		return testFirstSent(sent, protocol.MessageType_STREAM_DATA) != nil
	})
	openIndex := slices.IndexFunc(sent, func(envelope *protocol.Envelope) bool {
		return envelope.Type == uint32(protocol.MessageType_STREAM_OPEN)
	})
	dataIndex := slices.IndexFunc(sent, func(envelope *protocol.Envelope) bool {
		return envelope.Type == uint32(protocol.MessageType_STREAM_DATA)
	})
	if openIndex < 0 || dataIndex < openIndex {
		t.Fatalf("sent %v", testSentTypes(b))
	}
	open := &protocol.StreamOpen{}
	data := &protocol.StreamData{}
	if proto.Unmarshal(sent[openIndex].Body, open) != nil || proto.Unmarshal(sent[dataIndex].Body, data) != nil {
		t.Fatal("frames do not decode")
	}
	if !bytes.Equal(open.EarlyData, clientHello[:MaxStreamEarlyDataByteCount]) || data.Offset != MaxStreamEarlyDataByteCount ||
		!bytes.Equal(data.Data, clientHello[MaxStreamEarlyDataByteCount:]) {
		t.Errorf("early data %d B, then %d B at %d", len(open.EarlyData), len(data.Data), data.Offset)
	}
	if slices.Contains(testSentTypes(a), protocol.MessageType_STREAM_ACCEPT) {
		t.Errorf("accepted before the function answered")
	}
	close(answer)
	stream := testAwait(t, opened, "the open's answer")
	if got := testStreamReadFull(t, incoming.Stream, len(clientHello)); !bytes.Equal(got, clientHello) {
		t.Errorf("the ClientHello read back differs")
	}
	stream.Close()
	incoming.Stream.Close()
}

// Early data past the acceptor's initial window, and a StreamOpen past §6.5's budget, are refused here
// before anything is sent.
func TestStreamOpenRefusedPastItsBudget(t *testing.T) {
	_, a, b := newTestStreamSides(t, nil)
	testStreamAccepting(t, a, testStreamTarget)
	for _, request := range []*StreamOpenRequest{
		{Target: testStreamTarget, EarlyData: make([]byte, 16*1024+1)},
		{Target: string(make([]byte, DefaultSidecarProtocolSettings().StreamTargetMaxByteCount+1))},
		{Target: testStreamTarget, Metadata: make([]byte, DefaultSidecarProtocolSettings().StreamMetadataMaxByteCount+1)},
		{Target: testStreamTarget, Ticket: make([]byte, DefaultSidecarProtocolSettings().StreamTicketMaxByteCount+1)},
	} {
		if _, err := b.subprotocol.OpenStream(t.Context(), Id(a.clientId), request); err == nil {
			t.Errorf("an open past its budget went: %d B early", len(request.EarlyData))
		} else if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_INVALID_ARGUMENT {
			t.Errorf("refused %v", err)
		}
	}
	if slices.Contains(testSentTypes(b), protocol.MessageType_STREAM_OPEN) {
		t.Errorf("a refused open was sent")
	}
	testStreamsSettled(t, b)
	// every field at its most fits the 3,800 B budget and goes
	full := &StreamOpenRequest{
		Target:    string(bytes.Repeat([]byte{'t'}, DefaultSidecarProtocolSettings().StreamTargetMaxByteCount)),
		Metadata:  make([]byte, DefaultSidecarProtocolSettings().StreamMetadataMaxByteCount),
		Ticket:    make([]byte, DefaultSidecarProtocolSettings().StreamTicketMaxByteCount),
		EarlyData: make([]byte, MaxStreamEarlyDataByteCount),
	}
	incomings := testStreamAccepting(t, a, full.Target)
	stream, accepted := testStreamOpen(t, b, a, incomings, full)
	for _, envelope := range b.sent() {
		if envelope.Type == uint32(protocol.MessageType_STREAM_OPEN) && (DefaultSidecarProtocolSettings().StreamOpenMaxByteCount < len(envelope.Body) || MaxEnvelopeByteCount < proto.Size(envelope)) {
			t.Errorf("an open of %d B in an envelope of %d B", len(envelope.Body), proto.Size(envelope))
		}
	}
	stream.Close()
	accepted.Close()
}

// §6.7's reject codes are §9.6's ticket codes, one to one: whatever an accept function refuses with
// reaches the opener as that code with its wait, a zero code as INVALID and an error of any other kind as
// RETRY; the data held before the answer is discarded and its credit given back.
func TestStreamRejectCodesOneToOneWithSockets(t *testing.T) {
	_, a, b := newTestStreamSides(t, nil)
	refusals := make(chan error, 1)
	if _, err := a.subprotocol.Listen(testStreamTarget, func(ctx context.Context, incoming *StreamIncoming) error {
		return <-refusals
	}); err != nil {
		t.Fatal(err)
	}
	// §9.6's numbers: retry 1, busy 2, denied 3, invalid 4, quota 5
	for number, code := range map[uint32]protocol.StreamRejectCode{
		1: protocol.StreamRejectCode_SR_RETRY, 2: protocol.StreamRejectCode_SR_BUSY, 3: protocol.StreamRejectCode_SR_DENIED,
		4: protocol.StreamRejectCode_SR_INVALID, 5: protocol.StreamRejectCode_SR_QUOTA,
	} {
		if uint32(code) != number {
			t.Errorf("%s is %d, §9.6 says %d", code, code, number)
		}
	}
	cases := []struct {
		refusal error
		want    protocol.StreamRejectCode
		wait    time.Duration
	}{
		{refusal: &StreamRejectError{Code: protocol.StreamRejectCode_SR_RETRY, RetryAfter: 1500 * time.Millisecond}, want: protocol.StreamRejectCode_SR_RETRY, wait: 1500 * time.Millisecond},
		{refusal: &StreamRejectError{Code: protocol.StreamRejectCode_SR_BUSY}, want: protocol.StreamRejectCode_SR_BUSY},
		{refusal: &StreamRejectError{Code: protocol.StreamRejectCode_SR_DENIED}, want: protocol.StreamRejectCode_SR_DENIED},
		{refusal: &StreamRejectError{Code: protocol.StreamRejectCode_SR_INVALID}, want: protocol.StreamRejectCode_SR_INVALID},
		{refusal: &StreamRejectError{Code: protocol.StreamRejectCode_SR_QUOTA, RetryAfter: 30 * time.Second}, want: protocol.StreamRejectCode_SR_QUOTA, wait: 30 * time.Second},
		{refusal: &StreamRejectError{}, want: protocol.StreamRejectCode_SR_INVALID},
		{refusal: errors.New("a fetch failed"), want: protocol.StreamRejectCode_SR_RETRY},
	}
	for _, c := range cases {
		refusals <- c.refusal
		_, err := b.subprotocol.OpenStream(t.Context(), Id(a.clientId), &StreamOpenRequest{Target: testStreamTarget, EarlyData: []byte("discarded")})
		var rejectErr *StreamRejectError
		if !errors.As(err, &rejectErr) || rejectErr.Code != c.want || rejectErr.RetryAfter != c.wait || rejectErr.Local {
			t.Errorf("%v: answered %v", c.refusal, err)
		}
	}
	testStreamsSettled(t, a)
	testStreamsSettled(t, b)
	if stats := a.subprotocol.StreamStats(); stats.RejectedCount != uint64(len(cases)) {
		t.Errorf("rejected %d", stats.RejectedCount)
	}
	// a target nobody listens on is RETRY, as a ticket that raced an unlisten is (§9.6)
	_, err := b.subprotocol.OpenStream(t.Context(), Id(a.clientId), &StreamOpenRequest{Target: "examplenet:ur/nobody"})
	var rejectErr *StreamRejectError
	if !errors.As(err, &rejectErr) || rejectErr.Code != protocol.StreamRejectCode_SR_RETRY {
		t.Errorf("no listener: %v", err)
	}
}

// Half-close each way: the opener's CloseWrite reads as io.EOF after its bytes while the acceptor writes
// on, then the acceptor's does the same the other way, and the stream finishes on both ends with its
// credit back.
func TestStreamHalfCloseEachWay(t *testing.T) {
	_, a, b := newTestStreamSides(t, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	opened, accepted := testStreamOpen(t, b, a, incomings, nil)
	if _, err := opened.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := opened.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.Write([]byte("more")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a write after CloseWrite: %v", err)
	}
	all, err := io.ReadAll(accepted)
	if err != nil || string(all) != "request" {
		t.Fatalf("read %q %v", all, err)
	}
	if _, err := accepted.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := accepted.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	all, err = io.ReadAll(opened)
	if err != nil || string(all) != "response" {
		t.Fatalf("read back %q %v", all, err)
	}
	for _, stream := range []*SubprotocolStream{opened, accepted} {
		if n, err := stream.Read(make([]byte, 4)); n != 0 || err != io.EOF {
			t.Errorf("a finished stream reads %d %v", n, err)
		}
	}
	testStreamsSettled(t, a)
	testStreamsSettled(t, b)
}

// No stream before a verified Hello (D-PROTO-13): a sidecar's StreamOpen with no Hello standing is
// rejected INVALID and reaches no accept function; the same open after a Hello is accepted.
func TestStreamSidecarOpenWithNoHelloRefused(t *testing.T) {
	_, a, b := newTestStreamSides(t, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	body, err := proto.Marshal(&protocol.StreamOpen{Target: testStreamTarget, Window: 64 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	streamId := uint64(2)
	if 0 < b.clientId.Cmp(a.clientId) {
		streamId = 1
	}
	open := &protocol.Envelope{Version: WireVersionMajor, Type: uint32(protocol.MessageType_STREAM_OPEN), Flags: EnvelopeFlagNoReply, StreamId: streamId, Body: body}
	a.subprotocol.receive(connect.SourceId(b.clientId), open, b.peerTo(a))
	sent := testFirstSent(testAwaitSent(t, a, func(sent []*protocol.Envelope) bool {
		return testFirstSent(sent, protocol.MessageType_STREAM_REJECT) != nil
	}), protocol.MessageType_STREAM_REJECT)
	reject := &protocol.StreamReject{}
	if err := proto.Unmarshal(sent.Body, reject); err != nil || reject.Code != uint32(protocol.StreamRejectCode_SR_INVALID) || sent.StreamId != streamId {
		t.Errorf("answered %v %v", reject, err)
	}
	select {
	case incoming := <-incomings:
		t.Fatalf("an open with no Hello reached the function: %+v", incoming)
	default:
	}
	// its twin, after a Hello, opens
	stream, accepted := testStreamOpen(t, b, a, incomings, nil)
	stream.Close()
	accepted.Close()
}

// Waits until what side has sent satisfies done, failing past 10 s of real time.
func testAwaitSent(t *testing.T, side *testRpcSide, done func(sent []*protocol.Envelope) bool) []*protocol.Envelope {
	t.Helper()
	guard := time.After(10 * time.Second)
	for {
		_, changed := side.sentCount.Get()
		if sent := side.sent(); done(sent) {
			return sent
		}
		select {
		case <-changed:
		case <-guard:
			t.Fatalf("never sent what was waited for: %v", testSentTypes(side))
		}
	}
}

// The first envelope of messageType in sent, or nil.
func testFirstSent(sent []*protocol.Envelope, messageType protocol.MessageType) *protocol.Envelope {
	for _, envelope := range sent {
		if envelope.Type == uint32(messageType) {
			return envelope
		}
	}
	return nil
}

// Waits until stream has ended, by a reset, a reject or both closes.
func testAwaitStreamEnded(t *testing.T, stream *SubprotocolStream) {
	t.Helper()
	guard := time.After(testSubprotocolAwaitTimeout)
	for {
		var ended bool
		var changed chan struct{}
		func() {
			stream.stateLock.Lock()
			defer stream.stateLock.Unlock()
			ended = stream.state.phase == streamPhaseDone
			changed = stream.changed
		}()
		if ended {
			return
		}
		select {
		case <-changed:
		case <-guard:
			t.Fatal("the stream never ended")
		}
	}
}

// A key change under a stream (§6.4): a frame on it under another C15 key resets every stream with that
// peer with IDENTITY, here and at the peer, and a new open under that key is rejected INVALID.
//
// The acceptor resets as the frame arrives, so its StreamReset races the Write that sent the frame, and
// §6.4 orders neither. Each order is run, held by the pair's delivery: with resetFirst the Write's frame
// is delivered and the Write held until the reset has ended the opener's stream, so the Write, every byte
// sent, answers the peer's reset; without it the reset waits for the Write, which answers nil.
func testStreamIdentityMismatch(t *testing.T, resetFirst bool) {
	t.Helper()
	_, a, b := newTestStreamSides(t, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	opened, accepted := testStreamOpen(t, b, a, incomings, nil)
	otherSeed := make([]byte, ed25519.SeedSize)
	rand.Read(otherSeed)
	var otherKey [ed25519.PublicKeySize]byte
	copy(otherKey[:], ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey))
	func() {
		b.stateLock.Lock()
		defer b.stateLock.Unlock()
		b.presentedKey = &otherKey
	}()
	written := make(chan struct{})
	var writtenOnce sync.Once
	writeReturned := func() {
		writtenOnce.Do(func() { close(written) })
	}
	t.Cleanup(writeReturned)
	a.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
		switch {
		case resetFirst && from == b && envelope.Type == uint32(protocol.MessageType_STREAM_DATA):
			// on the Write's goroutine: the frame reaches the acceptor here, and the Write goes on only once
			// the acceptor's reset has come back and ended the opener's stream
			to.subprotocol.receive(connect.SourceId(from.clientId), envelope, from.peerTo(to))
			testAwaitStreamEnded(t, opened)
			return nil
		case !resetFirst && from == a && envelope.Type == uint32(protocol.MessageType_STREAM_RESET):
			// on the acceptor's stream sender: the reset leaves once the Write has returned
			select {
			case <-written:
			case <-time.After(testSubprotocolAwaitTimeout):
			}
		}
		return envelope
	})
	payload := []byte("under another key")
	n, err := opened.Write(payload)
	writeReturned()
	var resetErr *StreamResetError
	switch {
	case n != len(payload):
		t.Fatalf("the write sent %d B: %v", n, err)
	case resetFirst:
		if !errors.As(err, &resetErr) || resetErr.Code != protocol.StreamResetCode_RST_IDENTITY || resetErr.Local {
			t.Fatalf("the write the reset beat answered %v", err)
		}
	case err != nil:
		t.Fatalf("the write ahead of the reset answered %v", err)
	}
	a.setDeliver(nil)
	if _, err := accepted.Read(make([]byte, 64)); !errors.As(err, &resetErr) || resetErr.Code != protocol.StreamResetCode_RST_IDENTITY || !resetErr.Local {
		t.Errorf("the acceptor read %v", err)
	}
	if _, err := opened.Read(make([]byte, 64)); !errors.As(err, &resetErr) || resetErr.Code != protocol.StreamResetCode_RST_IDENTITY || resetErr.Local {
		t.Errorf("the opener read %v", err)
	}
	if _, err := opened.Write(payload); !errors.As(err, &resetErr) || resetErr.Code != protocol.StreamResetCode_RST_IDENTITY || resetErr.Local {
		t.Errorf("the opener's next write answered %v", err)
	}
	if stats := a.subprotocol.StreamStats(); stats.IdentityResetCount != 1 {
		t.Errorf("identity resets %d", stats.IdentityResetCount)
	}
	// the gate closed on the other key, so an open under it is rejected, never accepted
	var rejectErr *StreamRejectError
	_, err = b.subprotocol.OpenStream(t.Context(), Id(a.clientId), &StreamOpenRequest{Target: testStreamTarget})
	if !errors.As(err, &rejectErr) || rejectErr.Code != protocol.StreamRejectCode_SR_INVALID || rejectErr.Local {
		t.Fatalf("an open under another key answered %v", err)
	}
	select {
	case incoming := <-incomings:
		t.Fatalf("an open under another key reached the function: %+v", incoming)
	default:
	}
	testStreamsSettled(t, a)
	testStreamsSettled(t, b)
}

// The opener's Write returns before the acceptor's reset reaches it: nil, and the reset ends both ends.
func TestStreamIdentityMismatchResets(t *testing.T) {
	testStreamIdentityMismatch(t, false)
}

// The acceptor's reset reaches the opener before its Write returns: the Write, its bytes all sent, answers
// the peer's IDENTITY reset, and everything else holds as when the Write returned first.
func TestStreamIdentityMismatchResetBeatsWrite(t *testing.T) {
	testStreamIdentityMismatch(t, true)
}

// An edge sends no Hello and carries no binding (§6.4, §9.6's step 3): its open reaches the accept
// function with Edge set and no peer, both ways carry bytes, and no Hello or HeadCheck ever goes either
// way.
func TestStreamEdgeOpenWithNoHello(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	edge := pair.addEdge(nil)
	incomings := testStreamAccepting(t, a, "examplenet:tls/443/blog")
	opened, err := edge.subprotocol.OpenStream(t.Context(), Id(a.clientId), &StreamOpenRequest{
		Target: "examplenet:tls/443/blog", Metadata: []byte("tls edge open"), Ticket: []byte("an edge ticket"), EarlyData: []byte("client hello"),
	})
	if err != nil {
		t.Fatal(err)
	}
	incoming := testAwait(t, incomings, "the edge's open")
	if !incoming.Edge || incoming.Peer != nil || incoming.SourceId != Id(edge.clientId) {
		t.Errorf("incoming %+v", incoming)
	}
	if _, ok := incoming.Stream.Peer(); ok || !incoming.Stream.Edge() {
		t.Errorf("an edge stream shows an identity")
	}
	if got := testStreamReadFull(t, incoming.Stream, 12); string(got) != "client hello" {
		t.Errorf("early data %q", got)
	}
	if _, err := incoming.Stream.Write([]byte("server hello")); err != nil {
		t.Fatal(err)
	}
	if got := testStreamReadFull(t, opened, 12); string(got) != "server hello" {
		t.Errorf("reply %q", got)
	}
	for _, side := range []*testRpcSide{a, edge} {
		for _, messageType := range testSentTypes(side) {
			if sidecarOnlyMessageType(uint32(messageType)) {
				t.Errorf("%v sent between a sidecar and an edge", messageType)
			}
		}
	}
	// an edge runs no Hello and no HeadCheck at all
	if err := edge.subprotocol.EnsureHello(t.Context(), Id(a.clientId)); err == nil {
		t.Error("an edge ran a Hello")
	}
	if _, err := edge.subprotocol.AttachHeadCheck(&HeadCheckEnv{}); !errors.Is(err, errSubprotocolEdgeRole) {
		t.Errorf("an edge attached HeadCheck: %v", err)
	}
	opened.Close()
	incoming.Stream.Close()
	testStreamsSettled(t, a)
	testStreamsSettled(t, edge)
}

// A sidecar opening to an edge, as §14's stream to smtpedge, runs no Hello, and the edge's answers come as
// a Service-mode source's.
func TestStreamSidecarOpensToAnEdge(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	edge := pair.addEdge(nil)
	incomings := testStreamAccepting(t, edge, "ur/smtpedge")
	opened, err := a.subprotocol.OpenStream(t.Context(), Id(edge.clientId), &StreamOpenRequest{Target: "ur/smtpedge", Edge: true})
	if err != nil {
		t.Fatal(err)
	}
	incoming := testAwait(t, incomings, "the sidecar's open")
	if !incoming.Edge || incoming.Peer != nil {
		t.Errorf("incoming %+v", incoming)
	}
	if _, err := opened.Write([]byte("preamble")); err != nil {
		t.Fatal(err)
	}
	if got := testStreamReadFull(t, incoming.Stream, 8); string(got) != "preamble" {
		t.Errorf("read %q", got)
	}
	if slices.Contains(testSentTypes(a), protocol.MessageType_HELLO) {
		t.Error("a sidecar sent an edge a Hello")
	}
	// the same peer's sidecar stream is refused: a peer is an edge or a sidecar, never both
	if _, err := a.subprotocol.OpenStream(t.Context(), Id(edge.clientId), &StreamOpenRequest{Target: "ur/smtpedge"}); err == nil {
		t.Error("a sidecar stream to an edge opened")
	}
	opened.Close()
	incoming.Stream.Close()
}

// An edge's credit grows with its streams (§6.7's credit row): with a peer budget of two minimum windows,
// a sidecar's third open is refused BUSY while an edge's opens go on, the process's credit bounding it.
func TestStreamEdgeCreditGrowsWithItsStreams(t *testing.T) {
	adjust := func(settings *SidecarProtocolSettings) {
		settings.StreamMinWindowByteCount = 64 * 1024
		settings.StreamPressureMinWindowByteCount = 64 * 1024
		settings.StreamInitialWindowByteCount = 16 * 1024
		settings.StreamPeerCreditByteCount = 128 * 1024
		settings.StreamMaxWindowByteCount = 128 * 1024
	}
	pair := newTestRpcPair(t)
	a := pair.add(nil, adjust)
	// the openers grant plenty, so what refuses is the acceptor's credit
	b := pair.add(nil, nil)
	edge := pair.addEdge(nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	kept := []*SubprotocolStream{}
	// a sidecar's opens commit the initial window and then the minimum: two fit, the third does not
	refused := false
	for range 4 {
		stream, err := b.subprotocol.OpenStream(t.Context(), Id(a.clientId), &StreamOpenRequest{Target: testStreamTarget})
		var rejectErr *StreamRejectError
		if errors.As(err, &rejectErr) && rejectErr.Code == protocol.StreamRejectCode_SR_BUSY {
			refused = true
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		kept = append(kept, stream, testAwait(t, incomings, "an accept").Stream)
	}
	if !refused {
		t.Error("a sidecar's opens past its credit were not refused BUSY")
	}
	for range 4 {
		stream, err := edge.subprotocol.OpenStream(t.Context(), Id(a.clientId), &StreamOpenRequest{Target: testStreamTarget})
		if err != nil {
			t.Fatalf("an edge's open past a sidecar's credit: %v", err)
		}
		kept = append(kept, stream, testAwait(t, incomings, "an edge's accept").Stream)
	}
	for _, stream := range kept {
		stream.Close()
	}
}

// Close joins with bytes held: a dispatcher whose stream holds bytes no one read closes, its waiting
// reader returns, every byte of credit goes back, and the peer's stream ends too, at its keepalive.
func TestStreamCloseJoinsWithBytesBuffered(t *testing.T) {
	_, a, b := newTestStreamSides(t, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	opened, accepted := testStreamOpen(t, b, a, incomings, nil)
	if _, err := opened.Write(bytes.Repeat([]byte{7}, 10*1024)); err != nil {
		t.Fatal(err)
	}
	// a writer the window holds, and a reader waiting on the other end
	readErr := make(chan error, 1)
	go func() {
		_, err := opened.Read(make([]byte, 8))
		readErr <- err
	}()
	if usage := a.subprotocol.budget.currentUsage(); usage.creditByteCount == 0 {
		t.Fatal("no credit held for the bytes")
	}
	a.subprotocol.Close()
	if usage := a.subprotocol.budget.currentUsage(); usage.creditByteCount != 0 {
		t.Errorf("%d B of credit held after Close", usage.creditByteCount)
	}
	var resetErr *StreamResetError
	if _, err := accepted.Read(make([]byte, 8)); !errors.As(err, &resetErr) || resetErr.Code != protocol.StreamResetCode_RST_CANCELLED {
		t.Errorf("a closed dispatcher's stream reads %v", err)
	}
	if _, err := a.subprotocol.OpenStream(t.Context(), Id(b.clientId), &StreamOpenRequest{Target: testStreamTarget}); err == nil {
		t.Error("a closed dispatcher opened a stream")
	}
	// the peer's reader ends with its own dispatcher
	b.subprotocol.Close()
	if err := testAwait(t, readErr, "the peer's read"); err == nil {
		t.Error("the peer's read returned no error")
	}
}

// HoldProvideMode adds Service and FriendsAndFamily on top of the client's Network while a hold lives,
// counting holds, and refuses Public (D-PROTO-6).
func TestHoldProvideMode(t *testing.T) {
	_, a, _ := newTestStreamSides(t, nil)
	modes := func() map[connectprotocol.ProvideMode]bool {
		return a.subprotocol.client.ContractManager().GetProvideModes()
	}
	for _, mode := range []connectprotocol.ProvideMode{
		connectprotocol.ProvideMode_Public, connectprotocol.ProvideMode_PublicStream, connectprotocol.ProvideMode_Stream,
		connectprotocol.ProvideMode_None, connectprotocol.ProvideMode_Network,
	} {
		if _, err := a.subprotocol.HoldProvideMode(mode); !errors.Is(err, errProvideModeRefused) {
			t.Errorf("%v held: %v", mode, err)
		}
	}
	first, err := a.subprotocol.HoldProvideMode(connectprotocol.ProvideMode_Service)
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.subprotocol.HoldProvideMode(connectprotocol.ProvideMode_Service)
	if err != nil {
		t.Fatal(err)
	}
	share, err := a.subprotocol.HoldProvideMode(connectprotocol.ProvideMode_FriendsAndFamily)
	if err != nil {
		t.Fatal(err)
	}
	if got := modes(); !got[connectprotocol.ProvideMode_Network] || !got[connectprotocol.ProvideMode_Service] || !got[connectprotocol.ProvideMode_FriendsAndFamily] || got[connectprotocol.ProvideMode_Public] {
		t.Errorf("held: %v", got)
	}
	first()
	first()
	if got := modes(); !got[connectprotocol.ProvideMode_Service] {
		t.Errorf("one of two holds released dropped Service: %v", got)
	}
	second()
	share()
	if got := modes(); !got[connectprotocol.ProvideMode_Network] || got[connectprotocol.ProvideMode_Service] || got[connectprotocol.ProvideMode_FriendsAndFamily] {
		t.Errorf("released: %v", got)
	}
}
