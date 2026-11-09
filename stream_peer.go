//go:build !sidecar_http

// §6.7's streams on the wire, the dispatcher's half (R-PROTO-9, R-PROTO-10, D-PROTO-4, D-PROTO-13): each
// peer's stream ids, credit and liveness, the inline routing of stream frames, and the sender that carries
// the frames no caller of a stream sends itself.
//
// Stream frames never ride the per-peer queue: the inline handler routes each straight to its stream
// (stream bytes cannot be dropped and skipped, connect/CODESTYLE.md:123), where streamState holds them in
// a buffer its window bounds. A frame that breaks §6.7's rules resets its stream with PROTOCOL; one for a
// stream this side does not hold, a late frame after a reset among them, is dropped and counted. A frame
// of a stream already open passes no Hello gate: it must carry the C15 key the stream opened under, and a
// frame under another key resets every stream with that peer with IDENTITY (§6.4), so a stream outlives
// HelloCacheTimeout while its session's key holds. An edge stream takes frames only from a Service-mode
// source, and a sidecar's only from a Network one.
//
// The inline handler never sends (R-PROTO-7). What it and connect's ack callbacks must send, a reset, and
// what a reader asks for, a StreamWindow, goes to the stream sender: one goroutine that hands connect each
// frame with zero wait, so no peer holds it up, and puts back what connect refuses for another try after
// CallSendRetryInterval. A stream's windows coalesce to its newest, and nothing is dropped. StreamOpen,
// StreamAccept, StreamReject, StreamData and StreamClose go from the goroutine that made them, each a
// caller of the stream, which may wait for connect: a sender blocks, which is how backpressure reaches its
// source. A frame connect will not take within PeerSilenceTimeout, or whose ack is an error, resets its
// stream with TRANSFER_FAILED.
//
// A peer's ids live as long as the dispatcher, since ids are never reused per peer (§6.7); its streams'
// table empties as they end. Locks: a stream's stateLock may be held while the table's is taken, to queue
// a frame for the sender, and never the other way: the table's lock is let go before any stream's is
// taken.

package sidecar

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A peer this dispatcher holds as an edge asked for a sidecar stream, or the other way.
	errStreamPeerKind = errors.New("stream: an edge and a sidecar stream with one peer")
)

// What the dispatcher keeps of streams. Its own lock, so a stream frame does not contend with calls.
type subprotocolStreams struct {
	stateLock sync.Mutex
	// every peer a stream ever ran with, by client id
	peers map[connect.Id]*streamPeer
	// Listen's accept functions, by target
	listeners map[string]*streamListener
	// the sender's queue, oldest first
	outbound []*streamOutbound
	// whether the sender and the keepalive run
	loopsStarted bool

	// wakes the sender: something queued
	outboundWake chan struct{}
	// moves when a peer's streams or liveness change, which the keepalive waits on
	change *MonitorValue[uint64]

	stats streamStats
}

// One peer's side of every stream with it.
type streamPeer struct {
	peerId connect.Id
	// an edge peer: a Service-mode source, or any peer of an edge (stream_edge.go)
	edge bool
	ids  *streamIds
	// what this side grants the peer's streams; an edge's grows with its streams
	credit *streamCredit
	// the streams running now, by id
	streams map[uint64]*SubprotocolStream
	// opens whose accept function has not answered
	pendingAcceptCount int
	// the keepalive (stream_keepalive.go): the last frame from the peer that passed the inline checks, and
	// whether a Ping went since
	lastInboundTime time.Time
	pinged          bool
}

// What the stream layer has counted, each a running total.
type streamStats struct {
	openedCount   atomic.Uint64
	acceptedCount atomic.Uint64
	rejectedCount atomic.Uint64
	// streams this side reset, by any code
	localResetCount atomic.Uint64
	// frames for no stream this side holds, chunked, malformed or of the wrong source
	droppedFrameCount atomic.Uint64
	// streams reset IDENTITY and PEER_TIMEOUT
	identityResetCount    atomic.Uint64
	peerTimeoutResetCount atomic.Uint64
	pingCount             atomic.Uint64
	// frames the sender put back for another try
	sendRetryCount atomic.Uint64
	// D-PROTO-4's measure: how long each StreamData took from its send to connect's ack
	stall streamStallHistogram
}

// D-PROTO-4's stall measure (PROTO-M5-05 exports its p99 against the 500 ms review): each StreamData's
// time from its send to connect's ack, which a lost pack holds until it is resent, in buckets of powers of
// two milliseconds. A fixed format of the measure, not a tunable.
type streamStallHistogram struct {
	// bucket i counts ack times below 2^i ms; the last also counts everything past it
	buckets [streamStallBucketCount]atomic.Uint64
}

// 2^0 ms to 2^16 ms, the last past connect's 60 s ack timeout.
const streamStallBucketCount = 18

// Counts one frame's ack time.
func (self *streamStallHistogram) add(stall time.Duration) {
	bucket := 0
	for limit := time.Millisecond; bucket < streamStallBucketCount-1 && limit <= stall; limit *= 2 {
		bucket += 1
	}
	self.buckets[bucket].Add(1)
}

// The p-th percentile's upper bound, and how many frames were counted. Zero with none.
func (self *streamStallHistogram) percentile(p float64) (time.Duration, uint64) {
	counts := [streamStallBucketCount]uint64{}
	total := uint64(0)
	for i := range counts {
		counts[i] = self.buckets[i].Load()
		total += counts[i]
	}
	if total == 0 {
		return 0, 0
	}
	rank := uint64(p * float64(total))
	seen := uint64(0)
	for i, count := range counts {
		seen += count
		if rank < seen {
			return time.Millisecond << i, total
		}
	}
	return time.Millisecond << (streamStallBucketCount - 1), total
}

// D-PROTO-4's measure as it stands: the 99th percentile of StreamData's send-to-ack time, as the upper
// bound of its power-of-two bucket, and how many frames it counts.
func (self *Subprotocol) StreamStallP99() (time.Duration, uint64) {
	return self.streams.stats.stall.percentile(0.99)
}

// The stream layer's counters as they stand.
type SubprotocolStreamStats struct {
	OpenedCount           uint64
	AcceptedCount         uint64
	RejectedCount         uint64
	LocalResetCount       uint64
	DroppedFrameCount     uint64
	IdentityResetCount    uint64
	PeerTimeoutResetCount uint64
	PingCount             uint64
	SendRetryCount        uint64
}

// The stream layer's counters, each a running total since NewSubprotocol.
func (self *Subprotocol) StreamStats() SubprotocolStreamStats {
	stats := &self.streams.stats
	return SubprotocolStreamStats{
		OpenedCount:           stats.openedCount.Load(),
		AcceptedCount:         stats.acceptedCount.Load(),
		RejectedCount:         stats.rejectedCount.Load(),
		LocalResetCount:       stats.localResetCount.Load(),
		DroppedFrameCount:     stats.droppedFrameCount.Load(),
		IdentityResetCount:    stats.identityResetCount.Load(),
		PeerTimeoutResetCount: stats.peerTimeoutResetCount.Load(),
		PingCount:             stats.pingCount.Load(),
		SendRetryCount:        stats.sendRetryCount.Load(),
	}
}

// The client id peers reach this dispatcher at, which stream ids take their parity from.
func (self *Subprotocol) selfClientId() connect.Id {
	if self.streamClientId != (connect.Id{}) {
		return self.streamClientId
	}
	return self.client.ClientId()
}

// The peer's entry, made if it has none, with edge as its kind: false if it holds the other kind, which a
// peer cannot be both of, or the dispatcher has closed. Under the table's lock.
func (self *Subprotocol) streamPeerWithLock(peerId connect.Id, edge bool) (*streamPeer, error) {
	streams := &self.streams
	if peer := streams.peers[peerId]; peer != nil {
		if peer.edge != edge {
			return nil, errStreamPeerKind
		}
		return peer, nil
	}
	ids, err := newStreamIds(Id(self.selfClientId()), Id(peerId))
	if err != nil {
		return nil, err
	}
	peer := &streamPeer{
		peerId:          peerId,
		edge:            edge,
		ids:             ids,
		credit:          newStreamCredit(self.settings, self.budget, edge || self.role == SubprotocolRoleEdge, self.streamPressure),
		streams:         map[uint64]*SubprotocolStream{},
		lastInboundTime: self.clock.Now(),
	}
	if streams.peers == nil {
		streams.peers = map[connect.Id]*streamPeer{}
	}
	streams.peers[peerId] = peer
	return peer, nil
}

// Whether the dispatcher knows peerId from a stream, and as an edge or not.
func (self *Subprotocol) streamPeerKind(peerId connect.Id) (known bool, edge bool) {
	streams := &self.streams
	streams.stateLock.Lock()
	defer streams.stateLock.Unlock()
	if peer := streams.peers[peerId]; peer != nil {
		return true, peer.edge
	}
	return false, false
}

// Puts stream in its peer's table and starts the sender and the keepalive if they do not run. False once
// the dispatcher has closed, when nothing new starts.
func (self *Subprotocol) addStream(stream *SubprotocolStream) bool {
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.closed
	}()
	if closed {
		return false
	}
	start := false
	func() {
		streams := &self.streams
		streams.stateLock.Lock()
		defer streams.stateLock.Unlock()
		stream.peer.streams[stream.streamId] = stream
		if len(stream.peer.streams) == 1 {
			// silence counts from the first stream, not from whenever the peer was last heard
			stream.peer.lastInboundTime = self.clock.Now()
			stream.peer.pinged = false
		}
		if !streams.loopsStarted {
			streams.loopsStarted = true
			start = true
		}
	}()
	self.streams.change.Update(func(change uint64) uint64 { return change + 1 })
	if start {
		self.startStreamLoops()
	}
	return true
}

// Takes stream out of its peer's table, once it is done.
func (self *Subprotocol) removeStream(stream *SubprotocolStream) {
	streams := &self.streams
	streams.stateLock.Lock()
	defer streams.stateLock.Unlock()
	if stream.peer.streams[stream.streamId] == stream {
		delete(stream.peer.streams, stream.streamId)
	}
}

// The stream a frame from peerId names, or nil.
func (self *Subprotocol) streamOf(peerId connect.Id, streamId uint64) *SubprotocolStream {
	streams := &self.streams
	streams.stateLock.Lock()
	defer streams.stateLock.Unlock()
	if peer := streams.peers[peerId]; peer != nil {
		return peer.streams[streamId]
	}
	return nil
}

// Every stream running with peerId now.
func (self *Subprotocol) streamsOf(peerId connect.Id) []*SubprotocolStream {
	streams := &self.streams
	streams.stateLock.Lock()
	defer streams.stateLock.Unlock()
	peer := streams.peers[peerId]
	if peer == nil {
		return nil
	}
	list := make([]*SubprotocolStream, 0, len(peer.streams))
	for _, stream := range peer.streams {
		list = append(list, stream)
	}
	return list
}

// The keepalive's inbound traffic: any frame from peerId that passed the inline checks. Only a peer with
// a stream is tracked, so this is one map read for every other. The first frame after a Ping moves the
// keepalive's next Ping to PingTimeout from now, so the loop is woken for it then, and only then.
func (self *Subprotocol) noteStreamInbound(peerId connect.Id) {
	now := self.clock.Now()
	streams := &self.streams
	answered := func() bool {
		streams.stateLock.Lock()
		defer streams.stateLock.Unlock()
		peer := streams.peers[peerId]
		if peer == nil || len(peer.streams) == 0 {
			return false
		}
		peer.lastInboundTime = now
		pinged := peer.pinged
		peer.pinged = false
		return pinged
	}()
	if answered {
		streams.change.Update(func(change uint64) uint64 { return change + 1 })
	}
}

// Whether the process is past half of GOMEMLIMIT, the credit's pressure reading (stream_credit.go), or a
// test's.
func (self *Subprotocol) streamPressure() bool {
	if self.streamPressureOf != nil {
		return self.streamPressureOf()
	}
	return streamMemoryPressure()
}

// One stream frame, as the inline handler routes it, after the file header of rpc_subprotocol.go's seven
// checks: a StreamOpen to Listen's function (stream_listen.go), anything else to its stream. Never blocks
// and never sends; what a frame asks to be sent goes to the stream sender, and a StreamOpen's refusal to
// the reply queue.
func (self *Subprotocol) receiveStreamFrame(
	source connect.TransferPath,
	envelope *protocol.Envelope,
	peer connect.Peer,
	clientPublicKey [ed25519.PublicKeySize]byte,
	hasClientPublicKey bool,
) {
	sourceId := source.SourceId
	edge := peer.ProvideMode == connectprotocol.ProvideMode_Service || self.role == SubprotocolRoleEdge
	// one envelope each, never chunked: a StreamOpen is at most 3,800 B and StreamData 4,000 B of data
	if envelope.Chunk != nil || envelope.Flags&EnvelopeFlagMore != 0 || envelope.StreamId == 0 {
		self.streams.stats.droppedFrameCount.Add(1)
		return
	}
	if protocol.MessageType(envelope.Type) == protocol.MessageType_STREAM_OPEN {
		self.receiveStreamOpen(sourceId, envelope, peer, edge, clientPublicKey, hasClientPublicKey)
		return
	}
	stream := self.streamOf(sourceId, envelope.StreamId)
	if stream == nil || stream.edge != edge {
		self.streams.stats.droppedFrameCount.Add(1)
		return
	}
	if !edge && (!hasClientPublicKey || clientPublicKey != stream.clientPublicKey) {
		if !hasClientPublicKey {
			// a frame no session opened shows nothing about the stream's key
			self.streams.stats.droppedFrameCount.Add(1)
			return
		}
		// the session's key changed under the stream (§6.4): every stream that key opened ends
		self.resetPeerStreams(sourceId, protocol.StreamResetCode_RST_IDENTITY, func(stream *SubprotocolStream) bool {
			return !stream.edge && stream.clientPublicKey != clientPublicKey
		})
		return
	}
	var message proto.Message
	switch protocol.MessageType(envelope.Type) {
	case protocol.MessageType_STREAM_ACCEPT:
		message = &protocol.StreamAccept{}
	case protocol.MessageType_STREAM_REJECT:
		message = &protocol.StreamReject{}
	case protocol.MessageType_STREAM_DATA:
		message = &protocol.StreamData{}
	case protocol.MessageType_STREAM_WINDOW:
		message = &protocol.StreamWindow{}
	case protocol.MessageType_STREAM_CLOSE:
		message = &protocol.StreamClose{}
	case protocol.MessageType_STREAM_RESET:
		message = &protocol.StreamReset{}
	}
	if err := proto.Unmarshal(envelope.Body, message); err != nil {
		stream.resetLocal(protocol.StreamResetCode_RST_PROTOCOL)
		return
	}
	stream.receive(message)
}

// Resets with code every stream with peerId that match keeps, sending each reset through the stream
// sender.
func (self *Subprotocol) resetPeerStreams(peerId connect.Id, code protocol.StreamResetCode, match func(stream *SubprotocolStream) bool) {
	for _, stream := range self.streamsOf(peerId) {
		if match != nil && !match(stream) {
			continue
		}
		stream.resetLocal(code)
	}
}

// One frame for the stream sender: a stream's newest window, built when it goes, or an envelope built
// when it was queued, a reset or a Ping.
type streamOutbound struct {
	destinationId connect.Id
	// the lane it rides: an acceptor's the open's, an opener's none
	opts []any
	// whose window, or whose ack error resets
	stream *SubprotocolStream
	// nil for a window
	envelope *protocol.Envelope
}

// Queues outbound for the stream sender, with no wait.
func (self *Subprotocol) queueStreamOutbound(outbound *streamOutbound) {
	streams := &self.streams
	func() {
		streams.stateLock.Lock()
		defer streams.stateLock.Unlock()
		streams.outbound = append(streams.outbound, outbound)
	}()
	select {
	case streams.outboundWake <- struct{}{}:
	default:
	}
}

// Starts the stream sender and the keepalive, which Close joins with the handlers.
func (self *Subprotocol) startStreamLoops() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return
	}
	self.handlers.Add(2)
	go self.runStreamSender()
	go self.runStreamKeepalive()
}

// The stream sender: each queued frame to connect with zero wait, in order, what connect refuses put back
// and tried again after CallSendRetryInterval. Each wait is on the queue, the retry or the dispatcher's
// end, so it never spins; what is queued when the dispatcher ends is dropped, its streams ending too.
func (self *Subprotocol) runStreamSender() {
	defer self.handlers.Done()
	streams := &self.streams
	for {
		var outbound []*streamOutbound
		func() {
			streams.stateLock.Lock()
			defer streams.stateLock.Unlock()
			outbound = streams.outbound
			streams.outbound = nil
		}()
		if len(outbound) == 0 {
			select {
			case <-streams.outboundWake:
				continue
			case <-self.ctx.Done():
				return
			}
		}
		refused := []*streamOutbound{}
		for _, item := range outbound {
			if !self.sendStreamOutbound(item) {
				refused = append(refused, item)
			}
		}
		if len(refused) == 0 {
			continue
		}
		streams.stats.sendRetryCount.Add(uint64(len(refused)))
		func() {
			streams.stateLock.Lock()
			defer streams.stateLock.Unlock()
			streams.outbound = append(refused, streams.outbound...)
		}()
		select {
		case <-self.clock.After(self.settings.CallSendRetryInterval):
		case <-self.ctx.Done():
			return
		}
	}
}

// One frame's try: false when connect would not take it now, and it is to be tried again.
func (self *Subprotocol) sendStreamOutbound(outbound *streamOutbound) bool {
	envelope := outbound.envelope
	if envelope == nil {
		window := outbound.stream.takeWindow()
		if window == nil {
			return true
		}
		body, err := proto.Marshal(window)
		if err != nil {
			// two integers always encode
			panic(err)
		}
		envelope = outbound.stream.envelope(protocol.MessageType_STREAM_WINDOW, body)
		ack := outbound.stream.ackFunction(time.Time{})
		if err := self.sendEnvelopeAcked(outbound.destinationId, envelope, ack, 0, outbound.opts...); err != nil {
			if errors.Is(err, connect.ErrEncryptionRequiredNotEstablished) {
				// no session to send on: nothing a retry fixes, so the stream ends
				outbound.stream.resetLocal(protocol.StreamResetCode_RST_TRANSFER_FAILED)
				return true
			}
			outbound.stream.restoreWindow(window)
			return false
		}
		return true
	}
	ack := ignoreSubprotocolAck
	if outbound.stream != nil && protocol.MessageType(envelope.Type) != protocol.MessageType_STREAM_RESET {
		ack = outbound.stream.ackFunction(time.Time{})
	}
	if err := self.sendEnvelopeAcked(outbound.destinationId, envelope, ack, 0, outbound.opts...); err != nil {
		if errors.Is(err, connect.ErrEncryptionRequiredNotEstablished) {
			return true
		}
		return false
	}
	return true
}

// Ends every stream as the dispatcher closes: each resets CANCELLED here and sends nothing, since the
// client is going, so every reader and writer returns.
func (self *Subprotocol) closeStreams() {
	streams := &self.streams
	var all []*SubprotocolStream
	func() {
		streams.stateLock.Lock()
		defer streams.stateLock.Unlock()
		for _, peer := range streams.peers {
			for _, stream := range peer.streams {
				all = append(all, stream)
			}
		}
		streams.listeners = nil
		streams.outbound = nil
	}()
	for _, stream := range all {
		stream.endLocal(protocol.StreamResetCode_RST_CANCELLED)
	}
}

// A context that ends after timeout on this dispatcher's clock, at cancel, or with parent.
func (self *Subprotocol) clockContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	expire := self.clock.After(timeout)
	go func() {
		select {
		case <-expire:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
