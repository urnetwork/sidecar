//go:build !sidecar_http

// The acceptor's half of §6.7 (R-PROTO-4, I-5, D-PROTO-13): Listen hands each open of a target to its
// accept function, which answers StreamAccept or StreamReject.
//
// This code routes and enforces credit, and grants nothing itself (I-5): the function checks the ticket
// with §9's admission and §8's local policy (SOCK-M5-11), so every grant decision is the listener's own.
// What it is told: the target, metadata and ticket, the session's source client, and the peer's verified
// Hello, or for an edge's open none, with Edge set, since edges send no Hello and their tickets'
// dialer_network_id identifies them (§9.6's step 3, which the function still runs: dialer_client_id must
// be the session's source).
//
// An open from a sidecar passed Hello's gate inline (rpc_subprotocol.go), else it was rejected INVALID
// there. One that reuses an id resets with PROTOCOL; one past PeerQueueMessageCount opens awaiting their
// answer from one peer, or whose initial window this side's credit cannot hold, is rejected BUSY; one for a
// target no Listen holds is rejected RETRY, as §9.6 answers a ticket raced by an unlisten. Its early data
// and any StreamData before the answer are held against the initial window and reach no reader until the
// function accepts (FI-11); a reject discards them and gives their credit back.
//
// The function runs on a goroutine of its own, so it may fetch what it needs, and its ctx ends after
// DefaultCallTimeout, when the opener resets, or when the dispatcher closes.

package sidecar

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A target past §6.5's 128 B, or one Listen already holds.
	errStreamListenTarget = errors.New("stream: target refused or already listened")
)

// One open, as an accept function sees it before it answers.
type StreamIncoming struct {
	// The session's source client, as connect authenticated it.
	SourceId Id
	// The peer's verified Hello; nil from an edge, which sends none.
	Peer *SubprotocolPeerIdentity
	// The open came from a Service-mode source, a platform client in urnetwork-edge, admitted on its
	// ticket alone (§9.6's step 3).
	Edge   bool
	Target string
	// StreamOpen.metadata and .ticket, which the function may keep.
	Metadata []byte
	Ticket   []byte
	// The stream, which carries nothing to its reader until the function accepts it: one that accepts
	// keeps it, as an accept queue does, and one that refuses must not.
	Stream *SubprotocolStream
}

// Answers one open: nil accepts it; a *StreamRejectError rejects it with its code and retry_after_ms, a
// zero code going as INVALID; and any other error rejects it RETRY, so the dialer tries its next ticket.
// It runs on its own goroutine, and must answer once ctx ends. It must not read the stream before it
// answers, since a Read waits for the accept.
type StreamAcceptFunction func(ctx context.Context, incoming *StreamIncoming) error

// One Listen.
type streamListener struct {
	target string
	accept StreamAcceptFunction
}

// Hands every open of target to accept from now on, until remove is called; opens already handed on are
// answered as accept answers them. One function a target.
func (self *Subprotocol) Listen(target string, accept StreamAcceptFunction) (remove func(), err error) {
	if accept == nil || target == "" || MaxStreamTargetByteCount < len(target) {
		return nil, errStreamListenTarget
	}
	listener := &streamListener{target: target, accept: accept}
	streams := &self.streams
	streams.stateLock.Lock()
	defer streams.stateLock.Unlock()
	if streams.listeners == nil {
		streams.listeners = map[string]*streamListener{}
	}
	if streams.listeners[target] != nil {
		return nil, errStreamListenTarget
	}
	streams.listeners[target] = listener
	return func() {
		streams.stateLock.Lock()
		defer streams.stateLock.Unlock()
		if streams.listeners[target] == listener {
			delete(streams.listeners, target)
		}
	}, nil
}

// A StreamOpen, routed inline: decoded, its id taken, its initial window committed and its stream in the
// table, then handed to its target's function on a goroutine. Every refusal goes through the reply queue
// or the stream sender, so this never sends.
func (self *Subprotocol) receiveStreamOpen(
	sourceId connect.Id,
	envelope *protocol.Envelope,
	peer connect.Peer,
	edge bool,
	clientPublicKey [32]byte,
	hasClientPublicKey bool,
) {
	reject := func(code protocol.StreamRejectCode) {
		self.streams.stats.rejectedCount.Add(1)
		self.offerReply(streamRejectReply(sourceId, peer.TransferKey, envelope.StreamId, code))
	}
	open := &protocol.StreamOpen{}
	if err := proto.Unmarshal(envelope.Body, open); err != nil || MaxStreamTargetByteCount < len(open.Target) ||
		MaxStreamMetadataByteCount < len(open.Metadata) || MaxStreamTicketByteCount < len(open.Ticket) {
		reject(protocol.StreamRejectCode_SR_INVALID)
		return
	}
	var identity *SubprotocolPeerIdentity
	if !edge {
		// the gate passed this frame under a standing Hello: its peer, under the key on this frame
		var key [32]byte
		var ok bool
		identity, key, ok = self.peerVerifiedIdentity(sourceId)
		if !ok || !hasClientPublicKey || key != clientPublicKey {
			reject(protocol.StreamRejectCode_SR_INVALID)
			return
		}
	}
	opts := []any{self.replyLane(peer.TransferKey)}

	var stream *SubprotocolStream
	var listener *streamListener
	var frames streamFrames
	refusal := protocol.StreamRejectCode_SR_UNSPECIFIED
	reset := false
	func() {
		streams := &self.streams
		streams.stateLock.Lock()
		defer streams.stateLock.Unlock()
		streamPeer, err := self.streamPeerWithLock(sourceId, edge)
		if err != nil {
			refusal = protocol.StreamRejectCode_SR_INVALID
			return
		}
		if err := streamPeer.ids.accept(envelope.StreamId); err != nil {
			// a reused id: the open's answer is a reset (stream_state.go's ids)
			reset = true
			return
		}
		listener = streams.listeners[open.Target]
		switch {
		case listener == nil:
			refusal = protocol.StreamRejectCode_SR_RETRY
			return
		case self.settings.PeerQueueMessageCount <= streamPeer.pendingAcceptCount:
			refusal = protocol.StreamRejectCode_SR_BUSY
			return
		}
		var state *streamState
		state, frames = newStreamAcceptor(envelope.StreamId, streamPeer.credit, open)
		if frames.reject != nil || frames.reset != nil {
			return
		}
		streamPeer.pendingAcceptCount += 1
		stream = newSubprotocolStream(self, streamPeer, envelope.StreamId, state)
		stream.identity = identity
		stream.clientPublicKey = clientPublicKey
		stream.target = open.Target
		stream.metadata = open.Metadata
		stream.ticket = open.Ticket
		stream.opts = opts
	}()
	switch {
	case reset:
		body, _ := proto.Marshal(&protocol.StreamReset{Code: uint32(protocol.StreamResetCode_RST_PROTOCOL)})
		self.streams.stats.localResetCount.Add(1)
		self.queueStreamOutbound(&streamOutbound{destinationId: sourceId, opts: opts, envelope: &protocol.Envelope{
			Version: WireVersionMajor, Type: uint32(protocol.MessageType_STREAM_RESET), Flags: EnvelopeFlagNoReply,
			StreamId: envelope.StreamId, Body: body,
		}})
		return
	case refusal != protocol.StreamRejectCode_SR_UNSPECIFIED:
		reject(refusal)
		return
	case frames.reject != nil:
		reject(protocol.StreamRejectCode(frames.reject.Code))
		return
	case frames.reset != nil:
		body, _ := proto.Marshal(frames.reset)
		self.streams.stats.localResetCount.Add(1)
		self.queueStreamOutbound(&streamOutbound{destinationId: sourceId, opts: opts, envelope: &protocol.Envelope{
			Version: WireVersionMajor, Type: uint32(protocol.MessageType_STREAM_RESET), Flags: EnvelopeFlagNoReply,
			StreamId: envelope.StreamId, Body: body,
		}})
		return
	}
	if !self.addStream(stream) {
		self.finishAccept(stream)
		stream.endLocal(protocol.StreamResetCode_RST_CANCELLED)
		return
	}
	incoming := &StreamIncoming{
		SourceId: Id(sourceId),
		Peer:     identity,
		Edge:     edge,
		Target:   open.Target,
		Metadata: open.Metadata,
		Ticket:   open.Ticket,
		Stream:   stream,
	}
	started := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.handlers.Add(1)
		return true
	}()
	if !started {
		self.finishAccept(stream)
		stream.endLocal(protocol.StreamResetCode_RST_CANCELLED)
		return
	}
	go self.runAccept(listener, incoming)
}

// One accept function's run and its answer: StreamAccept with this side's window, or StreamReject. An
// accept this side's credit cannot back is answered BUSY. An open the opener reset meanwhile is answered
// with nothing, whatever the function said.
func (self *Subprotocol) runAccept(listener *streamListener, incoming *StreamIncoming) {
	defer self.handlers.Done()
	stream := incoming.Stream
	// the answer counts as given once decided, before it goes, so a peer that has it may open again
	finished := false
	finish := func() {
		if !finished {
			finished = true
			self.finishAccept(stream)
		}
	}
	defer finish()
	ctx, cancel := self.clockContext(self.ctx, self.settings.DefaultCallTimeout)
	defer cancel()
	ended := func() bool {
		stream.stateLock.Lock()
		defer stream.stateLock.Unlock()
		if stream.state.phase == streamPhaseDone {
			return true
		}
		stream.acceptCancel = cancel
		return false
	}()
	if ended {
		return
	}
	barrierKey := connect.Id(incoming.SourceId).String()
	testHookBarrier("stream.accept.before", barrierKey)
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				self.stats.panicCount.Add(1)
				self.log.Errorf("[stream]accept of %s from %s panic = %v\n", listener.target, incoming.SourceId, r)
				err = &StreamRejectError{Code: protocol.StreamRejectCode_SR_RETRY}
			}
		}()
		return listener.accept(ctx, incoming)
	}()
	testHookBarrier("stream.accept.after", barrierKey)

	var frames streamFrames
	func() {
		stream.stateLock.Lock()
		defer stream.stateLock.Unlock()
		stream.acceptCancel = nil
		if stream.state.phase != streamPhaseOpening {
			return
		}
		if err == nil {
			frames, _ = stream.state.accept()
		} else {
			code := protocol.StreamRejectCode_SR_RETRY
			retryAfterMs := uint32(0)
			var rejectErr *StreamRejectError
			if errors.As(err, &rejectErr) {
				code = rejectErr.Code
				retryAfterMs = uint32(min(rejectErr.RetryAfter/time.Millisecond, time.Duration(^uint32(0))))
			}
			frames, _ = stream.state.reject(code, retryAfterMs)
		}
		stream.notifyWithLock()
	}()
	switch {
	case frames.accept != nil:
		self.streams.stats.acceptedCount.Add(1)
	case frames.reject != nil:
		self.streams.stats.rejectedCount.Add(1)
	}
	finish()
	// a refused stream leaves the table before its answer goes
	stream.removeIfDone()
	stream.sendFrames(frames)
}

// Counts an open's answer as given, so its peer may have another awaiting one.
func (self *Subprotocol) finishAccept(stream *SubprotocolStream) {
	streams := &self.streams
	streams.stateLock.Lock()
	defer streams.stateLock.Unlock()
	stream.peer.pendingAcceptCount = max(stream.peer.pendingAcceptCount-1, 0)
}
