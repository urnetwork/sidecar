//go:build !sidecar_http && !ios_extension

// The opener's half of §6.7 (R-PROTO-4, D-PROTO-4, D-PROTO-13): OpenStream sends StreamOpen with its first
// bytes and waits for the acceptor's answer.
//
// A stream to a sidecar runs only after §6.4's Hello with it (ensurePeerVerified), and takes its frames
// only under the C15 key that Hello verified; the first stream or RPC with a peer each HeadCheckInterval
// starts a HeadCheck beside it (rpc_headcheck_rounds.go). A stream to an edge, as §14's to smtpedge,
// runs no Hello, since an edge has no binding to show (stream_edge.go), and takes its frames only from a
// Service-mode source.
//
// StreamOpen carries target (at most 128 B), metadata (1,024 B), ticket (512 B), this side's window and
// the first 2,048 B of the request's early data, at most 3,800 B in all (§6.5's budget); the rest of the
// early data, up to the acceptor's initial window, follows at once as StreamData, before the answer, so a
// long PQ ClientHello reaches a listener in one round trip. The window commits StreamMinWindowByteCount of
// this side's credit before it goes, else the open fails here with RESOURCE_EXHAUSTED.

package sidecar

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// What OpenStream sends.
type StreamOpenRequest struct {
	// A <net>:<name> socket (§9) or a service target (§13, §15).
	Target string
	// The target's own schema, such as §13.5's TlsEdgeOpen.
	Metadata []byte
	// §9's SignedSocketTicket, which the acceptor admits the open on.
	Ticket []byte
	// The stream's first bytes, such as a ClientHello: at most the acceptor's initial window, its Hello's
	// initial_window or 16 KiB toward an edge. The first 2,048 B ride StreamOpen and the rest StreamData
	// right behind it.
	EarlyData []byte
	// The destination is a platform client in urnetwork-edge, which shows no binding: the open runs no
	// Hello, and the stream takes its frames only from a Service-mode source (§6.4, §14.4).
	Edge bool
}

// Opens a stream to clientId and waits for its answer, until ctx ends and at most DefaultCallTimeout. An
// accept answers the stream; a reject answers *StreamRejectError with the acceptor's code and wait; the
// open's own failures answer *SubprotocolError: INVALID_ARGUMENT past §6.5's budget or the acceptor's
// window, RESOURCE_EXHAUSTED when this side's credit cannot commit a window, Hello's refusal, UNAVAILABLE
// when connect will not take it, and DEADLINE_EXCEEDED or CANCELLED with no answer, after which the stream
// is reset CANCELLED so a late accept finds nothing. A sidecar's INVALID that comes after the Hello the open
// went under ended is met once with a fresh Hello and the open again, within the same deadline.
func (self *Subprotocol) OpenStream(ctx context.Context, clientId Id, request *StreamOpenRequest) (*SubprotocolStream, error) {
	if request == nil {
		request = &StreamOpenRequest{}
	}
	if self.settings.StreamTargetMaxByteCount < len(request.Target) || self.settings.StreamMetadataMaxByteCount < len(request.Metadata) ||
		self.settings.StreamTicketMaxByteCount < len(request.Ticket) {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_INVALID_ARGUMENT, Message: "a stream open past §6.5's budget"}
	}
	peerId := connect.Id(clientId)
	edge := request.Edge || self.role == SubprotocolRoleEdge
	start := self.clock.Now()
	timeout := self.settings.DefaultCallTimeout
	if ctxDeadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, ctxDeadline.Sub(start))
	}
	if timeout <= 0 {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED}
	}

	// a peer is an edge or a sidecar for the dispatcher's life, never both: the other kind is refused
	// before any Hello goes, which an edge would only drop
	if known, peerEdge := self.streamPeerKind(peerId); known && peerEdge != edge {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_FAILED_PRECONDITION, Message: errStreamPeerKind.Error()}
	}
	deadline := start.Add(timeout)
	// One open: toward a sidecar §6.4's Hello first, then StreamOpen and its answer. Answers too when the Hello it
	// went under verified, zero toward an edge.
	openOnce := func() (*SubprotocolStream, time.Time, error) {
		var helloTime time.Time
		if !edge {
			if err := self.ensurePeerVerifiedWithin(ctx, peerId, deadline.Sub(self.clock.Now())); err != nil {
				return nil, helloTime, openFailure(err)
			}
			helloTime, _ = self.sessionTime(peerId)
		}
		openCtx, cancelOpen := self.clockContext(ctx, deadline.Sub(self.clock.Now()))
		stopOnClose := context.AfterFunc(self.ctx, cancelOpen)
		stream, err := self.startStreamOpen(openCtx, peerId, edge, request, deadline)
		stopOnClose()
		cancelOpen()
		if err != nil {
			if ctx.Err() != nil {
				return nil, helloTime, openFailure(ctx.Err())
			}
			if self.ctx.Err() != nil {
				return nil, helloTime, errSubprotocolClosed
			}
			if !self.clock.Now().Before(deadline) {
				return nil, helloTime, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED}
			}
			return nil, helloTime, err
		}
		if !edge {
			// the first stream with a peer each HeadCheckInterval starts a HeadCheck beside it
			self.headCheckOnExchange(peerId, protocol.MessageType_STREAM_OPEN)
		}

		for {
			var phase streamPhase
			var endErr error
			var changed chan struct{}
			func() {
				stream.stateLock.Lock()
				defer stream.stateLock.Unlock()
				phase = stream.state.phase
				endErr = stream.state.err
				changed = stream.changed
			}()
			switch phase {
			case streamPhaseOpen:
				return stream, helloTime, nil
			case streamPhaseDone:
				stream.removeIfDone()
				return nil, helloTime, streamEndError(endErr, false)
			}
			select {
			case <-changed:
				continue
			case <-ctx.Done():
				stream.resetLocal(protocol.StreamResetCode_RST_CANCELLED)
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return nil, helloTime, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED}
				}
				return nil, helloTime, &SubprotocolError{Code: protocol.ErrorCode_ERR_CANCELLED}
			case <-self.clock.After(deadline.Sub(self.clock.Now())):
				stream.resetLocal(protocol.StreamResetCode_RST_CANCELLED)
				return nil, helloTime, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED}
			case <-self.ctx.Done():
				return nil, helloTime, errSubprotocolClosed
			}
		}
	}
	// When the Hello this open went under ended while it was in flight, as it does when connect reports that the peer
	// lost its session with this client (rpc_peer_session.go), the peer's gate held no Hello with this side either, and
	// its INVALID is the gate's: one fresh Hello and the open again (QD-1185). An INVALID under a Hello that still
	// stands is the listener's own answer and is returned as it is, so no listener's admission runs twice.
	stream, helloTime, err := openOnce()
	var rejectErr *StreamRejectError
	if !edge && errors.As(err, &rejectErr) && !rejectErr.Local && rejectErr.Code == protocol.StreamRejectCode_SR_INVALID {
		if standingTime, standing := self.sessionTime(peerId); !standing || !standingTime.Equal(helloTime) {
			stream, _, err = openOnce()
		}
	}
	return stream, err
}

// Reserve an ID and submit this peer's open before letting another opener advance its watermark.
func (self *Subprotocol) startStreamOpen(ctx context.Context, peerId connect.Id, edge bool, request *StreamOpenRequest, deadline time.Time) (*SubprotocolStream, error) {
	firstByteCount := min(len(request.EarlyData), MaxStreamEarlyDataByteCount)

	streams := &self.streams
	streams.stateLock.Lock()
	peer, err := self.streamPeerWithLock(peerId, edge)
	streams.stateLock.Unlock()
	if err != nil {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_FAILED_PRECONDITION, Message: err.Error()}
	}
	// Assign and enqueue opens to a peer in the same order: its receiver advances
	// a single watermark. Other peers and the receive callback can still run.
	select {
	case peer.opening <- struct{}{}:
		defer func() { <-peer.opening }()
	case <-ctx.Done():
		return nil, openFailure(ctx.Err())
	case <-self.ctx.Done():
		return nil, errSubprotocolClosed
	}
	streamId, err := streams.nextId(ctx, peer)
	if err != nil {
		if errors.Is(err, errStreamIdsExhausted) {
			return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED, Message: err.Error()}
		}
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE, Message: "could not reserve stream IDs"}
	}
	remaining := deadline.Sub(self.clock.Now())
	if remaining <= 0 {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED}
	}
	var identity *SubprotocolPeerIdentity
	var clientPublicKey [32]byte
	var peerInitialWindow uint32
	if !edge {
		// Waiting for a peer's earlier open or for a durable ID range can outlive its verified Hello.
		var verified bool
		identity, clientPublicKey, verified = self.peerVerifiedIdentity(peerId)
		if !verified {
			return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAUTHENTICATED}
		}
		peerInitialWindow = identity.InitialWindow
	}
	state, window, err := newStreamOpener(streamId, peer.credit, peerInitialWindow, firstByteCount)
	switch {
	case errors.Is(err, errStreamCreditExhausted):
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED}
	case err != nil:
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_INVALID_ARGUMENT, Message: err.Error()}
	}
	// the rest of the early data within the acceptor's initial window, before any answer
	rest, n, err := state.write(request.EarlyData[firstByteCount:])
	if err != nil || n < len(request.EarlyData)-firstByteCount {
		state.end(&streamResetError{code: protocol.StreamResetCode_RST_CANCELLED, local: true})
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_INVALID_ARGUMENT, Message: "early data past the acceptor's initial window"}
	}
	stream := newSubprotocolStream(self, peer, streamId, state)
	// the lane every frame of the stream rides, chosen once at its open so none reorders across lanes
	stream.opts = self.peerLaneOpts(peerId)
	stream.identity = identity
	stream.clientPublicKey = clientPublicKey
	stream.target = request.Target
	stream.metadata = request.Metadata
	stream.ticket = request.Ticket
	open := &protocol.StreamOpen{
		Target:    request.Target,
		Metadata:  request.Metadata,
		Ticket:    request.Ticket,
		Window:    window,
		EarlyData: request.EarlyData[:firstByteCount],
	}
	body, err := proto.Marshal(open)
	if err != nil || self.settings.StreamOpenMaxByteCount < len(body) {
		stream.endLocal(protocol.StreamResetCode_RST_CANCELLED)
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_INVALID_ARGUMENT, Message: "a stream open past §6.5's budget"}
	}
	if !self.addStream(stream) {
		stream.endLocal(protocol.StreamResetCode_RST_CANCELLED)
		return nil, errSubprotocolClosed
	}
	self.streams.stats.openedCount.Add(1)

	barrierKey := peerId.String()
	testHookBarrier("stream.open.before", barrierKey)
	sendErr := self.sendEnvelopeAcked(peerId, stream.envelope(protocol.MessageType_STREAM_OPEN, body), stream.ackFunction(time.Time{}), remaining, stream.opts...)
	testHookBarrier("stream.open.after", barrierKey)
	if sendErr != nil {
		stream.endLocal(protocol.StreamResetCode_RST_TRANSFER_FAILED)
		self.removeStream(stream)
		return nil, sendFailure(sendErr, 0)
	}
	if err := stream.sendFrames(rest); err != nil {
		return nil, err
	}
	return stream, nil
}

// Hello's failure as an open reports it: its code, or the context's.
func openFailure(err error) error {
	var subprotocolError *SubprotocolError
	switch {
	case errors.As(err, &subprotocolError):
		return &SubprotocolError{Code: subprotocolError.Code, Reason: subprotocolError.Reason, MinVersion: subprotocolError.MinVersion, MaxVersion: subprotocolError.MaxVersion}
	case errors.Is(err, context.Canceled):
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_CANCELLED}
	case errors.Is(err, context.DeadlineExceeded):
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED}
	case errors.Is(err, errSubprotocolClosed):
		return err
	}
	return &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAUTHENTICATED}
}
