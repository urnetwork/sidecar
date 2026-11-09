//go:build !sidecar_http

// SubprotocolStream: one §6.7 stream as a net.Conn with CloseWrite (D-PROTO-4), what OpenStream answers
// and what Listen's accept function is handed. Its rules are streamState's (stream_state.go); this is the
// I/O over them.
//
//   - Read returns the peer's bytes in order, and io.EOF, plain, once the peer's StreamClose and every byte
//     before it are read. An acceptor's Read waits for its accept, so no byte, early data included, reaches
//     the application before the accept function says yes (FI-11).
//   - Write sends within the peer's window as StreamData of at most 4,000 B, waiting for StreamWindow when
//     the window is spent; an opener writes before the accept within the acceptor's initial window.
//   - CloseWrite sends StreamClose, a half-close, and reads on.
//   - Close sends StreamClose and stops reading: the peer reads io.EOF, what it still sends is dropped with
//     its credit returned, so it is never held waiting, and this end's Read and Write then return
//     net.ErrClosed. A second Close fails as a net.Conn's does.
//   - Reset sends StreamReset with its code, and both ends' Reads and Writes then return a
//     *StreamResetError, as they do when the peer resets: §20.6's quota reset is RST_QUOTA through it.
//   - Deadlines are net.Conn's: absolute, on the dispatcher's clock, os.ErrDeadlineExceeded once passed,
//     and the stream survives them, so clearing one lets I/O go on. A Write that has handed its frames
//     to connect sends them whatever its deadline, since a byte sent cannot be taken back.
//
// Safe for concurrent use, as net.Conn is. Writes are serialized, so two never interleave their bytes.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// A stream ended by a reset, from either end: what Read and Write return once it has.
type StreamResetError struct {
	Code protocol.StreamResetCode
	// This end sent the reset.
	Local bool
}

// The code, and which end reset.
func (self *StreamResetError) Error() string {
	if self.Local {
		return fmt.Sprintf("stream reset here: %s", self.Code)
	}
	return fmt.Sprintf("stream reset by the peer: %s", self.Code)
}

// An open the acceptor refused (§6.7's StreamReject, §9.6's codes one to one): what OpenStream returns,
// and what an accept function returns to refuse.
type StreamRejectError struct {
	// RETRY, BUSY, DENIED, INVALID or QUOTA. A zero code is sent as INVALID, which is how a receiver reads it.
	Code protocol.StreamRejectCode
	// When the opener may try again: QUOTA's wait, or any other code's hint.
	RetryAfter time.Duration
	// This end refused.
	Local bool
}

// The code and the wait.
func (self *StreamRejectError) Error() string {
	return fmt.Sprintf("stream rejected: %s, retry after %s", self.Code, self.RetryAfter)
}

// A stream's ends, as net.Conn's addresses: a client id, network "ur". Ids are opaque (I-13).
type StreamAddr struct {
	ClientId Id
}

var _ net.Addr = (*StreamAddr)(nil)

// "ur".
func (self *StreamAddr) Network() string {
	return "ur"
}

// The client id.
func (self *StreamAddr) String() string {
	return self.ClientId.String()
}

// One stream. See the file header.
type SubprotocolStream struct {
	subprotocol *Subprotocol
	peer        *streamPeer
	peerId      connect.Id
	streamId    uint64
	// a stream with an edge: no Hello either way, its frames from a Service-mode source alone
	edge bool
	// the C15 key every frame on a sidecar stream must carry, the key its open verified under
	clientPublicKey [ed25519.PublicKeySize]byte
	// the peer's verified Hello as the stream opened; nil for an edge
	identity *SubprotocolPeerIdentity
	// what StreamOpen carried: an acceptor's from the opener, an opener's its own
	target   string
	metadata []byte
	ticket   []byte
	// the send option every frame rides: an acceptor's the open's lane, an opener's none
	opts []any
	// serializes writes, so StreamData goes in offset order and StreamClose after the last of it
	writeLock sync.Mutex

	stateLock sync.Mutex
	state     *streamState
	// closed and replaced at each change, so a waiting Read, Write or open looks again
	changed       chan struct{}
	readDeadline  time.Time
	writeDeadline time.Time
	// Close has run: Read and Write answer net.ErrClosed
	closed bool
	// the newest window to send, and whether the sender holds an item for it
	pendingWindow *protocol.StreamWindow
	windowQueued  bool
	// ends an acceptor's accept function early, when the stream ends before it answers
	acceptCancel func()
}

var _ net.Conn = (*SubprotocolStream)(nil)

// A stream over state with the peer behind peer, not yet in its table.
func newSubprotocolStream(subprotocol *Subprotocol, peer *streamPeer, streamId uint64, state *streamState) *SubprotocolStream {
	return &SubprotocolStream{
		subprotocol: subprotocol,
		peer:        peer,
		peerId:      peer.peerId,
		streamId:    streamId,
		edge:        peer.edge,
		state:       state,
		changed:     make(chan struct{}),
	}
}

// The peer's client id.
func (self *SubprotocolStream) PeerId() Id {
	return Id(self.peerId)
}

// The stream's id, unique with its peer for the dispatcher's life (§6.7).
func (self *SubprotocolStream) StreamId() uint64 {
	return self.streamId
}

// Whether the stream runs with an edge, which shows no identity (§6.4).
func (self *SubprotocolStream) Edge() bool {
	return self.edge
}

// A copy of the peer's verified Hello as the stream opened, and false for an edge, which sends none.
func (self *SubprotocolStream) Peer() (*SubprotocolPeerIdentity, bool) {
	if self.identity == nil {
		return nil, false
	}
	return self.identity.clone(), true
}

// StreamOpen.target.
func (self *SubprotocolStream) Target() string {
	return self.target
}

// A copy of StreamOpen.metadata: an edge's open metadata, such as TlsEdgeOpen (§13.5).
func (self *SubprotocolStream) Metadata() []byte {
	return bytes.Clone(self.metadata)
}

// A copy of StreamOpen.ticket: §9's SignedSocketTicket, for the acceptor's admission.
func (self *SubprotocolStream) Ticket() []byte {
	return bytes.Clone(self.ticket)
}

// Wakes every wait on the stream. Under stateLock.
func (self *SubprotocolStream) notifyWithLock() {
	close(self.changed)
	self.changed = make(chan struct{})
}

// Whether deadline has passed on the dispatcher's clock, a zero deadline never.
func (self *SubprotocolStream) expiredWithLock(deadline time.Time) bool {
	return !deadline.IsZero() && !self.subprotocol.clock.Now().Before(deadline)
}

// Waits for changed, deadline on the dispatcher's clock, a zero one being none, or the dispatcher's end.
func (self *SubprotocolStream) wait(changed chan struct{}, deadline time.Time) {
	var expire <-chan time.Time
	if !deadline.IsZero() {
		expire = self.subprotocol.clock.After(deadline.Sub(self.subprotocol.clock.Now()))
	}
	select {
	case <-changed:
	case <-expire:
	case <-self.subprotocol.ctx.Done():
	}
}

// What a call on a stream that has ended returns: the reset or reject that ended it, or, when it finished
// cleanly, net.ErrClosed for a write and io.EOF for a read.
func streamEndError(err error, read bool) error {
	var resetErr *streamResetError
	var rejectErr *streamRejectError
	switch {
	case errors.As(err, &resetErr):
		return &StreamResetError{Code: resetErr.code, Local: resetErr.local}
	case errors.As(err, &rejectErr):
		return &StreamRejectError{Code: rejectErr.code, RetryAfter: time.Duration(rejectErr.retryAfterMs) * time.Millisecond, Local: rejectErr.local}
	case read:
		return io.EOF
	}
	return net.ErrClosed
}

// See net.Conn and the file header.
func (self *SubprotocolStream) Read(b []byte) (int, error) {
	for {
		var frames streamFrames
		var n int
		var err error
		var changed chan struct{}
		var deadline time.Time
		done := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			state := self.state
			switch {
			case state.phase == streamPhaseDone && state.err != nil:
				err = streamEndError(state.err, true)
				return true
			case self.closed:
				err = net.ErrClosed
				return true
			case self.expiredWithLock(self.readDeadline):
				err = os.ErrDeadlineExceeded
				return true
			case len(b) == 0:
				return true
			case state.phase == streamPhaseOpening:
				// an opener before its answer, an acceptor before its accept: nothing to read yet
			default:
				frames, n, err = state.read(b)
				if err != nil && err != io.EOF {
					err = streamEndError(err, true)
				}
				if 0 < n || err != nil {
					self.queueWindowWithLock(frames.window)
					if state.phase == streamPhaseDone {
						self.notifyWithLock()
					}
					return true
				}
			}
			changed = self.changed
			deadline = self.readDeadline
			return false
		}()
		if done {
			self.removeIfDone()
			return n, err
		}
		self.wait(changed, deadline)
	}
}

// See net.Conn and the file header.
func (self *SubprotocolStream) Write(b []byte) (int, error) {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	written := 0
	for {
		var frames streamFrames
		var n int
		var err error
		var changed chan struct{}
		var deadline time.Time
		wait := false
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			state := self.state
			switch {
			case state.phase == streamPhaseDone:
				err = streamEndError(state.err, false)
				return
			case self.closed || state.sendClosed:
				err = net.ErrClosed
				return
			case self.expiredWithLock(self.writeDeadline):
				err = os.ErrDeadlineExceeded
				return
			case written == len(b):
				return
			case state.role == streamRoleAcceptor && state.phase == streamPhaseOpening:
				wait = true
			default:
				frames, n, err = state.write(b[written:])
				if err != nil {
					err = streamEndError(err, false)
					return
				}
				wait = n == 0
			}
			if wait {
				changed = self.changed
				deadline = self.writeDeadline
			}
		}()
		switch {
		case err != nil:
			return written, err
		case wait:
			self.wait(changed, deadline)
			continue
		case n == 0:
			return written, nil
		}
		if err := self.sendFrames(frames); err != nil {
			return written, err
		}
		written += n
	}
}

// Half-closes this end: StreamClose with the final size, every byte written. Reads go on.
func (self *SubprotocolStream) CloseWrite() error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	var frames streamFrames
	var err error
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			err = net.ErrClosed
			return
		}
		if self.state.role == streamRoleAcceptor && self.state.phase == streamPhaseOpening {
			err = errStreamNotAccepted
			return
		}
		frames, err = self.state.closeWrite()
		if err != nil {
			err = streamEndError(err, false)
		}
		self.notifyWithLock()
	}()
	if err != nil {
		return err
	}
	if err := self.sendFrames(frames); err != nil {
		return err
	}
	self.removeIfDone()
	return nil
}

// Sends StreamClose, if this end has not, and stops reading: what the peer still sends is dropped with
// its credit returned, so it can finish, and the peer reads io.EOF. A waiting Read or Write returns
// net.ErrClosed. A second Close answers net.ErrClosed.
func (self *SubprotocolStream) Close() error {
	alreadyClosed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return true
		}
		self.closed = true
		self.notifyWithLock()
		return false
	}()
	if alreadyClosed {
		return net.ErrClosed
	}
	// after a Write that waits has seen closed and let go
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	var frames streamFrames
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state := self.state
		if state.phase == streamPhaseDone {
			return
		}
		if state.role == streamRoleAcceptor && state.phase == streamPhaseOpening {
			// an accept function that keeps nothing it refuses closes an open it has not answered: refuse it
			frames, _ = state.reject(protocol.StreamRejectCode_SR_RETRY, 0)
			self.notifyWithLock()
			return
		}
		if !state.sendClosed {
			frames, _ = state.closeWrite()
		}
		discarded := state.stopReading()
		frames.window = discarded.window
		self.notifyWithLock()
	}()
	err := self.sendFrames(frames)
	self.removeIfDone()
	if err != nil {
		var resetErr *StreamResetError
		if errors.As(err, &resetErr) {
			// the close went with the stream: nothing more to report than that it is closed
			return nil
		}
		return err
	}
	return nil
}

// Resets the stream with code, a zero code being PROTOCOL as a receiver reads it: both directions end at
// once, and bytes in flight are lost. Once ended, a reset sends nothing more.
func (self *SubprotocolStream) Reset(code protocol.StreamResetCode) error {
	self.resetLocal(code)
	return nil
}

// Ends the stream with code from this end and has the stream sender carry StreamReset. False when it had
// ended already.
func (self *SubprotocolStream) resetLocal(code protocol.StreamResetCode) bool {
	var frames streamFrames
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.state.phase == streamPhaseDone {
			return
		}
		frames = self.state.reset(code)
		// counted before anyone waiting sees the reset
		stats := &self.subprotocol.streams.stats
		stats.localResetCount.Add(1)
		switch code {
		case protocol.StreamResetCode_RST_IDENTITY:
			stats.identityResetCount.Add(1)
		case protocol.StreamResetCode_RST_PEER_TIMEOUT:
			stats.peerTimeoutResetCount.Add(1)
		}
		self.notifyWithLock()
	}()
	if frames.reset == nil {
		return false
	}
	self.cancelAccept()
	self.queueFrame(protocol.MessageType_STREAM_RESET, frames.reset)
	self.subprotocol.removeStream(self)
	return true
}

// Ends the stream with code from this end, sending nothing: the dispatcher is closing.
func (self *SubprotocolStream) endLocal(code protocol.StreamResetCode) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.state.reset(code)
		self.notifyWithLock()
	}()
	self.cancelAccept()
}

// Ends an accept function's wait, if one runs.
func (self *SubprotocolStream) cancelAccept() {
	var cancel func()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cancel = self.acceptCancel
		self.acceptCancel = nil
	}()
	if cancel != nil {
		cancel()
	}
}

// Takes the stream out of its peer's table once it has ended.
func (self *SubprotocolStream) removeIfDone() {
	done := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.state.phase == streamPhaseDone
	}()
	if done {
		self.cancelAccept()
		self.subprotocol.removeStream(self)
	}
}

// This end: the dispatcher's client.
func (self *SubprotocolStream) LocalAddr() net.Addr {
	return &StreamAddr{ClientId: Id(self.subprotocol.selfClientId())}
}

// The peer's client.
func (self *SubprotocolStream) RemoteAddr() net.Addr {
	return &StreamAddr{ClientId: Id(self.peerId)}
}

// Both deadlines. See net.Conn.
func (self *SubprotocolStream) SetDeadline(t time.Time) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readDeadline = t
	self.writeDeadline = t
	self.notifyWithLock()
	return nil
}

// See net.Conn. A passed deadline fails Read with os.ErrDeadlineExceeded, and the stream survives it.
func (self *SubprotocolStream) SetReadDeadline(t time.Time) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readDeadline = t
	self.notifyWithLock()
	return nil
}

// See net.Conn, as SetReadDeadline for Write.
func (self *SubprotocolStream) SetWriteDeadline(t time.Time) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.writeDeadline = t
	self.notifyWithLock()
	return nil
}

// One stream frame of messageType carrying body, as this stream sends it: NO_REPLY, never a response
// (reading 4).
func (self *SubprotocolStream) envelope(messageType protocol.MessageType, body []byte) *protocol.Envelope {
	return &protocol.Envelope{
		Version:  WireVersionMajor,
		Type:     uint32(messageType),
		Flags:    EnvelopeFlagNoReply,
		StreamId: self.streamId,
		Body:     body,
	}
}

// The ack callback a frame of this stream carries: an ack error resets the stream with TRANSFER_FAILED
// (§6.7's errors row), and a sent time records its StreamData's stall (D-PROTO-4). Connect calls it on its
// own goroutine, so it never waits.
func (self *SubprotocolStream) ackFunction(sentTime time.Time) connect.AckFunction {
	return func(err error) {
		if err != nil {
			self.resetLocal(protocol.StreamResetCode_RST_TRANSFER_FAILED)
			return
		}
		if !sentTime.IsZero() {
			self.subprotocol.streams.stats.stall.add(self.subprotocol.clock.Now().Sub(sentTime))
		}
	}
}

// Sends what a caller's event asked for, in streamFrames' order, from the caller's goroutine: each waits
// at most PeerSilenceTimeout for connect, past which, or on a send connect refuses, the stream resets with
// TRANSFER_FAILED. A window goes to the stream sender instead, which coalesces it.
func (self *SubprotocolStream) sendFrames(frames streamFrames) error {
	send := func(messageType protocol.MessageType, message proto.Message, stall bool) error {
		body, err := proto.Marshal(message)
		if err != nil {
			return err
		}
		sentTime := time.Time{}
		if stall {
			sentTime = self.subprotocol.clock.Now()
		}
		envelope := self.envelope(messageType, body)
		if err := self.subprotocol.sendEnvelopeAcked(self.peerId, envelope, self.ackFunction(sentTime), self.subprotocol.settings.PeerSilenceTimeout, self.opts...); err != nil {
			self.resetLocal(protocol.StreamResetCode_RST_TRANSFER_FAILED)
			return &StreamResetError{Code: protocol.StreamResetCode_RST_TRANSFER_FAILED, Local: true}
		}
		return nil
	}
	if frames.accept != nil {
		if err := send(protocol.MessageType_STREAM_ACCEPT, frames.accept, false); err != nil {
			return err
		}
	}
	if frames.reject != nil {
		// a refusal that does not go leaves the opener to its own wait
		send(protocol.MessageType_STREAM_REJECT, frames.reject, false)
	}
	for _, data := range frames.data {
		if err := send(protocol.MessageType_STREAM_DATA, data, true); err != nil {
			return err
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.queueWindowWithLock(frames.window)
	}()
	if frames.close != nil {
		if err := send(protocol.MessageType_STREAM_CLOSE, frames.close, false); err != nil {
			return err
		}
	}
	if frames.reset != nil {
		self.queueFrame(protocol.MessageType_STREAM_RESET, frames.reset)
	}
	return nil
}

// Hands the stream sender this stream's newest window, coalescing it with any not yet sent. Under
// stateLock.
func (self *SubprotocolStream) queueWindowWithLock(window *protocol.StreamWindow) {
	if window == nil {
		return
	}
	self.pendingWindow = window
	if self.windowQueued {
		return
	}
	self.windowQueued = true
	self.subprotocol.queueStreamOutbound(&streamOutbound{destinationId: self.peerId, opts: self.opts, stream: self})
}

// The window the stream sender sends now, which it takes, or nil.
func (self *SubprotocolStream) takeWindow() *protocol.StreamWindow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	window := self.pendingWindow
	self.pendingWindow = nil
	self.windowQueued = false
	return window
}

// Puts back a window connect would not take, unless a newer one has come since, and has the sender try
// again.
func (self *SubprotocolStream) restoreWindow(window *protocol.StreamWindow) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.pendingWindow == nil {
		self.pendingWindow = window
	}
	self.windowQueued = true
	// the sender put the item back itself
}

// Queues one frame of this stream for the stream sender.
func (self *SubprotocolStream) queueFrame(messageType protocol.MessageType, message proto.Message) {
	body, err := proto.Marshal(message)
	if err != nil {
		// a reset's two integers always encode
		panic(err)
	}
	self.subprotocol.queueStreamOutbound(&streamOutbound{
		destinationId: self.peerId,
		opts:          self.opts,
		stream:        self,
		envelope:      self.envelope(messageType, body),
	})
}

// One frame from the peer, routed inline: streamState's rule for it, a wake for what waits, and whatever
// that rule asks sent, through the stream sender.
func (self *SubprotocolStream) receive(message proto.Message) {
	var frames streamFrames
	var err error
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state := self.state
		switch frame := message.(type) {
		case *protocol.StreamAccept:
			frames, err = state.receiveAccept(frame)
		case *protocol.StreamReject:
			frames, err = state.receiveReject(frame)
		case *protocol.StreamData:
			frames, err = state.receiveData(frame)
		case *protocol.StreamWindow:
			frames, err = state.receiveWindow(frame)
		case *protocol.StreamClose:
			frames, err = state.receiveClose(frame)
		case *protocol.StreamReset:
			frames, err = state.receiveReset(frame)
		}
		if frames.reset != nil {
			// a frame that broke §6.7's rules: this side resets
			self.subprotocol.streams.stats.localResetCount.Add(1)
		}
		self.queueWindowWithLock(frames.window)
		self.notifyWithLock()
	}()
	if frames.reset != nil {
		self.queueFrame(protocol.MessageType_STREAM_RESET, frames.reset)
	}
	if err != nil && self.subprotocol.log.V(2).Enabled() {
		self.subprotocol.log.Infof("[stream]%s/%d: %s\n", self.peerId, self.streamId, err)
	}
	self.removeIfDone()
}
