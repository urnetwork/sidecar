// §6.7's fenced rules as pure code (R-PROTO-9, R-PROTO-10, D-PROTO-4): one stream's two halves, their
// offsets and final sizes, the windows its receiver grants and the credit behind them, the open and its
// answers, and the codes it ends with. Nothing here sends, waits or names a connect type: each event
// answers what the wire layer (PROTO-M5-02) sends, so these rules hold before streams have a wire.
//
// The rows, as the machine holds them:
//
//   - offsets: per direction, from 0, early_data first. StreamData.offset is data[0]'s, consumed_offset
//     the bytes the reader took (the delivery ack, R-PROTO-10), offset + len(data) never passes
//     max_offset, and final_offset counts every byte sent, QUIC's final size. Data past max_offset or a
//     known final offset, or a final offset that changes, is below the bytes received or passes the
//     window, resets with PROTOCOL. One sequence per peer delivers in order (C7's lanes are Later), so data
//     that skips ahead of the bytes received resets with PROTOCOL as well; data repeating bytes already
//     received is taken from where they end.
//   - open: data to the acceptor runs to its Hello.initial_window, StreamInitialWindowByteCount without
//     one, as from edges, until StreamAccept.window replaces it, the part before the accept held against
//     the acceptor's peer credit and discarded on reject; data to the opener runs to StreamOpen.window.
//     Both windows are offsets, as max_offset is.
//   - window: a receiver commits its minimum window of peer and process credit before it sends a window,
//     else the acceptor answers StreamReject{BUSY} and the opener fails locally with RESOURCE_EXHAUSTED.
//     Each StreamWindow then keeps max_offset - consumed_offset between that minimum and the stream's
//     maximum (stream_credit.go), doubling while the reader keeps up, and max_offset never falls.
//   - codes: a zero or unknown reject reads as INVALID, a zero or unknown reset as PROTOCOL
//     (envelope_codes.go), never as retry or drain.
//
// The credit a stream holds is its window's room, max_offset - consumed_offset, or final_offset -
// consumed_offset once the peer's final size is known, and none once the stream is done. Every path that
// ends a stream, a reset either way, a reject, or both halves closed and read, gives it back.
//
// Not safe for concurrent use: the wire layer holds each stream under its own lock.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/urnetwork/sidecar/protocol"
)

// The most StreamOpen.early_data carries (§6.5's StreamOpen budget).
const MaxStreamEarlyDataByteCount = 2048

var (
	// A frame that breaks §6.7's offset or open rules: the stream resets with PROTOCOL.
	errStreamProtocol = errors.New("stream protocol violation")
	// Early data past MaxStreamEarlyDataByteCount or the acceptor's initial window, which no StreamOpen
	// may carry.
	errStreamEarlyData = errors.New("stream early data past its bound")
	// A write after this side's half-close.
	errStreamClosed = errors.New("stream closed for writing")
	// A write or close by an acceptor that has not accepted.
	errStreamNotAccepted = errors.New("stream not accepted")
	// Anything after a stream finished cleanly, both halves closed and read.
	errStreamDone = errors.New("stream done")
	// Ids with a peer whose client id is this side's own, which no parity separates.
	errStreamIdsSelf = errors.New("stream ids with oneself")
	// An id the peer may not open: this side's parity, or not past every id it opened before.
	errStreamIdReused = errors.New("stream id reused")
	// Every id of this side's parity spent.
	errStreamIdsExhausted = errors.New("stream ids exhausted")
)

// A stream ended by a reset, from either side.
type streamResetError struct {
	code protocol.StreamResetCode
	// sent by this side
	local bool
}

// Names the code and which side sent it.
func (self *streamResetError) Error() string {
	if self.local {
		return fmt.Sprintf("stream reset here: %s", self.code)
	}
	return fmt.Sprintf("stream reset by peer: %s", self.code)
}

// A stream its acceptor refused.
type streamRejectError struct {
	code         protocol.StreamRejectCode
	retryAfterMs uint32
	// refused by this side
	local bool
}

// Names the code and the wait the acceptor asked for.
func (self *streamRejectError) Error() string {
	return fmt.Sprintf("stream rejected: %s, retry after %d ms", self.code, self.retryAfterMs)
}

// Which side opened a stream.
type streamRole int

const (
	streamRoleOpener   streamRole = 1
	streamRoleAcceptor streamRole = 2
)

// How far a stream has gone.
type streamPhase int

const (
	// The opener has sent StreamOpen, or the acceptor taken it, and neither has its answer.
	streamPhaseOpening streamPhase = 1
	// Accepted: both halves run within their windows.
	streamPhaseOpen streamPhase = 2
	// Rejected, reset, or both halves closed and read: nothing more flows, and its credit is back.
	streamPhaseDone streamPhase = 3
)

// What one event asks the wire layer to send, in this order.
type streamFrames struct {
	accept *protocol.StreamAccept
	reject *protocol.StreamReject
	data   []*protocol.StreamData
	window *protocol.StreamWindow
	close  *protocol.StreamClose
	reset  *protocol.StreamReset
}

// One stream's state.
type streamState struct {
	streamId uint64
	role     streamRole
	phase    streamPhase
	credit   *streamCredit

	// the receive half
	receivedOffset uint64
	maxOffset      uint64
	consumedOffset uint64
	finalOffset    uint64
	finalKnown     bool
	// whether a StreamWindow has acked the peer's every byte
	finalAcked bool
	// the credit held: the window's room
	committed int64
	// the window aimed for, max_offset - consumed_offset after each StreamWindow
	window int64
	buffer streamBuffer

	// the send half
	sentOffset         uint64
	sendMaxOffset      uint64
	peerConsumedOffset uint64
	sendClosed         bool

	// why it ended: a reset or a reject; nil while it runs or once it finished cleanly
	err error
}

// A window as StreamOpen and StreamAccept carry it.
func streamWindowField(offset uint64) uint32 {
	return uint32(min(offset, math.MaxUint32))
}

// Opens a stream this side starts. It commits the minimum window before StreamOpen carries it, else
// errStreamCreditExhausted, which the opener answers locally as RESOURCE_EXHAUSTED. peerInitialWindow is
// the acceptor's Hello.initial_window, zero for none, as toward an edge, when
// StreamInitialWindowByteCount stands in. earlyByteCount is StreamOpen.early_data's, its first bytes,
// at most MaxStreamEarlyDataByteCount and within that window. Answers StreamOpen's window.
func newStreamOpener(streamId uint64, credit *streamCredit, peerInitialWindow uint32, earlyByteCount int) (*streamState, uint32, error) {
	sendMaxOffset := uint64(peerInitialWindow)
	if peerInitialWindow == 0 {
		sendMaxOffset = uint64(credit.settings.StreamInitialWindowByteCount)
	}
	if earlyByteCount < 0 || MaxStreamEarlyDataByteCount < earlyByteCount || sendMaxOffset < uint64(earlyByteCount) {
		return nil, 0, fmt.Errorf("%w: %d B", errStreamEarlyData, earlyByteCount)
	}
	credit.openStream()
	window := credit.minWindowByteCount()
	if !credit.commit(window) {
		credit.closeStream()
		return nil, 0, errStreamCreditExhausted
	}
	self := &streamState{
		streamId:      streamId,
		role:          streamRoleOpener,
		phase:         streamPhaseOpening,
		credit:        credit,
		maxOffset:     uint64(window),
		committed:     window,
		window:        window,
		sentOffset:    uint64(earlyByteCount),
		sendMaxOffset: sendMaxOffset,
	}
	return self, streamWindowField(self.maxOffset), nil
}

// Takes a stream the peer opened. It holds this side's initial window, what its Hello advertised and the
// window without a Hello, against the peer's credit for what comes before the accept, early_data first.
// One that cannot hold it is answered StreamReject{BUSY} at once; early data past
// MaxStreamEarlyDataByteCount or that window resets with PROTOCOL. The id is the caller's to have
// checked with streamIds.accept.
func newStreamAcceptor(streamId uint64, credit *streamCredit, open *protocol.StreamOpen) (*streamState, streamFrames) {
	self := &streamState{
		streamId:      streamId,
		role:          streamRoleAcceptor,
		phase:         streamPhaseOpening,
		credit:        credit,
		sendMaxOffset: uint64(open.GetWindow()),
	}
	credit.openStream()
	initial := credit.settings.StreamInitialWindowByteCount
	if !credit.commit(initial) {
		frames := streamFrames{reject: &protocol.StreamReject{Code: uint32(protocol.StreamRejectCode_SR_BUSY)}}
		self.end(&streamRejectError{code: protocol.StreamRejectCode_SR_BUSY, local: true})
		return self, frames
	}
	self.maxOffset = uint64(initial)
	self.committed = initial
	self.window = initial
	earlyData := open.GetEarlyData()
	if MaxStreamEarlyDataByteCount < len(earlyData) || self.maxOffset < uint64(len(earlyData)) {
		return self, self.resetWith(protocol.StreamResetCode_RST_PROTOCOL)
	}
	self.buffer.append(earlyData)
	self.receivedOffset = uint64(len(earlyData))
	return self, streamFrames{}
}

// Ends the stream: drops what is unread, gives back its credit, and records why.
func (self *streamState) end(err error) {
	if self.phase == streamPhaseDone {
		return
	}
	self.buffer.discard()
	self.credit.release(self.committed)
	self.committed = 0
	self.credit.closeStream()
	self.phase = streamPhaseDone
	self.err = err
}

// Resets the stream from this side: StreamReset with code and the final size of what it sent.
func (self *streamState) resetWith(code protocol.StreamResetCode) streamFrames {
	frames := streamFrames{reset: &protocol.StreamReset{Code: uint32(code), FinalOffset: self.sentOffset}}
	self.end(&streamResetError{code: code, local: true})
	return frames
}

// A frame broke §6.7's rules: reset with PROTOCOL.
func (self *streamState) protocolReset(format string, a ...any) (streamFrames, error) {
	frames := self.resetWith(protocol.StreamResetCode_RST_PROTOCOL)
	return frames, fmt.Errorf("%w: %s", errStreamProtocol, fmt.Sprintf(format, a...))
}

// What an event on a stream already done answers: why it ended, or errStreamDone.
func (self *streamState) doneErr() error {
	if self.err != nil {
		return self.err
	}
	return errStreamDone
}

// The acceptor's yes. It commits the minimum window, the credit held before the accept counting toward
// it, and answers StreamAccept with max_offset; without the credit it answers StreamReject{BUSY}
// instead, the data before the accept discarded and its credit given back. An opener that has already
// closed sends nothing past its final size, so then nothing more is committed.
func (self *streamState) accept() (streamFrames, error) {
	switch {
	case self.phase == streamPhaseDone:
		return streamFrames{}, self.doneErr()
	case self.role != streamRoleAcceptor || self.phase != streamPhaseOpening:
		return streamFrames{}, errStreamNotAccepted
	}
	window := self.credit.minWindowByteCount()
	if maxOffset := self.consumedOffset + uint64(window); !self.finalKnown && self.maxOffset < maxOffset {
		extra := int64(maxOffset - self.maxOffset)
		if !self.credit.commit(extra) {
			return self.reject(protocol.StreamRejectCode_SR_BUSY, 0)
		}
		self.maxOffset = maxOffset
		self.committed += extra
	}
	self.window = window
	self.phase = streamPhaseOpen
	return streamFrames{accept: &protocol.StreamAccept{Window: streamWindowField(self.maxOffset)}}, nil
}

// The acceptor's no, with code, a zero code being INVALID, as a receiver would read it: the data before
// the accept is discarded and its credit given back.
func (self *streamState) reject(code protocol.StreamRejectCode, retryAfterMs uint32) (streamFrames, error) {
	switch {
	case self.phase == streamPhaseDone:
		return streamFrames{}, self.doneErr()
	case self.role != streamRoleAcceptor || self.phase != streamPhaseOpening:
		return streamFrames{}, errStreamNotAccepted
	}
	code = readStreamRejectCode(uint32(code))
	frames := streamFrames{reject: &protocol.StreamReject{Code: uint32(code), RetryAfterMs: retryAfterMs}}
	err := &streamRejectError{code: code, retryAfterMs: retryAfterMs, local: true}
	self.end(err)
	return frames, err
}

// The opener's answer: the acceptor's window replaces the initial one, never lowering what the opener
// may already send.
func (self *streamState) receiveAccept(accept *protocol.StreamAccept) (streamFrames, error) {
	switch {
	case self.phase == streamPhaseDone:
		return streamFrames{}, nil
	case self.role != streamRoleOpener || self.phase != streamPhaseOpening:
		return self.protocolReset("an accept the stream did not ask for")
	}
	self.sendMaxOffset = max(self.sendMaxOffset, uint64(accept.GetWindow()))
	self.phase = streamPhaseOpen
	return streamFrames{}, nil
}

// The opener's refusal: the stream ends with the acceptor's code and wait.
func (self *streamState) receiveReject(reject *protocol.StreamReject) (streamFrames, error) {
	switch {
	case self.phase == streamPhaseDone:
		return streamFrames{}, nil
	case self.role != streamRoleOpener || self.phase != streamPhaseOpening:
		return self.protocolReset("a reject after the open was answered")
	}
	err := &streamRejectError{code: readStreamRejectCode(reject.GetCode()), retryAfterMs: reject.GetRetryAfterMs()}
	self.end(err)
	return streamFrames{}, err
}

// Bytes from the peer, into the buffer, within the window and the final size (§6.7's offsets row).
// Before the accept the acceptor takes them against its initial window; the opener takes none, since an
// acceptor sends nothing before it accepts.
func (self *streamState) receiveData(data *protocol.StreamData) (streamFrames, error) {
	if self.phase == streamPhaseDone {
		return streamFrames{}, nil
	}
	if self.role == streamRoleOpener && self.phase == streamPhaseOpening {
		return self.protocolReset("data before the accept")
	}
	payload := data.GetData()
	offset := data.GetOffset()
	switch {
	case MaxStreamDataByteCount < len(payload):
		return self.protocolReset("data of %d B", len(payload))
	case self.receivedOffset < offset:
		return self.protocolReset("data at %d past the %d received", offset, self.receivedOffset)
	case math.MaxUint64-offset < uint64(len(payload)):
		return self.protocolReset("data past every offset")
	}
	end := offset + uint64(len(payload))
	switch {
	case self.maxOffset < end:
		return self.protocolReset("data to %d past max_offset %d", end, self.maxOffset)
	case self.finalKnown && self.finalOffset < end:
		return self.protocolReset("data to %d past the final size %d", end, self.finalOffset)
	case end <= self.receivedOffset:
		return streamFrames{}, nil
	}
	self.buffer.append(payload[self.receivedOffset-offset:])
	self.receivedOffset = end
	return streamFrames{}, nil
}

// A window from the peer: consumed_offset its reader's delivery ack, max_offset how far this side may
// send. Neither falls; a consumed offset past what this side sent, or past the window it names, resets
// with PROTOCOL. A stream that finished cleanly still takes the ack, which is how its last bytes are
// known delivered, and nothing else.
func (self *streamState) receiveWindow(window *protocol.StreamWindow) (streamFrames, error) {
	consumedOffset := window.GetConsumedOffset()
	if self.phase == streamPhaseDone {
		if self.err == nil && consumedOffset <= self.sentOffset {
			self.peerConsumedOffset = max(self.peerConsumedOffset, consumedOffset)
		}
		return streamFrames{}, nil
	}
	if self.sentOffset < consumedOffset || window.GetMaxOffset() < consumedOffset {
		return self.protocolReset("consumed %d of %d sent, window %d", consumedOffset, self.sentOffset, window.GetMaxOffset())
	}
	self.peerConsumedOffset = max(self.peerConsumedOffset, consumedOffset)
	self.sendMaxOffset = max(self.sendMaxOffset, window.GetMaxOffset())
	return streamFrames{}, nil
}

// The peer's half-close and its final size, which may not fall below the bytes received, pass the
// window, or change. The window's room past it goes back, since nothing comes past a final size.
func (self *streamState) receiveClose(close *protocol.StreamClose) (streamFrames, error) {
	if self.phase == streamPhaseDone {
		return streamFrames{}, nil
	}
	if self.role == streamRoleOpener && self.phase == streamPhaseOpening {
		return self.protocolReset("a close before the accept")
	}
	finalOffset := close.GetFinalOffset()
	switch {
	case finalOffset < self.receivedOffset:
		return self.protocolReset("final size %d below the %d received", finalOffset, self.receivedOffset)
	case self.maxOffset < finalOffset:
		return self.protocolReset("final size %d past max_offset %d", finalOffset, self.maxOffset)
	case self.finalKnown && finalOffset != self.finalOffset:
		return self.protocolReset("final size %d after %d", finalOffset, self.finalOffset)
	}
	self.finalOffset = finalOffset
	self.finalKnown = true
	if room := int64(finalOffset - self.consumedOffset); room < self.committed {
		self.credit.release(self.committed - room)
		self.committed = room
	}
	self.finishIfDone()
	return streamFrames{}, nil
}

// The peer's reset: the stream ends at once, unread bytes dropped and credit given back, with the
// peer's code, read as PROTOCOL when it is zero or unknown, or when the final size it names breaks the
// offsets row.
func (self *streamState) receiveReset(reset *protocol.StreamReset) (streamFrames, error) {
	if self.phase == streamPhaseDone {
		return streamFrames{}, nil
	}
	code := readStreamResetCode(reset.GetCode())
	finalOffset := reset.GetFinalOffset()
	if finalOffset < self.receivedOffset || (self.finalKnown && finalOffset != self.finalOffset) {
		code = protocol.StreamResetCode_RST_PROTOCOL
	}
	err := &streamResetError{code: code}
	self.end(err)
	return streamFrames{}, err
}

// Writes as much of p as the peer's window allows now, as StreamData of at most MaxStreamDataByteCount,
// and answers how much they carry; the rest waits for a StreamWindow. The opener may write before the
// accept, within the acceptor's initial window; the acceptor writes nothing until it accepts.
func (self *streamState) write(p []byte) (streamFrames, int, error) {
	switch {
	case self.phase == streamPhaseDone:
		return streamFrames{}, 0, self.doneErr()
	case self.sendClosed:
		return streamFrames{}, 0, errStreamClosed
	case self.role == streamRoleAcceptor && self.phase == streamPhaseOpening:
		return streamFrames{}, 0, errStreamNotAccepted
	}
	n := int(min(uint64(len(p)), self.sendMaxOffset-self.sentOffset))
	frames := streamFrames{}
	for written := 0; written < n; {
		size := min(n-written, MaxStreamDataByteCount)
		frames.data = append(frames.data, &protocol.StreamData{Offset: self.sentOffset, Data: bytes.Clone(p[written : written+size])})
		self.sentOffset += uint64(size)
		written += size
	}
	return frames, n, nil
}

// Half-closes this side: StreamClose with the final size, every byte written.
func (self *streamState) closeWrite() (streamFrames, error) {
	switch {
	case self.phase == streamPhaseDone:
		return streamFrames{}, self.doneErr()
	case self.sendClosed:
		return streamFrames{}, errStreamClosed
	case self.role == streamRoleAcceptor && self.phase == streamPhaseOpening:
		return streamFrames{}, errStreamNotAccepted
	}
	self.sendClosed = true
	frames := streamFrames{close: &protocol.StreamClose{FinalOffset: self.sentOffset}}
	self.finishIfDone()
	return frames, nil
}

// Resets the stream from this side with code, a zero code being PROTOCOL.
func (self *streamState) reset(code protocol.StreamResetCode) streamFrames {
	if self.phase == streamPhaseDone {
		return streamFrames{}
	}
	return self.resetWith(readStreamResetCode(uint32(code)))
}

// Moves up to len(p) received bytes into p, giving back their credit. It answers a StreamWindow when
// the window needs extending, and once the reader has every byte of a closed peer, one acking them all;
// then io.EOF, which a clean finish answers from then on.
func (self *streamState) read(p []byte) (streamFrames, int, error) {
	if self.phase == streamPhaseDone {
		if self.err != nil {
			return streamFrames{}, 0, self.err
		}
		return streamFrames{}, 0, io.EOF
	}
	n := self.buffer.read(p)
	self.consumedOffset += uint64(n)
	self.committed -= int64(n)
	self.credit.release(int64(n))
	frames := streamFrames{window: self.extendWindow(self.buffer.len() == 0)}
	if self.finalKnown && self.consumedOffset == self.finalOffset {
		if !self.finalAcked {
			self.finalAcked = true
			if frames.window == nil {
				frames.window = &protocol.StreamWindow{ConsumedOffset: self.consumedOffset, MaxOffset: self.maxOffset}
			}
		}
		self.finishIfDone()
		if n == 0 {
			return frames, 0, io.EOF
		}
	}
	return frames, n, nil
}

// A StreamWindow once the room left, max_offset - consumed_offset, falls below half the window aimed
// for: max_offset moves to consumed_offset plus that window, doubled first while the reader keeps up,
// within the stream's minimum and maximum. If the doubled window's credit is not there it keeps the one
// it had, and if that is not there either it sends nothing and the peer waits. Never once the peer's
// final size is known, past which it sends nothing, nor before an accept.
func (self *streamState) extendWindow(keptUp bool) *protocol.StreamWindow {
	if self.finalKnown || self.phase != streamPhaseOpen {
		return nil
	}
	if room := int64(self.maxOffset - self.consumedOffset); self.window/2 <= room {
		return nil
	}
	minWindow := self.credit.minWindowByteCount()
	maxWindow := self.credit.maxWindowByteCount()
	windows := []int64{max(self.window, minWindow)}
	if keptUp {
		windows = append([]int64{min(max(self.window*2, minWindow), maxWindow)}, windows...)
	}
	for _, window := range windows {
		maxOffset := self.consumedOffset + uint64(window)
		if maxOffset <= self.maxOffset {
			continue
		}
		extra := int64(maxOffset - self.maxOffset)
		if !self.credit.commit(extra) {
			continue
		}
		self.maxOffset = maxOffset
		self.committed += extra
		self.window = window
		return &protocol.StreamWindow{ConsumedOffset: self.consumedOffset, MaxOffset: self.maxOffset}
	}
	return nil
}

// Ends the stream cleanly once both halves are through: this side closed, and the peer's final size
// known and read.
func (self *streamState) finishIfDone() {
	if self.phase == streamPhaseDone || !self.sendClosed || !self.finalKnown || self.consumedOffset != self.finalOffset {
		return
	}
	self.end(nil)
}

// §6.7's stream ids with one peer: uint64, never reused, even from the side with the lower client id and
// odd from the other, so the two never open one id. Zero is no stream, the envelope's stream_id on
// everything but stream frames, so even ids start at 2. Not safe for concurrent use: the wire layer holds
// it with its peer.
type streamIds struct {
	// the next id this side opens
	next uint64
	// the least id the peer may open next
	peerNext      uint64
	exhausted     bool
	peerExhausted bool
}

// The ids between this side's client and its peer's.
func newStreamIds(clientId Id, peerClientId Id) (*streamIds, error) {
	switch clientId.Cmp(peerClientId) {
	case 0:
		return nil, errStreamIdsSelf
	case -1:
		return &streamIds{next: 2, peerNext: 1}, nil
	}
	return &streamIds{next: 1, peerNext: 2}, nil
}

// The next id this side opens. Once its parity's ids are spent, an error, never a reuse.
func (self *streamIds) open() (uint64, error) {
	if self.exhausted {
		return 0, errStreamIdsExhausted
	}
	streamId := self.next
	if math.MaxUint64-2 < self.next {
		self.exhausted = true
	} else {
		self.next += 2
	}
	return streamId, nil
}

// Takes an id the peer opens: of the peer's parity, and past every id it opened before. Anything else
// is a reuse, which the open's answer resets with PROTOCOL.
func (self *streamIds) accept(streamId uint64) error {
	if self.peerExhausted || streamId%2 != self.peerNext%2 || streamId < self.peerNext {
		return errStreamIdReused
	}
	if math.MaxUint64-2 < streamId {
		self.peerExhausted = true
	} else {
		self.peerNext = streamId + 2
	}
	return nil
}
