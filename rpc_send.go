//go:build !sidecar_http

// What the dispatcher sends: its own answers, through one bounded reply queue and the sender goroutine
// that owns it, and the one call into connect's send path. The inline handler never sends, since a
// send may wait and a receive callback must not (connect/CODESTYLE.md, receive callbacks), so it
// offers a refusal to the queue with zero wait, and a full queue drops it and counts it. Workers queue
// their Pongs and refusals the same way.
//
// The sender serves every peer, so it never waits on one: it hands connect each reply with a zero
// timeout and drops what connect cannot take at once. Every answer here is one a caller can live
// without, since a lost refusal or Pong fails the call at its own deadline, which the caller retries
// with its request_id (§6.6). A reply goes to the request's source, on the request's lane and
// encryption session (peer.TransferKey), as a non-companion contract.

package sidecar

import (
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// connect refused a send and said nothing more: a full queue, or a session the zero wait did not
	// reach.
	errSubprotocolSendRefused = errors.New("subprotocol send refused")
)

// Sends one envelope to destinationId, waiting at most timeout for connect to take it, with ack as
// connect's frame ack and opts as its send options: connect.SendSubprotocolWithTimeout's contract, which
// internal tests stand in for.
type subprotocolSendFunction func(destinationId connect.Id, envelope *protocol.Envelope, ack connect.AckFunction, timeout time.Duration, opts ...any) (bool, error)

// One answer the dispatcher gives itself: a refusal, as type ERROR with an Error of code, a Pong, a
// HelloResult, or a StreamOpen's StreamReject. A refusal's body is built by the sender, so queueing one copies a value and allocates
// nothing; a HelloResult carries its body, built on the worker.
type subprotocolReply struct {
	// the request's source
	destinationId connect.Id
	// the request's peer.TransferKey, which replyLane turns into the reply's send option
	transferKey connect.TransferKey
	// ERROR, PONG or HELLO_RESULT
	messageType protocol.MessageType
	requestId   uint64
	streamId    uint64
	// for ERROR: never ERR_OK, which no sender sets (§6.5)
	code protocol.ErrorCode
	// for HELLO_RESULT: its marshalled HelloResult; for STREAM_REJECT: its StreamReject
	body []byte
	// a stream frame, which carries NO_REPLY and no RESPONSE (reading 4): a StreamReject
	streamFrame bool
}

// The StreamReject of code answering a StreamOpen on streamId, a stream frame.
func streamRejectReply(destinationId connect.Id, transferKey connect.TransferKey, streamId uint64, code protocol.StreamRejectCode) subprotocolReply {
	body, err := proto.Marshal(&protocol.StreamReject{Code: uint32(code)})
	if err != nil {
		// two integers always encode
		panic(err)
	}
	return subprotocolReply{
		destinationId: destinationId,
		transferKey:   transferKey,
		messageType:   protocol.MessageType_STREAM_REJECT,
		streamId:      streamId,
		body:          body,
		streamFrame:   true,
	}
}

// The answer to a request, named by its request_id and stream_id, that this side refuses with code.
func refusalReply(destinationId connect.Id, transferKey connect.TransferKey, requestId uint64, streamId uint64, code protocol.ErrorCode) subprotocolReply {
	return subprotocolReply{
		destinationId: destinationId,
		transferKey:   transferKey,
		messageType:   protocol.MessageType_ERROR,
		requestId:     requestId,
		streamId:      streamId,
		code:          code,
	}
}

// Queues reply with zero wait, or drops it and counts it when the queue is full.
func (self *Subprotocol) offerReply(reply subprotocolReply) {
	select {
	case self.replies <- reply:
		self.stats.replyQueuedCount.Add(1)
	default:
		self.stats.replyDroppedCount.Add(1)
		if self.log.V(1).Enabled() {
			self.log.Infof("[subprotocol]reply to %s dropped: queue full\n", reply.destinationId)
		}
	}
}

// Sends what the queue holds until the Subprotocol closes. Each wait is on the queue or the context,
// so the loop never spins. What is still queued at the end holds no pool buffer, so it is left.
func (self *Subprotocol) runSender() {
	defer close(self.senderDone)
	for {
		select {
		case <-self.ctx.Done():
			return
		case reply := <-self.replies:
			self.sendReply(reply)
		}
	}
}

// Builds reply's envelope and hands it to connect with zero wait.
func (self *Subprotocol) sendReply(reply subprotocolReply) {
	envelope := &protocol.Envelope{
		Version:   WireVersionMajor,
		Type:      uint32(reply.messageType),
		RequestId: reply.requestId,
		Flags:     EnvelopeFlagResponse,
		StreamId:  reply.streamId,
	}
	if reply.streamFrame {
		envelope.Flags = EnvelopeFlagNoReply
	}
	if reply.body != nil {
		envelope.Body = reply.body
	}
	if reply.messageType == protocol.MessageType_ERROR {
		body, err := proto.Marshal(refusalError(reply.code))
		if err != nil {
			self.stats.replyFailedCount.Add(1)
			self.log.Errorf("[subprotocol]reply error body = %s\n", err)
			return
		}
		envelope.Flags |= EnvelopeFlagError
		envelope.Body = body
	}
	if err := self.sendEnvelopeAcked(reply.destinationId, envelope, ignoreSubprotocolAck, 0, self.replyLane(reply.transferKey)); err != nil {
		self.stats.replyFailedCount.Add(1)
		if self.log.V(1).Enabled() {
			self.log.Infof("[subprotocol]reply to %s = %s\n", reply.destinationId, err)
		}
		return
	}
	self.stats.replySentCount.Add(1)
}

// The one place this layer hands connect an envelope: to destinationId, waiting at most timeout for
// connect to take it, 0 meaning not at all, with no ack read. See sendEnvelopeAcked.
func (self *Subprotocol) sendEnvelope(destinationId connect.Id, envelope *protocol.Envelope, timeout time.Duration, opts ...any) error {
	return self.sendEnvelopeAcked(destinationId, envelope, ignoreSubprotocolAck, timeout, opts...)
}

// Hands connect an envelope for destinationId with ack as its frame ack, waiting at most timeout for
// connect to take it, 0 meaning not at all. connect encodes envelope into a pool buffer it takes on
// success and returns on failure, so envelope and its body stay the caller's either way. A refusal
// comes back as connect's error, or errSubprotocolSendRefused when connect gave none.
func (self *Subprotocol) sendEnvelopeAcked(destinationId connect.Id, envelope *protocol.Envelope, ack connect.AckFunction, timeout time.Duration, opts ...any) error {
	if len(opts) == 0 {
		// an initiated send: the peer's lane (rpc_subprotocol.go's peerLaneOpts)
		opts = self.peerLaneOpts(destinationId)
	}
	sent, err := self.send(destinationId, envelope, ack, timeout, opts...)
	if err != nil {
		return err
	}
	if !sent {
		return errSubprotocolSendRefused
	}
	return nil
}

// Sends through connect, the envelope's size held to §6.5 by envelopeCodec.
func (self *Subprotocol) connectSend(destinationId connect.Id, envelope *protocol.Envelope, ack connect.AckFunction, timeout time.Duration, opts ...any) (bool, error) {
	return connect.SendSubprotocolWithTimeout(self.client, SubprotocolId, envelope, destinationId, ack, timeout, opts...)
}

// The ack callback of a send whose ack nothing reads: a transfer ack says connect delivered a frame,
// never that anyone acted on it (R-PROTO-10), and nothing waits on a refusal's or a Pong's.
func ignoreSubprotocolAck(err error) {
}
