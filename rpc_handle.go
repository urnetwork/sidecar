//go:build !sidecar_http

// Peer RPC, the receiver's half (§6.6): Handle registers a function for one request type, which the
// dispatcher calls for each complete request of that type from a verified peer. The source's worker
// hands each request to a handler goroutine of its own, so a long handler holds up neither that peer's
// other requests nor the Cancel that names it; handlers in flight per peer are bounded by
// PeerQueueMessageCount, past which a request answers RESOURCE_EXHAUSTED.
//
// A handler's ctx ends at the request's timeout_ms from its arrival, on this side's clock, at a Cancel
// that names it (best effort, reading 4), or when the Subprotocol closes. Its answer goes back as
// RESPONSE with the request's type + 1, chunked past 4,016 B, on the request's lane; a failure goes back
// as RESPONSE, ERROR, type ERROR and an Error body. A mutating handler's answers are kept by
// rpc_idempotency.go, so a retry runs nothing twice.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A type the dispatcher answers itself, a push type, or a response type: no handler takes one.
	errHandleType = errors.New("subprotocol: no handler takes this type")
	// Why a handler's ctx ended: the request's timeout_ms passed.
	errHandlerDeadline = errors.New("subprotocol: the request's deadline passed")
	// Why a handler's ctx ended: its caller sent Cancel.
	errHandlerCancelled = errors.New("subprotocol: the caller cancelled")
)

// One request, as a handler gets it. Borrowed for the call: Body is valid until the handler returns, so
// a handler that keeps it copies it (R-PROTO-7).
type SubprotocolRequest struct {
	// The peer, as connect authenticated it.
	SourceId Id
	// The peer's verified Hello, as its gate stood when the request arrived.
	Peer        *SubprotocolPeerIdentity
	MessageType protocol.MessageType
	RequestId   uint64
	Body        []byte
	// Set by a mutating handler whose response is past IdempotencyMaxResponseByteCount: a retry of the
	// call is answered Error{ALREADY_EXISTS} with this ref instead of the response, which is not kept.
	ResultRef []byte
}

// Serves one request. An error that is a *SubprotocolError answers with its code, message, retry-after
// and result_ref; any other answers UNAVAILABLE and names nothing of the error.
type SubprotocolHandler func(ctx context.Context, request *SubprotocolRequest) ([]byte, error)

// How a request type is served. SEARCH is served by its own rules whatever these say (rpc_search.go).
type HandleOptions struct {
	// The handler changes state, so a retry must not run it twice: its answers are kept by (source,
	// request_id) for IdempotencyTimeout within the caps, and a retry while it runs joins it (§6.6).
	Mutating bool
}

// Whether a type is one no handler may take: the dispatcher's own, a push type, or 0.
func handleTypeReserved(messageType protocol.MessageType) bool {
	switch messageType {
	case protocol.MessageType_MESSAGE_TYPE_NONE,
		protocol.MessageType_HELLO, protocol.MessageType_HELLO_RESULT,
		protocol.MessageType_PING, protocol.MessageType_PONG,
		protocol.MessageType_CANCEL, protocol.MessageType_ERROR:
		return true
	}
	return pushMessageType(uint32(messageType))
}

// Serves every request of messageType from a verified peer with handler; remove takes it away. One
// handler per type.
func (self *Subprotocol) Handle(messageType protocol.MessageType, handler SubprotocolHandler, options *HandleOptions) (remove func(), err error) {
	if handler == nil || handleTypeReserved(messageType) {
		return nil, errHandleType
	}
	if options == nil {
		options = &HandleOptions{}
	}
	handleOptions := *options
	if messageType == protocol.MessageType_SEARCH {
		// SEARCH's rules key on its type, whatever the options (rpc_search.go): it mutates nothing, so a
		// retry is answered from the indexer's cursor, and its sizes are fixed below its handler
		handleOptions.Mutating = false
		handler = searchHandler(handler, self.settings.Search, self.log)
	}
	return self.setMessageTypeDispatch(messageType, func(ctx context.Context, message *subprotocolMessage) {
		self.dispatchRequest(handler, &handleOptions, message)
	})
}

// On the source's worker: answers from the idempotency cache, joins a live run, or starts the handler.
func (self *Subprotocol) dispatchRequest(handler SubprotocolHandler, options *HandleOptions, message *subprotocolMessage) {
	envelope := message.envelope
	if !message.answerable() {
		self.stats.unroutedCount.Add(1)
		return
	}
	key := rpcCallKey{sourceId: message.sourceId, requestId: envelope.RequestId}
	timeout := time.Duration(envelope.TimeoutMs) * time.Millisecond
	if timeout <= 0 || MaxCallTimeout < timeout {
		timeout = min(max(timeout, self.settings.DefaultCallTimeout), MaxCallTimeout)
	}
	deadline := message.arrivalTime.Add(timeout)
	reply := &rpcReplyTarget{
		destinationId: message.sourceId,
		transferKey:   message.transferKey,
		messageType:   protocol.MessageType(envelope.Type),
		requestId:     envelope.RequestId,
		deadline:      deadline,
	}

	var entry *idempotencyEntry
	if options.Mutating {
		var begin idempotencyBegin
		begin, entry = self.idempotency.begin(key)
		switch begin {
		case idempotencyAnswered:
			self.stats.idempotentAnswerCount.Add(1)
			self.sendOutcome(reply, entry.outcome, true)
			return
		case idempotencyJoin:
			self.stats.idempotentJoinCount.Add(1)
			self.handlers.Add(1)
			go func() {
				defer self.handlers.Done()
				select {
				case <-entry.done:
					self.sendOutcome(reply, entry.outcome, true)
				case <-self.ctx.Done():
				}
			}()
			return
		}
	}

	handlerCtx, cancel := context.WithCancelCause(self.ctx)
	if !self.startRun(key, cancel) {
		cancel(nil)
		if entry != nil {
			self.idempotency.finish(entry, self.idempotency.outcomeOf(nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED}, nil))
		}
		self.sendRefusal(reply, &SubprotocolError{Code: protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED})
		return
	}
	stopTimer := self.clock.AfterFunc(deadline.Sub(self.clock.Now()), func() {
		cancel(errHandlerDeadline)
	})
	var peer *SubprotocolPeerIdentity
	if identity, ok := self.PeerIdentity(Id(message.sourceId)); ok {
		peer = identity
	}
	request := &SubprotocolRequest{
		SourceId:    Id(message.sourceId),
		Peer:        peer,
		MessageType: protocol.MessageType(envelope.Type),
		RequestId:   envelope.RequestId,
		// the worker's buffer goes back when this returns, and the handler runs on
		Body: bytes.Clone(envelope.Body),
	}
	self.handlers.Add(1)
	go func() {
		defer self.handlers.Done()
		defer cancel(nil)
		defer stopTimer()
		defer self.endRun(key)
		body, err := self.runHandler(handlerCtx, handler, request)
		refusal := handlerRefusal(handlerCtx, err)
		outcome := &idempotencyOutcome{body: body, refusal: refusal}
		if entry != nil {
			outcome = self.idempotency.outcomeOf(body, refusal, request.ResultRef)
			self.idempotency.finish(entry, outcome)
			// the first answer carries the whole response, kept or not
			outcome = &idempotencyOutcome{body: body, refusal: refusal}
		}
		if refusal != nil && refusal.Code == protocol.ErrorCode_ERR_CANCELLED {
			// the caller gave up: nothing it would read
			return
		}
		self.sendOutcome(reply, outcome, false)
	}()
}

// Calls handler, keeping its panic to this request, which then answers UNAVAILABLE.
func (self *Subprotocol) runHandler(ctx context.Context, handler SubprotocolHandler, request *SubprotocolRequest) (body []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			self.stats.panicCount.Add(1)
			self.log.Errorf("[subprotocol]handler of type %d panic = %v\n", request.MessageType, r)
			body, err = nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
		}
	}()
	return handler(ctx, request)
}

// The refusal a handler's error answers with: its own code when it is a sender's, the ctx's end when
// the ctx ended, else UNAVAILABLE, naming nothing of the error (I-7).
func handlerRefusal(ctx context.Context, err error) *SubprotocolError {
	if err == nil {
		return nil
	}
	var subprotocolError *SubprotocolError
	if errors.As(err, &subprotocolError) && senderCode(protocol.ErrorCode_name, uint32(subprotocolError.Code)) {
		return &SubprotocolError{
			Code:       subprotocolError.Code,
			Message:    subprotocolError.Message,
			RetryAfter: subprotocolError.RetryAfter,
			ResultRef:  subprotocolError.ResultRef,
		}
	}
	if ctx.Err() != nil {
		if errors.Is(context.Cause(ctx), errHandlerCancelled) {
			return &SubprotocolError{Code: protocol.ErrorCode_ERR_CANCELLED}
		}
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED}
	}
	return &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE}
}

// Where a handler's answer goes: the request's source, on its lane, until its deadline.
type rpcReplyTarget struct {
	destinationId connect.Id
	transferKey   connect.TransferKey
	messageType   protocol.MessageType
	requestId     uint64
	deadline      time.Time
}

// Sends an outcome: the body as the request's type + 1, or the refusal. A retry answered from memory
// gets ALREADY_EXISTS for a response that was too large to keep.
func (self *Subprotocol) sendOutcome(reply *rpcReplyTarget, outcome *idempotencyOutcome, retry bool) {
	if retry && (outcome.uncached || outcome.refusal != nil) {
		self.sendRefusal(reply, outcome.retryRefusal())
		return
	}
	if outcome.refusal != nil {
		self.sendRefusal(reply, outcome.refusal)
		return
	}
	envelopes, err := chunkBody(&protocol.Envelope{
		Version:   WireVersionMajor,
		Type:      uint32(reply.messageType + 1),
		RequestId: reply.requestId,
		Flags:     EnvelopeFlagResponse,
	}, outcome.body)
	if err != nil {
		self.sendRefusal(reply, &SubprotocolError{Code: protocol.ErrorCode_ERR_TOO_LARGE})
		return
	}
	for _, envelope := range envelopes {
		if !self.sendReplyEnvelope(reply, envelope) {
			return
		}
	}
}

// Sends one Error answering reply's request.
func (self *Subprotocol) sendRefusal(reply *rpcReplyTarget, refusal *SubprotocolError) {
	refusalBody := refusalError(refusal.Code)
	refusalBody.Message = refusal.Message
	refusalBody.RetryAfterMs = uint32(refusal.RetryAfter / time.Millisecond)
	refusalBody.ResultRef = refusal.ResultRef
	body, err := proto.Marshal(refusalBody)
	if err != nil {
		self.stats.replyFailedCount.Add(1)
		return
	}
	self.sendReplyEnvelope(reply, &protocol.Envelope{
		Version:   WireVersionMajor,
		Type:      uint32(protocol.MessageType_ERROR),
		RequestId: reply.requestId,
		Flags:     EnvelopeFlagResponse | EnvelopeFlagError,
		Body:      body,
	})
}

// Sends one envelope of an answer, waiting at most until the request's deadline, which a handler's
// goroutine may: it holds up no one else. False when it was not sent.
func (self *Subprotocol) sendReplyEnvelope(reply *rpcReplyTarget, envelope *protocol.Envelope) bool {
	timeout := max(reply.deadline.Sub(self.clock.Now()), 0)
	if err := self.sendEnvelopeAcked(reply.destinationId, envelope, ignoreSubprotocolAck, timeout, replyTransferKey(reply.transferKey)); err != nil {
		self.stats.replyFailedCount.Add(1)
		return false
	}
	self.stats.replySentCount.Add(1)
	return true
}

// Records a handler run for Cancel and the per-peer bound: false past PeerQueueMessageCount, or when the
// Subprotocol has closed.
func (self *Subprotocol) startRun(key rpcCallKey, cancel context.CancelCauseFunc) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed || self.settings.PeerQueueMessageCount <= self.sourceIdRunCounts[key.sourceId] {
		return false
	}
	if _, running := self.runningCalls[key]; running {
		// the same request_id from the same peer while its first runs: only a non-mutating retry gets here
		return false
	}
	self.runningCalls[key] = cancel
	self.sourceIdRunCounts[key.sourceId] += 1
	return true
}

// Ends what startRun recorded.
func (self *Subprotocol) endRun(key rpcCallKey) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, running := self.runningCalls[key]; !running {
		return
	}
	delete(self.runningCalls, key)
	self.sourceIdRunCounts[key.sourceId] -= 1
	if self.sourceIdRunCounts[key.sourceId] <= 0 {
		delete(self.sourceIdRunCounts, key.sourceId)
	}
}

// Cancel (reading 4): cancels the handler run its request_id names, from its own peer, if one runs.
// Best effort, and never answered.
func (self *Subprotocol) dispatchCancel(ctx context.Context, message *subprotocolMessage) {
	key := rpcCallKey{sourceId: message.sourceId, requestId: message.envelope.RequestId}
	var cancel context.CancelCauseFunc
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cancel = self.runningCalls[key]
	}()
	if cancel == nil {
		self.stats.unroutedCount.Add(1)
		return
	}
	self.stats.cancelledCount.Add(1)
	cancel(errHandlerCancelled)
}
