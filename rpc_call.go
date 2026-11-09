//go:build !sidecar_http

// Peer RPC, the caller's half (§6.6, D-PROTO-3): Call sends a request and waits for the one response
// that echoes its request_id. A response is the only delivery this side reads: a transfer ack says
// connect carried a frame, never that anyone acted on it (R-PROTO-10).
//
// A call runs only after §6.4's Hello with the peer (ensurePeerVerified), with a random request_id and a
// timeout_ms of DefaultCallTimeout unless the caller asks less, at most 55 s, and never past ctx. A body
// past 4,016 B rides envelope_chunk.go's chunks, and one past the peer's Hello max_body_byte_count is
// TOO_LARGE here. Only a send connect refuses before the deadline is sent again, with the same
// request_id; a request that went out and got no answer by the deadline returns DEADLINE_EXCEEDED with
// its request_id, since a lost ack surfaces only at connect's 60 s AckTimeout, and the caller retries
// with CallOptions.RequestId. A Required peer with no session surfaces as UNAVAILABLE with reason
// encryption.
//
// The answer is the request's type + 1, or RESPONSE, ERROR, type ERROR and an Error body. Any other type
// fails the call without retry, as does an Error whose code is OK or one no sender sets (§6.5).

package sidecar

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A response that breaks §6.6's shape: neither the request's type + 1 nor an Error, or an Error whose
	// code no sender sets. Never retried.
	ErrSubprotocolResponse = errors.New("subprotocol: a response outside the protocol")
	// The Subprotocol has closed.
	errSubprotocolClosed = errors.New("subprotocol closed")
	// A call whose request_id is already waiting on that peer.
	errCallRequestIdTaken = errors.New("subprotocol: request_id already in flight")
)

// The reason a local UNAVAILABLE gives when a Required peer has no end-to-end session (§6.3).
const SubprotocolReasonEncryption = "encryption"

// A call's failure with an ErrorCode: the peer's Error, or this side's own DEADLINE_EXCEEDED,
// UNAVAILABLE, CANCELLED, INVALID_ARGUMENT or TOO_LARGE. A handler may return one to answer with it.
type SubprotocolError struct {
	Code    protocol.ErrorCode
	Message string
	// RESOURCE_EXHAUSTED and UNAVAILABLE: when to try again.
	RetryAfter time.Duration
	// ALREADY_EXISTS for a response too large to cache: the handler's reference to its result.
	ResultRef []byte
	// The call's request_id, which a retry passes back as CallOptions.RequestId.
	RequestId uint64
	// Why this side answered UNAVAILABLE: SubprotocolReasonEncryption, or empty.
	Reason string
	// VERSION from the peer: the wire majors it speaks, with Hello's meaning, zero when it named none
	// (plan-PROTO-version-error-range).
	MinVersion uint32
	MaxVersion uint32
}

// The code, and this side's reason, never the peer's message.
func (self *SubprotocolError) Error() string {
	if self.Reason != "" {
		return fmt.Sprintf("subprotocol: %s (%s)", self.Code, self.Reason)
	}
	return fmt.Sprintf("subprotocol: %s", self.Code)
}

// The code of a call's failure, and false for an error that carries none.
func SubprotocolErrorCode(err error) (protocol.ErrorCode, bool) {
	var subprotocolError *SubprotocolError
	if errors.As(err, &subprotocolError) {
		return subprotocolError.Code, true
	}
	return protocol.ErrorCode_ERR_OK, false
}

// One call's options. A SEARCH call keeps its own rules whatever these say (rpc_search.go): its
// timeout_ms is SearchTimeout, its wait ends there or at ctx, and it sends no Cancel.
type CallOptions struct {
	// The call's deadline, sent as timeout_ms: DefaultCallTimeout when zero, at most MaxCallTimeout, and
	// cut to ctx's deadline. A larger one is refused.
	Timeout time.Duration
	// The request_id to send, which a retry keeps (§6.6). Zero draws a random one.
	RequestId uint64
}

// One request this side waits on, a Hello or a call: the response that echoes its request_id from its
// peer, and nothing from any other.
type rpcPendingKey struct {
	peerId    connect.Id
	requestId uint64
}

// A response as a pending request gets it: the whole envelope, copied out of the worker's buffer, and
// C15's key on the frame that completed it, which Hello's check reads.
type rpcResponse struct {
	envelope           *protocol.Envelope
	clientPublicKey    [ed25519.PublicKeySize]byte
	hasClientPublicKey bool
	// the lane the response rode, whose contract a marked pair's sender adopts (rpc_marked_pair.go)
	transferKey connect.TransferKey
}

// One pending request's mailbox, which takes its first response.
type rpcPending struct {
	responses chan *rpcResponse
}

// Registers a request to clientId under requestId; remove takes it away. A second request under one
// id to one peer is refused, since its responses could not be told apart.
func (self *Subprotocol) addPending(clientId connect.Id, requestId uint64, resultType protocol.MessageType) (*rpcPending, func(), error) {
	key := rpcPendingKey{peerId: clientId, requestId: requestId}
	pending := &rpcPending{responses: make(chan *rpcResponse, 1)}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, nil, errSubprotocolClosed
	}
	if self.pendingRequests[key] != nil {
		return nil, nil, errCallRequestIdTaken
	}
	self.pendingRequests[key] = pending
	return pending, func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.pendingRequests[key] == pending {
			delete(self.pendingRequests, key)
		}
	}, nil
}

// The response dispatch: hands each response to the request it echoes, from that request's peer, and
// counts any other. Runs on the source's worker and never blocks: a request takes one response.
func (self *Subprotocol) dispatchResponse(ctx context.Context, message *subprotocolMessage) {
	key := rpcPendingKey{peerId: message.sourceId, requestId: message.envelope.RequestId}
	var pending *rpcPending
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		pending = self.pendingRequests[key]
	}()
	if pending == nil {
		self.stats.unroutedCount.Add(1)
		return
	}
	response := &rpcResponse{
		envelope:           proto.Clone(message.envelope).(*protocol.Envelope),
		clientPublicKey:    message.clientPublicKey,
		hasClientPublicKey: message.hasClientPublicKey,
		transferKey:        message.transferKey,
	}
	select {
	case pending.responses <- response:
	default:
		self.stats.unroutedCount.Add(1)
	}
}

// Waits for pending's response, at most timeout on this side's clock, ctx, or the Subprotocol's end. A
// timeout is DEADLINE_EXCEEDED with requestId, which the caller retries with.
func (self *Subprotocol) awaitPending(ctx context.Context, pending *rpcPending, timeout time.Duration, requestId uint64) (*rpcResponse, error) {
	select {
	case response := <-pending.responses:
		return response, nil
	case <-self.clock.After(timeout):
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED, RequestId: requestId}
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED, RequestId: requestId}
		}
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_CANCELLED, RequestId: requestId}
	case <-self.ctx.Done():
		return nil, errSubprotocolClosed
	}
}

// The Error a response carries, as a *SubprotocolError with requestId, or ErrSubprotocolResponse for one
// that breaks the shape: no ERROR flag, a body that does not decode, OK, or a code no sender sets.
func responseError(envelope *protocol.Envelope, requestId uint64) error {
	if envelope.Flags&EnvelopeFlagError == 0 {
		return ErrSubprotocolResponse
	}
	refusal := &protocol.Error{}
	if err := proto.Unmarshal(envelope.Body, refusal); err != nil {
		return ErrSubprotocolResponse
	}
	code, ok := readErrorCode(refusal.Code)
	if !ok {
		return ErrSubprotocolResponse
	}
	subprotocolError := &SubprotocolError{
		Code:       code,
		Message:    refusal.Message,
		RetryAfter: time.Duration(refusal.RetryAfterMs) * time.Millisecond,
		ResultRef:  refusal.ResultRef,
		RequestId:  requestId,
	}
	if code == protocol.ErrorCode_ERR_VERSION {
		// the range rides only VERSION; on any other code it is no one's to read
		subprotocolError.MinVersion = refusal.MinVersion
		subprotocolError.MaxVersion = refusal.MaxVersion
	}
	return subprotocolError
}

// A send that failed, as the call reports it: a Required peer with no session is UNAVAILABLE with
// reason encryption, and any other refusal UNAVAILABLE.
func sendFailure(err error, requestId uint64) error {
	if errors.Is(err, connect.ErrEncryptionRequiredNotEstablished) {
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE, Reason: SubprotocolReasonEncryption, RequestId: requestId}
	}
	return &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE, RequestId: requestId}
}

// The ack callback a send to clientId carries: an ack error ends the peer's Hello (reading 1), and
// nothing else is read from an ack (R-PROTO-10).
func (self *Subprotocol) forgetPeerOnAckError(clientId connect.Id) connect.AckFunction {
	return func(err error) {
		if err != nil {
			self.forgetPeer(clientId)
		}
	}
}

// Sends a request of messageType carrying body to clientId and answers the response's body, after
// §6.4's Hello. See the file header. A *SubprotocolError carries every coded failure with its request_id.
func (self *Subprotocol) Call(ctx context.Context, clientId Id, messageType protocol.MessageType, body []byte, options *CallOptions) ([]byte, error) {
	if options == nil {
		options = &CallOptions{}
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = self.settings.DefaultCallTimeout
	}
	search := messageType == protocol.MessageType_SEARCH
	if search {
		// one envelope of one size, and one timeout_ms, whatever the caller asks (rpc_search.go)
		if len(body) != SearchRequestByteCount {
			return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_INVALID_ARGUMENT, Message: "a SEARCH body of another size"}
		}
		timeout = SearchTimeout
	}
	if timeout < 0 || MaxCallTimeout < timeout {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_INVALID_ARGUMENT, Message: "timeout past the protocol's maximum"}
	}
	requestId := options.RequestId
	if requestId == 0 {
		requestId = newRequestId()
	}
	peerId := connect.Id(clientId)
	if search {
		// every search rides a marked pair: one whose mode cleared runs a bit-1 Hello first (rpc_marked_pair.go)
		self.prepareSearchPair(peerId)
	}
	start := self.clock.Now()
	if ctxDeadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, ctxDeadline.Sub(start))
	}
	if timeout <= 0 {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED, RequestId: requestId}
	}
	deadline := start.Add(timeout)

	// a peer that refused at its gate holds no Hello with this side any more: one fresh Hello, then the
	// same request again, which no handler can have run
	for attempt := 0; ; attempt += 1 {
		if err := self.ensurePeerVerifiedWithin(ctx, peerId, deadline.Sub(self.clock.Now())); err != nil {
			var subprotocolError *SubprotocolError
			switch {
			case errors.As(err, &subprotocolError):
				return nil, &SubprotocolError{Code: subprotocolError.Code, Reason: subprotocolError.Reason, RequestId: requestId}
			case errors.Is(err, context.Canceled):
				return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_CANCELLED, RequestId: requestId}
			case errors.Is(err, context.DeadlineExceeded):
				return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED, RequestId: requestId}
			case errors.Is(err, errSubprotocolClosed):
				return nil, err
			}
			return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAUTHENTICATED, RequestId: requestId}
		}
		// the first RPC with a peer each HeadCheckInterval starts a HeadCheck beside it (rpc_headcheck_rounds.go)
		self.headCheckOnExchange(peerId, messageType)
		response, err := self.callOnce(ctx, peerId, messageType, body, requestId, deadline)
		if code, ok := SubprotocolErrorCode(err); ok && code == protocol.ErrorCode_ERR_UNAUTHENTICATED && attempt == 0 {
			self.forgetPeer(peerId)
			continue
		}
		return response, err
	}
}

// One send of the request and its wait. A send connect refuses before the deadline goes again, with the
// same request_id, after CallSendRetryInterval; ctx ends the wait, and a cancel sends Cancel.
func (self *Subprotocol) callOnce(
	ctx context.Context,
	peerId connect.Id,
	messageType protocol.MessageType,
	body []byte,
	requestId uint64,
	deadline time.Time,
) ([]byte, error) {
	if peer, ok := self.PeerIdentity(Id(peerId)); ok && 0 < peer.MaxBodyByteCount && int64(peer.MaxBodyByteCount) < int64(len(body)) {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_TOO_LARGE, RequestId: requestId}
	}
	timeout := deadline.Sub(self.clock.Now())
	if timeout <= 0 {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED, RequestId: requestId}
	}
	timeoutMs := uint32((timeout + time.Millisecond - 1) / time.Millisecond)
	search := messageType == protocol.MessageType_SEARCH
	if search {
		// whatever ctx says, so the envelope has one length (§6.5)
		timeoutMs = uint32(SearchTimeout / time.Millisecond)
	}
	envelopes, err := chunkBody(&protocol.Envelope{
		Version:   WireVersionMajor,
		Type:      uint32(messageType),
		RequestId: requestId,
		TimeoutMs: timeoutMs,
	}, body)
	if err != nil {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_TOO_LARGE, RequestId: requestId}
	}
	pending, remove, err := self.addPending(peerId, requestId, messageType+1)
	if err != nil {
		return nil, err
	}
	defer remove()

	ack := self.forgetPeerOnAckError(peerId)
	for _, envelope := range envelopes {
		for {
			remaining := deadline.Sub(self.clock.Now())
			if remaining <= 0 {
				return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED, RequestId: requestId}
			}
			testHookBarrier("rpc.call_send.before", peerId.String())
			err := self.sendEnvelopeAcked(peerId, envelope, ack, remaining)
			testHookBarrier("rpc.call_send.after", peerId.String())
			if err == nil {
				break
			}
			if errors.Is(err, connect.ErrEncryptionRequiredNotEstablished) || deadline.Sub(self.clock.Now()) <= 0 {
				return nil, sendFailure(err, requestId)
			}
			// refused before the deadline: the same envelope, the same request_id, after a pause
			self.stats.callSendRetryCount.Add(1)
			select {
			case <-self.clock.After(self.settings.CallSendRetryInterval):
			case <-ctx.Done():
				return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_CANCELLED, RequestId: requestId}
			case <-self.ctx.Done():
				return nil, errSubprotocolClosed
			}
		}
	}

	response, err := self.awaitPending(ctx, pending, deadline.Sub(self.clock.Now()), requestId)
	if err != nil {
		// a search is never cancelled (§11.14): the indexer answers it at its size whatever happens here
		if code, ok := SubprotocolErrorCode(err); ok && code == protocol.ErrorCode_ERR_CANCELLED && !search {
			self.sendCancel(peerId, requestId)
		}
		return nil, err
	}
	if search {
		return searchResponseBody(response)
	}
	switch protocol.MessageType(response.envelope.Type) {
	case messageType + 1:
		if response.envelope.Flags&EnvelopeFlagError != 0 {
			return nil, ErrSubprotocolResponse
		}
		return response.envelope.Body, nil
	case protocol.MessageType_ERROR:
		return nil, responseError(response.envelope, requestId)
	}
	return nil, ErrSubprotocolResponse
}

// Tells peerId to stop the call requestId names, best effort: Cancel carries no body and expects no
// answer (reading 4), and a send connect will not take at once is dropped.
func (self *Subprotocol) sendCancel(peerId connect.Id, requestId uint64) {
	envelope := &protocol.Envelope{
		Version:   WireVersionMajor,
		Type:      uint32(protocol.MessageType_CANCEL),
		RequestId: requestId,
		Flags:     EnvelopeFlagNoReply,
	}
	if err := self.sendEnvelopeAcked(peerId, envelope, ignoreSubprotocolAck, 0); err != nil {
		self.stats.cancelDroppedCount.Add(1)
	}
}
