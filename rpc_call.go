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
// A call meets the identity gate at both ends (§6.4). A peer that holds no Hello with this side refuses it
// UNAUTHENTICATED. And this side's gate refuses the peer's answer when the Hello the call went under ended
// while the call was in flight: a send's ack error, HelloCacheTimeout, a change of C15's key, or connect's word
// that the peer lost its session ends it (QD-290, QD-1185). That answer is dropped unread, since a response is
// not answered, so the gate tells the call at once rather than leaving it to wait out its deadline. A peer
// restarted under its kept generation shows both orders: connect ends this side's Hello when the restarted
// peer nacks, and replays the Hello this side sent before the restart ahead of the call. When the replay opens
// the restarted gate first, the peer admits the call and answers it, and this side's gate refuses the answer.
// Either refusal is met once with a fresh Hello and the same request again, under the same request_id and within
// the same deadline. A mutating handler that did run answers that request from what it kept, and runs nothing
// twice (§6.6). The fresh Hello replaces only the Hello the call went under, never a newer one another call's
// Hello verified meanwhile, which the peer's gate holds too. A second refusal is the call's UNAUTHENTICATED.
//
// A call to an edge (CallOptions.Edge; §6.4, owner decision 624), as §14.5's SmtpProof and SmtpHandshake
// to smtpedge, runs no Hello and no HeadCheck, since an edge shows no binding and drops every Hello
// (stream_edge.go): the signed ur/ ticket its dialer verified is the edge's identity, the basis its stream
// rests on. It is refused before anything is sent on an edge's own dispatcher, for a peer this dispatcher
// knows as a sidecar, by a stream or a standing Hello, and for a type an edge drops (edgeSendRefusal); its
// answer comes as a Service-mode source's, which the inline guard admits (serviceMessageAdmits), and an
// UNAUTHENTICATED from it is the answer, never a cue for a Hello. The other way round, a call not so marked
// to a peer this dispatcher knows as an edge is refused before its Hello, which the edge would only drop,
// as OpenStream refuses the other kind.
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
// UNAVAILABLE, CANCELLED, INVALID_ARGUMENT, TOO_LARGE or UNAUTHENTICATED. A handler may return one to answer
// with it.
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
// timeout_ms is Search.Timeout of its settings, its wait ends there or at ctx, and it sends no Cancel.
type CallOptions struct {
	// The call's deadline, sent as timeout_ms: DefaultCallTimeout when zero, at most MaxCallTimeout, and
	// cut to ctx's deadline. A larger one is refused.
	Timeout time.Duration
	// The request_id to send, which a retry keeps (§6.6). Zero draws a random one.
	RequestId uint64
	// The destination is a platform client in urnetwork-edge, the listener a ur/ ticket named, which shows no
	// binding: the call runs no Hello and no HeadCheck, as StreamOpenRequest.Edge's open does (§6.4, owner
	// decision 624). See the file header for what refuses it.
	Edge bool
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
}

// One pending request's mailbox, which takes its first response.
type rpcPending struct {
	responses chan *rpcResponse
	// a call's: word that this side's gate refused the peer's answer to it (noteAnswerRefused). nil for a Hello's,
	// whose HelloResult and Error pass the gate closed (helloExchange).
	answerRefused chan struct{}
}

// Registers a request to clientId under requestId, whose answer is resultType; remove takes it away. A
// second request under one id to one peer is refused, since its responses could not be told apart.
func (self *Subprotocol) addPending(clientId connect.Id, requestId uint64, resultType protocol.MessageType) (*rpcPending, func(), error) {
	key := rpcPendingKey{peerId: clientId, requestId: requestId}
	pending := &rpcPending{responses: make(chan *rpcResponse, 1)}
	if resultType != protocol.MessageType_HELLO_RESULT {
		pending.answerRefused = make(chan struct{}, 1)
	}
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
		if protocol.MessageType(message.envelope.Type) == protocol.MessageType_HELLO_RESULT && message.envelope.Flags&EnvelopeFlagError == 0 {
			self.helloAnsweredUnasked(message.sourceId)
		}
		return
	}
	response := &rpcResponse{
		envelope:           proto.Clone(message.envelope).(*protocol.Envelope),
		clientPublicKey:    message.clientPublicKey,
		hasClientPublicKey: message.hasClientPublicKey,
	}
	select {
	case pending.responses <- response:
	default:
		self.stats.unroutedCount.Add(1)
	}
}

// Tells the call pending on sourceId under requestId that this side's gate refused a frame of the peer's answer to
// it, which was dropped unread: the Hello the call went under ended while it was in flight. Runs on connect's
// receive path and on the source's worker, so it takes the state lock for the lookup alone and never blocks. A
// frame no call waits on is left as the gate counted it.
func (self *Subprotocol) noteAnswerRefused(sourceId connect.Id, requestId uint64) {
	var pending *rpcPending
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		pending = self.pendingRequests[rpcPendingKey{peerId: sourceId, requestId: requestId}]
	}()
	if pending == nil || pending.answerRefused == nil {
		return
	}
	select {
	case pending.answerRefused <- struct{}{}:
	default:
		// a chunk of the same answer told it already
	}
}

// Waits for pending's response, at most timeout on this side's clock, ctx, or the Subprotocol's end. A
// timeout is DEADLINE_EXCEEDED with requestId, which the caller retries with. An answer this side's gate
// refused ends the wait as UNAUTHENTICATED with requestId, which Call meets with a fresh Hello, unless a
// response the gate took came beside it.
func (self *Subprotocol) awaitPending(ctx context.Context, pending *rpcPending, timeout time.Duration, requestId uint64) (*rpcResponse, error) {
	select {
	case response := <-pending.responses:
		return response, nil
	case <-pending.answerRefused:
		select {
		case response := <-pending.responses:
			return response, nil
		default:
		}
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAUTHENTICATED, RequestId: requestId}
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

// Whether a sidecar may send an edge messageType, as a request or a NO_REPLY envelope (owner decision 624):
// never a type the dispatcher answers itself or a push type (handleTypeReserved), a stream frame, which rides
// its stream, or one only sidecars of one network exchange (Hello's, HeadCheck's and SEARCH's), all of which
// an edge's guard drops (serviceMessageAdmits).
func edgeMessageType(messageType protocol.MessageType) bool {
	return !handleTypeReserved(messageType) && !streamMessageType(uint32(messageType)) && !sidecarOnlyMessageType(uint32(messageType))
}

// Why this dispatcher may not send peerId a call or a NO_REPLY envelope marked for an edge, nil when it may:
// an edge's dispatcher sends an edge nothing; ControlId is the platform's and takes no send; and a peer this
// dispatcher knows as a sidecar, by a stream or a standing Hello, is one, never both (stream_edge.go). A peer
// it knows by neither goes as an edge, whose identity is the ur/ ticket its dialer verified.
func (self *Subprotocol) edgeSendRefusal(peerId connect.Id) *SubprotocolError {
	if self.role == SubprotocolRoleEdge {
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_FAILED_PRECONDITION, Message: errSubprotocolEdgeSender.Error()}
	}
	if peerId == connect.ControlId {
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_FAILED_PRECONDITION, Message: errSubprotocolEdgeSender.Error()}
	}
	if known, edge := self.streamPeerKind(peerId); known && !edge {
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_FAILED_PRECONDITION, Message: errStreamPeerKind.Error()}
	}
	if self.peerVerified(peerId) {
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_FAILED_PRECONDITION, Message: errStreamPeerKind.Error()}
	}
	return nil
}

// Sends a request of messageType carrying body to clientId and answers the response's body, after
// §6.4's Hello unless options mark it for an edge. See the file header. A *SubprotocolError carries every
// coded failure with its request_id.
func (self *Subprotocol) Call(ctx context.Context, clientId Id, messageType protocol.MessageType, body []byte, options *CallOptions) ([]byte, error) {
	if options == nil {
		options = &CallOptions{}
	}
	if options.Edge && !edgeMessageType(messageType) {
		// an edge would drop it unanswered, so it never goes
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_INVALID_ARGUMENT, Message: "a type an edge does not take"}
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = self.settings.DefaultCallTimeout
	}
	search := messageType == protocol.MessageType_SEARCH
	if search {
		// one envelope of one size, and one timeout_ms, whatever the caller asks (rpc_search.go); a leg that links
		// no search refuses the call here, before anything is sent (rpc_search_leg.go)
		if err := searchRequestBodyError(body, &self.settings.Search); err != nil {
			return nil, err
		}
		timeout = self.settings.Search.Timeout
	}
	if timeout < 0 || MaxCallTimeout < timeout {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_INVALID_ARGUMENT, Message: "timeout past the protocol's maximum"}
	}
	requestId := options.RequestId
	if requestId == 0 {
		requestId = newRequestId()
	}
	peerId := connect.Id(clientId)
	start := self.clock.Now()
	if ctxDeadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, ctxDeadline.Sub(start))
	}
	if timeout <= 0 {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED, RequestId: requestId}
	}
	deadline := start.Add(timeout)

	if options.Edge {
		if refusal := self.edgeSendRefusal(peerId); refusal != nil {
			refusal.RequestId = requestId
			return nil, refusal
		}
		// no Hello and no HeadCheck (owner decision 624), and so nothing to run again: an UNAUTHENTICATED
		// from an edge is its answer
		return self.callOnce(ctx, peerId, messageType, body, requestId, deadline, true)
	}
	// a peer is an edge or a sidecar for the dispatcher's life, never both: an edge would only drop the Hello
	if known, edge := self.streamPeerKind(peerId); known && edge {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_FAILED_PRECONDITION, Message: errStreamPeerKind.Error(), RequestId: requestId}
	}

	// a peer that refused at its gate holds no Hello with this side any more, and an answer this side's gate
	// refused came after the Hello the call went under ended: either way one fresh Hello, then the same request
	// again, which a mutating handler that ran answers from what it kept (see the file header)
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
		// the Hello this attempt goes under, which a refusal ends, leaving a newer one standing
		helloSerial := self.standingHelloSerial(peerId)
		// the first RPC with a peer each HeadCheckInterval starts a HeadCheck beside it (rpc_headcheck_rounds.go)
		self.headCheckOnExchange(peerId, messageType)
		response, err := self.callOnce(ctx, peerId, messageType, body, requestId, deadline, false)
		if code, ok := SubprotocolErrorCode(err); ok && code == protocol.ErrorCode_ERR_UNAUTHENTICATED && attempt == 0 {
			self.forgetPeerHello(peerId, helloSerial)
			continue
		}
		return response, err
	}
}

// One send of the request and its wait. A send connect refuses before the deadline goes again, with the
// same request_id, after CallSendRetryInterval; ctx ends the wait, and a cancel sends Cancel. A call to an
// edge has no Hello to bound its body or to end on an ack's error.
func (self *Subprotocol) callOnce(
	ctx context.Context,
	peerId connect.Id,
	messageType protocol.MessageType,
	body []byte,
	requestId uint64,
	deadline time.Time,
	edge bool,
) ([]byte, error) {
	if !edge {
		if peer, ok := self.PeerIdentity(Id(peerId)); ok && 0 < peer.MaxBodyByteCount && int64(peer.MaxBodyByteCount) < int64(len(body)) {
			return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_TOO_LARGE, RequestId: requestId}
		}
	}
	timeout := deadline.Sub(self.clock.Now())
	if timeout <= 0 {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED, RequestId: requestId}
	}
	timeoutMs := uint32((timeout + time.Millisecond - 1) / time.Millisecond)
	search := messageType == protocol.MessageType_SEARCH
	if search {
		// whatever ctx says, so the envelope has one length (§6.5)
		timeoutMs = uint32(self.settings.Search.Timeout / time.Millisecond)
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

	ack := ignoreSubprotocolAck
	if !edge {
		ack = self.forgetPeerOnAckError(peerId)
	}
	barrierKey := peerId.String()
	err = self.sendEnvelopesUntil(ctx, peerId, envelopes, ack, deadline, requestId, func(before bool) {
		if before {
			testHookBarrier("rpc.call_send.before", barrierKey)
		} else {
			testHookBarrier("rpc.call_send.after", barrierKey)
		}
	})
	if err != nil {
		return nil, err
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
		return searchResponseBody(response, &self.settings.Search)
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

// Hands connect envelopes for peerId in order, each with ack, until deadline on this side's clock: a send
// connect refuses before then goes again after CallSendRetryInterval, the same envelope under the same
// request_id, and is counted. barrier runs before and after each send, at its linearization point. A Required
// peer with no session, or a refusal at the deadline, is sendFailure's; ctx's end CANCELLED.
func (self *Subprotocol) sendEnvelopesUntil(
	ctx context.Context,
	peerId connect.Id,
	envelopes []*protocol.Envelope,
	ack connect.AckFunction,
	deadline time.Time,
	requestId uint64,
	barrier func(before bool),
) error {
	for _, envelope := range envelopes {
		for {
			remaining := deadline.Sub(self.clock.Now())
			if remaining <= 0 {
				return &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED, RequestId: requestId}
			}
			barrier(true)
			err := self.sendEnvelopeAcked(peerId, envelope, ack, remaining)
			barrier(false)
			if err == nil {
				break
			}
			if errors.Is(err, connect.ErrEncryptionRequiredNotEstablished) || deadline.Sub(self.clock.Now()) <= 0 {
				return sendFailure(err, requestId)
			}
			// refused before the deadline: the same envelope, the same request_id, after a pause
			self.stats.callSendRetryCount.Add(1)
			select {
			case <-self.clock.After(self.settings.CallSendRetryInterval):
			case <-ctx.Done():
				return &SubprotocolError{Code: protocol.ErrorCode_ERR_CANCELLED, RequestId: requestId}
			case <-self.ctx.Done():
				return errSubprotocolClosed
			}
		}
	}
	return nil
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
