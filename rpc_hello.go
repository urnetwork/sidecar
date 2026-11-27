//go:build !sidecar_http

// Hello and HelloResult (§6.4): one exchange on the raw envelope path, each a single envelope of at most
// 512 B with connect's wrapper. The side that wants to talk sends Hello; the side that receives it checks
// it (rpc_identity.go) and, if it verifies, opens its gate to the sender and answers HelloResult with
// its own fields, which the sender checks in turn before it opens its own. Either side refuses with
// Error{UNAUTHENTICATED} or Error{VERSION}, which carries this side's range of wire majors
// (plan-PROTO-version-error-range), and a refused Hello closes any gate that stood.
//
// A verified Hello stands for HelloCacheTimeout, until a frame under another C15 key, until a send's ack
// error (plan-PROTO-small-readings reading 1), or until connect reports that the peer lost its session with
// this client (QD-1185, rpc_peer_session.go), and EnsureHello runs a new one when none stands, one at a time
// per peer: a second caller joins the first's. Both sides may send Hello at once: each answers the other's,
// so the pair converges.
//
// A HelloResult that no Hello of this side's awaits, from a sidecar this side holds no Hello with, runs a fresh
// one at once (QD-1197). It is the peer's word that its gate just opened to this side under a Hello this side no
// longer holds. Connect does this when it replays this side's earlier Hello to a peer restarted under its kept
// generation, after its report of the lost session ended this side's own. The peer's opens to this side would
// otherwise meet INVALID under the Hello its gate holds, which QD-1185 reads as the listener's own, until
// HelloCacheTimeout. Finding no Hello standing or in flight and starting one are one step, under the state lock
// EnsureHello takes its flight under, so such HelloResults arriving before the fresh Hello's answer verifies, as
// the replay's answer and a late one from before the restart can, start one Hello between them, and one that finds
// a Hello in flight starts nothing. A peer can prompt a Hello this way at most one in flight at a time, as it can
// by sending one.

package sidecar

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The peer answered a Hello with something other than HelloResult or Error.
	errHelloAnswer = errors.New("hello: answered with neither HelloResult nor Error")
)

// One Hello in flight to a peer, which every EnsureHello to that peer waits on.
type helloFlight struct {
	done chan struct{}
	err  error
}

// This side's Hello fields toward peerId: its version range, floor, bounds and binding, and the feature
// bits it sends that peer (rpc_features.go).
func (self *Subprotocol) ownHelloFields(peerId connect.Id) *helloFields {
	return &helloFields{
		minVersion:       WireVersionMajor,
		maxVersion:       WireVersionMajor,
		secureVersion:    SecureVersion,
		features:         self.featuresToward(peerId),
		maxBodyByteCount: uint32(self.settings.ReassemblyMaxBodyByteCount),
		initialWindow:    uint32(self.settings.StreamInitialWindowByteCount),
		binding:          self.binding,
	}
}

// The fields as a Hello.
func (self *helloFields) hello() *protocol.Hello {
	return &protocol.Hello{
		MinVersion:       self.minVersion,
		MaxVersion:       self.maxVersion,
		SecureVersion:    self.secureVersion,
		Features:         self.features,
		MaxBodyByteCount: self.maxBodyByteCount,
		InitialWindow:    self.initialWindow,
		Binding:          self.binding,
	}
}

// The fields as a HelloResult, the same fields with the same numbers.
func (self *helloFields) helloResult() *protocol.HelloResult {
	return &protocol.HelloResult{
		MinVersion:       self.minVersion,
		MaxVersion:       self.maxVersion,
		SecureVersion:    self.secureVersion,
		Features:         self.features,
		MaxBodyByteCount: self.maxBodyByteCount,
		InitialWindow:    self.initialWindow,
		Binding:          self.binding,
	}
}

// A random request_id, never 0.
func newRequestId() uint64 {
	var idBytes [8]byte
	for {
		if _, err := rand.Read(idBytes[:]); err != nil {
			panic(err)
		}
		if requestId := binary.BigEndian.Uint64(idBytes[:]); requestId != 0 {
			return requestId
		}
	}
}

// The verified peer behind clientId, while its Hello stands, and false while none does.
func (self *Subprotocol) PeerIdentity(clientId Id) (*SubprotocolPeerIdentity, bool) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	identity, ok := self.sourceIdIdentities[connect.Id(clientId)]
	if !ok || !now.Before(identity.expireTime) || identity.peer == nil {
		return nil, false
	}
	return identity.peer.clone(), true
}

// nil once a verified Hello with clientId stands, running one when none does, which waits at most
// DefaultCallTimeout and never past ctx. A refusal answers a *SubprotocolError with the peer's code, and
// a peer whose own HelloResult fails this side's checks answers the check's error.
func (self *Subprotocol) EnsureHello(ctx context.Context, clientId Id) error {
	return self.ensurePeerVerified(ctx, connect.Id(clientId))
}

// What OpenStream goes through before it sends to clientId (D-PROTO-13). See EnsureHello.
func (self *Subprotocol) ensurePeerVerified(ctx context.Context, clientId connect.Id) error {
	return self.ensurePeerVerifiedWithin(ctx, clientId, self.clock.Now().Add(self.settings.DefaultCallTimeout))
}

// What Call goes through before it sends to clientId: a Hello, if one has to run, waits until deadline at most on this
// side's clock, a wait for that time itself (QD-1425), and never past DefaultCallTimeout or ctx. A second caller joins
// the first's Hello.
func (self *Subprotocol) ensurePeerVerifiedWithin(ctx context.Context, clientId connect.Id, deadline time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if self.role == SubprotocolRoleEdge {
		// an edge shows no binding and checks none (stream_edge.go)
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_FAILED_PRECONDITION, Message: errSubprotocolEdgeRole.Error()}
	}
	// a standing Hello whose peer the state has since revoked or parked is closed first (rpc_admission.go)
	self.peerAdmissionStands(clientId)
	flight, owner := self.takeHelloFlight(clientId)
	if flight == nil {
		return nil
	}
	if owner {
		return self.runHelloFlight(ctx, clientId, flight, earlierTime(deadline, self.clock.Now().Add(self.settings.DefaultCallTimeout)))
	}
	select {
	case <-flight.done:
		return flight.err
	case <-ctx.Done():
		return ctx.Err()
	case <-self.ctx.Done():
		return errSubprotocolClosed
	}
}

// The Hello toward clientId a caller waits on, found or registered in one step under the state lock: nil while a
// verified Hello stands, else the one in flight, which the caller joins, or a new one the caller owns and must run
// with runHelloFlight. So one Hello at a time goes to a peer, however many callers and unasked HelloResults ask.
func (self *Subprotocol) takeHelloFlight(clientId connect.Id) (flight *helloFlight, owner bool) {
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if identity, ok := self.sourceIdIdentities[clientId]; ok && now.Before(identity.expireTime) {
		return nil, false
	}
	if flight = self.helloFlights[clientId]; flight != nil {
		return flight, false
	}
	flight = &helloFlight{done: make(chan struct{})}
	self.helloFlights[clientId] = flight
	return flight, true
}

// Runs the Hello of a flight takeHelloFlight gave its caller to own, waiting until deadline at most, then ends the
// flight for every caller that joined it.
func (self *Subprotocol) runHelloFlight(ctx context.Context, clientId connect.Id, flight *helloFlight, deadline time.Time) error {
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.helloFlights, clientId)
		close(flight.done)
	}()
	flight.err = self.runHello(ctx, clientId, deadline)
	return flight.err
}

// Sends one Hello and checks its answer, waiting until deadline at most, and opens the gate on a HelloResult that
// verifies. Every failure leaves the gate closed. The Hello's timeout_ms and its send take what is left of the wait as
// it starts; the wait for the answer is set for deadline itself (QD-1425).
func (self *Subprotocol) runHello(ctx context.Context, clientId connect.Id, deadline time.Time) error {
	timeout := deadline.Sub(self.clock.Now())
	if timeout <= 0 {
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_DEADLINE_EXCEEDED}
	}
	if len(self.binding) == 0 {
		// with no binding to show, no peer could verify this side
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAUTHENTICATED, Message: "no binding to show"}
	}
	if !self.selfAdmitted() {
		// until a SidecarAdmit names this sidecar in its own verified state, it gets no peer (§5.6)
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAVAILABLE, Message: "this sidecar is not admitted"}
	}
	body, err := proto.Marshal(self.ownHelloFields(clientId).hello())
	if err != nil {
		return err
	}
	requestId := newRequestId()
	envelope := &protocol.Envelope{
		Version:   WireVersionMajor,
		Type:      uint32(protocol.MessageType_HELLO),
		RequestId: requestId,
		TimeoutMs: uint32(timeout / time.Millisecond),
		Body:      body,
	}
	pending, remove, err := self.addPending(clientId, requestId, protocol.MessageType_HELLO_RESULT)
	if err != nil {
		return err
	}
	defer remove()
	if err := self.sendEnvelopeAcked(clientId, envelope, self.forgetPeerOnAckError(clientId), timeout); err != nil {
		return sendFailure(err, requestId)
	}

	response, err := self.awaitPending(ctx, pending, deadline, requestId)
	if err != nil {
		return err
	}
	switch {
	case response.envelope.Type == uint32(protocol.MessageType_HELLO_RESULT) && response.envelope.Flags&EnvelopeFlagError == 0:
		result := &protocol.HelloResult{}
		if err := proto.Unmarshal(response.envelope.Body, result); err != nil {
			self.forgetPeer(clientId)
			return errHelloMalformed
		}
		peer, _, err := self.checkHello(ctx, clientId, helloFieldsOfResult(result), response.clientPublicKey, response.hasClientPublicKey)
		if err != nil {
			self.forgetPeer(clientId)
			return err
		}
		self.markPeerVerifiedAs(clientId, response.clientPublicKey, peer)
		return nil
	case response.envelope.Type == uint32(protocol.MessageType_ERROR):
		self.forgetPeer(clientId)
		return responseError(response.envelope, requestId)
	}
	self.forgetPeer(clientId)
	return errHelloAnswer
}

// A HelloResult no Hello of this side's awaits came from peerId, on its source's worker: with no Hello standing toward a
// sidecar and none in flight, one fresh Hello runs on a goroutine of its own (see the file header). The worker takes
// the flight itself, so the next unasked HelloResult it takes from the peer finds the Hello in flight and starts
// nothing, and no goroutine waits on a Hello another started. An edge's dispatcher, and a peer it knows as an edge,
// run none.
func (self *Subprotocol) helloAnsweredUnasked(peerId connect.Id) {
	if self.role != SubprotocolRoleSidecar || peerId == connect.ControlId || self.ctx.Err() != nil {
		return
	}
	if known, edge := self.streamPeerKind(peerId); known && edge {
		return
	}
	flight, owner := self.takeHelloFlight(peerId)
	if !owner {
		// a Hello stands, or one in flight opens this side's gate when its answer verifies
		return
	}
	self.stats.helloUnaskedCount.Add(1)
	// a worker adds its goroutine before Close joins the handlers, since the workers are joined first
	self.handlers.Add(1)
	go func() {
		defer self.handlers.Done()
		if err := self.runHelloFlight(self.ctx, peerId, flight, self.clock.Now().Add(self.settings.DefaultCallTimeout)); err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[subprotocol]fresh Hello to %s on its unasked HelloResult: %s\n", peerId, err)
		}
	}()
}

// The responder's half, on the source's worker: checks the peer's Hello, and opens the gate and answers
// HelloResult if it verifies, else closes the gate and refuses with the check's code.
func (self *Subprotocol) dispatchHello(ctx context.Context, message *subprotocolMessage) {
	envelope := message.envelope
	if !message.answerable() {
		self.stats.unroutedCount.Add(1)
		return
	}
	refuse := func(code protocol.ErrorCode) {
		self.forgetPeer(message.sourceId)
		self.offerReply(refusalReply(message.sourceId, message.transferKey, envelope.RequestId, envelope.StreamId, code))
	}
	hello := &protocol.Hello{}
	if err := proto.Unmarshal(envelope.Body, hello); err != nil {
		refuse(protocol.ErrorCode_ERR_INVALID_ARGUMENT)
		return
	}
	peer, code, err := self.checkHello(ctx, message.sourceId, helloFieldsOf(hello), message.clientPublicKey, message.hasClientPublicKey)
	if err != nil {
		self.stats.helloRefusedCount.Add(1)
		if self.log.V(1).Enabled() {
			self.log.Infof("[subprotocol]hello from %s refused: %s\n", message.sourceId, err)
		}
		refuse(code)
		return
	}
	body, err := proto.Marshal(self.ownHelloFields(message.sourceId).helloResult())
	if err != nil {
		refuse(protocol.ErrorCode_ERR_UNAVAILABLE)
		return
	}
	self.markPeerVerifiedAs(message.sourceId, message.clientPublicKey, peer)
	self.offerReply(subprotocolReply{
		destinationId: message.sourceId,
		transferKey:   message.transferKey,
		messageType:   protocol.MessageType_HELLO_RESULT,
		requestId:     envelope.RequestId,
		streamId:      envelope.StreamId,
		body:          body,
	})
}
