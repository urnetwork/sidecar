//go:build !sidecar_http

// Hello and HelloResult (§6.4): one exchange on the raw envelope path, each a single envelope of at most
// 512 B with connect's wrapper. The side that wants to talk sends Hello; the side that receives it checks
// it (rpc_identity.go) and, if it verifies, opens its gate to the sender and answers HelloResult with
// its own fields, which the sender checks in turn before it opens its own. Either side refuses with
// Error{UNAUTHENTICATED} or Error{VERSION}, which carries this side's range of wire majors
// (plan-PROTO-version-error-range), and a refused Hello closes any gate that stood.
//
// A verified Hello stands for HelloCacheTimeout, until a frame under another C15 key, or until a send's
// ack error (plan-PROTO-small-readings reading 1), and EnsureHello runs a new one when none stands, one
// at a time per peer: a second caller joins the first's. Both sides may send Hello at once: each answers
// the other's, so the pair converges.

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
	return self.ensurePeerVerifiedWithin(ctx, clientId, self.settings.DefaultCallTimeout)
}

// What Call goes through before it sends to clientId: a Hello, if one has to run, waits at most timeout
// on this side's clock and never past DefaultCallTimeout or ctx. A second caller joins the first's Hello.
func (self *Subprotocol) ensurePeerVerifiedWithin(ctx context.Context, clientId connect.Id, timeout time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if self.role == SubprotocolRoleEdge {
		// an edge shows no binding and checks none (stream_edge.go)
		return &SubprotocolError{Code: protocol.ErrorCode_ERR_FAILED_PRECONDITION, Message: errSubprotocolEdgeRole.Error()}
	}
	// a standing Hello whose peer the state has since revoked or parked is closed first (rpc_admission.go)
	self.peerAdmissionStands(clientId)
	var flight *helloFlight
	owner := false
	now := self.clock.Now()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if identity, ok := self.sourceIdIdentities[clientId]; ok && now.Before(identity.expireTime) {
			return
		}
		flight = self.helloFlights[clientId]
		if flight == nil {
			flight = &helloFlight{done: make(chan struct{})}
			self.helloFlights[clientId] = flight
			owner = true
		}
	}()
	if flight == nil {
		return nil
	}
	if owner {
		func() {
			defer func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				delete(self.helloFlights, clientId)
				close(flight.done)
			}()
			flight.err = self.runHello(ctx, clientId, min(timeout, self.settings.DefaultCallTimeout))
		}()
		return flight.err
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

// Sends one Hello and checks its answer, waiting at most timeout, and opens the gate on a HelloResult
// that verifies. Every failure leaves the gate closed.
func (self *Subprotocol) runHello(ctx context.Context, clientId connect.Id, timeout time.Duration) error {
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
	fields := self.ownHelloFields(clientId)
	// a Hello carrying bit 1 marks the pair before it goes (rpc_marked_pair.go)
	marked := false
	if fields.features&SubprotocolFeatureAsksSearch != 0 {
		marked = self.markBeforeSend(clientId)
	}
	body, err := proto.Marshal(fields.hello())
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
	self.noteWindowActivity(clientId)
	if err := self.sendEnvelopeAcked(clientId, envelope, self.forgetPeerOnAckError(clientId), timeout); err != nil {
		return sendFailure(err, requestId)
	}

	response, err := self.awaitPending(ctx, pending, timeout, requestId)
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
		self.noteWindowActivity(clientId)
		switch {
		case marked:
			// the answer's contract opens the receive window
			self.peerWindows.AdoptPeerWindowContract(clientId, response.transferKey)
		case peer.Features&SubprotocolFeatureAsksSearch != 0:
			// an app host answering this indexer's Hello with bit 1
			self.markOnReceipt(clientId, response.transferKey)
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
	// a marked pair (rpc_marked_pair.go): a verified Hello carrying bit 1 marks it on receipt, before the
	// reply, and a reply carrying bit 1 marks it before it goes
	self.noteWindowActivity(message.sourceId)
	if peer.Features&SubprotocolFeatureAsksSearch != 0 {
		self.markOnReceipt(message.sourceId, message.transferKey)
	}
	fields := self.ownHelloFields(message.sourceId)
	if fields.features&SubprotocolFeatureAsksSearch != 0 {
		self.markBeforeSend(message.sourceId)
	}
	body, err := proto.Marshal(fields.helloResult())
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
