//go:build !sidecar_http && !js

// §22.5's §6 row for the source guard (D-PROTO-8), as a table over connect.Peer at the handler connect
// calls: ControlId's push kept over h1, h3, h3dns and h3dnspump and dropped over p2p and anything
// unknown, nothing else from ControlId, and no push from a peer, verified or not. Then step 4, the
// provide mode. A dropped frame is answered by nothing.

package sidecar

import (
	"context"
	"testing"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol"
)

// The pure rule, case by case: the source path, the type and the carrier.
func TestSourceGuardRule(t *testing.T) {
	peerId := connect.NewId()
	cases := []struct {
		name          string
		source        connect.TransferPath
		messageType   protocol.MessageType
		transportType connect.TransportType
		want          bool
	}{
		{name: "push reset h1", source: connect.SourceId(connect.ControlId), messageType: protocol.MessageType_PUSH_RESET, transportType: connect.TransportTypeH1, want: true},
		{name: "push hint h3", source: connect.SourceId(connect.ControlId), messageType: protocol.MessageType_PUSH_HINT, transportType: connect.TransportTypeH3, want: true},
		{name: "push hint h3dns", source: connect.SourceId(connect.ControlId), messageType: protocol.MessageType_PUSH_HINT, transportType: connect.TransportTypeH3Dns, want: true},
		{name: "push hint h3dnspump", source: connect.SourceId(connect.ControlId), messageType: protocol.MessageType_PUSH_HINT, transportType: connect.TransportTypeH3DnsPump, want: true},
		{name: "push hint p2p", source: connect.SourceId(connect.ControlId), messageType: protocol.MessageType_PUSH_HINT, transportType: connect.TransportTypeP2p, want: false},
		{name: "push hint unknown", source: connect.SourceId(connect.ControlId), messageType: protocol.MessageType_PUSH_HINT, transportType: connect.TransportTypeUnknown, want: false},
		{name: "push hint no carrier", source: connect.SourceId(connect.ControlId), messageType: protocol.MessageType_PUSH_HINT, transportType: "", want: false},
		{name: "push hint custom carrier", source: connect.SourceId(connect.ControlId), messageType: protocol.MessageType_PUSH_HINT, transportType: "quic", want: false},
		{name: "control hello", source: connect.SourceId(connect.ControlId), messageType: protocol.MessageType_HELLO, transportType: connect.TransportTypeH1, want: false},
		{name: "control ping", source: connect.SourceId(connect.ControlId), messageType: protocol.MessageType_PING, transportType: connect.TransportTypeH1, want: false},
		{name: "control stream data", source: connect.SourceId(connect.ControlId), messageType: protocol.MessageType_STREAM_DATA, transportType: connect.TransportTypeH1, want: false},
		{name: "control error", source: connect.SourceId(connect.ControlId), messageType: protocol.MessageType_ERROR, transportType: connect.TransportTypeH1, want: false},
		{name: "control id with a destination", source: connect.NewTransferPath(connect.ControlId, peerId, connect.Id{}), messageType: protocol.MessageType_PUSH_HINT, transportType: connect.TransportTypeH1, want: false},
		{name: "control id with a stream", source: connect.NewTransferPath(connect.ControlId, connect.Id{}, peerId), messageType: protocol.MessageType_PUSH_HINT, transportType: connect.TransportTypeH1, want: false},
		{name: "peer push reset", source: connect.SourceId(peerId), messageType: protocol.MessageType_PUSH_RESET, transportType: connect.TransportTypeH1, want: false},
		{name: "peer push hint", source: connect.SourceId(peerId), messageType: protocol.MessageType_PUSH_HINT, transportType: connect.TransportTypeH1, want: false},
		{name: "peer push service", source: connect.SourceId(peerId), messageType: protocol.MessageType(0x01FF), transportType: connect.TransportTypeH1, want: false},
		{name: "peer hello h1", source: connect.SourceId(peerId), messageType: protocol.MessageType_HELLO, transportType: connect.TransportTypeH1, want: true},
		{name: "peer hello p2p", source: connect.SourceId(peerId), messageType: protocol.MessageType_HELLO, transportType: connect.TransportTypeP2p, want: true},
		{name: "peer stream data", source: connect.SourceId(peerId), messageType: protocol.MessageType_STREAM_DATA, transportType: connect.TransportTypeP2p, want: true},
	}
	for _, c := range cases {
		if got := sourceAdmits(c.source, uint32(c.messageType), c.transportType); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

// The same table at the handler: ControlId's push reaches its function, with no Hello, no contract and
// no answer, over the platform's carriers only.
func TestControlPushKeptOnlyOverPlatformCarriers(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	pushes := fixture.collect(t, protocol.MessageType_PUSH_HINT)
	kept := []connect.TransportType{
		connect.TransportTypeH1,
		connect.TransportTypeH3,
		connect.TransportTypeH3Dns,
		connect.TransportTypeH3DnsPump,
	}
	dropped := []connect.TransportType{
		connect.TransportTypeP2p,
		connect.TransportTypeUnknown,
		"",
		"quic",
	}
	for _, transportType := range dropped {
		fixture.receive(connect.ControlId, testRequest(protocol.MessageType_PUSH_HINT, []byte{1}), connect.Peer{TransportType: transportType})
	}
	for _, transportType := range kept {
		push := testRequest(protocol.MessageType_PUSH_HINT, []byte{2})
		fixture.receive(connect.ControlId, push, connect.Peer{TransportType: transportType})
		message := testAwait(t, pushes, "push")
		if message.envelope.RequestId != push.RequestId || message.sourceId != connect.ControlId {
			t.Errorf("%s: push %d from %s", transportType, message.envelope.RequestId, message.sourceId)
		}
	}
	stats := &fixture.subprotocol.stats
	if count := stats.sourceDroppedCount.Load(); count != uint64(len(dropped)) {
		t.Errorf("dropped %d", count)
	}
	fixture.closeBalanced(t)
	if len(pushes) != 0 || stats.replyQueuedCount.Load() != 0 {
		t.Errorf("%d pushes past the guard, %d replies", len(pushes), stats.replyQueuedCount.Load())
	}
}

// ControlId's hints answer nothing this side asked, so one flagged as a response still goes to its
// type's function and never to the calls waiting on peers.
func TestControlPushGoesByTypeWhateverItsFlags(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	pushes := fixture.collect(t, protocol.MessageType_PUSH_HINT)
	responses := make(chan *subprotocolMessage, 1)
	remove, err := fixture.subprotocol.setResponseDispatch(func(ctx context.Context, message *subprotocolMessage) {
		responses <- testCopyMessage(message)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	push := testRequest(protocol.MessageType_PUSH_HINT, []byte{1})
	push.Flags = EnvelopeFlagResponse | EnvelopeFlagNoReply
	fixture.receive(connect.ControlId, push, connect.Peer{TransportType: connect.TransportTypeH1})
	if message := testAwait(t, pushes, "push"); message.envelope.RequestId != push.RequestId {
		t.Errorf("push %d", message.envelope.RequestId)
	}
	fixture.closeBalanced(t)
	if len(responses) != 0 {
		t.Error("a hint reached the response dispatch")
	}
}

// Nothing but push comes from ControlId, and no push from a peer, even a verified one; a push type
// nothing registered is left unanswered, since ControlId takes no sends.
func TestGuardDropsWhatComesFromTheWrongSide(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	peerId := connect.NewId()
	fixture.verify(peerId, "a")
	pushes := fixture.collect(t, protocol.MessageType_PUSH_HINT)
	// a push-service number no release uses, so ControlId's worker can be drained
	controlMarkerType := protocol.MessageType(0x01F0)
	controlMarkers := fixture.collect(t, controlMarkerType)
	controlPeer := connect.Peer{TransportType: connect.TransportTypeH1}
	for _, messageType := range []protocol.MessageType{
		protocol.MessageType_HELLO,
		protocol.MessageType_PING,
		protocol.MessageType_HEAD_CHECK,
		protocol.MessageType_STREAM_OPEN,
		protocol.MessageType_ERROR,
		testHeldMessageType,
	} {
		fixture.receive(connect.ControlId, testRequest(messageType, []byte{1}), controlPeer)
	}
	for _, messageType := range []protocol.MessageType{protocol.MessageType_PUSH_RESET, protocol.MessageType_PUSH_HINT} {
		fixture.receive(peerId, testRequest(messageType, []byte{1}), testNetworkPeer("a"))
		fixture.receive(connect.NewId(), testRequest(messageType, []byte{1}), testNetworkPeer("b"))
	}
	stats := &fixture.subprotocol.stats
	if count := stats.sourceDroppedCount.Load(); count != 10 {
		t.Errorf("dropped %d", count)
	}

	// a push of a type nothing takes reaches the worker and stops there
	fixture.receive(connect.ControlId, testRequest(protocol.MessageType_PUSH_RESET, []byte{1}), controlPeer)
	fixture.drain(t, connect.ControlId, controlPeer, controlMarkerType, controlMarkers)
	fixture.closeBalanced(t)
	if len(pushes) != 0 || stats.replyQueuedCount.Load() != 0 || stats.unroutedCount.Load() != 1 {
		t.Errorf("%d pushes, %d replies, %d unrouted", len(pushes), stats.replyQueuedCount.Load(), stats.unroutedCount.Load())
	}
}

// Step 4: Network only, until PROTO-M5-02 and PROTO-M6-01 add Service and FriendsAndFamily. Another
// mode is dropped before the gate, unanswered, even from a verified peer.
func TestProvideModeNetworkOnly(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	peerId := connect.NewId()
	fixture.verify(peerId, "a")
	modes := []connectprotocol.ProvideMode{
		connectprotocol.ProvideMode_None,
		connectprotocol.ProvideMode_FriendsAndFamily,
		connectprotocol.ProvideMode_Public,
		connectprotocol.ProvideMode_Stream,
		connectprotocol.ProvideMode_PublicStream,
		connectprotocol.ProvideMode(6),
	}
	for _, mode := range modes {
		peer := testNetworkPeer("a")
		peer.ProvideMode = mode
		fixture.receive(peerId, testRequest(protocol.MessageType_PING, nil), peer)
	}
	stats := &fixture.subprotocol.stats
	if stats.provideModeDroppedCount.Load() != uint64(len(modes)) || stats.identityRefusedCount.Load() != 0 || stats.replyQueuedCount.Load() != 0 {
		t.Errorf("dropped %d, refused %d, replies %d", stats.provideModeDroppedCount.Load(), stats.identityRefusedCount.Load(), stats.replyQueuedCount.Load())
	}
	fixture.receive(peerId, testRequest(protocol.MessageType_PING, nil), testNetworkPeer("a"))
	if pong := fixture.nextSent(t); pong.envelope.Type != uint32(protocol.MessageType_PONG) {
		t.Errorf("network: type %d", pong.envelope.Type)
	}
	fixture.closeBalanced(t)
}
