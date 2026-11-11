//go:build !sidecar_http && !js

package sidecar

// §6.10.1 items 4 and 5 on §6's side (PROTO-M6-01; C18, D-PROTO-9, D-PROTO-15): a share's contract is
// FriendsAndFamily and carries IP alone, so 21842 from a FriendsAndFamily source, a Hello, an RPC or a stream's open
// and frames, is dropped at the inline handler's mode check, counted, unanswered, even from a peer whose Hello
// verified on a Network contract; and a sidecar provides FriendsAndFamily only while an inbound share holds it,
// through HoldProvideMode, which never adds Public.

import (
	"slices"
	"testing"

	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

func TestShareSourceCarriesNo21842(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	peerId := connect.NewId()
	// the same peer's Hello verified over a Network contract: what a FriendsAndFamily one carries is still dropped
	fixture.verify(peerId, "a")
	share := testNetworkPeer("a")
	share.ProvideMode = connectprotocol.ProvideMode_FriendsAndFamily
	envelopes := []*protocol.Envelope{
		testRequest(protocol.MessageType_HELLO, []byte{1}),
		testRequest(protocol.MessageType_PING, nil),
		testRequest(testHeldMessageType, []byte{1}),
		testRequest(protocol.MessageType_HEAD_CHECK, []byte{1}),
		{Version: WireVersionMajor, Type: uint32(protocol.MessageType_STREAM_OPEN), StreamId: 2, Flags: EnvelopeFlagNoReply, Body: []byte{1}},
		{Version: WireVersionMajor, Type: uint32(protocol.MessageType_STREAM_DATA), StreamId: 2, Flags: EnvelopeFlagNoReply, Body: []byte{1}},
	}
	for _, envelope := range envelopes {
		fixture.receive(peerId, envelope, share)
	}
	stats := &fixture.subprotocol.stats
	if stats.provideModeDroppedCount.Load() != uint64(len(envelopes)) || stats.replyQueuedCount.Load() != 0 || stats.dispatchedCount.Load() != 0 {
		t.Errorf("dropped %d of %d, replies %d, dispatched %d", stats.provideModeDroppedCount.Load(), len(envelopes), stats.replyQueuedCount.Load(), stats.dispatchedCount.Load())
	}
	// the peer's Network contract still carries it
	fixture.receive(peerId, testRequest(protocol.MessageType_PING, nil), testNetworkPeer("a"))
	if pong := fixture.nextSent(t); pong.envelope.Type != uint32(protocol.MessageType_PONG) {
		t.Errorf("network: type %d", pong.envelope.Type)
	}
	fixture.closeBalanced(t)
}

// FriendsAndFamily is held only while a share holds it: held, the client provides it beside Network; released by
// its last hold, it goes; and Public is never added (D-PROTO-6).
func TestShareHoldsFriendsAndFamilyOnlyWhileItLives(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	modes := func() []connectprotocol.ProvideMode {
		provided := []connectprotocol.ProvideMode{}
		for mode, on := range fixture.subprotocol.providedModes() {
			if on {
				provided = append(provided, mode)
			}
		}
		slices.Sort(provided)
		return provided
	}
	network := []connectprotocol.ProvideMode{connectprotocol.ProvideMode_Network}
	shared := []connectprotocol.ProvideMode{connectprotocol.ProvideMode_Network, connectprotocol.ProvideMode_FriendsAndFamily}
	slices.Sort(shared)
	if !slices.Equal(modes(), network) {
		t.Fatalf("before any share: %v", modes())
	}
	first, err := fixture.subprotocol.HoldProvideMode(connectprotocol.ProvideMode_FriendsAndFamily)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.subprotocol.HoldProvideMode(connectprotocol.ProvideMode_FriendsAndFamily)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(modes(), shared) {
		t.Errorf("two shares: %v", modes())
	}
	first()
	first()
	if !slices.Equal(modes(), shared) {
		t.Errorf("one share left: %v", modes())
	}
	second()
	if !slices.Equal(modes(), network) {
		t.Errorf("no share left: %v", modes())
	}
	if _, err := fixture.subprotocol.HoldProvideMode(connectprotocol.ProvideMode_Public); err == nil {
		t.Error("Public was held")
	}
	fixture.closeBalanced(t)
}
