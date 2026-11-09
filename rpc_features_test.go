//go:build !sidecar_http && !js

// Hello's feature bits (PROTO-M10-01): what SetFeatures sets rides Hello and HelloResult alike, bit 1
// only toward the peers it names; bits this release does not implement are refused; a receiver records a
// peer's bits, ignores those it does not know, and grants nothing by one, its own bit 0 alone deciding
// what a control contract carries to it.

package sidecar

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol"
)

// Bit 0 rides Hello and HelloResult alike, and bit 1 only toward the peers asksSearch names.
func TestFeaturesRideHelloAndHelloResult(t *testing.T) {
	pair := newTestRpcPair(t)
	app := pair.add(nil, nil)
	indexer := pair.add(nil, nil)
	other := pair.add(nil, nil)
	if err := indexer.subprotocol.SetFeatures(SubprotocolFeatureServesSearch, nil); err != nil {
		t.Fatal(err)
	}
	if err := app.subprotocol.SetFeatures(0, func(clientId Id) bool {
		return clientId == Id(indexer.clientId)
	}); err != nil {
		t.Fatal(err)
	}
	for _, peer := range []*testRpcSide{indexer, other} {
		if err := app.subprotocol.EnsureHello(t.Context(), Id(peer.clientId)); err != nil {
			t.Fatal(err)
		}
	}
	if identity, _ := indexer.subprotocol.PeerIdentity(Id(app.clientId)); identity.Features != SubprotocolFeatureAsksSearch {
		t.Errorf("the indexer read the app's features %#x", identity.Features)
	}
	if identity, _ := other.subprotocol.PeerIdentity(Id(app.clientId)); identity.Features != 0 {
		t.Errorf("another peer read the app's features %#x", identity.Features)
	}
	if identity, _ := app.subprotocol.PeerIdentity(Id(indexer.clientId)); identity.Features != SubprotocolFeatureServesSearch {
		t.Errorf("the app read the indexer's HelloResult features %#x", identity.Features)
	}
}

// A bit this release does not implement, and bit 1 toward every peer, are refused.
func TestSetFeaturesRefusesBitsItMayNotSend(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	for _, features := range []uint64{1 << 2, 1 << 63, SubprotocolFeatureAsksSearch, SubprotocolFeatureServesSearch | SubprotocolFeatureAsksSearch} {
		if err := a.subprotocol.SetFeatures(features, nil); !errors.Is(err, errSubprotocolFeatures) {
			t.Errorf("%#x: %v", features, err)
		}
	}
	if err := a.subprotocol.SetFeatures(SubprotocolFeatureServesSearch, nil); err != nil {
		t.Errorf("bit 0: %v", err)
	}
}

// A receiver keeps a peer's bits, unknown ones included, refuses nothing for them, and grants nothing by
// them: a peer claiming bit 0 makes this side serve no SEARCH on control, which its own bit decides.
func TestUnknownBitsAreIgnoredAndBitsGrantNothing(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	a.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
		if from == a && envelope.Type == uint32(protocol.MessageType_HELLO) {
			hello := &protocol.Hello{}
			proto.Unmarshal(envelope.Body, hello)
			hello.Features = SubprotocolFeatureServesSearch | 1<<9 | 1<<40
			envelope.Body, _ = proto.Marshal(hello)
		}
		return envelope
	})
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatalf("unknown bits refused: %v", err)
	}
	if identity, _ := b.subprotocol.PeerIdentity(Id(a.clientId)); identity.Features != SubprotocolFeatureServesSearch|1<<9|1<<40 {
		t.Errorf("recorded %#x", identity.Features)
	}
	ran := make(chan struct{}, 1)
	if _, err := b.subprotocol.Handle(protocol.MessageType_SEARCH, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		ran <- struct{}{}
		return testSearchReply(t, request)
	}, nil); err != nil {
		t.Fatal(err)
	}
	a.setContractClass(connectprotocol.ContractClass_ContractClassControl)
	_, err := a.subprotocol.Call(t.Context(), Id(b.clientId), protocol.MessageType_SEARCH, testSearchRequestBody(t, 1, 0, 1), nil)
	if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_PERMISSION_DENIED {
		t.Errorf("SEARCH on control to a side without its own bit 0: %v", err)
	}
	select {
	case <-ran:
		t.Errorf("a peer's bit opened SEARCH on control")
	default:
	}
}
