//go:build !sidecar_http && !js

package sidecar

// PROTO-M6-02's lane choice (D-PROTO-10): an initiated send asks connect for its stream lane, which a P2P route may
// carry, only while EnablePeerP2p is on, from a sidecar's dispatcher, to a peer whose Hello verified; a reply keeps
// its request's lane only while the setting is on; and an edge, the control id and an unverified peer get none.

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

func TestPeerLaneOnlyForVerifiedSidecarsWhileEnabled(t *testing.T) {
	pair := newTestRpcPair(t)
	enable := func(settings *SidecarProtocolSettings) {
		settings.EnablePeerP2p = true
	}
	a := pair.add(newTestRpcIdentity(), enable)
	b := pair.add(newTestRpcIdentity(), nil)
	edge := pair.addEdge(enable)

	if opts := a.subprotocol.peerLaneOpts(b.clientId); len(opts) != 0 {
		t.Errorf("a lane before the Hello: %v", opts)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := a.subprotocol.EnsureHello(ctx, Id(b.clientId)); err != nil {
		t.Fatal(err)
	}
	if opts := a.subprotocol.peerLaneOpts(b.clientId); len(opts) != 1 {
		t.Errorf("no stream lane to a verified sidecar with P2P on: %v", opts)
	}
	if opts := b.subprotocol.peerLaneOpts(a.clientId); len(opts) != 0 {
		t.Errorf("a stream lane with P2P off: %v", opts)
	}
	for name, opts := range map[string][]any{
		"the control id": a.subprotocol.peerLaneOpts(connect.ControlId),
		"an edge's":      edge.subprotocol.peerLaneOpts(a.clientId),
		"to an edge":     a.subprotocol.peerLaneOpts(edge.clientId),
	} {
		if len(opts) != 0 {
			t.Errorf("%s: %v", name, opts)
		}
	}

	key := connect.TransferKey{ForceStream: true, CompanionContract: true, LogicalLane: 3}
	if reply := a.subprotocol.replyLane(key); !reply.ForceStream || reply.CompanionContract || reply.LogicalLane != 3 {
		t.Errorf("P2P on: the reply rides %+v", reply)
	}
	if reply := b.subprotocol.replyLane(key); reply.ForceStream || reply.CompanionContract || reply.LogicalLane != 3 {
		t.Errorf("P2P off: the reply rides %+v", reply)
	}
}
