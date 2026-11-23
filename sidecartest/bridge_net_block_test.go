//go:build !sidecar_http && !ios_extension

// BridgeNet's block over §17.4's first block row: the bootstrap draws a block into the network's first head before the
// fixture sets its own, so the fixture may write a block the head holds already, signed alike, since the owner's
// device signs the same record the same way. That saves nothing and answers the tip; it used to stop the test, which a
// 1-in-62 draw of the fixture's block did in FS-38's and FS-56's setups.

package sidecartest_test

import (
	"net/netip"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/sidecartest"
)

// Setting the block the head holds saves no head and answers the tip, again and again; another block lands its base.
func TestBridgeNetSetsTheBlockItsHeadHoldsAlready(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	world := sidecartest.NewBridgeNet(t, net, nil)
	t.Cleanup(world.Close)
	block := world.Settings().Block
	held := world.SetBlock(block)
	again := world.SetBlock(block)
	if held == nil || !proto.Equal(held, again) {
		t.Fatalf("setting the block the head holds moved the log from %v to %v", held, again)
	}
	moved := world.SetBlock(netip.MustParsePrefix("100.81.0.0/16"))
	if moved.GetVersion() <= held.GetVersion() {
		t.Fatalf("another block landed no base: %v after %v", moved, held)
	}
}
