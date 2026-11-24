//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http && !ios_extension

// A standing filing's idempotence (bridge_standing_filing_idempotent_test.go) on the path the MCP bridge tools take:
// bridge_expose through DaemonBridges over the real filer, with §16.6's stock gate passing the exposure on the engine's
// standing grant (record_gate_standing_bridge_test.go's world), and the filer's view behind the log. A route whose
// answer was lost answers uncertain; asked again it answers the id that landed with nothing asked, posting the same
// bytes again, and the log took one route of the host; withdrawn by bridge_close with a reset, nothing serves it.

package sidecar

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// bridge_expose of a route through the stock gate, its first post applied and its answer lost: uncertain; asked again
// with the view still behind, the same id with nothing asked and the same bytes posted again, the log holding one
// route of the host; and once bridge_close withdraws it with a reset, the host's compile serves no route.
func TestStockGateFilesAStandingRouteWhoseAnswerWasLostOnce(t *testing.T) {
	world := newTestBridgeEffectWorld(t)
	world.grants = world.engine
	world.open()
	lag := newTestStandingLagConfig(world.net)
	world.filer.args.Config = lag
	world.api.answers = []string{"lost"}

	params := &DaemonBridgeExposeParams{Prefixes: []string{"192.168.7.0/24"}}
	if _, err := world.expose(params); !errors.Is(err, ErrBridgeFileUncertain) {
		t.Fatalf("a route whose answer was lost: %v", err)
	}
	landed := world.hostRules(bridge.SignedType_SIGNED_BRIDGE_ROUTE)
	if len(landed) != 1 {
		t.Fatalf("%d routes landed", len(landed))
	}
	again, err := world.expose(params)
	rule := world.standingFiling("the route asked again", again, err)
	if !bytes.Equal(rule.RuleId, landed[0].RuleId) {
		t.Fatalf("the route asked again answered %x, the landed route %x", rule.RuleId, landed[0].RuleId)
	}
	if posted := world.api.postedBytes(); len(posted) != 2 || !bytes.Equal(posted[0], posted[1]) {
		t.Fatalf("%d posts, not each the route's same bytes", len(posted))
	}
	if filings := world.hostFilings(bridge.SignedType_SIGNED_BRIDGE_ROUTE); len(filings) != 1 {
		t.Fatalf("the log took %d routes of the host", len(filings))
	}
	if !world.nothingAsked() {
		t.Fatal("a standing route asked a person")
	}

	lag.catchUp()
	if _, err := world.bridges.CloseId(t.Context(), world.net.networkId, world.sidecar, world.mcp(), &DaemonBridgeCloseParams{Id: again.RuleId, Reset: true}); err != nil {
		t.Fatal(err)
	}
	if _, routeIds := testStandingServing(world.compiledRules()); len(routeIds) != 0 {
		t.Fatalf("after its withdrawal the host serves routes %x", routeIds)
	}
}
