//go:build !sidecar_http && !ios_extension

// S8 on T2 (§22.7; §3.7's F7, reach a subnet; BRIDGE-M4-22): sidecartest.BridgeScenarioS8's flow under the scenario
// harness, its canaries planted in the flows' payloads and the route's sealed site, its stores scanned and guarded.
// server's controller package runs the same flow on T3 over its CreateContract (TestScenarioS8OnT3).

package scenario_test

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

func TestScenarioS8(t *testing.T) {
	sidecartest.RunScenario(t, sidecartest.BridgeScenarioS8(nil), nil)
}
