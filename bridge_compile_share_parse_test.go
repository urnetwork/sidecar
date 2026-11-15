// The device role's parser for the root's compile tests (bridge_compile_share_test.go): an external test, so the root
// links no device/ (§4.4), installing device.ParseBridgeRules where the internal tests read it.

package sidecar_test

import (
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
)

func init() {
	sidecar.BridgeRulesParserForTest = func(rules []byte) error {
		_, err := device.ParseBridgeRules(rules, nil)
		return err
	}
}
