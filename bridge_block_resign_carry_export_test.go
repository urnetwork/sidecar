// A bridge for the external tests of the bridge block every reader holds (bridge_block_resign_carry_test.go; QD-1205):
// the record a state's newest base's readers hold, and the block a reader holding none of its own takes from a head.

package sidecar

import (
	"bytes"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// SHA-256 of the BridgeBlock record readers of the state's newest base hold, nil for none (ConfigState's).
func (self *ConfigState) BridgeBlockRecordSha256ForTest() []byte {
	return bytes.Clone(self.bridgeBlockRecordSha256)
}

// The block a reader holding none of its own, a filer's view, takes from head at state (readBridgeBlockInForce).
func ReadBridgeBlockInForceForTest(head *ConfigHead, state *ConfigState) (*bridge.BridgeBlock, error) {
	return readBridgeBlockInForce(head, state)
}
