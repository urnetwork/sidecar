//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package sidecar

import (
	"testing"
)

// What bridge_discovery_privacy_test.go, in sidecar_test, reaches of the discovery tests' world: host A gathering
// gathered and sharing the host labels shares, viewer B watching it, both logging to log; attach starts their watches,
// awaitView waits for B's view as discoveryTestViewString reads it, and devices answers A's and B's listings.
type BridgeDiscoveryPrivacyWorld struct {
	world *discoveryTestWorld
}

// A world over the options.
func NewBridgeDiscoveryPrivacyWorld(t *testing.T, log Logger, shares []string, gathered ...*BridgeDiscoveryGathered) *BridgeDiscoveryPrivacyWorld {
	return &BridgeDiscoveryPrivacyWorld{world: newDiscoveryTestWorldOf(t, &discoveryTestWorldOptions{log: log, gathered: gathered, shares: shares})}
}

func (self *BridgeDiscoveryPrivacyWorld) Attach() {
	self.world.attach()
}

func (self *BridgeDiscoveryPrivacyWorld) AwaitView(want string) {
	self.world.awaitView(want)
}

func (self *BridgeDiscoveryPrivacyWorld) Devices() (*DaemonBridgeDevicesReply, *DaemonBridgeDevicesReply) {
	return self.world.host.Devices(), self.world.viewer.Devices()
}

// The viewer's view, whole.
func (self *BridgeDiscoveryPrivacyWorld) View() []*BridgeDiscoveryViewInstance {
	return self.world.viewer.View()
}

// The time each viewer instance and answer is read at, for building gathered instances that outlive the test.
var BridgeDiscoveryPrivacyNow = discoveryTestNow
