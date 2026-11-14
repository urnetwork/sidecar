// The forwarding setup's control methods on ur daemon (BRIDGE-M8-06; §18.6's setup row): bridge.forwarding.setup and
// bridge.forwarding.witness, which a paired remote-mode app calls for its VPN component. Each resolves its network's
// Sidecar per call and refuses every caller but that app's control session, and every call while no setup is installed
// on the Sidecar: ur daemon installs none until it follows each network's config (question
// bridge-m4-16-daemon-config-follower), the closed direction.

package main

import (
	"github.com/urnetwork/sidecar"
)

func init() {
	urDaemonMethodExtensions = append(urDaemonMethodExtensions, urForwardingMethods)
}

// The forwarding methods, over any target: each finds its network's Sidecar per call.
func urForwardingMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	return sidecar.DaemonForwardingMethods()
}
