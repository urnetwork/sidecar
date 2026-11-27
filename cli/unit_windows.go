// The Windows host's unit environment: a Task Scheduler logon task needs nothing but the OS (§5.8). A logon task holds
// no socket, so the daemon binds the gateway's port itself at its start (DESIGN-COMPUTE §8.4's "where the OS offers
// it").

package main

import (
	"net"

	"github.com/urnetwork/sidecar"
)

// This user's environment for a logon task.
func hostUnitEnv() (*unitEnv, error) {
	return &unitEnv{goos: "windows"}, nil
}

// No unit holds the gateway's port here.
func urGatewayInheritedListeners(log sidecar.Logger) []net.Listener {
	return nil
}
