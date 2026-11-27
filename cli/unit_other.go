//go:build !darwin && !linux && !windows

// No daemon unit on a system ur is not released for, and no socket one hands over.

package main

import (
	"errors"
	"net"

	"github.com/urnetwork/sidecar"
)

func hostUnitEnv() (*unitEnv, error) {
	return nil, errors.New("no daemon unit on this system")
}

// No unit holds the gateway's port here.
func urGatewayInheritedListeners(log sidecar.Logger) []net.Listener {
	return nil
}
