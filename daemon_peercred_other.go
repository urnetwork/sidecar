//go:build !js && !ios && !android && !sdk_mobile_bind && !linux && !darwin && !windows

// The peer check where §5.8 names none: refused, so a daemon built for another system serves no one until its
// check is written.

package sidecar

import (
	"errors"
	"net"
)

// Refuses every peer.
func checkDaemonPeer(conn net.Conn) error {
	return errors.New("no peer check on this system")
}
