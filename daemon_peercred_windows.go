//go:build windows && !sdk_mobile_bind

// The peer check on Windows (§5.8): the pipe's DACL grants the user's SID alone (daemon_socket_windows.go), so a
// connection that opened it is the user's, and nothing more is read here.

package sidecar

import (
	"net"
)

// Every peer that opened the pipe passed its DACL.
func checkDaemonPeer(conn net.Conn) error {
	return nil
}
