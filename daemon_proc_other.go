//go:build !js && !ios && !android && !sdk_mobile_bind && !linux && !darwin && !windows

// The process table where §16.7 names none (daemon_proc.go): every lookup fails, so no session or command is placed
// under a harness, and each reads unbound and so tainted.

package sidecar

import (
	"net"
)

// No process is readable here.
func systemProcess(pid int) (*ProcessInfo, error) {
	return nil, ErrProcessUnknown
}

// No peer's pid is readable here.
func daemonPeerPid(conn net.Conn) int {
	return 0
}
