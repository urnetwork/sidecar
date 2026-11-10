//go:build linux && !android && !sdk_mobile_bind

// The process table on Linux (daemon_proc.go): /proc/<pid>/stat, which daemon_proc.go's parseProcStat reads, so its
// start time is milliseconds since boot. The peer's pid is SO_PEERCRED's.

package sidecar

import (
	"errors"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// The process of pid, from /proc.
func systemProcess(pid int) (*ProcessInfo, error) {
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return nil, ErrProcessUnknown
	}
	return parseProcStat(pid, stat)
}

// The pid at conn's other end, by SO_PEERCRED; 0 when it cannot be read.
func daemonPeerPid(conn net.Conn) int {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0
	}
	var ucred *unix.Ucred
	credErr := errors.New("unread")
	if err := raw.Control(func(fd uintptr) {
		ucred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil {
		return 0
	}
	return int(ucred.Pid)
}
