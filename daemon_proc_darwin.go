//go:build darwin && !ios && !sdk_mobile_bind

// The process table on macOS (daemon_proc.go): kern.proc.pid's kinfo_proc, its p_comm, e_ppid and p_starttime, so a
// start time is Unix milliseconds. The peer's pid is LOCAL_PEERPID's.

package sidecar

import (
	"bytes"
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// The process of pid, from the kernel.
func systemProcess(pid int) (*ProcessInfo, error) {
	kinfo, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || kinfo == nil || int(kinfo.Proc.P_pid) != pid {
		// a pid with no process answers a zeroed entry rather than an error
		return nil, ErrProcessUnknown
	}
	name := kinfo.Proc.P_comm[:]
	if end := bytes.IndexByte(name, 0); 0 <= end {
		name = name[:end]
	}
	startTime := kinfo.Proc.P_starttime
	return &ProcessInfo{
		Identity: ProcessIdentity{
			Pid:         pid,
			StartMillis: int64(startTime.Sec)*1000 + int64(startTime.Usec)/1000,
		},
		ParentPid: int(kinfo.Eproc.Ppid),
		Name:      string(name),
	}, nil
}

// The pid at conn's other end, by LOCAL_PEERPID; 0 when it cannot be read.
func daemonPeerPid(conn net.Conn) int {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0
	}
	pid := 0
	pidErr := errors.New("unread")
	if err := raw.Control(func(fd uintptr) {
		pid, pidErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil || pidErr != nil {
		return 0
	}
	return pid
}
