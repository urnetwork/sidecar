//go:build windows && !sdk_mobile_bind

// The process table on Windows (daemon_proc.go): a Toolhelp snapshot's entry for the pid, its executable and its
// parent's pid, and GetProcessTimes' creation time, so a start time is Unix milliseconds. Windows keeps a parent's pid
// after the parent exits and hands it out again, which daemon_proc.go's start-time rule catches. A process this user
// may not query has no start time, so it reads unknown and ends a walk there. The peer's pid is the pipe client's.

package sidecar

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The process of pid, from a snapshot and its handle's times.
func systemProcess(pid int) (*ProcessInfo, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, ErrProcessUnknown
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{}
	entry.Size = uint32(unsafe.Sizeof(entry))
	found := false
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		if int(entry.ProcessID) == pid {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrProcessUnknown
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil, ErrProcessUnknown
	}
	defer windows.CloseHandle(handle)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return nil, ErrProcessUnknown
	}
	return &ProcessInfo{
		Identity:  ProcessIdentity{Pid: pid, StartMillis: creation.Nanoseconds() / 1000000},
		ParentPid: int(entry.ParentProcessID),
		Name:      processBaseName(windows.UTF16ToString(entry.ExeFile[:])),
	}, nil
}

// The pid at conn's other end, the pipe's client; 0 when it cannot be read.
func daemonPeerPid(conn net.Conn) int {
	file, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return 0
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(file.Fd()), &pid); err != nil {
		return 0
	}
	return int(pid)
}
