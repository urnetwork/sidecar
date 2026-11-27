//go:build windows && !ios_extension && !sidecar_http

// Windows' discoverer (DESIGN-COMPUTE §26.5's Windows row; LSTN-M13-03): `ur daemon`, and the desktop app where it may,
// read their sockets from iphlpapi's owner tables (listeners_iphlpapi.go), through x/sys/windows's lazy procs with no
// cgo:
//
//	sockets  GetExtendedTcpTable (TCP_TABLE_OWNER_PID_LISTENER) and GetExtendedUdpTable (UDP_TABLE_OWNER_PID), AF_INET
//	         and AF_INET6, each asked for its size and then read, once more with the size answered where the table
//	         grew in between (ERROR_INSUFFICIENT_BUFFER), within TableMaxByteCount
//	owners   each row's pid; QueryFullProcessImageNameW on a handle opened with PROCESS_QUERY_LIMITED_INFORMATION, and
//	         "a system program" where it is refused
//	notices  none: the poll alone
//
// Never a probe: it opens no socket and sends nothing. Safe for concurrent use as ListenersDiscoverer says.

package sidecar

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// iphlpapi's identifiers (iprtrmib.h, iphlpapi.h).
const (
	listenersTcpTableOwnerPidListener = 3
	listenersUdpTableOwnerPid         = 1
	listenersWindowsAfInet            = 2
	listenersWindowsAfInet6           = 23
)

var (
	listenersIpHelper              = windows.NewLazySystemDLL("iphlpapi.dll")
	listenersGetExtendedTcpTable   = listenersIpHelper.NewProc("GetExtendedTcpTable")
	listenersGetExtendedUdpTable   = listenersIpHelper.NewProc("GetExtendedUdpTable")
	errListenersIpHelperUnanswered = errors.New("listeners: an iphlpapi table was not answered")
)

// See the file's comment.
type listenersWindowsDiscoverer struct {
	settings *ListenersSettings
	// one dump or owner call at a time, as the poller makes them
	callLock sync.Mutex
}

// The discoverer this OS has: iphlpapi's.
func NewListenersDiscoverer(settings *ListenersSettings) (ListenersDiscoverer, error) {
	if settings == nil {
		settings = DefaultListenersSettings()
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	return &listenersWindowsDiscoverer{settings: settings}, nil
}

// One table: its size asked, then read, once more where it grew, within TableMaxByteCount.
func (self *listenersWindowsDiscoverer) table(proc *windows.LazyProc, family uint32, class uint32) ([]byte, error) {
	if err := proc.Find(); err != nil {
		return nil, err
	}
	size := uint32(0)
	result, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(class), 0)
	for attempt := 0; attempt < 2; attempt++ {
		if result != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) || size == 0 || uint32(self.settings.TableMaxByteCount) < size {
			break
		}
		buffer := make([]byte, size)
		result, _, _ = proc.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(class), 0)
		if result == uintptr(windows.NO_ERROR) {
			return buffer[:min(int(size), len(buffer))], nil
		}
	}
	return nil, errListenersIpHelperUnanswered
}

// See ListenersDiscoverer.
func (self *listenersWindowsDiscoverer) Dump(ctx context.Context) ([]*ListenersSocket, error) {
	self.callLock.Lock()
	defer self.callLock.Unlock()
	sockets := []*ListenersSocket{}
	for _, table := range []struct {
		proc       *windows.LazyProc
		class      uint32
		ipProtocol uint8
	}{
		{proc: listenersGetExtendedTcpTable, class: listenersTcpTableOwnerPidListener, ipProtocol: listenersIpprotoTcp},
		{proc: listenersGetExtendedUdpTable, class: listenersUdpTableOwnerPid, ipProtocol: listenersIpprotoUdp},
	} {
		for _, family := range []uint32{listenersWindowsAfInet, listenersWindowsAfInet6} {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			data, err := self.table(table.proc, family, table.class)
			if err != nil {
				return nil, err
			}
			listed, err := listenersParseIpHelperTable(data, table.ipProtocol, family == listenersWindowsAfInet6, binary.NativeEndian)
			if err != nil {
				return nil, err
			}
			sockets = append(sockets, listed...)
		}
	}
	return sockets, nil
}

// See ListenersDiscoverer.
func (self *listenersWindowsDiscoverer) Owners(ctx context.Context, sockets []*ListenersSocket) error {
	self.callLock.Lock()
	defer self.callLock.Unlock()
	listenersWindowsOwners(sockets, func(pid uint32) (string, bool) {
		handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			return "", false
		}
		defer windows.CloseHandle(handle)
		buffer := make([]uint16, self.settings.ImageNameMaxCharCount)
		size := uint32(len(buffer))
		if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
			return "", false
		}
		return windows.UTF16ToString(buffer[:size]), true
	}, self.settings.OwnerScanMaxCount)
	return ctx.Err()
}

// See ListenersDiscoverer: Windows multicasts no destruction.
func (self *listenersWindowsDiscoverer) Destroyed() <-chan struct{} {
	return nil
}

// See ListenersDiscoverer: EphemeralFirstPort.
func (self *listenersWindowsDiscoverer) EphemeralFirstPort() uint16 {
	return self.settings.EphemeralFirstPort
}

// See ListenersDiscoverer: nothing is held open.
func (self *listenersWindowsDiscoverer) Close() error {
	return nil
}
