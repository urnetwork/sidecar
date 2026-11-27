//go:build darwin && !ios && !ios_extension && !sidecar_http

// macOS's discoverer (DESIGN-COMPUTE §26.5's macOS row; LSTN-M13-03): `ur daemon`, and a desktop app where its sandbox
// lets it read the tables, read their sockets from net.inet.tcp.pcblist_n and net.inet.udp.pcblist_n
// (listeners_pcblist.go), unprivileged, and their owners through libproc, which lsof uses, by purego with no cgo:
//
//	sockets  unix.SysctlRaw of each table, a table past TableMaxByteCount a failed dump
//	owners   libproc, loaded at the first lookup: proc_listpids for this user's own processes (every process as root),
//	         proc_pidinfo's PROC_PIDLISTFDS for a process's descriptors, proc_pidfdinfo's PROC_PIDFDSOCKETINFO for a
//	         socket's soi_so, which names the socket as the pcblist's xso_so does, and proc_name; the process the
//	         socket record names as its last user is looked in first. Another user's socket is "another user's
//	         program" (listeners_owners.go). A library that does not load reads as no owners, never a crash
//	notices  none: the poll alone
//
// Never a probe: it opens no socket and sends nothing. Safe for concurrent use as ListenersDiscoverer says.

package sidecar

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"slices"
	"strconv"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// libSystem, which holds libproc, and libproc's identifiers (sys/proc_info.h, libproc.h).
const (
	listenersLibSystemPath         = "/usr/lib/libSystem.B.dylib"
	listenersProcAllPids           = 1
	listenersProcUidOnly           = 4
	listenersProcPidListFds        = 1
	listenersProcFdInfoByteCount   = 8
	listenersProxFdTypeSocket      = 2
	listenersProcPidFdSocketInfo   = 3
	listenersSocketFdInfoByteCount = 792
	listenersSocketFdInfoSoOffset  = 160
	listenersProcNameMaxByteCount  = 2 * 1024
	listenersDarwinTcpPcbListName  = "net.inet.tcp.pcblist_n"
	listenersDarwinUdpPcbListName  = "net.inet.udp.pcblist_n"
)

// libproc does not load here, so no owner is named.
var errListenersNoLibproc = errors.New("listeners: libproc does not load")

// libproc's calls, as purego binds them.
type listenersLibproc struct {
	listPids  func(kind uint32, typeInfo uint32, buffer unsafe.Pointer, size int32) int32
	pidInfo   func(pid int32, flavor int32, argument uint64, buffer unsafe.Pointer, size int32) int32
	pidFdInfo func(pid int32, fd int32, flavor int32, buffer unsafe.Pointer, size int32) int32
	name      func(pid int32, buffer unsafe.Pointer, size uint32) int32
}

// libproc, loaded, or nil where it does not load.
func listenersLoadLibproc() (libproc *listenersLibproc) {
	defer func() {
		// purego panics on a symbol it cannot bind: no owners, never a crash
		if recover() != nil {
			libproc = nil
		}
	}()
	handle, err := purego.Dlopen(listenersLibSystemPath, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return nil
	}
	libproc = &listenersLibproc{}
	purego.RegisterLibFunc(&libproc.listPids, handle, "proc_listpids")
	purego.RegisterLibFunc(&libproc.pidInfo, handle, "proc_pidinfo")
	purego.RegisterLibFunc(&libproc.pidFdInfo, handle, "proc_pidfdinfo")
	purego.RegisterLibFunc(&libproc.name, handle, "proc_name")
	return libproc
}

// The owner scan's source over libproc, for this user's processes or, as root, every process.
type listenersLibprocSource struct {
	libproc   *listenersLibproc
	settings  *ListenersSettings
	euid      uint32
	superuser bool
}

// The pids libproc lists: this user's, or every one as root; none past TableMaxByteCount.
func (self *listenersLibprocSource) pids() []int {
	kind, typeInfo := uint32(listenersProcUidOnly), self.euid
	if self.superuser {
		kind, typeInfo = listenersProcAllPids, 0
	}
	size := self.libproc.listPids(kind, typeInfo, nil, 0)
	if size <= 0 || self.settings.TableMaxByteCount < int(size) {
		return []int{}
	}
	// room for processes started between the two calls
	buffer := make([]byte, min(int(size)*2, self.settings.TableMaxByteCount))
	filled := self.libproc.listPids(kind, typeInfo, unsafe.Pointer(&buffer[0]), int32(len(buffer)))
	pids := []int{}
	for offset := 0; offset+4 <= int(filled) && offset+4 <= len(buffer); offset += 4 {
		if pid := int(int32(binary.NativeEndian.Uint32(buffer[offset:]))); 0 < pid {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	return pids
}

// pid's socket descriptors, from PROC_PIDLISTFDS: none where libproc refuses this process.
func (self *listenersLibprocSource) fds(pid int) []string {
	size := self.libproc.pidInfo(int32(pid), listenersProcPidListFds, 0, nil, 0)
	if size <= 0 || self.settings.TableMaxByteCount < int(size) {
		return []string{}
	}
	buffer := make([]byte, min(int(size)*2, self.settings.TableMaxByteCount))
	filled := self.libproc.pidInfo(int32(pid), listenersProcPidListFds, 0, unsafe.Pointer(&buffer[0]), int32(len(buffer)))
	fds := []string{}
	for offset := 0; offset+listenersProcFdInfoByteCount <= int(filled) && offset+listenersProcFdInfoByteCount <= len(buffer); offset += listenersProcFdInfoByteCount {
		fd := int32(binary.NativeEndian.Uint32(buffer[offset:]))
		if binary.NativeEndian.Uint32(buffer[offset+4:]) == listenersProxFdTypeSocket {
			fds = append(fds, strconv.Itoa(int(fd)))
		}
	}
	return fds
}

// The socket handle, soi_so, behind pid's fd.
func (self *listenersLibprocSource) identity(pid int, fd string) (uint64, bool) {
	number, err := strconv.Atoi(fd)
	if err != nil {
		return 0, false
	}
	buffer := make([]byte, listenersSocketFdInfoByteCount)
	filled := self.libproc.pidFdInfo(int32(pid), int32(number), listenersProcPidFdSocketInfo, unsafe.Pointer(&buffer[0]), int32(len(buffer)))
	if int(filled) < listenersSocketFdInfoSoOffset+8 {
		return 0, false
	}
	return binary.NativeEndian.Uint64(buffer[listenersSocketFdInfoSoOffset:]), true
}

// proc_name's answer.
func (self *listenersLibprocSource) name(pid int) string {
	buffer := make([]byte, listenersProcNameMaxByteCount)
	filled := self.libproc.name(int32(pid), unsafe.Pointer(&buffer[0]), uint32(len(buffer)))
	if filled <= 0 || len(buffer) < int(filled) {
		return ""
	}
	return string(buffer[:filled])
}

// See the file's comment.
type listenersDarwinDiscoverer struct {
	settings *ListenersSettings
	euid     uint32

	// one dump or owner call at a time, as the poller makes them
	callLock    sync.Mutex
	libprocOnce sync.Once
	scanner     *listenersOwnerScanner
	// the pids each listed socket's record names, by its handle, from the last dump
	hints map[uint64][]int32
}

// The discoverer this OS has: pcblist's and libproc's.
func NewListenersDiscoverer(settings *ListenersSettings) (ListenersDiscoverer, error) {
	if settings == nil {
		settings = DefaultListenersSettings()
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	return &listenersDarwinDiscoverer{settings: settings, euid: uint32(os.Geteuid()), hints: map[uint64][]int32{}}, nil
}

// See ListenersDiscoverer.
func (self *listenersDarwinDiscoverer) Dump(ctx context.Context) ([]*ListenersSocket, error) {
	self.callLock.Lock()
	defer self.callLock.Unlock()
	sockets := []*ListenersSocket{}
	hints := map[uint64][]int32{}
	for _, table := range []struct {
		name       string
		ipProtocol uint8
	}{
		{name: listenersDarwinTcpPcbListName, ipProtocol: listenersIpprotoTcp},
		{name: listenersDarwinUdpPcbListName, ipProtocol: listenersIpprotoUdp},
	} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := unix.SysctlRaw(table.name)
		if err != nil {
			return nil, err
		}
		if self.settings.TableMaxByteCount < len(data) {
			return nil, errListenersPcbList
		}
		listed, err := listenersParsePcbList(data, table.ipProtocol, binary.NativeEndian)
		if err != nil {
			return nil, err
		}
		for _, pcb := range listed {
			sockets = append(sockets, pcb.socket)
			hints[pcb.socket.Inode] = []int32{pcb.ePid, pcb.lastPid}
		}
	}
	self.hints = hints
	return sockets, nil
}

// See ListenersDiscoverer. libproc loads at the first call; where it does not, every socket stays unknown.
func (self *listenersDarwinDiscoverer) Owners(ctx context.Context, sockets []*ListenersSocket) error {
	self.callLock.Lock()
	defer self.callLock.Unlock()
	self.libprocOnce.Do(func() {
		if libproc := listenersLoadLibproc(); libproc != nil {
			self.scanner = newListenersOwnerScanner(&listenersLibprocSource{
				libproc: libproc, settings: self.settings, euid: self.euid, superuser: self.euid == 0,
			}, self.euid, self.settings.OwnerScanMaxCount)
		}
	})
	if self.scanner == nil {
		return errListenersNoLibproc
	}
	self.scanner.owners(sockets, self.hints)
	return ctx.Err()
}

// See ListenersDiscoverer: macOS multicasts no destruction.
func (self *listenersDarwinDiscoverer) Destroyed() <-chan struct{} {
	return nil
}

// See ListenersDiscoverer: EphemeralFirstPort.
func (self *listenersDarwinDiscoverer) EphemeralFirstPort() uint16 {
	return self.settings.EphemeralFirstPort
}

// See ListenersDiscoverer: nothing is held open.
func (self *listenersDarwinDiscoverer) Close() error {
	return nil
}
