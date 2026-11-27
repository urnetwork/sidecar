//go:build linux && !android && !ios_extension && !sidecar_http

// Linux's discoverer (DESIGN-COMPUTE §26.5's Linux row; LSTN-M13-02): `ur daemon` and an enclave's daemon read their
// sockets from sock_diag and their owners from /proc.
//
//	dump       one NETLINK_SOCK_DIAG socket, through x/sys/unix: an inet_diag_req_v2 dump each for TCP in LISTEN and
//	           for UDP in CLOSE, bound and unconnected, over AF_INET and AF_INET6, read to NLMSG_DONE with its sequence
//	           number checked, from the kernel alone (a reply whose sender is not port 0 is dropped)
//	owners     /proc/<pid>/fd scanned for the sockets new to the poller only, within OwnerScanMaxCount a dump
//	           (listeners_procfs.go)
//	notices    a second netlink socket joined to SKNLGRP_INET_TCP_DESTROY, SKNLGRP_INET_UDP_DESTROY and their IPv6
//	           groups: a notice whose cookie the last dump listed fires Destroyed, so a closed socket leaves at once;
//	           the poll finds new ones. Where the groups cannot be joined, no notice comes, and the poll alone runs
//	ephemeral  /proc/sys/net/ipv4/ip_local_port_range's first port, read at each dump, LinuxEphemeralFirstPort where
//	           it does not read
//
// Never a probe: the only sockets it opens are those two netlink sockets (listenersNetlinkSocket, which the tests
// watch); it sends nothing but its dump requests to the kernel. Both sockets are non-blocking under the runtime's
// poller, so a dump's deadline and Close end a read in flight. Safe for concurrent use as ListenersDiscoverer says.

package sidecar

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// Opens a socket: unix.Socket, which the tests replace to see that discovery opens only netlink sockets.
var listenersNetlinkSocket = unix.Socket

// Where Linux keeps what discovery reads.
const (
	listenersProcRoot      = "/proc"
	listenersPortRangePath = "sys/net/ipv4/ip_local_port_range"
)

// The SKNLGRP_* groups a notice comes from: linux/sock_diag.h's, all four.
var listenersDestroyGroups = []int{
	unix.SKNLGRP_INET_TCP_DESTROY, unix.SKNLGRP_INET_UDP_DESTROY,
	unix.SKNLGRP_INET6_TCP_DESTROY, unix.SKNLGRP_INET6_UDP_DESTROY,
}

// The destruction notices a socket filter keeps: a message whose inet_diag_msg names no remote port (idiag_dport, at
// the nlmsghdr's 16 bytes and the sockid's 2), a listener's or an unconnected UDP socket's. A classic BPF program: load
// the half-word, keep the message where it is 0, else drop it.
var listenersDestroyFilter = []unix.SockFilter{
	{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: listenersNetlinkHeaderByteCount + 6},
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: 0},
	{Code: unix.BPF_RET | unix.BPF_K, K: 0xffffffff},
	{Code: unix.BPF_RET | unix.BPF_K, K: 0},
}

// The two dumps a family takes: TCP in LISTEN, UDP in CLOSE.
var listenersDumpProtocols = []struct {
	ipProtocol uint8
	states     uint32
}{
	{ipProtocol: listenersIpprotoTcp, states: 1 << listenersTcpListen},
	{ipProtocol: listenersIpprotoUdp, states: 1 << listenersTcpClose},
}

// See the file's comment.
type listenersLinuxDiscoverer struct {
	settings *ListenersSettings
	procRoot string
	order    binary.ByteOrder

	dumpFile *os.File
	dumpConn syscall.RawConn
	// nil where the destroy groups could not be joined
	destroyFile *os.File
	destroyed   chan struct{}
	watchDone   chan struct{}

	ephemeralFirstPort atomic.Uint32

	// one dump or owner call at a time, as the poller makes them
	dumpLock sync.Mutex
	sequence uint32
	scanner  *listenersProcScanner

	stateLock sync.Mutex
	// the cookies of the last dump's sockets, which a notice is matched to
	listedCookies map[uint64]bool
	closed        bool
}

// The discoverer this OS has: sock_diag's and /proc's.
func NewListenersDiscoverer(settings *ListenersSettings) (ListenersDiscoverer, error) {
	return newListenersLinuxDiscoverer(settings, listenersProcRoot)
}

// A discoverer reading procRoot for owners and the port range.
func newListenersLinuxDiscoverer(settings *ListenersSettings, procRoot string) (*listenersLinuxDiscoverer, error) {
	if settings == nil {
		settings = DefaultListenersSettings()
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	dumpFile, dumpConn, err := listenersOpenNetlink()
	if err != nil {
		return nil, err
	}
	self := &listenersLinuxDiscoverer{
		settings:      settings,
		procRoot:      procRoot,
		order:         binary.NativeEndian,
		dumpFile:      dumpFile,
		dumpConn:      dumpConn,
		scanner:       newListenersProcScanner(procRoot, uint32(os.Geteuid()), settings.OwnerScanMaxCount),
		listedCookies: map[uint64]bool{},
	}
	self.readPortRange()
	if destroyFile, destroyConn, err := listenersOpenNetlink(); err == nil {
		joined := true
		destroyConn.Control(func(fd uintptr) {
			// a connection's notice names a remote port, a listener's none: the kernel drops the connections' before
			// they wake this process, so a server's churn costs nothing here; where it cannot, the cookies still decide
			unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{
				Len:    uint16(len(listenersDestroyFilter)),
				Filter: &listenersDestroyFilter[0],
			})
			for _, group := range listenersDestroyGroups {
				if unix.SetsockoptInt(int(fd), unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, group) != nil {
					joined = false
				}
			}
		})
		if joined {
			self.destroyFile = destroyFile
			self.destroyed = make(chan struct{}, 1)
			self.watchDone = make(chan struct{})
			go self.watchDestroyed(destroyConn)
		} else {
			destroyFile.Close()
		}
	}
	return self, nil
}

// A NETLINK_SOCK_DIAG socket bound to the kernel's choice of port, non-blocking under the runtime's poller.
func listenersOpenNetlink() (*os.File, syscall.RawConn, error) {
	fd, err := listenersNetlinkSocket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), "sock_diag")
	conn, err := file.SyscallConn()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	return file, conn, nil
}

// See ListenersDiscoverer.
func (self *listenersLinuxDiscoverer) Dump(ctx context.Context) ([]*ListenersSocket, error) {
	self.dumpLock.Lock()
	defer self.dumpLock.Unlock()
	// a dump's reads end at its deadline, and one with none clears an earlier dump's
	deadline, _ := ctx.Deadline()
	self.dumpFile.SetReadDeadline(deadline)
	self.readPortRange()
	listed := []*listenersDiagSocket{}
	for _, family := range []uint8{listenersAfInet, listenersAfInet6} {
		for _, dump := range listenersDumpProtocols {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			replies, err := self.dumpOne(family, dump.ipProtocol, dump.states)
			if err != nil {
				return nil, err
			}
			listed = append(listed, listenersDiagListed(replies, dump.ipProtocol)...)
		}
	}
	cookies := map[uint64]bool{}
	sockets := make([]*ListenersSocket, 0, len(listed))
	for _, reply := range listed {
		cookies[reply.cookie] = true
		sockets = append(sockets, reply.socket)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.listedCookies = cookies
	}()
	return sockets, nil
}

// One request and its replies to NLMSG_DONE.
func (self *listenersLinuxDiscoverer) dumpOne(family uint8, ipProtocol uint8, states uint32) ([]*listenersDiagSocket, error) {
	self.sequence += 1
	sequence := self.sequence
	request := listenersSockDiagRequest(self.order, sequence, family, ipProtocol, states)
	var sendErr error
	if err := self.dumpConn.Write(func(fd uintptr) bool {
		sendErr = unix.Sendto(int(fd), request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		return sendErr != unix.EAGAIN
	}); err != nil {
		return nil, err
	}
	if sendErr != nil {
		return nil, sendErr
	}
	buffer := make([]byte, self.settings.NetlinkReadByteCount)
	replies := []*listenersDiagSocket{}
	for {
		data, err := listenersReadNetlink(self.dumpConn, buffer)
		if err != nil {
			return nil, err
		}
		sockets, done, _, err := listenersParseSockDiag(data, self.order, sequence, ipProtocol)
		if err != nil {
			return nil, err
		}
		replies = append(replies, sockets...)
		if done {
			return replies, nil
		}
	}
}

// One message from the kernel: a read that the buffer cut, or from any sender but the kernel, is no reply.
func listenersReadNetlink(conn syscall.RawConn, buffer []byte) ([]byte, error) {
	for {
		var n int
		var flags int
		var from unix.Sockaddr
		var readErr error
		if err := conn.Read(func(fd uintptr) bool {
			n, _, flags, from, readErr = unix.Recvmsg(int(fd), buffer, nil, 0)
			return readErr != unix.EAGAIN
		}); err != nil {
			return nil, err
		}
		if readErr != nil {
			return nil, readErr
		}
		if flags&unix.MSG_TRUNC != 0 {
			return nil, errListenersSockDiag
		}
		if sender, ok := from.(*unix.SockaddrNetlink); !ok || sender.Pid != 0 {
			// another process's message is never the kernel's answer
			continue
		}
		return buffer[:n], nil
	}
}

// See ListenersDiscoverer.
func (self *listenersLinuxDiscoverer) Owners(ctx context.Context, sockets []*ListenersSocket) error {
	self.dumpLock.Lock()
	defer self.dumpLock.Unlock()
	self.scanner.owners(sockets)
	return ctx.Err()
}

// See ListenersDiscoverer.
func (self *listenersLinuxDiscoverer) Destroyed() <-chan struct{} {
	if self.destroyed == nil {
		return nil
	}
	return self.destroyed
}

// See ListenersDiscoverer.
func (self *listenersLinuxDiscoverer) EphemeralFirstPort() uint16 {
	return uint16(self.ephemeralFirstPort.Load())
}

// Reads ip_local_port_range, LinuxEphemeralFirstPort where it does not read.
func (self *listenersLinuxDiscoverer) readPortRange() {
	first := self.settings.LinuxEphemeralFirstPort
	if data, err := os.ReadFile(filepath.Join(self.procRoot, listenersPortRangePath)); err == nil {
		if read, ok := listenersParsePortRange(string(data)); ok {
			first = read
		}
	}
	self.ephemeralFirstPort.Store(uint32(first))
}

// The notices' loop: each read's cookies against the last dump's, a match firing Destroyed once. A buffer the kernel
// overran (ENOBUFS) may have held a match, so it fires too; any other error ends the loop, the poll still running.
// Reads block under the runtime's poller, so the loop waits on the kernel and ends at Close.
func (self *listenersLinuxDiscoverer) watchDestroyed(conn syscall.RawConn) {
	defer close(self.watchDone)
	buffer := make([]byte, self.settings.NetlinkReadByteCount)
	fire := func() {
		select {
		case self.destroyed <- struct{}{}:
		default:
			// a notice already waits, and one dump answers both
		}
	}
	for {
		data, err := listenersReadNetlink(conn, buffer)
		if errors.Is(err, unix.ENOBUFS) || errors.Is(err, errListenersSockDiag) {
			fire()
			continue
		}
		if err != nil {
			return
		}
		cookies, err := listenersParseSockDiagCookies(data, self.order)
		if err != nil {
			fire()
			continue
		}
		listed := false
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			for _, cookie := range cookies {
				if self.listedCookies[cookie] {
					listed = true
					delete(self.listedCookies, cookie)
				}
			}
		}()
		if listed {
			fire()
		}
	}
}

// See ListenersDiscoverer.
func (self *listenersLinuxDiscoverer) Close() error {
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		closed := self.closed
		self.closed = true
		return closed
	}()
	if closed {
		return nil
	}
	err := self.dumpFile.Close()
	if self.destroyFile != nil {
		self.destroyFile.Close()
		<-self.watchDone
	}
	return err
}
