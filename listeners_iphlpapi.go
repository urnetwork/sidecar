//go:build !ios_extension && !sidecar_http

// Windows' socket tables (DESIGN-COMPUTE §26.5's Windows row; LSTN-M13-03): what iphlpapi's GetExtendedTcpTable
// (TCP_TABLE_OWNER_PID_LISTENER) and GetExtendedUdpTable (UDP_TABLE_OWNER_PID) answer for AF_INET and AF_INET6, each
// row with its owning pid, and the owners' names. No OS tag: the reader is bytes in and sockets out, so its goldens run
// on every host, and the naming takes its image-name call as a function.
//
// Each table is a DWORD count and then its rows (tcpmib.h, udpmib.h): MIB_TCPROW_OWNER_PID (24 bytes: state, local
// address, local port, remote address, remote port, pid), MIB_TCP6ROW_OWNER_PID (56: local address, scope, port, remote
// address, scope, port, state, pid), MIB_UDPROW_OWNER_PID (12: address, port, pid) and MIB_UDP6ROW_OWNER_PID (28:
// address, scope, port, pid). An address is in network order, a port in network order in its DWORD's low half, every
// other field the host's. A table whose count claims more rows than it holds fails the dump.
//
// Windows' tables do not say whether a `::` socket takes IPv4, so such a row is listed with v4_uncertain (§26.5's v4?),
// never read as taking IPv4. Owners: pid 0 and 4, the idle process and System, are "a system program", and so is any
// process whose image name QueryFullProcessImageNameW under PROCESS_QUERY_LIMITED_INFORMATION refuses; another's name
// is its image's file name. The tables name no user, so a Windows list has no "another user's program".

package sidecar

import (
	"encoding/binary"
	"errors"
	"hash/fnv"
	"net/netip"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// The rows' layouts and iphlpapi's identifiers.
const (
	listenersMibTcpRowByteCount  = 24
	listenersMibTcp6RowByteCount = 56
	listenersMibUdpRowByteCount  = 12
	listenersMibUdp6RowByteCount = 28
	listenersMibTcpStateListen   = 2
	listenersWindowsIdlePid      = 0
	listenersWindowsSystemPid    = 4
)

// A table that does not read: shorter than its count says.
var errListenersIpHelperTable = errors.New("listeners: an iphlpapi table does not read")

// The listed sockets of one table: TCP rows in LISTEN, or UDP rows, of ipProtocol (6 or 17) and the family (ipv6 or
// not), each with a port, its pid, and an identity hashed from its protocol, address, port and pid.
func listenersParseIpHelperTable(data []byte, ipProtocol uint8, ipv6 bool, order binary.ByteOrder) ([]*ListenersSocket, error) {
	if len(data) < 4 {
		return nil, errListenersIpHelperTable
	}
	count := int(order.Uint32(data[0:4]))
	var rowByteCount int
	switch {
	case ipProtocol == listenersIpprotoTcp && !ipv6:
		rowByteCount = listenersMibTcpRowByteCount
	case ipProtocol == listenersIpprotoTcp && ipv6:
		rowByteCount = listenersMibTcp6RowByteCount
	case ipProtocol == listenersIpprotoUdp && !ipv6:
		rowByteCount = listenersMibUdpRowByteCount
	case ipProtocol == listenersIpprotoUdp && ipv6:
		rowByteCount = listenersMibUdp6RowByteCount
	default:
		return nil, errListenersIpHelperTable
	}
	if count < 0 || (len(data)-4)/rowByteCount < count {
		return nil, errListenersIpHelperTable
	}
	sockets := make([]*ListenersSocket, 0, count)
	for index := range count {
		row := data[4+index*rowByteCount : 4+(index+1)*rowByteCount]
		var bind netip.Addr
		var portBytes []byte
		var pid uint32
		state := uint32(listenersMibTcpStateListen)
		switch rowByteCount {
		case listenersMibTcpRowByteCount:
			state = order.Uint32(row[0:4])
			bind = netip.AddrFrom4([4]byte(row[4:8]))
			portBytes = row[8:10]
			pid = order.Uint32(row[20:24])
		case listenersMibTcp6RowByteCount:
			bind = netip.AddrFrom16([16]byte(row[0:16]))
			portBytes = row[20:22]
			state = order.Uint32(row[48:52])
			pid = order.Uint32(row[52:56])
		case listenersMibUdpRowByteCount:
			bind = netip.AddrFrom4([4]byte(row[0:4]))
			portBytes = row[4:6]
			pid = order.Uint32(row[8:12])
		case listenersMibUdp6RowByteCount:
			bind = netip.AddrFrom16([16]byte(row[0:16]))
			portBytes = row[20:22]
			pid = order.Uint32(row[24:28])
		}
		port := binary.BigEndian.Uint16(portBytes)
		if port == 0 || state != listenersMibTcpStateListen {
			continue
		}
		socket := &ListenersSocket{Bind: bind, Port: port, Pid: int32(pid)}
		switch ipProtocol {
		case listenersIpprotoTcp:
			socket.Protocol = protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP
		case listenersIpprotoUdp:
			socket.Protocol = protocol.ListenersProtocol_LISTENERS_PROTOCOL_UDP
		}
		if ipv6 {
			// only "::" might take IPv4, and the table does not say
			socket.V4Uncertain = bind.IsUnspecified()
			socket.V6Only = !bind.IsUnspecified()
		}
		if pid == listenersWindowsIdlePid || pid == listenersWindowsSystemPid {
			socket.Owner = ListenersOwnerSystem
		}
		hash := fnv.New64a()
		hash.Write([]byte{ipProtocol})
		hash.Write(bind.AsSlice())
		hash.Write(portBytes)
		hash.Write(row[len(row)-4:])
		socket.Inode = hash.Sum64()
		sockets = append(sockets, socket)
	}
	return sockets, nil
}

// Names the owners of sockets by their rows' pids, at most maxCount image-name calls, each pid asked once; a pid
// imageName refuses is a system program's. imageName answers a process's image path, or false where it is refused.
func listenersWindowsOwners(sockets []*ListenersSocket, imageName func(pid uint32) (string, bool), maxCount int) {
	names := map[int32]string{}
	for _, socket := range sockets {
		if socket.Owner != ListenersOwnerUnknown {
			continue
		}
		if socket.Pid == listenersWindowsIdlePid || socket.Pid == listenersWindowsSystemPid {
			socket.Owner = ListenersOwnerSystem
			continue
		}
		program, asked := names[socket.Pid]
		if !asked {
			if maxCount <= 0 {
				// the next dump asks the rest
				continue
			}
			maxCount -= 1
			if path, ok := imageName(uint32(socket.Pid)); ok {
				program = path[strings.LastIndexAny(path, `\/`)+1:]
			}
			names[socket.Pid] = program
		}
		if program == "" {
			socket.Owner = ListenersOwnerSystem
		} else {
			socket.Owner = ListenersOwnerProgram
			socket.Program = program
		}
	}
}
