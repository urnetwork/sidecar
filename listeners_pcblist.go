//go:build !ios_extension && !sidecar_http

// macOS's socket tables (DESIGN-COMPUTE §26.5's macOS row; LSTN-M13-03): what `sysctl net.inet.tcp.pcblist_n` and
// `net.inet.udp.pcblist_n` answer, unprivileged, the tables netstat reads. No OS tag: the reader is bytes in and
// sockets out, so its goldens run on every host.
//
// The answer is an xinpgen (its own length first), then one group of records a pcb, each record framed by its own
// length and kind (struct xgen_n) and padded to 8 bytes, then a closing xinpgen: an inpcb record (XSO_INPCB) opens a
// group, and its socket (XSO_SOCKET), buffers, stats and, for TCP, its tcpcb (XSO_TCPCB) follow it. The records are
// xnu's `n` structures, laid out under #pragma pack(4) (bsd/netinet/in_pcb.h, bsd/sys/socketvar.h,
// bsd/netinet/tcp_var.h), and their layouts differ by release, so each record is read by its own length, a record
// shorter than the fields read refused, never indexed past: a refusal fails the dump, which then changes nothing. The
// fields read, verified against a running macOS:
//
//	xinpcb_n   inp_fport @16 and inp_lport @18 (network order), inp_flags @36 (IN6P_IPV6_V6ONLY 0x8000), inp_vflag
//	           @44 (INP_IPV4 0x1, INP_IPV6 0x2), the foreign address @48 and the local @64, 16 bytes each, an IPv4
//	           address in their last 4, and inp6_ifindex @92 for a link-local zone
//	xsocket_n  xso_so @8, the socket's kernel handle, which libproc's soi_so names alike; so_uid @64; so_last_pid @68
//	           and so_e_pid @72, the processes last to use it, a guess at its owner the owner lookup checks first
//	xtcpcb_n   t_state @36 (TCPS_LISTEN 1)
//
// A `::` socket takes IPv4 where its pcb's INP_IPV4 flag is on and IN6P_IPV6_V6ONLY off (§26.5's dual stack); a TCP
// pcb lists only in LISTEN, a UDP one only bound and unconnected, each with a port.

package sidecar

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"

	"github.com/urnetwork/sidecar/protocol"
)

// xnu's identifiers and the offsets the file's comment names.
const (
	listenersXsoSocket           = 0x001
	listenersXsoInpcb            = 0x010
	listenersXsoTcpcb            = 0x020
	listenersXgenHeaderByteCount = 8
	listenersXinpgenByteCount    = 24
	listenersInpFportOffset      = 16
	listenersInpLportOffset      = 18
	listenersInpFlagsOffset      = 36
	listenersInpVflagOffset      = 44
	listenersInpFaddrOffset      = 48
	listenersInpLaddrOffset      = 64
	listenersInpReadByteCount    = 80
	listenersInpIfindexOffset    = 92
	listenersInpIfindexEnd       = 94
	listenersSoHandleOffset      = 8
	listenersSoUidOffset         = 64
	listenersSoLastPidOffset     = 68
	listenersSoEPidOffset        = 72
	listenersSoReadByteCount     = 76
	listenersTcpStateOffset      = 36
	listenersTcpReadByteCount    = 40
	listenersInpIpv4             = 0x1
	listenersInpIpv6             = 0x2
	listenersIn6pIpv6V6only      = 0x8000
	listenersTcpsListen          = 1
)

// A pcblist that does not read: a header or a record shorter than it says or than the fields read.
var errListenersPcbList = errors.New("listeners: a pcblist does not read")

// One listed socket of a pcblist, with the pids its socket record names, which a lookup tries first.
type listenersPcbSocket struct {
	socket  *ListenersSocket
	lastPid int32
	ePid    int32
}

// The listed sockets of a pcblist_n answer for ipProtocol (6 or 17), in order: every TCP pcb in LISTEN, or every UDP
// pcb bound and unconnected, each with a port.
func listenersParsePcbList(data []byte, ipProtocol uint8, order binary.ByteOrder) ([]*listenersPcbSocket, error) {
	if len(data) < listenersXinpgenByteCount {
		return nil, errListenersPcbList
	}
	headerLength := int(order.Uint32(data[0:4]))
	if headerLength < listenersXinpgenByteCount || len(data) < headerLength {
		return nil, errListenersPcbList
	}
	rounded := func(n int) int {
		return (n + 7) &^ 7
	}
	listed := []*listenersPcbSocket{}
	var inpcb, socket, tcpcb []byte
	emit := func() error {
		if inpcb == nil {
			return nil
		}
		defer func() {
			inpcb, socket, tcpcb = nil, nil, nil
		}()
		if socket == nil || (ipProtocol == listenersIpprotoTcp && tcpcb == nil) {
			// a pcb whose socket went as the table was read: nothing to list
			return nil
		}
		if len(inpcb) < listenersInpReadByteCount || len(socket) < listenersSoReadByteCount ||
			(tcpcb != nil && len(tcpcb) < listenersTcpReadByteCount) {
			return errListenersPcbList
		}
		if ipProtocol == listenersIpprotoTcp && order.Uint32(tcpcb[listenersTcpStateOffset:]) != listenersTcpsListen {
			return nil
		}
		port := binary.BigEndian.Uint16(inpcb[listenersInpLportOffset:])
		foreignPort := binary.BigEndian.Uint16(inpcb[listenersInpFportOffset:])
		flags := order.Uint32(inpcb[listenersInpFlagsOffset:])
		vflag := inpcb[listenersInpVflagOffset]
		local := [16]byte(inpcb[listenersInpLaddrOffset : listenersInpLaddrOffset+16])
		foreign := [16]byte(inpcb[listenersInpFaddrOffset : listenersInpFaddrOffset+16])
		if port == 0 || foreignPort != 0 || foreign != [16]byte{} {
			// unbound, or connected: a client's
			return nil
		}
		listedSocket := &ListenersSocket{
			Port:     port,
			Inode:    order.Uint64(socket[listenersSoHandleOffset:]),
			Uid:      order.Uint32(socket[listenersSoUidOffset:]),
			UidKnown: true,
		}
		switch ipProtocol {
		case listenersIpprotoTcp:
			listedSocket.Protocol = protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP
		case listenersIpprotoUdp:
			listedSocket.Protocol = protocol.ListenersProtocol_LISTENERS_PROTOCOL_UDP
		}
		switch {
		case vflag&listenersInpIpv6 != 0:
			listedSocket.Bind = netip.AddrFrom16(local)
			listedSocket.V6Only = vflag&listenersInpIpv4 == 0 || flags&listenersIn6pIpv6V6only != 0
			if listedSocket.Bind.IsLinkLocalUnicast() && listenersInpIfindexEnd <= len(inpcb) {
				if index := order.Uint16(inpcb[listenersInpIfindexOffset:]); index != 0 {
					listedSocket.Bind = listedSocket.Bind.WithZone(strconv.FormatUint(uint64(index), 10))
				}
			}
		case vflag&listenersInpIpv4 != 0:
			listedSocket.Bind = netip.AddrFrom4([4]byte(local[12:16]))
		default:
			return nil
		}
		listed = append(listed, &listenersPcbSocket{
			socket:  listedSocket,
			lastPid: int32(order.Uint32(socket[listenersSoLastPidOffset:])),
			ePid:    int32(order.Uint32(socket[listenersSoEPidOffset:])),
		})
		return nil
	}

	offset := rounded(headerLength)
	for offset < len(data) {
		if len(data)-offset < listenersXgenHeaderByteCount {
			return nil, errListenersPcbList
		}
		length := int(order.Uint32(data[offset:]))
		kind := order.Uint32(data[offset+4:])
		if length <= listenersXinpgenByteCount {
			// the closing xinpgen, which netstat reads as the end too
			break
		}
		if len(data)-offset < length {
			return nil, errListenersPcbList
		}
		record := data[offset : offset+length]
		switch kind {
		case listenersXsoInpcb:
			if err := emit(); err != nil {
				return nil, err
			}
			inpcb = record
		case listenersXsoSocket:
			socket = record
		case listenersXsoTcpcb:
			tcpcb = record
		}
		offset += rounded(length)
	}
	if err := emit(); err != nil {
		return nil, err
	}
	return listed, nil
}
