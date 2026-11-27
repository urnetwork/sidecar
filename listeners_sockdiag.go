//go:build !ios_extension && !sidecar_http

// Linux's sock_diag messages (DESIGN-COMPUTE §26.5; LSTN-M13-02): the inet_diag_req_v2 dump a NETLINK_SOCK_DIAG
// socket sends, and the reader of what comes back, a multipart run of inet_diag_msg replies ended by NLMSG_DONE, each
// with its attributes, INET_DIAG_SKV6ONLY among them, and of the destruction notices the SKNLGRP_INET*_DESTROY groups
// multicast. No OS tag: the reader is bytes in and sockets out, so its goldens run on every host, the byte order a
// parameter (the kernel's own, the host's, on Linux; the goldens' little-endian elsewhere).
//
// The layouts are linux/netlink.h's, linux/sock_diag.h's and linux/inet_diag.h's: a 16-byte nlmsghdr, the 56-byte
// request and the 72-byte inet_diag_msg, each message 4-byte aligned. Ports and addresses are in network order, every
// other field in the host's. A reply that is short, overlong, or claims more than the bytes hold fails the whole dump,
// which then changes nothing; a reply of another dump's sequence number, one an earlier dump cut short left behind, is
// skipped.

package sidecar

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// netlink's and inet_diag's identifiers and layout, from the kernel's headers.
const (
	listenersNetlinkHeaderByteCount = 16
	listenersNetlinkAlign           = 4
	listenersNlmsgError             = 2
	listenersNlmsgDone              = 3
	listenersNlmFRequest            = 0x1
	listenersNlmFDump               = 0x300
	listenersSockDiagByFamily       = 20
	listenersInetDiagReqByteCount   = 56
	listenersInetDiagMsgByteCount   = 72
	listenersRtattrHeaderByteCount  = 4
	listenersNlaTypeMask            = 0x3fff
	listenersInetDiagSkv6only       = 11
	listenersAfInet                 = 2
	listenersAfInet6                = 10
	listenersIpprotoTcp             = 6
	listenersIpprotoUdp             = 17
	listenersTcpEstablished         = 1
	listenersTcpClose               = 7
	listenersTcpListen              = 10
)

// A dump's reply that is not one: short, overlong, an error the kernel sent, or a type no dump answers.
var errListenersSockDiag = errors.New("listeners: a sock_diag reply does not read")

// One socket of a reply: what ListenersSocket holds, and the kernel's state and cookie, which a destruction notice
// names its socket by.
type listenersDiagSocket struct {
	socket *ListenersSocket
	state  uint8
	cookie uint64
	// set where the reply names a remote end: a connected UDP socket's, a client's
	connected bool
}

// n rounded up to netlink's alignment.
func listenersNetlinkAligned(n int) int {
	return (n + listenersNetlinkAlign - 1) &^ (listenersNetlinkAlign - 1)
}

// One dump request: an nlmsghdr of SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST and NLM_F_DUMP, then an inet_diag_req_v2 for
// family and ipProtocol over the states in the mask (1 << state), every address and port.
func listenersSockDiagRequest(order binary.ByteOrder, sequence uint32, family uint8, ipProtocol uint8, states uint32) []byte {
	message := make([]byte, listenersNetlinkHeaderByteCount+listenersInetDiagReqByteCount)
	order.PutUint32(message[0:4], uint32(len(message)))
	order.PutUint16(message[4:6], listenersSockDiagByFamily)
	order.PutUint16(message[6:8], listenersNlmFRequest|listenersNlmFDump)
	order.PutUint32(message[8:12], sequence)
	// nlmsg_pid 0: the kernel answers to the socket's own port id
	request := message[listenersNetlinkHeaderByteCount:]
	request[0] = family
	request[1] = ipProtocol
	// idiag_ext 0: INET_DIAG_SKV6ONLY comes with every IPv6 socket in LISTEN or CLOSE unasked
	order.PutUint32(request[4:8], states)
	return message
}

// The messages of one read: each inet_diag_msg of sequence as a socket of ipProtocol, whether NLMSG_DONE ended the
// dump, and how many messages of another sequence it skipped. An NLMSG_ERROR or a negative NLMSG_DONE is a failed dump.
func listenersParseSockDiag(data []byte, order binary.ByteOrder, sequence uint32, ipProtocol uint8) (sockets []*listenersDiagSocket, done bool, skipped int, err error) {
	sockets = []*listenersDiagSocket{}
	for 0 < len(data) {
		if len(data) < listenersNetlinkHeaderByteCount {
			return nil, false, skipped, errListenersSockDiag
		}
		length := int(order.Uint32(data[0:4]))
		messageType := order.Uint16(data[4:6])
		messageSequence := order.Uint32(data[8:12])
		if length < listenersNetlinkHeaderByteCount || len(data) < length {
			return nil, false, skipped, errListenersSockDiag
		}
		body := data[listenersNetlinkHeaderByteCount:length]
		advance := min(listenersNetlinkAligned(length), len(data))
		data = data[advance:]
		if messageSequence != sequence {
			skipped += 1
			continue
		}
		switch messageType {
		case listenersNlmsgDone:
			if 4 <= len(body) && int32(order.Uint32(body[0:4])) < 0 {
				return nil, false, skipped, errListenersSockDiag
			}
			return sockets, true, skipped, nil
		case listenersNlmsgError:
			// an error code of 0 is an acknowledgment; any other ends the dump
			if len(body) < 4 || order.Uint32(body[0:4]) != 0 {
				return nil, false, skipped, errListenersSockDiag
			}
		case listenersSockDiagByFamily:
			socket, err := listenersParseInetDiagMsg(body, order, ipProtocol)
			if err != nil {
				return nil, false, skipped, err
			}
			sockets = append(sockets, socket)
		default:
			return nil, false, skipped, errListenersSockDiag
		}
	}
	return sockets, false, skipped, nil
}

// One inet_diag_msg and its attributes.
func listenersParseInetDiagMsg(body []byte, order binary.ByteOrder, ipProtocol uint8) (*listenersDiagSocket, error) {
	if len(body) < listenersInetDiagMsgByteCount {
		return nil, errListenersSockDiag
	}
	family := body[0]
	state := body[1]
	sourcePort := binary.BigEndian.Uint16(body[4:6])
	destinationPort := binary.BigEndian.Uint16(body[6:8])
	source := body[8:24]
	destination := body[24:40]
	interfaceIndex := order.Uint32(body[40:44])
	cookie := uint64(order.Uint32(body[44:48])) | uint64(order.Uint32(body[48:52]))<<32
	uid := order.Uint32(body[64:68])
	inode := order.Uint32(body[68:72])

	var bind netip.Addr
	connected := destinationPort != 0
	switch family {
	case listenersAfInet:
		bind = netip.AddrFrom4([4]byte(source[0:4]))
		connected = connected || !netip.AddrFrom4([4]byte(destination[0:4])).IsUnspecified()
	case listenersAfInet6:
		bind = netip.AddrFrom16([16]byte(source[0:16]))
		if bind.Is6() && (bind.IsLinkLocalUnicast() || bind.IsLinkLocalMulticast()) && interfaceIndex != 0 {
			bind = bind.WithZone(strconv.FormatUint(uint64(interfaceIndex), 10))
		}
		connected = connected || !netip.AddrFrom16([16]byte(destination[0:16])).IsUnspecified()
	default:
		return nil, errListenersSockDiag
	}

	v6Only := false
	attributes := body[listenersInetDiagMsgByteCount:]
	for 0 < len(attributes) {
		if len(attributes) < listenersRtattrHeaderByteCount {
			return nil, errListenersSockDiag
		}
		length := int(order.Uint16(attributes[0:2]))
		attributeType := order.Uint16(attributes[2:4]) & listenersNlaTypeMask
		if length < listenersRtattrHeaderByteCount || len(attributes) < length {
			return nil, errListenersSockDiag
		}
		payload := attributes[listenersRtattrHeaderByteCount:length]
		if attributeType == listenersInetDiagSkv6only && 1 <= len(payload) {
			v6Only = payload[0] != 0
		}
		attributes = attributes[min(listenersNetlinkAligned(length), len(attributes)):]
	}

	socket := &ListenersSocket{
		Bind:     bind,
		Port:     sourcePort,
		V6Only:   family == listenersAfInet6 && v6Only,
		Inode:    uint64(inode),
		Uid:      uid,
		UidKnown: true,
	}
	switch ipProtocol {
	case listenersIpprotoTcp:
		socket.Protocol = protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP
	case listenersIpprotoUdp:
		socket.Protocol = protocol.ListenersProtocol_LISTENERS_PROTOCOL_UDP
	}
	return &listenersDiagSocket{socket: socket, state: state, cookie: cookie, connected: connected}, nil
}

// The cookies of the sockets a destruction notice names: each SOCK_DIAG_BY_FAMILY message's inet_diag_msg, whatever its
// sequence, the multicast's being 0. A message that does not read fails the read, which then names no socket.
func listenersParseSockDiagCookies(data []byte, order binary.ByteOrder) ([]uint64, error) {
	cookies := []uint64{}
	for 0 < len(data) {
		if len(data) < listenersNetlinkHeaderByteCount {
			return nil, errListenersSockDiag
		}
		length := int(order.Uint32(data[0:4]))
		messageType := order.Uint16(data[4:6])
		if length < listenersNetlinkHeaderByteCount || len(data) < length {
			return nil, errListenersSockDiag
		}
		body := data[listenersNetlinkHeaderByteCount:length]
		data = data[min(listenersNetlinkAligned(length), len(data)):]
		if messageType != listenersSockDiagByFamily {
			continue
		}
		// the protocol does not matter here: a notice is matched by its cookie alone
		socket, err := listenersParseInetDiagMsg(body, order, 0)
		if err != nil {
			return nil, err
		}
		cookies = append(cookies, socket.cookie)
	}
	return cookies, nil
}

// The sockets a dump lists of what one protocol's replies held: TCP in LISTEN; UDP bound and unconnected, as CLOSE
// reads; each with a port.
func listenersDiagListed(replies []*listenersDiagSocket, ipProtocol uint8) []*listenersDiagSocket {
	listed := []*listenersDiagSocket{}
	for _, reply := range replies {
		if reply.socket.Port == 0 {
			continue
		}
		switch {
		case ipProtocol == listenersIpprotoTcp && reply.state == listenersTcpListen:
		case ipProtocol == listenersIpprotoUdp && reply.state == listenersTcpClose && !reply.connected:
		default:
			continue
		}
		listed = append(listed, reply)
	}
	return listed
}

// The first port of Linux's ephemeral range from ip_local_port_range's text, "<first>\t<last>\n", or false.
func listenersParsePortRange(text string) (uint16, bool) {
	fields := strings.Fields(text)
	if len(fields) != 2 {
		return 0, false
	}
	first, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil || first == 0 {
		return 0, false
	}
	return uint16(first), true
}
