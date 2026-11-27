//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// One synthetic inet_diag_msg reply, as the kernel lays it out (linux/inet_diag.h), documentation addresses only.
type testDiagReply struct {
	family     uint8
	state      uint8
	bind       netip.Addr
	port       uint16
	remote     netip.AddrPort
	cookie     uint64
	uid        uint32
	inode      uint32
	v6OnlyAttr int // -1 absent, else the attribute's byte
	ifindex    uint32
}

// The reply as an nlmsghdr of SOCK_DIAG_BY_FAMILY and its inet_diag_msg, then INET_DIAG_SHUTDOWN and, where asked,
// INET_DIAG_SKV6ONLY, as the kernel's inet_diag_msg_attrs_fill puts them, in order's byte order.
func testDiagMessage(order binary.ByteOrder, sequence uint32, reply testDiagReply) []byte {
	body := make([]byte, listenersInetDiagMsgByteCount)
	body[0] = reply.family
	body[1] = reply.state
	binary.BigEndian.PutUint16(body[4:6], reply.port)
	binary.BigEndian.PutUint16(body[6:8], reply.remote.Port())
	if reply.family == listenersAfInet {
		address := reply.bind.As4()
		copy(body[8:12], address[:])
		if reply.remote.IsValid() {
			remote := reply.remote.Addr().As4()
			copy(body[24:28], remote[:])
		}
	} else {
		address := reply.bind.As16()
		copy(body[8:24], address[:])
		if reply.remote.IsValid() {
			remote := reply.remote.Addr().As16()
			copy(body[24:40], remote[:])
		}
	}
	order.PutUint32(body[40:44], reply.ifindex)
	order.PutUint32(body[44:48], uint32(reply.cookie))
	order.PutUint32(body[48:52], uint32(reply.cookie>>32))
	order.PutUint32(body[64:68], reply.uid)
	order.PutUint32(body[68:72], reply.inode)
	attribute := func(attributeType uint16, value byte) {
		header := make([]byte, 8)
		order.PutUint16(header[0:2], 5)
		order.PutUint16(header[2:4], attributeType)
		header[4] = value
		body = append(body, header...)
	}
	// INET_DIAG_SHUTDOWN, 8, which every reply carries first
	attribute(8, 0)
	if 0 <= reply.v6OnlyAttr {
		attribute(listenersInetDiagSkv6only, byte(reply.v6OnlyAttr))
	}
	return testNetlinkMessage(order, sequence, listenersSockDiagByFamily, body)
}

// An nlmsghdr around body, padded to netlink's alignment.
func testNetlinkMessage(order binary.ByteOrder, sequence uint32, messageType uint16, body []byte) []byte {
	message := make([]byte, listenersNetlinkHeaderByteCount, listenersNetlinkHeaderByteCount+len(body)+4)
	order.PutUint32(message[0:4], uint32(listenersNetlinkHeaderByteCount+len(body)))
	order.PutUint16(message[4:6], messageType)
	// NLM_F_MULTI, as a dump's replies carry it
	order.PutUint16(message[6:8], 0x2)
	order.PutUint32(message[8:12], sequence)
	message = append(message, body...)
	for len(message)%listenersNetlinkAlign != 0 {
		message = append(message, 0)
	}
	return message
}

// NLMSG_DONE with its int.
func testNetlinkDone(order binary.ByteOrder, sequence uint32, code int32) []byte {
	body := make([]byte, 4)
	order.PutUint32(body, uint32(code))
	return testNetlinkMessage(order, sequence, listenersNlmsgDone, body)
}

// The golden replies: each kind of bind §26.4's rows read, TCP and UDP, the read testdata/listeners/linux/ holds.
var testDiagGoldenReplies = []struct {
	ipProtocol uint8
	reply      testDiagReply
}{
	{ipProtocol: listenersIpprotoTcp, reply: testDiagReply{family: listenersAfInet, state: listenersTcpListen, bind: netip.MustParseAddr("0.0.0.0"), port: 5432, cookie: 0x0000000100000001, uid: 1000, inode: 1001, v6OnlyAttr: -1}},
	{ipProtocol: listenersIpprotoTcp, reply: testDiagReply{family: listenersAfInet6, state: listenersTcpListen, bind: netip.MustParseAddr("::"), port: 8000, cookie: 0x0000000100000002, uid: 1000, inode: 1002, v6OnlyAttr: 0}},
	{ipProtocol: listenersIpprotoTcp, reply: testDiagReply{family: listenersAfInet6, state: listenersTcpListen, bind: netip.MustParseAddr("::"), port: 8443, cookie: 0x0000000100000003, uid: 1000, inode: 1003, v6OnlyAttr: 1}},
	{ipProtocol: listenersIpprotoTcp, reply: testDiagReply{family: listenersAfInet, state: listenersTcpListen, bind: netip.MustParseAddr("127.0.0.1"), port: 9222, cookie: 0x0000000100000004, uid: 1000, inode: 1004, v6OnlyAttr: -1}},
	{ipProtocol: listenersIpprotoTcp, reply: testDiagReply{family: listenersAfInet, state: listenersTcpListen, bind: netip.MustParseAddr("192.0.2.5"), port: 3000, cookie: 0x0000000100000005, uid: 1000, inode: 1005, v6OnlyAttr: -1}},
	{ipProtocol: listenersIpprotoTcp, reply: testDiagReply{family: listenersAfInet6, state: listenersTcpListen, bind: netip.MustParseAddr("::1"), port: 6379, cookie: 0x0000000100000006, uid: 0, inode: 1006, v6OnlyAttr: 1}},
	{ipProtocol: listenersIpprotoUdp, reply: testDiagReply{family: listenersAfInet, state: listenersTcpClose, bind: netip.MustParseAddr("0.0.0.0"), port: 53, cookie: 0x0000000200000001, uid: 0, inode: 2001, v6OnlyAttr: -1}},
	{ipProtocol: listenersIpprotoUdp, reply: testDiagReply{family: listenersAfInet6, state: listenersTcpClose, bind: netip.MustParseAddr("::"), port: 51820, cookie: 0x0000000200000002, uid: 1000, inode: 2002, v6OnlyAttr: 0}},
	{ipProtocol: listenersIpprotoUdp, reply: testDiagReply{family: listenersAfInet, state: listenersTcpClose, bind: netip.MustParseAddr("127.0.0.1"), port: 5353, cookie: 0x0000000200000003, uid: 1000, inode: 2003, v6OnlyAttr: -1}},
	{ipProtocol: listenersIpprotoUdp, reply: testDiagReply{family: listenersAfInet6, state: listenersTcpClose, bind: netip.MustParseAddr("2001:db8::5"), port: 4500, cookie: 0x0000000200000004, uid: 1000, inode: 2004, v6OnlyAttr: 1}},
	{ipProtocol: listenersIpprotoUdp, reply: testDiagReply{family: listenersAfInet6, state: listenersTcpClose, bind: netip.MustParseAddr("::1"), port: 1053, cookie: 0x0000000200000005, uid: 1000, inode: 2005, v6OnlyAttr: 1}},
	// a connected UDP socket, a client's, which no dump lists
	{ipProtocol: listenersIpprotoUdp, reply: testDiagReply{family: listenersAfInet, state: listenersTcpEstablished, bind: netip.MustParseAddr("192.0.2.5"), port: 40000, remote: netip.MustParseAddrPort("198.51.100.53:53"), cookie: 0x0000000200000006, uid: 1000, inode: 2006, v6OnlyAttr: -1}},
}

// The golden reads, hex, little-endian as Linux's amd64 and arm64 lay them out: testdata/listeners/linux/<name>.hex.
func testDiagGolden(t *testing.T, name string) []byte {
	t.Helper()
	text, err := os.ReadFile(filepath.Join("testdata", "listeners", "linux", name+".hex"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.Join(strings.Fields(string(text)), ""))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The goldens hold what the kernel would send for each bind §26.4's rows read, TCP's dump and UDP's each one read
// ended by NLMSG_DONE, and they read as their sockets: every interface on 0.0.0.0, :: with and without SKV6ONLY,
// 127.0.0.1, one interface's address, ::1, IPv6 alone, each TCP and UDP; a connected UDP socket is no server.
func TestListenersSockDiagGoldens(t *testing.T) {
	order := binary.LittleEndian
	for _, dump := range []struct {
		name       string
		ipProtocol uint8
		sequence   uint32
	}{
		{name: "tcp", ipProtocol: listenersIpprotoTcp, sequence: 7},
		{name: "udp", ipProtocol: listenersIpprotoUdp, sequence: 8},
	} {
		built := []byte{}
		want := []*ListenersSocket{}
		for _, golden := range testDiagGoldenReplies {
			if golden.ipProtocol != dump.ipProtocol {
				continue
			}
			built = append(built, testDiagMessage(order, dump.sequence, golden.reply)...)
			if golden.reply.remote.IsValid() {
				continue
			}
			socket := &ListenersSocket{
				Bind: golden.reply.bind, Port: golden.reply.port, V6Only: golden.reply.v6OnlyAttr == 1,
				Inode: uint64(golden.reply.inode), Uid: golden.reply.uid, UidKnown: true,
				Protocol: protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP,
			}
			if dump.ipProtocol == listenersIpprotoUdp {
				socket.Protocol = protocol.ListenersProtocol_LISTENERS_PROTOCOL_UDP
			}
			want = append(want, socket)
		}
		built = append(built, testNetlinkDone(order, dump.sequence, 0)...)
		golden := testDiagGolden(t, dump.name)
		if !bytes.Equal(built, golden) {
			t.Errorf("%s: the golden and the builder differ:\n%x\n%x", dump.name, golden, built)
		}
		replies, done, skipped, err := listenersParseSockDiag(golden, order, dump.sequence, dump.ipProtocol)
		if err != nil || !done || skipped != 0 {
			t.Fatalf("%s: done %t, skipped %d, %v", dump.name, done, skipped, err)
		}
		listed := listenersDiagListed(replies, dump.ipProtocol)
		if len(listed) != len(want) {
			t.Fatalf("%s: %d listed, want %d", dump.name, len(listed), len(want))
		}
		for i, reply := range listed {
			if *reply.socket != *want[i] {
				t.Errorf("%s %d: %+v, want %+v", dump.name, i, *reply.socket, *want[i])
			}
		}
	}
}

// A dump's replies over several reads, NLMSG_DONE in the last: each read adds its sockets, and done comes with the
// last; replies an earlier, cut dump left behind are skipped by their sequence.
func TestListenersSockDiagMultipart(t *testing.T) {
	order := binary.LittleEndian
	first := testDiagGoldenReplies[0].reply
	second := testDiagGoldenReplies[1].reply
	stale := testDiagMessage(order, 6, first)
	read1 := append(append(stale, testDiagMessage(order, 7, first)...), testDiagMessage(order, 7, second)...)
	read2 := append(testDiagMessage(order, 7, testDiagGoldenReplies[3].reply), testNetlinkDone(order, 7, 0)...)
	replies, done, skipped, err := listenersParseSockDiag(read1, order, 7, listenersIpprotoTcp)
	if err != nil || done || skipped != 1 || len(replies) != 2 {
		t.Fatalf("first read: %d replies, done %t, skipped %d, %v", len(replies), done, skipped, err)
	}
	replies, done, _, err = listenersParseSockDiag(read2, order, 7, listenersIpprotoTcp)
	if err != nil || !done || len(replies) != 1 || replies[0].socket.Port != 9222 {
		t.Fatalf("second read: %d replies, done %t, %v", len(replies), done, err)
	}
}

// What fails a dump, which then changes nothing: an NLMSG_ERROR with a code, a negative NLMSG_DONE, a reply shorter
// than its header or its inet_diag_msg, one claiming more than the read holds, an attribute running past its message,
// a type no dump answers and a family no inet socket has. An error code of 0, an acknowledgment, fails nothing.
func TestListenersSockDiagRefusals(t *testing.T) {
	order := binary.LittleEndian
	reply := testDiagMessage(order, 7, testDiagGoldenReplies[0].reply)
	errorBody := make([]byte, 20)
	order.PutUint32(errorBody[0:4], uint32(0xffffffff-12)) // -ENOMEM
	overlong := append([]byte{}, reply...)
	order.PutUint32(overlong[0:4], uint32(len(reply)+64))
	shortBody := testNetlinkMessage(order, 7, listenersSockDiagByFamily, make([]byte, 40))
	badAttribute := append([]byte{}, reply...)
	// the first attribute claims 64 bytes
	order.PutUint16(badAttribute[listenersNetlinkHeaderByteCount+listenersInetDiagMsgByteCount:], 64)
	badFamily := append([]byte{}, reply...)
	badFamily[listenersNetlinkHeaderByteCount] = 7
	cases := []struct {
		name string
		data []byte
	}{
		{name: "an error", data: testNetlinkMessage(order, 7, listenersNlmsgError, errorBody)},
		{name: "a failed done", data: testNetlinkDone(order, 7, -16)},
		{name: "a short header", data: reply[:10]},
		{name: "a short message", data: shortBody},
		{name: "an overlong length", data: overlong},
		{name: "an attribute past its message", data: badAttribute},
		{name: "another type", data: testNetlinkMessage(order, 7, 99, make([]byte, 4))},
		{name: "another family", data: badFamily},
	}
	for _, c := range cases {
		if replies, _, _, err := listenersParseSockDiag(c.data, order, 7, listenersIpprotoTcp); !errors.Is(err, errListenersSockDiag) {
			t.Errorf("%s: %v, %v", c.name, replies, err)
		}
	}
	acknowledgment := testNetlinkMessage(order, 7, listenersNlmsgError, make([]byte, 20))
	if _, _, _, err := listenersParseSockDiag(append(acknowledgment, reply...), order, 7, listenersIpprotoTcp); err != nil {
		t.Errorf("an acknowledgment failed the read: %v", err)
	}
}

// A request is the 72 bytes linux/inet_diag.h lays out: SOCK_DIAG_BY_FAMILY with NLM_F_REQUEST and NLM_F_DUMP, the
// family, protocol and state mask, every address.
func TestListenersSockDiagRequest(t *testing.T) {
	request := listenersSockDiagRequest(binary.LittleEndian, 9, listenersAfInet6, listenersIpprotoTcp, 1<<listenersTcpListen)
	want, _ := hex.DecodeString("48000000" + "1400" + "0103" + "09000000" + "00000000" + "0a060000" + "00040000" + strings.Repeat("00", 48))
	if !bytes.Equal(request, want) {
		t.Errorf("request %x\nwant    %x", request, want)
	}
}

// A destruction notice names its socket by cookie, whatever its sequence; another message in the read is passed over.
func TestListenersSockDiagNoticeCookies(t *testing.T) {
	order := binary.LittleEndian
	notice := append(testDiagMessage(order, 0, testDiagGoldenReplies[2].reply), testNetlinkDone(order, 0, 0)...)
	cookies, err := listenersParseSockDiagCookies(notice, order)
	if err != nil || len(cookies) != 1 || cookies[0] != testDiagGoldenReplies[2].reply.cookie {
		t.Errorf("cookies %x, %v", cookies, err)
	}
	if _, err := listenersParseSockDiagCookies(notice[:20], order); !errors.Is(err, errListenersSockDiag) {
		t.Errorf("a short notice read: %v", err)
	}
}

// ip_local_port_range's first port, and nothing from text that is not two numbers.
func TestListenersParsePortRange(t *testing.T) {
	if first, ok := listenersParsePortRange("32768\t60999\n"); !ok || first != 32768 {
		t.Errorf("read %d, %t", first, ok)
	}
	if first, ok := listenersParsePortRange("1024 65000"); !ok || first != 1024 {
		t.Errorf("read %d, %t", first, ok)
	}
	for _, text := range []string{"", "32768", "0\t60999", "x\t60999", "70000\t80000", "1 2 3"} {
		if first, ok := listenersParsePortRange(text); ok {
			t.Errorf("%q read as %d", text, first)
		}
	}
}
