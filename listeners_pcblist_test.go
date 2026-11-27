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

// One synthetic pcb, as a running macOS lays out its group: documentation addresses only.
type testPcb struct {
	bind     netip.Addr
	port     uint16
	vflag    uint8
	v6Only   bool
	foreign  netip.AddrPort
	state    uint32
	handle   uint64
	uid      uint32
	lastPid  uint32
	ePid     uint32
	noSocket bool
}

// The record lengths the running macOS this was read against writes: xinpcb_n 104, xsocket_n 104, xsockbuf_n 32,
// xsockstat_n 136, xtcpcb_n 204.
const (
	testPcbInpcbByteCount  = 104
	testPcbSocketByteCount = 104
	testPcbBufByteCount    = 32
	testPcbStatsByteCount  = 136
	testPcbTcpcbByteCount  = 204
)

// A record of kind with its xgen_n header, padded to 8 bytes.
func testPcbRecord(order binary.ByteOrder, kind uint32, body []byte) []byte {
	order.PutUint32(body[0:4], uint32(len(body)))
	order.PutUint32(body[4:8], kind)
	for len(body)%8 != 0 {
		body = append(body, 0)
	}
	return body
}

// An xinpgen: its length, the count, two generations.
func testXinpgen(order binary.ByteOrder, count uint32) []byte {
	header := make([]byte, listenersXinpgenByteCount)
	order.PutUint32(header[0:4], listenersXinpgenByteCount)
	order.PutUint32(header[4:8], count)
	order.PutUint64(header[8:16], 7)
	order.PutUint64(header[16:24], 9)
	return header
}

// A pcblist_n answer for pcbs: the opening xinpgen, each group in xnu's order (inpcb, socket, buffers, stats, and for
// TCP its tcpcb), the closing xinpgen.
func testPcbList(order binary.ByteOrder, tcp bool, pcbs []testPcb) []byte {
	data := testXinpgen(order, uint32(len(pcbs)))
	for _, pcb := range pcbs {
		inpcb := make([]byte, testPcbInpcbByteCount)
		binary.BigEndian.PutUint16(inpcb[listenersInpLportOffset:], pcb.port)
		if pcb.foreign.IsValid() {
			binary.BigEndian.PutUint16(inpcb[listenersInpFportOffset:], pcb.foreign.Port())
			foreign := pcb.foreign.Addr().As16()
			copy(inpcb[listenersInpFaddrOffset:], foreign[:])
		}
		flags := uint32(0x800040)
		if pcb.v6Only {
			flags |= listenersIn6pIpv6V6only
		}
		order.PutUint32(inpcb[listenersInpFlagsOffset:], flags)
		inpcb[listenersInpVflagOffset] = pcb.vflag
		local := pcb.bind.As16()
		copy(inpcb[listenersInpLaddrOffset:], local[:])
		data = append(data, testPcbRecord(order, listenersXsoInpcb, inpcb)...)
		if !pcb.noSocket {
			socket := make([]byte, testPcbSocketByteCount)
			order.PutUint64(socket[listenersSoHandleOffset:], pcb.handle)
			order.PutUint32(socket[listenersSoUidOffset:], pcb.uid)
			order.PutUint32(socket[listenersSoLastPidOffset:], pcb.lastPid)
			order.PutUint32(socket[listenersSoEPidOffset:], pcb.ePid)
			data = append(data, testPcbRecord(order, listenersXsoSocket, socket)...)
		}
		data = append(data, testPcbRecord(order, 0x2, make([]byte, testPcbBufByteCount))...)
		data = append(data, testPcbRecord(order, 0x4, make([]byte, testPcbBufByteCount))...)
		data = append(data, testPcbRecord(order, 0x8, make([]byte, testPcbStatsByteCount))...)
		if tcp {
			tcpcb := make([]byte, testPcbTcpcbByteCount)
			order.PutUint32(tcpcb[listenersTcpStateOffset:], pcb.state)
			data = append(data, testPcbRecord(order, listenersXsoTcpcb, tcpcb)...)
		}
	}
	return append(data, testXinpgen(order, uint32(len(pcbs)))...)
}

// IPv4's address as a pcb holds it: in the last 4 of its 16 bytes.
func testPcbIpv4(text string) netip.Addr {
	return netip.AddrFrom16([16]byte(append(make([]byte, 12), netip.MustParseAddr(text).AsSlice()...)))
}

// The golden pcbs: every interface on 0.0.0.0, dual stack on ::, IPv6 alone on ::, 127.0.0.1, one interface's address,
// ::1; TCP ones in LISTEN and one that is not; UDP ones bound, one connected, and one whose socket went.
var testPcbGoldenTcp = []testPcb{
	{bind: testPcbIpv4("0.0.0.0"), port: 5432, vflag: listenersInpIpv4, state: listenersTcpsListen, handle: 0x11, uid: 501, lastPid: 400},
	{bind: netip.IPv6Unspecified(), port: 8000, vflag: listenersInpIpv4 | listenersInpIpv6, state: listenersTcpsListen, handle: 0x12, uid: 501, lastPid: 401},
	{bind: netip.IPv6Unspecified(), port: 8443, vflag: listenersInpIpv6, v6Only: true, state: listenersTcpsListen, handle: 0x13, uid: 501, lastPid: 402},
	{bind: testPcbIpv4("127.0.0.1"), port: 9222, vflag: listenersInpIpv4, state: listenersTcpsListen, handle: 0x14, uid: 501, lastPid: 403},
	{bind: testPcbIpv4("192.0.2.5"), port: 3000, vflag: listenersInpIpv4, state: listenersTcpsListen, handle: 0x15, uid: 0, lastPid: 1, ePid: 77},
	{bind: netip.IPv6Loopback(), port: 6379, vflag: listenersInpIpv6, v6Only: true, state: listenersTcpsListen, handle: 0x16, uid: 501, lastPid: 404},
	// established, a connection's pcb
	{bind: testPcbIpv4("192.0.2.5"), port: 49200, vflag: listenersInpIpv4, foreign: netip.MustParseAddrPort("[::ffff:198.51.100.7]:443"), state: 4, handle: 0x17, uid: 501},
}

var testPcbGoldenUdp = []testPcb{
	{bind: testPcbIpv4("0.0.0.0"), port: 53, vflag: listenersInpIpv4, handle: 0x21, uid: 0, lastPid: 1},
	{bind: netip.IPv6Unspecified(), port: 51820, vflag: listenersInpIpv4 | listenersInpIpv6, handle: 0x22, uid: 501, lastPid: 405},
	{bind: testPcbIpv4("127.0.0.1"), port: 5353, vflag: listenersInpIpv4, handle: 0x23, uid: 501},
	{bind: netip.MustParseAddr("2001:db8::5"), port: 4500, vflag: listenersInpIpv6, handle: 0x24, uid: 501},
	// connected: a client's
	{bind: testPcbIpv4("192.0.2.5"), port: 61000, vflag: listenersInpIpv4, foreign: netip.MustParseAddrPort("[::ffff:198.51.100.53]:53"), handle: 0x25, uid: 501},
	// its socket went as the table was read
	{bind: testPcbIpv4("0.0.0.0"), port: 67, vflag: listenersInpIpv4, handle: 0x26, noSocket: true},
}

// testdata/listeners/darwin/<name>.hex, read.
func testPcbGolden(t *testing.T, name string) []byte {
	t.Helper()
	text, err := os.ReadFile(filepath.Join("testdata", "listeners", "darwin", name+".hex"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.Join(strings.Fields(string(text)), ""))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The goldens hold what pcblist_n answers for each pcb, little-endian as macOS on arm64 and amd64 lays them out, and
// read as their listed sockets: v4, v6 alone, dual stack, loopback, one address, UDP; a connection, a connected UDP
// socket and a pcb whose socket went are not listed; each socket carries its handle, uid and the pids that used it.
func TestListenersPcbListGoldens(t *testing.T) {
	order := binary.LittleEndian
	for _, table := range []struct {
		name       string
		ipProtocol uint8
		pcbs       []testPcb
	}{
		{name: "tcp", ipProtocol: listenersIpprotoTcp, pcbs: testPcbGoldenTcp},
		{name: "udp", ipProtocol: listenersIpprotoUdp, pcbs: testPcbGoldenUdp},
	} {
		built := testPcbList(order, table.ipProtocol == listenersIpprotoTcp, table.pcbs)
		golden := testPcbGolden(t, table.name)
		if !bytes.Equal(built, golden) {
			t.Errorf("%s: the golden and the builder differ", table.name)
		}
		listed, err := listenersParsePcbList(golden, table.ipProtocol, order)
		if err != nil {
			t.Fatalf("%s: %v", table.name, err)
		}
		want := []*listenersPcbSocket{}
		for _, pcb := range table.pcbs {
			if pcb.foreign.IsValid() || pcb.noSocket {
				continue
			}
			socket := &ListenersSocket{Port: pcb.port, Inode: pcb.handle, Uid: pcb.uid, UidKnown: true}
			socket.Protocol = protocol.ListenersProtocol_LISTENERS_PROTOCOL_UDP
			if table.ipProtocol == listenersIpprotoTcp {
				socket.Protocol = protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP
			}
			if pcb.vflag&listenersInpIpv6 != 0 {
				socket.Bind = pcb.bind
				socket.V6Only = pcb.vflag&listenersInpIpv4 == 0 || pcb.v6Only
			} else {
				socket.Bind = netip.AddrFrom4([4]byte(pcb.bind.AsSlice()[12:16]))
			}
			want = append(want, &listenersPcbSocket{socket: socket, lastPid: int32(pcb.lastPid), ePid: int32(pcb.ePid)})
		}
		if len(listed) != len(want) {
			t.Fatalf("%s: %d listed, want %d", table.name, len(listed), len(want))
		}
		for i := range listed {
			if *listed[i].socket != *want[i].socket || listed[i].lastPid != want[i].lastPid || listed[i].ePid != want[i].ePid {
				t.Errorf("%s %d: %+v (%d, %d), want %+v (%d, %d)", table.name, i, *listed[i].socket, listed[i].lastPid,
					listed[i].ePid, *want[i].socket, want[i].lastPid, want[i].ePid)
			}
		}
	}
	// the dual-stack :: takes IPv4, the other :: does not
	listed, _ := listenersParsePcbList(testPcbGolden(t, "tcp"), listenersIpprotoTcp, order)
	if listed[1].socket.V6Only || !listed[2].socket.V6Only {
		t.Errorf("dual stack %+v, v6 alone %+v", *listed[1].socket, *listed[2].socket)
	}
}

// A record shorter than the fields read, one claiming more than the answer holds, a header shorter than an xinpgen and
// a header claiming more than the answer each fail the dump, without a panic; a newer release's longer records read.
func TestListenersPcbListRefusals(t *testing.T) {
	order := binary.LittleEndian
	short := testXinpgen(order, 1)
	short = append(short, testPcbRecord(order, listenersXsoInpcb, make([]byte, 64))...)
	short = append(short, testPcbRecord(order, listenersXsoSocket, make([]byte, testPcbSocketByteCount))...)
	short = append(short, testPcbRecord(order, listenersXsoTcpcb, make([]byte, testPcbTcpcbByteCount))...)
	short = append(short, testXinpgen(order, 1)...)
	shortSocket := testXinpgen(order, 1)
	shortSocket = append(shortSocket, testPcbRecord(order, listenersXsoInpcb, make([]byte, testPcbInpcbByteCount))...)
	shortSocket = append(shortSocket, testPcbRecord(order, listenersXsoSocket, make([]byte, 40))...)
	shortSocket = append(shortSocket, testPcbRecord(order, listenersXsoTcpcb, make([]byte, testPcbTcpcbByteCount))...)
	overlong := testPcbList(order, true, testPcbGoldenTcp[:1])
	order.PutUint32(overlong[listenersXinpgenByteCount:], 4096)
	badHeader := testPcbList(order, true, testPcbGoldenTcp[:1])
	order.PutUint32(badHeader[0:4], 8)
	cases := []struct {
		name string
		data []byte
	}{
		{name: "a short inpcb", data: short},
		{name: "a short socket", data: shortSocket},
		{name: "an overlong record", data: overlong},
		{name: "a short header", data: badHeader},
		{name: "a header alone, cut", data: testXinpgen(order, 0)[:12]},
		{name: "a record header cut", data: append(testXinpgen(order, 1), 0x68, 0, 0)},
	}
	for _, c := range cases {
		if listed, err := listenersParsePcbList(c.data, listenersIpprotoTcp, order); !errors.Is(err, errListenersPcbList) {
			t.Errorf("%s: %v, %v", c.name, listed, err)
		}
	}

	// a release whose records grew: each read by its own length
	longer := testXinpgen(order, 1)
	inpcb := make([]byte, testPcbInpcbByteCount+24)
	binary.BigEndian.PutUint16(inpcb[listenersInpLportOffset:], 7000)
	inpcb[listenersInpVflagOffset] = listenersInpIpv4
	longer = append(longer, testPcbRecord(order, listenersXsoInpcb, inpcb)...)
	socket := make([]byte, testPcbSocketByteCount+16)
	order.PutUint64(socket[listenersSoHandleOffset:], 0x99)
	longer = append(longer, testPcbRecord(order, listenersXsoSocket, socket)...)
	tcpcb := make([]byte, testPcbTcpcbByteCount+8)
	order.PutUint32(tcpcb[listenersTcpStateOffset:], listenersTcpsListen)
	longer = append(longer, testPcbRecord(order, listenersXsoTcpcb, tcpcb)...)
	longer = append(longer, testXinpgen(order, 1)...)
	listed, err := listenersParsePcbList(longer, listenersIpprotoTcp, order)
	if err != nil || len(listed) != 1 || listed[0].socket.Port != 7000 || listed[0].socket.Inode != 0x99 {
		t.Errorf("longer records: %v, %v", listed, err)
	}
}
