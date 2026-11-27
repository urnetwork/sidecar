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

// One synthetic row: documentation addresses only.
type testIpHelperRow struct {
	bind  netip.Addr
	port  uint16
	state uint32
	pid   uint32
}

// A table as iphlpapi answers it: a DWORD count, then each row in its layout (listeners_iphlpapi.go's comment).
func testIpHelperTable(order binary.ByteOrder, ipProtocol uint8, ipv6 bool, rows []testIpHelperRow) []byte {
	data := make([]byte, 4)
	order.PutUint32(data, uint32(len(rows)))
	for _, row := range rows {
		var encoded []byte
		port := make([]byte, 4)
		binary.BigEndian.PutUint16(port, row.port)
		switch {
		case ipProtocol == listenersIpprotoTcp && !ipv6:
			encoded = make([]byte, listenersMibTcpRowByteCount)
			order.PutUint32(encoded[0:4], row.state)
			copy(encoded[4:8], row.bind.AsSlice())
			copy(encoded[8:12], port)
			order.PutUint32(encoded[20:24], row.pid)
		case ipProtocol == listenersIpprotoTcp && ipv6:
			encoded = make([]byte, listenersMibTcp6RowByteCount)
			copy(encoded[0:16], row.bind.AsSlice())
			copy(encoded[20:24], port)
			order.PutUint32(encoded[48:52], row.state)
			order.PutUint32(encoded[52:56], row.pid)
		case !ipv6:
			encoded = make([]byte, listenersMibUdpRowByteCount)
			copy(encoded[0:4], row.bind.AsSlice())
			copy(encoded[4:8], port)
			order.PutUint32(encoded[8:12], row.pid)
		default:
			encoded = make([]byte, listenersMibUdp6RowByteCount)
			copy(encoded[0:16], row.bind.AsSlice())
			copy(encoded[20:24], port)
			order.PutUint32(encoded[24:28], row.pid)
		}
		data = append(data, encoded...)
	}
	return data
}

// The golden tables: both families, TCP and UDP, a `::` row, pid 4's row, loopback and one address.
var testIpHelperGoldens = []struct {
	name       string
	ipProtocol uint8
	ipv6       bool
	rows       []testIpHelperRow
}{
	{name: "tcp4", ipProtocol: listenersIpprotoTcp, rows: []testIpHelperRow{
		{bind: netip.MustParseAddr("0.0.0.0"), port: 3389, state: listenersMibTcpStateListen, pid: 1044},
		{bind: netip.MustParseAddr("127.0.0.1"), port: 9222, state: listenersMibTcpStateListen, pid: 2208},
		{bind: netip.MustParseAddr("192.0.2.5"), port: 139, state: listenersMibTcpStateListen, pid: 4},
	}},
	{name: "tcp6", ipProtocol: listenersIpprotoTcp, ipv6: true, rows: []testIpHelperRow{
		{bind: netip.IPv6Unspecified(), port: 3389, state: listenersMibTcpStateListen, pid: 1044},
		{bind: netip.IPv6Loopback(), port: 6379, state: listenersMibTcpStateListen, pid: 3100},
		{bind: netip.IPv6Unspecified(), port: 445, state: listenersMibTcpStateListen, pid: 4},
	}},
	{name: "udp4", ipProtocol: listenersIpprotoUdp, rows: []testIpHelperRow{
		{bind: netip.MustParseAddr("0.0.0.0"), port: 53, pid: 2900},
		{bind: netip.MustParseAddr("192.0.2.5"), port: 137, pid: 4},
	}},
	{name: "udp6", ipProtocol: listenersIpprotoUdp, ipv6: true, rows: []testIpHelperRow{
		{bind: netip.IPv6Unspecified(), port: 5355, pid: 1500},
		{bind: netip.MustParseAddr("2001:db8::5"), port: 4500, pid: 1600},
	}},
}

// The goldens hold iphlpapi's layouts, little-endian as Windows on amd64 and arm64 lays them out, and read as their
// sockets: a `::` row with v4_uncertain, never as taking IPv4; another IPv6 address alone; pid 4 a system program's.
func TestListenersIpHelperGoldens(t *testing.T) {
	order := binary.LittleEndian
	for _, golden := range testIpHelperGoldens {
		built := testIpHelperTable(order, golden.ipProtocol, golden.ipv6, golden.rows)
		text, err := os.ReadFile(filepath.Join("testdata", "listeners", "windows", golden.name+".hex"))
		if err != nil {
			t.Fatal(err)
		}
		stored, err := hex.DecodeString(strings.Join(strings.Fields(string(text)), ""))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(built, stored) {
			t.Errorf("%s: the golden and the builder differ", golden.name)
		}
		sockets, err := listenersParseIpHelperTable(stored, golden.ipProtocol, golden.ipv6, order)
		if err != nil || len(sockets) != len(golden.rows) {
			t.Fatalf("%s: %d sockets, %v", golden.name, len(sockets), err)
		}
		for i, socket := range sockets {
			row := golden.rows[i]
			wantProtocol := protocol.ListenersProtocol_LISTENERS_PROTOCOL_UDP
			if golden.ipProtocol == listenersIpprotoTcp {
				wantProtocol = protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP
			}
			uncertain := golden.ipv6 && row.bind.IsUnspecified()
			if socket.Protocol != wantProtocol || socket.Bind != row.bind || socket.Port != row.port ||
				socket.Pid != int32(row.pid) || socket.V4Uncertain != uncertain ||
				socket.V6Only != (golden.ipv6 && !row.bind.IsUnspecified()) || socket.UidKnown || socket.Inode == 0 {
				t.Errorf("%s %d: %+v", golden.name, i, *socket)
			}
			if (row.pid == 4) != (socket.Owner == ListenersOwnerSystem) {
				t.Errorf("%s %d: owner %v", golden.name, i, socket.Owner)
			}
		}
	}
}

// Each row's identity is its own: the same port and pid in the two families differ, and a row read again matches.
func TestListenersIpHelperIdentities(t *testing.T) {
	order := binary.LittleEndian
	v4, _ := listenersParseIpHelperTable(testIpHelperTable(order, listenersIpprotoTcp, false, testIpHelperGoldens[0].rows), listenersIpprotoTcp, false, order)
	v6, _ := listenersParseIpHelperTable(testIpHelperTable(order, listenersIpprotoTcp, true, testIpHelperGoldens[1].rows), listenersIpprotoTcp, true, order)
	again, _ := listenersParseIpHelperTable(testIpHelperTable(order, listenersIpprotoTcp, false, testIpHelperGoldens[0].rows), listenersIpprotoTcp, false, order)
	if v4[0].Inode == v6[0].Inode || v4[0].Inode != again[0].Inode || v4[0].Inode == v4[1].Inode {
		t.Errorf("identities %x %x %x %x", v4[0].Inode, v6[0].Inode, again[0].Inode, v4[1].Inode)
	}
}

// A table whose count claims more rows than it holds, and one shorter than its count, fail the dump without a panic;
// a row not in LISTEN is no listener.
func TestListenersIpHelperRefusals(t *testing.T) {
	order := binary.LittleEndian
	table := testIpHelperTable(order, listenersIpprotoTcp, true, testIpHelperGoldens[1].rows)
	cases := [][]byte{table[:3], table[:len(table)-1], append(append([]byte{}, table[:4]...), 0)}
	order.PutUint32(cases[2][0:4], 1000)
	for i, data := range cases {
		if sockets, err := listenersParseIpHelperTable(data, listenersIpprotoTcp, true, order); !errors.Is(err, errListenersIpHelperTable) {
			t.Errorf("case %d: %v, %v", i, sockets, err)
		}
	}
	established := testIpHelperTable(order, listenersIpprotoTcp, false, []testIpHelperRow{
		{bind: netip.MustParseAddr("192.0.2.5"), port: 3389, state: 5, pid: 1044},
	})
	if sockets, err := listenersParseIpHelperTable(established, listenersIpprotoTcp, false, order); err != nil || len(sockets) != 0 {
		t.Errorf("an established row: %v, %v", sockets, err)
	}
}

// Owners by a fake image-name call: a path's file name; a refused call, a system program's; pid 4 never asked; each pid
// asked once; past the budget, the rest left for the next dump.
func TestListenersWindowsOwners(t *testing.T) {
	sockets := []*ListenersSocket{
		{Port: 3389, Pid: 1044},
		{Port: 3390, Pid: 1044},
		{Port: 445, Pid: 4},
		{Port: 6379, Pid: 3100},
		{Port: 9000, Pid: 3200},
	}
	asked := []uint32{}
	imageName := func(pid uint32) (string, bool) {
		asked = append(asked, pid)
		switch pid {
		case 1044:
			return `C:\Windows\System32\svchost.exe`, true
		case 3100:
			return "", false
		}
		return `D:\tools\server.exe`, true
	}
	listenersWindowsOwners(sockets, imageName, 2)
	if sockets[0].Program != "svchost.exe" || sockets[1].Program != "svchost.exe" || sockets[0].Owner != ListenersOwnerProgram {
		t.Errorf("svchost: %+v %+v", *sockets[0], *sockets[1])
	}
	if sockets[2].Owner != ListenersOwnerSystem || sockets[3].Owner != ListenersOwnerSystem {
		t.Errorf("system: %+v %+v", *sockets[2], *sockets[3])
	}
	if sockets[4].Owner != ListenersOwnerUnknown {
		t.Errorf("past the budget: %+v", *sockets[4])
	}
	if len(asked) != 2 || asked[0] != 1044 || asked[1] != 3100 {
		t.Errorf("asked %v", asked)
	}
	listenersWindowsOwners(sockets, imageName, 2)
	if sockets[4].Program != "server.exe" {
		t.Errorf("the next dump: %+v", *sockets[4])
	}
}
