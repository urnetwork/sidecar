//go:build darwin && !ios && !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The real tables: this process's TCP listener on 127.0.0.1, its dual-stack one on ::, its IPv6-only one on ::1 and its
// unconnected UDP socket, each named by libproc as this process; a connected UDP socket is none of them; and no notice
// channel, macOS sending none.
func TestListenersDarwinDumpFindsThisProcess(t *testing.T) {
	loopback, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer loopback.Close()
	dual, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer dual.Close()
	v6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer v6.Close()
	udp, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	connected, err := net.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()

	discoverer, err := NewListenersDiscoverer(DefaultListenersSettings())
	if err != nil {
		t.Fatal(err)
	}
	defer discoverer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sockets, err := discoverer.Dump(ctx)
	if err != nil {
		t.Fatal(err)
	}
	find := func(proto protocol.ListenersProtocol, port int) *ListenersSocket {
		for _, socket := range sockets {
			if socket.Protocol == proto && int(socket.Port) == port {
				return socket
			}
		}
		return nil
	}
	tcp := protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP
	ours := []*ListenersSocket{
		find(tcp, loopback.Addr().(*net.TCPAddr).Port),
		find(tcp, dual.Addr().(*net.TCPAddr).Port),
		find(tcp, v6.Addr().(*net.TCPAddr).Port),
		find(protocol.ListenersProtocol_LISTENERS_PROTOCOL_UDP, udp.LocalAddr().(*net.UDPAddr).Port),
	}
	for i, socket := range ours {
		if socket == nil {
			t.Fatalf("socket %d not dumped", i)
		}
	}
	if ours[0].Bind != netip.MustParseAddr("127.0.0.1") || ours[1].Bind != netip.IPv6Unspecified() || ours[1].V6Only ||
		ours[2].Bind != netip.IPv6Loopback() || !ours[2].V6Only || ours[3].Bind != netip.IPv4Unspecified() {
		t.Errorf("binds %+v %+v %+v %+v", *ours[0], *ours[1], *ours[2], *ours[3])
	}
	if socket := find(protocol.ListenersProtocol_LISTENERS_PROTOCOL_UDP, connected.LocalAddr().(*net.UDPAddr).Port); socket != nil {
		t.Errorf("a connected UDP socket listed: %+v", *socket)
	}
	if err := discoverer.Owners(ctx, ours); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for i, socket := range ours {
		// proc_name gives at most MAXCOMLEN of the executable's name
		if socket.Owner != ListenersOwnerProgram || socket.Pid != int32(os.Getpid()) || socket.Program == "" ||
			!strings.HasPrefix(filepath.Base(executable), socket.Program) {
			t.Errorf("owner %d: %+v", i, *socket)
		}
	}
	if discoverer.Destroyed() != nil || discoverer.EphemeralFirstPort() != 49152 {
		t.Error("macOS has a notice or another threshold")
	}
}
