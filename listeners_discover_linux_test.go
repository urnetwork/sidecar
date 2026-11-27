//go:build linux && !android && !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/urnetwork/sidecar/protocol"
)

// Discovery opens no socket but netlink's: never a probe (D-LSTN-2, IC-21). The socket hook sees each socket the
// discoverer opens, through a dump and its notices, and every one is AF_NETLINK's NETLINK_SOCK_DIAG.
func TestListenersDiscoveryOpensNoInetSocket(t *testing.T) {
	type opened struct {
		domain   int
		protocol int
	}
	var openedLock sync.Mutex
	sockets := []opened{}
	saved := listenersNetlinkSocket
	listenersNetlinkSocket = func(domain int, typ int, proto int) (int, error) {
		openedLock.Lock()
		sockets = append(sockets, opened{domain: domain, protocol: proto})
		openedLock.Unlock()
		return saved(domain, typ, proto)
	}
	t.Cleanup(func() { listenersNetlinkSocket = saved })

	discoverer, err := NewListenersDiscoverer(DefaultListenersSettings())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dumped, err := discoverer.Dump(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := discoverer.Owners(ctx, dumped); err != nil {
		t.Fatal(err)
	}
	discoverer.Close()
	openedLock.Lock()
	defer openedLock.Unlock()
	if len(sockets) == 0 {
		t.Fatal("the hook saw no socket")
	}
	for _, socket := range sockets {
		if socket.domain != unix.AF_NETLINK || socket.protocol != unix.NETLINK_SOCK_DIAG {
			t.Errorf("discovery opened a socket of domain %d, protocol %d", socket.domain, socket.protocol)
		}
	}
}

// The real tables: this process's own TCP listener on 127.0.0.1, its dual-stack one on ::, its IPv6-only one on ::1
// where the host has IPv6, and its unconnected UDP socket, each with its program's name, this process's comm; a
// connected UDP socket is none of them; closing the TCP listener fires a destruction notice, so it leaves at once.
func TestListenersLinuxDumpFindsThisProcess(t *testing.T) {
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
	v6, v6Err := net.Listen("tcp6", "[::1]:0")
	if v6Err == nil {
		defer v6.Close()
	}
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
	if err := discoverer.Owners(ctx, sockets); err != nil {
		t.Fatal(err)
	}
	comm, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatal(err)
	}
	program := strings.TrimSpace(string(comm))
	find := func(proto protocol.ListenersProtocol, port int) *ListenersSocket {
		for _, socket := range sockets {
			if socket.Protocol == proto && int(socket.Port) == port {
				return socket
			}
		}
		return nil
	}
	tcp := protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP
	if socket := find(tcp, loopback.Addr().(*net.TCPAddr).Port); socket == nil || socket.Bind != netip.MustParseAddr("127.0.0.1") ||
		socket.Owner != ListenersOwnerProgram || socket.Program != program || socket.Pid != int32(os.Getpid()) {
		t.Errorf("the loopback listener: %+v", socket)
	}
	if socket := find(tcp, dual.Addr().(*net.TCPAddr).Port); socket == nil || socket.Bind != netip.IPv6Unspecified() || socket.V6Only {
		t.Errorf("the dual-stack listener: %+v", socket)
	}
	if v6Err == nil {
		if socket := find(tcp, v6.Addr().(*net.TCPAddr).Port); socket == nil || socket.Bind != netip.IPv6Loopback() || !socket.V6Only {
			t.Errorf("the IPv6-only listener: %+v", socket)
		}
	}
	udpProtocol := protocol.ListenersProtocol_LISTENERS_PROTOCOL_UDP
	if socket := find(udpProtocol, udp.LocalAddr().(*net.UDPAddr).Port); socket == nil || socket.Bind != netip.IPv4Unspecified() || socket.Program != program {
		t.Errorf("the UDP socket: %+v", socket)
	}
	if socket := find(udpProtocol, connected.LocalAddr().(*net.UDPAddr).Port); socket != nil {
		t.Errorf("a connected UDP socket listed: %+v", socket)
	}
	if first := discoverer.EphemeralFirstPort(); first == 0 {
		t.Error("no ephemeral threshold")
	}

	destroyed := discoverer.Destroyed()
	if destroyed == nil {
		t.Skip("the kernel offers no destruction notice here")
	}
	loopback.Close()
	select {
	case <-destroyed:
	case <-time.After(30 * time.Second):
		t.Error("no notice for the closed listener")
	}
}

// A dump whose context ended is cut and lists nothing, and the next one reads again.
func TestListenersLinuxDumpCutByItsContext(t *testing.T) {
	discoverer, err := NewListenersDiscoverer(DefaultListenersSettings())
	if err != nil {
		t.Fatal(err)
	}
	defer discoverer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if sockets, err := discoverer.Dump(ctx); err == nil {
		t.Errorf("a cut dump listed %d sockets", len(sockets))
	}
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := discoverer.Dump(ctx); err != nil {
		t.Errorf("the dump after: %v", err)
	}
}
