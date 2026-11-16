//go:build !sidecar_http && !ios_extension

// bridgeNetDaemonListener's bounds (bridge_net.go): a host's stand-in daemon listener on no port of its upstream's,
// which rule 0 would refuse to every flow there whatever its protocol (FS-38's twin, tip-check's red at 54e31119).
// fault's TestFs38ShareDaemonListensOnNoPortOfTheUpstreams runs a share world whose first offer takes the upstream's
// datagram port.

package sidecartest

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
)

// An offer that holds no socket and says it listens at address, on whatever number a test names. Its taker closes it.
type bridgeNetOfferedListener struct {
	address   *net.TCPAddr
	closeOnce sync.Once
	closed    chan struct{}
}

func newBridgeNetOfferedListener(port uint16) *bridgeNetOfferedListener {
	return &bridgeNetOfferedListener{
		address: net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)),
		closed:  make(chan struct{}),
	}
}

func (self *bridgeNetOfferedListener) Accept() (net.Conn, error) {
	<-self.closed
	return nil, net.ErrClosed
}

func (self *bridgeNetOfferedListener) Close() error {
	self.closeOnce.Do(func() {
		close(self.closed)
	})
	return nil
}

func (self *bridgeNetOfferedListener) Addr() net.Addr {
	return self.address
}

func (self *bridgeNetOfferedListener) isClosed() bool {
	select {
	case <-self.closed:
		return true
	default:
		return false
	}
}

// An upstream on loopback, closed by t's cleanup.
func newBridgeNetDaemonUpstream(t *testing.T) *BridgeNetUpstream {
	t.Helper()
	upstream, err := newBridgeNetUpstream(DefaultBridgeNetSettings().ReadByteCount)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(upstream.close)
	return upstream
}

// Offers that keep taking the upstream's ports, its datagram port and its connection port in turn, are refused up to
// the bound, and each one is closed: no listener stands on an upstream port, and none is left open.
func TestBridgeNetDaemonListenerRefusesEveryUpstreamPort(t *testing.T) {
	upstream := newBridgeNetDaemonUpstream(t)
	var offers []*bridgeNetOfferedListener
	listen := func(upstream *BridgeNetUpstream) (net.Listener, error) {
		port := upstream.UdpPort()
		if len(offers)%2 == 1 {
			port = upstream.TcpPort()
		}
		offers = append(offers, newBridgeNetOfferedListener(port))
		return offers[len(offers)-1], nil
	}
	listener, err := bridgeNetDaemonListener(upstream, listen, 3)
	if err == nil {
		listener.Close()
		t.Fatalf("a daemon listener on %s, a port of the upstream's", listener.Addr())
	}
	if len(offers) != 3 {
		t.Fatalf("%d offers, not the bound's 3", len(offers))
	}
	for _, offer := range offers {
		if !offer.isClosed() {
			t.Fatalf("the refused offer at %s was left open", offer.Addr())
		}
	}
}

// A bound under one takes one offer, and a clear one is taken as offered.
func TestBridgeNetDaemonListenerBoundUnderOneTakesOneOffer(t *testing.T) {
	upstream := newBridgeNetDaemonUpstream(t)
	var offers []*bridgeNetOfferedListener
	listen := func(upstream *BridgeNetUpstream) (net.Listener, error) {
		offers = append(offers, newBridgeNetOfferedListener(upstream.UdpPort()))
		return offers[len(offers)-1], nil
	}
	if listener, err := bridgeNetDaemonListener(upstream, listen, 0); err == nil {
		listener.Close()
		t.Fatalf("a daemon listener on the upstream's datagram port %s", listener.Addr())
	}
	if len(offers) != 1 || !offers[0].isClosed() {
		t.Fatalf("%d offers under a bound of 0, the first closed: %v", len(offers), 0 < len(offers) && offers[0].isClosed())
	}

	clear := newBridgeNetOfferedListener(upstream.UdpPort() + 1)
	if upstream.UdpPort()+1 == upstream.TcpPort() {
		clear = newBridgeNetOfferedListener(upstream.UdpPort() + 2)
	}
	listener, err := bridgeNetDaemonListener(upstream, func(upstream *BridgeNetUpstream) (net.Listener, error) { return clear, nil }, 0)
	if err != nil || listener != clear || clear.isClosed() {
		t.Fatalf("the clear offer %s was not taken as offered: %v", clear.Addr(), err)
	}
	clear.Close()
}

// A listen that fails ends the offers with its error, and closes those refused before it.
func TestBridgeNetDaemonListenerReturnsAListenError(t *testing.T) {
	upstream := newBridgeNetDaemonUpstream(t)
	refused := newBridgeNetOfferedListener(upstream.UdpPort())
	listenErr := errors.New("bridge net daemon listen refused")
	calls := 0
	listen := func(upstream *BridgeNetUpstream) (net.Listener, error) {
		calls += 1
		if calls == 1 {
			return refused, nil
		}
		return nil, listenErr
	}
	if listener, err := bridgeNetDaemonListener(upstream, listen, 8); !errors.Is(err, listenErr) {
		if listener != nil {
			listener.Close()
		}
		t.Fatalf("the listen's error came back as %v", err)
	}
	if calls != 2 || !refused.isClosed() {
		t.Fatalf("%d listens, the refused offer closed: %v", calls, refused.isClosed())
	}
}

// With no listen given, the daemon listens on loopback, on no port of the upstream's.
func TestBridgeNetDaemonListenerDefaultListensOnLoopback(t *testing.T) {
	upstream := newBridgeNetDaemonUpstream(t)
	listener, err := bridgeNetDaemonListener(upstream, nil, DefaultBridgeNetSettings().DaemonListenAttemptCount)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() {
		t.Fatalf("the daemon listens at %s, not on loopback", listener.Addr())
	}
	if address.Port == int(upstream.TcpPort()) || address.Port == int(upstream.UdpPort()) {
		t.Fatalf("the daemon listens on %d, a port of the upstream's", address.Port)
	}
}
