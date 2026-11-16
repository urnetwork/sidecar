//go:build sidecar_testhooks && !sidecar_http && !ios_extension

// A listener a test hands §13.7's front its streams through (tls_front.go), for sidecartest's T2 tls suite
// (TLS-M5-25; QD-852): the suite's edge stream is an in-memory pair, since sidecartest has no edge-role connect
// client on its exchange, and the front accepts only from a SocketListener, whose conns only this package makes. With
// this the suite runs the front itself at the listener's end of a stream tlsedge opened, on the ticket the sockets
// engine signed and the TlsEdgeOpen the edge built, so the front's trust step, its handshake and its audience check
// are the production ones.
//
// What it stands in for is §9.6's admission alone: Deliver takes a ticket the test verified, as admission's step 3
// would have, and names the urnetwork-edge network the registrar would have answered.
//
// Nothing here holds or derives a key. Only the sidecar_testhooks build has these, which no release leg is (§22.4).

package sidecar

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One §6 stream as the front's conn uses it: the listener's end of a test's pair.
type TlsFrontTestStream interface {
	Read(b []byte) (int, error)
	Write(b []byte) (int, error)
	// This end's direction ends. Reads go on.
	CloseWrite() error
	// This end's direction ends, and this end stops reading.
	Close() error
	// Both directions end now, with code.
	Reset(code protocol.StreamResetCode) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// TlsFrontArgs.Listener for a test: the front accepts what Deliver hands it.
type TlsFrontTestListener struct {
	edgeNetworkId Id
	conns         chan *SocketConn
	closed        chan struct{}
	closeOnce     sync.Once
}

var _ tlsFrontListener = (*TlsFrontTestListener)(nil)

// A listener whose registrar named edgeNetworkId as urnetwork-edge.
func NewTlsFrontTestListener(edgeNetworkId Id) *TlsFrontTestListener {
	return &TlsFrontTestListener{
		edgeNetworkId: edgeNetworkId,
		conns:         make(chan *SocketConn),
		closed:        make(chan struct{}),
	}
}

// Hands the front stream as a stream admitted on ticket whose open carried openMetadata, and returns once the front
// accepted it. False once the listener closed, which the front's Close does.
func (self *TlsFrontTestListener) Deliver(stream TlsFrontTestStream, ticket *protocol.SocketTicket, openMetadata []byte) bool {
	conn := newSocketConn(stream, &SocketAddr{}, &SocketAddr{}, ticket, openMetadata)
	select {
	case <-self.closed:
		return false
	default:
	}
	select {
	case self.conns <- conn:
		return true
	case <-self.closed:
		return false
	}
}

// See tlsFrontListener.
func (self *TlsFrontTestListener) AcceptSocket(ctx context.Context) (*SocketConn, error) {
	select {
	case conn := <-self.conns:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// See tlsFrontListener. A test's listener has no registration to mark.
func (self *TlsFrontTestListener) SetServing(serving bool) {
}

// See tlsFrontListener.
func (self *TlsFrontTestListener) Close() error {
	self.closeOnce.Do(func() {
		close(self.closed)
	})
	return nil
}

// See tlsFrontListener.
func (self *TlsFrontTestListener) tlsEdgeNetworkId() (Id, bool) {
	return self.edgeNetworkId, true
}
