//go:build !sidecar_http && !ios_extension

// SocketConn: §9.9's connection, a net.Conn over one §6 stream (D-SOCK-8), what a dialer's Dial and a
// listener's Accept return (SOCK-M5-11, SOCK-M5-12). Close sends FIN and stops reading, so the peer
// reads io.EOF; CloseWrite is FIN alone; Abort is a reset. Deadlines are local and the stream survives
// them. RemoteAddr is the dialer's network and client id, Network() "ur"; an edge's visitor address
// arrives in-band (§13), never here. Every error but a plain io.EOF is a *net.OpError with Net "ur"
// (socket_errors.go).
//
// It names connect.Id, so it stays off the sidecar_http leg: a page Worker neither dials nor listens.
// Safe for concurrent use, as net.Conn is.

package sidecar

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/urnetwork/connect"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// One end of a SocketConn: a network and a client. Ids are opaque (I-13), so the text is safe to log.
type SocketAddr struct {
	NetworkId connect.Id
	ClientId  connect.Id
}

var _ net.Addr = (*SocketAddr)(nil)

// "ur", §9.9's network.
func (self *SocketAddr) Network() string {
	return "ur"
}

// <network_id>/<client_id>.
func (self *SocketAddr) String() string {
	return self.NetworkId.String() + "/" + self.ClientId.String()
}

// §9.9's connection. newSocketConn makes one around an admitted stream.
type SocketConn struct {
	stream     socketStream
	localAddr  *SocketAddr
	remoteAddr *SocketAddr
	ticket     *protocol.SocketTicket
	// StreamOpen.ticket's bytes as received, the service's signature over the ticket: a listener's reach evidence
	// for §16's ReachReceipt. Empty on a dialer's conn.
	signedTicket []byte
	// StreamOpen.metadata as the stream opened, which an edge fills (§13.5, C-07).
	openMetadata []byte
}

var _ net.Conn = (*SocketConn)(nil)

// A connection over stream between localAddr and remoteAddr, admitted on ticket with openMetadata.
// The connection keeps all four, so the caller must not change them afterwards.
func newSocketConn(stream socketStream, localAddr *SocketAddr, remoteAddr *SocketAddr, ticket *protocol.SocketTicket, openMetadata []byte) *SocketConn {
	return &SocketConn{
		stream:       stream,
		localAddr:    localAddr,
		remoteAddr:   remoteAddr,
		ticket:       ticket,
		openMetadata: openMetadata,
	}
}

// err as §9.9 says a SocketConn returns it, from op.
func (self *SocketConn) opError(op string, err error) error {
	var resetErr *socketStreamResetError
	if errors.As(err, &resetErr) {
		err = &SocketCodeError{Err: ErrSocketReset, ResetCode: resetErr.Code}
	}
	return &net.OpError{Op: op, Net: "ur", Source: self.localAddr, Addr: self.remoteAddr, Err: err}
}

// See net.Conn. io.EOF comes back plain once the peer's FIN and every byte before it are read.
func (self *SocketConn) Read(b []byte) (int, error) {
	n, err := self.stream.Read(b)
	if err == nil || err == io.EOF {
		return n, err
	}
	return n, self.opError("read", err)
}

// See net.Conn.
func (self *SocketConn) Write(b []byte) (int, error) {
	n, err := self.stream.Write(b)
	if err != nil {
		return n, self.opError("write", err)
	}
	return n, nil
}

// Sends FIN and stops reading: the peer reads io.EOF, and this end's Read and Write then fail. A
// second Close fails as a net.Conn's does.
func (self *SocketConn) Close() error {
	if err := self.stream.Close(); err != nil {
		return self.opError("close", err)
	}
	return nil
}

// Sends FIN and reads on, as TCP's half-close does.
func (self *SocketConn) CloseWrite() error {
	if err := self.stream.CloseWrite(); err != nil {
		return self.opError("close", err)
	}
	return nil
}

// Resets the stream (§6.7's RST_CANCELLED): both directions end at once and bytes in flight are lost.
func (self *SocketConn) Abort() error {
	if err := self.stream.Reset(protocol.StreamResetCode_RST_CANCELLED); err != nil {
		return self.opError("abort", err)
	}
	return nil
}

// Resets the stream with code (§6.7): how a component that took the conn refuses it with the reason, as the TLS
// front answers RST_IDENTITY to an open it does not trust (§13.5) and RST_PEER_TIMEOUT to a slow visitor (§13.7).
func (self *SocketConn) reset(code protocol.StreamResetCode) error {
	if err := self.stream.Reset(code); err != nil {
		return self.opError("abort", err)
	}
	return nil
}

// This end's network and client.
func (self *SocketConn) LocalAddr() net.Addr {
	return self.localAddr
}

// The dialer's network and client id, Network() "ur" (§9.9).
func (self *SocketConn) RemoteAddr() net.Addr {
	return self.remoteAddr
}

// See net.Conn: both deadlines, local to this end.
func (self *SocketConn) SetDeadline(t time.Time) error {
	if err := self.stream.SetReadDeadline(t); err != nil {
		return self.opError("set", err)
	}
	if err := self.stream.SetWriteDeadline(t); err != nil {
		return self.opError("set", err)
	}
	return nil
}

// See net.Conn. A passed deadline fails Read with os.ErrDeadlineExceeded, Timeout() true, and the
// stream survives it.
func (self *SocketConn) SetReadDeadline(t time.Time) error {
	if err := self.stream.SetReadDeadline(t); err != nil {
		return self.opError("set", err)
	}
	return nil
}

// See net.Conn, as SetReadDeadline for Write.
func (self *SocketConn) SetWriteDeadline(t time.Time) error {
	if err := self.stream.SetWriteDeadline(t); err != nil {
		return self.opError("set", err)
	}
	return nil
}

// A copy of the ticket this connection was admitted on (§9.6's step 7 keeps it as reach evidence).
func (self *SocketConn) Ticket() *protocol.SocketTicket {
	if self.ticket == nil {
		return nil
	}
	return proto.Clone(self.ticket).(*protocol.SocketTicket)
}

// A copy of the signed ticket a listener admitted this connection on, as received: the service's signature over
// Ticket, which §16's ReachReceipt keeps as reach evidence (§9.6's step 7). Empty on a dialer's connection.
func (self *SocketConn) SignedTicket() []byte {
	return append([]byte(nil), self.signedTicket...)
}

// A copy of StreamOpen.metadata as the stream opened: an edge's open metadata, such as TlsEdgeOpen
// (§13.5). C-07 names this accessor for §13 and §15.
func (self *SocketConn) OpenMetadata() []byte {
	return append([]byte(nil), self.openMetadata...)
}
