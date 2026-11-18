// A bridge for smtpedgeservice_test to serveSocket: a stream handed over as the ur/smtpedge listener hands one, on the
// ticket admission verified, so a test reads the dialer from the ticket the way the engine does (QD-989).

package smtpedgeservice

import (
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A test's stream admitted on ticket.
type testAdmittedConn struct {
	io.ReadWriteCloser
	ticket *protocol.SocketTicket
}

// See smtpAdmittedConn.
func (self *testAdmittedConn) Ticket() *protocol.SocketTicket {
	return proto.CloneOf(self.ticket)
}

// Serves conn as the listener hands the engine a stream admitted on ticket, everything about its dialer read from the
// ticket, and returns once its connection ended.
func (self *SmtpEdgeService) ServeTestAdmittedStream(conn io.ReadWriteCloser, ticket *protocol.SocketTicket) {
	if !self.startStream() {
		conn.Close()
		return
	}
	defer self.streams.Done()
	self.serveSocket(&testAdmittedConn{ReadWriteCloser: conn, ticket: ticket})
}
