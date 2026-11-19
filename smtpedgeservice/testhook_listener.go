//go:build sidecar_testhooks

// What a test in another module hands the engine its streams and calls through, for server's T3 of §14 (SMTP-M9-31):
// S6's and FS-123's rows run there on the smtpedge block's host over server's stores and Redis, where no sockets layer
// makes the streams. Serve's ur/smtpedge listener needs platform clients on an exchange, and those clients' dispatchers
// are what call SMTP_PROOF's and SMTP_HANDSHAKE's handlers, so a test stands in for both: Deliver serves a stream as
// the listener serves one admitted on a ticket, its dialer read from the ticket alone (QD-989), and Call runs the
// handler Serve registers for a type as a client's dispatcher calls it for a request from a source.
//
// What it stands in for is §9.6's admission and §6's dispatch alone: the ticket is one the test made, which
// admission's step 3 would have verified, and a call skips the dispatcher's own rules (its Hello, its idempotency
// cache). Everything from the ticket on, the preamble, the gate, the quota, the splice, the parts' checks and the
// send log, is the engine's own path.
//
// The waits let a test step the engine's clock without sleeping: AwaitStarted for what a preamble needs loaded first,
// and ProbeCount with AwaitProbes for a halt reload.
//
// Only the sidecar_testhooks build has this, which no release leg is (§22.4). Nothing here holds or derives a key.
// Safe for concurrent use.

package smtpedgeservice

import (
	"context"
	"errors"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A message type the engine registers no handler for.
var errSmtpEdgeTestListenerType = errors.New("smtpedge test listener: no handler for that type")

// The listener and dispatcher a test stands in for, for one engine.
type SmtpEdgeTestListener struct {
	service *SmtpEdgeService
}

// The test's listener for service.
func NewSmtpEdgeTestListener(service *SmtpEdgeService) *SmtpEdgeTestListener {
	return &SmtpEdgeTestListener{service: service}
}

// One stream as the listener hands it over.
type smtpTestAdmittedConn struct {
	io.ReadWriteCloser
	ticket *protocol.SocketTicket
}

// See smtpAdmittedConn.
func (self *smtpTestAdmittedConn) Ticket() *protocol.SocketTicket {
	return proto.CloneOf(self.ticket)
}

// Serves conn as a stream admitted on ticket, as Serve's loop serves one, and returns once its connection ended. A
// draining or closed engine takes none, and conn is closed.
func (self *SmtpEdgeTestListener) Deliver(conn io.ReadWriteCloser, ticket *protocol.SocketTicket) {
	if !self.service.startStream() {
		conn.Close()
		return
	}
	defer self.service.streams.Done()
	self.service.serveSocket(&smtpTestAdmittedConn{ReadWriteCloser: conn, ticket: proto.CloneOf(ticket)})
}

// Runs the handler Serve registers for messageType, SMTP_PROOF or SMTP_HANDSHAKE, on body as a client's dispatcher
// runs it for a request from sourceId, and returns its answer.
func (self *SmtpEdgeTestListener) Call(ctx context.Context, sourceId sidecar.Id, messageType protocol.MessageType, body []byte) ([]byte, error) {
	request := &sidecar.SubprotocolRequest{SourceId: sourceId, MessageType: messageType, Body: body}
	switch messageType {
	case protocol.MessageType_SMTP_PROOF:
		return self.service.handleProof(ctx, request)
	case protocol.MessageType_SMTP_HANDSHAKE:
		return self.service.handleHandshake(ctx, request)
	}
	return nil, errSmtpEdgeTestListenerType
}

// Waits until monitor counts at least count, or ctx ends.
func awaitSmtpTestCount[T comparable](ctx context.Context, monitor *sidecar.MonitorValue[T], count int, read func(value T) int) error {
	for {
		value, update := monitor.Get()
		if count <= read(value) {
			return nil
		}
		select {
		case <-update:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Waits until the engine has finished its first store probe, its sending set's first check and its breaker's first
// read of Community's median: what a preamble needs loaded before it can be answered OK. An engine missing one of
// them never gets there, and the wait ends with ctx.
func (self *SmtpEdgeTestListener) AwaitStarted(ctx context.Context) error {
	if err := self.AwaitProbes(ctx, 1); err != nil {
		return err
	}
	if self.service.sendingSet == nil || self.service.quota == nil {
		<-ctx.Done()
		return ctx.Err()
	}
	if err := awaitSmtpTestCount(ctx, self.service.sendingSet.checkCount, 1, func(count int) int { return count }); err != nil {
		return err
	}
	return awaitSmtpTestCount(ctx, self.service.quota.Breaker().median, 1, func(median smtpBreakerMedian) int { return median.readCount })
}

// How many store probes have finished, each with its next wait armed: a halt set now reaches the engine at the probe
// after this one, HaltReloadInterval on.
func (self *SmtpEdgeTestListener) ProbeCount() int {
	count, _ := self.service.probeCount.Get()
	return count
}

// Waits until at least count store probes have finished.
func (self *SmtpEdgeTestListener) AwaitProbes(ctx context.Context, count int) error {
	return awaitSmtpTestCount(ctx, self.service.probeCount, count, func(count int) int { return count })
}
