// The engine's streams (§14.4, §9.4, D-SMTP-1, C9; SMTP-M9-13): the ur/smtpedge listener, each stream's preamble
// and its connection, the connections by send_id for the RPCs, and the drain.
//
// Serve listens as ur/smtpedge through a SocketPlatformListener on the host's platform clients in
// urnetwork-edge (SOCK-M9-01), registers the SMTP_PROOF and SMTP_HANDSHAKE handlers on each client's dispatcher
// in the edge role (proof_rpc.go), and serves each admitted stream: the network and client come from its ticket,
// never from the sidecar, and the sidecar from SmtpDialerSource. A preamble that is not answered OK ends its
// stream after the result frame; an OK one becomes a connection (connection.go), registered by its send_id until
// it ends.
//
// Drain stops new tickets and new streams, lets connections finish up to DrainTimeout on the engine's clock, and
// resets the rest; mail then waits at its sender, never at the edge (§14.9). Close joins every goroutine.
//
// Cuts and outcomes reach §14.8's ladder through one goroutine and a bounded queue, off every connection's path:
// a cut's send record is written first, so the ladder counts it.
//
// Nothing here logs a network, a domain or an address (I-13). Safe for concurrent use.

package smtpedgeservice

import (
	"errors"
	"io"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The platform name the engine listens on (§9.4, §14.4): an identifier.
const SmtpEdgeSocketName = "ur/smtpedge"

// The sidecar a dialing client is, from memory the host fills off the path: the §8 subject of mail_send. A ur/
// ticket names the dialer's network and client and no sidecar, so until the ticket or the gate's feed carries
// the binding (question smtp-m9-13-dialer-sidecar) the host gives this, and a miss answers TRY_LATER. Safe for
// concurrent use; no method does I/O.
type SmtpDialerSource interface {
	SidecarForClient(networkId sidecar.Id, clientId sidecar.Id) (sidecarId sidecar.Id, ok bool)
}

// A cut or an outcome for the ladder, with the send record a cut writes first.
type smtpHaltWork struct {
	event *SmtpHaltEvent
	send  *SmtpSendRecord
}

// Queues event for the ladder, with zero wait: past HaltEventMaxCount it is dropped and counted.
func (self *SmtpEdgeService) haltEvent(event *SmtpHaltEvent, send *SmtpSendRecord) {
	if self.ladder == nil {
		self.metrics.haltEvents.Add(1, smtpHaltEventDropped)
		return
	}
	select {
	case self.haltWork <- &smtpHaltWork{event: event, send: send}:
	default:
		self.metrics.haltEvents.Add(1, smtpHaltEventDropped)
	}
}

// Runs the ladder over queued work until the engine ends.
func (self *SmtpEdgeService) runHalts() {
	defer self.workers.Done()
	for {
		select {
		case <-self.ctx.Done():
			return
		case work := <-self.haltWork:
			err := func() error {
				ctx, done := self.storeContext()
				defer done()
				if work.send != nil {
					// the ladder counts the cut from the send log, so the record goes first; a batch that
					// writes it again inserts nothing (InsertSends' key)
					if err := self.store.InsertSends(ctx, []*SmtpSendRecord{work.send}); err != nil {
						return err
					}
				}
				_, err := self.ladder.Apply(ctx, work.event)
				return err
			}()
			if err != nil {
				self.metrics.haltEvents.Add(1, smtpHaltEventFailed)
			} else {
				self.metrics.haltEvents.Add(1, smtpHaltEventApplied)
			}
			self.haltWorkCount.Update(func(count int) int { return count + 1 })
		}
	}
}

// Listens as ur/smtpedge on args' platform clients until the engine closes, serving each admitted stream, and
// returns once the listener closed. args.Name is set here. Called once, by the host, when its clients exist.
func (self *SmtpEdgeService) Serve(args *sidecar.SocketPlatformListenerArgs) error {
	if args == nil {
		return errors.New("smtpedge serves on platform clients")
	}
	if self.preamble == nil {
		return errors.New("smtpedge has no preamble path, so it serves nothing")
	}
	listenArgs := *args
	listenArgs.Name = SmtpEdgeSocketName
	listener, err := sidecar.NewSocketPlatformListener(self.ctx, &listenArgs)
	if err != nil {
		return err
	}
	removes := []func(){}
	fail := func(err error) error {
		for _, remove := range removes {
			remove()
		}
		listener.Close()
		return err
	}
	for _, client := range listenArgs.Clients {
		remove, err := client.Subprotocol.Handle(protocol.MessageType_SMTP_PROOF, self.handleProof, &sidecar.HandleOptions{Mutating: true})
		if err != nil {
			return fail(err)
		}
		removes = append(removes, remove)
		remove, err = client.Subprotocol.Handle(protocol.MessageType_SMTP_HANDSHAKE, self.handleHandshake, &sidecar.HandleOptions{Mutating: true})
		if err != nil {
			return fail(err)
		}
		removes = append(removes, remove)
	}
	kept := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed || self.listener != nil {
			return false
		}
		self.listener = listener
		self.handlerRemoves = removes
		return true
	}()
	if !kept {
		return fail(errors.New("smtpedge is closed or already serving"))
	}
	for {
		conn, err := listener.AcceptSocket(self.ctx)
		if err != nil {
			return nil
		}
		if !self.startStream() {
			conn.Abort()
			continue
		}
		go func() {
			defer self.streams.Done()
			self.serveSocket(conn)
		}()
	}
}

// Counts one more stream, unless the engine is draining or closed.
func (self *SmtpEdgeService) startStream() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed || self.draining {
		return false
	}
	self.streams.Add(1)
	return true
}

// One admitted stream: its dialer from the ticket, then its preamble and connection.
func (self *SmtpEdgeService) serveSocket(conn *sidecar.SocketConn) {
	ticket := conn.Ticket()
	networkId, networkErr := sidecar.IdFromBytes(ticket.GetDialerNetworkId())
	clientId, clientErr := sidecar.IdFromBytes(ticket.GetDialerClientId())
	if networkErr != nil || clientErr != nil {
		conn.Abort()
		return
	}
	stream := &smtpPreambleStream{NetworkId: networkId, ClientId: clientId}
	if self.deps.Dialers != nil {
		if sidecarId, ok := self.deps.Dialers.SidecarForClient(networkId, clientId); ok {
			stream.SidecarId = sidecarId
		}
	}
	self.serveStream(conn, stream)
}

// Ends a stream that never became a connection: a FIN after its result frame, or a reset.
func smtpAbortStream(conn io.ReadWriteCloser) {
	if aborter, ok := conn.(interface{ Abort() error }); ok {
		aborter.Abort()
		return
	}
	conn.Close()
}

// Serves one stream from its preamble to its connection's end.
func (self *SmtpEdgeService) serveStream(conn io.ReadWriteCloser, stream *smtpPreambleStream) {
	outcome, err := self.preamble.serve(self.ctx, stream, conn)
	if err != nil {
		smtpAbortStream(conn)
		return
	}
	if outcome.Result.GetCode() != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK) {
		// any other result ends the stream after its frame (plan-SMTP-wire-gaps#3)
		conn.Close()
		return
	}
	lease, err := self.leases.acquire(stream.NetworkId)
	if err != nil {
		outcome.abandon(self.ctx, self.quota)
		smtpAbortStream(conn)
		return
	}
	connection := newSmtpEdgeConnection(self, stream, conn, outcome, lease)
	if !self.register(connection) {
		outcome.abandon(self.ctx, self.quota)
		self.leases.release(lease)
		smtpAbortStream(conn)
		return
	}
	connection.run()
}

// Registers a connection by its send_id, unless the engine is closing or the id is taken.
func (self *SmtpEdgeService) register(connection *smtpEdgeConnection) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := string(connection.send.SendId)
	if self.closed || self.sendIdConnections[key] != nil {
		return false
	}
	self.sendIdConnections[key] = connection
	return true
}

// Takes an ended connection out, waking a drain.
func (self *SmtpEdgeService) unregister(connection *smtpEdgeConnection) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := string(connection.send.SendId)
	if self.sendIdConnections[key] == connection {
		delete(self.sendIdConnections, key)
		close(self.connectionsChanged)
		self.connectionsChanged = make(chan struct{})
	}
}

// The live connection of a send_id.
func (self *SmtpEdgeService) connection(sendId []byte) *smtpEdgeConnection {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sendIdConnections[string(sendId)]
}

// Every live connection.
func (self *SmtpEdgeService) liveConnections() []*smtpEdgeConnection {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	connections := make([]*smtpEdgeConnection, 0, len(self.sendIdConnections))
	for _, connection := range self.sendIdConnections {
		connections = append(connections, connection)
	}
	return connections
}

// Waits until no connection is live or DrainTimeout passes on the engine's clock, then resets what is left.
func (self *SmtpEdgeService) drainConnections() {
	timeout := self.clock.After(self.settings.DrainTimeout)
	for {
		changed, count := func() (chan struct{}, int) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.connectionsChanged, len(self.sendIdConnections)
		}()
		if count == 0 {
			return
		}
		select {
		case <-changed:
		case <-timeout:
			for _, connection := range self.liveConnections() {
				connection.end(smtpConnectionResultEnded)
			}
			return
		case <-self.ctx.Done():
			return
		}
	}
}

// The ends of halt work, a metric's result.
const (
	smtpHaltEventApplied = "applied"
	smtpHaltEventFailed  = "failed"
	smtpHaltEventDropped = "dropped"
)

// Ends every connection and waits for each stream's goroutine.
func (self *SmtpEdgeService) closeConnections() {
	for _, connection := range self.liveConnections() {
		connection.end(smtpConnectionResultEnded)
	}
	self.streams.Wait()
}
