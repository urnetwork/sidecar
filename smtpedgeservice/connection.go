// smtpEdgeConnection (§14.4, §14.5's E3, §14.7, D-SMTP-1, D-SMTP-10, D-SMTP-22; SMTP-M9-13): one connection after
// its preamble's OK, the sidecar's TLS spliced to the MX the preamble reached. One goroutine reads each direction
// and the connection owns the MX socket:
//
//	sidecar -> MX   whole records (record_split.go) through SmtpProofSession.ClientRecord; only what the session
//	                clears goes to the MX, in the session's order
//	MX -> sidecar   whole records through ServerRecord before each is relayed, so a part can cover them
//	parts           the SMTP_PROOF handler's VerifyPart, and SMTP_HANDSHAKE's DiscloseShts, whose cleared
//	                records go to the MX the same way (proof_rpc.go)
//
// ClientRecord, VerifyPart and DiscloseShts each run with the write of what they cleared under mxWriteLock, so
// the MX gets exactly the session's order; ServerRecord takes no part of that lock, so server records keep
// flowing while a part verifies. When the client octets the session holds reach ConnectionHeldMaxByteCount the
// sidecar's stream is not read until a part clears some: back-pressure, never a buffer, and no byte of either raw
// stream is ever dropped (connect/CODESTYLE.md).
//
// MailForwarded's first true debits the unit (SmtpQuota.DebitMail, §14.7), and the end closes the quota with the
// octets relayed both ways. Every record's octets are spent from the sending network's lease first (lease.go).
// §14.4's limits run on the engine's clock: ClientIdleTimeout after a client record, ServerIdleTimeout after a
// server record, ConnectionTimeout in all, DataConnectionTimeout once a part names DATA; the reservation's
// member is renewed each QuotaMemberRenewInterval meanwhile.
//
// How it ends, once: the MX closing (sent once MAIL went, else refused; ServerClosed makes any part moot;
// the sidecar's own close at a record boundary only half-closes toward the MX and waits for it),
// ErrSmtpRecordCut from the session (a cut, which §14.8 counts toward the network's halt), any other session
// error or a broken stream (ended, counted toward nothing), a limit (timeout), a spent lease (quota), or the
// engine's close. Either socket's end closes the other. The send record then goes to the send log, holding
// smtp-3's fields alone: the MX's name and never its IP, and no ciphertext, record length or SHTS (D-SMTP-10).
//
// Safe for concurrent use: its methods run from its two goroutines, its watcher and the RPC handlers.

package smtpedgeservice

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// A session call after the connection ended.
var errSmtpConnectionEnded = errors.New("smtp connection ended")

type smtpEdgeConnection struct {
	service     *SmtpEdgeService
	stream      *smtpPreambleStream
	sidecarConn io.ReadWriteCloser
	mx          *smtpMxConnection
	session     sidecar.SmtpProofSession
	reservation *SmtpQuotaReservation
	send        *SmtpSendRecord
	lease       *smtpEdgeLease
	startTime   time.Time
	// closed once the connection ended
	done chan struct{}

	// held across a session call that can clear records and the write of what it cleared
	mxWriteLock sync.Mutex

	stateLock      sync.Mutex
	ended          bool
	result         string
	cut            bool
	lastRecordTime time.Time
	lastServer     bool
	dataMode       bool
	heldByteCount  int
	byteCount      uint64
	partCount      int
	mailDebited    bool
	tlsVersion     uint16
	// closed and replaced when the held octets fall, or at the end
	heldChanged chan struct{}
}

func newSmtpEdgeConnection(service *SmtpEdgeService, stream *smtpPreambleStream, sidecarConn io.ReadWriteCloser, outcome *smtpPreambleOutcome, lease *smtpEdgeLease) *smtpEdgeConnection {
	now := service.clock.Now()
	return &smtpEdgeConnection{
		service:        service,
		stream:         stream,
		sidecarConn:    sidecarConn,
		mx:             outcome.Mx,
		session:        outcome.Session,
		reservation:    outcome.Reservation,
		send:           outcome.Send,
		lease:          lease,
		startTime:      now,
		done:           make(chan struct{}),
		lastRecordTime: now,
		heldChanged:    make(chan struct{}),
	}
}

// Splices both ways until the connection ends, then settles it: quota, lease, send record, metrics, and a cut's
// halt rule. Returns once everything it started has.
func (self *smtpEdgeConnection) run() {
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		self.watch()
	}()
	relayed := make(chan struct{})
	go func() {
		defer close(relayed)
		self.relayServer()
	}()
	self.relayClient()
	<-relayed
	<-watched
	self.finish()
}

// Ends the connection with result, once: both sockets close, so both goroutines stop. A clean end closes the
// sidecar's stream with a FIN after every relayed byte, any other resets it.
func (self *smtpEdgeConnection) end(result string) {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.ended {
			return false
		}
		self.ended = true
		self.result = result
		if result == smtpConnectionResultCut {
			self.cut = true
		}
		close(self.heldChanged)
		self.heldChanged = make(chan struct{})
		return true
	}()
	if !first {
		return
	}
	close(self.done)
	self.mx.conn.Close()
	switch result {
	case smtpConnectionResultSent, smtpConnectionResultRefused:
		self.sidecarConn.Close()
	default:
		if aborter, ok := self.sidecarConn.(interface{ Abort() error }); ok {
			aborter.Abort()
		} else {
			self.sidecarConn.Close()
		}
	}
}

// Ends on a session's error: ErrSmtpRecordCut is §14.7's cut, anything else ends uncounted.
func (self *smtpEdgeConnection) endSession(err error) {
	if errors.Is(err, sidecar.ErrSmtpRecordCut) {
		self.end(smtpConnectionResultCut)
		return
	}
	self.end(smtpConnectionResultEnded)
}

// Whether the connection ended.
func (self *smtpEdgeConnection) isEnded() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.ended
}

// A record's arrival, which restarts its idle limit, and its octets.
func (self *smtpEdgeConnection) touch(server bool, byteCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lastRecordTime = self.service.clock.Now()
	self.lastServer = server
	self.byteCount += uint64(byteCount)
}

// When the connection's limits end it: the idle limit after its last record or its lifetime, the earlier.
func (self *smtpEdgeConnection) deadline() time.Time {
	settings := self.service.settings
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lifetime := settings.ConnectionTimeout
	if self.dataMode {
		lifetime = settings.DataConnectionTimeout
	}
	idle := settings.ClientIdleTimeout
	if self.lastServer {
		idle = settings.ServerIdleTimeout
	}
	deadline := self.startTime.Add(lifetime)
	if idleEnd := self.lastRecordTime.Add(idle); idleEnd.Before(deadline) {
		deadline = idleEnd
	}
	return deadline
}

// Ends the connection at its deadline, which records only move later, and renews its quota member meanwhile.
func (self *smtpEdgeConnection) watch() {
	clock := self.service.clock
	renewAt := self.startTime.Add(self.service.settings.QuotaMemberRenewInterval)
	for {
		wake := self.deadline()
		if renewAt.Before(wake) {
			wake = renewAt
		}
		select {
		case <-self.done:
			return
		case <-clock.After(wake.Sub(clock.Now())):
		}
		now := clock.Now()
		if !now.Before(renewAt) {
			// a renewal that fails leaves the member to lapse, which heals the count if this edge is gone
			self.service.quota.Renew(self.service.ctx, self.reservation)
			renewAt = now.Add(self.service.settings.QuotaMemberRenewInterval)
		}
		if !now.Before(self.deadline()) {
			self.end(smtpConnectionResultTimeout)
			return
		}
	}
}

// Waits while the session holds ConnectionHeldMaxByteCount client octets. False once the connection ended.
func (self *smtpEdgeConnection) awaitRoom() bool {
	for {
		changed, room, ended := func() (chan struct{}, bool, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.heldChanged, self.heldByteCount < self.service.settings.ConnectionHeldMaxByteCount, self.ended
		}()
		if ended {
			return false
		}
		if room {
			return true
		}
		self.service.heldWaitCount.Update(func(count int) int { return count + 1 })
		select {
		case <-changed:
		case <-self.done:
			return false
		}
	}
}

// Moves the held count by delta, waking a reader waiting for room when it falls.
func (self *smtpEdgeConnection) addHeld(delta int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.heldByteCount += delta
	if delta < 0 {
		close(self.heldChanged)
		self.heldChanged = make(chan struct{})
	}
}

// Writes records the session cleared to the MX, in order, under mxWriteLock. mailNow is true the first time
// MailForwarded reads true after a write, which is when the unit is charged.
func (self *smtpEdgeConnection) writeMxWithLock(records [][]byte) (mailNow bool, err error) {
	for _, record := range records {
		if _, err := self.mx.conn.Write(record); err != nil {
			return false, err
		}
		self.addHeld(-len(record))
	}
	if len(records) == 0 {
		return false, nil
	}
	self.stateLock.Lock()
	debited := self.mailDebited
	self.stateLock.Unlock()
	if debited || !self.session.MailForwarded() {
		return false, nil
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.mailDebited {
		return false, nil
	}
	self.mailDebited = true
	return true, nil
}

// Charges the connection's unit and its recipients once MAIL has gone (§14.7). Off every lock.
func (self *smtpEdgeConnection) debitMail() {
	testHookBarrier("smtpedge.debit_mail.before", "")
	self.service.quota.DebitMail(self.service.ctx, self.reservation)
	testHookBarrier("smtpedge.debit_mail.after", "")
}

// Whether the unit was charged: MAIL went to the MX.
func (self *smtpEdgeConnection) mailForwarded() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.mailDebited
}

// Relays the sidecar's records until the connection ends.
func (self *smtpEdgeConnection) relayClient() {
	splitter := newSmtpRecordSplitter(self.sidecarConn, self.service.settings.RecordMaxByteCount)
	for {
		if !self.awaitRoom() {
			return
		}
		record, err := splitter.next()
		if errors.Is(err, io.EOF) {
			// the sidecar closed its half at a record boundary, after QUIT as a rule: the MX's close ends the
			// connection, or a limit does, and the MX hears the same half-close where its socket can say it
			if closer, ok := self.mx.conn.(interface{ CloseWrite() error }); ok {
				closer.CloseWrite()
			}
			return
		}
		if err != nil {
			// the sidecar broke its stream inside a record: nothing it sent is half-forwarded
			self.end(smtpConnectionResultEnded)
			return
		}
		self.touch(false, len(record))
		if !self.service.leases.spend(self.lease, len(record)) {
			self.end(smtpConnectionResultQuota)
			return
		}
		mailNow, err := func() (bool, error) {
			self.mxWriteLock.Lock()
			defer self.mxWriteLock.Unlock()
			if self.isEnded() {
				return false, errSmtpConnectionEnded
			}
			cleared, err := self.session.ClientRecord(record)
			self.addHeld(len(record))
			if err != nil {
				return false, err
			}
			return self.writeMxWithLock(cleared)
		}()
		if errors.Is(err, errSmtpConnectionEnded) {
			return
		}
		if err != nil {
			// a write the MX's close broke ends as the MX's close did, since the first end wins
			self.endSession(err)
			return
		}
		if mailNow {
			self.debitMail()
		}
	}
}

// Relays the MX's records until the connection ends; the MX's close ends it.
func (self *smtpEdgeConnection) relayServer() {
	splitter := newSmtpRecordSplitter(self.mx.conn, self.service.settings.RecordMaxByteCount)
	for {
		record, err := splitter.next()
		if err != nil {
			if self.isEnded() {
				return
			}
			// the MX closed, a 421 included: any outstanding part is moot (§14.5)
			self.session.ServerClosed()
			if self.mailForwarded() {
				self.end(smtpConnectionResultSent)
			} else {
				self.end(smtpConnectionResultRefused)
			}
			return
		}
		self.touch(true, len(record))
		if !self.service.leases.spend(self.lease, len(record)) {
			self.end(smtpConnectionResultQuota)
			return
		}
		if version := smtpServerHelloVersion(record); version != 0 {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				if self.tlsVersion == 0 {
					self.tlsVersion = version
				}
			}()
		}
		if err := self.session.ServerRecord(record); err != nil {
			self.endSession(err)
			return
		}
		if _, err := self.sidecarConn.Write(record); err != nil {
			self.end(smtpConnectionResultEnded)
			return
		}
	}
}

// Checks a part and writes what it clears (proof_rpc.go). Any error ends the connection; ErrSmtpRecordCut is a
// cut.
func (self *smtpEdgeConnection) verifyPart(ctx context.Context, part *sidecar.SmtpProofPart) error {
	start := self.service.clock.Now()
	mailNow, err := func() (bool, error) {
		self.mxWriteLock.Lock()
		defer self.mxWriteLock.Unlock()
		if self.isEnded() {
			return false, errSmtpConnectionEnded
		}
		cleared, err := self.session.VerifyPart(ctx, part)
		if err != nil {
			return false, err
		}
		return self.writeMxWithLock(cleared)
	}()
	elapsed := self.service.clock.Now().Sub(start)
	self.service.metrics.verifySeconds.Observe(elapsed.Seconds())
	if err != nil {
		if !errors.Is(err, errSmtpConnectionEnded) {
			self.endSession(err)
		}
		return err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.partCount += 1
		// DATA's connection lives DataConnectionTimeout (§14.4, D-SMTP-20)
		if sidecar.SmtpMode(part.Mode) == sidecar.SmtpModeData {
			self.dataMode = true
		}
	}()
	if mailNow {
		self.debitMail()
	}
	return nil
}

// Hands the session TLS 1.3's disclosed SHTS (E2) and writes what it clears. Any error ends the connection.
func (self *smtpEdgeConnection) discloseShts(shts []byte) error {
	mailNow, err := func() (bool, error) {
		self.mxWriteLock.Lock()
		defer self.mxWriteLock.Unlock()
		if self.isEnded() {
			return false, errSmtpConnectionEnded
		}
		cleared, err := self.session.DiscloseShts(shts)
		if err != nil {
			return false, err
		}
		return self.writeMxWithLock(cleared)
	}()
	if err != nil {
		if !errors.Is(err, errSmtpConnectionEnded) {
			self.endSession(err)
		}
		return err
	}
	if mailNow {
		self.debitMail()
	}
	return nil
}

// Settles an ended connection: the quota closed with its octets, the lease given back, its send record to the
// log, its outcome awaited, its metrics, and a cut's halt rule.
func (self *smtpEdgeConnection) finish() {
	service := self.service
	endTime := service.clock.Now()
	self.stateLock.Lock()
	result := self.result
	byteCount := self.byteCount
	tlsVersion := self.tlsVersion
	dataMode := self.dataMode
	partCount := self.partCount
	cut := self.cut
	mailDebited := self.mailDebited
	self.stateLock.Unlock()

	// past the engine's own end, so a close still returns what the connection held
	service.quota.Close(context.WithoutCancel(service.ctx), self.reservation, byteCount)
	service.leases.release(self.lease)
	self.mx.release()

	record := *self.send
	record.EndTime = endTime
	record.ByteCount = byteCount
	record.TlsVersion = tlsVersion
	record.Result = result
	if !mailDebited {
		// no MAIL went, so no recipient was sent to: rates and the RUA check count none of them
		record.RecipientCount = 0
	}
	if service.sendLog != nil {
		service.sendLog.add(&record)
	}
	service.outcomes.ended(record.SendId, self.stream.NetworkId, self.stream.ClientId, endTime)

	mode := smtpModeBdat
	if dataMode {
		mode = smtpModeData
	} else if partCount < 2 {
		mode = smtpModeUnknown
	}
	service.metrics.connections.Add(1, result, mode, smtpTlsLevelLabels[0])
	service.metrics.connectionParts.Observe(float64(partCount))
	if cut {
		service.haltEvent(&SmtpHaltEvent{Kind: SmtpHaltEventRecordCut, NetworkId: self.stream.NetworkId, Time: endTime}, &record)
	}
	service.unregister(self)
}
