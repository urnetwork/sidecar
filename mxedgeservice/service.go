// The engine. A session is a cap check, a banner, the pre-TLS dialog, then a handoff at STARTTLS's 220.
//
// A session never touches the store, and it reaches Redis only for the closed-handshake memory, inside
// StoreTimeout, so nothing on the connection path waits on Postgres (I-12). No log here holds an
// address, EHLO name or SNI (I-13), and a connection's error text is not logged either, since a
// net.OpError carries both addresses.
//
// Every wait is on MxEdgeClock, never a real deadline on a context or socket, so a schedule moves them
// all.

package mxedgeservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

var _ sidecar.StreamEngine = (*MxEdgeService)(nil)

const (
	// A read of this key answers whether Redis does. Nothing writes it, so no key exists, and a hash
	// is hex, so no sender's key can be this.
	mxReadyProbeKey = "{mxc_ready}"
)

// A time long past: setting it as a read deadline interrupts a blocked read without reading any clock.
var mxPastDeadline = time.Unix(1, 0)

// Time as the engine reads it, with sidecartest.Clock's methods, so a FakeClock fits as it stands.
// TEST-M0-02's sidecar.Clock replaces this once it lands.
type MxEdgeClock interface {
	Now() time.Time
	// Fires once the clock reaches now plus timeout.
	After(timeout time.Duration) <-chan time.Time
	// Calls function once the clock reaches now plus timeout. stop returns false once function has
	// been called or stopped.
	AfterFunc(timeout time.Duration, function func()) (stop func() bool)
}

// Real time, what a nil MxEdgeDeps.Clock means.
type mxRealClock struct{}

// The wall clock.
func (self mxRealClock) Now() time.Time {
	return time.Now()
}

// A real timer.
func (self mxRealClock) After(timeout time.Duration) <-chan time.Time {
	return time.After(timeout)
}

// A real timer, stopped through its own Stop.
func (self mxRealClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return time.AfterFunc(timeout, function).Stop
}

// TLS alert descriptions a closed handshake may send (RFC 8446 §6).
type MxTlsAlert uint8

const (
	// A hello that does not parse.
	MxTlsAlertDecodeError MxTlsAlert = 50
	// A name this edge cannot route for now.
	MxTlsAlertInternalError MxTlsAlert = 80
	// No name, or one this edge does not know.
	MxTlsAlertUnrecognizedName MxTlsAlert = 112
)

// What ReadClientHello found, with no tlsedgeservice type in it, since an engine imports no other.
type MxClientHello struct {
	// As the sender wrote it. Empty when the hello names none.
	ServerName string
	// Every byte read, verbatim, for the splice.
	RawBytes []byte
}

// What §4.4 forbids this engine importing, as functions (TLS reading 15), and what only a host holds.
// server/mxedgehost wires tlsedgeservice's functions here. The engine is not ready without the three
// functions and the secret, and a session then still fails closed.
type MxEdgeDeps struct {
	// TLS-M5-06's ReadClientHello: reads one hello, at most maxByteCount bytes.
	ReadClientHello func(conn net.Conn, maxByteCount int) (*MxClientHello, error)
	// TLS-M5-06's NormalizeSni.
	NormalizeSni func(serverName string) (normalized string, ok bool)
	// TLS-M5-06's WriteTlsAlert: one plaintext fatal alert.
	WriteTlsAlert func(conn net.Conn, alert MxTlsAlert) error
	// The fleet-wide key k is drawn from (reading 5), at least 32 bytes, from vault's secret_files.
	ClosedHandshakeSecret []byte
	// Whether §19.11's mxedge gate is open, read at each plaintext transaction. nil reads as closed,
	// since config/<env>/sidecar.yml's gates are dark when absent, and a closed gate answers 451, never
	// 530, so a sender retries once it opens (§22.5). OPS-M1-03's ServiceHost.Gates feeds this.
	GateOpen func() bool
	// nil is real time.
	Clock MxEdgeClock
	// nil discards.
	Log sidecar.Logger
}

// One session on TCP 25, from the banner on. Its goroutine owns it.
type mxSession struct {
	conn net.Conn
	// The peer the host's PROXY listener reports, unmapped. Connection memory only (§2.8 mx-1).
	sender netip.Addr
	hold   *mxCapHold
	dialog *mxDialog
}

// The engine. Hosts call Serve once for each listener, and everything here is safe for concurrent use.
type MxEdgeService struct {
	ctx              context.Context
	cancel           context.CancelFunc
	host             *sidecar.ServiceHost
	store            MxEdgeStore
	deps             *MxEdgeDeps
	settings         *MxEdgeSettings
	clock            MxEdgeClock
	log              sidecar.Logger
	metrics          *mxMetrics
	replies          *mxDialogReplies
	caps             *mxCaps
	closedHandshakes *mxClosedHandshakes
	// Every dependency Ready needs from deps was given.
	depsComplete bool
	// What follows STARTTLS's 220, returning a session result. Set once, at construction.
	handoff func(session *mxSession) string
	// Whether a sender gets 554 at the banner. nil rejects nothing, as §15.4 has it with the feed
	// down, and MAIL-M7-20's listings set this.
	bannerRefused func(sender netip.Addr) bool

	// What the last probe found.
	storesReachable *sidecar.MonitorValue[bool]
	// Sessions running, for Drain.
	sessionCount *sidecar.MonitorValue[int]
	sessionGroup sync.WaitGroup
	// Closed once everything is released.
	released chan struct{}

	stateLock       sync.Mutex
	draining        bool
	releasing       bool
	liveListeners   map[net.Listener]bool
	liveConnections map[net.Conn]bool
}

// Starts the engine, which stays not ready until its first probe answers, and runs until ctx ends or
// Close. host needs Redis and Metrics. A nil store or deps is allowed and leaves the engine not ready.
func NewMxEdgeService(
	ctx context.Context,
	host *sidecar.ServiceHost,
	store MxEdgeStore,
	deps *MxEdgeDeps,
	settings *MxEdgeSettings,
) (*MxEdgeService, error) {
	if host == nil || host.Redis == nil || host.Metrics == nil {
		return nil, errors.New("mxedge needs a host with Redis and Metrics")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if deps == nil {
		deps = &MxEdgeDeps{}
	}
	clock := deps.Clock
	if clock == nil {
		clock = mxRealClock{}
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &MxEdgeService{
		ctx:              cancelCtx,
		cancel:           cancel,
		host:             host,
		store:            store,
		deps:             deps,
		settings:         settings,
		clock:            clock,
		log:              log,
		metrics:          newMxMetrics(host.Metrics),
		replies:          newMxDialogReplies(settings),
		caps:             newMxCaps(settings),
		closedHandshakes: newMxClosedHandshakes(host.Redis, deps.ClosedHandshakeSecret, settings.ClosedHandshakeTtl, clock),
		storesReachable:  sidecar.NewMonitorValue(false),
		sessionCount:     sidecar.NewMonitorValue(0),
		released:         make(chan struct{}),
		liveListeners:    map[net.Listener]bool{},
		liveConnections:  map[net.Conn]bool{},
	}
	self.depsComplete = deps.ReadClientHello != nil && deps.NormalizeSni != nil && deps.WriteTlsAlert != nil &&
		self.closedHandshakes.Available()
	self.handoff = self.closeHandshake
	go self.run()
	return self, nil
}

// Probes the stores until the engine ends, then releases everything it holds. This loop is the one
// caller of the store until MAIL-M7-21's batch, so the store stays off the connection path.
func (self *MxEdgeService) run() {
	defer close(self.released)
	defer self.release()
	for {
		// the context's timer goes before the answer is published, so nothing of the probe outlives it
		reachable := func() bool {
			ctx, done := self.storeContext()
			defer done()
			if _, _, err := self.host.Redis.Get(ctx, mxReadyProbeKey); err != nil {
				return false
			}
			return self.store != nil && self.store.Ping(ctx) == nil
		}()
		self.storesReachable.Set(reachable)
		select {
		case <-self.ctx.Done():
			return
		case <-self.clock.After(self.settings.ReadyProbeInterval):
		}
	}
}

// A context bounded by StoreTimeout on the engine's clock, and the call that ends it.
func (self *MxEdgeService) storeContext() (context.Context, func()) {
	ctx, cancel := context.WithCancel(self.ctx)
	stop := self.clock.AfterFunc(self.settings.StoreTimeout, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// Closes what is open and waits for every session's goroutine.
func (self *MxEdgeService) release() {
	var listeners []net.Listener
	var connections []net.Conn
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.releasing = true
		for listener := range self.liveListeners {
			listeners = append(listeners, listener)
		}
		for conn := range self.liveConnections {
			connections = append(connections, conn)
		}
	}()
	for _, listener := range listeners {
		listener.Close()
	}
	for _, conn := range connections {
		conn.Close()
	}
	self.sessionGroup.Wait()
}

// See sidecar.Engine. A closed gate stays ready, as §19.11 has it.
func (self *MxEdgeService) Ready() bool {
	if !self.depsComplete || !self.storesReachable.Value() {
		return false
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return !self.draining && !self.releasing
}

// See sidecar.Engine. A session accepted from here on gets 421. Returns once every session has ended
// or DrainTimeout has passed.
func (self *MxEdgeService) Drain() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.draining = true
	}()
	timedOut := self.clock.After(self.settings.DrainTimeout)
	for {
		count, update := self.sessionCount.Get()
		if count == 0 {
			return
		}
		select {
		case <-update:
		case <-timedOut:
			return
		case <-self.ctx.Done():
			return
		}
	}
}

// See sidecar.Engine.
func (self *MxEdgeService) Close() {
	self.cancel()
	<-self.released
}

// See sidecar.StreamEngine.
func (self *MxEdgeService) Serve(listener net.Listener) error {
	defer listener.Close()
	listening := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.releasing {
			self.liveListeners[listener] = true
		}
		return !self.releasing
	}()
	if !listening {
		return nil
	}
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.liveListeners, listener)
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if self.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// as net/http's Serve does: descriptors run out and peers reset mid-accept, and neither
			// ends a listener
			var netError net.Error
			if !errors.As(err, &netError) || !netError.Temporary() {
				return err
			}
			self.metrics.acceptFailures.Add(1)
			self.log.Info("[mxedge]accept failed, retrying")
			select {
			case <-self.clock.After(self.settings.AcceptRetryDelay):
				continue
			case <-self.ctx.Done():
				return nil
			}
		}
		accepted := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.releasing {
				return false
			}
			self.liveConnections[conn] = true
			self.sessionGroup.Add(1)
			self.sessionCount.Update(func(count int) int { return count + 1 })
			return true
		}()
		if !accepted {
			conn.Close()
			return nil
		}
		go self.serveConnection(conn)
	}
}

// One connection, from Accept to its close, on its own goroutine.
func (self *MxEdgeService) serveConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.liveConnections, conn)
		}()
		self.sessionCount.Update(func(count int) int { return count - 1 })
		self.sessionGroup.Done()
	}()
	// bounds everything before TLS, a refusal's write included: closing conn ends any blocked call
	stopWatchdog := self.clock.AfterFunc(self.settings.DialogTimeout, func() {
		conn.Close()
	})
	defer stopWatchdog()

	result := func() string {
		sender, ok := mxSenderAddr(conn.RemoteAddr())
		if !ok {
			return mxSessionResultNoSender
		}
		draining := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.draining
		}()
		if draining {
			conn.Write(self.replies.serviceClosing)
			return mxSessionResultDraining
		}
		hold, refusal := self.caps.Admit(sender)
		if refusal != mxCapRefusalNone {
			self.metrics.capRefusals.Add(1, string(refusal))
			conn.Write(self.replies.overCap)
			return mxSessionResultOverCap
		}
		defer self.caps.Release(hold)

		bannerRefused := self.bannerRefused != nil && self.bannerRefused(sender)
		dialog := newMxDialog(self.replies, func() bool { return self.plaintextRecent(sender) }, bannerRefused)
		session := &mxSession{conn: conn, sender: sender, hold: hold, dialog: dialog}
		result, readyForTls := self.runDialog(session)
		if !readyForTls {
			return result
		}
		stopWatchdog()
		return self.handoff(session)
	}()
	self.metrics.sessions.Add(1, result)
}

// Runs the dialog from the banner until it ends, or until the 220 is out, which is readyForTls.
func (self *MxEdgeService) runDialog(session *mxSession) (result string, readyForTls bool) {
	conn := session.conn
	if _, err := conn.Write(session.dialog.Banner()); err != nil {
		return mxSessionResultEnded, false
	}
	// one past the limit, so a read can show the dialog it was passed without reading on
	readBuffer := make([]byte, mxDialogMaxByteCount+1)
	for {
		byteCount, readErr := conn.Read(readBuffer)
		if 0 < byteCount {
			reply, step := session.dialog.Receive(readBuffer[:byteCount])
			if step == mxDialogStepTls && self.byteFollowsStartTls(conn) {
				step = mxDialogStepReset
			}
			if step == mxDialogStepReset {
				mxResetConnection(conn)
				return mxSessionResultReset, false
			}
			if step == mxDialogStepTls {
				testHookBarrier("mxedge.starttls.before", "")
			}
			if 0 < len(reply) {
				if _, err := conn.Write(reply); err != nil {
					return mxSessionResultEnded, false
				}
			}
			switch step {
			case mxDialogStepTls:
				testHookBarrier("mxedge.starttls.after", "")
				return "", true
			case mxDialogStepQuit:
				return mxSessionResultQuit, false
			case mxDialogStepClose:
				return mxSessionResultLimit, false
			}
		}
		if readErr != nil {
			return mxSessionResultEnded, false
		}
	}
}

// Whether a byte arrives behind a STARTTLS line within StartTlsQuietTimeout, or the answer cannot be
// known. The dialog has seen an empty buffer, but a byte sent right behind the line may have missed
// that read, and §15.4 resets on any byte before the 220. One read does it: a timeout is quiet, and
// anything else, a byte, an end of stream or a deadline that will not clear, fails closed.
func (self *MxEdgeService) byteFollowsStartTls(conn net.Conn) bool {
	stop := self.clock.AfterFunc(self.settings.StartTlsQuietTimeout, func() {
		// a read this cannot interrupt waits out the dialog's watchdog, which closes conn
		conn.SetReadDeadline(mxPastDeadline)
	})
	defer stop()
	var probe [1]byte
	byteCount, err := conn.Read(probe[:])
	var netError net.Error
	if 0 < byteCount || !errors.As(err, &netError) || !netError.Timeout() {
		return true
	}
	return conn.SetReadDeadline(time.Time{}) != nil
}

// Whether a plaintext transaction gets 451 rather than 530: a closed gate, a recent closed handshake
// anywhere in the fleet, or no answer from Redis.
func (self *MxEdgeService) plaintextRecent(sender netip.Addr) bool {
	recent := true
	if self.deps.GateOpen != nil && self.deps.GateOpen() {
		var answered bool
		ctx, done := self.storeContext()
		defer done()
		recent, answered = self.closedHandshakes.Recent(ctx, sender)
		switch {
		case !answered:
			self.metrics.memoryReads.Add(1, mxMemoryResultFailed)
		case recent:
			self.metrics.memoryReads.Add(1, mxMemoryResultRecent)
		default:
			self.metrics.memoryReads.Add(1, mxMemoryResultAbsent)
		}
	}
	if recent {
		self.metrics.plaintextSessions.Add(1, mxPlaintextResult451)
	} else {
		self.metrics.plaintextSessions.Add(1, mxPlaintextResult530)
	}
	return recent
}

// The handoff until a role replaces it: a session that reached TLS has nowhere to go, so it closes in
// the handshake as an unknown name does. The memory is written before the alert, so it exists before
// a sender can see the close and retry in plaintext. A hello that never comes costs ClientHelloTimeout
// and closes the same way.
func (self *MxEdgeService) closeHandshake(session *mxSession) string {
	conn := session.conn
	stopHelloTimer := self.clock.AfterFunc(self.settings.ClientHelloTimeout, func() {
		conn.Close()
	})
	defer stopHelloTimer()

	alert := MxTlsAlertUnrecognizedName
	if self.deps.ReadClientHello == nil {
		alert = MxTlsAlertInternalError
	} else if _, err := self.deps.ReadClientHello(conn, self.settings.ClientHelloByteCount); err != nil {
		alert = MxTlsAlertDecodeError
	}
	// a failure is only counted: see Record
	func() {
		ctx, done := self.storeContext()
		defer done()
		if err := self.closedHandshakes.Record(ctx, session.sender); err != nil {
			self.metrics.memoryWrites.Add(1, mxMemoryResultFailed)
			return
		}
		self.metrics.memoryWrites.Add(1, mxMemoryResultWritten)
	}()
	if self.deps.WriteTlsAlert != nil {
		self.deps.WriteTlsAlert(conn, alert)
	}
	return mxSessionResultClosedHandshake
}

// The sender behind addr, unmapped, with no zone. The host's listeners have already taken any PROXY
// header off, so this is the sender and not the lb (§15.4).
func mxSenderAddr(addr net.Addr) (netip.Addr, bool) {
	if addr == nil {
		return netip.Addr{}, false
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		sender, ok := netip.AddrFromSlice(tcpAddr.IP)
		return sender.Unmap(), ok
	}
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return addrPort.Addr().Unmap().WithZone(""), true
}

// Ends conn with a reset where it can, so no bytes behind a STARTTLS are acknowledged by an orderly
// close (§15.4). A wrapper gets through by SetLinger or NetConn. Anything else closes plainly, and
// either way this session reads nothing more.
func mxResetConnection(conn net.Conn) {
	for inner := conn; inner != nil; {
		if linger, ok := inner.(interface{ SetLinger(seconds int) error }); ok {
			linger.SetLinger(0)
			break
		}
		wrapper, ok := inner.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		inner = wrapper.NetConn()
	}
	conn.Close()
}
