// What FI-11, path integrity, reads (TEST-M4-01; §22.8's FI-11, D-TEST-10, I-5, D-BRIDGE-21): "no application byte
// reaches a backend before its audience check, whatever the SNI or ALPN, nor a target after its flow's revocation; a
// proof accepts only what the MX's own state machine accepts". fault/fi11.go is the check; this is what it reads.
//
// RecordingBackend is the backend: a listener, or a wrapper over a world's own listener or connection, whose reader
// takes every byte off the socket as soon as it arrives and logs it, before anything parses it, with the audience
// state then, so a TLS record counts as any byte does and a byte that arrived before the check is not judged by a
// state its server read it under later. FI-11's oracle stamps each arrival with the step it arrived in at its next
// check. A world says where its audience check stands with SetAudience, or gives the backend a function that reads
// its own state (a hook's decisions, a listener's admissions); a revocation swap is SetAudience(RecordingBackendRevoked).
// A positive twin's backend says it must be reached (MustReach), so a check on a path nothing reaches fails rather
// than passing for nothing. BRIDGE-M4-22 (FS-38, FS-56), TLS-M5-25 (FS-34, FS-35), MAIL (FS-33) and DNS-M6-05
// (FS-32) share it.
//
// MxProofLedger is the proof clause's half: every proof an outbound edge's verifier accepted, as the envelope it
// proved, beside each MX's own record of what its state machine took (ScriptedMx's and RecordMx's Transactions), so
// a proof of a message the MX refused, or of one it took once proved twice, is a mismatch FI-11 names.
//
// A world makes each on its Net, which hands them to FI-11's oracle and closes the backends when it closes. Safe for
// concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"weak"
)

// Where a backend's audience check stands for a flow.
type RecordingBackendAudience string

const (
	// No audience check has passed: no byte may arrive.
	RecordingBackendUnchecked RecordingBackendAudience = "unchecked"
	// The check passed: bytes may arrive.
	RecordingBackendAdmitted RecordingBackendAudience = "admitted"
	// The flow was revoked: no byte may arrive again.
	RecordingBackendRevoked RecordingBackendAudience = "revoked"
)

type RecordingBackendSettings struct {
	// Names the backend in a finding: "the private audience's backend".
	Name string
	// Where NewRecordingBackend listens: a loopback port the kernel picks.
	ListenAddress string
	// What serves each connection once its bytes are logged: nil takes every byte and answers nothing.
	Serve func(conn net.Conn)
	// Where the audience state comes from at each arrival, when set, in place of SetAudience's: a world whose own
	// state says whether its check passed. It runs on the backend's reader, so it must not block.
	Audience func() (RecordingBackendAudience, string)
	// A positive twin's backend: FI-11 fails at a run's end unless a byte arrived here admitted (§22.8's twins).
	MustReach bool
	// The most one read takes off the socket.
	ReadByteCount int
	// The most of an arrival kept for a finding; its count is kept whole.
	SampleByteCount int
	// The most a connection holds for Serve before the reader stops taking bytes off the socket: the bound on what
	// a connection Serve does not read costs.
	BufferByteCount int
}

func DefaultRecordingBackendSettings() *RecordingBackendSettings {
	return &RecordingBackendSettings{
		Name:            "backend",
		ListenAddress:   "127.0.0.1:0",
		ReadByteCount:   32 * 1024,
		SampleByteCount: 64,
		BufferByteCount: 4 * 1024 * 1024,
	}
}

// Bytes one read took off a backend's socket.
type RecordingBackendArrival struct {
	// The backend's connection they came on, from 1.
	Connection int
	ByteCount  int
	// Their first SampleByteCount bytes.
	Sample []byte
	// The audience state when they arrived, and the reason the world gave for it.
	Audience       RecordingBackendAudience
	AudienceReason string
	// The step they arrived in, as FI-11's oracle stamps it at its next check; -1 until then.
	Step int
	// Stamped at a run's last check, after its last step.
	Final bool
}

func (self *RecordingBackendArrival) String() string {
	when := fmt.Sprintf("in step %d", self.Step)
	if self.Final {
		when = "at the end"
	} else if self.Step < 0 {
		when = "in no step yet"
	}
	return fmt.Sprintf("%d bytes on connection %d %s, %s (%s), starting %q", self.ByteCount, self.Connection, when, self.Audience, self.AudienceReason, self.Sample)
}

type RecordingBackend struct {
	settings *RecordingBackendSettings
	// nil for a backend that only wraps a world's listeners and connections
	listener net.Listener

	stateLock      sync.Mutex
	audience       RecordingBackendAudience
	audienceReason string
	arrivals       []*RecordingBackendArrival
	connections    int
	conns          map[*recordingConn]bool
	listeners      []net.Listener
	closed         bool

	waitGroup sync.WaitGroup
}

// A backend listening at settings' address, made on owner, which hands it to FI-11's oracle and closes it when it
// closes; owner nil makes one no oracle reads. settings nil takes the defaults.
func NewRecordingBackend(owner *Net, settings *RecordingBackendSettings) (*RecordingBackend, error) {
	self := newRecordingBackend(owner, settings)
	listener, err := net.Listen("tcp", self.settings.ListenAddress)
	if err != nil {
		self.Close()
		return nil, err
	}
	self.listener = listener
	self.serveListener(listener)
	return self, nil
}

// A backend that listens nowhere: a world hands it its own listeners (WrapListener) and connections (Wrap), as an
// upstream a NAT dials or an in-process pipe.
func NewRecordingBackendOver(owner *Net, settings *RecordingBackendSettings) *RecordingBackend {
	return newRecordingBackend(owner, settings)
}

func newRecordingBackend(owner *Net, settings *RecordingBackendSettings) *RecordingBackend {
	if settings == nil {
		settings = DefaultRecordingBackendSettings()
	}
	self := &RecordingBackend{
		settings: settings,
		audience: RecordingBackendUnchecked,
		conns:    map[*recordingConn]bool{},
	}
	if owner != nil {
		recordingWorldOf(owner, true).addBackend(self)
		context.AfterFunc(owner.Context(), self.Close)
	}
	return self
}

// The backend's name in a finding.
func (self *RecordingBackend) Name() string {
	return self.settings.Name
}

// Whether FI-11 fails a run's end on this backend unless a byte reached it admitted.
func (self *RecordingBackend) MustReach() bool {
	return self.settings.MustReach
}

// Where NewRecordingBackend's listener is, or nil for one that only wraps.
func (self *RecordingBackend) Addr() net.Addr {
	if self.listener == nil {
		return nil
	}
	return self.listener.Addr()
}

// Sets where the audience check stands for what arrives from now on, with the reason a finding repeats: Admitted
// once the check passes, Revoked when the flow's revocation swaps in. A backend whose settings name an Audience
// function reads that instead.
func (self *RecordingBackend) SetAudience(audience RecordingBackendAudience, reason string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.audience = audience
	self.audienceReason = reason
}

// Every arrival so far, in order.
func (self *RecordingBackend) Arrivals() []*RecordingBackendArrival {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	arrivals := make([]*RecordingBackendArrival, 0, len(self.arrivals))
	for _, arrival := range self.arrivals {
		kept := *arrival
		kept.Sample = bytes.Clone(arrival.Sample)
		arrivals = append(arrivals, &kept)
	}
	return arrivals
}

// Stamps every arrival no check has seen with step, or as the run's end when final, and returns those, in order: what
// FI-11's oracle judges at each check.
func (self *RecordingBackend) Stamp(step int, final bool) []*RecordingBackendArrival {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	stamped := []*RecordingBackendArrival{}
	for _, arrival := range self.arrivals {
		if arrival.Step < 0 && !arrival.Final {
			arrival.Step = step
			arrival.Final = final
			kept := *arrival
			kept.Sample = bytes.Clone(arrival.Sample)
			stamped = append(stamped, &kept)
		}
	}
	return stamped
}

// Whether any byte arrived while the audience check stood passed.
func (self *RecordingBackend) ReachedAdmitted() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.ContainsFunc(self.arrivals, func(arrival *RecordingBackendArrival) bool {
		return arrival.Audience == RecordingBackendAdmitted
	})
}

// How many connections arrived, whether or not they carried a byte.
func (self *RecordingBackend) ConnectionCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.connections
}

// A listener whose every accepted connection is logged as this backend's, for a world that owns the listener its
// backend serves on. Closing the backend closes it.
func (self *RecordingBackend) WrapListener(listener net.Listener) net.Listener {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.listeners = append(self.listeners, listener)
	return &recordingListener{Listener: listener, backend: self}
}

// conn, logged as this backend's from now on: what its peer sends is taken off it and logged at once, and the
// returned connection reads it. Closing the backend closes it. nil, with conn closed, once the backend is closed.
func (self *RecordingBackend) Wrap(conn net.Conn) net.Conn {
	if wrapped := self.adopt(conn, true); wrapped != nil {
		return wrapped
	}
	return nil
}

// Closes the listener and every connection and waits for the readers and servers to end. Idempotent.
func (self *RecordingBackend) Close() {
	var listeners []net.Listener
	var conns []*recordingConn
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return
		}
		self.closed = true
		listeners = slices.Clone(self.listeners)
		if self.listener != nil {
			listeners = append(listeners, self.listener)
		}
		for conn := range self.conns {
			conns = append(conns, conn)
		}
	}()
	for _, listener := range listeners {
		listener.Close()
	}
	for _, conn := range conns {
		conn.Close()
	}
	self.waitGroup.Wait()
}

func (self *RecordingBackend) serveListener(listener net.Listener) {
	self.waitGroup.Add(1)
	go func() {
		defer self.waitGroup.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wrapped := self.adopt(conn, self.settings.Serve != nil)
			if wrapped == nil || self.settings.Serve == nil {
				continue
			}
			self.waitGroup.Add(1)
			go func() {
				defer self.waitGroup.Done()
				defer wrapped.Close()
				self.settings.Serve(wrapped)
			}()
		}
	}()
}

// Starts logging conn: its reader takes what arrives off the socket and logs it, keeping it for a Read when serve.
// nil when the backend is closed, conn closed with it.
func (self *RecordingBackend) adopt(conn net.Conn, serve bool) *recordingConn {
	wrapped := &recordingConn{Conn: conn, backend: self, serve: serve}
	wrapped.monitor = sync.NewCond(&wrapped.stateLock)
	accepted := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.connections += 1
		wrapped.index = self.connections
		self.conns[wrapped] = true
		return true
	}()
	if !accepted {
		conn.Close()
		return nil
	}
	self.waitGroup.Add(1)
	go func() {
		defer self.waitGroup.Done()
		wrapped.pump()
	}()
	return wrapped
}

// Logs data as an arrival on connection index, under the audience state now.
func (self *RecordingBackend) record(index int, data []byte) {
	var audience RecordingBackendAudience
	var reason string
	if self.settings.Audience != nil {
		audience, reason = self.settings.Audience()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.settings.Audience == nil {
		audience, reason = self.audience, self.audienceReason
	}
	self.arrivals = append(self.arrivals, &RecordingBackendArrival{
		Connection:     index,
		ByteCount:      len(data),
		Sample:         bytes.Clone(data[:min(len(data), self.settings.SampleByteCount)]),
		Audience:       audience,
		AudienceReason: reason,
		Step:           -1,
	})
}

func (self *RecordingBackend) forget(conn *recordingConn) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.conns, conn)
}

type recordingListener struct {
	net.Listener
	backend *RecordingBackend
}

func (self *recordingListener) Accept() (net.Conn, error) {
	for {
		conn, err := self.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if wrapped := self.backend.adopt(conn, true); wrapped != nil {
			return wrapped, nil
		}
	}
}

// One logged connection: pump takes what arrives off the socket at once and logs it, and Read serves it from what
// pump kept, so a server that reads late reads what was logged early. Writes go straight to the socket.
type recordingConn struct {
	net.Conn
	backend *RecordingBackend
	index   int
	serve   bool

	stateLock sync.Mutex
	monitor   *sync.Cond
	pending   []byte
	readErr   error
	closed    bool
	deadline  time.Time
	// the timer that wakes a Read at its deadline
	deadlineStop func() bool
}

func (self *recordingConn) pump() {
	buffer := make([]byte, self.backend.settings.ReadByteCount)
	for {
		n, err := self.Conn.Read(buffer)
		if 0 < n {
			self.backend.record(self.index, buffer[:n])
			if self.serve && !self.keep(buffer[:n]) {
				return
			}
		}
		if err != nil {
			self.stateLock.Lock()
			self.readErr = err
			self.monitor.Broadcast()
			self.stateLock.Unlock()
			return
		}
	}
}

// Keeps data for Read, waiting while the connection holds BufferByteCount; false once it is closed.
func (self *recordingConn) keep(data []byte) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for !self.closed && self.backend.settings.BufferByteCount <= len(self.pending) {
		self.monitor.Wait()
	}
	if self.closed {
		return false
	}
	self.pending = append(self.pending, data...)
	self.monitor.Broadcast()
	return true
}

func (self *recordingConn) Read(buffer []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for len(self.pending) == 0 {
		switch {
		case self.closed:
			return 0, net.ErrClosed
		case self.readErr != nil:
			return 0, self.readErr
		case !self.deadline.IsZero() && !time.Now().Before(self.deadline):
			return 0, os.ErrDeadlineExceeded
		}
		self.monitor.Wait()
	}
	n := copy(buffer, self.pending)
	self.pending = self.pending[n:]
	self.monitor.Broadcast()
	return n, nil
}

func (self *recordingConn) SetReadDeadline(deadline time.Time) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.deadline = deadline
	if self.deadlineStop != nil {
		self.deadlineStop()
		self.deadlineStop = nil
	}
	if !deadline.IsZero() {
		timer := time.AfterFunc(time.Until(deadline), func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.monitor.Broadcast()
		})
		self.deadlineStop = timer.Stop
	}
	self.monitor.Broadcast()
	return nil
}

func (self *recordingConn) SetDeadline(deadline time.Time) error {
	self.SetReadDeadline(deadline)
	return self.Conn.SetWriteDeadline(deadline)
}

func (self *recordingConn) Close() error {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		if self.deadlineStop != nil {
			self.deadlineStop()
			self.deadlineStop = nil
		}
		self.monitor.Broadcast()
	}()
	err := self.Conn.Close()
	self.backend.forget(self)
	return err
}

// What an MX took, as ScriptedMx and RecordMx record it.
type MxTransactionSource interface {
	Transactions() []*MxTransaction
}

// One proof an outbound edge's verifier accepted, as the envelope it proved (§14.5).
type MxProvedEnvelope struct {
	// The MX the proof names, by host.
	Mx string
	// MAIL's path and RCPT's paths as MxTransaction writes them, angle brackets kept.
	Sender     string
	Recipients []string
	// SHA-256 of the message the proof binds, when it binds one.
	MessageSha256   [sha256.Size]byte
	BindsTheMessage bool
}

func (self *MxProvedEnvelope) String() string {
	return fmt.Sprintf("%s to %s at %s", self.Sender, strings.Join(self.Recipients, ", "), self.Mx)
}

type MxProofLedger struct {
	stateLock sync.Mutex
	mxs       map[string]MxTransactionSource
	proved    []*MxProvedEnvelope
}

// A ledger made on owner, which hands it to FI-11's oracle; owner nil makes one no oracle reads.
func NewMxProofLedger(owner *Net) *MxProofLedger {
	self := &MxProofLedger{mxs: map[string]MxTransactionSource{}}
	if owner != nil {
		recordingWorldOf(owner, true).addLedger(self)
	}
	return self
}

// Names the MX a proof names by host, whose own record says what its state machine took.
func (self *MxProofLedger) AddMx(host string, mx MxTransactionSource) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.mxs[strings.ToLower(host)] = mx
}

// Records a proof the edge's verifier accepted: what a T2 edge calls once it would forward the records.
func (self *MxProofLedger) Proved(envelope *MxProvedEnvelope) {
	kept := *envelope
	kept.Recipients = slices.Clone(envelope.Recipients)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.proved = append(self.proved, &kept)
}

// Every proof no transaction of its MX answers: each proof takes the first transaction it matches that no earlier
// proof took, the same sender, every proved recipient among the MX's accepted ones, and the same message where the
// proof binds one, so a proof of what the MX refused, or of one transaction twice, is a mismatch.
func (self *MxProofLedger) Mismatches() []error {
	var proved []*MxProvedEnvelope
	mxs := map[string]MxTransactionSource{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		proved = slices.Clone(self.proved)
		for host, mx := range self.mxs {
			mxs[host] = mx
		}
	}()
	taken := map[string][]bool{}
	transactions := map[string][]*MxTransaction{}
	mismatches := []error{}
	for _, envelope := range proved {
		host := strings.ToLower(envelope.Mx)
		mx, ok := mxs[host]
		if !ok {
			mismatches = append(mismatches, fmt.Errorf("a proof of %s names an MX the ledger does not hold", envelope))
			continue
		}
		if _, ok := transactions[host]; !ok {
			transactions[host] = mx.Transactions()
			taken[host] = make([]bool, len(transactions[host]))
		}
		matched := false
		for index, transaction := range transactions[host] {
			if taken[host][index] || transaction.Sender != envelope.Sender {
				continue
			}
			if !slices.ContainsFunc(envelope.Recipients, func(recipient string) bool { return !slices.Contains(transaction.Recipients, recipient) }) &&
				(!envelope.BindsTheMessage || sha256.Sum256(transaction.Message) == envelope.MessageSha256) {
				taken[host][index] = true
				matched = true
				break
			}
		}
		if !matched {
			mismatches = append(mismatches, fmt.Errorf("a proof accepted %s, which the MX's own state machine did not accept", envelope))
		}
	}
	return mismatches
}

// What one Net's worlds made for FI-11.
type recordingWorld struct {
	stateLock sync.Mutex
	backends  []*RecordingBackend
	ledgers   []*MxProofLedger
}

func (self *recordingWorld) addBackend(backend *RecordingBackend) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.backends = append(self.backends, backend)
}

func (self *recordingWorld) addLedger(ledger *MxProofLedger) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.ledgers = append(self.ledgers, ledger)
}

// Each Net's recording world, by a weak key, removed when the Net closes.
var recordingWorlds sync.Map

func recordingWorldOf(owner *Net, create bool) *recordingWorld {
	key := weak.Make(owner)
	if world, ok := recordingWorlds.Load(key); ok {
		return world.(*recordingWorld)
	}
	if !create {
		return nil
	}
	world, loaded := recordingWorlds.LoadOrStore(key, &recordingWorld{})
	if !loaded {
		context.AfterFunc(owner.Context(), func() { recordingWorlds.Delete(key) })
	}
	return world.(*recordingWorld)
}

// Every RecordingBackend a world made on this Net, in order: what FI-11's oracle reads.
func (self *Net) RecordingBackends() []*RecordingBackend {
	world := recordingWorldOf(self, false)
	if world == nil {
		return nil
	}
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	return slices.Clone(world.backends)
}

// Every MxProofLedger a world made on this Net, in order: what FI-11's oracle reads.
func (self *Net) MxProofLedgers() []*MxProofLedger {
	world := recordingWorldOf(self, false)
	if world == nil {
		return nil
	}
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	return slices.Clone(world.ledgers)
}

// An echo server for a backend: what arrives goes back, so a positive twin can see its bytes reached.
func RecordingBackendEcho(conn net.Conn) {
	io.Copy(conn, conn)
}
