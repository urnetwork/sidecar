// The dnsedge role (§12.6, D-DNS-3, R-DNS-8): UDP and TCP 53 answered from memory, signed online, on
// the port warp allocates through WARP_PORTS, with no proxy in front, so RRL sees resolvers' own
// addresses. It holds no DnsStore, no Redis and no Postgres handle at all (I-12): with the core down it
// keeps serving and signing from the view it holds, and only writes and ACME wait. FeedLoop publishes
// each view with the keys SelfCheck passed for it, and Prober the healthy set, each through an atomic
// pointer, so the answer path takes no lock but RRL's and the signature cache's.
//
// A root with no published view is not ready and answers nothing: a fresh edge serves no query until
// a view and key set have passed the self-check, rather than answer from nothing. A name in no root
// served here is REFUSED.
//
// It logs no query, no resolver address and no name, and no error text, since a net.OpError prints
// the addresses it failed on; its metrics carry only an rcode, an RRL class or a fixed reason (I-13,
// §2.8 dns-2).
//
// Every wait is on the host's Clock, never a socket deadline read off the wall clock: the TCP idle
// timer sets a deadline long past when it fires, which cuts a blocked read or write short.

package dnsservice

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
)

var _ sidecar.StreamEngine = (*DnsEdge)(nil)

// A time long past: set as a deadline, it cuts a blocked read or write short without reading a clock.
var dnsPastDeadline = time.Unix(1, 0)

// RFC 1035 §4.2.2: a TCP message's two-octet length prefix.
const dnsTcpLengthByteCount = 2

// RFC 1035 §4.1.1: the header every message opens with, and the bits of its third octet.
const (
	dnsHeaderByteCount    = 12
	dnsHeaderFlagResponse = 0x80
	dnsHeaderOpcodeShift  = 3
	dnsHeaderOpcodeMask   = 0x0f
)

// What the edge drops without an answer, the values of the dropped metric's reason label.
const (
	dnsDroppedMalformed = "malformed"
	dnsDroppedNotReady  = "not_ready"
)

// Why a TCP connection is closed at accept, the values of the tcp_refused metric's reason label.
const (
	dnsTcpRefusedSource   = "source"
	dnsTcpRefusedTotal    = "total"
	dnsTcpRefusedDraining = "draining"
)

// What an edge takes beyond its host and settings.
type DnsEdgeDeps struct {
	// Lifecycle only: nothing here logs a query, a name or an address. nil discards.
	Log sidecar.Logger
}

// One root's view and the keys SelfCheck passed for it, published together.
type dnsServing struct {
	view *ZoneView
	keys *DnsSigningKeys
}

// The edge. Safe for concurrent use; the host calls Serve and ServePacket once for each listener,
// each on its own goroutine.
type DnsEdge struct {
	ctx      context.Context
	cancel   context.CancelFunc
	settings *DnsSettings
	clock    sidecar.Clock
	log      sidecar.Logger
	metrics  *dnsMetrics
	signer   *Signer
	rrl      *dnsRrl
	// By root, fixed at construction, so a query finds its root with no lock.
	servings      map[string]*atomic.Pointer[dnsServing]
	servedSerials map[string]*sidecar.MonitorValue[uint64]
	healthy       atomic.Pointer[HealthySet]
	// TCP connections being served, for Drain.
	tcpCount *sidecar.MonitorValue[int]
	tcpGroup sync.WaitGroup

	stateLock      sync.Mutex
	draining       bool
	closed         bool
	listeners      map[net.Listener]bool
	packetConns    map[net.PacketConn]bool
	tcpConnections map[net.Conn]bool
	tcpSources     map[netip.Addr]int
}

// An edge for settings' roots, not ready until FeedLoop publishes a checked view for each. host needs
// Metrics; its Clock is the one every wait reads. It runs until ctx ends or Close.
func NewDnsEdge(ctx context.Context, host *sidecar.ServiceHost, settings *DnsSettings, deps *DnsEdgeDeps) (*DnsEdge, error) {
	if host == nil || host.Metrics == nil {
		return nil, errors.New("dnsedge needs a host with Metrics")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if deps == nil {
		deps = &DnsEdgeDeps{}
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	clock := host.ClockOrReal()
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &DnsEdge{
		ctx:            cancelCtx,
		cancel:         cancel,
		settings:       settings,
		clock:          clock,
		log:            log,
		metrics:        newDnsMetrics(host.Metrics),
		signer:         NewSigner(settings, clock, host.Metrics),
		rrl:            newDnsRrl(settings),
		servings:       map[string]*atomic.Pointer[dnsServing]{},
		servedSerials:  map[string]*sidecar.MonitorValue[uint64]{},
		tcpCount:       sidecar.NewMonitorValue(0),
		listeners:      map[net.Listener]bool{},
		packetConns:    map[net.PacketConn]bool{},
		tcpConnections: map[net.Conn]bool{},
		tcpSources:     map[netip.Addr]int{},
	}
	for _, root := range settings.Roots {
		self.servings[root] = &atomic.Pointer[dnsServing]{}
		self.servedSerials[root] = sidecar.NewMonitorValue[uint64](0)
	}
	context.AfterFunc(cancelCtx, self.closeAll)
	return self, nil
}

// Whether every root has a checked view to answer from.
func (self *DnsEdge) Ready() bool {
	for _, serving := range self.servings {
		if serving.Load() == nil {
			return false
		}
	}
	return true
}

// The serial root is served at, zero before any view, and a channel that closes when it changes, taken
// together, so a test or a harness waits for a serial with no sleep.
func (self *DnsEdge) ServedSerial(root string) (serial uint64, changed chan struct{}) {
	servedSerial, ok := self.servedSerials[root]
	if !ok {
		closed := make(chan struct{})
		close(closed)
		return 0, closed
	}
	return servedSerial.Get()
}

// The healthy set edge and router rows answer from, from the next query on. Prober calls this.
func (self *DnsEdge) SetHealthySet(healthy *HealthySet) {
	self.healthy.Store(healthy)
}

// Serves view under keys for its root, whole, from the next query on. keys must be what SelfCheck
// passed for view; FeedLoop is the one caller. A root this edge does not serve is ignored.
func (self *DnsEdge) publish(view *ZoneView, keys *DnsSigningKeys) {
	serving, ok := self.servings[view.root]
	if !ok {
		return
	}
	testHookBarrier("dnsservice.edge_publish.before", view.root)
	serving.Store(&dnsServing{view: view, keys: keys})
	testHookBarrier("dnsservice.edge_publish", view.root)
	self.servedSerials[view.root].Set(view.serial)
	withheldCount := 0
	for _, other := range self.servings {
		if current := other.Load(); current != nil {
			withheldCount += current.view.WithheldCount()
		}
	}
	self.metrics.withheldRrsets.Set(float64(withheldCount))
	testHookBarrier("dnsservice.edge_publish.after", view.root)
}

// What root's queries are answered from, and whether the question names a root served here at all.
func (self *DnsEdge) servingFor(request *dns.Msg) (serving *dnsServing, known bool) {
	if len(request.Question) != 1 {
		return nil, false
	}
	name := dns.CanonicalName(request.Question[0].Name)
	for root, rootServing := range self.servings {
		if dns.IsSubDomain(root, name) {
			return rootServing.Load(), true
		}
	}
	return nil, false
}

// The RRL class of an unsigned answer: an error's rcode, a denial (a name that does not exist or has no
// data of the type), or an answer, a truncated one included.
func dnsRrlClass(reply *dns.Msg) string {
	switch {
	case reply.Rcode != dns.RcodeSuccess && reply.Rcode != dns.RcodeNameError:
		return DnsRrlClassError
	case reply.Rcode == dns.RcodeNameError:
		return DnsRrlClassDenial
	case len(reply.Answer) == 0 && !reply.Truncated:
		return DnsRrlClassDenial
	}
	return DnsRrlClassAnswer
}

// FORMERR for a packet that does not parse but opens with a query's header, with its id and opcode
// and nothing else. nil for anything else, which gets no answer.
func dnsMalformedReply(packet []byte) *dns.Msg {
	if len(packet) < dnsHeaderByteCount || packet[2]&dnsHeaderFlagResponse != 0 {
		return nil
	}
	reply := &dns.Msg{}
	reply.Id = binary.BigEndian.Uint16(packet[0:2])
	reply.Response = true
	reply.Opcode = int(packet[2]>>dnsHeaderOpcodeShift) & dnsHeaderOpcodeMask
	reply.Rcode = dns.RcodeFormatError
	return reply
}

// The answer to one packet from source, packed, or nil for none. Over UDP RRL decides before anything
// is signed, so a flood it drops costs no signature.
func (self *DnsEdge) answer(packet []byte, source netip.Addr, tcp bool) []byte {
	now := self.clock.Now()
	request := &dns.Msg{}
	var reply *dns.Msg
	if err := request.Unpack(packet); err != nil {
		reply = dnsMalformedReply(packet)
		if reply == nil {
			self.metrics.dropped.Add(1, dnsDroppedMalformed)
			return nil
		}
	} else {
		serving, known := self.servingFor(request)
		if known && serving == nil {
			self.metrics.dropped.Add(1, dnsDroppedNotReady)
			return nil
		}
		var view *ZoneView
		var keys *DnsSigningKeys
		if serving != nil {
			view, keys = serving.view, serving.keys
		}
		healthy := self.healthy.Load()
		query := &DnsQuery{Message: request, Tcp: tcp}
		reply = Answer(query, view, healthy)
		if reply == nil {
			return nil
		}
		if !tcp {
			class := dnsRrlClass(reply)
			switch action := self.rrl.decide(source, class, now); action {
			case dnsRrlDrop:
				self.metrics.rrlLimited.Add(1, class, action.label())
				return nil
			case dnsRrlSlip:
				self.metrics.rrlLimited.Add(1, class, action.label())
				reply.Answer = nil
				reply.Ns = nil
				reply.Truncated = true
				return self.pack(reply)
			}
		}
		reply = self.signer.signReply(query, reply, view, keys, healthy, now)
	}
	return self.pack(reply)
}

// reply on the wire, counted by rcode. A reply that does not pack goes as SERVFAIL with nothing in it.
func (self *DnsEdge) pack(reply *dns.Msg) []byte {
	packed, err := reply.Pack()
	if err != nil {
		reply.Rcode = dns.RcodeServerFailure
		reply.Answer = nil
		reply.Ns = nil
		packed, err = reply.Pack()
		if err != nil {
			return nil
		}
	}
	self.metrics.answers.Add(1, dnsRcodeLabel(reply.Rcode))
	return packed
}

// A peer's address, unmapped, from what a socket reports. The zero value when it reports none.
func dnsPeerAddr(addr net.Addr) netip.Addr {
	switch typed := addr.(type) {
	case *net.UDPAddr:
		return typed.AddrPort().Addr().Unmap()
	case *net.TCPAddr:
		return typed.AddrPort().Addr().Unmap()
	}
	if addr == nil {
		return netip.Addr{}
	}
	if addrPort, err := netip.ParseAddrPort(addr.String()); err == nil {
		return addrPort.Addr().Unmap()
	}
	return netip.Addr{}
}

// Answers UDP on conn until it closes or the edge closes, with edge.udp_readers goroutines each
// answering what it reads. Returns nil when the edge closed, else why conn stopped.
func (self *DnsEdge) ServePacket(conn net.PacketConn) error {
	if !func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.packetConns[conn] = true
		return true
	}() {
		return nil
	}
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.packetConns, conn)
	}()
	readerCount := self.settings.Edge.UdpReaderCount
	if readerCount <= 0 {
		readerCount = runtime.GOMAXPROCS(0)
	}
	errs := make(chan error, readerCount)
	for range readerCount {
		go func() {
			errs <- self.readPackets(conn)
		}()
	}
	var first error
	for range readerCount {
		if err := <-errs; first == nil {
			first = err
		}
	}
	if self.ctx.Err() != nil {
		return nil
	}
	return first
}

// One reader of conn. A fault other than the socket closing waits edge.retry_ms and reads again, so a
// persistent one cannot spin.
func (self *DnsEdge) readPackets(conn net.PacketConn) error {
	buffer := make([]byte, dns.MaxMsgSize)
	for {
		byteCount, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || self.ctx.Err() != nil {
				return err
			}
			select {
			case <-self.ctx.Done():
				return nil
			case <-self.clock.After(time.Duration(self.settings.Edge.RetryMilliseconds) * time.Millisecond):
			}
			continue
		}
		if reply := self.answer(buffer[:byteCount], dnsPeerAddr(addr), false); reply != nil {
			// a failed write names the address, so it is neither logged nor retried
			conn.WriteTo(reply, addr)
		}
	}
}

// Answers TCP on listener until it closes or the edge closes, a goroutine to each connection it admits:
// at most tcp.connections_per_source from one address and tcp.connections in all, and none while
// draining. Returns nil when the edge closed, else why listener stopped.
func (self *DnsEdge) Serve(listener net.Listener) error {
	if !func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.listeners[listener] = true
		return true
	}() {
		return nil
	}
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.listeners, listener)
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if self.ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			select {
			case <-self.ctx.Done():
				return nil
			case <-self.clock.After(time.Duration(self.settings.Edge.RetryMilliseconds) * time.Millisecond):
			}
			continue
		}
		source := dnsPeerAddr(conn.RemoteAddr())
		if reason := self.admit(conn, source); reason != "" {
			self.metrics.tcpRefused.Add(1, reason)
			conn.Close()
			continue
		}
		go self.serveTcp(conn, source)
	}
}

// Takes conn on, or says why not. Counted inside the lock, so the caps hold under any interleaving.
func (self *DnsEdge) admit(conn net.Conn, source netip.Addr) string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch {
	case self.closed || self.draining:
		return dnsTcpRefusedDraining
	case self.settings.Tcp.ConnectionCount <= len(self.tcpConnections):
		return dnsTcpRefusedTotal
	case self.settings.Tcp.ConnectionsPerSource <= self.tcpSources[source]:
		return dnsTcpRefusedSource
	}
	self.tcpConnections[conn] = true
	self.tcpSources[source] += 1
	self.tcpGroup.Add(1)
	self.tcpCount.Set(len(self.tcpConnections))
	self.metrics.tcpConnections.Set(float64(len(self.tcpConnections)))
	return ""
}

// Lets conn go and closes it.
func (self *DnsEdge) release(conn net.Conn, source netip.Addr) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.tcpConnections, conn)
		if self.tcpSources[source] <= 1 {
			delete(self.tcpSources, source)
		} else {
			self.tcpSources[source] -= 1
		}
		self.tcpCount.Set(len(self.tcpConnections))
		self.metrics.tcpConnections.Set(float64(len(self.tcpConnections)))
	}()
	conn.Close()
}

// Whether the edge has stopped taking work.
func (self *DnsEdge) isDraining() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.draining || self.closed
}

// The TCP idle bound as a timer on the clock: armed for each query, it cuts the connection's reads and
// writes short tcp.idle_timeout_s after, unless disarmed first. A late firing of a disarmed timer
// does nothing, since it carries the generation it was armed in.
type dnsIdleCut struct {
	conn  net.Conn
	clock sidecar.Clock

	stateLock  sync.Mutex
	generation uint64
	stop       func() bool
}

func (self *dnsIdleCut) arm(timeout time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.generation += 1
	generation := self.generation
	self.stop = self.clock.AfterFunc(timeout, func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.generation == generation {
			self.conn.SetDeadline(dnsPastDeadline)
		}
	})
}

func (self *dnsIdleCut) disarm() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.generation += 1
	if self.stop != nil {
		self.stop()
		self.stop = nil
	}
}

// Answers one TCP connection, query by query, in order, until the peer closes, idles past
// tcp.idle_timeout_s, sends what does not parse, or the edge drains or closes.
func (self *DnsEdge) serveTcp(conn net.Conn, source netip.Addr) {
	defer self.tcpGroup.Done()
	defer self.release(conn, source)
	idleCut := &dnsIdleCut{conn: conn, clock: self.clock}
	defer idleCut.disarm()
	idle := dnsSeconds(self.settings.Tcp.IdleTimeoutSeconds)
	lengthBytes := make([]byte, dnsTcpLengthByteCount)
	for {
		served := func() bool {
			idleCut.arm(idle)
			defer idleCut.disarm()
			if _, err := io.ReadFull(conn, lengthBytes); err != nil {
				return false
			}
			packet := make([]byte, binary.BigEndian.Uint16(lengthBytes))
			if _, err := io.ReadFull(conn, packet); err != nil {
				return false
			}
			reply := self.answer(packet, source, true)
			if reply == nil {
				return false
			}
			out := make([]byte, dnsTcpLengthByteCount+len(reply))
			binary.BigEndian.PutUint16(out, uint16(len(reply)))
			copy(out[dnsTcpLengthByteCount:], reply)
			_, err := conn.Write(out)
			return err == nil
		}()
		if !served || self.isDraining() {
			return
		}
	}
}

// Takes no new TCP connection and closes each connection served once its current query is answered:
// a connection waiting for a query has its read cut now, and one answering closes after its answer.
// Returns when none is left or edge.drain_s has passed. UDP is answered until Close, since a datagram
// holds nothing in flight.
func (self *DnsEdge) Drain() {
	conns := []net.Conn{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.draining = true
		for conn := range self.tcpConnections {
			conns = append(conns, conn)
		}
	}()
	for _, conn := range conns {
		conn.SetReadDeadline(dnsPastDeadline)
	}
	deadline := self.clock.After(dnsSeconds(self.settings.Edge.DrainSeconds))
	for {
		count, changed := self.tcpCount.Get()
		if count == 0 {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			return
		case <-self.ctx.Done():
			return
		}
	}
}

// Ends everything at once: listeners, sockets and connections close, and this returns once every
// connection's goroutine has. Safe more than once.
func (self *DnsEdge) Close() {
	self.cancel()
	self.closeAll()
	self.tcpGroup.Wait()
}

// Closes everything the edge holds. Runs when the context ends, and from Close.
func (self *DnsEdge) closeAll() {
	closers := []io.Closer{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		for listener := range self.listeners {
			closers = append(closers, listener)
		}
		for conn := range self.packetConns {
			closers = append(closers, conn)
		}
		for conn := range self.tcpConnections {
			closers = append(closers, conn)
		}
	}()
	for _, closer := range closers {
		closer.Close()
	}
}
