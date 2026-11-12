// §13.5's connection path on a scripted dialer, sidecartest's fake store, quota and clock, and loopback
// TCP for the visitor: each alert of step 7's table, the route probe that touches nothing, and the
// hello arriving whole at the listener. A real timer here is only a guard that fails a hung test.

package tlsedgeservice_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

const testGuardTimeout = 30 * time.Second

// One direction of a stream: bytes written wait until they are read, and an end is either a clean
// close, which reads as EOF once the bytes are drained, or a failure, which every later call returns.
type testStreamHalf struct {
	stateLock sync.Mutex
	changed   *sync.Cond
	buffer    bytes.Buffer
	closed    bool
	err       error
}

func newTestStreamHalf() *testStreamHalf {
	half := &testStreamHalf{}
	half.changed = sync.NewCond(&half.stateLock)
	return half
}

func (self *testStreamHalf) Write(b []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return 0, self.err
	}
	if self.closed {
		return 0, net.ErrClosed
	}
	self.buffer.Write(b)
	self.changed.Broadcast()
	return len(b), nil
}

func (self *testStreamHalf) Read(b []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for {
		if self.err != nil {
			return 0, self.err
		}
		if 0 < self.buffer.Len() {
			return self.buffer.Read(b)
		}
		if self.closed {
			return 0, io.EOF
		}
		self.changed.Wait()
	}
}

func (self *testStreamHalf) closeWrite() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = true
	self.changed.Broadcast()
}

func (self *testStreamHalf) fail(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err == nil {
		self.err = err
	}
	self.changed.Broadcast()
}

// A stream between the engine and a listener a test plays. The engine holds it as a TlsEdgeStream, and
// the test reads what the engine sent, writes back, half-closes and resets from the listener's side.
type testPathStream struct {
	toListener   *testStreamHalf
	fromListener *testStreamHalf
	// TlsEdgeOpen as the engine built it for the ticket that opened
	metadata []byte
	// the code of the engine's Reset, sent once
	resetCodes chan protocol.StreamResetCode
	// closed by the engine's Close
	engineClosed chan struct{}
	closeOnce    sync.Once
	resetOnce    sync.Once
}

func newTestPathStream() *testPathStream {
	return &testPathStream{
		toListener:   newTestStreamHalf(),
		fromListener: newTestStreamHalf(),
		resetCodes:   make(chan protocol.StreamResetCode, 1),
		engineClosed: make(chan struct{}),
	}
}

var errTestStreamReset = &sidecar.SocketCodeError{Err: sidecar.ErrSocketReset}

// The engine's side.

func (self *testPathStream) Read(b []byte) (int, error)  { return self.fromListener.Read(b) }
func (self *testPathStream) Write(b []byte) (int, error) { return self.toListener.Write(b) }

func (self *testPathStream) CloseWrite() error {
	self.toListener.closeWrite()
	return nil
}

func (self *testPathStream) Close() error {
	self.closeOnce.Do(func() {
		self.toListener.closeWrite()
		self.fromListener.fail(net.ErrClosed)
		close(self.engineClosed)
	})
	return nil
}

func (self *testPathStream) Reset(code protocol.StreamResetCode) error {
	self.resetOnce.Do(func() {
		self.toListener.fail(errTestStreamReset)
		self.fromListener.fail(errTestStreamReset)
		self.resetCodes <- code
	})
	return nil
}

func (self *testPathStream) SetReadDeadline(t time.Time) error  { return nil }
func (self *testPathStream) SetWriteDeadline(t time.Time) error { return nil }

var _ tlsedgeservice.TlsEdgeStream = (*testPathStream)(nil)

// The listener's side.

// Reads exactly byteCount bytes of what the engine sent.
func (self *testPathStream) listenerRead(t *testing.T, byteCount int) []byte {
	t.Helper()
	read := make([]byte, byteCount)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(self.toListener, read)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the listener read: %v", err)
		}
	case <-time.After(testGuardTimeout):
		t.Fatal("the listener's bytes never came")
	}
	return read
}

// Waits for the engine's half-close and returns what came before it.
func (self *testPathStream) listenerReadAll(t *testing.T) []byte {
	t.Helper()
	type result struct {
		read []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		read, err := io.ReadAll(self.toListener)
		done <- result{read: read, err: err}
	}()
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("the listener read: %v", result.err)
		}
		return result.read
	case <-time.After(testGuardTimeout):
		t.Fatal("the engine never half-closed the stream")
	}
	return nil
}

func (self *testPathStream) listenerWrite(t *testing.T, b []byte) {
	t.Helper()
	if _, err := self.fromListener.Write(b); err != nil {
		t.Fatalf("the listener wrote: %v", err)
	}
}

func (self *testPathStream) listenerCloseWrite() {
	self.fromListener.closeWrite()
}

func (self *testPathStream) listenerReset() {
	self.fromListener.fail(errTestStreamReset)
	self.toListener.fail(errTestStreamReset)
}

// Waits for the engine's Reset and returns its code.
func (self *testPathStream) awaitReset(t *testing.T) protocol.StreamResetCode {
	t.Helper()
	select {
	case code := <-self.resetCodes:
		return code
	case <-time.After(testGuardTimeout):
		t.Fatal("the engine never reset the stream")
	}
	return protocol.StreamResetCode_RST_UNSPECIFIED
}

func (self *testPathStream) awaitEngineClose(t *testing.T) {
	t.Helper()
	select {
	case <-self.engineClosed:
	case <-time.After(testGuardTimeout):
		t.Fatal("the engine never closed the stream")
	}
}

// A dialer a test scripts: each Dial answers the next queued error, or else opens a stream, asking for
// its metadata once for each ticket expiry given and writing the hello into it as SocketEdgeDialer does,
// early_data and the remainder alike.
type testPathDialer struct {
	clientIds []sidecar.Id
	opened    chan *testPathStream
	dialCount atomic.Int64

	stateLock sync.Mutex
	errs      []error
	// the grant expiry of each ticket tried, the last one opening: a dead primary, then its backup
	ticketExpireTimeMillis []uint64
	requests               []*tlsedgeservice.TlsEdgeDialRequest
}

func newTestPathDialer() *testPathDialer {
	dialer := &testPathDialer{opened: make(chan *testPathStream, 64), ticketExpireTimeMillis: []uint64{0}}
	for range 4 {
		dialer.clientIds = append(dialer.clientIds, sidecar.NewId())
	}
	return dialer
}

func (self *testPathDialer) ClientIds() []sidecar.Id {
	return slices.Clone(self.clientIds)
}

func (self *testPathDialer) refuseNext(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.errs = append(self.errs, err)
}

func (self *testPathDialer) setTickets(expireTimeMillis ...uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.ticketExpireTimeMillis = expireTimeMillis
}

func (self *testPathDialer) lastRequest() *tlsedgeservice.TlsEdgeDialRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.requests[len(self.requests)-1]
}

func (self *testPathDialer) Dial(ctx context.Context, request *tlsedgeservice.TlsEdgeDialRequest) (tlsedgeservice.TlsEdgeStream, error) {
	self.dialCount.Add(1)
	err, tickets := func() (error, []uint64) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requests = append(self.requests, request)
		if 0 < len(self.errs) {
			err := self.errs[0]
			self.errs = self.errs[1:]
			return err, nil
		}
		return nil, slices.Clone(self.ticketExpireTimeMillis)
	}()
	if err != nil {
		return nil, err
	}
	stream := newTestPathStream()
	for _, expireTimeMillis := range tickets {
		metadata, err := request.Metadata(expireTimeMillis)
		if err != nil {
			return nil, err
		}
		stream.metadata = metadata
	}
	stream.toListener.Write(request.HelloBytes)
	self.opened <- stream
	return stream, nil
}

var _ tlsedgeservice.TlsEdgeDialer = (*testPathDialer)(nil)

func (self *testPathDialer) awaitOpened(t *testing.T) *testPathStream {
	t.Helper()
	select {
	case stream := <-self.opened:
		return stream
	case <-time.After(testGuardTimeout):
		t.Fatal("no stream was opened")
	}
	return nil
}

// A Quota that counts the leases asked of it.
type testCountingQuota struct {
	sidecar.Quota
	leaseCount atomic.Int64
}

func (self *testCountingQuota) Lease(ctx context.Context, networkId connect.Id, meter string) (sidecar.QuotaLease, *sidecar.QuotaRefusal, error) {
	self.leaseCount.Add(1)
	return self.Quota.Lease(ctx, networkId, meter)
}

// Community's caps as a network's own, so its limits read the same cold and loaded.
func testPathLimits() *sidecar.QuotaLimits {
	return &sidecar.QuotaLimits{Tier: "free", Limits: map[string]int64{
		"tls_endpoint_concurrent":        256,
		"tls_endpoint_new_per_s":         50,
		"tls_endpoint_mbit_per_s":        20,
		"tls_visitor_concurrent":         64,
		"tls_visitor_new_per_s":          20,
		"tls_visitor_aggregate_multiple": 4,
	}}
}

type testPathWorld struct {
	ctx       context.Context
	clock     *sidecartest.FakeClock
	host      *sidecartest.FakeHost
	quota     *testCountingQuota
	store     *sidecartest.FakeTlsEdgeStore
	dialer    *testPathDialer
	service   *tlsedgeservice.TlsEdgeService
	networkId sidecar.Id
	label     string
	address   string
	served    chan error
}

// A ready engine serving port 443 on loopback, one network with a label, a balance and the gate open to
// it.
func newTestPathWorld(t *testing.T, configure func(settings *tlsedgeservice.TlsEdgeSettings)) *testPathWorld {
	t.Helper()
	return newTestPathWorldOn(t, sidecartest.NewFakeTlsEdgeStore(nil), configure, nil)
}

// The same over a store of the test's and a host the test may change before the engine is built.
func newTestPathWorldOn(
	t *testing.T,
	store *sidecartest.FakeTlsEdgeStore,
	configure func(settings *tlsedgeservice.TlsEdgeSettings),
	configureHost func(host *sidecar.ServiceHost),
) *testPathWorld {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	networkId := sidecar.NewId()
	label, err := store.AddLabel(testServiceRoot, networkId)
	if err != nil {
		t.Fatal(err)
	}
	host.Quota.SetLimits(connect.Id(networkId), testPathLimits())
	host.Quota.SetBalance(connect.Id(networkId), 1024*1024*1024)
	host.Gates.OpenService(sidecar.ServiceGateTlsedge, connect.Id(networkId))
	quota := &testCountingQuota{Quota: host.Quota}
	serviceHost := host.ServiceHost()
	serviceHost.Quota = quota
	if configureHost != nil {
		configureHost(serviceHost)
	}
	settings := testServiceSettings()
	if configure != nil {
		configure(settings)
	}
	dialer := newTestPathDialer()
	service, err := tlsedgeservice.NewTlsEdgeService(ctx, serviceHost, store, dialer, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	testAwaitCount(t, service.NameLoadCountForTest(), 1)
	testAwaitCount(t, service.KillLoadCountForTest(), 1)
	if !service.Ready() {
		t.Fatal("the engine is not ready")
	}
	listener := testLoopbackListener(t, 443)
	world := &testPathWorld{
		ctx:       ctx,
		clock:     clock,
		host:      host,
		quota:     quota,
		store:     store,
		dialer:    dialer,
		service:   service,
		networkId: networkId,
		label:     label,
		address:   listener.Listener.Addr().String(),
		served:    make(chan error, 1),
	}
	go func() {
		world.served <- service.Serve(listener)
	}()
	return world
}

// The name of a host of the world's network.
func (self *testPathWorld) name(host string) string {
	return host + "." + self.label + "." + testServiceRoot
}

func (self *testPathWorld) dial(t *testing.T) *net.TCPConn {
	t.Helper()
	conn, err := net.Dial("tcp", self.address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(testGuardTimeout))
	return conn.(*net.TCPConn)
}

// Sends hello and reads until the engine closes, which is all a refused visitor ever sees.
func (self *testPathWorld) answer(t *testing.T, hello []byte) []byte {
	t.Helper()
	conn := self.dial(t)
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	answer, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("the visitor read: %v", err)
	}
	return answer
}

// Opens a connection to host through to its listener's stream, the hello read off it.
func (self *testPathWorld) open(t *testing.T, host string) (*net.TCPConn, *testPathStream, []byte) {
	t.Helper()
	hello := testEdgeHello(self.name(host), []string{"h2", "http/1.1"}, 0)
	conn := self.dial(t)
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	stream := self.dialer.awaitOpened(t)
	if read := stream.listenerRead(t, len(hello)); !bytes.Equal(read, hello) {
		t.Fatal("the listener's hello is not the visitor's")
	}
	return conn, stream, hello
}

// Sets a kill of host in the network's {tes_} key and tells the engine, as the key event would.
func (self *testPathWorld) kill(t *testing.T, host string) {
	t.Helper()
	value, err := json.Marshal(&sidecar.TlsKillEntry{Host: host, Reason: "case"})
	if err != nil {
		t.Fatal(err)
	}
	if err := self.host.Redis.HashSet(self.ctx, sidecar.TlsKillKey(self.networkId), map[string][]byte{host: value}); err != nil {
		t.Fatal(err)
	}
	before := self.service.KillChangeCountForTest().Value()
	self.service.KillChanged(self.networkId)
	testAwaitCount(t, self.service.KillChangeCountForTest(), before+1)
}

// Waits until the clock holds a timer for at.
func testAwaitTimer(t *testing.T, clock *sidecartest.FakeClock, at time.Time) {
	t.Helper()
	guard := time.After(testGuardTimeout)
	for {
		pending, added := clock.WatchTimers()
		if slices.Contains(pending, at) {
			return
		}
		select {
		case <-added:
		case <-guard:
			t.Fatalf("no timer was set for %v", at)
		}
	}
}

// Waits until count connections have run to their end since the engine started, counted or not.
func (self *testPathWorld) awaitEnded(t *testing.T, count uint64) {
	t.Helper()
	testAwaitCount(t, self.service.ConnectionEndCountForTest(), count)
}

// A big-endian length of byteCount bytes in front of data.
func testEdgePrefixed(byteCount int, data []byte) []byte {
	prefix := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
	return append(prefix[len(prefix)-byteCount:], data...)
}

// A ClientHello for serverName offering alpnIds, in one record, padded by padByteCount bytes of RFC
// 7685's padding extension, as a post-quantum key share would lengthen it.
func testEdgeHello(serverName string, alpnIds []string, padByteCount int) []byte {
	extensions := []byte{}
	extension := func(extensionType uint16, data []byte) {
		extensions = binary.BigEndian.AppendUint16(extensions, extensionType)
		extensions = append(extensions, testEdgePrefixed(2, data)...)
	}
	if serverName != "" {
		entry := append([]byte{0}, testEdgePrefixed(2, []byte(serverName))...)
		extension(0, testEdgePrefixed(2, entry))
	}
	if 0 < len(alpnIds) {
		entries := []byte{}
		for _, alpnId := range alpnIds {
			entries = append(entries, testEdgePrefixed(1, []byte(alpnId))...)
		}
		extension(16, testEdgePrefixed(2, entries))
	}
	if 0 < padByteCount {
		extension(21, make([]byte, padByteCount))
	}
	body := []byte{3, 3}
	body = append(body, bytes.Repeat([]byte{0x11}, 32)...)
	body = append(body, 0)
	body = append(body, testEdgePrefixed(2, []byte{0x13, 0x01})...)
	body = append(body, 1, 0)
	body = append(body, testEdgePrefixed(2, extensions)...)
	message := append([]byte{1}, testEdgePrefixed(3, body)...)
	return append([]byte{22, 3, 1}, testEdgePrefixed(2, message)...)
}

func testAlertBytes(code tlsedgeservice.TlsAlertCode) []byte {
	return []byte{21, 3, 3, 0, 2, 2, byte(code)}
}

// Step 7's table: each refusal is one alert and a close. An unknown label, a killed name and a denied
// one are the same bytes on the wire, and no listener, busy, quota, unavailable, a setup that failed and a
// network outside the gate are internal_error.
func TestTlsEdgeConnAlertTable(t *testing.T) {
	world := newTestPathWorld(t, nil)
	unrecognized := testAlertBytes(tlsedgeservice.TlsAlertUnrecognizedName)
	internal := testAlertBytes(tlsedgeservice.TlsAlertInternalError)
	alpnIds := []string{"h2"}

	// a record that is no handshake, read whole before it is refused
	if answer := world.answer(t, []byte{23, 3, 3, 0, 1}); !bytes.Equal(answer, testAlertBytes(tlsedgeservice.TlsAlertDecodeError)) {
		t.Fatalf("a malformed hello answered %x", answer)
	}

	unknown := world.answer(t, testEdgeHello("blog.zzzzzzzzzz."+testServiceRoot, alpnIds, 0))
	if !bytes.Equal(unknown, unrecognized) {
		t.Fatalf("an unknown label answered %x", unknown)
	}
	if answer := world.answer(t, testEdgeHello("blog.elsewhere.example", alpnIds, 0)); !bytes.Equal(answer, unrecognized) {
		t.Fatalf("a name outside the root answered %x", answer)
	}
	if answer := world.answer(t, testEdgeHello("", alpnIds, 0)); !bytes.Equal(answer, unrecognized) {
		t.Fatalf("a hello with no name answered %x", answer)
	}
	if got := world.dialer.dialCount.Load(); got != 0 {
		t.Fatalf("%d dials for names that map to nothing", got)
	}

	world.dialer.refuseNext(&sidecar.SocketCodeError{Err: sidecar.ErrSocketDenied})
	denied := world.answer(t, testEdgeHello(world.name("denied"), alpnIds, 0))
	if !bytes.Equal(denied, unknown) {
		t.Fatalf("a denied name answered %x, an unknown one %x", denied, unknown)
	}
	// the negative cache answers the next one, with no Find
	dialCount := world.dialer.dialCount.Load()
	if answer := world.answer(t, testEdgeHello(world.name("denied"), alpnIds, 0)); !bytes.Equal(answer, unknown) {
		t.Fatalf("a cached denial answered %x", answer)
	}
	if got := world.dialer.dialCount.Load(); got != dialCount {
		t.Fatal("a cached denial asked Find again")
	}

	world.dialer.refuseNext(&sidecar.SocketCodeError{Err: sidecar.ErrSocketNoListener})
	if answer := world.answer(t, testEdgeHello(world.name("idle"), alpnIds, 0)); !bytes.Equal(answer, internal) {
		t.Fatalf("no listener answered %x", answer)
	}
	dialCount = world.dialer.dialCount.Load()
	if answer := world.answer(t, testEdgeHello(world.name("idle"), alpnIds, 0)); !bytes.Equal(answer, internal) {
		t.Fatalf("a cached no listener answered %x", answer)
	}
	if got := world.dialer.dialCount.Load(); got != dialCount {
		t.Fatal("a cached no listener asked Find again")
	}
	// another ALPN set is another key (reading 18)
	world.dialer.refuseNext(&sidecar.SocketCodeError{Err: sidecar.ErrSocketBusy})
	if answer := world.answer(t, testEdgeHello(world.name("idle"), []string{"mqtt"}, 0)); !bytes.Equal(answer, internal) {
		t.Fatalf("busy answered %x", answer)
	}
	if got := world.dialer.dialCount.Load(); got != dialCount+1 {
		t.Fatal("another ALPN set was answered from the cache")
	}

	for _, err := range []error{sidecar.ErrSocketQuota, sidecar.ErrSocketUnavailable, errors.New("a transport failed")} {
		world.dialer.refuseNext(&sidecar.SocketCodeError{Err: err})
		if answer := world.answer(t, testEdgeHello(world.name("blog"), alpnIds, 0)); !bytes.Equal(answer, internal) {
			t.Fatalf("%v answered %x", err, answer)
		}
	}

	// a network the gate does not admit
	otherNetworkId := sidecar.NewId()
	otherLabel, err := world.store.AddLabel(testServiceRoot, otherNetworkId)
	if err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(5 * time.Second)
	testAwaitCount(t, world.service.NameLoadCountForTest(), 2)
	dialCount = world.dialer.dialCount.Load()
	if answer := world.answer(t, testEdgeHello("blog."+otherLabel+"."+testServiceRoot, alpnIds, 0)); !bytes.Equal(answer, internal) {
		t.Fatalf("a network outside the gate answered %x", answer)
	}
	if got := world.dialer.dialCount.Load(); got != dialCount {
		t.Fatal("a network outside the gate reached Find")
	}

	// a killed name reads as an unknown one (reading 5)
	world.kill(t, "blog")
	killed := world.answer(t, testEdgeHello(world.name("blog"), alpnIds, 0))
	if !bytes.Equal(killed, unknown) {
		t.Fatalf("a killed name answered %x, an unknown one %x", killed, unknown)
	}
	if got := world.dialer.dialCount.Load(); got != dialCount {
		t.Fatal("a killed name reached Find")
	}

	world.awaitEnded(t, 14)
	for result, count := range map[string]float64{
		"hello_refused":        1,
		"unmapped":             3,
		"denied":               1,
		"negative_denied":      1,
		"no_listener":          1,
		"negative_no_listener": 1,
		"busy":                 1,
		"quota":                1,
		"unavailable":          1,
		"setup_failed":         1,
		"gate_closed":          1,
		"killed":               1,
	} {
		if got := world.host.Metrics.Value("urnetwork_tlsedge_connections_total", result); got != count {
			t.Errorf("%s counted %v, not %v", result, got, count)
		}
	}
	if violations := world.host.Metrics.Violations(); 0 < len(violations) {
		t.Fatalf("metrics violations %v", violations)
	}
}

// A closed gate answers every name internal_error, a mapped one and an unknown one alike, with no Find.
func TestTlsEdgeConnClosedGate(t *testing.T) {
	world := newTestPathWorld(t, nil)
	if err := world.host.Gates.Set(""); err != nil {
		t.Fatal(err)
	}
	internal := testAlertBytes(tlsedgeservice.TlsAlertInternalError)
	for _, name := range []string{world.name("blog"), "blog.zzzzzzzzzz." + testServiceRoot} {
		if answer := world.answer(t, testEdgeHello(name, []string{"h2"}, 0)); !bytes.Equal(answer, internal) {
			t.Fatalf("a closed gate answered %x", answer)
		}
	}
	if got := world.dialer.dialCount.Load(); got != 0 {
		t.Fatalf("%d dials behind a closed gate", got)
	}
	if !world.service.Ready() {
		t.Fatal("a closed gate made the engine not ready")
	}
}

// A hello offering ur-route-probe gets unrecognized_name at once, whatever its SNI, and makes no store,
// dialer or lease call.
func TestTlsEdgeConnRouteProbeTouchesNothing(t *testing.T) {
	world := newTestPathWorld(t, nil)
	storeCounts := world.store.OpCounts()
	for _, name := range []string{world.name("blog"), "blog.zzzzzzzzzz." + testServiceRoot, ""} {
		answer := world.answer(t, testEdgeHello(name, []string{"h2", "ur-route-probe"}, 0))
		if !bytes.Equal(answer, testAlertBytes(tlsedgeservice.TlsAlertUnrecognizedName)) {
			t.Fatalf("a route probe answered %x", answer)
		}
	}
	world.awaitEnded(t, 3)
	if got := world.host.Metrics.Value("urnetwork_tlsedge_connections_total", "route_probe"); got != 3 {
		t.Fatalf("%v route probes counted", got)
	}
	if got := world.dialer.dialCount.Load(); got != 0 {
		t.Fatalf("%d dials for route probes", got)
	}
	if got := world.quota.leaseCount.Load(); got != 0 {
		t.Fatalf("%d leases for route probes", got)
	}
	if counts := world.store.OpCounts(); !maps.Equal(counts, storeCounts) {
		t.Fatalf("store calls moved from %v to %v", storeCounts, counts)
	}
	if got := world.service.RecordsPendingCountForTest(); got != 0 {
		t.Fatalf("%d records for route probes", got)
	}
}

// The process cap refuses before the hello is read: a connection past max_connections gets
// internal_error having sent nothing.
func TestTlsEdgeConnProcessCap(t *testing.T) {
	world := newTestPathWorld(t, func(settings *tlsedgeservice.TlsEdgeSettings) {
		settings.MaxConnectionCount = 1
	})
	conn, stream, _ := world.open(t, "blog")
	second := world.dial(t)
	answer, err := io.ReadAll(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(answer, testAlertBytes(tlsedgeservice.TlsAlertInternalError)) {
		t.Fatalf("past the process cap answered %x", answer)
	}
	world.awaitEnded(t, 1)
	if got := world.host.Metrics.Value("urnetwork_tlsedge_cap_refusals_total", "process"); got != 1 {
		t.Fatalf("%v process cap refusals counted", got)
	}
	// the first connection is untouched
	stream.listenerWrite(t, []byte("still open"))
	read := make([]byte, 10)
	if _, err := io.ReadFull(conn, read); err != nil || string(read) != "still open" {
		t.Fatalf("the open connection read %q, %v", read, err)
	}
}

// A post-quantum hello past 2,048 B reaches the listener whole and contiguous with what follows it, and
// TlsEdgeOpen says who came and for what.
func TestTlsEdgeConnLongHelloArrivesWhole(t *testing.T) {
	world := newTestPathWorld(t, nil)
	expireTimeMillis := uint64(world.clock.Now().Add(time.Hour).UnixMilli())
	world.dialer.setTickets(expireTimeMillis)
	hello := testEdgeHello(world.name("blog"), []string{"h2", "http/1.1"}, 3000)
	if len(hello) <= 2048 {
		t.Fatalf("the hello is only %d B", len(hello))
	}
	conn := world.dial(t)
	rest := bytes.Repeat([]byte{0xc5}, 700)
	// the hello arrives in pieces, and the first bytes after it behind its last
	if _, err := conn.Write(hello[:1000]); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(append(slices.Clone(hello[1000:]), rest...)); err != nil {
		t.Fatal(err)
	}
	stream := world.dialer.awaitOpened(t)
	if read := stream.listenerRead(t, len(hello)+len(rest)); !bytes.Equal(read, append(slices.Clone(hello), rest...)) {
		t.Fatal("the listener's stream is not the visitor's bytes in order")
	}

	request := world.dialer.lastRequest()
	if request.Target.NetworkId != world.networkId || request.Target.Name != "tls/443/blog" || request.Target.Host != "blog" {
		t.Fatalf("the dial's target %+v", request.Target)
	}
	if !slices.Equal(request.AlpnIds, []string{"h2", "http/1.1"}) {
		t.Fatalf("the dial's ALPN %v", request.AlpnIds)
	}
	if !bytes.Equal(request.HelloBytes, hello) {
		t.Fatal("the dial's hello is not the visitor's")
	}
	open, err := sidecar.ParseTlsEdgeOpen(stream.metadata)
	if err != nil {
		t.Fatal(err)
	}
	visitor := conn.LocalAddr().(*net.TCPAddr)
	if !net.IP(open.GetClientIp()).Equal(visitor.IP) || open.GetClientPort() != uint32(visitor.Port) {
		t.Fatal("TlsEdgeOpen does not name the visitor")
	}
	if open.GetServerName() != world.name("blog") || !slices.Equal(open.GetAlpn(), []string{"h2", "http/1.1"}) {
		t.Fatalf("TlsEdgeOpen names %q offering %v", open.GetServerName(), open.GetAlpn())
	}
	if open.GetClientHelloByteCount() != uint32(len(hello)) || open.GetExpireTimeMillis() != expireTimeMillis {
		t.Fatalf("TlsEdgeOpen's hello is %d B and it ends at %d", open.GetClientHelloByteCount(), open.GetExpireTimeMillis())
	}
}
