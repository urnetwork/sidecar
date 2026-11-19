// The router role (MAIL-M7-19) on fake stores: each §15.4 row past STARTTLS's 220, the splice, the route
// cache, MailIngress and the PTR. A scripted MxEdgeDialer stands in for SOCK-M5-13's SocketEdgeDialer, and
// a hello format of this file's stands in for TLS-M5-06's parser, which an engine may not import. Nothing
// here sleeps: a step waits on a pipe, a monitor or a timer it can see armed.

package mxedgeservice_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The names a router test routes, synthetic.
const (
	testRouteRoot    = "root.example"
	testRouteLabel   = "ab12cd34ef"
	testRouteAlias   = "acme"
	testRouteSni     = "mx." + testRouteLabel + "." + testRouteRoot
	testRouteEhlo    = "relay.sender.example"
	testRouteBalance = 64 * 1024 * 1024
)

// A network id of the tests' own.
func testRouteNetworkId(name string) sidecar.Id {
	var id sidecar.Id
	copy(id[:], name)
	return id
}

// The router's hello in these tests: a 4-byte length, then that many bytes beginning "hello <name>" and
// padded with zeros, read exactly, so nothing past it is read, as TLS-M5-06's reader reads exact records.
func testRouterHello(serverName string, byteCount int) []byte {
	body := []byte("hello " + serverName)
	if serverName == "" {
		body = []byte("hello")
	}
	if len(body) < byteCount {
		body = append(body, make([]byte, byteCount-len(body))...)
	}
	hello := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	return append(hello, body...)
}

// Reads one testRouterHello.
func testRouterReadHello(conn net.Conn, maxByteCount int) (*mxedgeservice.MxClientHello, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	byteCount := int(binary.BigEndian.Uint32(header[:]))
	if maxByteCount < 4+byteCount {
		return nil, errors.New("a hello past its bound")
	}
	body := make([]byte, byteCount)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	text := string(bytes.TrimRight(body, "\x00"))
	if text != "hello" && !strings.HasPrefix(text, "hello ") {
		return nil, errors.New("not a hello")
	}
	return &mxedgeservice.MxClientHello{
		ServerName: strings.TrimPrefix(strings.TrimPrefix(text, "hello"), " "),
		RawBytes:   append(header[:], body...),
	}, nil
}

// One end of a stream: what the router holds, as SocketConn is, over two io.Pipes so each half closes by
// itself.
type testStream struct {
	reader *io.PipeReader
	writer *io.PipeWriter

	stateLock  sync.Mutex
	resetCodes []protocol.StreamResetCode
	closed     bool
}

// The receiver's end of the same stream.
type testReceiver struct {
	reader *io.PipeReader
	writer *io.PipeWriter
	stream *testStream
	// what the dialer was asked
	request *mxedgeservice.MxEdgeDialRequest
	// MailIngress as Metadata gave it, decoded
	ingress *protocol.MailIngress
}

// A stream and the receiver's end of it.
func newTestStreamPair() (*testStream, *testReceiver) {
	toReceiverReader, toReceiverWriter := io.Pipe()
	toRouterReader, toRouterWriter := io.Pipe()
	stream := &testStream{reader: toRouterReader, writer: toReceiverWriter}
	return stream, &testReceiver{reader: toReceiverReader, writer: toRouterWriter, stream: stream}
}

func (self *testStream) Read(b []byte) (int, error) {
	return self.reader.Read(b)
}

func (self *testStream) Write(b []byte) (int, error) {
	return self.writer.Write(b)
}

// StreamClose of this direction: the receiver reads its end.
func (self *testStream) CloseWrite() error {
	return self.writer.Close()
}

func (self *testStream) Close() error {
	self.stateLock.Lock()
	self.closed = true
	self.stateLock.Unlock()
	self.writer.Close()
	return self.reader.Close()
}

var errTestStreamReset = errors.New("stream reset")

func (self *testStream) Reset(code protocol.StreamResetCode) error {
	self.stateLock.Lock()
	self.resetCodes = append(self.resetCodes, code)
	self.stateLock.Unlock()
	self.writer.CloseWithError(errTestStreamReset)
	return self.reader.CloseWithError(errTestStreamReset)
}

func (self *testStream) SetReadDeadline(t time.Time) error {
	return nil
}

func (self *testStream) SetWriteDeadline(t time.Time) error {
	return nil
}

// The codes the router reset the stream with.
func (self *testStream) ResetCodes() []protocol.StreamResetCode {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.resetCodes)
}

// What one Dial answers.
type testDialAnswer struct {
	// an error, when set
	err error
	// the grant expiry the ticket named
	grantExpireTimeMillis uint64
	// accept timeouts before this answer, as a dead primary: Metadata is called once more for each
	ticketTimeouts int
	// closed by the test to let the dial answer; nil answers at once
	release chan struct{}
}

// A scripted MxEdgeDialer.
type testDialer struct {
	clientIds []sidecar.Id
	ready     atomic.Bool

	stateLock sync.Mutex
	answers   []*testDialAnswer
	receivers []*testReceiver
	// signalled with each receiver as its dial begins, before any answer
	dialing chan *testReceiver
}

func newTestDialer(clientCount int) *testDialer {
	self := &testDialer{dialing: make(chan *testReceiver, 64)}
	for i := range clientCount {
		self.clientIds = append(self.clientIds, testRouteNetworkId(fmt.Sprintf("edge client %d", i)))
	}
	self.ready.Store(true)
	return self
}

// Queues the next dial's answer; with none queued a dial opens a stream.
func (self *testDialer) answer(answer *testDialAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.answers = append(self.answers, answer)
}

func (self *testDialer) ClientIds() []sidecar.Id {
	return slices.Clone(self.clientIds)
}

func (self *testDialer) Ready() bool {
	return self.ready.Load()
}

func (self *testDialer) Dial(ctx context.Context, request *mxedgeservice.MxEdgeDialRequest) (mxedgeservice.MxEdgeStream, uint64, error) {
	answer := func() *testDialAnswer {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if len(self.answers) == 0 {
			return &testDialAnswer{}
		}
		answer := self.answers[0]
		self.answers = self.answers[1:]
		return answer
	}()
	stream, receiver := newTestStreamPair()
	copied := *request
	copied.HelloBytes = slices.Clone(request.HelloBytes)
	receiver.request = &copied
	for range answer.ticketTimeouts + 1 {
		metadata, err := request.Metadata(0)
		if err != nil {
			return nil, 0, err
		}
		receiver.ingress = &protocol.MailIngress{}
		if err := proto.Unmarshal(metadata, receiver.ingress); err != nil {
			return nil, 0, err
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.receivers = append(self.receivers, receiver)
	}()
	self.dialing <- receiver
	if answer.release != nil {
		select {
		case <-answer.release:
		case <-ctx.Done():
			return nil, 0, &sidecar.SocketCodeError{Err: sidecar.ErrSocketUnavailable}
		}
	}
	if answer.err != nil {
		return nil, 0, answer.err
	}
	return stream, answer.grantExpireTimeMillis, nil
}

// Every receiver dialed so far.
func (self *testDialer) Receivers() []*testReceiver {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.receivers)
}

// A router engine and what is behind it.
type testRouter struct {
	*testEngine
	dialer     *testDialer
	gateAdmits atomic.Bool
	networkId  sidecar.Id
}

// What a router test may change before the engine starts.
type testRouterOptions struct {
	settings func(settings *mxedgeservice.MxEdgeSettings)
	deps     func(deps *mxedgeservice.MxEdgeDeps)
	router   func(routerDeps *mxedgeservice.MxEdgeRouterDeps)
	// no route for the label
	noRoute bool
	// the network's lease balance; 0 takes testRouteBalance, negative none
	balance int64
	// the host's Push in place of the fake host's
	push sidecar.Push
}

// Router settings that pass ValidateRouter, the STARTTLS quiet period apart from every other timer.
func testRouterSettings() *mxedgeservice.MxEdgeSettings {
	settings := testSettings()
	settings.RouteRootDomainName = testRouteRoot
	settings.StartTlsQuietTimeout = 37 * time.Millisecond
	return settings
}

// Sets name's route, as the projection would, uncounted.
func (self *testRouter) setRoute(name string, route *mxedgeservice.MailRoute) {
	self.t.Helper()
	value, err := json.Marshal(route)
	if err != nil {
		self.t.Fatal(err)
	}
	self.setRouteValue(name, value)
}

// Sets name's raw route value, uncounted.
func (self *testRouter) setRouteValue(name string, value []byte) {
	self.t.Helper()
	if err := self.host.Redis.Set(sidecartest.InspectContext(self.ctx), mxedgeservice.MailRouteKey(name), value, 0); err != nil {
		self.t.Fatal(err)
	}
}

// Deletes name's route, as the projection does for a released name, uncounted.
func (self *testRouter) deleteRoute(name string) {
	self.t.Helper()
	if err := self.host.Redis.Delete(sidecartest.InspectContext(self.ctx), []string{mxedgeservice.MailRouteKey(name)}); err != nil {
		self.t.Fatal(err)
	}
}

// A router serving a test listener, past its first probe, the gates open, one route for the test
// network's label and a balance for its lease.
func newTestRouter(t *testing.T, options *testRouterOptions) *testRouter {
	t.Helper()
	if options == nil {
		options = &testRouterOptions{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	settings := testRouterSettings()
	if options.settings != nil {
		options.settings(settings)
	}
	self := &testRouter{
		testEngine: &testEngine{
			t:        t,
			ctx:      ctx,
			clock:    clock,
			host:     host,
			settings: settings,
			log:      &testLogger{},
			listener: newTestListener(),
			served:   make(chan error, 1),
		},
		dialer:    newTestDialer(settings.Clients),
		networkId: testRouteNetworkId("router network"),
	}
	self.gateAdmits.Store(true)
	self.store = sidecartest.NewFakeMxEdgeStore(host.Redis.Faults())
	self.gateOpen.Store(true)
	deps := &mxedgeservice.MxEdgeDeps{
		ReadClientHello: testRouterReadHello,
		NormalizeSni:    testNormalizeSni,
		WriteTlsAlert:   testWriteTlsAlert,
		GateOpen:        self.gateOpen.Load,
		GateAdmits:      func(networkId sidecar.Id) bool { return self.gateAdmits.Load() },
		Clock:           clock,
		Log:             self.log,
	}
	if options.deps != nil {
		options.deps(deps)
	}
	routerDeps := &mxedgeservice.MxEdgeRouterDeps{Dialer: self.dialer}
	if options.router != nil {
		options.router(routerDeps)
	}
	if _, err := host.Redis.SetIfAbsent(sidecartest.InspectContext(ctx), mxedgeservice.DailyKeyName(clock.Now()), testDailyKey, mxedgeservice.DailyKeyTtl); err != nil {
		t.Fatal(err)
	}
	if !options.noRoute {
		self.setRoute(testRouteLabel, &mxedgeservice.MailRoute{NetworkId: self.networkId, Label: testRouteLabel, Host: "mx"})
	}
	switch {
	case options.balance == 0:
		host.Quota.SetBalance(connect.Id(self.networkId), testRouteBalance)
	case 0 < options.balance:
		host.Quota.SetBalance(connect.Id(self.networkId), options.balance)
	}
	serviceHost := host.ServiceHost()
	if options.push != nil {
		serviceHost.Push = options.push
	}
	service, err := mxedgeservice.NewMxEdgeRouterService(ctx, serviceHost, self.store, deps, routerDeps, settings)
	if err != nil {
		t.Fatal(err)
	}
	self.service = service
	t.Cleanup(service.Close)
	service.AwaitProbeCount(1)
	if !service.StoresReachable() {
		t.Fatal("the first probe found no store or no k")
	}
	listener := self.listener
	go func() {
		self.served <- service.Serve(listener)
	}()
	return self
}

// Waits until a timer at exactly at is pending, with no sleep.
func (self *testRouter) awaitTimerAt(at time.Time) {
	self.t.Helper()
	for {
		pending, added := self.clock.WatchTimers()
		if slices.ContainsFunc(pending, func(timer time.Time) bool { return timer.Equal(at) }) {
			return
		}
		select {
		case <-added:
		case <-self.ctx.Done():
			self.t.Fatal("no timer at", at)
		}
	}
}

// Connects as sender, says EHLO and STARTTLS, and reads the 220: the session is at TLS.
func (self *testRouter) reachTls(sender string) *testClient {
	self.t.Helper()
	client := self.open(sender)
	client.write("EHLO " + testRouteEhlo + "\r\n")
	client.expectEhlo()
	quietAt := self.clock.Now().Add(self.settings.StartTlsQuietTimeout)
	client.write("STARTTLS\r\n")
	self.awaitTimerAt(quietAt)
	self.clock.Advance(self.settings.StartTlsQuietTimeout)
	client.expect("220 2.0.0 Ready to start TLS")
	return client
}

// Reaches TLS, sends a hello naming serverName and waits for the dialer to be asked.
func (self *testRouter) dialFrom(sender string, serverName string) (*testClient, *testReceiver) {
	self.t.Helper()
	client := self.reachTls(sender)
	client.write(string(testRouterHello(serverName, 64)))
	select {
	case receiver := <-self.dialer.dialing:
		return client, receiver
	case <-self.ctx.Done():
		self.t.Fatal("no dial")
		return nil, nil
	}
}

// Reaches TLS, sends a hello naming serverName, and expects the handshake to close with alert, the
// session to end, and the closed-handshake memory to answer 451 for the sender's next plaintext try.
func (self *testRouter) expectClosedHandshake(sender string, serverName string, alert mxedgeservice.MxTlsAlert) {
	self.t.Helper()
	self.expectClosedHandshakeBeside(sender, serverName, alert, 0)
}

// expectClosedHandshake with running sessions open beside it, which go on.
func (self *testRouter) expectClosedHandshakeBeside(sender string, serverName string, alert mxedgeservice.MxTlsAlert, running int) {
	self.t.Helper()
	client := self.reachTls(sender)
	client.write(string(testRouterHello(serverName, 64)))
	client.expectBytes(testAlertRecord(alert))
	client.expectEnd()
	self.service.AwaitSessionCount(running)
	if code := self.plaintextReplyTo(sender); code != "451" {
		self.t.Errorf("a plaintext retry after the closed handshake got %s, not 451", code)
	}
	self.service.AwaitSessionCount(running)
}

// Reads exactly byteCount bytes from the receiver's end.
func (self *testReceiver) readFull(t *testing.T, byteCount int) []byte {
	t.Helper()
	got := make([]byte, byteCount)
	if _, err := io.ReadFull(self.reader, got); err != nil {
		t.Fatalf("receiver read: %v", err)
	}
	return got
}

// The bytes a test passes, every value and a run longer than a splice's buffer.
func testRouteCapture(byteCount int) []byte {
	capture := make([]byte, byteCount)
	for i := range capture {
		capture[i] = byte(i*7 + i/251)
	}
	return capture
}

// The records waiting, written by a flush into the fake store.
func (self *testRouter) flushRecords() []*mxedgeservice.MxConnectionRecord {
	self.t.Helper()
	if err := self.service.ConnectionRecords().Flush(self.ctx); err != nil {
		self.t.Fatal(err)
	}
	return self.store.Records()
}

// A routed session splices both ways byte for byte, from the hello on: the receiver's first bytes are the
// hello verbatim, every byte after it arrives untouched, and the receiver's bytes reach the sender
// untouched. The dial names the network's label and smtp/25/mx, and MailIngress carries the session.
func TestRouterSplicesARoutedSessionByteForByte(t *testing.T) {
	router := newTestRouter(t, nil)
	client, receiver := router.dialFrom(testSender, testRouteSni)
	request := receiver.request
	if request.NetworkId != router.networkId || request.NetworkLabel != testRouteLabel || request.Name != "smtp/25/mx" {
		t.Errorf("dialed %v %q %q", request.NetworkId, request.NetworkLabel, request.Name)
	}
	if !bytes.Equal(request.HelloBytes, testRouterHello(testRouteSni, 64)) {
		t.Errorf("the hello reached the dial as %x", request.HelloBytes)
	}
	ingress := receiver.ingress
	if ingress.GetVersion() != sidecar.MailIngressVersion || !bytes.Equal(ingress.GetSenderIp(), netip.MustParseAddr(testSender).AsSlice()) ||
		ingress.GetSenderPort() != 2525 || ingress.GetSni() != testRouteSni || ingress.GetEhloName() != testRouteEhlo ||
		ingress.GetReceiveTimeMillis() != uint64(sidecartest.DefaultClockStart().UnixMilli()) || ingress.GetPtrName() != "" {
		t.Errorf("MailIngress %v", ingress)
	}

	toReceiver := testRouteCapture(100 * 1024)
	go client.conn.Write(toReceiver)
	if got := receiver.readFull(t, len(toReceiver)); !bytes.Equal(got, toReceiver) {
		t.Error("the sender's bytes reached the receiver changed")
	}
	toSender := testRouteCapture(70 * 1024)[3:]
	go receiver.writer.Write(toSender)
	got := make([]byte, len(toSender))
	if _, err := io.ReadFull(client.reader, got); err != nil || !bytes.Equal(got, toSender) {
		t.Errorf("the receiver's bytes reached the sender changed: %v", err)
	}

	// the receiver's StreamClose ends a sender connection that cannot half-close
	receiver.writer.Close()
	client.expectEnd()
	// a session queues its record before it stops counting
	router.service.AwaitSessionCount(0)
	records := router.flushRecords()
	wantByteCount := int64(len(testRouterHello(testRouteSni, 64)) + len(toReceiver) + len(toSender))
	if len(records) != 1 || records[0].NetworkId != router.networkId || records[0].ByteCount != wantByteCount ||
		records[0].Result != "splice_closed" || !records[0].StartTime.Equal(sidecartest.DefaultClockStart()) {
		t.Errorf("records %+v, want one of %d bytes", records, wantByteCount)
	}
	if value := router.host.Metrics.Value("urnetwork_mxedge_sessions_total", "splice_closed"); value != 1 {
		t.Errorf("%v spliced sessions counted", value)
	}
}

// Each §15.4 row past the 220 that cannot splice closes in the handshake with one alert, writes the
// closed-handshake memory so the sender's plaintext retry gets 451, and leaves a record only when the SNI
// named a network.
func TestRouterClosesEachUnroutableSessionInTheHandshake(t *testing.T) {
	for _, c := range []struct {
		name       string
		serverName string
		options    *testRouterOptions
		setup      func(router *testRouter)
		alert      mxedgeservice.MxTlsAlert
		result     string
		// whether the SNI named a network, so a record is left
		named bool
	}{
		{name: "no SNI", serverName: "", alert: mxedgeservice.MxTlsAlertUnrecognizedName, result: "no_sni"},
		{name: "an unknown name", serverName: "mx.zz98yx76wv." + testRouteRoot, alert: mxedgeservice.MxTlsAlertUnrecognizedName, result: "unknown_name"},
		{name: "a name outside the root", serverName: "mx." + testRouteLabel + ".other.example", alert: mxedgeservice.MxTlsAlertUnrecognizedName, result: "unknown_name"},
		{name: "a suspended network, which has no key", serverName: testRouteSni, options: &testRouterOptions{noRoute: true}, alert: mxedgeservice.MxTlsAlertUnrecognizedName, result: "unknown_name"},
		{
			name: "a value the projection does not write", serverName: testRouteSni,
			setup: func(router *testRouter) { router.setRouteValue(testRouteLabel, []byte(`{"network_id":"`)) },
			alert: mxedgeservice.MxTlsAlertUnrecognizedName, result: "unknown_name",
		},
		{
			name: "a closed mxedge gate", serverName: testRouteSni,
			setup: func(router *testRouter) { router.gateOpen.Store(false) },
			alert: mxedgeservice.MxTlsAlertInternalError, result: "gate_closed",
		},
		{
			name: "a gate that does not admit the network", serverName: testRouteSni,
			setup: func(router *testRouter) { router.gateAdmits.Store(false) },
			alert: mxedgeservice.MxTlsAlertInternalError, result: "gate_closed", named: true,
		},
		{
			name: "clients not connected", serverName: testRouteSni,
			setup: func(router *testRouter) { router.dialer.ready.Store(false) },
			alert: mxedgeservice.MxTlsAlertInternalError, result: "not_ready",
		},
		{
			name: "a spent network", serverName: testRouteSni, options: &testRouterOptions{balance: -1},
			alert: mxedgeservice.MxTlsAlertInternalError, result: "spent", named: true,
		},
		{
			name: "no receiver", serverName: testRouteSni,
			setup: func(router *testRouter) {
				router.dialer.answer(&testDialAnswer{err: &sidecar.SocketCodeError{Err: sidecar.ErrSocketNoListener}})
			},
			alert: mxedgeservice.MxTlsAlertInternalError, result: "no_receiver", named: true,
		},
		{
			name: "sockets down", serverName: testRouteSni,
			setup: func(router *testRouter) {
				router.dialer.answer(&testDialAnswer{err: &sidecar.SocketCodeError{Err: sidecar.ErrSocketUnavailable}})
			},
			alert: mxedgeservice.MxTlsAlertInternalError, result: "sockets_unavailable", named: true,
		},
		{
			name: "a busy receiver", serverName: testRouteSni,
			setup: func(router *testRouter) {
				router.dialer.answer(&testDialAnswer{err: &sidecar.SocketCodeError{Err: sidecar.ErrSocketBusy}})
			},
			alert: mxedgeservice.MxTlsAlertInternalError, result: "receiver_busy", named: true,
		},
		{
			name: "a receiver that denies", serverName: testRouteSni,
			setup: func(router *testRouter) {
				router.dialer.answer(&testDialAnswer{err: &sidecar.SocketCodeError{Err: sidecar.ErrSocketDenied}})
			},
			alert: mxedgeservice.MxTlsAlertInternalError, result: "receiver_denied", named: true,
		},
	} {
		router := newTestRouter(t, c.options)
		if c.setup != nil {
			c.setup(router)
		}
		router.expectClosedHandshake(testSender, c.serverName, c.alert)
		if value := router.host.Metrics.Value("urnetwork_mxedge_sessions_total", c.result); value != 1 {
			t.Errorf("%s: %v sessions counted %s", c.name, value, c.result)
		}
		records := router.flushRecords()
		switch {
		case c.named && (len(records) != 1 || records[0].Result != c.result || records[0].NetworkId != router.networkId || records[0].ByteCount != 0):
			t.Errorf("%s: records %+v", c.name, records)
		case !c.named && len(records) != 0:
			t.Errorf("%s: a session that named no network left %+v", c.name, records)
		}
		if receivers := router.dialer.Receivers(); c.result != "no_receiver" && c.result != "sockets_unavailable" &&
			c.result != "receiver_busy" && c.result != "receiver_denied" && len(receivers) != 0 {
			t.Errorf("%s: dialed %d receivers", c.name, len(receivers))
		}
	}
}

// A hello that does not parse closes as decode_error, and is remembered as any closed handshake is.
func TestRouterClosesABadHelloAsDecodeError(t *testing.T) {
	router := newTestRouter(t, nil)
	client := router.reachTls(testSender)
	client.write("\x00\x00\x00\x05xyzzy")
	client.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertDecodeError))
	client.expectEnd()
	router.service.AwaitSessionCount(0)
	if code := router.plaintextReplyTo(testSender); code != "451" {
		t.Errorf("plaintext after a bad hello got %s", code)
	}
}

// A Redis that does not answer the route closes in the handshake as internal_error and keeps nothing, so
// the next session reads Redis again and routes.
func TestRouterRouteUnansweredClosesAndIsNotKept(t *testing.T) {
	router := newTestRouter(t, nil)
	if _, err := router.host.Redis.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpRedis, KeyPrefix: mxedgeservice.MailRouteKey(testRouteLabel), Result: sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	router.expectClosedHandshake(testSender, testRouteSni, mxedgeservice.MxTlsAlertInternalError)
	if value := router.host.Metrics.Value("urnetwork_mxedge_sessions_total", "route_unavailable"); value != 1 {
		t.Errorf("%v route_unavailable sessions", value)
	}
	client, receiver := router.dialFrom("203.0.113.77", testRouteSni)
	receiver.writer.Close()
	client.expectEnd()
}

// The network caps close in the handshake once SNI names the network (reading 1): with one session per
// sender /24 per network, a second sender of the /24 closes as internal_error while the first splices,
// and a sender of another /24 still splices.
func TestRouterNetworkCapsCloseInTheHandshake(t *testing.T) {
	router := newTestRouter(t, &testRouterOptions{settings: func(settings *mxedgeservice.MxEdgeSettings) {
		settings.NetworkSenderSessionCount = 1
	}})
	first, firstReceiver := router.dialFrom("203.0.113.9", testRouteSni)
	router.expectClosedHandshakeBeside("203.0.113.10", testRouteSni, mxedgeservice.MxTlsAlertInternalError, 1)
	if value := router.host.Metrics.Value("urnetwork_mxedge_cap_refusals_total", "network_sender"); value != 1 {
		t.Errorf("%v network_sender refusals", value)
	}
	other, otherReceiver := router.dialFrom("198.51.100.9", testRouteSni)
	firstReceiver.writer.Close()
	first.expectEnd()
	otherReceiver.writer.Close()
	other.expectEnd()
	router.service.AwaitSessionCount(0)
}

// An alias's route names the network's label, which the stream target needs, and its SNI is
// mx.<alias>.<root>.
func TestRouterRoutesAnAliasToItsNetworksLabel(t *testing.T) {
	router := newTestRouter(t, nil)
	router.setRoute(testRouteAlias, &mxedgeservice.MailRoute{
		NetworkId: router.networkId, Label: testRouteLabel, Host: "mx", Flags: mxedgeservice.MailRouteFlagAlias,
	})
	client, receiver := router.dialFrom(testSender, "MX."+strings.ToUpper(testRouteAlias)+"."+testRouteRoot)
	if receiver.request.NetworkLabel != testRouteLabel || receiver.request.Name != "smtp/25/mx" || receiver.ingress.GetSni() != "mx.acme.root.example" {
		t.Errorf("dialed %q %q with sni %q", receiver.request.NetworkLabel, receiver.request.Name, receiver.ingress.GetSni())
	}
	receiver.writer.Close()
	client.expectEnd()
}

// A scope's SNI reaches only that scope's receivers: its route's host mx.<scope> is the socket name.
func TestRouterRoutesAScopeToItsHost(t *testing.T) {
	router := newTestRouter(t, nil)
	router.setRoute("eng."+testRouteLabel, &mxedgeservice.MailRoute{
		NetworkId: router.networkId, Label: testRouteLabel, Host: "mx.eng", Flags: mxedgeservice.MailRouteFlagScope,
	})
	client, receiver := router.dialFrom(testSender, "mx.eng."+testRouteLabel+"."+testRouteRoot)
	if receiver.request.Name != "smtp/25/mx.eng" {
		t.Errorf("dialed %q", receiver.request.Name)
	}
	receiver.writer.Close()
	client.expectEnd()
}

// A released alias routes nothing (I-14): once the projection deletes its key, the cache's answer lapses
// within RouteCacheTtl and the next session closes as an unknown name, dialing nothing.
func TestRouterReleasedAliasRoutesNothing(t *testing.T) {
	router := newTestRouter(t, nil)
	router.setRoute(testRouteAlias, &mxedgeservice.MailRoute{NetworkId: router.networkId, Label: testRouteLabel, Host: "mx", Flags: mxedgeservice.MailRouteFlagAlias})
	aliasSni := "mx." + testRouteAlias + "." + testRouteRoot
	client, receiver := router.dialFrom(testSender, aliasSni)
	receiver.writer.Close()
	client.expectEnd()
	router.service.AwaitSessionCount(0)

	router.deleteRoute(testRouteAlias)
	router.clock.Advance(router.settings.RouteCacheTtl)
	dialCount := len(router.dialer.Receivers())
	router.expectClosedHandshake("198.51.100.20", aliasSni, mxedgeservice.MxTlsAlertUnrecognizedName)
	if len(router.dialer.Receivers()) != dialCount {
		t.Error("a released alias dialed a receiver")
	}
}

// Sessions naming one name within RouteCacheTtl read Redis once, and none reaches the store.
func TestRouterReadsARouteOnceATtl(t *testing.T) {
	router := newTestRouter(t, nil)
	router.host.Redis.ResetOpCounts()
	router.store.ResetOpCounts()
	for _, sender := range []string{"203.0.113.30", "198.51.100.31", "192.0.2.32"} {
		client, receiver := router.dialFrom(sender, testRouteSni)
		receiver.writer.Close()
		client.expectEnd()
	}
	router.service.AwaitSessionCount(0)
	if gets := router.host.Redis.OpCounts()["get"]; gets != 1 {
		t.Errorf("three sessions read the route %d times", gets)
	}
	if ops := router.store.OpCounts(); len(ops) != 0 {
		t.Errorf("sessions reached the store: %v", ops)
	}
}

// A long post-quantum hello reaches the dial whole, verbatim: the dialer sends its first 2,048 B in
// StreamOpen's early data and the rest in StreamData behind it.
func TestRouterPassesALongHelloWhole(t *testing.T) {
	router := newTestRouter(t, nil)
	client := router.reachTls(testSender)
	hello := testRouterHello(testRouteSni, 6000)
	client.write(string(hello))
	receiver := <-router.dialer.dialing
	if !bytes.Equal(receiver.request.HelloBytes, hello) {
		t.Errorf("a %d-byte hello reached the dial as %d bytes", len(hello), len(receiver.request.HelloBytes))
	}
	receiver.writer.Close()
	client.expectEnd()
}

// No byte past the hello reaches a receiver before its accept (FI-11): bytes a sender writes right
// behind its hello wait in its socket while the dial is open, and arrive only after.
func TestRouterSendsNoByteBeforeTheAccept(t *testing.T) {
	router := newTestRouter(t, nil)
	release := make(chan struct{})
	router.dialer.answer(&testDialAnswer{release: release})
	client := router.reachTls(testSender)
	hello := testRouterHello(testRouteSni, 64)
	behind := []byte("application data sent before the accept")
	written := make(chan error, 1)
	go func() {
		_, err := client.conn.Write(append(slices.Clone(hello), behind...))
		written <- err
	}()
	receiver := <-router.dialer.dialing
	if !bytes.Equal(receiver.request.HelloBytes, hello) {
		t.Errorf("the dial was given %q", receiver.request.HelloBytes)
	}
	// the sender's write cannot finish: the bytes behind the hello are still unread in its socket
	select {
	case err := <-written:
		t.Fatalf("the bytes behind the hello were read before the accept: %v", err)
	default:
	}
	close(release)
	if got := receiver.readFull(t, len(behind)); !bytes.Equal(got, behind) {
		t.Errorf("after the accept the receiver read %q", got)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	receiver.writer.Close()
	client.expectEnd()
}

// A dead primary falls to the backup ticket inside the dialer, which asks MailIngress again for it: the
// router gives the same bytes for every ticket and splices the stream that opened.
func TestRouterSplicesTheBackupAfterADeadPrimary(t *testing.T) {
	router := newTestRouter(t, nil)
	router.dialer.answer(&testDialAnswer{ticketTimeouts: 1})
	client, receiver := router.dialFrom(testSender, testRouteSni)
	if receiver.ingress.GetSni() != testRouteSni {
		t.Errorf("the backup's MailIngress %v", receiver.ingress)
	}
	payload := []byte("to the backup")
	go client.conn.Write(payload)
	if got := receiver.readFull(t, len(payload)); !bytes.Equal(got, payload) {
		t.Errorf("read %q", got)
	}
	receiver.writer.Close()
	client.expectEnd()
}

// The PTR is looked up during the dialog and forward-confirmed: a name whose own lookup holds the sender
// reaches MailIngress, one that does not is skipped, and a lookup still running at the handoff leaves "".
func TestRouterForwardConfirmsThePtr(t *testing.T) {
	sender := netip.MustParseAddr(testSender)
	var lookupsLock sync.Mutex
	hosts := map[string][]netip.Addr{
		"other.sender.example": {netip.MustParseAddr("192.0.2.200")},
		"relay.sender.example": {netip.MustParseAddr("2001:db8::9"), sender},
	}
	router := newTestRouter(t, &testRouterOptions{router: func(routerDeps *mxedgeservice.MxEdgeRouterDeps) {
		routerDeps.LookupPtr = func(ctx context.Context, addr netip.Addr) ([]string, error) {
			if addr != sender {
				return nil, errors.New("no PTR")
			}
			return []string{"Other.Sender.Example.", "relay.sender.example."}, nil
		}
		routerDeps.LookupHost = func(ctx context.Context, name string) ([]netip.Addr, error) {
			lookupsLock.Lock()
			defer lookupsLock.Unlock()
			return hosts[name], nil
		}
	}})
	client := router.reachTls(testSender)
	router.service.AwaitPtrLookups(1)
	client.write(string(testRouterHello(testRouteSni, 64)))
	receiver := <-router.dialer.dialing
	if ptr := receiver.ingress.GetPtrName(); ptr != "relay.sender.example" {
		t.Errorf("ptr_name %q", ptr)
	}
	receiver.writer.Close()
	client.expectEnd()

	other := router.reachTls("198.51.100.40")
	router.service.AwaitPtrLookups(2)
	other.write(string(testRouterHello(testRouteSni, 64)))
	otherReceiver := <-router.dialer.dialing
	if ptr := otherReceiver.ingress.GetPtrName(); ptr != "" {
		t.Errorf("an unconfirmed sender's ptr_name %q", ptr)
	}
	otherReceiver.writer.Close()
	other.expectEnd()
}

// A PTR lookup the handoff outruns leaves "", and the session splices without waiting for it.
func TestRouterDoesNotWaitForALatePtr(t *testing.T) {
	unblock := make(chan struct{})
	router := newTestRouter(t, &testRouterOptions{router: func(routerDeps *mxedgeservice.MxEdgeRouterDeps) {
		routerDeps.LookupPtr = func(ctx context.Context, addr netip.Addr) ([]string, error) {
			select {
			case <-unblock:
			case <-ctx.Done():
			}
			return []string{"late.sender.example"}, nil
		}
		routerDeps.LookupHost = func(ctx context.Context, name string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr(testSender)}, nil
		}
	}})
	defer close(unblock)
	client, receiver := router.dialFrom(testSender, testRouteSni)
	if ptr := receiver.ingress.GetPtrName(); ptr != "" {
		t.Errorf("a late PTR reached MailIngress as %q", ptr)
	}
	receiver.writer.Close()
	client.expectEnd()
}

// The router is not ready without the dialer's K clients, a Quota and its deps, and NewMxEdgeRouterService
// refuses settings with no route root.
func TestRouterReadiness(t *testing.T) {
	router := newTestRouter(t, nil)
	if !router.service.Ready() {
		t.Error("a router with every part is not ready")
	}
	router.dialer.ready.Store(false)
	if router.service.Ready() {
		t.Error("a router whose clients are not connected is ready")
	}
	router.dialer.ready.Store(true)
	router.dialer.clientIds = router.dialer.clientIds[:1]
	if router.service.Ready() {
		t.Error("a router holding fewer than K clients is ready")
	}

	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	settings := testRouterSettings()
	settings.RouteRootDomainName = ""
	if _, err := mxedgeservice.NewMxEdgeRouterService(ctx, host.ServiceHost(), nil, nil, nil, settings); !errors.Is(err, mxedgeservice.ErrMxEdgeSettingsRefused) {
		t.Errorf("no route root: %v", err)
	}
	settings = testRouterSettings()
	serviceHost := host.ServiceHost()
	serviceHost.Quota = nil
	service, err := mxedgeservice.NewMxEdgeRouterService(ctx, serviceHost, sidecartest.NewFakeMxEdgeStore(host.Redis.Faults()),
		&mxedgeservice.MxEdgeDeps{ReadClientHello: testRouterReadHello, NormalizeSni: testNormalizeSni, WriteTlsAlert: testWriteTlsAlert, Clock: clock},
		&mxedgeservice.MxEdgeRouterDeps{Dialer: newTestDialer(settings.Clients)}, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if service.Ready() {
		t.Error("a router with no Quota is ready")
	}
}

// The route value the projection writes, and every SNI's routable part, read the same here as server's
// model writes them.
func TestMailRouteNameAndValue(t *testing.T) {
	for sni, want := range map[string]string{
		"mx.ab12cd34ef.root.example":     "ab12cd34ef",
		"MX.Acme.Root.Example.":          "acme",
		"mx.eng.acme.root.example":       "eng.acme",
		"mx.customer.example":            "mx.customer.example",
		"mail.acme.root.example":         "mail.acme.root.example",
		"mx.root.example":                "mx.root.example",
		"":                               "",
		"mx.acme.other-root.example":     "mx.acme.other-root.example",
		"mx.acme.root.example.evil.test": "mx.acme.root.example.evil.test",
	} {
		if name := mxedgeservice.MailRouteName("root.example.", sni); name != want {
			t.Errorf("%q routes by %q, want %q", sni, name, want)
		}
	}
	if mxedgeservice.MailRouteKey("acme") != "{mxr_acme}" {
		t.Errorf("key %s", mxedgeservice.MailRouteKey("acme"))
	}
	for value, ok := range map[string]bool{
		`{"network_id":"01234567-89ab-cdef-0123-456789abcdef","label":"ab12cd34ef","host":"mx","flags":0,"receiver_sidecar_ids":[]}`:     true,
		`{"network_id":"01234567-89ab-cdef-0123-456789abcdef","label":"ab12cd34ef","host":"mx.eng","flags":2,"receiver_sidecar_ids":[]}`: true,
		`{"network_id":"00000000-0000-0000-0000-000000000000","label":"ab12cd34ef","host":"mx"}`:                                         false,
		`{"network_id":"01234567-89ab-cdef-0123-456789abcdef","label":"","host":"mx"}`:                                                   false,
		`{"network_id":"01234567-89ab-cdef-0123-456789abcdef","label":"a:b","host":"mx"}`:                                                false,
		`{"network_id":"01234567-89ab-cdef-0123-456789abcdef","label":"ab12cd34ef","host":"smtp"}`:                                       false,
		`{"network_id":"01234567-89ab-cdef-0123-456789abcdef","label":"ab12cd34ef","host":"mx."}`:                                        false,
		`not json`: false,
	} {
		if _, parsed := mxedgeservice.ParseMailRoute([]byte(value), 63); parsed != ok {
			t.Errorf("%s parsed %v", value, parsed)
		}
	}
}
