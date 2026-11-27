// The router's splice (MAIL-M7-19): each of §15.4's bounds on a fake clock, the half-closes and resets,
// the lease's byte count, a drain's reset, and MailIngress at its bound. On router_test.go's harness.
//
// run once armed its slow and session waits each by a timeout from a reading of its own, and the fake clock armed a
// wait at its own now, so a move between a reading and the arming it fed left that wait a whole move late (QD-1120).
// It now sets each for its bound itself (QD-1425), so a forced interleaving that holds run at its slow wait's arm
// while the clock moves to the bound finds the splice ending there; the helper still waits for every wait run arms
// before a byte can move.

package mxedgeservice_test

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strings"
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

// Splice bounds apart from each other and from every other timer, so a test moves past exactly one.
func testSpliceSettings(settings *mxedgeservice.MxEdgeSettings) {
	settings.SpliceIdleTimeout = 7 * time.Minute
	settings.SpliceSlowTimeout = 11 * time.Minute
	settings.SpliceSlowByteCount = 1024
	settings.SpliceSessionTimeout = 29 * time.Minute
}

// A spliced session, past its setup, with its timers armed. run arms its idle, slow and session waits, in
// that order, before its first byte can move, the slow and session waits each from a reading of the clock
// of its own. Waiting for the idle wait alone, a move to the slow bound could land between the slow wait's
// reading and its arming, and the slow wait then came a whole bound late, past the end the test waited for
// (QD-1120). So this waits for all three, each due at its bound from start, and a test may move the clock
// straight after it. A grant expiry's wait, which run arms after them, is the test's to wait for.
func (self *testRouter) splice(sender string) (*testClient, *testReceiver, time.Time) {
	self.t.Helper()
	return self.spliceWaiting(sender, nil)
}

// splice, running waiting, unless nil, each time it looks for one of the splice's waits and finds it not
// armed yet, given start and that wait's bound, before it waits for the next timer to be armed. It moves
// nothing. The bounds stand apart from each other and from every other timer, as testSpliceSettings sets
// them, so no other timer stands in for a wait's.
func (self *testRouter) spliceWaiting(sender string, waiting func(start time.Time, timeout time.Duration)) (*testClient, *testReceiver, time.Time) {
	self.t.Helper()
	client, receiver := self.dialFrom(sender, testRouteSni)
	start := self.clock.Now()
	for _, timeout := range []time.Duration{self.settings.SpliceIdleTimeout, self.settings.SpliceSlowTimeout, self.settings.SpliceSessionTimeout} {
		at := start.Add(timeout)
		// awaitTimerAt's loop, running waiting each time it finds none due then
		for {
			pending, added := self.clock.WatchTimers()
			if slices.ContainsFunc(pending, func(timer time.Time) bool { return timer.Equal(at) }) {
				break
			}
			if waiting != nil {
				waiting(start, timeout)
			}
			select {
			case <-added:
			case <-self.ctx.Done():
				self.t.Fatal("the splice armed no wait due at", at)
			}
		}
	}
	return client, receiver, start
}

// Expects the splice to have ended with reason: the stream reset with code, the sender's connection
// closed, the session's record naming the reason.
func (self *testRouter) expectSpliceEnd(client *testClient, receiver *testReceiver, reason string, code protocol.StreamResetCode) {
	self.t.Helper()
	client.expectEnd()
	self.service.AwaitSessionCount(0)
	if codes := receiver.stream.ResetCodes(); !slices.Equal(codes, []protocol.StreamResetCode{code}) {
		self.t.Errorf("%s reset the stream with %v, want %v", reason, codes, code)
	}
	records := self.flushRecords()
	if len(records) != 1 || records[0].Result != "splice_"+reason {
		self.t.Errorf("records %+v, want splice_%s", records, reason)
	}
	if value := self.host.Metrics.Value("urnetwork_mxedge_splice_ends_total", reason); value != 1 {
		self.t.Errorf("%v splices counted as ended by %s", value, reason)
	}
}

// No byte either way for SpliceIdleTimeout ends the splice; a byte resets the wait.
func TestSpliceEndsAfterIdle(t *testing.T) {
	router := newTestRouter(t, &testRouterOptions{settings: testSpliceSettings})
	client, receiver, start := router.splice(testSender)
	router.clock.Advance(3 * time.Minute)
	go client.conn.Write([]byte("x"))
	receiver.readFull(t, 1)
	// the wait at start+7m sees the byte at start+3m and waits until start+10m
	router.clock.AdvanceTo(start.Add(router.settings.SpliceIdleTimeout))
	router.awaitTimerAt(start.Add(3*time.Minute + router.settings.SpliceIdleTimeout))
	if router.service.SpliceCount() != 1 {
		t.Fatal("a splice with a byte 4 min ago ended at the idle wait")
	}
	router.clock.AdvanceTo(start.Add(3*time.Minute + router.settings.SpliceIdleTimeout))
	router.expectSpliceEnd(client, receiver, "idle", protocol.StreamResetCode_RST_PEER_TIMEOUT)
}

// A splice that passed fewer than SpliceSlowByteCount by SpliceSlowTimeout ends then.
func TestSpliceEndsWhenSlow(t *testing.T) {
	router := newTestRouter(t, &testRouterOptions{settings: func(settings *mxedgeservice.MxEdgeSettings) {
		testSpliceSettings(settings)
		settings.SpliceIdleTimeout = time.Hour
	}})
	client, receiver, start := router.splice(testSender)
	router.clock.AdvanceTo(start.Add(router.settings.SpliceSlowTimeout))
	router.expectSpliceEnd(client, receiver, "slow", protocol.StreamResetCode_RST_PEER_TIMEOUT)
}

// The router's clock, holding mxSplice.run's first wait for a time: its slow wait's arm, set once it has armed its
// idle wait. Held, the arm is asked and not yet set, until release closes or the test ends, and held closes once it
// is. Every other wait, run's later ones and every other caller's, and every reading go straight to the fake clock,
// whose waits for a time this clock sets as its own (sidecar.ClockAt). Safe for concurrent use.
type testSpliceHeldClock struct {
	sidecar.Clock
	// run's name as a stack frame gives it
	runFunction string
	held        chan struct{}
	release     chan struct{}
	// closed as the test ends, before the router closes, which waits for a held splice
	ended   chan struct{}
	holding atomic.Bool
}

var _ sidecar.ClockAt = (*testSpliceHeldClock)(nil)

// The fake clock's wait for at, run's first set only once release closes or the test ends.
func (self *testSpliceHeldClock) AfterAt(at time.Time) <-chan time.Time {
	if !self.holding.Load() && self.calledFromRun() && self.holding.CompareAndSwap(false, true) {
		close(self.held)
		select {
		case <-self.release:
		case <-self.ended:
		}
	}
	return self.Clock.(sidecar.ClockAt).AfterAt(at)
}

// The fake clock's call at at.
func (self *testSpliceHeldClock) AfterFuncAt(at time.Time, function func()) (stop func() bool) {
	return self.Clock.(sidecar.ClockAt).AfterFuncAt(at, function)
}

// Whether AfterAt's caller is run, by way of sidecar.ClockAfterAt: the first frames past Callers', this method's and
// AfterAt's, inlined frames counted.
func (self *testSpliceHeldClock) calledFromRun() bool {
	callers := make([]uintptr, 8)
	frames := runtime.CallersFrames(callers[:runtime.Callers(3, callers)])
	for range 3 {
		frame, more := frames.Next()
		if frame.Function == self.runFunction {
			return true
		}
		if !more {
			break
		}
	}
	return false
}

// Waits until run's slow wait's arm is held, and fails unless run had armed its idle wait and not its slow wait by
// then, or if run arms its slow wait with no arm held, as it would were this clock not to find run's.
func (self *testSpliceHeldClock) awaitHeld(router *testRouter, start time.Time) {
	router.t.Helper()
	idleAt := start.Add(router.settings.SpliceIdleTimeout)
	slowAt := start.Add(router.settings.SpliceSlowTimeout)
	armed := func(pending []time.Time, at time.Time) bool {
		return slices.ContainsFunc(pending, func(timer time.Time) bool { return timer.Equal(at) })
	}
	for {
		select {
		case <-self.held:
			// run arms nothing while it is held
			if pending := router.clock.PendingTimers(); !armed(pending, idleAt) || armed(pending, slowAt) {
				router.t.Fatalf("run's slow arm was held with %v pending, not after its idle wait and before its slow one", pending)
			}
			return
		default:
		}
		pending, added := router.clock.WatchTimers()
		if armed(pending, slowAt) {
			router.t.Fatal("run armed its slow wait with no arm held")
		}
		select {
		case <-self.held:
		case <-added:
		case <-router.ctx.Done():
			router.t.Fatal("run's slow arm was never held")
		}
	}
}

// A router on TestSpliceEndsWhenSlow's bounds whose engine reads its clock through a
// testSpliceHeldClock, and the clock.
func newTestHeldSpliceRouter(t *testing.T) (*testRouter, *testSpliceHeldClock) {
	t.Helper()
	clock := &testSpliceHeldClock{
		// a frame names a function by its package's path, read here so it follows the module's path where a
		// release rewrites it
		runFunction: reflect.TypeFor[mxedgeservice.MxEdgeSettings]().PkgPath() + ".(*mxSplice).run",
		held:        make(chan struct{}),
		release:     make(chan struct{}),
		ended:       make(chan struct{}),
	}
	router := newTestRouter(t, &testRouterOptions{
		settings: func(settings *mxedgeservice.MxEdgeSettings) {
			testSpliceSettings(settings)
			settings.SpliceIdleTimeout = time.Hour
		},
		deps: func(deps *mxedgeservice.MxEdgeDeps) {
			clock.Clock = deps.Clock
			deps.Clock = clock
		},
	})
	// after the router's cleanups, so it runs before them: the engine's close waits for the held splice
	t.Cleanup(func() { close(clock.ended) })
	return router, clock
}

// QD-1120's race, forced, as QD-1425 leaves it: held at its slow wait's arm, after arming its idle wait, while a move
// to the slow bound comes first, as TestSpliceEndsWhenSlow made when the helper waited for the idle wait alone, run
// sets the slow wait for the bound itself, reached, so the splice ends slow there with no further move. Armed by a
// timeout from a reading before the move, as it once was, the wait stood a whole bound past the bound.
func TestSpliceSlowBoundMovedBeforeItsTimerStillEndsAtTheBound(t *testing.T) {
	router, clock := newTestHeldSpliceRouter(t)
	client, receiver := router.dialFrom(testSender, testRouteSni)
	start := router.clock.Now()
	// all the helper waited for before QD-1120
	router.awaitTimerAt(start.Add(router.settings.SpliceIdleTimeout))
	clock.awaitHeld(router, start)
	slowAt := start.Add(router.settings.SpliceSlowTimeout)
	router.clock.AdvanceTo(slowAt)
	close(clock.release)
	router.expectSpliceEnd(client, receiver, "slow", protocol.StreamResetCode_RST_PEER_TIMEOUT)
	if pending := router.clock.PendingTimers(); slices.ContainsFunc(pending, slowAt.Add(router.settings.SpliceSlowTimeout).Equal) {
		t.Fatalf("a slow wait stands a bound late, at %v", pending)
	}
}

// The helper's wait, which QD-1120 added: held at run's slow arm, the helper looks for the slow wait, finds it not
// armed and waits, moving nothing, and only then does run go on. run sets its slow and session waits at their
// bounds, and the move to the slow bound straight after the helper ends the splice slow there.
func TestSpliceSlowBoundMoveWaitsForItsTimer(t *testing.T) {
	router, clock := newTestHeldSpliceRouter(t)
	looked := false
	client, receiver, start := router.spliceWaiting(testSender, func(start time.Time, timeout time.Duration) {
		if timeout != router.settings.SpliceSlowTimeout || looked {
			return
		}
		looked = true
		clock.awaitHeld(router, start)
		close(clock.release)
	})
	if !looked {
		t.Fatal("the helper never found the slow wait unarmed: it did not wait for it, or run's slow arm was not held")
	}
	router.clock.AdvanceTo(start.Add(router.settings.SpliceSlowTimeout))
	router.expectSpliceEnd(client, receiver, "slow", protocol.StreamResetCode_RST_PEER_TIMEOUT)
}

// One that passed SpliceSlowByteCount goes on past the slow bound, to SpliceSessionTimeout, where it ends
// whatever it carries.
func TestSpliceEndsAtTheSessionTimeout(t *testing.T) {
	router := newTestRouter(t, &testRouterOptions{settings: func(settings *mxedgeservice.MxEdgeSettings) {
		testSpliceSettings(settings)
		settings.SpliceIdleTimeout = time.Hour
	}})
	client, receiver, start := router.splice(testSender)
	payload := testRouteCapture(router.settings.SpliceSlowByteCount)
	go client.conn.Write(payload)
	receiver.readFull(t, len(payload))
	router.clock.AdvanceTo(start.Add(router.settings.SpliceSlowTimeout))
	if router.service.SpliceCount() != 1 {
		t.Fatal("a splice past the slow bytes ended at the slow bound")
	}
	router.clock.AdvanceTo(start.Add(router.settings.SpliceSessionTimeout))
	router.expectSpliceEnd(client, receiver, "session_timeout", protocol.StreamResetCode_RST_PEER_TIMEOUT)
}

// A splice ends once it would pass SpliceMessageMultiple times the cold message cap plus
// SpliceExtraByteCount, both ways, the hello included, and the chunk that would pass it never reaches the
// receiver.
func TestSpliceEndsAtTheByteCap(t *testing.T) {
	router := newTestRouter(t, &testRouterOptions{settings: func(settings *mxedgeservice.MxEdgeSettings) {
		settings.ColdMessageByteCount = 1000
		settings.SpliceMessageMultiple = 2
		settings.SpliceExtraByteCount = 500
	}})
	client, receiver := router.dialFrom(testSender, testRouteSni)
	helloByteCount := len(testRouterHello(testRouteSni, 64))
	// the cap is 2,500 B: this leaves room for exactly 100 more
	underCap := testRouteCapture(2500 - helloByteCount - 100)
	go client.conn.Write(underCap)
	if got := receiver.readFull(t, len(underCap)); !bytes.Equal(got, underCap) {
		t.Fatal("the bytes under the cap changed")
	}
	go client.conn.Write(testRouteCapture(101))
	client.expectEnd()
	router.service.AwaitSessionCount(0)
	if rest, _ := io.ReadAll(receiver.reader); 0 < len(rest) {
		t.Errorf("%d bytes past the cap reached the receiver", len(rest))
	}
	records := router.flushRecords()
	if len(records) != 1 || records[0].Result != "splice_byte_cap" || records[0].ByteCount != int64(2500-100) {
		t.Errorf("records %+v", records)
	}
}

// A network's own mail_inbound_message_bytes, once loaded, bounds its splices in place of the cold cap.
func TestSpliceTakesTheNetworksMessageCap(t *testing.T) {
	router := newTestRouter(t, &testRouterOptions{settings: func(settings *mxedgeservice.MxEdgeSettings) {
		settings.ColdMessageByteCount = 100000
		settings.SpliceMessageMultiple = 2
		settings.SpliceExtraByteCount = 500
	}})
	router.host.Quota.SetLimits(connect.Id(router.networkId), &sidecar.QuotaLimits{Tier: "pro", Limits: map[string]int64{"mail_inbound_message_bytes": 1000}})
	// the first session asks for the network's limits, loaded off its path
	client, receiver := router.dialFrom(testSender, testRouteSni)
	receiver.writer.Close()
	client.expectEnd()
	router.service.AwaitSessionCount(0)
	router.service.AwaitMessageLimitsPass(2)

	client, receiver = router.dialFrom("198.51.100.3", testRouteSni)
	go client.conn.Write(testRouteCapture(3000))
	client.expectEnd()
	router.service.AwaitSessionCount(0)
	records := router.flushRecords()
	if len(records) != 2 || records[1].Result != "splice_byte_cap" || 2500 < records[1].ByteCount {
		t.Errorf("records %+v", records)
	}
	io.ReadAll(receiver.reader)
}

// A splice ends at its ticket's grant expiry, revoked.
func TestSpliceEndsAtTheGrantExpiry(t *testing.T) {
	router := newTestRouter(t, &testRouterOptions{settings: testSpliceSettings})
	expireTime := router.clock.Now().Add(4 * time.Minute)
	router.dialer.answer(&testDialAnswer{grantExpireTimeMillis: uint64(expireTime.UnixMilli())})
	client, receiver, _ := router.splice(testSender)
	router.awaitTimerAt(expireTime)
	router.clock.AdvanceTo(expireTime)
	router.expectSpliceEnd(client, receiver, "expired", protocol.StreamResetCode_RST_REVOKED)
}

// The server's end of a sender's pipe whose reads fail as a reset would, once the test resets it.
type testResetConn struct {
	net.Conn
	sender net.Addr
	reset  atomic.Bool
}

var errTestConnReset = errors.New("connection reset by peer")

func (self *testResetConn) RemoteAddr() net.Addr {
	return self.sender
}

func (self *testResetConn) Read(b []byte) (int, error) {
	n, err := self.Conn.Read(b)
	if self.reset.Load() {
		return n, errTestConnReset
	}
	return n, err
}

// The sender resets: what the router reads from it fails as a reset.
func (self *testResetConn) injectReset() {
	self.reset.Store(true)
	self.Conn.Close()
}

// A sender's FIN maps to StreamClose, and the receiver's close then ends the splice cleanly, resetting
// nothing.
func TestSpliceMapsAFinToStreamClose(t *testing.T) {
	router := newTestRouter(t, nil)
	client, receiver := router.dialFrom(testSender, testRouteSni)
	client.conn.Close()
	if rest, err := io.ReadAll(receiver.reader); err != nil || 0 < len(rest) {
		t.Errorf("the receiver read %q, %v before the StreamClose", rest, err)
	}
	receiver.writer.Close()
	router.service.AwaitSessionCount(0)
	if codes := receiver.stream.ResetCodes(); 0 < len(codes) {
		t.Errorf("a clean end reset the stream with %v", codes)
	}
	if records := router.flushRecords(); len(records) != 1 || records[0].Result != "splice_closed" {
		t.Errorf("records %+v", records)
	}
}

// A sender's reset maps to StreamReset, and a receiver's StreamReset to a reset of the sender.
func TestSpliceMapsResets(t *testing.T) {
	router := newTestRouter(t, nil)
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close() })
	resetConn := &testResetConn{Conn: serverConn, sender: &net.TCPAddr{IP: net.ParseIP(testSender), Port: 2525}}
	router.listener.conns <- resetConn
	client := &testClient{t: t, conn: clientConn, reader: bufio.NewReader(clientConn)}
	client.expect("220 " + testBannerHostName + " ESMTP")
	client.write("EHLO " + testRouteEhlo + "\r\n")
	client.expectEhlo()
	quietAt := router.clock.Now().Add(router.settings.StartTlsQuietTimeout)
	client.write("STARTTLS\r\n")
	router.awaitTimerAt(quietAt)
	router.clock.Advance(router.settings.StartTlsQuietTimeout)
	client.expect("220 2.0.0 Ready to start TLS")
	client.write(string(testRouterHello(testRouteSni, 64)))
	receiver := <-router.dialer.dialing
	resetConn.injectReset()
	router.service.AwaitSessionCount(0)
	if codes := receiver.stream.ResetCodes(); !slices.Equal(codes, []protocol.StreamResetCode{protocol.StreamResetCode_RST_CANCELLED}) {
		t.Errorf("the sender's reset reset the stream with %v", codes)
	}

	client, receiver = router.dialFrom("198.51.100.5", testRouteSni)
	receiver.writer.CloseWithError(io.ErrUnexpectedEOF)
	client.expectEnd()
	router.service.AwaitSessionCount(0)
	records := router.flushRecords()
	if len(records) != 2 || records[0].Result != "splice_sender_reset" || records[1].Result != "splice_receiver_reset" {
		t.Errorf("records %+v", records)
	}
}

// Every byte both ways is spent from the network's lease on meter mx, the hello's included, and reaches
// the usage the drain sends: the network pays exactly what moved.
func TestSpliceSpendsTheLeaseByteForByte(t *testing.T) {
	router := newTestRouter(t, nil)
	client, receiver := router.dialFrom(testSender, testRouteSni)
	toReceiver := testRouteCapture(40000)
	go client.conn.Write(toReceiver)
	receiver.readFull(t, len(toReceiver))
	toSender := testRouteCapture(25000)
	go receiver.writer.Write(toSender)
	if _, err := io.ReadFull(client.reader, make([]byte, len(toSender))); err != nil {
		t.Fatal(err)
	}
	receiver.writer.Close()
	client.expectEnd()
	router.service.AwaitSessionCount(0)
	router.service.Drain()
	want := int64(len(testRouterHello(testRouteSni, 64)) + len(toReceiver) + len(toSender))
	if used := router.host.Quota.TransferUsed(connect.Id(router.networkId), sidecar.QuotaMeterMx); used != want {
		t.Errorf("the network paid %d bytes on meter mx, want %d", used, want)
	}
	if used := router.host.Quota.TransferUsed(connect.Id(router.networkId), sidecar.QuotaMeterTls); used != 0 {
		t.Errorf("the network paid %d bytes on meter tls", used)
	}
}

// A lease that runs out resets every splice of its network with RST_QUOTA. The chunk it could not pay
// for never moves. A spent network's next session asks Quota again, which TestRouterClosesEach...'s
// spent row answers with a refusal.
func TestSpliceLeaseRunOutResetsTheNetwork(t *testing.T) {
	router := newTestRouter(t, &testRouterOptions{balance: 1000})
	first, firstReceiver := router.dialFrom(testSender, testRouteSni)
	second, secondReceiver := router.dialFrom("198.51.100.6", testRouteSni)
	// both past their setup, each hello paid for, before the lease runs out
	router.service.AwaitSpliceCount(2)
	go first.conn.Write(testRouteCapture(2000))
	first.expectEnd()
	second.expectEnd()
	router.service.AwaitSessionCount(0)
	for _, receiver := range []*testReceiver{firstReceiver, secondReceiver} {
		if codes := receiver.stream.ResetCodes(); !slices.Equal(codes, []protocol.StreamResetCode{protocol.StreamResetCode_RST_QUOTA}) {
			t.Errorf("a spent network's splice reset with %v", codes)
		}
	}
	if rest, _ := io.ReadAll(firstReceiver.reader); 0 < len(rest) {
		t.Errorf("%d bytes the lease could not pay for reached the receiver", len(rest))
	}
	records := router.flushRecords()
	if len(records) != 2 || records[0].Result != "splice_quota" || records[1].Result != "splice_quota" {
		t.Errorf("records %+v", records)
	}
}

// A drain whose wait runs out resets what is still spliced with RST_DRAINING.
func TestSpliceDrainResets(t *testing.T) {
	router := newTestRouter(t, &testRouterOptions{settings: func(settings *mxedgeservice.MxEdgeSettings) {
		testSpliceSettings(settings)
		settings.DrainTimeout = 3 * time.Minute
	}})
	client, receiver, _ := router.splice(testSender)
	drained := make(chan struct{})
	drainAt := router.clock.Now().Add(router.settings.DrainTimeout)
	go func() {
		router.service.Drain()
		close(drained)
	}()
	router.awaitTimerAt(drainAt)
	router.clock.AdvanceTo(drainAt)
	<-drained
	router.expectSpliceEnd(client, receiver, "drain", protocol.StreamResetCode_RST_DRAINING)
}

// MailIngress at maximal fields fits 1,024 B: ptr_name drops first, then ip_listings from the end, and
// version, sender, port, SNI, EHLO and time are never dropped.
func TestMailIngressAtMaximalFieldsFits(t *testing.T) {
	format := sidecar.DefaultMailIngressFormatSettings()
	label := strings.Repeat("a", 61) + "."
	sni := strings.Repeat(label, 5)[:253]
	ehlo := strings.Repeat("e", 255)
	ptr := strings.Repeat("p", 253)
	listings := []string{}
	for i := range 20 {
		listings = append(listings, strings.Repeat(string(rune('a'+i)), 12))
	}
	listings = append([]string{"far-too-long-category"}, listings...)
	sender := netip.MustParseAddrPort("[2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]:65535")
	receiveTime := sidecartest.DefaultClockStart()
	data, err := mxedgeservice.BuildMailIngress(format, sender, sni, ehlo, ptr, listings, receiveTime)
	if err != nil {
		t.Fatal(err)
	}
	if format.MaxByteCount < len(data) {
		t.Fatalf("%d bytes", len(data))
	}
	ingress := &protocol.MailIngress{}
	if err := proto.Unmarshal(data, ingress); err != nil {
		t.Fatal(err)
	}
	if ingress.GetVersion() != sidecar.MailIngressVersion || !bytes.Equal(ingress.GetSenderIp(), sender.Addr().AsSlice()) ||
		ingress.GetSenderPort() != 65535 || ingress.GetSni() != sni || ingress.GetEhloName() != ehlo ||
		ingress.GetReceiveTimeMillis() != uint64(receiveTime.UnixMilli()) {
		t.Errorf("a field that is never dropped went: %v", ingress)
	}
	if ingress.GetPtrName() != "" {
		t.Error("ptr_name stayed while the message was past its bound")
	}
	if len(ingress.GetIpListings()) == 0 || format.ListingMaxCount < len(ingress.GetIpListings()) ||
		ingress.GetIpListings()[0] != strings.Repeat("a", 12) {
		t.Errorf("ip_listings %v", ingress.GetIpListings())
	}

	// with room, nothing drops, the long category aside and the count held to 16
	data, err = mxedgeservice.BuildMailIngress(format, netip.MustParseAddrPort("203.0.113.9:2525"), "mx.ab12cd34ef.root.example", "relay.example", "ptr.example", listings, receiveTime)
	if err != nil {
		t.Fatal(err)
	}
	ingress = &protocol.MailIngress{}
	if err := proto.Unmarshal(data, ingress); err != nil {
		t.Fatal(err)
	}
	if ingress.GetPtrName() != "ptr.example" || len(ingress.GetIpListings()) != format.ListingMaxCount || len(ingress.GetSenderIp()) != 4 {
		t.Errorf("%v", ingress)
	}
	if _, err := mxedgeservice.BuildMailIngress(format, netip.AddrPort{}, sni, ehlo, "", nil, receiveTime); err == nil {
		t.Error("built with no sender")
	}
	if _, err := mxedgeservice.BuildMailIngress(format, sender, "", ehlo, "", nil, receiveTime); err == nil {
		t.Error("built with no SNI")
	}
}
