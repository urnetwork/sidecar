// The composed engine: Serve, on a pipe, with fake stores and the fake clock. Each §15.4 row but the
// splice, which waits for MAIL-M7-19's router, and the engine's lifecycle.

package mxedgeservice_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A metric's value by its name, on the engine's single result label.
func (self *testEngine) metric(name string, result string) float64 {
	return self.host.Metrics.Value("urnetwork_mxedge_"+name, result)
}

// How many {mxc_} keys Redis holds.
func (self *testEngine) memoryKeyCount() int {
	count := 0
	for key := range self.host.Redis.Dump() {
		if strings.HasPrefix(key, "{mxc_") {
			count += 1
		}
	}
	return count
}

func TestSessionGreetsAnswersAndQuits(t *testing.T) {
	engine := newTestEngine(t, nil)
	client := engine.open(testSender)
	client.write("EHLO relay.example\r\n")
	client.expectEhlo()
	client.write("QUIT\r\n")
	client.expect("221 2.0.0 Bye")
	client.expectEnd()
	engine.service.AwaitSessionCount(0)
	if count := engine.metric("sessions_total", "quit"); count != 1 {
		t.Errorf("counted %v", count)
	}
}

// §15.4's SNI rows. No route exists yet, so every name is unknown, and a hello with none or a bad one
// closes the same way: a temporary failure, with the memory written.
func TestStartTlsClosesInTheHandshake(t *testing.T) {
	for _, c := range []struct {
		name      string
		hello     string
		wantAlert mxedgeservice.MxTlsAlert
	}{
		{name: "an unknown name", hello: "hello mx.net.example", wantAlert: mxedgeservice.MxTlsAlertUnrecognizedName},
		{name: "no name", hello: "hello", wantAlert: mxedgeservice.MxTlsAlertUnrecognizedName},
		{name: "a bad hello", hello: "not tls", wantAlert: mxedgeservice.MxTlsAlertDecodeError},
	} {
		engine := newTestEngine(t, nil)
		client := engine.open(testSender)
		client.write("EHLO relay.example\r\n")
		client.expectEhlo()
		engine.startTls(client)
		client.write(c.hello)
		client.expectBytes(testAlertRecord(c.wantAlert))
		// the memory is there by the time the sender can see the close
		if count := engine.memoryKeyCount(); count != 1 {
			t.Errorf("%s: %d keys after the alert", c.name, count)
		}
		client.expectEnd()
		engine.service.AwaitSessionCount(0)
		if count := engine.metric("sessions_total", "closed_handshake"); count != 1 {
			t.Errorf("%s: counted %v", c.name, count)
		}
		if count := engine.metric("closed_handshake_writes_total", "written"); count != 1 {
			t.Errorf("%s: writes %v", c.name, count)
		}
	}
}

// A handshake that dies is still one the sender may retry in plaintext.
func TestHelloThatNeverComesClosesInItsTime(t *testing.T) {
	// the hello's timer is armed before the read starts, so this says it is there to move past
	reading := make(chan struct{})
	engine := newTestEngine(t, &testEngineOptions{
		deps: func(deps *mxedgeservice.MxEdgeDeps) {
			deps.ReadClientHello = func(conn net.Conn, maxByteCount int) (*mxedgeservice.MxClientHello, error) {
				close(reading)
				return testReadClientHello(conn, maxByteCount)
			}
		},
	})
	client := engine.open(testSender)
	engine.startTls(client)
	<-reading
	engine.clock.Advance(engine.settings.ClientHelloTimeout)
	client.expectEnd()
	engine.service.AwaitSessionCount(0)
	if count := engine.memoryKeyCount(); count != 1 {
		t.Errorf("%d keys", count)
	}
}

// The dialog's bound stops at the handoff, so a hello is held to its own and no other.
func TestHandoffStopsTheDialogsBound(t *testing.T) {
	reading := make(chan struct{})
	engine := newTestEngine(t, &testEngineOptions{
		deps: func(deps *mxedgeservice.MxEdgeDeps) {
			deps.ReadClientHello = func(conn net.Conn, maxByteCount int) (*mxedgeservice.MxClientHello, error) {
				close(reading)
				return testReadClientHello(conn, maxByteCount)
			}
		},
	})
	client := engine.open(testSender)
	engine.clock.Advance(engine.settings.DialogTimeout - time.Second)
	engine.startTls(client)
	<-reading
	// past where the dialog's bound would have fallen, and inside the hello's
	engine.clock.Advance(time.Second)
	client.write("hello")
	client.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertUnrecognizedName))
	client.expectEnd()
}

// With no way to read a hello the session still closes in the handshake and is remembered.
func TestMissingHelloReaderStillClosesTheHandshake(t *testing.T) {
	engine := newTestEngine(t, &testEngineOptions{
		deps: func(deps *mxedgeservice.MxEdgeDeps) {
			deps.ReadClientHello = nil
		},
	})
	client := engine.open(testSender)
	engine.startTls(client)
	client.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertInternalError))
	client.expectEnd()
	engine.service.AwaitSessionCount(0)
	if count := engine.memoryKeyCount(); count != 1 {
		t.Errorf("%d keys", count)
	}
}

func TestMissingAlertWriterStillCloses(t *testing.T) {
	engine := newTestEngine(t, &testEngineOptions{
		deps: func(deps *mxedgeservice.MxEdgeDeps) {
			deps.WriteTlsAlert = nil
		},
	})
	client := engine.open(testSender)
	engine.startTls(client)
	client.write("hello")
	client.expectEnd()
}

// A failed write of the memory cannot hold the close up.
func TestRedisErrorStillClosesTheHandshake(t *testing.T) {
	engine := newTestEngine(t, nil)
	_, err := engine.host.Redis.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpRedis, KeyPrefix: "{mxc_", Result: sidecartest.FailBeforeApply,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := engine.open(testSender)
	engine.startTls(client)
	client.write("hello")
	client.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertUnrecognizedName))
	client.expectEnd()
	engine.service.AwaitSessionCount(0)
	if count := engine.metric("closed_handshake_writes_total", "failed"); count != 1 {
		t.Errorf("counted %v", count)
	}
}

// §15.4's plaintext row with nothing remembered.
func TestPlaintextGets530WithNoClosedHandshake(t *testing.T) {
	engine := newTestEngine(t, nil)
	client := engine.open(testSender)
	client.write("MAIL FROM:<a@relay.example>\r\n")
	client.expect(strings.TrimSuffix(testReply530, "\r\n"))
	client.write("RCPT TO:<b@net.example>\r\n")
	client.expect(strings.TrimSuffix(testReply530, "\r\n"))
	client.write("DATA\r\n")
	client.expect(strings.TrimSuffix(testReply530, "\r\n"))
	client.write("BDAT 1 LAST\r\n")
	client.expect(strings.TrimSuffix(testReply530, "\r\n"))
}

// The same row in two processes: one closes a handshake, a sibling address reaches the other.
func TestPlaintextGets451AfterAClosedHandshakeElsewhere(t *testing.T) {
	first := newTestEngine(t, nil)
	second := newTestEngine(t, &testEngineOptions{clock: first.clock, host: first.host})
	first.closeHandshakeFrom(testSender)
	if code := second.plaintextReplyTo("203.0.113.200"); code != "451" {
		t.Errorf("got %s", code)
	}
	if code := second.plaintextReplyTo("203.0.114.9"); code != "530" {
		t.Errorf("another /24 got %s", code)
	}
}

func TestPlaintextGets451ForTheHourAnd530After(t *testing.T) {
	first := newTestEngine(t, nil)
	second := newTestEngine(t, &testEngineOptions{clock: first.clock, host: first.host})
	first.closeHandshakeFrom(testSender)

	first.clock.Advance(59 * time.Minute)
	if code := second.plaintextReplyTo(testSender); code != "451" {
		t.Errorf("at 59 min got %s", code)
	}
	first.clock.Advance(2 * time.Minute)
	if code := second.plaintextReplyTo(testSender); code != "530" {
		t.Errorf("at 61 min got %s", code)
	}
}

func TestPlaintextGets451AcrossMidnightUtc(t *testing.T) {
	writeTime := time.Date(2026, time.March, 31, 23, 50, 0, 0, time.UTC)
	clock := sidecartest.NewFakeClock(writeTime)
	first := newTestEngine(t, &testEngineOptions{clock: clock})
	second := newTestEngine(t, &testEngineOptions{clock: clock, host: first.host})
	first.closeHandshakeFrom(testSender)

	// the clock stops at midnight while both probes read the new day's k: a move straight past it would
	// fire a probe's own store bound mid-read, failing the probe, whose next is a day away
	midnight := writeTime.Add(10 * time.Minute)
	clock.AdvanceTo(midnight)
	if clock.Now().Day() == writeTime.Day() {
		t.Fatal("the clock has not crossed midnight")
	}
	// both probes ran at the date change, so the 451 below is the memory's and not a missing k's
	first.service.AwaitKeyDay(midnight)
	second.service.AwaitKeyDay(midnight)
	clock.AdvanceTo(writeTime.Add(20 * time.Minute))
	if code := second.plaintextReplyTo(testSender); code != "451" {
		t.Errorf("at 00:10 got %s", code)
	}
	if count := second.metric("closed_handshake_reads_total", "recent"); count != 1 {
		t.Errorf("%v reads found the memory", count)
	}
	clock.AdvanceTo(writeTime.Add(61 * time.Minute))
	if code := second.plaintextReplyTo(testSender); code != "530" {
		t.Errorf("at 00:51 got %s", code)
	}
}

// The probe that comes at the date change reads the new day's k then, not a probe interval later, and
// the first process to get there makes it.
func TestProbeReadsTheNewDaysKeyAtTheDateChange(t *testing.T) {
	start := time.Date(2026, time.March, 31, 23, 59, 0, 0, time.UTC)
	engine := newTestEngine(t, &testEngineOptions{clock: sidecartest.NewFakeClock(start)})
	probeCount := engine.service.ProbeCount()
	engine.clock.AdvanceTo(start.Add(time.Minute))
	engine.service.AwaitProbeCount(probeCount + 1)
	engine.service.AwaitKeyDay(engine.clock.Now())
	if _, found := engine.host.Redis.Dump()["{vhk}mx:20260401"]; !found {
		t.Error("no k for the new day")
	}
	if count := engine.metric("daily_key_refreshes_total", "created"); count != 1 {
		t.Errorf("made %v", count)
	}
	if code := engine.plaintextReplyTo(testSender); code != "530" {
		t.Errorf("got %s", code)
	}
	if count := engine.metric("closed_handshake_reads_total", "absent"); count != 1 {
		t.Errorf("%v reads answered", count)
	}
}

// §22.5's other half of the 451 rule.
func TestClosedGateAnswers451AndAsksNoOne(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.gateOpen.Store(false)
	engine.host.Redis.ResetOpCounts()
	if code := engine.plaintextReplyTo(testSender); code != "451" {
		t.Errorf("got %s", code)
	}
	if counts := engine.host.Redis.OpCounts(); len(counts) != 0 {
		t.Errorf("redis calls: %v", counts)
	}
}

// A host that wired no gate gets a dark engine, which never says 530.
func TestNoGateReadsAsClosed(t *testing.T) {
	engine := newTestEngine(t, &testEngineOptions{
		deps: func(deps *mxedgeservice.MxEdgeDeps) {
			deps.GateOpen = nil
		},
	})
	if code := engine.plaintextReplyTo(testSender); code != "451" {
		t.Errorf("got %s", code)
	}
}

func TestGateIsReadAtEachSession(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.gateOpen.Store(false)
	if code := engine.plaintextReplyTo(testSender); code != "451" {
		t.Errorf("closed got %s", code)
	}
	engine.gateOpen.Store(true)
	if code := engine.plaintextReplyTo(testSender); code != "530" {
		t.Errorf("open got %s", code)
	}
}

func TestRedisErrorTellsASenderToRetry(t *testing.T) {
	engine := newTestEngine(t, nil)
	_, err := engine.host.Redis.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpRedis, KeyPrefix: "{mxc_", Result: sidecartest.FailBeforeApply, Repeat: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if code := engine.plaintextReplyTo(testSender); code != "451" {
		t.Errorf("got %s", code)
	}
	if count := engine.metric("closed_handshake_reads_total", "failed"); count != 1 {
		t.Errorf("counted %v", count)
	}
}

// A Redis that hangs costs a sender StoreTimeout, then the same retry.
func TestRedisStallTellsASenderToRetry(t *testing.T) {
	engine := newTestEngine(t, nil)
	_, err := engine.host.Redis.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpRedis, KeyPrefix: "{mxc_", Result: sidecartest.Delay, Delay: sidecartest.DelayNeverLands,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := engine.open(testSender)
	timerCount := len(engine.clock.PendingTimers())
	client.write("MAIL FROM:<a@relay.example>\r\n")
	// the engine's bound and the fake's own request timeout
	if err := engine.clock.AwaitTimers(engine.ctx, timerCount+2); err != nil {
		t.Fatal(err)
	}
	engine.clock.Advance(engine.settings.StoreTimeout)
	client.expect(strings.TrimSuffix(testReply451, "\r\n"))
}

// §22.5's op count: a plaintext session costs one read past a day's first hour, and two within it,
// however many commands it tries. closed_handshake_test.go counts the first hour's.
func TestPlaintextSessionCostsOneRedisReadPastTheFirstHour(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.host.Redis.ResetOpCounts()
	client := engine.open(testSender)
	for _, line := range []string{"MAIL FROM:<a@relay.example>\r\n", "RCPT TO:<b@net.example>\r\n", "DATA\r\n"} {
		client.write(line)
		client.expect(strings.TrimSuffix(testReply530, "\r\n"))
	}
	if counts := engine.host.Redis.OpCounts(); counts["get"] != 1 || len(counts) != 1 {
		t.Errorf("calls: %v", counts)
	}
}

// A byte in the same read as the line.
func TestByteBehindStartTlsResetsInOneRead(t *testing.T) {
	engine := newTestEngine(t, nil)
	client := engine.open(testSender)
	client.write("STARTTLS\r\nX")
	client.expectEnd()
	engine.service.AwaitSessionCount(0)
	if count := engine.metric("sessions_total", "reset"); count != 1 {
		t.Errorf("counted %v", count)
	}
	// nothing reached TLS, so no handshake closed
	if count := engine.memoryKeyCount(); count != 0 {
		t.Errorf("%d keys", count)
	}
}

// A byte in a read of its own, after the line: the 220 waits for the quiet period, so it is caught.
// The pipe's write returns only once the engine has read the byte, so this order is exact.
func TestByteBehindStartTlsResetsInALaterRead(t *testing.T) {
	engine := newTestEngine(t, nil)
	client := engine.open(testSender)
	client.write("STARTTLS\r\n")
	client.write("X")
	client.expectEnd()
	engine.service.AwaitSessionCount(0)
	if count := engine.metric("sessions_total", "reset"); count != 1 {
		t.Errorf("counted %v", count)
	}
}

func TestByteBehindStartTlsResetsWithTheLineSplitAcrossReads(t *testing.T) {
	engine := newTestEngine(t, nil)
	client := engine.open(testSender)
	client.write("START")
	client.write("TLS\r")
	client.write("\nX")
	client.expectEnd()
}

// A sender gone before its 220 gets none.
func TestSenderGoneBehindStartTlsResets(t *testing.T) {
	engine := newTestEngine(t, nil)
	client := engine.open(testSender)
	timerCount := len(engine.clock.PendingTimers())
	client.write("STARTTLS\r\n")
	if err := engine.clock.AwaitTimers(engine.ctx, timerCount+1); err != nil {
		t.Fatal(err)
	}
	client.conn.Close()
	engine.service.AwaitSessionCount(0)
	if count := engine.metric("sessions_total", "reset"); count != 1 {
		t.Errorf("counted %v", count)
	}
}

// What the quiet period costs an honest sender is the period itself, and the read it took left the
// connection usable: the hello reads as if nothing happened.
func TestQuietPeriodLeavesTheConnectionReadable(t *testing.T) {
	var helloName string
	engine := newTestEngine(t, &testEngineOptions{
		deps: func(deps *mxedgeservice.MxEdgeDeps) {
			deps.ReadClientHello = func(conn net.Conn, maxByteCount int) (*mxedgeservice.MxClientHello, error) {
				hello, err := testReadClientHello(conn, maxByteCount)
				if err == nil {
					helloName = hello.ServerName
				}
				return hello, err
			}
		},
	})
	client := engine.open(testSender)
	engine.startTls(client)
	client.write("hello mx.net.example")
	client.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertUnrecognizedName))
	if helloName != "mx.net.example" {
		t.Errorf("read %q", helloName)
	}
}

// On a real socket a reset is a reset: the peer sees ECONNRESET, not an orderly end of stream. The
// listener takes an ephemeral loopback port, and the dial goes only there.
func TestResetReachesARealPeerAsAReset(t *testing.T) {
	engine := newTestEngine(t, nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() {
		served <- engine.service.Serve(listener)
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	banner := make([]byte, len("220 "+testBannerHostName+" ESMTP\r\n"))
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("STARTTLS\r\nX")); err != nil {
		t.Fatal(err)
	}
	if rest, err := io.ReadAll(conn); !errors.Is(err, syscall.ECONNRESET) || 0 < len(rest) {
		t.Errorf("read %q and %v", rest, err)
	}
	listener.Close()
	if err := <-served; err != nil {
		t.Errorf("served %v", err)
	}
}

// The production combination, which the pipes above stand in for: a real socket, real timers and
// crypto/tls for a sender. The quiet period's read deadline has to clear on a real conn, or the hello
// would never be read, and a real client has to see the alert as a failed handshake. The listener takes
// an ephemeral loopback port, and the dial goes only there.
func TestRealSenderFailsInTheHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	host := sidecartest.NewFakeHost(ctx, nil, nil, nil, nil)
	service, err := mxedgeservice.NewMxEdgeService(ctx, host.ServiceHost(), sidecartest.NewFakeMxEdgeStore(nil), &mxedgeservice.MxEdgeDeps{
		// a real hello is no scripted one, so this takes whatever arrives for a hello naming nothing
		ReadClientHello: func(conn net.Conn, maxByteCount int) (*mxedgeservice.MxClientHello, error) {
			buffer := make([]byte, maxByteCount)
			byteCount, err := conn.Read(buffer)
			return &mxedgeservice.MxClientHello{RawBytes: buffer[:byteCount]}, err
		},
		NormalizeSni:  testNormalizeSni,
		WriteTlsAlert: testWriteTlsAlert,
		GateOpen:      func() bool { return true },
	}, testSettings())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go service.Serve(listener)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := &testClient{t: t, conn: conn, reader: bufio.NewReader(conn)}
	client.expect("220 " + testBannerHostName + " ESMTP")
	client.write("EHLO relay.example\r\n")
	client.expectEhlo()
	client.write("STARTTLS\r\n")
	client.expect("220 2.0.0 Ready to start TLS")

	// crypto/tls keeps its alert type to itself, so its text is what there is to read
	err = tls.Client(conn, &tls.Config{ServerName: "mx.net.example"}).Handshake()
	if err == nil || !strings.Contains(err.Error(), "remote error: tls: unrecognized name") {
		t.Errorf("the handshake ended with %v", err)
	}
	service.AwaitSessionCount(0)
	if keys := memoryKeys(host.Redis.Dump()); len(keys) != 1 {
		t.Errorf("%d keys", len(keys))
	}
}

// A sender that shuts its side behind STARTTLS has sent an end of stream where only silence may stand.
// A pipe cannot show this, since its deadline fails once the peer is gone: only on a real socket does
// the read's answer alone decide.
func TestHalfClosedSenderGetsNo220(t *testing.T) {
	engine := newTestEngine(t, nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go engine.service.Serve(listener)
	conn, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := &testClient{t: t, conn: conn, reader: bufio.NewReader(conn)}
	client.expect("220 " + testBannerHostName + " ESMTP")
	client.write("STARTTLS\r\n")
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// the fake clock stands still, so no quiet period can pass: only the end of stream can end this
	rest, err := io.ReadAll(client.reader)
	if 0 < len(rest) {
		t.Errorf("read %q and %v", rest, err)
	}
	engine.service.AwaitSessionCount(0)
	if count := engine.metric("sessions_total", "reset"); count != 1 {
		t.Errorf("counted %v", count)
	}
}

// A wrapper hides SetLinger, and NetConn is how a reset still gets through.
func TestResetGetsThroughAWrapper(t *testing.T) {
	// not zero, or a linger never set would read as the one wanted
	inner := &lingerConn{linger: -1}
	mxedgeservice.ResetConnection(&wrappedConn{inner: inner})
	if inner.linger != 0 || !inner.closed {
		t.Errorf("linger %d, closed %v", inner.linger, inner.closed)
	}
}

// Records SetLinger's argument. The rest of net.Conn is nil and never called.
type lingerConn struct {
	net.Conn
	linger int
	closed bool
}

// Records the argument.
func (self *lingerConn) SetLinger(seconds int) error {
	self.linger = seconds
	return nil
}

// Records the close.
func (self *lingerConn) Close() error {
	self.closed = true
	return nil
}

// Hides SetLinger behind NetConn, as a host's PROXY conn may.
type wrappedConn struct {
	net.Conn
	inner net.Conn
}

// What it wraps.
func (self *wrappedConn) NetConn() net.Conn {
	return self.inner
}

// Closes what it wraps.
func (self *wrappedConn) Close() error {
	return self.inner.Close()
}

// A sender who writes only part of its limit cannot hold the session past the dialog's bound.
func TestDialogEndsAtItsTimeout(t *testing.T) {
	engine := newTestEngine(t, nil)
	client := engine.open(testSender)
	client.write("EHLO relay.example\r\n")
	client.expectEhlo()
	client.write("EH")
	engine.clock.Advance(engine.settings.DialogTimeout - time.Second)
	client.write("L")
	engine.clock.Advance(time.Second)
	client.expectEnd()
	engine.service.AwaitSessionCount(0)
	if count := engine.metric("sessions_total", "ended"); count != 1 {
		t.Errorf("counted %v", count)
	}
}

func TestSessionPast2048BytesCloses(t *testing.T) {
	engine := newTestEngine(t, nil)
	client := engine.open(testSender)
	lines := testNoiseLines(mxedgeservice.DialogMaxByteCount)
	client.write(lines + "N")
	for range strings.Count(lines, "\r\n") {
		client.expect("502 5.5.1 Command not implemented")
	}
	client.expectEnd()
	engine.service.AwaitSessionCount(0)
	if count := engine.metric("sessions_total", "limit"); count != 1 {
		t.Errorf("counted %v", count)
	}
}

func TestSessionPast510ByteLineCloses(t *testing.T) {
	engine := newTestEngine(t, nil)
	client := engine.open(testSender)
	client.write(strings.Repeat("N", mxedgeservice.DialogMaxLineByteCount+1))
	client.expectEnd()
}

// A sender writing without end costs at most one read past the limit: the write fails, not the engine.
func TestSenderFloodingTheDialogIsCut(t *testing.T) {
	engine := newTestEngine(t, nil)
	client := engine.open(testSender)
	_, err := client.conn.Write(make([]byte, 1024*1024))
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("wrote through: %v", err)
	}
}

// §15.4's cap rows at the banner, each answered 421 and closed.
func TestSessionsOverACapGet421(t *testing.T) {
	for _, c := range []struct {
		name       string
		sender     func(i int) string
		count      func(settings *mxedgeservice.MxEdgeSettings) int
		wantResult string
	}{
		{
			name:       "per /32",
			sender:     func(i int) string { return testSender },
			count:      func(settings *mxedgeservice.MxEdgeSettings) int { return settings.SenderSessionCount },
			wantResult: "sender",
		},
		{
			name:       "per /64",
			sender:     func(i int) string { return fmt.Sprintf("2001:db8:1:2::%x", i+1) },
			count:      func(settings *mxedgeservice.MxEdgeSettings) int { return settings.SenderSessionCount },
			wantResult: "sender",
		},
		{
			name:       "per /24",
			sender:     func(i int) string { return fmt.Sprintf("203.0.113.%d", i+1) },
			count:      func(settings *mxedgeservice.MxEdgeSettings) int { return settings.SenderAggregateSessionCount },
			wantResult: "sender_aggregate",
		},
		{
			name:       "per /48",
			sender:     func(i int) string { return fmt.Sprintf("2001:db8:1:%x::1", i+1) },
			count:      func(settings *mxedgeservice.MxEdgeSettings) int { return settings.SenderAggregateSessionCount },
			wantResult: "sender_aggregate",
		},
	} {
		engine := newTestEngine(t, nil)
		count := c.count(engine.settings)
		for i := range count {
			engine.open(c.sender(i))
		}
		over := engine.dial(c.sender(count))
		over.expect("421 4.7.0 " + testBannerHostName + " Too many sessions, try again later")
		over.expectEnd()
		if refused := engine.metric("cap_refusals_total", c.wantResult); refused != 1 {
			t.Errorf("%s: counted %v", c.name, refused)
		}
		if refused := engine.metric("sessions_total", "over_cap"); refused != 1 {
			t.Errorf("%s: counted %v sessions", c.name, refused)
		}
	}
}

func TestProcessCapGets421(t *testing.T) {
	settings := testSettings()
	settings.ProcessSessionCount = 2
	engine := newTestEngine(t, &testEngineOptions{settings: settings})
	engine.open("192.0.2.1")
	engine.open("198.51.100.1")
	over := engine.dial("203.0.113.1")
	over.expect("421 4.7.0 " + testBannerHostName + " Too many sessions, try again later")
	over.expectEnd()
}

func TestSessionEndingFreesItsPlace(t *testing.T) {
	settings := testSettings()
	settings.SenderSessionCount = 1
	engine := newTestEngine(t, &testEngineOptions{settings: settings})
	client := engine.open(testSender)
	client.write("QUIT\r\n")
	client.expect("221 2.0.0 Bye")
	client.expectEnd()
	engine.service.AwaitSessionCount(0)
	engine.open(testSender)
}

// A session held through the handshake keeps its place until it closes.
func TestSessionHoldsItsPlaceThroughTheHandshake(t *testing.T) {
	settings := testSettings()
	settings.SenderSessionCount = 1
	engine := newTestEngine(t, &testEngineOptions{settings: settings})
	client := engine.open(testSender)
	engine.startTls(client)
	over := engine.dial(testSender)
	over.expect("421 4.7.0 " + testBannerHostName + " Too many sessions, try again later")
	over.expectEnd()
	client.write("hello")
	client.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertUnrecognizedName))
	client.expectEnd()
	engine.service.AwaitSessionCount(0)
	engine.open(testSender)
}

// §15.4's listing row, on what MAIL-M7-20 will set. An unset source rejects nothing.
func TestListedSenderGets554AtTheBanner(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.service.SetBannerRefused(func(sender netip.Addr) bool {
		return sender == netip.MustParseAddr(testSender)
	})
	listed := engine.dial(testSender)
	listed.expect("554 5.7.1 " + testBannerHostName + " Service refused")
	listed.write("EHLO relay.example\r\n")
	listed.expect("503 5.5.1 Bad sequence of commands")
	listed.write("QUIT\r\n")
	listed.expect("221 2.0.0 Bye")
	listed.expectEnd()
	engine.open("198.51.100.1")
}

// A peer no cap can count is never greeted.
func TestConnectionWithNoSenderIsDropped(t *testing.T) {
	engine := newTestEngine(t, nil)
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	// a pipe's own RemoteAddr has no address in it
	engine.listener.conns <- serverConn
	if rest, err := io.ReadAll(clientConn); err != nil || 0 < len(rest) {
		t.Errorf("read %q and %v", rest, err)
	}
	engine.service.AwaitSessionCount(0)
	if count := engine.metric("sessions_total", "no_sender"); count != 1 {
		t.Errorf("counted %v", count)
	}
}

func TestSenderAddr(t *testing.T) {
	for _, c := range []struct {
		name string
		addr net.Addr
		want string
	}{
		{name: "IPv4", addr: &net.TCPAddr{IP: net.ParseIP(testSender), Port: 25}, want: testSender},
		{name: "four bytes", addr: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 9).To4(), Port: 25}, want: testSender},
		{name: "IPv6", addr: &net.TCPAddr{IP: net.ParseIP(testSenderIp6), Port: 25}, want: testSenderIp6},
		{name: "mapped", addr: &net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.9"), Port: 25}, want: testSender},
		{name: "a wrapper's address", addr: testAddr("203.0.113.9:25"), want: testSender},
		{name: "a wrapper's mapped address", addr: testAddr("[::ffff:203.0.113.9]:25"), want: testSender},
		{name: "a wrapper's scoped address", addr: testAddr("[2001:db8:1:2:3:4:5:6%eth0]:25"), want: testSenderIp6},
	} {
		sender, ok := mxedgeservice.SenderAddr(c.addr)
		if !ok || sender != netip.MustParseAddr(c.want) {
			t.Errorf("%s: %v and %v", c.name, sender, ok)
		}
	}
}

func TestSenderAddrRefusesWhatHoldsNoAddress(t *testing.T) {
	for _, addr := range []net.Addr{nil, &net.TCPAddr{}, testAddr("pipe"), testAddr("203.0.113.9")} {
		if sender, ok := mxedgeservice.SenderAddr(addr); ok {
			t.Errorf("%v read as %v", addr, sender)
		}
	}
}

// A net.Addr that is only its text.
type testAddr string

// Not a real network.
func (self testAddr) Network() string {
	return "test"
}

// The text.
func (self testAddr) String() string {
	return string(self)
}

func TestNewRefusesWhatCannotRun(t *testing.T) {
	ctx := context.Background()
	host := sidecartest.NewFakeHost(ctx, nil, nil, nil, nil)
	store := sidecartest.NewFakeMxEdgeStore(nil)
	noRedis := host.ServiceHost()
	noRedis.Redis = nil
	noMetrics := host.ServiceHost()
	noMetrics.Metrics = nil
	for _, c := range []struct {
		name     string
		host     *sidecar.ServiceHost
		settings *mxedgeservice.MxEdgeSettings
	}{
		{name: "no host", host: nil, settings: testSettings()},
		{name: "no Redis", host: noRedis, settings: testSettings()},
		{name: "no metrics", host: noMetrics, settings: testSettings()},
		{name: "no settings", host: host.ServiceHost(), settings: nil},
		{name: "the bare defaults", host: host.ServiceHost(), settings: mxedgeservice.DefaultMxEdgeSettings()},
	} {
		if service, err := mxedgeservice.NewMxEdgeService(ctx, c.host, store, nil, c.settings); err == nil {
			service.Close()
			t.Errorf("%s: started", c.name)
		}
	}
}

func TestReadyAfterItsFirstProbe(t *testing.T) {
	engine := newTestEngine(t, nil)
	if !engine.service.Ready() {
		t.Error("not ready")
	}
}

// Each of what a host must supply, left out.
func TestNotReadyWithoutWhatItNeeds(t *testing.T) {
	for name, withhold := range map[string]func(deps *mxedgeservice.MxEdgeDeps){
		"ReadClientHello": func(deps *mxedgeservice.MxEdgeDeps) { deps.ReadClientHello = nil },
		"NormalizeSni":    func(deps *mxedgeservice.MxEdgeDeps) { deps.NormalizeSni = nil },
		"WriteTlsAlert":   func(deps *mxedgeservice.MxEdgeDeps) { deps.WriteTlsAlert = nil },
	} {
		engine := newTestEngine(t, &testEngineOptions{deps: withhold})
		if engine.service.Ready() {
			t.Errorf("ready with no %s", name)
		}
	}
}

// Until a host supplies a store, as MAIL-M7-21's seam says.
func TestNotReadyWithoutAStore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	service, err := mxedgeservice.NewMxEdgeService(ctx, host.ServiceHost(), nil, &mxedgeservice.MxEdgeDeps{
		ReadClientHello: testReadClientHello,
		NormalizeSni:    testNormalizeSni,
		WriteTlsAlert:   testWriteTlsAlert,
		Clock:           clock,
	}, testSettings())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	service.AwaitProbeCount(1)
	if service.Ready() {
		t.Error("ready")
	}
}

// A block that cannot read today's k stays out of the lb, and what reaches it anyway fails closed: a
// plaintext sender is told to retry, and a closed handshake writes nothing under a k no one else holds.
func TestNotReadyWithoutTheDailyKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	_, err := host.Redis.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpRedis, KeyPrefix: mxedgeservice.DailyKeyPrefix, Result: sidecartest.FailBeforeApply, Repeat: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	engine := newTestEngine(t, &testEngineOptions{clock: clock, host: host, unseeded: true, unready: true})
	if engine.service.Ready() {
		t.Error("ready with no k")
	}
	if count := engine.metric("daily_key_refreshes_total", "failed"); count != 1 {
		t.Errorf("counted %v", count)
	}
	if code := engine.plaintextReplyTo(testSender); code != "451" {
		t.Errorf("got %s", code)
	}
	if count := engine.metric("closed_handshake_reads_total", "failed"); count != 1 {
		t.Errorf("counted %v failed reads", count)
	}
	engine.closeHandshakeFrom(testSender)
	if count := engine.memoryKeyCount(); count != 0 {
		t.Errorf("%d keys", count)
	}
	if count := engine.metric("closed_handshake_writes_total", "failed"); count != 1 {
		t.Errorf("counted %v failed writes", count)
	}
}

// With no k in Redis, as on the day's first block, the engine makes it at its first probe.
func TestFirstEngineMakesTheDailyKey(t *testing.T) {
	engine := newTestEngine(t, &testEngineOptions{unseeded: true})
	if !engine.service.Ready() {
		t.Error("not ready")
	}
	if count := engine.metric("daily_key_refreshes_total", "created"); count != 1 {
		t.Errorf("made %v", count)
	}
	dayKey, found := engine.host.Redis.Dump()[mxedgeservice.DailyKeyName(engine.clock.Now())]
	if !found || len(dayKey) != mxedgeservice.DailyKeyByteCount || bytes.Equal(dayKey, testDailyKey) {
		t.Errorf("Redis holds %d bytes, found %v", len(dayKey), found)
	}
	second := newTestEngine(t, &testEngineOptions{clock: engine.clock, host: engine.host, unseeded: true})
	if count := second.metric("daily_key_refreshes_total", "read"); count != 1 {
		t.Errorf("the second read %v", count)
	}
	engine.closeHandshakeFrom(testSender)
	if code := second.plaintextReplyTo(testSender); code != "451" {
		t.Errorf("got %s", code)
	}
}

// §19.11: a closed gate is a state of the service, not of its readiness.
func TestClosedGateStaysReady(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.gateOpen.Store(false)
	if !engine.service.Ready() {
		t.Error("not ready")
	}
}

// Losing a store takes the block out of the lb at the next probe, and finding it again brings it back.
// Redis is found through the probe's read of today's k.
func TestReadyFollowsItsStores(t *testing.T) {
	for _, plan := range []*sidecartest.FaultPlan{
		{Op: sidecartest.FaultOpRedis, KeyPrefix: mxedgeservice.DailyKeyPrefix, Result: sidecartest.FailBeforeApply, Repeat: -1},
		{Op: sidecartest.FaultOpHost, KeyPrefix: "mxedge.Ping", Result: sidecartest.FailBeforeApply, Repeat: -1},
	} {
		settings := testSettings()
		settings.ReadyProbeInterval = 10 * time.Second
		engine := newTestEngine(t, &testEngineOptions{settings: settings})
		faults := engine.host.Redis.Faults()
		if _, err := faults.Add(plan); err != nil {
			t.Fatal(err)
		}
		probeCount := engine.service.ProbeCount()
		engine.clock.Advance(settings.ReadyProbeInterval)
		engine.service.AwaitProbeCount(probeCount + 1)
		if engine.service.Ready() {
			t.Errorf("%s: ready with its store down", plan)
		}
		faults.Clear()
		engine.clock.Advance(settings.ReadyProbeInterval)
		engine.service.AwaitProbeCount(probeCount + 2)
		if !engine.service.Ready() {
			t.Errorf("%s: not ready with its store back", plan)
		}
	}
}

// I-12: every path a session can take, and the store is called by none.
func TestNoSessionReachesTheStore(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.store.ResetOpCounts()
	engine.closeHandshakeFrom(testSender)
	engine.plaintextReplyTo(testSender)
	engine.plaintextReplyTo("198.51.100.1")
	client := engine.open("192.0.2.1")
	client.write("STARTTLS\r\nX")
	client.expectEnd()
	if counts := engine.store.OpCounts(); len(counts) != 0 {
		t.Errorf("store calls: %v", counts)
	}
}

func TestDrainRefusesNewSessionsAndWaitsForOpenOnes(t *testing.T) {
	engine := newTestEngine(t, nil)
	client := engine.open(testSender)
	timerCount := len(engine.clock.PendingTimers())
	drained := make(chan struct{})
	go func() {
		engine.service.Drain()
		close(drained)
	}()
	// Drain's bound is armed, so it has begun
	if err := engine.clock.AwaitTimers(engine.ctx, timerCount+1); err != nil {
		t.Fatal(err)
	}
	if engine.service.Ready() {
		t.Error("ready while draining")
	}
	late := engine.dial("198.51.100.1")
	late.expect("421 4.3.2 " + testBannerHostName + " Service closing, try again later")
	late.expectEnd()
	client.write("QUIT\r\n")
	client.expect("221 2.0.0 Bye")
	client.expectEnd()
	<-drained
}

func TestDrainEndsAtItsBound(t *testing.T) {
	settings := testSettings()
	settings.DrainTimeout = time.Minute
	engine := newTestEngine(t, &testEngineOptions{settings: settings})
	engine.open(testSender)
	timerCount := len(engine.clock.PendingTimers())
	drained := make(chan struct{})
	go func() {
		engine.service.Drain()
		close(drained)
	}()
	if err := engine.clock.AwaitTimers(engine.ctx, timerCount+1); err != nil {
		t.Fatal(err)
	}
	engine.clock.Advance(settings.DrainTimeout)
	<-drained
}

func TestDrainWithNothingOpenReturns(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.service.Drain()
}

func TestCloseEndsSessionsAndServe(t *testing.T) {
	engine := newTestEngine(t, nil)
	client := engine.open(testSender)
	engine.service.Close()
	client.expectEnd()
	if err := <-engine.served; err != nil {
		t.Errorf("served %v", err)
	}
	if engine.service.Ready() {
		t.Error("ready after Close")
	}
}

func TestCloseIsSafeAfterDrainAndTwice(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.service.Drain()
	engine.service.Close()
	engine.service.Close()
}

func TestServeAfterCloseReturnsAndClosesItsListener(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.service.Close()
	listener := newTestListener()
	if err := engine.service.Serve(listener); err != nil {
		t.Errorf("served %v", err)
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("accepted %v", err)
	}
}

// The host closes its listeners to stop new work, and Serve ends with no error.
func TestServeEndsWithItsListener(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.listener.Close()
	if err := <-engine.served; err != nil {
		t.Errorf("served %v", err)
	}
}

func TestEndOfItsContextClosesTheEngine(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(context.Background(), clock, nil, nil, nil)
	service, err := mxedgeservice.NewMxEdgeService(ctx, host.ServiceHost(), sidecartest.NewFakeMxEdgeStore(nil), &mxedgeservice.MxEdgeDeps{Clock: clock}, testSettings())
	if err != nil {
		t.Fatal(err)
	}
	listener := newTestListener()
	served := make(chan error, 1)
	go func() {
		served <- service.Serve(listener)
	}()
	cancel()
	if err := <-served; err != nil {
		t.Errorf("served %v", err)
	}
	service.Close()
}

// A temporary error in the fashion of EMFILE: a net.Error that says so.
type temporaryAcceptError struct{}

// Holds no address, as a real accept error names only the listener.
func (self *temporaryAcceptError) Error() string {
	return "accept: too many open files"
}

// Not a timeout.
func (self *temporaryAcceptError) Timeout() bool {
	return false
}

// It will pass.
func (self *temporaryAcceptError) Temporary() bool {
	return true
}

// An Accept that fails for now pauses and goes on, and a session after it is served.
func TestTemporaryAcceptFailureIsRetriedAfterAPause(t *testing.T) {
	engine := newTestEngine(t, nil)
	listener := newTestListener()
	listener.acceptErrs = []error{&temporaryAcceptError{}}
	timerCount := len(engine.clock.PendingTimers())
	served := make(chan error, 1)
	go func() {
		served <- engine.service.Serve(listener)
	}()
	if err := engine.clock.AwaitTimers(engine.ctx, timerCount+1); err != nil {
		t.Fatal(err)
	}
	engine.clock.Advance(engine.settings.AcceptRetryDelay)
	engine.listener = listener
	engine.open(testSender)
	if count := engine.host.Metrics.Value("urnetwork_mxedge_accept_failures_total"); count != 1 {
		t.Errorf("counted %v", count)
	}
	listener.Close()
	if err := <-served; err != nil {
		t.Errorf("served %v", err)
	}
}

func TestAcceptFailureThatStaysEndsServe(t *testing.T) {
	engine := newTestEngine(t, nil)
	listener := newTestListener()
	failure := errors.New("the listener broke")
	listener.acceptErrs = []error{failure}
	if err := engine.service.Serve(listener); !errors.Is(err, failure) {
		t.Errorf("served %v", err)
	}
}

// I-13 and §19.8, across every path a session takes: no address, EHLO name or SNI in a log, a metric
// or Redis. A canary stands for each name, and the scan looks for it in every encoding it knows.
func TestNoLogMetricOrKeyHoldsAnAddressEhloNameOrSni(t *testing.T) {
	engine := newTestEngine(t, nil)
	capture := sidecartest.NewPrivacyCapture()
	ehloName := capture.CanaryText("ehlo name")
	serverName := capture.CanaryText("sni")
	for _, text := range []string{testSender, "203.0.113", testSenderIp6, "2001:db8:1"} {
		capture.Forbid("address", []byte(text))
	}

	client := engine.open(testSender)
	client.write("EHLO " + ehloName + "\r\n")
	client.expectEhlo()
	engine.startTls(client)
	client.write("hello " + serverName)
	client.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertUnrecognizedName))
	client.expectEnd()
	engine.service.AwaitSessionCount(0)

	client = engine.open(testSenderIp6)
	client.write("HELO " + ehloName + "\r\n")
	client.expect("250 " + testBannerHostName)
	client.write("MAIL FROM:<" + ehloName + "@relay.example>\r\n")
	client.expect("530 5.7.0 Must issue a STARTTLS command first, see " + testDeviationUrl)
	client.write("STARTTLS\r\nX")
	client.expectEnd()
	engine.service.AwaitSessionCount(0)

	listener := newTestListener()
	listener.acceptErrs = []error{&temporaryAcceptError{}, errors.New("accept on " + testSender + " failed")}
	timerCount := len(engine.clock.PendingTimers())
	served := make(chan error, 1)
	go func() {
		served <- engine.service.Serve(listener)
	}()
	if err := engine.clock.AwaitTimers(engine.ctx, timerCount+1); err != nil {
		t.Fatal(err)
	}
	engine.clock.Advance(engine.settings.AcceptRetryDelay)
	<-served

	lines := engine.log.Lines()
	if len(lines) == 0 {
		t.Fatal("logged nothing, so the scan of the log proves nothing")
	}
	for _, line := range lines {
		capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "log", Body: []byte(line)})
	}
	for _, line := range engine.host.Metrics.Dump() {
		capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "metric", Body: []byte(line)})
	}
	// the one {mxc_} key and the day's k
	for key, value := range engine.host.Redis.Dump() {
		capture.AddItem(&sidecartest.PrivacyItem{Class: "CC3", Name: "redis", Body: append([]byte(key), value...)})
	}
	if count := capture.ItemCount("CC3"); count != 2 {
		t.Errorf("%d Redis items", count)
	}
	if hits := capture.Scan(); len(hits) != 0 {
		t.Errorf("%v", hits)
	}
}

// Results only, from closed sets: FakeMetrics flags an identity in a label, and every series here is
// spelled out, so a new label value needs a line in this test.
func TestMetricsCarryResultsOnly(t *testing.T) {
	engine := newTestEngine(t, nil)
	engine.closeHandshakeFrom(testSender)
	engine.plaintextReplyTo(testSender)
	engine.plaintextReplyTo("198.51.100.1")
	allowed := regexp.MustCompile(`^urnetwork_mxedge_(` +
		`sessions_total (over_cap|draining|no_sender|quit|limit|reset|ended|closed_handshake)|` +
		`cap_refusals_total (process|sender|sender_aggregate|network|network_sender)|` +
		`plaintext_sessions_total (451|530)|` +
		`closed_handshake_reads_total (recent|absent|failed)|` +
		`closed_handshake_writes_total (written|failed)|` +
		`daily_key_refreshes_total (created|read|failed)|` +
		`accept_failures_total ` +
		`)$`)
	lines := engine.host.Metrics.Dump()
	if len(lines) == 0 {
		t.Fatal("no metrics")
	}
	for _, line := range lines {
		if !allowed.MatchString(line) {
			t.Errorf("series %q", line)
		}
	}
	if violations := engine.host.Metrics.Violations(); len(violations) != 0 {
		t.Errorf("violations: %v", violations)
	}
}
