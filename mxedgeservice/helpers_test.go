// What the tests of this package share: an engine on fake stores behind a scripted listener, and a
// sender on the other end of a pipe. Nothing here sleeps. A step waits on a monitor, on a timer it can
// see armed, or on the pipe itself, whose reads and writes meet.

package mxedgeservice_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Synthetic, at the length the fleet's secret must have.
var testSecret = []byte("mxedge test secret, not a key...")

// RFC 5737 and RFC 3849 documentation addresses.
const (
	testSender    = "203.0.113.9"
	testSenderIp6 = "2001:db8:1:2:3:4:5:6"
)

// A Logger that keeps every line, for a scan.
type testLogger struct {
	stateLock sync.Mutex
	lines     []string
}

// Adds a line.
func (self *testLogger) keep(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

// Every line so far.
func (self *testLogger) Lines() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.lines...)
}

// Keeps it.
func (self *testLogger) Info(args ...any) {
	self.keep(fmt.Sprint(args...))
}

// Keeps it.
func (self *testLogger) Infof(format string, args ...any) {
	self.keep(fmt.Sprintf(format, args...))
}

// Keeps it.
func (self *testLogger) Warningf(format string, args ...any) {
	self.keep(fmt.Sprintf(format, args...))
}

// Keeps it.
func (self *testLogger) Errorf(format string, args ...any) {
	self.keep(fmt.Sprintf(format, args...))
}

// Every level.
func (self *testLogger) V(level int32) sidecar.Verbose {
	return &testVerbose{log: self}
}

// Every level on, so a verbose line is caught too.
type testVerbose struct {
	log *testLogger
}

// Always.
func (self *testVerbose) Enabled() bool {
	return true
}

// Keeps it.
func (self *testVerbose) Info(args ...any) {
	self.log.Info(args...)
}

// Keeps it.
func (self *testVerbose) Infof(format string, args ...any) {
	self.log.Infof(format, args...)
}

// A scripted hello: "hello <name>" is one naming name, "hello" one naming none, anything else fails.
// tlsedgeservice owns the real parser (TLS-M5-06), which an engine may not import.
func testReadClientHello(conn net.Conn, maxByteCount int) (*mxedgeservice.MxClientHello, error) {
	buffer := make([]byte, maxByteCount)
	byteCount, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	hello := string(buffer[:byteCount])
	if hello != "hello" && !strings.HasPrefix(hello, "hello ") {
		return nil, errors.New("not a hello")
	}
	return &mxedgeservice.MxClientHello{
		ServerName: strings.TrimPrefix(strings.TrimPrefix(hello, "hello"), " "),
		RawBytes:   buffer[:byteCount],
	}, nil
}

// Stands in for TLS-M5-06's.
func testNormalizeSni(serverName string) (string, bool) {
	return strings.ToLower(serverName), serverName != ""
}

// RFC 8446 §6's fatal alert record, which TLS-M5-06 writes for real.
func testWriteTlsAlert(conn net.Conn, alert mxedgeservice.MxTlsAlert) error {
	_, err := conn.Write(testAlertRecord(alert))
	return err
}

// What testWriteTlsAlert writes.
func testAlertRecord(alert mxedgeservice.MxTlsAlert) []byte {
	return []byte{21, 3, 3, 0, 2, 2, byte(alert)}
}

// A listener a test feeds. Close ends Accept, as a real one's does.
type testListener struct {
	conns     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
	// Answered by Accept before any conn, in order.
	stateLock  sync.Mutex
	acceptErrs []error
}

// A listener with nothing to accept yet.
func newTestListener() *testListener {
	return &testListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

// The next scripted error, else the next conn, else the end.
func (self *testListener) Accept() (net.Conn, error) {
	acceptErr := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if len(self.acceptErrs) == 0 {
			return nil
		}
		err := self.acceptErrs[0]
		self.acceptErrs = self.acceptErrs[1:]
		return err
	}()
	if acceptErr != nil {
		return nil, acceptErr
	}
	select {
	case conn := <-self.conns:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	}
}

// Ends Accept. Safe more than once.
func (self *testListener) Close() error {
	self.closeOnce.Do(func() {
		close(self.closed)
	})
	return nil
}

// A documentation address, since nothing dials it.
func (self *testListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 25), Port: 25}
}

// The server's end of a pipe, reporting the sender a PROXY listener would.
type testServerConn struct {
	net.Conn
	sender net.Addr
}

// The sender, not the pipe.
func (self *testServerConn) RemoteAddr() net.Addr {
	return self.sender
}

// An engine and everything behind it.
type testEngine struct {
	t        *testing.T
	ctx      context.Context
	clock    *sidecartest.FakeClock
	host     *sidecartest.FakeHost
	store    *sidecartest.FakeMxEdgeStore
	settings *mxedgeservice.MxEdgeSettings
	log      *testLogger
	gateOpen atomic.Bool
	service  *mxedgeservice.MxEdgeService
	listener *testListener
	served   chan error
}

// What a test may change before the engine starts.
type testEngineOptions struct {
	clock    *sidecartest.FakeClock
	host     *sidecartest.FakeHost
	settings *mxedgeservice.MxEdgeSettings
	deps     func(deps *mxedgeservice.MxEdgeDeps)
}

// An engine serving a test listener, past its first probe, with the mxedge gate open. Two engines given
// one clock and host are two processes of a fleet.
func newTestEngine(t *testing.T, options *testEngineOptions) *testEngine {
	t.Helper()
	if options == nil {
		options = &testEngineOptions{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	self := &testEngine{
		t:        t,
		ctx:      ctx,
		clock:    options.clock,
		host:     options.host,
		settings: options.settings,
		log:      &testLogger{},
		listener: newTestListener(),
		served:   make(chan error, 1),
	}
	if self.clock == nil {
		self.clock = sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	}
	if self.host == nil {
		self.host = sidecartest.NewFakeHost(ctx, self.clock, nil, nil, nil)
	}
	if self.settings == nil {
		self.settings = testSettings()
	}
	self.store = sidecartest.NewFakeMxEdgeStore(self.host.Redis.Faults())
	self.gateOpen.Store(true)
	deps := &mxedgeservice.MxEdgeDeps{
		ReadClientHello:       testReadClientHello,
		NormalizeSni:          testNormalizeSni,
		WriteTlsAlert:         testWriteTlsAlert,
		ClosedHandshakeSecret: testSecret,
		GateOpen:              self.gateOpen.Load,
		Clock:                 self.clock,
		Log:                   self.log,
	}
	if options.deps != nil {
		options.deps(deps)
	}
	timerCount := len(self.clock.PendingTimers())
	service, err := mxedgeservice.NewMxEdgeService(ctx, self.host.ServiceHost(), self.store, deps, self.settings)
	if err != nil {
		t.Fatal(err)
	}
	self.service = service
	t.Cleanup(service.Close)
	service.AwaitStoresReachable(true)
	// the probe's own timer is gone by now, so the next one to appear is its loop's
	if err := self.clock.AwaitTimers(ctx, timerCount+1); err != nil {
		t.Fatal(err)
	}
	listener := self.listener
	go func() {
		self.served <- service.Serve(listener)
	}()
	return self
}

// A sender's end of one connection.
type testClient struct {
	t      *testing.T
	conn   net.Conn
	reader *bufio.Reader
}

// Connects as sender, an address with no port, and returns before the banner is read.
func (self *testEngine) dial(sender string) *testClient {
	self.t.Helper()
	serverConn, clientConn := net.Pipe()
	self.t.Cleanup(func() { clientConn.Close() })
	self.listener.conns <- &testServerConn{
		Conn:   serverConn,
		sender: &net.TCPAddr{IP: net.ParseIP(sender), Port: 2525},
	}
	return &testClient{t: self.t, conn: clientConn, reader: bufio.NewReader(clientConn)}
}

// Connects as sender and reads the banner.
func (self *testEngine) open(sender string) *testClient {
	self.t.Helper()
	client := self.dial(sender)
	client.expect("220 " + testBannerHostName + " ESMTP")
	return client
}

// Sends STARTTLS and lets the quiet period pass, so the 220 comes.
func (self *testEngine) startTls(client *testClient) {
	self.t.Helper()
	timerCount := len(self.clock.PendingTimers())
	client.write("STARTTLS\r\n")
	if err := self.clock.AwaitTimers(self.ctx, timerCount+1); err != nil {
		self.t.Fatal(err)
	}
	self.clock.Advance(self.settings.StartTlsQuietTimeout)
	client.expect("220 2.0.0 Ready to start TLS")
}

// A session that reaches TLS and closes there, naming no route, as a sender's failed attempt does.
func (self *testEngine) closeHandshakeFrom(sender string) {
	self.t.Helper()
	client := self.open(sender)
	client.write("EHLO relay.example\r\n")
	client.expectEhlo()
	self.startTls(client)
	client.write("hello mx.net.example")
	client.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertUnrecognizedName))
	client.expectEnd()
	self.service.AwaitSessionCount(0)
}

// Writes text, which returns once the engine has read it all.
func (self *testClient) write(text string) {
	self.t.Helper()
	if _, err := self.conn.Write([]byte(text)); err != nil {
		self.t.Fatalf("write: %v", err)
	}
}

// Reads one line and compares it, CRLF aside.
func (self *testClient) expect(want string) {
	self.t.Helper()
	line, err := self.reader.ReadString('\n')
	if err != nil {
		self.t.Fatalf("expected %q: %v", want, err)
	}
	if line != want+"\r\n" {
		self.t.Fatalf("read %q, want %q", line, want)
	}
}

// Reads EHLO's three lines.
func (self *testClient) expectEhlo() {
	self.t.Helper()
	self.expect("250-" + testBannerHostName)
	self.expect("250-ENHANCEDSTATUSCODES")
	self.expect("250 STARTTLS")
}

// Reads exactly want.
func (self *testClient) expectBytes(want []byte) {
	self.t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(self.reader, got); err != nil {
		self.t.Fatalf("expected %x: %v", want, err)
	}
	if !bytes.Equal(got, want) {
		self.t.Fatalf("read %x, want %x", got, want)
	}
}

// Reads to the end, which must come with nothing more said.
func (self *testClient) expectEnd() {
	self.t.Helper()
	rest, err := io.ReadAll(self.reader)
	if err != nil {
		self.t.Fatalf("expected the end: %v", err)
	}
	if 0 < len(rest) {
		self.t.Fatalf("read %q before the end", rest)
	}
}

// Connects a plaintext sender, tries a transaction and returns the first reply's code.
func (self *testEngine) plaintextReplyTo(sender string) string {
	self.t.Helper()
	client := self.open(sender)
	client.write("MAIL FROM:<a@relay.example>\r\n")
	line, err := client.reader.ReadString('\n')
	if err != nil {
		self.t.Fatal(err)
	}
	client.write("QUIT\r\n")
	client.expect("221 2.0.0 Bye")
	client.expectEnd()
	return line[:3]
}
