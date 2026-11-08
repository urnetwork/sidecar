// The PROXY listener's waits on sidecartest's FakeClock (§22.4): timeout_s and the accept retry move
// only when a test moves the clock, so each side of each is forced rather than raced.
// connect/CODESTYLE.md asks this of anything that replaces a native socket deadline: both orderings
// of a read's end and its timeout, and a peer that stalls. Listener tests dial a real loopback
// listener, since a PROXY listener must know its port. A read that must finish holds a real deadline
// only as a guard against a hung test.

package tlsedgeservice_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// Long enough that a test never reaches it by accident, and short enough to fail rather than hang.
const testClockGuardTimeout = 30 * time.Second

// A v1 line from a documentation address, as the lb's nginx writes one.
func testClockProxyV1(sourcePort int) []byte {
	return fmt.Appendf(nil, "PROXY TCP4 192.0.2.1 198.51.100.2 %d 443\r\n", sourcePort)
}

// A v2 TCP over IPv4 header from a documentation address, proxy-protocol.txt §2.2.
func testClockProxyV2(sourcePort uint16) []byte {
	header := slices.Clone(proxyproto.SIGV2)
	header = append(header, 0x21, 0x11)
	header = binary.BigEndian.AppendUint16(header, 12)
	header = append(header, 192, 0, 2, 1, 198, 51, 100, 2)
	header = binary.BigEndian.AppendUint16(header, sourcePort)
	return binary.BigEndian.AppendUint16(header, 443)
}

// Default settings with every wait on a new fake clock.
func testClockSettings() (*tlsedgeservice.ProxyHeaderSettings, *sidecartest.FakeClock) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := tlsedgeservice.DefaultProxyHeaderSettings()
	settings.Clock = clock
	return settings, clock
}

// A PROXY listener over inner, closed at the test's end.
func testClockListenerOver(t *testing.T, inner net.Listener, settings *tlsedgeservice.ProxyHeaderSettings) net.Listener {
	t.Helper()
	listener, err := tlsedgeservice.NewProxyHeaderListener(context.Background(), inner, settings)
	if err != nil {
		inner.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		listener.Close()
	})
	return listener
}

// A fresh loopback listener.
func testClockInnerListener(t *testing.T) net.Listener {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return inner
}

// The lb's end of a new connection.
func testClockDial(t *testing.T, listener net.Listener) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Close()
	})
	return conn
}

// Writes from the lb's end. Loopback takes these few bytes at once, so no read need be waiting.
func testClockWrite(t *testing.T, conn net.Conn, b []byte) {
	t.Helper()
	if _, err := conn.Write(b); err != nil {
		t.Fatal(err)
	}
}

// Writes from a goroutine, since a pipe's write waits for its read.
func testClockPipeWrite(t *testing.T, conn net.Conn, b []byte) {
	t.Helper()
	failed := make(chan error, 1)
	go func() {
		_, err := conn.Write(b)
		failed <- err
	}()
	t.Cleanup(func() {
		select {
		case err := <-failed:
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				t.Error(err)
			}
		case <-time.After(testClockGuardTimeout):
			t.Error("a write never finished")
		}
	})
}

// Returns once count timers are pending on clock, which is how a test knows a goroutine has reached
// its wait before it moves the clock past it.
func testClockAwaitTimers(t *testing.T, clock *sidecartest.FakeClock, count int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testClockGuardTimeout)
	defer cancel()
	if err := clock.AwaitTimers(ctx, count); err != nil {
		t.Fatalf("waiting for %d timers: %v", count, err)
	}
}

// The next connection, failing rather than hanging when none comes.
func testClockAccept(t *testing.T, listener net.Listener) *tlsedgeservice.ProxyHeaderConn {
	t.Helper()
	type accepted struct {
		conn net.Conn
		err  error
	}
	result := make(chan accepted, 1)
	go func() {
		conn, err := listener.Accept()
		result <- accepted{conn: conn, err: err}
	}()
	select {
	case accepted := <-result:
		if accepted.err != nil {
			t.Fatal(accepted.err)
		}
		t.Cleanup(func() {
			accepted.conn.Close()
		})
		return accepted.conn.(*tlsedgeservice.ProxyHeaderConn)
	case <-time.After(testClockGuardTimeout):
		t.Fatal("nothing to accept")
		return nil
	}
}

// Fails unless the listener closed the lb's end with nothing written on it: a drop, never an alert. A
// close with bytes still unread in the kernel resets rather than ends, so either is a drop.
func testClockRequireDropped(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(testClockGuardTimeout))
	written, err := io.ReadAll(conn)
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("waiting for a drop: %v", err)
	}
	if len(written) != 0 {
		t.Fatalf("a drop wrote %x", written)
	}
}

// A stalled peer, and one whose header is still coming, is cut short when timeout_s runs out, and
// Accept never sees it: the next connection in is the next one out.
func TestProxyHeaderTimeoutDropsAHeaderStillComing(t *testing.T) {
	cases := [][]byte{
		nil,
		testClockProxyV1(1000)[:20],
		testClockProxyV2(1000)[:20],
	}
	for _, c := range cases {
		settings, clock := testClockSettings()
		listener := testClockListenerOver(t, testClockInnerListener(t), settings)
		stalled := testClockDial(t, listener)
		if 0 < len(c) {
			testClockWrite(t, stalled, c)
		}
		testClockAwaitTimers(t, clock, 1)
		clock.Advance(settings.Timeout)
		testClockRequireDropped(t, stalled)

		next := testClockDial(t, listener)
		testClockWrite(t, next, testClockProxyV1(2000))
		if conn := testClockAccept(t, listener); conn.VisitorAddr().Port() != 2000 {
			t.Errorf("%q: accepted %v", c, conn.VisitorAddr())
		}
	}
}

// A header whose last byte comes in before timeout_s runs out passes, and its timer is stopped rather
// than left to fire, so the connection outlives the timeout with no deadline on it.
func TestProxyHeaderTimeoutPassesAHeaderThatEndsInTime(t *testing.T) {
	headers := [][]byte{testClockProxyV1(1000), testClockProxyV2(1000)}
	for _, header := range headers {
		settings, clock := testClockSettings()
		listener := testClockListenerOver(t, testClockInnerListener(t), settings)
		peerConn := testClockDial(t, listener)
		testClockWrite(t, peerConn, header[:len(header)-1])
		testClockAwaitTimers(t, clock, 1)
		clock.Advance(settings.Timeout - time.Nanosecond)
		testClockWrite(t, peerConn, append(slices.Clone(header[len(header)-1:]), "hello"...))

		conn := testClockAccept(t, listener)
		if conn.VisitorAddr().Port() != 1000 {
			t.Errorf("%q: visitor %v", header, conn.VisitorAddr())
		}
		if pending := clock.PendingTimers(); len(pending) != 0 {
			t.Errorf("%q: timers left %v", header, pending)
		}
		clock.Advance(time.Hour)
		got := make([]byte, 5)
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("%q: %v", header, err)
		}
		if string(got) != "hello" {
			t.Errorf("%q: read %q", header, got)
		}
	}
}

// timeout_s bounds the header as a whole: a peer that keeps sending, a piece at a time, is cut short
// all the same once the time since accept runs out.
func TestProxyHeaderTimeoutBindsTheWholeHeader(t *testing.T) {
	settings, clock := testClockSettings()
	listener := testClockListenerOver(t, testClockInnerListener(t), settings)
	header := testClockProxyV1(1000)
	peerConn := testClockDial(t, listener)
	testClockWrite(t, peerConn, header[:10])
	testClockAwaitTimers(t, clock, 1)
	clock.Advance(settings.Timeout / 2)
	testClockWrite(t, peerConn, header[10:len(header)-1])
	clock.Advance(settings.Timeout - settings.Timeout/2)
	testClockRequireDropped(t, peerConn)
}

// A loopback listener whose first Accept fails as running out of descriptors does.
type testClockFailOnceListener struct {
	net.Listener
	failed atomic.Bool
}

func (self *testClockFailOnceListener) Accept() (net.Conn, error) {
	if self.failed.CompareAndSwap(false, true) {
		return nil, testClockTemporaryError{}
	}
	return self.Listener.Accept()
}

// A temporary net.Error.
type testClockTemporaryError struct{}

func (self testClockTemporaryError) Error() string   { return "temporary" }
func (self testClockTemporaryError) Timeout() bool   { return false }
func (self testClockTemporaryError) Temporary() bool { return true }

// A temporary accept failure waits AcceptRetryTimeout on the clock before the next accept, so the loop
// never spins, and a connection that came in meanwhile is taken once the wait ends.
func TestProxyHeaderAcceptRetryWaitsOnTheClock(t *testing.T) {
	settings, clock := testClockSettings()
	listener := testClockListenerOver(t, &testClockFailOnceListener{Listener: testClockInnerListener(t)}, settings)
	testClockAwaitTimers(t, clock, 1)
	wantPending := []time.Time{sidecartest.DefaultClockStart().Add(settings.AcceptRetryTimeout)}
	if pending := clock.PendingTimers(); !slices.EqualFunc(pending, wantPending, time.Time.Equal) {
		t.Fatalf("timers %v", pending)
	}
	peerConn := testClockDial(t, listener)
	testClockWrite(t, peerConn, testClockProxyV1(1000))
	clock.Advance(settings.AcceptRetryTimeout)
	if conn := testClockAccept(t, listener); conn.VisitorAddr().Port() != 1000 {
		t.Errorf("accepted %v", conn.VisitorAddr())
	}
}

// The ordering a goroutine's delay makes: the header's read is over, and the timer fires before the
// goroutine ends the timeout. end lifts the deadline the timer set, so a header read in time is never
// lost to scheduling.
func TestProxyHeaderTimeoutLiftsADeadlineSetAfterTheRead(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	peerConn, conn := net.Pipe()
	defer peerConn.Close()
	defer conn.Close()
	end := tlsedgeservice.NewProxyHeaderTimeoutForTest(clock, time.Second, conn)
	clock.Advance(time.Second)
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the timer set no deadline: read gave %v", err)
	}
	if !end() {
		t.Fatal("the deadline did not lift")
	}
	// a deadline still set would fail this read at once, and with none it waits for the byte
	testClockPipeWrite(t, peerConn, []byte("x"))
	got := make([]byte, 1)
	if _, err := conn.Read(got); err != nil || got[0] != 'x' {
		t.Errorf("read %q, %v", got, err)
	}
}

// The other ordering: the timer fires while the header is still being read, and the read is cut short,
// which the listener answers with a drop.
func TestProxyHeaderTimeoutCutsTheHeadersReadShort(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	peerConn, conn := net.Pipe()
	defer peerConn.Close()
	defer conn.Close()
	end := tlsedgeservice.NewProxyHeaderTimeoutForTest(clock, time.Second, conn)
	readErrs := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		readErrs <- err
	}()
	clock.Advance(time.Second)
	select {
	case err := <-readErrs:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("read gave %v", err)
		}
	case <-time.After(testClockGuardTimeout):
		t.Fatal("the read was not cut short")
	}
	if !end() {
		t.Error("the deadline did not lift")
	}
}

// Ended before its time, the timer never fires, and no deadline is ever set.
func TestProxyHeaderTimeoutEndedInTimeNeverFires(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	peerConn, conn := net.Pipe()
	defer peerConn.Close()
	defer conn.Close()
	end := tlsedgeservice.NewProxyHeaderTimeoutForTest(clock, time.Second, conn)
	if !end() {
		t.Fatal("a timer still to come did not stop")
	}
	if pending := clock.PendingTimers(); len(pending) != 0 {
		t.Errorf("timers left %v", pending)
	}
	clock.Advance(time.Hour)
	testClockPipeWrite(t, peerConn, []byte("x"))
	got := make([]byte, 1)
	if _, err := conn.Read(got); err != nil || got[0] != 'x' {
		t.Errorf("read %q, %v", got, err)
	}
}

// A connection that refuses every deadline.
type testClockNoDeadlineConn struct {
	net.Conn
}

func (self testClockNoDeadlineConn) SetReadDeadline(deadline time.Time) error {
	return errors.ErrUnsupported
}

// A connection that takes no deadline is closed when the timer fires, the only other way to cut its
// read short, and end then says it cannot go on.
func TestProxyHeaderTimeoutClosesAConnectionThatTakesNoDeadline(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	peerConn, conn := net.Pipe()
	defer peerConn.Close()
	end := tlsedgeservice.NewProxyHeaderTimeoutForTest(clock, time.Second, testClockNoDeadlineConn{Conn: conn})
	clock.Advance(time.Second)
	peerConn.SetReadDeadline(time.Now().Add(testClockGuardTimeout))
	if _, err := peerConn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("the lb's end read %v", err)
	}
	if end() {
		t.Error("a connection whose deadline cannot lift went on")
	}
}
