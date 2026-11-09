// T1 for the PROXY listener: what a connection must open with, what it gives, and what a peer that
// misbehaves can cost. Peers are net.Pipe ends behind a listener the test feeds, so nothing depends on
// timing, and a read that must not finish holds a deadline only as a guard against a hung test.

package tlsedgeservice

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// Long enough that a test never reaches it by accident, and short enough to fail rather than hang.
const testGuardTimeout = 30 * time.Second

// A timeout no test may wait out: reaching it means a read that should have been cut short was not.
const testNeverTimeout = time.Hour

// The port the test's listeners claim, one of §13.5's, so it differs from any PROXY destination below.
const testAcceptPort = 8443

// A listener whose connections and failures the test hands in, one at a time.
type testInnerListener struct {
	conns     chan net.Conn
	errs      chan error
	closed    chan struct{}
	closeOnce sync.Once
	addr      net.Addr
}

func newTestInnerListener() *testInnerListener {
	return &testInnerListener{
		conns:  make(chan net.Conn),
		errs:   make(chan error),
		closed: make(chan struct{}),
		addr:   &net.TCPAddr{IP: netip.MustParseAddr("198.51.100.7").AsSlice(), Port: testAcceptPort},
	}
}

func (self *testInnerListener) Accept() (net.Conn, error) {
	select {
	case conn := <-self.conns:
		return conn, nil
	case err := <-self.errs:
		return nil, err
	case <-self.closed:
		return nil, net.ErrClosed
	}
}

func (self *testInnerListener) Close() error {
	self.closeOnce.Do(func() {
		close(self.closed)
	})
	return nil
}

func (self *testInnerListener) Addr() net.Addr {
	return self.addr
}

// Hands in a new connection and returns the peer's end. Once this returns, run has come back to its
// accept, so the connection has taken a slot or been refused one.
func (self *testInnerListener) dial(t *testing.T) net.Conn {
	t.Helper()
	peerConn, acceptedConn := net.Pipe()
	t.Cleanup(func() {
		peerConn.Close()
		acceptedConn.Close()
	})
	select {
	case self.conns <- acceptedConn:
	case <-time.After(testGuardTimeout):
		t.Fatal("the listener stopped accepting")
	}
	return peerConn
}

// settings for a test that means to reach no deadline.
func testNeverSettings() *ProxyHeaderSettings {
	settings := DefaultProxyHeaderSettings()
	settings.Timeout = testNeverTimeout
	return settings
}

// A listener over a fresh inner one, closed at the test's end.
func testProxyListener(t *testing.T, settings *ProxyHeaderSettings) (net.Listener, *testInnerListener) {
	t.Helper()
	inner := newTestInnerListener()
	listener, err := NewProxyHeaderListener(context.Background(), inner, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		listener.Close()
	})
	return listener, inner
}

// The next connection, failing rather than hanging when none comes.
func testAccept(t *testing.T, listener net.Listener) *ProxyHeaderConn {
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
		return accepted.conn.(*ProxyHeaderConn)
	case <-time.After(testGuardTimeout):
		t.Fatal("nothing to accept")
		return nil
	}
}

// Writes each piece in order from another goroutine, since a pipe's write blocks until it is read.
func testWrite(t *testing.T, conn net.Conn, pieces ...[]byte) {
	t.Helper()
	failed := make(chan error, 1)
	go func() {
		for _, piece := range pieces {
			if _, err := conn.Write(piece); err != nil {
				failed <- err
				return
			}
		}
		failed <- nil
	}()
	t.Cleanup(func() {
		select {
		case err := <-failed:
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				t.Error(err)
			}
		case <-time.After(testGuardTimeout):
			t.Error("a write never finished")
		}
	})
}

// Fails unless conn's other end closes with nothing written on it: a drop, never an alert.
func testRequireDropped(t *testing.T, conn net.Conn) {
	t.Helper()
	// a pipe refuses this once its other end has closed, which is the answer this is waiting for
	conn.SetReadDeadline(time.Now().Add(testGuardTimeout))
	written, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("waiting for a drop: %v", err)
	}
	if len(written) != 0 {
		t.Fatalf("a drop wrote %x", written)
	}
}

// A v1 line the way the lb's nginx writes one.
func testProxyV1(source string, sourcePort int, destination string, destinationPort int) []byte {
	family := "TCP4"
	if strings.Contains(source, ":") {
		family = "TCP6"
	}
	return fmt.Appendf(nil, "PROXY %s %s %s %d %d\r\n", family, source, destination, sourcePort, destinationPort)
}

// A v2 header of a command, family and body, as proxy-protocol.txt §2.2 lays one out.
func testProxyV2(command byte, family byte, body []byte) []byte {
	header := slices.Clone(proxyproto.SIGV2)
	header = append(header, command, family)
	header = binary.BigEndian.AppendUint16(header, uint16(len(body)))
	return append(header, body...)
}

// The address block of a TCP over IPv4 header.
func testProxyV2Addresses4(source string, sourcePort uint16, destination string, destinationPort uint16) []byte {
	sourceBytes := netip.MustParseAddr(source).As4()
	destinationBytes := netip.MustParseAddr(destination).As4()
	block := append(sourceBytes[:], destinationBytes[:]...)
	block = binary.BigEndian.AppendUint16(block, sourcePort)
	return binary.BigEndian.AppendUint16(block, destinationPort)
}

// The address block of a TCP over IPv6 header.
func testProxyV2Addresses6(source string, sourcePort uint16, destination string, destinationPort uint16) []byte {
	sourceBytes := netip.MustParseAddr(source).As16()
	destinationBytes := netip.MustParseAddr(destination).As16()
	block := append(sourceBytes[:], destinationBytes[:]...)
	block = binary.BigEndian.AppendUint16(block, sourcePort)
	return binary.BigEndian.AppendUint16(block, destinationPort)
}

// A v2 TCP over IPv4 header padded with a NOOP TLV to exactly byteCount bytes.
func testProxyV2OfByteCount(byteCount int) []byte {
	const tlvTypeNoop = 4
	addresses := testProxyV2Addresses4("192.0.2.1", 56324, "198.51.100.2", 443)
	tlvBytes := append([]byte{tlvTypeNoop}, testPrefixed(2, make([]byte, byteCount-proxyHeaderV2FixedByteCount-len(addresses)-3))...)
	return testProxyV2(0x21, 0x11, append(addresses, tlvBytes...))
}

func TestProxyHeaderGivesTheVisitor(t *testing.T) {
	cases := []struct {
		name   string
		header []byte
		want   netip.AddrPort
	}{
		{
			name:   "v1 tcp4",
			header: testProxyV1("192.0.2.1", 56324, "198.51.100.2", 443),
			want:   netip.MustParseAddrPort("192.0.2.1:56324"),
		},
		{
			name:   "v1 tcp6",
			header: testProxyV1("2001:db8::1", 56324, "2001:db8::2", 443),
			want:   netip.MustParseAddrPort("[2001:db8::1]:56324"),
		},
		{
			name:   "v1 4-in-6",
			header: testProxyV1("::ffff:192.0.2.1", 56324, "::ffff:198.51.100.2", 443),
			want:   netip.MustParseAddrPort("192.0.2.1:56324"),
		},
		{
			name:   "v2 tcp4",
			header: testProxyV2(0x21, 0x11, testProxyV2Addresses4("192.0.2.1", 56324, "198.51.100.2", 443)),
			want:   netip.MustParseAddrPort("192.0.2.1:56324"),
		},
		{
			name:   "v2 tcp6",
			header: testProxyV2(0x21, 0x21, testProxyV2Addresses6("2001:db8::1", 56324, "2001:db8::2", 443)),
			want:   netip.MustParseAddrPort("[2001:db8::1]:56324"),
		},
		{
			name:   "v2 4-in-6",
			header: testProxyV2(0x21, 0x21, testProxyV2Addresses6("::ffff:192.0.2.1", 56324, "::ffff:198.51.100.2", 443)),
			want:   netip.MustParseAddrPort("192.0.2.1:56324"),
		},
		{
			name:   "v2 with tlvs",
			header: testProxyV2OfByteCount(300),
			want:   netip.MustParseAddrPort("192.0.2.1:56324"),
		},
	}
	for _, c := range cases {
		listener, inner := testProxyListener(t, testNeverSettings())
		peerConn := inner.dial(t)
		testWrite(t, peerConn, c.header)
		conn := testAccept(t, listener)
		if conn.VisitorAddr() != c.want {
			t.Errorf("%s: visitor %v", c.name, conn.VisitorAddr())
		}
		if conn.RemoteAddr().String() != c.want.String() {
			t.Errorf("%s: remote %v", c.name, conn.RemoteAddr())
		}
	}
}

func TestProxyHeaderAcceptPortIsTheListenersNeverProxysDestination(t *testing.T) {
	listener, inner := testProxyListener(t, testNeverSettings())
	headers := [][]byte{
		testProxyV1("192.0.2.1", 56324, "198.51.100.2", 9999),
		testProxyV2(0x21, 0x11, testProxyV2Addresses4("192.0.2.1", 56324, "198.51.100.2", 9999)),
	}
	for _, header := range headers {
		testWrite(t, inner.dial(t), header)
		conn := testAccept(t, listener)
		if conn.AcceptPort() != testAcceptPort {
			t.Errorf("accept port %d", conn.AcceptPort())
		}
		// the accepting socket's, and net.Pipe has no address of its own to give
		if strings.Contains(conn.LocalAddr().String(), "9999") {
			t.Errorf("local address %v came from PROXY", conn.LocalAddr())
		}
	}
}

func TestProxyHeaderDropsAConnectionWithNoHeader(t *testing.T) {
	listener, inner := testProxyListener(t, testNeverSettings())
	bad := inner.dial(t)
	testWrite(t, bad, testGoClientHello(t))
	testRequireDropped(t, bad)

	// and nothing of it reached Accept: the next one out is the next one with a header
	good := inner.dial(t)
	testWrite(t, good, testProxyV1("192.0.2.1", 1000, "198.51.100.2", 443))
	if conn := testAccept(t, listener); conn.VisitorAddr().Port() != 1000 {
		t.Errorf("accepted %v", conn.VisitorAddr())
	}
}

func TestProxyHeaderDrops(t *testing.T) {
	addresses4 := testProxyV2Addresses4("192.0.2.1", 1, "198.51.100.2", 2)
	addresses6 := testProxyV2Addresses6("2001:db8::1", 1, "2001:db8::2", 2)
	line108 := []byte("PROXY TCP6 " + strings.Repeat("a", 95) + "\r\n")
	cases := []struct {
		name   string
		stream []byte
	}{
		{name: "tls with no header", stream: testRecords(testHelloMessage(testServerNameExtension(testServerName)))},
		{name: "http", stream: []byte("GET / HTTP/1.0\r\n\r\n")},
		{name: "starting like v1", stream: []byte("POST / HTTP/1.0\r\n\r\n")},
		{name: "starting like v2", stream: []byte("\r\n\r\nGET")},
		{name: "lowercase v1", stream: []byte("proxy TCP4 192.0.2.1 198.51.100.2 1 2\r\n")},
		{name: "v1 unknown", stream: []byte("PROXY UNKNOWN\r\n")},
		{name: "v1 unknown with addresses", stream: []byte("PROXY UNKNOWN 192.0.2.1 198.51.100.2 1 2\r\n")},
		{name: "v1 with no family", stream: []byte("PROXY \r\n")},
		{name: "v1 with another family", stream: []byte("PROXY UDP4 192.0.2.1 198.51.100.2 1 2\r\n")},
		{name: "v1 past 107 bytes", stream: line108},
		{name: "v1 with no crlf", stream: []byte("PROXY TCP4 192.0.2.1 198.51.100.2 1 2\n")},
		{name: "v1 with a word too many", stream: []byte("PROXY TCP4 192.0.2.1 198.51.100.2 1 2 3\r\n")},
		{name: "v1 with an address of the other family", stream: []byte("PROXY TCP4 2001:db8::1 2001:db8::2 1 2\r\n")},
		{name: "v1 past port 65535", stream: []byte("PROXY TCP4 192.0.2.1 198.51.100.2 65536 2\r\n")},
		{name: "v2 local", stream: testProxyV2(0x20, 0x00, nil)},
		{name: "v2 local with addresses", stream: testProxyV2(0x20, 0x11, addresses4)},
		{name: "v2 unspecified family", stream: testProxyV2(0x21, 0x00, nil)},
		{name: "v2 udp over ipv4", stream: testProxyV2(0x21, 0x12, addresses4)},
		{name: "v2 udp over ipv6", stream: testProxyV2(0x21, 0x22, addresses6)},
		{name: "v2 unix stream", stream: testProxyV2(0x21, 0x31, make([]byte, 216))},
		{name: "v2 unix datagram", stream: testProxyV2(0x21, 0x32, make([]byte, 216))},
		{name: "v2 unknown family", stream: testProxyV2(0x21, 0x41, addresses4)},
		{name: "v2 unknown transport", stream: testProxyV2(0x21, 0x13, addresses4)},
		{name: "v2 unknown command", stream: testProxyV2(0x22, 0x11, addresses4)},
		{name: "v2 unknown version", stream: testProxyV2(0x31, 0x11, addresses4)},
		{name: "v2 addresses cut short", stream: testProxyV2(0x21, 0x11, addresses4[:11])},
		{name: "v2 past max bytes", stream: testProxyV2OfByteCount(2049)},
	}
	for _, c := range cases {
		t.Log(c.name)
		listener, inner := testProxyListener(t, testNeverSettings())
		peerConn := inner.dial(t)
		testWrite(t, peerConn, c.stream)
		testRequireDropped(t, peerConn)
		good := inner.dial(t)
		testWrite(t, good, testProxyV1("192.0.2.1", 1000, "198.51.100.2", 443))
		if conn := testAccept(t, listener); conn.VisitorAddr().Port() != 1000 {
			t.Errorf("%s: accepted %v", c.name, conn.VisitorAddr())
		}
	}
}

func TestProxyHeaderTakes2048BytesAndDrops2049(t *testing.T) {
	listener, inner := testProxyListener(t, testNeverSettings())
	header := testProxyV2OfByteCount(2048)
	if len(header) != 2048 {
		t.Fatalf("built %d B", len(header))
	}
	testWrite(t, inner.dial(t), header)
	if conn := testAccept(t, listener); conn.VisitorAddr() != netip.MustParseAddrPort("192.0.2.1:56324") {
		t.Errorf("visitor %v", conn.VisitorAddr())
	}

	header = testProxyV2OfByteCount(2049)
	if len(header) != 2049 {
		t.Fatalf("built %d B", len(header))
	}
	peerConn := inner.dial(t)
	testWrite(t, peerConn, header)
	testRequireDropped(t, peerConn)
}

// Its length gives a long header away, so nothing waits for the rest of it, whatever the deadline.
func TestProxyHeaderDropsAnOverlongHeaderOnItsLength(t *testing.T) {
	_, inner := testProxyListener(t, testNeverSettings())
	peerConn := inner.dial(t)
	testWrite(t, peerConn, testProxyV2OfByteCount(2049)[:proxyHeaderV2FixedByteCount])
	testRequireDropped(t, peerConn)
}

func TestProxyHeaderDropsAnOverlongV1LineWithNoLineFeed(t *testing.T) {
	_, inner := testProxyListener(t, testNeverSettings())
	peerConn := inner.dial(t)
	testWrite(t, peerConn, []byte("PROXY TCP4 "+strings.Repeat("1", proxyHeaderV1MaxByteCount)))
	testRequireDropped(t, peerConn)
}

// Records what a connection's read deadline was set to.
type testDeadlineConn struct {
	net.Conn
	stateLock sync.Mutex
	deadlines []time.Time
}

func (self *testDeadlineConn) SetReadDeadline(deadline time.Time) error {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.deadlines = append(self.deadlines, deadline)
	}()
	return self.Conn.SetReadDeadline(deadline)
}

// timeout_s is a timer, and a header in time never meets it, however it arrives: the connection
// reaches Accept with no read deadline ever set, so the hello's own deadline is the caller's alone.
// proxy_listener_clock_test.go moves the timer.
func TestProxyHeaderSetsNoDeadlineOnAHeaderInTime(t *testing.T) {
	listener, inner := testProxyListener(t, testNeverSettings())
	peerConn, acceptedConn := net.Pipe()
	defer peerConn.Close()
	deadlineConn := &testDeadlineConn{Conn: acceptedConn}
	inner.conns <- deadlineConn
	for _, b := range testProxyV1("192.0.2.1", 56324, "198.51.100.2", 443) {
		if _, err := peerConn.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	conn := testAccept(t, listener)
	if conn.VisitorAddr().Port() != 56324 {
		t.Errorf("visitor %v", conn.VisitorAddr())
	}
	deadlineConn.stateLock.Lock()
	defer deadlineConn.stateLock.Unlock()
	if len(deadlineConn.deadlines) != 0 {
		t.Errorf("deadlines %v", deadlineConn.deadlines)
	}
}

// A header in pieces is one header. pires alone refuses a v1 line that takes two reads.
func TestProxyHeaderTakesAHeaderAtAnyCut(t *testing.T) {
	hello := []byte("hello")
	headers := [][]byte{
		testProxyV1("192.0.2.1", 56324, "198.51.100.2", 443),
		testProxyV2(0x21, 0x11, testProxyV2Addresses4("192.0.2.1", 56324, "198.51.100.2", 443)),
	}
	listener, inner := testProxyListener(t, testNeverSettings())
	for _, header := range headers {
		stream := append(slices.Clone(header), hello...)
		for cutOffset := 1; cutOffset < len(stream); cutOffset += 1 {
			testWrite(t, inner.dial(t), stream[:cutOffset], stream[cutOffset:])
			conn := testAccept(t, listener)
			if conn.VisitorAddr().Port() != 56324 {
				t.Fatalf("cut at %d: visitor %v", cutOffset, conn.VisitorAddr())
			}
			got := make([]byte, len(hello))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("cut at %d: %v", cutOffset, err)
			}
			if !bytes.Equal(got, hello) {
				t.Fatalf("cut at %d: read %q", cutOffset, got)
			}
			conn.Close()
		}
	}
}

// What the lb writes comes through whole, however much of it arrived with the header: all of it, some
// of it or none, and more than the header's buffer holds.
func TestProxyHeaderKeepsHelloBytesIntact(t *testing.T) {
	large := bytes.Repeat([]byte("0123456789abcdef"), 512)
	go2048 := testProxyV2OfByteCount(2048)
	cases := []struct {
		name   string
		header []byte
		hello  []byte
		writes int
	}{
		{name: "together", header: testProxyV1("192.0.2.1", 1, "198.51.100.2", 2), hello: testGoClientHello(t), writes: 1},
		{name: "apart", header: testProxyV1("192.0.2.1", 1, "198.51.100.2", 2), hello: testGoClientHello(t), writes: 2},
		{name: "v2 together", header: testProxyV2OfByteCount(300), hello: testGoClientHello(t), writes: 1},
		{name: "past the buffer", header: testProxyV1("192.0.2.1", 1, "198.51.100.2", 2), hello: large, writes: 1},
		{name: "behind a full buffer", header: go2048, hello: large, writes: 1},
	}
	for _, c := range cases {
		listener, inner := testProxyListener(t, testNeverSettings())
		peerConn := inner.dial(t)
		stream := append(slices.Clone(c.header), c.hello...)
		if c.writes == 1 {
			testWrite(t, peerConn, stream)
		} else {
			testWrite(t, peerConn, stream[:len(c.header)], stream[len(c.header):])
		}
		conn := testAccept(t, listener)
		got := make([]byte, len(c.hello))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !bytes.Equal(got, c.hello) {
			t.Errorf("%s: hello bytes changed", c.name)
		}
	}
}

func TestProxyHeaderServesSurplusPastAnExpiredDeadline(t *testing.T) {
	listener, inner := testProxyListener(t, testNeverSettings())
	testWrite(t, inner.dial(t), append(testProxyV1("192.0.2.1", 1, "198.51.100.2", 2), "held"...))
	conn := testAccept(t, listener)
	if err := conn.SetReadDeadline(time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "held" {
		t.Errorf("read %q", got)
	}
	if _, err := conn.Read(got); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("past the surplus the deadline applies, and read gave %v", err)
	}
}

func TestProxyHeaderSurplusReadsInOrderInSmallPieces(t *testing.T) {
	listener, inner := testProxyListener(t, testNeverSettings())
	peerConn := inner.dial(t)
	testWrite(t, peerConn, append(testProxyV1("192.0.2.1", 1, "198.51.100.2", 2), "abcde"...))
	conn := testAccept(t, listener)
	got := []byte{}
	one := make([]byte, 1)
	for range 5 {
		if _, err := conn.Read(one); err != nil {
			t.Fatal(err)
		}
		got = append(got, one[0])
	}
	if string(got) != "abcde" {
		t.Errorf("read %q", got)
	}
	if conn.surplusBytes != nil {
		t.Error("a connection that lives for hours still holds the header's buffer")
	}
}

// Concurrent reads get each surplus byte exactly once: net.Conn promises they are safe. go test -race
// is what this is for.
func TestProxyHeaderSurplusIsSafeForConcurrentReads(t *testing.T) {
	listener, inner := testProxyListener(t, testNeverSettings())
	peerConn := inner.dial(t)
	surplus := bytes.Repeat([]byte{1}, 256)
	testWrite(t, peerConn, append(testProxyV1("192.0.2.1", 1, "198.51.100.2", 2), surplus...))
	conn := testAccept(t, listener)
	totals := make(chan int)
	for range 4 {
		go func() {
			total := 0
			buffer := make([]byte, 16)
			for range 4 {
				byteCount, err := conn.Read(buffer)
				if err != nil {
					t.Error(err)
				}
				total += byteCount
			}
			totals <- total
		}()
	}
	sum := 0
	for range 4 {
		sum += <-totals
	}
	if sum != len(surplus) {
		t.Errorf("read %d of %d", sum, len(surplus))
	}
}

func TestProxyHeaderStalledPeerDoesNotDelayAnother(t *testing.T) {
	listener, inner := testProxyListener(t, testNeverSettings())
	stalled := inner.dial(t)
	if _, err := stalled.Write([]byte("PRO")); err != nil {
		t.Fatal(err)
	}
	good := inner.dial(t)
	testWrite(t, good, testProxyV1("192.0.2.1", 1000, "198.51.100.2", 443))
	if conn := testAccept(t, listener); conn.VisitorAddr().Port() != 1000 {
		t.Errorf("accepted %v", conn.VisitorAddr())
	}
	// the stalled one is still waiting, deadline and all: finishing its header passes it through
	testWrite(t, stalled, []byte("XY TCP4 192.0.2.1 198.51.100.2 2000 443\r\n"))
	if conn := testAccept(t, listener); conn.VisitorAddr().Port() != 2000 {
		t.Errorf("accepted %v", conn.VisitorAddr())
	}
}

func TestProxyHeaderDropsPastMaxPendingCount(t *testing.T) {
	settings := testNeverSettings()
	settings.MaxPendingCount = 2
	listener, inner := testProxyListener(t, settings)
	first := inner.dial(t)
	second := inner.dial(t)
	third := inner.dial(t)
	// run has taken third and looked at the slots once it comes back for this one
	fourth := inner.dial(t)
	testRequireDropped(t, third)
	testRequireDropped(t, fourth)

	// neither of the first two lost anything, and a slot given back is used again
	testWrite(t, first, testProxyV1("192.0.2.1", 1000, "198.51.100.2", 443))
	if conn := testAccept(t, listener); conn.VisitorAddr().Port() != 1000 {
		t.Errorf("accepted %v", conn.VisitorAddr())
	}
	testWrite(t, second, testProxyV1("192.0.2.1", 2000, "198.51.100.2", 443))
	if conn := testAccept(t, listener); conn.VisitorAddr().Port() != 2000 {
		t.Errorf("accepted %v", conn.VisitorAddr())
	}
	for {
		next := inner.dial(t)
		if _, err := next.Write(testProxyV1("192.0.2.1", 3000, "198.51.100.2", 443)); err == nil {
			if conn := testAccept(t, listener); conn.VisitorAddr().Port() != 3000 {
				t.Errorf("accepted %v", conn.VisitorAddr())
			}
			break
		}
	}
}

// A connection with its header read and no one accepting it holds its slot, so a host that stops
// calling Accept cannot be made to hold more than MaxPendingCount.
func TestProxyHeaderHoldsASlotWaitingForAccept(t *testing.T) {
	settings := testNeverSettings()
	settings.MaxPendingCount = 1
	listener, inner := testProxyListener(t, settings)
	waiting := inner.dial(t)
	if _, err := waiting.Write(testProxyV1("192.0.2.1", 1000, "198.51.100.2", 443)); err != nil {
		t.Fatal(err)
	}
	refused := inner.dial(t)
	testRequireDropped(t, refused)
	if conn := testAccept(t, listener); conn.VisitorAddr().Port() != 1000 {
		t.Errorf("accepted %v", conn.VisitorAddr())
	}
}

func TestProxyHeaderCloseEndsEverythingNotYetAccepted(t *testing.T) {
	listener, inner := testProxyListener(t, testNeverSettings())
	reading := inner.dial(t)
	waiting := inner.dial(t)
	if _, err := waiting.Write(testProxyV1("192.0.2.1", 1000, "198.51.100.2", 443)); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	testRequireDropped(t, reading)
	testRequireDropped(t, waiting)
	select {
	case <-inner.closed:
	default:
		t.Error("the inner listener is still open")
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("accept after close gave %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Errorf("a second close: %v", err)
	}
}

func TestProxyHeaderCloseLeavesAcceptedConnectionsOpen(t *testing.T) {
	listener, inner := testProxyListener(t, testNeverSettings())
	peerConn := inner.dial(t)
	testWrite(t, peerConn, testProxyV1("192.0.2.1", 1000, "198.51.100.2", 443))
	conn := testAccept(t, listener)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	// a byte at a time, so that anything still on its way to close this has every chance to arrive
	pieces := [][]byte{}
	for range 1000 {
		pieces = append(pieces, []byte{'x'})
	}
	testWrite(t, peerConn, pieces...)
	got := make([]byte, 1)
	for range pieces {
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
	}
}

// Accept stops a connection's close before the connection is the caller's, so a close in the handoff
// either finds it stopped or has the connection, and then Accept refuses it rather than return a
// connection the close is ending. Here the close has it: Accept answers net.ErrClosed, and the
// connection ends.
func TestProxyHeaderAcceptRefusesAConnectionItsCloseHas(t *testing.T) {
	listener, _ := testProxyListener(t, testNeverSettings())
	serverConn, peerConn := net.Pipe()
	defer peerConn.Close()
	closeCtx, cancelClose := context.WithCancel(context.Background())
	stopClose := context.AfterFunc(closeCtx, func() {
		serverConn.Close()
	})
	// the close has started, so its stop reports it could not stop it
	cancelClose()
	go func() {
		listener.(*proxyHeaderListener).readyConns <- &proxyHeaderHandoff{conn: &ProxyHeaderConn{Conn: serverConn}, stopClose: stopClose}
	}()
	conn, err := listener.Accept()
	if conn != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("accept gave %v, %v", conn, err)
	}
	peerConn.SetReadDeadline(time.Now().Add(testGuardTimeout))
	if _, err := peerConn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("the refused connection read %v", err)
	}
}

func TestProxyHeaderCloseUnblocksAccept(t *testing.T) {
	listener, _ := testProxyListener(t, testNeverSettings())
	result := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		result <- err
	}()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("accept gave %v", err)
		}
	case <-time.After(testGuardTimeout):
		t.Fatal("accept never returned")
	}
}

func TestProxyHeaderContextEndClosesTheListener(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	inner := newTestInnerListener()
	listener, err := NewProxyHeaderListener(ctx, inner, testNeverSettings())
	if err != nil {
		t.Fatal(err)
	}
	reading := inner.dial(t)
	cancel()
	testRequireDropped(t, reading)
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("accept gave %v", err)
	}
	select {
	case <-inner.closed:
	case <-time.After(testGuardTimeout):
		t.Error("the inner listener stayed open")
	}
	if err := listener.Close(); err != nil {
		t.Error(err)
	}
}

// A temporary net.Error, as the kernel gives for running out of descriptors.
type testTemporaryError struct{}

func (self testTemporaryError) Error() string   { return "temporary" }
func (self testTemporaryError) Timeout() bool   { return false }
func (self testTemporaryError) Temporary() bool { return true }

func TestProxyHeaderCloseCutsAnAcceptRetryShort(t *testing.T) {
	settings := testNeverSettings()
	settings.AcceptRetryTimeout = testNeverTimeout
	listener, inner := testProxyListener(t, settings)
	inner.errs <- testTemporaryError{}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProxyHeaderGivesAPermanentAcceptFailureToAccept(t *testing.T) {
	listener, inner := testProxyListener(t, testNeverSettings())
	reading := inner.dial(t)
	failure := errors.New("the listener broke")
	inner.errs <- failure
	if _, err := listener.Accept(); !errors.Is(err, failure) {
		t.Errorf("accept gave %v", err)
	}
	testRequireDropped(t, reading)
	select {
	case <-inner.closed:
	case <-time.After(testGuardTimeout):
		t.Error("the inner listener stayed open")
	}
}

func TestNewProxyHeaderListenerRefusesWhatCannotRun(t *testing.T) {
	mutations := []func(settings *ProxyHeaderSettings){
		func(settings *ProxyHeaderSettings) { settings.Timeout = 0 },
		func(settings *ProxyHeaderSettings) { settings.Timeout = -1 },
		func(settings *ProxyHeaderSettings) { settings.MaxByteCount = 0 },
		func(settings *ProxyHeaderSettings) { settings.MaxByteCount = proxyHeaderV1MaxByteCount - 1 },
		func(settings *ProxyHeaderSettings) { settings.MaxPendingCount = 0 },
		func(settings *ProxyHeaderSettings) { settings.AcceptRetryTimeout = 0 },
	}
	for index, mutate := range mutations {
		settings := DefaultProxyHeaderSettings()
		mutate(settings)
		if _, err := NewProxyHeaderListener(context.Background(), newTestInnerListener(), settings); err == nil {
			t.Errorf("mutation %d: no error", index)
		}
	}
	if _, err := NewProxyHeaderListener(context.Background(), newTestInnerListener(), nil); err == nil {
		t.Error("no settings: no error")
	}

	inner := newTestInnerListener()
	inner.addr = &net.UnixAddr{Name: "not-a-tcp-listener", Net: "unix"}
	if _, err := NewProxyHeaderListener(context.Background(), inner, DefaultProxyHeaderSettings()); err == nil {
		t.Error("a unix listener: no error")
	}
}

func TestDefaultProxyHeaderSettingsAreSection13s(t *testing.T) {
	settings := DefaultProxyHeaderSettings()
	if settings.Timeout != 2*time.Second || settings.MaxByteCount != 2048 {
		t.Errorf("%+v", settings)
	}
	if err := settings.validate(); err != nil {
		t.Error(err)
	}
}

// Settings are the caller's to change afterward without reaching a running listener.
func TestNewProxyHeaderListenerCopiesItsSettings(t *testing.T) {
	settings := testNeverSettings()
	listener, inner := testProxyListener(t, settings)
	settings.MaxByteCount = proxyHeaderV1MaxByteCount
	testWrite(t, inner.dial(t), testProxyV2OfByteCount(2048))
	if conn := testAccept(t, listener); conn.VisitorAddr().Port() != 56324 {
		t.Errorf("accepted %v", conn.VisitorAddr())
	}
}

// §13.5's first step through real sockets: the lb's line and a visitor's hello in one write, then the
// alert back through the wrapped conn, as tlsedge's connection path will use them. timeout_s is out of
// reach, since a loaded host must not fail this on real time, and proxy_listener_clock_test.go moves it.
func TestProxyHeaderComposedOverTcp(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := NewProxyHeaderListener(context.Background(), inner, testNeverSettings())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	lbConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer lbConn.Close()
	hello := testGoClientHello(t)
	following := []byte("record after the hello")
	stream := append(testProxyV1("203.0.113.9", 56324, "198.51.100.2", 9999), hello...)
	if _, err := lbConn.Write(append(stream, following...)); err != nil {
		t.Fatal(err)
	}

	conn := testAccept(t, listener)
	if conn.VisitorAddr() != netip.MustParseAddrPort("203.0.113.9:56324") {
		t.Errorf("visitor %v", conn.VisitorAddr())
	}
	if conn.AcceptPort() != inner.Addr().(*net.TCPAddr).Port {
		t.Errorf("accept port %d", conn.AcceptPort())
	}
	if conn.LocalAddr().String() != inner.Addr().String() {
		t.Errorf("local address %v", conn.LocalAddr())
	}
	read, err := ReadClientHello(conn, testMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if read.ServerName != testServerName || !bytes.Equal(read.RawBytes, hello) {
		t.Errorf("read %q, %d B of %d", read.ServerName, len(read.RawBytes), len(hello))
	}
	got := make([]byte, len(following))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, following) {
		t.Errorf("bytes after the hello read %q", got)
	}

	if err := WriteTlsAlert(conn, TlsAlertUnrecognizedName); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	written, err := io.ReadAll(lbConn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 112}) {
		t.Errorf("the lb read %x", written)
	}
}

// A pipe has no half-close, and a caller must be told rather than fail silently.
func TestProxyHeaderCloseWriteSaysWhenItCannot(t *testing.T) {
	listener, inner := testProxyListener(t, testNeverSettings())
	testWrite(t, inner.dial(t), testProxyV1("192.0.2.1", 1, "198.51.100.2", 2))
	if err := testAccept(t, listener).CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("%v", err)
	}
}

// Every refusal is a fixed text, so even a host that logged one could leak no address.
func TestProxyHeaderErrorsHoldNoAddress(t *testing.T) {
	headers := [][]byte{
		[]byte("PROXY TCP4 192.0.2.1 198.51.100.2 65536 2\r\n"),
		[]byte("PROXY TCP4 192.0.2.1 198.51.100.2 1 2 3\r\n"),
		[]byte("PROXY TCP6 192.0.2.1 198.51.100.2 1 2\r\n"),
		[]byte("PROXY TCP4 192.0.2.1 198.51.100.2 1 2\n"),
		testProxyV2(0x21, 0x41, testProxyV2Addresses4("192.0.2.1", 1, "198.51.100.2", 2)),
		testProxyV2(0x20, 0x11, testProxyV2Addresses4("192.0.2.1", 1, "198.51.100.2", 2)),
	}
	for _, header := range headers {
		_, err := testReadProxyHeader(header, 0)
		if err == nil {
			t.Errorf("%q: read", header)
			continue
		}
		if strings.Contains(err.Error(), "192.0.2.1") || strings.Contains(err.Error(), "198.51.100.2") {
			t.Errorf("%q: %v", header, err)
		}
	}
}

// The file holds no logger, which is how neither address reaches a log, and no TLS library. The root
// holds a Logger, so the file may name only its Clock and RealClock from there.
func TestProxyListenerFileHoldsNoLoggerOrTlsLibrary(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "proxy_listener.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := "github.com/" + "urnetwork/sidecar"
	refusedImports := []string{"crypto/tls", "crypto/x509", "log", "log/slog", "github.com/" + "urnetwork/glog"}
	rootNames := map[string]bool{}
	for _, importSpec := range file.Imports {
		importPath, err := strconv.Unquote(importSpec.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(refusedImports, importPath) {
			t.Errorf("proxy_listener.go imports %s", importPath)
		}
		if importPath == rootPath {
			rootName := "sidecar"
			if importSpec.Name != nil {
				rootName = importSpec.Name.Name
			}
			rootNames[rootName] = true
		}
	}
	allowedRootNames := []string{"Clock", "RealClock"}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if packageIdent, ok := selector.X.(*ast.Ident); ok && rootNames[packageIdent.Name] && !slices.Contains(allowedRootNames, selector.Sel.Name) {
			t.Errorf("proxy_listener.go names the root's %s", selector.Sel.Name)
		}
		return true
	})
	// a dot or blank import would hide what the file takes from the root
	for rootName := range rootNames {
		if rootName == "." || rootName == "_" {
			t.Errorf("proxy_listener.go imports the root as %s", rootName)
		}
	}
}
