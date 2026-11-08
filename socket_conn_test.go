//go:build !sidecar_http

// §9.9's SocketConn on the in-memory stream seam (D-SOCK-8): net.Conn conformance by x/net's nettest,
// deadlines that leave the stream usable, half-close each way, Close as FIN that stops reading, Abort as
// a reset, and errors that reach their syscall values.

package sidecar

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"golang.org/x/net/nettest"

	"github.com/urnetwork/sidecar/protocol"
)

// A connected pair of SocketConns: dialer then listener, each direction holding 64 KiB.
func testSocketConnPair() (*SocketConn, *SocketConn) {
	dialerEnd, listenerEnd := newSocketStreamPipe(64 * 1024)
	dialerAddr := &SocketAddr{NetworkId: connect.Id(NewId()), ClientId: connect.Id(NewId())}
	listenerAddr := &SocketAddr{NetworkId: dialerAddr.NetworkId, ClientId: connect.Id(NewId())}
	ticket := &protocol.SocketTicket{TicketId: bytes.Repeat([]byte{7}, 16), Name: "tls/443/blog"}
	dialer := newSocketConn(dialerEnd, dialerAddr, listenerAddr, ticket, nil)
	listener := newSocketConn(listenerEnd, listenerAddr, dialerAddr, ticket, []byte("open metadata"))
	return dialer, listener
}

func TestSocketConnPassesNettest(t *testing.T) {
	nettest.TestConn(t, func() (net.Conn, net.Conn, func(), error) {
		dialer, listener := testSocketConnPair()
		stop := func() {
			dialer.Abort()
			dialer.Close()
			listener.Close()
		}
		return dialer, listener, stop, nil
	})
}

// A passed deadline fails I/O as a timeout, and clearing it lets the same stream go on.
func TestSocketConnDeadlineLeavesTheStreamUsable(t *testing.T) {
	dialer, listener := testSocketConnPair()
	if err := listener.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := listener.Read(make([]byte, 8))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a passed deadline: %v", err)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Net != "ur" {
		t.Fatalf("not ur's OpError: %#v", err)
	}
	if err := dialer.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := dialer.Write([]byte("lost")); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a write past its deadline: %d, %v", n, err)
	}
	if err := listener.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := dialer.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := dialer.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 8)
	n, err := listener.Read(buffer)
	if err != nil || string(buffer[:n]) != "after" {
		t.Fatalf("after the deadline: %q, %v", buffer[:n], err)
	}
}

// CloseWrite is a half-close: the peer reads io.EOF and can still write back, each way in turn.
func TestSocketConnHalfClosesEachWay(t *testing.T) {
	dialer, listener := testSocketConnPair()
	if _, err := dialer.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := dialer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(listener); err != nil || string(got) != "request" {
		t.Fatalf("the listener read %q, %v", got, err)
	}
	if _, err := dialer.Write([]byte("more")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a write after CloseWrite: %v", err)
	}
	if _, err := listener.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := listener.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(dialer); err != nil || string(got) != "response" {
		t.Fatalf("the dialer read %q, %v", got, err)
	}
}

// Close is FIN and stops reading: the peer reads io.EOF after what was sent, its later writes are
// dropped without blocking, and this end's own I/O then fails.
func TestSocketConnCloseIsFinAndStopsReading(t *testing.T) {
	dialer, listener := testSocketConnPair()
	if _, err := dialer.Write([]byte("last words")); err != nil {
		t.Fatal(err)
	}
	if err := dialer.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(listener); err != nil || string(got) != "last words" {
		t.Fatalf("the peer read %q, %v", got, err)
	}
	// more than a direction holds, so a write that waited on a closed reader would never return
	if _, err := listener.Write(make([]byte, 256*1024)); err != nil {
		t.Fatalf("a write to a closed reader: %v", err)
	}
	if _, err := dialer.Read(make([]byte, 8)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a read after Close: %v", err)
	}
	if err := dialer.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a second Close: %v", err)
	}
}

// Abort resets, and both ends see ErrSocketReset with the code, reaching ECONNRESET.
func TestSocketConnAbortSurfacesTheReset(t *testing.T) {
	dialer, listener := testSocketConnPair()
	if _, err := dialer.Write([]byte("in flight")); err != nil {
		t.Fatal(err)
	}
	if err := dialer.Abort(); err != nil {
		t.Fatal(err)
	}
	for _, conn := range []*SocketConn{listener, dialer} {
		_, err := conn.Read(make([]byte, 16))
		if !errors.Is(err, ErrSocketReset) || !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("a read after a reset: %v", err)
		}
		var codeErr *SocketCodeError
		if !errors.As(err, &codeErr) || codeErr.ResetCode != protocol.StreamResetCode_RST_CANCELLED {
			t.Fatalf("the reset's code: %v", err)
		}
		if _, err := conn.Write([]byte("x")); !errors.Is(err, ErrSocketReset) {
			t.Fatalf("a write after a reset: %v", err)
		}
	}
}

func TestSocketConnAddressesTicketAndMetadata(t *testing.T) {
	dialer, listener := testSocketConnPair()
	remote := listener.RemoteAddr()
	if remote.Network() != "ur" || remote.(*SocketAddr).ClientId != dialer.LocalAddr().(*SocketAddr).ClientId {
		t.Fatalf("the listener's remote address %v", remote)
	}
	if want := remote.(*SocketAddr).NetworkId.String() + "/" + remote.(*SocketAddr).ClientId.String(); remote.String() != want {
		t.Fatalf("%q, want %q", remote.String(), want)
	}
	ticket := listener.Ticket()
	ticket.Name = "changed"
	if listener.Ticket().GetName() != "tls/443/blog" {
		t.Fatal("Ticket gave the connection's own ticket")
	}
	metadata := listener.OpenMetadata()
	metadata[0] = 'X'
	if string(listener.OpenMetadata()) != "open metadata" || dialer.OpenMetadata() != nil {
		t.Fatal("OpenMetadata gave the connection's own bytes")
	}
}

// §9.9: each value reaches itself and its errno through the OpError a SocketConn returns, and a wait
// rides with the four that carry one.
func TestSocketErrorsReachTheirValues(t *testing.T) {
	for _, c := range []struct {
		value error
		errno syscall.Errno
	}{
		{value: ErrSocketNoListener, errno: syscall.ECONNREFUSED},
		{value: ErrSocketBusy, errno: syscall.ECONNREFUSED},
		{value: ErrSocketDenied, errno: syscall.EACCES},
		{value: ErrSocketReset, errno: syscall.ECONNRESET},
		{value: ErrSocketUnavailable},
		{value: ErrSocketQuota},
	} {
		err := error(&net.OpError{Op: "dial", Net: "ur", Err: &SocketCodeError{Err: c.value, RetryAfter: time.Second}})
		if !errors.Is(err, c.value) {
			t.Errorf("%v does not reach itself", c.value)
		}
		if c.errno != 0 && !errors.Is(err, c.errno) {
			t.Errorf("%v does not reach %v", c.value, c.errno)
		}
		for _, other := range []syscall.Errno{syscall.ECONNREFUSED, syscall.EACCES, syscall.ECONNRESET} {
			if other != c.errno && errors.Is(err, other) {
				t.Errorf("%v reaches %v", c.value, other)
			}
		}
		var codeErr *SocketCodeError
		if !errors.As(err, &codeErr) || codeErr.RetryAfter != time.Second {
			t.Errorf("%v lost its wait", c.value)
		}
	}
}

// Find's codes map to §9.9's values one to one, and anything else stops the dial.
func TestSocketFindErrorsMapOneToOne(t *testing.T) {
	for _, c := range []struct {
		code       SocketErrorCode
		value      error
		retryAfter time.Duration
	}{
		{code: SocketErrorCodeNoListener, value: ErrSocketNoListener, retryAfter: 1500 * time.Millisecond},
		{code: SocketErrorCodeBusy, value: ErrSocketBusy, retryAfter: 1500 * time.Millisecond},
		{code: SocketErrorCodeDenied, value: ErrSocketDenied},
		{code: SocketErrorCodeQuota, value: ErrSocketQuota, retryAfter: 1500 * time.Millisecond},
		{code: SocketErrorCodeUnavailable, value: ErrSocketUnavailable, retryAfter: 1500 * time.Millisecond},
		{code: SocketErrorCodeStale, value: ErrSocketDenied},
		{code: SocketErrorCode("from a later service"), value: ErrSocketDenied},
	} {
		err := socketFindError(&SocketError{Code: c.code, RetryAfterMs: 1500})
		if err.Err != c.value || err.RetryAfter != c.retryAfter {
			t.Errorf("%q: %v", c.code, err)
		}
	}
}

// A listener's last answer, once no ticket is left: busy, denied and quota as themselves, and the rest,
// 0 included, as no listener.
func TestSocketRejectErrorsMapOneToOne(t *testing.T) {
	for _, c := range []struct {
		code  uint32
		value error
	}{
		{code: uint32(protocol.StreamRejectCode_SR_RETRY), value: ErrSocketNoListener},
		{code: uint32(protocol.StreamRejectCode_SR_BUSY), value: ErrSocketBusy},
		{code: uint32(protocol.StreamRejectCode_SR_DENIED), value: ErrSocketDenied},
		{code: uint32(protocol.StreamRejectCode_SR_INVALID), value: ErrSocketNoListener},
		{code: uint32(protocol.StreamRejectCode_SR_QUOTA), value: ErrSocketQuota},
		{code: 0, value: ErrSocketNoListener},
		{code: 99, value: ErrSocketNoListener},
	} {
		if err := socketRejectError(c.code, 250); err.Err != c.value {
			t.Errorf("code %d: %v", c.code, err)
		}
	}
	if err := socketRejectError(uint32(protocol.StreamRejectCode_SR_DENIED), 250); err.RetryAfter != 0 {
		t.Error("denied carried a wait")
	}
}
