//go:build !sidecar_http && !js

// SubprotocolStream as a net.Conn (PROTO-M5-02): x/net's nettest over two dispatchers on real time, as
// net.Conn's deadlines are; a deadline that leaves the stream usable; Close as StreamClose that stops
// reading while the peer finishes; Reset and its code at both ends; an ack error resetting with
// TRANSFER_FAILED; and SOCK's SocketConn over a stream end to end, its reset reaching ECONNRESET (C-16).

package sidecar

import (
	"bytes"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/nettest"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// Two dispatchers on real time and a stream between them each time it is called.
func testStreamConnMaker(t *testing.T) func() (*SubprotocolStream, *SubprotocolStream) {
	t.Helper()
	pair := newTestRpcPair(t)
	pair.realClock = true
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	return func() (*SubprotocolStream, *SubprotocolStream) {
		return testStreamOpen(t, b, a, incomings, nil)
	}
}

// §22.5's net.Conn conformance: nettest's whole suite, deadlines and racing methods among it.
func TestSubprotocolStreamPassesNettest(t *testing.T) {
	makeStreams := testStreamConnMaker(t)
	nettest.TestConn(t, func() (net.Conn, net.Conn, func(), error) {
		opened, accepted := makeStreams()
		stop := func() {
			opened.Reset(protocol.StreamResetCode_RST_CANCELLED)
			opened.Close()
			accepted.Close()
		}
		return opened, accepted, stop, nil
	})
}

// A passed deadline fails I/O as a timeout and leaves the stream usable once it is cleared.
func TestSubprotocolStreamDeadlineLeavesTheStreamUsable(t *testing.T) {
	_, a, b := newTestStreamSides(t, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	opened, accepted := testStreamOpen(t, b, a, incomings, nil)
	if err := accepted.SetReadDeadline(a.clock.Now()); err != nil {
		t.Fatal(err)
	}
	var netErr net.Error
	if _, err := accepted.Read(make([]byte, 8)); !errors.As(err, &netErr) || !netErr.Timeout() || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a passed deadline: %v", err)
	}
	if err := opened.SetWriteDeadline(b.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if n, err := opened.Write([]byte("lost")); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a write past its deadline: %d %v", n, err)
	}
	accepted.SetReadDeadline(time.Time{})
	opened.SetWriteDeadline(time.Time{})
	if _, err := opened.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	if got := testStreamReadFull(t, accepted, 5); string(got) != "after" {
		t.Errorf("read %q", got)
	}
	// a deadline on the dispatcher's clock wakes a waiting read when the clock reaches it
	accepted.SetReadDeadline(a.clock.Now().Add(time.Second))
	readErr := make(chan error, 1)
	go func() {
		_, err := accepted.Read(make([]byte, 8))
		readErr <- err
	}()
	a.clock.awaitWaitCount(a.clock.waitCount.Value() + 1)
	a.clock.Advance(time.Second)
	if err := testAwait(t, readErr, "the read at its deadline"); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the read at its deadline: %v", err)
	}
	opened.Close()
	accepted.Close()
}

// Close is StreamClose that stops reading: the peer reads io.EOF, what the peer still sends is consumed
// and dropped with its credit returned, so the peer's writes past the window go on, and once the peer
// closes too the stream finishes on both ends.
func TestSubprotocolStreamCloseStopsReading(t *testing.T) {
	_, a, b := newTestStreamSides(t, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	opened, accepted := testStreamOpen(t, b, a, incomings, nil)
	if _, err := opened.Write([]byte("unread")); err != nil {
		t.Fatal(err)
	}
	if err := accepted.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := opened.Read(make([]byte, 8)); n != 0 || err != io.EOF {
		t.Errorf("the peer read %d %v", n, err)
	}
	// past every window the closed end ever granted: it drops and grants on
	if _, err := opened.Write(bytes.Repeat([]byte{1}, 2*1024*1024)); err != nil {
		t.Fatalf("writing to a closed reader: %v", err)
	}
	if _, err := accepted.Read(make([]byte, 8)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a read after Close: %v", err)
	}
	if _, err := accepted.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a write after Close: %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	testStreamsSettled(t, a)
	testStreamsSettled(t, b)
}

// Reset ends both directions at once with its code, here and at the peer; a zero code goes as PROTOCOL; a
// second Reset sends nothing more.
func TestSubprotocolStreamResetReachesBothEnds(t *testing.T) {
	_, a, b := newTestStreamSides(t, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	for _, c := range []struct {
		code protocol.StreamResetCode
		want protocol.StreamResetCode
	}{
		{code: protocol.StreamResetCode_RST_QUOTA, want: protocol.StreamResetCode_RST_QUOTA},
		{code: protocol.StreamResetCode_RST_UNSPECIFIED, want: protocol.StreamResetCode_RST_PROTOCOL},
	} {
		opened, accepted := testStreamOpen(t, b, a, incomings, nil)
		if _, err := accepted.Write([]byte("in flight")); err != nil {
			t.Fatal(err)
		}
		resetCount := len(testSentTypes(b))
		if err := opened.Reset(c.code); err != nil {
			t.Fatal(err)
		}
		var resetErr *StreamResetError
		if _, err := opened.Read(make([]byte, 64)); !errors.As(err, &resetErr) || resetErr.Code != c.want || !resetErr.Local {
			t.Errorf("%v: here %v", c.code, err)
		}
		if _, err := opened.Write([]byte("x")); !errors.As(err, &resetErr) || resetErr.Code != c.want {
			t.Errorf("%v: a write after the reset %v", c.code, err)
		}
		testAwaitSent(t, b, func(sent []*protocol.Envelope) bool {
			return testFirstSent(sent[resetCount:], protocol.MessageType_STREAM_RESET) != nil
		})
		if _, err := accepted.Read(make([]byte, 64)); !errors.As(err, &resetErr) || resetErr.Code != c.want || resetErr.Local {
			t.Errorf("%v: at the peer %v", c.code, err)
		}
		opened.Reset(c.code)
		if count := len(testSentTypes(b)) - resetCount; count != 1 {
			t.Errorf("%v: %d frames for two resets", c.code, count)
		}
	}
	testStreamsSettled(t, a)
	testStreamsSettled(t, b)
}

// An ack error on a stream's frame resets it with TRANSFER_FAILED (§6.7's errors row), and so does a send
// connect refuses.
func TestSubprotocolStreamAckErrorResetsTransferFailed(t *testing.T) {
	_, a, b := newTestStreamSides(t, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	opened, accepted := testStreamOpen(t, b, a, incomings, nil)
	opened.ackFunction(time.Time{})(errors.New("ack timeout"))
	var resetErr *StreamResetError
	if _, err := opened.Write([]byte("x")); !errors.As(err, &resetErr) || resetErr.Code != protocol.StreamResetCode_RST_TRANSFER_FAILED {
		t.Errorf("after an ack error: %v", err)
	}
	if _, err := accepted.Read(make([]byte, 8)); !errors.As(err, &resetErr) || resetErr.Code != protocol.StreamResetCode_RST_TRANSFER_FAILED || resetErr.Local {
		t.Errorf("at the peer: %v", err)
	}
	// a refused send: the data cannot be skipped, so the stream ends
	opened, accepted = testStreamOpen(t, b, a, incomings, nil)
	func() {
		b.stateLock.Lock()
		defer b.stateLock.Unlock()
		b.refuseCount = 1
	}()
	if _, err := opened.Write([]byte("refused")); !errors.As(err, &resetErr) || resetErr.Code != protocol.StreamResetCode_RST_TRANSFER_FAILED {
		t.Errorf("a refused send: %v", err)
	}
	accepted.Close()
}

// SOCK's SocketConn over a stream (C-16's join): bytes both ways, FIN as io.EOF, and the peer's Abort
// reaching this end as §9.9's ECONNRESET with the reset's code.
func TestSocketConnOverASubprotocolStream(t *testing.T) {
	_, a, b := newTestStreamSides(t, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	opened, accepted := testStreamOpen(t, b, a, incomings, nil)
	dialerAddr := &SocketAddr{NetworkId: connect.NewId(), ClientId: b.clientId}
	listenerAddr := &SocketAddr{NetworkId: dialerAddr.NetworkId, ClientId: a.clientId}
	dialer := newSocketConn(newSubprotocolSocketStream(opened), dialerAddr, listenerAddr, nil, nil)
	listener := newSocketConn(newSubprotocolSocketStream(accepted), listenerAddr, dialerAddr, nil, []byte("open metadata"))
	if _, err := dialer.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(listener, got); err != nil || string(got) != "ping" {
		t.Fatalf("read %q %v", got, err)
	}
	if err := dialer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n, err := listener.Read(got); n != 0 || err != io.EOF {
		t.Errorf("after FIN: %d %v", n, err)
	}
	if err := listener.Abort(); err != nil {
		t.Fatal(err)
	}
	_, err := dialer.Read(got)
	var opErr *net.OpError
	var codeErr *SocketCodeError
	if !errors.As(err, &opErr) || opErr.Net != "ur" || !errors.Is(err, syscall.ECONNRESET) ||
		!errors.As(err, &codeErr) || codeErr.ResetCode != protocol.StreamResetCode_RST_CANCELLED {
		t.Errorf("the peer's abort read as %v", err)
	}
}

// The stream_ files that build on every leg: §6.7's rules as pure code, which name no connect type
// (PROTO-M5-01). The wire's files are off the sidecar_http leg (§4.4), since a page Worker neither opens
// nor accepts a stream.
var streamEveryLegFiles = map[string]bool{
	"stream_state.go":  true,
	"stream_credit.go": true,
	"stream_buffer.go": true,
}

// make check's leg rule for streams: every stream_ file but the pure rules is absent from sidecar_http,
// and those name no connect package.
func TestStreamFilesKeepToTheirLegs(t *testing.T) {
	buildContext := sidecarHttpBuildContext()
	fileSet := token.NewFileSet()
	wireFileCount := 0
	for _, goFile := range rootGoFiles(t) {
		if !strings.HasPrefix(goFile, "stream_") || strings.HasSuffix(goFile, "_test.go") {
			continue
		}
		matched, err := buildContext.MatchFile(".", goFile)
		if err != nil {
			t.Fatal(err)
		}
		if !streamEveryLegFiles[goFile] {
			wireFileCount += 1
			if matched {
				t.Errorf("%s builds on the sidecar_http leg", goFile)
			}
			continue
		}
		if !matched {
			t.Errorf("%s is off the sidecar_http leg", goFile)
		}
		file, err := parser.ParseFile(fileSet, goFile, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			if namesConnect(strings.Trim(spec.Path.Value, `"`)) {
				t.Errorf("%s imports %s", goFile, spec.Path.Value)
			}
		}
	}
	if wireFileCount < 6 {
		t.Errorf("%d of the wire's stream_ files", wireFileCount)
	}
}
