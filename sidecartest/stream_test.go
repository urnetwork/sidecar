package sidecartest

// §22.5's §6 stream rows on T2 (PROTO-M5-05; D-PROTO-4, R-PROTO-9, R-PROTO-10), through real Sidecars' dispatchers on
// the Net's exchange: a stream over a lossy link delivers its bytes intact or resets, never a silent gap; a lost
// pack stalls the pair's streams until connect resends it, and they then recover; and a reader that stops reading
// holds its own stream at its window while a sibling stream on the same pair runs to its end. The stall a lost pack
// costs, D-PROTO-4's measure, is recorded at connect's ack, which no test here can wait for, so its export is held
// at the root on the dispatcher's own clock (stream_stall_test.go). The T3 half, on server's exchange, is
// server/connect/sidecar_stream_t3_test.go.

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A stream target the pair's acceptor listens on.
const testStreamTarget = "stream-test"

// How long, in real time, a stream step may take before the test fails: only a failure's bound.
const testStreamTimeout = 60 * time.Second

// Two admitted sidecars, b accepting every stream to testStreamTarget onto the channel answered.
func newTestStreamPair(t *testing.T) (*Net, *SubprotocolSidecar, *SubprotocolSidecar, chan *sidecar.SubprotocolStream) {
	t.Helper()
	net := newTestNet(t)
	sidecars, _, err := net.AddSubprotocolSidecars("laptop", "desktop")
	if err != nil {
		t.Fatal(err)
	}
	a, b := sidecars[0], sidecars[1]
	accepted := make(chan *sidecar.SubprotocolStream, 16)
	if _, err := b.Subprotocol().Listen(testStreamTarget, func(ctx context.Context, incoming *sidecar.StreamIncoming) error {
		accepted <- incoming.Stream
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return net, a, b, accepted
}

// Opens a stream from a to b and answers both ends.
func testOpenStream(t *testing.T, a *SubprotocolSidecar, b *SubprotocolSidecar, accepted chan *sidecar.SubprotocolStream) (*sidecar.SubprotocolStream, *sidecar.SubprotocolStream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testStreamTimeout)
	defer cancel()
	opened, err := a.Subprotocol().OpenStream(ctx, sidecar.Id(b.ClientId()), &sidecar.StreamOpenRequest{Target: testStreamTarget})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { opened.Close() })
	select {
	case stream := <-accepted:
		t.Cleanup(func() { stream.Close() })
		return opened, stream
	case <-ctx.Done():
		t.Fatal("no stream accepted")
	}
	return nil, nil
}

// size random bytes.
func testStreamBytes(t *testing.T, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return data
}

// Writes data to writer and closes its write side, on a goroutine of its own, answering what the write ended with.
func testStreamWrite(writer *sidecar.SubprotocolStream, data []byte) chan error {
	done := make(chan error, 1)
	go func() {
		if _, err := writer.Write(data); err != nil {
			done <- err
			return
		}
		done <- writer.CloseWrite()
	}()
	return done
}

// Runs read, which reads stream, and answers its error, failing t should deadline pass first in real time: the stream is
// then closed, which ends a read still waiting, t fails with what, and the answer is os.ErrDeadlineExceeded. A stream's
// own read deadline runs on its dispatcher's clock, the Net's fake one, which moves only as a test steps it, so it
// bounds no real wait: a read given a deadline a minute ahead waited twelve minutes in a landcheck once its bytes had
// gone to another stream (QD-1195).
func testStreamReadBy(t testing.TB, stream *sidecar.SubprotocolStream, deadline time.Time, what string, read func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- read()
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Until(deadline)):
		// Close wakes the read before it sends anything, so the read ends even while the close's own send waits
		go stream.Close()
		err := <-done
		t.Errorf("%s: nothing by its deadline in real time, the read ending %v once the stream closed", what, err)
		return os.ErrDeadlineExceeded
	}
}

// Reads reader to its end within testStreamTimeout in real time.
func testStreamReadAll(t testing.TB, reader *sidecar.SubprotocolStream) ([]byte, error) {
	t.Helper()
	var all []byte
	err := testStreamReadBy(t, reader, time.Now().Add(testStreamTimeout), "the read to the stream's end", func() error {
		var err error
		all, err = io.ReadAll(reader)
		return err
	})
	return all, err
}

// Fills read from reader within testStreamTimeout in real time.
func testStreamReadFull(t testing.TB, reader *sidecar.SubprotocolStream, read []byte) error {
	t.Helper()
	return testStreamReadBy(t, reader, time.Now().Add(testStreamTimeout), "the read", func() error {
		_, err := io.ReadFull(reader, read)
		return err
	})
}

// A TB that records what fails rather than failing the test.
type testStreamReadRecorder struct {
	testing.TB
	failures []string
}

// See testing.TB.
func (self *testStreamReadRecorder) Helper() {}

// See testing.TB: the failure is kept, and the test goes on.
func (self *testStreamReadRecorder) Errorf(format string, args ...any) {
	self.failures = append(self.failures, fmt.Sprintf(format, args...))
}

// What written, a testStreamWrite's answer, ended with, within testStreamTimeout in real time.
func testStreamWritten(t *testing.T, written chan error) error {
	t.Helper()
	select {
	case err := <-written:
		return err
	case <-time.After(testStreamTimeout):
		t.Fatal("the write never ended")
		return nil
	}
}

// Why a read here is bounded by testStreamReadBy's real timer: a stream's read deadline runs on its dispatcher's clock,
// the Net's fake one, so a deadline a second past that clock, which is months before real time, ends a read only once
// the Net's clock is stepped past it; and testStreamReadBy ends a read that nothing reaches when its real deadline
// passes, closing the stream, and fails the test it was given.
func TestStreamReadDeadlineRunsOnTheNetsClock(t *testing.T) {
	testNet, a, b, accepted := newTestStreamPair(t)
	_, stream := testOpenStream(t, a, b, accepted)
	clock := testNet.Clock()
	if !clock.Now().Add(time.Second).Before(time.Now()) {
		t.Fatal("the Net's clock is not behind real time")
	}
	if err := stream.SetReadDeadline(clock.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	read := make(chan error, 1)
	go func() {
		_, err := stream.Read(make([]byte, 1))
		read <- err
	}()
	clock.Advance(time.Second)
	select {
	case err := <-read:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("the read past its deadline on the Net's clock: %v", err)
		}
	case <-time.After(testStreamTimeout):
		t.Fatal("a read deadline the Net's clock passed never ended the read")
	}

	if err := stream.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	// no bytes and no deadline of the stream's own: only the real deadline, passed at once, ends this read, failing the
	// recorder in the test's place
	recorder := &testStreamReadRecorder{TB: t}
	var readErr error
	err := testStreamReadBy(recorder, stream, time.Now(), "a read nothing reaches", func() error {
		_, readErr = stream.Read(make([]byte, 1))
		return readErr
	})
	if !errors.Is(err, os.ErrDeadlineExceeded) || !errors.Is(readErr, net.ErrClosed) || len(recorder.failures) != 1 {
		t.Fatalf("a read nothing reaches, past its real deadline: %v, the read %v, failures %q", err, readErr, recorder.failures)
	}
}

// Over a link that drops a fifth of its frames, a stream's bytes arrive whole and in order, connect resending what
// was lost, or the stream resets: what the reader sees is never a gap or a change.
func TestStreamLossyLinkBytesIntactOrReset(t *testing.T) {
	net, a, b, accepted := newTestStreamPair(t)
	opened, stream := testOpenStream(t, a, b, accepted)
	net.SetLink(a.ClientId(), b.ClientId(), &LinkConditions{LossProbability: 0.2})
	net.SetLink(b.ClientId(), a.ClientId(), &LinkConditions{LossProbability: 0.2})
	data := testStreamBytes(t, 96*1024)
	written := testStreamWrite(opened, data)
	read, err := testStreamReadAll(t, stream)
	resetError := &sidecar.StreamResetError{}
	switch {
	case err == nil:
		if !bytes.Equal(read, data) {
			t.Fatalf("%d of %d bytes, changed or with a gap and no reset", len(read), len(data))
		}
	case errors.As(err, &resetError):
		// a reset is the stream's honest end; what came before it is a prefix of what was sent
		if !bytes.HasPrefix(data, read) {
			t.Fatalf("a reset after %d bytes that are not what was sent", len(read))
		}
	default:
		t.Fatalf("the read ended %v after %d bytes", err, len(read))
	}
	select {
	case err := <-written:
		if err != nil && !errors.As(err, &resetError) {
			t.Errorf("the write ended %v", err)
		}
	case <-time.After(testStreamTimeout):
		t.Error("the write never ended")
	}
}

// A partition that drops what was sent stalls the pair's stream until it heals and connect resends: the bytes then
// arrive whole.
func TestStreamLostPackStallsThenRecovers(t *testing.T) {
	net, a, b, accepted := newTestStreamPair(t)
	opened, stream := testOpenStream(t, a, b, accepted)
	warm := testStreamBytes(t, 4*1024)
	if _, err := opened.Write(warm); err != nil {
		t.Fatal(err)
	}
	read := make([]byte, len(warm))
	if err := testStreamReadFull(t, stream, read); err != nil || !bytes.Equal(read, warm) {
		t.Fatalf("before the partition: %v", err)
	}

	net.SetLink(a.ClientId(), b.ClientId(), &LinkConditions{Partition: true})
	data := testStreamBytes(t, 32*1024)
	written := testStreamWrite(opened, data)
	// healed: connect's sequence resends what the partition dropped
	net.SetLink(a.ClientId(), b.ClientId(), nil)
	all, err := testStreamReadAll(t, stream)
	if err != nil || !bytes.Equal(all, data) {
		t.Fatalf("after the partition: %d of %d bytes, %v", len(all), len(data), err)
	}
	if err := testStreamWritten(t, written); err != nil {
		t.Fatal(err)
	}
}

// One stream's reader stops reading: its writer is held at that stream's window, and the pair's other stream runs to
// its end beside it, since stream bytes sit in per-stream buffers bounded by credit, never a shared queue.
func TestStreamSlowReaderHealthySibling(t *testing.T) {
	_, a, b, accepted := newTestStreamPair(t)
	slowWriter, slowReader := testOpenStream(t, a, b, accepted)
	healthyWriter, healthyReader := testOpenStream(t, a, b, accepted)
	// far past any window the slow reader grants
	slowWritten := testStreamWrite(slowWriter, testStreamBytes(t, 4*1024*1024))
	data := testStreamBytes(t, 512*1024)
	healthyWritten := testStreamWrite(healthyWriter, data)
	read, err := testStreamReadAll(t, healthyReader)
	if err != nil || !bytes.Equal(read, data) {
		t.Fatalf("the healthy sibling: %d of %d bytes, %v", len(read), len(data), err)
	}
	if err := testStreamWritten(t, healthyWritten); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-slowWritten:
		t.Fatalf("the slow reader's writer finished past its window: %v", err)
	default:
	}
	// the slow reader still gets what it was sent once it reads
	first := make([]byte, 1024)
	if err := testStreamReadFull(t, slowReader, first); err != nil {
		t.Fatalf("the slow reader: %v", err)
	}
}
