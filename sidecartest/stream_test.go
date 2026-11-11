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
	"io"
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

// Reads reader to its end, bounded in real time by the stream's read deadline.
func testStreamReadAll(t *testing.T, reader *sidecar.SubprotocolStream) ([]byte, error) {
	t.Helper()
	if err := reader.SetReadDeadline(time.Now().Add(testStreamTimeout)); err != nil {
		t.Fatal(err)
	}
	return io.ReadAll(reader)
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
	if err := stream.SetReadDeadline(time.Now().Add(testStreamTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(stream, read); err != nil || !bytes.Equal(read, warm) {
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
	if err := <-written; err != nil {
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
	if err := <-healthyWritten; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-slowWritten:
		t.Fatalf("the slow reader's writer finished past its window: %v", err)
	default:
	}
	// the slow reader still gets what it was sent once it reads
	if err := slowReader.SetReadDeadline(time.Now().Add(testStreamTimeout)); err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 1024)
	if _, err := io.ReadFull(slowReader, first); err != nil {
		t.Fatalf("the slow reader: %v", err)
	}
}
