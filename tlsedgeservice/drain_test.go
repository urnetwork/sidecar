// How the engine ends (§13.5's drain_s): a drain waits for what is open, resets it at drain_s, and sends
// the last usage window and records.

package tlsedgeservice_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A drain stops accepting at once, lets an open stream run until drain_s, resets it then with
// RST_DRAINING, and leaves with the bytes billed and the record written.
func TestTlsEdgeDrainResetsAtDrainTimeout(t *testing.T) {
	world := newTestPathWorld(t, nil)
	conn, stream, hello := world.open(t, "blog")
	stream.listenerWrite(t, []byte("before the drain"))
	testVisitorRead(t, conn, 16)

	drained := make(chan struct{})
	drainStart := world.clock.Now()
	go func() {
		world.service.Drain()
		close(drained)
	}()
	testAwaitTimer(t, world.clock, drainStart.Add(600*time.Second))
	select {
	case err := <-world.served:
		if err != nil {
			t.Fatalf("Serve ended a drain with %v", err)
		}
	case <-time.After(testGuardTimeout):
		t.Fatal("Serve outlived the drain's start")
	}
	if late, err := net.Dial("tcp", world.address); err == nil {
		late.Close()
		t.Fatal("a draining engine still accepts")
	}
	// the open stream runs on
	stream.listenerWrite(t, []byte("during"))
	if read := testVisitorRead(t, conn, 6); string(read) != "during" {
		t.Fatalf("a draining stream read %q", read)
	}
	select {
	case <-drained:
		t.Fatal("the drain returned with a stream open")
	default:
	}

	world.clock.Advance(600 * time.Second)
	if code := stream.awaitReset(t); code != protocol.StreamResetCode_RST_DRAINING {
		t.Fatalf("a drain reset with %v", code)
	}
	select {
	case <-drained:
	case <-time.After(testGuardTimeout):
		t.Fatal("the drain never returned")
	}
	if _, err := io.ReadAll(conn); err == nil {
		t.Fatal("the drained visitor read a clean end")
	}
	byteCount := int64(len(hello) + 16 + 6)
	if got := world.host.Quota.TransferUsed(connect.Id(world.networkId), sidecar.QuotaMeterTls); got != byteCount {
		t.Fatalf("%d B billed of %d", got, byteCount)
	}
	records := world.store.Records()
	if len(records) != 1 || records[0].ByteCount != byteCount {
		t.Fatalf("the drain left records %+v", records)
	}
	if got := world.host.Metrics.Value("urnetwork_tlsedge_stream_ends_total", "drain"); got != 1 {
		t.Fatalf("%v drained streams counted", got)
	}
}

// A drain returns as soon as the last open connection ends by itself, with no reset.
func TestTlsEdgeDrainReturnsWhenConnectionsEnd(t *testing.T) {
	world := newTestPathWorld(t, nil)
	conn, stream, _ := world.open(t, "blog")
	drained := make(chan struct{})
	drainStart := world.clock.Now()
	go func() {
		world.service.Drain()
		close(drained)
	}()
	testAwaitTimer(t, world.clock, drainStart.Add(600*time.Second))
	conn.CloseWrite()
	stream.listenerReadAll(t)
	stream.listenerCloseWrite()
	select {
	case <-drained:
	case <-time.After(testGuardTimeout):
		t.Fatal("the drain outlived its last connection")
	}
	if got := world.host.Metrics.Value("urnetwork_tlsedge_stream_ends_total", "closed"); got != 1 {
		t.Fatalf("%v clean ends counted", got)
	}
	if got := len(world.store.Records()); got != 1 {
		t.Fatalf("%d records written", got)
	}
}
