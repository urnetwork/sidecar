// §13.5's step 6 on the scripted dialer: bytes pass untouched both ways, each half closes by itself, a
// reset on one side is a reset on the other, and a kill, a spent lease, the grant's expiry and idleness
// each end an open stream with their code.

package tlsedgeservice_test

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// Reads byteCount bytes from the visitor's side.
func testVisitorRead(t *testing.T, conn io.Reader, byteCount int) []byte {
	t.Helper()
	read := make([]byte, byteCount)
	if _, err := io.ReadFull(conn, read); err != nil {
		t.Fatalf("the visitor read: %v", err)
	}
	return read
}

// Bytes are the same on both sides of the splice, in both directions, a FIN from the visitor is a
// StreamClose and a StreamClose from the listener a FIN, each leaving the other half open, and the
// connection's record holds its network, host, id and bytes and no address. The inline path makes no
// store call: the record leaves with the next flush.
func TestTlsEdgeConnSpliceByteIdentityAndHalfClose(t *testing.T) {
	world := newTestPathWorld(t, nil)
	storeCounts := world.store.OpCounts()
	conn, stream, hello := world.open(t, "blog")

	toListener := bytes.Repeat([]byte("visitor to listener "), 4000)
	toVisitor := bytes.Repeat([]byte("listener to visitor "), 5000)
	go func() {
		conn.Write(toListener)
		// the visitor's FIN
		conn.CloseWrite()
	}()
	if read := stream.listenerReadAll(t); !bytes.Equal(read, toListener) {
		t.Fatalf("the listener read %d B that are not the visitor's %d B", len(read), len(toListener))
	}
	// the listener's half is still open after the visitor's FIN
	stream.listenerWrite(t, toVisitor)
	if read := testVisitorRead(t, conn, len(toVisitor)); !bytes.Equal(read, toVisitor) {
		t.Fatal("the visitor's bytes are not the listener's")
	}
	stream.listenerCloseWrite()
	if rest, err := io.ReadAll(conn); err != nil || len(rest) != 0 {
		t.Fatalf("after the listener's close the visitor read %d B, %v", len(rest), err)
	}
	stream.awaitEngineClose(t)
	world.awaitEnded(t, 1)

	byteCount := int64(len(hello) + len(toListener) + len(toVisitor))
	if got := world.host.Metrics.Value("urnetwork_tlsedge_bytes_total", "to_listener"); got != float64(len(hello)+len(toListener)) {
		t.Fatalf("%v B counted to the listener", got)
	}
	if got := world.host.Metrics.Value("urnetwork_tlsedge_bytes_total", "to_visitor"); got != float64(len(toVisitor)) {
		t.Fatalf("%v B counted to the visitor", got)
	}
	if got := world.host.Metrics.Value("urnetwork_tlsedge_stream_ends_total", "closed"); got != 1 {
		t.Fatalf("%v clean ends counted", got)
	}
	if got := world.host.Metrics.ObservationCount("urnetwork_tlsedge_setup_seconds"); got != 1 {
		t.Fatalf("%d setups observed", got)
	}

	// nothing reached the store on the connection's path
	if counts := world.store.OpCounts(); counts["InsertConnectionRecords"] != storeCounts["InsertConnectionRecords"] {
		t.Fatalf("the path wrote records: %v", counts)
	}
	if got := world.service.RecordsPendingCountForTest(); got != 1 {
		t.Fatalf("%d records wait", got)
	}
	flushCount := world.service.RecordFlushCountForTest().Value()
	world.clock.Advance(10 * time.Second)
	testAwaitCount(t, world.service.RecordFlushCountForTest(), flushCount+1)
	records := world.store.Records()
	if len(records) != 1 {
		t.Fatalf("%d records written", len(records))
	}
	record := records[0]
	open, err := sidecar.ParseTlsEdgeOpen(stream.metadata)
	if err != nil {
		t.Fatal(err)
	}
	if record.NetworkId != world.networkId || record.Host != "blog" || !bytes.Equal(record.ConnectionId[:], open.GetConnectionId()) {
		t.Fatalf("the record is %+v", record)
	}
	if record.ByteCount != byteCount {
		t.Fatalf("the record counts %d B of %d", record.ByteCount, byteCount)
	}
	if len(record.VisitorHash) != 16 || bytes.Contains(record.VisitorHash, []byte{127, 0, 0, 1}) {
		t.Fatalf("the record's visitor hash is %x", record.VisitorHash)
	}

	// the network paid for every byte, on meter tls
	if err := world.service.UsageDrainForTest(world.ctx); err != nil {
		t.Fatal(err)
	}
	if got := world.host.Quota.TransferUsed(connect.Id(world.networkId), sidecar.QuotaMeterTls); got != byteCount {
		t.Fatalf("%d B billed of %d", got, byteCount)
	}
	for _, batch := range world.host.Quota.Batches() {
		if batch.Producer != sidecar.QuotaProducerTlsEdge {
			t.Fatalf("a batch from %q", batch.Producer)
		}
	}
	if got := world.quota.leaseCount.Load(); got != 1 {
		t.Fatalf("%d leases asked", got)
	}
}

// A visitor's reset is a StreamReset, and a listener's StreamReset ends the visitor's connection.
func TestTlsEdgeConnResetsBothWays(t *testing.T) {
	world := newTestPathWorld(t, nil)

	conn, stream, _ := world.open(t, "blog")
	conn.SetLinger(0)
	conn.Close()
	if code := stream.awaitReset(t); code != protocol.StreamResetCode_RST_CANCELLED {
		t.Fatalf("a visitor's reset reached the listener as %v", code)
	}
	world.awaitEnded(t, 1)

	conn, stream, _ = world.open(t, "blog")
	stream.listenerReset()
	if _, err := io.ReadAll(conn); err == nil {
		t.Fatal("a listener's reset read as a clean end")
	}
	stream.awaitEngineClose(t)
	world.awaitEnded(t, 2)
	if got := world.host.Metrics.Value("urnetwork_tlsedge_stream_ends_total", "visitor_reset"); got != 1 {
		t.Fatalf("%v visitor resets counted", got)
	}
	if got := world.host.Metrics.Value("urnetwork_tlsedge_stream_ends_total", "listener_reset"); got != 1 {
		t.Fatalf("%v listener resets counted", got)
	}
	if got := world.service.SpliceCountForTest(); got != 0 {
		t.Fatalf("%d connections still spliced", got)
	}
}

// A kill resets the open streams of the name it names, with RST_REVOKED, and leaves the network's other
// hosts alone.
func TestTlsEdgeConnKillResetsOpenStreams(t *testing.T) {
	world := newTestPathWorld(t, nil)
	_, killedStream, _ := world.open(t, "blog")
	sparedConn, sparedStream, _ := world.open(t, "shop")

	world.kill(t, "blog")
	if code := killedStream.awaitReset(t); code != protocol.StreamResetCode_RST_REVOKED {
		t.Fatalf("a kill reset with %v", code)
	}
	world.awaitEnded(t, 1)
	if got := world.host.Metrics.Value("urnetwork_tlsedge_stream_ends_total", "killed"); got != 1 {
		t.Fatalf("%v killed streams counted", got)
	}
	sparedStream.listenerWrite(t, []byte("spared"))
	if read := testVisitorRead(t, sparedConn, 6); string(read) != "spared" {
		t.Fatalf("the spared host read %q", read)
	}

	world.kill(t, sidecar.TlsKillAllHosts)
	if code := sparedStream.awaitReset(t); code != protocol.StreamResetCode_RST_REVOKED {
		t.Fatalf("a kill of every host reset with %v", code)
	}
}

// A lease that runs out resets the network's open streams with RST_QUOTA, the one that met the end and
// the idle one beside it, and refuses its next connection.
func TestTlsEdgeConnSpentLeaseResetsWithQuota(t *testing.T) {
	world := newTestPathWorld(t, nil)
	world.host.Quota.SetBalance(connect.Id(world.networkId), 4096)
	conn, stream, _ := world.open(t, "blog")
	_, idleStream, _ := world.open(t, "shop")

	if _, err := conn.Write(bytes.Repeat([]byte{0x5a}, 8192)); err != nil {
		t.Fatal(err)
	}
	if code := stream.awaitReset(t); code != protocol.StreamResetCode_RST_QUOTA {
		t.Fatalf("a spent lease reset with %v", code)
	}
	if code := idleStream.awaitReset(t); code != protocol.StreamResetCode_RST_QUOTA {
		t.Fatalf("a spent lease reset the idle stream with %v", code)
	}
	world.awaitEnded(t, 2)
	if got := world.host.Metrics.Value("urnetwork_tlsedge_stream_ends_total", "quota"); got != 2 {
		t.Fatalf("%v spent streams counted", got)
	}

	// Find would refuse a spent network; a dialer that still opens meets the lease
	world.host.Quota.SetBalance(connect.Id(world.networkId), 0)
	answer := world.answer(t, testEdgeHello(world.name("blog"), []string{"h2"}, 0))
	if !bytes.Equal(answer, testAlertBytes(tlsedgeservice.TlsAlertInternalError)) {
		t.Fatalf("a spent network answered %x", answer)
	}
	if code := world.dialer.awaitOpened(t).awaitReset(t); code != protocol.StreamResetCode_RST_QUOTA {
		t.Fatalf("the refused connection's stream reset with %v", code)
	}
}

// A stream ends at its ticket's grant expiry. With a dead primary the backup's ticket is the one that
// opened, so its expiry is the one kept, and the visitor saw one connection.
func TestTlsEdgeConnEndsAtGrantExpiry(t *testing.T) {
	world := newTestPathWorld(t, nil)
	primaryExpire := world.clock.Now().Add(30 * time.Second)
	backupExpire := world.clock.Now().Add(60 * time.Second)
	world.dialer.setTickets(uint64(primaryExpire.UnixMilli()), uint64(backupExpire.UnixMilli()))
	conn, stream, _ := world.open(t, "blog")
	open, err := sidecar.ParseTlsEdgeOpen(stream.metadata)
	if err != nil {
		t.Fatal(err)
	}
	if open.GetExpireTimeMillis() != uint64(backupExpire.UnixMilli()) {
		t.Fatalf("TlsEdgeOpen ends at %d", open.GetExpireTimeMillis())
	}
	// a byte each way: the splice runs, so its timers are set
	stream.listenerWrite(t, []byte{1})
	testVisitorRead(t, conn, 1)

	world.clock.Advance(30 * time.Second)
	stream.listenerWrite(t, []byte{2})
	if read := testVisitorRead(t, conn, 1); read[0] != 2 {
		t.Fatal("the stream ended at the dead primary's expiry")
	}
	world.clock.Advance(30 * time.Second)
	if code := stream.awaitReset(t); code != protocol.StreamResetCode_RST_REVOKED {
		t.Fatalf("an expired grant reset with %v", code)
	}
	world.awaitEnded(t, 1)
	if got := world.host.Metrics.Value("urnetwork_tlsedge_stream_ends_total", "expired"); got != 1 {
		t.Fatalf("%v expired streams counted", got)
	}
}

// A stream no byte moves on for idle_timeout_s ends, and one a byte moved on inside it waits out the
// rest from that byte.
func TestTlsEdgeConnIdleTimeout(t *testing.T) {
	world := newTestPathWorld(t, nil)
	start := world.clock.Now()
	conn, stream, _ := world.open(t, "blog")
	// a byte each way: the splice runs, so its idle wait is set
	stream.listenerWrite(t, []byte{1})
	testVisitorRead(t, conn, 1)

	world.clock.Advance(600 * time.Second)
	stream.listenerWrite(t, []byte{2})
	testVisitorRead(t, conn, 1)
	// 900 s after the splice began and 300 s after its last byte: the wait is set again for the rest
	world.clock.Advance(300 * time.Second)
	testAwaitTimer(t, world.clock, start.Add(1500*time.Second))
	if got := world.service.SpliceCountForTest(); got != 1 {
		t.Fatal("the stream ended 300 s after its last byte")
	}
	world.clock.Advance(600 * time.Second)
	if code := stream.awaitReset(t); code != protocol.StreamResetCode_RST_PEER_TIMEOUT {
		t.Fatalf("an idle stream reset with %v", code)
	}
	if _, err := io.ReadAll(conn); err == nil {
		t.Fatal("the idle visitor read a clean end")
	}
	world.awaitEnded(t, 1)
	if got := world.host.Metrics.Value("urnetwork_tlsedge_stream_ends_total", "idle"); got != 1 {
		t.Fatalf("%v idle streams counted", got)
	}
}
