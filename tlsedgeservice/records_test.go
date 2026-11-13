// tls-3's records off the path: a store that fails keeps its batch for the next flush, and a queue at its
// bound drops records, never connections.

package tlsedgeservice_test

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

func sidecartestStore() *sidecartest.FakeTlsEdgeStore {
	return sidecartest.NewFakeTlsEdgeStore(nil)
}

// Runs one connection to a clean end.
func testServeOne(t *testing.T, world *testPathWorld, host string) {
	t.Helper()
	conn, stream, _ := world.open(t, host)
	conn.CloseWrite()
	stream.listenerReadAll(t)
	stream.listenerCloseWrite()
	stream.awaitEngineClose(t)
}

// A write that fails leaves its batch waiting, and the next flush writes it once.
func TestTlsEdgeRecordsFailedFlushKeepsBatch(t *testing.T) {
	faults := sidecartest.NewFaultQueue()
	world := newTestPathWorldOn(t, sidecartest.NewFakeTlsEdgeStore(faults), nil, nil)
	testServeOne(t, world, "blog")
	world.awaitEnded(t, 1)
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "tlsedge.InsertConnectionRecords", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	flushCount := world.service.RecordFlushCountForTest().Value()
	world.clock.Advance(10 * time.Second)
	testAwaitCount(t, world.service.RecordFlushCountForTest(), flushCount+1)
	if got := world.service.RecordsPendingCountForTest(); got != 1 {
		t.Fatalf("%d records wait after a failed write", got)
	}
	if got := world.host.Metrics.Value("urnetwork_tlsedge_record_flushes_total", "failed"); got != 1 {
		t.Fatalf("%v failed flushes counted", got)
	}
	world.clock.Advance(10 * time.Second)
	testAwaitCount(t, world.service.RecordFlushCountForTest(), flushCount+2)
	if got := len(world.store.Records()); got != 1 {
		t.Fatalf("%d records written", got)
	}
	if got := world.service.RecordsPendingCountForTest(); got != 0 {
		t.Fatalf("%d records still wait", got)
	}
}

// Past the queue's bound a record is dropped and counted, and its connection was served all the same.
func TestTlsEdgeRecordsQueueBoundDropsOnlyRecords(t *testing.T) {
	world := newTestPathWorld(t, func(settings *tlsedgeservice.TlsEdgeSettings) {
		settings.RecordQueueCount = 1
	})
	testServeOne(t, world, "blog")
	testServeOne(t, world, "shop")
	world.awaitEnded(t, 2)
	if got := world.host.Metrics.Value("urnetwork_tlsedge_connections_total", "spliced"); got != 2 {
		t.Fatalf("%v connections spliced", got)
	}
	if got := world.host.Metrics.Value("urnetwork_tlsedge_records_total", "dropped"); got != 1 {
		t.Fatalf("%v records dropped", got)
	}
	flushCount := world.service.RecordFlushCountForTest().Value()
	world.clock.Advance(10 * time.Second)
	testAwaitCount(t, world.service.RecordFlushCountForTest(), flushCount+1)
	if got := len(world.store.Records()); got != 1 {
		t.Fatalf("%d records written", got)
	}
}
