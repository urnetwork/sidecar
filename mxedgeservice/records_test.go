// mx-2's session records (MAIL-M7-21): queued without a wait, written in batches on the engine's clock,
// bounded, kept across a failed write, written once more at close, and holding nothing of the sender.
package mxedgeservice_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A queue on a fake clock, store and metrics, its writer running.
type testRecords struct {
	t        *testing.T
	ctx      context.Context
	settings *mxedgeservice.MxEdgeSettings
	clock    *sidecartest.FakeClock
	faults   *sidecartest.FaultQueue
	store    *sidecartest.FakeMxEdgeStore
	metrics  *sidecartest.FakeMetrics
	records  *mxedgeservice.ConnectionRecords
}

func newTestRecords(t *testing.T, settings *mxedgeservice.MxEdgeSettings) *testRecords {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	self := &testRecords{
		t:        t,
		ctx:      ctx,
		settings: settings,
		clock:    sidecartest.NewFakeClock(sidecartest.DefaultClockStart()),
		faults:   sidecartest.NewFaultQueue(),
		metrics:  sidecartest.NewFakeMetrics(nil),
	}
	self.store = sidecartest.NewFakeMxEdgeStore(self.faults)
	self.records = mxedgeservice.NewConnectionRecords(self.store, settings, self.clock, self.metrics)
	self.records.Start(ctx)
	t.Cleanup(func() {
		cancel()
		<-self.records.Done()
	})
	return self
}

// Moves the clock to the next flush and returns once it has run.
func (self *testRecords) nextFlush() {
	self.t.Helper()
	count := self.records.FlushCount()
	self.clock.Advance(self.settings.RecordFlushInterval)
	self.records.AwaitFlushCount(count + 1)
}

// A record of networkId.
func testRecord(networkId sidecar.Id, startTime time.Time, byteCount int64) *mxedgeservice.MxConnectionRecord {
	return &mxedgeservice.MxConnectionRecord{NetworkId: networkId, StartTime: startTime, ByteCount: byteCount, Result: "spliced"}
}

// Records wait for their flush, then go as one batch, as given.
func TestSessionRecordsWaitForTheirFlush(t *testing.T) {
	queue := newTestRecords(t, testSettings())
	networkId := sidecar.NewId()
	start := queue.clock.Now()
	for i := range 3 {
		if !queue.records.Add(testRecord(networkId, start.Add(time.Duration(i)*time.Second), int64(100*i))) {
			t.Fatalf("record %d not kept", i)
		}
	}
	queue.clock.Advance(queue.settings.RecordFlushInterval - time.Nanosecond)
	if records := queue.store.Records(); len(records) != 0 {
		t.Fatalf("%d records written before the flush", len(records))
	}
	queue.clock.Advance(time.Nanosecond)
	queue.records.AwaitFlushCount(2)
	records := queue.store.Records()
	if len(records) != 3 || queue.store.OpCounts()["mxedge.InsertConnectionRecords"] != 1 {
		t.Fatalf("records %v in %d writes", records, queue.store.OpCounts()["mxedge.InsertConnectionRecords"])
	}
	for i, record := range records {
		if record.NetworkId != networkId || !record.StartTime.Equal(start.Add(time.Duration(i)*time.Second)) || record.ByteCount != int64(100*i) || record.Result != "spliced" {
			t.Errorf("record %d is %+v", i, record)
		}
	}
	if written := queue.metrics.Value("urnetwork_mxedge_session_records_total", "written"); written != 3 {
		t.Errorf("%v counted written", written)
	}
	if queue.records.PendingCount() != 0 {
		t.Errorf("%d records still wait", queue.records.PendingCount())
	}
}

// A session that named no network leaves no record (reading 3).
func TestSessionRecordWithNoNetworkLeavesNone(t *testing.T) {
	queue := newTestRecords(t, testSettings())
	if queue.records.Add(testRecord(sidecar.Id{}, queue.clock.Now(), 10)) || queue.records.Add(nil) {
		t.Fatal("a record with no network was kept")
	}
	queue.nextFlush()
	if records := queue.store.Records(); len(records) != 0 {
		t.Fatalf("records %v", records)
	}
	if counts := queue.store.OpCounts(); counts["mxedge.InsertConnectionRecords"] != 0 {
		t.Fatalf("an empty queue wrote: %v", counts)
	}
}

// A full queue drops what comes next and counts it, and Add never waits: the store is never asked.
func TestSessionRecordsDropPastTheQueue(t *testing.T) {
	settings := testSettings()
	settings.RecordQueueCount = 3
	queue := newTestRecords(t, settings)
	networkId := sidecar.NewId()
	kept := 0
	for i := range 5 {
		if queue.records.Add(testRecord(networkId, queue.clock.Now(), int64(i))) {
			kept += 1
		}
	}
	if kept != 3 || queue.records.PendingCount() != 3 {
		t.Fatalf("kept %d, %d waiting", kept, queue.records.PendingCount())
	}
	if dropped := queue.metrics.Value("urnetwork_mxedge_session_records_total", "dropped"); dropped != 2 {
		t.Fatalf("%v counted dropped", dropped)
	}
	if counts := queue.store.OpCounts(); len(counts) != 0 {
		t.Fatalf("adding reached the store: %v", counts)
	}
	queue.nextFlush()
	if records := queue.store.Records(); len(records) != 3 {
		t.Fatalf("%d written", len(records))
	}
	// room again once written
	if !queue.records.Add(testRecord(networkId, queue.clock.Now(), 9)) {
		t.Fatal("a written queue still drops")
	}
}

// A failed write keeps its batch at the front, and the next flush writes it once, ahead of what came
// after.
func TestSessionRecordBatchWaitsAfterAFailedWrite(t *testing.T) {
	queue := newTestRecords(t, testSettings())
	networkId := sidecar.NewId()
	queue.records.Add(testRecord(networkId, queue.clock.Now(), 1))
	queue.records.Add(testRecord(networkId, queue.clock.Now(), 2))
	if _, err := queue.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "mxedge.InsertConnectionRecords", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	queue.nextFlush()
	if records := queue.store.Records(); len(records) != 0 || queue.records.PendingCount() != 2 {
		t.Fatalf("after a failed write: %d written, %d waiting", len(records), queue.records.PendingCount())
	}
	if failed := queue.metrics.Value("urnetwork_mxedge_session_record_flushes_total", "failed"); failed != 1 {
		t.Fatalf("%v failed flushes counted", failed)
	}
	queue.records.Add(testRecord(networkId, queue.clock.Now(), 3))
	queue.nextFlush()
	records := queue.store.Records()
	byteCounts := []int64{}
	for _, record := range records {
		byteCounts = append(byteCounts, record.ByteCount)
	}
	if fmt.Sprint(byteCounts) != "[1 2 3]" {
		t.Fatalf("written %v", byteCounts)
	}
}

// A flush writes at most RecordBatchCount records a write, and goes on until nothing waits.
func TestSessionRecordsWriteInBatches(t *testing.T) {
	settings := testSettings()
	settings.RecordBatchCount = 2
	queue := newTestRecords(t, settings)
	networkId := sidecar.NewId()
	for i := range 5 {
		queue.records.Add(testRecord(networkId, queue.clock.Now(), int64(i)))
	}
	queue.nextFlush()
	if records := queue.store.Records(); len(records) != 5 || queue.store.OpCounts()["mxedge.InsertConnectionRecords"] != 3 {
		t.Fatalf("%d written in %d writes", len(records), queue.store.OpCounts()["mxedge.InsertConnectionRecords"])
	}
}

// Close writes what the sessions left, once they have ended, and a record holds nothing of its sender.
func TestEngineCloseWritesItsSessionRecords(t *testing.T) {
	engine := newTestEngine(t, nil)
	networkId := sidecar.NewId()
	start := engine.clock.Now()
	if !engine.service.RecordSession(start, networkId, 4096, "spliced") {
		t.Fatal("not kept")
	}
	engine.service.Close()
	records := engine.store.Records()
	if len(records) != 1 || records[0].NetworkId != networkId || !records[0].StartTime.Equal(start) || records[0].ByteCount != 4096 {
		t.Fatalf("records %+v", records)
	}
	// a capture of what the store was given: no sender address in any form
	for _, record := range records {
		capture := fmt.Sprintf("%+v %#v", record, record)
		for _, sender := range []string{testSender, testSenderIp6, "203.0.113"} {
			if strings.Contains(capture, sender) {
				t.Errorf("a record holds %s: %s", sender, capture)
			}
		}
	}
}
