package sidecartest

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
)

func testMxConnectionRecord() *mxedgeservice.MxConnectionRecord {
	return &mxedgeservice.MxConnectionRecord{
		NetworkId: sidecar.Id{1},
		StartTime: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
		ByteCount: 1024,
		Result:    "spliced",
	}
}

func TestFakeMxEdgeStoreKeepsRowsAndCountsCalls(t *testing.T) {
	store := NewFakeMxEdgeStore(nil)
	ctx := context.Background()
	if err := store.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.InsertConnectionRecords(ctx, []*mxedgeservice.MxConnectionRecord{testMxConnectionRecord()}); err != nil {
		t.Fatal(err)
	}
	if records := store.Records(); len(records) != 1 || *records[0] != *testMxConnectionRecord() {
		t.Errorf("records %+v", records)
	}
	if counts := store.OpCounts(); counts["mxedge.Ping"] != 1 || counts["mxedge.InsertConnectionRecords"] != 1 {
		t.Errorf("counts %v", counts)
	}
	store.ResetOpCounts()
	if counts := store.OpCounts(); len(counts) != 0 {
		t.Errorf("counts %v after a reset", counts)
	}
}

// Neither a caller's batch nor a reader's copy reaches what the fake holds.
func TestFakeMxEdgeStoreKeepsItsOwnRows(t *testing.T) {
	store := NewFakeMxEdgeStore(nil)
	record := testMxConnectionRecord()
	if err := store.InsertConnectionRecords(context.Background(), []*mxedgeservice.MxConnectionRecord{record}); err != nil {
		t.Fatal(err)
	}
	record.ByteCount = 1
	store.Records()[0].ByteCount = 2
	if records := store.Records(); records[0].ByteCount != 1024 {
		t.Errorf("byte count %d", records[0].ByteCount)
	}
}

func TestFakeMxEdgeStoreTakesFaults(t *testing.T) {
	faults := NewFaultQueue()
	store := NewFakeMxEdgeStore(faults)
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: "mxedge.Ping", Result: FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	if err := store.Ping(context.Background()); err == nil {
		t.Error("the plan did not fire")
	}
	if counts := store.OpCounts(); len(counts) != 0 {
		t.Errorf("a failed call counted: %v", counts)
	}
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: "mxedge.InsertConnectionRecords", Result: ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	err := store.InsertConnectionRecords(context.Background(), []*mxedgeservice.MxConnectionRecord{testMxConnectionRecord()})
	if err == nil {
		t.Error("the plan did not fire")
	}
	if records := store.Records(); len(records) != 1 {
		t.Errorf("a dropped answer applied %d rows", len(records))
	}
}
