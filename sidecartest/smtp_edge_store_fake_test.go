package sidecartest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

func TestFakeSmtpEdgeStoreSuite(t *testing.T) {
	RunSmtpEdgeStoreSuite(t, NewFakeSmtpEdgeStore(nil, nil))
}

func TestFakeSmtpEdgeStoreReadsHaltsOnItsClock(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	store := NewFakeSmtpEdgeStore(clock, nil)
	ctx := context.Background()
	halt := &smtpedgeservice.SmtpHalt{HaltId: sidecar.NewId(), NetworkId: sidecar.NewId(), Trigger: smtpedgeservice.SmtpHaltTriggerCommunityComplaint, StartTime: clock.Now()}
	if err := store.SetHalt(ctx, halt); err != nil {
		t.Fatal(err)
	}
	clock.Advance(smtpedgeservice.SmtpHaltDuration - time.Nanosecond)
	if halts, err := store.ActiveHalts(ctx); err != nil || len(halts) != 1 {
		t.Fatalf("just before the day ends: %d halts, %v", len(halts), err)
	}
	clock.Advance(time.Nanosecond)
	if halts, err := store.ActiveHalts(ctx); err != nil || len(halts) != 0 {
		t.Fatalf("at the day's end: %d halts, %v", len(halts), err)
	}
}

func TestFakeSmtpEdgeStoreFaultsAndCounts(t *testing.T) {
	faults := NewFaultQueue()
	store := NewFakeSmtpEdgeStore(nil, faults)
	ctx := context.Background()
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: "smtpedge.InsertAggregate", Result: FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	report := &smtpedgeservice.SmtpAggregateReport{Reporter: "reporter.example", ReportId: "r1", Kind: smtpedgeservice.SmtpAggregateKindDmarc}
	if _, err := store.InsertAggregate(ctx, report); !errors.Is(err, errHostTransport) {
		t.Fatalf("a planned failure answered %v", err)
	}
	if inserted, err := store.InsertAggregate(ctx, report); err != nil || !inserted {
		t.Fatalf("after the failure: %v, %v", inserted, err)
	}
	if count := store.OpCounts()["smtpedge.InsertAggregate"]; count != 1 {
		t.Fatalf("%d counted calls, want the one that ran", count)
	}
	store.ResetOpCounts()
	if len(store.OpCounts()) != 0 {
		t.Fatal("counts survived a reset")
	}
}

func TestFakeSmtpEdgeStoreFindsDkimKeysWithoutCase(t *testing.T) {
	store := NewFakeSmtpEdgeStore(nil, nil)
	store.PutDkimKey(&smtpedgeservice.SmtpDkimKey{Selector: "abcdefghijklmnopqrstuvwxyz", Domain: "Net.Root.Example", NetworkId: sidecar.NewId(), Algorithm: "rsa-sha256", PublicKey: []byte{1, 2, 3}})
	key, err := store.FindDkimKey(context.Background(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "net.root.example")
	if err != nil || key == nil {
		t.Fatalf("%v, %v", key, err)
	}
	if missing, err := store.FindDkimKey(context.Background(), "other", "net.root.example"); err != nil || missing != nil {
		t.Fatalf("an unknown selector answered %v, %v", missing, err)
	}
}

func TestFakeSmtpEdgeStoreCountsRecipientsSince(t *testing.T) {
	store := NewFakeSmtpEdgeStore(nil, nil)
	networkId := sidecar.NewId()
	base := time.Date(2031, time.May, 1, 12, 0, 0, 0, time.UTC)
	early := smtpSuiteSend(networkId, base.Add(-time.Hour))
	late := smtpSuiteSend(networkId, base)
	other := smtpSuiteSend(sidecar.NewId(), base)
	if err := store.InsertSends(context.Background(), []*smtpedgeservice.SmtpSendRecord{early, late, other}); err != nil {
		t.Fatal(err)
	}
	count, err := store.RecipientCount(context.Background(), networkId, base)
	if err != nil || count != uint64(late.RecipientCount) {
		t.Fatalf("%d recipients, %v", count, err)
	}
}
