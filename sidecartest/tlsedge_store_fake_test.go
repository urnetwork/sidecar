package sidecartest

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

const testTlsEdgeRoot = "root.example"

// The suite's hooks bound to a fake's own methods.
func testTlsEdgeSuiteHooks(store *FakeTlsEdgeStore) *TlsEdgeStoreSuiteHooks {
	return &TlsEdgeStoreSuiteHooks{
		Root: testTlsEdgeRoot,
		AddLabel: func(ctx context.Context, networkId sidecar.Id) (string, error) {
			return store.AddLabel(testTlsEdgeRoot, networkId)
		},
		AddAlias: func(ctx context.Context, networkId sidecar.Id, alias string) error {
			return store.AddAlias(testTlsEdgeRoot, networkId, alias)
		},
		WithdrawNetwork: func(ctx context.Context, networkId sidecar.Id) error {
			store.WithdrawNetwork(networkId)
			return nil
		},
		SuspendZone: func(ctx context.Context, networkId sidecar.Id, until time.Time) error {
			store.SuspendZone(networkId, until)
			return nil
		},
		SuspendHost: func(ctx context.Context, networkId sidecar.Id, host string) error {
			store.SuspendHost(networkId, host)
			return nil
		},
		Restore: func(ctx context.Context, networkId sidecar.Id, host string) error {
			store.Restore(networkId, host)
			return nil
		},
		SetSuspension: func(ctx context.Context, row *sidecar.TlsSuspendArgs) error {
			store.SetSuspension(row)
			return nil
		},
		LiftSuspension: func(ctx context.Context, networkId sidecar.Id, host string) error {
			store.LiftSuspension(networkId, host)
			return nil
		},
		ReadRecords: func(ctx context.Context, networkId sidecar.Id, since time.Time) ([]*tlsedgeservice.TlsConnectionRecord, error) {
			records := []*tlsedgeservice.TlsConnectionRecord{}
			for _, record := range store.Records() {
				if record.NetworkId == networkId && !record.EndTime.Before(since) {
					records = append(records, record)
				}
			}
			return records, nil
		},
	}
}

// The fake keeps what store.go promises, as server's Postgres store must.
func TestFakeTlsEdgeStorePassesTheSuite(t *testing.T) {
	store := NewFakeTlsEdgeStore(nil)
	RunTlsEdgeStoreSuite(t, store, testTlsEdgeSuiteHooks(store))
}

// A fault plan reaches a store call, and each call is counted.
func TestFakeTlsEdgeStoreTakesFaultsAndCounts(t *testing.T) {
	faults := NewFaultQueue()
	store := NewFakeTlsEdgeStore(faults)
	if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: "tlsedge.NameSnapshot", Result: FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.NameSnapshot(context.Background(), testTlsEdgeRoot); err == nil {
		t.Fatal("the planned failure did not reach the call")
	}
	if _, err := store.NameSnapshot(context.Background(), testTlsEdgeRoot); err != nil {
		t.Fatal(err)
	}
	if counts := store.OpCounts(); counts["NameSnapshot"] != 1 {
		t.Fatalf("counts %v", counts)
	}
}

// A restore moves the root's restore serial and nothing else, and a name another network holds is
// refused.
func TestFakeTlsEdgeStoreRestoreAndHeldNames(t *testing.T) {
	store := NewFakeTlsEdgeStore(nil)
	networkId := sidecar.NewId()
	if err := store.SetLabel(testTlsEdgeRoot, networkId, "abcdefghij"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetLabel(testTlsEdgeRoot, sidecar.NewId(), "abcdefghij"); err == nil {
		t.Fatal("a held label was given to another network")
	}
	before, err := store.NameSnapshot(context.Background(), testTlsEdgeRoot)
	if err != nil {
		t.Fatal(err)
	}
	store.RestoreRoot(testTlsEdgeRoot)
	after, err := store.NameSnapshot(context.Background(), testTlsEdgeRoot)
	if err != nil {
		t.Fatal(err)
	}
	if after.RestoreSerial == before.RestoreSerial || len(after.Entries) != len(before.Entries) {
		t.Fatalf("restore serial %d to %d, entries %d to %d", before.RestoreSerial, after.RestoreSerial, len(before.Entries), len(after.Entries))
	}
}
