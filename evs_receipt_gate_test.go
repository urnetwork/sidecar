// EVS1-M3-01's opened read-receipt gate over the record's own receipts (§16.8, D-MCP-18; FS-30's evs side): the
// depositor NewEvsRecordReceiptDepositor makes over an EvsShare reader's RecordReceipts lands one receipt in the
// reader's deposit ref of the vault before it returns, the author offline, with the purpose and taint the read's
// context gives; a re-read of the same objects that day deposits nothing; a read with no context seals its receipt
// tainted, as an unbound read's; and a reader that may not deposit is refused, nothing landing. External, as
// record_receipt_test.go, whose world it reads.

package sidecar_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestEvsRecordReceiptDepositorLandsTheReceiptFirst(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	deposit := sidecar.NewEvsRecordReceiptDepositor(reader.open().Receipts())
	if deposit == nil {
		t.Fatal("no depositor over the reader's receipts")
	}
	segmentIds := testReceiptObjectIds(t, 3, 32)
	ctx := sidecar.WithEvsReadContext(t.Context(), &sidecar.EvsReadContext{Purpose: sidecar.RecordReadPurposeSearch, NoSession: true})
	if err := deposit(ctx, world.vaultId, sidecar.NewId(), segmentIds); err != nil {
		t.Fatal(err)
	}
	waiting := world.receiptsWaiting(author, reader)
	if len(waiting) != 1 {
		t.Fatalf("%d receipts deposited", len(waiting))
	}
	if body := waiting[0].body; body.GetPurpose() != uint32(sidecar.RecordReadPurposeSearch) ||
		!slices.EqualFunc(body.GetObjectIds(), segmentIds, bytes.Equal) {
		t.Fatalf("the receipt's body %v", body)
	}
	if header := waiting[0].header; header.GetKind() != uint32(sidecar.RecordKindRead) ||
		header.GetSource() != uint32(sidecar.RecordSourceObserved) || header.GetTainted() {
		t.Fatalf("the receipt's header %v", header)
	}
	// the same objects again that day: covered, nothing deposited
	if err := deposit(ctx, world.vaultId, sidecar.NewId(), segmentIds); err != nil {
		t.Fatal(err)
	}
	if len(world.receiptsWaiting(author, reader)) != 1 {
		t.Fatal("a re-read deposited again")
	}
	// a read whose context names nothing: purpose read, bound to no run, sealed tainted
	slotIds := testReceiptObjectIds(t, 1, 16)
	if err := deposit(t.Context(), world.vaultId, sidecar.NewId(), slotIds); err != nil {
		t.Fatal(err)
	}
	waiting = world.receiptsWaiting(author, reader)
	if len(waiting) != 2 || waiting[1].body.GetPurpose() != uint32(sidecar.RecordReadPurposeRead) || !waiting[1].header.GetTainted() {
		t.Fatalf("the unbound read's receipt: %d receipts", len(waiting))
	}
	if sidecar.NewEvsRecordReceiptDepositor(nil) != nil {
		t.Error("a depositor over no receipts")
	}
}

// A reader the state no longer lets deposit to the vault seals nothing, and its read is refused.
func TestEvsRecordReceiptDepositorRefusesANonDepositor(t *testing.T) {
	world := newTestRecordWorld(t)
	reader := world.shareReader()
	repo := world.fixture.Repos[world.vaultId]
	repo.Depositors = slices.DeleteFunc(repo.Depositors, func(sidecarId sidecar.Id) bool { return sidecarId == reader.sidecarId })
	world.publish()
	deposit := sidecar.NewEvsRecordReceiptDepositor(reader.open().Receipts())
	err := deposit(t.Context(), world.vaultId, sidecar.NewId(), testReceiptObjectIds(t, 1, 16))
	if !errors.Is(err, sidecar.ErrRecordReceiptNotDepositor) {
		t.Fatalf("a non-depositor: %v", err)
	}
	if len(reader.tap.depositAttempts()) != 0 {
		t.Fatal("a non-depositor sent a deposit")
	}
}
