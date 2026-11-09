//go:build !sidecar_http

// record_ingest.go's right step against the end of a depositor's right, and a deposit of one entry past the batch's
// byte bound (RECORD.md section 20's ingest list). External, as record_writer_test.go.

package sidecar_test

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A member's device removed after it deposited keeps what it filed while admitted: its deposit, declared at a pin
// before the removal and pushed before it, is ingested. One pushed more than TimeSkewTimeout after the log entry that
// ended its right, still declaring the old pin, is consumed unrecorded with bad_entry.
func TestRecordIngestJudgesARemovedDepositorByWhenItsRightEnded(t *testing.T) {
	world := newTestRecordWorld(t)
	ingester := world.device(true)
	depositor := world.device(false)
	hand := depositor.handChain()
	filed := hand.seal("filed while admitted")
	late := hand.seal("pushed long after removal")
	admittedPin := world.auth.Tip().Pin()

	// deposited at the admitted pin, at the clock's time now
	world.depositHand(depositor, []*sidecar.RecordSealedEntry{filed})
	// the removal lands a minute later
	world.clock.Advance(time.Minute)
	repo := world.fixture.Repos[world.vaultId]
	repo.Depositors = slices.DeleteFunc(repo.Depositors, func(sidecarId sidecar.Id) bool { return sidecarId == depositor.sidecarId })
	world.publish()
	// half an hour on, a push still declaring the admitted pin; evs takes it, as a token not yet expired would
	world.clock.Advance(30 * time.Minute)
	deposit := &sidecar.RecordStreamDeposit{
		PushId:             sidecar.NewId(),
		DepositorSidecarId: depositor.sidecarId,
		DepositId:          sidecar.NewId(),
		AuthPin:            admittedPin,
	}
	batch := &protocol.RecordDepositBatch{Entries: []*protocol.RecordDeposit{late.Deposit()}}
	deposit.Batch = testRecordMarshal(t, batch)
	if _, err := world.streams.For(depositor.sidecarId).Deposit(t.Context(), world.vaultId, deposit); err != nil {
		t.Fatal(err)
	}

	record := ingester.open()
	testRecordIngest(t, record, world)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, record, world)
	if deposits := world.waitingDeposits(ingester, depositor.sidecarId); len(deposits) != 0 {
		t.Fatalf("%d deposits left", len(deposits))
	}
	if got := testRecordTexts(t, world.storedEntries(ingester.sidecarId)); !slices.Equal(got, []string{"filed while admitted"}) {
		t.Fatalf("the ingester wrote %v", got)
	}
	if reasons := ingester.alarmReasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmBadEntry}) {
		t.Errorf("the late deposit raised %v", reasons)
	}
}

// A blob of 8 MiB, past the 1 MiB a batch takes, goes alone in a deposit of its own, which an ingester takes whole.
func TestRecordIngestTakesAnEntryPastTheBatchBoundAlone(t *testing.T) {
	world := newTestRecordWorld(t)
	ingester := world.device(true)
	depositor := world.device(false)
	depositorRecord := depositor.open()
	content := bytes.Repeat([]byte{0x5a}, 8*1024*1024)
	blob := &sidecar.RecordDraft{
		Kind:      sidecar.RecordKindBlob,
		Source:    sidecar.RecordSourceObserved,
		NoSession: true,
		Body:      &protocol.BlobBody{Path: "large.bin", Content: content, Size: uint64(len(content))},
	}
	testRecordAppend(t, depositorRecord, blob)
	testRecordAppend(t, depositorRecord, testRecordNote(nil, "after the blob"))
	if err := depositorRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if deposits := world.waitingDeposits(ingester, depositor.sidecarId); len(deposits) != 2 || len(deposits[0].Batch) < 8*1024*1024 {
		t.Fatalf("%d deposits", len(deposits))
	}
	record := ingester.open()
	testRecordIngest(t, record, world)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, record, world)
	stored := world.storedEntries(ingester.sidecarId)
	if len(stored) != 2 || stored[0].header.GetKind() != uint32(sidecar.RecordKindBlob) || len(stored[0].body) < len(content) {
		t.Fatalf("the ingester wrote %d entries", len(stored))
	}
}

// message's bytes, which must marshal.
func testRecordMarshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	encoded, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
