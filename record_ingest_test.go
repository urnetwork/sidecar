//go:build !sidecar_http

// record_deposit.go's deposit path and record_ingest.go's ingest (RECORD.md section 5.4) on sidecartest's streams: a
// device the vault does not consent deposits batches an ingester writes once into its own stream and consumes; two
// ingesters holding one entry, read as one; a crash between an ingester's push and its CONSUME only consuming on the
// re-run; a forged writer and a receipt-only depositor's other kind consumed unrecorded with their alarms (FS-30's
// clause), its read ingested; and a deposit of an erased entry, re-uploaded, recreating nothing (§22.5's §11 row).
// External, as record_writer_test.go.

package sidecar_test

import (
	"bytes"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The deposits waiting in depositorId's ref, read by a device with rw.
func (self *testRecordWorld) waitingDeposits(rw *testRecordDevice, depositorId sidecar.Id) []*sidecar.RecordStreamDepositVersion {
	self.t.Helper()
	deposits, err := self.streams.For(rw.sidecarId).ReadDeposits(self.t.Context(), self.vaultId, depositorId)
	if err != nil {
		self.t.Fatal(err)
	}
	return deposits
}

// Ingests the vault on device's record, which must pass.
func testRecordIngest(t *testing.T, record *sidecar.SidecarRecord, world *testRecordWorld) {
	t.Helper()
	if err := record.Ingester().Ingest(t.Context(), world.vaultId); err != nil {
		t.Fatal(err)
	}
}

// The alarms a device raised, by reason.
func (self *testRecordDevice) alarmReasons() []sidecar.SidecarRecordAlarm {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reasons := []sidecar.SidecarRecordAlarm{}
	for _, alarm := range self.alarms {
		reasons = append(reasons, alarm.Reason)
	}
	return reasons
}

// A device the vault does not consent deposits: its entries go as one batch of RecordDeposits, each a RecordEntry
// with no slot and its key and salt, and none reaches a stream of its own.
func TestRecordDepositBatchesADevicesEntries(t *testing.T) {
	world := newTestRecordWorld(t)
	ingester := world.device(true)
	depositor := world.device(false)
	record := depositor.open()
	for _, text := range []string{"one", "two", "three"} {
		ref := testRecordAppend(t, record, testRecordNote(nil, text))
		if ref.Spooled || ref.LogId != world.vaultId {
			t.Fatalf("a deposit-routed entry: %+v", ref)
		}
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	deposits := world.waitingDeposits(ingester, depositor.sidecarId)
	if len(deposits) != 1 {
		t.Fatalf("%d deposits", len(deposits))
	}
	entries, err := sidecar.RecordDepositBatchParse(deposits[0].Batch, depositor.settings.DepositByteCount)
	if err != nil || len(entries) != 3 {
		t.Fatalf("the batch: %d entries, %v", len(entries), err)
	}
	for _, entry := range entries {
		if len(entry.Key) != 32 || len(entry.Salt) != 32 {
			t.Errorf("a deposited entry's key and salt are %d and %d bytes", len(entry.Key), len(entry.Salt))
		}
	}
	if stored := world.storedEntries(depositor.sidecarId); len(stored) != 0 {
		t.Errorf("a depositor pushed %d entries to a stream", len(stored))
	}
}

// Past DepositByteCount a batch closes, and an entry larger than it goes alone.
func TestRecordDepositSplitsAtItsByteBound(t *testing.T) {
	world := newTestRecordWorld(t)
	ingester := world.device(true)
	depositor := world.device(false)
	depositor.settings.DepositByteCount = 2048
	record := depositor.open()
	for range 3 {
		testRecordAppend(t, record, testRecordNote(nil, string(bytes.Repeat([]byte{'n'}, 400))))
	}
	big := &sidecar.RecordDraft{
		Kind:      sidecar.RecordKindBlob,
		Source:    sidecar.RecordSourceObserved,
		NoSession: true,
		Body:      &protocol.BlobBody{Path: "a.bin", Content: bytes.Repeat([]byte{0x5a}, 4096)},
	}
	testRecordAppend(t, record, big)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	counts := []int{}
	for _, deposit := range world.waitingDeposits(ingester, depositor.sidecarId) {
		entries, err := sidecar.RecordDepositBatchParse(deposit.Batch, depositor.settings.DepositByteCount)
		if err != nil {
			t.Fatal(err)
		}
		counts = append(counts, len(entries))
	}
	if !slices.Equal(counts, []int{2, 1, 1}) {
		t.Errorf("batches of %v entries", counts)
	}
}

// One entry deposited, ingested once into the ingester's own stream with its bytes and chain as written, then the
// deposit consumed; a reader verifies it as the depositor's, with no alarm.
func TestRecordIngestWritesADepositOnceAndConsumesIt(t *testing.T) {
	world := newTestRecordWorld(t)
	ingester := world.device(true)
	depositor := world.device(false)
	depositorRecord := depositor.open()
	testRecordAppend(t, depositorRecord, testRecordNote(nil, "deposited"))
	if err := depositorRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	record := ingester.open()
	testRecordIngest(t, record, world)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, record, world)
	if deposits := world.waitingDeposits(ingester, depositor.sidecarId); len(deposits) != 0 {
		t.Fatalf("%d deposits left after ingest", len(deposits))
	}
	stored := world.storedEntries(ingester.sidecarId)
	if got := testRecordTexts(t, stored); !slices.Equal(got, []string{"deposited"}) {
		t.Fatalf("the ingester's stream holds %v", got)
	}
	if !bytes.Equal(stored[0].header.GetWriterSidecarId(), depositor.sidecarId[:]) || stored[0].header.GetSeq() != 1 {
		t.Error("the ingested entry's writer or chain changed")
	}
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 1 || entries[0].Body == nil || entries[0].State != sidecar.RecordEntryLive {
		t.Fatalf("the reader holds %d entries", len(entries))
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("alarms %v", reasons)
	}
	if reasons := ingester.alarmReasons(); len(reasons) != 0 {
		t.Errorf("the ingester raised %v", reasons)
	}
}

// Two ingesters may each write one entry before either consumes: each holds a copy in its own stream, readers show
// one with both places, and the second CONSUME, of a deposit already gone, reads as consumed.
func TestRecordIngestTwoIngestersHoldOneEntry(t *testing.T) {
	world := newTestRecordWorld(t)
	first := world.device(true)
	second := world.device(true)
	depositor := world.device(false)
	depositorRecord := depositor.open()
	testRecordAppend(t, depositorRecord, testRecordNote(nil, "shared"))
	if err := depositorRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	firstRecord := first.open()
	secondRecord := second.open()
	testRecordIngest(t, firstRecord, world)
	if err := firstRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, secondRecord, world)
	if err := secondRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, firstRecord, world)
	testRecordIngest(t, secondRecord, world)
	if deposits := world.waitingDeposits(first, depositor.sidecarId); len(deposits) != 0 {
		t.Fatalf("%d deposits left", len(deposits))
	}
	reader := world.newReader(nil, nil)
	entries := reader.sync(t, world)
	if len(entries) != 1 || len(entries[0].Copies) != 2 {
		t.Fatalf("%d entries", len(entries))
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		t.Errorf("two copies raised %v", reasons)
	}
}

// A crash between the ingester's push and its CONSUME leaves the deposit; the re-run finds the leaf in its stream and
// only consumes, so the stream holds the entry once.
func TestRecordIngestAfterACrashBetweenPushAndConsumeOnlyConsumes(t *testing.T) {
	world := newTestRecordWorld(t)
	ingester := world.device(true)
	depositor := world.device(false)
	depositorRecord := depositor.open()
	testRecordAppend(t, depositorRecord, testRecordNote(nil, "once"))
	if err := depositorRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	record := ingester.open()
	testRecordIngest(t, record, world)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	// the crash, before this life's next pass could consume
	record = ingester.open()
	testRecordIngest(t, record, world)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if deposits := world.waitingDeposits(ingester, depositor.sidecarId); len(deposits) != 0 {
		t.Fatalf("%d deposits left", len(deposits))
	}
	if got := testRecordTexts(t, world.storedEntries(ingester.sidecarId)); !slices.Equal(got, []string{"once"}) {
		t.Fatalf("the stream holds %v", got)
	}
}

// Deposits a batch of entries as depositor, by hand.
func (self *testRecordWorld) depositHand(depositor *testRecordDevice, entries []*sidecar.RecordSealedEntry) *sidecar.RecordStreamDeposit {
	self.t.Helper()
	batch := &protocol.RecordDepositBatch{}
	for _, entry := range entries {
		batch.Entries = append(batch.Entries, entry.Deposit())
	}
	batchBytes, err := proto.Marshal(batch)
	if err != nil {
		self.t.Fatal(err)
	}
	deposit := &sidecar.RecordStreamDeposit{
		PushId:             sidecar.NewId(),
		DepositorSidecarId: depositor.sidecarId,
		DepositId:          sidecar.NewId(),
		Batch:              batchBytes,
		AuthPin:            self.auth.Tip().Pin(),
	}
	if _, err := self.streams.For(depositor.sidecarId).Deposit(self.t.Context(), self.vaultId, deposit); err != nil {
		self.t.Fatal(err)
	}
	return deposit
}

// An entry another sidecar wrote, deposited as this depositor's, fails the signer step: consumed unrecorded, alarmed.
func TestRecordIngestConsumesAForgedWriterUnrecorded(t *testing.T) {
	world := newTestRecordWorld(t)
	ingester := world.device(true)
	depositor := world.device(false)
	other := world.device(false)
	forged := other.handChain().seal("not the depositor's")
	world.depositHand(depositor, []*sidecar.RecordSealedEntry{forged})
	record := ingester.open()
	testRecordIngest(t, record, world)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if deposits := world.waitingDeposits(ingester, depositor.sidecarId); len(deposits) != 0 {
		t.Fatalf("%d deposits left", len(deposits))
	}
	if stored := world.storedEntries(ingester.sidecarId); len(stored) != 0 {
		t.Fatalf("a forged entry was written: %d", len(stored))
	}
	if reasons := ingester.alarmReasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmBadEntry}) {
		t.Errorf("a forged writer raised %v", reasons)
	}
}

// FS-30's clause: a receipt-only depositor's entry of another kind, within its budget, is consumed and never ingested,
// with depositor_kind; its read entry is ingested.
func TestRecordIngestConsumesAReceiptOnlyDepositorsOtherKind(t *testing.T) {
	world := newTestRecordWorld(t)
	ingester := world.device(true)
	reader := world.device(false)
	world.fixture.Members[reader.sidecarId] = sidecar.NewId()
	world.fixture.Repos[world.vaultId].ReceiptOnly = append(world.fixture.Repos[world.vaultId].ReceiptOnly, reader.sidecarId)
	world.publish()
	if err := world.streams.Grant(world.vaultId, reader.sidecarId, sidecartest.RecordStreamsScope{Deposit: true, ReceiptOnly: true}); err != nil {
		t.Fatal(err)
	}
	hand := reader.handChain()
	note := hand.seal("an instruction dressed as a receipt")
	receipt, err := sidecar.RecordSeal(hand.env, &sidecar.RecordSealArgs{
		LogId:         world.vaultId,
		Kind:          sidecar.RecordKindRead,
		Source:        sidecar.RecordSourceObserved,
		TimeMillis:    world.clock.Now().UnixMilli(),
		PolicyVersion: world.auth.Tip().Pin().GetVersion(),
		Body:          &protocol.ReadBody{ObjectIds: [][]byte{sidecar.NewId().Bytes()}, Purpose: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	world.depositHand(reader, []*sidecar.RecordSealedEntry{note})
	world.depositHand(reader, []*sidecar.RecordSealedEntry{receipt})
	record := ingester.open()
	testRecordIngest(t, record, world)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, record, world)
	if deposits := world.waitingDeposits(ingester, reader.sidecarId); len(deposits) != 0 {
		t.Fatalf("%d deposits left", len(deposits))
	}
	stored := world.storedEntries(ingester.sidecarId)
	if len(stored) != 1 || stored[0].header.GetKind() != uint32(sidecar.RecordKindRead) {
		t.Fatalf("the ingester wrote %d entries", len(stored))
	}
	if reasons := ingester.alarmReasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmDepositorKind}) {
		t.Errorf("a receipt-only depositor's note raised %v", reasons)
	}
}

// §22.5's §11 row: once an entry is erased, its deposit uploaded again, as a spool after a site loss would, is
// consumed unrecorded: no body comes back.
func TestRecordIngestRecreatesNoErasedEntry(t *testing.T) {
	world := newTestRecordWorld(t)
	ingester := world.device(true)
	depositor := world.device(false)
	depositorRecord := depositor.open()
	testRecordAppend(t, depositorRecord, testRecordNote(nil, "to erase"))
	if err := depositorRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	batch := bytes.Clone(depositor.tap.deposits[0].Batch)
	record := ingester.open()
	testRecordIngest(t, record, world)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, record, world)
	stored := world.storedEntries(ingester.sidecarId)
	eraserId := sidecar.NewId()
	if err := world.streams.Grant(world.vaultId, eraserId, sidecartest.RecordStreamsScope{Admin: true}); err != nil {
		t.Fatal(err)
	}
	erase := &sidecar.RecordStreamErase{PushId: sidecar.NewId(), Keys: []*sidecar.RecordSlotKey{{SlotId: stored[0].slotId, KeyIndex: stored[0].keyIndex}}, SealedNote: []byte("note")}
	if _, err := world.streams.For(eraserId).Erase(t.Context(), world.vaultId, erase); err != nil {
		t.Fatal(err)
	}
	// the re-upload of the same signed bytes
	reupload := &sidecar.RecordStreamDeposit{
		PushId:             sidecar.NewId(),
		DepositorSidecarId: depositor.sidecarId,
		DepositId:          sidecar.NewId(),
		Batch:              batch,
		AuthPin:            world.auth.Tip().Pin(),
	}
	if _, err := world.streams.For(depositor.sidecarId).Deposit(t.Context(), world.vaultId, reupload); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, record, world)
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if deposits := world.waitingDeposits(ingester, depositor.sidecarId); len(deposits) != 0 {
		t.Fatalf("%d deposits left", len(deposits))
	}
	if stored := world.storedEntries(ingester.sidecarId); len(stored) != 1 || stored[0].body != nil {
		t.Fatalf("the erased entry came back: %d entries", len(stored))
	}
}
