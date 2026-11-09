//go:build !sidecar_http

// record_receipt.go's read receipts on sidecartest's streams and authorization state, as an EvsShare reader of
// another member's vault makes them: FS-30's M3 case on T2, the receipt landing before any decrypt with the author
// offline and ingested later, one receipt across a restart between deposit and read, the reader's other writes and
// deposits past the budget failing while a non-read entry within budget is consumed with an alarm; a refused,
// unreachable or unbound deposit refusing the read with no decrypt reaching the key; a deposit held in flight holding
// the read; a receipt sealed before a kill sent with fresh ids, and one refused at a closed gate sent again re-signing
// nothing; the day's receipts covering re-reads; reads past 64 objects split; taint failing closed; and the writer's
// push loop leaving a pending receipt alone. External, as record_writer_test.go.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// An EvsShare reader of the world's vault: a sidecar of another member that reads it and deposits read receipts
// alone, as §8.5 and §11.12 have it.
func (self *testRecordWorld) shareReader() *testRecordDevice {
	self.t.Helper()
	reader := self.device(false)
	self.fixture.Members[reader.sidecarId] = sidecar.NewId()
	repo := self.fixture.Repos[self.vaultId]
	repo.Readers = append(repo.Readers, reader.sidecarId)
	repo.ReceiptOnly = append(repo.ReceiptOnly, reader.sidecarId)
	self.publish()
	scope := sidecartest.RecordStreamsScope{Read: true, Deposit: true, ReceiptOnly: true}
	if err := self.streams.Grant(self.vaultId, reader.sidecarId, scope); err != nil {
		self.t.Fatal(err)
	}
	return reader
}

// The key a read decrypts its objects with, counting each use: a read whose receipt did not land must leave it
// unused.
type testReceiptKey struct {
	stateLock sync.Mutex
	useCount  int
}

func (self *testReceiptKey) use() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.useCount += 1
}

func (self *testReceiptKey) uses() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.useCount
}

// A read of the vault through the receipt gate, as EVS1-M3-01's gate runs it: the receipt first, and each object
// decrypted only once it returns.
func testReceiptRead(ctx context.Context, record *sidecar.SidecarRecord, world *testRecordWorld, key *testReceiptKey, purpose sidecar.RecordReadPurpose, objectIds [][]byte) error {
	request := &sidecar.RecordReceiptRequest{RepoId: world.vaultId, Purpose: purpose, ObjectIds: objectIds, NoSession: true}
	if err := record.Receipts().Deposit(ctx, request); err != nil {
		return err
	}
	for range objectIds {
		key.use()
	}
	return nil
}

// count random object ids of byteCount bytes.
func testReceiptObjectIds(t *testing.T, count int, byteCount int) [][]byte {
	t.Helper()
	objectIds := [][]byte{}
	for range count {
		objectId := make([]byte, byteCount)
		if _, err := rand.Read(objectId); err != nil {
			t.Fatal(err)
		}
		objectIds = append(objectIds, objectId)
	}
	return objectIds
}

// One receipt waiting in a deposit ref, opened as the author's ingester opens it.
type testReceiptWaiting struct {
	version        uint64
	pushId         sidecar.Id
	batchByteCount int
	signed         []byte
	header         *protocol.RecordHeader
	body           *protocol.ReadBody
}

// The receipts waiting in reader's deposit ref, read by rw, a device with rw on the vault: each a deposit of one
// entry.
func (self *testRecordWorld) receiptsWaiting(rw *testRecordDevice, reader *testRecordDevice) []*testReceiptWaiting {
	self.t.Helper()
	waiting := []*testReceiptWaiting{}
	for _, deposit := range self.waitingDeposits(rw, reader.sidecarId) {
		entries, err := sidecar.RecordDepositBatchParse(deposit.Batch, sidecar.DefaultSidecarSettings().Record.DepositByteCount)
		if err != nil {
			self.t.Fatal(err)
		}
		if len(entries) != 1 {
			self.t.Fatalf("a receipt's deposit holds %d entries", len(entries))
		}
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(entries[0].Signed, signed); err != nil {
			self.t.Fatal(err)
		}
		header, err := sidecar.ParseStoredRecordHeader(signed.GetBody())
		if err != nil {
			self.t.Fatal(err)
		}
		opened, err := sidecar.RecordOpen(header, entries[0].SealedBody, entries[0].Key, entries[0].Salt)
		if err != nil {
			self.t.Fatal(err)
		}
		body := &protocol.ReadBody{}
		if err := proto.Unmarshal(opened, body); err != nil {
			self.t.Fatal(err)
		}
		waiting = append(waiting, &testReceiptWaiting{
			version:        deposit.Version,
			pushId:         deposit.PushId,
			batchByteCount: len(deposit.Batch),
			signed:         entries[0].Signed,
			header:         header.Header,
			body:           body,
		})
	}
	return waiting
}

// Each deposit the tap was handed, in order.
func (self *testRecordStreamsTap) depositAttempts() []*sidecar.RecordStreamDeposit {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.deposits)
}

// The next push or deposit evs commits answers as if unreachable.
func (self *testRecordStreamsTap) loseNext() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.loseNextOutcome = true
}

// Whether a store holds a file whose path names directory.
func testReceiptStoreHolds(files *sidecartest.FakeStore, directory string) bool {
	return slices.ContainsFunc(files.Paths(), func(path string) bool { return strings.Contains(path, "/"+directory) })
}

// FS-30 on T2: an EvsShare reader's first read of the vault, its author offline, lands one durable receipt before
// anything is decrypted: kind read, source observed, the reader's chain from seq 1, no run or agent id, its objects
// and purpose sealed in its body. The author's device, once it runs, ingests it into its own stream with the reader's
// chain kept, and a reader of the vault shows it live with no alarm.
func TestRecordReceiptLandsWithTheAuthorOffline(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	key := &testReceiptKey{}
	objectIds := testReceiptObjectIds(t, 2, 16)
	if err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, objectIds); err != nil {
		t.Fatal(err)
	}
	if key.uses() != 2 {
		t.Fatalf("the read decrypted %d objects", key.uses())
	}
	waiting := world.receiptsWaiting(author, reader)
	if len(waiting) != 1 {
		t.Fatalf("%d receipts deposited", len(waiting))
	}
	header := waiting[0].header
	if header.GetKind() != uint32(sidecar.RecordKindRead) || header.GetSource() != uint32(sidecar.RecordSourceObserved) ||
		!bytes.Equal(header.GetWriterSidecarId(), reader.sidecarId[:]) || header.GetSeq() != 1 ||
		!bytes.Equal(header.GetPrevSha256(), make([]byte, 32)) || !bytes.Equal(header.GetLogId(), world.vaultId[:]) {
		t.Errorf("the receipt's header: %v", header)
	}
	if len(header.GetRunId()) != 0 || len(header.GetAgentId()) != 0 || len(header.GetActionId()) != 0 || header.GetTainted() {
		t.Errorf("the receipt names the reader's run, agent or action, or is tainted: %v", header)
	}
	body := waiting[0].body
	if body.GetPurpose() != uint32(sidecar.RecordReadPurposeRead) || len(body.GetReadLogId()) != 0 ||
		!slices.EqualFunc(body.GetObjectIds(), objectIds, bytes.Equal) {
		t.Errorf("the receipt's body: %v", body)
	}
	if 4*1024 < waiting[0].batchByteCount {
		t.Errorf("a receipt of %d bytes", waiting[0].batchByteCount)
	}

	// the author comes online
	authorRecord := author.open()
	testRecordIngest(t, authorRecord, world)
	if err := authorRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, authorRecord, world)
	if left := world.waitingDeposits(author, reader.sidecarId); len(left) != 0 {
		t.Fatalf("%d deposits left after ingest", len(left))
	}
	stored := world.storedEntries(author.sidecarId)
	if len(stored) != 1 || stored[0].header.GetKind() != uint32(sidecar.RecordKindRead) ||
		!bytes.Equal(stored[0].header.GetWriterSidecarId(), reader.sidecarId[:]) || stored[0].header.GetSeq() != 1 {
		t.Fatalf("the author's stream holds %d entries", len(stored))
	}
	vaultReader := world.newReader(nil, nil)
	entries := vaultReader.sync(t, world)
	if len(entries) != 1 || entries[0].State != sidecar.RecordEntryLive || entries[0].Body == nil {
		t.Fatalf("the vault reads %d entries", len(entries))
	}
	if reasons := vaultReader.reasons(); len(reasons) != 0 {
		t.Errorf("the receipt raised %v", reasons)
	}
	if reasons := author.alarmReasons(); len(reasons) != 0 {
		t.Errorf("the author's ingest raised %v", reasons)
	}
}

// FS-30's other clauses: the reader writes no stream of the vault, a deposit past the receipt bound gets 429, and a
// note it deposits within budget is consumed and never ingested, with depositor_kind, while its receipt is ingested.
func TestRecordReceiptReadersOtherWritesFail(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	streams := world.streams.For(reader.sidecarId)
	push := &sidecar.RecordStreamPush{
		PushId:          sidecar.NewId(),
		WriterSidecarId: reader.sidecarId,
		SlotId:          sidecar.NewId(),
		SlotRows:        []*sidecar.RecordSlotRow{{KeyIndex: 0, Row: make([]byte, 64)}},
		Entries:         []*sidecar.RecordStreamEntry{{Path: "e/0/0/1", Entry: []byte("an entry")}},
		AuthPin:         world.auth.Tip().Pin(),
	}
	_, err := streams.Append(t.Context(), world.vaultId, push)
	if code, ok := sidecar.RecordStreamRefusalCode(err); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
		t.Errorf("the reader's push to the vault: %v", err)
	}
	large := &sidecar.RecordStreamDeposit{
		PushId:             sidecar.NewId(),
		DepositorSidecarId: reader.sidecarId,
		DepositId:          sidecar.NewId(),
		Batch:              make([]byte, 4*1024+1),
		AuthPin:            world.auth.Tip().Pin(),
	}
	_, err = streams.Deposit(t.Context(), world.vaultId, large)
	if code, ok := sidecar.RecordStreamRefusalCode(err); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED {
		t.Errorf("a deposit past the receipt bound: %v", err)
	}

	note := reader.handChain().seal("an instruction dressed as a receipt")
	world.depositHand(reader, []*sidecar.RecordSealedEntry{note})
	if err := testReceiptRead(t.Context(), reader.open(), world, &testReceiptKey{}, sidecar.RecordReadPurposeRead, testReceiptObjectIds(t, 1, 16)); err != nil {
		t.Fatal(err)
	}
	authorRecord := author.open()
	testRecordIngest(t, authorRecord, world)
	if err := authorRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	testRecordIngest(t, authorRecord, world)
	if left := world.waitingDeposits(author, reader.sidecarId); len(left) != 0 {
		t.Fatalf("%d deposits left after ingest", len(left))
	}
	stored := world.storedEntries(author.sidecarId)
	if len(stored) != 1 || stored[0].header.GetKind() != uint32(sidecar.RecordKindRead) {
		t.Fatalf("the author's stream holds %d entries", len(stored))
	}
	if reasons := author.alarmReasons(); !slices.Equal(reasons, []sidecar.SidecarRecordAlarm{sidecar.SidecarRecordAlarmDepositorKind}) {
		t.Errorf("the reader's note raised %v", reasons)
	}
}

// evs as the reader reaches it, holding each deposit until the test lets it go on.
type testReceiptHeldStreams struct {
	sidecar.RecordStreams
	entered chan struct{}
	release chan struct{}
}

func (self *testReceiptHeldStreams) Deposit(ctx context.Context, repoId sidecar.Id, deposit *sidecar.RecordStreamDeposit) (*sidecar.RecordStreamCommit, error) {
	self.entered <- struct{}{}
	<-self.release
	return self.RecordStreams.Deposit(ctx, repoId, deposit)
}

// The read waits for evs's 200: while the deposit is in flight nothing is decrypted and Deposit has not returned, and
// once evs commits, the read goes on.
func TestRecordReceiptAwaitsEvsBeforeTheRead(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	held := &testReceiptHeldStreams{
		RecordStreams: world.streams.For(reader.sidecarId),
		entered:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	reader.tap.RecordStreams = held
	record := reader.open()
	key := &testReceiptKey{}
	objectIds := testReceiptObjectIds(t, 3, 16)
	done := make(chan error, 1)
	go func() {
		done <- testReceiptRead(t.Context(), record, world, key, sidecar.RecordReadPurposeRead, objectIds)
	}()
	<-held.entered
	// held inside the deposit: the read cannot have gone on
	select {
	case err := <-done:
		t.Fatalf("the read returned with its deposit in flight: %v", err)
	default:
	}
	if key.uses() != 0 {
		t.Fatalf("%d objects decrypted before evs answered", key.uses())
	}
	if waiting := world.waitingDeposits(author, reader.sidecarId); len(waiting) != 0 {
		t.Fatalf("%d deposits before the commit", len(waiting))
	}
	close(held.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if key.uses() != 3 || len(world.waitingDeposits(author, reader.sidecarId)) != 1 {
		t.Errorf("after the commit: %d decrypts, %d deposits", key.uses(), len(world.waitingDeposits(author, reader.sidecarId)))
	}
}

// A first read that cannot deposit is refused: evs unreachable, or no streams bound yet. No decrypt reaches the key,
// and once evs is back the same read lands the receipt sealed for it, with no second one.
func TestRecordReceiptRefusedDepositRefusesTheRead(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	record := reader.open()
	key := &testReceiptKey{}
	objectIds := testReceiptObjectIds(t, 2, 16)
	reader.tap.setDown(true)
	err := testReceiptRead(t.Context(), record, world, key, sidecar.RecordReadPurposeRead, objectIds)
	if !errors.Is(err, sidecar.ErrRecordReceiptRefused) || !errors.Is(err, errTestRecordEvsDown) {
		t.Fatalf("a read with evs down: %v", err)
	}
	if key.uses() != 0 {
		t.Fatalf("%d objects decrypted with no receipt", key.uses())
	}
	reader.tap.setDown(false)

	unbound := reader.open()
	unbound.Bind(sidecar.RecordStreamsUnavailable{}, nil)
	if err := testReceiptRead(t.Context(), unbound, world, key, sidecar.RecordReadPurposeRead, objectIds); !errors.Is(err, sidecar.ErrRecordStreamsUnavailable) {
		t.Fatalf("a read with no streams bound: %v", err)
	}
	if key.uses() != 0 {
		t.Fatalf("%d objects decrypted with no streams", key.uses())
	}

	if err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, objectIds); err != nil {
		t.Fatal(err)
	}
	waiting := world.receiptsWaiting(author, reader)
	if len(waiting) != 1 || waiting[0].header.GetSeq() != 1 || !slices.EqualFunc(waiting[0].body.GetObjectIds(), objectIds, bytes.Equal) {
		t.Fatalf("%d receipts deposited", len(waiting))
	}
}

// A sidecar the state lets read but not deposit cannot land a receipt: its read is refused with nothing sealed.
func TestRecordReceiptNeedsTheRightToDeposit(t *testing.T) {
	world := newTestRecordWorld(t)
	reader := world.shareReader()
	repo := world.fixture.Repos[world.vaultId]
	repo.Depositors = slices.DeleteFunc(repo.Depositors, func(sidecarId sidecar.Id) bool { return sidecarId == reader.sidecarId })
	world.publish()
	key := &testReceiptKey{}
	err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, testReceiptObjectIds(t, 1, 16))
	if !errors.Is(err, sidecar.ErrRecordReceiptNotDepositor) {
		t.Fatalf("a read with no deposit right: %v", err)
	}
	if key.uses() != 0 || len(reader.tap.depositAttempts()) != 0 || testReceiptStoreHolds(reader.files, "journal/") {
		t.Errorf("a refused receipt decrypted %d objects, sent %d deposits or sealed an entry", key.uses(), len(reader.tap.depositAttempts()))
	}
}

// FS-30: one receipt across a restart between deposit and read. evs commits but its answer is lost, so the read is
// refused; the restarted reader's read sends the same statement, which evs answers with that commit, and a third life
// sends nothing.
func TestRecordReceiptOneAcrossARestartBetweenDepositAndRead(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	key := &testReceiptKey{}
	objectIds := testReceiptObjectIds(t, 2, 16)
	reader.tap.loseNext()
	if err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, objectIds); !errors.Is(err, sidecar.ErrRecordReceiptRefused) {
		t.Fatalf("a read whose answer was lost: %v", err)
	}
	if key.uses() != 0 || len(world.waitingDeposits(author, reader.sidecarId)) != 1 {
		t.Fatalf("after the lost answer: %d decrypts, %d deposits", key.uses(), len(world.waitingDeposits(author, reader.sidecarId)))
	}
	// the restart, then the read again
	if err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, objectIds); err != nil {
		t.Fatal(err)
	}
	attempts := reader.tap.depositAttempts()
	if len(attempts) != 2 || attempts[0].PushId != attempts[1].PushId || attempts[0].DepositId != attempts[1].DepositId {
		t.Fatalf("%d attempts, not one statement sent twice", len(attempts))
	}
	if key.uses() != 2 || len(world.waitingDeposits(author, reader.sidecarId)) != 1 {
		t.Fatalf("after the restart: %d decrypts, %d deposits", key.uses(), len(world.waitingDeposits(author, reader.sidecarId)))
	}
	if err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, objectIds); err != nil {
		t.Fatal(err)
	}
	if attempts := reader.tap.depositAttempts(); len(attempts) != 2 || len(world.waitingDeposits(author, reader.sidecarId)) != 1 {
		t.Errorf("a third life sent %d attempts in all", len(attempts))
	}
}

// A kill after a receipt is journaled and before its file is written leaves an entry never sent: the next life takes
// it up with fresh ids and sends it as it was signed, seq 1, and the next receipt chains on it as seq 2.
func TestRecordReceiptSealedBeforeAKillGoesWithFreshIds(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	key := &testReceiptKey{}
	objectIds := testReceiptObjectIds(t, 2, 16)
	// the journal record's commit, then the kill
	reader.files.FailWritesAfter(1)
	if err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, objectIds); err == nil {
		t.Fatal("a read whose receipt file failed went on")
	}
	reader.files.FailWritesAfter(-1)
	if key.uses() != 0 || len(reader.tap.depositAttempts()) != 0 || !testReceiptStoreHolds(reader.files, "journal/") {
		t.Fatalf("before the restart: %d decrypts, %d attempts", key.uses(), len(reader.tap.depositAttempts()))
	}
	if err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, objectIds); err != nil {
		t.Fatal(err)
	}
	others := testReceiptObjectIds(t, 1, 16)
	if err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, others); err != nil {
		t.Fatal(err)
	}
	waiting := world.receiptsWaiting(author, reader)
	if len(waiting) != 2 || waiting[0].header.GetSeq() != 1 || waiting[1].header.GetSeq() != 2 {
		t.Fatalf("%d receipts", len(waiting))
	}
	if !slices.EqualFunc(waiting[0].body.GetObjectIds(), objectIds, bytes.Equal) || !slices.EqualFunc(waiting[1].body.GetObjectIds(), others, bytes.Equal) {
		t.Error("the receipts name other objects than their reads")
	}
	if testReceiptStoreHolds(reader.files, "journal/") {
		t.Error("a landed receipt's journal record stayed")
	}
}

// A pending receipt that lands while the store fails its mark still covers its read, which goes on with no second
// receipt sealed for the same objects; the next life, finding it pending, sends the same statement, which evs answers
// with that commit, and marks it, and the life after sends nothing.
func TestRecordReceiptCommittedWithAFailedMarkLandsOnce(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	record := reader.open()
	key := &testReceiptKey{}
	objectIds := testReceiptObjectIds(t, 2, 16)
	reader.tap.setDown(true)
	if err := testReceiptRead(t.Context(), record, world, key, sidecar.RecordReadPurposeRead, objectIds); err == nil {
		t.Fatal("a read with evs down went on")
	}
	reader.tap.setDown(false)
	// evs is back, and the store fails from its next write on: the receipt's mark
	reader.files.FailWritesAfter(0)
	err := testReceiptRead(t.Context(), record, world, key, sidecar.RecordReadPurposeRead, objectIds)
	reader.files.FailWritesAfter(-1)
	if err != nil {
		t.Fatalf("a landed receipt whose mark failed refused its read: %v", err)
	}
	if key.uses() != 2 || len(reader.tap.depositAttempts()) != 2 || len(world.waitingDeposits(author, reader.sidecarId)) != 1 {
		t.Fatalf("with the mark failed: %d decrypts, %d attempts", key.uses(), len(reader.tap.depositAttempts()))
	}
	if err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, objectIds); err != nil {
		t.Fatal(err)
	}
	attempts := reader.tap.depositAttempts()
	if len(attempts) != 3 || attempts[1].PushId != attempts[2].PushId || len(world.waitingDeposits(author, reader.sidecarId)) != 1 {
		t.Fatalf("the next life sent %d attempts in all", len(attempts))
	}
	if err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, objectIds); err != nil {
		t.Fatal(err)
	}
	if attempts := reader.tap.depositAttempts(); len(attempts) != 3 || testReceiptStoreHolds(reader.files, "journal/") {
		t.Errorf("once marked: %d attempts in all, journal record kept %t", len(attempts), testReceiptStoreHolds(reader.files, "journal/"))
	}
}

// 412 GATE_CLOSED spends the push id: the read is refused, and once the gate opens the same signed entry goes under a
// new push id and deposit id, re-signed nothing.
func TestRecordReceiptRebuiltAfterAClosedGateResignsNothing(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	key := &testReceiptKey{}
	objectIds := testReceiptObjectIds(t, 1, 16)
	world.streams.SetGateClosed(world.vaultId, true)
	err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, objectIds)
	if code, ok := sidecar.RecordStreamRefusalCode(err); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED {
		t.Fatalf("a read at a closed gate: %v", err)
	}
	if key.uses() != 0 {
		t.Fatalf("%d objects decrypted at a closed gate", key.uses())
	}
	world.streams.SetGateClosed(world.vaultId, false)
	if err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, objectIds); err != nil {
		t.Fatal(err)
	}
	attempts := reader.tap.depositAttempts()
	if len(attempts) != 2 || attempts[0].PushId == attempts[1].PushId || attempts[0].DepositId == attempts[1].DepositId {
		t.Fatalf("%d attempts, the second not under new ids", len(attempts))
	}
	waiting := world.receiptsWaiting(author, reader)
	if len(waiting) != 1 || waiting[0].header.GetSeq() != 1 || waiting[0].pushId != attempts[1].PushId {
		t.Fatalf("%d receipts", len(waiting))
	}
}

// A receipt covers its objects for the rest of its UTC day: a re-read of them deposits nothing, one of them with a new
// object deposits for the new one alone, another purpose deposits again, and so does the next day.
func TestRecordReceiptRereadsDepositNothing(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	record := reader.open()
	key := &testReceiptKey{}
	first := testReceiptObjectIds(t, 2, 16)
	second := testReceiptObjectIds(t, 1, 32)
	reads := []struct {
		purpose   sidecar.RecordReadPurpose
		objectIds [][]byte
	}{
		{purpose: sidecar.RecordReadPurposeRead, objectIds: first},
		{purpose: sidecar.RecordReadPurposeRead, objectIds: first},
		{purpose: sidecar.RecordReadPurposeRead, objectIds: append(slices.Clone(first), second...)},
		{purpose: sidecar.RecordReadPurposeSearch, objectIds: first[:1]},
	}
	for _, read := range reads {
		if err := testReceiptRead(t.Context(), record, world, key, read.purpose, read.objectIds); err != nil {
			t.Fatal(err)
		}
	}
	waiting := world.receiptsWaiting(author, reader)
	if len(waiting) != 3 {
		t.Fatalf("%d receipts for four reads", len(waiting))
	}
	if !slices.EqualFunc(waiting[1].body.GetObjectIds(), second, bytes.Equal) {
		t.Error("the third read's receipt names objects already receipted")
	}
	if waiting[2].body.GetPurpose() != uint32(sidecar.RecordReadPurposeSearch) {
		t.Error("another purpose took no receipt of its own")
	}
	world.clock.Advance(24 * time.Hour)
	if err := testReceiptRead(t.Context(), record, world, key, sidecar.RecordReadPurposeRead, first); err != nil {
		t.Fatal(err)
	}
	if waiting := world.receiptsWaiting(author, reader); len(waiting) != 4 || waiting[3].header.GetSeq() != 4 {
		t.Fatalf("the next day's read: %d receipts", len(waiting))
	}
}

// §11.12's budget: 256 receipts land in a UTC day, and the 257th read gets 429 and is refused, nothing decrypted. The
// next day its receipt goes first, as it was signed, and the next read's after it, the chain in order.
func TestRecordReceiptPastTheBudgetFailsTheRead(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	record := reader.open()
	key := &testReceiptKey{}
	for range 256 {
		if err := testReceiptRead(t.Context(), record, world, key, sidecar.RecordReadPurposeRead, testReceiptObjectIds(t, 1, 16)); err != nil {
			t.Fatal(err)
		}
	}
	refused := testReceiptObjectIds(t, 1, 16)
	err := testReceiptRead(t.Context(), record, world, key, sidecar.RecordReadPurposeRead, refused)
	if code, ok := sidecar.RecordStreamRefusalCode(err); !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED {
		t.Fatalf("the 257th read: %v", err)
	}
	if key.uses() != 256 {
		t.Fatalf("%d objects decrypted", key.uses())
	}
	world.clock.Advance(24 * time.Hour)
	next := testReceiptObjectIds(t, 1, 16)
	if err := testReceiptRead(t.Context(), record, world, key, sidecar.RecordReadPurposeRead, next); err != nil {
		t.Fatal(err)
	}
	waiting := world.receiptsWaiting(author, reader)
	if len(waiting) != 258 {
		t.Fatalf("%d receipts", len(waiting))
	}
	for index, receipt := range waiting {
		if receipt.header.GetSeq() != uint64(index+1) {
			t.Fatalf("receipt %d holds seq %d", index, receipt.header.GetSeq())
		}
	}
	if !slices.EqualFunc(waiting[256].body.GetObjectIds(), refused, bytes.Equal) || !slices.EqualFunc(waiting[257].body.GetObjectIds(), next, bytes.Equal) {
		t.Error("the refused read's receipt did not go first")
	}
}

// A read of 130 objects of 32 bytes takes three receipts, of 64, 64 and 2, each within §11.12's 4 KiB, chained.
func TestRecordReceiptSplitsAReadPast64Objects(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	objectIds := testReceiptObjectIds(t, 130, 32)
	if err := testReceiptRead(t.Context(), reader.open(), world, &testReceiptKey{}, sidecar.RecordReadPurposeSearch, objectIds); err != nil {
		t.Fatal(err)
	}
	waiting := world.receiptsWaiting(author, reader)
	counts := []int{}
	named := [][]byte{}
	for index, receipt := range waiting {
		counts = append(counts, len(receipt.body.GetObjectIds()))
		named = append(named, receipt.body.GetObjectIds()...)
		if receipt.header.GetSeq() != uint64(index+1) || 4*1024 < receipt.batchByteCount {
			t.Errorf("receipt %d: seq %d, %d bytes", index, receipt.header.GetSeq(), receipt.batchByteCount)
		}
	}
	if !slices.Equal(counts, []int{64, 64, 2}) || !slices.EqualFunc(named, objectIds, bytes.Equal) {
		t.Errorf("receipts of %v objects", counts)
	}
}

// A request breaking a rule seals nothing: no repo, a purpose section 6.4 does not name, an object id of 20 bytes.
func TestRecordReceiptRefusesAnInvalidRequest(t *testing.T) {
	world := newTestRecordWorld(t)
	reader := world.shareReader()
	record := reader.open()
	objectIds := testReceiptObjectIds(t, 1, 16)
	requests := []*sidecar.RecordReceiptRequest{
		nil,
		{Purpose: sidecar.RecordReadPurposeRead, ObjectIds: objectIds, NoSession: true},
		{RepoId: world.vaultId, Purpose: 0, ObjectIds: objectIds, NoSession: true},
		{RepoId: world.vaultId, Purpose: 5, ObjectIds: objectIds, NoSession: true},
		{RepoId: world.vaultId, Purpose: sidecar.RecordReadPurposeRead, ObjectIds: testReceiptObjectIds(t, 1, 20), NoSession: true},
	}
	for index, request := range requests {
		if err := record.Receipts().Deposit(t.Context(), request); !errors.Is(err, sidecar.ErrRecordReceiptInvalid) {
			t.Errorf("request %d: %v", index, err)
		}
	}
	if len(reader.tap.depositAttempts()) != 0 || testReceiptStoreHolds(reader.files, "journal/") {
		t.Error("an invalid request sealed or sent a receipt")
	}
}

// A receipt's taint fails closed (RECORD.md section 5.3): the read's run's bit, true with no run and no NoSession,
// and false only for a read no session asked for.
func TestRecordReceiptTaintFailsClosed(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	record := reader.open()
	cleanRunId := sidecar.NewId()
	world.runs.StartRun(cleanRunId)
	taintedRunId := sidecar.NewId()
	world.runs.StartRun(taintedRunId)
	world.runs.Taint(taintedRunId)
	cases := []struct {
		runId     *sidecar.Id
		noSession bool
		tainted   bool
	}{
		{runId: &cleanRunId, tainted: false},
		{runId: &taintedRunId, tainted: true},
		{tainted: true},
		{noSession: true, tainted: false},
	}
	for _, c := range cases {
		request := &sidecar.RecordReceiptRequest{
			RepoId:    world.vaultId,
			Purpose:   sidecar.RecordReadPurposeRead,
			ObjectIds: testReceiptObjectIds(t, 1, 16),
			RunId:     c.runId,
			NoSession: c.noSession,
		}
		if err := record.Receipts().Deposit(t.Context(), request); err != nil {
			t.Fatal(err)
		}
	}
	waiting := world.receiptsWaiting(author, reader)
	if len(waiting) != len(cases) {
		t.Fatalf("%d receipts", len(waiting))
	}
	for index, c := range cases {
		if waiting[index].header.GetTainted() != c.tainted || len(waiting[index].header.GetRunId()) != 0 {
			t.Errorf("case %d: tainted %t, run id %x", index, waiting[index].header.GetTainted(), waiting[index].header.GetRunId())
		}
	}
}

// A receipt that did not land stays journaled for its own path: the writer's push loop, in the next life, queues
// nothing for the vault and sends nothing, and the next read lands it.
func TestRecordWriterLeavesAPendingReceiptToItsPath(t *testing.T) {
	world := newTestRecordWorld(t)
	author := world.device(true)
	reader := world.shareReader()
	key := &testReceiptKey{}
	objectIds := testReceiptObjectIds(t, 1, 16)
	reader.tap.setDown(true)
	if err := testReceiptRead(t.Context(), reader.open(), world, key, sidecar.RecordReadPurposeRead, objectIds); err == nil {
		t.Fatal("a read with evs down went on")
	}
	reader.tap.setDown(false)
	record := reader.open()
	if err := record.Flush(t.Context()); err != nil {
		t.Fatalf("the writer held a receipt: %v", err)
	}
	if attempts := reader.tap.depositAttempts(); len(attempts) != 1 {
		t.Fatalf("the writer sent %d deposits", len(attempts)-1)
	}
	if err := testReceiptRead(t.Context(), record, world, key, sidecar.RecordReadPurposeRead, objectIds); err != nil {
		t.Fatal(err)
	}
	if waiting := world.receiptsWaiting(author, reader); len(waiting) != 1 || key.uses() != 1 {
		t.Errorf("%d receipts, %d decrypts", len(waiting), key.uses())
	}
}
