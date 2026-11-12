// RECORD-M3-06's erasure of entries on sidecartest's fakes (§22.5's §11 erasure case for an entry, FS-47's client
// rows): the world is record_writer_test.go's vault, its eraser a consented device that is an admin of it.

package sidecar_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A device's streams as the storage limit and a crash leave them: pushes to its own stream refused while limited, and
// an ERASE's answer lost after it committed while set.
type testEraseTap struct {
	sidecar.RecordStreams

	stateLock sync.Mutex
	limited   bool
	loseErase bool
}

var errTestEraseAnswerLost = errors.New("the ERASE's answer was lost")

func (self *testEraseTap) Append(ctx context.Context, repoId sidecar.Id, push *sidecar.RecordStreamPush) (*sidecar.RecordStreamCommit, error) {
	self.stateLock.Lock()
	limited := self.limited
	self.stateLock.Unlock()
	if limited {
		// §11.13's storage limit at the device's cluster, recorded against the push id
		return nil, &sidecar.RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL, Recorded: true}
	}
	return self.RecordStreams.Append(ctx, repoId, push)
}

func (self *testEraseTap) Erase(ctx context.Context, repoId sidecar.Id, erase *sidecar.RecordStreamErase) (*sidecar.RecordStreamCommit, error) {
	commit, err := self.RecordStreams.Erase(ctx, repoId, erase)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err == nil && self.loseErase {
		self.loseErase = false
		return nil, errTestEraseAnswerLost
	}
	return commit, err
}

func (self *testEraseTap) set(limited bool, loseErase bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.limited = limited
	self.loseErase = loseErase
}

// A consented device of the vault that is an admin of it, its streams behind a testEraseTap.
func (self *testRecordWorld) eraserDevice() (*testRecordDevice, *testEraseTap) {
	self.t.Helper()
	device := self.device(true)
	repo := self.fixture.Repos[self.vaultId]
	repo.Admins = append(repo.Admins, device.sidecarId)
	if err := self.streams.Grant(self.vaultId, device.sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true, Deposit: true, Admin: true}); err != nil {
		self.t.Fatal(err)
	}
	self.publish()
	tap := &testEraseTap{RecordStreams: device.tap.RecordStreams}
	device.tap.RecordStreams = tap
	return device, tap
}

// Each entry of writerId's stream by entry id.
func testEraseStored(world *testRecordWorld, writerId sidecar.Id) map[sidecar.Id]*testRecordStored {
	stored := map[sidecar.Id]*testRecordStored{}
	for _, item := range world.storedEntries(writerId) {
		stored[sidecar.Id(item.header.GetEntryId())] = item
	}
	return stored
}

// The erasure entries' bodies among stored.
func testEraseBodies(t *testing.T, stored map[sidecar.Id]*testRecordStored) []*protocol.ErasureBody {
	t.Helper()
	bodies := []*protocol.ErasureBody{}
	for _, item := range stored {
		if sidecar.RecordKind(item.header.GetKind()) != sidecar.RecordKindErasure {
			continue
		}
		body := &protocol.ErasureBody{}
		if err := proto.Unmarshal(item.body, body); err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
	}
	return bodies
}

// §22.5's §11 case for an entry: an entry in the eraser's stream and one waiting in another device's deposit are
// erased; the stream's body no longer opens, its header and chain still stand, and an entry beside it is untouched;
// the deposit is consumed and its entry never written; a reader that held the body drops it and refuses its key at
// its next sync; and the erasure entry lands in the eraser's stream naming both, reason 1.
func TestRecordEraserErasesAnEntryEverywhere(t *testing.T) {
	ctx := t.Context()
	world := newTestRecordWorld(t)
	eraser, _ := world.eraserDevice()
	depositor := world.device(false)
	other := world.device(true)
	eraserRecord := eraser.open()
	depositorRecord := depositor.open()
	otherRecord := other.open()
	first := testRecordAppend(t, eraserRecord, testRecordNote(nil, "first"))
	second := testRecordAppend(t, eraserRecord, testRecordNote(nil, "second"))
	if err := eraserRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	deposited := testRecordAppend(t, depositorRecord, testRecordNote(nil, "deposited"))
	if err := depositorRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := otherRecord.Reader().Sync(ctx, world.vaultId); err != nil {
		t.Fatal(err)
	}
	if entry, ok := otherRecord.Reader().Entry(world.vaultId, first.EntryId); !ok || entry.Body == nil {
		t.Fatal("the other device does not hold the first entry's body")
	}
	result, err := eraserRecord.Eraser().Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.vaultId, EntryIds: []sidecar.Id{first.EntryId, deposited.EntryId}, Reason: sidecar.RecordErasureReasonPerson, Confirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.LogId != world.vaultId || len(result.Erased) != 2 || len(result.Missing) != 0 || result.Entry == nil {
		t.Fatalf("the erasure answered %+v", result)
	}
	if err := eraserRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	stored := testEraseStored(world, eraser.sidecarId)
	if item := stored[first.EntryId]; item == nil || item.body != nil {
		t.Fatal("the first entry's file is gone, or its body still opens")
	}
	if item := stored[second.EntryId]; item == nil || string(item.body) == "" {
		t.Fatal("the entry beside the erased one lost its body")
	}
	if stored[deposited.EntryId] != nil {
		t.Fatal("the deposited entry was written after its erasure")
	}
	deposits, err := world.streams.For(eraser.sidecarId).ReadDeposits(ctx, world.vaultId, depositor.sidecarId)
	if err != nil || len(deposits) != 0 {
		t.Fatalf("%d deposits stand after the erasure: %v", len(deposits), err)
	}
	bodies := testEraseBodies(t, stored)
	if len(bodies) != 1 || sidecar.Id(bodies[0].GetErasureId()) != result.ErasureId || bodies[0].GetReason() != uint32(sidecar.RecordErasureReasonPerson) ||
		len(bodies[0].GetEntryIds()) != 2 {
		t.Fatalf("the erasure entries are %v", bodies)
	}
	if err := otherRecord.Reader().Sync(ctx, world.vaultId); err != nil {
		t.Fatal(err)
	}
	entry, ok := otherRecord.Reader().Entry(world.vaultId, first.EntryId)
	if !ok || entry.State != sidecar.RecordEntryErased || entry.Body != nil || !otherRecord.Reader().Erased(world.vaultId, first.EntryId) {
		t.Fatal("the other device kept the erased body or the entry's header")
	}
	if kept, ok := otherRecord.Reader().Entry(world.vaultId, second.EntryId); !ok || kept.State != sidecar.RecordEntryLive {
		t.Fatal("the other device erased the entry beside it")
	}
	other.stateLock.Lock()
	defer other.stateLock.Unlock()
	if len(other.alarms) != 0 {
		t.Fatalf("the other device alarmed: %v", other.alarms)
	}
}

// FS-47's erasure at the storage limit: the ERASE goes while every push to the eraser's stream is refused, so the
// body goes at once and another reader learns the erasure from the ERASE alone; the erasure entry waits in the
// writer's journal and lands once the limit lifts.
func TestRecordEraserEntryWaitsOutTheStorageLimit(t *testing.T) {
	ctx := t.Context()
	world := newTestRecordWorld(t)
	eraser, tap := world.eraserDevice()
	other := world.device(true)
	eraserRecord := eraser.open()
	otherRecord := other.open()
	first := testRecordAppend(t, eraserRecord, testRecordNote(nil, "first"))
	if err := eraserRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	tap.set(true, false)
	if _, err := eraserRecord.Eraser().Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.vaultId, EntryIds: []sidecar.Id{first.EntryId}, Reason: sidecar.RecordErasureReasonPerson, Confirmed: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := eraserRecord.Flush(ctx); err == nil {
		t.Fatal("the erasure entry landed at the storage limit")
	}
	stored := testEraseStored(world, eraser.sidecarId)
	if item := stored[first.EntryId]; item == nil || item.body != nil {
		t.Fatal("the body outlived its ERASE at the storage limit")
	}
	if len(testEraseBodies(t, stored)) != 0 {
		t.Fatal("an erasure entry landed at the storage limit")
	}
	if err := otherRecord.Reader().Sync(ctx, world.vaultId); err != nil {
		t.Fatal(err)
	}
	if !otherRecord.Reader().Erased(world.vaultId, first.EntryId) {
		t.Fatal("a reader holding only the ERASE does not read the entry as erased")
	}
	tap.set(false, false)
	// the writer's backoff after the refusals
	world.clock.Advance(eraser.settings.DepositInterval)
	if err := eraserRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if bodies := testEraseBodies(t, testEraseStored(world, eraser.sidecarId)); len(bodies) != 1 {
		t.Fatalf("%d erasure entries once the limit lifted", len(bodies))
	}
}

// A device killed after its ERASE committed and before it heard so: the restarted device resumes the erasure from
// its journal, sending the ERASE again under its push id, which evs answers as the commit it made, and appends the
// erasure entry once.
func TestRecordEraserResumesAfterACrash(t *testing.T) {
	ctx := t.Context()
	world := newTestRecordWorld(t)
	eraser, tap := world.eraserDevice()
	eraserRecord := eraser.open()
	first := testRecordAppend(t, eraserRecord, testRecordNote(nil, "first"))
	if err := eraserRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	tap.set(false, true)
	if _, err := eraserRecord.Eraser().Erase(ctx, &sidecar.RecordEraseArgs{
		LogId: world.vaultId, EntryIds: []sidecar.Id{first.EntryId}, Reason: sidecar.RecordErasureReasonPerson, Confirmed: true,
	}); !errors.Is(err, errTestEraseAnswerLost) {
		t.Fatalf("the erasure whose answer was lost: %v", err)
	}
	restarted := eraser.open()
	if err := restarted.Eraser().Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	erasures, err := world.streams.For(eraser.sidecarId).ReadErasures(ctx, world.vaultId, 0)
	if err != nil || len(erasures) != 1 {
		t.Fatalf("%d ERASEs committed: %v", len(erasures), err)
	}
	stored := testEraseStored(world, eraser.sidecarId)
	if item := stored[first.EntryId]; item == nil || item.body != nil {
		t.Fatal("the body outlived the resumed erasure")
	}
	if bodies := testEraseBodies(t, stored); len(bodies) != 1 || sidecar.Id(bodies[0].GetErasureId()) != erasures[0].ErasureId {
		t.Fatalf("the erasure entries after the resume: %v", bodies)
	}
	// nothing is left to resume
	if err := restarted.Eraser().Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if bodies := testEraseBodies(t, testEraseStored(world, eraser.sidecarId)); len(bodies) != 1 {
		t.Fatal("a second Resume wrote again")
	}
}

// What a person did not confirm, a harness process's descendant, a device that is no admin of the log, and a log-class
// entry, which lasts as long as the log, each erase nothing.
func TestRecordEraserRefusesWhatAPersonDidNotConfirm(t *testing.T) {
	ctx := t.Context()
	world := newTestRecordWorld(t)
	eraser, _ := world.eraserDevice()
	plain := world.device(true)
	eraserRecord := eraser.open()
	plainRecord := plain.open()
	first := testRecordAppend(t, eraserRecord, testRecordNote(nil, "first"))
	policy, err := proto.Marshal(&protocol.RetentionPolicy{LogId: world.vaultId.Bytes(), Class: 1})
	if err != nil {
		t.Fatal(err)
	}
	retention := testRecordAppend(t, eraserRecord, &sidecar.RecordDraft{
		Kind: sidecar.RecordKindRetention, Source: sidecar.RecordSourceApprover, NoSession: true,
		Body: &bridge.Signed{Body: policy, SignerId: eraser.sidecarId.Bytes(), Type: uint32(bridge.SignedType_SIGNED_RETENTION_POLICY)},
	})
	if err := eraserRecord.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		what   string
		record *sidecar.SidecarRecord
		args   *sidecar.RecordEraseArgs
		err    error
	}{
		{
			what: "unconfirmed", record: eraserRecord, err: sidecar.ErrRecordEraseUnconfirmed,
			args: &sidecar.RecordEraseArgs{LogId: world.vaultId, EntryIds: []sidecar.Id{first.EntryId}, Reason: sidecar.RecordErasureReasonPerson},
		},
		{
			what: "under a harness", record: eraserRecord, err: sidecar.ErrRecordEraseUnconfirmed,
			args: &sidecar.RecordEraseArgs{LogId: world.vaultId, EntryIds: []sidecar.Id{first.EntryId}, Reason: sidecar.RecordErasureReasonPerson, Confirmed: true, HarnessAncestor: true},
		},
		{
			what: "by a device that is no admin", record: plainRecord, err: sidecar.ErrRecordEraseNotAdmin,
			args: &sidecar.RecordEraseArgs{LogId: world.vaultId, EntryIds: []sidecar.Id{first.EntryId}, Reason: sidecar.RecordErasureReasonPerson, Confirmed: true},
		},
		{
			what: "of a log-class entry", record: eraserRecord, err: sidecar.ErrRecordEraseLogClass,
			args: &sidecar.RecordEraseArgs{LogId: world.vaultId, EntryIds: []sidecar.Id{retention.EntryId}, Reason: sidecar.RecordErasureReasonPerson, Confirmed: true},
		},
	}
	for _, c := range cases {
		if _, err := c.record.Eraser().Erase(ctx, c.args); !errors.Is(err, c.err) {
			t.Errorf("an erasure %s: %v", c.what, err)
		}
	}
	erasures, err := world.streams.For(eraser.sidecarId).ReadErasures(ctx, world.vaultId, 0)
	if err != nil || len(erasures) != 0 {
		t.Fatalf("%d ERASEs committed: %v", len(erasures), err)
	}
	if item := testEraseStored(world, eraser.sidecarId)[first.EntryId]; item == nil || item.body == nil {
		t.Fatal("a refused erasure took the body")
	}
	plan, err := eraserRecord.Eraser().Plan(ctx, &sidecar.RecordEraseArgs{LogId: world.vaultId, EntryIds: []sidecar.Id{first.EntryId, sidecar.NewId()}, Reason: sidecar.RecordErasureReasonPerson})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Items) != 1 || plan.Items[0].EntryId != first.EntryId || len(plan.Missing) != 1 || !slices.ContainsFunc(plan.Items, func(item *sidecar.RecordErasePlanItem) bool { return 0 < item.CopyCount }) {
		t.Fatalf("the plan answered %+v", plan)
	}
}
