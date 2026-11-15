package evsservice

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A drop table on fake clusters: a host, its metadata cluster held to the budget, the segment cluster, and a paid ctx
// for writes the tests make as a push's step 8 would.
type dropTestWorld struct {
	t              *testing.T
	ctx            context.Context
	clock          *sidecartest.FakeClock
	host           *sidecartest.FakeHost
	blobs          sidecar.BlobStore
	cluster        sidecar.BlobCluster
	segmentCluster sidecar.BlobCluster
	paidCtx        context.Context
	table          *DropTable
	repoId         sidecar.Id
	refId          sidecar.Id
}

func newDropTestWorld(t *testing.T) *dropTestWorld {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	blobs := NewBudgetedBlobs(host.Blobs)
	cluster, err := blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	segmentCluster, err := blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := host.Budget.AdmitP1(ctx, "meta-1", connectNetworkId(), sidecar.WriteCost{ImmediateByteCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(grant.Close)
	table, err := NewDropTable(host.ServiceHost(), blobs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &dropTestWorld{
		t: t, ctx: ctx, clock: clock, host: host, blobs: blobs, cluster: cluster, segmentCluster: segmentCluster,
		paidCtx: grant.Context(), table: table, repoId: testId("drop-repo"), refId: testId("drop-ref"),
	}
}

// A committed DROP of dropLabel at version, its place's minute now's.
func (self *dropTestWorld) dropCommit(dropLabel string, version uint64, notBefore time.Time) *DropCommit {
	return &DropCommit{
		ClusterId: "meta-1", RepoId: self.repoId, RefId: self.refId, PushId: testId("push-" + dropLabel), Version: version,
		Place: &protocol.EvsPlace{Minute: BatchMinute(self.clock.Now()), Instance: 7, Seq: uint32(version), Length: 100},
		Body: &protocol.EvsDropHistory{
			DropId: testId(dropLabel).Bytes(), Action: 1, NotBeforeMs: notBefore.UnixMilli(),
		},
	}
}

// A committed cancel of dropLabel at its version.
func (self *dropTestWorld) cancelCommit(dropLabel string, dropVersion uint64, version uint64) *DropCommit {
	return &DropCommit{
		ClusterId: "meta-1", RepoId: self.repoId, RefId: self.refId, PushId: testId("cancel-" + dropLabel), Version: version,
		Place: &protocol.EvsPlace{Minute: BatchMinute(self.clock.Now()), Instance: 7, Seq: uint32(version), Length: 100},
		Body:  &protocol.EvsDropHistory{DropId: testId("c-" + dropLabel).Bytes(), Action: 2, CancelsDropId: testId(dropLabel).Bytes(), CancelsVersion: dropVersion},
	}
}

func (self *dropTestWorld) read() *DropTableRead {
	read, err := self.table.Read(self.ctx, self.cluster, self.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	return read
}

// A table with every record kind, each field set.
func dropTestState() *DropTableState {
	place := &protocol.EvsPlace{Minute: 29000000, Instance: 3, Seq: 9, Offset: 32, Length: 512}
	state := &DropTableState{
		Job: &DropJobRecord{
			JobId: testId("job"), Owner: testId("owner"), UntilMs: 1234, Phase: protocol.EvsDropPhase_EVS_DROP_HORIZON, Held: true,
			Round: 3, FenceMs: 99, HorizonMs: 88, Cursor: DropCursor{Sequence: 2, Row: 77}, RetryMs: 4321, CoveredCount: 2,
			FreedByteCount: 1 << 40, HeldByteCount: 5, StartedMs: 7,
		},
		Voids: []*DropVoidRecord{{DropId: testId("void-a"), State: DropStateCancelled}, {DropId: testId("void-b"), State: DropStateRefusedVerify}},
		Previews: []*DropPreviewRecord{
			{PreviewId: testId("preview"), RefId: testId("ref"), State: protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_DONE, CreatedMs: 1, UntilMs: 2, SnapshotVersion: 3},
		},
	}
	for i, dropState := range []DropState{DropStatePending, DropStateCancelled, DropStateExecuting, DropStateDone,
		DropStateRefusedLocked, DropStateRefusedMismatch, DropStateRefusedVerify, DropStateHeld, DropStateObserved} {
		entry := &DropTableEntry{
			DropId: testId("drop-" + string(rune('a'+i))), RefId: testId("ref"), PushId: testId("push"), Version: uint64(10 + i),
			Place: place, NotBeforeMs: int64(1000 + i), SeenMs: int64(2000 + i), State: dropState, FreedByteCount: uint64(i),
			HeldByteCount: uint64(2 * i), PreviewId: testId("preview"),
		}
		if dropState == DropStateExecuting {
			entry.Phase = protocol.EvsDropPhase_EVS_DROP_MARK
		}
		if dropState.Ended() {
			entry.EndedDay = uint16(20000 + i)
		}
		state.Drops = append(state.Drops, entry)
	}
	return state
}

func TestDropTableRoundTrip(t *testing.T) {
	state := dropTestState()
	encoded, err := EncodeDropTable(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != state.byteCount() {
		t.Fatalf("encoded %d bytes, counted %d", len(encoded), state.byteCount())
	}
	decoded, err := DecodeDropTable(encoded)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EncodeDropTable(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, again) {
		t.Fatal("a decoded table encodes to other bytes")
	}
	if !proto.Equal(decoded.Drops[3].Place, state.Drops[3].Place) || *decoded.Job != *state.Job || len(decoded.Drops) != 9 ||
		*decoded.Voids[1] != *state.Voids[1] || *decoded.Previews[0] != *state.Previews[0] {
		t.Fatal("a decoded table differs from the one encoded")
	}
	for i := range state.Drops {
		want, got := *state.Drops[i], *decoded.Drops[i]
		want.Place, got.Place = nil, nil
		if want != got {
			t.Fatalf("drop %d: %+v, want %+v", i, got, want)
		}
	}
	// an empty table is a header and a trailer
	empty, err := EncodeDropTable(&DropTableState{})
	if err != nil || len(empty) != dropTableHeaderByteCount+dropTableTrailerByteCount {
		t.Fatalf("an empty table of %d bytes: %v", len(empty), err)
	}
}

func TestDropTableRefusesBadBytes(t *testing.T) {
	encoded, err := EncodeDropTable(dropTestState())
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(encoded)
	tampered[40] ^= 1
	if _, err := DecodeDropTable(tampered); !errors.Is(err, ErrDropTableInvalid) {
		t.Fatalf("a tampered table: %v", err)
	}
	if _, err := DecodeDropTable(encoded[:len(encoded)-1]); !errors.Is(err, ErrDropTableInvalid) {
		t.Fatalf("a short table: %v", err)
	}
	for name, adjust := range map[string]func(state *DropTableState){
		"a state out of range":      func(state *DropTableState) { state.Drops[0].State = 10 },
		"a phase on a pending drop": func(state *DropTableState) { state.Drops[0].Phase = protocol.EvsDropPhase_EVS_DROP_MARK },
		"a repeated drop":           func(state *DropTableState) { state.Drops[1].DropId = state.Drops[0].DropId },
		"a void record of a done drop": func(state *DropTableState) {
			state.Voids[0].State = DropStateDone
		},
		"a job in no phase": func(state *DropTableState) { state.Job.Phase = 0 },
	} {
		state := dropTestState()
		adjust(state)
		if _, err := EncodeDropTable(state); !errors.Is(err, ErrDropTableInvalid) {
			t.Errorf("%s encoded: %v", name, err)
		}
	}
}

// DESIGN-DETAILS 10.6's drop_table_test.go row: seen_ms is the appender's, read after its answer, and an unsure clock
// appends nothing. Step 7's 200, a reader's repair and evacuation's append all come through DropSink.Append.
func TestDropSinkAppendsWithSeenMs(t *testing.T) {
	world := newDropTestWorld(t)
	notBefore := world.clock.Now().Add(7 * 24 * time.Hour)
	// step 7's 200 answered, then the clock read
	world.clock.Advance(3 * time.Second)
	seenMs := world.clock.Now().UnixMilli()
	if err := world.table.Append(world.paidCtx, world.dropCommit("drop-1", 5, notBefore), seenMs); err != nil {
		t.Fatal(err)
	}
	read := world.read()
	entry := read.State.Drop(testId("drop-1"))
	if entry == nil || entry.State != DropStatePending || entry.SeenMs != seenMs || entry.NotBeforeMs != notBefore.UnixMilli() || entry.Version != 5 {
		t.Fatalf("the appended entry: %+v", entry)
	}
	// a later append, evacuation's or a reader's repair, keeps the first seen_ms
	world.clock.Advance(time.Hour)
	if err := world.table.Append(world.paidCtx, world.dropCommit("drop-1", 5, notBefore), world.clock.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if again := world.read(); again.State.Drop(testId("drop-1")).SeenMs != seenMs || len(again.State.Drops) != 1 {
		t.Fatal("a second append moved seen_ms or added an entry")
	}
	// the hint names the repo's cluster
	value, found, err := world.host.Redis.Get(world.ctx, DropHintKey(world.repoId))
	if err != nil || !found || string(value) != "meta-1" {
		t.Fatalf("the hint: %q %t %v", value, found, err)
	}
	if repoId, ok := DropHintRepoId(DropHintKey(world.repoId)); !ok || repoId != world.repoId {
		t.Fatal("the hint key does not name its repo")
	}
	if _, ok := DropHintRepoId(dropClusterLeaseKey("seg-1")); ok {
		t.Fatal("the cluster lease key reads as a hint")
	}
	// the job's own writes set no hint, so a run does not wake its own repo
	if err := world.host.Redis.Delete(world.ctx, []string{DropHintKey(world.repoId)}); err != nil {
		t.Fatal(err)
	}
	if _, err := world.table.Update(world.paidCtx, world.cluster, world.repoId, func(state *DropTableState, now time.Time) (bool, error) {
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := world.host.Redis.Get(world.ctx, DropHintKey(world.repoId)); found {
		t.Fatal("a write that left no new drop work set the hint")
	}
}

func TestDropSinkUnsureClockAppendsNothing(t *testing.T) {
	world := newDropTestWorld(t)
	world.host.ClockCheck.SetUnknown()
	err := world.table.Append(world.paidCtx, world.dropCommit("drop-1", 5, world.clock.Now()), world.clock.Now().UnixMilli())
	if !errors.Is(err, ErrDropClockUnsure) {
		t.Fatalf("an append on an unsure clock: %v", err)
	}
	if read := world.read(); read.Etag != "" {
		t.Fatal("an unsure clock wrote the table")
	}
	world.host.ClockCheck.SetOffset(80 * time.Millisecond)
	if err := world.table.Append(world.paidCtx, world.dropCommit("drop-1", 5, world.clock.Now()), world.clock.Now().UnixMilli()); !errors.Is(err, ErrDropClockUnsure) {
		t.Fatalf("an append 80 ms off: %v", err)
	}
}

func TestDropSinkCancels(t *testing.T) {
	world := newDropTestWorld(t)
	notBefore := world.clock.Now().Add(7 * 24 * time.Hour)
	if err := world.table.Append(world.paidCtx, world.dropCommit("drop-1", 5, notBefore), world.clock.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := world.table.Append(world.paidCtx, world.cancelCommit("drop-1", 5, 6), world.clock.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	read := world.read()
	if entry := read.State.Drop(testId("drop-1")); entry == nil || entry.State != DropStateCancelled || entry.EndedDay == 0 {
		t.Fatalf("the cancelled entry: %+v", entry)
	}
	if void := read.State.Void(testId("drop-1")); void == nil || void.State != DropStateCancelled {
		t.Fatal("a cancel left no void record")
	}
	// a cancel whose drop's append was lost leaves the void record, and the late append finds it cancelled
	if err := world.table.Append(world.paidCtx, world.cancelCommit("drop-2", 8, 9), world.clock.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := world.table.Append(world.paidCtx, world.dropCommit("drop-2", 8, notBefore), world.clock.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	read = world.read()
	if read.State.Drop(testId("drop-2")) != nil || read.State.Void(testId("drop-2")) == nil {
		t.Fatal("a drop cancelled before its append was appended pending")
	}
	status, reason := DropStateCancelled.Status()
	if status != protocol.EvsDropState_EVS_DROP_CANCELLED || reason != 0 {
		t.Fatal("a cancelled drop's status")
	}
}

// QD-179's rule 4: an entry absent with no void record means executed, so an append older than the eviction guard
// adds nothing, while evacuation's append within 26 h does.
func TestDropSinkSkipsAnExecutedDropPastTheGuard(t *testing.T) {
	world := newDropTestWorld(t)
	commit := world.dropCommit("drop-1", 5, world.clock.Now())
	world.clock.Advance(26 * time.Hour)
	if err := world.table.Append(world.paidCtx, commit, world.clock.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if world.read().State.Drop(testId("drop-1")) == nil {
		t.Fatal("evacuation's append at 26 h added nothing")
	}
	old := world.dropCommit("drop-2", 6, world.clock.Now())
	world.clock.Advance(28 * time.Hour)
	if err := world.table.Append(world.paidCtx, old, world.clock.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if world.read().State.Drop(testId("drop-2")) != nil {
		t.Fatal("an append 28 h after the commit re-added an executed drop")
	}
}

func TestDropTableEvictsByTheBounds(t *testing.T) {
	settings := DefaultDropSettings()
	now := sidecartest.DefaultClockStart().Add(400 * 24 * time.Hour)
	place := &protocol.EvsPlace{Minute: 1, Length: 100}
	entry := func(label string, state DropState, endedAgo time.Duration, seenAgo time.Duration) *DropTableEntry {
		entry := &DropTableEntry{DropId: testId(label), Place: place, State: state, SeenMs: now.Add(-seenAgo).UnixMilli()}
		if state.Ended() {
			entry.EndedDay = dropDay(now.Add(-endedAgo))
		}
		return entry
	}
	state := &DropTableState{Drops: []*DropTableEntry{
		entry("old-done", DropStateDone, 32*24*time.Hour, 40*24*time.Hour),
		entry("young-done", DropStateDone, 10*24*time.Hour, 20*24*time.Hour),
		entry("pending", DropStatePending, 0, 90*24*time.Hour),
		entry("observed", DropStateObserved, 0, 90*24*time.Hour),
	}}
	if err := state.evict(now, settings); err != nil {
		t.Fatal(err)
	}
	labels := []string{}
	for _, entry := range state.Drops {
		labels = append(labels, string(bytes.TrimRight(entry.DropId[:], " ")))
	}
	if !slices.Equal(labels, []string{"young-done", "pending", "observed"}) {
		t.Fatalf("kept %v", labels)
	}
	// past the bound: ended entries go oldest first, never one seen under 27 h ago, and pending ones never
	tight := DefaultDropSettings()
	tight.TableByteCount = dropTableHeaderByteCount + dropTableTrailerByteCount + 2*dropTableEntryByteCount
	tight.TableAdmitByteCount = tight.TableByteCount
	full := &DropTableState{Drops: []*DropTableEntry{
		entry("fresh-cancel", DropStateCancelled, time.Hour, time.Hour),
		entry("done-a", DropStateDone, 5*24*time.Hour, 6*24*time.Hour),
		entry("done-b", DropStateDone, 3*24*time.Hour, 4*24*time.Hour),
	}}
	if err := full.evict(now, tight); err != nil {
		t.Fatal(err)
	}
	if len(full.Drops) != 2 || full.Drops[0].DropId != testId("fresh-cancel") || full.Drops[1].DropId != testId("done-b") {
		t.Fatalf("evicted the wrong entry: %d left", len(full.Drops))
	}
	stuck := &DropTableState{Drops: []*DropTableEntry{
		entry("p1", DropStatePending, 0, time.Hour), entry("p2", DropStatePending, 0, time.Hour), entry("p3", DropStatePending, 0, time.Hour),
	}}
	if err := stuck.evict(now, tight); !errors.Is(err, ErrDropTableFull) {
		t.Fatalf("a table of pending drops past its bound: %v", err)
	}
}

// QD-179's rule 5: 5c answers 429 while pending, executing and observed entries and void records would pass 48 KiB;
// held entries never count.
func TestDropTableAdmitsDropsWithinItsLine(t *testing.T) {
	settings := DefaultDropSettings()
	state := &DropTableState{}
	place := &protocol.EvsPlace{Minute: 1, Length: 100}
	for i := 0; state.AdmitsDrop(settings); i += 1 {
		state.Drops = append(state.Drops, &DropTableEntry{DropId: testIdFrom(string(rune(i))), Place: place, State: DropStatePending})
	}
	if count := len(state.Drops); count != settings.TableAdmitByteCount/dropTableEntryByteCount {
		t.Fatalf("admitted %d drops", count)
	}
	for _, entry := range state.Drops {
		entry.State = DropStateHeld
	}
	if !state.AdmitsDrop(settings) {
		t.Fatal("held entries counted against the line")
	}
	state.Voids = make([]*DropVoidRecord, settings.TableAdmitByteCount/dropTableVoidByteCount)
	if state.AdmitsDrop(settings) {
		t.Fatal("void records did not count against the line")
	}
}

// A held drop reads done, its held bytes as freed, so no listing shows a hold (owner decision 184).
func TestDropStateHeldReadsDone(t *testing.T) {
	heldStatus, heldReason := DropStateHeld.Status()
	doneStatus, doneReason := DropStateDone.Status()
	if heldStatus != doneStatus || heldReason != doneReason {
		t.Fatal("a held drop's status differs from a done one's")
	}
	if !DropStateHeld.Ended() || DropStateHeld.Void() || !DropStateHeld.Executed() {
		t.Fatal("a held drop does not end, leave and count as a done one")
	}
	for _, state := range []DropState{DropStateRefusedLocked, DropStateRefusedMismatch, DropStateRefusedVerify} {
		if status, reason := state.Status(); status != protocol.EvsDropState_EVS_DROP_REFUSED || reason == 0 || !state.Void() {
			t.Fatalf("state %d's status", state)
		}
	}
}

func TestDropFilesRoundTrip(t *testing.T) {
	repoId, jobId := testId("repo"), testId("job")
	place := &protocol.EvsPlace{Minute: 5, Instance: 6, Seq: 7, Offset: 8, Length: 9}
	covered := []*DropCovered{{DropId: testId("d1"), RefId: testId("r1"), Version: 4, PushId: testId("p1"), Place: place, SeenMs: 12345}}
	file, err := DecodeDropFile(EncodeDropCoveredFile(repoId, jobId, covered), repoId, jobId, DropFileSnap, 0)
	if err != nil || len(file.Covered) != 1 || file.Covered[0].SeenMs != 12345 || !proto.Equal(file.Covered[0].Place, place) {
		t.Fatalf("snap-0: %+v %v", file, err)
	}
	horizon := time.UnixMilli(777000)
	round := &DropRoundSnapshot{Horizon: horizon, Refs: []*DropRefSnapshot{{RefId: testId("r2"), Marked: 3, Checked: 4}, {RefId: testId("r1"), Marked: 1, Checked: 2}}}
	file, err = DecodeDropFile(EncodeDropRoundFile(repoId, jobId, 2, round), repoId, jobId, DropFileSnap, 2)
	if err != nil || !file.Round.Horizon.Equal(horizon) || len(file.Round.Refs) != 2 || file.Round.Refs[0].RefId != testId("r1") {
		t.Fatalf("snap-2: %v", err)
	}
	segment := DropSegmentId([32]byte{9})
	slot := DropSlotId(testId("slot"))
	encoded, err := EncodeDropIdFile(DropFileCand, repoId, jobId, 0, []DropScanId{segment, slot})
	if err != nil {
		t.Fatal(err)
	}
	file, err = DecodeDropFile(encoded, repoId, jobId, DropFileCand, 0)
	if err != nil || len(file.Ids) != 2 || CompareDropScanIds(file.Ids[0], file.Ids[1]) >= 0 || file.Ids[1].Kind != DropIdSlot && file.Ids[0].Kind != DropIdSlot {
		t.Fatalf("cand: %v", err)
	}
	if slot.SlotId() != testId("slot") {
		t.Fatal("a slot's id does not round-trip")
	}
	file, err = DecodeDropFile(EncodeDropMarkFile(repoId, jobId, 3, testId("r1"), 17, []DropScanId{segment}), repoId, jobId, DropFileMark, 3)
	if err != nil || file.CursorRefId != testId("r1") || file.CursorVersion != 17 || len(file.Ids) != 1 {
		t.Fatalf("mark: %v", err)
	}
	answers := []*DropAnswer{{DropScanId: segment, Outcome: DropOutcomeYoung}, {DropScanId: slot, Outcome: DropOutcomeDeleted}}
	file, err = DecodeDropFile(EncodeDropDelFile(repoId, jobId, 0, answers), repoId, jobId, DropFileDel, 0)
	if err != nil || len(file.Answers) != 2 || file.Answers[0].Outcome != DropOutcomeYoung {
		t.Fatalf("del: %v", err)
	}
	encoded, err = EncodeDropMessageFile(DropFileAsk, repoId, jobId, []byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	if file, err = DecodeDropFile(encoded, repoId, jobId, DropFileAsk, 0); err != nil || string(file.Message) != "request" {
		t.Fatalf("ask: %v", err)
	}
	// a file is held to its key's repo, job, kind and sequence, and to its trailer
	if _, err := DecodeDropFile(encoded, repoId, testId("other"), DropFileAsk, 0); !errors.Is(err, ErrDropFileInvalid) {
		t.Fatalf("another job's file: %v", err)
	}
	if _, err := DecodeDropFile(encoded, repoId, jobId, DropFileRes, 0); !errors.Is(err, ErrDropFileInvalid) {
		t.Fatalf("another kind's file: %v", err)
	}
	tampered := bytes.Clone(encoded)
	tampered[len(tampered)-40] ^= 1
	if _, err := DecodeDropFile(tampered, repoId, jobId, DropFileAsk, 0); !errors.Is(err, ErrDropFileInvalid) {
		t.Fatalf("a tampered file: %v", err)
	}
	if key := DropFileKey(repoId, jobId, DropFileMark, 42); key != DropscanKey(repoId, jobId, "mark-0000000042") {
		t.Fatalf("a key spelled %q (QD-562)", key)
	}
	if !DropOutcomeDeleted.Final() || DropOutcomeYoung.Final() || !DropOutcomeObserved.Final() {
		t.Fatal("which outcomes answer an id for good")
	}
}

// The files a job reads back: candidates with their cand positions, marks as the union with the newest cursor, and each
// id's newest answer.
func TestDropFilesReadBack(t *testing.T) {
	world := newDropTestWorld(t)
	files := NewDropFiles(world.segmentCluster, world.repoId, testId("job"), DefaultDropSettings())
	a, b, c := DropSegmentId([32]byte{1}), DropSegmentId([32]byte{2}), DropSlotId(testId("slot"))
	put := func(kind DropFileKind, sequence uint32, encoded []byte, err error) {
		if err != nil {
			t.Fatal(err)
		}
		if err := files.Put(world.ctx, kind, sequence, encoded); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := EncodeDropIdFile(DropFileCand, world.repoId, testId("job"), 0, []DropScanId{a, b})
	put(DropFileCand, 0, encoded, err)
	encoded, err = EncodeDropIdFile(DropFileCand, world.repoId, testId("job"), 1, []DropScanId{c})
	put(DropFileCand, 1, encoded, err)
	// a second put of equal bytes is success; other bytes are refused
	put(DropFileCand, 1, encoded, nil)
	other, _ := EncodeDropIdFile(DropFileCand, world.repoId, testId("job"), 1, []DropScanId{a})
	if err := files.Put(world.ctx, DropFileCand, 1, other); !errors.Is(err, sidecar.ErrBlobImmutableMismatch) {
		t.Fatalf("other bytes at a written file: %v", err)
	}
	put(DropFileMark, 0, EncodeDropMarkFile(world.repoId, testId("job"), 0, testId("r1"), 5, []DropScanId{a}), nil)
	put(DropFileMark, 1, EncodeDropMarkFile(world.repoId, testId("job"), 1, testId("r2"), 9, nil), nil)
	put(DropFileDel, 0, EncodeDropDelFile(world.repoId, testId("job"), 0, []*DropAnswer{{DropScanId: b, Outcome: DropOutcomeYoung}}), nil)
	put(DropFileDel, 1, EncodeDropDelFile(world.repoId, testId("job"), 1, []*DropAnswer{{DropScanId: b, Outcome: DropOutcomeDeleted}}), nil)
	candidates, err := files.Candidates(world.ctx)
	if err != nil || len(candidates) != 3 || candidates[2].Cursor != (DropCursor{Sequence: 1, Row: 0}) || candidates[1].Cursor != (DropCursor{Sequence: 0, Row: 1}) {
		t.Fatalf("candidates: %v", err)
	}
	marks, cursorRefId, cursorVersion, err := files.Marks(world.ctx)
	if err != nil || !marks[a] || len(marks) != 1 || cursorRefId != testId("r2") || cursorVersion != 9 {
		t.Fatalf("marks: %v", err)
	}
	answers, err := files.Answers(world.ctx)
	if err != nil || answers[b] != DropOutcomeDeleted {
		t.Fatalf("answers: %v", err)
	}
	next, err := files.NextSequence(world.ctx, DropFileDel)
	if err != nil || next != 2 {
		t.Fatalf("next del sequence %d: %v", next, err)
	}
}
