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

// The labels of state's entries, in order.
func dropTestLabels(state *DropTableState) []string {
	labels := []string{}
	for _, entry := range state.Drops {
		labels = append(labels, string(bytes.TrimRight(entry.DropId[:], " ")))
	}
	return labels
}

// Owner decision 643 (QD-1113): a held entry stays past the 30 d an ended entry is kept, since the job resumes its
// deletions from it however long its hold lasts, and a table holding only such entries wants no write; a done entry
// of the same day goes. When the job moves a held entry to done it keeps the day it moved to held, so one held over
// 30 d back goes at that write, and one held inside them stays until they pass, exactly as its done twin would.
func TestDropTableKeepsAHeldEntryPastItsRetention(t *testing.T) {
	settings := DefaultDropSettings()
	now := sidecartest.DefaultClockStart().Add(400 * 24 * time.Hour)
	place := &protocol.EvsPlace{Minute: 1, Length: 100}
	entry := func(label string, state DropState, endedAgo time.Duration) *DropTableEntry {
		return &DropTableEntry{
			DropId: testId(label), Place: place, State: state, SeenMs: now.Add(-endedAgo - 2*24*time.Hour).UnixMilli(),
			EndedDay: dropDay(now.Add(-endedAgo)),
		}
	}
	state := &DropTableState{Drops: []*DropTableEntry{
		entry("held-90", DropStateHeld, 90*24*time.Hour),
		entry("held-31", DropStateHeld, 31*24*time.Hour),
		entry("done-31", DropStateDone, 31*24*time.Hour),
		entry("held-10", DropStateHeld, 10*24*time.Hour),
	}}
	if !state.expiring(now, settings) {
		t.Fatal("the aged done entry wants no write")
	}
	if err := state.evict(now, settings); err != nil {
		t.Fatal(err)
	}
	if labels := dropTestLabels(state); !slices.Equal(labels, []string{"held-90", "held-31", "held-10"}) {
		t.Fatalf("kept %v", labels)
	}
	if state.expiring(now, settings) {
		t.Fatal("aged held entries want a write, which would evict them")
	}
	if !state.Drop(testId("held-90")).aged(now, settings) || state.Drop(testId("held-10")).aged(now, settings) {
		t.Fatal("a held entry's retention does not run from the day it moved to held")
	}

	// the job's end moves each to done, keeping the day it moved to held
	heldDay := state.Drop(testId("held-10")).EndedDay
	for _, held := range slices.Clone(state.Drops) {
		state.setState(held, DropStateDone, dropDay(now))
	}
	if state.Drop(testId("held-10")).EndedDay != heldDay || state.Drop(testId("held-90")).EndedDay != dropDay(now.Add(-90*24*time.Hour)) {
		t.Fatal("the move to done stamped another day")
	}
	if err := state.evict(now, settings); err != nil {
		t.Fatal(err)
	}
	if labels := dropTestLabels(state); !slices.Equal(labels, []string{"held-10"}) {
		t.Fatalf("after the move to done kept %v", labels)
	}
	// the one held 10 d back goes when its 30 d from that day have passed, not 30 d from its move to done
	retained := dropDayStart(heldDay).Add(settings.EndedRetention + 24*time.Hour)
	if err := state.evict(retained.Add(-time.Second), settings); err != nil || len(state.Drops) != 1 {
		t.Fatalf("a second before its retention ends: %d entries, %v", len(state.Drops), err)
	}
	if err := state.evict(retained, settings); err != nil || len(state.Drops) != 0 {
		t.Fatalf("at its retention's end: %d entries, %v", len(state.Drops), err)
	}
}

// Owner decision 643: held entries count toward no refusal, so a table they fill past its bound still takes the next
// DROP, which never fails on them: the bound evicts done entries and never a held one, unlisting a held one instead
// where it would evict its done twin (QD-1126), and the table passes TableByteCount by its held entries, which a read
// takes back. Past TableReadByteCount a write is refused and a read too.
func TestDropTableBoundLeavesHeldEntriesOut(t *testing.T) {
	world := newDropTestWorld(t)
	tight := DefaultDropSettings()
	tight.TableByteCount = dropTableHeaderByteCount + dropTableTrailerByteCount + 2*dropTableEntryByteCount
	tight.TableAdmitByteCount = tight.TableByteCount
	table, err := NewDropTable(world.host.ServiceHost(), world.blobs, tight, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := world.clock.Now()
	place := &protocol.EvsPlace{Minute: 1, Length: 100}
	ended := func(label string, state DropState, endedAgo time.Duration) *DropTableEntry {
		// its DROP seen past the eviction guard, so only its state keeps the bound from taking it
		return &DropTableEntry{
			DropId: testId(label), RefId: world.refId, Place: place, State: state, SeenMs: now.Add(-endedAgo - 24*time.Hour).UnixMilli(),
			EndedDay: dropDay(now.Add(-endedAgo)),
		}
	}
	// four held entries and a newer done one: twice the bound, which counted held entries would have evicted
	if _, err := table.Update(world.paidCtx, world.cluster, world.repoId, func(state *DropTableState, now time.Time) (bool, error) {
		state.Drops = append(state.Drops,
			ended("held-a", DropStateHeld, 5*24*time.Hour), ended("held-b", DropStateHeld, 5*24*time.Hour),
			ended("held-c", DropStateHeld, 4*24*time.Hour), ended("held-d", DropStateHeld, 4*24*time.Hour),
			ended("done", DropStateDone, 24*time.Hour),
		)
		return true, nil
	}); err != nil {
		t.Fatalf("a table of held entries past its bound: %v", err)
	}
	read, err := table.Read(world.ctx, world.cluster, world.repoId)
	if err != nil {
		t.Fatalf("a read of held entries past the bound: %v", err)
	}
	if !read.State.AdmitsDrop(tight) {
		t.Fatal("held entries kept a DROP out")
	}
	for i, label := range []string{"drop-1", "drop-2"} {
		if err := table.Append(world.paidCtx, world.dropCommit(label, uint64(5+i), now), now.UnixMilli()); err != nil {
			t.Fatalf("%s beside held entries: %v", label, err)
		}
	}
	read, err = table.Read(world.ctx, world.cluster, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if labels := dropTestLabels(read.State); !slices.Equal(labels, []string{"held-a", "held-b", "held-c", "held-d", "drop-1", "drop-2"}) {
		t.Fatalf("the bound kept %v", labels)
	}
	if read.State.boundByteCount() != tight.TableByteCount || read.State.byteCount() != tight.TableByteCount+4*dropTableEntryByteCount {
		t.Fatalf("a table of %d bytes, %d counted", read.State.byteCount(), read.State.boundByteCount())
	}
	// the bound would have evicted each one's done twin, oldest first: each is unlisted, and the listing is the twin's
	for _, label := range []string{"held-a", "held-b", "held-c", "held-d"} {
		if entry := read.State.Drop(testId(label)); entry.State != DropStateHeld || entry.EndedDay != dropUnlistedDay {
			t.Fatalf("%s past the bound: %+v", label, entry)
		}
	}
	listing := DropStatuses(read.State, now, tight)
	if len(listing.Drops) != 2 || sidecar.Id(listing.Drops[0].DropId) != testId("drop-1") || sidecar.Id(listing.Drops[1].DropId) != testId("drop-2") {
		t.Fatalf("listed %d drops past the bound", len(listing.Drops))
	}

	// a read that takes in fewer held bytes than the table holds refuses it, and a write past them is refused
	capped := *tight
	capped.TableHeldByteCount = 3 * dropTableEntryByteCount
	cappedTable, err := NewDropTable(world.host.ServiceHost(), world.blobs, &capped, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cappedTable.Read(world.ctx, world.cluster, world.repoId); !errors.Is(err, ErrDropTableInvalid) {
		t.Fatalf("a read past TableReadByteCount: %v", err)
	}
	if err := read.State.evict(now, &capped); !errors.Is(err, ErrDropTableFull) {
		t.Fatalf("a write past TableReadByteCount: %v", err)
	}
	// and the count itself still refuses what is not held: a third pending drop past the bound
	stuck := &DropTableState{Drops: slices.Clone(read.State.Drops)}
	stuck.Drops = append(stuck.Drops, &DropTableEntry{DropId: testId("drop-3"), Place: place, State: DropStatePending, SeenMs: now.UnixMilli()})
	if err := stuck.evict(now, tight); !errors.Is(err, ErrDropTableFull) {
		t.Fatalf("pending drops past the bound beside held entries: %v", err)
	}
}

// A copy of state whose records a write may change without changing state's.
func dropTestCloneState(state *DropTableState) *DropTableState {
	clone := &DropTableState{}
	if state.Job != nil {
		job := *state.Job
		clone.Job = &job
	}
	for _, entry := range state.Drops {
		copied := *entry
		clone.Drops = append(clone.Drops, &copied)
	}
	for _, void := range state.Voids {
		copied := *void
		clone.Voids = append(clone.Voids, &copied)
	}
	for _, preview := range state.Previews {
		copied := *preview
		clone.Previews = append(clone.Previews, &copied)
	}
	return clone
}

// One write of state at now, as DropTable.Update makes it: changed by change, then evicted; a refused write leaves
// state as it was.
func dropTestWrite(state *DropTableState, now time.Time, settings *DropSettings, change func(state *DropTableState)) (*DropTableState, error) {
	written := dropTestCloneState(state)
	change(written)
	if err := written.evict(now, settings); err != nil {
		return state, err
	}
	return written, nil
}

// QD-1126 (owner decisions 184, 643): past its bound a table with held entries lists, evicts and admits as its no-hold
// twin's, whose drops are done and whose job has ended. A listed held entry counts and takes its place in the eviction
// order as its twin; where the bound evicts the twin it is unlisted, its ended_day dropUnlistedDay, and leaves the
// listing; a held job's record counts for nothing; a write the twin's bound refuses is refused too; and once the hold
// ends, the job's move of an unlisted entry to done evicts it at that write, leaving the twin's table.
func TestDropTableBoundMirrorsANoHoldTwin(t *testing.T) {
	settings := DefaultDropSettings()
	settings.TableByteCount = dropTableHeaderByteCount + dropTableTrailerByteCount + 4*dropTableEntryByteCount + dropTablePreviewByteCount
	settings.TableAdmitByteCount = settings.TableByteCount
	now := sidecartest.DefaultClockStart().Add(400 * 24 * time.Hour)
	day := 24 * time.Hour
	place := &protocol.EvsPlace{Minute: 1, Length: 100}
	ended := func(label string, state DropState, endedAgo time.Duration) *DropTableEntry {
		return &DropTableEntry{
			DropId: testId(label), Place: place, State: state, SeenMs: now.Add(-endedAgo - 2*day).UnixMilli(), EndedDay: dropDay(now.Add(-endedAgo)),
			FreedByteCount: 7,
		}
	}
	preview := func() *DropPreviewRecord {
		// a dry run long ended, which the bound takes only once no ended entry is left to take
		return &DropPreviewRecord{
			PreviewId: testId("preview"), RefId: testId("ref"), State: protocol.EvsDropPreviewState_EVS_DROP_PREVIEW_DONE,
			CreatedMs: now.Add(-21 * day).UnixMilli(), UntilMs: now.Add(-20 * day).UnixMilli(),
		}
	}
	held := &DropTableState{
		// the job that moved a and c to held keeps its record while the hold stands; the twin's ended
		Job: &DropJobRecord{JobId: testId("job"), Phase: protocol.EvsDropPhase_EVS_DROP_DELETE, Held: true},
		Drops: []*DropTableEntry{
			ended("a", DropStateHeld, 10*day), ended("b", DropStateDone, 8*day), ended("c", DropStateHeld, 6*day), ended("d", DropStateDone, 4*day),
		},
		Previews: []*DropPreviewRecord{preview()},
	}
	twin := &DropTableState{
		Drops: []*DropTableEntry{
			ended("a", DropStateDone, 10*day), ended("b", DropStateDone, 8*day), ended("c", DropStateDone, 6*day), ended("d", DropStateDone, 4*day),
		},
		Previews: []*DropPreviewRecord{preview()},
	}
	listed := func(state *DropTableState) []string {
		labels := []string{}
		for _, status := range DropStatuses(state, now, settings).Drops {
			labels = append(labels, string(bytes.TrimRight(status.DropId, " ")))
		}
		return labels
	}
	same := func(step string) {
		t.Helper()
		if !proto.Equal(DropStatuses(held, now, settings), DropStatuses(twin, now, settings)) {
			t.Fatalf("%s: the held table lists %v, its twin %v", step, listed(held), listed(twin))
		}
		if got, want := listed(held), dropTestLabels(twin); !slices.Equal(got, want) {
			t.Fatalf("%s: the held table lists %v, its twin keeps %v", step, got, want)
		}
		if held.AdmitsDrop(settings) != twin.AdmitsDrop(settings) {
			t.Fatalf("%s: the held table admits a DROP %t, its twin %t", step, held.AdmitsDrop(settings), twin.AdmitsDrop(settings))
		}
	}
	same("at the bound")

	// each DROP the repo makes takes the next entry the twin's bound evicts, oldest first: a, b, c and d, the held
	// ones unlisted in their twins' place
	for i, label := range []string{"e", "f", "g", "h"} {
		pending := &DropTableEntry{DropId: testId(label), Place: place, State: DropStatePending, SeenMs: now.UnixMilli()}
		var heldErr, twinErr error
		held, heldErr = dropTestWrite(held, now, settings, func(state *DropTableState) {
			copied := *pending
			state.Drops = append(state.Drops, &copied)
		})
		twin, twinErr = dropTestWrite(twin, now, settings, func(state *DropTableState) {
			copied := *pending
			state.Drops = append(state.Drops, &copied)
		})
		if heldErr != nil || twinErr != nil {
			t.Fatalf("DROP %s: %v, its twin %v", label, heldErr, twinErr)
		}
		same("DROP " + label)
		gone := []string{"a", "b", "c", "d"}[i]
		if twin.Drop(testId(gone)) != nil {
			t.Fatalf("DROP %s: the twin kept %s", label, gone)
		}
	}
	for _, label := range []string{"a", "c"} {
		if entry := held.Drop(testId(label)); entry == nil || entry.State != DropStateHeld || entry.EndedDay != dropUnlistedDay {
			t.Fatalf("held %s past the bound: %+v", label, entry)
		}
	}
	if held.Drop(testId("b")) != nil || held.Drop(testId("d")) != nil {
		t.Fatal("the held table kept a done entry its twin evicted")
	}

	// the next DROP finds four pending entries: both take the dry run and still pass the bound, so both refuse
	pending := &DropTableEntry{DropId: testId("i"), Place: place, State: DropStatePending, SeenMs: now.UnixMilli()}
	_, heldErr := dropTestWrite(held, now, settings, func(state *DropTableState) { state.Drops = append(state.Drops, pending) })
	_, twinErr := dropTestWrite(twin, now, settings, func(state *DropTableState) { state.Drops = append(state.Drops, pending) })
	if !errors.Is(heldErr, ErrDropTableFull) || !errors.Is(twinErr, ErrDropTableFull) {
		t.Fatalf("a write past the bound of pending entries: %v, its twin %v", heldErr, twinErr)
	}

	// the hold ends: the job's end moves a and c to done, and that write evicts both, leaving the twin's table
	held, err := dropTestWrite(held, now, settings, func(state *DropTableState) {
		for _, entry := range state.Drops {
			if entry.State == DropStateHeld {
				state.setState(entry, DropStateDone, dropDay(now))
			}
		}
		state.Job = nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := dropTestLabels(held), dropTestLabels(twin); !slices.Equal(got, want) {
		t.Fatalf("after the job's end the table holds %v, its twin %v", got, want)
	}
	same("after the hold")
}

// QD-1126 and owner decision 643: a write that only held entries keep past the bound, their DROPs seen under
// EvictGuard ago so that no bound may take them, is not refused, where the twin, whose entries are done and whose job
// has ended, refuses: held entries and a held job's record never count toward a refusal. The held table lists the new
// DROP beside its held one.
func TestDropTableBoundNeverRefusesAWriteForHeldEntries(t *testing.T) {
	settings := DefaultDropSettings()
	settings.TableByteCount = dropTableHeaderByteCount + dropTableTrailerByteCount + 2*dropTableEntryByteCount
	settings.TableAdmitByteCount = settings.TableByteCount
	now := sidecartest.DefaultClockStart().Add(400 * 24 * time.Hour)
	place := &protocol.EvsPlace{Minute: 1, Length: 100}
	entry := func(label string, state DropState) *DropTableEntry {
		// its DROP seen two hours ago, inside the eviction guard
		entry := &DropTableEntry{DropId: testId(label), Place: place, State: state, SeenMs: now.Add(-2 * time.Hour).UnixMilli()}
		if state.Ended() {
			entry.EndedDay = dropDay(now)
		}
		return entry
	}
	held := &DropTableState{
		Job:   &DropJobRecord{JobId: testId("job"), Phase: protocol.EvsDropPhase_EVS_DROP_DELETE, Held: true},
		Drops: []*DropTableEntry{entry("x", DropStateHeld), entry("p1", DropStatePending), entry("p2", DropStatePending)},
	}
	twin := &DropTableState{Drops: []*DropTableEntry{entry("x", DropStateDone), entry("p1", DropStatePending), entry("p2", DropStatePending)}}
	if err := twin.evict(now, settings); !errors.Is(err, ErrDropTableFull) {
		t.Fatalf("the twin's write past its bound: %v", err)
	}
	if err := held.evict(now, settings); err != nil {
		t.Fatalf("a write only a held entry takes past the bound: %v", err)
	}
	if entry := held.Drop(testId("x")); entry == nil || entry.EndedDay == dropUnlistedDay {
		t.Fatalf("a held entry inside the eviction guard was unlisted: %+v", entry)
	}
	if listing := DropStatuses(held, now, settings); len(listing.Drops) != 3 {
		t.Fatalf("listed %d drops", len(listing.Drops))
	}
}

// A held drop reads done, its held bytes as freed, so no listing shows a hold (owner decision 184); it ends as a done
// one does, but its entry is not evictable, since the job resumes its deletions from it (owner decision 643).
func TestDropStateHeldReadsDone(t *testing.T) {
	heldStatus, heldReason := DropStateHeld.Status()
	doneStatus, doneReason := DropStateDone.Status()
	if heldStatus != doneStatus || heldReason != doneReason {
		t.Fatal("a held drop's status differs from a done one's")
	}
	if !DropStateHeld.Ended() || DropStateHeld.Void() || !DropStateHeld.Executed() {
		t.Fatal("a held drop does not end, leave and count as a done one")
	}
	if DropStateHeld.Evictable() || !DropStateDone.Evictable() || !DropStateCancelled.Evictable() || DropStatePending.Evictable() {
		t.Fatal("which ended entries the table may evict")
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
	file, err := DecodeDropFile(EncodeDropCoveredFile(repoId, jobId, covered, DropListedShape{}), repoId, jobId, DropFileSnap, 0)
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
