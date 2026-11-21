package evsservice

// EVS2-M10-10's serving of listed versions (§11.9's reply, serve and dropped rows; FS-89's and FS-94's server clauses,
// FS-92 (c); DESIGN-DETAILS 10.6's read_drop_test.go and read_elide_test.go rows): a listed version served with its
// content and drop_pending before not_before_ms, dropped from then on with its inline entry version withheld and its
// record's bytes zeroed at the same length, every other entry version keeping its hash; a cancel before not_before
// leaving it readable; the DROP's statement and body once a reply and no body the request holds; a version found by
// a list file after its table entry left and its DROP left the window, a void record outranking the row, and an
// unreadable list file failing the read 503; the job's held ids answering missing while still stored; and a repo with
// no drop paying one cached GET of its table and nothing more.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A read of x at version pinned at the head, the request's held_drops beside it.
func (self *dropTestFixture) readX(version uint64, heldDrops ...uint64) *readTestReply {
	self.t.Helper()
	return self.readXAt(version, 0, heldDrops...)
}

// A read of x at version, whose push committed at commitVersion (0 unknown), as a history walk names it.
func (self *dropTestFixture) readXAt(version uint64, commitVersion uint64, heldDrops ...uint64) *readTestReply {
	self.t.Helper()
	return self.read(self.token(self.check.signerId), &protocol.EvsReadRequest{
		RefId: self.check.refId.Bytes(), PinVersion: self.head().Version(),
		Paths: []*protocol.EvsReadPath{{
			TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: self.x.Components()}}, Version: version, CommitVersion: commitVersion,
		}},
		HeldDrops: heldDrops,
	})
}

// The one path of a reply.
func readTestOnePath(t *testing.T, reply *readTestReply) *protocol.EvsReadPathReply {
	t.Helper()
	if len(reply.paths) != 1 {
		t.Fatalf("%d paths in the reply", len(reply.paths))
	}
	return reply.paths[0]
}

// FS-89's server clauses: before not_before_ms a listed version is served with its content and drop_pending, its
// DROP's statement and body beside it; from not_before_ms it reads dropped, its inline entry version withheld; the
// kept head reads as itself.
func TestReadDropPendingThenDropped(t *testing.T) {
	fixture := newDropTestFixture(t, 3)
	plan, history := fixture.dropPlan(false, fixture.listedBelow(4))
	fixture.commitDrop(plan, 4)

	pending := readTestOnePath(t, fixture.readX(2))
	if pending.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_DROP_PENDING || pending.GetNotBeforeMs() != history.GetNotBeforeMs() ||
		!bytes.Equal(pending.GetDropId(), history.GetDropId()) {
		t.Fatalf("a pending drop's version reads %s, not_before %d", pending.GetState(), pending.GetNotBeforeMs())
	}
	if len(pending.GetVersion().GetEntryVersion()) == 0 {
		t.Fatal("a pending drop's version was served without its content")
	}
	if len(pending.GetDropStatement()) == 0 || !bytes.Equal(pending.GetDropBody(), plan.DropBody) {
		t.Fatal("the reply lacks the DROP's statement or body")
	}

	fixture.clockTo(time.UnixMilli(history.GetNotBeforeMs()))
	dropped := readTestOnePath(t, fixture.readX(2))
	if dropped.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_DROPPED || dropped.GetDropVersion() != 4 {
		t.Fatalf("past not_before a listed version reads %s at %d", dropped.GetState(), dropped.GetDropVersion())
	}
	if dropped.GetVersion() == nil || len(dropped.GetVersion().GetEntryVersion()) != 0 {
		t.Fatal("a dropped version's inline entry version was served")
	}
	if kept := readTestOnePath(t, fixture.readX(4)); kept.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED || len(kept.GetVersion().GetEntryVersion()) == 0 {
		t.Fatalf("the kept head reads %s", kept.GetState())
	}
}

// A cancel committed before not_before_ms leaves the listed versions readable as any older version, past not_before_ms
// too.
func TestReadDropCancelledLeavesItReadable(t *testing.T) {
	fixture := newDropTestFixture(t, 2)
	plan, history := fixture.dropPlan(false, fixture.listedBelow(3))
	fixture.commitDrop(plan, 3)
	fixture.requireCommitted(fixture.postDrop(fixture.cancelPlan(history.GetDropId(), 3)), 4)
	fixture.awaitStepEights()
	fixture.clockTo(time.UnixMilli(history.GetNotBeforeMs()).Add(time.Hour))
	read := readTestOnePath(t, fixture.readX(1))
	if read.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED || len(read.GetVersion().GetEntryVersion()) == 0 {
		t.Fatalf("a cancelled drop's version reads %s", read.GetState())
	}
}

// A cancel committed before not_before_ms whose table append was lost: the window's cancel leaves the versions
// readable all the same, and the read makes the lost append again.
func TestReadDropCancelInTheWindowTheTableLacks(t *testing.T) {
	fixture := newDropTestFixture(t, 2)
	sink := &dropTestSink{next: fixture.engine.drops}
	fixture.engine.deps.Drops = sink
	plan, history := fixture.dropPlan(false, fixture.listedBelow(3))
	fixture.commitDrop(plan, 3)
	sink.stateLock.Lock()
	sink.failing = true
	sink.stateLock.Unlock()
	fixture.requireCommitted(fixture.postDrop(fixture.cancelPlan(history.GetDropId(), 3)), 4)
	fixture.awaitStepEights()
	if entry := fixture.table().Drop(sidecar.Id(history.GetDropId())); entry == nil || entry.State != DropStatePending {
		t.Fatalf("a lost cancel append left %+v", entry)
	}
	sink.stateLock.Lock()
	sink.failing = false
	sink.stateLock.Unlock()
	if err := fixture.host.Redis.Delete(fixture.ctx, []string{HeadCacheKey(fixture.check.repoId)}); err != nil {
		t.Fatal(err)
	}
	fixture.engine.dropIndex = NewDropIndex(fixture.settings.Drop, fixture.engine.records, fixture.engine.locator)
	read := fixture.read(fixture.token(fixture.check.signerId), &protocol.EvsReadRequest{
		RefId: fixture.check.refId.Bytes(), PinVersion: fixture.head().Version(), Fresh: true,
		Paths: []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: fixture.x.Components()}}, Version: 1}},
	})
	if path := readTestOnePath(t, read); path.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
		t.Fatalf("a version a window cancel freed reads %s", path.GetState())
	}
	fixture.awaitStepEights()
	if entry := fixture.table().Drop(sidecar.Id(history.GetDropId())); entry == nil || entry.State != DropStateCancelled {
		t.Fatalf("the read did not make the lost cancel's append again: %+v", entry)
	}
}

// The DROP's statement and body go once a reply, on its first path naming the drop, and no body goes for a DROP
// version the request's held_drops names.
func TestReadDropBodyOnceAndHeld(t *testing.T) {
	fixture := newDropTestFixture(t, 3)
	plan, _ := fixture.dropPlan(false, fixture.listedBelow(4))
	fixture.commitDrop(plan, 4)
	reply := fixture.read(fixture.token(fixture.check.signerId), &protocol.EvsReadRequest{
		RefId: fixture.check.refId.Bytes(), PinVersion: 4,
		Paths: []*protocol.EvsReadPath{
			{TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: fixture.x.Components()}}, Version: 1},
			{TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: fixture.x.Components()}}, Version: 2},
		},
	})
	if len(reply.paths) != 2 || len(reply.paths[0].GetDropBody()) == 0 || len(reply.paths[1].GetDropBody()) != 0 ||
		len(reply.paths[0].GetDropStatement()) == 0 || len(reply.paths[1].GetDropStatement()) != 0 {
		t.Fatal("the DROP's statement and body did not go once, on the first path")
	}
	held := readTestOnePath(t, fixture.readX(2, 4))
	if held.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_DROP_PENDING || len(held.GetDropBody()) != 0 {
		t.Fatal("a body the request holds went again, or the state went missing")
	}
}

// FS-94's lasting clause: once the DROP has left the window and its table entry has left, a list file finds the
// listed version, which reads dropped; a void record outranks the row; an unreadable list file fails the read 503.
func TestReadDropFoundByListFileAfterItsEntryLeft(t *testing.T) {
	fixture := newDropTestFixture(t, 3)
	plan, history := fixture.dropPlan(true, fixture.listedBelow(4))
	fixture.commitDrop(plan, 4)
	dropId := sidecar.Id(history.GetDropId())
	for filler := 0; EvsHeadWindowFirstVersion(fixture.head().Head) <= 4; filler += 1 {
		next := fixture.plan()
		fixture.create(next, fmt.Sprintf("f%04d", filler))
		fixture.requireCommitted(fixture.push(next), next.BaseVersion+1)
	}
	fixture.awaitStepEights()
	updateTable := func(decide func(state *DropTableState)) {
		if _, err := fixture.engine.drops.Update(fixture.paidContext(), fixture.cluster, fixture.check.repoId, func(state *DropTableState, now time.Time) (bool, error) {
			decide(state)
			return true, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	updateTable(func(state *DropTableState) { state.Drops = nil })
	segmentCluster, err := fixture.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	jobId := testId("list job")
	rows := []DropListRow{}
	for version := uint64(1); version < 4; version += 1 {
		rows = append(rows, DropListRow{EntrySha256: [32]byte(fixture.hashes[version]), Inline: true})
	}
	sortDropListRows(rows)
	drops := []*DropListDrop{{DropId: dropId, RefId: fixture.check.refId, Version: 4, PushId: plan.PushId}}
	listKey := DropFileKey(fixture.check.repoId, jobId, DropFileList, 0)
	if _, err := segmentCluster.PutIfNoneMatch(fixture.ctx, listKey, EncodeDropListFile(fixture.check.repoId, jobId, 0, drops, rows), nil); err != nil {
		t.Fatal(err)
	}
	fixture.engine.dropIndex = NewDropIndex(fixture.settings.Drop, fixture.engine.records, fixture.engine.locator)

	// the DROP's fold left x's entry holding its kept head alone, so the walk names version 2's commit
	found := readTestOnePath(t, fixture.readXAt(2, 2))
	if found.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_DROPPED || found.GetDropVersion() != 4 || len(found.GetVersion().GetEntryVersion()) != 0 {
		t.Fatalf("a version only a list file lists reads %s at %d", found.GetState(), found.GetDropVersion())
	}

	// a void record outranks the row
	updateTable(func(state *DropTableState) {
		state.Voids = append(state.Voids, &DropVoidRecord{DropId: dropId, State: DropStateRefusedMismatch})
	})
	fixture.engine.dropIndex = NewDropIndex(fixture.settings.Drop, fixture.engine.records, fixture.engine.locator)
	if read := readTestOnePath(t, fixture.readXAt(2, 2)); read.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED {
		t.Fatalf("a refused drop's row made a version read %s", read.GetState())
	}

	// an unreadable list file: 503, nothing served it could not clear
	updateTable(func(state *DropTableState) { state.Voids = nil })
	if err := segmentCluster.Delete(fixture.ctx, listKey); err != nil {
		t.Fatal(err)
	}
	if _, err := segmentCluster.PutIfNoneMatch(fixture.ctx, listKey, []byte("not a list file"), nil); err != nil {
		t.Fatal(err)
	}
	fixture.engine.dropIndex = NewDropIndex(fixture.settings.Drop, fixture.engine.records, fixture.engine.locator)
	recorder := fixture.call(fixture.token(fixture.check.signerId), http.MethodPost, "/read", &protocol.EvsReadRequest{
		RefId: fixture.check.refId.Bytes(), PinVersion: fixture.head().Version(),
		Paths: []*protocol.EvsReadPath{{TokenPaths: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: fixture.x.Components()}}, Version: 2, CommitVersion: 2}},
	})
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unreadable list file answered %d", recorder.Code)
	}
}

// Rows in a list file's order.
func sortDropListRows(rows []DropListRow) {
	for i := 1; i < len(rows); i += 1 {
		for j := i; 0 < j && 0 < compareDropListRows(rows[j-1], rows[j]); j -= 1 {
			rows[j-1], rows[j] = rows[j], rows[j-1]
		}
	}
}

// FS-94's record clause: a dropped version's inline-holding entry version goes as zeros of its length in its push's
// record, the record's other entry version keeping its hash; before not_before_ms the record goes as stored.
func TestReadElidesADroppedInlineRecord(t *testing.T) {
	fixture := newDropTestFixture(t, 1)
	// version 2 of the ref writes x's second version and creates z, both inline
	both := fixture.plan()
	xEntry := fixture.check.fileEntry(both, 2, []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("x two")}})
	both.Changes = append(both.Changes, &sidecar.EvsPlannedChange{TokenPath: fixture.x, BaseEntryVersion: 1, EntryVersion: xEntry})
	z := checkTestPath("z")
	zChange := fixture.check.change(both, z, 0, 2)
	both.Changes = append(both.Changes, zChange)
	fixture.requireCommitted(fixture.push(both), 2)
	fixture.awaitStepEights()
	xHash := sha256.Sum256(xEntry)
	fixture.newest, fixture.hashes[2] = 2, xHash[:]

	plan, history := fixture.dropPlan(false, fixture.listedBelow(3))
	fixture.commitDrop(plan, 3)
	readRecord := func() []byte {
		reply := fixture.read(fixture.token(fixture.check.signerId), &protocol.EvsReadRequest{
			RefId: fixture.check.refId.Bytes(), PinVersion: fixture.head().Version(),
			Pushes: []*protocol.EvsReadPush{{PushId: both.PushId.Bytes(), Version: 2}},
		})
		record := []byte{}
		for _, object := range reply.objects {
			record = append(record, object.GetBody()...)
		}
		return record
	}
	stored := readRecord()
	if !bytes.Contains(stored, xEntry) || !bytes.Contains(stored, zChange.EntryVersion) {
		t.Fatal("a pending drop's record did not go as stored")
	}
	fixture.clockTo(time.UnixMilli(history.GetNotBeforeMs()))
	elided := readRecord()
	if len(elided) != len(stored) {
		t.Fatalf("the elided record is %d bytes, the stored %d", len(elided), len(stored))
	}
	if bytes.Contains(elided, xEntry) || !bytes.Contains(elided, make([]byte, len(xEntry))) {
		t.Fatal("the dropped version's entry version was not zeroed")
	}
	if !bytes.Contains(elided, zChange.EntryVersion) {
		t.Fatal("the record's other entry version lost its bytes")
	}
}

// FS-92 (c) on the read side: a segment the job holds answers missing while it is still stored, as a deleted one
// does; one outside the set is served.
func TestReadWithholdsTheJobsHeldIds(t *testing.T) {
	fixture := newDropTestFixture(t, 1)
	plan, _ := fixture.dropPlan(false, fixture.listedBelow(2))
	fixture.commitDrop(plan, 2)
	segmentCluster, err := fixture.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	heldId := sha256.Sum256([]byte("a held segment"))
	freeId := sha256.Sum256([]byte("a free segment"))
	for _, segmentId := range [][32]byte{heldId, freeId} {
		if _, err := segmentCluster.PutIfNoneMatch(fixture.ctx, SegmentKey(fixture.check.repoId, segmentId), bytes.Repeat([]byte{1}, 4096), nil); err != nil {
			t.Fatal(err)
		}
	}
	jobId := testId("held job")
	read := func() *readTestReply {
		return fixture.read(fixture.token(fixture.check.signerId), &protocol.EvsReadRequest{
			RefId: fixture.check.refId.Bytes(),
			Ranges: []*protocol.EvsReadRange{
				{SegmentId: heldId[:], Length: 100},
				{SegmentId: freeId[:], Length: 100},
			},
		})
	}
	if reply := read(); len(reply.objects) != 2 || reply.objects[0].GetMissing() {
		t.Fatal("the segment was missing before the job started")
	}
	if _, err := fixture.engine.drops.Update(fixture.paidContext(), fixture.cluster, fixture.check.repoId, func(state *DropTableState, now time.Time) (bool, error) {
		state.Job = &DropJobRecord{JobId: jobId, Phase: protocol.EvsDropPhase_EVS_DROP_DELETE, StartedMs: now.UnixMilli()}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if reply := read(); len(reply.objects) != 2 || reply.objects[0].GetMissing() {
		t.Fatal("the segment was missing before the job withheld it")
	}
	heldFile, err := EncodeDropIdFile(DropFileHeld, fixture.check.repoId, jobId, 0, []DropScanId{DropSegmentId(heldId)})
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDropFiles(segmentCluster, fixture.check.repoId, jobId, fixture.settings.Drop).Put(fixture.ctx, DropFileHeld, 0, heldFile); err != nil {
		t.Fatal(err)
	}
	if reply := read(); len(reply.objects) != 2 || !reply.objects[0].GetMissing() || reply.objects[1].GetMissing() {
		t.Fatal("the warm reader missed a published held file before the table checkpoint")
	}
	if _, err := fixture.engine.drops.Update(fixture.paidContext(), fixture.cluster, fixture.check.repoId, func(state *DropTableState, now time.Time) (bool, error) {
		// a held job's record sits among the held jobs, out of the slot (QD-1127)
		state.Job.Held = true
		state.HeldJobs = append(state.HeldJobs, state.Job)
		state.Job = nil
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	reply := read()
	missing := map[string]bool{}
	served := map[string]bool{}
	for _, object := range reply.objects {
		if object.GetMissing() {
			missing[string(object.GetId())] = true
		} else {
			served[string(object.GetId())] = true
		}
	}
	if !missing[string(heldId[:])] || served[string(heldId[:])] {
		t.Fatal("a held segment's bytes were served")
	}
	if !served[string(freeId[:])] {
		t.Fatal("a segment outside the set was withheld")
	}
}

// A repo that never had a drop reads its table once, cached, and lists no dropscan/: an older version's read costs it
// nothing more.
func TestReadNoDropReadsNoDropState(t *testing.T) {
	fixture := newDropTestFixture(t, 2)
	lists := fixture.host.Blobs.RequestCount("seg-1", sidecartest.FaultOpList)
	read := readTestOnePath(t, fixture.readX(1))
	if read.GetState() != protocol.EvsReadPathState_EVS_READ_PATH_STATE_UNSPECIFIED || len(read.GetVersion().GetEntryVersion()) == 0 {
		t.Fatalf("a repo with no drop answered %s", read.GetState())
	}
	gets := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet)
	readTestOnePath(t, fixture.readX(1))
	if after := fixture.host.Blobs.RequestCount("seg-1", sidecartest.FaultOpList); after != lists {
		t.Fatalf("a repo with no drop listed dropscan/ %d times", after-lists)
	}
	again := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet) - gets
	readTestOnePath(t, fixture.readX(1))
	if third := fixture.host.Blobs.RequestCount("meta-1", sidecartest.FaultOpGet) - gets - again; third != again {
		t.Fatalf("a read within the table's cache paid %d GETs, the one before %d", third, again)
	}
}
