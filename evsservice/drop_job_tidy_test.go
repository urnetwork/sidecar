package evsservice

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

func TestDropJobRestartsBetweenHeldCheckpointAndParking(t *testing.T) {
	testDropJobRestartBeforeParking(t, false)
}

func TestDropJobObserveWorkerPreservesHeldCheckpointBeforeParking(t *testing.T) {
	testDropJobRestartBeforeParking(t, true)
}

// Stop after the physical deleter checkpointed held IDs but before the table
// CAS parked the job. The cursor points past every retained object.
func testDropJobRestartBeforeParking(t *testing.T, observe bool) {
	t.Helper()
	f := newDropJobFixture(t)
	hold := f.placeHold()
	f.deleter.held = true
	f.appendDrop("drop", f.world.clock.Now())
	f.ripen()
	f.stopAt = BarrierDropHeldBefore
	if _, err := f.job.Run(f.world.ctx, "meta-1", f.world.repoId); err == nil {
		t.Fatal("the stop before parking did not interrupt the job")
	}
	job := f.table().Job
	if job == nil || job.HeldByteCount == 0 || job.Cursor == (DropCursor{}) {
		t.Fatalf("no checkpoint before parking: %+v", job)
	}
	f.stopAt = ""
	f.job = f.newJob(testId("replacement before parking"))
	f.world.clock.AdvanceTo(time.UnixMilli(job.UntilMs).Add(f.job.settings.LeaseLapse))
	f.hddKnown()
	if observe {
		f.format2.mode = sidecar.Format2Observe
		f.job.deps.Deleter = nil
		if result := f.run(); result.Waiting != DropWaitUnanswered || f.table().Job == nil {
			t.Fatalf("the observe worker lost the active checkpoint: %+v", result)
		}
		f.format2.mode = sidecar.Format2On
		f.job.deps.Deleter = f.deleter
		f.advance(f.job.settings.PauseRetryInterval, 0)
	}
	if result := f.run(); result.Waiting != DropWaitHold || f.table().HeldJob(job.JobId) == nil {
		t.Fatalf("the retained objects lost their owner: %+v", result)
	}
	last := f.deleter.requests[len(f.deleter.requests)-1]
	if len(last.Candidates) != 3 {
		t.Fatalf("the checkpoint hid %d retained objects", 3-len(last.Candidates))
	}
	f.endHold(hold)
	f.deleter.held = false
	f.advance(f.job.settings.HorizonRetryInterval, 0)
	if result := f.run(); !result.Ended || f.entry("drop").State != DropStateDone {
		t.Fatalf("the released job did not finish: %+v", result)
	}
	for _, id := range []DropScanId{f.a, f.b, f.c} {
		if f.deleter.deleteCounts[id] != 1 {
			t.Fatalf("retained object deleted %d times", f.deleter.deleteCounts[id])
		}
	}
}

func TestLegacyHeldEntryWithIncompleteFilesProtectsItsFilesAndReads(t *testing.T) {
	fixture := newDropJobFixture(t)
	world := fixture.world
	fixture.placeHold()
	fixture.deleter.held = true
	fixture.appendDrop("legacy", world.clock.Now())
	fixture.ripen()
	fixture.run()
	jobId := fixture.table().HeldJobs[0].JobId
	segments, err := world.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	// The value an older worker could leave after it refused a resumed job.
	legacy, err := fixture.job.Table().Update(world.paidCtx, world.cluster, world.repoId, func(state *DropTableState, now time.Time) (bool, error) {
		state.HeldJobs = nil
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewDropIndex(nil, nil, nil).Withheld(world.ctx, segments, "meta-1", world.repoId, legacy.State, world.clock.Now())
	if !errors.Is(err, ErrDropJobState) {
		t.Fatalf("a content read accepted unknown held ownership: %v", err)
	}
	fixture.advance(fixture.job.settings.EndedRetention+48*time.Hour, 0)
	if _, err := fixture.job.Run(world.ctx, "meta-1", world.repoId); !errors.Is(err, ErrDropJobState) {
		t.Fatalf("the worker accepted unknown held ownership: %v", err)
	}
	if answers, err := fixture.files(jobId).Read(world.ctx, DropFileDel, 0); err != nil || answers == nil {
		t.Fatalf("the old job's retained evidence was lost: %v", err)
	}
}

func TestLegacyHeldEntryRecoversItsOwnerAndDeletesItsRetainedObjects(t *testing.T) {
	fixture := newDropJobFixture(t)
	world := fixture.world
	hold := fixture.placeHold()
	fixture.deleter.held = true
	fixture.appendDrop("legacy", world.clock.Now())
	fixture.ripen()
	fixture.run()
	jobId := fixture.table().HeldJobs[0].JobId
	files := fixture.files(jobId)
	// Production records both the del outcomes and the immutable held IDs.
	ids := []DropScanId{fixture.a, fixture.b, fixture.c}
	held, err := EncodeDropIdFile(DropFileHeld, world.repoId, jobId, 0, ids)
	if err != nil {
		t.Fatal(err)
	}
	if err := files.Put(world.ctx, DropFileHeld, 0, held); err != nil {
		t.Fatal(err)
	}
	var observed []*DropAnswer
	for _, id := range ids {
		observed = append(observed, &DropAnswer{DropScanId: id, Outcome: DropOutcomeObserved})
	}
	if err := files.Put(world.ctx, DropFileDel, 1, EncodeDropDelFile(world.repoId, jobId, 1, observed)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.job.Table().Update(world.paidCtx, world.cluster, world.repoId, func(state *DropTableState, now time.Time) (bool, error) {
		state.HeldJobs = nil
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	fixture.job = fixture.newJob(testId("recovery worker"))
	if result := fixture.run(); result.Waiting != DropWaitHold || fixture.table().HeldJob(jobId) == nil {
		t.Fatalf("legacy hold remained without its job: %+v", result)
	}
	fixture.endHold(hold)
	fixture.deleter.held = false
	fixture.advance(fixture.job.settings.HorizonRetryInterval, 0)
	result := fixture.run()
	entry := fixture.entry("legacy")
	if !result.Ended || entry.State != DropStateDone || entry.HeldByteCount != 300 || entry.FreedByteCount != 0 {
		t.Fatalf("recovered job: %+v, entry %+v", result, entry)
	}
	for _, id := range ids {
		if fixture.deleter.deleteCounts[id] != 1 {
			t.Fatalf("retained object was deleted %d times", fixture.deleter.deleteCounts[id])
		}
	}
}

// Owner decision 570 (QD-1021; §11.13's table row, §2.8's evs-28): an ended job's snap-0 stays past the 30 d its other
// files get, as its list files do, so `sidecarctl evs drop-reindex` can still read which drops the job covered. A job
// run to done leaves snap-0, a later round's snap, cand, mark and del; with a list file, a held file and a dry run's
// ask and res beside them, one second short of the retention every file stands, and at it only snap-0 and the list
// file do, each with the bytes it had, again a retention later.
func TestDropJobTidyKeepsSnapZeroAndTheListFilesPastTheRetention(t *testing.T) {
	fixture := newDropJobFixture(t)
	world := fixture.world
	fixture.appendDrop("drop-1", world.clock.Now())
	fixture.marker.marks = []DropScanId{fixture.b}
	fixture.ripen()
	if result := fixture.run(); !result.Ended || result.Moved[DropStateDone] != 1 {
		t.Fatalf("the run: %+v", result)
	}
	jobId := fixture.resolver.requests[0].JobId
	previewId := testId("preview-1")
	files := fixture.files(jobId)
	previewFiles := fixture.files(previewId)

	// what resolve's stand-in and this job's one round do not write: the listed index, a hold's ids and a dry run
	drop := fixture.entry("drop-1")
	listFiles, err := EncodeDropListFiles(world.repoId, jobId, []*dropListInput{{
		drop: &DropListDrop{DropId: drop.DropId, RefId: drop.RefId, Version: drop.Version, PushId: drop.PushId},
		rows: []*dropHit{{entrySha256: [32]byte{7}}},
	}}, DefaultDropSettings())
	if err != nil || len(listFiles) != 1 {
		t.Fatalf("%d list files: %v", len(listFiles), err)
	}
	if err := files.Put(world.ctx, DropFileList, 0, listFiles[0]); err != nil {
		t.Fatal(err)
	}
	held, err := EncodeDropIdFile(DropFileHeld, world.repoId, jobId, 0, []DropScanId{fixture.a})
	if err != nil {
		t.Fatal(err)
	}
	if err := files.Put(world.ctx, DropFileHeld, 0, held); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []DropFileKind{DropFileAsk, DropFileRes} {
		message, err := EncodeDropMessageFile(kind, world.repoId, previewId, []byte("a dry run's message"))
		if err != nil {
			t.Fatal(err)
		}
		if err := previewFiles.Put(world.ctx, kind, 0, message); err != nil {
			t.Fatal(err)
		}
	}

	segmentCluster, err := world.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	// every dropscan/ key of the repo, with its bytes as the fake store dumps them
	dropscan := func() map[string][]byte {
		t.Helper()
		prefix := segmentCluster.ClusterId() + "/" + dropscanKeyPrefix + sidecar.EvsKeyId(world.repoId) + "/"
		found := map[string][]byte{}
		for name, dumped := range world.host.Blobs.Dump() {
			if strings.HasPrefix(name, prefix) {
				found[name] = dumped
			}
		}
		return found
	}
	name := func(id sidecar.Id, kind DropFileKind, sequence uint32) string {
		return segmentCluster.ClusterId() + "/" + DropFileKey(world.repoId, id, kind, sequence)
	}
	before := dropscan()
	for _, want := range []string{
		name(jobId, DropFileSnap, 0), name(jobId, DropFileSnap, 1), name(jobId, DropFileCand, 0), name(jobId, DropFileMark, 0),
		name(jobId, DropFileDel, 0), name(jobId, DropFileList, 0), name(jobId, DropFileHeld, 0),
		name(previewId, DropFileAsk, 0), name(previewId, DropFileRes, 0),
	} {
		if _, ok := before[want]; !ok {
			t.Fatalf("the ended job left no %s, so this shows nothing of it; it left %v", want, slices.Sorted(maps.Keys(before)))
		}
	}

	// a second short of the retention, counted from the newest file: nothing goes
	world.clock.Advance(fixture.job.settings.EndedRetention - time.Second)
	fixture.run()
	if after := dropscan(); len(after) != len(before) {
		t.Fatalf("short of the retention %d of %d files stand", len(after), len(before))
	}

	// at it: every file but snap-0 and the list file goes, the dry run's too
	world.clock.Advance(time.Second)
	fixture.run()
	wantKept := []string{name(jobId, DropFileList, 0), name(jobId, DropFileSnap, 0)}
	slices.Sort(wantKept)
	kept := dropscan()
	if got := slices.Sorted(maps.Keys(kept)); !slices.Equal(got, wantKept) {
		t.Fatalf("past the retention %v stand, want %v", got, wantKept)
	}
	for _, keptName := range wantKept {
		if string(kept[keptName]) != string(before[keptName]) {
			t.Fatalf("%s changed", keptName)
		}
	}
	snap, err := files.Read(world.ctx, DropFileSnap, 0)
	if err != nil || snap == nil || len(snap.Covered) != 1 || snap.Covered[0].DropId != drop.DropId || snap.Covered[0].RefId != drop.RefId ||
		snap.Covered[0].Version != drop.Version || snap.Covered[0].PushId != drop.PushId {
		t.Fatalf("snap-0 past the retention: %+v, %v", snap, err)
	}
	if round, err := files.Read(world.ctx, DropFileSnap, 1); err != nil || round != nil {
		t.Fatalf("a later round's snap past the retention: %+v, %v", round, err)
	}

	// and for the repo's life: another retention on, both stand
	world.clock.Advance(fixture.job.settings.EndedRetention)
	fixture.run()
	if got := slices.Sorted(maps.Keys(dropscan())); !slices.Equal(got, wantKept) {
		t.Fatalf("two retentions on %v stand, want %v", got, wantKept)
	}
}

// Nothing is deleted while the segment cluster has not passed the settle cases, the retention passed or not.
func TestDropJobTidyDeletesNothingOnAnUnsettledSegmentCluster(t *testing.T) {
	fixture := newDropJobFixture(t)
	world := fixture.world
	fixture.appendDrop("drop-1", world.clock.Now())
	fixture.ripen()
	if result := fixture.run(); !result.Ended {
		t.Fatalf("the run: %+v", result)
	}
	segmentCluster, err := world.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	before := len(world.host.Blobs.Dump())
	world.host.Blobs.SetSettlePassed(segmentCluster.ClusterId(), false)
	world.clock.Advance(2 * fixture.job.settings.EndedRetention)
	fixture.run()
	if after := len(world.host.Blobs.Dump()); after != before {
		t.Fatalf("an unsettled cluster holds %d objects, held %d", after, before)
	}
}
