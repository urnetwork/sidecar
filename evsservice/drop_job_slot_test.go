package evsservice

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A network hold over the fixture's repo, 90 days from now, as api places a §2703(f) order.
func (self *dropJobFixture) placeHold() *sidecar.HoldRecord {
	world := self.world
	hold := &sidecar.HoldRecord{
		NetworkId: testId("network-a"), CaseId: testId("case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: world.clock.Now(), ExpireTime: world.clock.Now().Add(90 * 24 * time.Hour),
	}
	if err := sidecartest.PlaceHold(world.paidCtx, world.host.Blobs, hold); err != nil {
		self.t.Fatal(err)
	}
	return hold
}

// Ends hold, as api's pass does once it expires.
func (self *dropJobFixture) endHold(hold *sidecar.HoldRecord) {
	if err := sidecartest.RemoveHold(self.world.paidCtx, self.world.host.Blobs, hold.NetworkId, hold.CaseId); err != nil {
		self.t.Fatal(err)
	}
}

// Moves the clock by advance, the horizon to now less behind, and keeps the HDD figures known.
func (self *dropJobFixture) advance(advance time.Duration, behind time.Duration) {
	self.world.clock.Advance(advance)
	self.horizon.horizon = self.world.clock.Now().Add(-behind)
	self.hddKnown()
}

// Gives each job's resolve candidates of its own, as drops of different content have: the first job a, b and c, each
// later one three segments no other job lists.
func (self *dropJobFixture) ownCandidates(jobCount int) {
	self.resolver.nextCandidates = [][]DropScanId{{self.a, self.b, self.c}}
	for i := 1; i < jobCount; i += 1 {
		self.resolver.nextCandidates = append(self.resolver.nextCandidates, []DropScanId{
			DropSegmentId([32]byte{byte(16 * i), 1}), DropSegmentId([32]byte{byte(16 * i), 2}), DropSegmentId([32]byte{byte(16 * i), 3}),
		})
	}
}

// One run that must fail, as a kill at fixture.stopAt makes it.
func (self *dropJobFixture) runKilled(job *DropJob) {
	self.t.Helper()
	if _, err := job.Run(self.world.ctx, "meta-1", self.world.repoId); err == nil {
		self.t.Fatalf("the kill at %s did not stop the run", self.stopAt)
	}
	self.stopAt = ""
}

// The job ids the deletes were asked about, in order.
func (self *fakeDropDeleter) jobIds() []sidecar.Id {
	jobIds := []sidecar.Id{}
	for _, request := range self.requests {
		jobIds = append(jobIds, request.JobId)
	}
	return jobIds
}

func TestResumedDropRetainsItsJobWhenScansDisagree(t *testing.T) {
	testResumedDropRetainsItsJobUntilPhysicalDeletion(t, DropVerifyResult{Disagree: true}, sidecar.Format2On)
}

func TestResumedDropRetainsItsJobWhenLocked(t *testing.T) {
	testResumedDropRetainsItsJobUntilPhysicalDeletion(t, DropVerifyResult{Locked: true}, sidecar.Format2On)
}

func TestResumedDropRetainsItsJobInObserveMode(t *testing.T) {
	testResumedDropRetainsItsJobUntilPhysicalDeletion(t, DropVerifyResult{}, sidecar.Format2Observe)
}

// Restart a held job while deletion is blocked, then clear the block and account for its bytes.
func testResumedDropRetainsItsJobUntilPhysicalDeletion(t *testing.T, verification DropVerifyResult, mode sidecar.Format2Mode) {
	fixture := newDropJobFixture(t)
	world := fixture.world
	hold := fixture.placeHold()
	fixture.deleter.held = true
	fixture.appendDrop("drop", world.clock.Now())
	fixture.ripen()
	fixture.run()
	jobId := fixture.table().HeldJobs[0].JobId
	fixture.endHold(hold)
	fixture.deleter.held = false
	fixture.advance(fixture.job.settings.HorizonRetryInterval, 0)
	fixture.verifier.result = func(request *DropVerifyRequest) *DropVerifyResult {
		result := verification
		result.Snapshot = request.Marked
		return &result
	}
	fixture.format2.mode = mode
	fixture.stopAt = BarrierDropHeldAfter
	fixture.runKilled(fixture.job)
	fixture.job = fixture.newJob(testId("restarted"))
	table := fixture.table()
	if table.Job != nil || table.HeldJob(jobId) == nil || table.Drop(testId("drop")).State != DropStateHeld {
		t.Fatalf("lost held drop after restart: %+v", table)
	}
	cluster, err := world.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	withheld, err := NewDropIndex(nil, nil, nil).Withheld(world.ctx, cluster, "meta-1", world.repoId, table, world.clock.Now())
	if err != nil || !withheld[fixture.a] || len(fixture.deleter.requests) != 1 {
		t.Fatalf("after failed resume: withheld %v, deletes %d, error %v", withheld, len(fixture.deleter.requests), err)
	}
	if result := fixture.run(); !world.clock.Now().Before(result.Next) {
		t.Fatalf("blocked job ran without waiting: %+v", result)
	}
	fixture.format2.mode = sidecar.Format2On
	fixture.verifier.result = nil
	fixture.advance(fixture.job.settings.HorizonRetryInterval, 0)
	result := fixture.run()
	entry := fixture.entry("drop")
	if !result.Ended || entry.State != DropStateDone || fixture.deleter.deleteCounts[fixture.a] != 1 ||
		len(fixture.table().JobIds()) != 0 || entry.FreedByteCount+entry.HeldByteCount != 300 {
		t.Fatalf("after deletion: result %+v, entry %+v, deletions %v", result, entry, fixture.deleter.deleteCounts)
	}
}

// QD-1127, the probe of question held-drop-entry-kept-later-drops-wait-behind-a-held-job, beside a twin that places no
// hold: a hold covers the repo, drop-1's job moves it to held, and drop-2 is appended. The held job gave up the slot,
// so drop-2's job starts as the twin's does, reads executing while it waits for the horizon, and once its round's
// deletes meet the hold moves its candidates to held, so it reads done with its bytes off the count once, as the
// twin's done drop-2. The listing and the admission line equal the twin's at every step, the line tight enough that a
// drop-2 left pending would differ. At the hold's end each held job takes the slot back in turn, oldest first, and its
// round deletes what it held, reporting no byte again; the listing still equals the twin's.
func TestDropJobHeldJobGivesUpTheSlot(t *testing.T) {
	held, twin := newDropJobFixture(t), newDropJobFixture(t)
	settings := DefaultDropSettings()
	// one counted record in all: a DROP is taken only while no other drop is pending, executing or observed
	tight := DefaultDropSettings()
	tight.TableAdmitByteCount = dropTableEntryByteCount
	both := func(step func(fixture *dropJobFixture)) {
		step(held)
		step(twin)
	}
	same := func(name string) {
		t.Helper()
		heldTable, twinTable := held.table(), twin.table()
		now := held.world.clock.Now()
		if !proto.Equal(DropStatuses(heldTable, now, settings), DropStatuses(twinTable, now, settings)) {
			t.Fatalf("%s: the held world lists %v, its twin %v", name, DropStatuses(heldTable, now, settings), DropStatuses(twinTable, now, settings))
		}
		if heldTable.AdmitsDrop(tight) != twinTable.AdmitsDrop(tight) {
			t.Fatalf("%s: the held world admits a DROP %t, its twin %t", name, heldTable.AdmitsDrop(tight), twinTable.AdmitsDrop(tight))
		}
	}
	held.ownCandidates(2)
	twin.ownCandidates(2)
	hold := held.placeHold()
	held.deleter.held = true

	both(func(fixture *dropJobFixture) {
		fixture.appendDrop("drop-1", fixture.world.clock.Now())
		fixture.ripen()
		fixture.run()
	})
	table := held.table()
	if table.Job != nil || len(table.HeldJobs) != 1 || table.Drop(testId("drop-1")).State != DropStateHeld {
		t.Fatalf("drop-1's job did not give up the slot: %+v, %d held", table.Job, len(table.HeldJobs))
	}
	jobOne := table.HeldJobs[0].JobId
	same("drop-1 ended")

	// drop-2, made during the hold, starts and waits for the horizon to pass its cite bound: executing
	both(func(fixture *dropJobFixture) {
		fixture.appendDrop("drop-2", fixture.world.clock.Now())
		fixture.advance(26*time.Minute, time.Hour)
	})
	if held.table().AdmitsDrop(tight) || twin.table().AdmitsDrop(tight) {
		t.Fatal("drop-2 pending kept no DROP out")
	}
	both(func(fixture *dropJobFixture) {
		if result := fixture.run(); result.Waiting != DropWaitHorizon {
			t.Fatalf("drop-2's start: %+v", result)
		}
	})
	table = held.table()
	entry := table.Drop(testId("drop-2"))
	if table.Job == nil || table.Job.JobId == jobOne || entry.State != DropStateExecuting || entry.Phase != protocol.EvsDropPhase_EVS_DROP_HORIZON {
		t.Fatalf("drop-2 under the hold: %+v in the slot, drop-2 %+v", table.Job, entry)
	}
	if len(table.HeldJobs) != 1 || table.HeldJobs[0].JobId != jobOne || table.Drop(testId("drop-1")).State != DropStateHeld {
		t.Fatal("drop-2's job moved the held job")
	}
	jobTwo := table.Job.JobId
	same("drop-2 executing")

	// its round: the twin deletes, the held world's deletes meet the hold
	both(func(fixture *dropJobFixture) {
		fixture.world.clock.AdvanceTo(time.UnixMilli(fixture.table().Job.RetryMs))
		fixture.advance(0, 0)
		fixture.run()
	})
	table = held.table()
	entry = table.Drop(testId("drop-2"))
	if table.Job != nil || len(table.HeldJobs) != 2 || table.HeldJobs[0].JobId != jobOne || table.HeldJobs[1].JobId != jobTwo {
		t.Fatalf("drop-2's job under the hold: %+v in the slot, %d held", table.Job, len(table.HeldJobs))
	}
	if entry.State != DropStateHeld || entry.FreedByteCount != 0 || entry.HeldByteCount != 300 {
		t.Fatalf("drop-2 held: %+v", entry)
	}
	if twinEntry := twin.entry("drop-2"); twinEntry.State != DropStateDone || twinEntry.FreedByteCount != 300 {
		t.Fatalf("the twin's drop-2: %+v", twinEntry)
	}
	same("drop-2 ended")

	// while the hold stands each held job waits, writing its wake and deleting nothing
	held.deleter.held = false
	held.advance(11*time.Minute, 0)
	twin.advance(11*time.Minute, 0)
	deletesBefore := len(held.deleter.requests)
	if result := held.run(); result.Waiting != DropWaitHold || len(held.deleter.requests) != deletesBefore || result.Next.IsZero() {
		t.Fatalf("a run under the hold: %+v", result)
	}
	for _, job := range held.table().HeldJobs {
		if !held.world.clock.Now().Before(time.UnixMilli(job.RetryMs)) {
			t.Fatal("a held job's wake did not move on")
		}
	}

	// the hold ends: drop-1's job takes the slot back first, then drop-2's, each deleting what it held
	held.endHold(hold)
	held.advance(11*time.Minute, 0)
	twin.advance(11*time.Minute, 0)
	result := held.run()
	table = held.table()
	if !result.Ended || result.Moved[DropStateDone] != 1 || table.Drop(testId("drop-1")).State != DropStateDone || table.Drop(testId("drop-2")).State != DropStateHeld {
		t.Fatalf("the first run after the hold: %+v", result)
	}
	if len(table.HeldJobs) != 1 || table.HeldJobs[0].JobId != jobTwo || table.Job != nil || held.world.clock.Now().Before(result.Next) {
		t.Fatalf("after drop-1's job: the slot %+v, %d held, asking again at %s", table.Job, len(table.HeldJobs), result.Next)
	}
	result = held.run()
	table = held.table()
	if !result.Ended || table.Drop(testId("drop-2")).State != DropStateDone || len(table.HeldJobs) != 0 || table.Job != nil {
		t.Fatalf("the second run after the hold: %+v", result)
	}
	jobIds := held.deleter.jobIds()
	if len(jobIds) != 4 || jobIds[2] != jobOne || jobIds[3] != jobTwo {
		t.Fatalf("the deletes ran for %v", jobIds)
	}
	for _, request := range held.deleter.requests[2:] {
		if len(request.Candidates) != 3 {
			t.Fatalf("a round after the hold took %d of its 3 held ids", len(request.Candidates))
		}
	}
	for _, label := range []string{"drop-1", "drop-2"} {
		if entry := held.entry(label); entry.FreedByteCount+entry.HeldByteCount != 300 {
			t.Fatalf("%s's bytes after the hold: %+v", label, entry)
		}
	}
	same("after the hold")
	if result := held.run(); result.Ended || len(held.deleter.requests) != 4 {
		t.Fatalf("a run with nothing left: %+v", result)
	}
}

// QD-1127: a job that runs while another is held ends with only its own drops. Under a hold its deletes do not meet
// (the deletes' answer, not the job's, decides), drop-2's job deletes and ends done while drop-1 stays held and its
// job stays among the held ones; a later job whose every drop verify finds cancelled ends there, though a held entry
// of another job stands. Its end moves nothing of the held job's.
func TestDropJobEndsWithItsOwnDropsBesideAHeldJob(t *testing.T) {
	fixture := newDropJobFixture(t)
	fixture.ownCandidates(3)
	hold := fixture.placeHold()
	fixture.deleter.held = true
	fixture.appendDrop("drop-1", fixture.world.clock.Now())
	fixture.ripen()
	fixture.run()
	jobOne := fixture.table().HeldJobs[0].JobId

	fixture.deleter.held = false
	fixture.appendDrop("drop-2", fixture.world.clock.Now())
	fixture.advance(26*time.Minute, 0)
	result := fixture.run()
	table := fixture.table()
	if !result.Ended || table.Drop(testId("drop-2")).State != DropStateDone || table.Drop(testId("drop-1")).State != DropStateHeld {
		t.Fatalf("drop-2's job beside a held one: %+v", result)
	}
	if table.Job != nil || len(table.HeldJobs) != 1 || table.HeldJobs[0].JobId != jobOne {
		t.Fatalf("drop-2's end took the held job: %+v in the slot, %d held", table.Job, len(table.HeldJobs))
	}

	fixture.verifier.result = func(request *DropVerifyRequest) *DropVerifyResult {
		cancelled := []sidecar.Id{}
		for _, drop := range request.Drops {
			cancelled = append(cancelled, drop.DropId)
		}
		return &DropVerifyResult{Snapshot: request.Marked, Cancelled: cancelled}
	}
	fixture.appendDrop("drop-3", fixture.world.clock.Now())
	fixture.advance(26*time.Minute, 0)
	result = fixture.run()
	table = fixture.table()
	if !result.Ended || table.Drop(testId("drop-3")).State != DropStateCancelled || table.Drop(testId("drop-1")).State != DropStateHeld {
		t.Fatalf("a job whose drops verify found cancelled: %+v", result)
	}
	if table.Job != nil || len(table.HeldJobs) != 1 || len(fixture.deleter.requests) != 2 {
		t.Fatalf("after drop-3: %+v in the slot, %d held, %d delete runs", table.Job, len(table.HeldJobs), len(fixture.deleter.requests))
	}

	// the held job still takes the slot back at the hold's end and ends drop-1 alone
	fixture.verifier.result = nil
	fixture.endHold(hold)
	fixture.advance(11*time.Minute, 0)
	if result := fixture.run(); !result.Ended || fixture.entry("drop-1").State != DropStateDone || len(fixture.table().HeldJobs) != 0 {
		t.Fatalf("the held job after the hold: %+v", result)
	}
}

// QD-1127's crashes, each a kill at a barrier and the next run, or another instance once the lease lapsed, going on
// from what the table holds: after the CAS that moved drop-1's job to held and gave up the slot; before and after the
// start CAS of drop-2's job, which takes the free slot; and before and after the CAS by which the held job, its hold
// ended, takes the slot back. Each drop ends done, each held id is deleted once, nothing runs twice.
func TestDropJobResumesACrashAtTheSlotsHandOver(t *testing.T) {
	fixture := newDropJobFixture(t)
	fixture.ownCandidates(2)
	hold := fixture.placeHold()
	fixture.deleter.held = true
	fixture.appendDrop("drop-1", fixture.world.clock.Now())
	fixture.ripen()
	fixture.stopAt = BarrierDropHeldAfter
	fixture.runKilled(fixture.job)
	table := fixture.table()
	if table.Job != nil || len(table.HeldJobs) != 1 || table.Drop(testId("drop-1")).State != DropStateHeld {
		t.Fatalf("killed after the move to held: %+v in the slot, %d held", table.Job, len(table.HeldJobs))
	}
	jobOne := table.HeldJobs[0].JobId

	// drop-2's start, killed before its CAS: nothing moved; then after it: the slot is drop-2's job's
	fixture.appendDrop("drop-2", fixture.world.clock.Now())
	fixture.advance(26*time.Minute, 0)
	fixture.stopAt = BarrierDropStartBefore
	fixture.runKilled(fixture.job)
	if table := fixture.table(); table.Job != nil || fixture.entry("drop-2").State != DropStatePending || len(table.HeldJobs) != 1 {
		t.Fatal("a start killed before its CAS moved the table")
	}
	fixture.stopAt = BarrierDropStartAfter
	fixture.runKilled(fixture.job)
	table = fixture.table()
	if table.Job == nil || table.Job.JobId == jobOne || fixture.entry("drop-2").State != DropStateExecuting || len(table.HeldJobs) != 1 {
		t.Fatalf("a start killed after its CAS: %+v in the slot", table.Job)
	}
	jobTwo := table.Job.JobId
	other := fixture.newJob(testId("instance-b"))
	if result, err := other.Run(fixture.world.ctx, "meta-1", fixture.world.repoId); err != nil || result.Waiting != DropWaitLease {
		t.Fatalf("another instance inside the lease: %+v %v", result, err)
	}
	fixture.world.clock.AdvanceTo(time.UnixMilli(table.Job.UntilMs).Add(30 * time.Second))
	fixture.advance(0, 0)
	if result, err := other.Run(fixture.world.ctx, "meta-1", fixture.world.repoId); err != nil || result.Waiting != DropWaitHold {
		t.Fatalf("drop-2's job resumed by another instance: %+v %v", result, err)
	}
	table = fixture.table()
	if table.Job != nil || len(table.HeldJobs) != 2 || table.HeldJobs[1].JobId != jobTwo || fixture.entry("drop-2").State != DropStateHeld {
		t.Fatalf("drop-2's job under the hold: %+v in the slot, %d held", table.Job, len(table.HeldJobs))
	}
	if resolves := fixture.events.count("resolve"); resolves != 2 {
		t.Fatalf("%d resolves for two jobs", resolves)
	}

	// the hold ends: the take killed before its CAS leaves the job held, after it leaves the slot the job's, which
	// another instance resumes once the lease lapsed, a round over what it held
	fixture.deleter.held = false
	fixture.endHold(hold)
	fixture.advance(11*time.Minute, 0)
	fixture.stopAt = BarrierDropTakeBefore
	fixture.runKilled(fixture.job)
	if table := fixture.table(); table.Job != nil || len(table.HeldJobs) != 2 {
		t.Fatal("a take killed before its CAS moved the table")
	}
	fixture.stopAt = BarrierDropTakeAfter
	fixture.runKilled(fixture.job)
	table = fixture.table()
	if table.Job == nil || table.Job.JobId != jobOne || !table.Job.Resumed || table.Job.Held || len(table.HeldJobs) != 1 ||
		table.Job.Phase != protocol.EvsDropPhase_EVS_DROP_HORIZON || table.Job.Owner != testId("instance-a") {
		t.Fatalf("a take killed after its CAS: %+v in the slot, %d held", table.Job, len(table.HeldJobs))
	}
	if fixture.entry("drop-1").State != DropStateHeld {
		t.Fatal("the take moved its held drop")
	}
	// the resumed job's record counts toward the bound no more than the held one's, its twin long ended (QD-1126)
	if table.boundByteCount() != table.byteCount()-2*dropTableJobByteCount-2*dropTableEntryByteCount {
		t.Fatalf("a table of %d bytes counted %d", table.byteCount(), table.boundByteCount())
	}
	fixture.world.clock.AdvanceTo(time.UnixMilli(table.Job.UntilMs).Add(30 * time.Second))
	fixture.advance(0, 0)
	result, err := other.Run(fixture.world.ctx, "meta-1", fixture.world.repoId)
	if err != nil || !result.Ended || fixture.entry("drop-1").State != DropStateDone || fixture.entry("drop-2").State != DropStateHeld {
		t.Fatalf("the held job resumed by another instance: %+v %v", result, err)
	}
	result, err = other.Run(fixture.world.ctx, "meta-1", fixture.world.repoId)
	if err != nil || !result.Ended || fixture.entry("drop-2").State != DropStateDone {
		t.Fatalf("drop-2's held job after the hold: %+v %v", result, err)
	}
	table = fixture.table()
	if table.Job != nil || len(table.HeldJobs) != 0 {
		t.Fatalf("after both: %+v in the slot, %d held", table.Job, len(table.HeldJobs))
	}
	if jobIds := fixture.deleter.jobIds(); len(jobIds) != 4 || jobIds[2] != jobOne || jobIds[3] != jobTwo {
		t.Fatalf("the deletes ran for %v", jobIds)
	}
}

// QD-1127: a job's move to held hands the slot on at once. A drop made while drop-1's job waited for the horizon is
// startable when that job's deletes meet the hold, so the run asks to run again now, and the next run starts its job.
// Tidy keeps every held job's files as it keeps the running job's, however old.
func TestDropJobHeldMoveAsksForTheNextJob(t *testing.T) {
	fixture := newDropJobFixture(t)
	fixture.ownCandidates(2)
	fixture.placeHold()
	fixture.deleter.held = true
	seen := fixture.world.clock.Now()
	fixture.appendDrop("drop-1", seen)
	fixture.advance(26*time.Minute, time.Hour)
	if result := fixture.run(); result.Waiting != DropWaitHorizon {
		t.Fatalf("drop-1's job: %+v", result)
	}
	fixture.appendDrop("drop-2", fixture.world.clock.Now())
	fixture.world.clock.AdvanceTo(time.UnixMilli(fixture.table().Job.RetryMs))
	fixture.advance(0, 0)
	result := fixture.run()
	if result.Waiting != DropWaitHold || fixture.world.clock.Now().Before(result.Next) || fixture.entry("drop-2").State != DropStatePending {
		t.Fatalf("the move to held with drop-2 startable: %+v", result)
	}
	fixture.run()
	table := fixture.table()
	if len(table.HeldJobs) != 2 || fixture.entry("drop-2").State != DropStateHeld {
		t.Fatalf("drop-2's job: %d held, drop-2 %d", len(table.HeldJobs), fixture.entry("drop-2").State)
	}

	// 40 days on, both jobs' files stay: tidy keeps a held job's files as it keeps the running job's
	fixture.advance(40*24*time.Hour, 0)
	fixture.run()
	for _, job := range fixture.table().HeldJobs {
		file, err := fixture.files(job.JobId).Read(t.Context(), DropFileCand, 0)
		if err != nil || file == nil {
			t.Fatalf("held job %s's cand file after 40 days: %v", sidecar.EvsKeyId(job.JobId), err)
		}
	}
}

// QD-1127 on the read side: the withheld set is the union of the running job's ids and every held job's, so a held
// job out of the slot still withholds its held and deleted ids, and the set is read again once the jobs change.
func TestDropIndexWithholdsEveryHeldJobsIds(t *testing.T) {
	world := newDropTestWorld(t)
	index := NewDropIndex(nil, nil, nil)
	ids := map[string]DropScanId{}
	for _, label := range []string{"running-held", "held-a-deleted", "held-a-held", "held-b-packed", "held-b-file", "young", "later"} {
		ids[label] = DropSegmentId([32]byte([]byte(label + "................................")[:32]))
	}
	put := func(jobLabel string, answers []*DropAnswer, heldIds []DropScanId) {
		files := NewDropFiles(world.segmentCluster, world.repoId, testId(jobLabel), DefaultDropSettings())
		if err := files.Put(world.ctx, DropFileDel, 0, EncodeDropDelFile(world.repoId, testId(jobLabel), 0, answers)); err != nil {
			t.Fatal(err)
		}
		if len(heldIds) == 0 {
			return
		}
		encoded, err := EncodeDropIdFile(DropFileHeld, world.repoId, testId(jobLabel), 0, heldIds)
		if err != nil {
			t.Fatal(err)
		}
		if err := files.Put(world.ctx, DropFileHeld, 0, encoded); err != nil {
			t.Fatal(err)
		}
	}
	put("running", []*DropAnswer{{DropScanId: ids["running-held"], Outcome: DropOutcomeHeld}, {DropScanId: ids["young"], Outcome: DropOutcomeYoung}}, nil)
	put("held-a", []*DropAnswer{{DropScanId: ids["held-a-deleted"], Outcome: DropOutcomeDeleted}, {DropScanId: ids["held-a-held"], Outcome: DropOutcomeHeld}}, nil)
	put("held-b", []*DropAnswer{{DropScanId: ids["held-b-packed"], Outcome: DropOutcomePacked}}, []DropScanId{ids["held-b-file"]})
	heldJob := func(label string) *DropJobRecord {
		return &DropJobRecord{JobId: testId(label), Phase: protocol.EvsDropPhase_EVS_DROP_DELETE, Held: true}
	}
	state := &DropTableState{
		Job:      &DropJobRecord{JobId: testId("running"), Phase: protocol.EvsDropPhase_EVS_DROP_DELETE},
		HeldJobs: []*DropJobRecord{heldJob("held-a"), heldJob("held-b")},
	}
	now := world.clock.Now()
	withheld, err := index.Withheld(world.ctx, world.segmentCluster, "meta-1", world.repoId, state, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"running-held", "held-a-deleted", "held-a-held", "held-b-packed", "held-b-file"} {
		if !withheld[ids[label]] {
			t.Errorf("%s is served", label)
		}
	}
	if withheld[ids["young"]] || len(withheld) != 5 {
		t.Fatalf("%d ids withheld, the young one %t", len(withheld), withheld[ids["young"]])
	}

	// with no running job the held ones still withhold theirs; a held job's later file shows once the jobs change
	put("held-c", []*DropAnswer{{DropScanId: ids["later"], Outcome: DropOutcomeHeld}}, nil)
	state = &DropTableState{HeldJobs: []*DropJobRecord{heldJob("held-a"), heldJob("held-b"), heldJob("held-c")}}
	withheld, err = index.Withheld(world.ctx, world.segmentCluster, "meta-1", world.repoId, state, now)
	if err != nil {
		t.Fatal(err)
	}
	if withheld[ids["running-held"]] || !withheld[ids["held-a-held"]] || !withheld[ids["later"]] || len(withheld) != 5 {
		t.Fatalf("the held jobs alone withhold %d ids", len(withheld))
	}
	if withheld, err := index.Withheld(world.ctx, world.segmentCluster, "meta-1", world.repoId, &DropTableState{}, now); err != nil || withheld != nil {
		t.Fatalf("a table naming no job: %v %v", withheld, err)
	}
}

// A table naming held jobs and no running one, as it stands while a hold covers the repo, is written and read whole,
// and a later write that changes nothing of theirs, a DROP's append here, keeps them in the order they moved to held,
// which is the order they take the slot back in.
func TestDropTableKeepsTheHeldJobsOrder(t *testing.T) {
	world := newDropTestWorld(t)
	held := func(label string) *DropJobRecord {
		return &DropJobRecord{JobId: testId(label), Phase: protocol.EvsDropPhase_EVS_DROP_DELETE, Held: true}
	}
	if _, err := world.table.Update(world.paidCtx, world.cluster, world.repoId, func(state *DropTableState, now time.Time) (bool, error) {
		state.HeldJobs = []*DropJobRecord{held("first"), held("second"), held("third")}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := world.table.Append(world.paidCtx, world.dropCommit("drop-1", 3, world.clock.Now()), world.clock.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	state := world.read().State
	if state.Job != nil || len(state.HeldJobs) != 3 || len(state.Drops) != 1 {
		t.Fatalf("the table: %+v, %d held", state.Job, len(state.HeldJobs))
	}
	for i, label := range []string{"first", "second", "third"} {
		if state.HeldJobs[i].JobId != testId(label) {
			t.Fatalf("held job %d is not %s", i, label)
		}
	}
}

// QD-1127: once the holds have ended the oldest held job takes the slot back first, though only a newer one's
// retry_ms had come, and the held jobs behind it are due at once: its end asks to run again now, and the next run
// gives the slot to the next held job.
func TestDropJobHeldJobsTakeTheSlotBackOldestFirst(t *testing.T) {
	fixture := newDropJobFixture(t)
	fixture.ownCandidates(2)
	world := fixture.world
	hold := fixture.placeHold()
	fixture.deleter.held = true
	fixture.appendDrop("drop-1", world.clock.Now())
	fixture.ripen()
	fixture.run()
	fixture.appendDrop("drop-2", world.clock.Now())
	fixture.advance(26*time.Minute, 0)
	fixture.run()
	table := fixture.table()
	if len(table.HeldJobs) != 2 || table.Job != nil {
		t.Fatalf("two held jobs: %d held, %+v in the slot", len(table.HeldJobs), table.Job)
	}
	jobOne, jobTwo := table.HeldJobs[0].JobId, table.HeldJobs[1].JobId
	// only the newer one's wake has come
	if _, err := fixture.job.Table().Update(world.paidCtx, world.cluster, world.repoId, func(state *DropTableState, now time.Time) (bool, error) {
		state.HeldJobs[0].RetryMs = now.Add(30 * 24 * time.Hour).UnixMilli()
		state.HeldJobs[1].RetryMs = now.UnixMilli()
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	fixture.endHold(hold)
	fixture.deleter.held = false
	fixture.advance(time.Minute, 0)
	result := fixture.run()
	table = fixture.table()
	if !result.Ended || fixture.entry("drop-1").State != DropStateDone || fixture.entry("drop-2").State != DropStateHeld {
		t.Fatalf("the first run after the hold: %+v", result)
	}
	if len(table.HeldJobs) != 1 || table.HeldJobs[0].JobId != jobTwo || table.HeldJobs[0].RetryMs != 0 || !result.Next.Equal(world.clock.Now()) {
		t.Fatalf("behind the oldest: %d held, asking again at %s", len(table.HeldJobs), result.Next)
	}
	if jobIds := fixture.deleter.jobIds(); jobIds[len(jobIds)-1] != jobOne {
		t.Fatalf("the first round after the hold was %s's", sidecar.EvsKeyId(jobIds[len(jobIds)-1]))
	}
	result = fixture.run()
	table = fixture.table()
	if !result.Ended || fixture.entry("drop-2").State != DropStateDone || len(table.HeldJobs) != 0 || table.Job != nil {
		t.Fatalf("the second run after the hold: %+v", result)
	}
}

// QD-1127: two drops can list one segment, a copy's. A held job holds what it moved to held, its bytes off the stored
// count then, so a job that runs during the hold leaves that id to it: no id moves to held twice or counts twice, and
// the held job deletes it after its hold, as the twin's first job deleted it at once and its second found it absent.
// The listing equals the twin's throughout, and each id is deleted once.
func TestDropJobLeavesAHeldJobsIdsToIt(t *testing.T) {
	held, twin := newDropJobFixture(t), newDropJobFixture(t)
	settings := DefaultDropSettings()
	shared, own := held.c, DropSegmentId([32]byte{4})
	for _, fixture := range []*dropJobFixture{held, twin} {
		fixture.resolver.nextCandidates = [][]DropScanId{{fixture.a, fixture.b, shared}, {shared, own}}
	}
	both := func(step func(fixture *dropJobFixture)) {
		step(held)
		step(twin)
	}
	same := func(name string) {
		t.Helper()
		now := held.world.clock.Now()
		heldListing, twinListing := DropStatuses(held.table(), now, settings), DropStatuses(twin.table(), now, settings)
		if !proto.Equal(heldListing, twinListing) {
			t.Fatalf("%s: the held world lists %v, its twin %v", name, heldListing, twinListing)
		}
	}
	hold := held.placeHold()
	held.deleter.held = true
	both(func(fixture *dropJobFixture) {
		fixture.appendDrop("drop-1", fixture.world.clock.Now())
		fixture.ripen()
		fixture.run()
		fixture.appendDrop("drop-2", fixture.world.clock.Now())
		fixture.advance(26*time.Minute, 0)
		fixture.run()
	})
	request := held.deleter.requests[len(held.deleter.requests)-1]
	if len(request.Candidates) != 1 || request.Candidates[0].DropScanId != own {
		t.Fatalf("drop-2's deletes under the hold took %d candidates", len(request.Candidates))
	}
	if entry := held.entry("drop-2"); entry.State != DropStateHeld || entry.HeldByteCount != 100 || entry.FreedByteCount != 0 {
		t.Fatalf("drop-2 held: %+v", entry)
	}
	if entry := twin.entry("drop-2"); entry.State != DropStateDone || entry.FreedByteCount != 100 {
		t.Fatalf("the twin's drop-2: %+v", entry)
	}
	same("both ended")

	held.endHold(hold)
	held.deleter.held = false
	held.advance(11*time.Minute, 0)
	twin.advance(11*time.Minute, 0)
	for range 2 {
		if result := held.run(); !result.Ended {
			t.Fatalf("a run after the hold: %+v", result)
		}
	}
	if table := held.table(); len(table.HeldJobs) != 0 || table.Job != nil {
		t.Fatalf("after the hold: %d held, %+v in the slot", len(table.HeldJobs), table.Job)
	}
	same("after the hold")
	for _, fixture := range []*dropJobFixture{held, twin} {
		for _, scanId := range []DropScanId{fixture.a, fixture.b, shared, own} {
			if count := fixture.deleter.deleteCounts[scanId]; count != 1 {
				t.Fatalf("an id deleted %d times", count)
			}
		}
	}
}
