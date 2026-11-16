package evsservice

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A cluster whose Deletes first run a hook, as a write landing between a HEAD and its DELETE would, and are counted.
type dropHookedCluster struct {
	sidecar.BlobCluster
	stateLock   sync.Mutex
	deleteCount int
	beforeEach  func(key string)
}

func (self *dropHookedCluster) Delete(ctx context.Context, key string) error {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.deleteCount += 1
	}()
	if self.beforeEach != nil {
		self.beforeEach(key)
	}
	return self.BlobCluster.Delete(ctx, key)
}

func (self *dropHookedCluster) deletes() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.deleteCount
}

// The deletes of one round of the world's job: its candidates stored as the test puts them, its checkpoints kept.
type dropDeleteFixture struct {
	world       *dropWorld
	deleter     *DropDelete
	format2     *fakeDropFormat2
	metadata    *dropHookedCluster
	segment     *dropHookedCluster
	horizon     time.Time
	leaseUntil  time.Time
	checkpoints []*DropDeleteProgress
	// the lease a checkpoint renews to; zero renews to now + 2 min
	renewTo func() time.Time
}

func newDropDeleteFixture(t *testing.T) *dropDeleteFixture {
	world := newDropWorld(t)
	fixture := &dropDeleteFixture{
		world:    world,
		format2:  &fakeDropFormat2{mode: sidecar.Format2On},
		metadata: &dropHookedCluster{BlobCluster: world.cluster},
		segment:  &dropHookedCluster{BlobCluster: world.segment},
	}
	deleter, err := NewDropDelete(world.host.ServiceHost(), &DropDeleteDeps{Format2: fixture.format2, Settings: dropTestSettings(), EvsSettings: world.settings})
	if err != nil {
		t.Fatal(err)
	}
	fixture.deleter = deleter
	return fixture
}

// Stores a segment of byteCount bytes now.
func (self *dropDeleteFixture) putSegment(label string, byteCount int) DropScanId {
	self.world.t.Helper()
	id := dropTestId(label)
	if _, err := self.world.segment.PutIfNoneMatch(self.world.paidCtx, SegmentKey(self.world.repoId, id), make([]byte, byteCount), nil); err != nil {
		self.world.t.Fatal(err)
	}
	return DropSegmentId(id)
}

// Stores a slot now.
func (self *dropDeleteFixture) putSlot(label string) DropScanId {
	self.world.t.Helper()
	slotId := testId(label)
	if _, err := self.world.cluster.PutIfNoneMatch(self.world.paidCtx, SlotKey(self.world.repoId, slotId), []byte("slot "+label), nil); err != nil {
		self.world.t.Fatal(err)
	}
	return DropSlotId(slotId)
}

// Whether a candidate's object is still stored.
func (self *dropDeleteFixture) stored(scanId DropScanId) bool {
	self.world.t.Helper()
	var err error
	if scanId.Kind == DropIdSlot {
		_, err = self.world.cluster.Head(self.world.ctx, SlotKey(self.world.repoId, scanId.SlotId()))
	} else {
		_, err = self.world.segment.Head(self.world.ctx, SegmentKey(self.world.repoId, scanId.Id))
	}
	if err != nil && !errors.Is(err, sidecar.ErrBlobNotFound) {
		self.world.t.Fatal(err)
	}
	return err == nil
}

// One deletes run over candidates, written as the job's cand file, under the fixture's horizon and lease.
func (self *dropDeleteFixture) run(candidates ...DropScanId) *DropDeleteResult {
	self.world.t.Helper()
	result, err := self.runErr(candidates...)
	if err != nil {
		self.world.t.Fatal(err)
	}
	return result
}

func (self *dropDeleteFixture) runErr(candidates ...DropScanId) (*DropDeleteResult, error) {
	world := self.world
	world.writeCandidates(world.jobId, candidates...)
	set, err := world.files(world.jobId).Candidates(world.ctx)
	if err != nil {
		return nil, err
	}
	if self.leaseUntil.IsZero() {
		self.leaseUntil = world.clock.Now().Add(2 * time.Minute)
	}
	settings := dropTestSettings()
	return self.deleter.Delete(world.ctx, &DropDeleteRequest{
		Cluster: self.metadata, SegmentCluster: self.segment, RepoId: world.repoId, NetworkId: testId("network-a"), JobId: world.jobId,
		Round: 1, Horizon: self.horizon, Candidates: set, LeaseUntil: self.leaseUntil, LeaseMargin: settings.LeaseMargin,
		DeadlineMargin: settings.DeleteDeadlineMargin, AdoptionBound: settings.AdoptionBound, DeletesPerSecond: settings.DeletesPerSecond,
		Checkpoint: func(ctx context.Context, progress *DropDeleteProgress) (time.Time, error) {
			self.checkpoints = append(self.checkpoints, progress)
			if self.renewTo != nil {
				return self.renewTo(), nil
			}
			return world.clock.Now().Add(2 * time.Minute), nil
		},
	})
}

// Each answered id's newest outcome, from the job's del files.
func (self *dropDeleteFixture) answers() map[DropScanId]DropOutcome {
	self.world.t.Helper()
	answers, err := self.world.files(self.world.jobId).Answers(self.world.ctx)
	if err != nil {
		self.world.t.Fatal(err)
	}
	return answers
}

// §11.13's delete row with F7 and F9: ripe segments and a slot deleted, a candidate stored since within the adoption
// bound young for a later round, a missing one absent; the stored bytes of each deleted seg/ object reported once, as
// one usage batch keyed by the job and its cursor range, and slots nothing.
func TestDropDeleteDeletesRipeIdsAndLeavesYoungOnes(t *testing.T) {
	fixture := newDropDeleteFixture(t)
	world := fixture.world
	a, b, slot := fixture.putSegment("a", 100), fixture.putSegment("b", 200), fixture.putSlot("slot-k")
	world.clock.Advance(30 * time.Hour)
	young := fixture.putSegment("young", 300)
	absent := DropSegmentId(dropTestId("absent"))
	fixture.horizon = world.clock.Now()
	result := fixture.run(a, b, slot, young, absent)
	if result.Held || result.Unanswered != 0 {
		t.Fatalf("result %+v", result)
	}
	answers := fixture.answers()
	for scanId, want := range map[DropScanId]DropOutcome{a: DropOutcomeDeleted, b: DropOutcomeDeleted, slot: DropOutcomeDeleted, young: DropOutcomeYoung, absent: DropOutcomeAbsent} {
		if answers[scanId] != want {
			t.Fatalf("%x answered %d, want %d", scanId.Id[:4], answers[scanId], want)
		}
	}
	if fixture.stored(a) || fixture.stored(b) || fixture.stored(slot) || !fixture.stored(young) {
		t.Fatal("the store holds otherwise")
	}
	if want := world.clock.Now().Add(dropTestSettings().AdoptionBound); !result.YoungBound.Equal(want) {
		t.Fatalf("young bound %s, want %s", result.YoungBound, want)
	}
	if len(fixture.checkpoints) != 1 || fixture.checkpoints[0].FreedByteCount != 300 || fixture.checkpoints[0].HeldByteCount != 0 {
		t.Fatalf("checkpoints %+v", fixture.checkpoints)
	}
	if delta := world.host.Quota.StoredDelta(connect.Id(testId("network-a"))); delta != -300 {
		t.Fatalf("stored delta %d, want -300 with slots reporting nothing", delta)
	}
	batches := world.host.Quota.Batches()
	if len(batches) != 1 || batches[0].Producer != sidecar.QuotaProducerTaskworker {
		t.Fatalf("batches %+v", batches)
	}
	// a second run over the same ids, as an instance resuming before the checkpoint would, finds the deleted ones
	// gone and reports nothing more
	fixture.run(a, b, slot, young, absent)
	if answers := fixture.answers(); answers[a] != DropOutcomeAbsent || answers[slot] != DropOutcomeAbsent {
		t.Fatalf("the second run's answers %v", answers)
	}
	if delta := world.host.Quota.StoredDelta(connect.Id(testId("network-a"))); delta != -300 {
		t.Fatalf("freed bytes reported again: %d", delta)
	}
}

// F9: a segment stored again between its HEAD and its DELETE is another object: the DELETE naming the HEAD's
// LastModified answers 412, the id is replaced, never retried, and the new object stays.
func TestDropDeleteNeverRetriesAReplacedSegment(t *testing.T) {
	fixture := newDropDeleteFixture(t)
	world := fixture.world
	a := fixture.putSegment("a", 100)
	world.clock.Advance(30 * time.Hour)
	fixture.horizon = world.clock.Now()
	fixture.segment.beforeEach = func(key string) {
		if err := world.segment.Delete(world.ctx, key); err != nil {
			t.Fatal(err)
		}
		if _, err := world.segment.PutIfNoneMatch(world.paidCtx, key, make([]byte, 100), nil); err != nil {
			t.Fatal(err)
		}
	}
	fixture.run(a)
	if outcome := fixture.answers()[a]; outcome != DropOutcomeReplaced {
		t.Fatalf("outcome %d", outcome)
	}
	if fixture.segment.deletes() != 1 || !fixture.stored(a) {
		t.Fatalf("%d DELETEs; stored %t", fixture.segment.deletes(), fixture.stored(a))
	}
}

// A slot an ERASE rewrites in place between its HEAD and DELETE is read again: its new LastModified makes it young.
func TestDropDeleteReadsAnErasedSlotAgain(t *testing.T) {
	fixture := newDropDeleteFixture(t)
	world := fixture.world
	slot := fixture.putSlot("slot-k")
	world.clock.Advance(30 * time.Hour)
	fixture.horizon = world.clock.Now()
	fixture.metadata.beforeEach = func(key string) {
		info, err := world.cluster.Head(world.ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := world.cluster.PutIfMatch(world.paidCtx, key, info.Etag, []byte("erased"), nil); err != nil {
			t.Fatal(err)
		}
	}
	fixture.run(slot)
	if outcome := fixture.answers()[slot]; outcome != DropOutcomeYoung {
		t.Fatalf("outcome %d", outcome)
	}
	if fixture.metadata.deletes() != 1 || !fixture.stored(slot) {
		t.Fatalf("%d DELETEs; stored %t", fixture.metadata.deletes(), fixture.stored(slot))
	}
}

// Owner decision 184 and F8: a covering hold moves the rest of D to held, their stored bytes reported once as they move;
// once the hold ends the round over them deletes them and reports nothing more.
func TestDropDeleteMovesTheRestToHeldUnderAHold(t *testing.T) {
	fixture := newDropDeleteFixture(t)
	world := fixture.world
	a, b := fixture.putSegment("a", 100), fixture.putSegment("b", 200)
	world.clock.Advance(30 * time.Hour)
	fixture.horizon = world.clock.Now()
	if err := sidecartest.PlaceHold(world.ctx, world.host.Blobs, &sidecar.HoldRecord{
		NetworkId: testId("network-a"), CaseId: testId("hold case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: world.clock.Now(), ExpireTime: world.clock.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	result := fixture.run(a, b)
	if !result.Held || fixture.segment.deletes() != 0 || !fixture.stored(a) || !fixture.stored(b) {
		t.Fatalf("held %t, %d DELETEs", result.Held, fixture.segment.deletes())
	}
	if answers := fixture.answers(); answers[a] != DropOutcomeHeld || answers[b] != DropOutcomeHeld {
		t.Fatalf("answers %v", answers)
	}
	held, err := world.files(world.jobId).ReadAll(world.ctx, DropFileHeld)
	if err != nil || len(held) != 1 || len(held[0].Ids) != 2 {
		t.Fatalf("held files %v (%v)", held, err)
	}
	if delta := world.host.Quota.StoredDelta(connect.Id(testId("network-a"))); delta != -300 {
		t.Fatalf("stored delta at hold %d", delta)
	}
	if fixture.checkpoints[len(fixture.checkpoints)-1].HeldByteCount != 300 {
		t.Fatalf("checkpoints %+v", fixture.checkpoints)
	}
	if err := sidecartest.RemoveHold(world.ctx, world.host.Blobs, testId("network-a"), testId("hold case")); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(time.Minute)
	result = fixture.run(a, b)
	if result.Held || fixture.stored(a) || fixture.stored(b) {
		t.Fatalf("after the hold: %+v", result)
	}
	if delta := world.host.Quota.StoredDelta(connect.Id(testId("network-a"))); delta != -300 {
		t.Fatalf("held bytes reported again at their DELETE: %d", delta)
	}
}

// F0 and §11.13's clock row: an unsure clock, a cluster that has not passed the settle cases, drop in observe, and a
// lease that cannot be renewed past its margin each issue no DELETE, leaving every id unanswered.
func TestDropDeleteGatesIssueNothing(t *testing.T) {
	gates := map[string]func(fixture *dropDeleteFixture){
		"an unsure clock":    func(fixture *dropDeleteFixture) { fixture.world.host.ClockCheck.SetUnknown() },
		"the segment settle": func(fixture *dropDeleteFixture) { fixture.world.host.Blobs.SetSettlePassed("seg-1", false) },
		"the metadata settle": func(fixture *dropDeleteFixture) {
			fixture.world.host.Blobs.SetSettlePassed("meta-1", false)
		},
		"drop in observe": func(fixture *dropDeleteFixture) { fixture.format2.mode = sidecar.Format2Observe },
		"a lease at its margin": func(fixture *dropDeleteFixture) {
			fixture.leaseUntil = fixture.world.clock.Now().Add(500 * time.Millisecond)
			fixture.renewTo = func() time.Time { return fixture.leaseUntil }
		},
	}
	for name, close := range gates {
		fixture := newDropDeleteFixture(t)
		world := fixture.world
		a := fixture.putSegment("a", 100)
		world.clock.Advance(30 * time.Hour)
		fixture.horizon = world.clock.Now()
		close(fixture)
		result := fixture.run(a)
		if fixture.segment.deletes() != 0 || !fixture.stored(a) || result.Unanswered != 1 {
			t.Fatalf("%s: %d DELETEs, %d unanswered", name, fixture.segment.deletes(), result.Unanswered)
		}
	}
}

// The cursor passes only answered ids: a DELETE on a held key leaves its id unanswered and the cursor before it, while
// the ids after it are answered and carry their rows.
func TestDropDeleteStopsTheCursorBeforeAnUnansweredId(t *testing.T) {
	fixture := newDropDeleteFixture(t)
	world := fixture.world
	ids := []DropScanId{fixture.putSegment("a", 100), fixture.putSegment("b", 100), fixture.putSegment("c", 100)}
	world.clock.Advance(30 * time.Hour)
	fixture.horizon = world.clock.Now()
	sorted := sortedDropScanIds(ids...)
	if _, err := world.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpDelete, KeyPrefix: SegmentKey(world.repoId, sorted[1].Id), ClusterId: "seg-1", Result: sidecartest.Held,
	}); err != nil {
		t.Fatal(err)
	}
	result := fixture.run(ids...)
	if result.Unanswered != 1 {
		t.Fatalf("result %+v", result)
	}
	if cursor := fixture.checkpoints[len(fixture.checkpoints)-1].Cursor; cursor != (DropCursor{Sequence: 0, Row: 1}) {
		t.Fatalf("cursor %+v", cursor)
	}
	answers := fixture.answers()
	if answers[sorted[0]] != DropOutcomeDeleted || answers[sorted[2]] != DropOutcomeDeleted || answers[sorted[1]] != 0 {
		t.Fatalf("answers %v", answers)
	}
	if !fixture.stored(sorted[1]) {
		t.Fatal("the held key's object went")
	}
}

// While an unanswered id holds the cursor still, each later checkpoint that frees bytes sends a batch of its own id: a
// run that resumes before the same id and deletes a candidate the last run found young reports its bytes too, where
// a batch keyed by the cursor range alone would repeat the last one's id and api would apply it as a no-op.
func TestDropDeleteReportsEachBatchWhileTheCursorStandsBeforeAnUnansweredId(t *testing.T) {
	fixture := newDropDeleteFixture(t)
	world := fixture.world
	stuck, a, b := fixture.putSegment("stuck", 50), fixture.putSegment("a", 200), fixture.putSegment("b", 400)
	world.clock.Advance(30 * time.Hour)
	young := fixture.putSegment("young", 800)
	fixture.horizon = world.clock.Now()
	if _, err := world.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpDelete, KeyPrefix: SegmentKey(world.repoId, stuck.Id), ClusterId: "seg-1", Result: sidecartest.Held, Repeat: -1,
	}); err != nil {
		t.Fatal(err)
	}
	if result := fixture.run(stuck, a, b, young); result.Unanswered != 1 || result.YoungBound.IsZero() {
		t.Fatalf("the first run: %+v", result)
	}
	if delta := world.host.Quota.StoredDelta(connect.Id(testId("network-a"))); delta != -600 {
		t.Fatalf("stored delta after the first run %d, want -600", delta)
	}
	// the next run, past the young candidate's bound, still stops before the stuck id
	world.clock.Advance(30 * time.Hour)
	fixture.horizon = world.clock.Now()
	if result := fixture.run(stuck, a, b, young); result.Unanswered != 1 || fixture.stored(young) {
		t.Fatalf("the second run: %+v", result)
	}
	if fixture.checkpoints[0].Cursor != fixture.checkpoints[len(fixture.checkpoints)-1].Cursor {
		t.Fatalf("the cursor moved: %+v", fixture.checkpoints)
	}
	sent := world.host.Quota.SentBatches()
	if len(sent) != 2 || sent[0].BatchId == sent[1].BatchId {
		t.Fatalf("sent batches %+v", sent)
	}
	if delta := world.host.Quota.StoredDelta(connect.Id(testId("network-a"))); delta != -1400 {
		t.Fatalf("stored delta %d, want -1400: the second run's bytes went unreported", delta)
	}
}

// FS-90's stale instance: a DELETE delayed in the network until past the lease's deadline is refused by the store on
// arrival, so the object stays, and the id is left unanswered for the instance that holds the job next.
func TestDropDeleteStaleDeleteIsRefusedPastItsDeadline(t *testing.T) {
	fixture := newDropDeleteFixture(t)
	world := fixture.world
	a := fixture.putSegment("a", 100)
	world.clock.Advance(30 * time.Hour)
	fixture.horizon = world.clock.Now()
	fired, err := world.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpDelete, KeyPrefix: SegmentKey(world.repoId, a.Id), ClusterId: "seg-1", Result: sidecartest.Delay,
		Delay: sidecartest.DelayInNetwork,
	})
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result *DropDeleteResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := fixture.runErr(a)
		done <- outcome{result: result, err: err}
	}()
	<-fired
	// the lease lapses and another instance takes the job; the request then reaches the store
	world.clock.Advance(3 * time.Minute)
	if delivered := world.host.Blobs.DeliverDelayed("seg-1", SegmentKey(world.repoId, a.Id)); delivered != 1 {
		t.Fatalf("%d delivered", delivered)
	}
	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.result.Unanswered != 1 || !fixture.stored(a) {
		t.Fatalf("result %+v, stored %t", got.result, fixture.stored(a))
	}
	if answers := fixture.answers(); answers[a] != 0 {
		t.Fatalf("answers %v", answers)
	}
}

// An id moved to held, answered young in the round after the hold ends, and deleted in a later round reports its stored
// bytes once, at the hold: the job's held files, not an id's newest outcome, say what was reported.
func TestDropDeleteReportsAHeldIdOnceThroughALaterYoungRound(t *testing.T) {
	fixture := newDropDeleteFixture(t)
	world := fixture.world
	a := fixture.putSegment("a", 100)
	fixture.horizon = world.clock.Now()
	if err := sidecartest.PlaceHold(world.ctx, world.host.Blobs, &sidecar.HoldRecord{
		NetworkId: testId("network-a"), CaseId: testId("hold case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: world.clock.Now(), ExpireTime: world.clock.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if result := fixture.run(a); !result.Held {
		t.Fatalf("under the hold: %+v", result)
	}
	if err := sidecartest.RemoveHold(world.ctx, world.host.Blobs, testId("network-a"), testId("hold case")); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(time.Minute)
	fixture.horizon = world.clock.Now()
	if result := fixture.run(a); result.YoungBound.IsZero() || fixture.answers()[a] != DropOutcomeYoung {
		t.Fatalf("the round after the hold: %+v", result)
	}
	world.clock.Advance(30 * time.Hour)
	fixture.horizon = world.clock.Now()
	fixture.run(a)
	if fixture.answers()[a] != DropOutcomeDeleted || fixture.stored(a) {
		t.Fatal("the later round did not delete")
	}
	if delta := world.host.Quota.StoredDelta(connect.Id(testId("network-a"))); delta != -100 {
		t.Fatalf("stored delta %d, want the held bytes reported once", delta)
	}
}
