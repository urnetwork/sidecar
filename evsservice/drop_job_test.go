package evsservice

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What the job's seams were asked, in order.
type dropJobEvents struct {
	stateLock sync.Mutex
	names     []string
}

func (self *dropJobEvents) add(name string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.names = append(self.names, name)
}

func (self *dropJobEvents) list() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.names)
}

func (self *dropJobEvents) count(name string) int {
	count := 0
	for _, event := range self.list() {
		if event == name {
			count += 1
		}
	}
	return count
}

// Resolve's stand-in until EVSB-M10-04: writes cand-0 with its candidates and refuses its mismatches.
type fakeDropResolver struct {
	events     *dropJobEvents
	candidates []DropScanId
	mismatch   []sidecar.Id
	requests   []*DropResolveRequest
	preview    *DropPreviewResolveResult
	previewErr error
}

func (self *fakeDropResolver) Resolve(ctx context.Context, request *DropResolveRequest) (*DropResolveResult, error) {
	self.events.add("resolve")
	self.requests = append(self.requests, request)
	files := NewDropFiles(request.SegmentCluster, request.RepoId, request.JobId, DefaultDropSettings())
	encoded, err := EncodeDropIdFile(DropFileCand, request.RepoId, request.JobId, 0, self.candidates)
	if err != nil {
		return nil, err
	}
	if err := files.Put(ctx, DropFileCand, 0, encoded); err != nil {
		return nil, err
	}
	return &DropResolveResult{Mismatch: self.mismatch}, nil
}

func (self *fakeDropResolver) Preview(ctx context.Context, request *DropPreviewResolveRequest) (*DropPreviewResolveResult, error) {
	self.events.add("preview")
	if self.previewErr != nil {
		return nil, self.previewErr
	}
	files := NewDropFiles(request.SegmentCluster, request.RepoId, request.PreviewId, DefaultDropSettings())
	encoded, err := EncodeDropIdFile(DropFileCand, request.RepoId, request.PreviewId, 0, self.candidates)
	if err != nil {
		return nil, err
	}
	if err := files.Put(ctx, DropFileCand, 0, encoded); err != nil {
		return nil, err
	}
	return self.preview, nil
}

// Mark's stand-in until EVSB-M10-04: marks its marks in a new mark file and reports its snapshot.
type fakeDropMarker struct {
	events   *dropJobEvents
	marks    []DropScanId
	snapshot map[sidecar.Id]uint64
	requests []*DropMarkRequest
}

func (self *fakeDropMarker) Mark(ctx context.Context, request *DropMarkRequest) (*DropMarkResult, error) {
	self.events.add("mark")
	self.requests = append(self.requests, request)
	files := NewDropFiles(request.SegmentCluster, request.RepoId, request.JobId, DefaultDropSettings())
	sequence, err := files.NextSequence(ctx, DropFileMark)
	if err != nil {
		return nil, err
	}
	if err := files.Put(ctx, DropFileMark, sequence, EncodeDropMarkFile(request.RepoId, request.JobId, sequence, sidecar.Id{}, 0, self.marks)); err != nil {
		return nil, err
	}
	return &DropMarkResult{Snapshot: self.snapshot}, nil
}

// Verify's stand-in in these tests (dropverify is EVSB-M10-05's, tested on its own).
type fakeDropVerifier struct {
	events   *dropJobEvents
	result   func(request *DropVerifyRequest) *DropVerifyResult
	requests []*DropVerifyRequest
}

func (self *fakeDropVerifier) Verify(ctx context.Context, request *DropVerifyRequest) (*DropVerifyResult, error) {
	self.events.add("verify")
	self.requests = append(self.requests, request)
	if self.result != nil {
		return self.result(request), nil
	}
	return &DropVerifyResult{Snapshot: request.Marked}, nil
}

// The deletes' stand-in until EVSB-M10-06: each candidate's outcome by outcomeOf, a del file of the answers and one
// checkpoint; held moves the rest of D to held.
type fakeDropDeleter struct {
	events     *dropJobEvents
	outcomeOf  func(candidate *DropCandidate) DropOutcome
	held       bool
	youngBound time.Time
	freedEach  uint64
	requests   []*DropDeleteRequest
}

// The outcome a candidate meets that the deleter leaves unanswered.
const fakeDropUnanswered DropOutcome = 0

func (self *fakeDropDeleter) Delete(ctx context.Context, request *DropDeleteRequest) (*DropDeleteResult, error) {
	self.events.add("delete")
	self.requests = append(self.requests, request)
	result := &DropDeleteResult{Held: self.held, Progress: &DropDeleteProgress{}}
	answers := []*DropAnswer{}
	for _, candidate := range request.Candidates {
		outcome := DropOutcomeDeleted
		if self.outcomeOf != nil {
			outcome = self.outcomeOf(candidate)
		}
		if self.held {
			outcome = DropOutcomeHeld
		}
		if outcome == fakeDropUnanswered {
			result.Unanswered = len(request.Candidates) - len(answers)
			break
		}
		answers = append(answers, &DropAnswer{DropScanId: candidate.DropScanId, Outcome: outcome})
		result.Progress.Cursor = DropCursor{Sequence: candidate.Cursor.Sequence, Row: candidate.Cursor.Row + 1}
		switch outcome {
		case DropOutcomeDeleted:
			result.Progress.FreedByteCount += self.freedEach
		case DropOutcomeHeld:
			result.Progress.HeldByteCount += self.freedEach
		case DropOutcomeYoung:
			result.YoungBound = self.youngBound
		}
	}
	files := NewDropFiles(request.SegmentCluster, request.RepoId, request.JobId, DefaultDropSettings())
	sequence, err := files.NextSequence(ctx, DropFileDel)
	if err != nil {
		return nil, err
	}
	if err := files.Put(ctx, DropFileDel, sequence, EncodeDropDelFile(request.RepoId, request.JobId, sequence, answers)); err != nil {
		return nil, err
	}
	if _, err := request.Checkpoint(ctx, result.Progress); err != nil {
		return nil, err
	}
	return result, nil
}

type fakeDropLocks struct {
	standing bool
	answer   EvsAuthAnswer
}

func (self *fakeDropLocks) LockStanding(networkId sidecar.Id, repoId sidecar.Id) (bool, EvsAuthAnswer) {
	return self.standing, self.answer
}

// The format2 gate with a drop mode a test sets.
type fakeDropFormat2 struct {
	mode sidecar.Format2Mode
}

func (self *fakeDropFormat2) Admits(networkId sidecar.Id) bool { return true }
func (self *fakeDropFormat2) PurgeMode() sidecar.Format2Mode   { return sidecar.Format2Observe }
func (self *fakeDropFormat2) DropMode() sidecar.Format2Mode    { return self.mode }

// The horizon a test sets, each read an event.
type fakeDropHorizon struct {
	events  *dropJobEvents
	horizon time.Time
}

func (self *fakeDropHorizon) OrphanHorizon(ctx context.Context, cluster sidecar.BlobCluster) (time.Time, error) {
	self.events.add("horizon")
	return self.horizon, nil
}

// A repo's committed history (evsWorld) with a drop job over it, its seams fakes.
type dropJobFixture struct {
	t        *testing.T
	world    *evsWorld
	job      *DropJob
	events   *dropJobEvents
	resolver *fakeDropResolver
	marker   *fakeDropMarker
	verifier *fakeDropVerifier
	deleter  *fakeDropDeleter
	locks    *fakeDropLocks
	format2  *fakeDropFormat2
	horizon  *fakeDropHorizon
	// the barriers the job passed, and the one it stops at as a kill would
	steps  []string
	stopAt string
	// the candidates resolve writes
	a, b, c DropScanId
}

func newDropJobFixture(t *testing.T) *dropJobFixture {
	world := newEvsWorld(t)
	world.push(&worldChange{path: worldPath("x"), version: 1})
	world.push(&worldChange{path: worldPath("x"), base: 1, version: 2})
	events := &dropJobEvents{}
	fixture := &dropJobFixture{
		t: t, world: world, events: events,
		a: DropSegmentId([32]byte{1}), b: DropSegmentId([32]byte{2}), c: DropSlotId(testId("slot")),
		locks:   &fakeDropLocks{answer: EvsAuthAllowed},
		format2: &fakeDropFormat2{mode: sidecar.Format2On},
		horizon: &fakeDropHorizon{events: events},
	}
	fixture.resolver = &fakeDropResolver{events: events, candidates: []DropScanId{fixture.a, fixture.b, fixture.c}}
	fixture.marker = &fakeDropMarker{events: events, snapshot: map[sidecar.Id]uint64{world.refId: world.head.Version()}}
	fixture.verifier = &fakeDropVerifier{events: events}
	fixture.deleter = &fakeDropDeleter{events: events, freedEach: 100}
	fixture.job = fixture.newJob(testId("instance-a"))
	fixture.hddKnown()
	return fixture
}

// A job instance over the fixture's seams.
func (self *dropJobFixture) newJob(instance sidecar.Id) *DropJob {
	job, err := NewDropJob(self.world.host.ServiceHost(), &DropJobDeps{
		Resolver: self.resolver, Marker: self.marker, Verifier: self.verifier, Deleter: self.deleter, Locks: self.locks,
		Horizon: self.horizon, Format2: self.format2, Instance: instance,
		atStep: func(name string, key string) error {
			self.steps = append(self.steps, name)
			if name == self.stopAt {
				return errors.New("killed at " + name)
			}
			return nil
		},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return job
}

// The segment cluster's figures with a known capacity, well under the pause line.
func (self *dropJobFixture) hddKnown() {
	err := publishHddFigures(self.world.ctx, self.world.host.Redis, &HddFigures{
		ClusterId: "seg-1", TimeMs: self.world.clock.Now().UnixMilli(), DriveOpsPerSecond: 10, CapacityOps: 1000,
	}, 1000*time.Hour)
	if err != nil {
		self.t.Fatal(err)
	}
}

// Appends a drop committed at the head's version now, as step 8 would.
func (self *dropJobFixture) appendDrop(label string, notBefore time.Time) {
	world := self.world
	commit := &DropCommit{
		ClusterId: "meta-1", RepoId: world.repoId, RefId: world.refId, PushId: testId("push-" + label), Version: world.head.Version(),
		Place: &protocol.EvsPlace{Minute: BatchMinute(world.clock.Now()), Instance: 1, Seq: 1, Length: 100},
		Body:  &protocol.EvsDropHistory{DropId: testId(label).Bytes(), Action: 1, NotBeforeMs: notBefore.UnixMilli()},
	}
	if err := self.job.Table().Append(world.paidCtx, commit, world.clock.Now().UnixMilli()); err != nil {
		self.t.Fatal(err)
	}
}

func (self *dropJobFixture) run() *DropJobResult {
	result, err := self.job.Run(self.world.ctx, "meta-1", self.world.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	return result
}

func (self *dropJobFixture) table() *DropTableState {
	read, err := self.job.Table().Read(self.world.ctx, self.world.cluster, self.world.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	return read.State
}

func (self *dropJobFixture) entry(label string) *DropTableEntry {
	entry := self.table().Drop(testId(label))
	if entry == nil {
		self.t.Fatalf("no entry for %s", label)
	}
	return entry
}

// Moves the clock past the drop's start and the horizon past its cite bound.
func (self *dropJobFixture) ripen() {
	self.world.clock.Advance(26 * time.Minute)
	self.horizon.horizon = self.world.clock.Now()
	self.hddKnown()
}

// The job's files.
func (self *dropJobFixture) files(jobId sidecar.Id) *DropFiles {
	segmentCluster, err := self.world.host.Blobs.SegmentCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	return NewDropFiles(segmentCluster, self.world.repoId, jobId, DefaultDropSettings())
}

// DESIGN-DETAILS 10.2.8's table end to end, and F0 to F6's barriers in order: the start CAS, resolve, the horizon, mark
// and verify, each before and after, with the horizon read before mark's LIST of head/.
func TestDropJobRunsADropToDone(t *testing.T) {
	fixture := newDropJobFixture(t)
	now := fixture.world.clock.Now()
	fixture.appendDrop("drop-1", now)
	fixture.marker.marks = []DropScanId{fixture.b}
	fixture.ripen()
	result := fixture.run()
	if !result.Ended || result.Moved[DropStateDone] != 1 || result.Round != 1 {
		t.Fatalf("the run: %+v", result)
	}
	entry := fixture.entry("drop-1")
	if entry.State != DropStateDone || entry.FreedByteCount != 200 || entry.EndedDay == 0 {
		t.Fatalf("the entry: %+v", entry)
	}
	if fixture.table().Job != nil {
		t.Fatal("a done job kept its record")
	}
	wantSteps := []string{
		BarrierDropStartBefore, BarrierDropStartAfter, BarrierDropResolveBefore, BarrierDropResolveAfter,
		BarrierDropHorizonBefore, BarrierDropHorizonAfter, BarrierDropMarkBefore, BarrierDropMarkAfter,
		BarrierDropVerifyBefore, BarrierDropVerifyAfter,
	}
	if !slices.Equal(fixture.steps, wantSteps) {
		t.Fatalf("barriers %v", fixture.steps)
	}
	// the start's selection read the horizon once, then the round's F4 before mark (F5) and verify (F6)
	if events := fixture.events.list(); !slices.Equal(events, []string{"horizon", "resolve", "horizon", "mark", "verify", "delete"}) {
		t.Fatalf("events %v", events)
	}
	// D is the candidates mark did not mark
	request := fixture.deleter.requests[0]
	got := []DropScanId{}
	for _, candidate := range request.Candidates {
		got = append(got, candidate.DropScanId)
	}
	if !slices.EqualFunc(got, []DropScanId{fixture.a, fixture.c}, func(x DropScanId, y DropScanId) bool { return x == y }) {
		t.Fatalf("D was %v", got)
	}
	if !request.Horizon.Equal(fixture.horizon.horizon.Truncate(time.Millisecond)) {
		t.Fatal("the deletes were not handed the round's horizon")
	}
	jobId := fixture.resolver.requests[0].JobId
	snap, err := fixture.files(jobId).Read(t.Context(), DropFileSnap, 0)
	if err != nil || snap == nil || len(snap.Covered) != 1 || snap.Covered[0].DropId != testId("drop-1") {
		t.Fatalf("snap-0: %v", err)
	}
	round, err := fixture.files(jobId).Read(t.Context(), DropFileSnap, 1)
	if err != nil || round == nil || len(round.Round.Refs) != 1 || round.Round.Refs[0].Marked != fixture.world.head.Version() {
		t.Fatalf("snap-1: %v", err)
	}
}

// Owner decision 183: nothing starts before not_before_ms + DropStartDelay (FS-89's window clause).
func TestDropJobWaitsForTheStartDelay(t *testing.T) {
	fixture := newDropJobFixture(t)
	notBefore := fixture.world.clock.Now().Add(7 * 24 * time.Hour)
	fixture.appendDrop("drop-1", notBefore)
	fixture.horizon.horizon = notBefore.Add(time.Hour)
	fixture.world.clock.AdvanceTo(notBefore.Add(24 * time.Minute))
	fixture.hddKnown()
	result := fixture.run()
	if result.Waiting != DropWaitStart || !result.Next.Equal(notBefore.Add(25*time.Minute)) {
		t.Fatalf("the run before the start: %+v", result)
	}
	if fixture.entry("drop-1").State != DropStatePending || len(fixture.events.list()) != 0 {
		t.Fatal("a drop started before not_before_ms + 25 min")
	}
	fixture.world.clock.AdvanceTo(notBefore.Add(25 * time.Minute))
	fixture.hddKnown()
	if result := fixture.run(); !result.Ended || fixture.entry("drop-1").State != DropStateDone {
		t.Fatalf("the run at the start: %+v", result)
	}
}

// F4: a round goes on only once the horizon has passed fence_ms + DropCiteBound; until then the job waits in phase
// horizon, its lease released, woken at retry_ms.
func TestDropJobWaitsForTheHorizon(t *testing.T) {
	fixture := newDropJobFixture(t)
	seen := fixture.world.clock.Now()
	fixture.appendDrop("drop-1", seen)
	fixture.world.clock.Advance(26 * time.Minute)
	fixture.horizon.horizon = seen.Add(11 * time.Minute)
	result := fixture.run()
	if result.Waiting != DropWaitHorizon || fixture.deleter.requests != nil || fixture.marker.requests != nil {
		t.Fatalf("a run short of the cite bound: %+v", result)
	}
	table := fixture.table()
	job := table.Job
	if job == nil || job.Phase != protocol.EvsDropPhase_EVS_DROP_HORIZON || job.Owner != (sidecar.Id{}) || job.UntilMs != 0 {
		t.Fatalf("a waiting job holds its lease: %+v", job)
	}
	wantRetry := seen.Add(12*time.Minute + 25*time.Hour).Truncate(time.Millisecond)
	if job.RetryMs != wantRetry.UnixMilli() || !result.Next.Equal(wantRetry) {
		t.Fatalf("retry_ms %d, want %d", job.RetryMs, wantRetry.UnixMilli())
	}
	if entry := table.Drop(testId("drop-1")); entry.State != DropStateExecuting || entry.Phase != protocol.EvsDropPhase_EVS_DROP_HORIZON {
		t.Fatalf("the waiting drop: %+v", entry)
	}
	status, _ := table.Drop(testId("drop-1")).State.Status()
	if status != protocol.EvsDropState_EVS_DROP_EXECUTING {
		t.Fatal("a waiting drop does not read executing")
	}
	// before retry_ms nothing runs; at it, with the horizon past the bound, the round goes on
	if early := fixture.run(); early.Waiting != DropWaitHorizon || fixture.events.count("horizon") != 2 {
		t.Fatalf("a run before retry_ms: %+v", early)
	}
	fixture.world.clock.AdvanceTo(wantRetry)
	fixture.horizon.horizon = seen.Add(12 * time.Minute)
	fixture.hddKnown()
	if result := fixture.run(); !result.Ended || fixture.entry("drop-1").State != DropStateDone {
		t.Fatalf("the run at retry_ms: %+v", result)
	}
}

// A committed cancel after the drop in its ref's history, whose step-8 append was lost, is found by the start's read
// (F1): cancelled, with its void record.
func TestDropJobStartFindsACancel(t *testing.T) {
	fixture := newDropJobFixture(t)
	world := fixture.world
	fixture.appendDrop("drop-1", world.clock.Now())
	dropVersion := world.head.Version()
	cancelBody, err := proto.Marshal(&protocol.EvsDropHistory{
		DropId: testId("cancel-1").Bytes(), Action: 2, CancelsDropId: testId("drop-1").Bytes(), CancelsVersion: dropVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	commitDropPushForTest(t, world, cancelBody)
	fixture.ripen()
	result := fixture.run()
	if result.Moved[DropStateCancelled] != 1 || fixture.resolver.requests != nil {
		t.Fatalf("the run: %+v", result)
	}
	table := fixture.table()
	if table.Drop(testId("drop-1")).State != DropStateCancelled || table.Void(testId("drop-1")) == nil || table.Job != nil {
		t.Fatal("a cancel in the ref's history left the drop to start")
	}
}

// §8.8: a lock standing at the start CAS refuses the drop {locked}; a state that is not loaded starts nothing.
func TestDropJobStartRefusesALockedRepo(t *testing.T) {
	fixture := newDropJobFixture(t)
	fixture.appendDrop("drop-1", fixture.world.clock.Now())
	fixture.ripen()
	fixture.locks.answer = EvsAuthUnknown
	if result := fixture.run(); result.Waiting != DropWaitAuth || fixture.entry("drop-1").State != DropStatePending {
		t.Fatalf("a run with no authorization state: %+v", result)
	}
	fixture.locks.answer, fixture.locks.standing = EvsAuthAllowed, true
	result := fixture.run()
	table := fixture.table()
	if result.Moved[DropStateRefusedLocked] != 1 || table.Drop(testId("drop-1")).State != DropStateRefusedLocked || table.Void(testId("drop-1")) == nil {
		t.Fatalf("a locked repo's drop: %+v", result)
	}
	if fixture.resolver.requests != nil || table.Job != nil {
		t.Fatal("a refused drop started a job")
	}
}

// Each covered drop is resolved and refused alone: a mismatch refuses its drop, with its void record, and pages; the
// other runs on.
func TestDropJobRefusesAMismatchAlone(t *testing.T) {
	fixture := newDropJobFixture(t)
	fixture.appendDrop("drop-1", fixture.world.clock.Now())
	fixture.appendDrop("drop-2", fixture.world.clock.Now())
	fixture.resolver.mismatch = []sidecar.Id{testId("drop-2")}
	fixture.ripen()
	result := fixture.run()
	table := fixture.table()
	if table.Drop(testId("drop-1")).State != DropStateDone || table.Drop(testId("drop-2")).State != DropStateRefusedMismatch ||
		table.Void(testId("drop-2")) == nil || result.Moved[DropStateRefusedMismatch] != 1 {
		t.Fatalf("the run: %+v", result)
	}
	snap, err := fixture.files(fixture.resolver.requests[0].JobId).Read(t.Context(), DropFileSnap, 0)
	if err != nil || len(snap.Covered) != 1 || snap.Covered[0].DropId != testId("drop-1") {
		t.Fatal("snap-0 covers a refused drop")
	}
}

// F6: the scans disagree below M_r, so the job is refused {verify}, pages, and deletes nothing.
func TestDropJobRefusesWhenTheScansDisagree(t *testing.T) {
	fixture := newDropJobFixture(t)
	fixture.appendDrop("drop-1", fixture.world.clock.Now())
	fixture.verifier.result = func(request *DropVerifyRequest) *DropVerifyResult {
		return &DropVerifyResult{Snapshot: request.Marked, Disagree: true, Detail: "a live version names a candidate"}
	}
	fixture.ripen()
	result := fixture.run()
	table := fixture.table()
	if table.Drop(testId("drop-1")).State != DropStateRefusedVerify || table.Void(testId("drop-1")) == nil || fixture.deleter.requests != nil {
		t.Fatalf("the run: %+v", result)
	}
	// verify was asked for M_r and the round's covered drops, and a lock reread
	request := fixture.verifier.requests[0]
	if request.Marked[fixture.world.refId] != fixture.world.head.Version() || len(request.Drops) != 1 || request.LockStanding == nil {
		t.Fatalf("verify's request: %+v", request)
	}
	if standing, err := request.LockStanding(t.Context()); err != nil || standing {
		t.Fatalf("the lock reread: %t %v", standing, err)
	}
}

// Verify's hits above M_r are marked and kept: a mark file carries them, and D leaves them out.
func TestDropJobKeepsVerifysLateMarks(t *testing.T) {
	fixture := newDropJobFixture(t)
	fixture.appendDrop("drop-1", fixture.world.clock.Now())
	fixture.verifier.result = func(request *DropVerifyRequest) *DropVerifyResult {
		return &DropVerifyResult{Snapshot: request.Marked, LateMarks: []DropScanId{fixture.c}}
	}
	fixture.ripen()
	fixture.run()
	got := []DropScanId{}
	for _, candidate := range fixture.deleter.requests[0].Candidates {
		got = append(got, candidate.DropScanId)
	}
	if slices.Contains(got, fixture.c) || len(got) != 2 {
		t.Fatalf("D took a late mark: %v", got)
	}
	marks, _, _, err := fixture.files(fixture.resolver.requests[0].JobId).Marks(t.Context())
	if err != nil || !marks[fixture.c] {
		t.Fatal("no mark file holds the late mark")
	}
}

// §19.11's format2.drop: observe: executing ends after verify with D recorded, every outcome observed, nothing deleted;
// once drop turns on, the observed drop runs again under a new job.
func TestDropJobObservesAndRunsAgainWhenDropTurnsOn(t *testing.T) {
	fixture := newDropJobFixture(t)
	fixture.format2.mode = sidecar.Format2Observe
	fixture.deleter = nil
	fixture.job = fixture.newJob(testId("instance-a"))
	fixture.appendDrop("drop-1", fixture.world.clock.Now())
	fixture.ripen()
	result := fixture.run()
	if fixture.entry("drop-1").State != DropStateObserved || result.Moved[DropStateObserved] != 1 {
		t.Fatalf("the observed run: %+v", result)
	}
	firstJobId := fixture.resolver.requests[0].JobId
	answers, err := fixture.files(firstJobId).Answers(t.Context())
	if err != nil || len(answers) != 3 {
		t.Fatalf("observe recorded %d ids: %v", len(answers), err)
	}
	for _, outcome := range answers {
		if outcome != DropOutcomeObserved {
			t.Fatal("observe recorded an outcome other than observed")
		}
	}
	// an observed entry never leaves, and stays until drop turns on
	if result := fixture.run(); result.Ended || len(fixture.resolver.requests) != 1 {
		t.Fatal("an observed drop ran again under observe")
	}
	fixture.format2.mode = sidecar.Format2On
	fixture.deleter = &fakeDropDeleter{events: fixture.events, freedEach: 1}
	fixture.job = fixture.newJob(testId("instance-a"))
	fixture.hddKnown()
	if result := fixture.run(); !result.Ended || fixture.entry("drop-1").State != DropStateDone {
		t.Fatalf("the run once drop turned on: %+v", result)
	}
	if len(fixture.resolver.requests) != 2 || fixture.resolver.requests[1].JobId == firstJobId {
		t.Fatal("the observed drop did not run again under a new job")
	}
	if fixture.table().Void(testId("drop-1")) != nil {
		t.Fatal("an observed drop left a void record")
	}
}

// F7 by the deletes: a young id leaves the job in phase horizon until the horizon passes its bound, and the next round's
// scans read only versions after the earlier round's snapshots, while D takes the young id again.
func TestDropJobRunsAnotherRoundForAYoungId(t *testing.T) {
	fixture := newDropJobFixture(t)
	fixture.appendDrop("drop-1", fixture.world.clock.Now())
	fixture.deleter.youngBound = fixture.world.clock.Now().Add(30 * time.Hour)
	fixture.deleter.outcomeOf = func(candidate *DropCandidate) DropOutcome {
		if candidate.DropScanId == fixture.a {
			return DropOutcomeYoung
		}
		return DropOutcomeDeleted
	}
	fixture.ripen()
	result := fixture.run()
	job := fixture.table().Job
	wantRetry := fixture.deleter.youngBound.Add(25 * time.Hour).Truncate(time.Millisecond)
	if result.Waiting != DropWaitHorizon || job == nil || job.RetryMs != wantRetry.UnixMilli() || job.Round != 1 {
		t.Fatalf("after a young id: %+v %+v", result, job)
	}
	fixture.deleter.outcomeOf = nil
	fixture.world.clock.AdvanceTo(wantRetry)
	fixture.horizon.horizon = fixture.world.clock.Now()
	fixture.hddKnown()
	result = fixture.run()
	if !result.Ended || result.Round != 2 || fixture.entry("drop-1").State != DropStateDone {
		t.Fatalf("round 2: %+v", result)
	}
	if since := fixture.marker.requests[1].Since; since[fixture.world.refId] != fixture.world.head.Version() {
		t.Fatalf("round 2's mark read from %v", since)
	}
	if since := fixture.verifier.requests[1].Since; since[fixture.world.refId] != fixture.world.head.Version() {
		t.Fatalf("round 2's verify read from %v", since)
	}
	second := fixture.deleter.requests[1].Candidates
	if len(second) != 1 || second[0].DropScanId != fixture.a {
		t.Fatalf("round 2's D: %d candidates", len(second))
	}
	if fixture.entry("drop-1").FreedByteCount != 300 {
		t.Fatalf("freed %d", fixture.entry("drop-1").FreedByteCount)
	}
}

// Owner decision 184: a covering hold moves the rest of D to held, the drop reads done, and once every covering hold
// ends a round deletes what was held.
func TestDropJobWaitsOnAHold(t *testing.T) {
	fixture := newDropJobFixture(t)
	world := fixture.world
	fixture.appendDrop("drop-1", world.clock.Now())
	fixture.ripen()
	hold := &sidecar.HoldRecord{
		NetworkId: testId("network-a"), CaseId: testId("case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: world.clock.Now(), ExpireTime: world.clock.Now().Add(90 * 24 * time.Hour),
	}
	if err := sidecartest.PlaceHold(world.paidCtx, world.host.Blobs, hold); err != nil {
		t.Fatal(err)
	}
	fixture.deleter.held = true
	result := fixture.run()
	table := fixture.table()
	if result.Waiting != DropWaitHold || table.Drop(testId("drop-1")).State != DropStateHeld || table.Job == nil || !table.Job.Held {
		t.Fatalf("the held run: %+v", result)
	}
	status, _ := table.Drop(testId("drop-1")).State.Status()
	if status != protocol.EvsDropState_EVS_DROP_DONE || table.Drop(testId("drop-1")).HeldByteCount != 300 {
		t.Fatal("a held drop does not read done with its held bytes")
	}
	// while the hold stands the job waits
	fixture.deleter.held = false
	world.clock.Advance(11 * time.Minute)
	fixture.hddKnown()
	if result := fixture.run(); result.Waiting != DropWaitHold || len(fixture.deleter.requests) != 1 {
		t.Fatalf("a run under the hold: %+v", result)
	}
	if err := sidecartest.RemoveHold(world.paidCtx, world.host.Blobs, hold.NetworkId, hold.CaseId); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(11 * time.Minute)
	fixture.horizon.horizon = world.clock.Now()
	fixture.hddKnown()
	result = fixture.run()
	if !result.Ended || fixture.entry("drop-1").State != DropStateDone || len(fixture.deleter.requests) != 2 {
		t.Fatalf("the run after the hold: %+v", result)
	}
	if len(fixture.deleter.requests[1].Candidates) != 3 {
		t.Fatal("the round after the hold did not take the held ids")
	}
}

// A round killed before its verify ended restarts at its F4, reading the horizon again, with its round number kept
// (10.5's job-killed row).
func TestDropJobRestartsAtTheHorizonAfterAKill(t *testing.T) {
	fixture := newDropJobFixture(t)
	fixture.appendDrop("drop-1", fixture.world.clock.Now())
	fixture.ripen()
	fixture.stopAt = BarrierDropMarkAfter
	if _, err := fixture.job.Run(fixture.world.ctx, "meta-1", fixture.world.repoId); err == nil {
		t.Fatal("the kill did not stop the run")
	}
	job := fixture.table().Job
	if job == nil || job.Phase != protocol.EvsDropPhase_EVS_DROP_MARK || job.Round != 1 {
		t.Fatalf("the killed job: %+v", job)
	}
	// another instance takes it once the lease lapsed 30 s
	other := fixture.newJob(testId("instance-b"))
	fixture.stopAt = ""
	result, err := other.Run(fixture.world.ctx, "meta-1", fixture.world.repoId)
	if err != nil || result.Waiting != DropWaitLease {
		t.Fatalf("a run inside the lease: %+v %v", result, err)
	}
	fixture.world.clock.AdvanceTo(time.UnixMilli(job.UntilMs).Add(30 * time.Second))
	fixture.hddKnown()
	horizonsBefore := fixture.events.count("horizon")
	result, err = other.Run(fixture.world.ctx, "meta-1", fixture.world.repoId)
	if err != nil || !result.Ended || result.Round != 1 {
		t.Fatalf("the resumed run: %+v %v", result, err)
	}
	if fixture.events.count("horizon") != horizonsBefore+1 || fixture.events.count("resolve") != 1 {
		t.Fatal("the resumed round did not read the horizon again, or resolved again")
	}
	if fixture.entry("drop-1").State != DropStateDone {
		t.Fatal("the resumed job did not finish")
	}
}

// Two instances racing the take: one job record, the loser stopping at its lost If-Match.
func TestDropJobTakeIsOneInstances(t *testing.T) {
	fixture := newDropJobFixture(t)
	fixture.appendDrop("drop-1", fixture.world.clock.Now())
	fixture.ripen()
	fixture.stopAt = BarrierDropResolveBefore
	if _, err := fixture.job.Run(fixture.world.ctx, "meta-1", fixture.world.repoId); err == nil {
		t.Fatal("the kill did not stop the run")
	}
	fixture.stopAt = ""
	other := fixture.newJob(testId("instance-b"))
	result, err := other.Run(fixture.world.ctx, "meta-1", fixture.world.repoId)
	if err != nil || result.Waiting != DropWaitLease || fixture.events.count("resolve") != 0 {
		t.Fatalf("the second instance took a held job: %+v %v", result, err)
	}
	if owner := fixture.table().Job.Owner; owner != testId("instance-a") {
		t.Fatal("the job's owner moved")
	}
}

// F0: an unsure clock, a build short of the settle cases, an unknown HDD capacity and a deleted repo start nothing, and
// a job missing its seams starts nothing at all.
func TestDropJobGatesStartNothing(t *testing.T) {
	fixture := newDropJobFixture(t)
	world := fixture.world
	fixture.appendDrop("drop-1", world.clock.Now())
	fixture.ripen()
	check := func(name string, want string) {
		t.Helper()
		result := fixture.run()
		if result.Waiting != want || fixture.entry("drop-1").State != DropStatePending || len(fixture.events.list()) != 0 {
			t.Fatalf("%s: %+v, events %v", name, result, fixture.events.list())
		}
	}
	world.host.ClockCheck.SetUnknown()
	check("an unknown clock", DropWaitClock)
	world.host.ClockCheck.SetOffset(0)
	world.host.Blobs.SetSettlePassed("seg-1", false)
	check("a segment cluster short of the settle cases", DropWaitSettle)
	world.host.Blobs.SetSettlePassed("seg-1", true)
	if err := publishHddFigures(world.ctx, world.host.Redis, &HddFigures{ClusterId: "seg-1", TimeMs: world.clock.Now().UnixMilli(), DriveOpsPerSecond: 10}, time.Hour); err != nil {
		t.Fatal(err)
	}
	check("no capacity known", DropWaitHdd)
	if err := publishHddFigures(world.ctx, world.host.Redis, &HddFigures{ClusterId: "seg-1", TimeMs: world.clock.Now().UnixMilli(), DriveOpsPerSecond: 600, CapacityOps: 1000}, time.Hour); err != nil {
		t.Fatal(err)
	}
	check("past half the capacity", DropWaitHdd)
	fixture.hddKnown()
	world.putRepo(protocol.EvsRepoState_EVS_REPO_DELETED)
	fixture.job = fixture.newJob(testId("instance-a"))
	check("a deleted repo", DropWaitRepo)
	world.putRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.resolver = nil
	job, err := NewDropJob(world.host.ServiceHost(), &DropJobDeps{Marker: fixture.marker, Verifier: fixture.verifier, Deleter: fixture.deleter, Locks: fixture.locks, Horizon: fixture.horizon, Format2: fixture.format2})
	if err != nil {
		t.Fatal(err)
	}
	fixture.job = job
	check("no resolve", DropWaitParts)
}

// A job covers the startable drops past their cite bound and leaves a now drop short of its own for the next job.
func TestDropJobLeavesADropShortOfItsBoundForTheNextJob(t *testing.T) {
	fixture := newDropJobFixture(t)
	world := fixture.world
	fixture.appendDrop("old-drop", world.clock.Now())
	world.clock.Advance(2 * 24 * time.Hour)
	fixture.appendDrop("now-drop", world.clock.Now())
	world.clock.Advance(26 * time.Minute)
	fixture.horizon.horizon = world.clock.Now().Add(-25 * time.Hour)
	fixture.hddKnown()
	fixture.run()
	if fixture.entry("old-drop").State != DropStateDone || fixture.entry("now-drop").State != DropStatePending {
		t.Fatalf("old %d, now %d", fixture.entry("old-drop").State, fixture.entry("now-drop").State)
	}
	if covered := fixture.resolver.requests[0].Drops; len(covered) != 1 || covered[0].DropId != testId("old-drop") {
		t.Fatal("the job covered a drop short of its bound beside one past it")
	}
}

// Commits a DROP push (a cancel here) with no change at the head's next version: its record through the batch writer
// and its window entry, bit 5 set.
func commitDropPushForTest(t *testing.T, world *evsWorld, body []byte) uint64 {
	world.pushSeq += 1
	pushId := testId("drop-push-" + string(rune('a'+world.pushSeq)))
	baseVersion := world.head.Version()
	baseChain := [32]byte(world.head.Head.GetChain())
	plan := &sidecar.EvsPushPlan{
		RepoId: world.repoId, RefId: world.refId, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		PushId: pushId, BaseVersion: baseVersion, BaseChain: baseChain, Generation: 1, GroupId: testId("group"),
		GenerationCommitment: make([]byte, 32), PathEpoch: EvsHeadCurrentEpoch(world.head.Head), Auth: &bridge.AuthPin{Version: 1, Chain: make([]byte, 32)},
		SignerSidecarId: world.signerId, ClientId: testId("client"), TimeMs: world.clock.Now().UnixMilli(),
		SealedMetadata: []byte("sealed metadata"), Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_DROP), DropBody: body,
	}
	built, err := world.builder.BuildFormat2(plan)
	if err != nil {
		t.Fatal(err)
	}
	record := &sidecar.EvsBatchRecord{
		Type: protocol.EvsBatchRecordType_EVS_BATCH_PUSH, RepoId: world.repoId, RefId: world.refId, PushId: pushId,
		SignerSidecarId: world.signerId, TimeMs: plan.TimeMs, Body: sidecar.EvsPushRecordBody(built.Statement.Bytes, built.Payload),
	}
	place, err := world.batches.Append(world.paidCtx, "meta-1", record)
	if err != nil {
		t.Fatal(err)
	}
	windowEntry := sidecar.NewEvsWindowEntry(built.Statement.Sha256, built.Statement.Push, nil, nil, false, place)
	if !windowEntry.Drop() {
		t.Fatal("a DROP's window entry lacks bit 5")
	}
	next := CloneEvsHead(world.head.Head)
	chain := sidecar.EvsChainNext(baseChain, pushId, built.Statement.Sha256)
	next.Version = baseVersion + 1
	next.Chain = chain[:]
	next.PushId = pushId.Bytes()
	next.Window = append(bytes.Clone(next.GetWindow()), windowEntry.Encode()...)
	written, err := world.heads.Commit(world.ctx, world.cluster, world.repoId, world.refId, world.head, next)
	if err != nil {
		t.Fatal(err)
	}
	world.head = written
	return next.Version
}
