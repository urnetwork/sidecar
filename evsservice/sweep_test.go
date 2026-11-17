package evsservice

// EVSB-M10-02's sweep on T2: a committed record's list swept before its batch goes, each candidate HEADed and
// deleted only when present, by a DELETE naming its LastModified; the newest version's names and a hold's placement
// keeping theirs; a re-upload between the HEAD and the DELETE staying; the gates; the retries; the one-off passes'
// gates and their walk of a repo's refs; and QD-855's series: each run's DELETEs under its pass, and what observe
// keeps counted in ids.

import (
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The purge fixture's host with a sweep over it.
type sweepFixture struct {
	*purgeFixture
	sweep *Sweep
	// a test's action at a barrier
	onStep func(name string, key string) error
}

func newSweepFixture(t *testing.T) *sweepFixture {
	fixture := &sweepFixture{purgeFixture: newPurgeFixture(t, nil)}
	sweep, err := NewSweep(fixture.host.ServiceHost(), &SweepDeps{
		Format2: fixture.gate,
		Newest:  fixture.newest,
		atStep: func(name string, key string) error {
			if fixture.onStep != nil {
				return fixture.onStep(name, key)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.sweep = sweep
	return fixture
}

func (self *sweepFixture) repo() *protocol.EvsRepoObject {
	return &protocol.EvsRepoObject{RepoId: self.repoId.Bytes(), NetworkId: self.networkId.Bytes(), Format: 2}
}

func (self *sweepFixture) sweepList(list *protocol.EvsPurgeList) (*SweepResult, error) {
	self.t.Helper()
	cluster, err := self.host.Blobs.Cluster("meta-1")
	if err != nil {
		self.t.Fatal(err)
	}
	return self.sweep.SweepList(self.ctx, cluster, &SweepTarget{RepoId: self.repoId, RefId: self.refId, Repo: self.repo(), PathEpoch: 1, List: list},
		sidecar.WriteP2RankEvacuation, true, self.clock.Now())
}

func sweepTestList(path sidecar.EvsTokenPath, segmentIds [][]byte, stagedIds [][]byte, slotIds [][]byte) *protocol.EvsPurgeList {
	return &protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{{
		TokenPath: path.Components(), ReplacedVersion: 3, SegmentIds: segmentIds, StagedSegmentIds: stagedIds, SlotIds: slotIds,
	}}}
}

// §11.13's sweep row: each candidate the newest version does not name is HEADed and, present, deleted; one gone
// counts absent and one the newest names stays; the deleted share and the freed bytes are the sweep's series, and
// it reports no usage.
func TestSweepDeletesPresentCandidatesOnly(t *testing.T) {
	fixture := newSweepFixture(t)
	path := checkTestPath("x")
	present := fixture.segment("present", 700)
	staged := fixture.segment("staged at seg", 300)
	named := fixture.segment("named", 100)
	gone := make([]byte, 32)
	copy(gone, "long gone")
	slot := fixture.slot("swept slot")
	fixture.newest.name(path, named)
	result, err := fixture.sweepList(sweepTestList(path, [][]byte{present, gone, named}, [][]byte{staged}, [][]byte{slot}))
	if err != nil {
		t.Fatal(err)
	}
	if fixture.segmentStored(present) || fixture.segmentStored(staged) || fixture.slotStored(slot) || !fixture.segmentStored(named) {
		t.Fatal("the sweep's deletes are not what it judged")
	}
	if result.DeletedCount != 3 || result.AbsentCount != 1 || result.NamedCount != 1 || result.FreedByteCount != 1000 {
		t.Fatalf("result %+v", result)
	}
	if got := fixture.host.Metrics.Value(versionlessSweepDeletesMetricName, versionlessSweepPassEvacuation, versionlessSweepDeleted); got != 3 {
		t.Fatalf("deleted %v", got)
	}
	if got := fixture.host.Metrics.Value(versionlessSweepDeletesMetricName, versionlessSweepPassEvacuation, versionlessSweepAbsent); got != 1 {
		t.Fatalf("absent %v", got)
	}
	if got := fixture.host.Metrics.Value(versionlessPurgedBytesMetricName, versionlessPurgedBySweep); got != 1000 {
		t.Fatalf("purged by sweep %v", got)
	}
	if delta := fixture.storedDelta(); delta != 0 {
		t.Fatalf("the sweep reported a stored delta of %d", delta)
	}
	// swept again, as a rerun after a kill does: all absent now, nothing counted twice
	result, err = fixture.sweepList(sweepTestList(path, [][]byte{present}, [][]byte{staged}, [][]byte{slot}))
	if err != nil || result.DeletedCount != 0 || result.AbsentCount != 3 {
		t.Fatalf("a rerun: %+v %v", result, err)
	}
}

// The DELETE names the HEAD's LastModified: the same id uploaded again between the two is a new object, which stays.
func TestSweepLeavesASegmentUploadedAgain(t *testing.T) {
	fixture := newSweepFixture(t)
	path := checkTestPath("x")
	id := fixture.segment("again", 100)
	cluster, _ := fixture.host.Blobs.Cluster("seg-1")
	fixture.onStep = func(name string, key string) error {
		if name != BarrierSweepDeleteBefore {
			return nil
		}
		// the object goes and its bytes come back later, a new object under the id
		fixture.onStep = nil
		if err := cluster.Delete(fixture.ctx, SegmentKey(fixture.repoId, [32]byte(id))); err != nil {
			t.Fatal(err)
		}
		fixture.clock.Advance(time.Hour)
		if _, err := cluster.PutIfNoneMatch(fixture.ctx, SegmentKey(fixture.repoId, [32]byte(id)), make([]byte, 100), nil); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	result, err := fixture.sweepList(sweepTestList(path, [][]byte{id}, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !fixture.segmentStored(id) || result.DeletedCount != 0 || result.AbsentCount != 1 {
		t.Fatalf("a re-upload was taken: stored %v %+v", fixture.segmentStored(id), result)
	}
}

// A hold keeps an uploaded segment or slot that existed at its placement, and a staged one under any covering hold;
// content written after the placement is swept.
func TestSweepKeepsWhatAHoldKeeps(t *testing.T) {
	fixture := newSweepFixture(t)
	path := checkTestPath("x")
	before := fixture.segment("before", 100)
	stagedBefore := fixture.segment("staged before", 100)
	slotBefore := fixture.slot("slot before")
	fixture.clock.Advance(time.Minute)
	if err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, &sidecar.HoldRecord{
		NetworkId: fixture.networkId, CaseId: testId("sweep case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeRepos(fixture.repoId), PlaceTime: fixture.clock.Now(), ExpireTime: fixture.clock.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(time.Minute)
	after := fixture.segment("after", 100)
	result, err := fixture.sweepList(sweepTestList(path, [][]byte{before, after}, [][]byte{stagedBefore}, [][]byte{slotBefore}))
	if err != nil {
		t.Fatal(err)
	}
	if !fixture.segmentStored(before) || !fixture.segmentStored(stagedBefore) || !fixture.slotStored(slotBefore) || fixture.segmentStored(after) {
		t.Fatal("the hold's keep is not by its placement")
	}
	if result.HeldCount != 3 || result.DeletedCount != 1 {
		t.Fatalf("result %+v", result)
	}
}

// Observe mode, a build that has not passed the settle cases, a marked list with no record to recompute it from and a
// path the reader cannot judge keep their content; an unsure clock or a held head is a retry.
func TestSweepGatesKeepContent(t *testing.T) {
	fixture := newSweepFixture(t)
	path := checkTestPath("x")
	id := fixture.segment("kept", 100)
	list := sweepTestList(path, [][]byte{id}, nil, nil)

	fixture.gate.set(sidecar.Format2Observe)
	if result, err := fixture.sweepList(list); err != nil || result.KeptCount != 1 || !fixture.segmentStored(id) {
		t.Fatalf("observe: %+v %v", result, err)
	}
	fixture.gate.set(sidecar.Format2On)

	fixture.host.Blobs.SetSettlePassed("meta-1", false)
	if result, err := fixture.sweepList(list); err != nil || result.KeptCount != 1 || !fixture.segmentStored(id) {
		t.Fatalf("an unpassed build: %+v %v", result, err)
	}
	fixture.host.Blobs.SetSettlePassed("meta-1", true)

	if result, err := fixture.sweepList(&protocol.EvsPurgeList{Marked: true}); err != nil || result.KeptCount != 1 {
		t.Fatalf("a marked list: %+v %v", result, err)
	}

	fixture.newest.err = errPurgeUnjudged
	if result, err := fixture.sweepList(list); err != nil || result.KeptCount != 1 || !fixture.segmentStored(id) {
		t.Fatalf("an unjudged path: %+v %v", result, err)
	}
	fixture.newest.err = sidecar.ErrBlobHeld
	if _, err := fixture.sweepList(list); !errors.Is(err, ErrSweepRetry) || !fixture.segmentStored(id) {
		t.Fatalf("a held head: %v", err)
	}
	fixture.newest.err = nil

	fixture.host.ClockCheck.SetUnknown()
	if _, err := fixture.sweepList(list); !errors.Is(err, ErrSweepRetry) || !fixture.segmentStored(id) {
		t.Fatalf("an unsure clock: %v", err)
	}
}

// The one-off passes need a build that passed the settle cases and a sure clock, and walk every ref of the repo:
// a ref whose versions carry no bit 4 rereads no record.
func TestSweepPassesWalkTheReposRefs(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.push(plan), 1)
	sweep, err := NewSweep(fixture.host.ServiceHost(), &SweepDeps{Format2: &testFormat2Gate{purge: sidecar.Format2On}})
	if err != nil {
		t.Fatal(err)
	}
	placed := fixture.clock.Now().Add(-time.Hour)
	result, err := sweep.HoldEndPass(fixture.ctx, "meta-1", fixture.check.repoId, placed, fixture.clock.Now())
	if err != nil || result.RecordCount != 0 {
		t.Fatalf("a hold's pass over format-1 versions: %+v %v", result, err)
	}
	fixture.host.Blobs.SetSettlePassed("seg-1", false)
	if _, err := sweep.TurnOnPass(fixture.ctx, "meta-1", fixture.check.repoId, placed); !errors.Is(err, ErrSweepRetry) {
		t.Fatalf("a pass on an unpassed build: %v", err)
	}
}

// DESIGN-DETAILS 10.2.6: a part's record lists what its versions replaced, whole, with replaced set, and no sweep
// deletes from it, marked or not: its seal's list, which subtracts every part's versions, is the one swept.
func TestSweepIgnoresAPartRecordsList(t *testing.T) {
	fixture := newSweepFixture(t)
	path := checkTestPath("x")
	kept := fixture.segment("a rename's target names it", 700)
	slot := fixture.slot("kept slot")
	partList := sweepTestList(path, [][]byte{kept}, nil, [][]byte{slot})
	partList.Replaced = true
	result, err := fixture.sweepList(partList)
	if err != nil {
		t.Fatal(err)
	}
	if !fixture.segmentStored(kept) || !fixture.slotStored(slot) {
		t.Fatal("a part's replaced list deleted content")
	}
	if result.CandidateCount != 0 || result.DeletedCount != 0 || result.AbsentCount != 0 || result.RecomputedCount != 0 {
		t.Fatalf("a part's list was swept: %+v", result)
	}
	// marked as well: never recomputed, since its seal's list is
	result, err = fixture.sweepList(&protocol.EvsPurgeList{Marked: true, Replaced: true})
	if err != nil || result.RecomputedCount != 0 || result.KeptCount != 0 {
		t.Fatalf("a marked part list: %+v %v", result, err)
	}
	// the seal's list, the same ids less what the target names, deletes
	sealList := sweepTestList(path, [][]byte{kept}, nil, nil)
	result, err = fixture.sweepList(sealList)
	if err != nil || result.DeletedCount != 1 || fixture.segmentStored(kept) {
		t.Fatalf("the seal's list: %+v %v", result, err)
	}
}

// The sweep's DELETEs by pass and result, for a test's reading of QD-855's label.
func sweepTestDeletes(host *sidecartest.FakeHost) map[string]float64 {
	counts := map[string]float64{}
	for _, passLabel := range []string{versionlessSweepPassEvacuation, versionlessSweepPassHoldEnd, versionlessSweepPassTurnOn} {
		for _, outcome := range []string{versionlessSweepDeleted, versionlessSweepAbsent} {
			if value := host.Metrics.Value(versionlessSweepDeletesMetricName, passLabel, outcome); value != 0 {
				counts[passLabel+" "+outcome] = value
			}
		}
	}
	return counts
}

// QD-855: each run counts its DELETEs under its own pass, so §19.8's turn-on row tells the turn-on pass from the
// ordinary sweep: evacuation's sweep of u's record, a hold's end pass and the purge's turn-on pass each delete the same
// content once it is back, and a rerun of the turn-on finds it absent, under turn_on. A turn-on pass on a host that
// still reads observe deletes nothing and counts what it keeps as observed, never as a turn_on DELETE.
func TestSweepCountsEachRunsDeletesUnderItsPass(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	ref := newRecomputeRef(fixture)
	x, y := checkTestPath("x"), checkTestPath("y")
	s1, s2, y1 := fixture.recomputeSegment("s1", 300), fixture.recomputeSegment("s2", 300), fixture.recomputeSegment("y1", 500)
	ref.push(func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{
			{TokenPath: x, EntryVersion: recomputeTestEntry(t, plan, 1, true, nil, 0, recomputeTestKind5(s1))},
			{TokenPath: y, EntryVersion: recomputeTestEntry(t, plan, 1, true, nil, 0, recomputeTestKind5(y1))},
		}
	}, nil)
	vPushId := ref.pushIds[0]
	list := &protocol.EvsPurgeList{Candidates: []*protocol.EvsPurgeCandidate{
		{TokenPath: x.Components(), ReplacedVersion: 1, SegmentIds: [][]byte{s1}},
		{TokenPath: y.Components(), ReplacedVersion: 1, SegmentIds: [][]byte{y1}},
	}}
	u := ref.push(func(plan *sidecar.EvsPushPlan) []*sidecar.EvsPlannedChange {
		return []*sidecar.EvsPlannedChange{
			{TokenPath: x, BaseEntryVersion: 1, EntryVersion: recomputeTestEntry(t, plan, 2, true, &vPushId, 1, recomputeTestKind5(s2))},
			{TokenPath: y, BaseEntryVersion: 1},
		}
	}, list)
	newest := &fakePurgeNewest{}
	newest.name(x, s2)
	restore := func() {
		fixture.recomputeSegment("s1", 300)
		fixture.recomputeSegment("y1", 500)
	}

	lagging, err := NewSweep(fixture.host.ServiceHost(), &SweepDeps{
		Format2: &testFormat2Gate{purge: sidecar.Format2Observe}, Newest: newest, EvsSettings: fixture.settings2(),
	})
	if err != nil {
		t.Fatal(err)
	}
	kept, err := lagging.TurnOnPass(fixture.ctx, "meta-1", fixture.check.repoId, time.Time{})
	if err != nil || kept.RecordCount != 1 || kept.KeptCount != 2 || kept.DeletedCount != 0 {
		t.Fatalf("a turn-on pass under observe: %+v %v", kept, err)
	}
	if got := sweepTestDeletes(fixture.host); len(got) != 0 || fixture.host.Metrics.Value(versionlessObservedMetricName) != 2 {
		t.Fatalf("a turn-on pass under observe counted DELETEs %v, observed %v", got, fixture.host.Metrics.Value(versionlessObservedMetricName))
	}

	sweep := fixture.recomputeSweep(newest, nil)
	evacuated, err := sweep.SweepList(fixture.ctx, fixture.cluster, ref.target(u, ref.records[u-1], list), sidecar.WriteP2RankEvacuation, true, fixture.clock.Now())
	if err != nil || evacuated.DeletedCount != 2 {
		t.Fatalf("evacuation's sweep: %+v %v", evacuated, err)
	}
	restore()
	held, err := sweep.HoldEndPass(fixture.ctx, "meta-1", fixture.check.repoId, fixture.clock.Now().Add(-time.Hour), fixture.clock.Now())
	if err != nil || held.RecordCount != 1 || held.DeletedCount != 2 {
		t.Fatalf("a hold's end pass: %+v %v", held, err)
	}
	restore()
	turnedOn, err := sweep.TurnOnPass(fixture.ctx, "meta-1", fixture.check.repoId, time.Time{})
	if err != nil || turnedOn.RecordCount != 1 || turnedOn.DeletedCount != 2 {
		t.Fatalf("the turn-on pass: %+v %v", turnedOn, err)
	}
	rerun, err := sweep.TurnOnPass(fixture.ctx, "meta-1", fixture.check.repoId, time.Time{})
	if err != nil || rerun.DeletedCount != 0 || rerun.AbsentCount != 2 {
		t.Fatalf("the turn-on pass again: %+v %v", rerun, err)
	}
	if fixture.recomputeStored(s1) || fixture.recomputeStored(y1) || !fixture.recomputeStored(s2) {
		t.Fatal("the passes' deletes are not what they judged")
	}
	want := map[string]float64{
		versionlessSweepPassEvacuation + " " + versionlessSweepDeleted: 2,
		versionlessSweepPassHoldEnd + " " + versionlessSweepDeleted:    2,
		versionlessSweepPassTurnOn + " " + versionlessSweepDeleted:     2,
		versionlessSweepPassTurnOn + " " + versionlessSweepAbsent:      2,
	}
	if got := sweepTestDeletes(fixture.host); !maps.Equal(got, want) {
		t.Fatalf("the deletes series %v, want %v", got, want)
	}
	if got := fixture.host.Metrics.Value(versionlessObservedMetricName); got != 2 {
		t.Fatalf("observed %v, want only the observe pass's 2: purge on counts none", got)
	}
}

// QD-855: under purge: observe the sweep keeps its candidates and counts them in observed_total, in ids, a marked list
// one, a part's list none, deleting nothing and counting no DELETE. Once purge reads on, nothing more is counted
// there.
func TestSweepObserveCountsWhatItKeeps(t *testing.T) {
	fixture := newSweepFixture(t)
	path := checkTestPath("x")
	segment := fixture.segment("observed segment", 100)
	staged := fixture.segment("observed staged", 100)
	slot := fixture.slot("observed slot")
	list := sweepTestList(path, [][]byte{segment}, [][]byte{staged}, [][]byte{slot})
	observed := func() float64 {
		return fixture.host.Metrics.Value(versionlessObservedMetricName)
	}

	fixture.gate.set(sidecar.Format2Observe)
	result, err := fixture.sweepList(list)
	if err != nil || result.KeptCount != 3 || result.DeletedCount != 0 {
		t.Fatalf("observe: %+v %v", result, err)
	}
	if !fixture.segmentStored(segment) || !fixture.segmentStored(staged) || !fixture.slotStored(slot) {
		t.Fatal("observe mode deleted content")
	}
	if got := observed(); got != 3 {
		t.Fatalf("observed %v, want the list's 3 ids", got)
	}
	result, err = fixture.sweepList(&protocol.EvsPurgeList{Marked: true})
	if err != nil || result.KeptCount != 1 {
		t.Fatalf("a marked list: %+v %v", result, err)
	}
	if got := observed(); got != 4 {
		t.Fatalf("observed %v after a marked list, want one more", got)
	}
	// a part's list is never a candidate list, so observe keeps nothing of it
	partList := sweepTestList(path, [][]byte{segment}, nil, nil)
	partList.Replaced = true
	if _, err := fixture.sweepList(partList); err != nil || observed() != 4 {
		t.Fatalf("a part's list: observed %v, %v", observed(), err)
	}
	if got := sweepTestDeletes(fixture.host); len(got) != 0 {
		t.Fatalf("observe counted DELETEs %v", got)
	}

	fixture.gate.set(sidecar.Format2On)
	result, err = fixture.sweepList(list)
	if err != nil || result.DeletedCount != 3 {
		t.Fatalf("on: %+v %v", result, err)
	}
	if got := observed(); got != 4 {
		t.Fatalf("observed %v once purge reads on", got)
	}
}
