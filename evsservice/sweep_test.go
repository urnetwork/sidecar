package evsservice

// EVSB-M10-02's sweep on T2: a committed record's list swept before its batch goes, each candidate HEADed and
// deleted only when present, by a DELETE naming its LastModified; the newest version's names and a hold's placement
// keeping theirs; a re-upload between the HEAD and the DELETE staying; the gates; the retries; the one-off passes'
// gates and their walk of a repo's refs.

import (
	"errors"
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
	return self.sweep.SweepList(self.ctx, cluster, self.repoId, self.refId, self.repo(), 1, list,
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
	if got := fixture.host.Metrics.Value(versionlessSweepDeletesMetricName, versionlessSweepDeleted); got != 3 {
		t.Fatalf("deleted %v", got)
	}
	if got := fixture.host.Metrics.Value(versionlessSweepDeletesMetricName, versionlessSweepAbsent); got != 1 {
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

// Observe mode, a build that has not passed the settle cases, a marked list and a path the reader cannot judge keep
// their content; an unsure clock or a held head is a retry.
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
