package evsservice

// EVSB-M10-02's evs.sweep job on T2: its args and their refusals; a hold's end rereading its repos only once the hold
// has ended, deleting what the hold kept; a network's hold and the turn-on scanning each cluster's repo/ page by page,
// queueing the repos they cover.

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Each run's args read back as written, and args of any other shape are refused.
func TestEvsSweepArgsRoundTripAndRefuseOtherShapes(t *testing.T) {
	networkId, repoId := testId("sweep network"), testId("sweep repo")
	good := []*evsSweepArgs{
		{run: evsSweepRunStart, kind: evsSweepKindHoldEnd, networkId: networkId, placeMs: 1000, endMs: 2000},
		{run: evsSweepRunStart, kind: evsSweepKindHoldEnd, networkId: networkId, repoIds: []sidecar.Id{repoId, networkId}, placeMs: 1000, endMs: 2000},
		{run: evsSweepRunStart, kind: evsSweepKindTurnOn},
		{run: evsSweepRunScan, kind: evsSweepKindHoldEnd, clusterId: "meta-1", networkId: networkId, placeMs: 1000, endMs: 2000, startAfter: "repo/x"},
		{run: evsSweepRunScan, kind: evsSweepKindTurnOn, clusterId: "meta-1"},
		{run: evsSweepRunRepo, kind: evsSweepKindTurnOn, clusterId: "meta-1", repoIds: []sidecar.Id{repoId}},
	}
	for _, args := range good {
		parsed, err := parseEvsSweepArgs(args.encode())
		if err != nil {
			t.Fatalf("%+v: %v", args, err)
		}
		if string(parsed.encode()) != string(args.encode()) {
			t.Fatalf("%+v read back as %+v", args, parsed)
		}
	}
	bad := []*evsSweepArgs{
		{run: "other", kind: evsSweepKindTurnOn},
		{run: evsSweepRunStart, kind: "other"},
		{run: evsSweepRunStart, kind: evsSweepKindHoldEnd, placeMs: 1000, endMs: 2000},
		{run: evsSweepRunStart, kind: evsSweepKindHoldEnd, networkId: networkId, placeMs: 2000, endMs: 2000},
		{run: evsSweepRunStart, kind: evsSweepKindTurnOn, networkId: networkId},
		{run: evsSweepRunScan, kind: evsSweepKindTurnOn},
		{run: evsSweepRunScan, kind: evsSweepKindHoldEnd, clusterId: "meta-1"},
		{run: evsSweepRunRepo, kind: evsSweepKindTurnOn, clusterId: "meta-1"},
		{run: evsSweepRunRepo, kind: evsSweepKindTurnOn, clusterId: "meta-1", repoIds: []sidecar.Id{repoId, repoId}},
	}
	for _, args := range bad {
		if _, err := parseEvsSweepArgs(args.encode()); !errors.Is(err, ErrEvsSweepArgs) {
			t.Fatalf("%+v: %v", args, err)
		}
	}
	if _, err := parseEvsSweepArgs([]byte("start\nturn_on")); !errors.Is(err, ErrEvsSweepArgs) {
		t.Fatalf("short args: %v", err)
	}
	if _, err := EvsSweepHoldEndTaskRequest(&sidecar.HoldRecord{NetworkId: networkId, PlaceTime: time.UnixMilli(2000)}, time.UnixMilli(1000)); !errors.Is(err, ErrEvsSweepArgs) {
		t.Fatalf("a hold ending before its placement: %v", err)
	}
}

// evs.sweep bound in the fixture's queue, each run building its sweep from deps.
func (self *evacuateFixture) registerSweepTask(deps *SweepDeps, results *[]*EvsSweepRunResult) {
	self.host.Tasks.Register(EvsSweepTaskName, func(ctx context.Context, args []byte) error {
		result, err := RunSweepTask(ctx, self.host.ServiceHost(), deps, args)
		if result != nil && results != nil {
			*results = append(*results, result)
		}
		return err
	})
}

// §11.13's sweep row: content a hold kept at the sweep is deleted by the hold's end pass, which runs no sooner than
// the end, reading the repo's flagged versions from 26 h before the placement.
func TestEvsSweepHoldEndDeletesWhatTheHoldKept(t *testing.T) {
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
	fixture.clock.Advance(time.Minute)
	hold := &sidecar.HoldRecord{
		NetworkId: fixture.check.networkId, CaseId: testId("sweep task case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeRepos(fixture.check.repoId), PlaceTime: fixture.clock.Now(), ExpireTime: fixture.clock.Now().Add(time.Hour),
	}
	if err := sidecartest.PlaceHold(fixture.ctx, fixture.host.Blobs, hold); err != nil {
		t.Fatal(err)
	}
	deps := &SweepDeps{Format2: &testFormat2Gate{purge: sidecar.Format2On}, Newest: newest, EvsSettings: fixture.settings2()}
	sweep, err := NewSweep(fixture.host.ServiceHost(), deps)
	if err != nil {
		t.Fatal(err)
	}
	// evacuation's sweep of u's record: the hold keeps both
	held, err := sweep.SweepList(fixture.ctx, fixture.cluster, ref.target(u, ref.records[u-1], list), sidecar.WriteP2RankEvacuation, true, fixture.clock.Now())
	if err != nil || held.HeldCount != 2 || !fixture.recomputeStored(s1) || !fixture.recomputeStored(y1) {
		t.Fatalf("under the hold: %+v %v", held, err)
	}

	results := []*EvsSweepRunResult{}
	fixture.registerSweepTask(deps, &results)
	request, err := EvsSweepHoldEndTaskRequest(hold, hold.ExpireTime)
	if err != nil {
		t.Fatal(err)
	}
	if !request.RunAt.Equal(hold.ExpireTime) {
		t.Fatalf("a hold's pass due at %v, before its end %v", request.RunAt, hold.ExpireTime)
	}
	if err := fixture.host.Tasks.Schedule(fixture.ctx, request); err != nil {
		t.Fatal(err)
	}
	if ran, _ := fixture.host.Tasks.RunDue(fixture.ctx); ran != 0 {
		t.Fatal("a hold's pass ran before its end")
	}
	fixture.clock.Advance(time.Hour + time.Second)
	for i := 0; i < 3; i += 1 {
		if _, err := fixture.host.Tasks.RunDue(fixture.ctx); err != nil {
			t.Fatal(err)
		}
	}
	if fixture.recomputeStored(s1) || fixture.recomputeStored(y1) || !fixture.recomputeStored(s2) {
		t.Fatal("the hold's end did not delete what it kept, or took what the newest version names")
	}
	swept := 0
	for _, result := range results {
		if result.Swept != nil {
			swept += result.Swept.DeletedCount
		}
	}
	if swept != 2 {
		t.Fatalf("passes deleted %d", swept)
	}
}

// A repo's hold pass queued before the end, as a caller could, waits: it retries and deletes nothing.
func TestEvsSweepHoldEndPassWaitsForTheEnd(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	end := fixture.clock.Now().Add(time.Hour)
	args := &evsSweepArgs{run: evsSweepRunRepo, kind: evsSweepKindHoldEnd, clusterId: "meta-1", repoIds: []sidecar.Id{fixture.check.repoId},
		placeMs: fixture.clock.Now().UnixMilli(), endMs: end.UnixMilli()}
	if _, err := RunSweepTask(fixture.ctx, fixture.host.ServiceHost(), &SweepDeps{Format2: &testFormat2Gate{purge: sidecar.Format2On}}, args.encode()); !errors.Is(err, ErrSweepRetry) {
		t.Fatalf("before the end: %v", err)
	}
}

// A network's hold and the turn-on scan each metadata cluster's repo/ a page at a time: the network's repos, or those
// at format 2, get a pass each, a shredded one none, and each page queues the next.
func TestEvsSweepScansQueueTheReposTheyCover(t *testing.T) {
	fixture := newEvacuateFixture(t, nil)
	other := testId("sweep other network")
	putRepo := func(label string, networkId sidecar.Id, format uint32, state protocol.EvsRepoState) sidecar.Id {
		repoId := testId(label)
		repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
			RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: state, Format: format, NetworkId: networkId.Bytes(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.cluster.PutIfNoneMatch(fixture.ctx, RepoKey(repoId), repoBytes, nil); err != nil {
			t.Fatal(err)
		}
		return repoId
	}
	mine2 := putRepo("sweep mine 2", fixture.check.networkId, 2, protocol.EvsRepoState_EVS_REPO_ACTIVE)
	theirs2 := putRepo("sweep theirs 2", other, 2, protocol.EvsRepoState_EVS_REPO_ACTIVE)
	putRepo("sweep shredded 2", fixture.check.networkId, 2, protocol.EvsRepoState_EVS_REPO_SHREDDED)
	deps := &SweepDeps{Format2: &testFormat2Gate{purge: sidecar.Format2On}, Settings: &SweepSettings{ListLimit: 1, RecomputeVersionCount: 1}}
	// the passes themselves are not this test's: only the queue
	run := func(request *sidecar.TaskRequest) []string {
		repoKeys := []string{}
		queue := []*sidecar.TaskRequest{request}
		for len(queue) != 0 {
			next := queue[0]
			queue = queue[1:]
			parsed, err := parseEvsSweepArgs(next.Args)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.run == evsSweepRunRepo {
				repoKeys = append(repoKeys, parsed.kind+":"+sidecar.EvsKeyId(parsed.repoIds[0]))
				continue
			}
			before := len(fixture.host.Tasks.AllRequests())
			if _, err := RunSweepTask(fixture.ctx, fixture.host.ServiceHost(), deps, next.Args); err != nil {
				t.Fatal(err)
			}
			queue = append(queue, fixture.host.Tasks.AllRequests()[before:]...)
		}
		return repoKeys
	}
	holdRequest, err := EvsSweepHoldEndTaskRequest(&sidecar.HoldRecord{
		NetworkId: fixture.check.networkId, CaseId: testId("sweep scan case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: fixture.clock.Now().Add(-time.Hour), ExpireTime: fixture.clock.Now(),
	}, fixture.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	held := run(holdRequest)
	// the fixture's own repo, at format 1, is of the network too
	want := map[string]bool{evsSweepKindHoldEnd + ":" + sidecar.EvsKeyId(mine2): true, evsSweepKindHoldEnd + ":" + sidecar.EvsKeyId(fixture.check.repoId): true}
	if len(held) != len(want) {
		t.Fatalf("a network's hold queued %v", held)
	}
	for _, key := range held {
		if !want[key] {
			t.Fatalf("a network's hold queued %v", held)
		}
	}
	turnedOn := run(EvsSweepTurnOnTaskRequest())
	want = map[string]bool{evsSweepKindTurnOn + ":" + sidecar.EvsKeyId(mine2): true, evsSweepKindTurnOn + ":" + sidecar.EvsKeyId(theirs2): true}
	if len(turnedOn) != len(want) {
		t.Fatalf("the turn-on queued %v", turnedOn)
	}
	for _, key := range turnedOn {
		if !want[key] {
			t.Fatalf("the turn-on queued %v", turnedOn)
		}
	}
}
