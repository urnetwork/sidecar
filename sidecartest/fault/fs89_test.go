package fault

// FS-89's job-side clauses on T2 (EVSB-M10-03; DESIGN-DETAILS 10.6): a drop's window and pending state, a cancel before
// not_before deleting nothing, and --now deleting nothing before evacuation's horizon has passed seen_ms + 12 min nor
// before not_before_ms + 25 min, checked at 25 h, 25 h 12 min and 26 h 12 min on the fake clock with the real horizon
// (NightlyPass.OrphanHorizon over a store whose batches evacuation took). DROP pushes reach the table through
// DropSink as step 8 appends them, since the DROP push route is EVS2-M10-09's; resolve, mark, verify and the deletes
// are stand-ins here (EVSB-M10-04, -05's oracle tested on its own, -06), so these clauses hold the job's lifecycle and
// fences, not the candidates it would delete. The row's push, read and export clauses wait on those tasks.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A repo with one ref and a drop table, its drop job's seams counting what they were asked.
type fs89World struct {
	t       *testing.T
	ctx     context.Context
	clock   *sidecartest.FakeClock
	host    *sidecartest.FakeHost
	paidCtx context.Context
	job     *evsservice.DropJob
	repoId  sidecar.Id
	refId   sidecar.Id
	seams   *fs89Seams
}

// The job's stand-ins: each counts its calls; the deletes answer every candidate deleted.
type fs89Seams struct {
	resolves int
	marks    int
	verifies int
	deletes  int
}

func (self *fs89Seams) Resolve(ctx context.Context, request *evsservice.DropResolveRequest) (*evsservice.DropResolveResult, error) {
	self.resolves += 1
	files := evsservice.NewDropFiles(request.SegmentCluster, request.RepoId, request.JobId, evsservice.DefaultDropSettings())
	cand, err := evsservice.EncodeDropIdFile(evsservice.DropFileCand, request.RepoId, request.JobId, 0, []evsservice.DropScanId{evsservice.DropSegmentId([32]byte{1})})
	if err != nil {
		return nil, err
	}
	return &evsservice.DropResolveResult{}, files.Put(ctx, evsservice.DropFileCand, 0, cand)
}

func (self *fs89Seams) Preview(ctx context.Context, request *evsservice.DropPreviewResolveRequest) (*evsservice.DropPreviewResolveResult, error) {
	return nil, nil
}

func (self *fs89Seams) Mark(ctx context.Context, request *evsservice.DropMarkRequest) (*evsservice.DropMarkResult, error) {
	self.marks += 1
	return &evsservice.DropMarkResult{Snapshot: map[sidecar.Id]uint64{}}, nil
}

func (self *fs89Seams) Verify(ctx context.Context, request *evsservice.DropVerifyRequest) (*evsservice.DropVerifyResult, error) {
	self.verifies += 1
	return &evsservice.DropVerifyResult{Snapshot: request.Marked}, nil
}

func (self *fs89Seams) Delete(ctx context.Context, request *evsservice.DropDeleteRequest) (*evsservice.DropDeleteResult, error) {
	self.deletes += 1
	progress := &evsservice.DropDeleteProgress{}
	if 0 < len(request.Candidates) {
		last := request.Candidates[len(request.Candidates)-1]
		progress.Cursor = evsservice.DropCursor{Sequence: last.Cursor.Sequence, Row: last.Cursor.Row + 1}
	}
	if _, err := request.Checkpoint(ctx, progress); err != nil {
		return nil, err
	}
	return &evsservice.DropDeleteResult{Progress: progress}, nil
}

func (self *fs89Seams) LockStanding(networkId sidecar.Id, repoId sidecar.Id) (bool, evsservice.EvsAuthAnswer) {
	return false, evsservice.EvsAuthAllowed
}

// The format2 gate with drop on.
type fs89DropOn struct{}

func (self fs89DropOn) Admits(networkId sidecar.Id) bool { return true }
func (self fs89DropOn) PurgeMode() sidecar.Format2Mode   { return sidecar.Format2Observe }
func (self fs89DropOn) DropMode() sidecar.Format2Mode    { return sidecar.Format2On }

func newFs89World(t *testing.T) *fs89World {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	grant, err := host.Budget.AdmitP1(ctx, "meta-1", [16]byte{1}, sidecar.WriteCost{ImmediateByteCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(grant.Close)
	world := &fs89World{t: t, ctx: ctx, clock: clock, host: host, paidCtx: grant.Context(), repoId: sidecar.Id{0x89, 1}, refId: sidecar.Id{0x89, 2}, seams: &fs89Seams{}}
	cluster, _ := host.Blobs.Cluster("meta-1")
	repoBytes, _ := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_ACTIVE, Format: 2,
		NetworkId: sidecar.Id{0x89, 3}.Bytes(),
	})
	if _, err := cluster.PutIfNoneMatch(world.paidCtx, evsservice.RepoKey(world.repoId), repoBytes, nil); err != nil {
		t.Fatal(err)
	}
	// the DROP is the ref's newest version, so no cancel stands after it
	headBytes, _ := proto.Marshal(&protocol.EvsHead{
		Version: 7, Chain: make([]byte, 32), PushId: sidecar.Id{0x89, 4}.Bytes(), RefKind: uint32(protocol.EvsRefKind_EVS_REF_SHARED),
		RefMode: uint32(protocol.EvsRefMode_EVS_REF_FILE), PathEpoch: &protocol.EvsPathEpoch{Current: 1}, WindowBaseChain: make([]byte, 32),
	})
	if _, err := cluster.PutIfNoneMatch(world.paidCtx, evsservice.HeadKey(world.repoId, world.refId), headBytes, nil); err != nil {
		t.Fatal(err)
	}
	job, err := evsservice.NewDropJob(host.ServiceHost(), &evsservice.DropJobDeps{
		Resolver: world.seams, Marker: world.seams, Verifier: world.seams, Deleter: world.seams, Locks: world.seams, Format2: fs89DropOn{},
	})
	if err != nil {
		t.Fatal(err)
	}
	world.job = job
	return world
}

// The segment cluster's capacity known and well under the pause line, as §19.6's hdd loop publishes it.
func (self *fs89World) hddKnown() {
	figures, err := json.Marshal(&evsservice.HddFigures{ClusterId: "seg-1", TimeMs: self.clock.Now().UnixMilli(), DriveOpsPerSecond: 10, CapacityOps: 1000})
	if err != nil {
		self.t.Fatal(err)
	}
	if err := self.host.Redis.HashSet(self.ctx, "{nvb_seg-1}", map[string][]byte{"hdd": figures}); err != nil {
		self.t.Fatal(err)
	}
}

// Appends a DROP committed at version 7 now, with seen_ms the clock after its 200.
func (self *fs89World) appendDrop(label byte, notBefore time.Time) {
	commit := &evsservice.DropCommit{
		ClusterId: "meta-1", RepoId: self.repoId, RefId: self.refId, PushId: sidecar.Id{0x89, 5, label}, Version: 7,
		Place: &protocol.EvsPlace{Minute: evsservice.BatchMinute(self.clock.Now()), Instance: 1, Seq: 1, Length: 100},
		Body:  &protocol.EvsDropHistory{DropId: sidecar.Id{0x89, 6, label}.Bytes(), Action: 1, NotBeforeMs: notBefore.UnixMilli()},
	}
	if err := self.job.Table().Append(self.paidCtx, commit, self.clock.Now().UnixMilli()); err != nil {
		self.t.Fatal(err)
	}
}

func (self *fs89World) run() *evsservice.DropJobResult {
	self.hddKnown()
	result, err := self.job.Run(self.ctx, "meta-1", self.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	return result
}

func (self *fs89World) state(label byte) evsservice.DropState {
	cluster, _ := self.host.Blobs.Cluster("meta-1")
	read, err := self.job.Table().Read(self.ctx, cluster, self.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	entry := read.State.Drop(sidecar.Id{0x89, 6, label})
	if entry == nil {
		self.t.Fatalf("no entry for drop %d", label)
	}
	return entry.State
}

// --now: nothing before not_before_ms + 25 min, and no mark or delete until the horizon has passed seen_ms + 12 min,
// which a store with no batch left brings at 25 h 12 min after the commit; at 25 h the job waits in phase horizon.
func TestFs89NowWaitsForTheHorizon(t *testing.T) {
	world := newFs89World(t)
	commit := world.clock.Now()
	world.appendDrop(1, commit)
	world.clock.AdvanceTo(commit.Add(24 * time.Minute))
	if result := world.run(); world.seams.resolves != 0 || result.Waiting != evsservice.DropWaitStart {
		t.Fatalf("a --now drop started before not_before_ms + 25 min: %+v", result)
	}
	world.clock.AdvanceTo(commit.Add(25 * time.Hour))
	result := world.run()
	if world.seams.resolves != 1 || world.seams.marks != 0 || world.seams.deletes != 0 || result.Waiting != evsservice.DropWaitHorizon {
		t.Fatalf("at 25 h: %+v, %+v", result, world.seams)
	}
	if world.state(1) != evsservice.DropStateExecuting {
		t.Fatal("a waiting drop does not read executing")
	}
	// woken at retry_ms, 25 h 12 min after the commit, the horizon has passed seen_ms + 12 min
	if !result.Next.Equal(commit.Add(25*time.Hour + 12*time.Minute)) {
		t.Fatalf("woken at %s, want 25 h 12 min after the commit", result.Next.Sub(commit))
	}
	world.clock.AdvanceTo(commit.Add(25*time.Hour + 12*time.Minute))
	result = world.run()
	if world.seams.marks != 1 || world.seams.deletes != 1 || !result.Ended || world.state(1) != evsservice.DropStateDone {
		t.Fatalf("at 25 h 12 min: %+v, %+v", result, world.seams)
	}
	// a second --now drop taken at 26 h 12 min runs straight through: its bound has passed
	second := world.clock.Now()
	world.appendDrop(2, second)
	world.clock.AdvanceTo(second.Add(26*time.Hour + 12*time.Minute))
	if result := world.run(); !result.Ended || world.state(2) != evsservice.DropStateDone {
		t.Fatalf("at 26 h 12 min: %+v", result)
	}
}

// The window: a 7-day drop stays pending, listed as pending, until not_before_ms + 25 min, and a cancel before
// not_before ends it cancelled, deleting nothing.
func TestFs89WindowPendingAndCancel(t *testing.T) {
	world := newFs89World(t)
	notBefore := world.clock.Now().Add(7 * 24 * time.Hour)
	world.appendDrop(1, notBefore)
	world.appendDrop(2, notBefore)
	world.clock.AdvanceTo(notBefore.Add(-time.Hour))
	cancel := &evsservice.DropCommit{
		ClusterId: "meta-1", RepoId: world.repoId, RefId: world.refId, PushId: sidecar.Id{0x89, 7}, Version: 8,
		Place: &protocol.EvsPlace{Minute: evsservice.BatchMinute(world.clock.Now()), Instance: 1, Seq: 2, Length: 100},
		Body:  &protocol.EvsDropHistory{DropId: sidecar.Id{0x89, 8}.Bytes(), Action: 2, CancelsDropId: sidecar.Id{0x89, 6, 2}.Bytes(), CancelsVersion: 7},
	}
	if err := world.job.Table().Append(world.paidCtx, cancel, world.clock.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	cluster, _ := world.host.Blobs.Cluster("meta-1")
	read, err := world.job.Table().Read(world.ctx, cluster, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	listing := evsservice.DropStatuses(read.State)
	states := map[byte]protocol.EvsDropState{}
	for _, status := range listing.Drops {
		states[status.DropId[2]] = status.State
	}
	if states[1] != protocol.EvsDropState_EVS_DROP_PENDING || states[2] != protocol.EvsDropState_EVS_DROP_CANCELLED {
		t.Fatalf("the listing: %v", states)
	}
	world.clock.AdvanceTo(notBefore.Add(25 * time.Minute))
	world.run()
	if world.state(1) != evsservice.DropStateDone || world.state(2) != evsservice.DropStateCancelled || world.seams.resolves != 1 {
		t.Fatalf("after the window: %d and %d, %+v", world.state(1), world.state(2), world.seams)
	}
}
