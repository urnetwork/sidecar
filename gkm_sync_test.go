//go:build !sidecar_http

// Group sync on the fake gkm (KEYS-M2-23; §22.5's KF5 and KF7 rows, DESIGN-DETAILS 6.6's wait rows): replay at 100
// epochs behind and a resync at 101, a pruned device resyncing from the sealed GroupInfo, a resync and a read_only
// leaf's self-update waiting under R3 with their H2 ask, the 7-day and 30-day self-update boundary at 50 and 51
// leaves, a last-resort join's immediate path, and KF7 with gkm stopped.

package sidecar_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// count path-only commits by a device, each its own epoch at gkm.
func (self *gkmFlowWorld) selfUpdates(device *gkmWorldDevice, count int) {
	self.t.Helper()
	for index := 0; index < count; index += 1 {
		if err := self.flows[device].client.SelfUpdate(self.ctx, self.repoId); err != nil {
			self.t.Fatalf("%s's self-update %d: %v", device.label, index, err)
		}
	}
}

// A device's epoch pin.
func (self *gkmFlowWorld) pinnedEpoch(device *gkmWorldDevice) uint64 {
	self.t.Helper()
	_, epoch, _, err := self.flows[device].client.TestPins(self.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	return epoch
}

// KF5's boundary: 100 epochs behind, a leaf replays each commit in order and uploads nothing; 101 behind it resyncs
// from the newest epoch's sealed GroupInfo by one external commit that removes its own old leaf, which every other
// leaf processes and adopts.
func TestALeafReplaysAHundredEpochsAndResyncsPastThem(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	b := world.flows[world.b]
	world.selfUpdates(world.a, 100)
	if err := b.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if world.pinnedEpoch(world.b) != 101 || world.engineGroup(world.b).Epoch() != 101 || world.store.callCount("CommitEpoch") != 100 {
		t.Fatalf("100 epochs behind: at epoch %d after %d commits", world.pinnedEpoch(world.b), world.store.callCount("CommitEpoch"))
	}

	// c is now 101 behind
	world.selfUpdates(world.a, 1)
	c := world.flows[world.c]
	if err := c.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 103 || world.pinnedEpoch(world.c) != 103 || world.engineGroup(world.c).Epoch() != 103 {
		t.Fatalf("101 epochs behind: gkm at epoch %d, the leaf at %d", newest, world.pinnedEpoch(world.c))
	}
	epochs := world.store.groupEpochs[world.groupId]
	if !sidecar.GkmCommitIsExternal(epochs[103].GetCommit()) || len(epochs[103].GetGenWrap()) == 0 || len(epochs[103].GetSealedGroupInfo()) == 0 {
		t.Errorf("the resync's epoch is no external commit with its GenWrap and GroupInfo")
	}
	for _, device := range []*gkmWorldDevice{world.a, world.b} {
		if err := world.flows[device].client.SyncRepo(world.ctx, world.repoId); err != nil {
			t.Fatalf("%s processes the resync: %v", device.label, err)
		}
		if labels := world.rosterLabels(world.engineGroup(device)); strings.Join(labels, "") != "abcpx" || world.pinnedEpoch(device) != 103 {
			t.Errorf("%s after the resync: %v at epoch %d", device.label, labels, world.pinnedEpoch(device))
		}
	}
	for _, device := range world.devices {
		if alarms := world.flows[device].alarms; len(alarms) != 0 {
			t.Errorf("%s alarmed: %+v", device.label, alarms[0])
		}
	}
	// the resync is a fresh path: its self-update is not due
	if due, err := c.client.SelfUpdateDue(world.repoId); err != nil || due {
		t.Errorf("a self-update due right after a resync: %v", err)
	}
}

// A pruned device resyncs: gkm no longer holds the epochs after its own, so nothing replays, and it joins from the
// newest epoch's GroupInfo.
func TestAPrunedDeviceResyncs(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.selfUpdates(world.a, 3)
	world.store.prunedBelowEpoch = 4
	c := world.flows[world.c]
	if err := c.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if world.pinnedEpoch(world.c) != 5 || world.engineGroup(world.c).Epoch() != 5 {
		t.Fatalf("the pruned leaf is at epoch %d", world.pinnedEpoch(world.c))
	}
	if err := world.flows[world.a].client.SyncRepo(world.ctx, world.repoId); err != nil || world.pinnedEpoch(world.a) != 5 {
		t.Errorf("a leaf processes the resync: %v", err)
	}
	// a device its state no longer seats does not resync: it awaits a re-add
	world.selfUpdates(world.a, 1)
	world.store.prunedBelowEpoch = 6
	world.revoke(world.x)
	world.stateFor()
	x := world.flows[world.x]
	commits := world.store.callCount("CommitEpoch")
	if err := x.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatalf("a revoked device's sync: %v", err)
	}
	if world.store.callCount("CommitEpoch") != commits || world.pinnedEpoch(world.x) != 1 {
		t.Errorf("a device that reads nothing resynced")
	}
}

// TestAResyncWaitsWhileADroppedLeafStands: KF5's external commit removes only its own old leaf, so while the newest
// tree holds a revoked leaf the resync waits and asks H2, at most once a LateAskInterval; once a writer leaf's Remove
// and rotation have landed and a holder has delivered the new generation late, it lands, carrying that generation.
func TestAResyncWaitsWhileADroppedLeafStands(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	c := world.flows[world.c]
	world.selfUpdates(world.a, 2)
	world.store.prunedBelowEpoch = 3
	world.revoke(world.x)
	world.stateFor()

	commits := world.store.callCount("CommitEpoch")
	for count := 0; count < 2; count += 1 {
		if err := c.client.SyncRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmDroppedLeafStands) || !errors.Is(err, sidecar.ErrGkmWait) {
			t.Fatalf("a resync onto a tree that holds a dropped leaf: %v", err)
		}
	}
	if world.store.callCount("CommitEpoch") != commits || world.pinnedEpoch(world.c) != 1 {
		t.Fatalf("the waiting resync committed")
	}
	if !slices.Equal(world.store.groupInfoWants, []uint64{4}) {
		t.Errorf("H2's asks within a LateAskInterval: %v", world.store.groupInfoWants)
	}
	world.advance(sidecar.DefaultGkmSettings().LateAskInterval)
	if err := c.client.SyncRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmDroppedLeafStands) {
		t.Fatal(err)
	}
	if !slices.Equal(world.store.groupInfoWants, []uint64{4, 4}) {
		t.Errorf("H2's ask an interval later: %v", world.store.groupInfoWants)
	}

	// the writer leaf so hinted commits the Remove and rotates
	if err := a.client.AnswerWant(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 4 || world.store.newestGeneration(world.groupId) != 2 {
		t.Fatalf("after the writer's answer: epoch %d, generation %d", newest, world.store.newestGeneration(world.groupId))
	}
	// the new generation went by leaf_wrap under an epoch the resyncing leaf does not hold: it asks late
	if err := c.client.SyncRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Fatalf("a resync with no key of the newest generation: %v", err)
	}
	if len(world.store.lateAsks) != 1 {
		t.Fatalf("late asks: %v", world.store.lateAsks)
	}
	if err := a.client.DeliverLate(world.ctx, world.repoId, gkmHintRecipient(world.c)); err != nil {
		t.Fatal(err)
	}
	if err := c.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if world.pinnedEpoch(world.c) != 5 || strings.Join(world.rosterLabels(world.engineGroup(world.c)), "") != "abcp" {
		t.Fatalf("the resync after the Remove: epoch %d, tree %v", world.pinnedEpoch(world.c), world.rosterLabels(world.engineGroup(world.c)))
	}
	if key, err := c.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
		t.Errorf("the resynced leaf's key: %v", err)
	}
	// every remaining leaf replays to it and adopts it; the resync's GenWrap carries generation 2, which a leaf
	// that had no delivery of it takes from there
	world.store.prunedBelowEpoch = 0
	for _, device := range []*gkmWorldDevice{world.a, world.b, world.p} {
		if err := world.flows[device].client.SyncRepo(world.ctx, world.repoId); err != nil || world.pinnedEpoch(device) != 5 {
			t.Errorf("%s after the resync: %v", device.label, err)
		}
		if alarms := world.flows[device].alarms; len(alarms) != 0 {
			t.Errorf("%s alarmed: %+v", device.label, alarms[0])
		}
		if key, err := world.flows[device].client.CurrentRepoKey(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
			t.Errorf("%s's key after the resync's epoch: %v", device.label, err)
		}
	}
	if _, err := world.flows[world.x].client.RepoKey(world.ctx, world.repoId, 2); !errors.Is(err, sidecar.ErrGkmKeyMissing) && !errors.Is(err, sidecar.ErrGkmResyncNeeded) {
		t.Errorf("the removed leaf's generation 2: %v", err)
	}
}

// R3's wait for a read_only leaf's due self-update: it commits nothing while a dropped leaf stands, asks H2, and
// commits once the writer leaf's Remove has landed.
func TestAReadOnlyLeafsDueSelfUpdateWaitsAndAsks(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	p := world.flows[world.p]
	world.advance(sidecar.DefaultGkmSettings().SelfUpdateInterval)
	world.revoke(world.x)
	world.stateFor()

	if due, err := p.client.SelfUpdateDue(world.repoId); err != nil || !due {
		t.Fatalf("a self-update 7 days on: %v %v", due, err)
	}
	if err := p.client.RunSelfUpdate(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmDroppedLeafStands) {
		t.Fatalf("a read_only leaf's self-update while a dropped leaf stands: %v", err)
	}
	if world.store.callCount("CommitEpoch") != 0 || !slices.Equal(world.store.groupInfoWants, []uint64{2}) || len(p.alarms) != 0 {
		t.Fatalf("the waiting leaf committed, did not ask, or alarmed: wants %v", world.store.groupInfoWants)
	}
	if err := world.flows[world.a].client.AnswerWant(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if err := p.client.RunSelfUpdate(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 3 || world.pinnedEpoch(world.p) != 3 {
		t.Errorf("the self-update after the Remove: gkm at epoch %d", newest)
	}
	if due, err := p.client.SelfUpdateDue(world.repoId); err != nil || due {
		t.Errorf("a self-update due right after one: %v", err)
	}
	if err := world.flows[world.a].client.SyncRepo(world.ctx, world.repoId); err != nil || len(world.flows[world.a].alarms) != 0 {
		t.Errorf("a member adopts the read_only leaf's self-update: %v", err)
	}
}

// Grows the world's group to leafCount leaves on the creator's engine, each new leaf an admitted reader, and moves
// the creator's epoch pin to it.
func (self *gkmFlowWorld) growTo(leafCount int) {
	self.t.Helper()
	added := []*gkmWorldDevice{}
	for len(self.a.group.Roster())+len(added) < leafCount {
		device := self.admit("n" + string(rune('A'+len(added)/26)) + string(rune('a'+len(added)%26)))
		self.grant(false, device)
		added = append(added, device)
	}
	view := self.stateFor()
	staged := self.stage(self.a, 1, view.Pin(), added, nil)
	group, err := staged.Adopt()
	if err != nil {
		self.t.Fatal(err)
	}
	self.a.group = group
	if err := self.flows[self.a].client.TestHoldEpoch(self.repoId, group, gkmWorldHeader(self.t, 1, view.Pin())); err != nil {
		self.t.Fatal(err)
	}
	// gkm's side of the epoch: the catch-up's read finds nothing past it
	self.store.groupEpochs[self.groupId] = append(self.store.groupEpochs[self.groupId], &protocol.GkmEpochObject{
		Commit: staged.Message(), Header: &protocol.GkmCommitHeader{Generation: 1, Auth: view.Pin()}, Uploader: self.a.id.Bytes(), GroupInfoGeneration: 1,
	})
}

// The self-update boundary: at 50 leaves a leaf's path is due 7 days after its last and not a moment before; at 51
// leaves it is due at 30 days; a due one is one path-only commit, after which none is due.
func TestSelfUpdatesAreDueAtSevenDaysAndAtThirtyAboveFiftyLeaves(t *testing.T) {
	settings := sidecar.DefaultGkmSettings()
	for _, leafCount := range []int{50, 51} {
		world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
		world.growTo(leafCount)
		a := world.flows[world.a]
		if count := len(world.engineGroup(world.a).Roster()); count != leafCount {
			t.Fatalf("a tree of %d leaves", count)
		}
		interval := settings.SelfUpdateInterval
		passed := time.Duration(0)
		if settings.LargeGroupLeafCount < leafCount {
			interval = settings.SelfUpdateIntervalLarge
			passed = settings.SelfUpdateInterval
			world.advance(passed)
			if due, err := a.client.SelfUpdateDue(world.repoId); err != nil || due {
				t.Fatalf("%d leaves: a self-update due at 7 days: %v", leafCount, err)
			}
		}
		world.advance(interval - passed - time.Millisecond)
		if due, err := a.client.SelfUpdateDue(world.repoId); err != nil || due {
			t.Fatalf("%d leaves: a self-update due before %s: %v", leafCount, interval, err)
		}
		if err := a.client.RunSelfUpdate(world.ctx, world.repoId); err != nil || world.store.callCount("CommitEpoch") != 0 {
			t.Fatalf("%d leaves: a self-update committed before it was due: %v", leafCount, err)
		}
		world.advance(time.Millisecond)
		if due, err := a.client.SelfUpdateDue(world.repoId); err != nil || !due {
			t.Fatalf("%d leaves: no self-update due at %s: %v", leafCount, interval, err)
		}
		if err := a.client.RunSelfUpdate(world.ctx, world.repoId); err != nil {
			t.Fatalf("%d leaves: %v", leafCount, err)
		}
		if world.store.callCount("CommitEpoch") != 1 {
			t.Fatalf("%d leaves: %d commits for one self-update", leafCount, world.store.callCount("CommitEpoch"))
		}
		newest, _ := world.store.newestEpoch(world.groupId)
		object := world.store.groupEpochs[world.groupId][newest]
		if header, err := sidecar.ParseMlsHeader(object.GetCommit()); err != nil || header.External != nil || len(object.GetGenWrap()) == 0 {
			t.Errorf("%d leaves: the self-update is no member's commit with its GenWrap: %v", leafCount, err)
		}
		// above 16 leaves the GroupInfo rides group-info, not the epoch
		if len(object.GetSealedGroupInfo()) != 0 || world.store.groupInfos[world.groupId].GetEpoch() != newest {
			t.Errorf("%d leaves: the GroupInfo above 16 leaves", leafCount)
		}
		if due, err := a.client.SelfUpdateDue(world.repoId); err != nil || due {
			t.Errorf("%d leaves: a self-update due right after one: %v", leafCount, err)
		}
		world.advance(interval - time.Millisecond)
		if due, err := a.client.SelfUpdateDue(world.repoId); err != nil || due {
			t.Errorf("%d leaves: the next self-update due early: %v", leafCount, err)
		}
	}
}

// TestALastResortJoinSelfUpdatesAtOnce: a device added through its last-resort KeyPackage owes a path-only commit
// at its first opportunity, whatever the interval, and reports the join for upkeep to replace the package; a device
// added through a one-time KeyPackage owes none.
func TestALastResortJoinSelfUpdatesAtOnce(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	d := world.admitReader("d", 0)
	world.store.publishKeyPackages(d, 0, true)
	e := world.admitReader("e", 1)
	world.stateFor()
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	for _, device := range []*gkmWorldDevice{d, e} {
		if joined, err := world.flows[device].client.JoinWelcomes(world.ctx); err != nil || len(joined) != 1 {
			t.Fatalf("%s joins: %v %v", device.label, joined, err)
		}
	}
	if due, err := world.flows[e].client.SelfUpdateDue(world.repoId); err != nil || due || !world.flows[e].client.LastResortJoinedAt().IsZero() {
		t.Errorf("a one-time KeyPackage's join owes a path: %v", err)
	}
	joiner := world.flows[d]
	if due, err := joiner.client.SelfUpdateDue(world.repoId); err != nil || !due {
		t.Fatalf("a last-resort join owes no path: %v", err)
	}
	if joinedAt := joiner.client.LastResortJoinedAt(); !joinedAt.Equal(world.clock.Now()) {
		t.Errorf("the join reported to upkeep at %s", joinedAt)
	}
	commits := world.store.callCount("CommitEpoch")
	if err := joiner.client.RunSelfUpdate(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	newest, _ := world.store.newestEpoch(world.groupId)
	object := world.store.groupEpochs[world.groupId][newest]
	if world.store.callCount("CommitEpoch") != commits+1 || string(object.GetUploader()) != string(d.id.Bytes()) {
		t.Fatalf("the joiner's first commit is not its own path")
	}
	if due, err := joiner.client.SelfUpdateDue(world.repoId); err != nil || due {
		t.Errorf("the path is still owed: %v", err)
	}
	// the report survives a restart, for an upkeep pass that had not run yet
	joiner.restart()
	if joinedAt := joiner.client.LastResortJoinedAt(); !joinedAt.Equal(world.clock.Now()) {
		t.Errorf("the join's report after a restart: %s", joinedAt)
	}
	if err := a.client.SyncRepo(world.ctx, world.repoId); err != nil || len(a.alarms) != 0 {
		t.Errorf("a member adopts the joiner's path: %v", err)
	}
}

// KF7, gkm stopped: cached keys serve reads, a writer goes on sealing while its newest generation covers its state,
// and a removal still blocks writes; catch-up waits, and everything resumes when gkm returns.
func TestWithGkmStoppedReadsGoOnAndARemovalStillBlocksWrites(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	b := world.flows[world.b]
	if _, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if _, err := b.client.EnsureWritable(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	world.store.setDown(true)

	if key, err := b.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
		t.Errorf("a read's newest key with gkm stopped: %v", err)
	}
	if key, err := b.client.RepoKey(world.ctx, world.repoId, 1); err != nil || key.Generation() != 1 {
		t.Errorf("an older generation with gkm stopped: %v", err)
	}
	if key, err := b.client.EnsureWritable(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
		t.Errorf("a write with gkm stopped and every shrink covered: %v", err)
	}
	if err := b.client.SyncRepo(world.ctx, world.repoId); err == nil {
		t.Errorf("catch-up did not wait for gkm")
	}
	world.revoke(world.x)
	world.stateFor()
	if _, err := b.client.EnsureWritable(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Fatalf("a write past a removal with gkm stopped: %v", err)
	}
	if key, err := b.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
		t.Errorf("a read past a removal with gkm stopped: %v", err)
	}

	world.store.setDown(false)
	key, err := b.client.EnsureWritable(world.ctx, world.repoId)
	if err != nil || key.Generation() != 3 || key.Cause() != sidecar.GkmCauseRemove {
		t.Errorf("the write once gkm returns: %v", err)
	}
	if len(b.alarms) != 0 {
		t.Errorf("a stopped gkm alarmed: %+v", b.alarms[0])
	}
}

// The yields a page Worker's flows take (KEYS-M4-01): a catch-up of many commits and a rotation's deliveries step
// between each unit of work, and yield the thread once 50 ms have passed on the clock since the last yield.
func TestGkmFlowsYieldBetweenTheirSteps(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	for index := 0; index < 3; index += 1 {
		world.admitAgent("agent"+string(rune('a'+index)), false)
	}
	world.stateFor()
	world.selfUpdates(world.a, 5)
	b := world.flows[world.b]
	before := b.client.YieldStats()
	if before.StepCount != 0 {
		t.Fatalf("steps before any flow: %+v", before)
	}
	if err := b.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	stats := b.client.YieldStats()
	if stats.StepCount < 5 {
		t.Errorf("a catch-up of 5 commits took %d steps", stats.StepCount)
	}
	a := world.flows[world.a]
	stepsBefore := a.client.YieldStats().StepCount
	if _, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if steps := a.client.YieldStats().StepCount - stepsBefore; steps < 3 {
		t.Errorf("a rotation with 3 deliveries took %d steps", steps)
	}
}
