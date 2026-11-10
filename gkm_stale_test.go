//go:build !sidecar_http

// §7.10's group view on the fake gkm (KEYS-M4-01; FS-97's leaf legs and FS-106's page Worker case at unit level, on
// a fake clock): a page Worker's leaf read live, due and removed at each group's current epoch; a stale Remove
// carrying the dropped leaf its tree also holds; a Worker back by resync never read as removed; a weekly
// re-enroller's Workers removed about 90 days on; and a read_only page Worker's upkeep over 35 days.

package sidecar_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The stale_leaf_days every state of these tests answers.
const gkmStaleTestDays = 30

// Appends the world as the log's next position and gives every client a state that answers stale_leaf_days.
func (self *gkmFlowWorld) staleStateFor() *sidecartest.FakeGkmAuthView {
	self.t.Helper()
	view := self.state()
	for _, flow := range self.flows {
		flow.client.AuthAdvanced(gkmWorldStaleView{GkmAuthView: view, days: gkmStaleTestDays})
	}
	return view
}

// Admits a page Worker, a read_only member device, whose leaf will show its last change at lastChange, with one
// KeyPackage at gkm.
func (self *gkmFlowWorld) admitWorker(label string, lastChange time.Time) *gkmWorldDevice {
	self.t.Helper()
	worker := self.admit(label)
	worker.row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	worker.credential = self.credential(worker, worker.row.GetAdmissionSha256(), lastChange.Add(90*24*time.Hour))
	worker.mls = self.mlsWorld.Engine(worker.id, worker.credential)
	self.grant(false, worker)
	self.flow(worker)
	self.store.publishKeyPackages(worker, 1, false)
	return worker
}

// A world whose group seats a page Worker whose leaf last changed 20 days before the clock's start, so it goes
// stale 10 days in and is due its Remove a day after.
func newGkmStaleWorld(t *testing.T) (*gkmFlowWorld, *gkmWorldDevice) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	worker := world.admitWorker("w", gkmWorldStart.Add(-20*24*time.Hour))
	world.staleStateFor()
	if err := world.flows[world.a].client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if joined, err := world.flows[worker].client.JoinWelcomes(world.ctx); err != nil || len(joined) != 1 {
		t.Fatalf("the Worker joins: %v %v", joined, err)
	}
	return world, worker
}

// One Worker's leaf in a view's answer, nil for none.
func gkmStaleLeafOf(t *testing.T, world *gkmFlowWorld, view *sidecar.GkmStaleGroupView, workerId sidecar.Id) *sidecar.SidecarStaleLeaf {
	t.Helper()
	leaves, err := view.StaleLeaves(world.ctx, []sidecar.Id{workerId})
	if err != nil {
		t.Fatal(err)
	}
	if 1 < len(leaves) {
		t.Fatalf("%d leaves for one Worker in one group", len(leaves))
	}
	if len(leaves) == 0 {
		return nil
	}
	return leaves[0]
}

// The view's three states and its Remove: live until a day past stale_leaf_days, then due, on a writer leaf's view
// and on a reader's alike; the writer's stale Remove is one commit that also carries the dropped leaf the tree
// holds; every leaf that adopts it reads the Worker as removed; a device no group seated has no leaf; and a group
// that cannot be brought current answers an error.
func TestTheStaleViewReadsAWorkersLeafAtTheCurrentEpoch(t *testing.T) {
	world, worker := newGkmStaleWorld(t)
	a := world.flows[world.a]
	c := world.flows[world.c]
	writerView := sidecar.NewGkmStaleGroupView(a.client)
	readerView := sidecar.NewGkmStaleGroupView(c.client)
	outsider := world.admit("outsider")

	leaf := gkmStaleLeafOf(t, world, writerView, worker.id)
	if leaf == nil || leaf.State != sidecar.SidecarStaleLeafLive || !leaf.Writer || leaf.GroupId != world.groupId || leaf.Epoch != 2 ||
		!leaf.LastChange.Equal(gkmWorldStart.Add(-20*24*time.Hour)) {
		t.Fatalf("the Worker's leaf on a writer's view: %+v", leaf)
	}
	if leaf := gkmStaleLeafOf(t, world, writerView, outsider.id); leaf != nil {
		t.Fatalf("a leaf for a device no group seated: %+v", leaf)
	}
	// stale by the rule 10 days in, and due only a day after
	world.advance(10*24*time.Hour + 12*time.Hour)
	if leaf := gkmStaleLeafOf(t, world, writerView, worker.id); leaf.State != sidecar.SidecarStaleLeafLive {
		t.Fatalf("a leaf inside the day's margin: %+v", leaf)
	}
	if err := writerView.CommitStaleRemove(world.ctx, world.groupId, worker.id); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Fatalf("a stale Remove inside the day's margin: %v", err)
	}
	world.advance(12 * time.Hour)
	if leaf := gkmStaleLeafOf(t, world, writerView, worker.id); leaf.State != sidecar.SidecarStaleLeafDue || !leaf.Writer {
		t.Fatalf("a due leaf on a writer's view: %+v", leaf)
	}
	// a reader's view catches up to the epoch first, and may commit no Remove
	if leaf := gkmStaleLeafOf(t, world, readerView, worker.id); leaf == nil || leaf.State != sidecar.SidecarStaleLeafDue || leaf.Writer || leaf.Epoch != 2 {
		t.Fatalf("a due leaf on a reader's view: %+v", leaf)
	}
	if err := readerView.CommitStaleRemove(world.ctx, world.groupId, worker.id); !errors.Is(err, sidecar.ErrGkmNotWriter) {
		t.Fatalf("a reader's stale Remove: %v", err)
	}
	if err := writerView.CommitStaleRemove(world.ctx, world.groupId, world.b.id); !errors.Is(err, sidecar.ErrGkmWait) {
		t.Fatalf("a stale Remove of a leaf that is not due: %v", err)
	}

	// a dropped leaf stands too: the stale Remove carries its Remove
	world.revoke(world.x)
	world.staleStateFor()
	commits := world.store.callCount("CommitEpoch")
	if err := writerView.CommitStaleRemove(world.ctx, world.groupId, worker.id); err != nil {
		t.Fatal(err)
	}
	if world.store.callCount("CommitEpoch") != commits+1 || strings.Join(world.rosterLabels(world.engineGroup(world.a)), "") != "abcp" {
		t.Fatalf("the stale Remove's commit: tree %v", world.rosterLabels(world.engineGroup(world.a)))
	}
	for _, view := range []*sidecar.GkmStaleGroupView{writerView, readerView} {
		leaf := gkmStaleLeafOf(t, world, view, worker.id)
		if leaf == nil || leaf.State != sidecar.SidecarStaleLeafRemoved || leaf.Epoch != 3 || !leaf.LastChange.Equal(gkmWorldStart.Add(-20*24*time.Hour)) {
			t.Errorf("the removed Worker: %+v", leaf)
		}
		// the revoked leaf left for another input: nothing says it was stale
		if leaf := gkmStaleLeafOf(t, world, view, world.x.id); leaf != nil {
			t.Errorf("a dropped leaf read as stale: %+v", leaf)
		}
	}
	if len(a.alarms) != 0 || len(c.alarms) != 0 {
		t.Errorf("a stale Remove alarmed")
	}
	changes, err := a.client.LeafLastChanges([]sidecar.Id{world.b.id, worker.id})
	if err != nil || len(changes) != 1 || !changes[world.b.id].Equal(gkmWorldStart) {
		t.Errorf("the leaves' last changes: %v %v", changes, err)
	}
	// no evidence without the current epoch
	world.store.setDown(true)
	if _, err := writerView.StaleLeaves(world.ctx, []sidecar.Id{worker.id}); err == nil {
		t.Errorf("a view answered with gkm stopped")
	}
}

// A Worker back by resync is never read as removed (KF5): once its external commit stands, every view that adopts
// it reads the Worker's leaf in the tree again, and the record of its stale Remove is gone for good.
func TestAWorkerBackByResyncIsNotReadAsRemoved(t *testing.T) {
	world, worker := newGkmStaleWorld(t)
	a := world.flows[world.a]
	view := sidecar.NewGkmStaleGroupView(a.client)
	world.advance(11 * 24 * time.Hour)
	if err := view.CommitStaleRemove(world.ctx, world.groupId, worker.id); err != nil {
		t.Fatal(err)
	}
	if leaf := gkmStaleLeafOf(t, world, view, worker.id); leaf.State != sidecar.SidecarStaleLeafRemoved {
		t.Fatalf("the removed Worker: %+v", leaf)
	}
	// the Worker returns: it adopts its own Remove, then resyncs from the sealed GroupInfo
	w := world.flows[worker]
	if err := w.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if world.engineGroup(worker) == nil || world.pinnedEpoch(worker) != 4 {
		t.Fatalf("the Worker did not resync: epoch %d", world.pinnedEpoch(worker))
	}
	leaf := gkmStaleLeafOf(t, world, view, worker.id)
	if leaf == nil || leaf.State == sidecar.SidecarStaleLeafRemoved || leaf.Epoch != 4 {
		t.Fatalf("a Worker back by resync: %+v", leaf)
	}
	// a later Remove of it for another input says nothing of staleness
	world.revoke(worker)
	world.staleStateFor()
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if leaf := gkmStaleLeafOf(t, world, view, worker.id); leaf != nil {
		t.Errorf("a revoked Worker read as stale: %+v", leaf)
	}
}

// FS-97's leaf legs at unit level: a member's page Worker re-enrolled weekly for 13 weeks, each evicted Worker
// quiet from its enrollment on. The admitting device's weekly run adds the new Worker and commits the stale Remove
// of every Worker a day past stale_leaf_days, 30 here, so each is removed five weeks after it enrolled, the view
// reads it as removed with its leaf's last change, and the Workers that hold a leaf stop growing at five.
func TestAWeeklyReenrollersWorkersAreRemovedAsTheyGoStale(t *testing.T) {
	world := newGkmBareFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	// the fake engine signs no credential anew at a path, so the admitting device's own leaf is given a last change
	// far ahead: on the real subset its weekly commits keep it fresh
	world.a.credential = world.credential(world.a, world.a.row.GetAdmissionSha256(), gkmWorldStart.Add(2*365*24*time.Hour))
	world.a.mls = world.mlsWorld.Engine(world.a.id, world.a.credential)
	a := world.flows[world.a]
	a.restart()
	world.staleStateFor()
	key, err := a.client.CreateGroup(world.ctx, world.createArgs())
	if err != nil {
		t.Fatal(err)
	}
	world.groupId = key.GroupId()
	view := sidecar.NewGkmStaleGroupView(a.client)
	week := 7 * 24 * time.Hour
	workers := []*gkmWorldDevice{}
	workerIds := []sidecar.Id{}
	for weekIndex := 0; weekIndex < 13; weekIndex += 1 {
		worker := world.admitWorker("w"+string(rune('a'+weekIndex)), world.clock.Now())
		workers = append(workers, worker)
		workerIds = append(workerIds, worker.id)
		world.staleStateFor()
		if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
			t.Fatalf("week %d: %v", weekIndex, err)
		}
		leaves, err := view.StaleLeaves(world.ctx, workerIds)
		if err != nil {
			t.Fatalf("week %d: %v", weekIndex, err)
		}
		removedCount := 0
		for _, leaf := range leaves {
			index := slices.Index(workerIds, leaf.WorkerId)
			if !leaf.Writer || !leaf.LastChange.Equal(gkmWorldStart.Add(time.Duration(index)*week)) {
				t.Errorf("week %d: Worker %d's leaf: %+v", weekIndex, index, leaf)
			}
			switch leaf.State {
			case sidecar.SidecarStaleLeafRemoved:
				removedCount += 1
				if weekIndex < index+5 {
					t.Errorf("week %d: Worker %d removed %d weeks after it enrolled", weekIndex, index, weekIndex-index)
				}
			case sidecar.SidecarStaleLeafLive:
				if index+5 <= weekIndex {
					t.Errorf("week %d: Worker %d still holds a leaf", weekIndex, index)
				}
			default:
				t.Errorf("week %d: Worker %d is due after the run that removes what is due: %+v", weekIndex, index, leaf)
			}
		}
		if len(leaves) != len(workers) || removedCount != max(0, weekIndex-4) {
			t.Fatalf("week %d: %d leaves read, %d removed", weekIndex, len(leaves), removedCount)
		}
		if seated := len(world.engineGroup(world.a).Roster()) - 1; seated != min(weekIndex+1, 5) {
			t.Fatalf("week %d: %d Workers hold a leaf", weekIndex, seated)
		}
		world.advance(week)
	}
	if len(a.alarms) != 0 {
		t.Errorf("the admitting device alarmed: %+v", a.alarms[0])
	}
}

// FS-106's page Worker case at unit level, 35 days on a fake clock: a read_only leaf commits a path every 7 days,
// each adopted by the members; the groups it would ack are its own with their newest epochs; and after an epoch it
// lost to pruning it resyncs by external commit, another leaf then resyncing from the sealed GroupInfo its last
// path-only commit carries.
func TestAPageWorkersUpkeepOverThirtyFiveDays(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	p := world.flows[world.p]
	a := world.flows[world.a]
	pathCount := 0
	for day := 1; day <= 35; day += 1 {
		world.advance(24 * time.Hour)
		before := world.store.callCount("CommitEpoch")
		if err := p.client.SyncRepo(world.ctx, world.repoId); err != nil {
			t.Fatalf("day %d: %v", day, err)
		}
		if err := p.client.RunSelfUpdate(world.ctx, world.repoId); err != nil {
			t.Fatalf("day %d: %v", day, err)
		}
		if world.store.callCount("CommitEpoch") != before {
			pathCount += 1
			if day%7 != 0 {
				t.Errorf("a path on day %d", day)
			}
		}
		acks := p.client.AckGroups()
		if len(acks) != 1 || acks[0].GroupId != world.groupId || acks[0].Epoch != world.pinnedEpoch(world.p) {
			t.Fatalf("day %d: the groups to ack: %+v", day, acks)
		}
	}
	if pathCount != 5 || world.pinnedEpoch(world.p) != 6 {
		t.Fatalf("%d paths in 35 days, at epoch %d", pathCount, world.pinnedEpoch(world.p))
	}
	if err := a.client.SyncRepo(world.ctx, world.repoId); err != nil || world.pinnedEpoch(world.a) != 6 || len(a.alarms) != 0 {
		t.Fatalf("a member adopts the read_only leaf's paths: %v", err)
	}
	// a third leaf, far enough behind that gkm pruned what it needs, resyncs from the GroupInfo the read_only
	// leaf's last path-only commit carries
	world.store.prunedBelowEpoch = 6
	c := world.flows[world.c]
	if err := c.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if world.pinnedEpoch(world.c) != 7 || !sidecar.GkmCommitIsExternal(world.store.groupEpochs[world.groupId][7].GetCommit()) {
		t.Fatalf("the third leaf's resync: epoch %d", world.pinnedEpoch(world.c))
	}
	// the read_only leaf loses an epoch to pruning and resyncs itself
	world.selfUpdates(world.a, 1)
	world.selfUpdates(world.a, 1)
	world.store.prunedBelowEpoch = 9
	if err := p.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if world.pinnedEpoch(world.p) != 10 || !sidecar.GkmCommitIsExternal(world.store.groupEpochs[world.groupId][10].GetCommit()) {
		t.Fatalf("the read_only leaf's resync: epoch %d", world.pinnedEpoch(world.p))
	}
	world.store.prunedBelowEpoch = 0
	if err := a.client.SyncRepo(world.ctx, world.repoId); err != nil || world.pinnedEpoch(world.a) != 10 || len(a.alarms) != 0 {
		t.Errorf("a member adopts the read_only leaf's resync: %v", err)
	}
}
