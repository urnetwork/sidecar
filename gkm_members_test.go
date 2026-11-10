//go:build !sidecar_http

// The pending engine on the fake gkm (KEYS-M2-21, §22.5's KF2 to KF4 and KF6, DESIGN-DETAILS 6.6): one commit
// carrying every pending Remove with its Adds, a member's refusal of the same commit made without them, a read_only
// leaf waiting while a dropped leaf stands, the 409 loser processing the winner and committing what remains, a
// Remove then the rotation, a wrapped revoker rotating first, and the Welcome a kill would have lost.

package sidecar_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A flow world with every leaf holding generation 1 and epoch 1.
func newGkmEngineWorld(t *testing.T, kind protocol.RepoKind) *gkmFlowWorld {
	world := newGkmFlowWorld(t, kind)
	world.holdAll()
	return world
}

// Admits a member device that reads the repo and has uploaded KeyPackages.
func (self *gkmFlowWorld) admitReader(label string, keyPackageCount int) *gkmWorldDevice {
	self.t.Helper()
	device := self.admit(label)
	self.grant(false, device)
	self.flow(device)
	self.store.publishKeyPackages(device, keyPackageCount, false)
	return device
}

// Every leaf but those named catches up and commits whatever it may.
func (self *gkmFlowWorld) runAll(skip ...*gkmWorldDevice) {
	self.t.Helper()
	for _, device := range self.devices {
		if slices.Contains(skip, device) || self.engineGroup(device) == nil {
			continue
		}
		if err := self.flows[device].client.RunPending(self.ctx, self.repoId); err != nil {
			self.t.Fatalf("%s runs the engine: %v", device.label, err)
		}
	}
}

// TestACommitCarriesEveryPendingRemove: a writer leaf at a state past two revocations commits one Remove of both
// with its Add (KF2, KF4), writes the Welcome, and rotates with cause REMOVE on the clean tree; every other leaf
// processes the commit and adopts it, and the joiner joins by its Welcome.
func TestACommitCarriesEveryPendingRemove(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	world.revoke(world.x)
	world.revoke(world.c)
	d := world.admitReader("d", 1)
	second := world.stateFor()

	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 2 || world.store.callCount("CommitEpoch") != 1 {
		t.Fatalf("one commit for two Removes and an Add: gkm at epoch %d after %d commits", newest, world.store.callCount("CommitEpoch"))
	}
	if labels := world.rosterLabels(world.engineGroup(world.a)); !slices.Equal(labels, []string{"a", "b", "d", "p"}) {
		t.Errorf("the tree after the commit: %v", labels)
	}
	if epochs := world.store.welcomeEpochs(d); !slices.Equal(epochs, []uint64{2}) {
		t.Errorf("the joiner's Welcome pointers: %v", epochs)
	}
	// the rotation after: cause REMOVE, a leaf_wrap under the new epoch, no ReaderWrap to a leaf
	gen2 := world.storedGeneration(second, 2)
	if sidecar.GkmCause(gen2.Rotate.GetCause()) != sidecar.GkmCauseRemove || gen2.Rotate.GetLeafWrap() == nil || gen2.Rotate.GetLeafWrap().GetEpoch() != 2 || len(world.deliveryRecipients(2)) != 0 {
		t.Errorf("the rotation after the Remove: cause %d, leaf_wrap %v, deliveries %v", gen2.Rotate.GetCause(), gen2.Rotate.GetLeafWrap(), world.deliveryRecipients(2))
	}
	firstCommit, _ := world.store.callSpan("CommitEpoch")
	firstClaim, _ := world.store.callSpan("ClaimGeneration")
	if firstClaim < firstCommit {
		t.Errorf("the rotation was claimed before the Remove was committed")
	}
	// the joiner joins, and every remaining leaf adopts the commit
	if joined, err := world.flows[d].client.JoinWelcomes(world.ctx); err != nil || len(joined) != 1 {
		t.Fatalf("the joiner: %v %v", joined, err)
	}
	world.runAll(world.x, world.c)
	for _, device := range []*gkmWorldDevice{world.b, world.p, d} {
		if labels := world.rosterLabels(world.engineGroup(device)); !slices.Equal(labels, []string{"a", "b", "d", "p"}) {
			t.Errorf("%s's tree: %v", device.label, labels)
		}
		if _, epoch, _, err := world.flows[device].client.TestPins(world.repoId); err != nil || epoch != 2 {
			t.Errorf("%s's epoch pin: %d %v", device.label, epoch, err)
		}
		if len(world.flows[device].alarms) != 0 {
			t.Errorf("%s alarmed: %+v", device.label, world.flows[device].alarms[0])
		}
	}
	// the removed leaves adopt their Remove and hold no leaf
	for _, device := range []*gkmWorldDevice{world.x, world.c} {
		if err := world.flows[device].client.RunPending(world.ctx, world.repoId); err != nil {
			t.Errorf("%s processes its Remove: %v", device.label, err)
		}
		if world.engineGroup(device) != nil {
			t.Errorf("%s still holds a leaf", device.label)
		}
	}
	if pending, _, err := a.client.Pending(world.ctx, world.repoId); err != nil || !pending.Empty() {
		t.Errorf("pending after the engine's run: %+v %v", pending, err)
	}
}

// R3's member half on the engine: the same Add made without the Removes, standing at gkm, is refused by every
// member, which alarms refused naming the committer and the epoch, never adopts it, and holds the generation its
// GenWrap carried as poisoned.
func TestAMemberNeverAdoptsACommitThatLeavesADroppedLeaf(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.revoke(world.x)
	d := world.admitReader("d", 1)
	second := world.stateFor()
	// a's twin: the Add with no Remove
	world.inject(world.a, world.stage(world.a, 1, second.Pin(), []*gkmWorldDevice{d}, nil), world.gen1)
	for _, device := range []*gkmWorldDevice{world.b, world.p} {
		flow := world.flows[device]
		if err := flow.client.RunPending(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmCommitRefused) {
			t.Fatalf("%s processes the twin's commit: %v", device.label, err)
		}
		if _, epoch, _, err := flow.client.TestPins(world.repoId); err != nil || epoch != 1 || world.engineGroup(device).Epoch() != 1 {
			t.Errorf("%s adopted the refused epoch", device.label)
		}
		if len(flow.alarms) != 1 || flow.alarms[0].Kind != sidecar.GkmAlarmRefused || flow.alarms[0].SidecarId != world.a.id || flow.alarms[0].Epoch != 2 ||
			flow.alarms[0].Reason != sidecar.GkmRefusalRoster || flow.alarms[0].Generation != 1 {
			t.Errorf("%s's alarm: %+v", device.label, flow.alarms)
		}
		if _, poisoned, found, err := flow.client.TestHeldGeneration(world.repoId, 1); err != nil || !found || !poisoned {
			t.Errorf("%s does not hold the carried generation as poisoned", device.label)
		}
	}
	if world.store.callCount("CommitEpoch") != 0 {
		t.Errorf("a member committed on the refused epoch")
	}
}

// TestAReadOnlyLeafWaitsWhileADroppedLeafStands: after a wrapped writer's rotation, a read_only leaf's self-update
// is refused by its own check before any upload while the dropped leaf stands, and lands once a writer leaf's
// Remove does; the commit it would have made, standing at gkm, is refused by every member.
func TestAReadOnlyLeafWaitsWhileADroppedLeafStands(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a, p := world.flows[world.a], world.flows[world.p]
	agent := world.admit("agent", sidecar.NewId())
	world.grant(true, agent)
	world.stateFor()
	wrapped := world.hold(agent, world.gen1)
	world.revoke(world.x)
	world.stateFor()
	// the wrapped writer rotates while x's leaf stands
	if _, err := wrapped.client.RotateRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if err := p.client.SelfUpdate(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmCommitRefused) {
		t.Fatalf("a read_only leaf's self-update over a dropped leaf: %v", err)
	}
	if world.store.callCount("CommitEpoch") != 0 {
		t.Fatalf("the waiting leaf uploaded a commit")
	}
	// a writer leaf's Remove releases it
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if err := p.client.SelfUpdate(world.ctx, world.repoId); err != nil {
		t.Fatalf("the self-update once the Remove landed: %v", err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 3 {
		t.Errorf("gkm at epoch %d", newest)
	}
	if labels := world.rosterLabels(world.engineGroup(world.p)); !slices.Equal(labels, []string{"a", "b", "c", "p"}) {
		t.Errorf("the read_only leaf's tree: %v", labels)
	}
	// a's own check passes each commit it makes: no alarm on the honest path
	if len(a.alarms) != 0 || len(p.alarms) != 0 {
		t.Errorf("an honest run alarmed")
	}

	// the twin: the read_only leaf's self-update over the dropped leaf, uploaded past its check
	twin := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	twin.revoke(twin.x)
	second := twin.stateFor()
	twin.inject(twin.p, twin.stage(twin.p, 1, second.Pin(), nil, nil), twin.gen1)
	for _, device := range []*gkmWorldDevice{twin.a, twin.b, twin.c} {
		flow := twin.flows[device]
		if err := flow.client.RunPending(twin.ctx, twin.repoId); !errors.Is(err, sidecar.ErrGkmCommitRefused) {
			t.Errorf("%s processes the twin's self-update: %v", device.label, err)
		}
		if len(flow.alarms) != 1 || flow.alarms[0].SidecarId != twin.p.id || flow.alarms[0].Reason != sidecar.GkmRefusalRoster {
			t.Errorf("%s's alarm: %+v", device.label, flow.alarms)
		}
	}
}

// KF6: two writer leaves commit at one epoch. The loser's 409 discards its commit, having written no Welcome; it
// processes the winner and commits what remains, a device only its newer state shows.
func TestTheCommitRacesLoserProcessesTheWinnerAndCommitsWhatRemains(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a, b := world.flows[world.a], world.flows[world.b]
	d := world.admitReader("d", 2)
	world.stateFor()
	// only b's log has reached e's admission; the commit b loses spends a KeyPackage of each, as a claim does
	e := world.admitReader("e", 2)
	world.stateFor(world.a)
	world.store.plantHook("b", "CommitEpoch", func() {
		if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
			t.Errorf("the winner's run: %v", err)
		}
	})
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 3 {
		t.Fatalf("gkm at epoch %d", newest)
	}
	if labels := world.rosterLabels(world.engineGroup(world.b)); !slices.Equal(labels, []string{"a", "b", "c", "d", "e", "p", "x"}) {
		t.Errorf("the loser's tree: %v", labels)
	}
	// one Welcome each: the winner's for d at epoch 2, the loser's for e at epoch 3, and none from the lost commit
	if epochs := world.store.welcomeEpochs(d); !slices.Equal(epochs, []uint64{2}) {
		t.Errorf("d's Welcome pointers: %v", epochs)
	}
	if epochs := world.store.welcomeEpochs(e); !slices.Equal(epochs, []uint64{3}) {
		t.Errorf("e's Welcome pointers: %v", epochs)
	}
	if world.store.callCount("UploadWelcome") != 2 {
		t.Errorf("%d Welcomes written", world.store.callCount("UploadWelcome"))
	}
	for _, device := range []*gkmWorldDevice{d, e} {
		if joined, err := world.flows[device].client.JoinWelcomes(world.ctx); err != nil || len(joined) != 1 {
			t.Errorf("%s joins: %v %v", device.label, joined, err)
		}
	}
	if len(a.alarms) != 0 || len(b.alarms) != 0 {
		t.Errorf("an honest race alarmed")
	}
}

// KF4 from a wrapped revoker: an agent that writes rotates first, by ReaderWraps, and commits nothing; the next
// writer leaf's run commits the Remove, and no second rotation follows, since the generation already covers.
func TestAWrappedRevokerRotatesFirstAndALeafRemovesAfter(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	agent := world.admit("agent", sidecar.NewId())
	world.grant(true, agent)
	world.stateFor()
	wrapped := world.hold(agent, world.gen1)
	world.revoke(world.x)
	third := world.stateFor()
	if err := wrapped.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if world.store.callCount("CommitEpoch") != 0 || world.store.newestGeneration(world.groupId) != 2 {
		t.Fatalf("the wrapped revoker: %d commits, generation %d", world.store.callCount("CommitEpoch"), world.store.newestGeneration(world.groupId))
	}
	gen2 := world.storedGeneration(third, 2)
	if sidecar.GkmCause(gen2.Rotate.GetCause()) != sidecar.GkmCauseRemove || gen2.Rotate.GetLeafWrap() != nil {
		t.Errorf("the wrapped revoker's rotation: cause %d, leaf_wrap %v", gen2.Rotate.GetCause(), gen2.Rotate.GetLeafWrap())
	}
	if _, toRevoked := world.deliveryRecipients(2)["s:x"]; toRevoked {
		t.Errorf("a delivery of generation 2 to the revoked leaf")
	}
	// a takes generation 2 by its ReaderWrap, then its run removes x
	if key, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
		t.Fatalf("the leaf takes generation 2: %v %v", key, err)
	}
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if labels := world.rosterLabels(world.engineGroup(world.a)); !slices.Equal(labels, []string{"a", "b", "c", "p"}) {
		t.Errorf("the tree after the leaf's Remove: %v", labels)
	}
	if world.store.newestGeneration(world.groupId) != 2 {
		t.Errorf("a second rotation for one revocation: generation %d", world.store.newestGeneration(world.groupId))
	}
	// the Remove's epoch carries generation 2 into a tree of holders alone
	world.runAll(world.x)
	if _, epoch, generation, err := world.flows[world.b].client.TestPins(world.repoId); err != nil || epoch != 2 || generation != 2 {
		t.Errorf("b after the Remove: epoch %d, generation %d, %v", epoch, generation, err)
	}
}

// The config group's committers (owner decisions 128, 182): the admission's signer, a leaf that does not write the
// config, commits the Add it requires with no admin online; a leaf that neither writes nor signed it commits
// nothing; a read_only leaf commits nothing.
func TestASignerCommitsItsAddWithNoAdminOnline(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_CONFIG)
	d := world.admitReader("d", 1)
	d.row.AdmissionSigners = [][]byte{world.c.id.Bytes()}
	world.stateFor()
	for _, device := range []*gkmWorldDevice{world.x, world.p} {
		if err := world.flows[device].client.RunPending(world.ctx, world.repoId); err != nil {
			t.Fatalf("%s runs the engine: %v", device.label, err)
		}
	}
	if world.store.callCount("CommitEpoch") != 0 || world.store.callCount("ClaimKeyPackage") != 0 {
		t.Fatalf("a leaf that may not commit the Add claimed or committed")
	}
	c := world.flows[world.c]
	if pending, granting, err := c.client.Pending(world.ctx, world.repoId); err != nil || !granting || !slices.Equal(pending.Adds, []sidecar.Id{d.id}) {
		t.Errorf("the signer's pending: %+v granting %t %v", pending, granting, err)
	}
	if wait := c.client.PendingCommitWait(true); wait != 0 {
		t.Errorf("the granting device waits %s", wait)
	}
	if wait := world.flows[world.a].client.PendingCommitWait(false); wait != sidecar.DefaultGkmSettings().PendingCommitDelay {
		t.Errorf("another writer waits %s", wait)
	}
	if err := c.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if labels := world.rosterLabels(world.engineGroup(world.c)); !slices.Equal(labels, []string{"a", "b", "c", "d", "p", "x"}) {
		t.Errorf("the tree after the signer's Add: %v", labels)
	}
	world.runAll()
	for _, device := range []*gkmWorldDevice{world.a, world.b} {
		if len(world.flows[device].alarms) != 0 {
			t.Errorf("%s refused the signer's commit: %+v", device.label, world.flows[device].alarms[0])
		}
	}
}

// KF2's waits: a device with no KeyPackage is not added and nothing is committed for it; an owner-bound repo's
// unconsented device is parked with approval_pending; a device a restored binding admitted waits for its anchor.
func TestTheEngineAddsOnlyADeviceThatMayJoin(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_VAULT)
	a := world.flows[world.a]
	world.repo.OwnerMemberId = world.memberId.Bytes()
	for _, device := range []*gkmWorldDevice{world.a, world.b, world.c, world.p, world.x} {
		world.repo.ConsentedSidecarIds = append(world.repo.ConsentedSidecarIds, device.id.Bytes())
	}
	noKeyPackage := world.admitReader("no KeyPackage", 0)
	unconsented := world.admitReader("unconsented", 1)
	world.repo.ConsentedSidecarIds = append(world.repo.ConsentedSidecarIds, noKeyPackage.id.Bytes())
	world.stateFor()
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if world.store.callCount("CommitEpoch") != 0 {
		t.Fatalf("a commit with no one to add")
	}
	if len(a.alarms) != 1 || a.alarms[0].Kind != sidecar.GkmAlarmApprovalPending || a.alarms[0].SidecarId != unconsented.id {
		t.Errorf("the alarm for the unconsented device: %+v", a.alarms)
	}
	if len(world.store.keyPackages[unconsented.id]) != 1 {
		t.Errorf("a KeyPackage of the parked device was claimed")
	}
	// it uploads KeyPackages, and consent lands
	world.store.publishKeyPackages(noKeyPackage, 1, false)
	world.repo.ConsentedSidecarIds = append(world.repo.ConsentedSidecarIds, unconsented.id.Bytes())
	world.stateFor()
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if labels := world.rosterLabels(world.engineGroup(world.a)); len(labels) != 7 || world.store.callCount("CommitEpoch") != 1 {
		t.Errorf("the tree once both may join: %v", labels)
	}
}

// A Welcome is never lost to a kill between the epoch's 200 and its write: it is in the keychain before the commit
// is uploaded, and the next run after a restart writes it. A Welcome owed for a commit that lost its epoch is
// dropped. Two Adds of one device leave two pointers, and it joins by the newer.
func TestAnOwedWelcomeSurvivesAKillAndTheNewerPointerJoins(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	d := world.admitReader("d", 2)
	world.stateFor()
	world.store.plant("UploadWelcome", true)
	if err := a.client.RunPending(world.ctx, world.repoId); !errors.Is(err, errGkmFakeFault) {
		t.Fatalf("the killed run: %v", err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 2 || len(world.store.welcomeEpochs(d)) != 0 {
		t.Fatalf("at the kill: epoch %d, pointers %v", newest, world.store.welcomeEpochs(d))
	}
	a.restart()
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if epochs := world.store.welcomeEpochs(d); !slices.Equal(epochs, []uint64{2}) {
		t.Fatalf("the Welcome after the restart: %v", epochs)
	}
	// d is dropped and admitted again before it ever joined: a second Add, a second pointer
	world.drop(d)
	world.repo.HoldersShrunkAt = world.nextPosition()
	world.stateFor()
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	world.grant(false, d)
	world.stateFor()
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if epochs := world.store.welcomeEpochs(d); !slices.Equal(epochs, []uint64{2, 4}) {
		t.Fatalf("the pointers after the second Add: %v", epochs)
	}
	joiner := world.flows[d]
	if joined, err := joiner.client.JoinWelcomes(world.ctx); err != nil || len(joined) != 1 {
		t.Fatalf("the join: %v %v", joined, err)
	}
	if _, epoch, generation, err := joiner.client.TestPins(world.repoId); err != nil || epoch != 4 || generation != world.store.newestGeneration(world.groupId) {
		t.Errorf("the joiner's pins: epoch %d, generation %d, %v", epoch, generation, err)
	}
	if joined, err := joiner.client.JoinWelcomes(world.ctx); err != nil || len(joined) != 0 {
		t.Errorf("a pointer at or below the epoch reached was taken: %v %v", joined, err)
	}
}

// gkm's pending hint drives the engine: a writer leaf that did not sign the admission waits PendingCommitDelay on
// the clock, then commits the Add, and a second hint in that time starts no second run.
func TestAPendingHintRunsTheEngineAfterItsDelay(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	world.admitReader("d", 1)
	world.stateFor()
	ctx, cancel := context.WithCancel(world.ctx)
	defer cancel()
	hints, err := sidecar.NewGkmHints(ctx, &sidecar.GkmHintsArgs{Clock: world.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer hints.Close()
	a.client.AttachHints(ctx, hints)
	hint, err := proto.Marshal(&protocol.GkmHint{Kind: protocol.GkmHintKind_GKM_HINT_PENDING, GroupId: world.groupId.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	notice := sidecar.PushNotice{Topic: sidecar.PushTopicGkm, Version: 1, Kind: uint32(protocol.MessageType_GKM_HINT), Hint: hint}
	committed := make(chan struct{})
	world.store.plantHook("a", "UploadWelcome", func() { close(committed) })
	hints.Receive(notice)
	// the engine's wait is a timer on the clock, PendingCommitDelay from now
	due := world.clock.Now().Add(sidecar.DefaultGkmSettings().PendingCommitDelay)
	for {
		timers, added := world.clock.WatchTimers()
		if slices.ContainsFunc(timers, func(at time.Time) bool { return at.Equal(due) }) {
			break
		}
		<-added
	}
	hints.Receive(notice)
	if world.store.callCount("CommitEpoch") != 0 {
		t.Fatalf("a writer that did not sign the admission committed before its delay")
	}
	world.advance(sidecar.DefaultGkmSettings().PendingCommitDelay)
	<-committed
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 2 || world.store.callCount("CommitEpoch") != 1 {
		t.Errorf("after the delay: epoch %d, %d commits", newest, world.store.callCount("CommitEpoch"))
	}
}
