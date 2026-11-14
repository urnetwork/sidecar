//go:build !sidecar_http

// The WelcomeTimeout re-add on the fake gkm (§10.6's Welcomes row, QD-747): a joiner whose uploader was killed before
// its Welcome is removed and added again by another writer leaf once gkm answers that no Welcome stands; a Welcome
// that stands leaves the joiner alone; a leaf that does not write never asks, and one gkm refuses stops asking; an
// ask gkm does not answer is asked again; a joiner that committed is asked after no more; a joiner with no
// KeyPackage keeps its leaf; the hint intake's timer runs the ask when it falls due; and a leaf that reached its
// epoch by a resync, by a join or in a re-formed group holds no watch from before it and asks nothing.

package sidecar_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// An engine world where a has committed d's Add at epoch 2 and, when killed, died before it wrote the Welcome.
func newGkmWelcomeWatchWorld(t *testing.T, keyPackageCount int, killed bool) (*gkmFlowWorld, *gkmWorldDevice) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	d := world.admitReader("d", keyPackageCount)
	world.stateFor()
	a := world.flows[world.a]
	if killed {
		world.store.plant("UploadWelcome", true)
		if err := a.client.RunPending(world.ctx, world.repoId); !errors.Is(err, errGkmFakeFault) {
			t.Fatalf("the killed run: %v", err)
		}
	} else if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 2 {
		t.Fatalf("after the Add: epoch %d", newest)
	}
	return world, d
}

// The uploader is killed between epoch/<n> and welcome/<n> and never returns. Another writer leaf adopts the Add,
// asks nothing before WelcomeTimeout, and at it asks once, takes gkm's 404, and removes and adds the joiner in one
// commit whose Welcome it writes; the joiner joins by that Welcome, every other leaf adopts the commit, and the
// watch survives the leaf's restart.
func TestAJoinerWhoseUploaderCrashedIsReaddedByAnotherLeafAfterTheTimeout(t *testing.T) {
	world, d := newGkmWelcomeWatchWorld(t, 2, true)
	b := world.flows[world.b]
	timeout := sidecar.DefaultGkmSettings().WelcomeTimeout
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	b.restart()
	world.advance(timeout - time.Second)
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 2 || world.store.callCount("WelcomeStands") != 0 {
		t.Fatalf("before the timeout: epoch %d, %d asks", newest, world.store.callCount("WelcomeStands"))
	}
	world.advance(time.Second)
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 3 || world.store.callCount("WelcomeStands") != 1 {
		t.Fatalf("at the timeout: epoch %d, %d asks", newest, world.store.callCount("WelcomeStands"))
	}
	if labels := world.rosterLabels(world.engineGroup(world.b)); !slices.Equal(labels, []string{"a", "b", "c", "d", "p", "x"}) {
		t.Errorf("the tree after the re-add: %v", labels)
	}
	if epochs := world.store.welcomeEpochs(d); !slices.Equal(epochs, []uint64{3}) {
		t.Fatalf("d's Welcome pointers: %v", epochs)
	}
	joiner := world.flows[d]
	if joined, err := joiner.client.JoinWelcomes(world.ctx); err != nil || len(joined) != 1 {
		t.Fatalf("the join: %v %v", joined, err)
	}
	if _, epoch, _, err := joiner.client.TestPins(world.repoId); err != nil || epoch != 3 {
		t.Errorf("the joiner's epoch: %d, %v", epoch, err)
	}
	// the re-add is a commit every member accepts, and nothing is asked or committed again
	world.runAll(world.a)
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 3 || world.store.callCount("WelcomeStands") != 1 {
		t.Errorf("after every leaf ran: epoch %d, %d asks", newest, world.store.callCount("WelcomeStands"))
	}
	for _, device := range []*gkmWorldDevice{world.b, world.c, world.p, world.x, d} {
		if alarms := world.flows[device].alarms; len(alarms) != 0 {
			t.Errorf("%s alarmed at an honest re-add: %v", device.label, alarms[0])
		}
	}
}

// The uploader wrote its Welcome: the other writer leaf's one ask is answered 200, and it commits nothing and asks
// no more.
func TestAWelcomeThatStandsLeavesItsJoinerAlone(t *testing.T) {
	world, d := newGkmWelcomeWatchWorld(t, 2, false)
	b := world.flows[world.b]
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	world.advance(sidecar.DefaultGkmSettings().WelcomeTimeout)
	for pass := 0; pass < 2; pass += 1 {
		if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
			t.Fatal(err)
		}
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 2 || world.store.callCount("WelcomeStands") != 1 || world.store.callCount("ClaimKeyPackage") != 1 {
		t.Errorf("a Welcome that stands: epoch %d, %d asks, %d claims", newest, world.store.callCount("WelcomeStands"), world.store.callCount("ClaimKeyPackage"))
	}
	if epochs := world.store.welcomeEpochs(d); !slices.Equal(epochs, []uint64{2}) {
		t.Errorf("d's Welcome pointers: %v", epochs)
	}
}

// Only a writer asks: a leaf that reads, and a read_only one, adopt the Add and never ask, whatever the time; and a
// writer gkm refuses, whose token carries no rw there, stops at that answer and removes no one.
func TestALeafWithoutWriteNeverAsksAndARefusedOneStops(t *testing.T) {
	world, _ := newGkmWelcomeWatchWorld(t, 2, true)
	b, c, p := world.flows[world.b], world.flows[world.c], world.flows[world.p]
	for _, flow := range []*gkmFlowDevice{b, c, p} {
		if err := flow.client.RunPending(world.ctx, world.repoId); err != nil {
			t.Fatalf("%s adopts the Add: %v", flow.label, err)
		}
	}
	world.advance(2 * sidecar.DefaultGkmSettings().WelcomeTimeout)
	for _, flow := range []*gkmFlowDevice{c, p} {
		if err := flow.client.RunPending(world.ctx, world.repoId); err != nil {
			t.Fatalf("%s after the timeout: %v", flow.label, err)
		}
	}
	if world.store.callCount("WelcomeStands") != 0 {
		t.Fatalf("a leaf that does not write asked %d times", world.store.callCount("WelcomeStands"))
	}
	world.store.refuseOnce("WelcomeStands", http.StatusForbidden)
	for pass := 0; pass < 2; pass += 1 {
		if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
			t.Fatal(err)
		}
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 2 || world.store.callCount("WelcomeStands") != 1 {
		t.Errorf("a refused ask: epoch %d, %d asks", newest, world.store.callCount("WelcomeStands"))
	}
}

// An ask gkm does not answer removes no one and fails nothing: it is asked again at the next run, and the 404 then
// brings the re-add.
func TestAnAskGkmDoesNotAnswerIsAskedAgain(t *testing.T) {
	world, d := newGkmWelcomeWatchWorld(t, 2, true)
	b := world.flows[world.b]
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	world.advance(sidecar.DefaultGkmSettings().WelcomeTimeout)
	world.store.plant("WelcomeStands", true)
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatalf("a run whose ask was lost: %v", err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 2 {
		t.Fatalf("a lost ask committed: epoch %d", newest)
	}
	world.store.refuseOnce("WelcomeStands", http.StatusServiceUnavailable)
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatalf("a run whose ask was answered 503: %v", err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 2 {
		t.Fatalf("a 503 committed: epoch %d", newest)
	}
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 3 || world.store.callCount("WelcomeStands") != 3 {
		t.Errorf("the ask answered: epoch %d, %d asks", newest, world.store.callCount("WelcomeStands"))
	}
	if epochs := world.store.welcomeEpochs(d); !slices.Equal(epochs, []uint64{3}) {
		t.Errorf("d's Welcome pointers: %v", epochs)
	}
}

// A joiner that committed has joined: the leaf that watched its Add adopts that commit and asks nothing, even where
// gkm would answer 404.
func TestAJoinerThatCommittedIsAskedAfterNoMore(t *testing.T) {
	world, d := newGkmWelcomeWatchWorld(t, 2, false)
	b := world.flows[world.b]
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	joiner := world.flows[d]
	if joined, err := joiner.client.JoinWelcomes(world.ctx); err != nil || len(joined) != 1 {
		t.Fatalf("the join: %v %v", joined, err)
	}
	if err := joiner.client.SelfUpdate(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	// gkm loses the Welcome, as retention would in time
	func() {
		world.store.stateLock.Lock()
		defer world.store.stateLock.Unlock()
		clear(world.store.groupWelcomes)
	}()
	world.advance(sidecar.DefaultGkmSettings().WelcomeTimeout)
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 3 || world.store.callCount("WelcomeStands") != 0 {
		t.Errorf("a joiner that committed: epoch %d, %d asks", newest, world.store.callCount("WelcomeStands"))
	}
}

// A re-add needs a KeyPackage: with none at gkm the joiner keeps its leaf and nothing is committed, the 404 is not
// asked for again, and the re-add follows once the joiner has uploaded one.
func TestAReaddWaitsForTheJoinersKeyPackage(t *testing.T) {
	world, d := newGkmWelcomeWatchWorld(t, 1, true)
	b := world.flows[world.b]
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	world.advance(sidecar.DefaultGkmSettings().WelcomeTimeout)
	for pass := 0; pass < 2; pass += 1 {
		if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
			t.Fatal(err)
		}
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 2 || world.store.callCount("WelcomeStands") != 1 {
		t.Fatalf("with no KeyPackage: epoch %d, %d asks", newest, world.store.callCount("WelcomeStands"))
	}
	if labels := world.rosterLabels(world.engineGroup(world.b)); !slices.Contains(labels, "d") {
		t.Fatalf("the joiner lost its leaf with no re-add: %v", labels)
	}
	world.store.publishKeyPackages(d, 1, false)
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 3 || world.store.callCount("WelcomeStands") != 1 {
		t.Errorf("once it has a KeyPackage: epoch %d, %d asks", newest, world.store.callCount("WelcomeStands"))
	}
	if epochs := world.store.welcomeEpochs(d); !slices.Equal(epochs, []uint64{3}) {
		t.Errorf("d's Welcome pointers: %v", epochs)
	}
}

// With hints attached the ask needs no other wake: the leaf that adopts the Add arms a timer on the clock at
// WelcomeTimeout past the epoch, and when it fires the engine asks and re-adds.
func TestTheWelcomeAsksTimerRunsTheEngineWhenItFallsDue(t *testing.T) {
	world, _ := newGkmWelcomeWatchWorld(t, 2, true)
	b := world.flows[world.b]
	ctx, cancel := context.WithCancel(world.ctx)
	defer cancel()
	hints, err := sidecar.NewGkmHints(ctx, &sidecar.GkmHintsArgs{Clock: world.clock})
	if err != nil {
		t.Fatal(err)
	}
	defer hints.Close()
	b.client.AttachHints(ctx, hints)
	// the epoch's time is the clock's now, so its ask is due one WelcomeTimeout from here
	settings := sidecar.DefaultGkmSettings()
	start := world.clock.Now()
	due := start.Add(settings.WelcomeTimeout)
	hint, err := proto.Marshal(&protocol.GkmHint{Kind: protocol.GkmHintKind_GKM_HINT_PENDING, GroupId: world.groupId.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	readded := make(chan struct{})
	world.store.plantHook("b", "UploadWelcome", func() { close(readded) })
	awaitTimer := func(at time.Time) {
		for {
			timers, added := world.clock.WatchTimers()
			if slices.ContainsFunc(timers, func(timer time.Time) bool { return timer.Equal(at) }) {
				return
			}
			<-added
		}
	}
	// b has not adopted the Add yet, so the pending hint's run waits its PendingCommitDelay, then adopts it
	hints.Receive(sidecar.PushNotice{Topic: sidecar.PushTopicGkm, Version: 1, Kind: uint32(protocol.MessageType_GKM_HINT), Hint: hint})
	awaitTimer(start.Add(settings.PendingCommitDelay))
	world.advance(settings.PendingCommitDelay)
	awaitTimer(due)
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 2 || world.store.callCount("WelcomeStands") != 0 {
		t.Fatalf("before the timeout: epoch %d, %d asks", newest, world.store.callCount("WelcomeStands"))
	}
	world.advance(settings.WelcomeTimeout - settings.PendingCommitDelay)
	<-readded
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 3 || world.store.callCount("WelcomeStands") != 1 {
		t.Errorf("after the timer: epoch %d, %d asks", newest, world.store.callCount("WelcomeStands"))
	}
}

// Pending's Unwelcomed is a Remove and an Add of the same leaf, or neither: a joiner that may join is in both, its
// seat kept; one that may not join now, a device not anchored, keeps its leaf.
func TestAnUnwelcomedLeafIsRemovedOnlyWithItsAdd(t *testing.T) {
	world := newGkmWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.admit("a")
	d := world.admit("d")
	e := world.admit("e")
	world.grant(true, a)
	world.grant(false, d, e)
	view := world.state()
	roster := []sidecar.MlsMember{
		{LeafIndex: 0, SidecarId: a.id, Credential: a.credential},
		{LeafIndex: 1, SidecarId: d.id, Credential: d.credential},
	}
	pendingWith := func(seatCount int, anchored func(sidecarId sidecar.Id) bool) *sidecar.GkmPending {
		t.Helper()
		pending, err := sidecar.GkmPendingChanges(view, &sidecar.GkmPendingArgs{
			RepoId: world.repoId, Roster: roster, Unwelcomed: []sidecar.Id{d.id}, Anchored: anchored,
			SeatCount: seatCount, ScheduleInterval: 30 * 24 * time.Hour, StaleRemoveMargin: 24 * time.Hour, Now: world.now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return pending
	}
	pending := pendingWith(1000, nil)
	if len(pending.Removes) != 1 || pending.Removes[0].SidecarId != d.id || !slices.Equal(pending.Adds, []sidecar.Id{d.id, e.id}) {
		t.Errorf("a re-add: removes %v, adds %v", pending.Removes, pending.Adds)
	}
	// two seats, both held: the re-added joiner keeps its own, and the device outside the tree waits
	pending = pendingWith(2, nil)
	if len(pending.Removes) != 1 || !slices.Equal(pending.Adds, []sidecar.Id{d.id}) || !slices.Equal(pending.Waiting, []sidecar.Id{e.id}) {
		t.Errorf("a re-add in a full tree: removes %v, adds %v, waiting %v", pending.Removes, pending.Adds, pending.Waiting)
	}
	pending = pendingWith(1000, func(sidecarId sidecar.Id) bool { return sidecarId != d.id })
	if len(pending.Removes) != 0 || !slices.Equal(pending.Adds, []sidecar.Id{e.id}) || !slices.Equal(pending.Unanchored, []sidecar.Id{d.id}) {
		t.Errorf("a joiner that may not join now: removes %v, adds %v, unanchored %v", pending.Removes, pending.Adds, pending.Unanchored)
	}
}

// The epochs of the watches a device's keychain holds, with the epoch the record names them current at.
func (self *gkmFlowWorld) welcomeWatches(device *gkmWorldDevice) (groupId sidecar.Id, epoch uint64, watchEpochs []uint64) {
	self.t.Helper()
	groupId, epoch, watchEpochs, err := self.flows[device].client.TestWelcomeWatches(self.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	return groupId, epoch, watchEpochs
}

// A resync reaches its epoch by no commit this device processed: a leaf that watched an Add, was pruned past, and
// returned by an external commit holds no watch after it, asks nothing once WelcomeTimeout has passed, and removes
// no one, even where gkm would answer 404.
func TestAResyncForgetsTheWelcomeWatches(t *testing.T) {
	world, _ := newGkmWelcomeWatchWorld(t, 2, true)
	b := world.flows[world.b]
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if _, epoch, watchEpochs := world.welcomeWatches(world.b); epoch != 2 || !slices.Equal(watchEpochs, []uint64{2}) {
		t.Fatalf("b's watches after it adopted the Add: %v at epoch %d", watchEpochs, epoch)
	}
	// a reader leaf's paths take the group past what gkm still serves b
	world.selfUpdates(world.c, 3)
	world.store.prunedBelowEpoch = 4
	if err := b.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 6 || world.pinnedEpoch(world.b) != 6 {
		t.Fatalf("after the resync: gkm at epoch %d, b at %d", newest, world.pinnedEpoch(world.b))
	}
	if _, _, watchEpochs := world.welcomeWatches(world.b); len(watchEpochs) != 0 {
		t.Errorf("b's watches after its resync: %v", watchEpochs)
	}
	world.advance(2 * sidecar.DefaultGkmSettings().WelcomeTimeout)
	for pass := 0; pass < 2; pass += 1 {
		if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
			t.Fatal(err)
		}
	}
	if newest, _ := world.store.newestEpoch(world.groupId); newest != 6 || world.store.callCount("WelcomeStands") != 0 {
		t.Errorf("after the timeout: epoch %d, %d asks", newest, world.store.callCount("WelcomeStands"))
	}
	if labels := world.rosterLabels(world.engineGroup(world.b)); !slices.Contains(labels, "d") {
		t.Errorf("the joiner lost its leaf: %v", labels)
	}
}

// A join reaches its epoch by no commit this device processed: a leaf that watched an Add, was removed and added
// again while away, and returned by its Welcome asks nothing of the epochs before its join, and its keychain holds
// no watch once its engine has run.
func TestAJoinForgetsTheWelcomeWatches(t *testing.T) {
	world, _ := newGkmWelcomeWatchWorld(t, 2, true)
	a, b := world.flows[world.a], world.flows[world.b]
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	if _, epoch, watchEpochs := world.welcomeWatches(world.b); epoch != 2 || !slices.Equal(watchEpochs, []uint64{2}) {
		t.Fatalf("b's watches after it adopted the Add: %v at epoch %d", watchEpochs, epoch)
	}
	// b's grant ends and a removes its leaf; a new grant, and a adds it again: b sees neither commit
	world.drop(world.b)
	world.repo.HoldersShrunkAt = world.nextPosition()
	world.stateFor(world.b)
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatalf("a removes b: %v", err)
	}
	if labels := world.rosterLabels(world.engineGroup(world.a)); slices.Contains(labels, "b") {
		t.Fatalf("b kept its leaf: %v", labels)
	}
	world.grant(true, world.b)
	world.store.publishKeyPackages(world.b, 1, false)
	world.stateFor()
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatalf("a adds b again: %v", err)
	}
	joinEpoch, _ := world.store.newestEpoch(world.groupId)
	if epochs := world.store.welcomeEpochs(world.b); !slices.Equal(epochs, []uint64{joinEpoch}) || joinEpoch <= 3 {
		t.Fatalf("b's Welcome pointers: %v, gkm at epoch %d", epochs, joinEpoch)
	}
	if joined, err := b.client.JoinWelcomes(world.ctx); err != nil || len(joined) != 1 {
		t.Fatalf("b's join: %v %v", joined, err)
	}
	if world.pinnedEpoch(world.b) != joinEpoch {
		t.Fatalf("b joined at epoch %d, not %d", world.pinnedEpoch(world.b), joinEpoch)
	}
	// gkm holds no Welcome of the watched epoch: an ask would be answered 404
	func() {
		world.store.stateLock.Lock()
		defer world.store.stateLock.Unlock()
		for key := range world.store.groupWelcomes {
			if strings.HasSuffix(key, "/2") {
				delete(world.store.groupWelcomes, key)
			}
		}
	}()
	world.advance(2 * sidecar.DefaultGkmSettings().WelcomeTimeout)
	commits := world.store.callCount("CommitEpoch")
	for pass := 0; pass < 2; pass += 1 {
		if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
			t.Fatal(err)
		}
	}
	if world.store.callCount("WelcomeStands") != 0 || world.store.callCount("CommitEpoch") != commits {
		t.Errorf("after the timeout: %d asks, %d commits since the join", world.store.callCount("WelcomeStands"), world.store.callCount("CommitEpoch")-commits)
	}
	if _, _, watchEpochs := world.welcomeWatches(world.b); len(watchEpochs) != 0 {
		t.Errorf("b's watches after its join and a run of its engine: %v", watchEpochs)
	}
	if labels := world.rosterLabels(world.engineGroup(world.b)); !slices.Contains(labels, "d") {
		t.Errorf("the joiner lost its leaf: %v", labels)
	}
}

// A re-form reaches its group by no commit this device processed: a leaf that watched an Add at the old group's
// epoch 2 and joins the re-formed group at its epoch 2 asks nothing there, since the watches name the old group,
// and its keychain holds no watch once its engine has run.
func TestAReformForgetsTheWelcomeWatches(t *testing.T) {
	world, _ := newGkmWelcomeWatchWorld(t, 2, true)
	a, b := world.flows[world.a], world.flows[world.b]
	if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	oldGroupId := world.groupId
	if groupId, epoch, watchEpochs := world.welcomeWatches(world.b); groupId != oldGroupId || epoch != 2 || !slices.Equal(watchEpochs, []uint64{2}) {
		t.Fatalf("b's watches after it adopted the Add: %v at epoch %d", watchEpochs, epoch)
	}
	// one of the repo's admins re-forms the group while b has no KeyPackage, so the new group's epoch 1 leaves b out
	world.members[0].Role = bridge.MemberRole_MEMBER_ROLE_MEMBER
	world.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: world.a.id.Bytes(), Signer: world.a.id.Bytes(), At: 1}}
	world.stateFor()
	for _, device := range []*gkmWorldDevice{world.c, world.p, world.x} {
		world.store.publishKeyPackages(device, 1, false)
	}
	newGroupId, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId})
	if err != nil {
		t.Fatalf("the re-form: %v", err)
	}
	// b uploads a KeyPackage, and a adds it at the new group's epoch 2
	world.store.publishKeyPackages(world.b, 1, false)
	if err := a.client.RunPending(world.ctx, world.repoId); err != nil {
		t.Fatalf("a adds b to the new group: %v", err)
	}
	if joined, err := b.client.JoinWelcomes(world.ctx); err != nil || !slices.Contains(joined, world.repoId) {
		t.Fatalf("b joins the re-formed group: %v %v", joined, err)
	}
	if groupId, epoch, _, err := b.client.TestPins(world.repoId); err != nil || groupId != newGroupId || epoch != 2 {
		t.Fatalf("b in the re-formed group: epoch %d, %v", epoch, err)
	}
	world.advance(2 * sidecar.DefaultGkmSettings().WelcomeTimeout)
	commits := world.store.callCount("CommitEpoch")
	for pass := 0; pass < 2; pass += 1 {
		if err := b.client.RunPending(world.ctx, world.repoId); err != nil {
			t.Fatal(err)
		}
	}
	if world.store.callCount("WelcomeStands") != 0 || world.store.callCount("CommitEpoch") != commits {
		t.Errorf("after the timeout: %d asks, %d commits since the join", world.store.callCount("WelcomeStands"), world.store.callCount("CommitEpoch")-commits)
	}
	if _, _, watchEpochs := world.welcomeWatches(world.b); len(watchEpochs) != 0 {
		t.Errorf("b's watches after the re-form and a run of its engine: %v", watchEpochs)
	}
}
