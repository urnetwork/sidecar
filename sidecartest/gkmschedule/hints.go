package gkmschedule

// FS-24 and FS-62's gkm part on T2 and T3 (KEYS-M2-27; §10.6's pending changes and late wraps rows, D-KEYS-19, DESIGN-DETAILS 6.2.3's H1 to H3):
// an idle writer on the real subset is told its work on its per-client gkm topic, at an epoch nothing has moved,
// after a Redis loss too, and does it within the gate's target; a rotation with no commit raises gkm:<group_id> for
// the repo's readers; a holder's late ask raises wrap-pending, which a writer answers with a late delivery to the
// holder's current key; 6.6's H1 repeats pending while a dropped holder precedes the newest epoch's pin, a wrapped
// rotation having reopened the gate, and stops at the first commit past it; and H2, a waiting leaf's want, raises
// wrap-pending for the group's writers, whose pending run commits the Remove the leaf waits on. gkm's reconciler runs
// on the world's log and clock; hints are waited on as they land, never slept for.

import (
	"bytes"
	"errors"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
)

// A world past KF1 and the first Adds, with the reconciler running: a, its creator and admin, and b, writer leaves;
// the agent d reading by its ReaderWrap.
func newFsKeysHintWorld(t FsKeysT, newWorld FsKeysNewWorld) (*FsKeysWorld, *gkmservice.GkmReconciler, *FsKeysDevice, *FsKeysDevice, *FsKeysDevice) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	d := world.AddAgent("d")
	world.Grant(true, a, b, d)
	world.Admin(a)
	reconciler := world.StartReconciler(nil)
	world.AwaitPass(reconciler, func() { world.Advance() })
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	if _, err := d.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	return world, reconciler, a, b, d
}

// A pending hint about the world's group on the device's per-client gkm topic.
func (self *FsKeysWorld) pendingHint(hint *FsKeysHint) bool {
	return hint.Topic == sidecar.PushTopicGkm && hint.Hint.GetKind() == protocol.GkmHintKind_GKM_HINT_PENDING &&
		bytes.Equal(hint.Hint.GetGroupId(), self.GroupId.Bytes())
}

// FS-24: a member device joins the repo's readers with nothing committed since: the reconciler tells the idle
// writers pending, on their per-client topic, naming the group at an unchanged epoch; the writer that acts adds it
// at once, by the clock the hint went at; after Redis is lost, the next holder change is hinted the same way, its
// version above every earlier one, and done the same way.
func FsKeysScheduleIdleWriterHint(t FsKeysT, newWorld FsKeysNewWorld) {
	world, reconciler, a, b, _ := newFsKeysHintWorld(t, newWorld)
	epoch := world.NewestEpoch()
	e := world.AddMember("e", false)
	world.Grant(false, e)
	world.AwaitPass(reconciler, func() { world.Advance() })
	world.Publish()
	hinted := world.AwaitHint(a, world.pendingHint)
	world.AwaitHint(b, world.pendingHint)
	if world.NewestEpoch() != epoch {
		t.Fatalf("an epoch moved before the writers acted")
	}
	hintedAt := world.Clock.Now()
	if err := a.Client.RunPending(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("the hinted writer's pending run: %v", err)
	}
	if _, err := e.Client.JoinWelcomes(world.Ctx); err != nil {
		t.Fatal(err)
	}
	if labels := world.Roster(a); labels != "abe" {
		t.Errorf("the tree after the hinted Add: %s", labels)
	}
	// the work took no time past the hint: well within the gate's target
	if elapsed := world.Clock.Now().Sub(hintedAt); 0 < elapsed {
		t.Errorf("the hinted work took %s", elapsed)
	}

	// Redis is lost: soft state only, so the next change is hinted all the same, its version from gkm's clock, which
	// has moved on, above the last
	world.LoseRedis()
	world.Clock.Advance(time.Second)
	f := world.AddMember("f", false)
	world.Grant(false, f)
	world.AwaitPass(reconciler, func() { world.Advance() })
	world.Publish()
	again := world.AwaitHint(a, func(hint *FsKeysHint) bool { return world.pendingHint(hint) && hinted.Version < hint.Version })
	if again.Version <= hinted.Version {
		t.Errorf("a hint after the loss at version %d, not above %d", again.Version, hinted.Version)
	}
	if err := a.Client.RunPending(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("the pending run after the loss: %v", err)
	}
	if labels := world.Roster(a); labels != "abef" {
		t.Errorf("the tree after the second Add: %s", labels)
	}
}

// FS-24 and D-KEYS-19: the agent's rotation, which commits nothing, raises gkm:<group_id> to the repo's readers, a
// version above the newest epoch's, so a reader learns of a generation no commit announced.
func FsKeysScheduleRotationGroupHint(t FsKeysT, newWorld FsKeysNewWorld) {
	world, _, a, b, d := newFsKeysHintWorld(t, newWorld)
	topic := sidecar.PushTopicGkmGroup(world.GroupId)
	groupHint := func(generation uint64) func(hint *FsKeysHint) bool {
		version, err := sidecar.GkmGroupVersion(world.NewestEpoch(), generation)
		if err != nil {
			t.Fatal(err)
		}
		return func(hint *FsKeysHint) bool { return hint.Topic == topic && version <= hint.Version }
	}
	epoch := world.NewestEpoch()
	key, err := d.Client.RotateRepo(world.Ctx, world.RepoId)
	if err != nil || key.Generation() != 2 {
		t.Fatalf("the agent's rotation: %v", err)
	}
	if world.NewestEpoch() != epoch {
		t.Fatal("the agent's rotation committed")
	}
	for _, device := range []*FsKeysDevice{a, b} {
		world.AwaitHint(device, groupHint(2))
		if err := device.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
			t.Fatal(err)
		}
		if held, err := device.Client.CurrentRepoKey(world.Ctx, world.RepoId); err != nil || held.Generation() != 2 {
			t.Errorf("%s does not hold the generation the hint named: %v", device.Label, err)
		}
	}
}

// FS-24 and §10.6's late wraps row: the agent replaces its ReaderKey and asks for the newest generation under the new
// key's k8: gkm tells the writers wrap-pending naming it, a writer delivers late at the new key, and the agent opens
// the generation with that key.
func FsKeysScheduleLateAsk(t FsKeysT, newWorld FsKeysNewWorld) {
	world, _, a, _, d := newFsKeysHintWorld(t, newWorld)
	if _, err := a.Client.RotateRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatal(err)
	}
	staged := world.WrapRecipients(2)
	if !staged[d.SidecarId()] {
		t.Fatal("generation 2 holds no staged ReaderWrap to the agent")
	}
	// a new key past gkm's one replacement a day, and the ask under its k8
	world.Clock.Advance(25 * time.Hour)
	d.PublishReaderKey()
	if _, err := d.Api.Wraps(world.Ctx, world.RepoId, world.GroupId, 2, &sidecar.GkmWrapsQuery{
		Recipient: fsKeysRecipient(d.SidecarId()), Want: d.readerKeySha256[:8], Since: world.Clock.Now(),
	}); err != nil {
		t.Fatalf("the late ask: %v", err)
	}
	hint := world.AwaitHint(a, func(hint *FsKeysHint) bool {
		return hint.Hint.GetKind() == protocol.GkmHintKind_GKM_HINT_WRAP_PENDING && string(hint.Hint.GetRecipient()) == fsKeysRecipient(d.SidecarId())
	})
	if err := a.Client.DeliverLate(world.Ctx, world.RepoId, string(hint.Hint.GetRecipient())); err != nil {
		t.Fatalf("the late delivery: %v", err)
	}
	// the agent forgets its old key's private half: only the late delivery to its new key opens generation 2
	for keySha256 := range d.readerPrivateKeys {
		if !bytes.Equal([]byte(keySha256), d.readerKeySha256) {
			delete(d.readerPrivateKeys, keySha256)
		}
	}
	d.Restart()
	if err := d.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("the agent's sync: %v", err)
	}
	held, err := d.Client.CurrentRepoKey(world.Ctx, world.RepoId)
	if err != nil || held.Generation() != 2 {
		t.Fatalf("the agent's generation 2 by its new key: %v", err)
	}
}

// One whole pass of the reconciler's sweeps, page by page from the start.
func (self *FsKeysWorld) Sweep(reconciler *gkmservice.GkmReconciler) {
	self.t.Helper()
	cursor := &gkmservice.GkmSweepCursor{}
	for pageCount := 0; ; pageCount += 1 {
		next, done, err := reconciler.SweepPage(self.Ctx, cursor)
		if err != nil {
			self.t.Fatalf("a sweep page: %v", err)
		}
		if done {
			return
		}
		if 1000 < pageCount {
			self.t.Fatal("the sweep never ended")
		}
		cursor = next
	}
}

// How many of the group's epochs gkm still holds.
func (self *FsKeysWorld) EpochCount() int {
	return len(self.objects(gkmservice.GkmEpochPrefix(self.GroupId)))
}

// FS-62's gkm part (§10.6's retention, gkm-10): {gka_} is soft state, and losing it deletes no epoch: the reconciler
// deletes nothing until the ack family a leaf's next ack makes again has existed 30 days, however old the epochs are,
// where the twin, its family never lost, deletes every epoch past 30 days that every recent ack passed, never the
// newest.
func FsKeysScheduleLostAcks(t FsKeysT, newWorld FsKeysNewWorld) {
	for _, lost := range []bool{false, true} {
		world, reconciler, a, b, _ := newFsKeysHintWorld(t, newWorld)
		for _, device := range []*FsKeysDevice{a, b} {
			if err := device.Client.SelfUpdate(world.Ctx, world.RepoId); err != nil {
				t.Fatal(err)
			}
			for _, other := range []*FsKeysDevice{a, b} {
				if err := other.Client.SyncRepo(world.Ctx, world.RepoId); err != nil {
					t.Fatal(err)
				}
			}
		}
		newest := world.NewestEpoch()
		epochCount := world.EpochCount()
		ack := func() {
			for _, device := range []*FsKeysDevice{a, b} {
				if err := device.Api.Ack(world.Ctx, world.RepoId, world.GroupId, newest); err != nil {
					t.Fatalf("%s's ack: %v", device.Label, err)
				}
			}
		}
		ack()
		if lost {
			// Redis is lost a day on, and the leaves' daily acks make the family again a day later: on day 31 the
			// epochs are 31 days old and the family 29
			world.Clock.Advance(24 * time.Hour)
			world.LoseRedis()
			world.Clock.Advance(24 * time.Hour)
			ack()
			world.Clock.Advance(29 * 24 * time.Hour)
			world.Sweep(reconciler)
			if count := world.EpochCount(); count != epochCount {
				t.Fatalf("a sweep 29 days into a family made again deleted %d epochs", epochCount-count)
			}
			// the leaves go on acking daily, which renews the family's 31 days
			ack()
			world.Clock.Advance(2 * 24 * time.Hour)
			ack()
		} else {
			world.Clock.Advance(30*24*time.Hour + time.Hour)
		}
		world.Sweep(reconciler)
		if count := world.EpochCount(); count != 1 || world.EpochObject(newest) == nil {
			t.Errorf("past 30 days (lost %v), %d epochs stand, the newest %v", lost, count, world.EpochObject(newest) != nil)
		}
	}
}

// How many hints device was told that match takes.
func (self *FsKeysWorld) HintCount(device *FsKeysDevice, match func(hint *FsKeysHint) bool) int {
	count := 0
	for _, hint := range self.Hints(device) {
		if match(hint) {
			count += 1
		}
	}
	return count
}

// The reconciler's next pass after the world's clock moves past its gate interval, its timer's own wake.
func (self *FsKeysWorld) AwaitTimedPass(reconciler *gkmservice.GkmReconciler) {
	self.t.Helper()
	interval := gkmservice.DefaultGkmReconcilerSettings().DroppedLeafHintInterval
	self.AwaitPass(reconciler, func() { self.Clock.Advance(interval + time.Second) })
}

// FS-24, 6.6's H1: x is revoked and the reconciler hints pending; the agent's wrapped rotation reopens the gate while
// x's leaf stands, and pending repeats at each DroppedLeafHintInterval all the same; a's Remove, the first commit past
// the drop, stops it.
func FsKeysScheduleDroppedHolderHint(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	b := world.AddMember("b", false)
	x := world.AddMember("x", false)
	d := world.AddAgent("d")
	world.Grant(true, a, b, x, d)
	world.Admin(a)
	reconciler := world.StartReconciler(nil)
	world.AwaitPass(reconciler, func() { world.Advance() })
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	world.Again("d's first wrap", func() error {
		_, err := d.Client.CurrentRepoKey(world.Ctx, world.RepoId)
		return err
	})
	world.Revoke(x)
	x.Offline = true
	world.AwaitPass(reconciler, func() { world.Advance() })
	world.AwaitHint(a, world.pendingHint)
	if key, err := d.Client.EnsureWritable(world.Ctx, world.RepoId); err != nil || key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("the wrapped writer's REMOVE rotation: %v", err)
	}
	generation2 := world.Generation(2)
	if !sidecar.GkmGatePasses(world.Log.Tip(), world.RepoId, generation2.Rotate.GetAuth(), world.GenerationTime(generation2), world.Clock.Now()) {
		t.Fatalf("the wrapped rotation does not reopen the gate")
	}
	// the gate open, x's leaf standing: pending repeats
	before := world.HintCount(a, world.pendingHint)
	world.AwaitTimedPass(reconciler)
	if repeated := world.HintCount(a, world.pendingHint); repeated <= before {
		t.Errorf("no pending repeated while the dropped leaf stands: %d hints, %d before", repeated, before)
	}
	// a's Remove, the first commit past the drop: pending stops
	world.Again("a's sync", func() error { return a.Client.SyncRepo(world.Ctx, world.RepoId) })
	world.Again("a's Remove", func() error { return a.Client.RunPending(world.Ctx, world.RepoId) })
	if labels := world.Roster(a); labels != "ab" {
		t.Fatalf("the tree after a's Remove: %s", labels)
	}
	after := world.HintCount(a, world.pendingHint)
	world.AwaitTimedPass(reconciler)
	world.AwaitTimedPass(reconciler)
	if stopped := world.HintCount(a, world.pendingHint); stopped != after {
		t.Errorf("pending went on past the first commit past the drop: %d hints, %d after it", stopped, after)
	}
}

// FS-24, 6.6's H2: the read_only leaf c's due self-update waits under R3 while revoked x's leaf stands, a wrapped
// rotation having reopened the gate; c asks group-info?want=, which gkm answers by hinting wrap-pending to the
// group's writers; the hint's work on a, its pending run, commits the Remove, and c's self-update then lands.
func FsKeysScheduleWaitingLeafWant(t FsKeysT, newWorld FsKeysNewWorld) {
	world := newWorld(protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.AddMember("a", false)
	c := world.AddMember("c", true)
	x := world.AddMember("x", false)
	d := world.AddAgent("d")
	world.Grant(true, a, x, d)
	world.Grant(false, c)
	world.Admin(a)
	world.Advance()
	world.Publish()
	world.Create(a)
	world.AddPending(a)
	world.Again("d's first wrap", func() error {
		_, err := d.Client.CurrentRepoKey(world.Ctx, world.RepoId)
		return err
	})
	world.Revoke(x)
	x.Offline = true
	world.Advance()
	if _, err := d.Client.EnsureWritable(world.Ctx, world.RepoId); err != nil {
		t.Fatalf("the wrapped writer's REMOVE rotation: %v", err)
	}
	wantHint := func(hint *FsKeysHint) bool {
		return hint.Topic == sidecar.PushTopicGkm && hint.Hint.GetKind() == protocol.GkmHintKind_GKM_HINT_WRAP_PENDING &&
			bytes.Equal(hint.Hint.GetGroupId(), world.GroupId.Bytes()) && len(hint.Hint.GetRecipient()) == 0
	}
	before := world.HintCount(a, wantHint)
	world.Again("c's sync", func() error { return c.Client.SyncRepo(world.Ctx, world.RepoId) })
	// upkeep's self-update, due once its interval has passed since c's join
	world.Clock.Advance(sidecar.DefaultGkmSettings().SelfUpdateInterval + time.Minute)
	if due, err := c.Client.SelfUpdateDue(world.RepoId); err != nil || !due {
		t.Fatalf("c's self-update is not due: %v", err)
	}
	if err := c.Client.RunSelfUpdate(world.Ctx, world.RepoId); !errors.Is(err, sidecar.ErrGkmDroppedLeafStands) {
		t.Fatalf("the read_only leaf's self-update while the revoked leaf stands: %v", err)
	}
	world.AwaitHint(a, func(hint *FsKeysHint) bool { return wantHint(hint) && before < world.HintCount(a, wantHint) })
	world.Again("a's sync", func() error { return a.Client.SyncRepo(world.Ctx, world.RepoId) })
	world.Again("a's pending run", func() error { return a.Client.RunPending(world.Ctx, world.RepoId) })
	if labels := world.Roster(a); labels != "ac" {
		t.Fatalf("the tree after a's Remove: %s", labels)
	}
	world.Again("c's sync after the Remove", func() error { return c.Client.SyncRepo(world.Ctx, world.RepoId) })
	epoch := world.NewestEpoch()
	world.Again("c's self-update after the Remove", func() error { return c.Client.RunSelfUpdate(world.Ctx, world.RepoId) })
	if world.NewestEpoch() != epoch+1 {
		t.Errorf("c's self-update did not land after the Remove")
	}
	world.Again("a's sync", func() error { return a.Client.SyncRepo(world.Ctx, world.RepoId) })
	world.AgreeOnEpoch(a, c)
}
