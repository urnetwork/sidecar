// QD-1202 on the subscriber's rounds (evs_subscribe_pin_wait.go) on the stand-in evs: a subscriber of two refs of one
// repo whose config is a ConfigClient following the log through api's projection, which serves only what the test
// publishes. A statement on main pinned at a base the follower does not hold holds main alone: the round that meets it
// never waits for the log, the other ref's commits are heard in the round their hint wakes, the held ref is retried
// once its bound passes and withheld again while its log stays behind, and it is heard once the log reaches the pin.

package sidecar

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A subscriber of main and of another ref of a pin-ahead world, each through a subscription of its own, its config
// the world's follower and every bound its holds arm on bounds, which the test ends.
type evsTestPinWaitWorld struct {
	*evsTestPinAheadWorld
	// the other ref, a world of its own beside main sharing its repo, keys and signer
	other      *evsTestWorld
	subscriber *evsTestClient
	bounds     chan evsTestPinWaitBound
	// main's subscription's changes, and the other ref's
	held   *evsTestChanges
	onTime *evsTestChanges
	// the follower's pin when the world was made, which the other ref's pushes are pinned at
	behind *bridge.AuthPin
	// the last hint's push sequence
	sequence uint64
}

// The world, each ref holding one commit under docs/ at the follower's pin, both subscribed and their leases' rereads
// run, which raise nothing.
func newEvsTestPinWaitWorld(t *testing.T) *evsTestPinWaitWorld {
	t.Helper()
	ahead := newEvsTestPinAheadWorld(t)
	self := &evsTestPinWaitWorld{
		evsTestPinAheadWorld: ahead,
		other:                ahead.world.otherRef([]byte("other")),
		held:                 &evsTestChanges{},
		onTime:               &evsTestChanges{},
		behind:               ahead.client.Pin(),
		sequence:             99,
	}
	ahead.push(&evsTestChange{path: "docs/a", content: []byte("main before the base")})
	self.pushOther("docs/a", "the other ref before the base")
	leases := newEvsTestLeases(ahead.world)
	self.subscriber = newEvsSubscribeTest(t, ahead.world, leases, newEvsTestStore(t))
	// the hourly resync half an hour on, out of this test's way
	self.subscriber.client.subscriber.random = func(limit time.Duration) time.Duration { return limit / 2 }
	ahead.follow(self.subscriber)
	self.bounds = evsTestBoundedReader(self.subscriber)
	ctx := context.Background()
	repo := self.subscriber.client.Repo(ahead.repoId)
	if _, err := repo.Subscribe(ctx, &EvsSubscribeArgs{RefName: EvsMainRefName, Paths: []string{"docs"}, Changes: self.held.add}); err != nil {
		t.Fatal(err)
	}
	otherRefId := self.other.refId
	if _, err := repo.Subscribe(ctx, &EvsSubscribeArgs{RefId: &otherRefId, Paths: []string{"docs"}, Changes: self.onTime.add}); err != nil {
		t.Fatal(err)
	}
	self.subscriber.clock.advance(self.subscriber.client.settings.SubscribeRereadDelay)
	self.subscriber.client.subscriber.runDue(ctx)
	if changes := len(self.held.versions()) + len(self.onTime.versions()); changes != 0 {
		t.Fatalf("%d changes before any commit past the pins", changes)
	}
	return self
}

// Commits path on the other ref, pinned at the follower's pin, which its log holds.
func (self *evsTestPinWaitWorld) pushOther(path string, content string) uint64 {
	self.other.authVersion, self.other.authChain = self.behind.GetVersion(), bytes.Clone(self.behind.GetChain())
	return self.other.push(&evsTestChange{path: path, content: []byte(content)})
}

// A hint naming ref's head at the next push sequence: the first one reads every subscribed ref, each after it only
// the ref it names.
func (self *evsTestPinWaitWorld) hint(ref *evsTestWorld) {
	self.sequence += 1
	ref.hint(self.subscriber, self.sequence)
}

// Waits until the subscriber's holds released count of them in all.
func (self *evsTestPinWaitWorld) awaitReleases(t *testing.T, count int) {
	t.Helper()
	evsTestAwaitPinReleases(t, self.subscriber, count)
}

// Waits until test's subscriber's holds released count of them in all.
func evsTestAwaitPinReleases(t *testing.T, test *evsTestClient, count int) {
	t.Helper()
	timeout := time.After(30 * time.Second)
	for {
		released, changed := test.client.subscriber.pinReleaseCount.Get()
		if count <= released {
			return
		}
		select {
		case <-changed:
		case <-timeout:
			t.Fatalf("%d holds released, not %d", released, count)
		}
	}
}

// main's pin on the subscriber, 0 for none.
func (self *evsTestPinWaitWorld) mainPin() uint64 {
	pin, ok, _ := self.subscriber.client.pins.Pin(self.repoId, self.world.refId)
	if !ok {
		return 0
	}
	return pin.Version
}

// A statement on main pinned at a base the follower never reaches, one api never serves, holds main alone. The round
// that meets it answers at once, main's wait for its log running off the round; the next round hears a commit on the
// other ref as it would with nothing held; and a hint naming main reads nothing of it while the wait runs. Once the
// wait's bound passes main is retried after ReadRetryWait and withheld again, raising nothing, pinning nothing and
// alarming nothing, and its next wait asks the log again. Before the change the round waited on main's log for the
// bound, which this test's clock never ends, so the other ref's commit waited with it.
func TestEvsSubscriberRoundsGoOnWhileOneRefWaitsForAPinItsLogNeverReaches(t *testing.T) {
	world := newEvsTestPinWaitWorld(t)
	subscriber := world.subscriber.client.subscriber
	settings := world.subscriber.client.settings
	ctx := context.Background()
	pin := world.base()
	world.push(&evsTestChange{path: "docs/b", content: []byte("main under a base the follower never reaches")})
	mainReads := world.world.readCount()
	world.hint(world.world)

	done := make(chan time.Time, 1)
	go func() { done <- subscriber.runDue(ctx) }()
	evsTestAnswer(t, "the round that meets main's pin", done)
	if n := world.nextWait(t); n != pin.GetVersion() {
		t.Fatalf("main's wait asked its log to reach %d, not the commit's pin %d", n, pin.GetVersion())
	}
	bound := evsTestAnswer(t, "main's bound", world.bounds)
	if bound.timeout != settings.AuthPinWaitTimeout {
		t.Fatalf("main's bound %s, the setting %s", bound.timeout, settings.AuthPinWaitTimeout)
	}
	if reads := world.world.readCount(); reads != mainReads+1 {
		t.Fatalf("the round read main %d times", reads-mainReads)
	}

	otherVersion := world.pushOther("docs/b", "the other ref, pinned where the follower stands")
	world.hint(world.other)
	subscriber.runDue(ctx)
	if got := world.onTime.versions(); !slices.Equal(got, []uint64{otherVersion}) {
		t.Fatalf("the other ref's subscription heard %v while main waited, want [%d]", got, otherVersion)
	}
	world.hint(world.world)
	subscriber.runDue(ctx)
	if reads := world.world.readCount(); reads != mainReads+1 {
		t.Fatalf("a hint naming main read it %d times more while its wait ran", reads-mainReads-1)
	}

	bound.expire()
	world.awaitReleases(t, 1)
	subscriber.runDue(ctx)
	if reads := world.world.readCount(); reads != mainReads+1 {
		t.Fatalf("main was retried before ReadRetryWait passed")
	}
	world.subscriber.clock.advance(settings.ReadRetryWait)
	subscriber.runDue(ctx)
	if reads := world.world.readCount(); reads != mainReads+2 {
		t.Fatalf("main was read %d times past its bound, not retried once", reads-mainReads-1)
	}
	if n := world.nextWait(t); n != pin.GetVersion() {
		t.Fatalf("main's next wait asked its log to reach %d, not %d", n, pin.GetVersion())
	}
	evsTestAnswer(t, "main's next bound", world.bounds)
	if got := world.held.versions(); len(got) != 0 {
		t.Errorf("main's subscription heard %v of a statement its log never reached", got)
	}
	if got := world.mainPin(); got != 1 {
		t.Errorf("main's pin %d, not 1", got)
	}
	if got := world.onTime.versions(); !slices.Equal(got, []uint64{otherVersion}) {
		t.Errorf("the other ref's subscription heard %v, want [%d]", got, otherVersion)
	}
	evsTestRequireNoAlarm(t, "the subscriber", world.subscriber)
	if got := world.client.Pin().GetVersion(); got != world.behind.GetVersion() {
		t.Errorf("the follower stands at %d, not %d", got, world.behind.GetVersion())
	}
	if alarms := world.config.headAlarms(SidecarHeadAlarmWithheld); alarms != 0 {
		t.Errorf("the follower counted api withholding a pin only evs named: %d alarms", alarms)
	}
}

// A clock whose timers fire for no one, so the rounds run at a wake, and whose bounds go on bounds for the test to
// end.
type evsTestPinWaitLoopClock struct {
	*evsSubscribeLoopClock
	bounds chan evsTestPinWaitBound
}

// Arms a bound only the test ends, by calling its expire.
func (self *evsTestPinWaitLoopClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	self.bounds <- evsTestPinWaitBound{timeout: timeout, expire: function}
	return func() bool { return true }
}

// The same on the rounds' own goroutine, as a daemon runs them: while main's wait runs, which nothing in this test
// ends, a hint naming the other ref wakes a round that raises its commit; and Close ends main's wait, releasing it,
// and joins the waiter. Before the change the loop sat in main's read, and the other ref's commit never came.
func TestEvsSubscriberLoopHearsTheOtherRefWhileOneWaitsForItsPin(t *testing.T) {
	world := newEvsTestPinWaitWorld(t)
	client := world.subscriber.client
	client.clock = &evsTestPinWaitLoopClock{
		evsSubscribeLoopClock: &evsSubscribeLoopClock{evsTestClock: world.subscriber.clock, armed: make(chan time.Duration, 1024), fire: make(chan time.Time)},
		bounds:                world.bounds,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	awaitRound := func(after int) {
		t.Helper()
		for {
			count, next := client.subscriber.roundCount.Get()
			if after < count {
				return
			}
			select {
			case <-next:
			case <-ctx.Done():
				t.Fatalf("no round after %d", after)
			}
		}
	}
	rounds, _ := client.subscriber.roundCount.Get()
	if err := client.StartSubscriptions(); err != nil {
		t.Fatal(err)
	}
	awaitRound(rounds)
	pin := world.base()
	world.push(&evsTestChange{path: "docs/b", content: []byte("main under a base the follower never reaches")})
	rounds, _ = client.subscriber.roundCount.Get()
	world.hint(world.world)
	if n := world.nextWait(t); n != pin.GetVersion() {
		t.Fatalf("main's wait asked its log to reach %d, not the commit's pin %d", n, pin.GetVersion())
	}
	evsTestAnswer(t, "main's bound", world.bounds)
	awaitRound(rounds)

	otherVersion := world.pushOther("docs/b", "the other ref, pinned where the follower stands")
	world.hint(world.other)
	if err := world.onTime.await(ctx, otherVersion); err != nil {
		t.Fatalf("the other ref's subscription while main waited: %v", err)
	}
	if got := world.held.versions(); len(got) != 0 {
		t.Errorf("main's subscription heard %v of a statement its log never reached", got)
	}
	if released, _ := client.subscriber.pinReleaseCount.Get(); released != 0 {
		t.Fatalf("%d holds released while main's wait ran", released)
	}

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		client.Close()
	}()
	evsTestAnswer(t, "Close with main's wait under way", closed)
	if released, _ := client.subscriber.pinReleaseCount.Get(); released != 1 {
		t.Errorf("Close released %d holds, not main's", released)
	}
	if got := world.held.versions(); len(got) != 0 {
		t.Errorf("main's subscription heard %v", got)
	}
	evsTestRequireNoAlarm(t, "the subscriber", world.subscriber)
}

// A delivery held for a pin: main's pin raised past its commit by a walk judging at the net's own log, which holds
// the base, and carrying no statement, as a reader that walks the ref itself raises it, then the subscriber's config
// the follower's again, a base behind, so the delivery's walk of main's log meets the statement's pin above its
// state, as it would where evs served a log other than what this device verified. The round holds main's delivery and
// delivers the other ref's commit; past the bound main's delivery is retried after ReadRetryWait and held again,
// raising nothing; and once api serves the base the wait ends, and the next round walks the log and raises main's
// commit once. Before the change the round waited on the delivery's walk, holding deliverLock and every ref behind it.
func TestEvsSubscriberDeliveryHeldForAPinDefersOnlyItsRef(t *testing.T) {
	world := newEvsTestPinWaitWorld(t)
	client := world.subscriber.client
	subscriber := client.subscriber
	ctx := context.Background()
	pin := world.base()
	mainVersion := world.push(&evsTestChange{path: "docs/b", content: []byte("main under a base the follower lacks")})
	client.args.Config = func() GkmAuthView { return world.net.log.State() }
	if err := evsTestWalkRaise(ctx, client, world.repoId, world.world.refId); err != nil {
		t.Fatal(err)
	}
	world.follow(world.subscriber)
	if got := world.mainPin(); got != mainVersion {
		t.Fatalf("the walk raised main's pin to %d, not %d", got, mainVersion)
	}
	otherVersion := world.pushOther("docs/b", "the other ref, pinned where the follower stands")
	world.hint(world.other)

	done := make(chan time.Time, 1)
	go func() { done <- subscriber.runDue(ctx) }()
	evsTestAnswer(t, "the round that meets main's pin", done)
	if n := world.nextWait(t); n != pin.GetVersion() {
		t.Fatalf("main's wait asked its log to reach %d, not the commit's pin %d", n, pin.GetVersion())
	}
	bound := evsTestAnswer(t, "main's bound", world.bounds)
	if got := world.onTime.versions(); !slices.Equal(got, []uint64{otherVersion}) {
		t.Fatalf("the other ref's subscription heard %v in the round main's delivery was held, want [%d]", got, otherVersion)
	}
	if got := world.held.versions(); len(got) != 0 {
		t.Fatalf("main's subscription heard %v before its log reached the pin", got)
	}

	bound.expire()
	world.awaitReleases(t, 1)
	world.subscriber.clock.advance(client.settings.ReadRetryWait)
	subscriber.runDue(ctx)
	if n := world.nextWait(t); n != pin.GetVersion() {
		t.Fatalf("main's retried delivery asked its log to reach %d, not %d", n, pin.GetVersion())
	}
	evsTestAnswer(t, "main's next bound", world.bounds)
	if got := world.held.versions(); len(got) != 0 {
		t.Fatalf("main's subscription heard %v past the bound", got)
	}

	world.publish()
	world.awaitReleases(t, 2)
	subscriber.runDue(ctx)
	if got := world.held.versions(); !slices.Equal(got, []uint64{mainVersion}) {
		t.Fatalf("main's subscription heard %v once its log reached the pin, want [%d]", got, mainVersion)
	}
	subscriber.runDue(ctx)
	if got := world.held.versions(); !slices.Equal(got, []uint64{mainVersion}) {
		t.Errorf("a round after raised main's commit again: %v", got)
	}
	if got := world.onTime.versions(); !slices.Equal(got, []uint64{otherVersion}) {
		t.Errorf("the other ref's subscription heard %v, want [%d]", got, otherVersion)
	}
	evsTestRequireNoAlarm(t, "the subscriber", world.subscriber)
}
