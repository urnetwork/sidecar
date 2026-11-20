package gkmservice

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// T2's GkmReconcilerState: each network's state as a test sets it, announced to the reconciler's watch.
type fakeGkmReconcilerState struct {
	stateLock       sync.Mutex
	networkStates   map[sidecar.Id]*GkmNetworkState
	sidecarNetworks map[sidecar.Id]sidecar.Id
	revokedIds      map[sidecar.Id]bool
	changed         func(change *GkmStateChange)
}

func newFakeGkmReconcilerState() *fakeGkmReconcilerState {
	return &fakeGkmReconcilerState{
		networkStates:   map[sidecar.Id]*GkmNetworkState{},
		sidecarNetworks: map[sidecar.Id]sidecar.Id{},
		revokedIds:      map[sidecar.Id]bool{},
	}
}

func (self *fakeGkmReconcilerState) Watch(changed func(change *GkmStateChange)) (func(), error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.changed = changed
	return func() {}, nil
}

func (self *fakeGkmReconcilerState) Networks() []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	networkIds := []sidecar.Id{}
	for networkId := range self.networkStates {
		networkIds = append(networkIds, networkId)
	}
	return networkIds
}

func (self *fakeGkmReconcilerState) State(ctx context.Context, networkId sidecar.Id) (*GkmNetworkState, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state, ok := self.networkStates[networkId]
	if !ok {
		return nil, errors.New("not loaded")
	}
	return state, nil
}

func (self *fakeGkmReconcilerState) SidecarStanding(ctx context.Context, sidecarId sidecar.Id) (sidecar.Id, bool, bool, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	networkId, ok := self.sidecarNetworks[sidecarId]
	return networkId, self.revokedIds[sidecarId], ok, nil
}

// Moves a network to view and announces the change, signed by signerId.
func (self *fakeGkmReconcilerState) set(networkId sidecar.Id, view sidecar.GkmAuthView, repoIds []sidecar.Id, signerId *sidecar.Id) {
	changed := func() func(change *GkmStateChange) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.networkStates[networkId] = &GkmNetworkState{View: view, RepoIds: slices.Clone(repoIds)}
		return self.changed
	}()
	if changed != nil {
		changed(&GkmStateChange{NetworkId: networkId, SignerId: signerId})
	}
}

// One network, one repo on the second cluster with its group, and a reconciler on the fixture's host.
//
// The world moves the fake clock only while the reconciler's hint loop waits, and only as far as the timer the loop
// waits on (advance), the rule of §22.8's determinism row (owner decision 549): the loop sets its next timer from the
// clock's time when a pass ends, so a move that runs on while the pass an earlier timer started is still arming sets
// that timer past the move's end, and a wake the move passed is left unrun until the clock moves again. One move of
// an hour hung TestGkmReconcilerAfterARestartSweepsAnObjectWhoseRowLeft so (tip-check's red at 59e5b8f2). Every wait
// fails the test after awaitTimeout of real time, saying what it waited for.
type gkmReconcilerWorld struct {
	t          *testing.T
	fixture    *gkmFixture
	state      *fakeGkmReconcilerState
	reconciler *GkmReconciler
	// the clock reconciler reads, which notes each timer its hint loop arms
	loopClock *gkmLoopClock
	// how long in real time one wait may take before it fails the test: §22.8's bound, the barrier driver's (QD-1101)
	awaitTimeout time.Duration
	log          *sidecartest.FakeGkmAuthLog
	networkId    sidecar.Id
	repoId       sidecar.Id
	groupId      sidecar.Id
	memberId     sidecar.Id
	signer       *gkmTestSidecar
	key1         *sidecar.EvsRepoKey
}

func newGkmReconcilerWorld(t *testing.T) *gkmReconcilerWorld {
	fixture := newGkmFixture(t)
	world := &gkmReconcilerWorld{
		t:            t,
		fixture:      fixture,
		state:        newFakeGkmReconcilerState(),
		awaitTimeout: sidecartest.DefaultBarrierDriverSettings().AwaitTimeout,
		log:          sidecartest.NewFakeGkmAuthLog(),
		networkId:    testId("network-a"),
		repoId:       testId("repo-g"),
		groupId:      testId("group-g"),
		memberId:     testId("member-a"),
	}
	fixture.placeRepo(world.repoId, "meta-2", protocol.EvsRepoState_EVS_REPO_ACTIVE)
	fixture.fileForm(world.repoId, "meta-2", 1, world.groupId)
	world.signer = fixture.newSidecar("sc-signer", memberDeviceFacts(world.memberId))
	world.startReconciler(fixture.host.ServiceHost(), DefaultGkmReconcilerSettings(), &GkmReconcilerDeps{State: world.state})
	return world
}

// Starts a reconciler on host that reads the fixture's clock through a loop clock of its own, and makes it the
// world's. The world closes none: a restart closes the one it replaces first.
func (self *gkmReconcilerWorld) startReconciler(host *sidecar.ServiceHost, settings *GkmReconcilerSettings, deps *GkmReconcilerDeps) {
	self.t.Helper()
	if deps.Networks != nil {
		// the listing arms timers of its own, which the loop clock would take for the loop's
		self.t.Fatal("the world's reconciler runs no listing")
	}
	loopClock := newGkmLoopClock(self.fixture.clock)
	host.Clock = loopClock
	reconciler, err := NewGkmReconciler(self.fixture.ctx, host, settings, deps)
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(reconciler.Close)
	self.reconciler = reconciler
	self.loopClock = loopClock
}

// The fake clock as one reconciler reads it, noting each timer the hint loop arms with the time it is set for, so the
// world knows the timer the loop waits on. With no listing, the loop is the only caller of After among the
// reconciler's goroutines: a hint's timeout is an AfterFunc. Safe for concurrent use.
type gkmLoopClock struct {
	clock  *sidecartest.FakeClock
	arming *sidecar.MonitorValue[gkmLoopArming]

	stateLock sync.Mutex
	// runs once, on the loop's goroutine, as the loop arms its next timer and before the clock holds it; nil for none
	beforeArming func()
}

// The timers the hint loop has armed.
type gkmLoopArming struct {
	// timers armed, one each pass
	count int
	// the newest one's time, at or before the clock's time when it was armed for a timer that fires at once
	at time.Time
}

func newGkmLoopClock(clock *sidecartest.FakeClock) *gkmLoopClock {
	return &gkmLoopClock{
		clock:  clock,
		arming: sidecar.NewMonitorValue(gkmLoopArming{}),
	}
}

func (self *gkmLoopClock) Now() time.Time {
	return self.clock.Now()
}

func (self *gkmLoopClock) After(timeout time.Duration) <-chan time.Time {
	beforeArming := func() func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		beforeArming := self.beforeArming
		self.beforeArming = nil
		return beforeArming
	}()
	if beforeArming != nil {
		beforeArming()
	}
	// the world moves the clock only while the loop waits, so nothing moves it between this read and the arming
	at := self.clock.Now().Add(max(0, timeout))
	fired := self.clock.After(timeout)
	self.arming.Update(func(arming gkmLoopArming) gkmLoopArming {
		return gkmLoopArming{count: arming.count + 1, at: at}
	})
	return fired
}

func (self *gkmLoopClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return self.clock.AfterFunc(timeout, function)
}

// Has fn run on the loop's goroutine as the loop arms its next timer, once: where a move of the clock that runs on
// while the loop arms lands.
func (self *gkmLoopClock) setBeforeArming(fn func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.beforeArming = fn
}

// A log position at which readers read the repo, writers write it, holders_shrunk_at is shrunkAt, and each reader in
// expiries stops reading at its time.
func (self *gkmReconcilerWorld) appendState(readers []sidecar.Id, writers []sidecar.Id, shrunkAt uint64, expiries map[sidecar.Id]time.Time) *sidecartest.FakeGkmAuthView {
	fixture := &sidecartest.FakeGkmAuthFixture{
		Rows:               sidecartest.FakeGkmAuthRows(&protocol.AclRepo{RepoId: self.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, HoldersShrunkAt: shrunkAt}),
		IdentityKeys:       map[sidecar.Id][]byte{},
		RepoReaders:        map[sidecar.Id][]sidecar.Id{self.repoId: readers},
		RepoWriters:        map[sidecar.Id][]sidecar.Id{self.repoId: writers},
		RepoReaderExpiries: map[sidecar.Id]map[sidecar.Id]time.Time{self.repoId: expiries},
	}
	allIds := slices.Clone(readers)
	for _, writerId := range writers {
		if !slices.Contains(allIds, writerId) {
			allIds = append(allIds, writerId)
		}
	}
	sidecarRows, memberRow := sidecartest.FakeGkmAuthMemberDevices(self.memberId, allIds...)
	fixture.Rows.Sidecars = sidecarRows
	fixture.Rows.Members = []*bridge.MemberRow{memberRow}
	return self.log.Append(fixture)
}

// Writes gen/<g> of the group at pin and now, as a claim would have: the first from a new key, a later one from
// parent.
func (self *gkmReconcilerWorld) putGeneration(parent *sidecar.EvsRepoKey, pin *bridge.AuthPin) *sidecar.EvsRepoKey {
	self.t.Helper()
	args := &sidecar.GkmGenerationArgs{Cause: sidecar.GkmCauseRemove, Auth: pin, Time: self.fixture.clock.Now(), HoldersSha256: gkmTestHoldersSha256()}
	var key *sidecar.EvsRepoKey
	var rotate *protocol.GenRotate
	var err error
	if parent == nil {
		args.Cause = sidecar.GkmCauseRequest
		key, rotate, err = sidecar.NewGkmFirstGeneration(self.repoId, self.groupId, args)
	} else {
		key, rotate, err = parent.NextGeneration(args)
	}
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := sidecar.SignGenRotate(rotate, self.signer.sign)
	if err != nil {
		self.t.Fatal(err)
	}
	self.fixture.put("meta-2", GkmGenerationKey(self.groupId, key.Generation()), self.fixture.marshal(signed))
	return key
}

// Waits until check holds, reading it again each time the channel it gives closes, which it takes before it reads.
// Past awaitTimeout of real time it fails the test with what it waited for, what it saw last and where the clock and
// the loop stand, so a wait that cannot end costs seconds rather than the package's timeout (§22.8's determinism row).
func (self *gkmReconcilerWorld) await(what string, check func() (done bool, changed chan struct{}, seen string)) {
	self.t.Helper()
	timeout := time.After(self.awaitTimeout)
	for {
		done, changed, seen := check()
		if done {
			return
		}
		select {
		case <-changed:
		case <-self.fixture.ctx.Done():
			self.t.Fatalf("the test ended while waiting for %s: %s", what, seen)
		case <-timeout:
			self.t.Fatalf("waited %s of real time for %s: %s; %s", self.awaitTimeout, what, seen, self.loopState())
		}
	}
}

// A time on the fixture's clock as its distance from the clock's start, "none" for the zero time.
func (self *gkmReconcilerWorld) clockTime(at time.Time) string {
	if at.IsZero() {
		return "none"
	}
	return "+" + at.Sub(sidecartest.DefaultClockStart()).String()
}

// Where the clock and the loop stand, for a wait that fails.
func (self *gkmReconcilerWorld) loopState() string {
	idle, _ := self.reconciler.Idle()
	passes, _ := self.reconciler.Passes()
	arming := self.loopClock.arming.Value()
	earliest, _ := self.reconciler.earliestWake()
	finished, _ := self.reconciler.DelegationKeyDeletes()
	timerTimes := []string{}
	for _, at := range self.fixture.clock.PendingTimers() {
		timerTimes = append(timerTimes, self.clockTime(at))
	}
	return fmt.Sprintf(
		"the clock at %s; the loop idle %t after %d passes, its timer %d at %s, its earliest wake at %s; %d key deletions finished; the clock's timers at %v",
		self.clockTime(self.fixture.clock.Now()), idle, passes, arming.count, self.clockTime(arming.at), self.clockTime(earliest), finished, timerTimes,
	)
}

// Notes a change with fn once the loop waits, then waits until the reconciler holds view for the network: the pass
// that read it has read it. Noted while the loop waits, the change's wake starts the pass that reads it, and none is
// left over to start a pass the world does not see coming.
func (self *gkmReconcilerWorld) awaitNetworkState(networkId sidecar.Id, view sidecar.GkmAuthView, fn func()) {
	self.t.Helper()
	self.awaitIdle()
	fn()
	self.await("the reconciler to read the network's state", func() (bool, chan struct{}, string) {
		_, changed := self.reconciler.Passes()
		held := func() sidecar.GkmAuthView {
			self.reconciler.stateLock.Lock()
			defer self.reconciler.stateLock.Unlock()
			if entry, ok := self.reconciler.networkEntries[networkId]; ok && entry.state != nil {
				return entry.state.View
			}
			return nil
		}()
		return held == view, changed, fmt.Sprintf("it holds another view, nil %t", held == nil)
	})
}

// awaitNetworkState for the world's network.
func (self *gkmReconcilerWorld) awaitState(view sidecar.GkmAuthView, fn func()) {
	self.t.Helper()
	self.awaitNetworkState(self.networkId, view, fn)
}

// Waits until the loop has finished count passes in all.
func (self *gkmReconcilerWorld) awaitPasses(count int, what string) {
	self.t.Helper()
	self.await(what, func() (bool, chan struct{}, string) {
		passes, changed := self.reconciler.Passes()
		return count <= passes, changed, fmt.Sprintf("%d passes of %d", passes, count)
	})
}

// Waits until the loop waits on the timer it armed after its last pass, a timer the clock holds past its time, with no
// state change noted for it and no wake signalled, and returns what it armed. Until the clock reaches that timer or a
// test notes a change, nothing moves the loop.
func (self *gkmReconcilerWorld) awaitArming() gkmLoopArming {
	self.t.Helper()
	var arming gkmLoopArming
	self.await("the loop to wait on a timer the clock holds", func() (bool, chan struct{}, string) {
		// every move of the loop closes this: a pass sets idle false, its arming sets it true
		idle, changed := self.reconciler.Idle()
		passes, _ := self.reconciler.Passes()
		arming = self.loopClock.arming.Value()
		now := self.fixture.clock.Now()
		pending := func() bool {
			self.reconciler.stateLock.Lock()
			defer self.reconciler.stateLock.Unlock()
			return 0 < len(self.reconciler.pendingChanges) || self.reconciler.resyncPending || 0 < len(self.reconciler.wake)
		}()
		held := slices.ContainsFunc(self.fixture.clock.PendingTimers(), arming.at.Equal)
		done := idle && arming.count == passes && now.Before(arming.at) && held && !pending
		return done, changed, fmt.Sprintf("idle %t, %d timers armed for %d passes, the newest at %s, held %t, a change or wake pending %t", idle, arming.count, passes, self.clockTime(arming.at), held, pending)
	})
	return arming
}

// awaitArming, held to the loop's own schedule: the timer it waits on is no later than its earliest network wake or
// sweep, which a move of the clock while it armed would leave behind (the type's header). Returns the timer's time.
func (self *gkmReconcilerWorld) awaitIdle() time.Time {
	self.t.Helper()
	arming := self.awaitArming()
	if earliest, found := self.reconciler.earliestWake(); found && earliest.Before(arming.at) {
		self.t.Fatalf("the loop waits on a timer at %s, past its earliest wake at %s: the clock moved while it armed", self.clockTime(arming.at), self.clockTime(earliest))
	}
	return arming.at
}

// Moves the clock forward by timeout, as advanceTo does.
func (self *gkmReconcilerWorld) advance(timeout time.Duration) {
	self.t.Helper()
	self.advanceTo(self.fixture.clock.Now().Add(timeout))
}

// Moves the clock forward to target one timer of the loop at a time (§22.8's determinism row; owner decision 549):
// each move ends at the timer the loop waits on, once the clock holds it, and the next starts only once the pass that
// timer starts has ended and the loop waits on its next, so no move passes a timer the loop has not yet armed. Returns
// with the loop waiting on a timer past target: every network's wake and sweep, every retry and every gate's hint due
// by target has run in its own pass, whichever network it was.
func (self *gkmReconcilerWorld) advanceTo(target time.Time) {
	self.t.Helper()
	for {
		armedAt := self.awaitIdle()
		if target.Before(armedAt) {
			self.fixture.clock.AdvanceTo(target)
			return
		}
		passes, _ := self.reconciler.Passes()
		self.fixture.clock.AdvanceTo(armedAt)
		self.awaitPasses(passes+1, "the pass the loop's timer at "+self.clockTime(armedAt)+" starts")
	}
}

// The pending hints a sidecar's client holds about the group.
func (self *gkmReconcilerWorld) pendingHints(sidecarId sidecar.Id) int {
	self.t.Helper()
	count := 0
	for _, hint := range self.fixture.hints(sidecarId) {
		if hint.GetKind() == protocol.GkmHintKind_GKM_HINT_PENDING && sidecar.Id(hint.GetGroupId()) == self.groupId {
			count += 1
		}
	}
	return count
}

// §10.6's pending changes: a shrink hints the writers, the revoking device first, and again every interval while the
// gate stays closed; a covering generation stops it; an expiry, which no entry announces, closes the gate at its time
// and hints within one interval.
func TestGkmReconcilerHintsAShrinkAndAnExpiryWithinOneInterval(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	writer, readerA, readerB := testId("sc-writer"), testId("sc-reader-a"), testId("sc-reader-b")
	for _, sidecarId := range []sidecar.Id{writer, readerA, readerB} {
		fixture.clientOf(sidecarId)
	}
	view1 := world.appendState([]sidecar.Id{writer, readerA, readerB}, []sidecar.Id{writer}, 0, nil)
	world.key1 = world.putGeneration(nil, view1.Pin())
	world.awaitState(view1, func() { world.state.set(world.networkId, view1, []sidecar.Id{world.repoId}, nil) })
	if count := world.pendingHints(writer); count != 0 {
		t.Fatalf("a first sight with the gate open hinted: %d", count)
	}

	// A is revoked: a shrink at position 2, which gen/1 does not cover
	view2 := world.appendState([]sidecar.Id{writer, readerB}, []sidecar.Id{writer}, 2, nil)
	world.awaitState(view2, func() { world.state.set(world.networkId, view2, []sidecar.Id{world.repoId}, &writer) })
	if count := world.pendingHints(writer); count != 1 {
		t.Fatalf("pending hints after the shrink: %d", count)
	}
	if count := world.pendingHints(readerB); count != 0 {
		t.Errorf("a reader that writes nothing was hinted: %d", count)
	}
	world.advance(world.reconciler.settings.PendingHintInterval)
	if count := world.pendingHints(writer); count != 2 {
		t.Errorf("pending hints one interval into a closed gate: %d", count)
	}

	// a rotation covering the shrink reopens the gate, and the hints stop
	key2 := world.putGeneration(world.key1, view2.Pin())
	world.advance(world.reconciler.settings.PendingHintInterval)
	world.advance(world.reconciler.settings.PendingHintInterval)
	if count := world.pendingHints(writer); count != 2 {
		t.Errorf("pending hints once a generation covers the shrink: %d", count)
	}

	// B's grant expires in an hour, with no entry: the gate closes then
	expiry := fixture.clock.Now().Add(time.Hour)
	view3 := world.appendState([]sidecar.Id{writer, readerB}, []sidecar.Id{writer}, 2, map[sidecar.Id]time.Time{readerB: expiry})
	world.putGeneration(key2, view3.Pin())
	world.awaitState(view3, func() { world.state.set(world.networkId, view3, []sidecar.Id{world.repoId}, nil) })
	if count := world.pendingHints(writer); count != 2 {
		t.Fatalf("a change with no shrink hinted: %d", count)
	}
	for fixture.clock.Now().Before(expiry) {
		world.advance(world.reconciler.settings.PendingHintInterval)
	}
	if count := world.pendingHints(writer); count != 3 {
		t.Errorf("pending hints within an interval of the expiry: %d", count)
	}
}

// DESIGN-DETAILS 6.2.3's H1: after a rotation that covers a shrink, the gate is open, yet pending still goes to the
// writers every DroppedLeafHintInterval while the newest epoch's pin is below the drop, since the dropped holder's
// leaf may still stand; it stops at the first epoch whose pin passes the drop.
func TestGkmReconcilerHintsWhileADroppedHolderPrecedesTheNewestEpochsPin(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	writer, readerA := testId("sc-writer"), testId("sc-reader-a")
	for _, sidecarId := range []sidecar.Id{writer, readerA} {
		fixture.clientOf(sidecarId)
	}
	putEpoch := func(epoch uint64, pin *bridge.AuthPin) {
		fixture.put("meta-2", GkmEpochKey(world.groupId, epoch), fixture.marshal(&protocol.GkmEpochObject{
			Header: &protocol.GkmCommitHeader{Generation: 1, Auth: pin}, TimeMs: fixture.clock.Now().UnixMilli(),
		}))
	}
	view1 := world.appendState([]sidecar.Id{writer, readerA}, []sidecar.Id{writer}, 0, nil)
	world.key1 = world.putGeneration(nil, view1.Pin())
	putEpoch(0, view1.Pin())
	world.awaitState(view1, func() { world.state.set(world.networkId, view1, []sidecar.Id{world.repoId}, nil) })
	if count := world.pendingHints(writer); count != 0 {
		t.Fatalf("a first sight with nothing dropped hinted: %d", count)
	}
	// A is revoked at position 2, and a wrapped writer's rotation covers it at once: the gate is open
	view2 := world.appendState([]sidecar.Id{writer}, []sidecar.Id{writer}, 2, nil)
	world.putGeneration(world.key1, view2.Pin())
	world.awaitState(view2, func() { world.state.set(world.networkId, view2, []sidecar.Id{world.repoId}, &writer) })
	hinted := world.pendingHints(writer)
	if hinted == 0 {
		t.Fatalf("no pending hint at the shrink")
	}
	// epoch 0's pin is below the drop: the hint repeats though the gate is open
	world.advance(world.reconciler.settings.DroppedLeafHintInterval)
	if count := world.pendingHints(writer); count != hinted+1 {
		t.Errorf("pending hints one interval into a dropped holder before the newest epoch: %d, was %d", count, hinted)
	}
	// a writer leaf's Remove lands at a pin past the drop: the hints stop
	putEpoch(1, view2.Pin())
	world.advance(world.reconciler.settings.DroppedLeafHintInterval)
	stopped := world.pendingHints(writer)
	world.advance(world.reconciler.settings.DroppedLeafHintInterval)
	world.advance(world.reconciler.settings.DroppedLeafHintInterval)
	if count := world.pendingHints(writer); count != stopped {
		t.Errorf("pending hints after an epoch whose pin passes the drop: %d, was %d", count, stopped)
	}
}

// Places repoId keying on clusterId as evs's PUT by creator does.
func (self *gkmFixture) placeRepoBy(repoId sidecar.Id, clusterId string, creator sidecar.Id) {
	self.t.Helper()
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: clusterId, CreatorSidecarId: creator}).Marshal()
	if err != nil {
		self.t.Fatal(err)
	}
	self.put("meta-1", sidecar.EvsPlaceKey(repoId), placeBytes)
	self.put(clusterId, GkmEvsRepoKey(repoId), self.marshal(&protocol.EvsRepoObject{
		RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, State: protocol.EvsRepoState_EVS_REPO_KEYING,
		Format: 1, NetworkId: testId("network-a").Bytes(),
	}))
}

// The pending hints a sidecar's client holds that name no group: QD-638's, for a repo with no group yet.
func (self *gkmReconcilerWorld) formlessHints(sidecarId sidecar.Id) int {
	self.t.Helper()
	count := 0
	for _, hint := range self.fixture.hints(sidecarId) {
		if hint.GetKind() == protocol.GkmHintKind_GKM_HINT_PENDING && len(hint.GetGroupId()) == 0 {
			count += 1
		}
	}
	return count
}

// QD-638 (KEYS-M2-32): a repo a tagged sidecar placed, keying with no form, has pending go to the network's config
// writers, naming no group, at the state that first holds it and every PendingHintInterval while it stands so; a
// repo a member device placed takes none, since its creator forms its group; a repo not yet placed is watched and
// hinted once it is; and the agent's repo's first form ends its hints.
func TestGkmReconcilerHintsTheConfigWritersOfAKeyingRepoAnAgentCreated(t *testing.T) {
	world := newGkmReconcilerWorld(t)
	fixture := world.fixture
	configRepoId, agentRepoId, memberRepoId, laterRepoId := testId("repo-config"), testId("repo-agent"), testId("repo-member"), testId("repo-later")
	configWriter, agent, otherWriter := testId("sc-config-writer"), testId("sc-agent"), testId("sc-other-writer")
	for _, sidecarId := range []sidecar.Id{configWriter, agent, otherWriter} {
		fixture.clientOf(sidecarId)
	}
	fixture.placeRepoBy(agentRepoId, "meta-2", agent)
	fixture.placeRepoBy(memberRepoId, "meta-2", configWriter)
	// the config repo is the Genesis's, whose row the state adds while the rows hold none (QD-719, QD-762)
	rows := sidecartest.FakeGkmAuthRows(
		&protocol.AclRepo{RepoId: agentRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
		&protocol.AclRepo{RepoId: memberRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
		&protocol.AclRepo{RepoId: laterRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
	)
	sidecarRows, memberRow := sidecartest.FakeGkmAuthMemberDevices(world.memberId, configWriter, otherWriter)
	rows.Sidecars = append(sidecarRows, &bridge.SidecarRow{SidecarId: agent.Bytes(), TagIds: [][]byte{testId("tag-agent").Bytes()}, AdmittedAt: 1})
	rows.Members = []*bridge.MemberRow{memberRow}
	view := world.log.Append(&sidecartest.FakeGkmAuthFixture{
		Rows:         rows,
		IdentityKeys: map[sidecar.Id][]byte{},
		RepoReaders:  map[sidecar.Id][]sidecar.Id{configRepoId: {configWriter, otherWriter, agent}, agentRepoId: {agent, configWriter}},
		RepoWriters:  map[sidecar.Id][]sidecar.Id{configRepoId: {configWriter}, agentRepoId: {agent}, memberRepoId: {configWriter}},
		ConfigRepoId: configRepoId,
	})
	repoIds := []sidecar.Id{configRepoId, agentRepoId, memberRepoId, laterRepoId}
	world.awaitState(view, func() { world.state.set(world.networkId, view, repoIds, nil) })
	if count := world.formlessHints(configWriter); count != 1 {
		t.Fatalf("the config writer's hints at the agent's repo's first sight: %d", count)
	}
	if count := world.formlessHints(otherWriter); count != 0 {
		t.Errorf("a member device that writes no config was hinted: %d", count)
	}
	if count := world.formlessHints(agent); count != 0 {
		t.Errorf("the agent was hinted: %d", count)
	}
	world.advance(world.reconciler.settings.PendingHintInterval)
	if count := world.formlessHints(configWriter); count != 2 {
		t.Errorf("the config writer's hints one interval on: %d", count)
	}
	// the later repo is placed by the agent: watched since its row appeared, it is hinted at the next interval
	fixture.placeRepoBy(laterRepoId, "meta-2", agent)
	world.advance(world.reconciler.settings.PendingHintInterval)
	if count := world.formlessHints(configWriter); count != 4 {
		t.Errorf("the config writer's hints once the later repo is placed: %d", count)
	}
	// a member device forms the agent's repos' groups: the hints stop
	fixture.fileForm(agentRepoId, "meta-2", 1, testId("group-agent"))
	fixture.fileForm(laterRepoId, "meta-2", 1, testId("group-later"))
	world.advance(world.reconciler.settings.PendingHintInterval)
	world.advance(world.reconciler.settings.PendingHintInterval)
	if count := world.formlessHints(configWriter); count != 4 {
		t.Errorf("the config writer's hints once the groups stand: %d", count)
	}
}
