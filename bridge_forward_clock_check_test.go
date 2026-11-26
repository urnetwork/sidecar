// The Forwarder's clock after sleep or a clock step (core_clock_check.go, bridge_forward.go's comment; owner decision
// 789's seam, QD-1422), on a clock whose wall time jumps while its timers stand still, as a device's does across a
// sleep: the next follow and the posture's overdue-alarm points the device slept past come only at CheckClock, which
// follows or reads the decision, where the posture raises narrowing_overdue once for the newest point passed, and arms
// the loop's wait again from the wall clock; a hint, a revocation's, is followed at once with no check; and checks from
// many goroutines are one, and one after Close does nothing.

package sidecar

import (
	"context"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A clock whose wall time can jump while its timers stand still, as a device's does across a sleep or a step of its
// clock forward: Now reads the awake clock's time plus the time slept, and a timer runs on the awake clock beneath,
// whose time counts only while the device is awake, as Go's runtime timers do (mach_absolute_time on darwin,
// CLOCK_MONOTONIC on linux). A timeout that is not positive fires at once, as Clock says, whatever the clock beneath
// does with one, and AfterFunc's call then runs on the caller's goroutine. Safe for concurrent use.
type testSleepingClock struct {
	awake Clock

	stateLock sync.Mutex
	slept     time.Duration
}

func newTestSleepingClock(awake Clock) *testSleepingClock {
	return &testSleepingClock{awake: awake}
}

// The wall clock: the awake time plus the time slept.
func (self *testSleepingClock) Now() time.Time {
	self.stateLock.Lock()
	slept := self.slept
	self.stateLock.Unlock()
	return self.awake.Now().Add(slept)
}

// See Clock: on the awake clock.
func (self *testSleepingClock) After(timeout time.Duration) <-chan time.Time {
	if timeout <= 0 {
		fired := make(chan time.Time, 1)
		fired <- self.Now()
		return fired
	}
	return self.awake.After(timeout)
}

// See Clock: on the awake clock.
func (self *testSleepingClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	if timeout <= 0 {
		function()
		return func() bool { return false }
	}
	return self.awake.AfterFunc(timeout, function)
}

// Sleeps for timeout: the wall clock moves on, and no timer fires.
func (self *testSleepingClock) sleep(timeout time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.slept += timeout
}

// How long a test waits for what a goroutine of the code under test does before it fails: the guard, never the proof.
const testClockCheckGuardTimeout = time.Minute

// A posture as the Forwarder reads it, pending with one narrowing entry waiting, whose overdue-alarm points are the
// test's: a read of the decision at or past a point not yet raised raises once, for the newest point passed, and names
// the next point (DESIGN-DETAILS 4.2.5's once a point). Safe for concurrent use.
type testClockCheckSink struct {
	clock Clock

	stateLock sync.Mutex
	// the alarm points, earliest first
	points []time.Time
	// how many points are raised or passed by a raise
	passed int
	raises int
}

func (self *testClockCheckSink) SetPending(pending *bridge.Pending) error {
	return nil
}

func (self *testClockCheckSink) SetState(state *bridge.BridgeState, log *BridgeStateLog) error {
	return nil
}

func (self *testClockCheckSink) ApplyDeltas(log *BridgeStateLog) error {
	return nil
}

func (self *testClockCheckSink) SetFork(fork bool) error {
	return nil
}

func (self *testClockCheckSink) Decision() BridgeSinkDecision {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	decision := BridgeSinkDecision{State: BridgeSinkPending, WaitingCount: 1}
	passed := self.passed
	for passed < len(self.points) && !self.points[passed].After(now) {
		passed += 1
	}
	if 0 < passed {
		decision.Overdue = &BridgeSinkOverdue{N: 7, Age: now.Sub(self.points[0]), Raised: self.passed < passed}
		if self.passed < passed {
			self.raises += 1
		}
	}
	self.passed = passed
	if passed < len(self.points) {
		decision.NextAlarmAt = self.points[passed]
	}
	return decision
}

// How many times the posture raised its alarm.
func (self *testClockCheckSink) raiseCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.raises
}

// A Forwarder's fakes for its clock: a projection that answers every read with nothing past the tip and tells the test
// of each, the sink above, and the sleeping clock over a test clock that tells the test of each wait it arms.
type testForwarderClockWorld struct {
	t        *testing.T
	awake    *testConfigClock
	clock    *testSleepingClock
	sink     *testClockCheckSink
	settings *ForwarderSettings
	// one value for each read of the projection, a follow's
	reads chan struct{}
	// each bridge_alarm the Forwarder raised
	alarms chan SidecarBridgeAlarm
}

func newTestForwarderClockWorld(t *testing.T) *testForwarderClockWorld {
	awake := newTestConfigClock()
	clock := newTestSleepingClock(awake)
	return &testForwarderClockWorld{
		t:        t,
		awake:    awake,
		clock:    clock,
		sink:     &testClockCheckSink{clock: clock},
		settings: DefaultForwarderSettings(ForwarderHostApple),
		reads:    make(chan struct{}, 64),
		alarms:   make(chan SidecarBridgeAlarm, 64),
	}
}

// See ConfigProjectionReader: nothing past the tip.
func (self *testForwarderClockWorld) ReadConfigProjection(ctx context.Context, after uint64) (*ConfigProjection, error) {
	self.reads <- struct{}{}
	return &ConfigProjection{}, nil
}

// A Forwarder over the world, closed at the test's end.
func (self *testForwarderClockWorld) forwarder() *Forwarder {
	self.t.Helper()
	networkId := testConfigId("clock check network")
	genesisSha256 := sha256.Sum256([]byte("clock check genesis"))
	forwarder, err := NewForwarder(context.Background(), &ForwarderArgs{
		NetworkId:  networkId,
		SidecarId:  testConfigId("clock check sidecar"),
		Pending:    &bridge.Pending{NetworkId: networkId.Bytes(), GenesisSha256: genesisSha256[:]},
		Projection: self,
		Store:      newTestConfigClientStore(),
		Keys:       &testForwarderKeys{},
		Sink:       self.sink,
		Emit: func(event SidecarEvent) {
			if event.Kind == SidecarEventBridgeAlarm {
				self.alarms <- event.BridgeAlarm
			}
		},
		Clock:    self.clock,
		Log:      NewNoopLogger(),
		Settings: self.settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(forwarder.Close)
	return forwarder
}

// Waits for the Forwarder's next read of the projection.
func (self *testForwarderClockWorld) awaitRead() {
	self.t.Helper()
	select {
	case <-self.reads:
	case <-time.After(testClockCheckGuardTimeout):
		self.t.Fatal("the Forwarder did not follow")
	}
}

// Waits until the Forwarder's loop arms a wait of timeout on the awake clock: the loop is then idle in its select.
func (self *testForwarderClockWorld) awaitArmed(timeout time.Duration) {
	self.t.Helper()
	guard := time.After(testClockCheckGuardTimeout)
	for {
		select {
		case armed := <-self.awake.armed:
			if armed == timeout {
				return
			}
		case <-guard:
			self.t.Fatalf("the Forwarder armed no wait of %v", timeout)
		}
	}
}

// Fails on a follow or an alarm the loop has made since the last read of each, which an idle loop cannot.
func (self *testForwarderClockWorld) expectQuiet(what string) {
	self.t.Helper()
	select {
	case <-self.reads:
		self.t.Fatalf("%s: the Forwarder followed", what)
	case alarm := <-self.alarms:
		self.t.Fatalf("%s: the Forwarder raised %s", what, alarm)
	default:
	}
}

// The next follow, an hour after the last, the device slept past: the loop's wait stood on the awake clock, so no
// follow came. CheckClock follows at once and arms the next follow an hour from the wall clock's now, so the awake
// clock moving a second short of the hour follows nothing, and the second more follows.
func TestForwarderCheckClockFollowsWhatTheDeviceSleptPast(t *testing.T) {
	world := newTestForwarderClockWorld(t)
	if world.settings.FollowInterval != time.Hour {
		t.Fatalf("the follow's interval is %v", world.settings.FollowInterval)
	}
	forwarder := world.forwarder()
	world.awaitRead()
	world.awaitArmed(time.Hour)

	world.clock.sleep(2 * time.Hour)
	world.expectQuiet("slept past the follow with no check")
	forwarder.CheckClock()
	world.awaitRead()
	world.awaitArmed(time.Hour)
	if status := forwarder.Status(); status.FollowCount != 2 {
		t.Fatalf("%d follows", status.FollowCount)
	}

	// the loop's wait, armed at the check, stands until the awake clock has moved the hour
	world.awake.Advance(time.Hour - time.Second)
	world.expectQuiet("a second before the next follow")
	world.awake.Advance(time.Second)
	world.awaitRead()
}

// The posture's overdue-alarm points (DESIGN-DETAILS 4.2.5: an entry's age of 10, 30 and 70 min, then 150) the device
// slept past, through 70 min: the loop's wait for the first stood on the awake clock, so nothing was raised. CheckClock
// reads the decision, where the posture raises narrowing_overdue once, for the newest point passed, which the Forwarder
// raises as bridge_alarm, and arms its wait for the next point from the wall clock, so the awake clock moving to it
// raises the next and no sooner.
func TestForwarderCheckClockRaisesTheOverdueAlarmTheDeviceSleptPast(t *testing.T) {
	world := newTestForwarderClockWorld(t)
	world.settings.FollowInterval = 24 * time.Hour
	start := world.clock.Now()
	world.sink.points = []time.Time{start.Add(10 * time.Minute), start.Add(30 * time.Minute), start.Add(70 * time.Minute), start.Add(150 * time.Minute)}
	forwarder := world.forwarder()
	world.awaitRead()
	world.awaitArmed(10 * time.Minute)

	world.clock.sleep(75 * time.Minute)
	world.expectQuiet("slept past three points with no check")
	forwarder.CheckClock()
	select {
	case alarm := <-world.alarms:
		if alarm != SidecarBridgeAlarm(ForwarderAlarmNarrowingOverdue) {
			t.Fatalf("raised %s", alarm)
		}
	case <-time.After(testClockCheckGuardTimeout):
		t.Fatal("the check raised no alarm")
	}
	// the next point, 150 min, is 75 min of the wall clock on
	world.awaitArmed(75 * time.Minute)
	if raises := world.sink.raiseCount(); raises != 1 {
		t.Fatalf("the posture raised %d times for the points slept past", raises)
	}
	world.expectQuiet("after the check")

	world.awake.Advance(75*time.Minute - time.Second)
	world.expectQuiet("a second before the next point")
	world.awake.Advance(time.Second)
	select {
	case <-world.alarms:
	case <-time.After(testClockCheckGuardTimeout):
		t.Fatal("the next point raised no alarm")
	}
	if raises := world.sink.raiseCount(); raises != 2 {
		t.Fatalf("the posture raised %d times", raises)
	}
}

// A hint, as a revocation's entry brings, is followed at once whatever the clock: the posture applies the revocation
// as the page arrives, and needs no check.
func TestForwarderHintNeedsNoCheckAfterSleep(t *testing.T) {
	world := newTestForwarderClockWorld(t)
	forwarder := world.forwarder()
	world.awaitRead()
	world.awaitArmed(time.Hour)
	world.clock.sleep(10 * time.Minute)
	forwarder.ReceiveHint(0)
	world.awaitRead()
}

// Checks from many goroutines at once while nothing is due are one or a few turns of the loop, none following; and a
// check after Close does nothing and returns.
func TestForwarderCheckClockFromManyGoroutinesAndAfterClose(t *testing.T) {
	world := newTestForwarderClockWorld(t)
	forwarder := world.forwarder()
	world.awaitRead()
	world.awaitArmed(time.Hour)
	checks := sync.WaitGroup{}
	for range 32 {
		checks.Add(1)
		go func() {
			defer checks.Done()
			forwarder.CheckClock()
		}()
	}
	checks.Wait()
	// each turn a check makes arms the same hour again, the wall clock not having moved
	world.awaitArmed(time.Hour)
	if err := forwarder.Witness(nil, false); err != nil {
		t.Fatal(err)
	}
	// the witness's own follow, and none of the checks'
	world.awaitRead()
	world.expectQuiet("after the checks and the witness")
	forwarder.Close()
	forwarder.CheckClock()
}
