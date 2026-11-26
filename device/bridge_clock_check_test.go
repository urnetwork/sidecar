// The clock's seam after sleep or a clock step (§17.8, owner decision 789, QD-1404): device.Bridge's waits are runtime
// timers, which count only the time a device is awake, while the rules' times are the wall clock's. On a clock whose
// wall time jumps while its timers stand still, as a device's does across a sleep: a map's expiry the device slept
// past leaves the map's flows open until CheckClock, which closes them and arms run's wait again from the wall clock;
// a check with nothing due arms a late wait again; a phone's settings take no cap, and the desktop's cap reads the
// clock again, publishing nothing short of the time and ending what lapsed once it has passed; a revocation publishes
// at once and a check leaves it in force; a check is safe from a change callback, from many goroutines and after
// Close; the link manager's wait takes both the check, which ends a replaced link's drain the device slept past, and
// the cap; and a link's age counts on the wall clock, so its rebuild is the check's to bring forward too.

package device_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A clock whose wall time can jump while its timers stand still, as a device's does across a sleep or a step of its
// clock forward: Now reads the awake clock's time plus the time slept, and timers run on the clock beneath, whose
// time counts only while the device is awake, as Go's runtime timers do (mach_absolute_time on darwin,
// CLOCK_MONOTONIC on linux). Safe for concurrent use.
type clockCheckTestClock struct {
	// the clock timers run on: the awake clock, or a held clock over it
	device.Clock
	awake *sidecartest.FakeClock

	stateLock sync.Mutex
	slept     time.Duration
}

// Puts a sleeping clock in settings over the clock they hold, whose time is awake's.
func newClockCheckTestClock(settings *device.BridgeSettings, awake *sidecartest.FakeClock) *clockCheckTestClock {
	clock := &clockCheckTestClock{Clock: settings.Clock, awake: awake}
	settings.Clock = clock
	return clock
}

// The wall clock: the awake time plus the time slept.
func (self *clockCheckTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.awake.Now().Add(self.slept)
}

// Sleeps for timeout: the wall clock moves on, and no timer fires.
func (self *clockCheckTestClock) sleep(timeout time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.slept += timeout
}

// The disposition fixture with map 1 expiring at first and map 2 at second.
func clockCheckTestFixture(first time.Time, second time.Time) *sidecartest.BridgeRulesFixture {
	fixture := dispositionTestFixture()
	fixture.Maps[0].Expires = first.UnixMilli()
	fixture.Maps[1].Expires = second.UnixMilli()
	return fixture
}

// The tags a map's flows carry, both subjects', sorted.
func clockCheckTestMapTags(mapSeed byte) []uint64 {
	tags := []uint64{
		egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(mapSeed)),
		egressTestTag(egressTestTagged, sidecartest.BridgeFixtureMapId(mapSeed)),
	}
	slices.Sort(tags)
	return tags
}

// A state test on the sleeping clock, the cap set to interval, enforcing the maps' expiries an hour and four hours on,
// once run's timer for the first stands. Returns the test and its clock.
func newClockCheckStateTest(t *testing.T, interval time.Duration) (*stateTest, *clockCheckTestClock) {
	t.Helper()
	start := time.UnixMilli(egressTestTimeMs)
	var clock *clockCheckTestClock
	test := newStateTestWithSettings(t, dispositionTestFixture(), true, func(settings *device.BridgeSettings) {
		settings.ClockCheckInterval = interval
		clock = newClockCheckTestClock(settings, settings.Clock.(*sidecartest.FakeClock))
	})
	test.log.Tick()
	test.setState(clockCheckTestFixture(start.Add(time.Hour), start.Add(4*time.Hour)), true)
	// what a new expiry's edit closes is not this file's concern
	test.closer.take()
	test.drainChanges()
	return test, clock
}

// Waits until clock has a timer at at; the context is the guard that fails a test it never comes to.
func clockCheckTestAwaitTimer(t *testing.T, clock *sidecartest.FakeClock, at time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for {
		pending, added := clock.WatchTimers()
		if slices.ContainsFunc(pending, at.Equal) {
			return
		}
		select {
		case <-added:
		case <-ctx.Done():
			t.Fatalf("no timer at %v; pending %v", at, pending)
		}
	}
}

// A phone's settings, which take no cap: run's timer stands at the map's expiry an hour on. The device sleeps two
// hours past it, and the timer, an hour of awake time away, stands: a new flow no longer takes the map at once, since
// the hook reads the wall clock (it takes rule 3, the hosted address itself), but no publish ends the map's flows.
// CheckClock does, and run's wait is armed again from the wall clock, map 2's expiry two hours of it on, so its timer
// stands two hours of awake time on, and map 2's flows end there.
func TestBridgeCheckClockEndsWhatLapsedWhileTheDeviceSlept(t *testing.T) {
	start := time.UnixMilli(egressTestTimeMs)
	test, clock := newClockCheckStateTest(t, device.MobileBridgeSettings().ClockCheckInterval)
	test.awaitTimerAt(start.Add(time.Hour))
	if pending := test.clock.PendingTimers(); !slices.Equal(pending, []time.Time{start.Add(time.Hour)}) {
		t.Fatalf("a phone's run waits on %v, want the expiry alone", pending)
	}
	mapped := test.flow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432")
	mapTag := egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(1))
	if decision := test.bridge.EgressHook().ResolveEgress(mapped); decision.Verdict != connect.EgressVerdictMap || decision.RuleTag != mapTag {
		t.Fatalf("map 1 before its expiry: %+v", decision)
	}

	clock.sleep(2 * time.Hour)
	if decision := test.bridge.EgressHook().ResolveEgress(mapped); decision.RuleTag == mapTag {
		t.Fatalf("a new flow took the map the wall clock says expired: %+v", decision)
	}
	if tags, _ := test.closer.take(); 0 < len(tags) {
		t.Fatalf("closed %v with no check", tags)
	}
	if status := test.bridge.Status(); status.ExpiredCount != 0 {
		t.Fatalf("%d expired with no check", status.ExpiredCount)
	}
	if pending := test.clock.PendingTimers(); !slices.Equal(pending, []time.Time{start.Add(time.Hour)}) {
		t.Fatalf("run's timer %v, want it standing at an hour of awake time", pending)
	}

	test.bridge.CheckClock()
	test.awaitChange()
	if tags, _ := test.closer.take(); !slices.Equal(tags, clockCheckTestMapTags(1)) {
		t.Fatalf("the check closed %v, want map 1's %v", tags, clockCheckTestMapTags(1))
	}
	if status := test.bridge.Status(); status.ExpiredCount != 1 {
		t.Fatalf("%d expired after the check", status.ExpiredCount)
	}
	test.awaitTimerAt(start.Add(2 * time.Hour))
	test.advanceTo(start.Add(2 * time.Hour))
	if tags, _ := test.closer.take(); !slices.Equal(tags, clockCheckTestMapTags(2)) {
		t.Fatalf("map 2's expiry closed %v, want %v", tags, clockCheckTestMapTags(2))
	}
}

// A check with nothing due publishes and closes nothing, and arms the wait again: the device slept half an hour, so
// map 1's expiry is half an hour of wall time on, and its flows end half an hour of awake time on, not at the hour
// the timer armed before the sleep stood at.
func TestBridgeCheckClockArmsALateWaitAgain(t *testing.T) {
	start := time.UnixMilli(egressTestTimeMs)
	test, clock := newClockCheckStateTest(t, 0)
	test.awaitTimerAt(start.Add(time.Hour))
	generation := test.bridge.EgressHook().PolicyGeneration()
	clock.sleep(30 * time.Minute)
	test.bridge.CheckClock()
	test.awaitChange()
	if tags, _ := test.closer.take(); 0 < len(tags) {
		t.Fatalf("a check with nothing due closed %v", tags)
	}
	if test.bridge.EgressHook().PolicyGeneration() <= generation {
		t.Fatal("the check did not publish at now")
	}
	test.awaitTimerAt(start.Add(30 * time.Minute))
	test.advanceTo(start.Add(30 * time.Minute))
	if tags, _ := test.closer.take(); !slices.Equal(tags, clockCheckTestMapTags(1)) {
		t.Fatalf("map 1's expiry closed %v, want %v", tags, clockCheckTestMapTags(1))
	}
}

// The desktop's cap: run's timer stands at the cap, not at the expiry an hour on; awake, the capped wait reads the
// clock short of the expiry, publishes nothing and waits again; and once the device has slept past the expiry, the
// next capped wait ends the map's flows, with no CheckClock.
func TestBridgeClockCheckIntervalCapsRunsWaitOnADesktop(t *testing.T) {
	start := time.UnixMilli(egressTestTimeMs)
	interval := device.DefaultBridgeSettings().ClockCheckInterval
	test, clock := newClockCheckStateTest(t, interval)
	test.awaitTimerAt(start.Add(interval))
	if slices.ContainsFunc(test.clock.PendingTimers(), start.Add(time.Hour).Equal) {
		t.Fatal("a desktop's run waits for the expiry uncapped")
	}
	generation := test.bridge.EgressHook().PolicyGeneration()
	test.clock.AdvanceTo(start.Add(interval))
	test.awaitTimerAt(start.Add(2 * interval))
	if test.bridge.EgressHook().PolicyGeneration() != generation {
		t.Fatal("a capped wait short of the expiry published")
	}
	select {
	case <-test.changes:
		t.Fatal("a capped wait short of the expiry told the change callbacks")
	default:
	}
	if tags, _ := test.closer.take(); 0 < len(tags) {
		t.Fatalf("a capped wait short of the expiry closed %v", tags)
	}

	clock.sleep(2 * time.Hour)
	test.advanceTo(start.Add(2 * interval))
	if tags, _ := test.closer.take(); !slices.Equal(tags, clockCheckTestMapTags(1)) {
		t.Fatalf("the capped wait after the sleep closed %v, want map 1's %v", tags, clockCheckTestMapTags(1))
	}
}

// A desktop caps by default and a phone does not; a negative cap is refused.
func TestBridgeClockCheckIntervalDefaults(t *testing.T) {
	if interval := device.DefaultBridgeSettings().ClockCheckInterval; interval != 30*time.Second {
		t.Fatalf("a desktop caps at %v", interval)
	}
	if interval := device.MobileBridgeSettings().ClockCheckInterval; interval != 0 {
		t.Fatalf("a phone caps at %v", interval)
	}
	settings := device.DefaultBridgeSettings()
	settings.ClockCheckInterval = -time.Second
	if _, err := device.NewBridge(context.Background(), device.PendingPostureStoreForTest(t), nil, settings); !errors.Is(err, device.ErrBridgeSettingsInvalid) {
		t.Fatalf("a negative cap: %v", err)
	}
}

// Nothing of a revocation waits for the clock: with run's timer standing across a sleep, a GrantRevoke closes its tag
// at once, and a check after it publishes at now and keeps it, reopening nothing and closing nothing more.
func TestBridgeCheckClockLeavesARevocationInForce(t *testing.T) {
	start := time.UnixMilli(egressTestTimeMs)
	test, clock := newClockCheckStateTest(t, 0)
	test.awaitTimerAt(start.Add(time.Hour))
	routed := test.flow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.20:443")
	if test.verdict(routed) != connect.EgressVerdictPass {
		t.Fatal("the route's flow before the revocation")
	}
	clock.sleep(10 * time.Minute)
	if err := test.bridge.Revoke(bridge.SignedType_SIGNED_GRANT_REVOKE, sidecartest.BridgeFixtureGrantId(1), test.log.Tip()+1); err != nil {
		t.Fatal(err)
	}
	revoked := []uint64{egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(1))}
	if tags, _ := test.closer.take(); !slices.Equal(tags, revoked) {
		t.Fatalf("the revocation closed %v, want %v", tags, revoked)
	}
	if test.verdict(routed) != connect.EgressVerdictDeny {
		t.Fatal("the revoked route admits")
	}
	test.drainChanges()
	test.bridge.CheckClock()
	test.awaitChange()
	if tags, _ := test.closer.take(); 0 < len(tags) {
		t.Fatalf("the check after the revocation closed %v", tags)
	}
	if test.verdict(routed) != connect.EgressVerdictDeny {
		t.Fatal("the check lifted the revocation")
	}
}

// CheckClock never blocks: called from a change callback, on the publishing goroutine, it returns and run publishes
// once more; many at once from many goroutines return and publish at least once more; and after Close it does nothing.
func TestBridgeCheckClockIsSafeFromACallbackAndAfterClose(t *testing.T) {
	test := newStateTest(t, dispositionTestFixture(), true)
	checked := make(chan struct{})
	var once sync.Once
	t.Cleanup(test.bridge.AddChangeCallback(func() {
		once.Do(func() {
			test.bridge.CheckClock()
			close(checked)
		})
	}))
	test.drainChanges()
	test.bridge.CheckClock()
	test.awaitChange()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	select {
	case <-checked:
	case <-ctx.Done():
		t.Fatal("CheckClock from a change callback did not return")
	}
	test.awaitChange()

	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			test.bridge.CheckClock()
		}()
	}
	group.Wait()
	test.awaitChange()

	closed, err := device.NewBridge(context.Background(), device.PendingPostureStoreForTest(t), nil, bridgeTestSettings(test.clock))
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	// more than the one check it holds
	closed.CheckClock()
	closed.CheckClock()
}

// Bridge.CheckClock takes the link manager a pass at now as well: a bridge with no links, whose manager waits on
// nothing, takes one at the check.
func TestBridgeCheckClockReachesTheLinks(t *testing.T) {
	test := newStateTest(t, dispositionTestFixture(), true)
	passes := test.bridge.LinksForTest().WatchForTest()
	test.bridge.CheckClock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	select {
	case <-passes:
	case <-ctx.Done():
		t.Fatal("the link manager took no pass at the check")
	}
}

// The link manager's own wall-clock time: a link replaced at 6 days drains until its window clients' strict_exp at 7,
// and the device sleeps from 6 days to 8, past it, with the manager's timer for it a day of awake time away and no
// wake waiting. The old link serves on, its drain unended, until the check, whose pass at now closes it, and the
// manager's next timer is armed from the wall clock: the new link's rebuild at 12 days, four of awake time on. The
// manager is held at each arm the test moves or sleeps by (linkTestHeldClock), the last after the new link's build,
// so no wake waits behind it.
func TestBridgeLinkCheckClockEndsADrainTheDeviceSleptPast(t *testing.T) {
	var held *linkTestHeldClock
	var clock *clockCheckTestClock
	test := newLinkTest(t, func(settings *device.BridgeSettings) {
		// no idle close in the test's days, so only the drain ends the old link
		settings.LinkIdleTimeout = 30 * 24 * time.Hour
		held = newLinkTestHeldClock(settings)
		clock = newClockCheckTestClock(settings, held.FakeClock)
	})
	start := test.clock.Now()
	rebuildAt := start.Add(6 * 24 * time.Hour)
	strictExp := start.Add(7 * 24 * time.Hour)
	// the built link's arm for its rebuild; then the replacement's arm for the old link's drain end, and the same arm
	// after the new link's build has ended
	rebuild := held.holdArmAt(rebuildAt)
	t.Cleanup(rebuild.release)
	replaced := held.holdArmAt(strictExp)
	t.Cleanup(replaced.release)
	rebuilt := held.holdArmAt(strictExp)
	t.Cleanup(rebuilt.release)
	link := test.link(4)
	old := test.open(link)
	test.awaitHeld(rebuild)
	test.clock.AdvanceTo(rebuildAt)
	rebuild.release()
	test.awaitHeld(replaced)
	replaced.release()
	test.awaitHeld(rebuilt)

	clock.sleep(2 * 24 * time.Hour)
	rebuilt.release()
	clockCheckTestAwaitTimer(t, test.clock, strictExp)
	if old.Closed() {
		t.Fatal("the old link closed with no check")
	}
	test.manager.CheckClockForTest()
	test.await("the drain's end at the check", func() bool { return old.Closed() })
	uses := test.manager.Retain([]device.BridgeLinkTarget{linkTestTarget(4)})[linkTestTarget(4)]
	if len(uses) != 1 || uses[0].Link == link || !uses[0].DrainingSince.IsZero() {
		t.Fatalf("uses after the drain %+v", uses)
	}
	clockCheckTestAwaitTimer(t, test.clock, start.Add(10*24*time.Hour))
}

// On a desktop the link manager's wait takes the cap too: a built link idles out 600 s on, and the manager reads the
// clock again each interval before then, its links as they were.
func TestBridgeClockCheckIntervalCapsTheLinksWaitOnADesktop(t *testing.T) {
	interval := device.DefaultBridgeSettings().ClockCheckInterval
	test := newLinkTest(t, func(settings *device.BridgeSettings) {
		settings.ClockCheckInterval = interval
	})
	start := test.clock.Now()
	opened := test.open(test.link(4))
	clockCheckTestAwaitTimer(t, test.clock, start.Add(interval))
	if slices.ContainsFunc(test.clock.PendingTimers(), start.Add(600*time.Second).Equal) {
		t.Fatal("a desktop's link manager waits for the idle uncapped")
	}
	test.clock.AdvanceTo(start.Add(interval))
	clockCheckTestAwaitTimer(t, test.clock, start.Add(2*interval))
	if opened.Closed() {
		t.Fatal("a capped wait closed a link short of its idle")
	}
}

// A link's age counts on the wall clock, as the window clients' strict_exp it rebuilds before does: on real time its
// build time carries no monotonic reading, which stops while the device sleeps, so the rebuild 6 days on is judged by
// the wall clock and a check of the clock or the cap brings it forward after a sleep.
func TestBridgeLinkAgeCountsOnTheWallClock(t *testing.T) {
	test := newLinkTest(t, func(settings *device.BridgeSettings) {
		// real time, whose readings carry a monotonic clock
		settings.Clock = nil
	})
	if !strings.Contains(time.Now().String(), " m=") {
		t.Fatal("CONTROL FAILED: real time carries no monotonic reading here")
	}
	link := test.link(4)
	test.open(link)
	builtAt, ok := test.manager.LinkBuiltAtForTest(link)
	if !ok {
		t.Fatal("the link has no build")
	}
	if strings.Contains(builtAt.String(), " m=") {
		t.Fatalf("the link's build time %v carries a monotonic reading", builtAt)
	}
}
