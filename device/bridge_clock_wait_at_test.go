// run's and the link manager's waits for a time (QD-1425): each sets its timer for the time itself, so a move of the
// clock by another goroutine while either is between its read of the clock and its timer's arm leaves the timer at its
// time, and it fires with no further move. Each test holds the arm, moves the clock to the time while it is held, and
// releases it, the window bridge-drain-floor-load-flake found under load; a timer set by a duration from the earlier
// read, as both once were, stands a whole wait past the time, and the test fails at its guard.

package device_test

import (
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A drain's end: run reads the clock at the drain's start and is held at its timer's arm while the clock moves to the
// floor, 600 s on; once released it publishes at once and the route's tag closes, though nothing moves the clock again.
func TestBridgeRunPublishesForAMoveBetweenItsReadAndItsArm(t *testing.T) {
	routed := egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(1))
	start := time.UnixMilli(egressTestTimeMs)
	floor := start.Add(600 * time.Second)
	draining := dispositionTestFixture()
	draining.Served[0].DrainingSince = egressTestTimeMs
	draining.Served[0].DrainUntil = egressTestTimeMs + 30_000

	var clock *stateTestHeldClock
	test := newStateTestWithSettings(t, dispositionTestFixture(), true, func(settings *device.BridgeSettings) {
		clock = newStateTestHeldClock(settings)
	})
	// the fixture times nothing, so run's next arm is the drain's
	held, release := clock.holdNextArm()
	t.Cleanup(release)
	test.log.Tick()
	test.setState(draining, true)
	if tags, _ := test.closer.take(); 0 < len(tags) {
		t.Fatalf("a drain closed %v at once", tags)
	}
	test.awaitHeld(held)
	if pending := test.clock.PendingTimers(); 0 < len(pending) {
		t.Fatalf("timers at %v before run armed the drain's", pending)
	}
	flow := test.flow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.20:443")
	if test.verdict(flow) != connect.EgressVerdictPass {
		t.Fatal("a draining route stopped admitting before its floor")
	}
	// another goroutine's move, while run is between its read and its arm: no timer stands, so the move fires none
	test.drainChanges()
	test.clock.AdvanceTo(floor)
	release()
	test.awaitChange()
	if tags, _ := test.closer.take(); !slices.Equal(tags, []uint64{routed}) {
		t.Fatalf("the drain's end closed %v", tags)
	}
	if test.verdict(flow) != connect.EgressVerdictDeny {
		t.Fatal("a drained route still admits")
	}
}

// A link's rebuild at 6 days: the manager's run, its last wake taken, reads the clock and is held at its timer's arm
// while the clock moves to the rebuild; once released the timer fires at once and the replacement comes, though nothing
// moves the clock again. The build's end and the first packet each send run to arm for the rebuild, so the hold is the
// second's, which every wake before it has passed; the held clock sets an AfterFunc by the timeout it was given, as a
// racing move would.
func TestBridgeLinkTimerFiresForAMoveBetweenItsReadAndItsArm(t *testing.T) {
	var clock *linkTestHeldClock
	test := newLinkTest(t, func(settings *device.BridgeSettings) {
		settings.LinkIdleTimeout = 8 * 24 * time.Hour
		clock = newLinkTestHeldClock(settings)
		clock.racing = true
	})
	start := test.clock.Now()
	rebuildAt := start.Add(6 * 24 * time.Hour)
	built := clock.holdArmAt(rebuildAt)
	t.Cleanup(built.release)
	routed := clock.holdArmAt(rebuildAt)
	t.Cleanup(routed.release)
	link := test.link(4)
	if _, route := test.manager.RouteForTest(link); route != "wait" {
		t.Fatalf("the first packet routes %s", route)
	}
	test.awaitHeld(built)
	test.manager.SealForTest(link)
	client, route := test.manager.RouteForTest(link)
	if route != "client" {
		t.Fatalf("link %d routes %s once built", link, route)
	}
	old := client.(*sidecartest.FakeBridgeLink)
	built.release()
	test.awaitHeld(routed)
	if pending := test.clock.PendingTimers(); 0 < len(pending) && !pending[0].After(rebuildAt) {
		t.Fatalf("a timer stands at %v, by the rebuild, before the held arm sets one", pending)
	}
	// another goroutine's move, while run is between its pass's read and its arm: no timer stands by the rebuild, so
	// the move fires none
	test.clock.AdvanceTo(rebuildAt)
	routed.release()
	test.await("the replacement", func() bool {
		uses := test.manager.Retain([]device.BridgeLinkTarget{linkTestTarget(4)})[linkTestTarget(4)]
		return len(uses) == 2
	})
	uses := test.manager.Retain([]device.BridgeLinkTarget{linkTestTarget(4)})[linkTestTarget(4)]
	if uses[0].Link != link || !uses[0].DrainingSince.Equal(rebuildAt) {
		t.Fatalf("the old link's use %+v", uses[0])
	}
	if client, route := test.manager.RouteForTest(link); route != "client" || client != old || old.Closed() {
		t.Fatal("the old link stopped serving its pairs while it drains")
	}
}
