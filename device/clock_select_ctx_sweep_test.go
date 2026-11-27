// The device role's waits end with their context (clock-select-ctx-sweep): device.Bridge's run and its link manager's
// each selected on their context's end beside a wait the clock fires, a timer for run and a wake its AfterFunc pokes
// for the manager, and went on whenever select took the wait as the end landed. run published at the time it waited
// for, ending a map's flows on the dead bridge, and the manager took a pass, which starts the builds that are due,
// fetching a target's binding and asking the host for its link for a manager whose context had ended. Each now
// answers the end whatever else was ready. The proof is sidecartest.EndingClock, which ends the context as the wait
// fires, over 64 rounds.

package device_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A state test whose bridge runs under ctx on clock, as newStateTestWithSettings makes one, with fixture's rules in
// force. Its run's wait stands at the first time a row's meaning changes.
func newClockSelectStateTest(t *testing.T, ctx context.Context, clock device.Clock, fixture *sidecartest.BridgeRulesFixture) *stateTest {
	t.Helper()
	settings := device.DefaultBridgeSettings()
	settings.Clock = clock
	// run's wait uncapped, so it stands at the time a row's meaning changes
	settings.ClockCheckInterval = 0
	log := device.NewBridgeLogFixtureForTest(t)
	log.Base(true)
	log.Tick()
	bridgeBridge, err := device.NewBridge(ctx, log.EmptyStore(), nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridgeBridge.Close)
	self := &stateTest{
		t:       t,
		log:     log,
		bridge:  bridgeBridge,
		closer:  &stateTestCloser{hook: bridgeBridge.EgressHook()},
		changes: make(chan struct{}, 64),
	}
	unbind := bridgeBridge.EgressHook().(connect.EgressHookBinder).BindFlowCloser(self.closer)
	t.Cleanup(unbind)
	if err := bridgeBridge.SetPending(log.Pending()); err != nil {
		t.Fatal(err)
	}
	self.setState(fixture, true)
	self.closer.take()
	return self
}

// The bridge publishes nothing once its context has ended: with map 1 expiring an hour on, run waits for that hour,
// and an end landing as the wait fires leaves map 1's flows open and nothing expired, in each of 64 rounds. A run that
// took the timer's case published at the expiry on the dead bridge, closing map 1's flows and counting it expired.
func TestBridgeRunPublishesNothingAfterItsContextEnds(t *testing.T) {
	start := time.UnixMilli(egressTestTimeMs)
	for round := range 64 {
		clock := sidecartest.NewEndingClock(start, sidecartest.EndingClockCounts(time.Hour))
		clock.MoveOnFire()
		ctx, cancel := context.WithCancel(context.Background())
		clock.Arm(1, cancel)
		clock.Open()
		test := newClockSelectStateTest(t, ctx, clock, clockCheckTestFixture(start.Add(time.Hour), start.Add(4*time.Hour)))
		select {
		case <-ctx.Done():
		case <-time.After(time.Minute):
			t.Fatalf("round %d: run did not wait for the expiry", round)
		}
		test.bridge.Close()
		if tags, _ := test.closer.take(); 0 < len(tags) || test.bridge.Status().ExpiredCount != 0 || clock.Waits() != 1 {
			t.Fatalf("round %d: closed %v, %d expired, after %d waits; want none after 1", round, tags, test.bridge.Status().ExpiredCount, clock.Waits())
		}
		cancel()
	}
}

// A link test whose manager runs under ctx on clock, as newLinkTest makes one, a failed build waiting downTimeout
// before the next, and the sidecar role's sign failing its first call after firstSign runs. The caller closes the
// manager.
func newClockSelectLinkTest(t *testing.T, ctx context.Context, clock device.Clock, downTimeout time.Duration, firstSign func()) *linkTest {
	t.Helper()
	self := &linkTest{
		t:        t,
		host:     sidecartest.NewFakeBridgeHost(time.UnixMilli(linkTestTimeMs).Add(7 * 24 * time.Hour)),
		downs:    make(chan device.BridgeLinkId, 256),
		changes:  make(chan struct{}, 1),
		bindings: map[connect.Id][]byte{},
	}
	settings := device.DefaultBridgeSettings()
	settings.Clock = clock
	settings.ClockCheckInterval = 0
	settings.LinkDownTimeout = downTimeout
	signCount := &atomic.Int64{}
	settings.LinkSign = func(ctx context.Context, delegation *bridge.WindowDelegation) ([]byte, error) {
		if signCount.Add(1) == 1 {
			firstSign()
			return nil, errors.New("the sidecar role refuses the first window client")
		}
		return self.sign(ctx, delegation)
	}
	settings.LinkTargetKey = self.targetKey
	self.manager = device.NewBridgeLinkManager(ctx, self.host, settings)
	self.passes = self.manager.WatchForTest()
	self.manager.SetIdentity(linkTestNetworkId, linkTestSidecarId)
	return self
}

// The link manager builds nothing once its context has ended: a link whose first build failed while a packet wanted
// it again waits LinkDownTimeout to build, and an end landing as that wait's wake comes ends the manager with no
// second build asked of the host, in each of 64 rounds. A manager that took the wake's case passed on its dead context
// and started the build, which fetched the target's binding and asked the host for the link on that context.
func TestBridgeLinkManagerBuildsNothingAfterItsContextEnds(t *testing.T) {
	// apart from LinkBuildTimeout, so the clock counts the retry's wait alone
	downTimeout := 45 * time.Second
	for round := range 64 {
		clock := sidecartest.NewEndingClock(time.UnixMilli(linkTestTimeMs), sidecartest.EndingClockCounts(downTimeout))
		clock.MoveOnFire()
		clock.FireAfterFuncs()
		ctx, cancel := context.WithCancel(context.Background())
		clock.Arm(1, cancel)
		clock.Open()
		var test *linkTest
		var link device.BridgeLinkId
		// a packet while the first build runs wants the link again, which the build's failure then holds for
		// downTimeout
		test = newClockSelectLinkTest(t, ctx, clock, downTimeout, func() {
			test.manager.RouteForTest(link)
		})
		link = test.link(4)
		// the first packet starts the build that fails
		test.manager.RouteForTest(link)
		// run ends before Close, so a pass of its past the end is not cut short by Close's own mark
		select {
		case <-test.manager.RunDoneForTest():
		case <-time.After(time.Minute):
			t.Fatalf("round %d: the manager did not wait for the retry", round)
		}
		// Close joins any build a pass started
		test.manager.Close()
		if builds := len(test.host.Builds()); builds != 1 || clock.Waits() != 1 {
			t.Fatalf("round %d: %d builds asked of the host after %d waits; want the failed first alone after 1", round, builds, clock.Waits())
		}
		cancel()
	}
}
