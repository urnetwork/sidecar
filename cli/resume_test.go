// The daemon's resume watch (resume.go): at each resume the platform's watch reports, every bridge the daemon holds
// reads the clock again, a network added after the watch began included and one forgotten not; the watch runs for the
// daemon's life and close waits for it; and a wire's network hands the daemon its device.Bridge's own check. The core's
// checks (QD-1422) run beside the bridges' at each resume until removed, and at the desktop's cap, every interval of
// the daemon's clock, alone, the bridges capping their own waits; the daemon's forwards' check joins them; and a
// daemon's args take the bridges' own interval.

package main

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A watch a test drives: it hands the test the resumed it is given, and returns once its context ends.
type testResumeWatch struct {
	started chan func()
	ended   chan struct{}
}

func newTestResumeWatch() *testResumeWatch {
	return &testResumeWatch{started: make(chan func(), 1), ended: make(chan struct{})}
}

// urResumeWatchFunction.
func (self *testResumeWatch) watch(ctx context.Context, resumed func(), log sidecar.Logger) {
	self.started <- resumed
	<-ctx.Done()
	close(self.ended)
}

// The resumed the daemon handed the watch; the context is the guard that fails a test it never comes to.
func (self *testResumeWatch) awaitStarted(t *testing.T) func() {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	select {
	case resumed := <-self.started:
		return resumed
	case <-ctx.Done():
		t.Fatal("the daemon started no resume watch")
		return nil
	}
}

// A fake network whose bridge's check counts.
func testResumeNetwork(checks *atomic.Int64) *urBridgeNetwork {
	network := &urBridgeNetwork{
		networkId:         sidecar.NewId(),
		bridge:            newTestTunBridge(),
		links:             &testTunLinks{},
		componentSettings: sidecar.DefaultBridgeComponentSettings(),
	}
	if checks != nil {
		network.checkClock = func() {
			checks.Add(1)
		}
	}
	return network
}

// Each resume checks the clock of every bridge held then: one added after the watch began, and not one forgotten; a
// network with no check is passed over. close ends the watch and waits for it.
func TestDaemonResumeChecksEveryBridgesClock(t *testing.T) {
	watch := newTestResumeWatch()
	bridges := newUrBridgeDaemon(context.Background(), &urBridgeDaemonArgs{
		Instance:    "test",
		Settings:    testUrTunSettings(),
		ResumeWatch: watch.watch,
	})
	closed := false
	t.Cleanup(func() {
		if !closed {
			bridges.close()
		}
	})
	resumed := watch.awaitStarted(t)
	first, second := &atomic.Int64{}, &atomic.Int64{}
	for _, network := range []*urBridgeNetwork{testResumeNetwork(first), testResumeNetwork(nil)} {
		if _, err := bridges.addNetwork(network); err != nil {
			t.Fatal(err)
		}
	}
	forget, err := bridges.addNetwork(testResumeNetwork(second))
	if err != nil {
		t.Fatal(err)
	}
	resumed()
	if first.Load() != 1 || second.Load() != 1 {
		t.Fatalf("a resume checked %d and %d", first.Load(), second.Load())
	}
	forget()
	resumed()
	if first.Load() != 2 || second.Load() != 1 {
		t.Fatalf("after one was forgotten a resume checked %d and %d", first.Load(), second.Load())
	}
	bridges.close()
	closed = true
	select {
	case <-watch.ended:
	default:
		t.Fatal("close returned before the watch")
	}
}

// With no watch, as on macOS, the daemon starts none and closes as ever.
func TestDaemonWithNoResumeWatchCloses(t *testing.T) {
	bridges := newUrBridgeDaemon(context.Background(), &urBridgeDaemonArgs{Instance: "test", Settings: testUrTunSettings()})
	checks := &atomic.Int64{}
	if _, err := bridges.addNetwork(testResumeNetwork(checks)); err != nil {
		t.Fatal(err)
	}
	bridges.checkClock()
	bridges.close()
	if checks.Load() != 1 {
		t.Fatalf("a check reached %d bridges", checks.Load())
	}
}

// A wire's network hands the daemon its bridge's CheckClock, which publishes at now (device.Bridge's own tests show
// what that ends): a bridge restored from an empty store, legacy, takes the check and publishes.
func TestWireNetworkHandsTheBridgesCheck(t *testing.T) {
	store, err := device.NewFilePostureStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	deviceBridge, err := device.NewBridge(context.Background(), store, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(deviceBridge.Close)
	wire := &urBridgeWire{
		args:   &urBridgeWireArgs{NetworkId: sidecar.NewId(), Sidecar: &sidecar.Sidecar{}},
		bridge: deviceBridge,
	}
	network := wire.network()
	if network.checkClock == nil {
		t.Fatal("a wire's network has no check")
	}
	published := make(chan struct{}, 1)
	t.Cleanup(deviceBridge.AddChangeCallback(func() {
		select {
		case published <- struct{}{}:
		default:
		}
	}))
	network.checkClock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	select {
	case <-published:
	case <-ctx.Done():
		t.Fatal("the network's check did not reach its bridge")
	}
}

// A core check added runs at each resume beside every bridge's check, and not once removed.
func TestDaemonResumeChecksTheCoresClocksBesideTheBridges(t *testing.T) {
	watch := newTestResumeWatch()
	bridges := newUrBridgeDaemon(context.Background(), &urBridgeDaemonArgs{
		Instance:    "test",
		Settings:    testUrTunSettings(),
		ResumeWatch: watch.watch,
	})
	t.Cleanup(bridges.close)
	resumed := watch.awaitStarted(t)
	bridgeChecks, coreChecks := &atomic.Int64{}, &atomic.Int64{}
	if _, err := bridges.addNetwork(testResumeNetwork(bridgeChecks)); err != nil {
		t.Fatal(err)
	}
	remove := bridges.addClockCheck(func() {
		coreChecks.Add(1)
	})
	resumed()
	if bridgeChecks.Load() != 1 || coreChecks.Load() != 1 {
		t.Fatalf("a resume checked the bridge %d times and the core %d", bridgeChecks.Load(), coreChecks.Load())
	}
	remove()
	resumed()
	if bridgeChecks.Load() != 2 || coreChecks.Load() != 1 {
		t.Fatalf("after the core's check was removed a resume checked the bridge %d times and the core %d", bridgeChecks.Load(), coreChecks.Load())
	}
}

// The desktop's cap: every interval of the daemon's clock the core's checks run, never the bridges', which cap their
// own waits; nothing runs a second short of the interval; and close waits for the cap. The shared blocks' judgment
// waits on the same clock, so the test knows the cap's wait by its time, the interval from the clock's reading, never
// by a count of the clock's timers: a count the judgment's met before the cap armed its own let the test move the
// clock first, which set the cap's wait from the moved time, past the test's next move.
func TestDaemonClockCapChecksTheCoreEachInterval(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	interval := 30 * time.Second
	settings := testUrTunSettings()
	// the judgment's waits an hour apart, so none of its is due when the cap's is
	settings.SharedBlockInterval = time.Hour
	bridges := newUrBridgeDaemon(context.Background(), &urBridgeDaemonArgs{
		Instance:           "test",
		Settings:           settings,
		ClockCheckInterval: interval,
		Clock:              clock,
	})
	closed := false
	t.Cleanup(func() {
		if !closed {
			bridges.close()
		}
	})
	bridgeChecks := &atomic.Int64{}
	if _, err := bridges.addNetwork(testResumeNetwork(bridgeChecks)); err != nil {
		t.Fatal(err)
	}
	coreChecked := make(chan struct{}, 16)
	bridges.addClockCheck(func() {
		coreChecked <- struct{}{}
	})
	// the cap's wait, set as the cap reaches it for the interval from where the clock stands, which only the test moves
	awaitCapWait := func() {
		capAt := clock.Now().Add(interval)
		guard := time.After(time.Minute)
		for {
			// read with the channel the next timer closes, so no timer set between the read and the wait goes unseen
			pending, added := clock.WatchTimers()
			if slices.ContainsFunc(pending, capAt.Equal) {
				return
			}
			select {
			case <-added:
			case <-guard:
				t.Fatalf("the cap armed no wait for %v, only %v", capAt, pending)
			}
		}
	}
	awaitCoreCheck := func() {
		select {
		case <-coreChecked:
		case <-time.After(time.Minute):
			t.Fatal("the cap checked no core clock")
		}
	}
	for range 2 {
		awaitCapWait()
		clock.Advance(interval - time.Second)
		select {
		case <-coreChecked:
			t.Fatal("the cap checked short of its interval")
		default:
		}
		clock.Advance(time.Second)
		awaitCoreCheck()
	}
	if bridgeChecks.Load() != 0 {
		t.Fatalf("the cap checked the bridges %d times", bridgeChecks.Load())
	}
	bridges.close()
	closed = true
	select {
	case <-bridges.clockCapDone:
	default:
		t.Fatal("close returned before the cap")
	}
}

// The daemon's forwards' check joins the core's checks once the daemon's root bridge methods are built, and a resume
// reaches it; and a daemon's args take the bridges' own interval as the cap.
func TestDaemonForwardsCheckJoinsTheCoresChecks(t *testing.T) {
	if interval := urBridgeDaemonArgsOf("test", sidecar.NewNoopLogger()).ClockCheckInterval; interval != device.DefaultBridgeSettings().ClockCheckInterval || interval <= 0 {
		t.Fatalf("a daemon's cap is %v", interval)
	}
	bridges := newUrBridgeDaemon(context.Background(), &urBridgeDaemonArgs{Instance: "test", Settings: testUrTunSettings()})
	t.Cleanup(bridges.close)
	if _, err := newUrDaemonBridges(bridges, func(args *sidecar.DaemonLocalListenArgs) (*sidecar.DaemonLocalListener, error) {
		return nil, errors.New("no listener in this test")
	}); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		bridges.stateLock.Lock()
		defer bridges.stateLock.Unlock()
		return len(bridges.coreClockChecks)
	}()
	if count != 1 {
		t.Fatalf("%d core checks with the forwards'", count)
	}
	// the forwards' check, over none, at a resume
	bridges.checkClock()
}
