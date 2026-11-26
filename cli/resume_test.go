// The daemon's resume watch (resume.go): at each resume the platform's watch reports, every bridge the daemon holds
// reads the clock again, a network added after the watch began included and one forgotten not; the watch runs for the
// daemon's life and close waits for it; and a wire's network hands the daemon its device.Bridge's own check.

package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
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
