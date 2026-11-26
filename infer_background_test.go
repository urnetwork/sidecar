//go:build !ios_extension && !sidecar_http && !js

package sidecar

// Phones in the background (infer_background.go; INFER-M11-06, DESIGN-COMPUTE §6.5), on a clock the test fires: a call
// in flight finishes within the grant and is cancelled past it, no new call starts, a local GPU call on iOS is
// cancelled at once, a remote call's stream is closed, and the foreground lets calls start again.

import (
	"context"
	"slices"
	"testing"
	"time"
)

// A router on world's parts whose local engine runs on device and whose engine and paths block each call until it is
// released or its context ends, on clock.
type testInferBackgroundWorld struct {
	router  *inferRouter
	clock   *testInferDownloadClock
	release chan struct{}
	started chan string
}

// The world on device.
func newTestInferBackgroundWorld(t *testing.T, device *InferDeviceCapabilities) *testInferBackgroundWorld {
	t.Helper()
	world := &testInferBackgroundWorld{
		clock:   newTestInferDownloadClock(),
		release: make(chan struct{}),
		started: make(chan string, 8),
	}
	blocking := func(name string) testInferScript {
		return func(ctx context.Context, call *InferCall, emit InferEmit) error {
			emit(&InferEvent{Kind: InferEventStart})
			world.started <- name
			select {
			case <-world.release:
				emit(&InferEvent{Kind: InferEventText, Text: name})
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	paths := &inferRemotePaths{paths: map[InferCatalogKind]InferRemotePath{
		InferCatalogKindTee:    &testInferPath{script: blocking("tee")},
		InferCatalogKindDirect: &testInferPath{script: blocking("direct")},
	}, errs: map[InferCatalogKind]error{}}
	router, err := newInferRouter(&inferRouterArgs{
		Settings:      DefaultInferSettings(),
		Manifest:      testInferManifest(),
		RemotePaths:   paths,
		RemoteCatalog: &testInferRemoteCatalog{entries: testInferRemoteEntries()},
		Checker:       &testInferPassChecker{},
		Clock:         world.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	router.setLocalEngine(&testInferEngine{capabilities: device, script: blocking("local")})
	world.router = router
	return world
}

// Starts a call to model and waits for its engine or path to hold it.
func (self *testInferBackgroundWorld) start(t *testing.T, model string) <-chan *InferEvent {
	t.Helper()
	events, err := self.router.Infer(context.Background(), testInferRequest(model, ""))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-self.started:
	case <-time.After(testInferWait):
		t.Fatalf("%s never started", model)
	}
	return events
}

// The stream's last event.
func testInferLast(t *testing.T, events <-chan *InferEvent) *InferEvent {
	t.Helper()
	all := testInferDrain(t, events)
	return all[len(all)-1]
}

// A call in flight when the app leaves the foreground finishes within the grant, whole.
func TestBackgroundFinishesWithinGrant(t *testing.T) {
	world := newTestInferBackgroundWorld(t, testInferDevice("android/arm64", InferDeviceClassPhone, 8, false, InferAcceleratorGpu))
	events := world.start(t, "local-gemma-4-e2b-off")
	world.router.Background(0)
	close(world.release)
	all := testInferDrain(t, events)
	if kinds := testInferKinds(all); !slices.Equal(kinds, []InferEventKind{InferEventStart, InferEventText, InferEventEnd}) {
		t.Errorf("a call within its grant ended %v", kinds)
	}
	// the grant's end after the call finished cancels nothing
	if fired := world.clock.fire(DefaultInferSettings().BackgroundAndroidGrant); fired != 1 {
		t.Errorf("%d grants armed", fired)
	}
}

// Past the grant a call still in flight is cancelled, local and remote alike: the remote one's stream closed, its
// path's context ended. Android's grant is the settings' when the app names none.
func TestBackgroundCancelsPastGrant(t *testing.T) {
	world := newTestInferBackgroundWorld(t, testInferDevice("android/arm64", InferDeviceClassPhone, 8, false, InferAcceleratorGpu))
	local := world.start(t, "local-gemma-4-e2b-off")
	tee := world.start(t, "chutes-qwen3.8-27b-tee-high")
	world.router.Background(0)
	// nothing fires before the grant's end
	if fired := world.clock.fire(DefaultInferSettings().BackgroundIosGrant); fired != 0 {
		t.Errorf("iOS's grant fired on Android: %d", fired)
	}
	if fired := world.clock.fire(DefaultInferSettings().BackgroundAndroidGrant); fired != 1 {
		t.Fatalf("%d grants fired", fired)
	}
	for _, events := range []<-chan *InferEvent{local, tee} {
		if last := testInferLast(t, events); last.Kind != InferEventError || last.Error.Code != InferErrorCanceled {
			t.Errorf("a call past its grant ended %+v", last)
		}
	}
	// a grant the app names is the one armed
	world.router.Foreground()
	world.router.Background(7 * time.Second)
	if fired := world.clock.fire(7 * time.Second); fired != 1 {
		t.Errorf("the app's grant was not armed: %d", fired)
	}
}

// While the app is in the background no call starts, Infer and Check alike, canceled with reason backgrounded; the
// foreground lets them start again.
func TestBackgroundRefusesNewCall(t *testing.T) {
	world := newTestInferBackgroundWorld(t, testInferDevice("ios/arm64", InferDeviceClassPhone, 8, true, InferAcceleratorGpu))
	world.router.Background(0)
	for _, model := range []string{"local-gemma-4-e2b-off", "chutes-qwen3.8-27b-tee-high"} {
		_, err := world.router.Infer(context.Background(), testInferRequest(model, ""))
		if refused := testInferErrorOf(t, err, InferErrorCanceled); refused.Reason != InferCanceledReasonBackgrounded {
			t.Errorf("%s in the background: %+v", model, refused)
		}
		if err := world.router.Check(context.Background(), testInferRequest(model, "")); InferErrorCodeOf(err) != InferErrorCanceled {
			t.Errorf("%s checked in the background: %v", model, err)
		}
	}
	world.router.Foreground()
	close(world.release)
	events := world.start(t, "local-gemma-4-e2b-off")
	if last := testInferLast(t, events); last.Kind != InferEventEnd {
		t.Errorf("a call in the foreground again ended %+v", last)
	}
	// the background's grant, stopped by the foreground, cancels nothing
	if fired := world.clock.fire(DefaultInferSettings().BackgroundIosGrant); fired != 0 {
		t.Errorf("a stopped grant fired %d", fired)
	}
}

// iOS gives a background app no GPU: a local call on the GPU is cancelled at once, while a CPU device's call, or a
// remote one, waits for the grant.
func TestBackgroundCancelsIosGpuCallAtOnce(t *testing.T) {
	world := newTestInferBackgroundWorld(t, testInferDevice("ios/arm64", InferDeviceClassPhone, 8, true, InferAcceleratorGpu))
	local := world.start(t, "local-gemma-4-e2b-off")
	remote := world.start(t, "engy-glm-5.2-high")
	world.router.Background(0)
	if last := testInferLast(t, local); last.Kind != InferEventError || last.Error.Code != InferErrorCanceled {
		t.Fatalf("an iOS GPU call in the background ended %+v", last)
	}
	select {
	case event := <-remote:
		if event.Kind != InferEventStart {
			t.Errorf("the remote call did not wait for its grant: %+v", event)
		}
	default:
	}
	if fired := world.clock.fire(DefaultInferSettings().BackgroundIosGrant); fired != 1 {
		t.Fatalf("%d grants fired", fired)
	}
	if last := testInferLast(t, remote); last.Kind != InferEventError || last.Error.Code != InferErrorCanceled {
		t.Errorf("the remote call past its grant ended %+v", last)
	}
	// on a CPU the local call waits for the grant too
	cpu := newTestInferBackgroundWorld(t, testInferDevice("ios/arm64", InferDeviceClassPhone, 8, true))
	events := cpu.start(t, "local-gemma-4-e2b-off")
	cpu.router.Background(0)
	close(cpu.release)
	if last := testInferLast(t, events); last.Kind != InferEventEnd {
		t.Errorf("an iOS CPU call within its grant ended %+v", last)
	}
}

// A remote call past its grant has its stream closed: its path's context ends, which is what tells the broker to
// cancel the provider's call on the TEE path, and its reader gets canceled.
func TestBackgroundClosesRemoteStream(t *testing.T) {
	world := newTestInferBackgroundWorld(t, testInferDevice("android/arm64", InferDeviceClassPhone, 8, false))
	ended := make(chan struct{})
	tee := world.router.remotePaths.paths[InferCatalogKindTee].(*testInferPath)
	tee.script = func(ctx context.Context, call *InferCall, emit InferEmit) error {
		emit(&InferEvent{Kind: InferEventStart})
		world.started <- "tee"
		<-ctx.Done()
		close(ended)
		return ctx.Err()
	}
	events := world.start(t, "chutes-qwen3.8-27b-tee-high")
	world.router.Background(0)
	if fired := world.clock.fire(DefaultInferSettings().BackgroundAndroidGrant); fired != 1 {
		t.Fatalf("%d grants fired", fired)
	}
	select {
	case <-ended:
	case <-time.After(testInferWait):
		t.Fatal("the remote path's context did not end")
	}
	if last := testInferLast(t, events); last.Kind != InferEventError || last.Error.Code != InferErrorCanceled {
		t.Errorf("the remote stream ended %+v", last)
	}
}
