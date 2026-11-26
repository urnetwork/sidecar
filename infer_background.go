//go:build !ios_extension && !sidecar_http

// Phones in the background (DESIGN-COMPUTE §6.5; INFER-M11-06): an app's Harness runs only while the app does (§20.7),
// so when the app leaves the foreground the router starts no new model call, and a call in flight finishes within the
// time the OS grants (iOS: a background task, about 30 seconds; Android: a short foreground service, about 3 minutes;
// InferSettings' BackgroundIosGrant and BackgroundAndroidGrant), else it is cancelled:
//
//   - a local call on the GPU on iOS at once, since iOS gives a background app no GPU;
//   - a remote call by closing its stream, its path's context ended, the broker then cancelling the provider's call on
//     the TEE path, and a closed stream billed as its provider bills it (§6.6);
//   - any other once the grant runs out.
//
// The Harness journals each item already complete and pauses at that item boundary with stop reason backgrounded
// (HARN): a refused call is canceled with reason backgrounded, which it reads as that. Foreground lets calls start
// again; a call the grant cancelled is the Harness's to retry, with nothing lost or done twice.
//
// The router tracks every dispatched call for this, under the background's own lock, which no engine or path call holds.

package sidecar

import (
	"context"
	"sync"
	"time"
)

// canceled's reason while the app is in the background: no new model call starts.
const InferCanceledReasonBackgrounded = "backgrounded"

// What an app's lifecycle tells the router (§6.5): the concrete router implements it, beside InferRouter, and the
// Sidecar's InferBackground and InferForeground reach it.
type InferRouterLifecycle interface {
	// The app left the foreground with grant of the OS's time to finish, or, where it is not positive, the settings'
	// grant for this device's platform: no new call starts, and calls in flight are cancelled as the file comment says.
	Background(grant time.Duration)
	// The app is in the foreground again: calls start again.
	Foreground()
}

// One dispatched call, as the background sees it.
type inferBackgroundCall struct {
	cancel context.CancelFunc
	// a local call whose engine runs it on the GPU
	gpu bool
}

// The router's calls in flight and whether the app is in the background. Safe for concurrent use.
type inferBackground struct {
	settings *InferSettings
	clock    Clock

	stateLock    sync.Mutex
	calls        map[*inferBackgroundCall]bool
	backgrounded bool
	// counts each Background and Foreground, so a grant's end acts only on the background that set it
	generation uint64
	// stops the grant's wait
	stopGrant func() bool
}

// A background over settings, on clock.
func newInferBackground(settings *InferSettings, clock Clock) *inferBackground {
	return &inferBackground{settings: settings, clock: clockOrReal(clock), calls: map[*inferBackgroundCall]bool{}}
}

// canceled, reason backgrounded, for a call named name while the app is in the background; nil in the foreground.
func (self *inferBackground) refusal(name string) *InferError {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.backgrounded {
		return nil
	}
	return &InferError{
		Code:    InferErrorCanceled,
		Model:   name,
		Reason:  InferCanceledReasonBackgrounded,
		Message: "the app is in the background: no model call starts until it is in the foreground again",
	}
}

// Tracks a dispatched call until done is called; one dispatched as the app left the foreground is cancelled at once.
func (self *inferBackground) track(gpu bool, cancel context.CancelFunc) func() {
	call := &inferBackgroundCall{cancel: cancel, gpu: gpu}
	backgrounded := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.calls[call] = true
		return self.backgrounded
	}()
	if backgrounded {
		cancel()
	}
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.calls, call)
	}
}

// The grant settings give platform: iOS's, Android's, and iOS's, the shorter, where the device is not known.
func (self *inferBackground) settingsGrant(platform string) time.Duration {
	if platform == "android/arm64" {
		return self.settings.BackgroundAndroidGrant
	}
	return self.settings.BackgroundIosGrant
}

// See InferRouterLifecycle, platform the router's device's ("" where none is known).
func (self *inferBackground) background(grant time.Duration, platform string) {
	if grant <= 0 {
		grant = self.settingsGrant(platform)
	}
	// iOS gives a background app no GPU
	noGpu := platform == "ios/arm64"
	now := []*inferBackgroundCall{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.stopGrant != nil {
			self.stopGrant()
		}
		self.backgrounded = true
		self.generation += 1
		generation := self.generation
		for call := range self.calls {
			if noGpu && call.gpu {
				now = append(now, call)
			}
		}
		self.stopGrant = self.clock.AfterFunc(grant, func() {
			self.grantEnded(generation)
		})
	}()
	for _, call := range now {
		call.cancel()
	}
}

// The grant of background generation ran out: every call still in flight is cancelled, if the app is still in that
// background.
func (self *inferBackground) grantEnded(generation uint64) {
	calls := func() []*inferBackgroundCall {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.backgrounded || self.generation != generation {
			return nil
		}
		calls := []*inferBackgroundCall{}
		for call := range self.calls {
			calls = append(calls, call)
		}
		return calls
	}()
	testHookBarrier("infer.background.grant.end", "")
	for _, call := range calls {
		call.cancel()
	}
}

// See InferRouterLifecycle.
func (self *inferBackground) foreground() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.stopGrant != nil {
		self.stopGrant()
		self.stopGrant = nil
	}
	self.backgrounded = false
	self.generation += 1
}

// See InferRouterLifecycle: the grant, and the device the router's local view was judged for.
func (self *inferRouter) Background(grant time.Duration) {
	platform := ""
	if device := self.local(context.Background()).Device(); device != nil {
		platform = device.Platform
	}
	self.background.background(grant, platform)
}

// See InferRouterLifecycle.
func (self *inferRouter) Foreground() {
	self.background.foreground()
}

// Whether call, a local one, runs on the GPU on this router's device: the engine's choice (inferLocalModelFile).
func (self *inferRouter) onGpu(ctx context.Context, call *InferCall) bool {
	if call.Entry.Kind != InferCatalogKindLocal {
		return false
	}
	device := self.local(ctx).Device()
	if device == nil {
		return false
	}
	_, backend, err := inferLocalModelFile(call.Entry, device)
	return err == nil && backend == InferAcceleratorGpu
}

// The app left the foreground (§6.5): this Sidecar's router starts no new model call, and cancels the ones in flight as
// grant, or the settings' grant for the device where it is not positive, runs out; a local GPU call on iOS at once.
func (self *Sidecar) InferBackground(grant time.Duration) error {
	infer, err := sidecarComputeComponent[sidecarInfer](self, computeInferComponentName)
	if err != nil {
		return err
	}
	infer.router.Background(grant)
	return nil
}

// The app is in the foreground again: this Sidecar's router starts calls again.
func (self *Sidecar) InferForeground() error {
	infer, err := sidecarComputeComponent[sidecarInfer](self, computeInferComponentName)
	if err != nil {
		return err
	}
	infer.router.Foreground()
	return nil
}
