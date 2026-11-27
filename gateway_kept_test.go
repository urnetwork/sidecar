//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension && !windows

package sidecar

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// GW-M12-05's kept response across restarts (DESIGN-COMPUTE §8.5's crash paragraph, R2-04): each call kept in the
// network's sealed store as its items are journaled; after a crash a call journaled whole is answered from it and a
// cut one is recorded as cut and never replayed; a planned restart waits for its calls first. The crash is the fronts'
// stand-in for a process that died: nothing more of the old fronts reaches the store, and new fronts read it.

// Restarts the fronts over the same server and stores: after a crash, the old fronts write nothing more; either way
// the old calls end and new fronts, which have read nothing yet, take their place.
func (self *testGatewayFrontWorld) restart(crash bool) {
	self.t.Helper()
	old := self.fronts
	if crash {
		old.tables.stopped.Store(true)
	}
	old.Close()
	self.fronts = newGatewayFronts(self.server, &GatewayFrontsArgs{
		Recorder: self.recorder,
		Random:   &testGatewayCounter{next: 1 << 40},
		Clock:    self.clock,
	})
	self.fronts.followWritten = old.followWritten
	self.t.Cleanup(self.fronts.Close)
}

// Waits until no call's producer runs.
func (self *testGatewayFrontWorld) awaitIdle() {
	self.t.Helper()
	guard := time.After(testGatewayWait)
	for {
		running, changed := func() (int, chan struct{}) {
			self.fronts.stateLock.Lock()
			defer self.fronts.stateLock.Unlock()
			return self.fronts.running, self.fronts.runningChanged
		}()
		if running == 0 {
			return
		}
		select {
		case <-changed:
		case <-guard:
			self.t.Fatalf("%d calls still run", running)
		}
	}
}

// After a crash, a call journaled whole is answered from its kept answer: by its Idempotency-Key, and, for a call its
// caller left before the end, by its handle and bytes; neither makes a provider call.
func TestCrashJournaledWholeAnsweredFromKept(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.router.script(&testGatewayTurn{reasoning: []string{"thought"}, text: []string{"a whole answer"}, usage: &InferUsage{InputTokens: 9, OutputTokens: 4}})
	key := map[string]string{"Idempotency-Key": "synthetic-operation-crash"}
	first := world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), key)
	abandoned := testGatewayStallingTurn("left ", "behind")
	world.router.script(abandoned)
	chatBody := testGatewayChatBody(true)
	world.serveAndLeave(world.caller, gatewayChatFront{}, chatBody, nil, abandoned)
	close(abandoned.release)
	world.awaitIdle()

	world.restart(true)
	second := world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), key)
	if second.Body.String() != first.Body.String() {
		t.Errorf("the kept answer differs:\n%s\n%s", first.Body.String(), second.Body.String())
	}
	rejoined := world.serveAs(context.Background(), world.caller, gatewayChatFront{}, chatBody, nil)
	if !strings.Contains(rejoined.Body.String(), `"content":"behind"`) || !strings.HasSuffix(rejoined.Body.String(), "data: [DONE]\n\n") {
		t.Errorf("the abandoned call's kept answer: %s", rejoined.Body.String())
	}
	if len(world.router.inferred()) != 2 {
		t.Errorf("%d provider calls", len(world.router.inferred()))
	}
	world.recorder.stateLock.Lock()
	cuts := len(world.recorder.cuts)
	world.recorder.stateLock.Unlock()
	if cuts != 0 {
		t.Errorf("%d whole calls recorded as cut", cuts)
	}
}

// A call a crash cut, its reasoning item journaled and its text not finished, is recorded as cut, its output as far as
// it was journaled, and its retry is a new call, recorded and charged as a second call; its kept part is never
// replayed.
func TestCrashCutCallRetriedAsSecondCall(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	turn := &testGatewayTurn{reasoning: []string{"thinking"}, text: []string{"partial ", "rest"}, stallAfter: 2,
		release: make(chan struct{}), stalled: make(chan struct{})}
	world.router.script(turn, &testGatewayTurn{text: []string{"the second call"}})
	done := make(chan struct{})
	go func() {
		defer close(done)
		world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	}()
	select {
	case <-turn.stalled:
	case <-time.After(testGatewayWait):
		t.Fatal("never stalled")
	}
	guard := time.After(testGatewayWait)
	for partial := false; !partial; {
		select {
		case written := <-world.written:
			partial = strings.Contains(written, `"delta":"partial "`)
		case <-guard:
			t.Fatal("the partial text never streamed")
		}
	}
	begins, items, _ := world.recorder.snapshot()
	if len(items) != 1 {
		t.Fatalf("%d items journaled before the crash", len(items))
	}

	world.restart(true)
	retry := world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), nil)
	if !strings.Contains(retry.Body.String(), "the second call") || strings.Contains(retry.Body.String(), "partial") {
		t.Errorf("the retry: %s", retry.Body.String())
	}
	if len(world.router.inferred()) != 2 {
		t.Errorf("%d provider calls", len(world.router.inferred()))
	}
	world.recorder.stateLock.Lock()
	cuts := world.recorder.cuts
	world.recorder.stateLock.Unlock()
	if len(cuts) != 1 || cuts[0].ResponseId != begins[0].ResponseId || len(cuts[0].NodeIds) != 1 || cuts[0].Binding == nil ||
		cuts[0].Binding.RunId != world.binder.runId {
		t.Errorf("the cut: %+v", cuts)
	}
	if again, _, _ := world.recorder.snapshot(); len(again) != 2 {
		t.Errorf("the retry was not recorded as a second call: %d begins", len(again))
	}
	close(turn.release)
	<-done
}

// A planned restart refuses new calls and waits for those in flight, which end whole; after it, the call's
// Idempotency-Key retry is answered from its kept answer, charged once.
func TestPlannedRestartWaitsForCalls(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	turn := testGatewayStallingTurn("held ", "through the restart")
	world.router.script(turn)
	key := map[string]string{"Idempotency-Key": "synthetic-operation-planned"}
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		first <- world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), key)
	}()
	select {
	case <-turn.stalled:
	case <-time.After(testGatewayWait):
		t.Fatal("never stalled")
	}
	drained := make(chan int, 1)
	go func() {
		drained <- world.fronts.Drain(context.Background())
	}()
	world.clock.awaitArmed(t, world.settings.PlannedRestartWait)
	if refused := world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(false), nil); refused.Code != http.StatusServiceUnavailable {
		t.Errorf("a new call while draining: %d", refused.Code)
	}
	close(turn.release)
	select {
	case running := <-drained:
		if running != 0 {
			t.Fatalf("%d calls still ran", running)
		}
	case <-time.After(testGatewayWait):
		t.Fatal("the drain never ended")
	}
	answer := <-first
	world.restart(false)
	again := world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), key)
	if again.Body.String() != answer.Body.String() || len(world.router.inferred()) != 1 {
		t.Errorf("after the restart: %d calls\n%s\n%s", len(world.router.inferred()), answer.Body.String(), again.Body.String())
	}
}

// The kept file holds the answer only while it fits KeptResponseByteCount: past it the call is not joined, its retry a
// new call, while a crash still finds it.
func TestKeptAnswerPastItsBoundNotJoined(t *testing.T) {
	world := newTestGatewayFrontWorld(t, func(settings *GatewaySettings) {
		settings.KeptResponseByteCount = 512
	})
	world.router.script(&testGatewayTurn{text: []string{strings.Repeat("long ", 200)}}, &testGatewayTurn{text: []string{"new"}})
	key := map[string]string{"Idempotency-Key": "synthetic-operation-long"}
	world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), key)
	again := world.serveAs(context.Background(), world.caller, gatewayResponsesFront{}, testGatewayCodexBody(true), key)
	if len(world.router.inferred()) != 2 || !strings.Contains(again.Body.String(), "new") {
		t.Errorf("an answer past its bound was joined: %s", again.Body.String())
	}
}
