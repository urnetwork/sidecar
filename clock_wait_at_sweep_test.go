//go:build !sidecar_http && !js && !ios_extension

// The sweep of waits for a time onto clock_at.go's helpers (QD-1425). A site that read the clock, took the timeout to
// its time and set the wait was set late by a move of a fake clock between the two; it now sets the wait for the time
// itself. The racing clock here moves a FakeClock to a wait's time as that wait is set: the move another goroutine
// makes between a site's reading and its arm, which each test so meets on every run. A wait set by a timeout from the
// earlier reading then stands a whole move past its time, and the test fails at its guard. The device role's run and
// link manager are held to the same in device/bridge_clock_wait_at_test.go.

package sidecar_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A FakeClock that another goroutine moves to a wait's time just as the wait is set: the next wait set for the raced
// time moves the clock there first, whichever way it is set. A wait for a time (AfterAt, AfterFuncAt) still stands at
// its time, reached, so it fires at once; a wait by a timeout (After, AfterFunc), the timeout taken from the caller's
// reading before the move, stands the move past the time.
type clockWaitAtRacingClock struct {
	*sidecartest.FakeClock

	stateLock sync.Mutex
	// the time whose wait moves the clock, zero for none or once moved
	raceAt time.Time
}

var _ sidecar.ClockAt = (*clockWaitAtRacingClock)(nil)

func newClockWaitAtRacingClock() *clockWaitAtRacingClock {
	return &clockWaitAtRacingClock{FakeClock: sidecartest.NewFakeClock(sidecartest.DefaultClockStart())}
}

// Has the next wait set for at move the clock to at as it is set.
func (self *clockWaitAtRacingClock) raceNextWaitFor(at time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.raceAt = at
}

// Moves the clock to at, once, when at is the raced time.
func (self *clockWaitAtRacingClock) race(at time.Time) {
	raced := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.raceAt.IsZero() || !self.raceAt.Equal(at) {
			return false
		}
		self.raceAt = time.Time{}
		return true
	}()
	if raced {
		self.FakeClock.AdvanceTo(at)
	}
}

func (self *clockWaitAtRacingClock) After(timeout time.Duration) <-chan time.Time {
	self.race(self.FakeClock.Now().Add(timeout))
	return self.FakeClock.After(timeout)
}

func (self *clockWaitAtRacingClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	self.race(self.FakeClock.Now().Add(timeout))
	return self.FakeClock.AfterFunc(timeout, function)
}

func (self *clockWaitAtRacingClock) AfterAt(at time.Time) <-chan time.Time {
	self.race(at)
	return self.FakeClock.AfterAt(at)
}

func (self *clockWaitAtRacingClock) AfterFuncAt(at time.Time, function func()) (stop func() bool) {
	self.race(at)
	return self.FakeClock.AfterFuncAt(at, function)
}

// Waits for done; the context is the guard that fails a test it never closes for.
func clockWaitAtAwait(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("%s never came", what)
	}
}

// The racing clock's window, set both ways: ClockAfterAt's wait for the time fires though the clock moved to it as the
// wait was set, where the old way, the timeout from the reading before the move, stands a whole move past the time.
func TestClockAfterAtFiresForAMoveBetweenTheReadingAndTheWait(t *testing.T) {
	clock := newClockWaitAtRacingClock()
	at := clock.Now().Add(time.Second)
	clock.raceNextWaitFor(at)
	fired := sidecar.ClockAfterAt(clock, at)
	select {
	case <-fired:
	default:
		t.Fatalf("a wait for a time the clock reached as it was set has not fired; timers at %v", clock.PendingTimers())
	}

	late := clock.Now().Add(time.Second)
	clock.raceNextWaitFor(late)
	timedOut := clock.After(late.Sub(clock.Now()))
	select {
	case <-timedOut:
		t.Fatal("the racing clock did not race the timeout")
	default:
	}
	if pending := clock.PendingTimers(); len(pending) != 1 || !pending[0].Equal(late.Add(time.Second)) {
		t.Fatalf("the timeout's timer stands at %v, not a move past %v", pending, late)
	}
}

// ClockAfterFuncAtAsync with a time the clock has reached, called with a lock held that the function takes, returns
// without the call, which then runs on a goroutine of its own once the lock is let go.
func TestClockAfterFuncAtAsyncCallsAReachedTimeOffTheSettingGoroutine(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	var stateLock sync.Mutex
	called := make(chan struct{})
	func() {
		stateLock.Lock()
		defer stateLock.Unlock()
		stop := sidecar.ClockAfterFuncAtAsync(clock, clock.Now(), func() {
			stateLock.Lock()
			defer stateLock.Unlock()
			close(called)
		})
		if stop() {
			t.Error("a reached time's call was still stoppable once handed to its goroutine")
		}
		select {
		case <-called:
			t.Error("the call ran while its setter held the lock")
		default:
		}
	}()
	clockWaitAtAwait(t, called, "the reached time's call")
}

// ClockAfterFuncAtAsync with a time still to come calls on the clock's goroutine, so the Advance that reaches the
// time returns with the call made; one stopped first is never called.
func TestClockAfterFuncAtAsyncCallsATimeToComeWhereTheClockFiresIt(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	at := clock.Now().Add(time.Second)
	calledCount := 0
	sidecar.ClockAfterFuncAtAsync(clock, at, func() {
		calledCount += 1
	})
	stoppedCount := 0
	stop := sidecar.ClockAfterFuncAtAsync(clock, at, func() {
		stoppedCount += 1
	})
	if !stop() {
		t.Fatal("a call still to come did not stop")
	}
	clock.Advance(time.Second)
	if calledCount != 1 || stoppedCount != 0 {
		t.Fatalf("called %d times, the stopped one %d, as the Advance to the time returned", calledCount, stoppedCount)
	}
}

// On the real clock, which is no ClockAt, a time passed calls on a goroutine of its own, as time.AfterFunc does.
func TestClockAfterFuncAtAsyncOnTheRealClockCallsAPassedTime(t *testing.T) {
	clock := sidecar.RealClock{}
	called := make(chan struct{})
	sidecar.ClockAfterFuncAtAsync(clock, clock.Now().Add(-time.Second), func() {
		close(called)
	})
	clockWaitAtAwait(t, called, "the passed time's call")
}

// A held delta's flush, set under the batcher's locks for the end of its interval: the clock moves to that end as the
// flush is set, and the flush still comes, on its own goroutine, with no further move. Set by a timeout from Add's
// reading, as it once was, it stood an interval past the end and never came.
func TestHarnessEventBatcherFlushesForAMoveBetweenItsReadAndItsArm(t *testing.T) {
	settings := sidecar.DefaultHarnessSettings()
	clock := newClockWaitAtRacingClock()
	var receivedLock sync.Mutex
	received := []*sidecar.HarnessEvent{}
	flushed := make(chan struct{})
	batcher := sidecar.NewHarnessEventBatcher(settings, clock, func(event *sidecar.HarnessEvent) {
		receivedLock.Lock()
		defer receivedLock.Unlock()
		received = append(received, event)
		if len(received) == 2 {
			close(flushed)
		}
	})
	t.Cleanup(batcher.Close)
	agent := sidecar.NewId().String()
	update := func(delta string) *sidecar.HarnessEvent {
		event := sidecar.NewHarnessMessageUpdateEvent(nil, &sidecar.HarnessAssistantMessageEvent{Type: sidecar.HarnessAssistantEventTextDelta, Delta: delta})
		event.Agent = agent
		return event
	}
	// the first delta goes at once; the second, a millisecond on, is held to the interval's end, 1/EventRate after
	start := clock.Now()
	batcher.Add(update("a"))
	clock.Advance(time.Millisecond)
	intervalEnd := start.Add(time.Second / time.Duration(settings.EventRate))
	clock.raceNextWaitFor(intervalEnd)
	batcher.Add(update("b"))
	clockWaitAtAwait(t, flushed, "the held delta's flush")
	receivedLock.Lock()
	defer receivedLock.Unlock()
	if len(received) != 2 || received[1].Type != sidecar.HarnessEventMessageUpdate {
		t.Fatalf("received %d events, the second %v", len(received), received[len(received)-1].Type)
	}
	if !clock.Now().Equal(intervalEnd) {
		t.Fatalf("the clock moved to %v, past the interval's end %v", clock.Now(), intervalEnd)
	}
}
