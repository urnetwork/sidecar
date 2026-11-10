package sidecar

// §18.10's threads row: a long operation yields between its steps once 50 ms have passed, so on js/wasm's one thread
// a long-poll's reply and a page's requests run between two steps.

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A clock a test steps by hand, with no timers.
type yieldTestClock struct {
	stateLock sync.Mutex
	current   time.Time
}

func (self *yieldTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.current
}

func (self *yieldTestClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

func (self *yieldTestClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return true }
}

func (self *yieldTestClock) advance(timeout time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.current = self.current.Add(timeout)
}

// An operation of twenty 20 ms steps yields once 50 ms pass since its last yield, so never more than 60 ms of compute
// run between two yields, and a short operation yields not at all.
func TestLongOperationYields(t *testing.T) {
	clock := &yieldTestClock{current: time.Date(2026, time.May, 6, 7, 8, 9, 0, time.UTC)}
	yield := newSidecarYield(clock)
	yieldTimes := []time.Time{}
	yield.yield = func() {
		yieldTimes = append(yieldTimes, clock.Now())
	}
	start := clock.Now()
	for step := 0; step < 20; step += 1 {
		clock.advance(20 * time.Millisecond)
		yield.step()
	}
	if len(yieldTimes) != 6 {
		t.Errorf("%d yields over 400 ms of steps", len(yieldTimes))
	}
	last := start
	for _, yieldTime := range yieldTimes {
		if gap := yieldTime.Sub(last); gap < sidecarYieldInterval || 3*20*time.Millisecond < gap {
			t.Errorf("a yield %s after the last", gap)
		}
		last = yieldTime
	}

	short := newSidecarYield(clock)
	short.yield = func() {
		t.Error("an operation under 50 ms yielded")
	}
	clock.advance(40 * time.Millisecond)
	short.step()
}

// A yield hands the thread to what waits for it: with one thread, a goroutine made runnable before a long operation
// runs at the operation's first yield, before the operation ends, as the long-poll's reply does in the page Worker.
func TestYieldLetsTheWaitingRun(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	clock := &yieldTestClock{current: time.Date(2026, time.May, 6, 7, 8, 9, 0, time.UTC)}
	yield := newSidecarYield(clock)
	var ran atomic.Bool
	ready := make(chan struct{})
	go func() {
		ran.Store(true)
		close(ready)
	}()
	ranBeforeEnd := false
	for step := 0; step < 10; step += 1 {
		clock.advance(30 * time.Millisecond)
		if yield.step() && ran.Load() {
			ranBeforeEnd = true
			break
		}
	}
	<-ready
	if !ranBeforeEnd {
		t.Error("the waiting goroutine did not run at a yield")
	}
}
