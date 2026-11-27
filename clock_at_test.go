//go:build !sidecar_http && !js

// clock_at.go's waits for a time (QD-1425): a ClockAt sets the wait for the time itself, and any other clock, the
// real one among them, for the timeout to the time from a reading of it, as before. Built where testAwait is.

package sidecar

import (
	"slices"
	"sync"
	"testing"
	"time"
)

// A ClockAt over a testEnvelopeClock that fires its waits, recording what it is asked: the times its waits for a time
// are set for, and how many waits are set by a timeout instead. Its waits are the test clock's, for the timeout to the
// time, which nothing here moves the clock beside.
type testClockAt struct {
	clock *testEnvelopeClock

	stateLock    sync.Mutex
	atTimes      []time.Time
	timeoutCount int
}

var _ ClockAt = (*testClockAt)(nil)

func newTestClockAt() *testClockAt {
	clock := newTestEnvelopeClock()
	clock.firesWaits = true
	return &testClockAt{clock: clock}
}

// The times waits for a time were set for, in order, and the count of waits set by a timeout.
func (self *testClockAt) asked() ([]time.Time, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.atTimes), self.timeoutCount
}

func (self *testClockAt) Now() time.Time {
	return self.clock.Now()
}

func (self *testClockAt) After(timeout time.Duration) <-chan time.Time {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.timeoutCount += 1
	}()
	return self.clock.After(timeout)
}

func (self *testClockAt) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.timeoutCount += 1
	}()
	return self.clock.AfterFunc(timeout, function)
}

func (self *testClockAt) AfterAt(at time.Time) <-chan time.Time {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.atTimes = append(self.atTimes, at)
	}()
	return self.clock.After(at.Sub(self.clock.Now()))
}

func (self *testClockAt) AfterFuncAt(at time.Time, function func()) (stop func() bool) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.atTimes = append(self.atTimes, at)
	}()
	return self.clock.AfterFunc(at.Sub(self.clock.Now()), function)
}

// On a ClockAt, both helpers set the wait for the time itself, and set none by a timeout; each fires once the clock
// reaches its time.
func TestClockAfterAtSetsAClockAtsWaitForTheTime(t *testing.T) {
	clock := newTestClockAt()
	at := clock.Now().Add(time.Second)
	later := at.Add(time.Second)
	fired := ClockAfterAt(clock, at)
	called := make(chan struct{})
	ClockAfterFuncAt(clock, later, func() {
		close(called)
	})
	if times, timeoutCount := clock.asked(); !slices.EqualFunc(times, []time.Time{at, later}, time.Time.Equal) || timeoutCount != 0 {
		t.Fatalf("waits for a time set for %v, %d set by a timeout", times, timeoutCount)
	}
	clock.clock.Advance(2 * time.Second)
	testAwait(t, fired, "the wait for the time")
	testAwait(t, called, "the call at the time")
}

// On a clock that is no ClockAt, both helpers set the wait for the timeout to the time from a reading of the clock, so
// with nothing moving the clock beside them the wait ends at the time itself.
func TestClockAfterAtTimesAnotherClockFromAReading(t *testing.T) {
	clock := newTestEnvelopeClock()
	clock.firesWaits = true
	waits := clock.waitCount.Value()
	at := clock.Now().Add(time.Second)
	fired := ClockAfterAt(clock, at)
	if set, _ := clock.waitAt(waits, at); !set {
		t.Fatal("no wait set for the timeout to the time")
	}
	called := make(chan struct{})
	ClockAfterFuncAt(clock, at, func() {
		close(called)
	})
	clock.Advance(time.Second)
	testAwait(t, fired, "the wait for the time")
	testAwait(t, called, "the call at the time")
}

// On the real clock, which is no ClockAt, a time already passed fires at once, as its timeout, not positive, does.
func TestClockAfterAtOnTheRealClockFiresAPassedTimeAtOnce(t *testing.T) {
	clock := RealClock{}
	passed := clock.Now().Add(-time.Second)
	testAwait(t, ClockAfterAt(clock, passed), "the wait for a passed time")
	called := make(chan struct{})
	ClockAfterFuncAt(clock, passed, func() {
		close(called)
	})
	testAwait(t, called, "the call at a passed time")
}
