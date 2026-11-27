// A clock for a loop whose waits must end with its context (clock-select-ctx-sweep, after tls-wait-ctx-shape). Go's
// select takes any of its ready cases at random, so a loop that selects on ctx.Done() beside a clock's timer runs one
// more pass after its context ended whenever both are ready at once and the timer's case wins. This clock makes them
// ready at once: its waits are held until the test opens it, so the test arms it before the loop asks; then each wait
// it counts fires at once, until the counted one at which it runs the test's end, a cancel or a Close, before it hands
// the timer back, so the waiter's select finds the end and the timer both ready, as a cancel landing with a timer does.
// A counted wait after that one never fires, nor does a wait it does not count, so a loop beside the one under test
// stays parked. A loop that answers the end whatever else was ready passes in every round; one that does not takes the
// timer's case at least half the time, so a test of 64 rounds leaves it no chance worth naming to pass.
//
// Now stays where the clock started, unless MoveOnFire has it move to each wait's time as the wait fires, as a real
// timer's firing finds the time passed, for a loop that reads the clock again after its wait. AfterFunc never calls
// its function. The clock is no sidecar.ClockAt, so a wait for a time, sidecar.ClockAfterAt's, is a wait for the
// timeout to it from Now. Safe for concurrent use.

package sidecartest

import (
	"sync"
	"time"
)

// See the file header.
type EndingClock struct {
	// whether it counts a wait of timeout; nil counts every wait
	counts func(timeout time.Duration) bool
	// closed when the test lets the waits through
	opened   chan struct{}
	openOnce sync.Once

	stateLock sync.Mutex
	now       time.Time
	// whether a wait that fires moves now to its time
	moves bool
	// the counted wait, from 1, at which end runs; 0 for none, which fires every counted wait
	endIndex int
	end      func()
	// the counted waits asked so far
	waitCount int
	// every wait asked so far, counted or not
	askCount int
}

var _ Clock = (*EndingClock)(nil)

// A held clock reading now that counts the waits counts takes, every wait when counts is nil.
func NewEndingClock(now time.Time, counts func(timeout time.Duration) bool) *EndingClock {
	return &EndingClock{
		counts: counts,
		opened: make(chan struct{}),
		now:    now,
	}
}

// An EndingClock's counts for the waits of these timeouts alone.
func EndingClockCounts(timeouts ...time.Duration) func(timeout time.Duration) bool {
	return func(timeout time.Duration) bool {
		for _, counted := range timeouts {
			if timeout == counted {
				return true
			}
		}
		return false
	}
}

// See sidecar.Clock.
func (self *EndingClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

// Has each wait that fires from here on move the clock to its time first.
func (self *EndingClock) MoveOnFire() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.moves = true
}

// See sidecar.Clock: blocks until Open, then fires at once when it is a counted wait at or before the end's, running
// the end first when it is the end's.
func (self *EndingClock) After(timeout time.Duration) <-chan time.Time {
	<-self.opened
	var end func()
	fires, firedAt := func() (bool, time.Time) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.askCount += 1
		if self.counts != nil && !self.counts(timeout) {
			return false, time.Time{}
		}
		self.waitCount += 1
		if self.waitCount == self.endIndex {
			end = self.end
		}
		fires := self.endIndex == 0 || self.waitCount <= self.endIndex
		if fires && self.moves {
			self.now = self.now.Add(max(0, timeout))
		}
		return fires, self.now
	}()
	// the end lands before the timer's channel is handed back, so the waiter's select finds both ready
	if end != nil {
		end()
	}
	fire := make(chan time.Time, 1)
	if fires {
		fire <- firedAt
	}
	return fire
}

// See sidecar.Clock. It never calls function.
func (self *EndingClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool {
		return true
	}
}

// Runs end as the index-th counted wait, from 1, fires.
func (self *EndingClock) Arm(index int, end func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.endIndex = index
	self.end = end
}

// Lets the waits through. Safe more than once.
func (self *EndingClock) Open() {
	self.openOnce.Do(func() {
		close(self.opened)
	})
}

// The counted waits asked so far.
func (self *EndingClock) Waits() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.waitCount
}

// Every wait asked so far.
func (self *EndingClock) Asks() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.askCount
}
