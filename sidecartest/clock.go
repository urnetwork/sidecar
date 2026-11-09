// The injected clock (§22.4): every fake here reads it, and a schedule moves it with Advance. Nothing
// in this package sleeps. A wait that must end at a time on this clock is a timer on it, and it fires
// only when a schedule moves the clock past it, so a test holds no real-time race.

package sidecartest

import (
	"cmp"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// What an actor reads time from: the shared FakeClock, or a view of it with an offset, as a host whose
// clock runs fast has (FS-1's evs2). The root's Clock, so a FakeClock or a view of one goes straight
// into ServiceHost.Clock and SidecarSettings.Clock (TEST-M0-02).
type Clock = sidecar.Clock

type clockTimer struct {
	at   time.Time
	seq  uint64
	fire func(at time.Time)
}

// Shared by every actor of a test, and starts at the time given, which stays the same from run to run
// so a schedule's trace repeats. Safe for concurrent use.
type FakeClock struct {
	stateLock sync.Mutex
	now       time.Time
	timerSeq  uint64
	timers    []*clockTimer
	// closed and replaced whenever a timer is added, for AwaitTimers
	timerAdded chan struct{}
}

func NewFakeClock(start time.Time) *FakeClock {
	return &FakeClock{
		now:        start,
		timerAdded: make(chan struct{}),
	}
}

// Where a test's clock starts by default: a fixed date, so ids and traces repeat.
func DefaultClockStart() time.Time {
	return time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
}

func (self *FakeClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *FakeClock) addTimerWithLock(at time.Time, fire func(at time.Time)) *clockTimer {
	self.timerSeq += 1
	timer := &clockTimer{at: at, seq: self.timerSeq, fire: fire}
	self.timers = append(self.timers, timer)
	close(self.timerAdded)
	self.timerAdded = make(chan struct{})
	return timer
}

func (self *FakeClock) removeTimer(timer *clockTimer) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	index := slices.Index(self.timers, timer)
	if index < 0 {
		return false
	}
	self.timers = slices.Delete(self.timers, index, index+1)
	return true
}

func (self *FakeClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	if timeout <= 0 {
		fired <- self.Now()
		return fired
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.addTimerWithLock(self.now.Add(timeout), func(at time.Time) {
			fired <- at
		})
	}()
	return fired
}

func (self *FakeClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	if timeout <= 0 {
		function()
		return func() bool { return false }
	}
	var timer *clockTimer
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		timer = self.addTimerWithLock(self.now.Add(timeout), func(at time.Time) {
			function()
		})
	}()
	return func() bool { return self.removeTimer(timer) }
}

// Moves the clock forward, firing every timer it passes in time order, each at its own time, so a
// timer that adds a nearer one sees it fire before the move ends. A negative timeout is a bug in the
// schedule.
func (self *FakeClock) Advance(timeout time.Duration) {
	if timeout < 0 {
		panic("the fake clock only moves forward")
	}
	var target time.Time
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		target = self.now.Add(timeout)
	}()
	for {
		var next *clockTimer
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			for _, timer := range self.timers {
				if timer.at.After(target) {
					continue
				}
				if next == nil || timer.at.Before(next.at) || (timer.at.Equal(next.at) && timer.seq < next.seq) {
					next = timer
				}
			}
			if next == nil {
				self.now = target
				return
			}
			self.timers = slices.Delete(self.timers, slices.Index(self.timers, next), slices.Index(self.timers, next)+1)
			self.now = next.at
		}()
		if next == nil {
			return
		}
		// on this goroutine, with no lock held: a callback may read the clock or add a timer
		next.fire(next.at)
	}
}

// Moves the clock to at. A time already past does nothing.
func (self *FakeClock) AdvanceTo(at time.Time) {
	if timeout := at.Sub(self.Now()); 0 < timeout {
		self.Advance(timeout)
	}
}

// Timers set and not yet fired, nearest first, for a test's trace.
func (self *FakeClock) PendingTimers() []time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pendingTimersWithLock()
}

// PendingTimers with a channel that closes when the next timer is set, read together, so a test that
// does not find the timer it wants waits for the next with no sleep, and no timer set between its read
// and its wait goes unseen.
func (self *FakeClock) WatchTimers() (pending []time.Time, added chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pendingTimersWithLock(), self.timerAdded
}

func (self *FakeClock) pendingTimersWithLock() []time.Time {
	times := make([]time.Time, 0, len(self.timers))
	for _, timer := range self.timers {
		times = append(times, timer.at)
	}
	slices.SortFunc(times, func(a time.Time, b time.Time) int { return cmp.Compare(a.UnixNano(), b.UnixNano()) })
	return times
}

// Returns once at least timerCount timers are pending, or ctx ends: how a test knows a goroutine has
// reached its wait before moving the clock past it, with no sleep.
func (self *FakeClock) AwaitTimers(ctx context.Context, timerCount int) error {
	for {
		var added chan struct{}
		var enough bool
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			added = self.timerAdded
			enough = timerCount <= len(self.timers)
		}()
		if enough {
			return nil
		}
		select {
		case <-added:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// This clock seen from a host whose own clock is offset ahead of the shared one. Timers run on the
// shared clock, so a timeout takes the same fake time on every view.
func (self *FakeClock) WithOffset(offset time.Duration) Clock {
	return &offsetClock{clock: self, offset: offset}
}

type offsetClock struct {
	clock  *FakeClock
	offset time.Duration
}

func (self *offsetClock) Now() time.Time {
	return self.clock.Now().Add(self.offset)
}

func (self *offsetClock) After(timeout time.Duration) <-chan time.Time {
	return self.clock.After(timeout)
}

func (self *offsetClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return self.clock.AfterFunc(timeout, function)
}
