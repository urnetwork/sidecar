//go:build !ios_extension && !sidecar_http

// The Harness tests' clock: a Clock a test moves, whose timers fire only when the test advances past them, on the
// test's goroutine, in time order, so no Harness test waits on real time (§22.4).

package sidecar

import (
	"context"
	"slices"
	"sync"
	"time"
)

// One timer, armed until its time.
type harnessTestTimer struct {
	at   time.Time
	seq  uint64
	fire func(at time.Time)
}

// A clock a test moves.
type harnessTestClock struct {
	stateLock sync.Mutex
	now       time.Time
	timerSeq  uint64
	timers    []*harnessTestTimer
	// closed and replaced whenever a timer is armed
	armed chan struct{}
}

// A clock at a fixed date, so a test repeats.
func newHarnessTestClock() *harnessTestClock {
	return &harnessTestClock{
		now:   time.Date(2026, time.November, 24, 12, 0, 0, 0, time.UTC),
		armed: make(chan struct{}),
	}
}

func (self *harnessTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *harnessTestClock) arm(at time.Time, fire func(at time.Time)) *harnessTestTimer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.timerSeq += 1
	timer := &harnessTestTimer{at: at, seq: self.timerSeq, fire: fire}
	self.timers = append(self.timers, timer)
	close(self.armed)
	self.armed = make(chan struct{})
	return timer
}

func (self *harnessTestClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	if timeout <= 0 {
		fired <- self.Now()
		return fired
	}
	self.arm(self.Now().Add(timeout), func(at time.Time) {
		fired <- at
	})
	return fired
}

func (self *harnessTestClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	if timeout <= 0 {
		go function()
		return func() bool { return false }
	}
	timer := self.arm(self.Now().Add(timeout), func(at time.Time) {
		function()
	})
	return func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		index := slices.Index(self.timers, timer)
		if index < 0 {
			return false
		}
		self.timers = slices.Delete(self.timers, index, index+1)
		return true
	}
}

// Moves the clock forward by, firing each timer it passes in time order on this goroutine.
func (self *harnessTestClock) Advance(by time.Duration) {
	target := self.Now().Add(by)
	for {
		var next *harnessTestTimer
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
			index := slices.Index(self.timers, next)
			self.timers = slices.Delete(self.timers, index, index+1)
			self.now = next.at
		}()
		if next == nil {
			return
		}
		next.fire(next.at)
	}
}

// Returns once count timers are armed, or ctx ends.
func (self *harnessTestClock) AwaitTimers(ctx context.Context, count int) error {
	for {
		armed, enough := func() (chan struct{}, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.armed, count <= len(self.timers)
		}()
		if enough {
			return nil
		}
		select {
		case <-armed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// How many timers are armed.
func (self *harnessTestClock) TimerCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.timers)
}
