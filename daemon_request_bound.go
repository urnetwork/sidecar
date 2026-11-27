//go:build !js && !ios && !android && !sdk_mobile_bind

// A control request's bound (§5.8; QD-518): SidecarLocalSettings.RequestTimeout of the request's own work, on the
// daemon's clock. Time the request waits on a person is outside it: from a person wait's start to its end
// (daemonPersonWait) the bound stands still, the request's own work so far staying counted, and once the last wait
// under way ends it runs on with what that work left of it, expiring at once where nothing is left. The daemon's
// presence prompt is such a wait (daemon_presence.go), whether it runs on the handler's goroutine or on a held act's
// run for the call that drives the act (daemon_approvals.go). Once the bound expired or its request ended, a wait
// changes nothing.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"sync"
	"time"
)

// One request's bound. Construct with newDaemonRequestBound, which starts it.
type daemonRequestBound struct {
	clock   Clock
	timeout time.Duration
	// what the bound's expiry calls, at most once
	expire func()

	stateLock sync.Mutex
	// the request's own work the bound counted before its current run
	counted time.Duration
	// when its current run began
	runAt time.Time
	// the person waits under way: while any is, the bound stands still
	waits int
	// moved on whenever the bound stops, so a timer armed before it does nothing
	generation uint64
	// the current run's timer, nil while none runs
	stop func() bool
	// the bound expired or its request ended: nothing runs it again
	done bool
}

// The bound of a request on clock: timeout of its own work, past which expire is called, once, unless the request ends
// first. It runs from now.
func newDaemonRequestBound(clock Clock, timeout time.Duration, expire func()) *daemonRequestBound {
	bound := &daemonRequestBound{clock: clock, timeout: timeout, expire: expire}
	bound.run()
	return bound
}

// Runs the bound on with what the request's own work left of it, unless it ended or a wait is under way: its expiry is
// that much past the run's start, the time the timer is set for itself (QD-1425), as a wait counts from that start.
// Called with no lock held, since a clock may call back before it answers.
func (self *daemonRequestBound) run() {
	generation, expireAt, ok := func() (uint64, time.Time, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.done || 0 < self.waits {
			return 0, time.Time{}, false
		}
		self.generation += 1
		self.runAt = self.clock.Now()
		return self.generation, self.runAt.Add(self.timeout - self.counted), true
	}()
	if !ok {
		return
	}
	stop := ClockAfterFuncAt(self.clock, expireAt, func() {
		expired := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.done || self.generation != generation {
				return false
			}
			self.done = true
			self.generation += 1
			self.stop = nil
			return true
		}()
		if expired {
			self.expire()
		}
	})
	stale := func() func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.generation != generation {
			// a wait, the expiry or the request's end stopped this run meanwhile
			return stop
		}
		self.stop = stop
		return nil
	}()
	if stale != nil {
		stale()
	}
}

// Stops the bound for a wait on the person until the returned function is called, which it may be from any goroutine
// and more than once, the first call counting. The request's own work so far stays counted. Nothing once the bound
// expired or its request ended.
func (self *daemonRequestBound) personWait() func() {
	stop, ok := func() (func() bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.done {
			return nil, false
		}
		var stop func() bool
		if self.waits == 0 {
			self.counted += self.clock.Now().Sub(self.runAt)
			self.generation += 1
			stop = self.stop
			self.stop = nil
		}
		self.waits += 1
		return stop, true
	}()
	if !ok {
		return func() {}
	}
	if stop != nil {
		stop()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			last := func() bool {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.waits -= 1
				return self.waits == 0
			}()
			if last {
				self.run()
			}
		})
	}
}

// Ends the bound with its request: nothing expires or runs it again.
func (self *daemonRequestBound) end() {
	stop := func() func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.done = true
		self.generation += 1
		stop := self.stop
		self.stop = nil
		return stop
	}()
	if stop != nil {
		stop()
	}
}

// The context key of a request's bound.
type daemonRequestBoundKey struct{}

// ctx, carrying bound as its request's, nil for none.
func withDaemonRequestBound(ctx context.Context, bound *daemonRequestBound) context.Context {
	return context.WithValue(ctx, daemonRequestBoundKey{}, bound)
}

// The bound of the request ctx carries, nil for none.
func daemonRequestBoundOf(ctx context.Context) *daemonRequestBound {
	bound, _ := ctx.Value(daemonRequestBoundKey{}).(*daemonRequestBound)
	return bound
}

// Starts a wait on the person within the request ctx carries (QD-518): its bound stands still until the returned
// function is called, once the person answered or the wait ended otherwise. A context with no bounded request has
// nothing to stop.
func daemonPersonWait(ctx context.Context) func() {
	bound := daemonRequestBoundOf(ctx)
	if bound == nil {
		return func() {}
	}
	return bound.personWait()
}
