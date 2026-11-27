// Waits for a time on a Clock rather than for a timeout (QD-1425). A Clock sets a wait by a timeout, so a caller that
// waits for a time reads the clock, takes the timeout to that time, and then sets the wait, which the clock times from
// its own reading as it sets it. A move of the clock by another goroutine between the two sets the wait late by the
// move. On the real clock that is the nanoseconds between the two calls, but on a fake clock a test moves, a test that
// moved the clock exactly to the time then waits forever, since nothing moves the clock again.
//
// A clock that can set a wait for a time does so here, under its own lock, as sidecartest's FakeClock and its offset
// views do, so no move of it sets the wait late; every other clock, the real one among them, takes the timeout from a
// reading of it as before. Every wait for a time sets its wait here: the root's, and through the exported names the
// engines' and the other packages' that import the root; device/, which may not import the root, keeps the same
// helpers in device/clock.go. A wait for a duration, a retry's backoff or a poll's interval, stays the Clock's own; a
// wait for the earlier of a time and a duration is a wait for a time, the duration's end read from the clock before
// the wait is set, so a move between the two makes it early, never late. Every leg builds this file: it names no
// connect or operator-core type, only the leg's Clock.

package sidecar

import (
	"sync/atomic"
	"time"
)

// What a Clock may also do: set a wait for a time on itself, rather than for a timeout from a reading of it. A time
// already reached fires at once. Implementations are safe for concurrent use.
type ClockAt interface {
	// Fires once this clock reaches at.
	AfterAt(at time.Time) <-chan time.Time
	// Calls function once this clock reaches at, on a goroutine of the clock's choosing, the setting one among them,
	// so function must not assume the caller's locks are held or free. stop is AfterFunc's.
	AfterFuncAt(at time.Time, function func()) (stop func() bool)
}

// Fires once clock reaches at: set for the time itself on a clock that is a ClockAt, and otherwise for the timeout to
// at from a reading of clock, zero for a time already reached, which fires at once.
func ClockAfterAt(clock Clock, at time.Time) <-chan time.Time {
	if clockAt, ok := clock.(ClockAt); ok {
		return clockAt.AfterAt(at)
	}
	return clock.After(max(0, at.Sub(clock.Now())))
}

// Calls function once clock reaches at, as ClockAfterAt sets its wait. A time already reached may call function on the
// setting goroutine before this returns, as a FakeClock does, so a caller that holds a lock function takes, or that
// function calls again, sets its wait with ClockAfterFuncAtAsync. See ClockAt.AfterFuncAt.
func ClockAfterFuncAt(clock Clock, at time.Time, function func()) (stop func() bool) {
	if clockAt, ok := clock.(ClockAt); ok {
		return clockAt.AfterFuncAt(at, function)
	}
	return clock.AfterFunc(max(0, at.Sub(clock.Now())), function)
}

// ClockAfterFuncAt for a caller that function must not run on: one holding a lock function takes, or one that function
// calls again. A time the clock has reached as the wait is set calls function on a goroutine of its own, as the real
// clock's AfterFunc does for a time passed, never on the setting goroutine; a time still to come calls it where
// ClockAfterFuncAt does, on the clock's goroutine, so a FakeClock's Advance past it returns with it called. stop is
// AfterFunc's: false once function has been called, or handed to its own goroutine.
func ClockAfterFuncAtAsync(clock Clock, at time.Time, function func()) (stop func() bool) {
	// set once the wait is: a call before that is the clock's at once, on the setting goroutine or racing it
	var set atomic.Bool
	stop = ClockAfterFuncAt(clock, at, func() {
		if !set.Load() {
			go function()
			return
		}
		function()
	})
	set.Store(true)
	return stop
}
