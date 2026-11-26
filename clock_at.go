// Waits for a time on a Clock rather than for a timeout (QD-1425). A Clock sets a wait by a timeout, so a caller that
// waits for a time reads the clock, takes the timeout to that time, and then sets the wait, which the clock times from
// its own reading as it sets it. A move of the clock by another goroutine between the two sets the wait late by the
// move. On the real clock that is the nanoseconds between the two calls, but on a fake clock a test moves, a test that
// moved the clock exactly to the time then waits forever, since nothing moves the clock again.
//
// A clock that can set a wait for a time does so here, under its own lock, as sidecartest's FakeClock and its offset
// views do, so no move of it sets the wait late; every other clock, the real one among them, takes the timeout from a
// reading of it as before. Every leg builds this file: it names no connect or operator-core type, only the leg's Clock.

package sidecar

import (
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
// at from a reading of clock.
func clockAfterAt(clock Clock, at time.Time) <-chan time.Time {
	if clockAt, ok := clock.(ClockAt); ok {
		return clockAt.AfterAt(at)
	}
	return clock.After(at.Sub(clock.Now()))
}

// Calls function once clock reaches at, as clockAfterAt sets its wait. See ClockAt.AfterFuncAt.
func clockAfterFuncAt(clock Clock, at time.Time, function func()) (stop func() bool) {
	if clockAt, ok := clock.(ClockAt); ok {
		return clockAt.AfterFuncAt(at, function)
	}
	return clock.AfterFunc(at.Sub(clock.Now()), function)
}
