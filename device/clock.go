// The clock the device role reads (§22.4, D-TEST-10). This package may not import the root (§4.4,
// D-SDK-20), so it declares the root's Clock method set again, and Go's structural typing lets one
// fake, sidecartest's FakeClock or a view of it, serve the root and this role alike. A nil Clock is
// real time, as in the root. A wait for a time, run's and the link manager's, is set through
// clockAfterAt and clockAfterFuncAt, the root's clock_at.go helpers declared again here (QD-1425).

package device

import (
	"time"
)

// What the device role reads time from. Implementations are safe for concurrent use.
type Clock interface {
	// The time on this clock.
	Now() time.Time
	// Fires once this clock reaches now plus timeout. A timeout that is not positive fires at once.
	After(timeout time.Duration) <-chan time.Time
	// Calls function once this clock reaches now plus timeout, on a goroutine of the clock's choosing.
	// stop returns false once function has been called or stopped.
	AfterFunc(timeout time.Duration, function func()) (stop func() bool)
}

// Real time, what a nil Clock reads: the one place in this package that calls time's clock.
type RealClock struct{}

// The system's time.
func (self RealClock) Now() time.Time {
	return time.Now()
}

// time.After's channel.
func (self RealClock) After(timeout time.Duration) <-chan time.Time {
	return time.After(timeout)
}

// time.AfterFunc's call, on its own goroutine, stopped by its timer's Stop.
func (self RealClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return time.AfterFunc(timeout, function).Stop
}

// What a Clock may also do: set a wait for a time on itself rather than for a timeout from a reading of it, under its
// own lock, so a move of the clock by another goroutine between a caller's reading and its wait cannot set the wait
// late. The root's ClockAt, declared again as Clock is; sidecartest's FakeClock and its offset views are both.
type clockAt interface {
	// Fires once this clock reaches at; a time already reached fires at once.
	AfterAt(at time.Time) <-chan time.Time
	// Calls function once this clock reaches at, on a goroutine of the clock's choosing, the setting one among them.
	AfterFuncAt(at time.Time, function func()) (stop func() bool)
}

// Fires once clock reaches at, as the root's ClockAfterAt: a clockAt sets the wait for the time itself, and any other
// clock, the real one among them, for the timeout to at from a reading of it, zero for a time reached, late on the real
// clock by the nanoseconds between the two calls.
func clockAfterAt(clock Clock, at time.Time) <-chan time.Time {
	if atClock, ok := clock.(clockAt); ok {
		return atClock.AfterAt(at)
	}
	return clock.After(max(0, at.Sub(clock.Now())))
}

// Calls function once clock reaches at, as clockAfterAt sets its wait: the root's ClockAfterFuncAt. A time already
// reached may call function on the setting goroutine before this returns, so the caller holds no lock function takes.
func clockAfterFuncAt(clock Clock, at time.Time, function func()) (stop func() bool) {
	if atClock, ok := clock.(clockAt); ok {
		return atClock.AfterFuncAt(at, function)
	}
	return clock.AfterFunc(max(0, at.Sub(clock.Now())), function)
}
