// The one clock the core and the engines read (§22.4, D-TEST-10, R-TEST-1). Every reading of time
// and every wait goes through a Clock, so a test moves time with sidecartest's FakeClock and never
// sleeps, and one host can run fast or slow beside the others, as FS-1's evs2 runs 150 ms ahead
// through FakeClock.WithOffset (plan-TEST-clock-seam). ServiceHost.Clock carries an engine's,
// SidecarSettings.Clock a Sidecar's, and nil in either is real time.
//
// It is declared on every leg, sidecar_http included, so it names no connect type. device/ may not
// import the root, so it declares the same method set (device/clock.go), and one fake serves both.
// connect's own timers stay real and connect does not change for this (X9): a schedule moves a link
// with Net.SetLink, never connect's timers. Nor does a context's deadline stand in for a fake one,
// as WithBlobDeadline says: a deadline on this clock is a timer on it.
//
// make check refuses a direct call to time's clock in the root, an engine, mcp/ or device/, outside
// RealClock and a dated list of exceptions, id.go's ULID first (check/clock_rule_test.go).

package sidecar

import (
	"time"
)

// What a Sidecar, an engine or a host reads time from. Implementations are safe for concurrent use.
type Clock interface {
	// The time on this clock.
	Now() time.Time
	// Fires once this clock reaches now plus timeout. A timeout that is not positive fires at once.
	After(timeout time.Duration) <-chan time.Time
	// Calls function once this clock reaches now plus timeout, on a goroutine of the clock's choosing,
	// so function must not assume the caller's locks are held or free. stop returns false once
	// function has been called or stopped, and true when it stopped a call still to come.
	AfterFunc(timeout time.Duration, function func()) (stop func() bool)
}

// Real time: the clock a nil Clock reads, and the one place in the root that calls time's clock.
type RealClock struct{}

func (self RealClock) Now() time.Time {
	return time.Now()
}

func (self RealClock) After(timeout time.Duration) <-chan time.Time {
	return time.After(timeout)
}

func (self RealClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return time.AfterFunc(timeout, function).Stop
}

// clock, or real time when clock is nil: how a holder of a Clock field reads it.
func clockOrReal(clock Clock) Clock {
	if clock == nil {
		return RealClock{}
	}
	return clock
}

// The clock a Sidecar reads: SidecarSettings.Clock, or real time when the host set none.
func (self *SidecarSettings) ClockOrReal() Clock {
	return clockOrReal(self.Clock)
}
