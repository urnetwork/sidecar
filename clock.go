//go:build !sidecar_http

// The one clock the core and the engines read (§22.4, D-TEST-10, R-TEST-1). Every reading of time
// and every wait goes through a Clock, so a test moves time with sidecartest's FakeClock and never
// sleeps, and one host can run fast or slow beside the others, as FS-1's evs2 runs 150 ms ahead
// through FakeClock.WithOffset (plan-TEST-clock-seam). ServiceHost.Clock carries an engine's,
// SidecarSettings.Clock a Sidecar's, and nil in either is real time.
//
// The interface is operator-core's (owner decision 251), aliased here on every leg but sidecar_http,
// which links no operator-core (QD-856): clock_http.go declares the same method set there, with this
// file's RealClock and helpers, and TestClockTwinKeepsTheSharedSource holds the two equal. It names
// no connect type. device/ may not import the root, so it declares the same method set
// (device/clock.go), and one fake serves both.
// connect's own timers stay real and connect does not change for this (X9): a schedule moves a link
// with Net.SetLink, never connect's timers. Nor does a context's deadline stand in for a fake one,
// as WithBlobDeadline says: a deadline on this clock is a timer on it.
//
// make check refuses a direct call to time's clock in the root, an engine, mcp/ or device/, outside
// RealClock and a dated list of exceptions, id.go's ULID first (check/clock_rule_test.go).

package sidecar

import (
	"time"

	operator "github.com/urnetwork/operator-core"
)

// What a Sidecar, an engine or a host reads time from: Now, After and AfterFunc. Implementations are
// safe for concurrent use.
type Clock = operator.Clock

// Real time: the clock a nil Clock reads, and the one place in the root that calls time's clock.
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
