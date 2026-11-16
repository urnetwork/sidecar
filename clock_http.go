//go:build sidecar_http

// The one clock the core reads, on the sidecar_http leg (§22.4, D-TEST-10, R-TEST-1): the twin of
// clock.go, whose Clock is operator-core's. This leg, the page Worker's sdk.wasm, links no
// operator-core (QD-856), so it declares the same method set itself, and sidecartest's FakeClock
// serves it as it serves the alias. RealClock and the helpers are clock.go's, function by function,
// which TestClockTwinKeepsTheSharedSource holds.

package sidecar

import (
	"time"
)

// What a Sidecar or a host reads time from, the method set of operator-core's Clock. Implementations
// are safe for concurrent use.
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
