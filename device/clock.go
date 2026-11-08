// The clock the device role reads (§22.4, D-TEST-10). This package may not import the root (§4.4,
// D-SDK-20), so it declares the root's Clock method set again, and Go's structural typing lets one
// fake, sidecartest's FakeClock or a view of it, serve the root and this role alike. A nil Clock is
// real time, as in the root.

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

func (self RealClock) Now() time.Time {
	return time.Now()
}

func (self RealClock) After(timeout time.Duration) <-chan time.Time {
	return time.After(timeout)
}

func (self RealClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return time.AfterFunc(timeout, function).Stop
}
