// Yielding between the steps of a long operation (§18.10's threads row): js/wasm runs one thread, and Go cannot
// preempt a goroutine there, so an operation that computes for longer than 50 ms without blocking holds the page
// Worker's long-poll and page requests until it ends. A multi-step operation, keychain work over several networks,
// MLS and X-Wing steps, an index walk, calls step between its steps, and step yields the thread once 50 ms have passed
// on the clock since the last yield, so a poll's reply and a page's request run between two steps. A step itself is
// not cut: Argon2id's one call is one step, which §5.9's wasm cost keeps short (settings_http.go).
//
// On native legs the scheduler preempts, and a yield is a cheap hand-off, so the same code runs on every leg.

package sidecar

import (
	"runtime"
	"time"
)

// The longest a long operation computes between two yields (§18.10).
const sidecarYieldInterval = 50 * time.Millisecond

// One long operation's yields. Not safe for concurrent use: each operation has its own.
type sidecarYield struct {
	clock Clock
	// runtime.Gosched, which a test replaces
	yield    func()
	interval time.Duration
	last     time.Time
}

// A yielder for one operation starting now on clock.
func newSidecarYield(clock Clock) *sidecarYield {
	clock = clockOrReal(clock)
	return &sidecarYield{
		clock:    clock,
		yield:    runtime.Gosched,
		interval: sidecarYieldInterval,
		last:     clock.Now(),
	}
}

// Called between two steps: yields once the interval has passed since the last yield or the start, and reports
// whether it did.
func (self *sidecarYield) step() bool {
	now := self.clock.Now()
	if now.Sub(self.last) < self.interval {
		return false
	}
	self.yield()
	self.last = self.clock.Now()
	return true
}
