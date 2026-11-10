// gkm's flows in a page Worker (KEYS-M4-01; §18.10's threads row, §18.8): js/wasm runs one thread and Go cannot
// preempt a goroutine there, so a flow that computes for long without blocking holds the Worker's long-poll and its
// pages' requests until it ends. Each flow that loops over MLS or X-Wing work, a catch-up's commits, a rotation's
// deliveries, a ladder walk, the deliveries a holder opens, calls step between two of them, and step yields the
// thread once 50 ms have passed on the clock since the last yield (sidecar_yield.go). On native legs a yield is a
// cheap hand-off, so the same code runs on every leg.
//
// A step itself is not cut: one commit's processing or one X-Wing seal is one step. The client keeps what its flows'
// yields measured, the steps taken and the longest stretch of clock between two, so the wasm leg's run reads how
// long the Worker went without yielding.
//
// A page Worker is a read_only leaf of each group it reads (§18.8), and only the Worker that holds the network's
// Web Lock loads state: GkmGroupClientArgs.HoldsState says whether this process does, and one that does not loads
// no MLS state and runs no flow (gkm_pins.go's holdsState).

package sidecar

import (
	"time"
)

// What the flows' yields measured since the client started.
type GkmYieldStats struct {
	// Calls of step: the boundaries between two units of work.
	StepCount int
	// The steps that yielded the thread.
	YieldCount int
	// The longest stretch of clock between two steps of one flow, or between its start and its first.
	LongestStep time.Duration
}

// One flow's yields, measured into its client. Not safe for concurrent use: each flow has its own.
type gkmYield struct {
	client *GkmGroupClient
	yield  *sidecarYield
	last   time.Time
}

// A yielder for one flow starting now.
func (self *GkmGroupClient) newYield() *gkmYield {
	return &gkmYield{client: self, yield: newSidecarYield(self.clock), last: self.clock.Now()}
}

// Called between two units of a flow's work: yields once the interval has passed since the last yield.
func (self *gkmYield) step() {
	now := self.client.clock.Now()
	elapsed := now.Sub(self.last)
	self.last = now
	yielded := self.yield.step()
	self.client.stateLock.Lock()
	defer self.client.stateLock.Unlock()
	stats := &self.client.yieldStats
	stats.StepCount += 1
	if yielded {
		stats.YieldCount += 1
	}
	if stats.LongestStep < elapsed {
		stats.LongestStep = elapsed
	}
}

// What the flows' yields measured so far.
func (self *GkmGroupClient) YieldStats() GkmYieldStats {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.yieldStats
}
