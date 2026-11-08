// §11.13's fallback row: the shares a process takes for its next interval, fresh or not.
//
//   - A fresh allowance, one the loop published since the last the process took with a share for this
//     process, is taken as it is.
//   - With none fresh for less than FallbackAfter, the last shares again: the loop is late, not gone.
//   - With none fresh for FallbackAfter or longer, P1 and unfunded P2 at FallbackShare of the last, and
//     funded P2 at most at the rate the process issued it over the last FallbackFundedWindow.
//   - A process that never had one runs P1 and unfunded P2 within the refill over FallbackProcessFactor
//     times the process count, unfunded P2 at most UnfundedShare of it, and no funded P2, unless the
//     loop's saved state shows B at zero, when it runs neither.
//
// P0 is not here: it runs at once throughout (owner decision 186).

package evsservice

import (
	"math"
	"time"
)

// What the account's goroutine read for one interval.
type writeBudgetIntervalInput struct {
	now time.Time
	// the cluster's allowance, nil when none was read
	allowance *WriteBudgetAllowance
	// for a process that never had an allowance: whether the loop's saved state was read, its B and k,
	// and how many processes report on the cluster, this one included
	stateRead            bool
	stateBucketByteCount int64
	stateCalibration     float64
	processCount         int
}

// The account's history for the fallback, kept under its stateLock.
type writeBudgetFallback struct {
	hadAllowance bool
	lastShare    *WriteBudgetShare
	lastSeq      uint64
	lastTimeMs   int64
	freshTime    time.Time
	// funded P2 issued in each of the last FallbackFundedWindow's intervals, newest last
	fundedIssued []int64
}

// Whether allowance is one the process has not taken yet.
func (self *writeBudgetFallback) isNew(allowance *WriteBudgetAllowance) bool {
	return allowance != nil && (allowance.Seq != self.lastSeq || allowance.TimeMs != self.lastTimeMs)
}

// The shares for the next interval, and whether they came fresh. Records the interval's funded issue
// for the fallback's rate first.
func (self *writeBudgetFallback) takeShares(settings *WriteBudgetSettings, processId string, input *writeBudgetIntervalInput, fundedIssued int64) (*WriteBudgetShare, bool) {
	self.fundedIssued = append(self.fundedIssued, fundedIssued)
	if windowCount := settings.intervalCount(settings.FallbackFundedWindow); windowCount < len(self.fundedIssued) {
		self.fundedIssued = self.fundedIssued[len(self.fundedIssued)-windowCount:]
	}

	if self.isNew(input.allowance) {
		if share, ok := input.allowance.Shares[processId]; ok && share != nil {
			self.hadAllowance = true
			self.lastShare = share
			self.lastSeq = input.allowance.Seq
			self.lastTimeMs = input.allowance.TimeMs
			self.freshTime = input.now
			copied := *share
			return &copied, true
		}
	}

	if self.hadAllowance {
		last := self.lastShare
		if input.now.Sub(self.freshTime) < settings.FallbackAfter {
			copied := *last
			return &copied, false
		}
		var fundedSum int64
		for _, byteCount := range self.fundedIssued {
			fundedSum += byteCount
		}
		fundedRate := fundedSum / int64(max(1, len(self.fundedIssued)))
		scale := func(byteCount int64) int64 {
			return int64(math.Floor(float64(byteCount) * settings.FallbackShare))
		}
		return &WriteBudgetShare{
			P1ByteCount:        scale(last.P1ByteCount),
			UnfundedByteCount:  scale(last.UnfundedByteCount),
			UncoveredByteCount: scale(last.UncoveredByteCount),
			FundedByteCount:    min(last.FundedByteCount, fundedRate),
		}, false
	}

	if input.stateRead && input.stateBucketByteCount <= 0 {
		return &WriteBudgetShare{}, false
	}
	calibration := settings.InitialCalibration
	if input.stateRead && 0 < input.stateCalibration {
		calibration = input.stateCalibration
	}
	processCount := int64(max(1, input.processCount))
	total := int64(math.Floor(settings.intervalRefillByteCount() / calibration / float64(settings.FallbackProcessFactor*processCount)))
	unfunded := int64(math.Floor(settings.UnfundedShare * float64(total)))
	return &WriteBudgetShare{
		P1ByteCount:       total - unfunded,
		UnfundedByteCount: unfunded,
	}, false
}
