// The write budget's tunables, the governor's and each process's (connect/CODESTYLE.md:140): every
// number §11.13's budget rows and §19.6's budget row give, and the price table until §22.8's nvme run
// measures one (D-TEST-11). DefaultWriteBudgetSettings is the only source of a default. The loop and
// every process of a cluster run on the same values, which config/<env> sets for all of them.

package evsservice

import (
	"time"
)

type WriteBudgetSettings struct {
	// §11.13's accounting interval: the governor steps, and each process reports and takes its next
	// shares, this often. 5 s.
	Interval time.Duration
	// The drive the budget is for: R-OPS-12's Samsung PM9A3, 1.92 TB.
	DriveByteCount int64
	// The refill r, in drive writes a day: 0.768, 0.8 x 24/25, so a day of refill and the bucket's depth
	// together hold 0.8 DWPD (owner decision 140). §22.8's runs set 0.8.
	RefillDwpd float64
	// The bucket's depth D, as a span of refill: 1 h.
	Depth time.Duration
	// T's factor at an empty bucket, rising linearly to 1 as B reaches FactorFullShare of D: 0.2 and 0.5
	// (§11.13's accounts row).
	FactorFloor     float64
	FactorFullShare float64
	// The most of T unfunded P2 takes while its backlog lasts: 0.4.
	UnfundedShare float64
	// The span k is measured over: 10 min.
	CalibrationWindow time.Duration
	// k before any priced byte has been issued: 1, the price table taken as it is.
	InitialCalibration float64
	// k is measured only over intervals whose priced bytes reach this share of their refill, and held
	// while none in the window does: 0.1. Heals and the scanner, which the counters measure and nothing
	// prices, would otherwise drive k toward infinity on an idle cluster and price the first pushes
	// after it out of T. B drains by those bytes either way.
	CalibrationMinShare float64
	// The bounds k is held within, for the same reason: 0.25 and 4. A table off by more than that is
	// the nvme run's to correct, and B, which measured bytes drain, carries the difference meanwhile.
	CalibrationMin float64
	CalibrationMax float64
	// A process the governor has not heard from this long is forgotten: 60 s, four report ttls.
	ProcessForgetAfter time.Duration

	// {nvb_<set>}'s ttl on an allowance and on each process's report: 15 s (§19.6).
	AllowanceTtl time.Duration
	ReportTtl    time.Duration
	// The governor's saved B, W and counter readings: 48 h after the loop's last write (§19.4).
	StateTtl time.Duration

	// A process without a fresh allowance this long falls back (§11.13's fallback row): 60 s.
	FallbackAfter time.Duration
	// Its P1 and unfunded P2 then run at this share of its last shares: 0.5.
	FallbackShare float64
	// Its funded P2 then runs at most at its rate over this span: 1 min.
	FallbackFundedWindow time.Duration
	// A process that never had an allowance runs P1 and unfunded P2 within the refill over this many
	// times the process count: 2.
	FallbackProcessFactor int64

	// The queueing delay past which a process refuses the heaviest network (§11.13's shed row): 100 ms.
	ShedDelay time.Duration
	// A refusal's retry_after_ms: one interval, when the next shares arrive.
	RefusalRetryAfter time.Duration
	// How old a network's store_weight may be before it reads DefaultStoreWeight: 5 s, Quota's own
	// cache (§20.7).
	WeightMaxAge time.Duration
	// How often a process rereads the weights of the networks it admitted lately: 2.5 s, so none is read
	// past WeightMaxAge.
	WeightRefreshInterval time.Duration
	// Networks with a P1 admission within this span keep their weights fresh: 1 min.
	WeightActiveWindow time.Duration
	// The weight of a network whose weight is unread, stale or absent: 1, Community's (pro.yml's
	// <tier>.sidecar: store_weight is 1, 4 and 16).
	DefaultStoreWeight int64

	// EVS1-M2-17's path-epoch copies on a cluster: 250 operations a second (§11.6), and up to 1,000
	// while P1 left CopySpareShare of T unspent over CopySpareWindow: a quarter, over a minute.
	CopyOpsPerSecond    int
	CopyOpsPerSecondMax int
	CopySpareShare      float64
	CopySpareWindow     time.Duration

	// §11.13's cost rows for the cluster's XFS block size.
	PriceTable *PriceTable
}

// §11.13's figures, and the 4 KiB block table.
func DefaultWriteBudgetSettings() *WriteBudgetSettings {
	return &WriteBudgetSettings{
		Interval:              5 * time.Second,
		DriveByteCount:        1920 * 1000 * 1000 * 1000,
		RefillDwpd:            0.768,
		Depth:                 1 * time.Hour,
		FactorFloor:           0.2,
		FactorFullShare:       0.5,
		UnfundedShare:         0.4,
		CalibrationWindow:     10 * time.Minute,
		InitialCalibration:    1,
		CalibrationMinShare:   0.1,
		CalibrationMin:        0.25,
		CalibrationMax:        4,
		ProcessForgetAfter:    60 * time.Second,
		AllowanceTtl:          15 * time.Second,
		ReportTtl:             15 * time.Second,
		StateTtl:              48 * time.Hour,
		FallbackAfter:         60 * time.Second,
		FallbackShare:         0.5,
		FallbackFundedWindow:  1 * time.Minute,
		FallbackProcessFactor: 2,
		ShedDelay:             100 * time.Millisecond,
		RefusalRetryAfter:     5 * time.Second,
		WeightMaxAge:          5 * time.Second,
		WeightRefreshInterval: 2500 * time.Millisecond,
		WeightActiveWindow:    1 * time.Minute,
		DefaultStoreWeight:    1,
		CopyOpsPerSecond:      250,
		CopyOpsPerSecondMax:   1000,
		CopySpareShare:        0.25,
		CopySpareWindow:       1 * time.Minute,
		PriceTable:            DefaultPriceTable4KiB(),
	}
}

// The refill r, in drive bytes a second.
func (self *WriteBudgetSettings) refillBytesPerSecond() float64 {
	return self.RefillDwpd * float64(self.DriveByteCount) / (24 * time.Hour).Seconds()
}

// One interval's refill, in drive bytes.
func (self *WriteBudgetSettings) intervalRefillByteCount() float64 {
	return self.refillBytesPerSecond() * self.Interval.Seconds()
}

// The bucket's depth D, in drive bytes.
func (self *WriteBudgetSettings) depthByteCount() int64 {
	return int64(self.refillBytesPerSecond() * self.Depth.Seconds())
}

// How many intervals a span holds, at least one.
func (self *WriteBudgetSettings) intervalCount(span time.Duration) int {
	return max(1, int(span/self.Interval))
}
