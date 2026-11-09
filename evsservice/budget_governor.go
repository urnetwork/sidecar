// §11.13's accounts for one metadata cluster as a pure state machine (D-EVS-21, D-EVS-33, FI-14):
// taskworker's budget loop (§19.6's budget row, EVSB-M2-07) holds a Redis lease, steps a Governor every
// interval with its busiest drive not under heal's measured bytes and the processes' reports, publishes
// the allowance it returns in {nvb_<set>} and saves its State. It does no I/O and reads no clock, so
// FS-116 runs it alone on a fake clock.
//
// Units: B, D, the refill r and the forgiven excess are drive bytes; every account a process spends (T,
// A_U, A1, A2, W) and every figure a process reports is priced bytes, §11.13's cost rows before
// calibration. k, measured over priced bytes, converts: a priced byte times k is a drive byte, so a
// process comparing a write's price against an allowance in priced bytes is comparing its drive bytes
// against the allowance's.
//
// Each step, in §11.13's order:
//
//   - k is the measured bytes over the priced bytes issued in the last CalibrationWindow, P0's
//     included (plan-EVSB-nvb-fields), over the intervals that priced at least CalibrationMinShare of
//     their refill and held within [CalibrationMin, CalibrationMax], so an idle cluster's heals and
//     scanner do not price pushes out (see the settings);
//   - B gains an interval of r and loses the measured bytes, floored at zero and capped at D. The bytes
//     past what B held are P0's forgiven excess, by kind in proportion to P0's bytes, never repaid
//     (owner decision 190), and any rest is the other classes' pricing error, at most one interval's;
//   - f = FactorFloor + (1 - FactorFloor) min(1, B / (FactorFullShare D));
//   - T = max(0, min(r f - P0's priced bytes k, B - in flight k)), in priced bytes T / k;
//   - W gains the credit the processes moved, loses the funded P2 they issued, and is clamped to
//     [0, the funded backlog they report], so the credit of work that never runs lapses;
//   - A_U = min(unfunded demand, UnfundedShare T) while unfunded backlog lasts, where funded work W no
//     longer covers counts as unfunded (a process killed before its report, {nvb_<set>} lost): it is
//     then paid once, from A_U (§11.13's wallet row);
//   - A1 = T - A_U;
//   - A2 = max(0, min(W, (B - T k - in flight k) / k)), so funded P2 spends only what B holds beyond T
//     and never T itself: a push's P2 work is paid once (D-EVS-33's trap);
//   - shares: A1 by each process's P1 demand, its queued and last interval's admitted priced bytes,
//     evenly while no process has any; A_U by unfunded demand; A2 by funded demand rank by rank, then
//     by the backlog not yet due, rank by rank (§11.13's order row).
//
// Not safe for concurrent use: one loop owns a Governor.

package evsservice

import (
	"fmt"
	"maps"
	"math"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
)

// One process's report on one metadata cluster, written every interval (§11.13's reports row,
// plan-EVSB-nvb-fields). Totals count from the process's start, so a report the governor missed loses
// nothing but timing, and levels are as of TimeMs. It names no network or repo (evs-10).
type WriteBudgetReport struct {
	// 16 random bytes drawn at the process's start, as hex: not a host, network or repo.
	ProcessId string `json:"process"`
	// When the process started and wrote this, Unix ms by its clock.
	StartMs int64 `json:"start_ms"`
	TimeMs  int64 `json:"time_ms"`

	// P0's priced bytes by kind.
	P0ByteCounts map[sidecar.WriteP0Kind]int64 `json:"p0,omitempty"`
	// P1's admitted priced bytes: the immediate part, and the deferred part it moved into W.
	P1ByteCount     int64 `json:"p1"`
	CreditByteCount int64 `json:"credit"`
	// P2 issued: unfunded, with funded work paid from A_U among it, and funded from A2, the credit spent.
	UnfundedByteCount int64 `json:"p2u"`
	FundedByteCount   int64 `json:"p2f"`

	// P1 waiting in the process's fair queues.
	P1QueuedByteCount int64 `json:"p1q"`
	// Issued and not yet ended.
	InFlightByteCount int64 `json:"flight"`
	// By WriteP2Rank: P2 waiting to issue, and all P2 the process knows is outstanding, due or not.
	UnfundedDemandByteCounts  []int64 `json:"p2ud,omitempty"`
	UnfundedBacklogByteCounts []int64 `json:"p2ub,omitempty"`
	FundedDemandByteCounts    []int64 `json:"p2fd,omitempty"`
	FundedBacklogByteCounts   []int64 `json:"p2fb,omitempty"`
}

// A report the governor cannot use is dropped whole: its process reads as absent this step.
func (self *WriteBudgetReport) validate() error {
	if self.ProcessId == "" {
		return fmt.Errorf("a report with no process")
	}
	for kind, byteCount := range self.P0ByteCounts {
		if !kind.Valid() || byteCount < 0 {
			return fmt.Errorf("P0 of kind %q: %d", kind, byteCount)
		}
	}
	for _, byteCount := range []int64{
		self.P1ByteCount, self.CreditByteCount, self.UnfundedByteCount, self.FundedByteCount,
		self.P1QueuedByteCount, self.InFlightByteCount,
	} {
		if byteCount < 0 {
			return fmt.Errorf("a count below zero")
		}
	}
	for _, byteCounts := range [][]int64{
		self.UnfundedDemandByteCounts, self.UnfundedBacklogByteCounts,
		self.FundedDemandByteCounts, self.FundedBacklogByteCounts,
	} {
		if sidecar.WriteP2RankCount < len(byteCounts) {
			return fmt.Errorf("%d ranks", len(byteCounts))
		}
		for _, byteCount := range byteCounts {
			if byteCount < 0 {
				return fmt.Errorf("a backlog below zero")
			}
		}
	}
	return nil
}

// A rank's figure, zero past the end of what a report sent.
func rankByteCount(byteCounts []int64, rank int) int64 {
	if rank < len(byteCounts) {
		return byteCounts[rank]
	}
	return 0
}

// The ranks' sum.
func sumByteCounts(byteCounts []int64) int64 {
	var sum int64
	for _, byteCount := range byteCounts {
		sum += byteCount
	}
	return sum
}

// One process's part of an allowance, priced bytes for the next interval.
type WriteBudgetShare struct {
	// A1's part.
	P1ByteCount int64 `json:"a1"`
	// A_U's part, UncoveredByteCount included.
	UnfundedByteCount int64 `json:"au"`
	// Of UnfundedByteCount, what the process's funded work W does not cover may spend.
	UncoveredByteCount int64 `json:"uncovered"`
	// A2's part.
	FundedByteCount int64 `json:"a2"`
}

// What a step publishes in {nvb_<set>} (§19.6's budget row): the accounts, the calibration, P0's
// figures, the copy rate and each reporting process's share.
type WriteBudgetAllowance struct {
	ClusterId string `json:"cluster"`
	// The step, rising by one each interval while the state is kept.
	Seq    uint64 `json:"seq"`
	TimeMs int64  `json:"time_ms"`
	// k.
	Calibration float64 `json:"k"`
	// B and D, drive bytes.
	BucketByteCount int64 `json:"b"`
	DepthByteCount  int64 `json:"d"`
	// W, T, A1, A_U and A2, priced bytes.
	WalletByteCount   int64 `json:"w"`
	TotalByteCount    int64 `json:"t"`
	P1ByteCount       int64 `json:"a1"`
	UnfundedByteCount int64 `json:"au"`
	FundedByteCount   int64 `json:"a2"`
	// The busiest drive's measured bytes this interval and P0's part, drive bytes.
	MeasuredByteCount   int64 `json:"measured"`
	P0MeasuredByteCount int64 `json:"p0_measured"`
	// This interval's bytes past what B held that P0 did not account for: the other classes' pricing
	// error, drive bytes.
	PricingErrorByteCount int64 `json:"error"`
	// P0's forgiven excess by kind since the state began, drive bytes (owner decision 190).
	P0ExcessByteCounts map[sidecar.WriteP0Kind]int64 `json:"excess,omitempty"`
	// The cluster's path-epoch copy rate, and how many processes report copies to split it.
	CopyOpsPerSecond int `json:"copy_ops"`
	CopyProcessCount int `json:"copy_processes"`
	// §19.9's line, which the loop sets from FileClusterAdminInfo (plan-EVSB-nvb-fields).
	AtLimit bool `json:"at_limit"`
	// This interval's figures for §19.8's liabilities, priced bytes: what the processes reported issued since
	// the last step, P1's immediate and deferred parts together, and what they hold queued or outstanding.
	P1IssuedByteCount        int64 `json:"p1_issued"`
	FundedIssuedByteCount    int64 `json:"p2f_issued"`
	UnfundedIssuedByteCount  int64 `json:"p2u_issued"`
	P1QueuedByteCount        int64 `json:"p1_queued"`
	FundedBacklogByteCount   int64 `json:"p2f_backlog"`
	UnfundedBacklogByteCount int64 `json:"p2u_backlog"`
	// By process id.
	Shares map[string]*WriteBudgetShare `json:"shares,omitempty"`
}

// The last totals the governor saw from a process.
type GovernorProcess struct {
	LastSeenMs        int64                         `json:"seen_ms"`
	P0ByteCounts      map[sidecar.WriteP0Kind]int64 `json:"p0,omitempty"`
	P1ByteCount       int64                         `json:"p1"`
	CreditByteCount   int64                         `json:"credit"`
	UnfundedByteCount int64                         `json:"p2u"`
	FundedByteCount   int64                         `json:"p2f"`
}

// One interval's calibration figures.
type GovernorCalibrationSample struct {
	MeasuredByteCount int64 `json:"m"`
	PricedByteCount   int64 `json:"p"`
}

// One interval's figures for the copy rate: the A1 and T in force, and the P1 debited against them.
type GovernorCopySample struct {
	P1AllowanceByteCount int64 `json:"a1"`
	TotalByteCount       int64 `json:"t"`
	P1DebitByteCount     int64 `json:"p1"`
}

// What the loop saves every interval with a 48 h ttl, so a loop that takes the lease resumes exactly
// (§19.6). Its absence starts B and W at zero, which is conservative.
type GovernorState struct {
	Seq                   uint64                        `json:"seq"`
	TimeMs                int64                         `json:"time_ms"`
	BucketByteCount       int64                         `json:"b"`
	WalletByteCount       int64                         `json:"w"`
	Calibration           float64                       `json:"k"`
	CalibrationSamples    []*GovernorCalibrationSample  `json:"ks,omitempty"`
	CopySamples           []*GovernorCopySample         `json:"cs,omitempty"`
	LastP1ByteCount       int64                         `json:"last_a1"`
	LastTotalByteCount    int64                         `json:"last_t"`
	P0ExcessByteCounts    map[sidecar.WriteP0Kind]int64 `json:"excess,omitempty"`
	PricingErrorByteCount int64                         `json:"error"`
	Processes             map[string]*GovernorProcess   `json:"processes,omitempty"`
	// The loop's drive counter readings, kept here so B and the readings it was taken at stay together.
	// The governor does not read them.
	CounterReadings map[string]uint64 `json:"counters,omitempty"`
	// The loop's running total of each drive's written bytes, a fall or a new drive counting from zero, and
	// its snapshots, for §19.8's DWPD windows (budget_loop.go). The governor does not read them either.
	DriveTotals    map[string]uint64        `json:"totals,omitempty"`
	DriveSnapshots []*GovernorDriveSnapshot `json:"snapshots,omitempty"`
}

// A deep copy.
func (self *GovernorState) clone() *GovernorState {
	state := *self
	state.CalibrationSamples = []*GovernorCalibrationSample{}
	for _, sample := range self.CalibrationSamples {
		copied := *sample
		state.CalibrationSamples = append(state.CalibrationSamples, &copied)
	}
	state.CopySamples = []*GovernorCopySample{}
	for _, sample := range self.CopySamples {
		copied := *sample
		state.CopySamples = append(state.CopySamples, &copied)
	}
	state.P0ExcessByteCounts = maps.Clone(self.P0ExcessByteCounts)
	state.Processes = map[string]*GovernorProcess{}
	for processId, process := range self.Processes {
		copied := *process
		copied.P0ByteCounts = maps.Clone(process.P0ByteCounts)
		state.Processes[processId] = &copied
	}
	state.CounterReadings = maps.Clone(self.CounterReadings)
	state.DriveTotals = maps.Clone(self.DriveTotals)
	state.DriveSnapshots = cloneGovernorDriveSnapshots(self.DriveSnapshots)
	return &state
}

// See the file header.
type Governor struct {
	clusterId string
	settings  *WriteBudgetSettings
	state     *GovernorState
	// funded backlog the loop counts beyond the processes' reports, priced bytes
	standingFundedByteCount int64
}

// Sets the funded backlog the loop counts beyond what the processes report, for the steps that follow:
// evacuation's batches still standing on the cluster, which their admissions paid for 25 h before the work
// runs (budget_loop.go, §11.13's wallet row). It holds W's credit against the clamp and is no process's
// demand, so it takes no share.
func (self *Governor) SetStandingFundedBacklog(byteCount int64) {
	self.standingFundedByteCount = max(0, byteCount)
}

// A governor resuming state, or starting B and W at zero when state is nil. settings may be nil for
// the defaults.
func NewGovernor(clusterId string, settings *WriteBudgetSettings, state *GovernorState) *Governor {
	if settings == nil {
		settings = DefaultWriteBudgetSettings()
	}
	if state == nil {
		state = &GovernorState{Calibration: settings.InitialCalibration}
	} else {
		state = state.clone()
	}
	if state.Calibration <= 0 || math.IsNaN(state.Calibration) || math.IsInf(state.Calibration, 0) {
		state.Calibration = settings.InitialCalibration
	}
	if state.P0ExcessByteCounts == nil {
		state.P0ExcessByteCounts = map[sidecar.WriteP0Kind]int64{}
	}
	if state.Processes == nil {
		state.Processes = map[string]*GovernorProcess{}
	}
	return &Governor{
		clusterId: clusterId,
		settings:  settings,
		state:     state,
	}
}

// A copy of the state, for the loop to save.
func (self *Governor) State() *GovernorState {
	return self.state.clone()
}

// One reporting process this step: its report, and what it did since its last.
type governorLive struct {
	report *WriteBudgetReport
	// deltas since the last report seen
	p0ByteCounts      map[sidecar.WriteP0Kind]int64
	p1ByteCount       int64
	creditByteCount   int64
	unfundedByteCount int64
	fundedByteCount   int64
}

// The live processes' deltas, in process id order, the latest report of each id kept and every one the
// governor cannot use, or older than ReportTtl, dropped. A process it has not seen counts from its start only if it started
// after the last step, so a governor that lost its state takes a running process's totals as its
// baseline rather than as one interval's work.
func (self *Governor) takeReports(nowMs int64, reports []*WriteBudgetReport) []*governorLive {
	processIdReports := map[string]*WriteBudgetReport{}
	for _, report := range reports {
		if report == nil || report.validate() != nil {
			continue
		}
		// a report whose ttl never landed outlives its process: past ReportTtl it is gone
		if self.settings.ReportTtl.Milliseconds() < nowMs-report.TimeMs {
			continue
		}
		if previous, ok := processIdReports[report.ProcessId]; !ok || previous.TimeMs < report.TimeMs {
			processIdReports[report.ProcessId] = report
		}
	}
	lives := []*governorLive{}
	for _, processId := range slices.Sorted(maps.Keys(processIdReports)) {
		report := processIdReports[processId]
		live := &governorLive{report: report, p0ByteCounts: map[sidecar.WriteP0Kind]int64{}}
		previous, seen := self.state.Processes[processId]
		if !seen {
			previous = &GovernorProcess{}
			if self.state.TimeMs == 0 || report.StartMs < self.state.TimeMs {
				// a baseline: everything up to now was counted, or lost, before
				previous = &GovernorProcess{
					P0ByteCounts:      maps.Clone(report.P0ByteCounts),
					P1ByteCount:       report.P1ByteCount,
					CreditByteCount:   report.CreditByteCount,
					UnfundedByteCount: report.UnfundedByteCount,
					FundedByteCount:   report.FundedByteCount,
				}
			}
		}
		// a total that went down is a process that began again: its totals are the new baseline
		delta := func(now int64, before int64) int64 {
			return max(0, now-before)
		}
		for kind, byteCount := range report.P0ByteCounts {
			live.p0ByteCounts[kind] = delta(byteCount, previous.P0ByteCounts[kind])
		}
		live.p1ByteCount = delta(report.P1ByteCount, previous.P1ByteCount)
		live.creditByteCount = delta(report.CreditByteCount, previous.CreditByteCount)
		live.unfundedByteCount = delta(report.UnfundedByteCount, previous.UnfundedByteCount)
		live.fundedByteCount = delta(report.FundedByteCount, previous.FundedByteCount)
		self.state.Processes[processId] = &GovernorProcess{
			LastSeenMs:        nowMs,
			P0ByteCounts:      maps.Clone(report.P0ByteCounts),
			P1ByteCount:       report.P1ByteCount,
			CreditByteCount:   report.CreditByteCount,
			UnfundedByteCount: report.UnfundedByteCount,
			FundedByteCount:   report.FundedByteCount,
		}
		lives = append(lives, live)
	}
	for processId, process := range self.state.Processes {
		if self.settings.ProcessForgetAfter.Milliseconds() < nowMs-process.LastSeenMs {
			delete(self.state.Processes, processId)
		}
	}
	return lives
}

// total split in proportion to weights, each share rounded down, so the shares never pass total. A
// weight at or below zero takes nothing, and all of them so leaves total unsplit.
func splitByWeights(total int64, weights []int64) []int64 {
	shares := make([]int64, len(weights))
	var weightSum float64
	for _, weight := range weights {
		if 0 < weight {
			weightSum += float64(weight)
		}
	}
	if total <= 0 || weightSum == 0 {
		return shares
	}
	var shareSum int64
	for i, weight := range weights {
		if 0 < weight {
			shares[i] = int64(math.Floor(float64(total) * (float64(weight) / weightSum)))
			shareSum += shares[i]
		}
	}
	// floating point may pass total by a byte: take it back from the largest
	for total < shareSum {
		largest := 0
		for i := range shares {
			if shares[largest] < shares[i] {
				largest = i
			}
		}
		taken := min(shareSum-total, shares[largest])
		shares[largest] -= taken
		shareSum -= taken
	}
	return shares
}

// total handed out rank by rank, each rank's part split by the weights at that rank and never more
// than they sum to, as §11.13's order row runs P2. Returns each process's share and what is left.
func splitByRank(total int64, rankWeights func(i int, rank int) int64, count int) ([]int64, int64) {
	shares := make([]int64, count)
	left := max(0, total)
	for rank := 0; rank < sidecar.WriteP2RankCount && 0 < left; rank += 1 {
		weights := make([]int64, count)
		var weightSum int64
		for i := range count {
			weights[i] = max(0, rankWeights(i, rank))
			weightSum += weights[i]
		}
		if weightSum == 0 {
			continue
		}
		rankShares := splitByWeights(min(left, weightSum), weights)
		for i, share := range rankShares {
			shares[i] += share
			left -= share
		}
	}
	return shares, left
}

// One interval: see the file header. measuredByteCount is the busiest drive not under heal's written
// bytes since the last step, which the loop reads from §19.6's counters; reports are the live ones in
// {nvb_<set>}.
func (self *Governor) Step(now time.Time, measuredByteCount int64, reports []*WriteBudgetReport) *WriteBudgetAllowance {
	settings := self.settings
	state := self.state
	nowMs := now.UnixMilli()
	measuredByteCount = max(0, measuredByteCount)
	lives := self.takeReports(nowMs, reports)

	p0KindByteCounts := map[sidecar.WriteP0Kind]int64{}
	var p0ByteCount, p1ByteCount, creditByteCount, unfundedByteCount, fundedByteCount, inFlightByteCount int64
	var fundedDemandByteCount, fundedBacklogByteCount, unfundedDemandByteCount, unfundedBacklogByteCount int64
	var p1QueuedByteCount int64
	for _, live := range lives {
		p1QueuedByteCount += live.report.P1QueuedByteCount
		for kind, byteCount := range live.p0ByteCounts {
			p0KindByteCounts[kind] += byteCount
			p0ByteCount += byteCount
		}
		p1ByteCount += live.p1ByteCount
		creditByteCount += live.creditByteCount
		unfundedByteCount += live.unfundedByteCount
		fundedByteCount += live.fundedByteCount
		inFlightByteCount += live.report.InFlightByteCount
		fundedDemand := sumByteCounts(live.report.FundedDemandByteCounts)
		unfundedDemand := sumByteCounts(live.report.UnfundedDemandByteCounts)
		fundedDemandByteCount += fundedDemand
		unfundedDemandByteCount += unfundedDemand
		// a backlog holds its demand, whatever a report says
		fundedBacklogByteCount += max(fundedDemand, sumByteCounts(live.report.FundedBacklogByteCounts))
		unfundedBacklogByteCount += max(unfundedDemand, sumByteCounts(live.report.UnfundedBacklogByteCounts))
	}

	fundedBacklogByteCount += self.standingFundedByteCount

	// k, over the priced bytes issued to the drives: P0's, P1's immediate part and P2's
	pricedByteCount := p0ByteCount + p1ByteCount + unfundedByteCount + fundedByteCount
	state.CalibrationSamples = append(state.CalibrationSamples, &GovernorCalibrationSample{
		MeasuredByteCount: measuredByteCount,
		PricedByteCount:   pricedByteCount,
	})
	if sampleCount := settings.intervalCount(settings.CalibrationWindow); sampleCount < len(state.CalibrationSamples) {
		state.CalibrationSamples = state.CalibrationSamples[len(state.CalibrationSamples)-sampleCount:]
	}
	var windowMeasured, windowPriced float64
	for _, sample := range state.CalibrationSamples {
		if float64(sample.PricedByteCount) < settings.CalibrationMinShare*settings.intervalRefillByteCount() {
			continue
		}
		windowMeasured += float64(sample.MeasuredByteCount)
		windowPriced += float64(sample.PricedByteCount)
	}
	if 0 < windowPriced {
		state.Calibration = min(max(windowMeasured/windowPriced, settings.CalibrationMin), settings.CalibrationMax)
	}
	k := state.Calibration

	// B, P0's forgiven excess and the pricing error
	refill := settings.intervalRefillByteCount()
	depth := settings.depthByteCount()
	p0Measured := float64(p0ByteCount) * k
	bucket := float64(state.BucketByteCount) + refill - float64(measuredByteCount)
	deficit := max(0, -bucket)
	p0Excess := min(deficit, p0Measured)
	pricingError := int64(math.Round(deficit - p0Excess))
	if 0 < p0Excess && 0 < p0ByteCount {
		excessByteCount := int64(math.Round(p0Excess))
		kinds := slices.Sorted(maps.Keys(p0KindByteCounts))
		weights := []int64{}
		for _, kind := range kinds {
			weights = append(weights, p0KindByteCounts[kind])
		}
		shares := splitByWeights(excessByteCount, weights)
		var shareSum int64
		for i, kind := range kinds {
			state.P0ExcessByteCounts[kind] += shares[i]
			shareSum += shares[i]
		}
		// what rounding left goes to the kind that wrote the most, so no forgiven byte goes uncounted
		if shareSum < excessByteCount {
			largest := 0
			for i := range weights {
				if weights[largest] < weights[i] {
					largest = i
				}
			}
			state.P0ExcessByteCounts[kinds[largest]] += excessByteCount - shareSum
		}
	}
	state.PricingErrorByteCount += pricingError
	bucket = min(max(bucket, 0), float64(depth))
	state.BucketByteCount = int64(math.Floor(bucket))

	// T
	factor := settings.FactorFloor + (1-settings.FactorFloor)*min(1, bucket/(settings.FactorFullShare*float64(depth)))
	inFlight := float64(inFlightByteCount) * k
	total := max(0, min(refill*factor-p0Measured, bucket-inFlight))
	totalByteCount := int64(math.Floor(total / k))

	// W
	wallet := max(0, state.WalletByteCount+creditByteCount-fundedByteCount)
	wallet = min(wallet, fundedBacklogByteCount)
	state.WalletByteCount = wallet

	// A_U and A1
	uncoveredDemandByteCount := max(0, fundedDemandByteCount-wallet)
	uncoveredBacklogByteCount := max(0, fundedBacklogByteCount-wallet)
	var unfundedAllowance int64
	if 0 < unfundedBacklogByteCount+uncoveredBacklogByteCount {
		unfundedAllowance = min(unfundedDemandByteCount+uncoveredDemandByteCount, int64(math.Floor(settings.UnfundedShare*float64(totalByteCount))))
	}
	p1Allowance := totalByteCount - unfundedAllowance

	// A2
	room := bucket - total - inFlight
	fundedAllowance := max(0, min(wallet, int64(math.Floor(room/k))))

	// the copy rate, from the spare A1 left over the last CopySpareWindow
	p1Debit := p1ByteCount + creditByteCount
	if 0 < state.Seq {
		state.CopySamples = append(state.CopySamples, &GovernorCopySample{
			P1AllowanceByteCount: state.LastP1ByteCount,
			TotalByteCount:       state.LastTotalByteCount,
			P1DebitByteCount:     p1Debit,
		})
		if sampleCount := settings.intervalCount(settings.CopySpareWindow); sampleCount < len(state.CopySamples) {
			state.CopySamples = state.CopySamples[len(state.CopySamples)-sampleCount:]
		}
	}
	var spare, windowTotal int64
	for _, sample := range state.CopySamples {
		spare += sample.P1AllowanceByteCount - sample.P1DebitByteCount
		windowTotal += sample.TotalByteCount
	}
	copyOpsPerSecond := settings.CopyOpsPerSecond
	if 0 < windowTotal && settings.CopySpareShare*float64(windowTotal) <= float64(spare) {
		copyOpsPerSecond = settings.CopyOpsPerSecondMax
	}

	// shares
	count := len(lives)
	p1Weights := make([]int64, count)
	allIdle := true
	for i, live := range lives {
		p1Weights[i] = live.report.P1QueuedByteCount + live.p1ByteCount + live.creditByteCount
		if 0 < p1Weights[i] {
			allIdle = false
		}
	}
	if allIdle {
		for i := range p1Weights {
			p1Weights[i] = 1
		}
	}
	p1Shares := splitByWeights(p1Allowance, p1Weights)

	fundedDemandShares, fundedLeft := splitByRank(fundedAllowance, func(i int, rank int) int64 {
		return rankByteCount(lives[i].report.FundedDemandByteCounts, rank)
	}, count)
	fundedBacklogShares, _ := splitByRank(fundedLeft, func(i int, rank int) int64 {
		report := lives[i].report
		return rankByteCount(report.FundedBacklogByteCounts, rank) - rankByteCount(report.FundedDemandByteCounts, rank)
	}, count)

	// funded demand A2 did not meet, which the uncovered part is split by
	unmetWeights := make([]int64, count)
	for i, live := range lives {
		unmetWeights[i] = max(0, sumByteCounts(live.report.FundedDemandByteCounts)-fundedDemandShares[i])
	}
	uncoveredWeights := splitByWeights(uncoveredDemandByteCount, unmetWeights)
	unfundedWeights := make([]int64, count)
	for i, live := range lives {
		unfundedWeights[i] = sumByteCounts(live.report.UnfundedDemandByteCounts) + uncoveredWeights[i]
	}
	unfundedShares := splitByWeights(unfundedAllowance, unfundedWeights)

	copyProcessCount := 0
	shares := map[string]*WriteBudgetShare{}
	for i, live := range lives {
		share := &WriteBudgetShare{
			P1ByteCount:       p1Shares[i],
			UnfundedByteCount: unfundedShares[i],
			FundedByteCount:   fundedDemandShares[i] + fundedBacklogShares[i],
		}
		if 0 < unfundedWeights[i] {
			share.UncoveredByteCount = int64(math.Floor(float64(unfundedShares[i]) * float64(uncoveredWeights[i]) / float64(unfundedWeights[i])))
		}
		shares[live.report.ProcessId] = share
		report := live.report
		if 0 < rankByteCount(report.UnfundedDemandByteCounts, int(sidecar.WriteP2RankCopy))+rankByteCount(report.UnfundedBacklogByteCounts, int(sidecar.WriteP2RankCopy)) {
			copyProcessCount += 1
		}
	}

	state.Seq += 1
	state.TimeMs = nowMs
	state.LastP1ByteCount = p1Allowance
	state.LastTotalByteCount = totalByteCount

	return &WriteBudgetAllowance{
		ClusterId:             self.clusterId,
		Seq:                   state.Seq,
		TimeMs:                nowMs,
		Calibration:           k,
		BucketByteCount:       state.BucketByteCount,
		DepthByteCount:        depth,
		WalletByteCount:       wallet,
		TotalByteCount:        totalByteCount,
		P1ByteCount:           p1Allowance,
		UnfundedByteCount:     unfundedAllowance,
		FundedByteCount:       fundedAllowance,
		MeasuredByteCount:     measuredByteCount,
		P0MeasuredByteCount:   int64(math.Round(p0Measured)),
		PricingErrorByteCount: pricingError,
		P0ExcessByteCounts:    maps.Clone(state.P0ExcessByteCounts),
		CopyOpsPerSecond:      copyOpsPerSecond,
		CopyProcessCount:      copyProcessCount,
		Shares:                shares,

		P1IssuedByteCount:        p1Debit,
		FundedIssuedByteCount:    fundedByteCount,
		UnfundedIssuedByteCount:  unfundedByteCount,
		P1QueuedByteCount:        p1QueuedByteCount,
		FundedBacklogByteCount:   fundedBacklogByteCount,
		UnfundedBacklogByteCount: unfundedBacklogByteCount,
	}
}
