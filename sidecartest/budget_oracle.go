// FI-14's oracle (§22.8, §11.13; D-EVS-21, D-EVS-33; EVSB-M2-16): the write budget's accounts recomputed from raw
// events, one interval at a time, from §11.13's accounts row and nothing else. It shares no code with
// evsservice.Governor, which this package cannot import, so a schedule that steps both and compares them holds the
// governor to the design's text and not to itself.
//
// A schedule gives each interval's raw events: what the busiest drive not under heal wrote, the priced bytes each
// class issued, and the levels the processes hold. The oracle answers the accounts those events leave for the next
// interval (B, W, T, A1, A_U, A2, P0's forgiven excess by kind) and §19.8's gauges, and it checks the events
// themselves against the accounts that were in force when they happened:
//
//	FI-14 (a)  over every window (24 h), the drive's writes less P0's forgiven excess stay within the window's
//	           refill, the bucket's depth and one interval's pricing error (WindowSlackByteCount)
//	FI-14 (b)  P1's debits and unfunded P2 stay within T, funded P2 within A2 and W, W within the funded backlog,
//	           and every deferred byte is paid once: from W, as unfunded P2, or lapsed with work that never runs
//	FI-14 (c)  no P0 write waited or was refused
//	FI-14 (d)  a network was refused only while none with more queued priced bytes per weight was served
//
// Units are the design's: B, D, the refill and the forgiven excess are drive bytes, and every account a process
// spends is priced bytes, k drive bytes each. Two computations of one figure may differ by rounding, so Compare
// allows ToleranceByteCount.
//
// A loop that resumes after a gap steps once on its saved state with everything the drives wrote meanwhile
// (§11.13's fallback row), so a gap's refill past one interval is not credited: Step models that, which errs low.
//
// Not safe for concurrent use: one schedule owns an oracle.

package sidecartest

import (
	"fmt"
	"math"
	"slices"
	"time"
)

// §11.13's figures for one metadata cluster.
type BudgetOracleSettings struct {
	// One step: 5 s.
	Interval time.Duration
	// r, drive bytes a second: 0.768 DWPD of the drive, or §22.8's 0.8.
	RefillBytesPerSecond float64
	// D, drive bytes: an hour of r.
	DepthByteCount int64
	// T's factor of B: FactorFloor (0.2) at an empty bucket, rising linearly to 1 at FactorFullShare (a half) of D.
	FactorFloor     float64
	FactorFullShare float64
	// The most of T unfunded P2 takes while its backlog lasts: 0.4.
	UnfundedShare float64
	// k: measured over priced bytes of the last CalibrationWindow (10 min), over the intervals that priced at
	// least CalibrationMinShare of their refill, held within [CalibrationMin, CalibrationMax], InitialCalibration
	// until one counts.
	CalibrationWindow   time.Duration
	CalibrationMinShare float64
	CalibrationMin      float64
	CalibrationMax      float64
	InitialCalibration  float64
	// FI-14 (a)'s window, 24 h, and what the classes other than P0 may write in it past its refill and the
	// bucket's depth: one interval's issue times the pricing error, at most one interval's refill.
	Window               time.Duration
	WindowSlackByteCount int64
	// §19.8's P0 ratio: P0's measured bytes over this long against its refill, 1 h. Past 1 it pages.
	RefillRatioWindow time.Duration
	// What rounding may leave between two computations of one figure, bytes.
	ToleranceByteCount int64
}

// §11.13's defaults on the PM9A3: 1.92 TB at 0.768 DWPD.
func DefaultBudgetOracleSettings() *BudgetOracleSettings {
	refill := 0.768 * 1920 * 1000 * 1000 * 1000 / (24 * time.Hour).Seconds()
	return &BudgetOracleSettings{
		Interval:             5 * time.Second,
		RefillBytesPerSecond: refill,
		DepthByteCount:       int64(refill * time.Hour.Seconds()),
		FactorFloor:          0.2,
		FactorFullShare:      0.5,
		UnfundedShare:        0.4,
		CalibrationWindow:    10 * time.Minute,
		CalibrationMinShare:  0.1,
		CalibrationMin:       0.25,
		CalibrationMax:       4,
		InitialCalibration:   1,
		Window:               24 * time.Hour,
		WindowSlackByteCount: int64(refill * 5),
		RefillRatioWindow:    time.Hour,
		ToleranceByteCount:   2,
	}
}

// One refusal a process gave a network's P1 write, for FI-14 (d).
type BudgetOracleRefusal struct {
	// The refused network's queued priced bytes per weight.
	RefusedPerWeight float64
	// The same for each network the process served in that interval.
	ServedPerWeights []float64
}

// One interval's raw events on one metadata cluster, summed over its processes.
type BudgetOracleEvents struct {
	// What the busiest drive not under heal wrote, drive bytes.
	MeasuredByteCount int64
	// Priced bytes issued, by class: P0 by kind; P1's immediate part and the deferred part it moved into W; funded
	// P2 from W; unfunded P2, UncoveredByteCount of it being funded work W no longer covered.
	P0ByteCounts       map[string]int64
	P1ByteCount        int64
	CreditByteCount    int64
	FundedByteCount    int64
	UnfundedByteCount  int64
	UncoveredByteCount int64
	// Deferred work that will never run: an aborted push's, a deduplicated retry's, a record evacuation dropped.
	LapsedByteCount int64
	// Levels as the interval ended, priced bytes.
	InFlightByteCount        int64
	P1QueuedByteCount        int64
	FundedDemandByteCount    int64
	FundedBacklogByteCount   int64
	UnfundedDemandByteCount  int64
	UnfundedBacklogByteCount int64
	// P0 writes that waited in a queue, and that were refused. FI-14 (c) allows neither.
	P0WaitedCount  int
	P0RefusedCount int
	// P1 refusals, for FI-14 (d).
	Refusals []*BudgetOracleRefusal
}

// The accounts for one interval, and §19.8's gauges as they stand.
type BudgetOracleAccounts struct {
	// k.
	Calibration float64
	// B, drive bytes.
	BucketByteCount int64
	// W, T, A1, A_U and A2, priced bytes.
	WalletByteCount   int64
	TotalByteCount    int64
	P1ByteCount       int64
	UnfundedByteCount int64
	FundedByteCount   int64
	// P0's forgiven excess by kind: this step's, and since the oracle began, drive bytes.
	P0ExcessStepByteCounts map[string]int64
	P0ExcessByteCounts     map[string]int64
	// The bytes past what B held that P0 did not account for this step: the other classes' pricing error.
	PricingErrorByteCount int64
	// P0's measured bytes over RefillRatioWindow against that window's refill.
	P0RefillRatio float64
	// The liabilities, priced bytes.
	P1QueuedByteCount        int64
	FundedBacklogByteCount   int64
	UnfundedBacklogByteCount int64
}

// One step the oracle keeps for its windows: its own figures, and running totals through it, so a window's sum is
// two reads however long the window.
type budgetOracleSample struct {
	measured     int64
	forgiven     int64
	pricingError int64
	p0Measured   float64
	priced       int64

	measuredTotal     int64
	forgivenTotal     int64
	pricingErrorTotal int64
	p0MeasuredTotal   float64
}

// The running totals through the step before the last stepCount steps.
func (self *BudgetOracle) totalsBefore(stepCount int) *budgetOracleSample {
	if len(self.samples) <= stepCount {
		return &budgetOracleSample{}
	}
	return self.samples[len(self.samples)-stepCount-1]
}

// See the file header.
type BudgetOracle struct {
	settings *BudgetOracleSettings
	// B as a fraction survives the floor of each step's published figure
	bucket      float64
	wallet      int64
	calibration float64
	// the accounts in force for the interval whose events come next, nil before the first step and after a lost
	// state
	inForce *BudgetOracleAccounts
	// every step since the oracle began, for FI-14 (a) and the P0 ratio; calibrationStart is where k's window may
	// begin, which a lost state moves
	samples          []*budgetOracleSample
	calibrationStart int
	excessByteCounts map[string]int64
	// (b)'s paid-once ledger, priced bytes
	deferredByteCount  int64
	paidFundedCount    int64
	paidUncoveredCount int64
	lapsedByteCount    int64
	stepCount          int
	// the next step is the first after a lost state
	baseline bool
	// the copy ledger: each ref, the moves made in the interval running and in each one closed
	copyRefs               map[string]*budgetOracleCopyRef
	copyIntervalMoveCount  int64
	copyIntervalMoveCounts []int64
	violations             []string
}

// An oracle starting at bucket B and wallet W, as a loop resuming that saved state does. settings nil takes the
// defaults.
func NewBudgetOracle(settings *BudgetOracleSettings, bucketByteCount int64, walletByteCount int64) *BudgetOracle {
	if settings == nil {
		settings = DefaultBudgetOracleSettings()
	}
	return &BudgetOracle{
		settings:         settings,
		bucket:           float64(bucketByteCount),
		wallet:           walletByteCount,
		calibration:      settings.InitialCalibration,
		excessByteCounts: map[string]int64{},
	}
}

// {nvb_<set>} lost: B and W restart at zero, k at its initial value, and the accounts in force are gone, so the
// next interval's events are held to nothing but (a) and (c) (§11.13's fallback row). The first step after it takes
// the running processes' totals as its baseline: what they issued in that interval was counted, or lost, with the
// state, so it reaches the new accounts only through what the drive measured.
func (self *BudgetOracle) LoseState() {
	self.bucket = 0
	self.wallet = 0
	self.calibration = self.settings.InitialCalibration
	self.calibrationStart = len(self.samples)
	self.inForce = nil
	self.baseline = true
}

// The processes ran an interval with no fresh allowance, on §11.13's fallback row: their events are counted, and
// held only to (c), since the accounts they were issued under are no longer in force. The drive bytes they caused
// reach B at the next Step, in its measured bytes.
func (self *BudgetOracle) Fallback(events *BudgetOracleEvents) {
	self.inForce = nil
	self.checkP0(events)
	self.count(events)
}

// One interval's refill, drive bytes.
func (self *BudgetOracle) intervalRefill() float64 {
	return self.settings.RefillBytesPerSecond * self.settings.Interval.Seconds()
}

// How many steps a span holds, at least one.
func (self *BudgetOracle) stepsIn(span time.Duration) int {
	return max(1, int(span/self.settings.Interval))
}

// Records a violation.
func (self *BudgetOracle) violate(format string, args ...any) {
	self.violations = append(self.violations, fmt.Sprintf("step %d: ", self.stepCount)+fmt.Sprintf(format, args...))
}

// FI-14 (c).
func (self *BudgetOracle) checkP0(events *BudgetOracleEvents) {
	if 0 < events.P0WaitedCount || 0 < events.P0RefusedCount {
		self.violate("FI-14 (c): %d P0 writes waited and %d were refused", events.P0WaitedCount, events.P0RefusedCount)
	}
}

// The paid-once ledger's part of an interval's events.
func (self *BudgetOracle) count(events *BudgetOracleEvents) {
	self.deferredByteCount += events.CreditByteCount
	self.paidFundedCount += events.FundedByteCount
	self.paidUncoveredCount += events.UncoveredByteCount
	self.lapsedByteCount += events.LapsedByteCount
}

// One interval: checks its events against the accounts in force, then computes the accounts they leave. See the
// file header.
func (self *BudgetOracle) Step(events *BudgetOracleEvents) *BudgetOracleAccounts {
	settings := self.settings
	self.stepCount += 1
	tolerance := settings.ToleranceByteCount

	// the events, against what was in force when they happened
	self.checkP0(events)
	if inForce := self.inForce; inForce != nil {
		if inForce.TotalByteCount+tolerance < events.P1ByteCount+events.CreditByteCount+events.UnfundedByteCount {
			self.violate("FI-14 (b): P1 debited %d and unfunded P2 issued %d, past T %d",
				events.P1ByteCount+events.CreditByteCount, events.UnfundedByteCount, inForce.TotalByteCount)
		}
		if inForce.FundedByteCount+tolerance < events.FundedByteCount || inForce.WalletByteCount+tolerance < events.FundedByteCount {
			self.violate("FI-14 (b): funded P2 issued %d, past A2 %d or W %d", events.FundedByteCount, inForce.FundedByteCount, inForce.WalletByteCount)
		}
	}
	for _, refusal := range events.Refusals {
		for _, served := range refusal.ServedPerWeights {
			if refusal.RefusedPerWeight < served {
				self.violate("FI-14 (d): a network with %.1f queued per weight was refused while one with %.1f was served", refusal.RefusedPerWeight, served)
			}
		}
	}
	self.count(events)
	if self.baseline {
		// the levels stand, and the issued totals are a baseline
		self.baseline = false
		baseline := *events
		baseline.P0ByteCounts = nil
		baseline.P1ByteCount, baseline.CreditByteCount, baseline.FundedByteCount, baseline.UnfundedByteCount = 0, 0, 0, 0
		events = &baseline
	}

	// k, over the priced bytes issued to the drives
	var p0ByteCount int64
	for _, byteCount := range events.P0ByteCounts {
		p0ByteCount += byteCount
	}
	priced := p0ByteCount + events.P1ByteCount + events.UnfundedByteCount + events.FundedByteCount
	sample := &budgetOracleSample{measured: max(0, events.MeasuredByteCount), priced: priced}
	self.samples = append(self.samples, sample)
	refill := self.intervalRefill()
	windowStart := max(self.calibrationStart, len(self.samples)-self.stepsIn(settings.CalibrationWindow))
	var windowMeasured, windowPriced float64
	for _, earlier := range self.samples[windowStart:] {
		if float64(earlier.priced) < settings.CalibrationMinShare*refill {
			continue
		}
		windowMeasured += float64(earlier.measured)
		windowPriced += float64(earlier.priced)
	}
	if 0 < windowPriced {
		self.calibration = min(max(windowMeasured/windowPriced, settings.CalibrationMin), settings.CalibrationMax)
	}
	k := self.calibration

	// B gains an interval of r and loses the measured bytes, floored at zero and capped at D; what it did not hold
	// is P0's forgiven excess, up to P0's own bytes, and the rest the other classes' pricing error
	p0Measured := float64(p0ByteCount) * k
	sample.p0Measured = p0Measured
	bucket := self.bucket + refill - float64(sample.measured)
	deficit := math.Max(0, -bucket)
	forgiven := int64(math.Round(math.Min(deficit, p0Measured)))
	sample.forgiven = forgiven
	sample.pricingError = int64(math.Round(deficit - math.Min(deficit, p0Measured)))
	before := self.totalsBefore(1)
	sample.measuredTotal = before.measuredTotal + sample.measured
	sample.forgivenTotal = before.forgivenTotal + sample.forgiven
	sample.pricingErrorTotal = before.pricingErrorTotal + sample.pricingError
	sample.p0MeasuredTotal = before.p0MeasuredTotal + sample.p0Measured
	stepExcess := map[string]int64{}
	if 0 < forgiven && 0 < p0ByteCount {
		// by kind in proportion to P0's bytes, what rounding leaves going to the kind that wrote the most
		kinds := []string{}
		for kind := range events.P0ByteCounts {
			kinds = append(kinds, kind)
		}
		slices.Sort(kinds)
		var given int64
		largest := kinds[0]
		for _, kind := range kinds {
			part := int64(math.Floor(float64(forgiven) * float64(events.P0ByteCounts[kind]) / float64(p0ByteCount)))
			stepExcess[kind] = part
			given += part
			if events.P0ByteCounts[largest] < events.P0ByteCounts[kind] {
				largest = kind
			}
		}
		stepExcess[largest] += forgiven - given
		for kind, part := range stepExcess {
			self.excessByteCounts[kind] += part
		}
	}
	bucket = math.Min(math.Max(bucket, 0), float64(settings.DepthByteCount))
	self.bucket = math.Floor(bucket)

	// T: the refill at its factor of B less P0's own, never more than B holds less what is in flight
	factor := settings.FactorFloor + (1-settings.FactorFloor)*math.Min(1, bucket/(settings.FactorFullShare*float64(settings.DepthByteCount)))
	inFlight := float64(events.InFlightByteCount) * k
	total := math.Max(0, math.Min(refill*factor-p0Measured, bucket-inFlight))
	totalByteCount := int64(math.Floor(total / k))

	// W gains the credit moved, loses the funded P2 issued, and is clamped to the funded backlog
	fundedBacklog := max(events.FundedBacklogByteCount, events.FundedDemandByteCount)
	unfundedBacklog := max(events.UnfundedBacklogByteCount, events.UnfundedDemandByteCount)
	wallet := max(0, self.wallet+events.CreditByteCount-events.FundedByteCount)
	wallet = min(wallet, fundedBacklog)
	self.wallet = wallet

	// A_U while unfunded backlog lasts, funded work W no longer covers counting as unfunded; A1 the rest
	uncoveredDemand := max(0, events.FundedDemandByteCount-wallet)
	uncoveredBacklog := max(0, fundedBacklog-wallet)
	var unfunded int64
	if 0 < unfundedBacklog+uncoveredBacklog {
		unfunded = min(events.UnfundedDemandByteCount+uncoveredDemand, int64(math.Floor(settings.UnfundedShare*float64(totalByteCount))))
	}

	// A2: what B holds beyond T and what is in flight, never T itself
	funded := max(0, min(wallet, int64(math.Floor((bucket-total-inFlight)/k))))

	accounts := &BudgetOracleAccounts{
		Calibration:              k,
		BucketByteCount:          int64(self.bucket),
		WalletByteCount:          wallet,
		TotalByteCount:           totalByteCount,
		P1ByteCount:              totalByteCount - unfunded,
		UnfundedByteCount:        unfunded,
		FundedByteCount:          funded,
		P0ExcessStepByteCounts:   stepExcess,
		P0ExcessByteCounts:       map[string]int64{},
		PricingErrorByteCount:    sample.pricingError,
		P0RefillRatio:            self.p0RefillRatio(),
		P1QueuedByteCount:        events.P1QueuedByteCount,
		FundedBacklogByteCount:   fundedBacklog,
		UnfundedBacklogByteCount: unfundedBacklog,
	}
	for kind, byteCount := range self.excessByteCounts {
		accounts.P0ExcessByteCounts[kind] = byteCount
	}
	self.inForce = accounts
	self.checkWindow()
	if self.bucket < 0 {
		self.violate("B fell to %v, below zero", self.bucket)
	}
	return accounts
}

// P0's measured bytes over the last RefillRatioWindow against that many intervals of refill (§19.8).
func (self *BudgetOracle) p0RefillRatio() float64 {
	stepCount := min(len(self.samples), self.stepsIn(self.settings.RefillRatioWindow))
	newest, before := self.samples[len(self.samples)-1], self.totalsBefore(stepCount)
	return (newest.p0MeasuredTotal - before.p0MeasuredTotal) / (self.intervalRefill() * float64(stepCount))
}

// FI-14 (a) for the window ending at the newest step: the drive's writes less P0's forgiven excess within the
// window's refill, the bucket's depth and one interval's pricing error. The bucket's floor makes every byte past it
// either P0's forgiven excess or pricing error, so this fails exactly when the classes other than P0 wrote past an
// empty bucket by more than that slack.
func (self *BudgetOracle) checkWindow() {
	stepCount := min(len(self.samples), self.stepsIn(self.settings.Window))
	newest, before := self.samples[len(self.samples)-1], self.totalsBefore(stepCount)
	measured := newest.measuredTotal - before.measuredTotal
	forgiven := newest.forgivenTotal - before.forgivenTotal
	pricingError := newest.pricingErrorTotal - before.pricingErrorTotal
	bound := int64(math.Ceil(self.intervalRefill()*float64(stepCount))) + self.settings.DepthByteCount + self.settings.WindowSlackByteCount + self.settings.ToleranceByteCount
	if bound < measured-forgiven {
		self.violate("FI-14 (a): the window of %d steps wrote %d less %d forgiven, past %d, with %d of pricing error", stepCount, measured, forgiven, bound, pricingError)
	}
}

// The drive's writes over the last span as drive-writes a day of a drive of driveByteCount: the run's report of its
// windows past 0.8 and 1 DWPD.
func (self *BudgetOracle) Dwpd(span time.Duration, driveByteCount int64) float64 {
	stepCount := min(len(self.samples), self.stepsIn(span))
	if stepCount == 0 || driveByteCount <= 0 {
		return 0
	}
	measured := self.samples[len(self.samples)-1].measuredTotal - self.totalsBefore(stepCount).measuredTotal
	days := float64(stepCount) * self.settings.Interval.Seconds() / (24 * time.Hour).Seconds()
	return float64(measured) / float64(driveByteCount) / days
}

// Holds observed figures to the accounts the newest step computed: B, W, T, A1, A_U, A2 and this step's forgiven
// excess by kind within the tolerance, and k and the P0 ratio closely. A nil field of observed's excess compares
// as none forgiven.
func (self *BudgetOracle) Compare(observed *BudgetOracleAccounts) error {
	expected := self.inForce
	if expected == nil {
		return fmt.Errorf("step %d: no accounts to compare", self.stepCount)
	}
	tolerance := self.settings.ToleranceByteCount
	if observed.BucketByteCount < 0 {
		return fmt.Errorf("step %d: B is %d, below zero", self.stepCount, observed.BucketByteCount)
	}
	figures := []struct {
		name     string
		observed int64
		expected int64
	}{
		{"B", observed.BucketByteCount, expected.BucketByteCount},
		{"W", observed.WalletByteCount, expected.WalletByteCount},
		{"T", observed.TotalByteCount, expected.TotalByteCount},
		{"A1", observed.P1ByteCount, expected.P1ByteCount},
		{"A_U", observed.UnfundedByteCount, expected.UnfundedByteCount},
		{"A2", observed.FundedByteCount, expected.FundedByteCount},
		{"queued P1", observed.P1QueuedByteCount, expected.P1QueuedByteCount},
		{"the funded backlog", observed.FundedBacklogByteCount, expected.FundedBacklogByteCount},
		{"the unfunded backlog", observed.UnfundedBacklogByteCount, expected.UnfundedBacklogByteCount},
	}
	for _, figure := range figures {
		if tolerance < figure.observed-figure.expected || tolerance < figure.expected-figure.observed {
			return fmt.Errorf("step %d: %s is %d, and the oracle's %d", self.stepCount, figure.name, figure.observed, figure.expected)
		}
	}
	if 1e-9 < math.Abs(observed.Calibration-expected.Calibration) {
		return fmt.Errorf("step %d: k is %v, and the oracle's %v", self.stepCount, observed.Calibration, expected.Calibration)
	}
	kinds := map[string]bool{}
	for kind := range observed.P0ExcessStepByteCounts {
		kinds[kind] = true
	}
	for kind := range expected.P0ExcessStepByteCounts {
		kinds[kind] = true
	}
	for kind := range kinds {
		difference := observed.P0ExcessStepByteCounts[kind] - expected.P0ExcessStepByteCounts[kind]
		if tolerance < difference || tolerance < -difference {
			return fmt.Errorf("step %d: P0's forgiven excess of kind %s is %d, and the oracle's %d", self.stepCount, kind,
				observed.P0ExcessStepByteCounts[kind], expected.P0ExcessStepByteCounts[kind])
		}
	}
	return nil
}

// FI-14 (b)'s last clause, once a schedule says what deferred work is still outstanding: every deferred byte
// admitted is paid once, from W or as unfunded P2, lapsed with work that never runs, or still owed.
func (self *BudgetOracle) CheckPaidOnce(outstandingByteCount int64) error {
	paid := self.paidFundedCount + self.paidUncoveredCount + self.lapsedByteCount + outstandingByteCount
	if paid != self.deferredByteCount {
		return fmt.Errorf("FI-14 (b): %d deferred bytes admitted; %d paid from W, %d as unfunded P2, %d lapsed and %d outstanding",
			self.deferredByteCount, self.paidFundedCount, self.paidUncoveredCount, self.lapsedByteCount, outstandingByteCount)
	}
	return nil
}

// P0's forgiven excess by kind since the oracle began, drive bytes.
func (self *BudgetOracle) ForgivenByteCounts() map[string]int64 {
	forgiven := map[string]int64{}
	for kind, byteCount := range self.excessByteCounts {
		forgiven[kind] = byteCount
	}
	return forgiven
}

// Every violation the oracle found, in step order.
func (self *BudgetOracle) Violations() []string {
	return slices.Clone(self.violations)
}

// The first violation as an error, nil for none.
func (self *BudgetOracle) Err() error {
	if len(self.violations) == 0 {
		return nil
	}
	return fmt.Errorf("%s (and %d more)", self.violations[0], len(self.violations)-1)
}

// §11.6's path-epoch copies as §19.8 reports them, recounted from their events (FS-118): a cut-over adds a source
// to its ref and gives the newest map's moves to make; moves done come off them, and at none left every source of
// the ref drops; a batched epoch waits while two sources stand.
type budgetOracleCopyRef struct {
	sourceCount int
	moveCount   int64
	deferred    bool
}

// §19.8's copy figures.
type BudgetOracleCopyGauges struct {
	// The moves left on the cluster: the copy liability.
	LiabilityMoveCount int64
	// The liability over the last hour's moves a second. Infinite while there is a liability and no move was
	// made, zero with no liability.
	DrainSeconds float64
	// Drain past 24 h: §19.8 warns.
	Warn bool
	// Refs with a batched epoch waiting.
	DeferredCount int
	// Refs holding one, two and three sources, at indexes 1 to 3.
	SourceCounts [4]int
}

// The copy ledger's ref, made at its first event.
func (self *BudgetOracle) copyRef(ref string) *budgetOracleCopyRef {
	if self.copyRefs == nil {
		self.copyRefs = map[string]*budgetOracleCopyRef{}
	}
	copyRef, ok := self.copyRefs[ref]
	if !ok {
		copyRef = &budgetOracleCopyRef{}
		self.copyRefs[ref] = copyRef
	}
	return copyRef
}

// A PATH_EPOCH committed on ref: one more source, and moveCount moves for the newest map, which replace what an
// older map had left. A fourth source is a violation: §11.6 refuses it.
func (self *BudgetOracle) CopyCutOver(ref string, moveCount int64) {
	copyRef := self.copyRef(ref)
	copyRef.sourceCount += 1
	copyRef.moveCount = moveCount
	copyRef.deferred = false
	if 3 < copyRef.sourceCount {
		self.violate("a ref reached %d sources, past §11.6's three", copyRef.sourceCount)
	}
}

// moveCount moves made on ref. At none left, its sources drop.
func (self *BudgetOracle) CopyMoved(ref string, moveCount int64) {
	copyRef := self.copyRef(ref)
	if copyRef.moveCount < moveCount {
		self.violate("a copy made %d moves with %d left", moveCount, copyRef.moveCount)
		moveCount = copyRef.moveCount
	}
	copyRef.moveCount -= moveCount
	self.copyIntervalMoveCount += moveCount
	if copyRef.moveCount == 0 {
		copyRef.sourceCount = 0
	}
}

// A batched epoch due on ref waits, which §11.6 allows only while two sources stand.
func (self *BudgetOracle) CopyDeferred(ref string) {
	copyRef := self.copyRef(ref)
	if copyRef.sourceCount < 2 {
		self.violate("a batched epoch waited on a ref holding %d sources", copyRef.sourceCount)
	}
	copyRef.deferred = true
}

// Closes one interval of the copy ledger, for the drain rate.
func (self *BudgetOracle) CopyEndInterval() {
	self.copyIntervalMoveCounts = append(self.copyIntervalMoveCounts, self.copyIntervalMoveCount)
	self.copyIntervalMoveCount = 0
}

// §19.8's copy figures as the ledger stands.
func (self *BudgetOracle) CopyGauges() *BudgetOracleCopyGauges {
	gauges := &BudgetOracleCopyGauges{}
	for _, copyRef := range self.copyRefs {
		gauges.LiabilityMoveCount += copyRef.moveCount
		if copyRef.deferred {
			gauges.DeferredCount += 1
		}
		gauges.SourceCounts[min(copyRef.sourceCount, 3)] += 1
	}
	stepCount := min(len(self.copyIntervalMoveCounts), self.stepsIn(self.settings.RefillRatioWindow))
	var moved int64
	for _, moveCount := range self.copyIntervalMoveCounts[len(self.copyIntervalMoveCounts)-stepCount:] {
		moved += moveCount
	}
	switch {
	case gauges.LiabilityMoveCount == 0:
	case moved == 0:
		gauges.DrainSeconds = math.Inf(1)
	default:
		gauges.DrainSeconds = float64(gauges.LiabilityMoveCount) / (float64(moved) / (float64(stepCount) * self.settings.Interval.Seconds()))
	}
	gauges.Warn = (24 * time.Hour).Seconds() < gauges.DrainSeconds
	return gauges
}
