package fault

// FS-116 (§22.8, FI-14; EVSB-M2-05): the governor alone on a fake clock with exact prices (k = 1) and
// no P0. T is 1,000 units an interval, each push 100 units, 63 immediate and 37 deferred, and the
// deferred units come due as one durable funded P2 queue a fixed number of intervals later, as
// evacuation does. The processes are modeled as §11.13 says each class spends, since this is the
// governor's test: evsservice's own tests hold the real process client to the same rules.
//
// FI-14 (a) and (b) are checked as properties of every run: each interval's P1 and unfunded P2 debits
// within the T in force, funded P2 within A2 and W, W within the funded backlog the processes reported,
// every deferred unit paid once, and the drive writes of any 24 h window within its refill, the
// bucket's depth and one interval's pricing error.

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	fs116PushImmediate = 63
	fs116PushDeferred  = 37
	fs116PushPrice     = fs116PushImmediate + fs116PushDeferred
	// intervals a push's deferred work waits before it comes due
	fs116FundedDelay = 12
	// the funded queue's steady backlog, which W is preloaded with: twelve intervals of ten pushes
	fs116Preload = fs116FundedDelay * 10 * fs116PushDeferred
)

// Round numbers: r is 200 units a second, so T is 1,000 an interval at a full bucket and D is 720,000.
func fs116Settings() *evsservice.WriteBudgetSettings {
	settings := evsservice.DefaultWriteBudgetSettings()
	settings.RefillDwpd = 1
	settings.DriveByteCount = 17280000
	return settings
}

// One unit of funded P2 work: a push's deferred units.
type fs116Work struct {
	dueStep   int
	byteCount int64
}

type fs116Process struct {
	id      string
	startMs int64
	// pushes it is asked for each interval; zero for taskworker
	pushesPerInterval int
	taskworker        bool
	share             *evsservice.WriteBudgetShare
	// totals since its start, and its queued P1 as of the last interval
	p1ByteCount       int64
	creditByteCount   int64
	unfundedByteCount int64
	fundedByteCount   int64
	queuedByteCount   int64
}

// One interval: the allowance in force and what was spent under it.
type fs116Interval struct {
	allowance      *evsservice.WriteBudgetAllowance
	pushesWanted   int
	pushesAdmitted int
	// at full price
	p1Debit           int64
	unfundedIssued    int64
	uncoveredIssued   int64
	fundedIssued      int64
	issued            int64
	measured          int64
	reportedBacklog   int64
	pricingErrorBound int64
}

type fs116World struct {
	t        *testing.T
	settings *evsservice.WriteBudgetSettings
	clock    *sidecartest.FakeClock
	governor *evsservice.Governor
	step     int

	processes      []*fs116Process
	processCounter int
	// the durable funded P2 queue, due order, whichever taskworker process owns it
	funded []*fs116Work
	// unfunded work waiting, and what arrives each interval
	unfundedBacklog     int64
	unfundedPerInterval int64
	// measured is issued times 1 + priceError
	priceError float64
	pausedP2   bool
	// the mutant: funded P2's spend comes off the pushers' A1 as well
	mutantFundedFromT bool
	lastFundedSpend   int64

	// issued during the interval running now, and what the drives measured of the last one, at the
	// price error in force when it was issued
	issued          int64
	pendingMeasured int64
	intervals       []*fs116Interval

	totalDeferred      int64
	totalPaidFunded    int64
	totalPaidUncovered int64
}

// A world at a full bucket, W preloaded beside a steady funded queue, with evs asked for seven pushes
// an interval, gkm for three, and one taskworker.
func newFs116World(t *testing.T) *fs116World {
	settings := fs116Settings()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	world := &fs116World{
		t:        t,
		settings: settings,
		clock:    clock,
		governor: evsservice.NewGovernor("meta-1", settings, &evsservice.GovernorState{
			Seq:             1,
			TimeMs:          clock.Now().UnixMilli(),
			BucketByteCount: 720000,
			WalletByteCount: fs116Preload,
			Calibration:     1,
		}),
	}
	for step := 1; step <= fs116FundedDelay; step += 1 {
		for range 10 {
			world.funded = append(world.funded, &fs116Work{dueStep: step, byteCount: fs116PushDeferred})
			world.totalDeferred += fs116PushDeferred
		}
	}
	world.startProcess(7, false)
	world.startProcess(3, false)
	world.startProcess(0, true)
	return world
}

func (self *fs116World) startProcess(pushesPerInterval int, taskworker bool) *fs116Process {
	self.processCounter += 1
	process := &fs116Process{
		id:                fmt.Sprintf("process-%d", self.processCounter),
		startMs:           self.clock.Now().UnixMilli() + 1,
		pushesPerInterval: pushesPerInterval,
		taskworker:        taskworker,
	}
	self.processes = append(self.processes, process)
	return process
}

// Kills a process between an admission and its report, so the governor never hears of what it did
// since its last report, and starts its successor.
func (self *fs116World) kill(process *fs116Process) *fs116Process {
	for i, other := range self.processes {
		if other == process {
			self.processes = append(self.processes[:i], self.processes[i+1:]...)
			break
		}
	}
	return self.startProcess(process.pushesPerInterval, process.taskworker)
}

// {nvb_<set>} lost: the loop starts again with no state, so B and W start at zero.
func (self *fs116World) loseState() {
	self.governor = evsservice.NewGovernor("meta-1", self.settings, nil)
}

func (self *fs116World) report(process *fs116Process) *evsservice.WriteBudgetReport {
	report := &evsservice.WriteBudgetReport{
		ProcessId:         process.id,
		StartMs:           process.startMs,
		TimeMs:            self.clock.Now().UnixMilli(),
		P1ByteCount:       process.p1ByteCount,
		CreditByteCount:   process.creditByteCount,
		UnfundedByteCount: process.unfundedByteCount,
		FundedByteCount:   process.fundedByteCount,
		P1QueuedByteCount: process.queuedByteCount,
	}
	if process.taskworker {
		var demand, backlog int64
		for _, work := range self.funded {
			backlog += work.byteCount
			if work.dueStep <= self.step+1 {
				demand += work.byteCount
			}
		}
		report.FundedDemandByteCounts = fs116Ranks(sidecar.WriteP2RankEvacuation, demand)
		report.FundedBacklogByteCounts = fs116Ranks(sidecar.WriteP2RankEvacuation, backlog)
		report.UnfundedDemandByteCounts = fs116Ranks(sidecar.WriteP2RankGc, self.unfundedBacklog)
		report.UnfundedBacklogByteCounts = fs116Ranks(sidecar.WriteP2RankGc, self.unfundedBacklog)
	}
	return report
}

func fs116Ranks(rank sidecar.WriteP2Rank, byteCount int64) []int64 {
	byteCounts := make([]int64, sidecar.WriteP2RankCount)
	byteCounts[rank] = byteCount
	return byteCounts
}

// One interval: the processes report, the governor steps on what the drives measured of the last
// interval, and the processes spend their shares.
func (self *fs116World) stepOnce() *fs116Interval {
	self.unfundedBacklog += self.unfundedPerInterval
	reports := []*evsservice.WriteBudgetReport{}
	var reportedBacklog int64
	for _, process := range self.processes {
		report := self.report(process)
		reports = append(reports, report)
		for _, byteCount := range report.FundedBacklogByteCounts {
			reportedBacklog += byteCount
		}
	}
	self.clock.Advance(self.settings.Interval)
	allowance := self.governor.Step(self.clock.Now(), self.pendingMeasured, reports)
	self.step += 1
	self.issued = 0

	interval := &fs116Interval{allowance: allowance, reportedBacklog: reportedBacklog}
	empty := &evsservice.WriteBudgetShare{}
	var pusherShareSum int64
	for _, process := range self.processes {
		process.share = allowance.Shares[process.id]
		if process.share == nil {
			process.share = empty
		}
		if !process.taskworker {
			pusherShareSum += process.share.P1ByteCount
		}
	}
	for _, process := range self.processes {
		if process.taskworker {
			continue
		}
		p1Left := process.share.P1ByteCount
		if self.mutantFundedFromT && 0 < pusherShareSum {
			p1Left -= self.lastFundedSpend * process.share.P1ByteCount / pusherShareSum
		}
		admitted := 0
		for admitted < process.pushesPerInterval && fs116PushPrice <= p1Left {
			p1Left -= fs116PushPrice
			admitted += 1
			process.p1ByteCount += fs116PushImmediate
			process.creditByteCount += fs116PushDeferred
			self.issued += fs116PushImmediate
			self.funded = append(self.funded, &fs116Work{dueStep: self.step + fs116FundedDelay, byteCount: fs116PushDeferred})
			self.totalDeferred += fs116PushDeferred
		}
		process.queuedByteCount = int64(process.pushesPerInterval-admitted) * fs116PushPrice
		interval.pushesWanted += process.pushesPerInterval
		interval.pushesAdmitted += admitted
		interval.p1Debit += int64(admitted) * fs116PushPrice
	}
	for _, process := range self.processes {
		if !process.taskworker || self.pausedP2 {
			continue
		}
		fundedLeft := process.share.FundedByteCount
		uncoveredLeft := process.share.UncoveredByteCount
		unfundedLeft := process.share.UnfundedByteCount - process.share.UncoveredByteCount
		for 0 < len(self.funded) && self.funded[0].dueStep <= self.step {
			work := self.funded[0]
			if work.byteCount <= fundedLeft {
				fundedLeft -= work.byteCount
				process.fundedByteCount += work.byteCount
				interval.fundedIssued += work.byteCount
				self.totalPaidFunded += work.byteCount
			} else if work.byteCount <= uncoveredLeft {
				uncoveredLeft -= work.byteCount
				process.unfundedByteCount += work.byteCount
				interval.unfundedIssued += work.byteCount
				interval.uncoveredIssued += work.byteCount
				self.totalPaidUncovered += work.byteCount
			} else {
				break
			}
			self.issued += work.byteCount
			self.funded = self.funded[1:]
		}
		paid := min(self.unfundedBacklog, unfundedLeft)
		self.unfundedBacklog -= paid
		process.unfundedByteCount += paid
		interval.unfundedIssued += paid
		self.issued += paid
	}
	self.lastFundedSpend = interval.fundedIssued
	interval.issued = self.issued
	interval.measured = int64(math.Round(float64(self.issued) * (1 + self.priceError)))
	interval.pricingErrorBound = int64(math.Ceil(float64(self.issued)*math.Abs(self.priceError))) + 1
	self.pendingMeasured = interval.measured
	self.intervals = append(self.intervals, interval)
	self.checkConservation(interval)
	return interval
}

func (self *fs116World) run(count int) []*fs116Interval {
	intervals := []*fs116Interval{}
	for range count {
		intervals = append(intervals, self.stepOnce())
	}
	return intervals
}

// FI-14 (b) for one interval: P1 and unfunded P2 within T, funded P2 within A2 and W, and W within the
// funded backlog the processes reported.
func (self *fs116World) checkConservation(interval *fs116Interval) {
	self.t.Helper()
	allowance := interval.allowance
	if allowance.TotalByteCount < interval.p1Debit+interval.unfundedIssued {
		self.t.Errorf("step %d: P1 %d and unfunded %d past T %d", self.step, interval.p1Debit, interval.unfundedIssued, allowance.TotalByteCount)
	}
	if allowance.P1ByteCount+allowance.UnfundedByteCount != allowance.TotalByteCount {
		self.t.Errorf("step %d: A1 %d and A_U %d are not T %d", self.step, allowance.P1ByteCount, allowance.UnfundedByteCount, allowance.TotalByteCount)
	}
	if allowance.FundedByteCount < interval.fundedIssued || allowance.WalletByteCount < interval.fundedIssued {
		self.t.Errorf("step %d: funded %d past A2 %d or W %d", self.step, interval.fundedIssued, allowance.FundedByteCount, allowance.WalletByteCount)
	}
	if interval.reportedBacklog < allowance.WalletByteCount {
		self.t.Errorf("step %d: W %d past the funded backlog %d", self.step, allowance.WalletByteCount, interval.reportedBacklog)
	}
	if float64(allowance.UnfundedByteCount) > self.settings.UnfundedShare*float64(allowance.TotalByteCount) {
		self.t.Errorf("step %d: A_U %d past its share of T %d", self.step, allowance.UnfundedByteCount, allowance.TotalByteCount)
	}
}

// FI-14 (a) with no P0: the drive writes of every window of windowCount intervals within its refill,
// the bucket's depth and the largest one interval's pricing error.
func (self *fs116World) checkWindows(windowCount int) {
	self.t.Helper()
	windowCount = min(windowCount, len(self.intervals))
	refill := 1000.0
	var errorBound int64
	for _, interval := range self.intervals {
		errorBound = max(errorBound, interval.pricingErrorBound)
	}
	var windowSum int64
	for i, interval := range self.intervals {
		windowSum += interval.measured
		if windowCount <= i {
			windowSum -= self.intervals[i-windowCount].measured
		}
		if windowCount-1 <= i {
			bound := int64(refill*float64(windowCount)) + 720000 + errorBound
			if bound < windowSum {
				self.t.Errorf("the window ending at interval %d wrote %d, past %d", i, windowSum, bound)
				return
			}
		}
	}
}

// Every push's deferred units paid once, from W or as unfunded P2, once the queue is drained.
func (self *fs116World) checkPaidOnce() {
	self.t.Helper()
	var unpaid int64
	for _, work := range self.funded {
		unpaid += work.byteCount
	}
	if self.totalPaidFunded+self.totalPaidUncovered+unpaid != self.totalDeferred {
		self.t.Errorf("deferred %d: paid %d from W, %d unfunded, %d unpaid", self.totalDeferred, self.totalPaidFunded, self.totalPaidUncovered, unpaid)
	}
}

// Stops the pushes and runs until the funded queue is empty.
func (self *fs116World) drain(limit int) {
	self.t.Helper()
	for _, process := range self.processes {
		process.pushesPerInterval = 0
	}
	for range limit {
		if len(self.funded) == 0 && self.unfundedBacklog == 0 {
			return
		}
		self.stepOnce()
	}
	self.t.Errorf("%d funded units still unpaid after %d intervals", len(self.funded), limit)
}

// FS-116's steady clause, which the mutant must fail: after warm-up, every push asked for is admitted
// each interval, none queued, and W back at its preload.
func fs116CheckSteady(intervals []*fs116Interval) error {
	for i, interval := range intervals {
		if interval.pushesAdmitted != 10 || interval.pushesWanted != 10 {
			return fmt.Errorf("interval %d admitted %d of %d pushes", i, interval.pushesAdmitted, interval.pushesWanted)
		}
		if interval.allowance.WalletByteCount != fs116Preload {
			return fmt.Errorf("interval %d: W %d, preload %d", i, interval.allowance.WalletByteCount, fs116Preload)
		}
	}
	return nil
}

func TestFs116SteadyLoadAdmitsTenPushesAnInterval(t *testing.T) {
	world := newFs116World(t)
	world.run(2 * fs116FundedDelay)
	steady := world.run(100)
	if err := fs116CheckSteady(steady); err != nil {
		t.Error(err)
	}
	for _, interval := range steady {
		if interval.allowance.TotalByteCount != 1000 || interval.allowance.Calibration != 1 {
			t.Fatalf("T %d, k %v", interval.allowance.TotalByteCount, interval.allowance.Calibration)
		}
	}
	for _, process := range world.processes {
		if process.queuedByteCount != 0 {
			t.Errorf("%s queues %d", process.id, process.queuedByteCount)
		}
	}
	world.drain(100)
	world.checkPaidOnce()
	world.checkWindows(len(world.intervals))
}

// P2 paused 100 intervals, then resumed: ten pushes still admitted each interval while W drains, the
// bucket above its midpoint, and W back at its preload once the backlog is spent.
func TestFs116PausedP2DrainsTheWalletWithoutStallingPushes(t *testing.T) {
	world := newFs116World(t)
	world.run(2 * fs116FundedDelay)
	world.pausedP2 = true
	paused := world.run(100)
	world.pausedP2 = false
	resumed := world.run(50)
	for i, interval := range append(paused, resumed...) {
		if interval.pushesAdmitted != 10 {
			t.Errorf("interval %d admitted %d", i, interval.pushesAdmitted)
		}
		if interval.allowance.BucketByteCount < 360000 {
			t.Errorf("interval %d: B %d below its midpoint", i, interval.allowance.BucketByteCount)
		}
	}
	// the last paused interval's allowance carries the credit of the 99 before it, a report lagging
	// its interval by one
	if want := int64(fs116Preload + 99*10*fs116PushDeferred); paused[len(paused)-1].allowance.WalletByteCount != want {
		t.Errorf("W %d after the pause, want %d", paused[len(paused)-1].allowance.WalletByteCount, want)
	}
	if resumed[len(resumed)-1].allowance.WalletByteCount != fs116Preload {
		t.Errorf("W %d after the resume", resumed[len(resumed)-1].allowance.WalletByteCount)
	}
	world.drain(100)
	world.checkPaidOnce()
	world.checkWindows(len(world.intervals))
}

// Each evs, gkm and taskworker process killed between an admission and its report, then restarted:
// every push's deferred units are paid once, from W or as unfunded P2, and the credit the governor
// never heard of is paid from A_U once W runs out.
func TestFs116KilledProcessesPayEachPushsDeferredWorkOnce(t *testing.T) {
	world := newFs116World(t)
	world.run(2 * fs116FundedDelay)
	for _, index := range []int{0, 1, 2} {
		killed := world.processes[0]
		for _, process := range world.processes {
			if process.id == fmt.Sprintf("process-%d", index+1) {
				killed = process
			}
		}
		world.kill(killed)
		world.run(20)
	}
	world.drain(400)
	world.checkPaidOnce()
	if world.totalPaidUncovered == 0 {
		t.Error("no credit was lost, so the kills tested nothing")
	}
	// the next step sees the backlog empty, and no credit outlives the work it was for
	if last := world.stepOnce().allowance; last.WalletByteCount != 0 {
		t.Errorf("W %d with nothing left to pay for", last.WalletByteCount)
	}
	world.checkWindows(len(world.intervals))
}

// {nvb_<set>} lost: W restarts at zero, and P1 admits T less only what A_U issues while the funded
// work W no longer covers runs unfunded, until admissions refill W.
func TestFs116LostStateRestartsTheWalletAtZero(t *testing.T) {
	world := newFs116World(t)
	world.run(2 * fs116FundedDelay)
	world.loseState()
	after := world.run(1500)
	if after[0].allowance.WalletByteCount != 0 {
		t.Errorf("W %d once the state was lost", after[0].allowance.WalletByteCount)
	}
	pusherCount := int64(2)
	for i, interval := range after {
		allowance := interval.allowance
		// P1 takes all of A1, but for one push a process, and A_U is all that comes off T
		if interval.pushesAdmitted < interval.pushesWanted && interval.p1Debit+pusherCount*fs116PushPrice <= allowance.P1ByteCount {
			t.Errorf("interval %d: P1 took %d of A1 %d", i, interval.p1Debit, allowance.P1ByteCount)
		}
		if allowance.UnfundedByteCount < interval.unfundedIssued {
			t.Errorf("interval %d: unfunded %d past A_U %d", i, interval.unfundedIssued, allowance.UnfundedByteCount)
		}
	}
	if world.totalPaidUncovered == 0 {
		t.Error("nothing ran uncovered")
	}
	// the bucket refilled: back to ten pushes. W stays short of the backlog by the lost credit that has
	// not yet run uncovered, which the drain pays from A_U
	for i, interval := range world.run(20) {
		if interval.pushesAdmitted != 10 {
			t.Errorf("recovered interval %d admitted %d", i, interval.pushesAdmitted)
		}
	}
	world.drain(400)
	world.checkPaidOnce()
	world.checkWindows(len(world.intervals))
}

// 200 units of unfunded backlog an interval: only A_U's issue, never past 40% of T, comes off A1.
func TestFs116UnfundedBacklogTakesOnlyItsShare(t *testing.T) {
	world := newFs116World(t)
	world.run(2 * fs116FundedDelay)
	world.unfundedPerInterval = 200
	world.run(2)
	for i, interval := range world.run(100) {
		allowance := interval.allowance
		// whole pushes leave each pusher's remainder of its share unspent
		if allowance.UnfundedByteCount != 200 || allowance.P1ByteCount != 800 || interval.p1Debit+2*fs116PushPrice <= allowance.P1ByteCount {
			t.Errorf("interval %d: A_U %d, A1 %d, P1 %d", i, allowance.UnfundedByteCount, allowance.P1ByteCount, interval.p1Debit)
		}
	}
	world.unfundedPerInterval = 5000
	for i, interval := range world.run(20) {
		if allowance := interval.allowance; allowance.UnfundedByteCount != 400 {
			t.Errorf("interval %d of a deep backlog: A_U %d of T %d", i, allowance.UnfundedByteCount, allowance.TotalByteCount)
		}
	}
	world.unfundedPerInterval = 0
	world.drain(400)
	world.checkPaidOnce()
	world.checkWindows(len(world.intervals))
}

// Prices 10% low for 10 min, from a bucket a storm left empty: k converges, the bucket's floor absorbs
// at most one interval's error, and every 24 h window holds the budget.
func TestFs116LowPricesConvergeAndHoldTheBound(t *testing.T) {
	world := newFs116World(t)
	world.run(2 * fs116FundedDelay)
	world.loseState()
	world.priceError = 0.1
	low := world.run(120)
	if k := low[len(low)-1].allowance.Calibration; math.Abs(k-1.1) > 0.005 {
		t.Errorf("k %v after 10 min 10%% low", k)
	}
	// a step's error is of the interval before it
	for i := 1; i < len(low); i += 1 {
		if low[i-1].pricingErrorBound < low[i].allowance.PricingErrorByteCount {
			t.Errorf("interval %d: error %d past one interval's %d", i-1, low[i].allowance.PricingErrorByteCount, low[i-1].pricingErrorBound)
		}
	}
	world.priceError = 0
	recovered := world.run(17280)
	if k := recovered[len(recovered)-1].allowance.Calibration; k != 1 {
		t.Errorf("k %v with exact prices again", k)
	}
	world.drain(400)
	world.checkPaidOnce()
	world.checkWindows(17280)
}

// The mutant that debits funded P2 from T as well admits ~7.3 pushes an interval, 1,000 / 137, and
// fails the steady clause.
func TestFs116MutantDebitingFundedP2FromTFails(t *testing.T) {
	world := newFs116World(t)
	world.mutantFundedFromT = true
	world.run(10 * fs116FundedDelay)
	intervals := world.run(200)
	if fs116CheckSteady(intervals) == nil {
		t.Error("the mutant passed")
	}
	admitted := 0
	for _, interval := range intervals {
		admitted += interval.pushesAdmitted
	}
	average := float64(admitted) / float64(len(intervals))
	t.Logf("the mutant admits %.2f pushes an interval", average)
	if average < 7.0 || 7.6 < average {
		t.Errorf("the mutant admits %.2f pushes an interval", average)
	}
}

// After a storm empties the bucket, with pushes taking all of T, T reaches half of r in ~18 minutes and
// 90% after ~78 (§11.13's gates row), the ramp holding back half of D.
func TestFs116AllowanceRampsBackAfterAStorm(t *testing.T) {
	settings := fs116Settings()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	governor := evsservice.NewGovernor("meta-1", settings, &evsservice.GovernorState{
		Seq:         1,
		TimeMs:      clock.Now().UnixMilli(),
		Calibration: 1,
	})
	start := clock.Now()
	evs := &evsservice.WriteBudgetReport{ProcessId: "evs-1", StartMs: start.UnixMilli()}
	var measured int64
	var halfAt, ninetyAt time.Duration
	for halfAt == 0 || ninetyAt == 0 {
		clock.Advance(settings.Interval)
		evs.P1QueuedByteCount = 1000000
		allowance := governor.Step(clock.Now(), measured, []*evsservice.WriteBudgetReport{evs})
		// pushes take all of it, small ones, so whole pushes lose nothing
		measured = allowance.P1ByteCount
		evs.P1ByteCount += measured
		elapsed := clock.Now().Sub(start)
		if halfAt == 0 && 500 <= allowance.TotalByteCount {
			halfAt = elapsed
		}
		if ninetyAt == 0 && 900 <= allowance.TotalByteCount {
			ninetyAt = elapsed
		}
		if 3*time.Hour < elapsed {
			t.Fatal("no ramp in three hours")
		}
	}
	t.Logf("half of r after %s, 90%% after %s", halfAt, ninetyAt)
	if halfAt < 16*time.Minute || 20*time.Minute < halfAt {
		t.Errorf("half of r after %s", halfAt)
	}
	if ninetyAt < 75*time.Minute || 81*time.Minute < ninetyAt {
		t.Errorf("90%% of r after %s", ninetyAt)
	}
}
