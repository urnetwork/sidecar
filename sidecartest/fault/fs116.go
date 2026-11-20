// FS-116 (§22.8, FI-14; EVSB-M2-05): the governor alone on a fake clock with exact prices (k = 1) and no P0. T is
// 1,000 units an interval, each push 100 units, 63 immediate and 37 deferred, and the deferred units come due as one
// durable funded P2 queue a fixed number of intervals later, as evacuation does. The processes are modeled as §11.13
// says each class spends, since this is the governor's test: evsservice's own tests hold the real process client to the
// same rules.
//
// FI-14 (a) and (b) are checked as properties of every run: each interval's P1 and unfunded P2 debits within the T in
// force, funded P2 within A2 and W, W within the funded backlog the processes reported, every deferred unit paid once,
// and the drive writes of any 24 h window within its refill, the bucket's depth and one interval's pricing error. The
// world records each breach it finds, and FI-14's check fails a schedule's step that left one.
//
// The steady run is the row's registered case (Fs116Case; QD-1084), a schedule a step each for the warm-up, the steady
// intervals and the drain, and each of the row's other runs a clause registered beside it (clauses.go): P2 paused and
// resumed, processes killed between an admission and their report, {nvb_<set>} lost, an unfunded backlog, prices 10%
// low, and the ramp after a storm. Each runs under every rule §22.8 gives the row, FI-14 checked after every step as
// this world reads it: FI-14's oracle is EVSB-M2-16's and unbound (fault.FI(14) fails closed), so the check is the
// row's own (FI-14/fs116). The world runs on a fake clock of its own and touches no store and no barrier, so the
// explorer's seeds each take the one order there is. The mutant that debits funded P2 from T stays a plain test
// (fs116_test.go), since it must fail.

package fault

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The world's figures: round numbers, so the governor's arithmetic reads as the row's.
type Fs116WorldSettings struct {
	// The governor's: r 200 units a second, a refill of 1 DWPD of a 17,280,000-unit drive, so T is 1,000 an interval
	// at a full bucket and D is 720,000.
	Budget *evsservice.WriteBudgetSettings
	// T at a full bucket: r an interval, 1,000.
	IntervalRefillByteCount int64
	// The bucket's depth D, where the world starts: 720,000.
	DepthByteCount int64
	// What a push spends at once: 63.
	PushImmediateByteCount int64
	// What a push defers to the funded P2 queue: 37.
	PushDeferredByteCount int64
	// Intervals a push's deferred work waits before it comes due: 12.
	FundedDelayCount int
	// The pushes each pushing process is asked for an interval: evs 7 and gkm 3, ten in all.
	ProcessPushCounts []int
}

func DefaultFs116WorldSettings() *Fs116WorldSettings {
	budget := evsservice.DefaultWriteBudgetSettings()
	budget.RefillDwpd = 1
	budget.DriveByteCount = 17280000
	return &Fs116WorldSettings{
		Budget:                  budget,
		IntervalRefillByteCount: 1000,
		DepthByteCount:          720000,
		PushImmediateByteCount:  63,
		PushDeferredByteCount:   37,
		FundedDelayCount:        12,
		ProcessPushCounts:       []int{7, 3},
	}
}

// What a push costs in all.
func (self *Fs116WorldSettings) pushPrice() int64 {
	return self.PushImmediateByteCount + self.PushDeferredByteCount
}

// The pushes asked for each interval in all: ten.
func (self *Fs116WorldSettings) steadyPushCount() int {
	count := 0
	for _, pushCount := range self.ProcessPushCounts {
		count += pushCount
	}
	return count
}

// The funded queue's steady backlog, which W is preloaded with: a delay's worth of the steady pushes' deferred units.
func (self *Fs116WorldSettings) preloadByteCount() int64 {
	return int64(self.FundedDelayCount) * int64(self.steadyPushCount()) * self.PushDeferredByteCount
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
	settings *Fs116WorldSettings
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

	// every breach a check found, in the order found
	breaches []error
}

// A world at a full bucket, W preloaded beside a steady funded queue, with evs asked for seven pushes
// an interval, gkm for three, and one taskworker.
func newFs116WorldOf(settings *Fs116WorldSettings) *fs116World {
	if settings == nil {
		settings = DefaultFs116WorldSettings()
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	world := &fs116World{
		settings: settings,
		clock:    clock,
		governor: evsservice.NewGovernor("meta-1", settings.Budget, &evsservice.GovernorState{
			Seq:             1,
			TimeMs:          clock.Now().UnixMilli(),
			BucketByteCount: settings.DepthByteCount,
			WalletByteCount: settings.preloadByteCount(),
			Calibration:     1,
		}),
	}
	for step := 1; step <= settings.FundedDelayCount; step += 1 {
		for range settings.steadyPushCount() {
			world.funded = append(world.funded, &fs116Work{dueStep: step, byteCount: settings.PushDeferredByteCount})
			world.totalDeferred += settings.PushDeferredByteCount
		}
	}
	for _, pushCount := range settings.ProcessPushCounts {
		world.startProcess(pushCount, false)
	}
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
	self.governor = evsservice.NewGovernor("meta-1", self.settings.Budget, nil)
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
	self.clock.Advance(self.settings.Budget.Interval)
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
		price := self.settings.pushPrice()
		for admitted < process.pushesPerInterval && price <= p1Left {
			p1Left -= price
			admitted += 1
			process.p1ByteCount += self.settings.PushImmediateByteCount
			process.creditByteCount += self.settings.PushDeferredByteCount
			self.issued += self.settings.PushImmediateByteCount
			self.funded = append(self.funded, &fs116Work{dueStep: self.step + self.settings.FundedDelayCount, byteCount: self.settings.PushDeferredByteCount})
			self.totalDeferred += self.settings.PushDeferredByteCount
		}
		process.queuedByteCount = int64(process.pushesPerInterval-admitted) * price
		interval.pushesWanted += process.pushesPerInterval
		interval.pushesAdmitted += admitted
		interval.p1Debit += int64(admitted) * price
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

// Records a breach a check found.
func (self *fs116World) breach(format string, args ...any) {
	self.breaches = append(self.breaches, fmt.Errorf(format, args...))
}

// Every breach the checks found, or nil.
func (self *fs116World) err() error {
	return errors.Join(self.breaches...)
}

// FI-14 (b) for one interval: P1 and unfunded P2 within T, funded P2 within A2 and W, and W within the
// funded backlog the processes reported.
func (self *fs116World) checkConservation(interval *fs116Interval) {
	allowance := interval.allowance
	if allowance.TotalByteCount < interval.p1Debit+interval.unfundedIssued {
		self.breach("step %d: P1 %d and unfunded %d past T %d", self.step, interval.p1Debit, interval.unfundedIssued, allowance.TotalByteCount)
	}
	if allowance.P1ByteCount+allowance.UnfundedByteCount != allowance.TotalByteCount {
		self.breach("step %d: A1 %d and A_U %d are not T %d", self.step, allowance.P1ByteCount, allowance.UnfundedByteCount, allowance.TotalByteCount)
	}
	if allowance.FundedByteCount < interval.fundedIssued || allowance.WalletByteCount < interval.fundedIssued {
		self.breach("step %d: funded %d past A2 %d or W %d", self.step, interval.fundedIssued, allowance.FundedByteCount, allowance.WalletByteCount)
	}
	if interval.reportedBacklog < allowance.WalletByteCount {
		self.breach("step %d: W %d past the funded backlog %d", self.step, allowance.WalletByteCount, interval.reportedBacklog)
	}
	if float64(allowance.UnfundedByteCount) > self.settings.Budget.UnfundedShare*float64(allowance.TotalByteCount) {
		self.breach("step %d: A_U %d past its share of T %d", self.step, allowance.UnfundedByteCount, allowance.TotalByteCount)
	}
}

// FI-14 (a) with no P0: the drive writes of every window of windowCount intervals within its refill,
// the bucket's depth and the largest one interval's pricing error.
func (self *fs116World) checkWindows(windowCount int) {
	if err := self.windowsErr(windowCount); err != nil {
		self.breach("%v", err)
	}
}

// checkWindows' reading, nil where every window holds.
func (self *fs116World) windowsErr(windowCount int) error {
	windowCount = min(windowCount, len(self.intervals))
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
			bound := self.settings.IntervalRefillByteCount*int64(windowCount) + self.settings.DepthByteCount + errorBound
			if bound < windowSum {
				return fmt.Errorf("the window ending at interval %d wrote %d, past %d", i, windowSum, bound)
			}
		}
	}
	return nil
}

// Every push's deferred units paid once, from W or as unfunded P2, the queue's unpaid among them, which once
// the queue is drained is none.
func (self *fs116World) checkPaidOnce() {
	if err := self.paidOnceErr(); err != nil {
		self.breach("%v", err)
	}
}

// checkPaidOnce's reading, nil where every deferred unit is paid once or queued.
func (self *fs116World) paidOnceErr() error {
	var unpaid int64
	for _, work := range self.funded {
		unpaid += work.byteCount
	}
	if self.totalPaidFunded+self.totalPaidUncovered+unpaid != self.totalDeferred {
		return fmt.Errorf("deferred %d: paid %d from W, %d unfunded, %d unpaid", self.totalDeferred, self.totalPaidFunded, self.totalPaidUncovered, unpaid)
	}
	return nil
}

// Stops the pushes and runs until the funded queue is empty.
func (self *fs116World) drain(limit int) {
	for _, process := range self.processes {
		process.pushesPerInterval = 0
	}
	for range limit {
		if len(self.funded) == 0 && self.unfundedBacklog == 0 {
			return
		}
		self.stepOnce()
	}
	self.breach("%d funded units still unpaid after %d intervals", len(self.funded), limit)
}

// FS-116's steady clause, which the mutant must fail: after warm-up, every push asked for is admitted
// each interval, none queued, and W back at its preload.
func fs116CheckSteady(settings *Fs116WorldSettings, intervals []*fs116Interval) error {
	steadyPushCount := settings.steadyPushCount()
	for i, interval := range intervals {
		if interval.pushesAdmitted != steadyPushCount || interval.pushesWanted != steadyPushCount {
			return fmt.Errorf("interval %d admitted %d of %d pushes", i, interval.pushesAdmitted, interval.pushesWanted)
		}
		if interval.allowance.WalletByteCount != settings.preloadByteCount() {
			return fmt.Errorf("interval %d: W %d, preload %d", i, interval.allowance.WalletByteCount, settings.preloadByteCount())
		}
	}
	return nil
}

// The steady run, FS-116's registered case: after the warm-up, ten pushes an interval admitted, none queued, T a
// full 1,000 at k = 1 and W back at its preload; then the pushes stop and the funded queue drains, every deferred unit
// paid once. FI-14 (a) and (b), as the world reads them, are checked after every step.
var Fs116Case = Register("FS-116", "", []Tier{TierT2}, fs116SteadyLoad(nil))

// The steady run's builder, mutate applied to each run's world before its warm-up where not nil.
func fs116SteadyLoad(mutate func(world *fs116World)) Builder {
	return func(net *Net) *Schedule {
		var world *fs116World
		return &Schedule{
			Steps: []*Step{
				{Actor: "governor", Action: func(ctx context.Context, net *Net) error {
					world = newFs116WorldOf(nil)
					if mutate != nil {
						mutate(world)
					}
					world.run(2 * world.settings.FundedDelayCount)
					return nil
				}},
				{Actor: "governor", Action: func(ctx context.Context, net *Net) error {
					steady := world.run(100)
					if err := fs116CheckSteady(world.settings, steady); err != nil {
						return err
					}
					for i, interval := range steady {
						if interval.allowance.TotalByteCount != world.settings.IntervalRefillByteCount || interval.allowance.Calibration != 1 {
							return fmt.Errorf("steady interval %d: T %d, k %v", i, interval.allowance.TotalByteCount, interval.allowance.Calibration)
						}
					}
					for _, process := range world.processes {
						if process.queuedByteCount != 0 {
							return fmt.Errorf("%s queues %d", process.id, process.queuedByteCount)
						}
					}
					return nil
				}},
				{Actor: "governor", Action: func(ctx context.Context, net *Net) error {
					world.drain(100)
					if len(world.funded) != 0 {
						return fmt.Errorf("%d funded units unpaid after the drain", len(world.funded))
					}
					return nil
				}},
			},
			Check: []Invariant{fs116Check(&world)},
		}
	}
}

// FI-14's check as the world reads it, after every step: every breach the world's checks found, every deferred unit
// paid once or queued, and every window of the run's intervals within its refill.
func fs116Check(world **fs116World) Invariant {
	return NewInvariant("FI-14/fs116", func(ctx context.Context, oracle *Oracle) error {
		if *world == nil {
			return nil
		}
		return errors.Join((*world).err(), (*world).paidOnceErr(), (*world).windowsErr(len((*world).intervals)))
	})
}

// A clause's schedule on a fresh world warmed up a delay's worth past its preload: a step for the warm-up, then a step
// for each phase, each phase's findings failing its step.
func fs116Clause(phases ...func(world *fs116World) error) *Schedule {
	var world *fs116World
	steps := []*Step{
		{Actor: "governor", Action: func(ctx context.Context, net *Net) error {
			world = newFs116WorldOf(nil)
			world.run(2 * world.settings.FundedDelayCount)
			return nil
		}},
	}
	for _, phase := range phases {
		steps = append(steps, &Step{Actor: "governor", Action: func(ctx context.Context, net *Net) error {
			return phase(world)
		}})
	}
	return &Schedule{Steps: steps, Check: []Invariant{fs116Check(&world)}}
}

// P2 paused 100 intervals, then resumed: ten pushes still admitted each interval while W drains, the bucket above its
// midpoint, and W back at its preload once the backlog is spent.
func Fs116PausedP2DrainsTheWalletWithoutStallingPushes(net *Net) *Schedule {
	var paused, resumed []*fs116Interval
	return fs116Clause(
		func(world *fs116World) error {
			world.pausedP2 = true
			paused = world.run(100)
			world.pausedP2 = false
			resumed = world.run(50)
			found := []error{}
			for i, interval := range append(slices.Clone(paused), resumed...) {
				if interval.pushesAdmitted != world.settings.steadyPushCount() {
					found = append(found, fmt.Errorf("interval %d admitted %d", i, interval.pushesAdmitted))
				}
				if interval.allowance.BucketByteCount < world.settings.DepthByteCount/2 {
					found = append(found, fmt.Errorf("interval %d: B %d below its midpoint", i, interval.allowance.BucketByteCount))
				}
			}
			// the last paused interval's allowance carries the credit of the 99 before it, a report lagging its
			// interval by one
			want := world.settings.preloadByteCount() + 99*int64(world.settings.steadyPushCount())*world.settings.PushDeferredByteCount
			if got := paused[len(paused)-1].allowance.WalletByteCount; got != want {
				found = append(found, fmt.Errorf("W %d after the pause, want %d", got, want))
			}
			if got := resumed[len(resumed)-1].allowance.WalletByteCount; got != world.settings.preloadByteCount() {
				found = append(found, fmt.Errorf("W %d after the resume", got))
			}
			return errors.Join(found...)
		},
		func(world *fs116World) error {
			world.drain(100)
			return nil
		},
	)
}

// Each evs, gkm and taskworker process killed between an admission and its report, then restarted: every push's
// deferred units are paid once, from W or as unfunded P2, and the credit the governor never heard of is paid from A_U
// once W runs out.
func Fs116KilledProcessesPayDeferredWorkOnce(net *Net) *Schedule {
	return fs116Clause(
		func(world *fs116World) error {
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
			return nil
		},
		func(world *fs116World) error {
			world.drain(400)
			if world.totalPaidUncovered == 0 {
				return errors.New("no credit was lost, so the kills tested nothing")
			}
			// the next step sees the backlog empty, and no credit outlives the work it was for
			if last := world.stepOnce().allowance; last.WalletByteCount != 0 {
				return fmt.Errorf("W %d with nothing left to pay for", last.WalletByteCount)
			}
			return nil
		},
	)
}

// {nvb_<set>} lost: W restarts at zero, and P1 admits T less only what A_U issues while the funded work W no longer
// covers runs unfunded, until admissions refill W.
func Fs116LostStateRestartsTheWalletAtZero(net *Net) *Schedule {
	return fs116Clause(
		func(world *fs116World) error {
			world.loseState()
			after := world.run(1500)
			found := []error{}
			if after[0].allowance.WalletByteCount != 0 {
				found = append(found, fmt.Errorf("W %d once the state was lost", after[0].allowance.WalletByteCount))
			}
			pusherCount := int64(len(world.settings.ProcessPushCounts))
			for i, interval := range after {
				allowance := interval.allowance
				// P1 takes all of A1, but for one push a process, and A_U is all that comes off T
				if interval.pushesAdmitted < interval.pushesWanted && interval.p1Debit+pusherCount*world.settings.pushPrice() <= allowance.P1ByteCount {
					found = append(found, fmt.Errorf("interval %d: P1 took %d of A1 %d", i, interval.p1Debit, allowance.P1ByteCount))
				}
				if allowance.UnfundedByteCount < interval.unfundedIssued {
					found = append(found, fmt.Errorf("interval %d: unfunded %d past A_U %d", i, interval.unfundedIssued, allowance.UnfundedByteCount))
				}
			}
			if world.totalPaidUncovered == 0 {
				found = append(found, errors.New("nothing ran uncovered"))
			}
			return errors.Join(found...)
		},
		// the bucket refilled: back to ten pushes. W stays short of the backlog by the lost credit that has not yet
		// run uncovered, which the drain pays from A_U
		func(world *fs116World) error {
			for i, interval := range world.run(20) {
				if interval.pushesAdmitted != world.settings.steadyPushCount() {
					return fmt.Errorf("recovered interval %d admitted %d", i, interval.pushesAdmitted)
				}
			}
			return nil
		},
		func(world *fs116World) error {
			world.drain(400)
			return nil
		},
	)
}

// 200 units of unfunded backlog an interval: only A_U's issue, never past 40% of T, comes off A1.
func Fs116UnfundedBacklogTakesOnlyItsShare(net *Net) *Schedule {
	return fs116Clause(
		func(world *fs116World) error {
			world.unfundedPerInterval = 200
			world.run(2)
			pusherCount := int64(len(world.settings.ProcessPushCounts))
			for i, interval := range world.run(100) {
				allowance := interval.allowance
				// whole pushes leave each pusher's remainder of its share unspent
				if allowance.UnfundedByteCount != 200 || allowance.P1ByteCount != 800 || interval.p1Debit+pusherCount*world.settings.pushPrice() <= allowance.P1ByteCount {
					return fmt.Errorf("interval %d: A_U %d, A1 %d, P1 %d", i, allowance.UnfundedByteCount, allowance.P1ByteCount, interval.p1Debit)
				}
			}
			return nil
		},
		func(world *fs116World) error {
			world.unfundedPerInterval = 5000
			for i, interval := range world.run(20) {
				if allowance := interval.allowance; allowance.UnfundedByteCount != 400 {
					return fmt.Errorf("interval %d of a deep backlog: A_U %d of T %d", i, allowance.UnfundedByteCount, allowance.TotalByteCount)
				}
			}
			return nil
		},
		func(world *fs116World) error {
			world.unfundedPerInterval = 0
			world.drain(400)
			return nil
		},
	)
}

// Prices 10% low for 10 min, from a bucket a storm left empty: k converges, the bucket's floor absorbs at most one
// interval's error, and every 24 h window holds the budget, which FI-14's check reads after every step.
func Fs116LowPricesConvergeAndHoldTheBound(net *Net) *Schedule {
	return fs116Clause(
		func(world *fs116World) error {
			world.loseState()
			world.priceError = 0.1
			low := world.run(120)
			if k := low[len(low)-1].allowance.Calibration; math.Abs(k-1.1) > 0.005 {
				return fmt.Errorf("k %v after 10 min 10%% low", k)
			}
			// a step's error is of the interval before it
			for i := 1; i < len(low); i += 1 {
				if low[i-1].pricingErrorBound < low[i].allowance.PricingErrorByteCount {
					return fmt.Errorf("interval %d: error %d past one interval's %d", i-1, low[i].allowance.PricingErrorByteCount, low[i-1].pricingErrorBound)
				}
			}
			return nil
		},
		// a day at exact prices again
		func(world *fs116World) error {
			world.priceError = 0
			recovered := world.run(17280)
			if k := recovered[len(recovered)-1].allowance.Calibration; k != 1 {
				return fmt.Errorf("k %v with exact prices again", k)
			}
			return nil
		},
		func(world *fs116World) error {
			world.drain(400)
			return nil
		},
	)
}

// After a storm empties the bucket, with pushes taking all of T, T reaches half of r in ~18 minutes and 90% after ~78
// (§11.13's gates row), the ramp holding back half of D. The governor alone, from an empty bucket, with one evs process
// whose queue always holds more than T.
func Fs116AllowanceRampsBackAfterAStorm(net *Net) *Schedule {
	settings := DefaultFs116WorldSettings()
	steps := []*Step{
		{Actor: "governor", Action: func(ctx context.Context, net *Net) error {
			clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
			governor := evsservice.NewGovernor("meta-1", settings.Budget, &evsservice.GovernorState{
				Seq:         1,
				TimeMs:      clock.Now().UnixMilli(),
				Calibration: 1,
			})
			start := clock.Now()
			evs := &evsservice.WriteBudgetReport{ProcessId: "evs-1", StartMs: start.UnixMilli()}
			var measured int64
			var halfAt, ninetyAt time.Duration
			for halfAt == 0 || ninetyAt == 0 {
				clock.Advance(settings.Budget.Interval)
				evs.P1QueuedByteCount = 1000 * settings.IntervalRefillByteCount
				allowance := governor.Step(clock.Now(), measured, []*evsservice.WriteBudgetReport{evs})
				// pushes take all of it, small ones, so whole pushes lose nothing
				measured = allowance.P1ByteCount
				evs.P1ByteCount += measured
				elapsed := clock.Now().Sub(start)
				if halfAt == 0 && settings.IntervalRefillByteCount/2 <= allowance.TotalByteCount {
					halfAt = elapsed
				}
				if ninetyAt == 0 && settings.IntervalRefillByteCount*9/10 <= allowance.TotalByteCount {
					ninetyAt = elapsed
				}
				if 3*time.Hour < elapsed {
					return errors.New("no ramp in three hours")
				}
			}
			if halfAt < 16*time.Minute || 20*time.Minute < halfAt {
				return fmt.Errorf("half of r after %s", halfAt)
			}
			if ninetyAt < 75*time.Minute || 81*time.Minute < ninetyAt {
				return fmt.Errorf("90%% of r after %s", ninetyAt)
			}
			return nil
		}},
	}
	return &Schedule{Steps: steps}
}
