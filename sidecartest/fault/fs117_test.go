package fault

// FS-117 (§22.8, FI-14; owner decisions 186 and 190; EVSB-M2-16) on T2: P0 alone past the refill for 24 h of fake
// counters on one metadata set, then 24 h after it, then again with the governor killed for 10 min and again with
// {nvb_<set>} lost mid-storm. This is the budget's own part of the row. Its gkm legs, each gate's close-to-reopen
// time and the mislabeled rotations on the real gkm engine, are KEYS-M2-30's (sidecartest/fs_keys_budget_test.go).
//
// The world is FS-116's, with P0 and an oracle: the real evsservice.Governor stepped every 5 s of a fake clock on
// what a modeled drive measured, beside processes modeled as §11.13 says each class spends, at exact prices (k =
// 1). r is 200 units a second, 0.768 DWPD of a 22.5M-unit drive, so T is 1,000 an interval at a full bucket and D
// is 720,000. A push is 100 units, 63 now and 37 deferred, and its deferred units come due as evacuation's funded
// work 25 h on. The storm is every P0 kind together at twice the refill, with a Pro network's pushes and 2x year
// one's mix still asked for beside it, and two rotations whose claims state REMOVE with no shrink behind them
// arriving at gkm as P1.
//
// sidecartest.BudgetOracle recomputes every account from each interval's raw events, sharing no code with the
// governor, and is compared with what the governor published at every step: B, W, T, A1, A_U, A2, k, P0's forgiven
// excess by kind and the P0 ratio that pages. It holds FI-14 (a) to (d) on the events themselves. Three mutants, of
// the governor's T, of P0's issue and of the bucket's floor, each fail it.

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	budgetPushImmediate = 63
	budgetPushDeferred  = 37
	budgetPushPrice     = budgetPushImmediate + budgetPushDeferred
	// one interval's refill and the bucket's depth, in the world's units
	budgetIntervalRefill = 1000
	budgetDepth          = 720000
	// the refill a day, which a drive's size is set from: 200 units a second
	budgetRefillPerDay = 17280000
	// 25 h of 5 s intervals: when a push's deferred work comes due
	budgetEvacuationDelay = 25 * 720
	budgetStepsPerHour    = 720
	// a push's fold comes due a minute after it
	budgetFoldDelay = 12
)

// The world's budget settings at a refill of refillDwpd: the drive sized so r stays 200 units a second.
func budgetWorldSettings(refillDwpd float64) *evsservice.WriteBudgetSettings {
	settings := evsservice.DefaultWriteBudgetSettings()
	settings.RefillDwpd = refillDwpd
	settings.DriveByteCount = int64(budgetRefillPerDay / refillDwpd)
	return settings
}

// The oracle's settings, written from §11.13's figures and not read from the governor's.
func budgetOracleSettings() *sidecartest.BudgetOracleSettings {
	return &sidecartest.BudgetOracleSettings{
		Interval:             5 * time.Second,
		RefillBytesPerSecond: 200,
		DepthByteCount:       budgetDepth,
		FactorFloor:          0.2,
		FactorFullShare:      0.5,
		UnfundedShare:        0.4,
		CalibrationWindow:    10 * time.Minute,
		CalibrationMinShare:  0.1,
		CalibrationMin:       0.25,
		CalibrationMax:       4,
		InitialCalibration:   1,
		Window:               24 * time.Hour,
		WindowSlackByteCount: budgetIntervalRefill,
		RefillRatioWindow:    time.Hour,
		ToleranceByteCount:   2,
	}
}

// A process as the governor sees it: its totals since its start.
type budgetProcess struct {
	id                string
	startMs           int64
	p0ByteCounts      map[sidecar.WriteP0Kind]int64
	p1ByteCount       int64
	creditByteCount   int64
	unfundedByteCount int64
	fundedByteCount   int64
	queuedByteCount   int64
}

// One interval's deferred work, due together: the batches one interval's pushes wrote.
type budgetWork struct {
	createdStep int
	dueStep     int
	byteCount   int64
}

// What one interval did, for a schedule's clauses.
type budgetInterval struct {
	// the allowance in force, nil while the governor is down
	allowance *evsservice.WriteBudgetAllowance
	// P0's arrivals and what issued of them, priced
	p0Arrived int64
	p0Issued  int64
	// pushes asked for and admitted, and P1 admitted in all, at full price
	pushesWanted   int
	pushesAdmitted int
	p1Debit        int64
	fundedIssued   int64
	unfundedIssued int64
	measured       int64
	// the oldest batch still on the cluster
	oldestBatchAge time.Duration
	// §19.8's P0 ratio, as the loop computes it from the governor's figures
	p0RefillRatio float64
}

// See the file header.
type budgetWorld struct {
	t        *testing.T
	settings *evsservice.WriteBudgetSettings
	clock    *sidecartest.FakeClock
	governor *evsservice.Governor
	oracle   *sidecartest.BudgetOracle
	step     int

	evs        *budgetProcess
	gkm        *budgetProcess
	api        *budgetProcess
	taskworker *budgetProcess

	// the workload, an interval
	pushesWanted int
	// P0's arrivals by kind, priced
	p0Arrivals map[sidecar.WriteP0Kind]int64
	// the mislabeled rotations' P1 arrivals at gkm, priced
	mislabeledArrival int64
	// unfunded P2 arriving at taskworker, at rank copy
	unfundedArrival int64

	// of a push's 37 deferred units, what is its fold's, due foldDelay intervals on; the rest is its evacuation's
	foldDeferred int64
	// evacuation's funded queue, oldest first, and the folds', which rank after it (§11.13's order row)
	funded []*budgetWork
	folds  []*budgetWork
	// the longest a fold waited past its due step, in intervals
	foldMaxLag int
	// path-epoch copies, when a schedule runs them: they are the unfunded work
	copies *copyModel
	// unfunded P2 that can issue in the next interval within its own rates, and what has issued of it
	unfundedDemand       int64
	unfundedOwnByteCount int64
	// the mislabeled rotations' P1 refused so far: P1 is shed past its queueing delay, never kept (§11.13's shed row)
	mislabeledShed  int64
	unfundedBacklog int64

	// the allowance the processes hold, and how many intervals they have held it with no fresh one
	allowance    *evsservice.WriteBudgetAllowance
	staleSteps   int
	governorDown bool
	// funded P2 issued in each of the last twelve intervals, for the fallback row's last minute's rate
	fundedRecent []int64

	// what happened since the governor's last step
	pending         *sidecartest.BudgetOracleEvents
	pendingMeasured int64
	// the governor's P0 measured figure of each step, for the P0 ratio
	p0Measured []int64

	// the mutants: T floored at a fifth of the refill while B is empty; P0 queued behind B; P0's excess repaid, B
	// going below zero
	mutantFloorT      bool
	mutantQueueP0     bool
	mutantRepayExcess bool
	p0Waiting         int64
	mutantDebt        int64

	intervals  []*budgetInterval
	pushesShed int
	// the deferred work queued before the oracle's ledger began
	preloadedByteCount int64
	// what a storm run found as its storm ended: the busiest drive's writes over the storm, and the mislabeled
	// rotations' P1 shed in it
	stormDwpd           float64
	stormMislabeledShed int64
	// and after it: how long the storm's evacuation backlog took to spend, and from there how long T took to
	// reach half and 90% of r
	backlogSpent time.Duration
	rampHalf     time.Duration
	rampNinety   time.Duration
	// where the governor's figures left the oracle's
	mismatches []error
}

func newBudgetProcess(id string, startMs int64) *budgetProcess {
	return &budgetProcess{id: id, startMs: startMs, p0ByteCounts: map[sidecar.WriteP0Kind]int64{}}
}

// A world at a full bucket in steady state: pushes pushes an interval for the last 25 h, their deferred work
// queued and W holding its credit, every deferred unit an evacuation's.
func newBudgetWorld(t *testing.T, refillDwpd float64, pushes int) *budgetWorld {
	return newBudgetWorldWithFolds(t, refillDwpd, pushes, 0)
}

// newBudgetWorld with foldDeferred of each push's 37 deferred units its fold's, due a minute after it.
func newBudgetWorldWithFolds(t *testing.T, refillDwpd float64, pushes int, foldDeferred int64) *budgetWorld {
	settings := budgetWorldSettings(refillDwpd)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	world := &budgetWorld{
		t:            t,
		settings:     settings,
		clock:        clock,
		pushesWanted: pushes,
		foldDeferred: foldDeferred,
		p0Arrivals:   map[sidecar.WriteP0Kind]int64{},
		pending:      &sidecartest.BudgetOracleEvents{},
	}
	var wallet int64
	if 0 < pushes {
		for step := 1; step <= budgetEvacuationDelay; step += 1 {
			work := &budgetWork{createdStep: step - budgetEvacuationDelay, dueStep: step, byteCount: int64(pushes) * (budgetPushDeferred - foldDeferred)}
			world.funded = append(world.funded, work)
			wallet += work.byteCount
		}
		for step := 1; 0 < foldDeferred && step <= budgetFoldDelay; step += 1 {
			work := &budgetWork{createdStep: step - budgetFoldDelay, dueStep: step, byteCount: int64(pushes) * foldDeferred}
			world.folds = append(world.folds, work)
			wallet += work.byteCount
		}
	}
	world.preloadedByteCount = wallet
	world.governor = evsservice.NewGovernor("meta-1", settings, &evsservice.GovernorState{
		Seq:             1,
		TimeMs:          clock.Now().UnixMilli(),
		BucketByteCount: budgetDepth,
		WalletByteCount: wallet,
		Calibration:     1,
	})
	world.oracle = sidecartest.NewBudgetOracle(budgetOracleSettings(), budgetDepth, wallet)
	startMs := clock.Now().UnixMilli() + 1
	world.evs = newBudgetProcess("evs-1", startMs)
	world.gkm = newBudgetProcess("gkm-1", startMs)
	world.api = newBudgetProcess("api-1", startMs)
	world.taskworker = newBudgetProcess("taskworker-1", startMs)
	return world
}

func (self *budgetWorld) processes() []*budgetProcess {
	return []*budgetProcess{self.evs, self.gkm, self.api, self.taskworker}
}

// The process that issues each P0 kind.
func (self *budgetWorld) p0Process(kind sidecar.WriteP0Kind) *budgetProcess {
	switch kind {
	case sidecar.WriteP0KindRemove, sidecar.WriteP0KindRotation:
		return self.gkm
	case sidecar.WriteP0KindShred:
		return self.taskworker
	case sidecar.WriteP0KindErasure:
		return self.evs
	}
	return self.api
}

// A storm of every P0 kind together, perInterval priced units an interval in all.
func (self *budgetWorld) setP0(perInterval int64) {
	self.p0Arrivals = map[sidecar.WriteP0Kind]int64{}
	if perInterval <= 0 {
		return
	}
	// rotations and removes carry most of it, as a shrinking Team's do (§11.13's gates row)
	shares := map[sidecar.WriteP0Kind]int64{
		sidecar.WriteP0KindRotation: 40, sidecar.WriteP0KindRemove: 20, sidecar.WriteP0KindRevocation: 10,
		sidecar.WriteP0KindLog: 10, sidecar.WriteP0KindErasure: 8, sidecar.WriteP0KindShred: 8, sidecar.WriteP0KindLifecycle: 4,
	}
	for kind, share := range shares {
		self.p0Arrivals[kind] = perInterval * share / 100
	}
}

func budgetRanks(rank sidecar.WriteP2Rank, byteCount int64) []int64 {
	byteCounts := make([]int64, sidecar.WriteP2RankCount)
	byteCounts[rank] = byteCount
	return byteCounts
}

// The funded queues' due work and all of it, by rank, as of the interval about to run.
func (self *budgetWorld) fundedRankLevels() (demand []int64, backlog []int64) {
	demand = make([]int64, sidecar.WriteP2RankCount)
	backlog = make([]int64, sidecar.WriteP2RankCount)
	for rank, queue := range map[sidecar.WriteP2Rank][]*budgetWork{sidecar.WriteP2RankEvacuation: self.funded, sidecar.WriteP2RankFold: self.folds} {
		for _, work := range queue {
			backlog[rank] += work.byteCount
			if work.dueStep <= self.step+1 {
				demand[rank] += work.byteCount
			}
		}
	}
	return demand, backlog
}

// The funded queues' due work and all of it.
func (self *budgetWorld) fundedLevels() (demand int64, backlog int64) {
	demands, backlogs := self.fundedRankLevels()
	for rank := range demands {
		demand += demands[rank]
		backlog += backlogs[rank]
	}
	return demand, backlog
}

func (self *budgetWorld) reports() []*evsservice.WriteBudgetReport {
	reports := []*evsservice.WriteBudgetReport{}
	for _, process := range self.processes() {
		report := &evsservice.WriteBudgetReport{
			ProcessId:         process.id,
			StartMs:           process.startMs,
			TimeMs:            self.clock.Now().UnixMilli(),
			P0ByteCounts:      map[sidecar.WriteP0Kind]int64{},
			P1ByteCount:       process.p1ByteCount,
			CreditByteCount:   process.creditByteCount,
			UnfundedByteCount: process.unfundedByteCount,
			FundedByteCount:   process.fundedByteCount,
			P1QueuedByteCount: process.queuedByteCount,
		}
		for kind, byteCount := range process.p0ByteCounts {
			report.P0ByteCounts[kind] = byteCount
		}
		if process == self.taskworker {
			report.FundedDemandByteCounts, report.FundedBacklogByteCounts = self.fundedRankLevels()
			report.UnfundedDemandByteCounts = budgetRanks(sidecar.WriteP2RankCopy, self.unfundedDemand)
			report.UnfundedBacklogByteCounts = budgetRanks(sidecar.WriteP2RankCopy, self.unfundedBacklog)
		}
		reports = append(reports, report)
	}
	return reports
}

// Kills the governor: the processes keep the allowance they hold, on §11.13's fallback row.
func (self *budgetWorld) killGovernor() {
	self.governorDown = true
}

// A new loop takes the lease and resumes the saved state exactly.
func (self *budgetWorld) resumeGovernor() {
	self.governor = evsservice.NewGovernor("meta-1", self.settings, self.governor.State())
	self.governorDown = false
}

// {nvb_<set>} lost: the loop starts again with no state, B and W at zero.
func (self *budgetWorld) loseState() {
	self.governor = evsservice.NewGovernor("meta-1", self.settings, nil)
	self.oracle.LoseState()
	self.mutantDebt = 0
}

// The governor's figures in the oracle's form, with the P0 ratio as the loop computes it.
func (self *budgetWorld) observed(allowance *evsservice.WriteBudgetAllowance, before map[sidecar.WriteP0Kind]int64) *sidecartest.BudgetOracleAccounts {
	observed := &sidecartest.BudgetOracleAccounts{
		Calibration:              allowance.Calibration,
		BucketByteCount:          allowance.BucketByteCount,
		WalletByteCount:          allowance.WalletByteCount,
		TotalByteCount:           allowance.TotalByteCount,
		P1ByteCount:              allowance.P1ByteCount,
		UnfundedByteCount:        allowance.UnfundedByteCount,
		FundedByteCount:          allowance.FundedByteCount,
		P0ExcessStepByteCounts:   map[string]int64{},
		P1QueuedByteCount:        allowance.P1QueuedByteCount,
		FundedBacklogByteCount:   allowance.FundedBacklogByteCount,
		UnfundedBacklogByteCount: allowance.UnfundedBacklogByteCount,
	}
	for kind, byteCount := range allowance.P0ExcessByteCounts {
		if delta := byteCount - before[kind]; delta != 0 {
			observed.P0ExcessStepByteCounts[string(kind)] = delta
		}
	}
	return observed
}

// The P0 ratio over the last hour of the governor's own figures (budget_loop.go's gauge).
func (self *budgetWorld) p0RefillRatio() float64 {
	count := min(len(self.p0Measured), budgetStepsPerHour)
	if count == 0 {
		return 0
	}
	var p0 int64
	for _, byteCount := range self.p0Measured[len(self.p0Measured)-count:] {
		p0 += byteCount
	}
	return float64(p0) / float64(budgetIntervalRefill*count)
}

// One interval: the governor, if it is up, steps on what the drive measured since its last step and the
// processes' reports, and the oracle on the same interval's raw events; then the processes spend what they hold.
func (self *budgetWorld) stepOnce() *budgetInterval {
	reports := self.reports()
	self.clock.Advance(self.settings.Interval)
	self.step += 1
	interval := &budgetInterval{}

	if self.governorDown {
		self.oracle.Fallback(self.pending)
		self.staleSteps += 1
	} else {
		excessBefore := self.governor.State().P0ExcessByteCounts
		demand, backlog := self.fundedLevels()
		// the levels as this step's reports carry them
		self.pending.FundedDemandByteCount = demand
		self.pending.FundedBacklogByteCount = backlog
		self.pending.MeasuredByteCount = self.pendingMeasured
		allowance := self.governor.Step(self.clock.Now(), self.pendingMeasured, reports)
		expected := self.oracle.Step(self.pending)
		self.p0Measured = append(self.p0Measured, allowance.P0MeasuredByteCount)
		observed := self.observed(allowance, excessBefore)
		if self.mutantRepayExcess {
			// the mutant carries what P0 took past the bucket as a debt: B reads below zero, and nothing but P0
			// issues until the refill has repaid it
			for _, byteCount := range observed.P0ExcessStepByteCounts {
				self.mutantDebt += byteCount
			}
			if 0 < self.mutantDebt {
				repaid := min(self.mutantDebt, allowance.BucketByteCount)
				self.mutantDebt -= repaid
				mutant := *allowance
				mutant.BucketByteCount = allowance.BucketByteCount - repaid - self.mutantDebt
				mutant.TotalByteCount, mutant.P1ByteCount, mutant.UnfundedByteCount, mutant.FundedByteCount = 0, 0, 0, 0
				mutant.Shares = map[string]*evsservice.WriteBudgetShare{}
				allowance = &mutant
				observed.BucketByteCount = mutant.BucketByteCount
				observed.TotalByteCount, observed.P1ByteCount, observed.UnfundedByteCount, observed.FundedByteCount = 0, 0, 0, 0
			}
		}
		if self.mutantFloorT && allowance.TotalByteCount < budgetIntervalRefill/5 {
			// the mutant floors T at a fifth of the refill whatever B holds and P0 takes
			mutant := *allowance
			mutant.TotalByteCount = budgetIntervalRefill / 5
			mutant.P1ByteCount = mutant.TotalByteCount - mutant.UnfundedByteCount
			mutant.Shares = map[string]*evsservice.WriteBudgetShare{
				self.evs.id: {P1ByteCount: mutant.P1ByteCount},
			}
			allowance = &mutant
			observed.TotalByteCount, observed.P1ByteCount = mutant.TotalByteCount, mutant.P1ByteCount
		}
		if err := self.oracle.Compare(observed); err != nil {
			self.mismatches = append(self.mismatches, err)
		}
		if ratio := self.p0RefillRatio(); 1e-9 < ratio-expected.P0RefillRatio || 1e-9 < expected.P0RefillRatio-ratio {
			// the governor rounds each step's P0 figure to a byte
			if 0.001 < ratio-expected.P0RefillRatio || 0.001 < expected.P0RefillRatio-ratio {
				self.mismatches = append(self.mismatches, fmt.Errorf("step %d: the P0 ratio is %v, and the oracle's %v", self.step, ratio, expected.P0RefillRatio))
			}
		}
		self.allowance = allowance
		self.staleSteps = 0
		self.pending = &sidecartest.BudgetOracleEvents{}
		self.pendingMeasured = 0
		interval.allowance = allowance
	}
	interval.p0RefillRatio = self.p0RefillRatio()

	// what each process may spend this interval: its share, or §11.13's fallback row on a stale one
	share := func(process *budgetProcess) evsservice.WriteBudgetShare {
		if self.allowance == nil || self.allowance.Shares[process.id] == nil {
			return evsservice.WriteBudgetShare{}
		}
		held := *self.allowance.Shares[process.id]
		if int(self.settings.FallbackAfter/self.settings.Interval) <= self.staleSteps {
			held.P1ByteCount = int64(float64(held.P1ByteCount) * self.settings.FallbackShare)
			held.UnfundedByteCount = int64(float64(held.UnfundedByteCount) * self.settings.FallbackShare)
			held.UncoveredByteCount = int64(float64(held.UncoveredByteCount) * self.settings.FallbackShare)
			var recent int64
			for _, byteCount := range self.fundedRecent {
				recent += byteCount
			}
			held.FundedByteCount = min(held.FundedByteCount, recent/int64(max(1, len(self.fundedRecent))))
		}
		return held
	}
	var issued int64
	events := self.pending

	// P0 issues on arrival, whatever the bucket holds (owner decision 186)
	if events.P0ByteCounts == nil {
		events.P0ByteCounts = map[string]int64{}
	}
	var p0Arrived int64
	for _, byteCount := range self.p0Arrivals {
		p0Arrived += byteCount
	}
	interval.p0Arrived = p0Arrived
	p0Room := int64(-1)
	if self.mutantQueueP0 && self.allowance != nil {
		// the mutant makes P0 wait for what B holds
		p0Room = self.allowance.BucketByteCount
		self.p0Waiting += p0Arrived
	}
	for kind, byteCount := range self.p0Arrivals {
		if 0 <= p0Room {
			byteCount = min(byteCount, p0Room)
			p0Room -= byteCount
			self.p0Waiting -= byteCount
		}
		self.p0Process(kind).p0ByteCounts[kind] += byteCount
		events.P0ByteCounts[string(kind)] += byteCount
		interval.p0Issued += byteCount
		issued += byteCount
	}
	if 0 < self.p0Waiting {
		events.P0WaitedCount += 1
	}

	// pushes, within evs's part of A1; what it cannot admit it sheds (429)
	evsShare := share(self.evs)
	admitted := 0
	for admitted < self.pushesWanted && int64(admitted+1)*budgetPushPrice <= evsShare.P1ByteCount {
		admitted += 1
	}
	if 0 < admitted {
		self.evs.p1ByteCount += int64(admitted) * budgetPushImmediate
		self.evs.creditByteCount += int64(admitted) * budgetPushDeferred
		events.P1ByteCount += int64(admitted) * budgetPushImmediate
		events.CreditByteCount += int64(admitted) * budgetPushDeferred
		issued += int64(admitted) * budgetPushImmediate
		self.funded = append(self.funded, &budgetWork{createdStep: self.step, dueStep: self.step + budgetEvacuationDelay, byteCount: int64(admitted) * (budgetPushDeferred - self.foldDeferred)})
		if 0 < self.foldDeferred {
			self.folds = append(self.folds, &budgetWork{createdStep: self.step, dueStep: self.step + budgetFoldDelay, byteCount: int64(admitted) * self.foldDeferred})
		}
	}
	self.evs.queuedByteCount = int64(self.pushesWanted-admitted) * budgetPushPrice
	self.pushesShed += self.pushesWanted - admitted
	interval.pushesWanted = self.pushesWanted
	interval.pushesAdmitted = admitted
	interval.p1Debit += int64(admitted) * budgetPushPrice

	// the mislabeled rotations' deliveries and claims: P1 at gkm, within its part of A1, the rest shed
	mislabeled := min(self.mislabeledArrival, share(self.gkm).P1ByteCount)
	self.mislabeledShed += self.mislabeledArrival - mislabeled
	self.gkm.p1ByteCount += mislabeled
	self.gkm.queuedByteCount = self.mislabeledArrival - mislabeled
	events.P1ByteCount += mislabeled
	issued += mislabeled
	interval.p1Debit += mislabeled

	// evacuation, oldest first: from A2, then from the part of A_U funded work W no longer covers may take
	taskworkerShare := share(self.taskworker)
	fundedLeft := taskworkerShare.FundedByteCount
	uncoveredLeft := taskworkerShare.UncoveredByteCount
	pay := func(queue []*budgetWork) []*budgetWork {
		for 0 < len(queue) && queue[0].dueStep <= self.step {
			work := queue[0]
			paid := min(work.byteCount, fundedLeft)
			fundedLeft -= paid
			work.byteCount -= paid
			self.taskworker.fundedByteCount += paid
			events.FundedByteCount += paid
			interval.fundedIssued += paid
			uncovered := min(work.byteCount, uncoveredLeft)
			uncoveredLeft -= uncovered
			work.byteCount -= uncovered
			self.taskworker.unfundedByteCount += uncovered
			events.UnfundedByteCount += uncovered
			events.UncoveredByteCount += uncovered
			interval.unfundedIssued += uncovered
			issued += paid + uncovered
			if 0 < work.byteCount {
				break
			}
			queue = queue[1:]
		}
		return queue
	}
	self.funded = pay(self.funded)
	// the folds, after evacuation: a fold still waiting is a ref on its way to FOLD_BEHIND
	self.folds = pay(self.folds)
	if 0 < len(self.folds) && self.folds[0].dueStep <= self.step {
		self.foldMaxLag = max(self.foldMaxLag, self.step-self.folds[0].dueStep+1)
	}
	self.fundedRecent = append(self.fundedRecent, interval.fundedIssued)
	if 12 < len(self.fundedRecent) {
		self.fundedRecent = self.fundedRecent[1:]
	}

	// copies and the other unfunded work, within what is left of A_U
	unfundedLeft := max(0, taskworkerShare.UnfundedByteCount-taskworkerShare.UncoveredByteCount)
	var unfunded int64
	if self.copies != nil {
		unfunded = self.copies.step(self, unfundedLeft)
	} else {
		self.unfundedBacklog += self.unfundedArrival
		unfunded = min(self.unfundedBacklog, unfundedLeft)
		self.unfundedBacklog -= unfunded
		self.unfundedDemand = self.unfundedBacklog
	}
	self.taskworker.unfundedByteCount += unfunded
	self.unfundedOwnByteCount += unfunded
	events.UnfundedByteCount += unfunded
	interval.unfundedIssued += unfunded
	issued += unfunded

	// the levels the next reports carry, and what the drive measured at exact prices
	events.P1QueuedByteCount = self.evs.queuedByteCount + self.gkm.queuedByteCount
	events.UnfundedDemandByteCount = self.unfundedDemand
	events.UnfundedBacklogByteCount = self.unfundedBacklog
	self.pendingMeasured += issued
	interval.measured = issued
	if 0 < len(self.funded) {
		interval.oldestBatchAge = time.Duration(self.step-self.funded[0].createdStep) * self.settings.Interval
	}
	self.intervals = append(self.intervals, interval)
	return interval
}

// The unfunded P2 that was no deferred work of a push: copies and the like.
func (self *budgetWorld) copiedByteCount() int64 {
	return self.unfundedOwnByteCount
}

func (self *budgetWorld) run(count int) []*budgetInterval {
	intervals := make([]*budgetInterval, 0, count)
	for range count {
		intervals = append(intervals, self.stepOnce())
	}
	return intervals
}

// Everything the run broke: where the governor's figures left the oracle's, and FI-14 on the events.
func (self *budgetWorld) err() error {
	found := []error{}
	if 0 < len(self.mismatches) {
		found = append(found, fmt.Errorf("%w (and %d more)", self.mismatches[0], len(self.mismatches)-1))
	}
	if err := self.oracle.Err(); err != nil {
		found = append(found, err)
	}
	// the ledger holds every interval the oracle has stepped on, so the queue is taken as it stood before the
	// interval still pending; work queued before the oracle began was admitted before its ledger did, so it comes
	// off what is owed
	var queued int64
	for _, work := range append(append([]*budgetWork{}, self.funded...), self.folds...) {
		queued += work.byteCount
	}
	queued += self.pending.FundedByteCount + self.pending.UncoveredByteCount - self.pending.CreditByteCount
	if err := self.oracle.CheckPaidOnce(queued - self.preloadedByteCount); err != nil {
		found = append(found, err)
	}
	return errors.Join(found...)
}

// The storm's clauses over its intervals: every P0 write issued on arrival; while P0 took the refill and the bucket
// was empty, P1 and unfunded P2 issued nothing and funded P2 nothing past what B held; B never below zero.
func budgetCheckStorm(intervals []*budgetInterval) error {
	for i, interval := range intervals {
		if interval.p0Issued != interval.p0Arrived {
			return fmt.Errorf("storm interval %d: %d of %d P0 units issued on arrival", i, interval.p0Issued, interval.p0Arrived)
		}
		allowance := interval.allowance
		if allowance == nil {
			continue
		}
		if allowance.BucketByteCount < 0 {
			return fmt.Errorf("storm interval %d: B is %d", i, allowance.BucketByteCount)
		}
		if allowance.TotalByteCount == 0 && (interval.p1Debit != 0 || interval.unfundedIssued != 0) {
			return fmt.Errorf("storm interval %d: P1 %d and unfunded P2 %d issued while P0 took the refill", i, interval.p1Debit, interval.unfundedIssued)
		}
		if allowance.BucketByteCount < interval.fundedIssued {
			return fmt.Errorf("storm interval %d: funded P2 issued %d past what B held, %d", i, interval.fundedIssued, allowance.BucketByteCount)
		}
	}
	return nil
}

// The clause for the storm's end: within one interval of the first whose P0 is back under the refill, pushes are
// admitted and evacuation issues, on what B holds beyond T.
func budgetCheckResume(after []*budgetInterval) error {
	if len(after) < 2 {
		return errors.New("no interval after the storm")
	}
	second := after[1]
	if second.allowance == nil || second.allowance.BucketByteCount < 0 {
		return errors.New("no allowance, or B below zero, one interval after the storm")
	}
	if second.pushesAdmitted == 0 {
		return fmt.Errorf("no push admitted one interval after the storm: T %d", second.allowance.TotalByteCount)
	}
	if second.fundedIssued == 0 {
		return fmt.Errorf("evacuation issued nothing one interval after the storm: A2 %d, W %d", second.allowance.FundedByteCount, second.allowance.WalletByteCount)
	}
	return nil
}

// The storm and the day after it, with an optional fault in the storm's middle: the clauses every variant holds.
// It reports what §22.8 asks the run to report.
func budgetRunStormDwpd(t *testing.T, world *budgetWorld, stormSteps int, afterSteps int, fault func(world *budgetWorld)) (storm []*budgetInterval, after []*budgetInterval) {
	world.run(200)
	world.setP0(2 * budgetIntervalRefill)
	world.mislabeledArrival = 60
	stormStart := world.step
	storm = world.run(stormSteps / 2)
	if fault != nil {
		fault(world)
	}
	storm = append(storm, world.run(stormSteps-stormSteps/2)...)
	shedInStorm := world.pushesShed
	world.stormMislabeledShed = world.mislabeledShed
	world.stormDwpd = world.oracle.Dwpd(time.Duration(stormSteps)*world.settings.Interval, world.settings.DriveByteCount)

	// the storm stops: P0 back at its ordinary rate
	world.setP0(50)
	world.mislabeledArrival = 0
	after = world.run(afterSteps)

	pageStep := -1
	var maxAge time.Duration
	for i, interval := range storm {
		if pageStep < 0 && 1 < interval.p0RefillRatio {
			pageStep = i
		}
		maxAge = max(maxAge, interval.oldestBatchAge)
	}
	// the ramp, from the interval the storm's evacuation backlog is spent
	spentAt := -1
	var halfAt, ninetyAt time.Duration
	for i, interval := range after {
		maxAge = max(maxAge, interval.oldestBatchAge)
		if interval.allowance == nil {
			continue
		}
		if spentAt < 0 && 1 < i && interval.fundedIssued == 0 && interval.unfundedIssued == 0 {
			spentAt = i
		}
		if spentAt < 0 {
			continue
		}
		if halfAt == 0 && budgetIntervalRefill/2 <= interval.allowance.TotalByteCount {
			halfAt = time.Duration(i-spentAt) * world.settings.Interval
		}
		if ninetyAt == 0 && budgetIntervalRefill*9/10 <= interval.allowance.TotalByteCount {
			ninetyAt = time.Duration(i-spentAt) * world.settings.Interval
		}
	}
	world.rampHalf, world.rampNinety = halfAt, ninetyAt
	if 0 <= spentAt {
		world.backlogSpent = time.Duration(spentAt) * world.settings.Interval
	}
	t.Logf("storm from step %d: P0 page after %s; forgiven excess by kind %v", stormStart, time.Duration(pageStep)*world.settings.Interval, world.oracle.ForgivenByteCounts())
	t.Logf("busiest drive over the storm: %.2f DWPD; pushes shed in the storm %d; mislabeled P1 shed %d units",
		world.stormDwpd, shedInStorm, world.stormMislabeledShed)
	t.Logf("after the storm: evacuation's backlog spent in %s, then T at half of r after %s and 90%% after %s; oldest batch at most %s old",
		world.backlogSpent, halfAt, ninetyAt, maxAge)
	return storm, after
}

// FS-117's main run: 24 h of P0 at twice the refill, then 24 h after it.
func TestFs117P0PastTheRefillForADayThenTheDayAfter(t *testing.T) {
	world := newBudgetWorld(t, 0.768, 12)
	storm, after := budgetRunStormDwpd(t, world, 24*budgetStepsPerHour, 24*budgetStepsPerHour, nil)
	if err := world.err(); err != nil {
		t.Fatal(err)
	}
	if err := budgetCheckStorm(storm); err != nil {
		t.Error(err)
	}
	if err := budgetCheckResume(after); err != nil {
		t.Error(err)
	}
	// P0 takes the refill within the hour the bucket lasts: after it nothing but P0 issues
	emptied := -1
	for i, interval := range storm {
		if interval.allowance.BucketByteCount == 0 && interval.allowance.TotalByteCount == 0 {
			emptied = i
			break
		}
	}
	if emptied < 0 || budgetStepsPerHour < emptied {
		t.Errorf("the bucket emptied at storm interval %d, not within an hour", emptied)
	}
	for i, interval := range storm[emptied+1:] {
		if interval.pushesAdmitted != 0 || interval.fundedIssued != 0 || interval.unfundedIssued != 0 || interval.p1Debit != 0 {
			t.Fatalf("storm interval %d past the empty bucket: %d pushes, %d P1, %d funded, %d unfunded", emptied+1+i,
				interval.pushesAdmitted, interval.p1Debit, interval.fundedIssued, interval.unfundedIssued)
		}
	}
	// the page: within an hour of P0 passing the refill
	paged := -1
	for i, interval := range storm {
		if 1 < interval.p0RefillRatio {
			paged = i
			break
		}
	}
	if paged < 0 || budgetStepsPerHour < paged {
		t.Errorf("the P0 page fired at storm interval %d, not within an hour", paged)
	}
	// P0 wrote past the budget and past the drive's rating while it lasted, forgiven by kind and never repaid
	if world.stormDwpd <= 1 {
		t.Errorf("the storm's last 24 h wrote %.2f DWPD, not past the drive's rating", world.stormDwpd)
	}
	forgiven := world.oracle.ForgivenByteCounts()
	if len(forgiven) != len(sidecar.WriteP0Kinds) {
		t.Errorf("forgiven excess names %d kinds: %v", len(forgiven), forgiven)
	}
	var forgivenSum int64
	for _, byteCount := range forgiven {
		forgivenSum += byteCount
	}
	// 24 h at twice the refill, less the hour the bucket held and the refill P0 took: about 23 h of r
	if forgivenSum < 22*budgetStepsPerHour*budgetIntervalRefill || 24*budgetStepsPerHour*budgetIntervalRefill < forgivenSum {
		t.Errorf("forgiven excess %d", forgivenSum)
	}
	if forgiven[string(sidecar.WriteP0KindRotation)] < forgiven[string(sidecar.WriteP0KindLifecycle)] {
		t.Errorf("forgiven excess not in proportion to P0's bytes: %v", forgiven)
	}
	// the mislabeled rotations were charged as P1 and shed with the pushes: none issued past the empty bucket
	if world.stormMislabeledShed < int64(23*budgetStepsPerHour)*60 {
		t.Errorf("mislabeled rotations shed %d units: some issued while P0 took the refill", world.stormMislabeledShed)
	}
	// with pushes then taking all of T, T reaches half of r ~18 minutes after the backlog is spent and 90% after
	// ~78, a little sooner here since a whole push leaves part of T unspent (§11.13's gates row)
	if world.rampHalf < 10*time.Minute || 30*time.Minute < world.rampHalf || world.rampNinety < 40*time.Minute || 110*time.Minute < world.rampNinety {
		t.Errorf("T at half of r %s after the backlog was spent and 90%% after %s", world.rampHalf, world.rampNinety)
	}
	// evacuation stopped with every class but P0, so batches passed 26 h, and it caught up after
	var stormAge, endAge time.Duration
	for _, interval := range storm {
		stormAge = max(stormAge, interval.oldestBatchAge)
	}
	endAge = after[len(after)-1].oldestBatchAge
	if stormAge <= 26*time.Hour {
		t.Errorf("the oldest batch reached %s in the storm: evacuation did not stop", stormAge)
	}
	if 26*time.Hour < endAge {
		t.Errorf("the oldest batch is still %s old a day after the storm", endAge)
	}
	// T follows its factor of B each interval after the storm: it only rises while pushes take all of it
	for i := 2; i < len(after); i += 1 {
		if after[i].allowance.BucketByteCount < budgetDepth/2 && after[i].allowance.TotalByteCount+1 < after[i-1].allowance.TotalByteCount && after[i-1].fundedIssued == 0 && after[i].fundedIssued == 0 {
			t.Fatalf("T fell from %d to %d at interval %d after the storm, with B at %d", after[i-1].allowance.TotalByteCount, after[i].allowance.TotalByteCount, i, after[i].allowance.BucketByteCount)
		}
	}
	if last := after[len(after)-1].allowance; last.TotalByteCount < budgetIntervalRefill*9/10-50 {
		t.Errorf("T is %d a day after the storm", last.TotalByteCount)
	}
}

// The storm again with the governor killed for 10 min in its middle: the processes keep their shares, which are
// nothing while P0 takes the refill, P0 still issues on arrival, and a new loop resumes the saved state exactly.
func TestFs117GovernorKilledTenMinutesMidStorm(t *testing.T) {
	world := newBudgetWorld(t, 0.768, 12)
	var down []*budgetInterval
	storm, after := budgetRunStormDwpd(t, world, 24*budgetStepsPerHour, 24*budgetStepsPerHour, func(world *budgetWorld) {
		world.killGovernor()
		down = world.run(120)
		world.resumeGovernor()
	})
	if err := world.err(); err != nil {
		t.Fatal(err)
	}
	if err := budgetCheckStorm(append(storm, down...)); err != nil {
		t.Error(err)
	}
	for i, interval := range down {
		if interval.allowance != nil || interval.p1Debit != 0 || interval.unfundedIssued != 0 || interval.fundedIssued != 0 {
			t.Fatalf("interval %d with the governor down: P1 %d, funded %d, unfunded %d", i, interval.p1Debit, interval.fundedIssued, interval.unfundedIssued)
		}
	}
	if err := budgetCheckResume(after); err != nil {
		t.Error(err)
	}
}

// The storm again with {nvb_<set>} lost in its middle: B and W restart at zero, P0 is untouched, the other classes'
// writes still hold FI-14 (a), and the funded backlog whose credit went with W is paid once, as unfunded P2.
func TestFs117StateLostMidStorm(t *testing.T) {
	world := newBudgetWorld(t, 0.768, 12)
	lostAt := 0
	storm, after := budgetRunStormDwpd(t, world, 24*budgetStepsPerHour, 24*budgetStepsPerHour, func(world *budgetWorld) {
		world.loseState()
		lostAt = len(world.intervals)
	})
	if err := world.err(); err != nil {
		t.Fatal(err)
	}
	if err := budgetCheckStorm(storm); err != nil {
		t.Error(err)
	}
	first := world.intervals[lostAt].allowance
	if first.WalletByteCount != 0 || budgetIntervalRefill < first.BucketByteCount {
		t.Errorf("after the state was lost: B %d, W %d", first.BucketByteCount, first.WalletByteCount)
	}
	// evacuation, its credit lost with W, resumes within one interval of the storm's end as unfunded P2, from A_U,
	// which leaves pushes three-fifths of T: a whole push, a tenth of an interval's refill in this world, fits
	// once B has refilled a minute
	if len(after) < 13 || after[1].unfundedIssued == 0 {
		t.Error("the backlog whose credit was lost did not run as unfunded P2 one interval after the storm")
	}
	admitted := 0
	for _, interval := range after[:13] {
		admitted += interval.pushesAdmitted
	}
	if admitted == 0 {
		t.Error("no push admitted within a minute of the storm's end")
	}
}

// A control day of 2x year one's mix with a --now shred of a 1M-object repo: P0 stays far under the refill, the page
// never fires, no push is shed and the budget is never touched.
func TestFs117ControlDayNeverPages(t *testing.T) {
	world := newBudgetWorld(t, 0.768, 6)
	world.setP0(50)
	world.run(6 * budgetStepsPerHour)
	// the shred's deletes: ~6% of an hour's refill, issued over ten minutes
	world.p0Arrivals[sidecar.WriteP0KindShred] += 350
	world.run(120)
	world.p0Arrivals[sidecar.WriteP0KindShred] -= 350
	world.run(18*budgetStepsPerHour - 120)
	if err := world.err(); err != nil {
		t.Fatal(err)
	}
	for i, interval := range world.intervals {
		if 1 <= interval.p0RefillRatio {
			t.Fatalf("the P0 page fired at interval %d of the control day: ratio %.3f", i, interval.p0RefillRatio)
		}
		// the first shares are split before any process has reported demand
		if 2 < i && interval.pushesAdmitted != interval.pushesWanted {
			t.Fatalf("interval %d of the control day admitted %d of %d pushes", i, interval.pushesAdmitted, interval.pushesWanted)
		}
	}
	if forgiven := world.oracle.ForgivenByteCounts(); len(forgiven) != 0 {
		t.Errorf("P0 was forgiven %v on the control day", forgiven)
	}
}

// The three mutants, each failing: T floored at a fifth of the refill while B is empty, so pushes issue while P0
// takes the refill; P0 queued behind B; and P0's excess repaid, B going below zero and nothing resuming at the
// storm's end.
func TestFs117MutantsFail(t *testing.T) {
	mutants := []struct {
		name  string
		apply func(world *budgetWorld)
	}{
		{"T floored at a fifth of the refill", func(world *budgetWorld) { world.mutantFloorT = true }},
		{"P0 queued behind B", func(world *budgetWorld) { world.mutantQueueP0 = true }},
		{"P0's excess repaid", func(world *budgetWorld) { world.mutantRepayExcess = true }},
	}
	for _, mutant := range mutants {
		world := newBudgetWorld(t, 0.768, 12)
		mutant.apply(world)
		storm, after := budgetRunStormDwpd(t, world, 3*budgetStepsPerHour, 2*budgetStepsPerHour, nil)
		failed := world.err() != nil || budgetCheckStorm(storm) != nil || budgetCheckResume(after) != nil
		if !failed {
			t.Errorf("the mutant passed: %s", mutant.name)
		}
		if err := world.err(); err != nil {
			t.Logf("%s: %v", mutant.name, err)
		}
	}
	// the same short run with no mutant passes, so each failure above is its mutant's
	world := newBudgetWorld(t, 0.768, 12)
	storm, after := budgetRunStormDwpd(t, world, 3*budgetStepsPerHour, 2*budgetStepsPerHour, nil)
	if err := errors.Join(world.err(), budgetCheckStorm(storm), budgetCheckResume(after)); err != nil {
		t.Fatalf("the unmutated short run: %v", err)
	}
}
