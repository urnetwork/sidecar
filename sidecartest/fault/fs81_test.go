package fault

// FS-81 (§22.8, FI-14; EVSB-M10-08) on T2: fake drive counters at 0.9 DWPD's rate with format 2's mix, its writes
// priced by §11.13's format-2 rows (evsservice.PriceRows) on the price tables. Two parts:
//
//	flood    on the real loop and a real process budget (FS-61's world), a network whose background index work
//	         (roll-ups, merges, backfills, full builds) floods its queue is refused first, 429 with retry_after_ms,
//	         while a light network's indexed pushes are each admitted within an interval and the shed delay of
//	         asking, so its p99 holds; erasures' CLOSURE pushes and slot rewrites issue at once as P0 of kind
//	         erasure, their bytes reported under it
//	26 h     at 2x year one with the index on in every eligible repo and the budget refilled at 0.8 DWPD, the real
//	         governor stepped every 5 s beside modeled processes at exact prices (k = 1), as FS-61's 26 h tail is,
//	         and the oracle beside it: no push is refused once the governor has seen each process's demand, no fold
//	         waits toward FOLD_BEHIND, no batch outlives 26 h, and each companion and roll-up push's deferred work
//	         is paid once, from W, never from T
//
// The flood runs in a synctest bubble, whose Wait returns only once every goroutine in it is blocked again, so each
// admission has queued before the test moves the fake clock.
//
// The 26 h world's unit is 1/100,000 of an interval's refill, which is D-TEST-11's 43 KiB a push at 2x year one's
// pushes, here 80 an interval, so a push is about a thousand units and one push's arrival moves little: at the
// scale of FS-61's world, where eight pushes fill an interval, a companion or roll-up push alone is a spike no
// real cluster's 2,000 pushes an interval show. Its prices are the 1 KiB table's, D-TEST-11's first choice, where
// §11.13 puts format 2 at ~34-37 KiB a push at 2x year one. Content pushes are three in four in-ref indexed and the
// rest on git-mode refs and record streams, whose index rides companion pushes, one per eight content pushes it
// indexes; a roll-up comes each minute, more often than a 30-day bucket's expiry brings one, so it is exercised.
//
// FS-81's T3 run, the loop and process budgets on T3's Redis and MinIO, is not built here.

import (
	"errors"
	"fmt"
	"math"
	"testing"
	"testing/synctest"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One P1 admission in flight, decided once done closes.
type fs81Admission struct {
	asked   time.Time
	done    chan struct{}
	grant   sidecar.WriteGrant
	err     error
	decided time.Time
}

// Asks client to admit cost for networkId on its own goroutine.
func fs81Admit(world *fs61World, client *evsservice.WriteBudgetClient, networkId connect.Id, cost sidecar.WriteCost) *fs81Admission {
	admission := &fs81Admission{asked: world.clock.Now(), done: make(chan struct{})}
	go func() {
		defer close(admission.done)
		admission.grant, admission.err = client.AdmitP1(world.ctx, "meta-1", networkId, cost)
		admission.decided = world.clock.Now()
	}()
	return admission
}

func (self *fs81Admission) isDone() bool {
	select {
	case <-self.done:
		return true
	default:
		return false
	}
}

// The sum of two costs.
func fs81Add(a sidecar.WriteCost, b sidecar.WriteCost) sidecar.WriteCost {
	return sidecar.WriteCost{ImmediateByteCount: a.ImmediateByteCount + b.ImmediateByteCount, DeferredByteCount: a.DeferredByteCount + b.DeferredByteCount}
}

// A row's priced bytes on table.
func fs81Price(t *testing.T, table *evsservice.PriceTable, rows []*evsservice.PriceRow, event evsservice.PriceEvent) sidecar.WriteCost {
	t.Helper()
	row, err := evsservice.PriceRowOf(rows, event)
	if err != nil {
		t.Fatal(err)
	}
	cost, err := table.PriceRow(row)
	if err != nil {
		t.Fatal(err)
	}
	return cost
}

// Moves the clock to at, the processes' next tick, the drives writing byteCount meanwhile, waits for every tick and
// steps the loop.
func (self *fs61World) tickAt(at time.Time, byteCount uint64) *evsservice.WriteBudgetAllowance {
	self.t.Helper()
	self.counters.write(byteCount)
	next := at.Add(self.settings.Budget.Interval)
	before := self.timerCount(next)
	self.clock.AdvanceTo(at)
	self.awaitTimers(next, before+len(self.clients))
	return self.loop.Step(self.ctx)
}

// FS-81's flood: with the drives at 0.9 DWPD's rate, a Pro network's background index work, each item a push that
// stages a roll-up's or full build's rewritten files, asks past its process's share every interval, between two
// Community networks' indexed content pushes, the one before it and the other after, turn by turn. The push before it
// is admitted at once from the fresh share. Past the shed delay the flood's waiters are refused whole, 429 with
// retry_after_ms, never the Community push queued behind it, which is admitted at the next share, within an interval
// and the shed delay of asking. The erasures' CLOSURE pushes and slot rewrites asked beside them issue at once as P0.
//
// Two light networks both queued behind the flood are not this test's: past the delay the shed refuses every waiting
// network but the last, heaviest first and equal loads by id, so one of them is refused too
// (questions/evsb-m10-08-shed-several-light-networks).
func TestFs81IndexWorkFloodIsRefusedFirstWhileALightNetworkKeepsItsP99(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		settings := evsservice.DefaultBudgetLoopSettings()
		depth := int64(settings.Budget.RefillDwpd * float64(settings.Budget.DriveByteCount) / 24)
		world := newFs61World(t, depth)
		world.loop.Step(world.ctx)
		client := world.addClient()
		next := world.clock.Now().Add(world.settings.Budget.Interval)
		busy := fs61IntervalBytes(world.settings.Budget, 0.9)
		world.tickAt(next, busy)
		next = next.Add(world.settings.Budget.Interval)
		world.tickAt(next, busy)

		table := evsservice.DefaultPriceTable4KiB()
		rows, err := evsservice.PriceRows(nil)
		if err != nil {
			t.Fatal(err)
		}
		// an indexed content push: a push and what its index adds
		content := fs81Add(fs81Price(t, table, rows, evsservice.PriceEventDirectoryNoticeRewrite), fs81Price(t, table, rows, evsservice.PriceEventIndexedPush))
		// a background index push: a companion-shaped push whose record stages 4 MiB of rewritten files
		staged, err := table.Price(evsservice.WriteOperation{Kind: evsservice.WriteOperationStaged, ObjectByteCount: 4 * 1024 * 1024, Count: 1})
		if err != nil {
			t.Fatal(err)
		}
		background := fs81Add(fs81Price(t, table, rows, evsservice.PriceEventCompanionPush), sidecar.WriteCost{ImmediateByteCount: staged})
		// a CLOSURE push, a push with its index rewrites, and a slot rewrite
		closure := fs81Price(t, table, rows, evsservice.PriceEventDropPush).ByteCount()
		slotRewrite, err := table.Price(evsservice.WriteOperation{Kind: evsservice.WriteOperationOverwrite, ObjectByteCount: 12 * 1024, Count: 1})
		if err != nil {
			t.Fatal(err)
		}

		pro := connect.NewId()
		world.host.Quota.SetLimits(pro, &sidecar.QuotaLimits{Tier: "pro", Limits: map[string]int64{"store_weight": 4}})
		communities := []connect.Id{connect.NewId(), connect.NewId()}
		refill := int64(fs61IntervalBytes(world.settings.Budget, world.settings.Budget.RefillDwpd))
		// the flood asks for twice what an interval's refill could admit
		floodCount := int(2 * refill / background.ByteCount())

		var proAdmitted, proRefused int
		var p0Issued int64
		waits := []time.Duration{}
		for round := range 8 {
			first, last := communities[round%2], communities[(round+1)%2]
			before := fs81Admit(world, client, first, content)
			synctest.Wait()
			if !before.isDone() || before.err != nil {
				t.Fatalf("round %d: the push asked at the fresh share was not admitted at once: %v", round, before.err)
			}
			before.grant.Close()
			waits = append(waits, before.decided.Sub(before.asked))

			pros := []*fs81Admission{}
			for range floodCount {
				pros = append(pros, fs81Admit(world, client, pro, background))
			}
			synctest.Wait()
			pending := 0
			for _, admission := range pros {
				if !admission.isDone() {
					pending += 1
				}
			}
			if pending == 0 {
				t.Fatalf("round %d: the share admitted the whole flood of %d", round, floodCount)
			}
			after := fs81Admit(world, client, last, content)
			synctest.Wait()
			if after.isDone() {
				t.Fatalf("round %d: the push behind the flood was decided before the next share: %v", round, after.err)
			}

			// P0 never waits: the erasures' work issues on arrival, with the flood queued and B draining
			for range 4 {
				ctx := client.IssueP0(world.ctx, "meta-1", sidecar.WriteP0KindErasure, closure)
				ctx = client.IssueP0(ctx, "meta-1", sidecar.WriteP0KindErasure, slotRewrite)
				if class, ok := sidecar.WriteClassOf(ctx); !ok || class != sidecar.WriteClassP0 {
					t.Fatalf("round %d: an erasure's write carries class %v", round, class)
				}
				p0Issued += closure + slotRewrite
			}

			// past the shed delay the heaviest network by queued bytes per weight is refused whole
			world.clock.Advance(world.settings.Budget.ShedDelay)
			synctest.Wait()
			for i, admission := range pros {
				if !admission.isDone() {
					t.Fatalf("round %d: flood push %d is still queued past the shed delay", round, i)
				}
				refusal := &sidecar.WriteRefusal{}
				switch {
				case admission.err == nil:
					proAdmitted += 1
					admission.grant.Close()
				case errors.As(admission.err, &refusal) && int64(refusal.RetryAfterMs()) == world.settings.Budget.RefusalRetryAfter.Milliseconds():
					proRefused += 1
				default:
					t.Fatalf("round %d: a flood push ended %v", round, admission.err)
				}
			}
			if after.isDone() {
				t.Fatalf("round %d: the Community push behind the flood was decided at the shed: %v", round, after.err)
			}

			// the next share admits it
			next = next.Add(world.settings.Budget.Interval)
			world.tickAt(next, busy)
			synctest.Wait()
			if !after.isDone() || after.err != nil {
				t.Fatalf("round %d: the Community push behind the flood after the next share: done %v, %v", round, after.isDone(), after.err)
			}
			after.grant.Close()
			waits = append(waits, after.decided.Sub(after.asked))
		}
		if proAdmitted == 0 || proRefused == 0 {
			t.Fatalf("the flood: %d admitted and %d refused", proAdmitted, proRefused)
		}
		longest := time.Duration(0)
		for _, wait := range waits {
			longest = max(longest, wait)
		}
		if world.settings.Budget.Interval+world.settings.Budget.ShedDelay < longest {
			t.Fatalf("a Community push waited %s", longest)
		}
		if shed := world.host.Metrics.Value("urnetwork_evs_budget_shed_total", "meta-1"); shed != float64(proRefused) {
			t.Errorf("the shed series counts %v, the flood was refused %d times", shed, proRefused)
		}
		if issued := world.host.Metrics.Value("urnetwork_evs_budget_issued_bytes_total", "meta-1", "p0", string(sidecar.WriteP0KindErasure)); issued != float64(p0Issued) {
			t.Errorf("erasure P0 issued %v, asked %d", issued, p0Issued)
		}
		t.Logf("the flood: %d pushes of %d B admitted, %d refused; the longest Community wait %s", proAdmitted, background.ByteCount(), proRefused, longest)
	})
}

// The 26 h world's scale: see the file header.
const (
	fs81IntervalRefill = 100000
	// 2x year one's pushes an interval, scaled with the refill
	fs81ContentPushes = 80
	// the intervals before the governor has seen a report of each process's demand, whose shares it splits evenly
	fs81WarmSteps = 2
)

// One class of format 2's mix: what one push costs, split by when its deferred work comes due, and how many arrive.
type fs81Class struct {
	name string
	// priced units: now, the fold part of the deferred work, due a minute on, and the rest, evacuation's, due 25 h on
	immediate  int64
	fold       int64
	evacuation int64
	// arrivals an interval: count every interval, and one more every extraEvery intervals at extraOffset
	count       int
	extraEvery  int
	extraOffset int
	// what the run did
	wanted, admitted int
	credited         int64
	paidFunded       int64
	paidUncovered    int64
}

func (self *fs81Class) price() int64 {
	return self.immediate + self.fold + self.evacuation
}

// The pushes of the class arriving at step.
func (self *fs81Class) arrivals(step int) int {
	if 0 < self.extraEvery && step%self.extraEvery == self.extraOffset {
		return self.count + 1
	}
	return self.count
}

// A unit of deferred work, due together, and the class whose push it is.
type fs81Work struct {
	class       *fs81Class
	createdStep int
	dueStep     int
	byteCount   int64
}

// One class's price in the world's units from a cost on table and the cost's deferred operations, split into the
// fold's overwrites and evacuation's rest.
func newFs81Class(t *testing.T, name string, table *evsservice.PriceTable, unit float64, operations evsservice.PushOperations) *fs81Class {
	t.Helper()
	price := func(writes []evsservice.WriteOperation) int64 {
		byteCount, err := table.PriceOperations(writes)
		if err != nil {
			t.Fatal(err)
		}
		return int64(math.Round(float64(byteCount) / unit))
	}
	folds, rest := []evsservice.WriteOperation{}, []evsservice.WriteOperation{}
	for _, operation := range operations.Deferred {
		if operation.Kind == evsservice.WriteOperationOverwrite {
			folds = append(folds, operation)
		} else {
			rest = append(rest, operation)
		}
	}
	return &fs81Class{name: name, immediate: price(operations.Immediate), fold: price(folds), evacuation: price(rest)}
}

// See the file header.
type fs81World struct {
	t        *testing.T
	settings *evsservice.WriteBudgetSettings
	clock    *sidecartest.FakeClock
	governor *evsservice.Governor
	oracle   *sidecartest.BudgetOracle
	step     int

	evs        *budgetProcess
	taskworker *budgetProcess
	classes    []*fs81Class
	// P0 at its ordinary rate, priced units an interval, by kind
	p0Arrivals map[sidecar.WriteP0Kind]int64

	funded []*fs81Work
	folds  []*fs81Work

	allowance       *evsservice.WriteBudgetAllowance
	pending         *sidecartest.BudgetOracleEvents
	pendingMeasured int64
	preloaded       int64
	mismatches      []error

	refused       int
	refusedSteps  []int
	foldMaxLag    int
	oldestBatch   time.Duration
	refillPercent float64
}

// The world at steady state: the last 25 h of the mix's evacuation work and its last minute of folds queued, W
// holding their credit, and the bucket full.
func newFs81World(t *testing.T, classes []*fs81Class) *fs81World {
	settings := evsservice.DefaultWriteBudgetSettings()
	settings.RefillDwpd = 0.8
	// r is 20,000 units a second, so an interval's refill is fs81IntervalRefill
	refillPerDay := float64(fs81IntervalRefill) / settings.Interval.Seconds() * 86400
	settings.DriveByteCount = int64(refillPerDay / settings.RefillDwpd)
	depth := int64(float64(fs81IntervalRefill) * time.Hour.Seconds() / settings.Interval.Seconds())
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	world := &fs81World{
		t:          t,
		settings:   settings,
		clock:      clock,
		classes:    classes,
		p0Arrivals: map[sidecar.WriteP0Kind]int64{sidecar.WriteP0KindRevocation: 1000, sidecar.WriteP0KindLog: 1500, sidecar.WriteP0KindErasure: 1500, sidecar.WriteP0KindRotation: 1000},
		pending:    &sidecartest.BudgetOracleEvents{},
	}
	evacuationDelay := int(25 * time.Hour / settings.Interval)
	foldDelay := int(time.Minute / settings.Interval)
	var wallet int64
	for step := 1; step <= evacuationDelay; step += 1 {
		for _, class := range classes {
			if pushes := class.arrivals(step - evacuationDelay); 0 < pushes && 0 < class.evacuation {
				work := &fs81Work{class: class, createdStep: step - evacuationDelay, dueStep: step, byteCount: int64(pushes) * class.evacuation}
				world.funded = append(world.funded, work)
				wallet += work.byteCount
			}
		}
	}
	for step := 1; step <= foldDelay; step += 1 {
		for _, class := range classes {
			if pushes := class.arrivals(step - foldDelay); 0 < pushes && 0 < class.fold {
				work := &fs81Work{class: class, createdStep: step - foldDelay, dueStep: step, byteCount: int64(pushes) * class.fold}
				world.folds = append(world.folds, work)
				wallet += work.byteCount
			}
		}
	}
	world.preloaded = wallet
	world.governor = evsservice.NewGovernor("meta-1", settings, &evsservice.GovernorState{
		Seq: 1, TimeMs: clock.Now().UnixMilli(), BucketByteCount: depth, WalletByteCount: wallet, Calibration: 1,
	})
	oracleSettings := budgetOracleSettings()
	oracleSettings.RefillBytesPerSecond = float64(fs81IntervalRefill) / settings.Interval.Seconds()
	oracleSettings.DepthByteCount = depth
	oracleSettings.WindowSlackByteCount = fs81IntervalRefill
	world.oracle = sidecartest.NewBudgetOracle(oracleSettings, depth, wallet)
	startMs := clock.Now().UnixMilli() + 1
	world.evs = newBudgetProcess("evs-1", startMs)
	world.taskworker = newBudgetProcess("taskworker-1", startMs)
	return world
}

// Each queue's due work and all of it, by rank, for the interval about to run.
func (self *fs81World) fundedRankLevels() (demand []int64, backlog []int64) {
	demand = make([]int64, sidecar.WriteP2RankCount)
	backlog = make([]int64, sidecar.WriteP2RankCount)
	for rank, queue := range map[sidecar.WriteP2Rank][]*fs81Work{sidecar.WriteP2RankEvacuation: self.funded, sidecar.WriteP2RankFold: self.folds} {
		for _, work := range queue {
			backlog[rank] += work.byteCount
			if work.dueStep <= self.step+1 {
				demand[rank] += work.byteCount
			}
		}
	}
	return demand, backlog
}

func (self *fs81World) reports() []*evsservice.WriteBudgetReport {
	reports := []*evsservice.WriteBudgetReport{}
	for _, process := range []*budgetProcess{self.evs, self.taskworker} {
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
			report.UnfundedDemandByteCounts = make([]int64, sidecar.WriteP2RankCount)
			report.UnfundedBacklogByteCounts = make([]int64, sidecar.WriteP2RankCount)
		}
		reports = append(reports, report)
	}
	return reports
}

// One interval: the governor steps on what the drive measured and the reports, the oracle on the same events, and
// then P0 issues, the pushes take evs's share, and evacuation and the folds spend taskworker's.
func (self *fs81World) stepOnce() {
	reports := self.reports()
	self.clock.Advance(self.settings.Interval)
	self.step += 1
	var demand, backlog int64
	demands, backlogs := self.fundedRankLevels()
	for rank := range demands {
		demand += demands[rank]
		backlog += backlogs[rank]
	}
	self.pending.FundedDemandByteCount = demand
	self.pending.FundedBacklogByteCount = backlog
	self.pending.MeasuredByteCount = self.pendingMeasured
	allowance := self.governor.Step(self.clock.Now(), self.pendingMeasured, reports)
	self.oracle.Step(self.pending)
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
	if err := self.oracle.Compare(observed); err != nil {
		self.mismatches = append(self.mismatches, err)
	}
	self.allowance = allowance
	self.pending = &sidecartest.BudgetOracleEvents{P0ByteCounts: map[string]int64{}}
	self.pendingMeasured = 0
	events := self.pending
	share := func(process *budgetProcess) evsservice.WriteBudgetShare {
		if self.allowance.Shares[process.id] == nil {
			return evsservice.WriteBudgetShare{}
		}
		return *self.allowance.Shares[process.id]
	}
	var issued int64

	// P0 on arrival
	for kind, byteCount := range self.p0Arrivals {
		self.evs.p0ByteCounts[kind] += byteCount
		events.P0ByteCounts[string(kind)] += byteCount
		issued += byteCount
	}

	// the pushes, class by class within evs's part of A1: what does not fit is shed (429)
	p1Left := share(self.evs).P1ByteCount
	var queued int64
	for _, class := range self.classes {
		wanted := class.arrivals(self.step)
		admitted := 0
		for admitted < wanted && class.price() <= p1Left {
			admitted += 1
			p1Left -= class.price()
		}
		class.wanted += wanted
		class.admitted += admitted
		if admitted < wanted && fs81WarmSteps < self.step {
			self.refused += wanted - admitted
			if len(self.refusedSteps) == 0 || self.refusedSteps[len(self.refusedSteps)-1] != self.step {
				self.refusedSteps = append(self.refusedSteps, self.step)
			}
		}
		queued += int64(wanted-admitted) * class.price()
		if admitted == 0 {
			continue
		}
		immediate := int64(admitted) * class.immediate
		deferred := int64(admitted) * (class.fold + class.evacuation)
		self.evs.p1ByteCount += immediate
		self.evs.creditByteCount += deferred
		class.credited += deferred
		events.P1ByteCount += immediate
		events.CreditByteCount += deferred
		issued += immediate
		if 0 < class.evacuation {
			self.funded = append(self.funded, &fs81Work{class: class, createdStep: self.step, dueStep: self.step + int(25*time.Hour/self.settings.Interval), byteCount: int64(admitted) * class.evacuation})
		}
		if 0 < class.fold {
			self.folds = append(self.folds, &fs81Work{class: class, createdStep: self.step, dueStep: self.step + int(time.Minute/self.settings.Interval), byteCount: int64(admitted) * class.fold})
		}
	}
	self.evs.queuedByteCount = queued

	// evacuation first, then the folds, from A2 and then from the part of A_U funded work W no longer covers
	taskworkerShare := share(self.taskworker)
	fundedLeft := taskworkerShare.FundedByteCount
	uncoveredLeft := taskworkerShare.UncoveredByteCount
	pay := func(queue []*fs81Work) []*fs81Work {
		for 0 < len(queue) && queue[0].dueStep <= self.step {
			work := queue[0]
			paid := min(work.byteCount, fundedLeft)
			fundedLeft -= paid
			work.byteCount -= paid
			work.class.paidFunded += paid
			self.taskworker.fundedByteCount += paid
			events.FundedByteCount += paid
			uncovered := min(work.byteCount, uncoveredLeft)
			uncoveredLeft -= uncovered
			work.byteCount -= uncovered
			work.class.paidUncovered += uncovered
			self.taskworker.unfundedByteCount += uncovered
			events.UnfundedByteCount += uncovered
			events.UncoveredByteCount += uncovered
			issued += paid + uncovered
			if 0 < work.byteCount {
				break
			}
			queue = queue[1:]
		}
		return queue
	}
	self.funded = pay(self.funded)
	self.folds = pay(self.folds)
	if 0 < len(self.folds) && self.folds[0].dueStep <= self.step {
		self.foldMaxLag = max(self.foldMaxLag, self.step-self.folds[0].dueStep+1)
	}
	if 0 < len(self.funded) {
		self.oldestBatch = max(self.oldestBatch, time.Duration(self.step-self.funded[0].createdStep)*self.settings.Interval)
	}
	events.P1QueuedByteCount = queued
	self.pendingMeasured += issued
	self.refillPercent = max(self.refillPercent, 100*float64(issued)/fs81IntervalRefill)
}

// What the run broke: the governor's figures against the oracle's, FI-14 on the events, and every deferred unit
// paid once.
func (self *fs81World) err() error {
	found := []error{}
	if 0 < len(self.mismatches) {
		found = append(found, fmt.Errorf("%w (and %d more)", self.mismatches[0], len(self.mismatches)-1))
	}
	if err := self.oracle.Err(); err != nil {
		found = append(found, err)
	}
	var queued int64
	for _, work := range append(append([]*fs81Work{}, self.funded...), self.folds...) {
		queued += work.byteCount
	}
	queued += self.pending.FundedByteCount + self.pending.UncoveredByteCount - self.pending.CreditByteCount
	if err := self.oracle.CheckPaidOnce(queued - self.preloaded); err != nil {
		found = append(found, err)
	}
	return errors.Join(found...)
}

// Format 2's mix on table: see the file header.
func fs81Mix(t *testing.T, table *evsservice.PriceTable) []*fs81Class {
	t.Helper()
	rows, err := evsservice.PriceRows(nil)
	if err != nil {
		t.Fatal(err)
	}
	// D-TEST-11's gate is the refill at 2x year one's pushes: 43 KiB a push
	unit := 43 * 1024 * float64(fs81ContentPushes) / fs81IntervalRefill
	row := func(event evsservice.PriceEvent) evsservice.PushOperations {
		found, err := evsservice.PriceRowOf(rows, event)
		if err != nil {
			t.Fatal(err)
		}
		return found.Operations
	}
	join := func(a evsservice.PushOperations, b evsservice.PushOperations) evsservice.PushOperations {
		return evsservice.PushOperations{Immediate: append(append([]evsservice.WriteOperation{}, a.Immediate...), b.Immediate...), Deferred: append(append([]evsservice.WriteOperation{}, a.Deferred...), b.Deferred...)}
	}
	push := row(evsservice.PriceEventDirectoryNoticeRewrite)
	indexed := newFs81Class(t, "indexed", table, unit, join(push, row(evsservice.PriceEventIndexedPush)))
	indexed.count = fs81ContentPushes * 3 / 4
	plain := newFs81Class(t, "git-mode and stream", table, unit, push)
	plain.count = fs81ContentPushes / 4
	// a companion push for each eight content pushes it indexes: 2.5 an interval
	companion := newFs81Class(t, "companion", table, unit, row(evsservice.PriceEventCompanionPush))
	companion.count, companion.extraEvery, companion.extraOffset = 2, 2, 0
	// a roll-up: the expired bucket's removal and the rewritten all files, a push of eight changes, each minute
	rollup := newFs81Class(t, "roll-up", table, unit, join(push, evsservice.PushOperations{
		Deferred: []evsservice.WriteOperation{{Kind: evsservice.WriteOperationOverwrite, Count: 7 * evsservice.DefaultPriceRowSettings().PushFoldShare}},
	}))
	rollup.count, rollup.extraEvery, rollup.extraOffset = 0, 12, 1
	return []*fs81Class{indexed, plain, companion, rollup}
}

// FS-81's 26 h: see the file header. Every clause holds on the real governor at exact prices, beside the oracle.
func TestFs81TwiceYearOnesFormat2MixForTwentySixHours(t *testing.T) {
	classes := fs81Mix(t, evsservice.DefaultPriceTable1KiB())
	world := newFs81World(t, classes)
	for range int(26 * time.Hour / world.settings.Interval) {
		world.stepOnce()
	}
	if err := world.err(); err != nil {
		t.Fatal(err)
	}
	if world.refused != 0 {
		t.Errorf("the budget refused %d pushes", world.refused)
	}
	for _, class := range classes {
		// charged once: every deferred unit it paid came out of W, none from T
		if class.paidUncovered != 0 {
			t.Errorf("%s: %d deferred units paid from T", class.name, class.paidUncovered)
		}
	}
	for _, class := range classes[2:] {
		if class.admitted == 0 || class.paidFunded == 0 {
			t.Errorf("%s: %d pushes admitted, %d deferred units paid from W", class.name, class.admitted, class.paidFunded)
		}
	}
	if fs61FoldBehindSteps <= world.foldMaxLag {
		t.Errorf("a fold waited %d intervals past due: a ref reached FOLD_BEHIND", world.foldMaxLag)
	}
	if 26*time.Hour <= world.oldestBatch {
		t.Errorf("a batch reached %s", world.oldestBatch)
	}
	if dwpd := world.oracle.Dwpd(24*time.Hour, world.settings.DriveByteCount); 0.8 < dwpd {
		t.Errorf("the busiest drive wrote %.3f DWPD over the last 24 h", dwpd)
	}
	for _, class := range classes {
		t.Logf("%-20s %5d units a push (%d now, %d fold, %d evacuation), %d admitted, %d deferred units paid from W", class.name, class.price(), class.immediate, class.fold, class.evacuation, class.admitted, class.paidFunded)
	}
	t.Logf("26 h: oldest batch %s, longest fold wait %d intervals, the busiest interval issued %.1f%% of the refill", world.oldestBatch, world.foldMaxLag, world.refillPercent)
}

// The twin past the refill: the same mix with every content push in-ref indexed and twice the companion pushes, on
// the 4 KiB table, where §11.13 puts format 2 at the gate's edge, outruns T, so the budget refuses pushes, which is
// what FS-81's clause rules out at the mix it names.
func TestFs81AMixPastTheRefillIsRefused(t *testing.T) {
	classes := fs81Mix(t, evsservice.DefaultPriceTable4KiB())
	classes[0].count = fs81ContentPushes
	classes[1].count = 0
	classes[2].count, classes[2].extraEvery = 5, 0
	world := newFs81World(t, classes)
	for range int(time.Hour / world.settings.Interval) {
		world.stepOnce()
	}
	if err := world.err(); err != nil {
		t.Fatal(err)
	}
	if world.refused == 0 {
		t.Fatal("a mix past the refill was admitted whole")
	}
	t.Logf("past the refill: %d pushes refused in an hour", world.refused)
}
