package fault

// FS-118 (§22.8, FI-14; §11.6's commit and copy rows; EVSB-M2-16) on T2: path-epoch copies for 7 days of fake clock
// on one metadata cluster, beside FS-61's mix, in FS-117's world (fs117_test.go): the real governor, an oracle
// recomputing every account, and processes modeled as §11.13 says each class spends.
//
// The copy job here is a scaled fake holding §11.6's rules and rates, which the task allows until EVS1's real job
// (evsservice.RunPathEpochCopy) is driven at this scale; nothing here runs that job. Entries and copy limits are
// scaled by 1/100 together, and a scaled move is priced at 100 moves' bytes, so the copies ask the budget for what
// the unscaled load would (copyModelSettings holds the figures):
//
//	rates    2.5 moves an interval on the cluster (250 operations a second), up to 10 while the governor finds A1
//	         left a quarter of T unspent over the last minute (1,000); 0.5 a ref's repo (50), 1.5 while it holds two
//	         or more sources (150); all of it within the copies' part of A_U
//	order    the ref holding the most sources first, then the one with the oldest source
//	sources  a cut-over lists the old epoch as a source and gives the newest map's moves, 3 an entry; they empty
//	         together when those moves are made; at most 2: every epoch is batched (QD-1046) and waits while two
//	         stand, covering every expiry due when it lands, so none takes a third
//
// §19.8's copy liability, drain time, deferrals and source counts are read from the model and from the oracle's own
// ledger of the same events, and compared each interval.
//
// The planned load for 7 days is the row's registered case (Fs118Case; QD-1084), a schedule a step each for the
// world's start, every hour of the week and the run's clauses, which TestFs118 runs under every rule §22.8 gives the
// row, FI-14 checked after every step as the world reads it (FI-14/fs118), FI-14's own oracle binding being
// EVSB-M2-16's. The world runs on a fake clock of its own and touches no store and no barrier, so the explorer takes
// its short form, one seed (QD-1151). The row's FI-1 and FI-6 wait on EVS1's real copy job at this scale, which no
// run here drives. The million-entry refs stay a plain test: a clause registers from a non-test file
// (register_clause.go), and this world is a test file's.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The copy model's figures: §11.6's rates and a move's price, scaled by 1/100 with the entries (see the file header).
type copyModelSettings struct {
	// A scaled move's price in the world's units: 100 moves at about 12% of a unit each, so the planned load asks about
	// 7% of r. 12.
	MovePriceByteCount int64
	// Moves an entry's copy makes (§22.8: live entries times epochs times 3). 3.
	EntryMoveCount int64
	// §11.6's rate on a ref's repo, scaled, in moves an interval: 0.5 a second, 2.5.
	RepoMovesPerInterval float64
	// The same while the ref holds BusySourceCount sources or more: 1.5 a second, 7.5.
	RepoBusyMovesPerInterval float64
	// Sources a ref holds from which its repo moves at the busy rate. 2.
	BusySourceCount int
	// The cluster's rate while no allowance has published one, in moves an interval: 250 operations a second, 2.5.
	ClusterMovesPerInterval float64
	// Unscaled operations a scaled move stands for, which the governor's published rate is divided by. 100.
	ScaleCount int64
	// How many moves past one interval's rate a rate's credit carries into the next. 1.
	CarryMoveCount float64
	// Sources a ref holds at which a batched epoch due on it waits (QD-1046). 2.
	SourceMaxCount int
	// The intervals in a day, when each ref's batched epoch falls due once: 24 h of the world's 5 s intervals.
	DayStepCount int
	// §19.8's drain time past which the copy gauges warn. 24 h.
	DrainWarnAfter time.Duration
}

func defaultCopyModelSettings() *copyModelSettings {
	return &copyModelSettings{
		MovePriceByteCount:       12,
		EntryMoveCount:           3,
		RepoMovesPerInterval:     0.5 * 5,
		RepoBusyMovesPerInterval: 1.5 * 5,
		BusySourceCount:          2,
		ClusterMovesPerInterval:  2.5,
		ScaleCount:               100,
		CarryMoveCount:           1,
		SourceMaxCount:           2,
		DayStepCount:             24 * budgetStepsPerHour,
		DrainWarnAfter:           24 * time.Hour,
	}
}

// One ref with a rotating path epoch, in a repo of its own.
type copyRef struct {
	name    string
	entries int64
	// each standing source's cut-over step, oldest first
	sources []int
	// the newest map's moves still to make
	moveCount int64
	// what this ref's repo may still move, carried between intervals as a fraction
	credit float64
	// a batched epoch is due and waiting
	deferred bool
	// when its batched epoch falls due each day, as steps into the day
	batchedOffset int
}

// See the file header.
type copyModel struct {
	settings *copyModelSettings
	refs     []*copyRef
	// the cluster's moves carried between intervals as a fraction
	credit float64
	// moves made in each interval, for the drain rate
	intervalMoveCounts []int64

	// what the clauses read
	deferredCount      int
	longestSourceSteps int
	gaugeMismatch      error

	// the mutant: every move standing made at once, whatever the rates and A_U leave
	mutantUnbounded bool
}

// The rate a ref's repo moves at: its busy rate while it holds two or more sources.
func (self *copyModel) repoRate(ref *copyRef) float64 {
	if self.settings.BusySourceCount <= len(ref.sources) {
		return self.settings.RepoBusyMovesPerInterval
	}
	return self.settings.RepoMovesPerInterval
}

// Commits a PATH_EPOCH on ref at step: the old epoch joins the sources and the newest map's moves replace what was
// left.
func (self *copyModel) cutOver(world *budgetWorld, ref *copyRef) {
	ref.sources = append(ref.sources, world.step)
	ref.moveCount = ref.entries * self.settings.EntryMoveCount
	ref.deferred = false
	world.oracle.CopyCutOver(ref.name, ref.moveCount)
}

// One interval of copies within budgetLeft priced units: the epochs that fall due, then the moves. It sets the
// world's unfunded levels and answers the priced units issued.
func (self *copyModel) step(world *budgetWorld, budgetLeft int64) int64 {
	settings := self.settings
	dayStep := world.step % settings.DayStepCount
	for _, ref := range self.refs {
		if ref.batchedOffset == dayStep {
			ref.deferred = true
		}
		if ref.deferred {
			// a batched epoch waits while two sources stand, with no block and no map built meanwhile, and
			// covers every expiry due when it lands
			if settings.SourceMaxCount <= len(ref.sources) {
				self.deferredCount += 1
				world.oracle.CopyDeferred(ref.name)
			} else {
				self.cutOver(world, ref)
			}
		}
	}

	// the cluster's rate, as the governor published it, and the copies' part of A_U
	clusterRate := settings.ClusterMovesPerInterval
	if world.allowance != nil {
		clusterRate = float64(world.allowance.CopyOpsPerSecond) / float64(settings.ScaleCount) * world.settings.Interval.Seconds()
	}
	self.credit = math.Min(self.credit+clusterRate, clusterRate+settings.CarryMoveCount)
	movesLeft := int64(math.Min(self.credit, float64(budgetLeft/settings.MovePriceByteCount)))

	// jobs whose ref holds the most sources first, then the one with the oldest source
	working := []*copyRef{}
	for _, ref := range self.refs {
		if 0 < ref.moveCount {
			working = append(working, ref)
		}
	}
	slices.SortStableFunc(working, func(a *copyRef, b *copyRef) int {
		if len(a.sources) != len(b.sources) {
			return len(b.sources) - len(a.sources)
		}
		return a.sources[0] - b.sources[0]
	})
	var moved int64
	for _, ref := range working {
		rate := self.repoRate(ref)
		ref.credit = math.Min(ref.credit+rate, rate+settings.CarryMoveCount)
		moves := min(ref.moveCount, int64(ref.credit), movesLeft-moved)
		if self.mutantUnbounded {
			moves = ref.moveCount
		}
		if moves <= 0 {
			continue
		}
		ref.credit -= float64(moves)
		ref.moveCount -= moves
		moved += moves
		world.oracle.CopyMoved(ref.name, moves)
		if ref.moveCount == 0 {
			// every source is empty: a fence write drops them
			for _, cutOverStep := range ref.sources {
				self.longestSourceSteps = max(self.longestSourceSteps, world.step-cutOverStep)
			}
			ref.sources = nil
		}
	}
	self.credit -= float64(moved)
	self.intervalMoveCounts = append(self.intervalMoveCounts, moved)
	world.oracle.CopyEndInterval()

	// the levels the next report carries: all the moves left, and what the rates let the next interval make
	var liability, demand float64
	for _, ref := range self.refs {
		liability += float64(ref.moveCount)
		if 0 < ref.moveCount {
			demand += math.Min(float64(ref.moveCount), self.repoRate(ref))
		}
	}
	world.unfundedBacklog = int64(liability) * settings.MovePriceByteCount
	world.unfundedDemand = int64(math.Min(demand, clusterRate)) * settings.MovePriceByteCount
	if self.gaugeMismatch == nil {
		self.gaugeMismatch = self.compareGauges(world)
	}
	return moved * settings.MovePriceByteCount
}

// §19.8's copy figures from the model's own state.
func (self *copyModel) gauges(world *budgetWorld) *sidecartest.BudgetOracleCopyGauges {
	gauges := &sidecartest.BudgetOracleCopyGauges{}
	for _, ref := range self.refs {
		gauges.LiabilityMoveCount += ref.moveCount
		if ref.deferred {
			gauges.DeferredCount += 1
		}
		if 0 < len(ref.sources) || 0 < ref.moveCount || ref.deferred {
			gauges.SourceCounts[min(len(ref.sources), len(gauges.SourceCounts)-1)] += 1
		}
	}
	count := min(len(self.intervalMoveCounts), budgetStepsPerHour)
	var moved int64
	for _, moveCount := range self.intervalMoveCounts[len(self.intervalMoveCounts)-count:] {
		moved += moveCount
	}
	switch {
	case gauges.LiabilityMoveCount == 0:
	case moved == 0:
		gauges.DrainSeconds = math.Inf(1)
	default:
		gauges.DrainSeconds = float64(gauges.LiabilityMoveCount) * float64(count) * world.settings.Interval.Seconds() / float64(moved)
	}
	gauges.Warn = self.settings.DrainWarnAfter.Seconds() < gauges.DrainSeconds
	return gauges
}

// The model's copy figures against the oracle's ledger of the same events.
func (self *copyModel) compareGauges(world *budgetWorld) error {
	model, oracle := self.gauges(world), world.oracle.CopyGauges()
	// the ledger knows only refs that had an event, so refs holding nothing are not compared
	model.SourceCounts[0], oracle.SourceCounts[0] = 0, 0
	drainEqual := model.DrainSeconds == oracle.DrainSeconds || math.Abs(model.DrainSeconds-oracle.DrainSeconds) < 1e-6*math.Max(1, oracle.DrainSeconds)
	if model.LiabilityMoveCount != oracle.LiabilityMoveCount || model.DeferredCount != oracle.DeferredCount ||
		model.SourceCounts != oracle.SourceCounts || !drainEqual || model.Warn != oracle.Warn {
		return fmt.Errorf("step %d: copy figures %+v, and the oracle's %+v", world.step, *model, *oracle)
	}
	return nil
}

// A world of FS-61's mix with the planned copy load: 360 refs of 100 entries (36,000 scaled, 3.6M unscaled) whose
// epoch falls due daily, every epoch being batched (QD-1046): 108,000 scaled moves a day, half the cluster's 216,000.
// For a schedule, which has no test of its own.
func newCopyWorldOf(settings *copyModelSettings) (*budgetWorld, *copyModel) {
	world := newBudgetWorldOf(0.8, 8, 20)
	world.setP0(50)
	copies := &copyModel{settings: settings}
	for i := 0; i < 360; i += 1 {
		copies.refs = append(copies.refs, &copyRef{name: fmt.Sprintf("ref-%03d", i), entries: 100, batchedOffset: i * settings.DayStepCount / 360})
	}
	world.copies = copies
	return world, copies
}

// newCopyWorldOf's world on the defaults, for a test.
func newCopyWorld(t *testing.T) (*budgetWorld, *copyModel) {
	world, copies := newCopyWorldOf(defaultCopyModelSettings())
	world.t = t
	return world, copies
}

// The planned load's clauses over intervals from index first on, each interval's: P1's admission unchanged beside the
// copies once the first shares are split, the copies within A_U, and no batch older than 26 h.
func copyIntervalsErr(intervals []*budgetInterval, first int) error {
	for i := first; i < len(intervals); i += 1 {
		interval := intervals[i]
		// the first shares are split before any process has reported demand
		if 2 < i && interval.pushesAdmitted != interval.pushesWanted {
			return fmt.Errorf("interval %d admitted %d of %d pushes beside the copies", i, interval.pushesAdmitted, interval.pushesWanted)
		}
		if interval.allowance.UnfundedByteCount < interval.unfundedIssued {
			return fmt.Errorf("interval %d: copies issued %d past A_U %d", i, interval.unfundedIssued, interval.allowance.UnfundedByteCount)
		}
		if 26*time.Hour < interval.oldestBatchAge {
			return fmt.Errorf("interval %d: the oldest batch is %s old beside the copies", i, interval.oldestBatchAge)
		}
	}
	return nil
}

// The planned load's clauses over its days: each source emptied within 30 h of its cut-over, no batched epoch waited,
// the days' planned copies made less what stands at the end, and no drain warning at the planned load.
func copyPlannedLoadErr(world *budgetWorld, copies *copyModel, intervals []*budgetInterval, days int) error {
	found := []error{}
	longest := time.Duration(copies.longestSourceSteps) * world.settings.Interval
	if 30*time.Hour < longest {
		found = append(found, fmt.Errorf("a source stood %s after its cut-over, past 30 h", longest))
	}
	if copies.deferredCount != 0 {
		found = append(found, fmt.Errorf("batched epochs waited %d intervals", copies.deferredCount))
	}
	// an epoch a day on each ref
	var planned, copied int64
	for _, ref := range copies.refs {
		planned += int64(days) * ref.entries * copies.settings.EntryMoveCount * copies.settings.MovePriceByteCount
	}
	for _, interval := range intervals {
		copied += interval.unfundedIssued
	}
	if copied < planned*97/100 || planned < copied {
		found = append(found, fmt.Errorf("copies issued %d of the planned %d", copied, planned))
	}
	if gauges := copies.gauges(world); gauges.Warn {
		found = append(found, fmt.Errorf("the drain warning stands at the planned load: %+v", *gauges))
	}
	return errors.Join(found...)
}

// The planned load for 7 days, FS-118's registered case: each source empties within 30 h of its cut-over, no batched
// epoch waits, the copies stay within A_U, P1's admission is unchanged, and the copy figures equal the oracle's with
// no drain warning.
var Fs118Case = Register("FS-118", "", []Tier{TierT2}, fs118PlannedCopyLoad(nil))

// The planned load's builder: a step for the world's start, one for each hour of the 7 days, and one for the run's
// clauses, mutate applied to each run's world before its first hour where not nil.
func fs118PlannedCopyLoad(mutate func(world *budgetWorld, copies *copyModel)) Builder {
	return func(net *Net) *Schedule {
		const days = 7
		settings := defaultCopyModelSettings()
		var world *budgetWorld
		var copies *copyModel
		var intervals []*budgetInterval
		governor := func(action func() error) *Step {
			return &Step{Actor: "governor", Action: func(ctx context.Context, net *Net) error { return action() }}
		}
		steps := []*Step{governor(func() error {
			world, copies = newCopyWorldOf(settings)
			if mutate != nil {
				mutate(world, copies)
			}
			return nil
		})}
		for range days * settings.DayStepCount / budgetStepsPerHour {
			steps = append(steps, governor(func() error {
				first := len(intervals)
				intervals = append(intervals, world.run(budgetStepsPerHour)...)
				return copyIntervalsErr(intervals, first)
			}))
		}
		steps = append(steps, governor(func() error {
			return copyPlannedLoadErr(world, copies, intervals, days)
		}))
		return &Schedule{
			Steps: steps,
			Check: []Invariant{NewInvariant("FI-14/fs118", func(ctx context.Context, oracle *Oracle) error {
				if world == nil {
					return nil
				}
				return errors.Join(world.err(), copies.gaugeMismatch)
			})},
		}
	}
}

func TestFs118(t *testing.T) {
	RunRow(t, "FS-118", "", nil)
}

// The registered case fails what its world breaks: a copy figure the oracle disagrees with fails FI-14's check at the
// step that left it, and a mutant making every move standing at once, whatever the rates and A_U leave, fails the hour
// it issues past A_U in.
func TestFs118CaseFailsWhatItsWorldBreaks(t *testing.T) {
	for _, planted := range []struct {
		name   string
		mutate func(world *budgetWorld, copies *copyModel)
		wants  []string
		step   int
	}{
		{
			name: "a copy figure mismatch",
			mutate: func(world *budgetWorld, copies *copyModel) {
				copies.gaugeMismatch = errors.New("a planted copy figure mismatch")
			},
			wants: []string{"a planted copy figure mismatch"},
			step:  0,
		},
		{
			name:   "copies past A_U",
			mutate: func(world *budgetWorld, copies *copyModel) { copies.mutantUnbounded = true },
			wants:  []string{"past A_U", "FI-14/fs118"},
			step:   1,
		},
	} {
		func() {
			net := sidecartest.NewNet(t.Context(), nil)
			defer net.Close()
			schedule := fs118PlannedCopyLoad(planted.mutate)(net)
			schedule.Id = "FS-118 " + planted.name
			result := Run(t.Context(), schedule, net)
			if result.Err == nil || !slices.ContainsFunc(planted.wants, func(want string) bool { return strings.Contains(result.Err.Error(), want) }) {
				t.Errorf("%s: %s", planted.name, result)
				return
			}
			if result.FailedStep != planted.step {
				t.Errorf("%s failed the run at step %d, not at the step that left it, %d", planted.name, result.FailedStep, planted.step)
			}
		}()
	}
}

// Then 30 one-million-entry refs, 10,000 scaled, with a batched epoch due daily each: a copy outlasts its day, so
// batched epochs wait while two sources stand, with no block and nothing refused, and no ref reaches a third source,
// every epoch being batched (QD-1046); P1's admission is unchanged, the copies stay within A_U, and §19.8's drain time
// warns past 24 h.
func TestFs118MillionEntryRefsDeferBatchedEpochs(t *testing.T) {
	world, copies := newCopyWorld(t)
	dayStepCount := copies.settings.DayStepCount
	world.run(dayStepCount)
	large := []*copyRef{}
	for i := 0; i < 30; i += 1 {
		ref := &copyRef{name: fmt.Sprintf("large-%02d", i), entries: 10000, batchedOffset: i * dayStepCount / 30}
		large = append(large, ref)
		copies.refs = append(copies.refs, ref)
	}
	warned := false
	maxSources := 0
	run := func(count int) {
		for range count {
			interval := world.stepOnce()
			if 2 < len(world.intervals) && interval.pushesAdmitted != interval.pushesWanted {
				t.Fatalf("step %d admitted %d of %d pushes beside the copies", world.step, interval.pushesAdmitted, interval.pushesWanted)
			}
			if interval.allowance.UnfundedByteCount < interval.unfundedIssued {
				t.Fatalf("step %d: copies issued %d past A_U %d", world.step, interval.unfundedIssued, interval.allowance.UnfundedByteCount)
			}
			warned = warned || copies.gauges(world).Warn
			for _, ref := range large {
				maxSources = max(maxSources, len(ref.sources))
			}
		}
	}
	run(3 * dayStepCount)
	if copies.deferredCount == 0 {
		t.Error("no batched epoch waited, though copies outlast their day")
	}
	if !warned {
		t.Error("the drain time never warned past 24 h")
	}
	if copies.settings.SourceMaxCount != maxSources {
		t.Errorf("after three days the large refs hold %d sources at most, not the %d a deferral waits on", maxSources, copies.settings.SourceMaxCount)
	}
	run(2 * dayStepCount)

	if err := world.err(); err != nil {
		t.Fatal(err)
	}
	if copies.gaugeMismatch != nil {
		t.Error(copies.gaugeMismatch)
	}
	// nothing was refused or blocked: a batched epoch only waits, and no ref reached a third source
	if copies.settings.SourceMaxCount < maxSources {
		t.Errorf("a ref at %d sources", maxSources)
	}
	gauges := copies.gauges(world)
	t.Logf("after six days: liability %d moves, drain %.0f h, %d refs deferring, sources %v; batched epochs deferred %d intervals",
		gauges.LiabilityMoveCount, gauges.DrainSeconds/3600, gauges.DeferredCount, gauges.SourceCounts, copies.deferredCount)
}
