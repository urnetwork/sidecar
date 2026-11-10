package fault

// FS-118 (§22.8, FI-14; §11.6's commit and copy rows; EVSB-M2-16) on T2: path-epoch copies for 7 days of fake clock
// on one metadata cluster, beside FS-61's mix, in FS-117's world (fs117_test.go): the real governor, an oracle
// recomputing every account, and processes modeled as §11.13 says each class spends.
//
// The copy job here is a scaled fake holding §11.6's rules and rates, which the task allows until EVS1's real job
// (evsservice.RunPathEpochCopy) is driven at this scale; nothing here runs that job. Entries and copy limits are
// scaled by 1/100 together, and a scaled move is priced at 100 moves' bytes, so the copies ask the budget for what
// the unscaled load would:
//
//	rates    2.5 moves an interval on the cluster (250 operations a second), up to 10 while the governor finds A1
//	         left a quarter of T unspent over the last minute (1,000); 0.5 a ref's repo (50), 1.5 while it holds two
//	         or more sources (150); all of it within the copies' part of A_U
//	order    the ref holding the most sources first, then the one with the oldest source
//	sources  a cut-over lists the old epoch as a source and gives the newest map's moves, 3 an entry; they empty
//	         together when those moves are made; at most 3: a fourth is refused (EPOCH_SOURCES_FULL), a batched
//	         epoch waits while two stand, covering every expiry due when it lands, and an immediate one takes the
//	         third
//
// §19.8's copy liability, drain time, deferrals and source counts are read from the model and from the oracle's own
// ledger of the same events, and compared each interval.

import (
	"fmt"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	// a scaled move's price: 100 moves at ~12% of a unit each, so the planned load asks ~7% of r
	copyMovePrice = 12
	// moves an entry's copy makes (§22.8: live entries times epochs times 3)
	copyMovesPerEntry = 3
	// §11.6's rates, scaled by 1/100, in moves an interval
	copyRepoRate      = 0.5 * 5
	copyRepoBusyRate  = 1.5 * 5
	copyStepsPerDay   = 24 * budgetStepsPerHour
	copyThreeSourceOk = 10 * 60 / 5
)

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
	// when its batched epoch falls due each day, and its immediate one every other day, as steps into the day;
	// negative for none
	batchedOffset   int
	immediateOffset int
	// the step it came to hold three sources
	threeSince int
}

// See the file header.
type copyModel struct {
	refs []*copyRef
	// the cluster's moves carried between intervals as a fraction
	credit float64
	// moves made in each interval, for the drain rate
	intervalMoveCounts []int64

	// what the clauses read
	sourcesFullCount    int
	deferredCount       int
	longestSourceSteps  int
	longestThreeSteps   int
	immediateThirdCount int
	// an immediate epoch that took a third source, and whether its ref's copy ran first in the same interval
	immediateRanFirst bool
	gaugeMismatch     error
}

// Commits a PATH_EPOCH on ref at step: the old epoch joins the sources and the newest map's moves replace what was
// left.
func (self *copyModel) cutOver(world *budgetWorld, ref *copyRef) {
	ref.sources = append(ref.sources, world.step)
	ref.moveCount = ref.entries * copyMovesPerEntry
	ref.deferred = false
	if len(ref.sources) == 3 {
		ref.threeSince = world.step
	}
	world.oracle.CopyCutOver(ref.name, ref.moveCount)
}

// One interval of copies within budgetLeft priced units: the epochs that fall due, then the moves. It sets the
// world's unfunded levels and answers the priced units issued.
func (self *copyModel) step(world *budgetWorld, budgetLeft int64) int64 {
	dayStep := world.step % copyStepsPerDay
	day := world.step / copyStepsPerDay
	var immediateThird *copyRef
	for _, ref := range self.refs {
		if ref.immediateOffset == dayStep && day%2 == 0 {
			// an immediate epoch commits at once, onto the third source if two stand; a fourth is refused
			if 3 <= len(ref.sources) {
				self.sourcesFullCount += 1
			} else {
				if len(ref.sources) == 2 {
					self.immediateThirdCount += 1
					immediateThird = ref
				}
				self.cutOver(world, ref)
			}
		}
		if ref.batchedOffset == dayStep {
			ref.deferred = true
		}
		if ref.deferred {
			// a batched epoch waits while two sources stand, with no block and no map built meanwhile, and
			// covers every expiry due when it lands
			if 2 <= len(ref.sources) {
				self.deferredCount += 1
				world.oracle.CopyDeferred(ref.name)
			} else {
				self.cutOver(world, ref)
			}
		}
	}

	// the cluster's rate, as the governor published it, and the copies' part of A_U
	clusterRate := 2.5
	if world.allowance != nil {
		clusterRate = float64(world.allowance.CopyOpsPerSecond) / 100 * world.settings.Interval.Seconds()
	}
	self.credit = math.Min(self.credit+clusterRate, clusterRate+1)
	movesLeft := int64(math.Min(self.credit, float64(budgetLeft/copyMovePrice)))

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
	if immediateThird != nil {
		self.immediateRanFirst = 0 < len(working) && working[0] == immediateThird
	}
	var moved int64
	for _, ref := range working {
		rate := copyRepoRate
		if 2 <= len(ref.sources) {
			rate = copyRepoBusyRate
		}
		ref.credit = math.Min(ref.credit+rate, rate+1)
		moves := min(ref.moveCount, int64(ref.credit), movesLeft-moved)
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
			if 3 <= len(ref.sources) {
				self.longestThreeSteps = max(self.longestThreeSteps, world.step-ref.threeSince)
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
			rate := copyRepoRate
			if 2 <= len(ref.sources) {
				rate = copyRepoBusyRate
			}
			demand += math.Min(float64(ref.moveCount), rate)
		}
		if 3 <= len(ref.sources) {
			self.longestThreeSteps = max(self.longestThreeSteps, world.step-ref.threeSince)
		}
	}
	world.unfundedBacklog = int64(liability) * copyMovePrice
	world.unfundedDemand = int64(math.Min(demand, clusterRate)) * copyMovePrice
	if self.gaugeMismatch == nil {
		self.gaugeMismatch = self.compareGauges(world)
	}
	return moved * copyMovePrice
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
			gauges.SourceCounts[min(len(ref.sources), 3)] += 1
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
	gauges.Warn = (24 * time.Hour).Seconds() < gauges.DrainSeconds
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
// batched epoch falls due daily, and an immediate one every other day on a third of them: 108,000 scaled moves a
// day, half the cluster's 216,000, and 36,000 more on the immediate epochs' days.
func newCopyWorld(t *testing.T) (*budgetWorld, *copyModel) {
	world := newBudgetWorldWithFolds(t, 0.8, 8, 20)
	world.setP0(50)
	copies := &copyModel{}
	for i := 0; i < 360; i += 1 {
		ref := &copyRef{name: fmt.Sprintf("ref-%03d", i), entries: 100, batchedOffset: i * copyStepsPerDay / 360, immediateOffset: -1}
		if i%3 == 0 {
			// half a day off its batched epoch, so the two meet only when a copy runs long
			ref.immediateOffset = (ref.batchedOffset + copyStepsPerDay/2) % copyStepsPerDay
		}
		copies.refs = append(copies.refs, ref)
	}
	world.copies = copies
	return world, copies
}

// The planned load for 7 days: each source empties within 30 h of its cut-over, no ref holds three sources 10 min,
// no PATH_EPOCH meets EPOCH_SOURCES_FULL, no batched epoch waits, the copies stay within A_U, P1's admission is
// unchanged, and the copy figures equal the oracle's with no drain warning.
func TestFs118PlannedCopyLoadForSevenDays(t *testing.T) {
	world, copies := newCopyWorld(t)
	intervals := world.run(7 * copyStepsPerDay)
	if err := world.err(); err != nil {
		t.Fatal(err)
	}
	if copies.gaugeMismatch != nil {
		t.Error(copies.gaugeMismatch)
	}
	longest := time.Duration(copies.longestSourceSteps) * world.settings.Interval
	t.Logf("longest source %s; EPOCH_SOURCES_FULL %d; batched epochs deferred %d intervals; three sources at most %s", longest,
		copies.sourcesFullCount, copies.deferredCount, time.Duration(copies.longestThreeSteps)*world.settings.Interval)
	if 30*time.Hour < longest {
		t.Errorf("a source stood %s after its cut-over, past 30 h", longest)
	}
	if copyThreeSourceOk <= copies.longestThreeSteps {
		t.Errorf("a ref held three sources %s", time.Duration(copies.longestThreeSteps)*world.settings.Interval)
	}
	if copies.sourcesFullCount != 0 || copies.deferredCount != 0 {
		t.Errorf("EPOCH_SOURCES_FULL %d times, batched epochs waited %d intervals", copies.sourcesFullCount, copies.deferredCount)
	}
	var copied int64
	for i, interval := range intervals {
		// the first shares are split before any process has reported demand
		if 2 < i && interval.pushesAdmitted != interval.pushesWanted {
			t.Fatalf("interval %d admitted %d of %d pushes beside the copies", i, interval.pushesAdmitted, interval.pushesWanted)
		}
		if interval.allowance.UnfundedByteCount < interval.unfundedIssued {
			t.Fatalf("interval %d: copies issued %d past A_U %d", i, interval.unfundedIssued, interval.allowance.UnfundedByteCount)
		}
		if 26*time.Hour < interval.oldestBatchAge {
			t.Fatalf("interval %d: the oldest batch is %s old beside the copies", i, interval.oldestBatchAge)
		}
		copied += interval.unfundedIssued
	}
	// seven days of the planned load were made, less what stands at the end: a batched epoch a day on each of 360
	// refs, and an immediate one on a third of them on each of the four even days
	planned := int64(7*360+4*120) * 100 * copyMovesPerEntry * copyMovePrice
	if copied < planned*97/100 || planned < copied {
		t.Errorf("copies issued %d of the planned %d", copied, planned)
	}
	if gauges := copies.gauges(world); gauges.Warn {
		t.Errorf("the drain warning stands at the planned load: %+v", *gauges)
	}
}

// Then 30 one-million-entry refs, 10,000 scaled, with a batched epoch due daily each: a copy outlasts its day, so
// batched epochs wait while two sources stand, with no block and nothing refused, and no ref reaches a fourth
// source; an immediate epoch on such a ref commits at once onto its third source and its copy runs first; P1's
// admission is unchanged, the copies stay within A_U, and §19.8's drain time warns past 24 h.
func TestFs118MillionEntryRefsDeferBatchedEpochs(t *testing.T) {
	world, copies := newCopyWorld(t)
	world.run(copyStepsPerDay)
	large := []*copyRef{}
	for i := 0; i < 30; i += 1 {
		ref := &copyRef{name: fmt.Sprintf("large-%02d", i), entries: 10000, batchedOffset: i * copyStepsPerDay / 30, immediateOffset: -1}
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
	run(3 * copyStepsPerDay)
	if copies.deferredCount == 0 {
		t.Error("no batched epoch waited, though copies outlast their day")
	}
	if !warned {
		t.Error("the drain time never warned past 24 h")
	}
	// an immediate epoch on a ref holding two sources: it commits at once onto the third, and its copy runs first
	var twoSources *copyRef
	for _, ref := range large {
		if len(ref.sources) == 2 {
			twoSources = ref
			break
		}
	}
	if twoSources == nil {
		t.Fatal("no large ref holds two sources after three days")
	}
	before := copies.immediateThirdCount
	twoSources.immediateOffset = (world.step + 1) % copyStepsPerDay
	if ((world.step+1)/copyStepsPerDay)%2 != 0 {
		// immediate epochs fall on even days: wait for the next
		run(copyStepsPerDay)
		twoSources.immediateOffset = (world.step + 1) % copyStepsPerDay
		for len(twoSources.sources) != 2 {
			run(1)
			twoSources.immediateOffset = (world.step + 1) % copyStepsPerDay
		}
	}
	run(1)
	if copies.immediateThirdCount != before+1 || len(twoSources.sources) != 3 || !copies.immediateRanFirst {
		t.Errorf("the immediate epoch: took a third source %t, %d sources, ran first %t", copies.immediateThirdCount == before+1, len(twoSources.sources), copies.immediateRanFirst)
	}
	twoSources.immediateOffset = -1
	run(2 * copyStepsPerDay)

	if err := world.err(); err != nil {
		t.Fatal(err)
	}
	if copies.gaugeMismatch != nil {
		t.Error(copies.gaugeMismatch)
	}
	// nothing was refused or blocked: a batched epoch only waits, and no ref reached a fourth source
	if copies.sourcesFullCount != 0 || 3 < maxSources {
		t.Errorf("EPOCH_SOURCES_FULL %d times, a ref at %d sources", copies.sourcesFullCount, maxSources)
	}
	gauges := copies.gauges(world)
	t.Logf("after six days: liability %d moves, drain %.0f h, %d refs deferring, sources %v; batched epochs deferred %d intervals",
		gauges.LiabilityMoveCount, gauges.DrainSeconds/3600, gauges.DeferredCount, gauges.SourceCounts, copies.deferredCount)
}
