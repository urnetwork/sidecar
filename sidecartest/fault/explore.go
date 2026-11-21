// §22.8's explorer: each schedule also runs under seeded barrier orders, 10 seeds a merge for a T2 row
// and 100 a night for a T3 one, checking its invariants after every step as any run does. A failing
// seed writes its trace beside the repository's other seeds, where Replay makes it a fixed schedule
// that runs from then on. The trace is kept and not the seed alone, since a goroutine no actor owns
// runs free and a seed may not order it the same way twice.
//
// Nothing here retries: a seed that failed once is a failure, whatever a second run of it would do
// (R-TEST-9). And a seed that passes proves only the orders it reached, so a report says how many seeds
// ran, never that there is no race.
//
// After a fixed run, CheckRow and CheckClause take the short form where a seed has nothing to order
// (QD-1151). A seed chooses only through the seeded baton: whether an actor passing a barrier yields, the
// order a Release step lets its sites go, and which of the actors waiting for the baton together takes
// it. Actors wait together only beside an action that outlives its step, a Background step's or one
// parked by the fault its step ended on, or beside runs an action starts and waits on with the baton
// given up, as EvsWorld's duplicate push does. So when the fixed run passed with no barrier event in its
// trace, its schedule has no Background step and no step ending when its fault fires, and the baton moved
// only as each step's action began, every seed takes the fixed run's order and can find nothing it did
// not. The first seed runs, and if it passes in that same order the rest do not, the report saying so
// ("no barrier passed: every seed takes this order"). Anything else runs every seed, as before. Without
// sidecar_testhooks no barrier in sidecar's own code reaches the driver, so far more schedules take the
// short form on that build than on the gate's.

package fault

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/sidecartest"
)

// What the rules across runs run with.
type RuleSettings struct {
	// The tier the runs are on, for reports: T2, or T3 when Net's Engines are server's (sidecart3).
	// Empty is T2.
	Tier Tier
	// Each run's Net. Its barriers' AwaitTimeout is §22.8's 60 s, and CheckRow refuses a longer one:
	// a slow row is fixed, never given more time. Its Engines decide the tier: nil is T2's fakes, and
	// server's sidecart3 sets T3's.
	Net *sidecartest.NetSettings
	// The explorer's seeds: MergeSeeds for a T2 row, NightlySeeds for a T3 one.
	Seeds []int64
	// Where traces are written and read. Empty: testdata/fault/seeds in the repository above the
	// working directory, found as SeedsDirectory says.
	SeedsDirectory string
	// Whether a failing seed writes its trace there.
	WriteTraces bool
}

func DefaultRuleSettings() *RuleSettings {
	return &RuleSettings{
		Net:         sidecartest.DefaultNetSettings(),
		Seeds:       MergeSeeds(),
		WriteTraces: true,
	}
}

// §22.8's seeds for a T2 row at each merge: 1 to 10.
func MergeSeeds() []int64 {
	return seedRange(10)
}

// §22.8's seeds for a T3 row each night: 1 to 100.
func NightlySeeds() []int64 {
	return seedRange(100)
}

func seedRange(count int) []int64 {
	seeds := make([]int64, 0, count)
	for seed := range int64(count) {
		seeds = append(seeds, seed+1)
	}
	return seeds
}

// What the explorer ran and found.
type ExploreReport struct {
	Id string
	// Every seed run, passing or not.
	Seeds []int64
	// The explorer took its short form (QD-1151; the file header): nothing in the fixed run left a seed
	// anything to order, and the first seed passed in the fixed run's order, so that seed ran alone.
	OneOrder bool
	// Each failing seed's result, with its trace.
	Failures []*Result
	// The trace file each failure wrote, in the order of Failures, empty where none was written.
	TracePaths []string
	// Why a failure's trace could not be written.
	TraceErrors []error
}

// What a report of the short form says, after its seeds (QD-1151).
const ExploreOneOrderText = "no barrier passed: every seed takes this order"

// "FS-1: 10 seeds run (1 to 10), 1 failed; seed 7, trace ...", or in the short form "FS-116: 1 seed run
// (1), 0 failed; no barrier passed: every seed takes this order". Never "no race": a seed that passed
// proves only the orders it reached.
func (self *ExploreReport) String() string {
	var text strings.Builder
	switch len(self.Seeds) {
	case 0:
		fmt.Fprintf(&text, "%s: 0 seeds run", self.Id)
	case 1:
		fmt.Fprintf(&text, "%s: 1 seed run (%d)", self.Id, self.Seeds[0])
	default:
		fmt.Fprintf(&text, "%s: %d seeds run (%d to %d)", self.Id, len(self.Seeds), self.Seeds[0], self.Seeds[len(self.Seeds)-1])
	}
	fmt.Fprintf(&text, ", %d failed", len(self.Failures))
	for index, failure := range self.Failures {
		fmt.Fprintf(&text, "; seed %d", failure.Seed)
		if index < len(self.TracePaths) && self.TracePaths[index] != "" {
			fmt.Fprintf(&text, ", trace %s", self.TracePaths[index])
		}
	}
	if self.OneOrder {
		fmt.Fprintf(&text, "; %s", ExploreOneOrderText)
	}
	return text.String()
}

// Runs builder's schedule once under each of settings' seeds, each on a fresh Net. A failing seed's
// trace is written when settings say so. settings nil takes the defaults.
func Explore(ctx context.Context, builder Builder, settings *RuleSettings) *ExploreReport {
	if settings == nil {
		settings = DefaultRuleSettings()
	}
	report := &ExploreReport{}
	for _, seed := range settings.Seeds {
		report.runSeed(ctx, builder, settings, seed, nil)
	}
	return report
}

// Runs builder's schedule under seed and records it, writing a failure's trace when settings say so.
// built, when not nil, is handed the schedule as built, before it runs.
func (self *ExploreReport) runSeed(ctx context.Context, builder Builder, settings *RuleSettings, seed int64, built func(schedule *Schedule)) *Result {
	result := runBuilt(ctx, builder, settings.Net, func(schedule *Schedule) {
		schedule.Seed = seed
		if built != nil {
			built(schedule)
		}
	})
	self.Id = result.Id
	self.Seeds = append(self.Seeds, seed)
	if result.Err == nil {
		return result
	}
	self.Failures = append(self.Failures, result)
	tracePath := ""
	if settings.WriteTraces {
		path, err := WriteTrace(settings.SeedsDirectory, TraceOf(result))
		if err != nil {
			self.TraceErrors = append(self.TraceErrors, err)
		}
		tracePath = path
	}
	self.TracePaths = append(self.TracePaths, tracePath)
	return result
}

// The explorer after fixed, the fixed run of builder's schedule: the first seed, and the rest unless the
// short form holds (the file header). settings nil takes the defaults.
func exploreAfter(ctx context.Context, builder Builder, fixed *Result, settings *RuleSettings) *ExploreReport {
	if settings == nil {
		settings = DefaultRuleSettings()
	}
	report := &ExploreReport{}
	if len(settings.Seeds) == 0 {
		return report
	}
	var schedule *Schedule
	first := report.runSeed(ctx, builder, settings, settings.Seeds[0], func(built *Schedule) {
		schedule = built
	})
	if first.Err == nil && exploreOrderChoice(schedule, fixed) == "" && slices.Equal(first.Trace, fixed.Trace) {
		report.OneOrder = true
		return report
	}
	for _, seed := range settings.Seeds[1:] {
		report.runSeed(ctx, builder, settings, seed, nil)
	}
	return report
}

// What leaves a seed something to order in schedule, built as the one fixed ran was, or empty when nothing
// does (the file header). A fixed run that failed stopped short of the rest of its schedule, so it shows
// nothing of it.
// Its trace holds an event for every barrier anything reached and for every stall and kill, beside a ran
// event each time an actor took the baton. With no barrier event and no step an action outlives, the baton
// moves only when the running action ends or gives it up: the ran events are one for each step's action,
// in order, unless an action started runs of its own or waited with the baton given up, when other actors
// may have waited for it together.
func exploreOrderChoice(schedule *Schedule, fixed *Result) string {
	switch {
	case fixed == nil || schedule == nil:
		return "no fixed run"
	case fixed.Err != nil:
		return "the fixed run failed"
	}
	ranActors := []string{}
	for _, event := range fixed.Events {
		if event.Kind != sidecartest.BarrierRan {
			return "the fixed run's trace holds a barrier event: " + strings.Join(strings.Fields(event.String()), " ")
		}
		ranActors = append(ranActors, event.Actor)
	}
	actionActors := []string{}
	for index, step := range schedule.Steps {
		switch {
		case step.Background:
			return fmt.Sprintf("step %d is a Background step", index)
		case step.Await == FaultFired:
			return fmt.Sprintf("step %d ends when its fault fires, and its action may run on", index)
		}
		if step.Action != nil {
			actionActors = append(actionActors, step.Actor)
		}
	}
	if !slices.Equal(ranActors, actionActors) {
		return fmt.Sprintf("the baton moved %d times in the fixed run, not once as each of its %d actions began", len(ranActors), len(actionActors))
	}
	return ""
}

// Builds and runs one schedule on a Net of its own, closed before this returns: under
// sidecar_testhooks only one is open at a time. adjust, when not nil, changes the schedule first.
func runBuilt(ctx context.Context, builder Builder, settings *sidecartest.NetSettings, adjust func(schedule *Schedule)) *Result {
	net := sidecartest.NewNet(ctx, settings)
	defer net.Close()
	schedule := builder(net)
	if adjust != nil {
		adjust(schedule)
	}
	return Run(ctx, schedule, net)
}
