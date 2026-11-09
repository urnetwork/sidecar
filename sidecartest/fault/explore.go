// §22.8's explorer: each schedule also runs under seeded barrier orders, 10 seeds a merge for a T2 row
// and 100 a night for a T3 one, checking its invariants after every step as any run does. A failing
// seed writes its trace beside the repository's other seeds, where Replay makes it a fixed schedule
// that runs from then on. The trace is kept and not the seed alone, since a goroutine no actor owns
// runs free and a seed may not order it the same way twice.
//
// Nothing here retries: a seed that failed once is a failure, whatever a second run of it would do
// (R-TEST-9). And a seed that passes proves only the orders it reached, so a report says how many seeds
// ran, never that there is no race.

package fault

import (
	"context"
	"fmt"
	"strings"

	"github.com/urnetwork/sidecar/sidecartest"
)

// What the rules across runs run with.
type RuleSettings struct {
	// The tier the runs are on, for reports: T2, or T3 when Net's Engines are server's (sidecart3).
	// Empty is T2.
	Tier Tier
	// Each run's Net. Its barriers' AwaitTimeout is §22.8's 10 s, and CheckRow refuses a longer one:
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
	// Each failing seed's result, with its trace.
	Failures []*Result
	// The trace file each failure wrote, in the order of Failures, empty where none was written.
	TracePaths []string
	// Why a failure's trace could not be written.
	TraceErrors []error
}

// "FS-1: 10 seeds run (1 to 10), 1 failed (seed 7, trace ...)". Never "no race": a seed that passed
// proves only the orders it reached.
func (self *ExploreReport) String() string {
	var text strings.Builder
	fmt.Fprintf(&text, "%s: %d seeds run", self.Id, len(self.Seeds))
	if 0 < len(self.Seeds) {
		fmt.Fprintf(&text, " (%d to %d)", self.Seeds[0], self.Seeds[len(self.Seeds)-1])
	}
	fmt.Fprintf(&text, ", %d failed", len(self.Failures))
	for index, failure := range self.Failures {
		fmt.Fprintf(&text, "; seed %d", failure.Seed)
		if index < len(self.TracePaths) && self.TracePaths[index] != "" {
			fmt.Fprintf(&text, ", trace %s", self.TracePaths[index])
		}
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
		result := runBuilt(ctx, builder, settings.Net, func(schedule *Schedule) {
			schedule.Seed = seed
		})
		report.Id = result.Id
		report.Seeds = append(report.Seeds, seed)
		if result.Err == nil {
			continue
		}
		report.Failures = append(report.Failures, result)
		tracePath := ""
		if settings.WriteTraces {
			path, err := WriteTrace(settings.SeedsDirectory, TraceOf(result))
			if err != nil {
				report.TraceErrors = append(report.TraceErrors, err)
			}
			tracePath = path
		}
		report.TracePaths = append(report.TracePaths, tracePath)
	}
	return report
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
