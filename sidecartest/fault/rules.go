// A registered case on T2 under every rule of §22.8 its row takes, which a row's thin T2 test runs:
//
//	func TestFs2(t *testing.T) {
//		fault.RunRow(t, "FS-2", "", nil)
//	}
//
// In order: the fixed schedule; its twin, when it refuses something; the explorer's seeds over both;
// every write's lost response, for a row on the unknown list; and a replay of every trace committed
// for the case and for its twin. Each run checks the row's invariants after every step. A failure is
// reported once, as it happened: nothing reruns a failed attempt to see whether it passes (R-TEST-9).
//
// The explorer takes its short form after a fixed run that passed no barrier, of a schedule with no
// Background step, where nothing else left a seed anything to order (QD-1151; explore.go): one seed, the
// report saying "no barrier passed: every seed takes this order". The gate's rules item names the cases
// some registered schedule of which takes it (exploreOneOrderCases). On the gate's build, with the hooks
// linked, a registered case, twin or clause that takes it for a case the list leaves out fails, and
// rules_testhooks_test.go holds the list to every registered T2 schedule's fixed run, so the item stays
// true.
//
// T3 runs the same registration's builder through server's sidecart3, with the nightly seeds.

package fault

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The cases, as Case.String names them, some registered T2 schedule of which the explorer runs in its short
// form under sidecar_testhooks (QD-1151), which the gate's rules item names. FS-116's to FS-118's governor
// worlds, on fake clocks of their own, touch no store; FS-45's, FS-47's and FS-61's cases and clauses step
// their fakes and models a step at a time and pass no barrier, as their file headers say; FS-44's clauses
// two hosts on one balance and edge killed before its post do the same over the fake Quota; and FS-27's
// twin, the untainted run keeping its grant, passes none either. FS-27's case and FS-44's case and other
// clauses pass barriers and run every seed.
func exploreOneOrderCases() []string {
	return []string{"FS-27", "FS-44", "FS-45", "FS-47", "FS-61", "FS-116", "FS-117", "FS-118"}
}

// What CheckRow ran for one case.
type RowReport struct {
	Case *Case
	// The tier it ran on.
	Tier Tier
	// The schedule as written, with no seed.
	Fixed *Result
	// Its twin, nil when it refuses nothing.
	Twin *Result
	// The explorer over the schedule and over its twin.
	Explore     *ExploreReport
	ExploreTwin *ExploreReport
	// For a row on the unknown list, the writes whose responses the reruns lost.
	LostWrites []LostWrite
	// Each committed trace's replay.
	Replays []*Result
	// Every run that failed.
	Failures []*Result
	// What kept a rule from running, which fails the case as a failure does.
	Errors []error
}

func (self *RowReport) Failed() bool {
	return 0 < len(self.Failures) || 0 < len(self.Errors)
}

// What ran, for a test's log: seeds run and failed, lost writes, replays, and every failure.
func (self *RowReport) String() string {
	var text strings.Builder
	tier := self.Tier
	if tier == "" {
		tier = TierT2
	}
	fmt.Fprintf(&text, "%s on %s:", self.Case, tier)
	if self.Explore != nil {
		fmt.Fprintf(&text, " %s.", self.Explore)
	}
	if self.ExploreTwin != nil {
		fmt.Fprintf(&text, " twin %s.", self.ExploreTwin)
	}
	if self.Case.Row.Unknown {
		fmt.Fprintf(&text, " %d writes run with their responses lost.", len(self.LostWrites))
	}
	fmt.Fprintf(&text, " %d traces replayed.", len(self.Replays))
	for _, failure := range self.Failures {
		fmt.Fprintf(&text, "\n%s", failure)
	}
	for _, err := range self.Errors {
		fmt.Fprintf(&text, "\n%v", err)
	}
	return text.String()
}

// A slow row is fixed, never given longer than §22.8's 60 s for a barrier.
func checkRuleSettings(settings *RuleSettings) error {
	if settings.Net == nil || settings.Net.Barriers == nil {
		return errors.New("rule settings name no barrier settings")
	}
	limit := sidecartest.DefaultBarrierDriverSettings().AwaitTimeout
	if limit < settings.Net.Barriers.AwaitTimeout {
		return fmt.Errorf("a barrier wait of %s: §22.8's %s is never raised for a slow row", settings.Net.Barriers.AwaitTimeout, limit)
	}
	if len(settings.Seeds) == 0 {
		return errors.New("rule settings name no explorer seed")
	}
	return nil
}

// Runs registration's case under every rule its row takes, on T2, or on the tier settings' Net names:
// server's sidecart3 runs a T3 registration through here with T3's NetSettings and the nightly seeds.
// settings nil takes the defaults.
func CheckRow(ctx context.Context, registration *Registration, settings *RuleSettings) *RowReport {
	if settings == nil {
		settings = DefaultRuleSettings()
	}
	testCase := DefaultCatalog().Case(registration.Row, registration.Case)
	report := &RowReport{Case: testCase, Tier: settings.Tier}
	if testCase == nil {
		report.Case = &Case{Name: registration.Case, Row: &Row{Id: registration.Row}}
		report.Errors = append(report.Errors, fmt.Errorf("%s names no case the catalog holds", registration))
		return report
	}
	if err := checkRuleSettings(settings); err != nil {
		report.Errors = append(report.Errors, err)
		return report
	}
	// the case's schedule, named for its case and flagged as the catalog says
	builder := func(net *Net) *Schedule {
		schedule := registration.Build(net)
		schedule.Id = testCase.String()
		schedule.Forged = testCase.Forged()
		return schedule
	}

	// the traces committed for the case and its twin, read before the explorer writes this run's own;
	// a twin's seeds leave theirs under the twin's name
	traces, err := Traces(settings.SeedsDirectory, testCase.String())
	if err != nil {
		report.Errors = append(report.Errors, err)
	}
	twinTraces, err := Traces(settings.SeedsDirectory, testCase.String()+" twin")
	if err != nil {
		report.Errors = append(report.Errors, err)
	}

	var fixed *Schedule
	func() {
		net := sidecartest.NewNet(ctx, settings.Net)
		defer net.Close()
		fixed = builder(net)
		report.Fixed = Run(ctx, fixed, net)
	}()
	report.fail(report.Fixed)
	if fixed.Forged && fixed.Twin == nil {
		report.Errors = append(report.Errors, fmt.Errorf("%s is forged, and its twin, which runs on T3, is missing", testCase))
	}
	var twin Builder
	if fixed.Twin != nil {
		twin = twinBuilder(fixed)
		report.Twin = RunTwin(ctx, fixed, settings.Net)
		report.fail(report.Twin)
	}

	report.Explore = exploreAfter(ctx, builder, report.Fixed, settings)
	report.Failures = append(report.Failures, report.Explore.Failures...)
	report.Errors = append(report.Errors, report.Explore.TraceErrors...)
	if twin != nil {
		report.ExploreTwin = exploreAfter(ctx, twin, report.Twin, settings)
		report.Failures = append(report.Failures, report.ExploreTwin.Failures...)
		report.Errors = append(report.Errors, report.ExploreTwin.TraceErrors...)
	}
	// the registered case alone, which the gate shows, on the build it runs: the rules' own tests run toys
	// under rows' names
	tier := settings.Tier
	if tier == "" {
		tier = TierT2
	}
	if sidecartest.HooksLinked && Lookup(registration.Row, registration.Case, tier) == registration {
		report.Errors = append(report.Errors, report.oneOrderErrors(testCase)...)
	}

	if testCase.Row.Unknown {
		failures, lostWrites := EveryWrite(ctx, builder, settings.Net)
		report.Failures = append(report.Failures, failures...)
		report.LostWrites = lostWrites
	}

	for _, trace := range traces {
		result := runBuilt(ctx, Replay(builder, trace), settings.Net, nil)
		report.Replays = append(report.Replays, result)
		report.fail(result)
	}
	if twin != nil {
		for _, trace := range twinTraces {
			result := runBuilt(ctx, Replay(twin, trace), settings.Net, nil)
			report.Replays = append(report.Replays, result)
			report.fail(result)
		}
	}
	return report
}

func (self *RowReport) fail(result *Result) {
	if result != nil && result.Err != nil {
		self.Failures = append(self.Failures, result)
	}
}

// An explorer of this run, over the schedule or its twin, that took the short form though exploreOneOrderCases
// leaves out testCase, the case the run's schedule or clause is of, so the gate's rules item would say every seed
// ran where one did. That a case the list names has a schedule taking it is rules_testhooks_test.go's to hold,
// since its other schedules may run every seed.
func (self *RowReport) oneOrderErrors(testCase *Case) []error {
	if slices.Contains(exploreOneOrderCases(), testCase.String()) {
		return nil
	}
	errs := []error{}
	for _, explore := range []*ExploreReport{self.Explore, self.ExploreTwin} {
		if explore != nil && explore.OneOrder {
			errs = append(errs, fmt.Errorf(
				"%s: the explorer ran one seed, %s, and the gate's rules item does not name %s among the cases it runs one seed for (exploreOneOrderCases; QD-1151)",
				explore.Id, ExploreOneOrderText, testCase,
			))
		}
	}
	return errs
}

// CheckRow for the case's T2 registration, failing t with each failure and logging what ran. A case
// with no T2 builder fails as missing. settings nil takes the defaults.
func RunRow(t testing.TB, rowId string, caseName string, settings *RuleSettings) {
	t.Helper()
	registration := Lookup(rowId, caseName, TierT2)
	if registration == nil {
		t.Fatalf("%s %q has no T2 builder registered: missing", rowId, caseName)
	}
	report := CheckRow(t.Context(), registration, settings)
	t.Log(report.String())
	for _, failure := range report.Failures {
		t.Errorf("%s", failure)
	}
	for _, err := range report.Errors {
		t.Errorf("%v", err)
	}
}
