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
// The fixed run is also the unknown rule's dry run, whose writes the reruns lose one at a time. After
// each explorer's first seed, the runs that depend on nothing but their own schedule, the explorers'
// other seeds, the reruns and the replays, run together in child processes of the test binary where a
// child can rebuild them (rules_processes.go), and each result goes where it went when they ran one
// after another. A report says what each rule's runs cost, and where they ran.
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
	"time"

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
	// What each rule's runs cost.
	Costs RuleCosts
}

// What one rule's runs cost: how many schedules it ran, and their times in real time added up, each run's own
// wherever it ran.
type RuleCost struct {
	Runs int
	Time time.Duration
}

func (self *RuleCost) add(runs int, took time.Duration) {
	self.Runs += runs
	self.Time += took
}

func (self RuleCost) String() string {
	noun := "runs"
	if self.Runs == 1 {
		noun = "run"
	}
	return fmt.Sprintf("%d %s %s", self.Runs, noun, self.Time.Round(time.Millisecond))
}

// What each rule's runs cost, which a report's log says, so a slow row says where its time went: the fixed run, which
// is the unknown rule's dry run too, the twin, the explorer's seeds over each, the unknown rule's rerun for each write,
// and the replays. The times are real time, read for the log alone: nothing decides by them, and no schedule sees them.
type RuleCosts struct {
	Fixed       RuleCost
	Twin        RuleCost
	Explore     RuleCost
	ExploreTwin RuleCost
	EveryWrite  RuleCost
	Replays     RuleCost
	// How long the rules took together in real time, the runs sent to child processes running side by side.
	Wall time.Duration
	// How many child processes the runs went to (rules_processes.go), zero when every run ran in this one.
	ChildProcesses int
	// Why every run ran in this process though a child could rebuild the schedule, or empty.
	Here string
}

// Every rule's runs together.
func (self *RuleCosts) Total() RuleCost {
	total := RuleCost{}
	for _, cost := range []RuleCost{self.Fixed, self.Twin, self.Explore, self.ExploreTwin, self.EveryWrite, self.Replays} {
		total.Runs += cost.Runs
		total.Time += cost.Time
	}
	return total
}

// "fixed 1 run 1.2s, twin 0 runs 0s, explorer 10 runs 6.1s, twin's explorer 0 runs 0s, every write 716 runs 7m10s,
// replays 0 runs 0s; 727 runs 7m17s, in 1m9s with 7 child processes".
func (self *RuleCosts) String() string {
	where := "in this process"
	switch {
	case 0 < self.ChildProcesses:
		where = fmt.Sprintf("with %d child processes", self.ChildProcesses)
	case self.Here != "":
		where += ": " + self.Here
	}
	return fmt.Sprintf(
		"fixed %s, twin %s, explorer %s, twin's explorer %s, every write %s, replays %s; %s, in %s %s",
		self.Fixed, self.Twin, self.Explore, self.ExploreTwin, self.EveryWrite, self.Replays, self.Total(), self.Wall.Round(time.Millisecond), where,
	)
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
	fmt.Fprintf(&text, " Cost: %s.", &self.Costs)
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
	subject := &ruleSubject{id: testCase.String(), builder: caseBuilder(registration, testCase), unknown: testCase.Row.Unknown, forgedCase: testCase}
	// the registered case alone, which the gate shows, on the build it runs, and which a child process rebuilds: the
	// rules' own tests run toys under rows' names
	tier := settings.Tier
	if tier == "" {
		tier = TierT2
	}
	if Lookup(registration.Row, registration.Case, tier) == registration {
		if sidecartest.HooksLinked {
			subject.oneOrderCase = testCase
		}
		if tier == TierT2 {
			subject.child = &ruleChildName{Row: registration.Row, Case: registration.Case}
		}
	}
	report.checkRules(ctx, subject, settings)
	return report
}

// registration's schedule, named for its case and flagged as the catalog says.
func caseBuilder(registration *Registration, testCase *Case) Builder {
	return func(net *Net) *Schedule {
		schedule := registration.Build(net)
		schedule.Id = testCase.String()
		schedule.Forged = testCase.Forged()
		return schedule
	}
}

// What the rules run over, as CheckRow and CheckClause name it.
type ruleSubject struct {
	// The schedule, named, and its traces' name.
	id      string
	builder Builder
	// The row is on the unknown list.
	unknown bool
	// A case, whose schedule must name its twin where the case is forged; nil for a clause.
	forgedCase *Case
	// The case whose short form the gate's rules item must name, for a registered case or clause on the gate's build;
	// nil for none.
	oneOrderCase *Case
	// How a child process rebuilds builder (rules_processes.go), nil when none can.
	child *ruleChildName
}

// The rules over subject into the report, in the file header's order: the fixed run, which is the unknown rule's dry
// run too, since it is the same run; the twin; each explorer's first seed; then every run that depends on nothing but
// its own schedule together, in child processes where a child can rebuild it (rules_processes.go): the explorers'
// other seeds unless the short form holds, a rerun for each write with its answer lost, and each committed trace's
// replay. Each run's result goes where it went when the runs were made one after another.
func (self *RowReport) checkRules(ctx context.Context, subject *ruleSubject, settings *RuleSettings) {
	started := time.Now()
	defer func() {
		self.Costs.Wall = time.Since(started)
	}()
	// the traces committed for the schedule and its twin, read before the explorer writes this run's own; a twin's
	// seeds leave theirs under the twin's name
	traces, err := Traces(settings.SeedsDirectory, subject.id)
	if err != nil {
		self.Errors = append(self.Errors, err)
	}
	twinTraces, err := Traces(settings.SeedsDirectory, subject.id+" twin")
	if err != nil {
		self.Errors = append(self.Errors, err)
	}

	var fixed *Schedule
	var opResults map[string][]FaultResult
	// whether the schedule's connect clients ran, on the fixed run or the twin's
	var connectClients bool
	runStarted := time.Now()
	func() {
		net := sidecartest.NewNet(ctx, settings.Net)
		defer net.Close()
		fixed = subject.builder(net)
		self.Fixed = Run(ctx, fixed, net)
		opResults = everyWriteResults(net)
		connectClients = net.UsesPlatformFakes()
	}()
	self.Costs.Fixed.add(1, time.Since(runStarted))
	self.fail(self.Fixed)
	if subject.forgedCase != nil && fixed.Forged && fixed.Twin == nil {
		self.Errors = append(self.Errors, fmt.Errorf("%s is forged, and its twin, which runs on T3, is missing", subject.forgedCase))
	}
	var twin Builder
	if fixed.Twin != nil {
		twin = twinBuilder(fixed)
		runStarted = time.Now()
		func() {
			net := sidecartest.NewNet(ctx, settings.Net)
			defer net.Close()
			self.Twin = runTwinOn(ctx, fixed, net)
			connectClients = connectClients || net.UsesPlatformFakes()
		}()
		self.Costs.Twin.add(1, time.Since(runStarted))
		self.fail(self.Twin)
	}
	child := subject.child
	if connectClients && child != nil {
		// two processes' connect clients share the host's network stack, where darwin hands each process's datagram
		// ICMP sockets the other's echo replies under the same process-local ids (connect's ip_icmp_egress_unix.go)
		self.Costs.Here = "its connect clients egress through the host's network stack, which two processes share"
		child = nil
	}

	runStarted = time.Now()
	explore, exploreRest := exploreFirst(ctx, subject.builder, self.Fixed, settings)
	self.Costs.Explore.add(len(explore.Seeds), time.Since(runStarted))
	var exploreTwin *ExploreReport
	var exploreTwinRest []int64
	if twin != nil {
		runStarted = time.Now()
		exploreTwin, exploreTwinRest = exploreFirst(ctx, twin, self.Twin, settings)
		self.Costs.ExploreTwin.add(len(exploreTwin.Seeds), time.Since(runStarted))
	}

	// every run left, in the order the runs were made one after another
	runs := []*ruleRun{}
	for _, seed := range exploreRest {
		runs = append(runs, &ruleRun{Seed: seed})
	}
	for _, seed := range exploreTwinRest {
		runs = append(runs, &ruleRun{Twin: true, Seed: seed})
	}
	var lostWrites []LostWrite
	if subject.unknown && self.Fixed.Err == nil {
		// a fixed run that failed is a dry run that failed, which leaves nothing to rerun (EveryWrite)
		lostWrites = everyWriteLosses(opResults)
	}
	for _, lost := range lostWrites {
		runs = append(runs, &ruleRun{Lost: &lost})
	}
	for _, trace := range traces {
		runs = append(runs, &ruleRun{Replay: trace})
	}
	if twin != nil {
		for _, trace := range twinTraces {
			runs = append(runs, &ruleRun{Twin: true, Replay: trace})
		}
	}
	outcomes := self.runAll(ctx, subject, child, twin, runs, settings)

	for index, run := range runs {
		outcome := outcomes[index]
		switch {
		case run.Replay != nil:
			self.Costs.Replays.add(1, outcome.took)
		case run.Lost != nil:
			self.Costs.EveryWrite.add(1, outcome.took)
		case run.Twin:
			self.Costs.ExploreTwin.add(1, outcome.took)
			exploreTwin.record(run.Seed, outcome.result, settings, !outcome.childEnded)
		default:
			self.Costs.Explore.add(1, outcome.took)
			explore.record(run.Seed, outcome.result, settings, !outcome.childEnded)
		}
	}
	self.Explore = explore
	self.Failures = append(self.Failures, explore.Failures...)
	self.Errors = append(self.Errors, explore.TraceErrors...)
	if exploreTwin != nil {
		self.ExploreTwin = exploreTwin
		self.Failures = append(self.Failures, exploreTwin.Failures...)
		self.Errors = append(self.Errors, exploreTwin.TraceErrors...)
	}
	if subject.oneOrderCase != nil {
		self.Errors = append(self.Errors, self.oneOrderErrors(subject.oneOrderCase)...)
	}
	if subject.unknown {
		self.LostWrites = lostWrites
		for index, run := range runs {
			if run.Lost != nil {
				self.fail(outcomes[index].result)
			}
		}
	}
	for index, run := range runs {
		if run.Replay != nil {
			self.Replays = append(self.Replays, outcomes[index].result)
			self.fail(outcomes[index].result)
		}
	}
}

// Runs runs, each on a Net of its own, in child processes rebuilding subject's builder by child where settings allow
// it, child nil keeping them here, and returns what each left, in runs' order.
func (self *RowReport) runAll(ctx context.Context, subject *ruleSubject, child *ruleChildName, twin Builder, runs []*ruleRun, settings *RuleSettings) []*ruleOutcome {
	outcomes := make([]*ruleOutcome, len(runs))
	if count := ruleChildCount(settings, child); 1 < count && 1 < len(runs) {
		outcomes, self.Costs.ChildProcesses = runInChildren(ctx, child, subject.id, runs, count, settings.Processes)
	}
	twinOf := func() (Builder, error) {
		if twin == nil {
			return nil, fmt.Errorf("%s names no twin", subject.id)
		}
		return twin, nil
	}
	// what no child took
	for index, run := range runs {
		if outcomes[index] != nil {
			continue
		}
		started := time.Now()
		result := run.run(ctx, subject.id, subject.builder, twinOf, settings.Net)
		outcomes[index] = &ruleOutcome{result: result, took: time.Since(started)}
	}
	return outcomes
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
