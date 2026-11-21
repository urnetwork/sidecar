// The rules' independent runs in child processes (rules_processes.go): the child's entry, toys a child rebuilds by
// name, and the tests that hold a report made with children to the one made with every run here, a failing or crashing
// run in a child to a failure of the report, and a child that loses its parent to its end. The toys are run_test.go's
// race, two writers committing to one head with barriers around each swap, which the explorer interleaves and whose
// puts the unknown rule loses one at a time.

package fault

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// How the crashing toy's child exits.
const ruleChildToyExitCode = 7

// The blocking toy's two ends, which a test sets before it runs the toy, in this process: the run closes started once
// its action holds the baton, and its action ends when release closes.
type ruleChildBlockingEnds struct {
	started chan struct{}
	release chan struct{}
}

var ruleChildBlocking atomic.Pointer[ruleChildBlockingEnds]

func init() {
	ruleChildEntry = "TestRuleChildProcess"
	race := func(writer func() *toyWriter) Builder {
		return func(net *Net) *Schedule {
			return raceSchedule(writer(), writer())
		}
	}
	ruleChildTestBuilders["race"] = race(func() *toyWriter { return &toyWriter{} })
	ruleChildTestBuilders["race trusting preconditions"] = race(func() *toyWriter { return &toyWriter{trustsPrecondition: true} })
	ruleChildTestBuilders["race retrying blindly"] = race(func() *toyWriter { return &toyWriter{retriesBlindly: true} })
	ruleChildTestBuilders["race with a twin"] = Twin(func(net *Net) *Schedule {
		schedule := raceSchedule(&toyWriter{}, &toyWriter{})
		schedule.Refuses = "nothing: a toy's refusal, which the same race twins"
		return schedule
	}, ruleChildTestBuilders["race"])
	ruleChildTestBuilders["race ending its child"] = func(net *Net) *Schedule {
		schedule := raceSchedule(&toyWriter{}, &toyWriter{})
		schedule.Steps[0] = &Step{Actor: "setup", Action: seedToyHeadEndingAChild}
		return schedule
	}
	ruleChildTestBuilders["blocking"] = func(net *Net) *Schedule {
		ends := ruleChildBlocking.Load()
		return &Schedule{Id: "toy-blocking", Steps: []*Step{{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			close(ends.started)
			net.Barriers().Blocking(func() {
				select {
				case <-ends.release:
				case <-ctx.Done():
				}
			})
			return nil
		}}}}
	}
}

// Not a test: the entry of the child processes the rules send their independent runs to (rules_processes.go). Run on
// its own, it does nothing.
func TestRuleChildProcess(t *testing.T) {
	if os.Getenv(ruleChildEnvironment) == "" {
		return
	}
	if err := serveRuleChild(t.Context(), os.Stdin, os.NewFile(3, "results"), os.Exit); err != nil {
		t.Fatal(err)
	}
}

// seedToyHead, but a child process whose put's answer is lost ends there, as a crash in the run would end it; in this
// process it rereads, as seedToyHead does, and passes.
func seedToyHeadEndingAChild(ctx context.Context, net *Net) error {
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return err
	}
	_, err = cluster.PutIfNoneMatch(ctx, toyHeadKey, []byte("genesis"), nil)
	var unknown *sidecar.BlobUnknownError
	if errors.As(err, &unknown) {
		if os.Getenv(ruleChildEnvironment) != "" {
			fmt.Fprintln(os.Stderr, "the toy ends its child at a lost answer")
			os.Exit(ruleChildToyExitCode)
		}
		_, err = cluster.Head(ctx, toyHeadKey)
	}
	return err
}

// The rules over toy, on row FS-1's unknown list, with settings' processes at count and its traces written to and read
// from directory: a child rebuilds the toy by its name.
func checkToyRules(t *testing.T, toy string, directory string, count int, seeds []int64) *RowReport {
	t.Helper()
	settings := DefaultRuleSettings()
	settings.SeedsDirectory = directory
	settings.TraceDirectory = directory
	settings.Processes.Count = count
	if seeds != nil {
		settings.Seeds = seeds
	}
	return checkToyRulesUnder(t, toy, settings)
}

// The rules over toy, on row FS-1's unknown list, under settings: a child rebuilds the toy by its name.
func checkToyRulesUnder(t *testing.T, toy string, settings *RuleSettings) *RowReport {
	t.Helper()
	report := &RowReport{Case: &Case{Name: toy, Row: &Row{Id: "FS-1", Number: 1, Unknown: true}}}
	report.checkRules(t.Context(), &ruleSubject{id: "toy-race", builder: ruleChildTestBuilders[toy], unknown: true, child: &ruleChildName{Test: toy}}, settings)
	return report
}

// Each failure's id and seed, in the report's order.
func ruleFailureNames(report *RowReport) []string {
	names := []string{}
	for _, failure := range report.Failures {
		names = append(names, fmt.Sprintf("%s seed %d", failure.Id, failure.Seed))
	}
	return names
}

// The trace files in directory.
func ruleTraceFileNames(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// A toy's runs in three child processes report as they do with every run here: its seeds and its twin's in order, the
// same writes lost, the committed trace replayed the same way, nothing failed, and the report saying where the runs
// went.
func TestRunsInChildProcessesReportAsInThisOne(t *testing.T) {
	directory := t.TempDir()
	// a trace committed for the toy, which each report replays
	func() {
		net := sidecartest.NewNet(t.Context(), nil)
		defer net.Close()
		schedule := ruleChildTestBuilders["race with a twin"](net)
		schedule.Seed = 4
		if _, err := WriteTrace(directory, TraceOf(Run(t.Context(), schedule, net))); err != nil {
			t.Fatal(err)
		}
	}()
	here := checkToyRules(t, "race with a twin", directory, 1, nil)
	children := checkToyRules(t, "race with a twin", directory, 3, nil)
	for _, report := range []*RowReport{here, children} {
		if report.Failed() {
			t.Fatalf("%s", report)
		}
	}
	if here.Costs.ChildProcesses != 0 || children.Costs.ChildProcesses != 3 {
		t.Errorf("%d and %d child processes, want 0 and 3", here.Costs.ChildProcesses, children.Costs.ChildProcesses)
	}
	if !slices.Equal(here.Explore.Seeds, MergeSeeds()) || !slices.Equal(children.Explore.Seeds, MergeSeeds()) ||
		!slices.Equal(children.ExploreTwin.Seeds, MergeSeeds()) || here.Explore.Id != children.Explore.Id || here.ExploreTwin.Id != children.ExploreTwin.Id {
		t.Errorf("the explorers ran %v and %v, twins %v", here.Explore, children.Explore, children.ExploreTwin)
	}
	if len(here.LostWrites) == 0 || !slices.Equal(here.LostWrites, children.LostWrites) {
		t.Errorf("lost %v here and %v in children", here.LostWrites, children.LostWrites)
	}
	if len(here.Replays) != 1 || len(children.Replays) != 1 || !slices.Equal(here.Replays[0].Trace, children.Replays[0].Trace) || here.Replays[0].LeftTrace != children.Replays[0].LeftTrace {
		t.Errorf("replays %v here and %v in children", here.Replays, children.Replays)
	}
	if children.Costs.EveryWrite.Runs != len(children.LostWrites) || children.Costs.Explore.Runs != 10 || children.Costs.ExploreTwin.Runs != 10 || children.Costs.Replays.Runs != 1 {
		t.Errorf("the costs count other runs: %s", &children.Costs)
	}
	if !strings.Contains(children.String(), "with 3 child processes") || !strings.Contains(here.String(), "in this process") {
		t.Errorf("the reports do not say where the runs went: %s; %s", here, children)
	}
}

// A run failing in a child process fails the report as it does here: a seed of the mutant that trusts a failed
// condition, with its trace written, and a rerun of the mutant that retries blindly on a lost answer, each where the
// run made one after another put it.
func TestARunFailingInAChildProcessFailsTheReport(t *testing.T) {
	// seeds enough to find the race (TestExplorerFindsARaceTheFixedOrderMisses)
	seeds := seedRange(40)
	hereDirectory := t.TempDir()
	childrenDirectory := t.TempDir()
	here := checkToyRules(t, "race trusting preconditions", hereDirectory, 1, seeds)
	children := checkToyRules(t, "race trusting preconditions", childrenDirectory, 4, seeds)
	if len(here.Explore.Failures) == 0 || !slices.Equal(ruleFailureNames(here), ruleFailureNames(children)) {
		t.Fatalf("failed %v here and %v in children", ruleFailureNames(here), ruleFailureNames(children))
	}
	if children.Costs.ChildProcesses == 0 {
		t.Errorf("no child ran: %s", children)
	}
	if !strings.Contains(children.Explore.Failures[0].Err.Error(), "was lost") || 0 == len(children.Explore.Failures[0].Trace) {
		t.Errorf("a child's failing seed failed on something else, or carried no trace: %s", children.Explore.Failures[0])
	}
	if names := ruleTraceFileNames(t, childrenDirectory); len(names) == 0 || !slices.Equal(names, ruleTraceFileNames(t, hereDirectory)) {
		t.Errorf("traces %v in children, %v here", names, ruleTraceFileNames(t, hereDirectory))
	}

	blindHere := checkToyRules(t, "race retrying blindly", t.TempDir(), 1, nil)
	blindChildren := checkToyRules(t, "race retrying blindly", t.TempDir(), 4, nil)
	lostFailures := func(report *RowReport) []string {
		names := []string{}
		for _, name := range ruleFailureNames(report) {
			if strings.Contains(name, "response lost") {
				names = append(names, name)
			}
		}
		return names
	}
	if len(lostFailures(blindHere)) == 0 || !slices.Equal(ruleFailureNames(blindHere), ruleFailureNames(blindChildren)) {
		t.Errorf("the blind writer failed %v here and %v in children", ruleFailureNames(blindHere), ruleFailureNames(blindChildren))
	}
}

// A child process ending under a run fails that run, with how it ended and what it printed last, and every other run
// still runs and passes: here the rerun that loses the head's first put, after which the toy ends its child.
func TestAChildProcessEndingUnderARunFailsItAndTheRestRun(t *testing.T) {
	here := checkToyRules(t, "race ending its child", t.TempDir(), 1, nil)
	if here.Failed() {
		t.Fatalf("the toy fails in this process: %s", here)
	}
	children := checkToyRules(t, "race ending its child", t.TempDir(), 2, nil)
	if want := []string{"toy-race with put write 1's response lost seed 0"}; !slices.Equal(ruleFailureNames(children), want) {
		t.Fatalf("failed %v, want %v: %s", ruleFailureNames(children), want, children)
	}
	text := children.Failures[0].Err.Error()
	if !strings.Contains(text, "the child process running it ended") || !strings.Contains(text, fmt.Sprintf("exit status %d", ruleChildToyExitCode)) ||
		!strings.Contains(text, "the toy ends its child at a lost answer") {
		t.Errorf("the failure does not say how the child ended: %s", text)
	}
	if !slices.Equal(children.Explore.Seeds, MergeSeeds()) || !slices.Equal(children.LostWrites, here.LostWrites) {
		t.Errorf("not every run ran: seeds %v, lost %v of %v", children.Explore.Seeds, children.LostWrites, here.LostWrites)
	}
}

// A child whose stdin ends while it runs a run has lost its parent and exits at once, since a parent closes a child's
// stdin only between runs; one whose stdin ends between runs answers every run it took and returns.
func TestAChildLosingItsParentMidRunExits(t *testing.T) {
	ends := &ruleChildBlockingEnds{started: make(chan struct{}), release: make(chan struct{})}
	ruleChildBlocking.Store(ends)
	input, inputWriter := io.Pipe()
	output, outputWriter := io.Pipe()
	exits := make(chan int, 1)
	served := make(chan error, 1)
	go func() {
		served <- serveRuleChild(t.Context(), input, outputWriter, func(code int) {
			exits <- code
		})
		outputWriter.Close()
	}()
	results := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(output)
		results <- data
	}()
	if _, err := fmt.Fprintf(inputWriter, `{"name":{"test":"blocking"},"schedule_id":"toy-blocking"}`+"\n"+`{"index":0,"seed":1}`+"\n"); err != nil {
		t.Fatal(err)
	}
	<-ends.started
	inputWriter.Close()
	if code := <-exits; code != ruleChildOrphanExitCode {
		t.Errorf("exited %d, want %d", code, ruleChildOrphanExitCode)
	}
	// with exit faked, the run goes on to its end and the child to its return
	close(ends.release)
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if data := <-results; !strings.Contains(string(data), `"index":0`) {
		t.Errorf("the child answered %q", data)
	}

	// stdin ending between runs is the parent done with the child
	input, inputWriter = io.Pipe()
	go func() {
		served <- serveRuleChild(t.Context(), input, io.Discard, func(code int) {
			exits <- code
		})
	}()
	if _, err := fmt.Fprintf(inputWriter, `{"name":{"test":"race"},"schedule_id":"toy-race"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	inputWriter.Close()
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-exits:
		t.Errorf("a child its parent was done with exited %d", code)
	default:
	}
}

// Runs go to child processes only where a child rebuilds them as they run here: a builder it can name, T2's default Net
// settings, more than one process, a binary linking the entry, and a process that is no child itself.
func TestRunsGoToChildProcessesOnlyWhereAChildRebuildsThem(t *testing.T) {
	name := &ruleChildName{Row: "FS-1"}
	if count := ruleChildCount(DefaultRuleSettings(), name); count != DefaultRuleProcessSettings().Count || DefaultRuleProcessSettings().Count < 1 {
		t.Errorf("the defaults take %d children", count)
	}
	if !reflect.DeepEqual(sidecartest.DefaultNetSettings(), sidecartest.DefaultNetSettings()) {
		t.Fatal("two default Net settings differ, so no run ever goes to a child")
	}
	for _, c := range []struct {
		why    string
		change func(settings *RuleSettings)
		// no name a child can rebuild
		unnamed bool
	}{
		{why: "a builder no child can name", unnamed: true},
		{why: "no process settings", change: func(settings *RuleSettings) { settings.Processes = nil }},
		{why: "one process", change: func(settings *RuleSettings) { settings.Processes.Count = 1 }},
		{why: "T3", change: func(settings *RuleSettings) { settings.Tier = TierT3 }},
		{why: "a barrier bound of the test's own", change: func(settings *RuleSettings) { settings.Net.Barriers.AwaitTimeout /= 2 }},
		{why: "engines of the test's own", change: func(settings *RuleSettings) {
			settings.Net.Engines = func(ctx context.Context, net *sidecartest.Net) (*sidecar.ServiceHost, func(), error) {
				return nil, nil, errors.New("unused")
			}
		}},
	} {
		settings := DefaultRuleSettings()
		if c.change != nil {
			c.change(settings)
		}
		childName := name
		if c.unnamed {
			childName = nil
		}
		if count := ruleChildCount(settings, childName); count != 0 {
			t.Errorf("%s: %d children", c.why, count)
		}
	}

	func() {
		entry := ruleChildEntry
		defer func() {
			ruleChildEntry = entry
		}()
		ruleChildEntry = ""
		if count := ruleChildCount(DefaultRuleSettings(), name); count != 0 {
			t.Errorf("a binary linking no entry: %d children", count)
		}
	}()

	t.Setenv(ruleChildEnvironment, "1")
	if count := ruleChildCount(DefaultRuleSettings(), name); count != 0 {
		t.Errorf("a child: %d children of its own", count)
	}
}

// A schedule whose connect clients ran keeps every run here, the report saying why: FS-56's, whose bridge host maps its
// echoes onto the host's loopback, where two children on darwin read each other's echo replies under the same ids, so
// a revoked subject in one saw an echo answered that the other's twin had sent, in 8 of 20 tests with children
// (connect's ip_icmp_egress_unix.go).
func TestAScheduleWhoseConnectClientsRanKeepsItsRunsHere(t *testing.T) {
	report := CheckRow(t.Context(), Fs56Case, nil)
	if report.Failed() {
		t.Fatalf("%s", report)
	}
	if report.Costs.ChildProcesses != 0 || report.Costs.Here == "" || !strings.Contains(report.String(), "in this process: its connect clients") {
		t.Errorf("FS-56's runs went to %d child processes: %s", report.Costs.ChildProcesses, report)
	}
}

// FS-45's registered case, whose host writes the unknown rule loses one at a time, sends its reruns to child processes
// under the default rules and reports as it does with every run here.
func TestARegisteredCaseRunsInChildProcessesAsInThisOne(t *testing.T) {
	settings := DefaultRuleSettings()
	settings.Processes.Count = 1
	here := CheckRow(t.Context(), Fs45, settings)
	children := CheckRow(t.Context(), Fs45, nil)
	for _, report := range []*RowReport{here, children} {
		if report.Failed() {
			t.Fatalf("%s", report)
		}
	}
	if here.Costs.ChildProcesses != 0 || children.Costs.ChildProcesses == 0 {
		t.Errorf("%d and %d child processes: %s", here.Costs.ChildProcesses, children.Costs.ChildProcesses, children)
	}
	if len(here.LostWrites) < 2 || !slices.Equal(here.LostWrites, children.LostWrites) || !slices.Equal(here.Explore.Seeds, children.Explore.Seeds) {
		t.Errorf("lost %v and %v, seeds %v and %v", here.LostWrites, children.LostWrites, here.Explore.Seeds, children.Explore.Seeds)
	}
}
