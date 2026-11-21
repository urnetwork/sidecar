// §22.8's rules' independent runs in child processes of this test binary, beside the process CheckRow or CheckClause
// runs in. Under sidecar_testhooks a Net installs the process's hooks, so a process holds one Net at a time, and a
// row's runs one after another took FS-1's test 56 minutes under make check's load: its unknown rule alone reruns the
// schedule once for each of its 716 writes. The explorer's seeds after the first, each write's rerun with its answer
// lost and each committed trace's replay depend on nothing but their own schedule, so the rules send them to
// RuleProcessSettings.Count children together, each running one run at a time on a Net of its own, and take back each
// run's result as it left it. The fixed run, the twin and each explorer's first seed, which decide what else runs, stay
// here. Every run still runs, under the seed, lost write or trace it ran under before, checking its invariants after
// every step: only where it runs moves.
//
// A child rebuilds a run's schedule as server's T3 test does, from the registries: a registered case's builder or a
// registered clause's, named as CheckRow and CheckClause name them, under the run's seed, lost write or trace. So a run
// goes to a child only for a registered builder on T2's default Net settings, in a binary that links the child's entry
// (rules_processes_test.go's TestRuleChildProcess), and everything runs here otherwise: a test's own builder or
// settings, T3's Nets in server's sidecart3, whose binary links no entry, and a search heap process's rows, FS-77's and
// FS-109's, whose heap samplers answer only in the one process their test runs in (sidecartest's
// search_heap_process.go). A schedule whose connect clients ran, on its fixed run or its twin's, keeps its runs here
// too: their egress is the host's own network stack, which processes share, and on darwin connect's datagram ICMP
// sockets take every echo reply the host receives, each process filtering by ids it counts from one, so two children
// running a bridge row's world at once each read the other's replies, and FS-56's revoked subject saw an echo answered
// that the other child's twin had sent (connect's ip_icmp_egress_unix.go).
//
// A child is this binary run as `<binary> -test.run=^TestRuleChildProcess$` with ruleChildEnvironment set. It reads
// the name of its builder and then one run at a time from stdin, and writes each run's result to fd 3, a pipe of its
// own, one JSON value a run. The next run goes to whichever child answers first. A child whose stdin ends while it runs
// a run has lost its parent, since the parent closes a child's stdin only between runs, and it exits at once, so no
// child outlives the test that started it. A child that ends before answering fails the run it was given, with the end
// of what it printed: what crashed it is that run's failure, as it would have crashed the run here. A run no child took,
// since none could start, runs here. Nothing is rerun (R-TEST-9).
//
// Each result keeps its run's place: a report lists seeds, failures, lost writes and replays in the order the runs were
// made, whichever child finished first, so it reads the same however the children were scheduled.

package fault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// Where the rules' independent runs go.
type RuleProcessSettings struct {
	// How many child processes of this test binary the runs take at once, each holding one Net at a time. One or
	// fewer runs every run in this process.
	Count int
	// How much of a child's output, from its end, the failure of a run it ended during carries.
	OutputTailByteCount int
}

// Half the host's CPUs: a run keeps about one busy, and make check runs other packages beside this one.
func DefaultRuleProcessSettings() *RuleProcessSettings {
	return &RuleProcessSettings{
		Count:               max(1, runtime.NumCPU()/2),
		OutputTailByteCount: 16 * 1024,
	}
}

// What the environment of a child process carries, so its entry test serves the parent's runs.
const ruleChildEnvironment = "SIDECAR_FAULT_RULE_CHILD"

// How a child that lost its parent mid-run exits.
const ruleChildOrphanExitCode = 3

// The test a child process runs, which this package's tests set (rules_processes_test.go): empty in a binary that
// links no entry, such as server's, which runs every run in its own process.
var ruleChildEntry string

// Builders a child rebuilds by name beside the registries': none outside this package's tests, whose toys hold the
// child path to failing, crashing and orphaned runs (rules_processes_test.go). Written only by init.
var ruleChildTestBuilders = map[string]Builder{}

// Names the builder a child rebuilds: a registered case's, by its row and case, or a registered clause's, by its row
// and clause, or one of this package's tests' toys.
type ruleChildName struct {
	Row    string `json:"row,omitempty"`
	Case   string `json:"case,omitempty"`
	Clause string `json:"clause,omitempty"`
	Test   string `json:"test,omitempty"`
}

// The builder, named as the rules name it.
func (self *ruleChildName) builder() (Builder, error) {
	switch {
	case self.Test != "":
		builder, ok := ruleChildTestBuilders[self.Test]
		if !ok {
			return nil, fmt.Errorf("no test builder %q", self.Test)
		}
		return builder, nil
	case self.Clause != "":
		registration := LookupClause(self.Row, self.Clause)
		row := DefaultCatalog().Row(self.Row)
		if registration == nil || row == nil || !slices.Contains(registration.Tiers, TierT2) {
			return nil, fmt.Errorf("%s has no clause %q registered on T2", self.Row, self.Clause)
		}
		return clauseBuilder(row, registration.Id(), registration.Build), nil
	}
	registration := Lookup(self.Row, self.Case, TierT2)
	testCase := DefaultCatalog().Case(self.Row, self.Case)
	if registration == nil || testCase == nil {
		return nil, fmt.Errorf("%s %q has no T2 builder registered", self.Row, self.Case)
	}
	return caseBuilder(registration, testCase), nil
}

// One run a rule makes after the fixed run: an explorer's seed, a write's lost answer or a trace's replay, over the
// schedule or its twin.
type ruleRun struct {
	// Its place among the rules' runs.
	Index int  `json:"index"`
	Twin  bool `json:"twin,omitempty"`
	// The explorer's seed, zero for a lost write or a replay.
	Seed int64      `json:"seed,omitempty"`
	Lost *LostWrite `json:"lost,omitempty"`
	// The trace the run follows.
	Replay *Trace `json:"replay,omitempty"`
}

// Builds and runs it on a Net of its own, over builder, whose schedules run as scheduleId, or over the twin twinOf
// gives when it is the twin's.
func (self *ruleRun) run(ctx context.Context, scheduleId string, builder Builder, twinOf func() (Builder, error), settings *sidecartest.NetSettings) *Result {
	if self.Twin {
		twin, err := twinOf()
		if err != nil {
			return &Result{Id: self.id(scheduleId), Seed: self.Seed, FailedStep: -1, Err: err}
		}
		builder = twin
	}
	switch {
	case self.Replay != nil:
		return runBuilt(ctx, Replay(builder, self.Replay), settings, nil)
	case self.Lost != nil:
		return runBuilt(ctx, builder, settings, lostWriteAdjust(*self.Lost))
	}
	seed := self.Seed
	return runBuilt(ctx, builder, settings, func(schedule *Schedule) {
		schedule.Seed = seed
	})
}

// The id its schedule runs under, from the schedule's own, as the builders name it.
func (self *ruleRun) id(scheduleId string) string {
	if self.Twin {
		scheduleId += " twin"
	}
	if self.Lost != nil {
		scheduleId = lostWriteId(scheduleId, *self.Lost)
	}
	return scheduleId
}

// What one run left, and how long it took in real time.
type ruleOutcome struct {
	result *Result
	took   time.Duration
	// It ended with its child, which left no barrier events to write a trace from.
	childEnded bool
}

// What the stdin of a child begins with: its builder's name, and the id the builder's schedules run under.
type ruleChildHeader struct {
	Name       *ruleChildName `json:"name"`
	ScheduleId string         `json:"schedule_id"`
}

// A run's result as a child sends it: Result's fields, each error as its text.
type ruleChildResult struct {
	Index      int                         `json:"index"`
	Took       time.Duration               `json:"took"`
	Id         string                      `json:"id"`
	Seed       int64                       `json:"seed,omitempty"`
	Failed     bool                        `json:"failed,omitempty"`
	Err        string                      `json:"err,omitempty"`
	FailedStep int                         `json:"failed_step"`
	Events     []*sidecartest.BarrierEvent `json:"events,omitempty"`
	LeftTrace  string                      `json:"left_trace,omitempty"`
	Violations []*ruleChildViolation       `json:"violations,omitempty"`
	Slow       []string                    `json:"slow,omitempty"`
}

type ruleChildViolation struct {
	Invariant string `json:"invariant"`
	Step      int    `json:"step"`
	Final     bool   `json:"final,omitempty"`
	Err       string `json:"err"`
}

func newRuleChildResult(index int, took time.Duration, result *Result) *ruleChildResult {
	childResult := &ruleChildResult{
		Index:      index,
		Took:       took,
		Id:         result.Id,
		Seed:       result.Seed,
		FailedStep: result.FailedStep,
		Events:     result.Events,
		LeftTrace:  result.LeftTrace,
		Slow:       result.Slow,
	}
	if result.Err != nil {
		childResult.Failed = true
		childResult.Err = result.Err.Error()
	}
	for _, violation := range result.Violations {
		text := ""
		if violation.Err != nil {
			text = violation.Err.Error()
		}
		childResult.Violations = append(childResult.Violations, &ruleChildViolation{Invariant: violation.Invariant, Step: violation.Step, Final: violation.Final, Err: text})
	}
	return childResult
}

// The Result the child's run left, its trace's lines read from its events as Run writes them.
func (self *ruleChildResult) result() *Result {
	result := &Result{
		Id:         self.Id,
		Seed:       self.Seed,
		FailedStep: self.FailedStep,
		Events:     self.Events,
		LeftTrace:  self.LeftTrace,
		Slow:       self.Slow,
	}
	if self.Failed {
		result.Err = errors.New(self.Err)
	}
	for _, event := range self.Events {
		result.Trace = append(result.Trace, event.String())
	}
	for _, violation := range self.Violations {
		result.Violations = append(result.Violations, &Violation{Invariant: violation.Invariant, Step: violation.Step, Final: violation.Final, Err: errors.New(violation.Err)})
	}
	return result
}

// How many children the rules' runs over subject may take under settings: none unless a child can rebuild what runs
// here (the file header), and never from inside a child.
func ruleChildCount(settings *RuleSettings, name *ruleChildName) int {
	switch {
	case name == nil || ruleChildEntry == "":
		return 0
	case settings.Processes == nil || settings.Processes.Count <= 1:
		return 0
	case settings.Tier != "" && settings.Tier != TierT2:
		return 0
	case os.Getenv(ruleChildEnvironment) != "":
		return 0
	case sidecartest.InSearchHeapProcess():
		// FS-77's and FS-109's samplers answer only in their search heap process, which no child is
		return 0
	case !reflect.DeepEqual(settings.Net, sidecartest.DefaultNetSettings()):
		// a child builds its Nets from the defaults alone
		return 0
	}
	return settings.Processes.Count
}

// Sends runs to up to count children rebuilding name's builder, whose schedules run as scheduleId, and returns each
// run's outcome in runs' order, nil for a run no child took, which the caller runs itself, and how many children
// started.
func runInChildren(ctx context.Context, name *ruleChildName, scheduleId string, runs []*ruleRun, count int, settings *RuleProcessSettings) ([]*ruleOutcome, int) {
	outcomes := make([]*ruleOutcome, len(runs))
	executable, err := os.Executable()
	if err != nil {
		return outcomes, 0
	}
	queue := make(chan int, len(runs))
	for index := range runs {
		queue <- index
	}
	close(queue)
	started := atomic.Int64{}
	waitGroup := sync.WaitGroup{}
	for range min(count, len(runs)) {
		waitGroup.Go(func() {
			child := &ruleChild{executable: executable, name: name, scheduleId: scheduleId, runs: runs, outcomes: outcomes, settings: settings}
			if child.start(ctx) {
				started.Add(1)
				child.serve(queue)
			}
		})
	}
	waitGroup.Wait()
	return outcomes, int(started.Load())
}

// One child process and the runs it answers. Each run's outcome is written by the one child that took the run off the
// queue, at the run's own index, and read after every child has ended.
type ruleChild struct {
	executable string
	name       *ruleChildName
	scheduleId string
	runs       []*ruleRun
	outcomes   []*ruleOutcome
	settings   *RuleProcessSettings

	command *exec.Cmd
	input   io.WriteCloser
	encoder *json.Encoder
	decoder *json.Decoder
	results *os.File
	output  *tailBuffer
}

// Starts the child and sends it its builder's name. false when it could not start, and then nothing of it is left.
func (self *ruleChild) start(ctx context.Context) bool {
	self.command = exec.CommandContext(ctx, self.executable, "-test.run=^"+ruleChildEntry+"$", "-test.count=1", "-test.timeout=0")
	self.command.Env = append(os.Environ(), ruleChildEnvironment+"=1")
	self.output = newTailBuffer(self.settings.OutputTailByteCount)
	self.command.Stdout = self.output
	self.command.Stderr = self.output
	results, resultsWriter, err := os.Pipe()
	if err != nil {
		return false
	}
	input, err := self.command.StdinPipe()
	if err != nil {
		results.Close()
		resultsWriter.Close()
		return false
	}
	self.command.ExtraFiles = []*os.File{resultsWriter}
	err = self.command.Start()
	// the child holds its own copy of the pipe's write end
	resultsWriter.Close()
	if err != nil {
		results.Close()
		return false
	}
	self.input = input
	self.results = results
	self.encoder = json.NewEncoder(input)
	self.decoder = json.NewDecoder(results)
	if err := self.encoder.Encode(&ruleChildHeader{Name: self.name, ScheduleId: self.scheduleId}); err != nil {
		self.end()
		return false
	}
	return true
}

// Takes runs off queue one at a time until it is empty or the child ends, then ends the child.
func (self *ruleChild) serve(queue <-chan int) {
	for index := range queue {
		run := *self.runs[index]
		run.Index = index
		if err := self.encoder.Encode(&run); err != nil {
			// the child never had the run, so it is left for the caller, which runs it itself
			self.end()
			return
		}
		childResult := &ruleChildResult{}
		if err := self.decoder.Decode(childResult); err != nil || childResult.Index != index {
			waitErr := self.end()
			self.outcomes[index] = &ruleOutcome{
				result: &Result{
					Id:         run.id(self.scheduleId),
					Seed:       run.Seed,
					FailedStep: -1,
					Err:        fmt.Errorf("the child process running it ended (%v; %v), and its output ended with:\n%s", err, waitErr, self.output),
				},
				childEnded: true,
			}
			return
		}
		self.outcomes[index] = &ruleOutcome{result: childResult.result(), took: childResult.Took}
	}
	self.end()
}

// Closes the child's stdin, between runs, which ends it, and waits for it.
func (self *ruleChild) end() error {
	self.input.Close()
	err := self.command.Wait()
	self.results.Close()
	return err
}

// A child process's side: runs each run the parent sends on input over the builder its header names, and writes each
// result to output, until input ends. Its Nets are T2's defaults (ruleChildCount). Input ending while a run is under
// way means the parent is gone, and exit, os.Exit but in this package's tests, ends the process at once.
func serveRuleChild(ctx context.Context, input io.Reader, output io.Writer, exit func(code int)) error {
	decoder := json.NewDecoder(input)
	header := &ruleChildHeader{}
	if err := decoder.Decode(header); err != nil {
		return fmt.Errorf("the child's header: %w", err)
	}
	if header.Name == nil {
		return errors.New("the child's header names no builder")
	}
	builder, err := header.Name.builder()
	if err != nil {
		return err
	}
	settings := sidecartest.DefaultNetSettings()
	var twin Builder
	twinOf := func() (Builder, error) {
		if twin != nil {
			return twin, nil
		}
		// read off a schedule built on a Net of its own, as the parent reads it off the fixed run's
		net := sidecartest.NewNet(ctx, settings)
		schedule := builder(net)
		net.Close()
		if schedule.Twin == nil {
			return nil, fmt.Errorf("%s names no twin", schedule.Id)
		}
		twin = twinBuilder(schedule)
		return twin, nil
	}

	running := atomic.Bool{}
	runs := make(chan *ruleRun)
	go func() {
		defer close(runs)
		for {
			run := &ruleRun{}
			if err := decoder.Decode(run); err != nil {
				if running.Load() {
					exit(ruleChildOrphanExitCode)
				}
				return
			}
			running.Store(true)
			select {
			case runs <- run:
			case <-ctx.Done():
				return
			}
		}
	}()
	encoder := json.NewEncoder(output)
	for run := range runs {
		started := time.Now()
		result := run.run(ctx, header.ScheduleId, builder, twinOf, settings)
		took := time.Since(started)
		// before the answer, after which the parent may close input
		running.Store(false)
		if err := encoder.Encode(newRuleChildResult(run.Index, took, result)); err != nil {
			return err
		}
	}
	return nil
}

// The last limit bytes written to it. Safe for concurrent use.
type tailBuffer struct {
	limit int

	stateLock sync.Mutex
	data      []byte
	// bytes dropped from the front
	dropped int
}

func newTailBuffer(limit int) *tailBuffer {
	return &tailBuffer{limit: max(0, limit)}
}

func (self *tailBuffer) Write(data []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.data = append(self.data, data...)
	if over := len(self.data) - self.limit; 0 < over {
		self.data = append(self.data[:0], self.data[over:]...)
		self.dropped += over
	}
	return len(data), nil
}

func (self *tailBuffer) String() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < self.dropped {
		return fmt.Sprintf("[%d bytes before]\n%s", self.dropped, self.data)
	}
	return string(self.data)
}
