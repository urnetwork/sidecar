// Runs a Schedule. Run reports through its Result rather than failing a test, so a schedule that must
// fail can be asserted, which is how a mutant proves a check bites.

package fault

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// What a run did.
type Result struct {
	Id   string
	Seed int64
	// Why it failed, or nil. A failed step or invariant.
	Err error
	// The step it failed at, or -1 for the end of the run.
	FailedStep int
	// Every barrier event, in order: what a failing seed becomes a fixed schedule from.
	Trace []string
}

func (self *Result) String() string {
	var text strings.Builder
	fmt.Fprintf(&text, "%s seed=%d", self.Id, self.Seed)
	if self.Err == nil {
		text.WriteString(" passed\n")
	} else {
		fmt.Fprintf(&text, " failed at step %d: %v\n", self.FailedStep, self.Err)
	}
	for _, line := range self.Trace {
		text.WriteString("  ")
		text.WriteString(line)
		text.WriteByte('\n')
	}
	return text.String()
}

type runner struct {
	ctx      context.Context
	schedule *Schedule
	net      *Net
	barriers *sidecartest.BarrierDriver
	random   *rand.Rand
	// the plans armed so far, latest last, each with what closes when it first fires
	lastFired <-chan struct{}
	runs      []*sidecartest.ActorRun
	// started by Background steps and not yet resumed
	paused bool
}

// Runs schedule on net, which it leaves to its caller to close.
func Run(ctx context.Context, schedule *Schedule, net *Net) *Result {
	self := &runner{ctx: ctx, schedule: schedule, net: net, barriers: net.Barriers()}
	result := &Result{Id: schedule.Id, Seed: schedule.Seed, FailedStep: -1}
	if schedule.Seed != 0 {
		self.barriers.SetSeed(schedule.Seed)
		self.random = rand.New(rand.NewPCG(uint64(schedule.Seed), 0xfa17))
	}
	result.Err = self.run(result)
	for _, event := range self.barriers.Trace() {
		result.Trace = append(result.Trace, event.String())
	}
	// after the last check: what a dead actor's deferred calls do, nothing reads
	self.barriers.Close()
	return result
}

// Runs schedule on a net of its own, and fails t with the trace if it fails.
func RunTest(t testing.TB, schedule *Schedule, settings *sidecartest.NetSettings) {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), settings)
	defer net.Close()
	if result := Run(t.Context(), schedule, net); result.Err != nil {
		t.Fatalf("%s", result)
	}
}

func (self *runner) run(result *Result) error {
	for _, step := range self.schedule.Steps {
		if step.Await == "" || step.Await == FaultFired {
			continue
		}
		if err := self.barriers.Arm(step.Await, step.Actor, step.AwaitSkip); err != nil {
			return err
		}
	}
	for index, step := range self.schedule.Steps {
		if err := self.runStep(step); err != nil {
			result.FailedStep = index
			return fmt.Errorf("%v: %w", step, err)
		}
		if err := self.check(index, false); err != nil {
			result.FailedStep = index
			return err
		}
	}
	if err := self.finish(); err != nil {
		return err
	}
	return self.check(len(self.schedule.Steps), true)
}

func (self *runner) runStep(step *Step) error {
	self.barriers.Pause()
	self.paused = true
	if step.Fault != nil {
		fired, err := self.net.Faults().Add(step.Fault)
		if err != nil {
			return err
		}
		self.lastFired = fired
	}
	if step.Counters != nil {
		self.net.SetDriveCounters(step.Counters)
	}
	if step.Advance != 0 {
		self.net.Clock().Advance(step.Advance)
	}
	if step.Kill {
		if err := self.net.Kill(step.Actor); err != nil {
			return err
		}
	}
	if step.Restart != "" {
		if err := self.net.Restart(step.Actor, step.Restart); err != nil {
			return err
		}
	}
	if step.ClockOffset != 0 {
		actor := self.net.Actors().Actor(self.net.Context(), step.Actor)
		actor.SetClockOffset(self.net.Clock(), step.ClockOffset)
	}
	release := step.Release
	if self.random != nil {
		// the explorer's other choice: the order of a Release is the schedule's only in a fixed run
		release = slices.Clone(release)
		self.random.Shuffle(len(release), func(i int, j int) { release[i], release[j] = release[j], release[i] })
	}
	for _, site := range release {
		if err := self.barriers.Release(site); err != nil {
			return err
		}
	}
	var run *sidecartest.ActorRun
	if step.Action != nil {
		actor := self.net.Actors().Actor(self.ctx, step.Actor)
		run = self.barriers.Start(actor, func() error {
			return step.Action(actor.Context(), self.net)
		})
		self.runs = append(self.runs, run)
	}
	if step.Background {
		return nil
	}
	self.resume()
	if err := self.waitStep(step, run); err != nil {
		return err
	}
	if err := self.barriers.Settle(self.ctx); err != nil {
		return err
	}
	return self.failedRun()
}

func (self *runner) resume() {
	if self.paused {
		self.paused = false
		self.barriers.Resume()
	}
}

// Waits for what the step says it ends on.
func (self *runner) waitStep(step *Step, run *sidecartest.ActorRun) error {
	switch {
	case step.Await == FaultFired:
		if self.lastFired == nil {
			return errors.New("no fault armed to wait for")
		}
		return self.barriers.AwaitChannel(self.ctx, "the fault to fire", self.lastFired)
	case step.Await != "":
		return self.barriers.AwaitHeldOrEnded(self.ctx, step.Await, step.Actor, run)
	case step.Join:
		for _, each := range self.runs {
			if each.Actor().Name() == step.Actor {
				if err := self.barriers.AwaitChannel(self.ctx, "actor "+step.Actor+" to end", each.Ended()); err != nil {
					return err
				}
			}
		}
		return nil
	case run != nil:
		return self.barriers.AwaitChannel(self.ctx, "actor "+step.Actor+" to end", run.Ended())
	}
	return nil
}

// A run that ended with an error fails the schedule, whichever step was going.
func (self *runner) failedRun() error {
	for _, run := range self.runs {
		select {
		case <-run.Ended():
			if err := run.Err(); err != nil {
				return fmt.Errorf("actor %s: %w", run.Actor().Name(), err)
			}
		default:
		}
	}
	return nil
}

func (self *runner) check(step int, final bool) error {
	// after a Background step nothing has run yet, so there is nothing to settle
	if !self.paused {
		if err := self.barriers.Settle(self.ctx); err != nil {
			return err
		}
	}
	oracle := &Oracle{Net: self.net, Step: step, Final: final}
	ctx := sidecartest.InspectContext(self.ctx)
	for _, invariant := range self.schedule.Check {
		if err := invariant.Check(ctx, oracle); err != nil {
			return fmt.Errorf("%s after step %d: %w", invariant.Id(), step, err)
		}
	}
	if violations := self.barriers.Violations(); 0 < len(violations) {
		return fmt.Errorf("a barrier broke its naming rule: %s", strings.Join(violations, "; "))
	}
	return self.stalled()
}

// An actor that kept the baton past the stall timeout let another run while it ran on, in an order the
// schedule did not choose and a seed cannot repeat, so the run proves nothing it can be held to (§22.8's
// determinism row).
func (self *runner) stalled() error {
	actorNames := []string{}
	for _, event := range self.barriers.Trace() {
		if event.Kind == sidecartest.BarrierStalled && !slices.Contains(actorNames, event.Actor) {
			actorNames = append(actorNames, event.Actor)
		}
	}
	if 0 < len(actorNames) {
		return fmt.Errorf("%s stalled, blocked where no barrier sees it, and the run left the schedule's order", strings.Join(actorNames, ", "))
	}
	return nil
}

// The schedule's end: everything it started has ended, every barrier it named was reached and let go,
// and every fault it armed fired. Anything left means the schedule did not do what it says.
func (self *runner) finish() error {
	self.resume()
	for _, run := range self.runs {
		if err := self.barriers.AwaitChannel(self.ctx, "actor "+run.Actor().Name()+" to end", run.Ended()); err != nil {
			if held := self.barriers.HeldSites(); 0 < len(held) {
				return fmt.Errorf("%w, with %v still held", err, held)
			}
			return err
		}
	}
	if err := self.failedRun(); err != nil {
		return err
	}
	if armed := self.barriers.ArmedSites(); 0 < len(armed) {
		return fmt.Errorf("never reached: %v", armed)
	}
	if held := self.barriers.HeldSites(); 0 < len(held) {
		return fmt.Errorf("still held at the end: %v", held)
	}
	if unfired := self.net.Faults().Unfired(); 0 < len(unfired) {
		return fmt.Errorf("never fired: %v", unfired)
	}
	return nil
}

// §22.8's explorer: runs one schedule under each seed, on a fresh Net from build each time. Every
// failure comes back with its seed and trace, from which it becomes a fixed schedule.
func Explore(ctx context.Context, seeds []int64, build func(net *Net) *Schedule, settings *sidecartest.NetSettings) []*Result {
	failures := []*Result{}
	for _, seed := range seeds {
		func() {
			net := sidecartest.NewNet(ctx, settings)
			defer net.Close()
			schedule := build(net)
			schedule.Seed = seed
			if result := Run(ctx, schedule, net); result.Err != nil {
				failures = append(failures, result)
			}
		}()
	}
	return failures
}

// §22.8's seeds for a T2 row at each merge: 1 to 10.
func MergeSeeds() []int64 {
	return []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
}

// §22.8's unknown rule: every write in the named rows also runs with ApplyThenDrop. This runs the
// schedule once to count its writes, then once for each, with that write's response lost, and returns
// the failures. Writes are counted where a plan counts them, at the fault queue, so a write the
// schedule's own plan faults counts as well as one a store served. A write the schedule fails before
// apply runs with its response lost instead, its plan counting as fired there, since a caller cannot
// tell the two apart; one the schedule delays, holds, crashes or already drops keeps that fault, which
// is the row's own. A fake counts the writes, so this is T2's; a T3 row sets its own plans.
func RunEveryWriteUnknown(ctx context.Context, build func(net *Net) *Schedule, settings *sidecartest.NetSettings) []*Result {
	writeOps := []string{sidecartest.FaultOpPut, sidecartest.FaultOpDelete}
	opResults := map[string][]FaultResult{}
	failures := []*Result{}
	func() {
		net := sidecartest.NewNet(ctx, settings)
		defer net.Close()
		result := Run(ctx, build(net), net)
		if result.Err != nil {
			failures = append(failures, result)
		}
		for _, op := range writeOps {
			opResults[op] = net.Faults().OpResults(op)
		}
	}()
	if 0 < len(failures) {
		return failures
	}
	runLost := func(op string, nth int) {
		net := sidecartest.NewNet(ctx, settings)
		defer net.Close()
		schedule := build(net)
		lost := &FaultPlan{Op: op, Nth: nth, Result: ApplyThenDrop, Displaces: true}
		schedule.Steps = append([]*Step{{Fault: lost}}, schedule.Steps...)
		schedule.Id = fmt.Sprintf("%s with %s %d's response lost", schedule.Id, op, nth)
		if result := Run(ctx, schedule, net); result.Err != nil {
			failures = append(failures, result)
		}
	}
	for _, op := range writeOps {
		for index, result := range opResults[op] {
			if result == 0 || result == FailBeforeApply {
				runLost(op, index+1)
			}
		}
	}
	return failures
}
