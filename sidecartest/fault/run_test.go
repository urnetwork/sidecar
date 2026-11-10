package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

const toyHeadKey = "head/toy/_"

// A small commit protocol, §11.8's in miniature: read the head, then swap it If-Match, with barriers
// around the swap. The real one is evs's, so this exists to show what a schedule does to a protocol
// and that a broken protocol fails: each mutant below is a bug a check must catch.
type toyWriter struct {
	// A lost response is treated as a refusal to retry from the old read, instead of rereading.
	retriesBlindly bool
	// A failed condition is treated as a commit, which loses the commit.
	trustsPrecondition bool
}

func toyCommits(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	return strings.Split(string(body), ",")
}

func (self *toyWriter) commit(ctx context.Context, net *Net, commitId string) error {
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return err
	}
	object, err := cluster.Get(ctx, toyHeadKey)
	if err != nil {
		return err
	}
	etag := object.Etag
	body, err := io.ReadAll(object.Body)
	if err != nil {
		return err
	}
	for {
		if slices.Contains(toyCommits(body), commitId) {
			// a retry of what committed returns its original result (FI-2)
			return nil
		}
		next := append(bytes.Clone(body), []byte(","+commitId)...)
		if len(body) == 0 {
			next = []byte(commitId)
		}
		net.Barriers().Hit("evs.head_cas.before", "toy")
		newEtag, err := cluster.PutIfMatch(ctx, toyHeadKey, etag, next, nil)
		net.Barriers().Hit("evs.head_cas.after", "toy")

		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			_ = newEtag
			return nil
		case errors.As(err, &unknown) && self.retriesBlindly:
			// the mutant: another try from the same read, with a condition that can only pass if
			// the first attempt never landed. A real blind retry would re-sign; here it appends again
			body = next
			etag = newEtag
			if etag == "" {
				etag = object.Etag
			}
			return self.commitAgain(ctx, cluster, next, commitId)
		case errors.Is(err, sidecar.ErrBlobPrecondition) && self.trustsPrecondition:
			return nil
		case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
			object, err = cluster.Get(ctx, toyHeadKey)
			if err != nil {
				return err
			}
			etag = object.Etag
			if body, err = io.ReadAll(object.Body); err != nil {
				return err
			}
		default:
			return err
		}
	}
}

// The blind mutant's second attempt: rewrites whatever the head now holds with the commit appended
// again, without looking for it first.
func (self *toyWriter) commitAgain(ctx context.Context, cluster sidecar.BlobCluster, next []byte, commitId string) error {
	object, err := cluster.Get(ctx, toyHeadKey)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(object.Body)
	if err != nil {
		return err
	}
	_, err = cluster.PutIfMatch(ctx, toyHeadKey, object.Etag, append(body, []byte(","+commitId)...), nil)
	return err
}

func seedToyHead(ctx context.Context, net *Net) error {
	cluster, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return err
	}
	_, err = cluster.PutIfNoneMatch(ctx, toyHeadKey, []byte("genesis"), nil)
	var unknown *sidecar.BlobUnknownError
	if errors.As(err, &unknown) {
		// never retry past one on faith: reread (host_blobs.go)
		_, err = cluster.Head(ctx, toyHeadKey)
	}
	return err
}

func toyHeadCommits(ctx context.Context, oracle *Oracle) ([]string, error) {
	cluster, err := oracle.Host().Blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	object, err := cluster.Get(ctx, toyHeadKey)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(object.Body)
	if err != nil {
		return nil, err
	}
	return toyCommits(body), nil
}

// What this file's toy promises: each commit lands at most once, and at the end the named ones have.
func commitsOnce(commitIds ...string) Invariant {
	return NewInvariant("toy-commits-once", func(ctx context.Context, oracle *Oracle) error {
		commits, err := toyHeadCommits(ctx, oracle)
		if err != nil {
			return err
		}
		for _, commitId := range commitIds {
			count := 0
			for _, commit := range commits {
				if commit == commitId {
					count += 1
				}
			}
			if 1 < count {
				return fmt.Errorf("%s committed %d times: %v", commitId, count, commits)
			}
			if oracle.Final && count == 0 {
				return fmt.Errorf("%s was lost: %v", commitId, commits)
			}
		}
		return nil
	})
}

func newRunNet(t *testing.T) *Net {
	net := sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	return net
}

// Runs schedule on a net closed before this returns: under sidecar_testhooks only one is open at a time.
func runFresh(t *testing.T, schedule *Schedule) *Result {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	return Run(t.Context(), schedule, net)
}

func wantPass(t *testing.T, result *Result) {
	t.Helper()
	if result.Err != nil {
		t.Fatalf("%s", result)
	}
}

func wantFailure(t *testing.T, result *Result, contains string) {
	t.Helper()
	if result.Err == nil {
		t.Fatalf("passed: %s", result)
	}
	if !strings.Contains(result.Err.Error(), contains) {
		t.Fatalf("failed on something else, want %q: %s", contains, result)
	}
}

func commitAction(writer *toyWriter, commitId string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		return writer.commit(ctx, net, commitId)
	}
}

func seedStep() *Step {
	return &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error { return seedToyHead(ctx, net) }}
}

// FS-1's kernel, at this toy's size: the swap applies, its answer is dropped, another writer commits,
// and the retry finds the commit and returns.
func lostResponseSchedule(writer *toyWriter) *Schedule {
	return &Schedule{
		Id: "toy-lost-response",
		Steps: []*Step{
			seedStep(),
			{Fault: &FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "head/", Result: ApplyThenDrop}},
			{Actor: "writerA", Action: commitAction(writer, "a1"), Await: "evs.head_cas.after@toy"},
			{Actor: "writerB", Action: commitAction(&toyWriter{}, "b1")},
			{Release: []string{"evs.head_cas.after@toy"}},
			{Actor: "writerA", Join: true},
		},
		Check: []Invariant{commitsOnce("a1", "b1"), FI(30)},
	}
}

func TestScheduleOfALostResponsePasses(t *testing.T) {
	wantPass(t, runFresh(t, lostResponseSchedule(&toyWriter{})))
}

// The twin that makes the pass mean something: the same schedule, a writer that does not reread.
func TestScheduleCatchesABlindRetry(t *testing.T) {
	wantFailure(t, runFresh(t, lostResponseSchedule(&toyWriter{retriesBlindly: true})), "committed 2 times")
}

func TestAScheduleRepeatsItsTraceExactly(t *testing.T) {
	first := runFresh(t, lostResponseSchedule(&toyWriter{}))
	wantPass(t, first)
	for range 5 {
		func() {
			net := sidecartest.NewNet(t.Context(), nil)
			defer net.Close()
			again := Run(t.Context(), lostResponseSchedule(&toyWriter{}), net)
			wantPass(t, again)
			if !slices.Equal(first.Trace, again.Trace) {
				t.Errorf("two traces:\n%s\n%s", strings.Join(first.Trace, "\n"), strings.Join(again.Trace, "\n"))
			}
		}()
	}
}

func TestAHeldActorLetsTheOtherCommitFirst(t *testing.T) {
	net := newRunNet(t)
	wantPass(t, Run(t.Context(), &Schedule{
		Id: "toy-order",
		Steps: []*Step{
			seedStep(),
			{Actor: "writerA", Action: commitAction(&toyWriter{}, "a1"), Await: "evs.head_cas.before@toy"},
			{Actor: "writerB", Action: commitAction(&toyWriter{}, "b1")},
			{Release: []string{"evs.head_cas.before@toy"}},
			{Actor: "writerA", Join: true},
		},
		Check: []Invariant{commitsOnce("a1", "b1")},
	}, net))
	commits := headOf(t, net)
	if !slices.Equal(commits, []string{"genesis", "b1", "a1"}) {
		t.Errorf("commits %v", commits)
	}
}

func headOf(t *testing.T, net *Net) []string {
	t.Helper()
	commits, err := toyHeadCommits(sidecartest.InspectContext(t.Context()), &Oracle{Net: net})
	if err != nil {
		t.Fatal(err)
	}
	return commits
}

// A check runs after every step, so a state that is wrong only for a moment is caught at its moment.
func TestChecksRunAfterEveryStepAndAtTheEnd(t *testing.T) {
	steps := []int{}
	finals := 0
	result := runFresh(t, &Schedule{
		Id: "toy-check-cadence",
		Steps: []*Step{
			seedStep(),
			{Advance: 1 * time.Second},
			{Advance: 1 * time.Second},
		},
		Check: []Invariant{NewInvariant("toy-cadence", func(ctx context.Context, oracle *Oracle) error {
			steps = append(steps, oracle.Step)
			if oracle.Final {
				finals += 1
			}
			return nil
		})},
	})
	wantPass(t, result)
	if !slices.Equal(steps, []int{0, 1, 2, 3}) || finals != 1 {
		t.Errorf("steps %v, finals %d", steps, finals)
	}
}

func TestAFailedCheckNamesItsStep(t *testing.T) {
	result := runFresh(t, &Schedule{
		Id: "toy-failed-check",
		Steps: []*Step{
			{Advance: 1 * time.Second},
			{Advance: 1 * time.Second},
		},
		Check: []Invariant{NewInvariant("toy-fails", func(ctx context.Context, oracle *Oracle) error {
			if oracle.Step == 1 {
				return errors.New("the state went bad")
			}
			return nil
		})},
	})
	wantFailure(t, result, "toy-fails after step 1")
	if result.FailedStep != 1 {
		t.Errorf("failed step %d", result.FailedStep)
	}
}

// A check nobody wrote fails the schedule that asks for it (the brief's no fake completeness). FI-19's oracle waits on
// DESIGN-DETAILS section 1, so it stays unbuilt longest.
func TestAnUnbuiltInvariantFailsClosed(t *testing.T) {
	result := runFresh(t, &Schedule{Id: "toy-unbuilt", Check: []Invariant{FI(19)}})
	if !errors.Is(result.Err, ErrInvariantUnbuilt) {
		t.Errorf("err %v", result.Err)
	}
	if !strings.Contains(result.Err.Error(), "FI-19 index erasure") {
		t.Errorf("err %v", result.Err)
	}
}

func TestEveryFiIsCataloged(t *testing.T) {
	for n := 1; n <= 30; n += 1 {
		if invariant := DefaultCatalog().Invariant(n); invariant == nil || invariant.Name == "" {
			t.Errorf("FI-%d has no name", n)
		}
	}
	if count := len(DefaultCatalog().Invariants); count != 30 {
		t.Errorf("%d names", count)
	}
	if built := BuiltInvariants(); !slices.Contains(built, 30) || !slices.Contains(built, 1) || !slices.Contains(built, 6) {
		t.Errorf("built %v", built)
	}
}

func TestRegisteringAnInvariantTwicePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a second check for FI-30 passed")
		}
	}()
	RegisterInvariant(30, func(ctx context.Context, oracle *Oracle) error { return nil })
}

func TestRegisteringAnInvariantOutsideTheCatalogPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("FI-31 passed")
		}
	}()
	RegisterInvariant(31, func(ctx context.Context, oracle *Oracle) error { return nil })
}

// An Action's error fails the schedule at its step, wherever it ran.
func TestAnActionsErrorFailsTheSchedule(t *testing.T) {
	result := runFresh(t, &Schedule{
		Id: "toy-action-error",
		Steps: []*Step{
			{Actor: "writerA", Action: func(ctx context.Context, net *Net) error { return errors.New("refused") }},
		},
	})
	wantFailure(t, result, "refused")
	if result.FailedStep != 0 {
		t.Errorf("failed step %d", result.FailedStep)
	}
}

// §22.8: a schedule waiting over its bound for a barrier fails with its trace.
func TestABarrierNeverReachedFailsWithTheTrace(t *testing.T) {
	settings := sidecartest.DefaultNetSettings()
	settings.Barriers.AwaitTimeout = 10 * time.Millisecond
	net := sidecartest.NewNet(t.Context(), settings)
	t.Cleanup(net.Close)
	blocked := make(chan struct{})
	defer close(blocked)
	result := Run(t.Context(), &Schedule{
		Id: "toy-timeout",
		Steps: []*Step{
			{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
				net.Barriers().Hit("evs.first", "")
				<-blocked
				return nil
			}, Await: "evs.never"},
		},
	}, net)
	wantFailure(t, result, "barrier evs.never")
	if len(result.Trace) == 0 || !strings.Contains(strings.Join(result.Trace, "\n"), "evs.first") {
		t.Errorf("trace %v", result.Trace)
	}
}

func TestAnActionEndingShortOfItsAwaitFailsAtOnce(t *testing.T) {
	result := runFresh(t, &Schedule{
		Id: "toy-no-barrier",
		Steps: []*Step{
			{Actor: "writerA", Action: func(ctx context.Context, net *Net) error { return nil }, Await: "evs.never"},
		},
	})
	wantFailure(t, result, "ended without reaching barrier evs.never")
}

func TestReleasingWhatNobodyHoldsFails(t *testing.T) {
	result := runFresh(t, &Schedule{Id: "toy-release", Steps: []*Step{{Release: []string{"evs.head_cas"}}}})
	wantFailure(t, result, "nothing is held at evs.head_cas")
}

func TestAnActorLeftHeldFailsTheSchedule(t *testing.T) {
	settings := sidecartest.DefaultNetSettings()
	settings.Barriers.AwaitTimeout = 10 * time.Millisecond
	net := sidecartest.NewNet(t.Context(), settings)
	t.Cleanup(net.Close)
	result := Run(t.Context(), &Schedule{
		Id: "toy-left-held",
		Steps: []*Step{
			{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
				net.Barriers().Hit("evs.head_cas", "")
				return nil
			}, Await: "evs.head_cas"},
		},
	}, net)
	wantFailure(t, result, "still held")
}

// A fault that never fires proved nothing, so the schedule says so.
func TestAFaultThatNeverFiresFailsTheSchedule(t *testing.T) {
	result := runFresh(t, &Schedule{
		Id:    "toy-unfired",
		Steps: []*Step{{Fault: &FaultPlan{Op: sidecartest.FaultOpDelete, Result: FailBeforeApply}}},
	})
	wantFailure(t, result, "never fired")
}

func TestAFakeRefusesAResultOnlyT3Has(t *testing.T) {
	result := runFresh(t, &Schedule{
		Id:    "toy-quorum",
		Steps: []*Step{{Fault: &FaultPlan{Op: sidecartest.FaultOpPut, Result: QuorumLoss}}},
	})
	if !errors.Is(result.Err, sidecartest.ErrFaultNeedsRealStore) {
		t.Errorf("err %v", result.Err)
	}
}

func TestABrokenBarrierNameFailsTheSchedule(t *testing.T) {
	result := runFresh(t, &Schedule{
		Id: "toy-bad-name",
		Steps: []*Step{
			{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
				net.Barriers().Hit("no-dots-here", "some/path")
				return nil
			}},
		},
	})
	wantFailure(t, result, "naming rule")
}

func TestABrokenAwaitNameFailsBeforeAnythingRuns(t *testing.T) {
	ran := false
	result := runFresh(t, &Schedule{
		Id: "toy-bad-await",
		Steps: []*Step{
			{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
				ran = true
				return nil
			}, Await: "no-dots-here"},
		},
	})
	wantFailure(t, result, "not <file prefix>.<step>")
	if ran {
		t.Error("the action ran")
	}
}

// Kill and Restart: the process dies held at its barrier, and a new instance works from durable state
// alone, where the old one's commit may or may not stand.
func TestKillAtABarrierAndRestartOnAnotherInstance(t *testing.T) {
	net := newRunNet(t)
	ranAfter := false
	wantPass(t, Run(t.Context(), &Schedule{
		Id: "toy-kill",
		Steps: []*Step{
			seedStep(),
			{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
				if err := (&toyWriter{}).commit(ctx, net, "a1"); err != nil {
					return err
				}
				ranAfter = true
				return nil
			}, Await: "evs.head_cas.after@toy"},
			{Actor: "evs1", Kill: true},
			{Actor: "evs1", Restart: "evs2"},
			{Actor: "evs2", Action: commitAction(&toyWriter{}, "a1")},
		},
		Check: []Invariant{commitsOnce("a1"), FI(30)},
	}, net))
	if ranAfter {
		t.Error("the killed process ran past its barrier")
	}
	if actor := net.Actors().Lookup("evs1"); actor == nil || !actor.Killed() {
		t.Error("evs1 lives")
	}
}

func TestKillingAnActorNobodyStartedFails(t *testing.T) {
	result := runFresh(t, &Schedule{Id: "toy-kill-nobody", Steps: []*Step{{Actor: "evs1", Kill: true}}})
	wantFailure(t, result, "no actor")
}

// A crash point: the swap lands, the process dies before it hears, and a retry from the client on
// another instance finds the commit.
func TestACrashAfterApplyLeavesARetryToFindIt(t *testing.T) {
	net := newRunNet(t)
	returned := false
	wantPass(t, Run(t.Context(), &Schedule{
		Id: "toy-crash",
		Steps: []*Step{
			seedStep(),
			{Fault: &FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "head/", Result: CrashAfterApply}},
			{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
				if err := (&toyWriter{}).commit(ctx, net, "a1"); err != nil {
					return err
				}
				returned = true
				return nil
			}, Await: FaultFired},
			{Actor: "evs2", Action: commitAction(&toyWriter{}, "a1")},
		},
		Check: []Invariant{commitsOnce("a1")},
	}, net))
	if returned {
		t.Error("a crashed process returned")
	}
}

// The other crash point, with nothing committed: the retry commits it.
func TestACrashBeforeApplyLeavesTheRetryToCommit(t *testing.T) {
	wantPass(t, runFresh(t, &Schedule{
		Id: "toy-crash-before",
		Steps: []*Step{
			seedStep(),
			{Fault: &FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "head/", Result: CrashBeforeApply}},
			{Actor: "evs1", Action: commitAction(&toyWriter{}, "a1"), Await: FaultFired},
			{Actor: "evs2", Action: commitAction(&toyWriter{}, "a1")},
		},
		Check: []Invariant{commitsOnce("a1")},
	}))
}

// FS-1's delayed PUT: evs1 dies with its swap on the wire, a retry commits on evs2, and the swap then
// arrives and fails its stale condition. Everything is decided by the steps, none by timing.
func TestADelayedSwapThatArrivesLateFailsItsCondition(t *testing.T) {
	net := newRunNet(t)
	wantPass(t, Run(t.Context(), &Schedule{
		Id: "toy-delay",
		Steps: []*Step{
			seedStep(),
			{Fault: &FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "head/", Result: Delay, Delay: sidecartest.DelayInNetwork}},
			{Actor: "evs1", Action: commitAction(&toyWriter{}, "a1"), Await: FaultFired, Background: false},
			{Actor: "evs1", Kill: true},
			{Actor: "evs2", Action: commitAction(&toyWriter{}, "a1")},
			{Actor: "stripe", Action: func(ctx context.Context, net *Net) error {
				if delivered := net.Fakes().Blobs.DeliverDelayed("meta-1", "head/"); delivered != 1 {
					return fmt.Errorf("delivered %d", delivered)
				}
				return nil
			}},
		},
		Check: []Invariant{commitsOnce("a1"), FI(30)},
	}, net))
}

// The clock moves between steps, and a deadline passed on it is refused: nothing here waits.
func TestAClockMoveBetweenStepsRefusesALateRequest(t *testing.T) {
	net := newRunNet(t)
	wantPass(t, Run(t.Context(), &Schedule{
		Id: "toy-deadline",
		Steps: []*Step{
			seedStep(),
			{Fault: &FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "head/", Result: Delay, Delay: sidecartest.DelayInNetwork}},
			{Actor: "writerA", Action: commitAction(&toyWriter{}, "a1"), Await: FaultFired},
			// past the request's deadline: the client gives up and rereads, and a retry commits
			{Advance: 10 * time.Second},
			{Actor: "writerA", Join: true},
			{Actor: "stripe", Action: func(ctx context.Context, net *Net) error {
				if delivered := net.Fakes().Blobs.DeliverDelayed("meta-1", "head/"); delivered != 1 {
					return fmt.Errorf("delivered %d", delivered)
				}
				return nil
			}},
		},
		Check: []Invariant{commitsOnce("a1"), FI(30)},
	}, net))
	// the swap that arrived late did not commit a second time, which commitsOnce holds, and its
	// refusal came from the deadline, since the head it read still stood
	if commits := headOf(t, net); len(commits) != 2 {
		t.Errorf("commits %v", commits)
	}
}

func TestAnActorsClockOffsetReachesItsDeadlines(t *testing.T) {
	net := newRunNet(t)
	wantPass(t, Run(t.Context(), &Schedule{
		Id: "toy-offset",
		Steps: []*Step{
			{Actor: "evs2", ClockOffset: 150 * time.Millisecond},
			{Actor: "evs2", Action: func(ctx context.Context, net *Net) error {
				if offset := sidecartest.ActorFromContext(ctx).Clock().Now().Sub(net.Clock().Now()); offset != 150*time.Millisecond {
					return fmt.Errorf("offset %v", offset)
				}
				return nil
			}},
		},
	}, net))
}

func TestCountersReachTheNet(t *testing.T) {
	net := newRunNet(t)
	counters := &DriveCounters{ClusterId: "meta-1", Drives: []*sidecartest.DriveCounter{{DriveId: "nvme0n1", SectorsWritten: 1024}}}
	wantPass(t, Run(t.Context(), &Schedule{Id: "toy-counters", Steps: []*Step{{Counters: counters}}}, net))
	if net.DriveCounters("meta-1") != counters {
		t.Error("the counters did not arrive")
	}
}

// Actors of Background steps queue together, and the fixed schedule runs them in the order written.
func TestBackgroundActorsStartTogetherAndRunInOrder(t *testing.T) {
	order := []string{}
	note := func(name string) func(ctx context.Context, net *Net) error {
		return func(ctx context.Context, net *Net) error {
			order = append(order, name)
			net.Barriers().Hit("evs.step", "")
			order = append(order, name)
			return nil
		}
	}
	wantPass(t, runFresh(t, &Schedule{
		Id: "toy-background",
		Steps: []*Step{
			{Actor: "writerA", Action: note("a"), Background: true},
			{Actor: "writerB", Action: note("b"), Background: true},
			{Actor: "writerC", Action: note("c")},
			{Actor: "writerA", Join: true},
			{Actor: "writerB", Join: true},
		},
	}))
	if !slices.Equal(order, []string{"a", "a", "b", "b", "c", "c"}) {
		t.Errorf("order %v", order)
	}
}

func raceSchedule(writerA *toyWriter, writerB *toyWriter) *Schedule {
	return &Schedule{
		Id: "toy-race",
		Steps: []*Step{
			seedStep(),
			{Actor: "writerA", Action: commitAction(writerA, "a1"), Background: true},
			{Actor: "writerB", Action: commitAction(writerB, "b1"), Background: true},
			{Actor: "writerA", Join: true},
			{Actor: "writerB", Join: true},
		},
		Check: []Invariant{commitsOnce("a1", "b1"), FI(30)},
	}
}

// §22.8's explorer: a correct writer passes every seed.
func TestExplorerPassesACorrectProtocol(t *testing.T) {
	report := Explore(t.Context(), func(net *Net) *Schedule {
		return raceSchedule(&toyWriter{}, &toyWriter{})
	}, toyRuleSettings(t))
	for _, failure := range report.Failures {
		t.Errorf("%s", failure)
	}
}

// Rule settings for a toy: the merge seeds, and traces into a directory of the test's own, never the
// repository's.
func toyRuleSettings(t *testing.T) *RuleSettings {
	settings := DefaultRuleSettings()
	settings.SeedsDirectory = t.TempDir()
	return settings
}

// The explorer's reason to exist: the fixed order runs these one after the other and never sees the
// bug, which needs the two swaps to interleave, and a seed finds it.
func TestExplorerFindsARaceTheFixedOrderMisses(t *testing.T) {
	mutant := &toyWriter{trustsPrecondition: true}
	wantPass(t, runFresh(t, raceSchedule(mutant, mutant)))

	settings := toyRuleSettings(t)
	settings.Seeds = seedRange(40)
	failures := Explore(t.Context(), func(net *Net) *Schedule {
		return raceSchedule(mutant, mutant)
	}, settings).Failures
	if len(failures) == 0 {
		t.Fatal("40 seeds found no interleaving where a commit was lost")
	}
	if !strings.Contains(failures[0].Err.Error(), "was lost") {
		t.Errorf("failed on something else: %s", failures[0])
	}
	if failures[0].Seed == 0 {
		t.Error("a failure lost its seed")
	}
}

// A failing seed is a fixed schedule: rerunning it gives the same order and the same failure.
func TestASeedRepeatsItsOrder(t *testing.T) {
	run := func() *Result {
		net := sidecartest.NewNet(t.Context(), nil)
		defer net.Close()
		schedule := raceSchedule(&toyWriter{}, &toyWriter{})
		schedule.Seed = 7
		return Run(t.Context(), schedule, net)
	}
	first, second := run(), run()
	wantPass(t, first)
	wantPass(t, second)
	if !slices.Equal(first.Trace, second.Trace) {
		t.Errorf("two traces:\n%s\n%s", strings.Join(first.Trace, "\n"), strings.Join(second.Trace, "\n"))
	}
}

// §22.8's unknown rule, applied to every write in a schedule.
func TestEveryWriteUnknownPassesACorrectProtocol(t *testing.T) {
	failures, _ := EveryWrite(t.Context(), func(net *Net) *Schedule {
		return raceSchedule(&toyWriter{}, &toyWriter{})
	}, nil)
	for _, failure := range failures {
		t.Errorf("%s", failure)
	}
}

func TestEveryWriteUnknownCatchesABlindRetry(t *testing.T) {
	failures, _ := EveryWrite(t.Context(), func(net *Net) *Schedule {
		return raceSchedule(&toyWriter{retriesBlindly: true}, &toyWriter{})
	}, nil)
	if len(failures) == 0 {
		t.Fatal("no lost response caught the blind retry")
	}
	if !strings.Contains(failures[0].Err.Error(), "committed 2 times") {
		t.Errorf("failed on something else: %s", failures[0])
	}
}

// FI-2's store clause on a cleanup that trusts a lost response.
func TestUnknownDeletesNothingCatchesACleanupOnAnUnknownOutcome(t *testing.T) {
	cleanup := func(rereads bool) *Schedule {
		return &Schedule{
			Id: "toy-cleanup",
			Steps: []*Step{
				{Fault: &FaultPlan{Op: sidecartest.FaultOpPut, Result: ApplyThenDrop}},
				{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
					cluster, err := net.Host().Blobs.FirstCluster()
					if err != nil {
						return err
					}
					if _, err := cluster.PutIfNoneMatch(ctx, "slot/a/_", []byte("v"), nil); err == nil {
						return errors.New("the plan did not fire")
					}
					if rereads {
						if _, err := cluster.Head(ctx, "slot/a/_"); err != nil {
							return err
						}
						return nil
					}
					return cluster.Delete(ctx, "slot/a/_")
				}},
			},
			Check: []Invariant{UnknownDeletesNothing},
		}
	}
	wantFailure(t, runFresh(t, cleanup(false)), "on an unknown outcome")
	wantPass(t, runFresh(t, cleanup(true)))
}

// FI-30 with a store that breaks the settle rule: a mutant cluster that lets a write land after a
// later request saw the key without it, past its deadline.
func TestFi30CatchesAWriteLandingPastItsDeadline(t *testing.T) {
	net := newRunNet(t)
	host := *net.Host()
	mutant := &lateLandingBlobs{BlobStore: net.Fakes().Blobs}
	host.Blobs = mutant
	net.AddEngines(&host)
	result := Run(t.Context(), &Schedule{
		Id: "toy-late",
		Steps: []*Step{
			{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
				cluster, err := net.Host().Blobs.FirstCluster()
				if err != nil {
					return err
				}
				var unknown *sidecar.BlobUnknownError
				if _, err := cluster.PutIfNoneMatch(ctx, "head/a/_", []byte("late"), nil); !errors.As(err, &unknown) {
					return fmt.Errorf("err %v", err)
				}
				return nil
			}},
			{Advance: 11 * time.Second},
			{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
				cluster, err := net.Host().Blobs.FirstCluster()
				if err != nil {
					return err
				}
				if _, err := cluster.Head(ctx, "head/a/_"); !errors.Is(err, sidecar.ErrBlobNotFound) {
					return fmt.Errorf("err %v", err)
				}
				// the write lands now, long past its deadline, which the settle rule forbids
				mutant.land(ctx)
				_, err = cluster.Head(ctx, "head/a/_")
				return err
			}},
		},
		Check: []Invariant{FI(30)},
	}, net)
	wantFailure(t, result, "FI-30")
}

// A cluster whose first PUT is lost until land writes it, as the deployed MinIO can do (§19.6's settle
// row).
type lateLandingBlobs struct {
	sidecar.BlobStore
	pendingKey  string
	pendingBody []byte
}

func (self *lateLandingBlobs) FirstCluster() (sidecar.BlobCluster, error) {
	cluster, err := self.BlobStore.FirstCluster()
	if err != nil {
		return nil, err
	}
	return &lateLandingCluster{BlobCluster: cluster, store: self}, nil
}

func (self *lateLandingBlobs) land(ctx context.Context) {
	cluster, err := self.BlobStore.FirstCluster()
	if err != nil {
		panic(err)
	}
	// around the deadline, as a stalled drive commit is
	if _, err := cluster.PutIfNoneMatch(context.WithoutCancel(ctx), self.pendingKey, self.pendingBody, nil); err != nil {
		panic(err)
	}
}

type lateLandingCluster struct {
	sidecar.BlobCluster
	store *lateLandingBlobs
}

func (self *lateLandingCluster) PutIfNoneMatch(ctx context.Context, key string, body []byte, options *sidecar.BlobPutOptions) (string, error) {
	self.store.pendingKey = key
	self.store.pendingBody = body
	return "", &sidecar.BlobUnknownError{Err: errors.New("the answer never came")}
}

// Three writes, the row's own fault armed first, each write reread after an unknown or refused answer,
// as §11.8 says.
func threeWrites(plan *FaultPlan) *Schedule {
	return &Schedule{
		Id: "three-writes",
		Steps: []*Step{
			{Fault: plan},
			{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
				cluster, err := net.Host().Blobs.FirstCluster()
				if err != nil {
					return err
				}
				for _, key := range []string{"a/_", "b/_", "c/_"} {
					if _, err := cluster.PutIfNoneMatch(ctx, key, []byte("v"), nil); err != nil {
						if _, err := cluster.Head(ctx, key); err != nil && !errors.Is(err, sidecar.ErrBlobNotFound) {
							return err
						}
					}
				}
				return nil
			}},
		},
		Check: []Invariant{UnknownDeletesNothing, FI(30)},
	}
}

// Every write runs with its response lost, the one the row fails before apply included: the failure
// gives way, counted as fired, since its caller could not have told the two apart.
func TestEveryWriteUnknownCountsAWriteTheRowFaultsItself(t *testing.T) {
	builds := 0
	failures, _ := EveryWrite(t.Context(), func(net *Net) *Schedule {
		builds += 1
		return threeWrites(&FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "a/", Result: FailBeforeApply})
	}, nil)
	for _, failure := range failures {
		t.Errorf("%s", failure)
	}
	if builds != 4 {
		t.Errorf("%d builds: want one to count and one for each of the 3 writes", builds)
	}
}

// A write the row holds keeps its hold, which is the row's own case, and no plan goes unfired.
func TestEveryWriteUnknownLeavesARowsOwnHold(t *testing.T) {
	builds := 0
	failures, _ := EveryWrite(t.Context(), func(net *Net) *Schedule {
		builds += 1
		return threeWrites(&FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: "b/", Result: Held})
	}, nil)
	for _, failure := range failures {
		t.Errorf("%s", failure)
	}
	if builds != 3 {
		t.Errorf("%d builds: want one to count and one for each write the row does not hold", builds)
	}
}

// An actor blocked where no barrier sees it loses the baton at the stall timeout, and the actor behind
// it runs out of the schedule's order. The run fails rather than pass under an order it did not choose.
func TestARunInWhichAnActorStalledFails(t *testing.T) {
	settings := sidecartest.DefaultNetSettings()
	// writerA stalls however long this is. writerB only closes the gate, but on a loaded machine it can
	// keep the baton past a 1 ms timeout and be named as well, so it gets room here, and the check asks
	// only that writerA is among those named.
	settings.Barriers.StallTimeout = 50 * time.Millisecond
	net := sidecartest.NewNet(t.Context(), settings)
	defer net.Close()
	gate := make(chan struct{})
	result := Run(t.Context(), &Schedule{
		Id: "stall",
		Steps: []*Step{
			// started first, so it takes the baton first, and keeps it waiting where no barrier sees
			{Actor: "writerA", Background: true, Action: func(ctx context.Context, net *Net) error {
				<-gate
				return nil
			}},
			{Actor: "writerB", Action: func(ctx context.Context, net *Net) error {
				close(gate)
				return nil
			}},
		},
	}, net)
	stalled := ""
	if result.Err != nil {
		stalled, _, _ = strings.Cut(result.Err.Error(), " stalled, blocked where no barrier sees it")
		if i := strings.LastIndex(stalled, ": "); 0 <= i {
			stalled = stalled[i+2:]
		}
	}
	if !slices.Contains(strings.Split(stalled, ", "), "writerA") {
		t.Errorf("%s", result)
	}
}

// A row whose connect clients run on the fake contract issuer and ControlId sink names T3, where a
// divergence from server's exchange fails (Q-TEST-1). One that does not fails here.
func TestARowOnThePlatformFakesNamesT3(t *testing.T) {
	run := func(tiers []Tier) *Result {
		net := sidecartest.NewNet(t.Context(), nil)
		defer net.Close()
		return Run(t.Context(), &Schedule{
			Id: "platform-fakes",
			Steps: []*Step{
				{Actor: "daemonM", Action: func(ctx context.Context, net *Net) error {
					net.AddClient("m", nil)
					return nil
				}},
			},
			Tiers: tiers,
		}, net)
	}
	if result := run(nil); result.Err == nil || !strings.Contains(result.Err.Error(), "Q-TEST-1") {
		t.Errorf("%s", result)
	}
	wantPass(t, run([]Tier{TierT2, TierT3}))
}

// A Net that refuses the platform fakes, as T3's does until server's exchange carries its clients, fails a
// row that added a client there, whatever tiers it names; a row adding none passes on it.
func TestANetRefusingThePlatformFakesFailsARowOnThem(t *testing.T) {
	run := func(addClient bool) *Result {
		settings := sidecartest.DefaultNetSettings()
		settings.RefusePlatformFakes = "T3's clients ride server's exchange"
		net := sidecartest.NewNet(t.Context(), settings)
		defer net.Close()
		return Run(t.Context(), &Schedule{
			Id: "platform-fakes-refused",
			Steps: []*Step{
				{Actor: "daemonM", Action: func(ctx context.Context, net *Net) error {
					if addClient {
						net.AddClient("m", nil)
					}
					return nil
				}},
			},
			Tiers: []Tier{TierT2, TierT3},
		}, net)
	}
	if result := run(true); result.Err == nil || !strings.Contains(result.Err.Error(), "T3's clients ride server's exchange") {
		t.Errorf("%s", result)
	}
	wantPass(t, run(false))
}
