// FS-1 (§22.8; §11.8's outcome rows, D-EVS-23, I-EVS-2, I-EVS-3; EVS1-M2-40) on the evs world (evs_world.go): real
// pushes by sidecar.EvsClient devices through evsservice's engine, on T2's fakes and, through server's evshost,
// on T3's stores. FS-1 is on §22.8's unknown list, so every write each clause issues also runs with its response lost.
//
// The registered case, Fs1LostAnswerRetriedOnEvs2: writerB commits 62 versions; writerA's push P, a segment, reaches
// evs1, whose head CAS applies and loses its answer; evs1 is killed at the CAS, so the lb sends P on to evs2, which
// holds it at arrival while writerB adds 66 commits, paging P's version out of the window into log page 0; released,
// evs2 finds P in the log page and answers the original version, once; then the clock passes 26 h, evacuation and the
// nightly pass with orphan GC run, and the closure stays whole (FI-1), the reader reading P throughout.
//
// The clauses beside it, each an exported Builder that fs1_test.go runs under the same rules (CheckClause):
//
//   - Fs1ConcurrentRetries: two attempts of one push id reach evs1 and evs2 at once, and commit once, each answering
//     the same version;
//   - Fs1UnknownDeletesNothing: evs1's head CAS applies and loses its answer, and every reread of the head fails, as
//     reads losing quorum do: evs1 answers 503 unknown, the device gives up with the outcome unknown, and nothing is
//     deleted; the head then shows P committed once, and the reader reads it.
//
// What FS-1 also names and these schedules do not yet run is EVS1-M2-40's report: evs1's delayed step 7 across a
// gate closing with the refusal recorded on evs2, evs1 in its 412 loop past the lb's read timeout while evs2
// answers 429 BUSY, the git-mode PATH_EPOCH and FORCE pushes, a stream of recorded refusals beside honest pushes,
// and evs2's clock 150 ms fast. FI-2 holds through the world's checks (TEST-M2-04); FI-9's oracle is not bound
// (TEST-M2-06), so the schedules name nothing in its place.

package fault

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs1 = Register("FS-1", "", []Tier{TierT2, TierT3}, Fs1LostAnswerRetriedOnEvs2)

// A step writing count paths in steps of at most 16 pushes each, so each step stays well inside §22.8's 10 s and the
// outcome check reads every version in the window.
func evsWorldWriteSteps(world *EvsWorld, device string, pattern string, first int, count int) []*Step {
	steps := []*Step{}
	for start := first; start < first+count; start += 16 {
		steps = append(steps, &Step{Actor: device, Action: world.WriteMany(device, pattern, start, min(16, first+count-start))})
	}
	return steps
}

// See the file header.
func Fs1LostAnswerRetriedOnEvs2(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	pContent := EvsWorldContent("fs1 p", 64*1024)
	steps := []*Step{{Actor: "writerA", Action: world.Setup}}
	steps = append(steps, evsWorldWriteSteps(world, "writerB", "pre/%03d", 0, 62)...)
	steps = append(steps, []*Step{
		{Fault: &FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: evsservice.HeadRepoPrefix(world.RepoId), Result: ApplyThenDrop, Actor: "evs1", WritesOnly: true}},
		{Actor: "writerA", Action: world.WriteAny("writerA", "p.bin", pContent), Background: true},
		{Actor: "evs1", Await: evsservice.BarrierHeadCasAfter},
		{Actor: "evs1", Kill: true},
		{Actor: "evs2", Await: evsservice.BarrierPushArrive},
		{Actor: "reader", Action: world.Verify("reader", "p.bin", "pre/000", "pre/061")},
	}...)
	steps = append(steps, evsWorldWriteSteps(world, "writerB", "post/%03d", 0, 66)...)
	steps = append(steps, []*Step{
		{Actor: "check", Action: world.Expect("P paged out of the window", func(ctx context.Context) error {
			return fs1PagedOut(ctx, world)
		})},
		{Release: []string{evsservice.BarrierPushArrive}},
		{Actor: "writerA", Join: true},
		{Actor: "check", Action: world.Expect("P answered its original version once", func(ctx context.Context) error {
			return fs1AnsweredOriginal(world)
		})},
		{Actor: "reader", Action: world.Verify("reader", "p.bin", "post/065")},
		{Advance: 26 * time.Hour},
		{Actor: "evacuator", Action: world.Evacuate()},
		{Advance: 25 * time.Hour},
		{Actor: "gc", Action: world.Nightly()},
		{Actor: "reader", Action: world.Verify("reader", "p.bin", "pre/030", "post/000")},
	}...)
	return &Schedule{Id: "FS-1", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// P's version left the window for a log page.
func fs1PagedOut(ctx context.Context, world *EvsWorld) error {
	pushes := world.DevicePushes("writerA")
	if len(pushes) != 1 {
		return fmt.Errorf("writerA posted %d push ids", len(pushes))
	}
	version, ok := world.committedVersionOf(pushes[0].PushId)
	if !ok {
		return fmt.Errorf("P is not in main's history")
	}
	head, err := world.Head(ctx)
	if err != nil {
		return err
	}
	if first := evsservice.EvsHeadWindowFirstVersion(head); first <= version {
		return fmt.Errorf("P at %d is still in the window, which starts at %d", version, first)
	}
	return nil
}

// writerA's write committed at P's version, which every 200 named, and the lb answered P once with it.
func fs1AnsweredOriginal(world *EvsWorld) error {
	version, pushId, err := world.CommittedVersion("writerA", "p.bin")
	if err != nil {
		return err
	}
	committedAt, ok := world.committedVersionOf(pushId)
	if !ok || committedAt != version {
		return fmt.Errorf("writerA's write answered %d, and P's history says %d (%t)", version, committedAt, ok)
	}
	pushes := world.DevicePushes("writerA")
	if len(pushes) != 1 {
		return fmt.Errorf("writerA posted %d push ids", len(pushes))
	}
	lbAnswers := 0
	for _, answer := range pushes[0].Answers {
		if answer.Instance == "lb" {
			lbAnswers += 1
			if answer.Status != http.StatusOK || answer.Version != version {
				return fmt.Errorf("the lb answered %s", answer)
			}
		}
	}
	if lbAnswers != 1 {
		return fmt.Errorf("the lb answered P %d times", lbAnswers)
	}
	return nil
}

// Two attempts of one push id at once commit once: see the file header.
func Fs1ConcurrentRetries(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "a.txt", EvsWorldContent("fs1 a", 100))},
		{Actor: "writerA", Action: world.DuplicateNextPush("writerA", "evs1", "evs2")},
		{Actor: "writerA", Action: world.Write("writerA", "b.bin", EvsWorldContent("fs1 b", 32*1024))},
		{Actor: "check", Action: world.Expect("both attempts answered the one version", func(ctx context.Context) error {
			pushes := world.DevicePushes("writerA")
			push := pushes[len(pushes)-1]
			answers := push.InstanceAnswers()
			if len(answers) != 2 {
				return fmt.Errorf("%d instance answers: %v", len(answers), answers)
			}
			version, _, err := world.CommittedVersion("writerA", "b.bin")
			if err != nil {
				return err
			}
			for _, answer := range answers {
				if answer.Status != http.StatusOK || answer.Version != version {
					return fmt.Errorf("%s, and the write committed at %d", answer, version)
				}
			}
			return nil
		})},
		{Actor: "reader", Action: world.Verify("reader", "a.txt", "b.bin")},
	}
	return &Schedule{Id: "FS-1 concurrent retries", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// A lost head CAS answer whose rereads all fail: see the file header.
func Fs1UnknownDeletesNothing(net *Net) *Schedule {
	settings := DefaultEvsWorldSettings()
	settings.Devices[0].Instances = []string{"evs1"}
	world := NewEvsWorld(net, settings)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "a.txt", EvsWorldContent("fs1 a", 100))},
		{Actor: "writerA", Action: world.WriteAny("writerA", "p.txt", EvsWorldContent("fs1 p", 200)), Background: true},
		// a.txt's CAS passes first
		{Actor: "evs1", Await: evsservice.BarrierHeadCasBefore, AwaitSkip: 1},
		{Fault: &FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: evsservice.HeadRepoPrefix(world.RepoId), Result: ApplyThenDrop, Actor: "evs1", WritesOnly: true}},
		{Fault: &FaultPlan{Op: sidecartest.FaultOpGet, KeyPrefix: evsservice.HeadRepoPrefix(world.RepoId), Result: FailBeforeApply, Actor: "evs1", Repeat: -1}},
		{Release: []string{evsservice.BarrierHeadCasBefore}},
		{Actor: "writerA", Join: true},
		{Actor: "check", Action: world.Expect("P answered unknown and committed once", func(ctx context.Context) error {
			pushes := world.DevicePushes("writerA")
			push := pushes[len(pushes)-1]
			// the attempt whose CAS applied answers unknown, and each retry, reading nothing, refuses nothing
			answers := push.InstanceAnswers()
			if len(answers) == 0 || !answers[0].Unknown {
				return fmt.Errorf("evs1 answered %v, the first not unknown", answers)
			}
			for _, answer := range answers {
				if answer.Status != http.StatusServiceUnavailable {
					return fmt.Errorf("evs1 answered %s with its reads failing", answer)
				}
			}
			if _, ok := world.committedVersionOf(push.PushId); !ok {
				return fmt.Errorf("P's applied CAS is not in main's history")
			}
			return nil
		})},
		{Actor: "reader", Action: world.Verify("reader", "a.txt", "p.txt")},
	}
	return &Schedule{Id: "FS-1 unknown deletes nothing", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}
