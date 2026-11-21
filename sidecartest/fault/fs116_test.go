package fault

// FS-116 on T2 (EVSB-M2-05): the registered case and the clauses of fs116.go, each under every rule §22.8 gives the
// row; the registered case failing what its world breaks; and the mutant that debits funded P2 from T, which must fail
// the steady clause, a plain test since it must fail.

import (
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// newFs116WorldOf's world on the defaults, which fails t at its end with every breach its checks found.
func newFs116World(t *testing.T) *fs116World {
	world := newFs116WorldOf(nil)
	t.Cleanup(func() {
		if err := world.err(); err != nil {
			t.Error(err)
		}
	})
	return world
}

func TestFs116(t *testing.T) {
	RunRow(t, "FS-116", "", nil)
}

// The registered case fails what its world breaks: FI-14's check, run after every step, fails a world holding a breach
// at the step that left it, and the mutant debiting funded P2 from T fails the steady step.
func TestFs116CaseFailsWhatItsWorldBreaks(t *testing.T) {
	for _, planted := range []struct {
		name   string
		mutate func(world *fs116World)
		want   string
	}{
		{name: "a breach", mutate: func(world *fs116World) { world.breach("a planted breach") }, want: "a planted breach"},
		{name: "funded P2 debited from T", mutate: func(world *fs116World) { world.mutantFundedFromT = true }, want: "pushes"},
	} {
		func() {
			net := sidecartest.NewNet(t.Context(), nil)
			defer net.Close()
			schedule := fs116SteadyLoad(planted.mutate)(net)
			schedule.Id = "FS-116 " + planted.name
			result := Run(t.Context(), schedule, net)
			if result.Err == nil || !strings.Contains(result.Err.Error(), planted.want) {
				t.Errorf("%s: %s", planted.name, result)
			}
			if planted.name == "a breach" && result.FailedStep != 0 {
				t.Errorf("the planted breach failed the run at step %d, not the step that left it", result.FailedStep)
			}
		}()
	}
}

func TestFs116PausedP2DrainsTheWalletWithoutStallingPushes(t *testing.T) {
	RunRegisteredClause(t, "FS-116", "paused p2 drains the wallet without stalling pushes", nil)
}

func TestFs116KilledProcessesPayDeferredWorkOnce(t *testing.T) {
	RunRegisteredClause(t, "FS-116", "killed processes pay deferred work once", nil)
}

func TestFs116LostStateRestartsTheWalletAtZero(t *testing.T) {
	RunRegisteredClause(t, "FS-116", "lost state restarts the wallet at zero", nil)
}

func TestFs116UnfundedBacklogTakesOnlyItsShare(t *testing.T) {
	RunRegisteredClause(t, "FS-116", "unfunded backlog takes only its share", nil)
}

func TestFs116LowPricesConvergeAndHoldTheBound(t *testing.T) {
	RunRegisteredClause(t, "FS-116", "low prices converge and hold the bound", nil)
}

func TestFs116AllowanceRampsBackAfterAStorm(t *testing.T) {
	RunRegisteredClause(t, "FS-116", "allowance ramps back after a storm", nil)
}

// The mutant that debits funded P2 from T as well admits ~7.3 pushes an interval, 1,000 / 137, and
// fails the steady clause.
func TestFs116MutantDebitingFundedP2FromTFails(t *testing.T) {
	world := newFs116World(t)
	world.mutantFundedFromT = true
	world.run(10 * world.settings.FundedDelayCount)
	intervals := world.run(200)
	if fs116CheckSteady(world.settings, intervals) == nil {
		t.Error("the mutant passed")
	}
	admitted := 0
	for _, interval := range intervals {
		admitted += interval.pushesAdmitted
	}
	average := float64(admitted) / float64(len(intervals))
	t.Logf("the mutant admits %.2f pushes an interval", average)
	if average < 7.0 || 7.6 < average {
		t.Errorf("the mutant admits %.2f pushes an interval", average)
	}
}
