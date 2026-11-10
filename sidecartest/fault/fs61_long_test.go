package fault

// FS-61's last clauses (§22.8, FI-14; D-TEST-11's load; EVSB-M2-16) on T2, in FS-117's world (fs117_test.go): 2x
// year one's mix for 26 h of fake clock with the budget on and refilled at 0.8 DWPD, as for the nvme row. Each
// push's P2 work is charged once, so the budget refuses no push, no ref reaches FOLD_BEHIND and no batch outlives
// 26 h; with a full-rate path-epoch copy added, evacuation, first in P2's deadline order, still keeps every batch
// under 26 h. FS-61's first clauses, on the real loop and process budgets, are fs61_test.go's.
//
// The mix is eight pushes an interval, four-fifths of the refill at full price, with P0 at its ordinary rate. Of a
// push's 37 deferred units, 20 are its fold's, due a minute on, and 17 its evacuation's, due 25 h on. A fold that
// waits is a ref's window growing toward 255 versions: with a busy ref committing a push an interval, a fold 128
// intervals late is FOLD_BEHIND, so the clause holds while no fold waits that long.

import (
	"testing"
	"time"
)

// A fold this many intervals past due leaves a busy ref's window at 255 versions.
const fs61FoldBehindSteps = 128

// The clauses of 26 h at the mix: no push refused by the budget, no fold near FOLD_BEHIND, no batch past 26 h, and
// every deferred unit paid once, from W.
func fs61CheckLongRun(t *testing.T, world *budgetWorld, intervals []*budgetInterval) {
	t.Helper()
	if err := world.err(); err != nil {
		t.Fatal(err)
	}
	var uncovered int64
	var oldest time.Duration
	for i, interval := range intervals {
		// the first shares are split before any process has reported demand
		if 2 < i && interval.pushesAdmitted != interval.pushesWanted {
			t.Fatalf("interval %d: the budget refused %d of %d pushes", i, interval.pushesWanted-interval.pushesAdmitted, interval.pushesWanted)
		}
		oldest = max(oldest, interval.oldestBatchAge)
	}
	uncovered = world.taskworker.unfundedByteCount - world.copiedByteCount()
	if 26*time.Hour < oldest {
		t.Errorf("a batch reached %s, past 26 h", oldest)
	}
	if fs61FoldBehindSteps <= world.foldMaxLag {
		t.Errorf("a fold waited %d intervals past due: a ref reached FOLD_BEHIND", world.foldMaxLag)
	}
	// charged once: every deferred unit came out of W, none a second time from T
	if uncovered != 0 {
		t.Errorf("%d deferred units were paid as unfunded P2, from T", uncovered)
	}
	t.Logf("26 h at the mix: oldest batch %s, longest fold wait %d intervals, %d pushes shed", oldest, world.foldMaxLag, world.pushesShed)
}

func TestFs61TwiceYearOnesMixForTwentySixHours(t *testing.T) {
	world := newBudgetWorldWithFolds(t, 0.8, 8, 20)
	world.setP0(50)
	intervals := world.run(26 * budgetStepsPerHour)
	fs61CheckLongRun(t, world, intervals)
	// the drive stayed inside the budget: the mix and its deferred work are under the refill
	if dwpd := world.oracle.Dwpd(24*time.Hour, world.settings.DriveByteCount); 0.8 < dwpd {
		t.Errorf("the busiest drive wrote %.3f DWPD over the last 24 h", dwpd)
	}
}

// The same 26 h with a full-rate path-epoch copy added: 250 operations a second of unfunded P2, which A_U carries
// beside the pushes, and evacuation, first in P2's order, keeps every batch under 26 h.
func TestFs61TwiceYearOnesMixWithAFullRateCopy(t *testing.T) {
	world := newBudgetWorldWithFolds(t, 0.8, 8, 20)
	world.setP0(50)
	// 250 operations a second for 5 s at a move's price, scaled as FS-118 scales it
	world.unfundedArrival = 150
	intervals := world.run(26 * budgetStepsPerHour)
	fs61CheckLongRun(t, world, intervals)
	var copied int64
	for _, interval := range intervals {
		copied += interval.unfundedIssued
		if interval.allowance.UnfundedByteCount < interval.unfundedIssued {
			t.Fatalf("the copy issued %d past A_U %d", interval.unfundedIssued, interval.allowance.UnfundedByteCount)
		}
	}
	// the copy ran at its full rate, less the first intervals' shares
	if copied < int64(26*budgetStepsPerHour-12)*150 {
		t.Errorf("the copy issued %d units in 26 h", copied)
	}
}
