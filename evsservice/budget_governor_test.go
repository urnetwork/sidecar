package evsservice

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// Round numbers: r is 200 B/s, so an interval's refill is 1,000 and D is 720,000.
func governorTestSettings() *WriteBudgetSettings {
	settings := DefaultWriteBudgetSettings()
	settings.RefillDwpd = 1
	settings.DriveByteCount = 17280000
	return settings
}

func governorTestStart() time.Time {
	return time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
}

// A governor on settings resuming bucket and wallet, its last step at start.
func newTestGovernor(settings *WriteBudgetSettings, bucketByteCount int64, walletByteCount int64) *Governor {
	return NewGovernor("meta-1", settings, &GovernorState{
		Seq:             1,
		TimeMs:          governorTestStart().UnixMilli(),
		BucketByteCount: bucketByteCount,
		WalletByteCount: walletByteCount,
		Calibration:     1,
	})
}

// A report of a process that started at start.
func testReport(processId string) *WriteBudgetReport {
	return &WriteBudgetReport{ProcessId: processId, StartMs: governorTestStart().UnixMilli()}
}

// Steps governor at now with reports written just before it, as a process writes them.
func stepAt(governor *Governor, now time.Time, measuredByteCount int64, reports ...*WriteBudgetReport) *WriteBudgetAllowance {
	for _, report := range reports {
		report.TimeMs = now.UnixMilli()
	}
	return governor.Step(now, measuredByteCount, reports)
}

func ranks(rank sidecar.WriteP2Rank, byteCount int64) []int64 {
	byteCounts := make([]int64, sidecar.WriteP2RankCount)
	byteCounts[rank] = byteCount
	return byteCounts
}

// B gains an interval of refill and loses what the drives measured, floored at zero and capped at D.
func TestGovernorBucketRefillsToItsDepth(t *testing.T) {
	settings := governorTestSettings()
	governor := newTestGovernor(settings, 0, 0)
	now := governorTestStart()
	var allowance *WriteBudgetAllowance
	for range 800 {
		now = now.Add(settings.Interval)
		allowance = stepAt(governor, now, 0)
	}
	if allowance.BucketByteCount != 720000 || allowance.DepthByteCount != 720000 {
		t.Errorf("B %d of D %d", allowance.BucketByteCount, allowance.DepthByteCount)
	}
	allowance = stepAt(governor, now.Add(settings.Interval), 1500)
	if allowance.BucketByteCount != 719500 {
		t.Errorf("B %d after 1,500 measured", allowance.BucketByteCount)
	}
}

// T is r's interval times f(B): a fifth at an empty bucket, rising linearly to all of it at half of D.
func TestGovernorAllowanceFollowsTheBucketsFactor(t *testing.T) {
	settings := governorTestSettings()
	for _, c := range []struct {
		bucketByteCount int64
		want            int64
	}{
		// the step's refill leaves B at 1,000, which T may not pass, and f is a hair over a fifth
		{bucketByteCount: 0, want: 202},
		{bucketByteCount: 180000 - 1000, want: 600},
		{bucketByteCount: 360000 - 1000, want: 1000},
		{bucketByteCount: 720000, want: 1000},
	} {
		governor := newTestGovernor(settings, c.bucketByteCount, 0)
		allowance := stepAt(governor, governorTestStart().Add(settings.Interval), 0)
		if allowance.TotalByteCount != c.want {
			t.Errorf("B %d: T %d, want %d", c.bucketByteCount, allowance.TotalByteCount, c.want)
		}
		if allowance.P1ByteCount != allowance.TotalByteCount {
			t.Errorf("B %d: A1 %d with no P2", c.bucketByteCount, allowance.P1ByteCount)
		}
	}
}

// T never passes what B holds less the priced bytes in flight.
func TestGovernorAllowanceLeavesWhatIsInFlight(t *testing.T) {
	settings := governorTestSettings()
	governor := newTestGovernor(settings, 0, 0)
	report := testReport("evs-1")
	report.InFlightByteCount = 900
	allowance := stepAt(governor, governorTestStart().Add(settings.Interval), 0, report)
	if allowance.TotalByteCount != 100 {
		t.Errorf("T %d with 900 in flight and B at 1,000", allowance.TotalByteCount)
	}
}

// P0 never waits: its bytes drain B to zero and past it, the rest forgiven by kind and never repaid
// (owner decision 190), and T is zero while P0 takes the refill.
func TestGovernorForgivesP0sExcessByKind(t *testing.T) {
	settings := governorTestSettings()
	governor := newTestGovernor(settings, 2000, 0)
	report := testReport("gkm-1")
	report.P0ByteCounts = map[sidecar.WriteP0Kind]int64{sidecar.WriteP0KindRemove: 3000, sidecar.WriteP0KindRotation: 1000}
	// the process started after the last step, so all of it is this interval's
	report.StartMs = governorTestStart().Add(time.Second).UnixMilli()
	allowance := stepAt(governor, governorTestStart().Add(settings.Interval), 7000, report)
	if allowance.BucketByteCount != 0 || allowance.TotalByteCount != 0 {
		t.Errorf("B %d, T %d", allowance.BucketByteCount, allowance.TotalByteCount)
	}
	// 2,000 held and 1,000 refilled, so 4,000 of P0's 4,000 is past B: 3,000 to remove and 1,000 to rotation
	if allowance.P0ExcessByteCounts[sidecar.WriteP0KindRemove] != 3000 || allowance.P0ExcessByteCounts[sidecar.WriteP0KindRotation] != 1000 {
		t.Errorf("excess %v", allowance.P0ExcessByteCounts)
	}
	if allowance.PricingErrorByteCount != 0 {
		t.Errorf("pricing error %d", allowance.PricingErrorByteCount)
	}
	// the storm ends: B refills by the difference, nothing repaid
	allowance = stepAt(governor, governorTestStart().Add(2*settings.Interval), 0, report)
	if allowance.BucketByteCount != 1000 {
		t.Errorf("B %d after the storm", allowance.BucketByteCount)
	}
}

// Bytes past B that P0 does not account for are the other classes' pricing error, not forgiven excess.
func TestGovernorCountsOtherOvershootAsPricingError(t *testing.T) {
	settings := governorTestSettings()
	governor := newTestGovernor(settings, 0, 0)
	report := testReport("evs-1")
	report.StartMs = governorTestStart().Add(time.Second).UnixMilli()
	report.P1ByteCount = 1000
	allowance := stepAt(governor, governorTestStart().Add(settings.Interval), 1100, report)
	if allowance.PricingErrorByteCount != 100 || len(allowance.P0ExcessByteCounts) != 0 || allowance.BucketByteCount != 0 {
		t.Errorf("error %d, excess %v, B %d", allowance.PricingErrorByteCount, allowance.P0ExcessByteCounts, allowance.BucketByteCount)
	}
}

// Pay P2 once (D-EVS-33): A1 is all of T, funded P2 spends only A2 = min(W, B - T - in flight), and W
// gains credit, loses spend and is clamped to the funded backlog.
func TestGovernorPaysFundedP2FromTheWalletAlone(t *testing.T) {
	settings := governorTestSettings()
	governor := newTestGovernor(settings, 720000, 5000)
	evs := testReport("evs-1")
	evs.P1ByteCount = 630
	evs.CreditByteCount = 370
	taskworker := testReport("taskworker-1")
	taskworker.FundedByteCount = 370
	taskworker.FundedDemandByteCounts = ranks(sidecar.WriteP2RankEvacuation, 370)
	taskworker.FundedBacklogByteCounts = ranks(sidecar.WriteP2RankEvacuation, 5000)
	now := governorTestStart().Add(settings.Interval)
	// the first sight of each is its baseline
	stepAt(governor, now, 1000, evs, taskworker)
	evs.P1ByteCount *= 2
	evs.CreditByteCount *= 2
	taskworker.FundedByteCount *= 2
	allowance := stepAt(governor, now.Add(settings.Interval), 1000, evs, taskworker)
	if allowance.TotalByteCount != 1000 || allowance.P1ByteCount != 1000 || allowance.UnfundedByteCount != 0 {
		t.Errorf("T %d, A1 %d, A_U %d", allowance.TotalByteCount, allowance.P1ByteCount, allowance.UnfundedByteCount)
	}
	if allowance.WalletByteCount != 5000 || allowance.FundedByteCount != 5000 {
		t.Errorf("W %d, A2 %d", allowance.WalletByteCount, allowance.FundedByteCount)
	}
	// A2's demand is served first, the rest of W by the backlog not yet due
	if share := allowance.Shares["taskworker-1"]; share == nil || share.FundedByteCount != 5000 || share.P1ByteCount != 0 {
		t.Errorf("taskworker's share %+v", share)
	}
	if share := allowance.Shares["evs-1"]; share == nil || share.P1ByteCount != 1000 || share.FundedByteCount != 0 {
		t.Errorf("evs's share %+v", share)
	}

	// the backlog shrinks: W's credit for work that will not run lapses
	taskworker.FundedBacklogByteCounts = ranks(sidecar.WriteP2RankEvacuation, 2000)
	allowance = stepAt(governor, now.Add(2*settings.Interval), 1000, evs, taskworker)
	if allowance.WalletByteCount != 2000 {
		t.Errorf("W %d past a backlog of 2,000", allowance.WalletByteCount)
	}
}

// A2 is what B holds beyond T and what is in flight: funded P2 stops once B is spent.
func TestGovernorFundedP2SpendsOnlyWhatTheBucketHoldsBeyondT(t *testing.T) {
	settings := governorTestSettings()
	governor := newTestGovernor(settings, 1500, 100000)
	taskworker := testReport("taskworker-1")
	taskworker.FundedDemandByteCounts = ranks(sidecar.WriteP2RankEvacuation, 100000)
	taskworker.FundedBacklogByteCounts = ranks(sidecar.WriteP2RankEvacuation, 100000)
	allowance := stepAt(governor, governorTestStart().Add(settings.Interval), 0, taskworker)
	// B 2,500 after the refill, T 205.6 at f a hair over a fifth, so A2 is what is left, rounded down
	if allowance.BucketByteCount != 2500 || allowance.TotalByteCount != 205 || allowance.FundedByteCount != 2294 {
		t.Errorf("B %d, T %d, A2 %d", allowance.BucketByteCount, allowance.TotalByteCount, allowance.FundedByteCount)
	}
}

// Unfunded P2 takes at most UnfundedShare of T while its backlog lasts, and only A_U comes off A1.
func TestGovernorUnfundedTakesAtMostItsShare(t *testing.T) {
	settings := governorTestSettings()
	for _, c := range []struct {
		demand  int64
		backlog int64
		want    int64
	}{
		{demand: 200, backlog: 200, want: 200},
		{demand: 5000, backlog: 5000, want: 400},
		{demand: 0, backlog: 0, want: 0},
	} {
		governor := newTestGovernor(settings, 720000, 0)
		taskworker := testReport("taskworker-1")
		taskworker.UnfundedDemandByteCounts = ranks(sidecar.WriteP2RankGc, c.demand)
		taskworker.UnfundedBacklogByteCounts = ranks(sidecar.WriteP2RankGc, c.backlog)
		allowance := stepAt(governor, governorTestStart().Add(settings.Interval), 0, taskworker)
		if allowance.UnfundedByteCount != c.want || allowance.P1ByteCount != allowance.TotalByteCount-c.want {
			t.Errorf("demand %d: A_U %d, A1 %d of T %d", c.demand, allowance.UnfundedByteCount, allowance.P1ByteCount, allowance.TotalByteCount)
		}
	}
}

// Funded work the wallet no longer covers runs as unfunded P2, paid once from A_U: here {nvb_<set>} was
// lost, so W restarts at zero.
func TestGovernorRunsUncoveredFundedWorkAsUnfunded(t *testing.T) {
	settings := governorTestSettings()
	governor := NewGovernor("meta-1", settings, nil)
	taskworker := testReport("taskworker-1")
	taskworker.FundedDemandByteCounts = ranks(sidecar.WriteP2RankEvacuation, 300)
	taskworker.FundedBacklogByteCounts = ranks(sidecar.WriteP2RankEvacuation, 3000)
	now := governorTestStart()
	var allowance *WriteBudgetAllowance
	// long enough for B to pass half of D, so T is all of an interval's refill and A_U's cap is 400
	for range 400 {
		now = now.Add(settings.Interval)
		allowance = stepAt(governor, now, 0, taskworker)
	}
	if allowance.TotalByteCount != 1000 || allowance.WalletByteCount != 0 || allowance.FundedByteCount != 0 {
		t.Errorf("T %d, W %d, A2 %d", allowance.TotalByteCount, allowance.WalletByteCount, allowance.FundedByteCount)
	}
	share := allowance.Shares["taskworker-1"]
	if allowance.UnfundedByteCount != 300 || share == nil || share.UnfundedByteCount != 300 || share.UncoveredByteCount != 300 {
		t.Errorf("A_U %d, share %+v", allowance.UnfundedByteCount, share)
	}
}

// k is measured over priced bytes of the last 10 min, and holds while too little was priced to say.
func TestGovernorCalibrationFollowsTheMeasuredBytes(t *testing.T) {
	settings := governorTestSettings()
	governor := newTestGovernor(settings, 720000, 0)
	evs := testReport("evs-1")
	now := governorTestStart()
	stepAt(governor, now.Add(settings.Interval), 0, evs)
	now = now.Add(settings.Interval)
	var allowance *WriteBudgetAllowance
	for range 120 {
		now = now.Add(settings.Interval)
		evs.P1ByteCount += 1000
		allowance = stepAt(governor, now, 1100, evs)
	}
	if math.Abs(allowance.Calibration-1.1) > 1e-9 || allowance.TotalByteCount != 909 {
		t.Errorf("k %v, T %d", allowance.Calibration, allowance.TotalByteCount)
	}
	// an idle cluster's heals and scanner, which nothing prices, leave k where it was, and pushes after
	// it are priced as before
	for range 240 {
		now = now.Add(settings.Interval)
		allowance = stepAt(governor, now, 900, evs)
	}
	if math.Abs(allowance.Calibration-1.1) > 1e-9 {
		t.Errorf("k %v after 20 idle minutes", allowance.Calibration)
	}
	// and a table far off is held to the bounds, B carrying the rest
	for range 120 {
		now = now.Add(settings.Interval)
		evs.P1ByteCount += 200
		allowance = stepAt(governor, now, 2000, evs)
	}
	if allowance.Calibration != settings.CalibrationMax {
		t.Errorf("k %v at ten times the table", allowance.Calibration)
	}
}

// A1 goes to the processes with P1 demand, evenly while none has any.
func TestGovernorSplitsP1ByDemand(t *testing.T) {
	settings := governorTestSettings()
	governor := newTestGovernor(settings, 720000, 0)
	evs := testReport("evs-1")
	gkm := testReport("gkm-1")
	api := testReport("api-1")
	now := governorTestStart().Add(settings.Interval)
	allowance := stepAt(governor, now, 0, evs, gkm, api)
	for _, processId := range []string{"evs-1", "gkm-1", "api-1"} {
		if share := allowance.Shares[processId]; share.P1ByteCount != 333 {
			t.Errorf("idle %s: %+v", processId, share)
		}
	}
	evs.P1QueuedByteCount = 300
	evs.P1ByteCount = 400
	gkm.P1QueuedByteCount = 300
	allowance = stepAt(governor, now.Add(settings.Interval), 400, evs, gkm, api)
	if allowance.Shares["evs-1"].P1ByteCount != 700 || allowance.Shares["gkm-1"].P1ByteCount != 300 || allowance.Shares["api-1"].P1ByteCount != 0 {
		t.Errorf("shares %+v %+v %+v", allowance.Shares["evs-1"], allowance.Shares["gkm-1"], allowance.Shares["api-1"])
	}
}

// A2 serves the lowest rank's demand first, whichever process holds it (§11.13's order row).
func TestGovernorSplitsFundedP2RankByRank(t *testing.T) {
	settings := governorTestSettings()
	governor := newTestGovernor(settings, 720000, 1000)
	folds := testReport("evs-1")
	folds.FundedDemandByteCounts = ranks(sidecar.WriteP2RankFold, 800)
	folds.FundedBacklogByteCounts = ranks(sidecar.WriteP2RankFold, 800)
	evacuation := testReport("taskworker-1")
	evacuation.FundedDemandByteCounts = ranks(sidecar.WriteP2RankEvacuation, 600)
	evacuation.FundedBacklogByteCounts = ranks(sidecar.WriteP2RankEvacuation, 600)
	allowance := stepAt(governor, governorTestStart().Add(settings.Interval), 0, folds, evacuation)
	if allowance.FundedByteCount != 1000 || allowance.Shares["taskworker-1"].FundedByteCount != 600 || allowance.Shares["evs-1"].FundedByteCount != 400 {
		t.Errorf("A2 %d: evacuation %+v, folds %+v", allowance.FundedByteCount, allowance.Shares["taskworker-1"], allowance.Shares["evs-1"])
	}
	// what W does not cover is uncovered work, run from A_U by the process that holds it
	if share := allowance.Shares["evs-1"]; share.UncoveredByteCount != 400 || share.UnfundedByteCount != 400 {
		t.Errorf("folds' uncovered %+v", share)
	}
}

// A governor that lost its state takes a running process's totals as its baseline, and a process that
// started since the last step counts from its start.
func TestGovernorTakesARunningProcessAsItsBaseline(t *testing.T) {
	settings := governorTestSettings()
	governor := NewGovernor("meta-1", settings, nil)
	running := testReport("evs-1")
	running.P1ByteCount = 9000000
	running.CreditByteCount = 9000000
	running.FundedBacklogByteCounts = ranks(sidecar.WriteP2RankFold, 9000000)
	now := governorTestStart()
	allowance := stepAt(governor, now, 0, running)
	if allowance.WalletByteCount != 0 {
		t.Errorf("W %d from a running process's totals", allowance.WalletByteCount)
	}
	started := testReport("evs-2")
	started.StartMs = now.Add(time.Second).UnixMilli()
	started.CreditByteCount = 500
	started.FundedBacklogByteCounts = ranks(sidecar.WriteP2RankFold, 500)
	allowance = stepAt(governor, now.Add(settings.Interval), 0, running, started)
	if allowance.WalletByteCount != 500 {
		t.Errorf("W %d from a process started since", allowance.WalletByteCount)
	}
}

// A report it cannot use is dropped whole, and its process reads as absent.
func TestGovernorDropsAReportItCannotUse(t *testing.T) {
	settings := governorTestSettings()
	governor := newTestGovernor(settings, 720000, 0)
	bad := testReport("evs-1")
	bad.P0ByteCounts = map[sidecar.WriteP0Kind]int64{"not-a-kind": 10}
	negative := testReport("evs-2")
	negative.CreditByteCount = -1
	tooManyRanks := testReport("evs-3")
	tooManyRanks.FundedDemandByteCounts = make([]int64, sidecar.WriteP2RankCount+1)
	allowance := stepAt(governor, governorTestStart().Add(settings.Interval), 0, bad, negative, tooManyRanks, testReport(""))
	if len(allowance.Shares) != 0 {
		t.Errorf("shares %v", allowance.Shares)
	}
}

// A report older than ReportTtl is a process gone, whatever Redis still holds.
func TestGovernorDropsAReportPastItsTtl(t *testing.T) {
	settings := governorTestSettings()
	governor := newTestGovernor(settings, 720000, 0)
	stale := testReport("evs-1")
	stale.P1QueuedByteCount = 5000
	now := governorTestStart().Add(settings.Interval)
	stale.TimeMs = now.Add(-settings.ReportTtl - time.Millisecond).UnixMilli()
	fresh := testReport("evs-2")
	fresh.TimeMs = now.UnixMilli()
	allowance := governor.Step(now, 0, []*WriteBudgetReport{stale, fresh})
	if _, ok := allowance.Shares["evs-1"]; ok || allowance.Shares["evs-2"].P1ByteCount != 1000 {
		t.Errorf("shares %v", allowance.Shares)
	}
}

// The copy rate rises to its most while P1 left a quarter of T unspent over the last minute.
func TestGovernorCopyRateRisesWithSpareP1(t *testing.T) {
	settings := governorTestSettings()
	governor := newTestGovernor(settings, 720000, 0)
	evs := testReport("evs-1")
	now := governorTestStart()
	var allowance *WriteBudgetAllowance
	for range 13 {
		now = now.Add(settings.Interval)
		evs.P1ByteCount += 900
		allowance = stepAt(governor, now, 900, evs)
	}
	if allowance.CopyOpsPerSecond != 250 {
		t.Errorf("busy: %d", allowance.CopyOpsPerSecond)
	}
	for range 13 {
		now = now.Add(settings.Interval)
		evs.P1ByteCount += 500
		allowance = stepAt(governor, now, 500, evs)
	}
	if allowance.CopyOpsPerSecond != 1000 {
		t.Errorf("spare: %d", allowance.CopyOpsPerSecond)
	}
}

// What the loop saves is all a successor needs: one that resumes it steps exactly as the original.
func TestGovernorStateResumesExactly(t *testing.T) {
	settings := governorTestSettings()
	original := newTestGovernor(settings, 300000, 2000)
	evs := testReport("evs-1")
	taskworker := testReport("taskworker-1")
	now := governorTestStart()
	step := func(governor *Governor, at time.Time) *WriteBudgetAllowance {
		return stepAt(governor, at, 1200, evs, taskworker)
	}
	for i := range 30 {
		now = now.Add(settings.Interval)
		evs.P1ByteCount += 600
		evs.CreditByteCount += 300
		evs.P0ByteCounts = map[sidecar.WriteP0Kind]int64{sidecar.WriteP0KindLog: int64(100 * i)}
		taskworker.FundedByteCount += 250
		taskworker.FundedDemandByteCounts = ranks(sidecar.WriteP2RankFold, 250)
		taskworker.FundedBacklogByteCounts = ranks(sidecar.WriteP2RankFold, 4000)
		step(original, now)
	}
	text, err := json.Marshal(original.State())
	if err != nil {
		t.Fatal(err)
	}
	state := &GovernorState{}
	if err := json.Unmarshal(text, state); err != nil {
		t.Fatal(err)
	}
	resumed := NewGovernor("meta-1", settings, state)
	now = now.Add(settings.Interval)
	evs.P1ByteCount += 600
	want, err := json.Marshal(step(original, now))
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(step(resumed, now))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("resumed %s\nwant %s", got, want)
	}
}

func TestSplitByWeightsNeverPassesTheTotal(t *testing.T) {
	for _, c := range []struct {
		total   int64
		weights []int64
	}{
		{total: 1000, weights: []int64{1, 1, 1}},
		{total: 7, weights: []int64{3, 3, 3, 3}},
		{total: 999999999937, weights: []int64{999999999989, 1, 3, 999999999959}},
		{total: 1000, weights: []int64{0, -5, 0}},
	} {
		var sum int64
		for _, share := range splitByWeights(c.total, c.weights) {
			if share < 0 {
				t.Errorf("%v: a share below zero", c)
			}
			sum += share
		}
		if c.total < sum {
			t.Errorf("%v: shares sum to %d", c, sum)
		}
	}
}
