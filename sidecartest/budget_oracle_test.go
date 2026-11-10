package sidecartest

import (
	"strings"
	"testing"
	"time"
)

// Round numbers: r is 200 a second, so an interval's refill is 1,000 and D is 720,000.
func budgetOracleTestSettings() *BudgetOracleSettings {
	settings := DefaultBudgetOracleSettings()
	settings.RefillBytesPerSecond = 200
	settings.DepthByteCount = 720000
	settings.WindowSlackByteCount = 1000
	return settings
}

// §11.13's accounts row by hand: T follows its factor of B less P0's own, A_U takes at most two-fifths of T while
// unfunded backlog lasts, W is clamped to the funded backlog, and A2 is what B holds beyond T.
func TestBudgetOracleAccountsFollowTheAccountsRow(t *testing.T) {
	// a full bucket: T is the refill
	oracle := NewBudgetOracle(budgetOracleTestSettings(), 720000, 5000)
	accounts := oracle.Step(&BudgetOracleEvents{
		MeasuredByteCount: 1000, P1ByteCount: 600, CreditByteCount: 370, FundedByteCount: 400,
		FundedDemandByteCount: 300, FundedBacklogByteCount: 4000,
		UnfundedDemandByteCount: 9000, UnfundedBacklogByteCount: 9000,
	})
	if accounts.BucketByteCount != 720000 || accounts.TotalByteCount != 1000 || accounts.UnfundedByteCount != 400 || accounts.P1ByteCount != 600 {
		t.Fatalf("at a full bucket: %+v", accounts)
	}
	// W gains the credit, loses the funded spend, and is clamped to the backlog: 5,000 + 370 - 400, then 4,000
	if accounts.WalletByteCount != 4000 || accounts.FundedByteCount != 4000 {
		t.Fatalf("W %d, A2 %d", accounts.WalletByteCount, accounts.FundedByteCount)
	}

	// a quarter of D: the factor is 0.2 + 0.8 x (180,000 / 360,000) = 0.6, less P0's 100
	oracle = NewBudgetOracle(budgetOracleTestSettings(), 180000, 0)
	accounts = oracle.Step(&BudgetOracleEvents{MeasuredByteCount: 1000, P0ByteCounts: map[string]int64{"remove": 100}, P1ByteCount: 900})
	if accounts.BucketByteCount != 180000 || accounts.TotalByteCount != 500 || accounts.UnfundedByteCount != 0 || accounts.FundedByteCount != 0 {
		t.Fatalf("at a quarter of D: %+v", accounts)
	}
	if err := oracle.Err(); err != nil {
		t.Fatal(err)
	}
}

// B floors at zero: what P0 wrote past it is forgiven by kind in proportion and never repaid, T is zero while P0
// takes the refill, and the next interval's refill is B's again.
func TestBudgetOracleForgivesP0sExcessAndFloorsTheBucket(t *testing.T) {
	oracle := NewBudgetOracle(budgetOracleTestSettings(), 500, 0)
	accounts := oracle.Step(&BudgetOracleEvents{
		MeasuredByteCount: 4000, P0ByteCounts: map[string]int64{"rotation": 3000, "shred": 1000},
	})
	// 500 + 1,000 - 4,000 leaves 2,500 past the bucket, all of it P0's
	if accounts.BucketByteCount != 0 || accounts.TotalByteCount != 0 || accounts.PricingErrorByteCount != 0 {
		t.Fatalf("an emptied bucket: %+v", accounts)
	}
	if accounts.P0ExcessStepByteCounts["rotation"] != 1875 || accounts.P0ExcessStepByteCounts["shred"] != 625 {
		t.Fatalf("forgiven by kind: %v", accounts.P0ExcessStepByteCounts)
	}
	if ratio := accounts.P0RefillRatio; ratio != 4 {
		t.Fatalf("the P0 ratio is %v", ratio)
	}
	// the storm over: one interval's refill, none of it owed to the past, and T at its factor of that:
	// 1,000 x (0.2 + 0.8 x 1,000 / 360,000)
	accounts = oracle.Step(&BudgetOracleEvents{MeasuredByteCount: 0})
	if accounts.BucketByteCount != 1000 || accounts.TotalByteCount != 202 {
		t.Fatalf("an interval after the storm: %+v", accounts)
	}
	if oracle.ForgivenByteCounts()["rotation"] != 1875 {
		t.Fatalf("forgiven since the start: %v", oracle.ForgivenByteCounts())
	}
	if err := oracle.Err(); err != nil {
		t.Fatal(err)
	}
	// a published B below zero, the repaying mutant's, fails the comparison
	observed := *accounts
	observed.BucketByteCount = -1500
	if err := oracle.Compare(&observed); err == nil {
		t.Fatal("B below zero compared equal")
	}
	if err := oracle.Compare(accounts); err != nil {
		t.Fatal(err)
	}
}

// FI-14 (b), (c) and (d) on the events, and the paid-once ledger.
func TestBudgetOracleHoldsTheEventsToTheAccountsInForce(t *testing.T) {
	violation := func(events *BudgetOracleEvents) string {
		oracle := NewBudgetOracle(budgetOracleTestSettings(), 720000, 1000)
		// T 1,000, W and A2 1,000 in force
		oracle.Step(&BudgetOracleEvents{MeasuredByteCount: 1000, FundedBacklogByteCount: 1000})
		oracle.Step(events)
		return strings.Join(oracle.Violations(), "; ")
	}
	cases := []struct {
		events *BudgetOracleEvents
		want   string
	}{
		{&BudgetOracleEvents{P1ByteCount: 630, CreditByteCount: 370, FundedByteCount: 1000, FundedBacklogByteCount: 370}, ""},
		{&BudgetOracleEvents{P1ByteCount: 700, CreditByteCount: 370}, "FI-14 (b): P1 debited"},
		{&BudgetOracleEvents{P1ByteCount: 600, UnfundedByteCount: 500}, "FI-14 (b): P1 debited"},
		{&BudgetOracleEvents{FundedByteCount: 1100}, "FI-14 (b): funded P2"},
		{&BudgetOracleEvents{P0WaitedCount: 1}, "FI-14 (c)"},
		{&BudgetOracleEvents{P0RefusedCount: 1}, "FI-14 (c)"},
		{&BudgetOracleEvents{Refusals: []*BudgetOracleRefusal{{RefusedPerWeight: 10, ServedPerWeights: []float64{4, 10}}}}, ""},
		{&BudgetOracleEvents{Refusals: []*BudgetOracleRefusal{{RefusedPerWeight: 10, ServedPerWeights: []float64{4, 11}}}}, "FI-14 (d)"},
	}
	for i, c := range cases {
		got := violation(c.events)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("case %d: violations %q, want %q", i, got, c.want)
		}
	}

	// every deferred byte once: from W, as unfunded P2, lapsed, or still owed
	oracle := NewBudgetOracle(budgetOracleTestSettings(), 720000, 0)
	oracle.Step(&BudgetOracleEvents{CreditByteCount: 370, FundedBacklogByteCount: 370})
	oracle.Step(&BudgetOracleEvents{FundedByteCount: 100, UnfundedByteCount: 50, UncoveredByteCount: 50, LapsedByteCount: 20, FundedBacklogByteCount: 200})
	if err := oracle.CheckPaidOnce(200); err != nil {
		t.Fatal(err)
	}
	if err := oracle.CheckPaidOnce(100); err == nil {
		t.Fatal("a deferred byte that went missing passed")
	}
}

// FI-14 (a): writes at the refill pass, and so does an hour that spends the whole bucket; writes past the empty
// bucket with no P0 behind them are pricing error, which the window allows one interval of and no more. A lost
// state restarts B and W at zero and takes the running totals as its baseline.
func TestBudgetOracleWindowAndLostState(t *testing.T) {
	settings := budgetOracleTestSettings()
	// a window that holds the whole run, the full bucket it began with included
	settings.Window = 4 * time.Hour
	oracle := NewBudgetOracle(settings, 720000, 0)
	for range 2 * 720 {
		oracle.Step(&BudgetOracleEvents{MeasuredByteCount: 1000, P1ByteCount: 1000})
	}
	// the drive writes the whole bucket and an hour's refill in an hour
	for range 720 {
		oracle.Step(&BudgetOracleEvents{MeasuredByteCount: 2000})
	}
	if err := oracle.Err(); err != nil {
		t.Fatalf("an hour that spent the bucket: %v", err)
	}
	accounts := oracle.Step(&BudgetOracleEvents{MeasuredByteCount: 2000})
	if accounts.PricingErrorByteCount != 1000 || accounts.BucketByteCount != 0 {
		t.Fatalf("writes past an empty bucket with no P0: %+v", accounts)
	}
	if err := oracle.Err(); err != nil {
		t.Fatalf("one interval's pricing error: %v", err)
	}
	oracle.Step(&BudgetOracleEvents{MeasuredByteCount: 2000})
	if err := oracle.Err(); err == nil || !strings.Contains(err.Error(), "FI-14 (a)") {
		t.Fatalf("a second interval past the empty bucket: %v", err)
	}

	lost := NewBudgetOracle(budgetOracleTestSettings(), 720000, 5000)
	lost.Step(&BudgetOracleEvents{MeasuredByteCount: 1000, FundedBacklogByteCount: 5000})
	lost.LoseState()
	accounts = lost.Step(&BudgetOracleEvents{MeasuredByteCount: 400, P0ByteCounts: map[string]int64{"shred": 400}, FundedDemandByteCount: 300, FundedBacklogByteCount: 5000})
	// B is one interval's refill less what the drive wrote; W is zero, so the funded backlog runs uncovered
	if accounts.BucketByteCount != 600 || accounts.WalletByteCount != 0 || accounts.FundedByteCount != 0 || len(accounts.P0ExcessStepByteCounts) != 0 {
		t.Fatalf("after a lost state: %+v", accounts)
	}
	if accounts.UnfundedByteCount == 0 {
		t.Fatalf("the uncovered backlog got no part of A_U: %+v", accounts)
	}
}

// The copy ledger: sources by ref, the liability and its drain time, a batched epoch waiting only while two sources
// stand, and a fourth source refused.
func TestBudgetOracleCopyLedger(t *testing.T) {
	oracle := NewBudgetOracle(budgetOracleTestSettings(), 720000, 0)
	oracle.CopyCutOver("a", 300)
	oracle.CopyCutOver("b", 600)
	oracle.CopyMoved("a", 100)
	oracle.CopyEndInterval()
	gauges := oracle.CopyGauges()
	// 800 moves left at 100 moves in 5 s
	if gauges.LiabilityMoveCount != 800 || gauges.DrainSeconds != 40 || gauges.Warn || gauges.SourceCounts != [4]int{0, 2, 0, 0} {
		t.Fatalf("gauges %+v", *gauges)
	}
	oracle.CopyCutOver("b", 600)
	oracle.CopyDeferred("b")
	oracle.CopyMoved("a", 200)
	oracle.CopyEndInterval()
	gauges = oracle.CopyGauges()
	if gauges.LiabilityMoveCount != 600 || gauges.DeferredCount != 1 || gauges.SourceCounts != [4]int{1, 0, 1, 0} {
		t.Fatalf("gauges %+v", *gauges)
	}
	if err := oracle.Err(); err != nil {
		t.Fatal(err)
	}
	oracle.CopyDeferred("a")
	oracle.CopyCutOver("b", 600)
	oracle.CopyCutOver("b", 600)
	if violations := oracle.Violations(); len(violations) != 2 {
		t.Fatalf("violations %v", violations)
	}
}
