package model

// compute_rollup_day's comparisons (BAL-M12-05), with no database: a day row re-derived and stored alike is no
// difference, and a row one side lacks, or one sum apart, is one difference per network and kind; the totals balance
// against the day rows and the pruned sums, units and refunds compared only while nothing was pruned.

import (
	"testing"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// A test id from a byte.
func testComputeRollupId(b byte) operator.Id {
	return operator.Id{b, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, b}
}

// One day row of kind on day, its key's nullable columns set as given.
func testComputeRollupDay(networkId operator.Id, kind ComputeChargeKind, day time.Time, catalogId *string, amount int64) *ComputeChargeDay {
	return &ComputeChargeDay{
		NetworkId: networkId, Day: day, Kind: kind, SidecarId: testComputeRollupId(9), CatalogId: catalogId, Provider: 1,
		Units: ComputeUnits{InputTokens: 100, OutputTokens: 20}, AmountNanoUsd: amount, Count: 1,
	}
}

func TestComputeRollupDayDifferencesByNetworkAndKind(t *testing.T) {
	day := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	first, second := testComputeRollupId(1), testComputeRollupId(2)
	catalogId := "chutes-qwen3.8-27b-tee-high"
	derived := []*ComputeChargeDay{
		testComputeRollupDay(first, ComputeChargeKindInference, day, &catalogId, 1_000),
		testComputeRollupDay(first, ComputeChargeKindInference, day, nil, 2_000),
		testComputeRollupDay(second, ComputeChargeKindWebSearch, day, nil, 12_000_000),
	}
	copyOf := func(rows []*ComputeChargeDay) []*ComputeChargeDay {
		copied := []*ComputeChargeDay{}
		for _, row := range rows {
			one := *row
			copied = append(copied, &one)
		}
		return copied
	}
	if differences := ComputeRollupDayDifferences(derived, copyOf(derived), nil); len(differences) != 0 {
		t.Fatalf("alike rows differ: %v", differences)
	}
	// one sum apart: the network and kind once, though two of its rows are compared
	stored := copyOf(derived)
	stored[1].Units.OutputTokens += 1
	stored[0].RefundedNanoUsd += 1
	differences := ComputeRollupDayDifferences(derived, stored, nil)
	if len(differences) != 1 || differences[0].NetworkId != first || differences[0].Kind != ComputeChargeKindInference {
		t.Fatalf("a changed row: %+v", differences)
	}
	// a row only the stored side holds, and one only the derived side holds
	stored = copyOf(derived[:2])
	stored = append(stored, testComputeRollupDay(second, ComputeChargeKindInference, day, nil, 5))
	differences = ComputeRollupDayDifferences(derived, stored, nil)
	if len(differences) != 2 || differences[0].NetworkId != second || differences[0].Kind != ComputeChargeKindInference ||
		differences[1].Kind != ComputeChargeKindWebSearch {
		t.Fatalf("rows on one side: %+v", differences)
	}
	// a kind left out of the comparison differs in nothing
	if differences := ComputeRollupDayDifferences(derived, copyOf(derived[:2]), []ComputeChargeKind{ComputeChargeKindInference}); len(differences) != 0 {
		t.Fatalf("a kind left out: %+v", differences)
	}
	// a null catalog id and a set one are two keys, never one
	stored = copyOf(derived)
	stored[1].CatalogId = &catalogId
	if differences := ComputeRollupDayDifferences(derived, stored, nil); len(differences) != 1 {
		t.Fatalf("a null key column read as a set one: %+v", differences)
	}
}

func TestComputeRollupSumsBalance(t *testing.T) {
	figures := ComputeRollupFigures{Units: ComputeUnits{Seconds: 600}, AmountNanoUsd: 9_000, RefundedNanoUsd: 1_000, Count: 3}
	sums := &ComputeRollupSums{Kind: ComputeChargeKindEnclaveRun, Total: figures, Day: figures}
	if !sums.Balanced() {
		t.Fatal("equal totals and day rows do not balance")
	}
	sums.Total.Units.Seconds += 1
	if sums.Balanced() {
		t.Fatal("units apart balance while nothing was pruned")
	}
	// once a day row of the kind was pruned, the amount and count are what compute_charge_pruned keeps
	sums.Day = ComputeRollupFigures{Units: ComputeUnits{Seconds: 100}, AmountNanoUsd: 4_000, Count: 1}
	sums.Pruned = &ComputeRollupFigures{AmountNanoUsd: 5_000, Count: 2}
	if !sums.Balanced() {
		t.Fatal("totals of day rows and pruned sums do not balance")
	}
	sums.Pruned.Count += 1
	if sums.Balanced() {
		t.Fatal("a count apart balances")
	}
	sums.Pruned.Count -= 1
	sums.Total.AmountNanoUsd += 1
	if sums.Balanced() {
		t.Fatal("an amount apart balances")
	}
}
