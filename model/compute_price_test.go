package model

// §9.6's retail prices and §9.7's worst case (BAL-M12-01): exact integer arithmetic, each unit class rounding up to its
// own step, and the design's two worked holds.

import (
	"errors"
	"math"
	"testing"
)

// Vectors per unit class: the markup applied, then rounded up to the class's step, exactly; zero stays zero; a
// negative price, a broken markup and a result past int64 are refused.
func TestComputeRetailPriceRoundsUp(t *testing.T) {
	settings := DefaultComputeLedgerSettings()
	type vector struct {
		class    ComputePriceClass
		provider int64
		retail   int64
	}
	for _, v := range []vector{
		// per million tokens, to $0.001
		{class: ComputePriceClassTokens, provider: 1_850_000_000, retail: 2_220_000_000},
		{class: ComputePriceClassTokens, provider: 9_500_000_000, retail: 11_400_000_000},
		// 0.1481472 rounds up to 0.149
		{class: ComputePriceClassTokens, provider: 123_456_000, retail: 149_000_000},
		// one nano-USD a million tokens still costs one step
		{class: ComputePriceClassTokens, provider: 1, retail: 1_000_000},
		{class: ComputePriceClassTokens, provider: 0, retail: 0},
		// per hour, to $0.001: 0.50004 rounds up to 0.501
		{class: ComputePriceClassHour, provider: 500_000_000, retail: 600_000_000},
		{class: ComputePriceClassHour, provider: 416_700_000, retail: 501_000_000},
		// per GiB, to $0.001
		{class: ComputePriceClassGib, provider: 90_000_000, retail: 108_000_000},
		// per search, to $0.0001: $0.01 gives $0.012, and 0.001476 rounds up to 0.0015
		{class: ComputePriceClassSearch, provider: 10_000_000, retail: 12_000_000},
		{class: ComputePriceClassSearch, provider: 5_000_000, retail: 6_000_000},
		{class: ComputePriceClassSearch, provider: 1_230_000, retail: 1_500_000},
	} {
		retail, err := ComputeRetailPrice(settings, v.class, v.provider)
		if err != nil {
			t.Errorf("class %d, %d: %v", v.class, v.provider, err)
			continue
		}
		if retail != v.retail {
			t.Errorf("class %d, %d: retail %d, want %d", v.class, v.provider, retail, v.retail)
		}
		// a retail price is a whole number of its class's steps, never below the marked-up price
		step, _ := v.class.step(settings)
		if retail%step != 0 || float64(retail) < float64(v.provider)*1.2-0.5 {
			t.Errorf("class %d, %d: retail %d is no step at or above the markup", v.class, v.provider, retail)
		}
	}

	for label, refused := range map[string]func() error{
		"a negative price": func() error {
			_, err := ComputeRetailPrice(settings, ComputePriceClassTokens, -1)
			return err
		},
		"no class": func() error {
			_, err := ComputeRetailPrice(settings, ComputePriceClass(9), 1)
			return err
		},
		"a zero denominator": func() error {
			broken := DefaultComputeLedgerSettings()
			broken.MarkupDenominator = 0
			_, err := ComputeRetailPrice(broken, ComputePriceClassTokens, 1)
			return err
		},
		"a zero step": func() error {
			broken := DefaultComputeLedgerSettings()
			broken.SearchPriceStepNanoUsd = 0
			_, err := ComputeRetailPrice(broken, ComputePriceClassSearch, 1)
			return err
		},
		"past int64": func() error {
			_, err := ComputeRetailPrice(settings, ComputePriceClassTokens, math.MaxInt64)
			return err
		},
	} {
		if err := refused(); !errors.Is(err, ErrComputePrice) {
			t.Errorf("%s: %v", label, err)
		}
	}
}

// §9.7's two holds: the costliest model in §4.4, a 1M-token context at $1.85 a million in and 32K out at $9.50
// (provider prices), holds about $2.58 at 1.20; a 256K model at $0.12 and $0.48 about $0.05, so a $10 balance runs
// over a hundred such TEE calls at once. And the worst case rounds up to the nano-USD and refuses an overflow.
func TestComputeWorstCaseMatchesTheDesign(t *testing.T) {
	settings := DefaultComputeLedgerSettings()
	retail := func(provider int64) int64 {
		price, err := ComputeRetailPrice(settings, ComputePriceClassTokens, provider)
		if err != nil {
			t.Fatal(err)
		}
		return price
	}

	costliest, err := ComputeWorstCase(1_000_000, 32_000, retail(1_850_000_000), retail(9_500_000_000))
	if err != nil {
		t.Fatal(err)
	}
	// 2.22 + 0.3648
	if costliest != 2_584_800_000 {
		t.Errorf("the costliest model holds %d nano-USD", costliest)
	}
	if costliest < 2_580_000_000 || 2_590_000_000 <= costliest {
		t.Errorf("the costliest model holds %d nano-USD, not about $2.58", costliest)
	}

	small, err := ComputeWorstCase(256_000, 32_000, retail(120_000_000), retail(480_000_000))
	if err != nil {
		t.Fatal(err)
	}
	// 0.036864 + 0.018432
	if small != 55_296_000 {
		t.Errorf("the small model holds %d nano-USD", small)
	}
	if small < 50_000_000 || 60_000_000 <= small {
		t.Errorf("the small model holds %d nano-USD, not about $0.05", small)
	}
	if calls := 10 * ComputeCreditNanoUsd / small; calls < 100 {
		t.Errorf("a $10 balance runs %d small calls at once", calls)
	}

	// two token-nano-USD over a million tokens is a fraction, which rounds up to one
	if worst, err := ComputeWorstCase(1, 1, 1, 1); err != nil || worst != 1 {
		t.Errorf("the smallest worst case is %d, %v", worst, err)
	}
	if worst, err := ComputeWorstCase(0, 0, 1_000_000, 1_000_000); err != nil || worst != 0 {
		t.Errorf("an empty call holds %d, %v", worst, err)
	}
	if _, err := ComputeWorstCase(math.MaxInt64, math.MaxInt64, math.MaxInt64, math.MaxInt64); !errors.Is(err, ErrComputePrice) {
		t.Errorf("an overflow: %v", err)
	}
	if _, err := ComputeWorstCase(-1, 0, 1, 1); !errors.Is(err, ErrComputePrice) {
		t.Errorf("a negative context: %v", err)
	}
}
