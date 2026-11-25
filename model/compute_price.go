// §9.6's prices and §9.7's worst case (BAL-M12-01), in exact integer arithmetic: money is int64 nano-USD and never a
// float (D-BAL-2), and every product is taken in 128 bits, so a large price or context overflows into an error,
// never into a wrong amount.
//
//   - ComputeRetailPrice: the provider's price for a unit, in gamma, which is USD-valued (§10.2) and so reads here as
//     nano-USD, times the compute markup, rounded up to its unit class's step: per million tokens to $0.001, per hour
//     to $0.001, per search to $0.0001 (and per GiB of host egress to $0.001, a reading). The caller converts a gamma
//     price at its read's USD value before it asks.
//   - ComputeWorstCase: what a TEE call holds (§9.7's step 2): its model's context window times the input price plus
//     its maximum output times the output price, each price per million tokens, rounded up to the nano-USD. The
//     prices are retail ones, the catalog's, so a 1M-token context at $1.85 in and 32K out at $9.50 (provider prices)
//     holds about $2.58 at 1.20, and a 256K model at $0.12 and $0.48 about $0.05.

package model

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
)

// A price's unit, which sets the step its retail price rounds up to (§9.6).
type ComputePriceClass int

const (
	// Per million tokens: input, output or cached input.
	ComputePriceClassTokens ComputePriceClass = 1
	// Per hour of an enclave shape's running time.
	ComputePriceClassHour ComputePriceClass = 2
	// Per GiB of an enclave's host egress (kind 4).
	ComputePriceClassGib ComputePriceClass = 3
	// Per web search.
	ComputePriceClassSearch ComputePriceClass = 4
)

// A price or worst case that cannot be: a negative input, settings without a positive markup or step, or a result
// past int64.
var ErrComputePrice = errors.New("compute price")

// The step class's prices round up to, from settings.
func (self ComputePriceClass) step(settings *ComputeLedgerSettings) (int64, error) {
	switch self {
	case ComputePriceClassTokens:
		return settings.TokenPriceStepNanoUsd, nil
	case ComputePriceClassHour:
		return settings.HourPriceStepNanoUsd, nil
	case ComputePriceClassGib:
		return settings.GibPriceStepNanoUsd, nil
	case ComputePriceClassSearch:
		return settings.SearchPriceStepNanoUsd, nil
	}
	return 0, fmt.Errorf("%w: no price class %d", ErrComputePrice, int(self))
}

// The network's price for a unit of class, from the provider's price for it in nano-USD: the markup applied and the
// result rounded up to the class's step, exactly. A provider price of zero is a retail price of zero.
func ComputeRetailPrice(settings *ComputeLedgerSettings, class ComputePriceClass, providerNanoUsd int64) (int64, error) {
	step, err := class.step(settings)
	if err != nil {
		return 0, err
	}
	if providerNanoUsd < 0 {
		return 0, fmt.Errorf("%w: a negative provider price", ErrComputePrice)
	}
	if step <= 0 || settings.MarkupNumerator <= 0 || settings.MarkupDenominator <= 0 {
		return 0, fmt.Errorf("%w: the markup and each step are positive", ErrComputePrice)
	}
	// ceil(price × num / (den × step)) steps, each step exact
	divisorHi, divisor := bits.Mul64(uint64(settings.MarkupDenominator), uint64(step))
	if divisorHi != 0 {
		return 0, fmt.Errorf("%w: the markup's denominator and step overflow", ErrComputePrice)
	}
	productHi, productLo := bits.Mul64(uint64(providerNanoUsd), uint64(settings.MarkupNumerator))
	steps, ok := computeDivCeil(productHi, productLo, divisor)
	if !ok {
		return 0, fmt.Errorf("%w: past int64", ErrComputePrice)
	}
	retailHi, retail := bits.Mul64(steps, uint64(step))
	if retailHi != 0 || math.MaxInt64 < retail {
		return 0, fmt.Errorf("%w: past int64", ErrComputePrice)
	}
	return int64(retail), nil
}

// What a call to a model holds at its worst (§9.7): contextWindowTokens at the input price plus maxOutputTokens at
// the output price, each price in nano-USD per million tokens, rounded up to the nano-USD. The prices are the
// catalog's retail ones.
func ComputeWorstCase(contextWindowTokens int64, maxOutputTokens int64, inputNanoUsdPerMillion int64, outputNanoUsdPerMillion int64) (int64, error) {
	if contextWindowTokens < 0 || maxOutputTokens < 0 || inputNanoUsdPerMillion < 0 || outputNanoUsdPerMillion < 0 {
		return 0, fmt.Errorf("%w: a negative count or price", ErrComputePrice)
	}
	inputHi, inputLo := bits.Mul64(uint64(contextWindowTokens), uint64(inputNanoUsdPerMillion))
	outputHi, outputLo := bits.Mul64(uint64(maxOutputTokens), uint64(outputNanoUsdPerMillion))
	sumLo, carry := bits.Add64(inputLo, outputLo, 0)
	sumHi, overflow := bits.Add64(inputHi, outputHi, carry)
	if overflow != 0 {
		return 0, fmt.Errorf("%w: past int64", ErrComputePrice)
	}
	worst, ok := computeDivCeil(sumHi, sumLo, uint64(computeTokensPerPriceUnit))
	if !ok || math.MaxInt64 < worst {
		return 0, fmt.Errorf("%w: past int64", ErrComputePrice)
	}
	return int64(worst), nil
}

// The 128-bit hi:lo over a positive divisor, rounded up, or false where the quotient passes 64 bits.
func computeDivCeil(hi uint64, lo uint64, divisor uint64) (uint64, bool) {
	if divisor == 0 || divisor <= hi {
		return 0, false
	}
	quotient, remainder := bits.Div64(hi, lo, divisor)
	if remainder != 0 {
		if quotient == math.MaxUint64 {
			return 0, false
		}
		quotient += 1
	}
	return quotient, true
}
