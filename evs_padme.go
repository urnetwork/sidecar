// Padmé (Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs", PETS
// 2019, §4): the padded length that hides all but O(log log L) bits of a length L, at most 12% more. A segment pads to
// it with random bytes (§11.6's segment row), so evs sees a segment's padded size and never its length; an inline or
// staged record is one that pads to at most 16 KiB.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"math/bits"
)

// The largest length Padmé is computed for here. Its padding never passes the next power of two, so every result
// fits in 64 bits; nothing evs stores comes near it.
const evsPadmeMaxLength = uint64(1) << 63

// Padmé(L): with E = floor(log2 L) and S = floor(log2 E) + 1, L rounded up to a multiple of 2^(E - S). Lengths 0 to 3
// are their own. A length past 2^63, which no object reaches, gives 0, which no length pads to.
func EvsPadme(length uint64) uint64 {
	if length < 4 {
		return length
	}
	if evsPadmeMaxLength < length {
		return 0
	}
	exponent := uint64(bits.Len64(length) - 1)
	mantissaBits := uint64(bits.Len64(exponent))
	mask := uint64(1)<<(exponent-mantissaBits) - 1
	return ((length - 1) | mask) + 1
}

// Whether size is a length Padmé gives: a padded size whose segment could be honest. Every Padmé length pads to
// itself.
func EvsIsPadme(size uint64) bool {
	return size != 0 && EvsPadme(size) == size
}
