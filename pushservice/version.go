// §6.8's version and stream-id arithmetic on the Go side, which the scripts in hint_script.go repeat in
// Lua rule for rule (D-PROTO-12). A version is a canonical decimal string in Redis: digits only, no
// leading zero, at most 20, so every uint64 but 0 has exactly one. "Higher" compares lengths, then, at
// equal length, the digits before the last 10 and the last 10 as two numbers, each exact in a double,
// so neither side ever holds a whole version as a Lua number. A stream id is <ms>-<seq>, compared as
// its two integer parts.
//
// Callers hold versions as uint64 and convert here with FormatVersion and ParseVersion. Every function
// is safe for concurrent use.

package pushservice

import (
	"errors"
	"strconv"
	"strings"
)

// The most digits a version holds: uint64's 20 (§6.8).
const maxVersionDigitCount = 20

// The digits of the low part §6.8's comparison splits off, each part exact in a double.
const versionLowDigitCount = 10

var (
	// A version that is not a canonical decimal, or 0, which no topic's state ever has.
	ErrVersionNotCanonical = errors.New("push version is not a canonical decimal")
	// A stream id that is not <ms>-<seq> in canonical decimals.
	ErrStreamIdMalformed = errors.New("push stream id is malformed")
)

// The canonical string of version. 0 has one too, but no hint carries it: CanonicalVersion refuses it.
func FormatVersion(version uint64) string {
	return strconv.FormatUint(version, 10)
}

// Whether text is a canonical version: 1 to 20 digits, the first not 0. A 20-digit text past uint64 is
// canonical for the comparison, as the script holds it, and refused by ParseVersion.
func CanonicalVersion(text string) bool {
	return canonicalDecimal(text) && text != "0"
}

// Whether text is a decimal with no leading zero, 0 itself allowed, of at most 20 digits: the form both
// a version and each part of a stream id have.
func canonicalDecimal(text string) bool {
	if len(text) == 0 || maxVersionDigitCount < len(text) {
		return false
	}
	if text[0] == '0' && len(text) != 1 {
		return false
	}
	for i := 0; i < len(text); i += 1 {
		if text[i] < '0' || '9' < text[i] {
			return false
		}
	}
	return true
}

// The version text holds, or ErrVersionNotCanonical for a text that is not canonical or does not fit a
// uint64.
func ParseVersion(text string) (uint64, error) {
	if !CanonicalVersion(text) {
		return 0, ErrVersionNotCanonical
	}
	version, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, ErrVersionNotCanonical
	}
	return version, nil
}

// -1, 0 or 1 as a is below, equal to or above b, by the script's rule. Both must be canonical
// versions, else ErrVersionNotCanonical.
func CompareVersion(a string, b string) (int, error) {
	if !CanonicalVersion(a) || !CanonicalVersion(b) {
		return 0, ErrVersionNotCanonical
	}
	return compareDecimal(a, b), nil
}

// The script's comparison of two canonical decimals: lengths first, since neither has a leading zero,
// then the digits before the last 10 and the last 10, each read as a number of at most 10 digits, as
// the Lua reads them with tonumber.
func compareDecimal(a string, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	if versionLowDigitCount < len(a) {
		split := len(a) - versionLowDigitCount
		if c := compareSmallDecimal(a[:split], b[:split]); c != 0 {
			return c
		}
		return compareSmallDecimal(a[split:], b[split:])
	}
	return compareSmallDecimal(a, b)
}

// Compares two runs of at most 10 digits as numbers, which a double and a uint64 both hold exactly.
// Leading zeros are allowed here: the low part of a version has them.
func compareSmallDecimal(a string, b string) int {
	aValue, _ := strconv.ParseUint(a, 10, 64)
	bValue, _ := strconv.ParseUint(b, 10, 64)
	switch {
	case aValue < bValue:
		return -1
	case bValue < aValue:
		return 1
	}
	return 0
}

// The two parts of a stream id, <ms>-<seq>, each a canonical decimal that fits a uint64.
func ParseStreamId(text string) (ms uint64, seq uint64, err error) {
	msText, seqText, found := strings.Cut(text, "-")
	if !found || !canonicalDecimal(msText) || !canonicalDecimal(seqText) {
		return 0, 0, ErrStreamIdMalformed
	}
	ms, err = strconv.ParseUint(msText, 10, 64)
	if err != nil {
		return 0, 0, ErrStreamIdMalformed
	}
	seq, err = strconv.ParseUint(seqText, 10, 64)
	if err != nil {
		return 0, 0, ErrStreamIdMalformed
	}
	return ms, seq, nil
}

// -1, 0 or 1 as stream id a is below, equal to or above b, comparing ms and then seq as integers, as
// §6.8 says and Redis orders a stream. ErrStreamIdMalformed for either malformed.
func CompareStreamId(a string, b string) (int, error) {
	aMs, aSeq, err := ParseStreamId(a)
	if err != nil {
		return 0, err
	}
	bMs, bSeq, err := ParseStreamId(b)
	if err != nil {
		return 0, err
	}
	switch {
	case aMs < bMs:
		return -1, nil
	case bMs < aMs:
		return 1, nil
	case aSeq < bSeq:
		return -1, nil
	case bSeq < aSeq:
		return 1, nil
	}
	return 0, nil
}
