//go:build !ios_extension && !sidecar_http

// The classifier's confusables table (DESIGN-COMPUTE §27.6's two views; SAFE-M13-02): Unicode's confusables.txt, the
// data of TS #39's skeletons, which maps each character that looks like another to its prototype, as "і" (Cyrillic) to
// "i". No Go module carries it (x/text has none), so the release pins Unicode's own file for its Unicode version in the
// signed manifest beside the exported models (question compute-plan-safe-confusables-table, QD-1368), and the device
// loads it only once its SHA-256 matches (SAFE-M13-05): it moves only with a release, as the model does. Until a
// verified table loads, the normalizer has none, and every verdict asks, reason unavailable (SafetyNormalize), never
// a view without skeletons.
//
// The file's format, which LoadSafetyConfusables reads strictly: UTF-8, a byte order mark allowed first; "#" starts a
// comment; each other line is "source ; target ; type", the source one code point and the target one or more, in hex
// separated by spaces, the type one of TS #39's MA, ML, SA or SL. A line it cannot read, a source twice, a code point
// that is no Unicode scalar value, or a table past the settings' bounds is refused whole, matching
// ErrSafetyConfusablesInvalid and ErrSafetyUnavailable.
//
// A loaded table is read only, so safe for concurrent use.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A confusables table that does not read. Every refusal also matches ErrSafetyUnavailable.
var ErrSafetyConfusablesInvalid = errors.New("safety confusables table refused")

// A table refusal, naming the line.
func safetyConfusablesFault(line int, format string, a ...any) error {
	return fmt.Errorf("%w: %w: line %d: %s", ErrSafetyUnavailable, ErrSafetyConfusablesInvalid, line, fmt.Sprintf(format, a...))
}

// TS #39's mapping types: the current file writes MA alone, earlier ones all four.
var safetyConfusablesTypes = []string{"MA", "ML", "SA", "SL"}

// Unicode's confusables, each source code point's prototype (see the file comment).
type SafetyConfusables struct {
	prototypes map[rune]string
}

// The entries the table holds.
func (self *SafetyConfusables) EntryCount() int {
	return len(self.prototypes)
}

// The table in data, Unicode's confusables.txt, refused as the file comment says.
func LoadSafetyConfusables(data []byte, settings *SafetySettings) (*SafetyConfusables, error) {
	if settings.ConfusablesMaxByteCount < len(data) {
		return nil, safetyConfusablesFault(0, "longer than %d bytes", settings.ConfusablesMaxByteCount)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if !utf8.Valid(data) {
		return nil, safetyConfusablesFault(0, "not UTF-8")
	}
	table := &SafetyConfusables{prototypes: map[rune]string{}}
	for index, line := range strings.Split(string(data), "\n") {
		number := index + 1
		if comment := strings.IndexByte(line, '#'); 0 <= comment {
			line = line[:comment]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ";")
		if len(fields) != 3 {
			return nil, safetyConfusablesFault(number, "%d fields, not 3", len(fields))
		}
		source, err := safetyConfusablesCodePoints(fields[0])
		if err != nil || len(source) != 1 {
			return nil, safetyConfusablesFault(number, "a source that is not one code point")
		}
		target, err := safetyConfusablesCodePoints(fields[1])
		if err != nil || len(target) == 0 || settings.ConfusablesTargetMaxCodePointCount < len(target) {
			return nil, safetyConfusablesFault(number, "a target that is not 1 to %d code points", settings.ConfusablesTargetMaxCodePointCount)
		}
		mappingType := strings.TrimSpace(fields[2])
		known := false
		for _, knownType := range safetyConfusablesTypes {
			known = known || mappingType == knownType
		}
		if !known {
			return nil, safetyConfusablesFault(number, "the type %q", mappingType)
		}
		if _, ok := table.prototypes[source[0]]; ok {
			return nil, safetyConfusablesFault(number, "U+%04X twice", source[0])
		}
		if settings.ConfusablesMaxEntryCount <= len(table.prototypes) {
			return nil, safetyConfusablesFault(number, "more than %d entries", settings.ConfusablesMaxEntryCount)
		}
		table.prototypes[source[0]] = string(target)
	}
	if len(table.prototypes) == 0 {
		return nil, safetyConfusablesFault(0, "no entry")
	}
	return table, nil
}

// The code points of field: hex numbers separated by spaces, each a Unicode scalar value.
func safetyConfusablesCodePoints(field string) ([]rune, error) {
	codePoints := []rune{}
	for _, word := range strings.Fields(field) {
		if len(word) < 4 || 6 < len(word) {
			return nil, errors.New("a code point of the wrong length")
		}
		value, err := strconv.ParseUint(word, 16, 32)
		if err != nil || !utf8.ValidRune(rune(value)) {
			return nil, errors.New("no Unicode scalar value")
		}
		codePoints = append(codePoints, rune(value))
	}
	return codePoints, nil
}
