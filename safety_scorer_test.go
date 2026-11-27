//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The classifier's runtime seam (safety_scorer.go; SAFE-M13-01): two logits a window turned to a probability in basis
// points, rounded up; the hosts' JSON both ways, refused unless whole; and the windows a runtime may be given.

import (
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
)

// Softmax in basis points: equal logits are even, a wide margin either way reaches the ends, a probability between
// two basis points rounds up, and a logit that is no finite number is refused.
func TestSafetyLogitsMaliciousBasisPoints(t *testing.T) {
	cases := []struct {
		logits SafetyLogits
		want   int
	}{
		{logits: SafetyLogits{Benign: 0, Malicious: 0}, want: 5000},
		{logits: SafetyLogits{Benign: 3, Malicious: 3}, want: 5000},
		{logits: SafetyLogits{Benign: -40, Malicious: 40}, want: 10000},
		{logits: SafetyLogits{Benign: 40, Malicious: -40}, want: 1},
		{logits: SafetyLogits{Benign: 800, Malicious: -800}, want: 0},
		// 1 / (1 + e^ln(4)) = 0.2, exactly 2,000
		{logits: SafetyLogits{Benign: math.Log(4), Malicious: 0}, want: 2000},
		// a hair over 0.2 is 2,001, never 2,000, so a threshold of 2,001 asks
		{logits: SafetyLogits{Benign: math.Log(4) - 1e-6, Malicious: 0}, want: 2001},
	}
	for _, c := range cases {
		got, err := c.logits.MaliciousBasisPoints()
		if err != nil || got != c.want {
			t.Errorf("%+v: %d, %v; want %d", c.logits, got, err, c.want)
		}
	}
	for _, logits := range []SafetyLogits{
		{Benign: math.NaN(), Malicious: 0},
		{Benign: 0, Malicious: math.Inf(1)},
		{Benign: math.Inf(-1), Malicious: 0},
	} {
		if _, err := logits.MaliciousBasisPoints(); !errors.Is(err, ErrSafetyUnavailable) {
			t.Errorf("%+v: %v, want unavailable", logits, err)
		}
	}
}

// The hosts' JSON: windows out and logits back, a pair a window; anything not whole is unavailable.
func TestSafetyScorerJson(t *testing.T) {
	settings := DefaultSafetySettings()
	windows := [][]int64{{1, 9, 2}, {1, 2}}
	encoded, err := safetyWindowsJson(windows)
	if err != nil || encoded != "[[1,9,2],[1,2]]" {
		t.Fatalf("%s, %v", encoded, err)
	}
	decoded, err := parseSafetyWindowsJson([]byte(encoded), settings)
	if err != nil || len(decoded) != 2 || !slices.Equal(decoded[0], windows[0]) || !slices.Equal(decoded[1], windows[1]) {
		t.Fatalf("%v, %v", decoded, err)
	}
	logits := []SafetyLogits{{Benign: 2.5, Malicious: -1.25}, {Benign: -3, Malicious: 4}}
	answer, err := safetyLogitsJson(logits)
	if err != nil || answer != "[[2.5,-1.25],[-3,4]]" {
		t.Fatalf("%s, %v", answer, err)
	}
	parsed, err := parseSafetyLogitsJson([]byte(answer), 2)
	if err != nil || !slices.Equal(parsed, logits) {
		t.Fatalf("%v, %v", parsed, err)
	}
	if _, err := safetyLogitsJson([]SafetyLogits{{Benign: math.NaN()}}); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("a NaN encoded: %v", err)
	}
	for _, refused := range []struct {
		name   string
		answer string
		count  int
	}{
		{name: "a pair short", answer: "[[2.5,-1.25]]", count: 2},
		{name: "a pair over", answer: "[[1,2],[3,4],[5,6]]", count: 2},
		{name: "three logits", answer: "[[1,2,3],[3,4]]", count: 2},
		{name: "one logit", answer: "[[1],[3,4]]", count: 2},
		{name: "not numbers", answer: `[["1","2"],[3,4]]`, count: 2},
		{name: "past a double", answer: "[[1e999,2],[3,4]]", count: 2},
		{name: "trailing", answer: "[[1,2],[3,4]] []", count: 2},
		{name: "nothing", answer: "", count: 2},
	} {
		if _, err := parseSafetyLogitsJson([]byte(refused.answer), refused.count); !errors.Is(err, ErrSafetyUnavailable) {
			t.Errorf("%s: %v, want unavailable", refused.name, err)
		}
	}
}

// The windows a runtime may be given: one to EngineWindowMaxCount, each of 2 to WindowTokenCount ids, none negative
// or past an int32.
func TestSafetyCheckWindows(t *testing.T) {
	settings := DefaultSafetySettings()
	full := make([]int64, settings.WindowTokenCount)
	if err := safetyCheckWindows([][]int64{full, {1, 2}}, settings); err != nil {
		t.Errorf("windows within bounds: %v", err)
	}
	many := make([][]int64, settings.EngineWindowMaxCount+1)
	for i := range many {
		many[i] = []int64{1, 2}
	}
	for _, refused := range []struct {
		name    string
		windows [][]int64
	}{
		{name: "none", windows: nil},
		{name: "too many", windows: many},
		{name: "a window of one id", windows: [][]int64{{1}}},
		{name: "a window too long", windows: [][]int64{append(slices.Clone(full), 0)}},
		{name: "a negative id", windows: [][]int64{{1, -5, 2}}},
		{name: "an id past an int32", windows: [][]int64{{1, math.MaxInt32 + 1, 2}}},
	} {
		if err := safetyCheckWindows(refused.windows, settings); !errors.Is(err, ErrSafetyUnavailable) {
			t.Errorf("%s: %v, want unavailable", refused.name, err)
		}
	}
	if _, err := parseSafetyWindowsJson([]byte("[[1,2]] x"), settings); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("trailing windows: %v", err)
	}
	if _, err := parseSafetyWindowsJson([]byte("[["+strings.Repeat("1,", settings.WindowTokenCount)+"2]]"), settings); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("a window past its bound: %v", err)
	}
}
