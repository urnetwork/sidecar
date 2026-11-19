// What a server or a relay sees of two searches that differ only in what was asked must not differ (§22.7's
// request-traces and query-canaries rows; FI-23, FI-24, D-TEST-16; TEST-M10-02). RequestTraceEqual holds devices'
// server-visible request traces equal, as PrivacyCapture.RequestLog gives them: engine, method, target and body size,
// never what a run draws fresh. FrameSizesEqual holds a relay's frame-size sequences of remote searches equal, as
// PrivacyCapture.FrameSizes gives them, kind by kind.
//
// Both refuse a comparison that cannot show a leak rather than pass it: traces from unequal sync states, where a real
// leak hides among legitimate differences, fewer than two traces, and a relay trace that carried nothing. S11's and
// S12's asserts and FI-23's and FI-24's checks call these, so the rule is written once.

package sidecartest

import (
	"errors"
	"fmt"
	"slices"
)

// A comparison that would show nothing.
var ErrTraceNotCompared = errors.New("trace: nothing compared")

// One search's server-visible requests, and the sync state it ran from.
type RequestTrace struct {
	// What the trace is of, for a failure: the host and a label for the query, never the query itself.
	Label string
	// The device's sync state when the search ran, in a form two equal states give alike: the index versions it
	// holds, its fetch rule and the results its person opened. Traces compare only at one state.
	SyncState string
	// The requests the search made, in order, as PrivacyCapture.RequestLog gives them for the device's actor.
	Requests []string
}

// Holds every trace's requests to the first's, line for line and in order, so no request, target or body size
// depends on what was asked. Fewer than two traces, a trace with no sync state, and traces from unequal sync states are
// ErrTraceNotCompared. Empty request lists are equal: a desktop's search, which reads its cache alone, sends nothing.
func RequestTraceEqual(traces ...*RequestTrace) error {
	if len(traces) < 2 {
		return fmt.Errorf("%w: %d request traces", ErrTraceNotCompared, len(traces))
	}
	first := traces[0]
	for _, trace := range traces {
		if trace == nil {
			return fmt.Errorf("%w: a nil request trace", ErrTraceNotCompared)
		}
		if trace.SyncState == "" {
			return fmt.Errorf("%w: %s names no sync state", ErrTraceNotCompared, trace.Label)
		}
		if trace.SyncState != first.SyncState {
			return fmt.Errorf("%w: %s ran from sync state %q and %s from %q", ErrTraceNotCompared, first.Label, first.SyncState, trace.Label, trace.SyncState)
		}
	}
	for _, trace := range traces[1:] {
		if index, ok := traceFirstDifference(first.Requests, trace.Requests); !ok {
			return fmt.Errorf("%s and %s, from one sync state, differ at request %d: %q and %q", first.Label, trace.Label, index,
				traceLineAt(first.Requests, index), traceLineAt(trace.Requests, index))
		}
	}
	return nil
}

// What a relay carried of one remote search: the size of each frame between requester and indexer, each way.
type FrameSizeTrace struct {
	// What the trace is of, for a failure: a label for the query and its results, never the query itself.
	Label string
	// The kind of exchange, which fixes its sizes whatever the query: the steps it asked for, say "1 step", or the
	// fifth search of a session. A failure after parsing answers as a success of its kind does, so it shares its kind.
	Kind string
	// Requester to indexer, and indexer to requester, in the order the relay carried them (PrivacyCapture.FrameSizes).
	Requests []int
	Replies  []int
}

// Holds each kind's traces to one frame-size sequence each way: every trace equal to the first of its kind, frame for
// frame, so a query, its scope, its filters, its hits (0 to 20) and a failure after parsing change no size the relay
// sees. Fewer than two traces, a kind with one trace, and a trace that carried nothing either way are
// ErrTraceNotCompared.
func FrameSizesEqual(traces ...*FrameSizeTrace) error {
	if len(traces) < 2 {
		return fmt.Errorf("%w: %d frame-size traces", ErrTraceNotCompared, len(traces))
	}
	kindTraces := map[string][]*FrameSizeTrace{}
	kinds := []string{}
	for _, trace := range traces {
		if trace == nil {
			return fmt.Errorf("%w: a nil frame-size trace", ErrTraceNotCompared)
		}
		if len(trace.Requests) == 0 || len(trace.Replies) == 0 {
			return fmt.Errorf("%w: %s carried %d frames out and %d back", ErrTraceNotCompared, trace.Label, len(trace.Requests), len(trace.Replies))
		}
		if _, ok := kindTraces[trace.Kind]; !ok {
			kinds = append(kinds, trace.Kind)
		}
		kindTraces[trace.Kind] = append(kindTraces[trace.Kind], trace)
	}
	errs := []error{}
	for _, kind := range kinds {
		kindOf := kindTraces[kind]
		if len(kindOf) < 2 {
			errs = append(errs, fmt.Errorf("%w: %s is the only trace of kind %q", ErrTraceNotCompared, kindOf[0].Label, kind))
			continue
		}
		first := kindOf[0]
		for _, trace := range kindOf[1:] {
			if index, ok := traceFirstDifference(first.Requests, trace.Requests); !ok {
				errs = append(errs, fmt.Errorf("kind %q: %s's and %s's request frames differ at frame %d: %s and %s", kind, first.Label, trace.Label,
					index, traceSizeAt(first.Requests, index), traceSizeAt(trace.Requests, index)))
			}
			if index, ok := traceFirstDifference(first.Replies, trace.Replies); !ok {
				errs = append(errs, fmt.Errorf("kind %q: %s's and %s's reply frames differ at frame %d: %s and %s", kind, first.Label, trace.Label,
					index, traceSizeAt(first.Replies, index), traceSizeAt(trace.Replies, index)))
			}
		}
	}
	return errors.Join(errs...)
}

// The first index at which a and b differ, a length counting as a difference at the shorter's end; ok when equal.
func traceFirstDifference[T comparable](a []T, b []T) (int, bool) {
	if slices.Equal(a, b) {
		return 0, true
	}
	for index := 0; index < min(len(a), len(b)); index += 1 {
		if a[index] != b[index] {
			return index, false
		}
	}
	return min(len(a), len(b)), false
}

func traceLineAt(lines []string, index int) string {
	if index < len(lines) {
		return lines[index]
	}
	return "(none)"
}

func traceSizeAt(sizes []int, index int) string {
	if index < len(sizes) {
		return fmt.Sprintf("%d B", sizes[index])
	}
	return "none"
}
