package sidecartest

// RequestTraceEqual and FrameSizesEqual (TEST-M10-02): equal traces pass, each mutant the search rows name fails, a
// fetch that depends on the query and an early short reply among them, and a comparison that could show nothing is
// refused rather than passed.

import (
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/connect"
)

// Two queries' traces on one phone surrogate from one sync state.
func phoneTraces() (*RequestTrace, *RequestTrace) {
	first := &RequestTrace{Label: "ios32 query a", SyncState: "index@7 rule=phone opened=", Requests: []string{
		"evs1 GET /evs/read?ref=r1&path=b/20000/s/0 0",
		"evs1 GET /evs/read?ref=r1&path=a/m 0",
	}}
	second := &RequestTrace{Label: "ios32 query b", SyncState: first.SyncState, Requests: append([]string{}, first.Requests...)}
	return first, second
}

func TestRequestTracesFromOneSyncStatePass(t *testing.T) {
	first, second := phoneTraces()
	desktopA := &RequestTrace{Label: "desktop query a", SyncState: "index@7 rule=desktop opened="}
	desktopB := &RequestTrace{Label: "desktop query b", SyncState: desktopA.SyncState}
	if err := RequestTraceEqual(first, second); err != nil {
		t.Errorf("phone: %v", err)
	}
	// a desktop reads its cache alone, so both searches send nothing
	if err := RequestTraceEqual(desktopA, desktopB); err != nil {
		t.Errorf("desktop: %v", err)
	}
}

// A fetch that depends on the query: the second query reads a shard the first does not.
func TestARequestTraceThatDependsOnTheQueryFails(t *testing.T) {
	first, second := phoneTraces()
	second.Requests = append(second.Requests, "evs1 GET /evs/read?ref=r1&path=a/3 0")
	err := RequestTraceEqual(first, second)
	if err == nil || errors.Is(err, ErrTraceNotCompared) || !strings.Contains(err.Error(), "request 2") {
		t.Errorf("an extra read: %v", err)
	}
	first, second = phoneTraces()
	second.Requests[1] = "evs1 GET /evs/read?ref=r1&path=a/m 16384"
	if err := RequestTraceEqual(first, second); err == nil || !strings.Contains(err.Error(), "request 1") {
		t.Errorf("another size: %v", err)
	}
}

// Unequal sync states, one trace or none, and a trace naming no state compare nothing, so they are refused.
func TestARequestTraceComparisonThatCouldShowNothingIsRefused(t *testing.T) {
	first, second := phoneTraces()
	second.SyncState = "index@8 rule=phone opened="
	cases := [][]*RequestTrace{{first, second}, {first}, {}, {first, {Label: "no state", Requests: first.Requests}}, {first, nil}}
	for index, traces := range cases {
		if err := RequestTraceEqual(traces...); !errors.Is(err, ErrTraceNotCompared) {
			t.Errorf("case %d: %v", index, err)
		}
	}
}

// A relay's capture of one pair's frames, as FrameSizes gives it: requests of 4,016 B and replies of steps x 16,384 B,
// each with the same framing whatever the query.
func relayTrace(t *testing.T, label string, kind string, requestSizes []int, replySizes []int) *FrameSizeTrace {
	t.Helper()
	capture := NewPrivacyCapture()
	requester := connect.NewId()
	indexer := connect.NewId()
	for _, size := range requestSizes {
		capture.AddFrame(requester, indexer, make([]byte, size))
	}
	for _, size := range replySizes {
		capture.AddFrame(indexer, requester, make([]byte, size))
	}
	return &FrameSizeTrace{Label: label, Kind: kind, Requests: capture.FrameSizes(requester, indexer), Replies: capture.FrameSizes(indexer, requester)}
}

func TestFrameSizesOfOneKindPass(t *testing.T) {
	traces := []*FrameSizeTrace{
		relayTrace(t, "0 hits", "1 step", []int{4096}, []int{16464}),
		relayTrace(t, "20 hits", "1 step", []int{4096}, []int{16464}),
		relayTrace(t, "a post-parse failure", "1 step", []int{4096}, []int{16464}),
		relayTrace(t, "3 hits", "2 steps", []int{4096}, []int{16464, 16464}),
		relayTrace(t, "19 hits", "2 steps", []int{4096}, []int{16464, 16464}),
	}
	if err := FrameSizesEqual(traces...); err != nil {
		t.Error(err)
	}
}

// An early short reply: a failure after parsing answers in fewer bytes than its kind's steps.
func TestAnEarlyShortReplyFails(t *testing.T) {
	err := FrameSizesEqual(
		relayTrace(t, "20 hits", "1 step", []int{4096}, []int{16464}),
		relayTrace(t, "a post-parse failure", "1 step", []int{4096}, []int{80}),
	)
	if err == nil || errors.Is(err, ErrTraceNotCompared) || !strings.Contains(err.Error(), "reply frames differ at frame 0") {
		t.Errorf("a short reply: %v", err)
	}
	err = FrameSizesEqual(
		relayTrace(t, "2 hits", "2 steps", []int{4096}, []int{16464, 16464}),
		relayTrace(t, "20 hits", "2 steps", []int{4096}, []int{16464}),
	)
	if err == nil || !strings.Contains(err.Error(), "reply frames differ at frame 1") {
		t.Errorf("a reply cut a step short: %v", err)
	}
	err = FrameSizesEqual(
		relayTrace(t, "a long query", "1 step", []int{4096, 1200}, []int{16464}),
		relayTrace(t, "a short query", "1 step", []int{4096}, []int{16464}),
	)
	if err == nil || !strings.Contains(err.Error(), "request frames differ at frame 1") {
		t.Errorf("a request sized by its query: %v", err)
	}
}

// One trace, a kind with one trace, and a trace that carried nothing compare nothing.
func TestAFrameSizeComparisonThatCouldShowNothingIsRefused(t *testing.T) {
	one := relayTrace(t, "one", "1 step", []int{4096}, []int{16464})
	lone := relayTrace(t, "lone", "2 steps", []int{4096}, []int{16464, 16464})
	empty := &FrameSizeTrace{Label: "nothing carried", Kind: "1 step", Requests: []int{4096}}
	cases := [][]*FrameSizeTrace{{one}, {}, {one, one, lone}, {one, empty}, {one, nil}}
	for index, traces := range cases {
		if err := FrameSizesEqual(traces...); !errors.Is(err, ErrTraceNotCompared) {
			t.Errorf("case %d: %v", index, err)
		}
	}
}
