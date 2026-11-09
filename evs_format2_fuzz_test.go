//go:build !js

// §22.6's format-2 evs targets, which need go test's corpus directory, so they stay off the Worker legs. Each target's
// seeds also run as a test on every leg (evs_format2_codec_test.go, evs_drop_payload_test.go), so the Worker leg
// checks what they check.

package sidecar

import (
	"testing"
)

// The kind-5 segment target: a tampered kind-5 segment's one record opens to its body or fails before plaintext.
func FuzzEvsKind5Segment(f *testing.F) {
	for _, seed := range evsFuzzSeedFiles(f, "testdata/fuzz/evs_segment") {
		f.Add(seed)
	}
	fixture := newEvsFuzzKind5SegmentFixture(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsKind5SegmentTampering(t, fixture, input)
	})
}

// The format-2 batch target: a tampered batch fails or reads back the original's records and tails.
func FuzzEvsFormat2Batch(f *testing.F) {
	for _, seed := range evsFuzzSeedFiles(f, "testdata/fuzz/evs_batch") {
		f.Add(seed)
	}
	writer, _, _ := evsTestFormat2Batch(f)
	original, err := writer.Bytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsFormat2BatchTampering(t, original, input)
	})
}

// The DROP target (§22.6's EvsDropHistory and its lists): a tampered body or lists that still check adopt exactly the
// original's.
func FuzzEvsDrop(f *testing.F) {
	for _, seed := range evsDropFuzzSeedFiles(f, "testdata/fuzz/evs_drop") {
		f.Add(seed)
	}
	push, body, lists := evsTestTwoPathDrop(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsDropTampering(t, push, body, lists, input)
	})
}
