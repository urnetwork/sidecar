//go:build !js

// §22.6's evs targets, which need go test's corpus directory, so they stay off the Worker legs, whose Worker has no
// file system. Each target's seeds also run as a test on every leg (evs_record_test.go, evs_statement_test.go and
// evs_batch_test.go), so the Worker leg checks what they check.

package sidecar

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func FuzzEvsSegment(f *testing.F) {
	for _, seed := range evsRecordFuzzSeedFiles(f, "testdata/fuzz/evs_segment") {
		f.Add(seed)
	}
	fixture := newEvsFuzzSegmentFixture(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsSegmentTampering(t, fixture, input)
	})
}

func FuzzEvsNameTable(f *testing.F) {
	for _, seed := range evsRecordFuzzSeedFiles(f, "testdata/fuzz/evs_name_table") {
		f.Add(seed)
	}
	built := newEvsTestNameTable(f)
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(built.table)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsNameTableTampering(t, built, encoded, input)
	})
}
