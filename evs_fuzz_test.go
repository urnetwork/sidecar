//go:build !js

// §22.6's evs targets, which need go test's corpus directory, so they stay off the Worker legs, whose Worker has no
// file system. Each target's seeds also run as a test on every leg (evs_record_test.go, evs_statement_test.go and
// evs_batch_test.go), so the Worker leg checks what they check.

package sidecar

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
)

func FuzzEvsSegment(f *testing.F) {
	for _, seed := range evsFuzzSeedFiles(f, "testdata/fuzz/evs_segment") {
		f.Add(seed)
	}
	fixture := newEvsFuzzSegmentFixture(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsSegmentTampering(t, fixture, input)
	})
}

func FuzzEvsNameTable(f *testing.F) {
	for _, seed := range evsFuzzSeedFiles(f, "testdata/fuzz/evs_name_table") {
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

func FuzzEvsPush(f *testing.F) {
	for _, seed := range evsFuzzSeedFiles(f, "testdata/fuzz/evs_push") {
		f.Add(seed)
	}
	fixture := newEvsFuzzPushFixture(f)
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsPushTampering(t, fixture, input)
	})
}

// §22.6's EvsPushPart target: a part that still checks against its statement carries the original's changes and
// entry versions.
func FuzzEvsPushPart(f *testing.F) {
	signer := newEvsTestSigner("fuzz parts")
	built, _ := evsTestBuildAndCheck(f, signer, evsTestPlan(f, signer, "fuzz parts", 1100))
	original, err := EvsCheckPart(built.Statement, built.Parts[0])
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range evsFuzzSeedFiles(f, "testdata/fuzz/evs_push") {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		checked, err := EvsCheckPart(built.Statement, evsFuzzTamper(built.Parts[0], input, func([]byte) {}))
		if err != nil {
			return
		}
		if len(checked.Changes) != len(original.Changes) || checked.Root != original.Root {
			t.Fatal("a tampered part checked with other changes")
		}
		for i, change := range checked.Changes {
			if !bytes.Equal(change.Leaf, original.Changes[i].Leaf) || !bytes.Equal(change.EntryVersion, original.Changes[i].EntryVersion) {
				t.Fatalf("change %d checked otherwise", i)
			}
		}
	})
}

func FuzzEvsBatch(f *testing.F) {
	for _, seed := range evsFuzzSeedFiles(f, "testdata/fuzz/evs_batch") {
		f.Add(seed)
	}
	writer, _ := evsTestBatch(f)
	batchBytes, err := writer.Bytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsBatchTampering(t, batchBytes, input)
	})
}

func FuzzEvsWindowEntry(f *testing.F) {
	f.Add(make([]byte, 64))
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		checkEvsWindowEntryDecode(t, encoded)
	})
}

func FuzzEvsReceiptAndPathMap(f *testing.F) {
	f.Add(evsTestPathMap(f))
	f.Add([]byte{0x0a, 0x10})
	f.Fuzz(func(t *testing.T, input []byte) {
		checkEvsReceiptAndMapDecode(t, input)
	})
}
