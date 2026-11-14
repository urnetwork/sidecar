//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// record.proto's freeze evidence (RECORD-M3-11; §22.10's row for record.proto, §23.8's Gn-out): the list a gate reads,
// held to what this repository holds, so an item that went away fails here and is never read as passed.
//
//	vectors   testdata/record/vectors.json over the stored bytes of every M3 kind, verified on each leg by
//	          record_vectors_test.go and sealed again to the same bytes by record_vectors_fixture_test.go
//	fuzz      FuzzRecordHeader and FuzzRecordEntry, their seeds in testdata/fuzz/ running in every test run
//	FS rows   FS-25 to FS-29, MCP's, each a builder registered on T2 that its own test runs under every rule of §22.8
//
// FS-30 is not in §22.10's list for record.proto: it is M3-out's own row, and Missing("M3-out", T2) reports it while
// no builder is registered for it. No schedule for it is here yet: the root's unit cases cover its clauses over
// sidecartest's fake streams (record_receipt_test.go, record_ingest_test.go, evs_receipt_gate_test.go), and a schedule
// over evsservice's engine needs a record world this package does not have.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The FS rows §22.10 lists as record.proto's Gn-out evidence.
var recordFreezeRows = []string{"FS-25", "FS-26", "FS-27", "FS-28", "FS-29"}

// Those of them whose builders hold barriers, linked on the sidecar_testhooks leg alone.
var recordFreezeHookRows = []string{"FS-26"}

// The seed shapes RECORD-M3-11 names, a file of each in both targets' corpora.
var recordFreezeSeeds = []string{"seed-valid", "seed-reordered", "seed-repeated", "seed-unknown", "seed-packed", "seed-unpacked", "seed-non-minimal"}

// Every item of record.proto's Gn-out evidence is in this repository: the vectors hold every part RECORD-M3-11 names,
// both fuzz targets hold every seed shape, and each of FS-25 to FS-29 has a T2 builder on the leg that links it. What ran is each item's own
// test's to say; this fails when an item is gone.
func TestRecordFreezeEvidenceIsHeld(t *testing.T) {
	root := filepath.Join("..", "..")
	content, err := os.ReadFile(filepath.Join(root, "testdata", "record", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectors := map[string]json.RawMessage{}
	if err := json.Unmarshal(content, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"entries", "deposit_batch", "decision", "actions"} {
		if raw, ok := vectors[part]; !ok || len(raw) <= len("null") {
			t.Errorf("the vectors hold no %s", part)
		}
	}
	for _, target := range []string{"FuzzRecordHeader", "FuzzRecordEntry"} {
		entries, err := os.ReadDir(filepath.Join(root, "testdata", "fuzz", target))
		if err != nil {
			t.Errorf("%s has no corpus: %v", target, err)
			continue
		}
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		for _, seed := range recordFreezeSeeds {
			if !slices.Contains(names, seed) {
				t.Errorf("%s has no %s", target, seed)
			}
		}
	}
	for _, rowId := range recordFreezeRows {
		registration := Lookup(rowId, "", TierT2)
		if registration == nil && slices.Contains(recordFreezeHookRows, rowId) && !sidecartest.HooksLinked {
			t.Logf("record.proto Gn-out: %s holds barriers, so its builder links on the sidecar_testhooks leg alone", rowId)
			continue
		}
		if registration == nil {
			t.Errorf("%s has no T2 builder registered: missing", rowId)
			continue
		}
		t.Logf("record.proto Gn-out: %s", registration)
	}
	if Lookup("FS-30", "", TierT2) == nil {
		t.Log("record.proto Gn-out: FS-30 has no T2 builder registered, which M3-out's sweep reports as missing")
	}
}
