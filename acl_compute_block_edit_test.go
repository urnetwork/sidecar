//go:build !ios_extension

package sidecar

// CACL-M12-03: editing compute.disclosures in place for CTRUST-M12-02 (DESIGN-COMPUTE §2.8, §16.4): one entry added,
// replaced or taken out, every other byte as written, comments and trailing commas included, in a document or a
// block-alone record, and nothing the readers would refuse. Pure, on every leg.

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

// A document a person wrote, comments, spacing and a trailing comma included, with a block holding one disclosure.
const testComputeEditDocument = `// the network's policy
{
  "grants": [
    { "src": ["autogroup:member"], "dst": ["*"], "allow": ["*"] }, // everyone
  ],
  "compute": {
    "assurance_floor": "AP",   /* raised in March */
    "disclosures": {
      "inference:engy": "c2lnbmVk",
    },
  },
}
`

// Whether edited is before with inserted put at one place and nothing else changed.
func testComputeEditInserted(before []byte, edited []byte, inserted string) bool {
	for at := 0; at <= len(before); at += 1 {
		if bytes.Equal(edited, slices.Concat(before[:at], []byte(inserted), before[at:])) {
			return true
		}
	}
	return false
}

// An added, a replaced and a removed entry each change only its own bytes; the result parses with the entry as set.
func TestComputeBlockDisclosureEditKeepsBytes(t *testing.T) {
	source := []byte(testComputeEditDocument)
	added, err := SetComputeBlockDisclosure(source, "search:parallel", "c2VhcmNo")
	if err != nil {
		t.Fatal(err)
	}
	if !testComputeEditInserted(source, added, `, "search:parallel": "c2VhcmNo"`) {
		t.Errorf("an added entry changed more than its own bytes:\n%s", added)
	}
	if block := testComputeBlockParsed(t, string(added)); len(block.Disclosures) != 2 || block.Disclosures[1].Statement != "c2VhcmNo" {
		t.Errorf("the added entry: %+v", block.Disclosures)
	}

	replaced, err := SetComputeBlockDisclosure(added, "inference:engy", "bmV3ZXI=")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replaced, bytes.Replace(added, []byte(`"c2lnbmVk"`), []byte(`"bmV3ZXI="`), 1)) {
		t.Errorf("a replaced entry changed more than its value:\n%s", replaced)
	}

	removed, err := RemoveComputeBlockDisclosure(replaced, "search:parallel")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(removed, bytes.Replace(source, []byte(`"c2lnbmVk"`), []byte(`"bmV3ZXI="`), 1)) {
		t.Errorf("a removal changed more than its entry:\n%s", removed)
	}
	// the first of two, then the last one standing
	first, err := RemoveComputeBlockDisclosure(added, "inference:engy")
	if err != nil {
		t.Fatal(err)
	}
	if block := testComputeBlockParsed(t, string(first)); len(block.Disclosures) != 1 || block.Disclosures[0].Id != "search:parallel" {
		t.Errorf("after removing the first: %s", first)
	}
	last, err := RemoveComputeBlockDisclosure(first, "search:parallel")
	if err != nil {
		t.Fatal(err)
	}
	if block := testComputeBlockParsed(t, string(last)); len(block.Disclosures) != 0 || block.AssuranceFloor == 0 {
		t.Errorf("after removing both: %s", last)
	}
	// an entry that does not stand leaves the source as it was
	if same, err := RemoveComputeBlockDisclosure(source, "connect:notes"); err != nil || !bytes.Equal(same, source) {
		t.Errorf("removing what is not there: %v", err)
	}
}

// A document or record with no compute key, or no disclosures key, gains it holding the one entry; an empty source
// becomes a block-alone record.
func TestComputeBlockDisclosureEditAddsTheKey(t *testing.T) {
	document := []byte(`{"grants": [], /* none yet */}`)
	edited, err := SetComputeBlockDisclosure(document, "enclave:hippius", "aGlwcGl1cw==")
	if err != nil {
		t.Fatal(err)
	}
	if !testComputeEditInserted(document, edited, `, "compute": {"disclosures": {"enclave:hippius": "aGlwcGl1cw=="}}`) {
		t.Errorf("the document: %s", edited)
	}
	record := []byte("{\"compute\": {\"fetch\": {\"enabled\": false}}}\n")
	edited, err = SetComputeBlockDisclosure(record, "enclave:hippius", "aGlwcGl1cw==")
	if err != nil {
		t.Fatal(err)
	}
	if block, err := ParseAclComputeRecord(edited); err != nil || len(block.Disclosures) != 1 || *block.Fetch.Enabled {
		t.Errorf("the record: %s, %v", edited, err)
	}
	empty, err := SetComputeBlockDisclosure(nil, "approvals:auto", "YXV0bw==")
	if err != nil {
		t.Fatal(err)
	}
	if block, err := ParseAclComputeRecord(empty); err != nil || block.Disclosures[0].Id != "approvals:auto" {
		t.Errorf("a new record: %s, %v", empty, err)
	}
	emptyBlock, err := SetComputeBlockDisclosure([]byte(`{"compute": {}}`), "approvals:auto", "YXV0bw==")
	if err != nil || !bytes.Equal(emptyBlock, []byte(`{"compute": {"disclosures": {"approvals:auto": "YXV0bw=="}}}`)) {
		t.Errorf("an empty block: %s, %v", emptyBlock, err)
	}
}

// An edit the readers would refuse is no edit: a bad id, a statement that is not base64, a source that does not parse
// or whose compute value is no object.
func TestComputeBlockDisclosureEditRefuses(t *testing.T) {
	for name, edit := range map[string]func() ([]byte, error){
		"an id":        func() ([]byte, error) { return SetComputeBlockDisclosure(nil, "engy", "YQ==") },
		"a statement":  func() ([]byte, error) { return SetComputeBlockDisclosure(nil, "inference:engy", "not base64") },
		"no statement": func() ([]byte, error) { return SetComputeBlockDisclosure(nil, "inference:engy", "") },
		"a source": func() ([]byte, error) {
			return SetComputeBlockDisclosure([]byte(`{"grants": [}`), "inference:engy", "YQ==")
		},
		"a compute": func() ([]byte, error) {
			return SetComputeBlockDisclosure([]byte(`{"compute": []}`), "inference:engy", "YQ==")
		},
		"a removal's": func() ([]byte, error) { return RemoveComputeBlockDisclosure([]byte(`{}`), "Inference:engy") },
		"an unknown key": func() ([]byte, error) {
			return SetComputeBlockDisclosure([]byte(`{"compute": {"floor": "AP"}}`), "inference:engy", "YQ==")
		},
	} {
		if edited, err := edit(); !errors.Is(err, ErrAclComputeEditInvalid) || edited != nil {
			t.Errorf("%s: %s, %v", name, edited, err)
		}
	}
}

// A network's first document takes its block-alone record's block in, the block's text as the record holds it, and a
// document naming a block of its own is the person's to reconcile.
func TestComputeBlockCarryRecordKeepsItsText(t *testing.T) {
	record := []byte("{\"compute\": { /* set in March */ \"fetch\": {\"enabled\": false} }}\n")
	document := []byte(`{"grants": [], /* none yet */}`)
	carried, err := AclComputeCarryRecord(document, record)
	if err != nil {
		t.Fatal(err)
	}
	if !testComputeEditInserted(document, carried, `, "compute": { /* set in March */ "fetch": {"enabled": false} }`) {
		t.Errorf("the carried document: %s", carried)
	}
	if _, err := AclComputeCarryRecord([]byte(`{"compute": {}}`), record); !errors.Is(err, ErrAclComputeRecordBesideDocument) {
		t.Errorf("a document with its own block: %v", err)
	}
	if _, err := AclComputeCarryRecord(document, []byte(`{"compute": {}, "grants": []}`)); !errors.Is(err, ErrAclComputeEditInvalid) {
		t.Errorf("a record that is no record: %v", err)
	}
}
