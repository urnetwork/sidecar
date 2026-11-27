package sidecar

// CACL-M12-03: the compute block's compile (DESIGN-COMPUTE §16.4, §16.6): AclRows.compute_rows from the floors,
// providers, shapes, search's switch and cap and the budgets by subject atom, deterministic and sorted, against a golden;
// the keys that stay on the device off the rows; a head naming the block while compute_policy is off refused alike in
// every compile; and a network with no document's block-alone record, which sets no reach. Pure, on every leg.

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Rewrites testdata/acl_compute/'s goldens from the compile as it stands.
var testUpdateAclComputeGoldens = flag.Bool("update-acl-compute", false, "rewrite testdata/acl_compute/'s goldens")

// The golden encoding of testComputeBlockFull's compute rows in the compile test world, embedded, since the
// sidecar_http leg's Worker reads no file.
const testComputeRowsGoldenPath = "testdata/acl_compute/compute_rows.hex"

//go:embed testdata/acl_compute/compute_rows.hex
var testComputeRowsGolden string

// Holds encoded to golden, or writes it to path under -update-acl-compute.
func testAclComputeGolden(t *testing.T, path string, golden string, encoded []byte) {
	t.Helper()
	if *testUpdateAclComputeGoldens {
		if err := os.WriteFile(path, []byte(hex.EncodeToString(encoded)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if strings.TrimSpace(golden) != hex.EncodeToString(encoded) {
		t.Errorf("the rows moved from %s: %x", path, encoded)
	}
}

// A compile world holding the block's subjects' names, its document source, and compute_policy on.
func newTestComputeBlockWorld(t *testing.T, source string) *aclCompileWorld {
	t.Helper()
	world := newAclCompileWorld("compute block")
	owner := world.member("owner@example.com", bridge.MemberRole_MEMBER_ROLE_OWNER)
	world.device("phone", owner)
	world.group("interns")
	world.tag("exit")
	world.setPolicy(t, source)
	return world
}

// The world's input with compute_policy on.
func testComputeBlockInput(world *aclCompileWorld) *AclCompileInput {
	input := world.input()
	input.AuthFeatures = AuthFeatureComputePolicy
	return input
}

// The block compiles into rows: the floors, the sorted providers and shapes, search's switch and cap, and a budget row
// per subject atom; a golden holds the bytes, and the same block written in another order compiles to them.
func TestComputeBlockRowsGolden(t *testing.T) {
	world := newTestComputeBlockWorld(t, testComputeBlockFull)
	rows, err := CompileAcl(testComputeBlockInput(world))
	if err != nil {
		t.Fatal(err)
	}
	want := &protocol.AclComputeRows{
		AssuranceFloor:        protocol.ComputeAssurance_COMPUTE_ASSURANCE_AP,
		EnclaveAssuranceFloor: protocol.ComputeAssurance_COMPUTE_ASSURANCE_A1,
		Providers:             []string{"chutes", "engy"},
		EnclaveShapes:         []string{"cpu-2", "cpu-4"},
		SearchEnabled:         true,
		SearchDayMax:          2000,
		Budgets: aclSortComputeBudgets([]*protocol.AclComputeBudgetRow{
			{Subject: AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED).Bytes(), Per: uint32(AclComputeBudgetPerSubject),
				DayNanoUsd: 5_000_000_000, MonthNanoUsd: 50_000_000_000},
			{Subject: world.group("interns").Bytes(), Per: uint32(AclComputeBudgetPerMember), MonthNanoUsd: 100_500_000_000},
		}),
	}
	if !proto.Equal(rows.GetComputeRows(), want) {
		t.Errorf("the compute rows:\n%v\nwant\n%v", rows.GetComputeRows(), want)
	}
	if !rows.GetComputeRows().GetSearchEnabled() || rows.GetHasDocument() != true {
		t.Errorf("the rows: %v", rows)
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(rows.GetComputeRows())
	if err != nil {
		t.Fatal(err)
	}
	testAclComputeGolden(t, testComputeRowsGoldenPath, testComputeRowsGolden, encoded)
	// the interns' group atom is among the rows' atoms, as a rule's src would make it
	if !strings.Contains(rows.String(), "") || !testAclRowsHoldAtom(rows, world.group("interns")) {
		t.Error("the budget's group has no atom row")
	}

	// the same block in another order, a list reordered and the budgets swapped, compiles to the same bytes
	reordered := strings.NewReplacer(`["engy", "chutes"]`, `["chutes", "engy"]`, `["cpu-4", "cpu-2"]`, `["cpu-2", "cpu-4"]`).Replace(testComputeBlockFull)
	reordered = strings.Replace(reordered, `{"subjects": ["autogroup:tagged"], "per": "subject", "day_usd": 5, "month_usd": 50},
    {"subjects": ["group:interns"], "per": "member", "month_usd": 100.5},`, `{"subjects": ["group:interns"], "per": "member", "month_usd": 100.5},
    {"subjects": ["autogroup:tagged"], "per": "subject", "day_usd": 5.000, "month_usd": 50},`, 1)
	other := newTestComputeBlockWorld(t, reordered)
	otherRows, err := CompileAcl(testComputeBlockInput(other))
	if err != nil {
		t.Fatal(err)
	}
	otherEncoded, _ := proto.MarshalOptions{Deterministic: true}.Marshal(otherRows.GetComputeRows())
	if !bytes.Equal(encoded, otherEncoded) {
		t.Errorf("a reordered block compiled to other rows: %x", otherEncoded)
	}
	// a block naming nothing that reaches rows still turns search on and leaves the rest unset
	if rows, err := CompileAcl(testComputeBlockInput(newTestComputeBlockWorld(t, `{"compute": {}}`))); err != nil ||
		!proto.Equal(rows.GetComputeRows(), &protocol.AclComputeRows{SearchEnabled: true}) {
		t.Errorf("an empty block: %v, %v", rows.GetComputeRows(), err)
	}
	// with no block, compute_rows stays unset and the broker applies §16.5's defaults
	if rows, err := CompileAcl(testComputeBlockInput(newTestComputeBlockWorld(t, `{"grants": []}`))); err != nil || rows.ComputeRows != nil {
		t.Errorf("no block: %v, %v", rows.GetComputeRows(), err)
	}
}

// Whether rows hold an atom row for atomId.
func testAclRowsHoldAtom(rows *protocol.AclRows, atomId Id) bool {
	for _, atom := range rows.GetAtoms() {
		if bytes.Equal(atom.GetAtom(), atomId.Bytes()) {
			return true
		}
	}
	return false
}

// Two blocks that differ only in what stays on the device, modes, fetch, calendar, connect, support, approvals,
// disclosures and history, compile to the same rows; their local policies hold each as written.
func TestComputeBlockDeviceOnlyKeysStayOffRows(t *testing.T) {
	device := `{"compute": {"assurance_floor": "AP", "search": {"day_max": 10, "modes": ["fast"]},
  "fetch": {"enabled": false}, "calendar": {"egress": "direct"}, "connect": {"services": ["notes"], "generic": false},
  "support": {"egress": "off"}, "approvals": {"auto": []}, "disclosures": {"inference:engy": "c3RhdGVtZW50"},
  "history": {"member_share": 0.5}}}`
	plain := `{"compute": {"assurance_floor": "AP", "search": {"day_max": 10}}}`
	compiled := map[string][]byte{}
	for name, source := range map[string]string{"device": device, "plain": plain} {
		input := testComputeBlockInput(newTestComputeBlockWorld(t, source))
		rows, err := CompileAcl(input)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		compiled[name], _ = proto.MarshalOptions{Deterministic: true}.Marshal(rows)
		local, err := CompileAclLocal(input)
		if err != nil || local.Compute == nil {
			t.Fatalf("%s: the local policy %v, %v", name, local, err)
		}
		if name == "device" && (*local.Compute.Fetch.Enabled || local.Compute.History.MemberSharePpm != 500_000 ||
			len(local.Compute.Disclosures) != 1 || local.Compute.Support.Egress != "off") {
			t.Errorf("the local policy's block: %+v", local.Compute)
		}
	}
	if !bytes.Equal(compiled["device"], compiled["plain"]) {
		t.Error("a key that stays on the device changed the rows")
	}
}

// Before the network turns compute_policy on, a head whose document names the block, or that holds a block-alone record,
// compiles in no reader: rows, the local policy and the projection alike; with the feature on, both compile. A reader
// built before the block refuses its key as unknown, the same verdict.
func TestComputeBlockBeforeFeatureRefusedAlike(t *testing.T) {
	world := newTestComputeBlockWorld(t, testComputeBlockFull)
	off := world.input()
	if _, err := CompileAcl(off); !errors.Is(err, ErrAclCompile) || !strings.Contains(err.Error(), "compute_policy feature is off") {
		t.Errorf("rows before the feature: %v", err)
	}
	if _, err := CompileAclLocal(off); !errors.Is(err, ErrAclCompile) {
		t.Errorf("the local policy before the feature: %v", err)
	}
	// another feature on is no help
	off.AuthFeatures = AuthFeatureAgentRepos | AuthFeatureListeners
	if _, err := CompileAcl(off); !errors.Is(err, ErrAclCompile) {
		t.Errorf("rows under other features: %v", err)
	}
	if _, err := CompileAcl(testComputeBlockInput(world)); err != nil {
		t.Errorf("rows under the feature: %v", err)
	}

	record := newAclCompileWorld("compute record")
	recordInput := record.input()
	recordInput.ComputeRecord = []byte(`{"compute": {"assurance_floor": "A1"}}`)
	if _, err := CompileAcl(recordInput); !errors.Is(err, ErrAclCompile) || !strings.Contains(err.Error(), "compute_policy feature is off") {
		t.Errorf("a record before the feature: %v", err)
	}
	recordInput.AuthFeatures = AuthFeatureComputePolicy
	if rows, err := CompileAcl(recordInput); err != nil || rows.GetComputeRows().GetAssuranceFloor() != protocol.ComputeAssurance_COMPUTE_ASSURANCE_A1 {
		t.Errorf("a record under the feature: %v, %v", rows.GetComputeRows(), err)
	}
	// a document holding the key, read by a reader whose schema has no place for it, is refused as an unknown key: the
	// same verdict, a head that does not compile
	if _, err := ParseAclPolicy([]byte(`{"computer": {}}`)); !errors.Is(err, ErrAclPolicyInvalid) {
		t.Errorf("an unknown top-level key: %v", err)
	}
}

// A network with no document keeps its block alone: has_document stays false and the rows' rules, requests and atoms
// are the implicit document's, so the record changes no reach; a record beside a document is refused.
func TestComputeBlockNoDocumentRecord(t *testing.T) {
	world := newAclCompileWorld("compute record")
	owner := world.member("owner@example.com", bridge.MemberRole_MEMBER_ROLE_OWNER)
	world.device("phone", owner)
	implicit := world.input()
	implicit.AuthFeatures = AuthFeatureComputePolicy
	implicitRows, err := CompileAcl(implicit)
	if err != nil {
		t.Fatal(err)
	}
	recorded := world.input()
	recorded.AuthFeatures = AuthFeatureComputePolicy
	recorded.ComputeRecord = []byte(`{"compute": {"providers": ["chutes"], "budgets": [{"subjects": ["autogroup:member"], "per": "member", "day_usd": 3}]}}`)
	rows, err := CompileAcl(recorded)
	if err != nil {
		t.Fatal(err)
	}
	if rows.GetHasDocument() || rows.GetComputeRows() == nil || len(rows.GetComputeRows().GetBudgets()) != 1 {
		t.Fatalf("the record's rows: %v", rows)
	}
	withoutCompute := proto.Clone(rows).(*protocol.AclRows)
	withoutCompute.ComputeRows = nil
	if !proto.Equal(withoutCompute, implicitRows) {
		t.Error("the record changed the implicit document's reach")
	}
	local, err := CompileAclLocal(recorded)
	if err != nil || local.HasDocument || local.Compute == nil || local.Compute.Providers[0] != "chutes" {
		t.Errorf("the record's local policy: %+v, %v", local, err)
	}

	beside := newTestComputeBlockWorld(t, `{"grants": []}`)
	besideInput := testComputeBlockInput(beside)
	besideInput.ComputeRecord = []byte(`{"compute": {}}`)
	if _, err := CompileAcl(besideInput); !errors.Is(err, ErrAclCompile) || !strings.Contains(err.Error(), "beside a document") {
		t.Errorf("a record beside a document: %v", err)
	}
	broken := world.input()
	broken.AuthFeatures = AuthFeatureComputePolicy
	broken.ComputeRecord = []byte(`{"compute": {}, "grants": []}`)
	if _, err := CompileAcl(broken); !errors.Is(err, ErrAclCompile) || !errors.Is(err, ErrAclComputeRecordInvalid) {
		t.Errorf("a record holding a grant: %v", err)
	}
}

// The head knows the record's path, and a head holding it hands its bytes to the compile.
func TestComputeBlockRecordIsAHeadFile(t *testing.T) {
	if !configHeadFilePaths[ConfigHeadComputePath] || ConfigHeadComputePath != "compute.hujson" {
		t.Errorf("the head's paths: %v", configHeadFilePaths)
	}
}
