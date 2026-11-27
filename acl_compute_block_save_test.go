//go:build !sidecar_http && !js

// CACL-M12-03's block-alone record saved through TEAM's writer on T2's fake api, every reader recompiling the head with
// CompileAcl: the record lands as a head the readers take, its rows carrying the block with has_document false; a
// network with a document saves no record; a record that does not parse, or a head the writer moved past, is refused.

package sidecar_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A record saved on the owner's writer lands: the readers' rows hold its floor, the implicit document stays in force,
// and the head holds the record's bytes as written.
func TestComputeRecordSaveLands(t *testing.T) {
	world := newTestAclSaveWorld(t)
	state := world.caughtUp(world.client)
	if !state.AuthFeatureOn(sidecar.AuthFeatureComputePolicy) {
		t.Fatal("a network this release bootstraps does not turn compute_policy on")
	}
	head, _ := world.head()
	source := []byte("// the network's compute block\n{\"compute\": {\"assurance_floor\": \"A1\", \"fetch\": {\"enabled\": false}}}\n")
	if _, err := sidecar.AclComputeRecordSave(world.ctx, world.ownerWriter, head, state, source, nil); err != nil {
		t.Fatal(err)
	}
	saved, _ := world.head()
	if string(saved.File(sidecar.ConfigHeadComputePath)) != string(source) || saved.File(sidecar.ConfigHeadPolicyPath) != nil {
		t.Fatalf("the head's record: %q", saved.File(sidecar.ConfigHeadComputePath))
	}
	after := world.caughtUp(world.client)
	acl, err := after.Acl()
	if err != nil {
		t.Fatal(err)
	}
	if acl.HasDocument() {
		t.Error("the record set has_document")
	}
	if floor := acl.ComputeRows().GetAssuranceFloor(); floor != protocol.ComputeAssurance_COMPUTE_ASSURANCE_A1 {
		t.Errorf("the readers' floor: %v", floor)
	}

	// a record that does not parse, or names what the head's tables do not hold, saves nothing
	for _, bad := range []string{`{"compute": {"floor": "A1"}}`, `{"compute": {}, "grants": []}`,
		`{"compute": {"budgets": [{"subjects": ["tag:nowhere"], "per": "subject", "day_usd": 1}]}}`} {
		if _, err := sidecar.AclComputeRecordSave(world.ctx, world.ownerWriter, saved, after, []byte(bad), nil); err == nil {
			t.Errorf("%s was saved", bad)
		}
	}
	// the network's first document takes the record's block in, its text unchanged, and the head drops the record
	plan := world.plan(testAclSavePolicyB)
	if !strings.Contains(string(plan.Head.File(sidecar.ConfigHeadPolicyPath)), `"compute": {"assurance_floor": "A1", "fetch": {"enabled": false}}`) ||
		plan.Head.File(sidecar.ConfigHeadComputePath) != nil {
		t.Fatalf("the first document's plan:\n%s", plan.Head.File(sidecar.ConfigHeadPolicyPath))
	}
	if _, err := sidecar.AclSave(world.ctx, world.ownerWriter, plan); err != nil {
		t.Fatal(err)
	}
	documented, _ := world.head()
	if documented.File(sidecar.ConfigHeadComputePath) != nil {
		t.Error("the record stands beside the document")
	}
	documentedState := world.caughtUp(world.client)
	if acl, err := documentedState.Acl(); err != nil || !acl.HasDocument() || acl.ComputeRows().GetAssuranceFloor() != protocol.ComputeAssurance_COMPUTE_ASSURANCE_A1 {
		t.Errorf("the document's rows: %v", err)
	}
	// and a network with a document keeps its block there, never in a record
	if _, err := sidecar.PlanAclComputeRecordSave(documented, documentedState, source); !errors.Is(err, sidecar.ErrAclComputeRecordBesideDocument) {
		t.Errorf("a record beside a document: %v", err)
	}
}
