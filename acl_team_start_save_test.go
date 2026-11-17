//go:build !sidecar_http && !js && !ios_extension

// Team's starting document on the save path (ACL-M6-01; owner decision 344), on T2's fake api through TEAM's writer and
// every reader's real compile: planned under Team's limits as SaveAclTeamStart plans it, its own tests pass,
// autogroup:self#route among them, and it lands as a head the readers recompile, grant 1's via in their rows.

package sidecar_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The starting document's own tests pass on save, all six of its checks over the writer's state, and the head it
// lands holds the document, whose one route rule the reader's rows carry with its via, autogroup:self.
func TestAclTeamStartPassesItsTestsOnSave(t *testing.T) {
	world := newTestAclSaveWorld(t)
	head, version := world.head()
	start := sidecar.AclTeamStartDocument()
	// §20.4's Team column, as GET /sidecar/limits would give it
	team := &sidecar.AclLimits{Rules: 5000, Groups: 500, Requests: 500, ApproversTwo: true, NetworkShares: 500, StandingPublishes: true}
	plan, err := sidecar.PlanAclSave(world.ctx, &sidecar.AclSaveInput{
		Policy: start, Head: head, State: world.caughtUp(world.client), Limits: team, Now: world.clock.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Tests.Passed() || plan.Tests.TestCount != 2 || plan.Tests.CheckCount != 6 || plan.Tests.DocumentAlone {
		t.Fatalf("its tests on save: %+v", plan.Tests)
	}
	if _, err := sidecar.AclSave(world.ctx, world.ownerWriter, plan); err != nil {
		t.Fatal(err)
	}
	saved, savedVersion := world.head()
	if savedVersion <= version || !bytes.Equal(saved.File(sidecar.ConfigHeadPolicyPath), start) {
		t.Fatalf("the head at %d after %d holds another policy", savedVersion, version)
	}
	acl, err := world.caughtUp(world.client).Acl()
	if err != nil || !acl.HasDocument() {
		t.Fatalf("the reader's rows: %v", err)
	}
	selfAtom := sidecar.AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF).Bytes()
	routeRules := 0
	for _, rule := range acl.Rows().GetRules() {
		if !slices.Contains(rule.GetActions(), uint32(protocol.AclAction_ACL_ACTION_ROUTE)) {
			continue
		}
		routeRules += 1
		if len(rule.GetVia()) != 1 || !bytes.Equal(rule.GetVia()[0].GetAtom(), selfAtom) {
			t.Errorf("grant 1's via in the reader's rows: %v", rule.GetVia())
		}
	}
	if routeRules != 1 {
		t.Errorf("%d route rules in the reader's rows", routeRules)
	}
}
