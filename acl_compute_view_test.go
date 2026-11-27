//go:build !ios_extension && !sidecar_http && !js

package sidecar

// CACL-M12-03: ComputePolicyView (DESIGN-COMPUTE §16.4, §16.5): §16.5's defaults where a network has no block or its
// block leaves a key out, each key as a block sets it, the network's floor and providers in ComputeModelGate, and a
// device that has not read its head answering ErrComputePolicyUnread rather than the defaults. Synthetic values only.

import (
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// With no block, and with a block naming nothing, every read is §16.5's default.
func TestComputePolicyViewDefaults(t *testing.T) {
	for name, view := range map[string]*ComputePolicyView{
		"no block":    NewComputePolicyView(nil, true),
		"empty block": NewComputePolicyView(testComputeBlockParsed(t, `{"compute": {}}`), true),
	} {
		models := view.NetworkModels()
		if models.Floor != ComputeLabelNone || !slices.Equal(models.Providers, []string{"*"}) {
			t.Errorf("%s: the models %+v", name, models)
		}
		if view.EnclaveFloor() != ComputeLabelAp || view.EnclaveShapes() != nil || !view.AllowsEnclaveShape("gpu-1") {
			t.Errorf("%s: the enclaves", name)
		}
		if search := view.Search(); !search.Enabled || search.Modes != nil || search.DayMax != 0 || !view.AllowsSearchMode("advanced") {
			t.Errorf("%s: search %+v", name, search)
		}
		for _, route := range []*ComputeRoutePolicy{view.Fetch(), view.Calendar(), &view.Connect().ComputeRoutePolicy} {
			if !route.Enabled || route.Egress != AclComputeEgressAuto || route.Exit != "" {
				t.Errorf("%s: a route %+v", name, route)
			}
		}
		if connect := view.Connect(); connect.Services != nil || !connect.Generic || !connect.Custom || !view.AllowsService("notes") {
			t.Errorf("%s: connect %+v", name, connect)
		}
		if support := view.Support(); support.Egress != "on" || !support.Agents || !support.Logs {
			t.Errorf("%s: support %+v", name, support)
		}
		if !slices.Equal(view.ApprovalsAuto(), []SidecarActionKind{23, 24, 25, 26, 27}) || !view.ApprovalAutoAllowed(SidecarActionSupportSend) {
			t.Errorf("%s: approvals %v", name, view.ApprovalsAuto())
		}
		if len(view.Disclosures()) != 0 || len(view.Budgets()) != 0 {
			t.Errorf("%s: disclosures or budgets", name)
		}
		if share := view.MemberShare(); !share.Auto {
			t.Errorf("%s: the share %+v", name, share)
		}
	}
}

// A full block reads as written, each narrowing kept.
func TestComputePolicyViewReadsTheBlock(t *testing.T) {
	view := NewComputePolicyView(testComputeBlockParsed(t, testComputeBlockFull), true)
	if models := view.NetworkModels(); models.Floor != ComputeLabelAp || !slices.Equal(models.Providers, []string{"engy", "chutes"}) {
		t.Errorf("the models %+v", models)
	}
	if view.EnclaveFloor() != ComputeLabelA1 || view.AllowsEnclaveShape("gpu-1") || !view.AllowsEnclaveShape("cpu-2") {
		t.Error("the enclaves")
	}
	if !view.AllowsSearchMode("fast") || view.AllowsSearchMode("advanced") || view.Search().DayMax != 2000 {
		t.Errorf("search %+v", view.Search())
	}
	if fetch := view.Fetch(); fetch.Egress != AclComputeEgressExits || fetch.Exit != "tag:exit" {
		t.Errorf("fetch %+v", fetch)
	}
	if calendar := view.Calendar(); calendar.Enabled || calendar.Egress != AclComputeEgressDirect {
		t.Errorf("calendar %+v", calendar)
	}
	if connect := view.Connect(); connect.Generic || !view.AllowsService("google-calendar") || view.AllowsService("notes") {
		t.Errorf("connect %+v", connect)
	}
	if support := view.Support(); support.Egress != "persons" || support.Logs {
		t.Errorf("support %+v", support)
	}
	if view.ApprovalAutoAllowed(SidecarActionTaintedSend) || !view.ApprovalAutoAllowed(SidecarActionServiceWrite) {
		t.Errorf("approvals %v", view.ApprovalsAuto())
	}
	if statement, ok := view.Disclosure("inference:engy"); !ok || statement != "c3RhdGVtZW50" {
		t.Errorf("the disclosure %q", statement)
	}
	if share := view.MemberShare(); share.Auto || share.Fraction != 0.25 {
		t.Errorf("the share %+v", share)
	}
	if !view.FeatureOn() || len(view.Budgets()) != 2 {
		t.Error("the feature or budgets")
	}
}

// The network's floor and providers reach ComputeModelGate through the view: below the floor or outside the providers
// refused by its rule, a local model passing both (CO-9).
func TestComputeModelGateNetworkFloorAndProviders(t *testing.T) {
	view := NewComputePolicyView(testComputeBlockParsed(t, `{"compute": {"assurance_floor": "A1", "providers": ["chutes"]}}`), true)
	gate := NewComputeModelGate(view.NetworkModels(), nil, nil)
	refusedBy := func(name string, label ComputeLabel) ComputeModelRule {
		var refused *ComputeModelRefusedError
		if err := gate.Allows(name, label); errors.As(err, &refused) {
			return refused.Rule
		} else if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return ""
	}
	for _, item := range []struct {
		name  string
		label ComputeLabel
		rule  ComputeModelRule
	}{
		{name: "chutes-qwen3.8-27b-tee-high", label: ComputeLabelA1},
		{name: "chutes-qwen3.8-27b-tee-high", label: ComputeLabelA2},
		{name: "chutes-kimi-k3-tee-high", label: ComputeLabelAp, rule: ComputeModelRuleFloor},
		{name: "engy-glm-5.2-high", label: ComputeLabelA1, rule: ComputeModelRuleProvider},
		{name: "engy-glm-5.2-high", label: ComputeLabelNone, rule: ComputeModelRuleFloor},
		{name: "local-gemma-4-e4b-off", label: ComputeLabelLocal},
	} {
		if rule := refusedBy(item.name, item.label); rule != item.rule {
			t.Errorf("%s at %s refused by %q, want %q", item.name, item.label, rule, item.rule)
		}
	}
	// the defaults admit every label and provider (CO-18)
	open := NewComputeModelGate(NewComputePolicyView(nil, true).NetworkModels(), nil, nil)
	if err := open.Allows("engy-glm-5.2-high", ComputeLabelNone); err != nil {
		t.Errorf("the defaults refused a none model: %v", err)
	}
}

// A device that has read no head answers ErrComputePolicyUnread, and the router's source with it, never the defaults.
func TestComputePolicyUnreadFailsClosed(t *testing.T) {
	sidecar, _, _ := newIdentityTestSidecar(t)
	if _, err := sidecar.ComputePolicy(); !errors.Is(err, ErrComputePolicyUnread) {
		t.Errorf("a sidecar with no follower: %v", err)
	}
	source := &sidecarComputeBlockSource{sidecar: sidecar}
	if models, err := source.ComputeNetworkModels(t.Context()); !errors.Is(err, ErrComputePolicyUnread) || models != nil {
		t.Errorf("the router's source: %v, %v", models, err)
	}
	if !slices.ContainsFunc(inferCheckSourcesRegistrations, func(registration *inferCheckSourcesRegistration) bool {
		return registration.name == "cacl-compute-block"
	}) {
		t.Error("the compute block is not among the router's sources")
	}
}

// A model: grant never passes the floor (R1-56): a glob naming SayGM's -tee names grants them by their name, while the
// network's floor of AP refuses them at their label, none, in ComputeModelGate, which holds every remote call apart.
func TestAclComputeModelGrantNeverPassesTheFloor(t *testing.T) {
	world := newAclCompileWorld("glob floor")
	owner := world.member("owner@example.com", bridge.MemberRole_MEMBER_ROLE_OWNER)
	laptop := world.device("laptop", owner)
	world.setPolicy(t, `{"grants": [{"src": ["autogroup:member"], "dst": ["model:*-tee-*"], "allow": ["infer"]}], "compute": {"assurance_floor": "AP"}}`)
	input := world.input()
	input.AuthFeatures = AuthFeatureComputePolicy
	rows, err := CompileAcl(input)
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewAclState(rows, world.view())
	if err != nil {
		t.Fatal(err)
	}
	name := "saygm-llama-4-tee-high"
	if decision := state.ComputeAllows(AclSidecarSubject(laptop), AclComputeTarget{Model: name}, protocol.AclAction_ACL_ACTION_INFER, aclTestNow); !decision.Allowed {
		t.Fatalf("the glob does not grant %s", name)
	}
	local, err := CompileAclLocal(input)
	if err != nil {
		t.Fatal(err)
	}
	gate := NewComputeModelGate(NewComputePolicyView(local.Compute, true).NetworkModels(), nil, nil)
	var refused *ComputeModelRefusedError
	if err := gate.Allows(name, ComputeLabelNone); !errors.As(err, &refused) || refused.Rule != ComputeModelRuleFloor {
		t.Errorf("the floor let %s's grant through: %v", name, err)
	}
	if err := gate.Allows("chutes-qwen3.8-27b-tee-high", ComputeLabelA1); err != nil {
		t.Errorf("a TEE model above the floor: %v", err)
	}
}
