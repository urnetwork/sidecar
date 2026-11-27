package sidecar

// CACL-M12-04: §16.2's evaluation (DESIGN-COMPUTE §16.2, §16.5): subjects by resources by actions, in a personal network
// under the compute_policy feature's implicit rules and in a Team under its document; a model: grant matching names,
// never labels; a hard-denied subject taking nothing. Pure, on every leg.

import (
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The state of world's rows under features.
func testAclComputeState(t *testing.T, world *aclCompileWorld, features AuthFeature) *AclState {
	t.Helper()
	input := world.input()
	input.AuthFeatures = features
	rows, err := CompileAcl(input)
	if err != nil {
		t.Fatal(err)
	}
	state, err := NewAclState(rows, world.view())
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// One check of the matrix.
type testAclComputeCheck struct {
	name    string
	subject Id
	target  AclComputeTarget
	action  protocol.AclAction
	allowed bool
}

// Runs each check against state.
func testAclComputeChecks(t *testing.T, label string, state *AclState, checks []testAclComputeCheck) {
	t.Helper()
	for _, check := range checks {
		decision := state.ComputeAllows(AclSidecarSubject(check.subject), check.target, check.action, aclTestNow)
		if decision.Allowed != check.allowed {
			t.Errorf("%s: %s allowed %v (%s)", label, check.name, decision.Allowed, decision.Reason)
		}
	}
}

// The matrix: in a personal network with no document, once compute_policy is on, every member device infers on any
// remote model and searches, and no one buys, creates or sshes by a rule (their defaults are roles' and the enclaves
// feature's); before the feature, nothing; in a Team, what its document grants, to whom it grants it.
func TestAclComputeEvalMatrix(t *testing.T) {
	enclaveSearch := AclComputeTarget{Resource: protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_SEARCH}
	buy := AclComputeTarget{Resource: protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_BUY}
	enclave := AclComputeTarget{Resource: protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_ENCLAVE}
	model := func(name string) AclComputeTarget { return AclComputeTarget{Model: name} }

	personal := newAclCompileWorld("compute personal")
	owner := personal.member("owner@example.com", bridge.MemberRole_MEMBER_ROLE_OWNER)
	laptop := personal.device("laptop", owner)
	worker := personal.agent("worker", owner, "ci")
	personalChecks := []testAclComputeCheck{
		{name: "a member device infers on a TEE model", subject: laptop, target: model("chutes-qwen3.8-27b-tee-high"), action: protocol.AclAction_ACL_ACTION_INFER, allowed: true},
		{name: "a member device infers on a none model", subject: laptop, target: model("engy-glm-5.2-high"), action: protocol.AclAction_ACL_ACTION_INFER, allowed: true},
		{name: "a member device searches", subject: laptop, target: enclaveSearch, action: protocol.AclAction_ACL_ACTION_QUERY, allowed: true},
		{name: "a member device buys by no rule", subject: laptop, target: buy, action: protocol.AclAction_ACL_ACTION_BUY},
		{name: "a member device creates an enclave by no rule", subject: laptop, target: enclave, action: protocol.AclAction_ACL_ACTION_CREATE},
		{name: "a tagged sidecar infers", subject: worker, target: model("chutes-qwen3.8-27b-tee-high"), action: protocol.AclAction_ACL_ACTION_INFER},
		{name: "a tagged sidecar searches", subject: worker, target: enclaveSearch, action: protocol.AclAction_ACL_ACTION_QUERY},
		{name: "infer with no model", subject: laptop, target: AclComputeTarget{}, action: protocol.AclAction_ACL_ACTION_INFER},
		{name: "dial is no compute action", subject: laptop, target: enclaveSearch, action: protocol.AclAction_ACL_ACTION_DIAL},
	}
	testAclComputeChecks(t, "personal", testAclComputeState(t, personal, AuthFeatureComputePolicy), personalChecks)
	before := testAclComputeState(t, personal, 0)
	for _, check := range personalChecks {
		if decision := before.ComputeAllows(AclSidecarSubject(check.subject), check.target, check.action, aclTestNow); decision.Allowed {
			t.Errorf("before the feature: %s allowed", check.name)
		}
	}

	team := newAclCompileWorld("compute team")
	teamOwner := team.member("owner@example.com", bridge.MemberRole_MEMBER_ROLE_OWNER)
	billing := team.member("billing@example.com", bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN)
	builder := team.member("builder@example.com", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	other := team.member("other@example.com", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	ownerLaptop := team.device("owner laptop", teamOwner)
	billingLaptop := team.device("billing laptop", billing)
	builderLaptop := team.device("builder laptop", builder)
	otherLaptop := team.device("other laptop", other)
	enclaveIncarnation := team.agent("enclave incarnation", builder, "enclave")
	team.tag("printer")
	source := strings.Replace(testAclComputeDocument, `"group:builders"`, `"user:builder@example.com"`, 1)
	team.setPolicy(t, source)
	teamState := testAclComputeState(t, team, AuthFeatureComputePolicy|AuthFeatureListeners)
	sshTo := func(subject Id) AclComputeTarget { return AclComputeTarget{Subject: AclSidecarSubject(subject)} }
	testAclComputeChecks(t, "team", teamState, []testAclComputeCheck{
		{name: "a member infers on a chutes model", subject: otherLaptop, target: model("chutes-kimi-k3-tee-high"), action: protocol.AclAction_ACL_ACTION_INFER, allowed: true},
		{name: "a member infers on a local model's name", subject: otherLaptop, target: model("local-gemma-4-e4b-off"), action: protocol.AclAction_ACL_ACTION_INFER, allowed: true},
		{name: "a member infers on an engy model the globs do not match", subject: otherLaptop, target: model("engy-glm-5.2-high"), action: protocol.AclAction_ACL_ACTION_INFER},
		{name: "the builder creates an enclave", subject: builderLaptop, target: enclave, action: protocol.AclAction_ACL_ACTION_CREATE, allowed: true},
		{name: "another member creates no enclave", subject: otherLaptop, target: enclave, action: protocol.AclAction_ACL_ACTION_CREATE},
		{name: "the builder administers no enclave", subject: builderLaptop, target: enclave, action: protocol.AclAction_ACL_ACTION_ADMIN},
		{name: "the owner administers enclaves", subject: ownerLaptop, target: enclave, action: protocol.AclAction_ACL_ACTION_ADMIN, allowed: true},
		{name: "the billing admin buys", subject: billingLaptop, target: buy, action: protocol.AclAction_ACL_ACTION_BUY, allowed: true},
		{name: "a member buys by no rule", subject: otherLaptop, target: buy, action: protocol.AclAction_ACL_ACTION_BUY},
		{name: "a member searches", subject: otherLaptop, target: enclaveSearch, action: protocol.AclAction_ACL_ACTION_QUERY, allowed: true},
		{name: "a member sshes into the enclave", subject: otherLaptop, target: sshTo(enclaveIncarnation), action: protocol.AclAction_ACL_ACTION_SSH, allowed: true},
		{name: "no one sshes into a laptop", subject: otherLaptop, target: sshTo(builderLaptop), action: protocol.AclAction_ACL_ACTION_SSH},
		{name: "ssh names its destination", subject: otherLaptop, target: AclComputeTarget{}, action: protocol.AclAction_ACL_ACTION_SSH},
		{name: "the enclave infers by no rule", subject: enclaveIncarnation, target: model("chutes-kimi-k3-tee-high"), action: protocol.AclAction_ACL_ACTION_INFER},
	})
	// a revoked device takes nothing
	for _, row := range team.sidecars {
		if Id(row.GetSidecarId()) == otherLaptop {
			row.RevokedAt = team.position
		}
	}
	revoked := testAclComputeState(t, team, AuthFeatureComputePolicy|AuthFeatureListeners)
	if decision := revoked.ComputeAllows(AclSidecarSubject(otherLaptop), model("chutes-kimi-k3-tee-high"), protocol.AclAction_ACL_ACTION_INFER, aclTestNow); decision.Allowed || decision.Reason != AclReasonRevoked {
		t.Errorf("a revoked device: %v, %s", decision.Allowed, decision.Reason)
	}
}

// A model: glob matches canonical names and never labels: a glob naming a word of a name matches that name whatever
// its label, so tee in a name promises nothing, and the grant never passes the floor, which ComputeModelGate holds.
func TestAclComputeModelGlobNotALabel(t *testing.T) {
	for glob, names := range map[string]map[string]bool{
		"*":                 {"chutes-qwen3.8-27b-tee-high": true, "local-gemma-4-e4b-off": true},
		"chutes-*":          {"chutes-qwen3.8-27b-tee-high": true, "engy-chutes-x-high": false},
		"*-tee-*":           {"saygm-llama-4-tee-high": true, "chutes-qwen3.8-27b-high": false},
		"engy-glm-5.2-high": {"engy-glm-5.2-high": true, "engy-glm-5.2-low": false},
	} {
		for name, want := range names {
			if AclComputeModelGlobMatch(glob, name) != want {
				t.Errorf("%s matching %s: %v", glob, name, !want)
			}
		}
	}
	for _, label := range []string{"AP", "A1", "A2", "tee_only"} {
		if aclComputeModelGlob(label, DefaultAclComputeBlockSettings()) {
			t.Errorf("the label %s reads as a glob", label)
		}
	}
	// SayGM's -tee name is labeled none: the glob grants it by its name, and only the floor, ComputeModelGate's, holds
	// it to its label (acl_compute_view_test.go's TestAclComputeModelGrantNeverPassesTheFloor)
	world := newAclCompileWorld("glob label")
	owner := world.member("owner@example.com", bridge.MemberRole_MEMBER_ROLE_OWNER)
	laptop := world.device("laptop", owner)
	world.setPolicy(t, `{"grants": [{"src": ["autogroup:member"], "dst": ["model:*-tee-*"], "allow": ["infer"]}]}`)
	state := testAclComputeState(t, world, AuthFeatureComputePolicy)
	for name, want := range map[string]bool{"saygm-llama-4-tee-high": true, "chutes-qwen3.8-27b-high": false} {
		if decision := state.ComputeAllows(AclSidecarSubject(laptop), AclComputeTarget{Model: name}, protocol.AclAction_ACL_ACTION_INFER, aclTestNow); decision.Allowed != want {
			t.Errorf("the glob granting %s: %v", name, decision.Allowed)
		}
	}
}
