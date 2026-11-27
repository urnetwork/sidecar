package sidecar

// CACL-M12-04: §16.2's resources and actions (DESIGN-COMPUTE §16.2, §16.6): their parse, each destination taking its
// own actions alone, their compile under their feature into rows golden-held, ssh's users and check and an enclave
// rule's shapes kept on the device, the compute_policy feature's implicit rules only once a base turns it on, and the
// frozen implicit document's golden unchanged. Pure, on every leg.

import (
	"bytes"
	_ "embed"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The golden encoding of testAclComputeDocument's rows, embedded, since the sidecar_http leg's Worker reads no file.
//
//go:embed testdata/acl_compute/resources_rows.hex
var testAclComputeResourcesGolden string

// A document naming each of §16.2's resources.
const testAclComputeDocument = `{
  "grants": [
    {"src": ["autogroup:member"], "dst": ["model:chutes-*", "model:local-*"], "allow": ["infer"]},
    {"src": ["group:builders"], "dst": ["compute:enclave"], "allow": ["create"], "shapes": ["cpu-2", "cpu-4"]},
    {"src": ["autogroup:admin"], "dst": ["compute:enclave"], "allow": ["admin"]},
    {"src": ["autogroup:member"], "dst": ["compute:search"], "allow": ["query"]},
    {"src": ["user:billing@example.com"], "dst": ["compute:buy"], "allow": ["buy"]},
    {"src": ["autogroup:member"], "dst": ["tag:enclave"], "allow": ["ssh"], "users": ["agent", "edit"], "check": "12h"},
    {"src": ["autogroup:member"], "dst": ["listener:tag:printer"], "allow": ["dial"], "ip": ["tcp:631"]},
  ],
}`

// The resources and their actions parse, each as §16.2 writes it, and print back to the same text.
func TestAclComputeResourcesParse(t *testing.T) {
	for text, want := range map[string]AclResource{
		"model:*":               {Kind: AclResourceModel, Name: "*"},
		"model:chutes-*-tee-*":  {Kind: AclResourceModel, Name: "chutes-*-tee-*"},
		"model:engy-glm-5.2":    {Kind: AclResourceModel, Name: "engy-glm-5.2"},
		"compute:enclave":       {Kind: AclResourceCompute, ComputeResource: protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_ENCLAVE},
		"compute:buy":           {Kind: AclResourceCompute, ComputeResource: protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_BUY},
		"compute:search":        {Kind: AclResourceCompute, ComputeResource: protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_SEARCH},
		"listener:*":            {Kind: AclResourceListener, Subject: AclSelector{Kind: AclSelectorAutogroup, Autogroup: protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK}},
		"listener:tag:printer":  {Kind: AclResourceListener, Subject: AclSelector{Kind: AclSelectorTag, Name: "printer"}},
		"listener:group:family": {Kind: AclResourceListener, Subject: AclSelector{Kind: AclSelectorGroup, Name: "family"}},
	} {
		resource, err := parseAclResource(text)
		if err != nil || resource != want || resource.String() != text {
			t.Errorf("%s: %+v (%s), %v", text, resource, resource.String(), err)
		}
	}
	for _, text := range []string{
		"model:", "model:Chutes-*", "model:chutes_x", "model:a*b*c*d*e*f", "model:" + strings.Repeat("a", 129),
		"compute:gpu", "compute:", "listener:network:*", "listener:client:01020304050607080910111213141516",
		"listener:autogroup:internet",
	} {
		if _, err := parseAclResource(text); !errors.Is(err, ErrAclPolicyInvalid) {
			t.Errorf("%s parsed: %v", text, err)
		}
	}
	policy, err := ParseAclPolicy([]byte(testAclComputeDocument))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(policy.Grants[1].Shapes, []string{"cpu-2", "cpu-4"}) || policy.Grants[1].Ssh != nil {
		t.Errorf("the enclave rule: %+v", policy.Grants[1])
	}
	if ssh := policy.Grants[5].Ssh; ssh == nil || !slices.Equal(ssh.Users, []string{"agent", "edit"}) || ssh.Check != 12*time.Hour {
		t.Errorf("the ssh rule: %+v", policy.Grants[5])
	}
	if !slices.Equal(policy.Grants[0].Allow, []protocol.AclAction{protocol.AclAction_ACL_ACTION_INFER}) {
		t.Errorf("infer: %v", policy.Grants[0].Allow)
	}
	// `*` stays §8.4's nine actions
	star, err := ParseAclPolicy([]byte(`{"grants": [{"src": ["autogroup:member"], "dst": ["*"], "allow": ["*"]}]}`))
	if err != nil || slices.ContainsFunc(star.Grants[0].Allow, aclComputeAction) || len(star.Grants[0].Allow) != 9 {
		t.Errorf("* reads as %v, %v", star.Grants[0].Allow, err)
	}
	for _, action := range []protocol.AclAction{protocol.AclAction_ACL_ACTION_INFER, protocol.AclAction_ACL_ACTION_SSH} {
		if aclActionName(action) == "" || AclActionName(action) == "" {
			t.Errorf("action %d has no name", action)
		}
	}
}

// A destination takes its own actions alone, and §16.2's actions stand on no other: each refusal names its place.
func TestAclComputeActionResourceMismatchRefused(t *testing.T) {
	for _, grant := range []string{
		`{"src": ["autogroup:member"], "dst": ["model:*"], "allow": ["dial"]}`,
		`{"src": ["autogroup:member"], "dst": ["model:*"], "allow": ["infer", "query"]}`,
		`{"src": ["autogroup:member"], "dst": ["compute:search"], "allow": ["infer"]}`,
		`{"src": ["autogroup:member"], "dst": ["compute:enclave"], "allow": ["buy"]}`,
		`{"src": ["autogroup:member"], "dst": ["compute:buy"], "allow": ["admin"]}`,
		`{"src": ["autogroup:member"], "dst": ["*"], "allow": ["infer"]}`,
		`{"src": ["autogroup:member"], "dst": ["evs:notes"], "allow": ["query"]}`,
		`{"src": ["autogroup:member"], "dst": ["model:*", "compute:search"], "allow": ["infer"]}`,
		`{"src": ["autogroup:member"], "dst": ["model:*", "autogroup:self"], "allow": ["infer"]}`,
		`{"src": ["autogroup:member"], "dst": ["compute:enclave", "compute:buy"], "allow": ["create"]}`,
		`{"src": ["autogroup:member"], "dst": ["listener:*"], "allow": ["route"]}`,
		`{"src": ["autogroup:member"], "dst": ["tag:enclave"], "allow": ["ssh"]}`,
		`{"src": ["autogroup:member"], "dst": ["tag:enclave"], "allow": ["ssh", "dial"], "users": ["agent"]}`,
		`{"src": ["autogroup:member"], "dst": ["sock:ssh"], "allow": ["ssh"], "users": ["agent"]}`,
		`{"src": ["autogroup:member"], "dst": ["tag:enclave"], "allow": ["ssh"], "users": ["admin"]}`,
		`{"src": ["autogroup:member"], "dst": ["tag:enclave"], "allow": ["dial"], "users": ["agent"]}`,
		`{"src": ["autogroup:member"], "dst": ["compute:search"], "allow": ["query"], "shapes": ["cpu-2"]}`,
		`{"src": ["autogroup:member"], "dst": ["tag:enclave"], "allow": ["ssh"], "users": ["agent"], "check": "0h"}`,
	} {
		if _, err := ParseAclPolicy([]byte(`{"grants": [` + grant + `]}`)); !errors.Is(err, ErrAclPolicyInvalid) || !strings.Contains(err.Error(), "grants[0]") {
			t.Errorf("%s: %v", grant, err)
		}
	}
	// a requests rule may ask for ssh with no users: the filed request names its own
	if _, err := ParseAclPolicy([]byte(`{"requests": [{"src": ["autogroup:member"], "dst": ["tag:enclave"], "allow": ["ssh"], "approver": ["autogroup:dst-owner"]}]}`)); err != nil {
		t.Errorf("an ssh request: %v", err)
	}
}

// A compile world for the document, its names in the head's tables, the features as given.
func newTestAclComputeWorld(t *testing.T, label string, source string) *aclCompileWorld {
	t.Helper()
	world := newAclCompileWorld(label)
	world.member("billing@example.com", bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN)
	world.group("builders")
	world.tag("enclave")
	world.tag("printer")
	world.setPolicy(t, source)
	return world
}

// Before their feature's base, a document naming §16.2's resources or actions compiles in no reader, rows and local
// policy alike; compute_policy does not turn listener: on, nor listeners model:.
func TestAclComputeResourcesBeforeFeatureRefusedAlike(t *testing.T) {
	for source, feature := range map[string]AuthFeature{
		`{"grants": [{"src": ["autogroup:member"], "dst": ["model:*"], "allow": ["infer"]}]}`:                       AuthFeatureComputePolicy,
		`{"grants": [{"src": ["autogroup:member"], "dst": ["compute:search"], "allow": ["query"]}]}`:                AuthFeatureComputePolicy,
		`{"grants": [{"src": ["autogroup:member"], "dst": ["tag:enclave"], "allow": ["ssh"], "users": ["agent"]}]}`: AuthFeatureComputePolicy,
		`{"requests": [{"src": ["autogroup:member"], "dst": ["compute:buy"], "allow": ["buy"]}]}`:                   AuthFeatureComputePolicy,
		`{"grants": [{"src": ["autogroup:member"], "dst": ["listener:*"], "allow": ["dial"]}]}`:                     AuthFeatureListeners,
	} {
		world := newTestAclComputeWorld(t, "before "+source, source)
		input := world.input()
		for _, features := range []AuthFeature{0, authFeaturesKnown &^ feature} {
			input.AuthFeatures = features
			if _, err := CompileAcl(input); !errors.Is(err, ErrAclCompile) || !strings.Contains(err.Error(), "feature is off") {
				t.Errorf("%s under %s: %v", source, features, err)
			}
			if _, err := CompileAclLocal(input); !errors.Is(err, ErrAclCompile) {
				t.Errorf("%s's local policy under %s: %v", source, features, err)
			}
		}
		input.AuthFeatures = feature
		if _, err := CompileAcl(input); err != nil {
			t.Errorf("%s under %s: %v", source, feature, err)
		}
	}
}

// The document's rows: model_glob, compute_resource and listener targets with their actions, held to a golden; ssh
// rows name their subjects; and what rows drop stays on the device: ssh's users and check, the enclave rule's shapes,
// the listener grant's ports.
func TestAclComputeRowsGolden(t *testing.T) {
	world := newTestAclComputeWorld(t, "compute rows", testAclComputeDocument)
	input := world.input()
	input.AuthFeatures = AuthFeatureComputePolicy | AuthFeatureListeners
	rows, err := CompileAcl(input)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, rule := range rows.GetRules() {
		for _, target := range rule.GetTargets() {
			switch {
			case target.GetModelGlob() != "":
				found["model:"+target.GetModelGlob()] = slices.Equal(rule.GetActions(), []uint32{uint32(protocol.AclAction_ACL_ACTION_INFER)})
			case target.GetComputeResource() != 0:
				found["compute:"+aclComputeResourceName(target.GetComputeResource())] = true
			case len(target.GetListener()) != 0:
				found["listener"] = bytes.Equal(target.GetListener(), world.tag("printer").Bytes())
			case bytes.Equal(target.GetAtom(), world.tag("enclave").Bytes()):
				found["ssh"] = slices.Equal(rule.GetActions(), []uint32{uint32(protocol.AclAction_ACL_ACTION_SSH)})
			}
		}
	}
	for _, name := range []string{"model:chutes-*", "model:local-*", "compute:enclave", "compute:search", "compute:buy", "listener", "ssh"} {
		if !found[name] {
			t.Errorf("no row for %s: %v", name, found)
		}
	}
	testAclComputeGolden(t, "testdata/acl_compute/resources_rows.hex", testAclComputeResourcesGolden, aclEncodeRows(t, rows))
	if again, _ := CompileAcl(input); !proto.Equal(again, rows) {
		t.Error("a second compile gave other rows")
	}
}

// ssh's users and check period, an enclave rule's shapes and a listener grant's ports enter no row, which hold only
// their subjects and actions; the device's local policy holds them, and a change to them alone makes a new rule.
func TestAclComputeSshUsersStayLocal(t *testing.T) {
	compile := func(source string) (*protocol.AclRows, *AclLocalPolicy) {
		world := newTestAclComputeWorld(t, "ssh local", source)
		input := world.input()
		input.AuthFeatures = AuthFeatureComputePolicy | AuthFeatureListeners
		rows, err := CompileAcl(input)
		if err != nil {
			t.Fatal(err)
		}
		local, err := CompileAclLocal(input)
		if err != nil {
			t.Fatal(err)
		}
		return rows, local
	}
	rows, local := compile(testAclComputeDocument)
	if strings.Contains(rows.String(), "edit") || strings.Contains(rows.String(), "cpu-2") {
		t.Error("an ssh user or a shape reached the rows")
	}
	var ssh *AclLocalSsh
	var shapes []string
	var ports []AclPortRange
	for _, rule := range local.Rules {
		if rule.Ssh != nil {
			ssh = rule.Ssh
		}
		if rule.Shapes != nil {
			shapes = rule.Shapes
		}
		if rule.Ports != nil {
			ports = rule.Ports
		}
	}
	if ssh == nil || !slices.Equal(ssh.Users, []string{"agent", "edit"}) || ssh.Check != 12*time.Hour {
		t.Errorf("the local ssh: %+v", ssh)
	}
	if !slices.Equal(shapes, []string{"cpu-2", "cpu-4"}) || len(ports) != 1 || ports[0].First != 631 {
		t.Errorf("the local shapes %v and ports %v", shapes, ports)
	}
	// a change of users alone is a new rule: its canonical form holds them
	other := strings.Replace(testAclComputeDocument, `"users": ["agent", "edit"]`, `"users": ["agent"]`, 1)
	otherRows, _ := compile(other)
	if slices.EqualFunc(rows.GetRules(), otherRows.GetRules(), func(a *protocol.AclRule, b *protocol.AclRule) bool {
		return bytes.Equal(a.GetRuleId(), b.GetRuleId())
	}) {
		t.Error("a change of users kept every rule id")
	}
}

// The compute_policy feature's implicit rules compile into a network with no document only once its base turns the
// feature on, with ids from the feature rules' domain; before it, the rows are the frozen implicit document's alone.
func TestAclComputeImplicitRulesOnlyAfterBase(t *testing.T) {
	world := newAclCompileWorld("compute implicit")
	before := world.input()
	beforeRows, err := CompileAcl(before)
	if err != nil {
		t.Fatal(err)
	}
	after := world.input()
	after.AuthFeatures = AuthFeatureComputePolicy
	afterRows, err := CompileAcl(after)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterRows.GetRules()) != len(beforeRows.GetRules())+2 {
		t.Fatalf("%d rules before the base, %d after", len(beforeRows.GetRules()), len(afterRows.GetRules()))
	}
	for index, want := range map[uint32]string{0: "model:*", 1: "compute:search"} {
		ruleId := aclImplicitFeatureRuleId(AuthFeatureComputePolicy, index).Bytes()
		ruleIndex := slices.IndexFunc(afterRows.GetRules(), func(rule *protocol.AclRule) bool { return bytes.Equal(rule.GetRuleId(), ruleId) })
		if ruleIndex < 0 {
			t.Fatalf("no implicit rule %d", index)
		}
		target := afterRows.GetRules()[ruleIndex].GetTargets()[0]
		if (want == "model:*") != (target.GetModelGlob() == "*") {
			t.Errorf("implicit rule %d's target: %v", index, target)
		}
	}
	if slices.ContainsFunc(beforeRows.GetRules(), func(rule *protocol.AclRule) bool {
		return slices.ContainsFunc(rule.GetTargets(), func(target *protocol.AclTarget) bool { return target.GetModelGlob() != "" })
	}) {
		t.Error("a model rule before the base")
	}
	if !slices.ContainsFunc(authFeatureRegistrations, func(registration *authFeatureRegistration) bool {
		return registration.feature == AuthFeatureComputePolicy && registration.fragment != nil
	}) || AuthFeaturesImplemented()&AuthFeatureComputePolicy == 0 {
		t.Error("compute_policy is not registered as implemented with its fragment")
	}
	// Team's starting document carries the same two rules in its compute_policy block, and nothing else of it moves
	team := AclTeamStartDocumentFor(AuthFeatureComputePolicy)
	plain := AclTeamStartDocumentFor(0)
	teamPolicy, err := ParseAclPolicy(team)
	if err != nil {
		t.Fatal(err)
	}
	plainPolicy, err := ParseAclPolicy(plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(teamPolicy.Grants) != len(plainPolicy.Grants)+2 || !bytes.Contains(team, []byte(`"model:*"`)) || bytes.Contains(plain, []byte("model:")) {
		t.Errorf("Team's starting document under compute_policy: %d grants, %d without", len(teamPolicy.Grants), len(plainPolicy.Grants))
	}
	// a document names its own rules: the fragment adds none
	documented := newTestAclComputeWorld(t, "compute documented", `{"grants": []}`)
	input := documented.input()
	input.AuthFeatures = AuthFeatureComputePolicy
	if rows, err := CompileAcl(input); err != nil || 0 < len(rows.GetRules()) {
		t.Errorf("a document's rows under the feature: %v, %v", rows.GetRules(), err)
	}
}

// The frozen implicit document compiles to its golden, unmoved by §16.2's actions and the compute fragment.
func TestAclImplicitGoldenUnchanged(t *testing.T) {
	rows := newAclCompileWorld("implicit").compile(t)
	golden, err := testAclVectorFiles.ReadFile("testdata/acl/vectors/implicit_rows.hex")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(aclEncodeRows(t, rows)); got != strings.TrimSpace(string(golden)) {
		t.Fatal("the implicit document compiles to other rows")
	}
	for _, rule := range rows.GetRules() {
		if slices.ContainsFunc(rule.GetActions(), func(action uint32) bool { return aclComputeAction(protocol.AclAction(action)) }) {
			t.Errorf("an implicit rule takes one of §16.2's actions: %v", rule.GetActions())
		}
	}
}
