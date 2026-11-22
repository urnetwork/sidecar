//go:build !sidecar_http && !ios_extension

// QD-1164's ip: tests against a surviving activated route grant (acl_tests.go's activated grants row): a grant whose
// sealed detail opens is judged by its prefixes and ports, one whose detail does not open establishes no accept and
// fails a deny it may apply to as indeterminate, naming the grant by id and the test by index, and one whose action
// seals no detail reaches nothing, as the bridge compile and AclEngine read it. The details open through the writer's
// own state and config keys (aclStateGrantDetails) and through PlanAclSave at the verified base a save stands on.
// Synthetic values only.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A test's opener: each grant's detail, or the error it answers, by grant id, an id it holds neither for answering as
// a state holding no action for the grant does. Safe for concurrent use.
type testAclGrantDetails struct {
	details map[string]*protocol.CanonicalActionDetail
	errs    map[string]error

	stateLock sync.Mutex
	opened    []string
}

func (self *testAclGrantDetails) GrantDetail(grantId []byte) (*protocol.CanonicalActionDetail, error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.opened = append(self.opened, string(grantId))
	}()
	if err := self.errs[string(grantId)]; err != nil {
		return nil, err
	}
	detail, found := self.details[string(grantId)]
	if !found {
		return nil, ErrAclGrantActionNotHeld
	}
	return proto.Clone(detail).(*protocol.CanonicalActionDetail), nil
}

// The grant ids asked so far, in the order asked.
func (self *testAclGrantDetails) asked() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.opened)
}

// A world whose log activated a route grant for dana's laptop through amir's, its requests rule the document's
// first: the grant's id, dana's laptop and amir's.
type aclTestsGrantWorld struct {
	*aclTestsWorld
	grantId []byte
	dana    Id
	amir    Id
}

// The document's requests rule takes a member's route to another member; the grant limits ports where sealed, as every
// GrantActivate carrying a sealed_detail folds.
const aclTestsGrantRequests = `"requests": [
    { "src": ["autogroup:member"], "dst": ["autogroup:member"], "allow": ["route"], "approver": ["autogroup:admin"], "maxExpiry": "7d" },
  ]`

// The sidecar ids newAclTestsWorld admits for dana's and amir's laptops, which a document's tests name.
func aclTestsGrantLaptops() (Id, Id) {
	ids := newAclCompileWorld("laptops")
	return ids.id("sidecar dana laptop"), ids.id("sidecar amir laptop")
}

// The world over document, which holds aclTestsGrantRequests, the grant sealing a detail where sealed says.
func newAclTestsGrantWorld(t *testing.T, document string, sealed bool) *aclTestsGrantWorld {
	t.Helper()
	world := &aclTestsGrantWorld{aclTestsWorld: newAclTestsWorld(t, document)}
	compile := world.world
	world.dana, world.amir = aclTestsGrantLaptops()
	world.grantId = compile.key("activated route grant")
	danaAtom := AclDerivedAtom(AclDerivedAtomSidecar, world.dana.Bytes())
	compile.statements.Atoms = append(compile.statements.Atoms, &protocol.AclAtom{Atom: danaAtom.Bytes(), SidecarIds: [][]byte{world.dana.Bytes()}})
	target := &protocol.AclTarget{SidecarId: world.amir.Bytes()}
	compile.statements.Rules = append(compile.statements.Rules, &protocol.AclRule{
		RuleId:       bytes.Clone(world.grantId),
		SrcAtoms:     [][]byte{danaAtom.Bytes()},
		Targets:      []*protocol.AclTarget{target},
		Via:          []*protocol.AclTarget{proto.Clone(target).(*protocol.AclTarget)},
		Actions:      []uint32{uint32(protocol.AclAction_ACL_ACTION_ROUTE)},
		PortsLimited: sealed,
		Expires:      compile.headTimeMs + 60*60*1000,
		SourceRuleId: compile.documentRuleId(t, "request", 0).Bytes(),
	})
	return world
}

// The run's report over the opener.
func (self *aclTestsGrantWorld) runWith(t *testing.T, details AclGrantDetails) *AclPolicyTestReport {
	t.Helper()
	report, err := AclPolicyTestRun(&AclPolicyTestInput{Compile: self.world.input(), View: self.world.view(), Now: aclTestNow, GrantDetails: details})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

// The grant's name in a failure.
func (self *aclTestsGrantWorld) grantName() string {
	return "grant " + hex.EncodeToString(self.grantId)
}

// A grant whose detail opens is judged by its cidrs and ip: destinations: an accept they hold whole passes and a wider
// one fails, a deny they overlap fails naming the grant by id, and one they miss passes; its sidecar destinations' ports
// meet a check's before its prefixes do; a source the grant does not take, amir's device or a new device of dana's,
// passes every deny; and a grant whose requests rule the document no longer holds does not survive the save, so its
// deny passes. The opener was asked for this grant alone.
func TestAclPolicyTestRunJudgesAnActivatedRouteGrantByItsOpenedDetail(t *testing.T) {
	tests := func(dana Id, amir Id) string {
		return `"tests": [
    { "src": "sidecar:` + dana.String() + `", "accept": ["ip:198.51.100.0/26#route", "ip:203.0.113.0/30#route"], "deny": ["ip:192.0.2.0/24#route"] },
    { "src": "sidecar:` + dana.String() + `", "deny": ["ip:198.51.100.64/26#route", "ip:203.0.113.8/29#route"] },
    { "src": "sidecar:` + dana.String() + `", "accept": ["ip:198.51.100.0/24#route"] },
    { "src": "sidecar:` + amir.String() + `", "deny": ["ip:198.51.100.0/25#route"] },
    { "src": "dana@tests.example", "deny": ["ip:198.51.100.0/25#route"] },
  ]`
	}
	dana, amir := aclTestsGrantLaptops()
	world := newAclTestsGrantWorld(t, `{ `+aclTestsGrantRequests+`, `+tests(dana, amir)+` }`, true)
	details := &testAclGrantDetails{details: map[string]*protocol.CanonicalActionDetail{
		string(world.grantId): {Cidrs: []string{"198.51.100.0/25"}, GrantDst: []string{"ip:203.0.113.0/28"}},
	}}
	report := world.runWith(t, details)
	want := []string{
		"tests[1].deny[0]: allowed by " + world.grantName(),
		"tests[1].deny[1]: allowed by " + world.grantName(),
		"tests[2].accept[0]: refused: no_grant",
	}
	if got := aclTestsFailureLines(report); !slices.Equal(got, want) {
		t.Errorf("failures %q", got)
	}
	for _, failure := range report.Failures {
		if failure.GrantId != nil {
			t.Errorf("a definite failure carries an unread grant: %v", failure)
		}
	}
	if asked := details.asked(); len(asked) == 0 || slices.ContainsFunc(asked, func(opened string) bool { return opened != string(world.grantId) }) {
		t.Errorf("the opener was asked for %d details", len(asked))
	}

	// its ports, from its sidecar destinations, meet a check's first
	ported := newAclTestsGrantWorld(t, `{ `+aclTestsGrantRequests+`, "tests": [
    { "src": "sidecar:`+dana.String()+`", "accept": ["ip:198.51.100.0/26#route:tcp:22"], "deny": ["ip:198.51.100.0/26#route:tcp:443"] },
    { "src": "sidecar:`+dana.String()+`", "accept": ["ip:198.51.100.0/26#route:tcp:443"], "deny": ["ip:198.51.100.0/26#route:tcp:22"] },
  ] }`, true)
	report = ported.runWith(t, &testAclGrantDetails{details: map[string]*protocol.CanonicalActionDetail{
		string(ported.grantId): {GrantDst: []string{"ip:198.51.100.0/25", "sidecar:" + hex.EncodeToString(ported.amir.Bytes()) + ":tcp:22"}},
	}})
	want = []string{"tests[1].accept[0]: refused: no_grant", "tests[1].deny[0]: allowed by " + ported.grantName()}
	if got := aclTestsFailureLines(report); !slices.Equal(got, want) {
		t.Errorf("ported failures %q", got)
	}

	// the document dropped the grant's requests rule, so the grant ends at this save's base (FS-14)
	dropped := newAclTestsGrantWorld(t, `{ `+aclTestsGrantRequests+` }`, true)
	dropped.world.setPolicy(t, `{ "tests": [ { "src": "sidecar:`+dana.String()+`", "deny": ["ip:198.51.100.0/25#route"] } ] }`)
	if report := dropped.runWith(t, details); !report.Passed() {
		t.Errorf("a grant whose requests rule left: failures %q", aclTestsFailureLines(report))
	}
}

// A grant whose sealed detail does not open here may route its source into any range at any port: a deny it may apply
// to fails as indeterminate, naming the grant by id beside the test's index and the writer's three ways out, and an
// accept nothing else holds fails naming it too; a source it does not take passes; a document rule that holds the
// accept still passes it, and one that overlaps the deny fails it outright, carrying no grant. With no opener at all
// the same checks are indeterminate.
func TestAclPolicyTestRunHoldsAnUnopenedActivatedGrantIndeterminate(t *testing.T) {
	danaId, amirId := aclTestsGrantLaptops()
	dana, amir := danaId.String(), amirId.String()
	document := `{ ` + aclTestsGrantRequests + `,
  "grants": [ { "src": ["user:amir@tests.example"], "dst": ["ip:198.51.100.0/24"], "via": ["user:dana@tests.example"], "allow": ["route"] } ],
  "tests": [
    { "src": "sidecar:` + dana + `", "deny": ["ip:192.0.2.0/24#route"] },
    { "src": "sidecar:` + dana + `", "accept": ["ip:198.51.100.0/26#route"] },
    { "src": "sidecar:` + amir + `", "accept": ["ip:198.51.100.0/26#route"], "deny": ["ip:192.0.2.0/24#route", "ip:198.51.100.0/25#route"] },
  ] }`
	world := newAclTestsGrantWorld(t, document, true)
	indeterminate := func(test int, why string) string {
		return fmt.Sprintf("tests[%d].deny[0]: indeterminate: %s may route its source into the range, but its sealed detail %s: "+
			"restore this device's config keys, remove the test or wait for the grant to end", test, world.grantName(), why)
	}
	unaccepted := func(test int, why string) string {
		return fmt.Sprintf("tests[%d].accept[0]: refused: no_grant; %s may route it, but its sealed detail %s, so it establishes "+
			"no accept", test, world.grantName(), why)
	}
	for _, c := range []struct {
		name    string
		details AclGrantDetails
		why     string
	}{
		{name: "a missing generation", why: "needs a config key generation this device does not hold",
			details: &testAclGrantDetails{errs: map[string]error{string(world.grantId): fmt.Errorf("%w: generation 3", ErrConfigSealGenerationMissing)}}},
		{name: "a detail not its action's", why: "does not open here",
			details: &testAclGrantDetails{errs: map[string]error{string(world.grantId): ErrCanonicalActionDetailInvalid}}},
		{name: "an action the base does not hold", why: "is not held here: the state keeps no action for it", details: &testAclGrantDetails{}},
		{name: "a port with no protocol", why: "names a port with no protocol",
			details: &testAclGrantDetails{details: map[string]*protocol.CanonicalActionDetail{string(world.grantId): {Cidrs: []string{"198.51.100.0/24"}, TargetPort: 22}}}},
		{name: "no opener", why: "has no opener here", details: nil},
	} {
		report := world.runWith(t, c.details)
		want := []string{indeterminate(0, c.why), unaccepted(1, c.why), "tests[2].deny[1]: allowed by rule"}
		if got := aclTestsFailureLines(report); !slices.Equal(got, want) {
			t.Errorf("%s: failures %q", c.name, got)
			continue
		}
		for _, failure := range report.Failures {
			unread := failure.Test != 2
			if unread != bytes.Equal(failure.GrantId, world.grantId) || (!unread && failure.GrantId != nil) {
				t.Errorf("%s: %s carries grant %x", c.name, failure, failure.GrantId)
			}
		}
		if err := report.Err(); !errors.Is(err, ErrAclPolicyTests) || strings.Contains(err.Error(), "192.0.2") || strings.Contains(err.Error(), "tests.example") {
			t.Errorf("%s: the error names a value: %v", c.name, err)
		}
	}
}

// A grant whose action seals no detail, one from before version 4, its rule limiting no ports, names nothing any
// reader can read: the bridge compile gives it no entry and no row and AclEngine reaches nothing by it (QD-003), so the
// save reads it the same way, holding no accept and failing no deny of dana's laptop, through amir's laptop or any
// other, with no opener asked. Before the readers were one, the save read it as routing by its subjects and failed the
// deny, which no device served.
func TestAclPolicyTestRunHoldsAnUnsealedActivatedGrantClosed(t *testing.T) {
	dana, _ := aclTestsGrantLaptops()
	world := newAclTestsGrantWorld(t, `{ `+aclTestsGrantRequests+`, "tests": [
    { "src": "sidecar:`+dana.String()+`", "deny": ["ip:192.0.2.0/24#route", "ip:0.0.0.0/0#route"] },
    { "src": "sidecar:`+dana.String()+`", "accept": ["ip:192.0.2.0/24#route"] },
  ] }`, false)
	details := &testAclGrantDetails{}
	report := world.runWith(t, details)
	want := []string{"tests[1].accept[0]: refused: no_grant"}
	if got := aclTestsFailureLines(report); !slices.Equal(got, want) {
		t.Errorf("failures %q", got)
	}
	for _, failure := range report.Failures {
		if failure.GrantId != nil {
			t.Errorf("an unsealed grant left a check indeterminate: %v", failure)
		}
	}
	if asked := details.asked(); len(asked) != 0 {
		t.Errorf("a grant sealing no detail was opened %d times", len(asked))
	}
}

// A route grant's action as a daemon builds it, its prefix sealed beside its clear fields in network networkId under
// key: a version-4 forward naming via alone in its clear grant_dst.
func testAclRouteGrantAction(t *testing.T, networkId Id, via Id, key *EvsRepoKey, cidrs ...string) *StoredCanonicalAction {
	t.Helper()
	clear := proto.Clone(testBuildableActions()["bridge_forward"]).(*protocol.CanonicalAction)
	clear.SealedDetail = nil
	clear.GrantDst = []string{"sidecar:" + hex.EncodeToString(via.Bytes())}
	clear.GrantAllow = []string{"route"}
	stored, err := NewSealedCanonicalAction(clear, &protocol.CanonicalActionDetail{Cidrs: cidrs}, key, networkId, testActionDetailRandom())
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// The writer's opener over its state's actions opens a route grant's detail under the config key of its generation,
// held to its action; it answers ErrConfigSealGenerationMissing without that key, refuses the detail in another network
// and an action the state does not hold, and the run then judges the grant by what opened.
func TestAclStateGrantDetailsOpensASealedRouteGrant(t *testing.T) {
	dana, _ := aclTestsGrantLaptops()
	world := newAclTestsGrantWorld(t, `{ `+aclTestsGrantRequests+`, "tests": [
    { "src": "sidecar:`+dana.String()+`", "accept": ["ip:198.51.100.0/26#route"], "deny": ["ip:198.51.100.128/25#route", "ip:198.51.100.0/27#route"] },
  ] }`, true)
	key := testConfigSealKey(testActionDetailGeneration)
	stored := testAclRouteGrantAction(t, world.world.networkId, world.amir, key, "198.51.100.0/25")
	actions := map[string][]byte{string(world.grantId): stored.Bytes}
	opener := &aclStateGrantDetails{actions: actions, networkId: world.world.networkId, repoKeyAt: testConfigSealKeyAt(key)}
	detail, err := opener.GrantDetail(world.grantId)
	if err != nil || !slices.Equal(detail.GetCidrs(), []string{"198.51.100.0/25"}) {
		t.Fatalf("the detail: %v, %v", detail, err)
	}
	keyless := &aclStateGrantDetails{actions: actions, networkId: world.world.networkId, repoKeyAt: testConfigSealKeyAt()}
	if _, err := keyless.GrantDetail(world.grantId); !errors.Is(err, ErrConfigSealGenerationMissing) {
		t.Errorf("without the key: %v", err)
	}
	if _, err := (&aclStateGrantDetails{actions: actions, networkId: testConfigId("another network"), repoKeyAt: testConfigSealKeyAt(key)}).GrantDetail(world.grantId); err == nil {
		t.Error("the detail opened in another network")
	}
	if _, err := opener.GrantDetail(world.world.key("another grant")); !errors.Is(err, ErrAclGrantDetailUnread) {
		t.Errorf("an action the state does not hold: %v", err)
	}

	want := []string{"tests[0].deny[1]: allowed by " + world.grantName()}
	if got := aclTestsFailureLines(world.runWith(t, opener)); !slices.Equal(got, want) {
		t.Errorf("opened: failures %q", got)
	}
	report := world.runWith(t, keyless)
	if len(report.Failures) != 3 || !slices.ContainsFunc(report.Failures, func(failure AclPolicyTestFailure) bool {
		return failure.List == "deny" && failure.Check == 0 && strings.HasPrefix(failure.Reason, "indeterminate: ") && bytes.Equal(failure.GrantId, world.grantId)
	}) {
		t.Errorf("keyless: failures %q", aclTestsFailureLines(report))
	}
}

// PlanAclSave judges a save's tests at the verified base it stands on: an activated route grant the state holds, whose
// requests rule the planned document keeps, fails a deny its sealed prefix overlaps, naming the grant, when the writer's
// RepoKeyAt holds the detail's generation, and fails it as indeterminate when the writer holds no key; either way the
// plan's tests fail, so AclSave signs nothing.
func TestPlanAclSaveJudgesAnActivatedRouteGrantAtItsBase(t *testing.T) {
	net := newTestConfigNet(t)
	via := net.device("route via", net.ownerMemberId)
	net.admitDevice(net.owner, via, 0)
	source := []byte(`{ ` + aclTestsGrantRequests + `, "tests": [ { "src": "sidecar:` + net.owner.sidecarId.String() + `", "deny": ["ip:198.51.100.0/26#route"] } ] }`)
	policy, err := ParseAclPolicy(source)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := AclPolicyRuleKeys(policy)
	if err != nil {
		t.Fatal(err)
	}
	requestId := testConfigId("the requests rule")
	rules := &protocol.ConfigRuleTable{}
	for _, ruleKey := range keys {
		if ruleKey.Kind == "request" {
			rules.Rules = append(rules.Rules, &protocol.ConfigRuleId{CanonicalSha256: bytes.Clone(ruleKey.CanonicalSha256[:]), RuleId: requestId.Bytes()})
		}
	}
	rulesBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	head, err := testConfigHead(t, net).WithFile(ConfigHeadRulesPath, rulesBytes)
	if err != nil {
		t.Fatal(err)
	}

	key := testConfigSealKey(testActionDetailGeneration)
	stored := testAclRouteGrantAction(t, net.networkId, via.sidecarId, key, "198.51.100.0/25")
	grantId := bytes.Repeat([]byte{0x6b}, 32)
	ownerAtom := AclDerivedAtom(AclDerivedAtomSidecar, net.owner.sidecarId.Bytes())
	target := &protocol.AclTarget{SidecarId: via.sidecarId.Bytes()}
	state := configCopyState(net.log.State())
	state.aclRows = &protocol.AclRows{
		Atoms: []*protocol.AclAtom{{Atom: ownerAtom.Bytes(), SidecarIds: [][]byte{net.owner.sidecarId.Bytes()}}},
		Rules: []*protocol.AclRule{{
			RuleId: grantId, SrcAtoms: [][]byte{ownerAtom.Bytes()}, Targets: []*protocol.AclTarget{target},
			Via: []*protocol.AclTarget{proto.Clone(target).(*protocol.AclTarget)}, Actions: []uint32{uint32(protocol.AclAction_ACL_ACTION_ROUTE)},
			PortsLimited: true, SourceRuleId: requestId.Bytes(),
		}},
	}
	state.grantActions = map[string][]byte{string(grantId): stored.Bytes}

	plan := func(repoKeyAt func(uint64) *EvsRepoKey) *AclPolicyTestReport {
		t.Helper()
		planned, err := PlanAclSave(context.Background(), &AclSaveInput{Policy: source, Head: head, State: state, Now: aclTestNow, RepoKeyAt: repoKeyAt})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(planned.Rows.GetRules(), func(rule *protocol.AclRule) bool { return bytes.Equal(rule.GetRuleId(), grantId) }) {
			t.Fatal("the activated grant did not survive the planned head")
		}
		return planned.Tests
	}
	grant := "grant " + hex.EncodeToString(grantId)
	if got := aclTestsFailureLines(plan(testConfigSealKeyAt(key))); !slices.Equal(got, []string{"tests[0].deny[0]: allowed by " + grant}) {
		t.Errorf("with the key: failures %q", got)
	}
	keyless := plan(nil)
	if len(keyless.Failures) != 1 || !strings.HasPrefix(keyless.Failures[0].Reason, "indeterminate: "+grant+" ") ||
		!bytes.Equal(keyless.Failures[0].GrantId, grantId) || keyless.Failures[0].Test != 0 || keyless.Err() == nil {
		t.Errorf("without a key: failures %q", aclTestsFailureLines(keyless))
	}
}
