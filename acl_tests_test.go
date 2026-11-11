//go:build !sidecar_http && !ios_extension

// §8.5's tests and §8.8's save plan, pure (T1): each test's src held to its accepts and denies over the compiled rows,
// a check over a set and an unresolvable name failing rather than passing unseen, ports judged at a sidecar's own
// engine, a group src held for every member; the document's own world when no state is at hand; and PlanAclSave's
// tables keeping ids and drawing new ones, its validation, and its preview naming the readers it changes, the repos
// that cannot seat a reader, and each new resolve row. The writer's flows run on the fake api in acl_save_test.go.

package sidecar

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network for test runs: dana and amir members with a device each, a db socket, a notes and a secrets repo.
type aclTestsWorld struct {
	world *aclCompileWorld
	dana  Id
	amir  Id
	notes Id
}

func newAclTestsWorld(t testing.TB, policy string) *aclTestsWorld {
	world := newAclCompileWorld("tests")
	self := &aclTestsWorld{world: world}
	owner := world.member("owner@tests.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	world.device("owner laptop", owner)
	self.dana = world.member("dana@tests.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.device("dana laptop", self.dana)
	self.amir = world.member("amir@tests.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world.device("amir laptop", self.amir)
	world.tag("db")
	world.group("eng")
	self.notes = world.repo("notes", protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	world.repo("secrets", protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	world.setPolicy(t, policy)
	return self
}

// The run's report, failing the test on an error.
func (self *aclTestsWorld) run(t testing.TB) *AclPolicyTestReport {
	t.Helper()
	report, err := AclPolicyTestRun(&AclPolicyTestInput{Compile: self.world.input(), View: self.world.view(), Now: aclTestNow})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

// The failures as lines, sorted.
func aclTestsFailureLines(report *AclPolicyTestReport) []string {
	lines := []string{}
	for _, failure := range report.Failures {
		lines = append(lines, failure.String())
	}
	slices.Sort(lines)
	return lines
}

const aclTestsPolicy = `{
  "groups": { "group:eng": ["dana@tests.example"] },
  "tagOwners": { "tag:db": ["autogroup:admin"] },
  "grants": [
    { "src": ["group:eng"], "dst": ["sock:db"], "allow": ["dial"] },
    { "src": ["tag:db"], "dst": ["sock:db"], "allow": ["listen"] },
    { "src": ["group:eng"], "dst": ["evs:notes"], "allow": ["read"] },
    { "src": ["group:eng"], "dst": ["user:amir@tests.example"], "allow": ["dial"], "ip": ["tcp:22"] },
  ],
  "tests": [
    { "src": "dana@tests.example", "accept": ["sock:db#dial", "evs:notes#read", "user:amir@tests.example#dial:tcp:22"],
      "deny": ["evs:secrets#read", "user:amir@tests.example#dial:tcp:80"] },
    { "src": "tag:db", "accept": ["sock:db#listen"], "deny": ["sock:db#dial"] },
    { "src": "amir@tests.example", "accept": ["sock:db#dial"] },
    { "src": "dana@tests.example", "deny": ["evs:notes#read"] },
    { "src": "dana@tests.example", "accept": ["user:amir@tests.example#dial:tcp:20-22"] },
  ],
}`

// Passing tests pass, and each failing check names its test, list and index with why.
func TestAclPolicyTestRunJudgesEachCheck(t *testing.T) {
	report := newAclTestsWorld(t, aclTestsPolicy).run(t)
	if report.TestCount != 5 || report.CheckCount != 10 || report.Passed() {
		t.Fatalf("%d tests, %d checks, %d failures", report.TestCount, report.CheckCount, len(report.Failures))
	}
	want := []string{
		"tests[2].accept[0]: refused: no_grant",
		"tests[3].deny[0]: allowed by rule",
		"tests[4].accept[0]: refused: no_grant at port 20",
	}
	if got := aclTestsFailureLines(report); !slices.Equal(got, want) {
		t.Errorf("failures %q", got)
	}
	if err := report.Err(); !errors.Is(err, ErrAclPolicyTests) || strings.Contains(err.Error(), "amir") {
		t.Errorf("the error names a value: %v", err)
	}
}

// A check over a set, a name the head does not hold and a group holding no one fail their tests; nothing passes
// unseen.
func TestAclPolicyTestRunFailsWhatItCannotJudge(t *testing.T) {
	policy := `{
  "groups": { "group:eng": ["dana@tests.example"], "group:empty": [] },
  "grants": [ { "src": ["group:eng"], "dst": ["sock:db"], "allow": ["dial"] } ],
  "tests": [
    { "src": "dana@tests.example", "deny": ["sock:db*#dial", "*#dial", "evs:no*#read", "evs:unknown#read", "dns:*-preview#publish"] },
    { "src": "group:empty", "deny": ["sock:db#dial"] },
    { "src": "nobody@tests.example", "deny": ["sock:db#dial"] },
    { "src": "network:*", "deny": ["sock:db#dial"] },
  ],
}`
	world := newAclTestsWorld(t, policy)
	world.world.group("empty")
	world.world.resolve.Members = append(world.world.resolve.Members, &protocol.ConfigMemberResolution{Email: "nobody@tests.example", MemberId: world.world.id("member nobody").Bytes()})
	report := world.run(t)
	want := []string{
		"tests[0].deny[0]: a check over a set of names: name one",
		"tests[0].deny[1]: a check over a set: name one resource",
		"tests[0].deny[2]: a check over a set of repos: name one",
		"tests[0].deny[3]: a repo label the labels file does not hold",
		"tests[0].deny[4]: a check over a set of names: name one",
		"tests[1].src: a group holding no member of the state",
		"tests[2].src: a user the state does not hold",
		"tests[3].src: a check over every network: name one",
	}
	if got := aclTestsFailureLines(report); !slices.Equal(got, want) {
		t.Errorf("failures %q", got)
	}
}

// A group src holds for every member: an accept one member lacks fails, and a deny passes only when none has it.
func TestAclPolicyTestRunHoldsAGroupForEveryMember(t *testing.T) {
	policy := `{
  "groups": { "group:eng": ["dana@tests.example", "amir@tests.example"] },
  "grants": [ { "src": ["user:dana@tests.example"], "dst": ["evs:notes"], "allow": ["read"] } ],
  "tests": [
    { "src": "group:eng", "accept": ["evs:notes#read"] },
    { "src": "group:eng", "deny": ["evs:secrets#read"] },
    { "src": "group:eng", "deny": ["evs:notes#read"] },
  ],
}`
	report := newAclTestsWorld(t, policy).run(t)
	want := []string{"tests[0].accept[0]: refused: no_grant", "tests[2].deny[0]: allowed by rule"}
	if got := aclTestsFailureLines(report); !slices.Equal(got, want) {
		t.Errorf("failures %q", got)
	}
}

// With no state, the document's own world: every user it names a member, so its tests check it against itself.
func TestAclPolicyTestOverTheDocumentAlone(t *testing.T) {
	policy := `{
  "groups": { "group:eng": ["dana@tests.example"] },
  "grants": [ { "src": ["group:eng"], "dst": ["user:amir@tests.example"], "allow": ["dial"] } ],
  "tests": [
    { "src": "dana@tests.example", "accept": ["user:amir@tests.example#dial"] },
    { "src": "amir@tests.example", "accept": ["user:dana@tests.example#dial"] },
  ],
}`
	report, err := AclPolicyTestOver([]byte(policy), nil, nil, aclTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if !report.DocumentAlone || report.TestCount != 2 {
		t.Fatalf("%+v", report)
	}
	if got := aclTestsFailureLines(report); !slices.Equal(got, []string{"tests[1].accept[0]: refused: no_grant"}) {
		t.Errorf("failures %q", got)
	}
	if _, err := AclPolicyTestOver([]byte(`{ "grants": [ { "src": ["user:x"] } ] }`), nil, nil, aclTestNow); !errors.Is(err, ErrAclPolicyInvalid) {
		t.Errorf("a document that does not parse: %v", err)
	}
}

// A random source that never repeats: each read the next counter, for ids a test can tell apart.
type aclTestCounterReader struct {
	next uint64
}

func (self *aclTestCounterReader) Read(p []byte) (int, error) {
	for i := 0; i < len(p); i += 8 {
		self.next += 1
		block := binary.BigEndian.AppendUint64(nil, self.next|1<<63)
		copy(p[i:], block)
	}
	return len(p), nil
}

// A resolver answering from a map.
type aclTestResolver struct {
	members map[string]Id
}

func (self *aclTestResolver) ResolveMember(ctx context.Context, email string) (Id, bool, error) {
	memberId, found := self.members[email]
	return memberId, found, nil
}

func (self *aclTestResolver) ResolveNetwork(ctx context.Context, text string) (Id, bool, error) {
	return Id{}, false, nil
}

func (self *aclTestResolver) ResolveClient(ctx context.Context, clientId Id) (Id, bool, error) {
	return Id{}, false, nil
}

// A head holding the network's genesis and a labels file.
func aclTestsHead(t testing.TB, net *testConfigNet, labels map[string]Id) *ConfigHead {
	t.Helper()
	table := &protocol.ConfigLabelTable{}
	for _, label := range slices.Sorted(maps.Keys(labels)) {
		table.Labels = append(table.Labels, &protocol.ConfigRepoLabel{Label: label, RepoId: labels[label].Bytes()})
	}
	head, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: net.signedGenesis, ConfigHeadLabelsPath: testConfigMarshal(t, table)})
	if err != nil {
		t.Fatal(err)
	}
	return head
}

// The atom id a table holds for a name.
func aclTestsAtomId(t testing.TB, head *ConfigHead, path string, name string) Id {
	t.Helper()
	table := &protocol.ConfigAtomTable{}
	if err := aclSaveDecode(head, path, table); err != nil {
		t.Fatal(err)
	}
	for _, row := range table.GetAtoms() {
		if row.GetName() == name {
			return Id(row.GetAtomId())
		}
	}
	return Id{}
}

// A save's tables: every name keeps its id across saves, a new name draws one, a dropped name leaves; an unchanged rule
// keeps its id and a changed one draws a new one.
func TestPlanAclSaveKeepsAndDrawsIds(t *testing.T) {
	net := newTestConfigNet(t)
	member, _ := net.consentedMember("plan")
	resolver := &aclTestResolver{members: map[string]Id{"plan@tests.example": member}}
	random := &aclTestCounterReader{}
	first := `{
  "groups": { "group:eng": ["plan@tests.example"] },
  "tagOwners": { "tag:ci": ["autogroup:admin"], "tag:old": ["autogroup:admin"] },
  "grants": [ { "src": ["group:eng"], "dst": ["tag:ci"], "allow": ["dial"] } ],
}`
	plan, err := PlanAclSave(context.Background(), &AclSaveInput{Policy: []byte(first), Head: aclTestsHead(t, net, nil), State: net.log.State(), Resolver: resolver, Random: random, Now: aclTestNow})
	if err != nil {
		t.Fatal(err)
	}
	ci, old := aclTestsAtomId(t, plan.Head, ConfigHeadTagsPath, "ci"), aclTestsAtomId(t, plan.Head, ConfigHeadTagsPath, "old")
	eng := aclTestsAtomId(t, plan.Head, ConfigHeadGroupsPath, "eng")
	if ci == (Id{}) || old == (Id{}) || eng == (Id{}) || ci == old || aclAtomHasAutogroupForm(ci) {
		t.Fatalf("drawn ids %v %v %v", ci, old, eng)
	}
	if len(plan.Rows.GetRules()) != 1 {
		t.Fatalf("%d rules", len(plan.Rows.GetRules()))
	}
	firstRuleId := Id(plan.Rows.GetRules()[0].GetRuleId())

	second := `{
  "groups": { "group:eng": ["plan@tests.example"] },
  "tagOwners": { "tag:ci": ["autogroup:admin"], "tag:db": ["autogroup:admin"] },
  "grants": [
    { "src": ["group:eng"], "dst": ["tag:ci"], "allow": ["dial"] },
    { "src": ["group:eng"], "dst": ["tag:db"], "allow": ["dial"], "ip": ["tcp:5432"] },
  ],
}`
	next, err := PlanAclSave(context.Background(), &AclSaveInput{Policy: []byte(second), Head: plan.Head, State: net.log.State(), Resolver: resolver, Random: random, Now: aclTestNow})
	if err != nil {
		t.Fatal(err)
	}
	if aclTestsAtomId(t, next.Head, ConfigHeadTagsPath, "ci") != ci || aclTestsAtomId(t, next.Head, ConfigHeadGroupsPath, "eng") != eng {
		t.Error("a kept name changed its id")
	}
	if db := aclTestsAtomId(t, next.Head, ConfigHeadTagsPath, "db"); db == (Id{}) || db == ci || db == old {
		t.Errorf("tag:db's id %v", db)
	}
	if aclTestsAtomId(t, next.Head, ConfigHeadTagsPath, "old") != (Id{}) {
		t.Error("a dropped tag kept its row")
	}
	ruleIds := []Id{}
	for _, rule := range next.Rows.GetRules() {
		ruleIds = append(ruleIds, Id(rule.GetRuleId()))
	}
	if len(ruleIds) != 2 || !slices.Contains(ruleIds, firstRuleId) {
		t.Errorf("rule ids %v, the unchanged one %v", ruleIds, firstRuleId)
	}
	// the network's state holds no document yet, so both rules are new to it
	if !slices.Equal(next.Preview.RulesAdded, slices.SortedFunc(slices.Values(ruleIds), Id.Cmp)) || len(next.Preview.RulesRemoved) != 0 {
		t.Errorf("rules added %v, removed %v", next.Preview.RulesAdded, next.Preview.RulesRemoved)
	}
	if next.Digest == plan.Digest {
		t.Error("two plans share a digest")
	}
}

// Validation runs before anything compiles: a label the head does not hold and a user no resolver or row names refuse
// the save, every refusal at once.
func TestPlanAclSaveRefusesWhatValidationRefuses(t *testing.T) {
	net := newTestConfigNet(t)
	policy := `{ "grants": [
  { "src": ["user:stranger@tests.example"], "dst": ["evs:nowhere"], "allow": ["read"] },
] }`
	_, err := PlanAclSave(context.Background(), &AclSaveInput{Policy: []byte(policy), Head: aclTestsHead(t, net, nil), State: net.log.State(), Now: aclTestNow})
	validation := &AclValidationError{}
	if !errors.As(err, &validation) || len(validation.Refusals) != 2 {
		t.Fatalf("%v", err)
	}
}

// The preview: a new resolve row with the member's role and devices, the readers a grant adds, and a data repo whose
// 1,001st reading member device cannot take a seat (§8.12).
func TestPlanAclSavePreviewNamesReadersResolutionsAndAnUnseatableRepo(t *testing.T) {
	net := newTestConfigNet(t)
	member := testConfigId("preview member")
	repoId := testConfigId("preview data repo")
	rows := net.log.State().Rows()
	rows.Members = append(rows.Members, &bridge.MemberRow{MemberId: member.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER})
	for i := range aclRepoSeatCount - 1 {
		device := testConfigId(fmt.Sprintf("preview device %d", i))
		rows.Sidecars = append(rows.Sidecars, &bridge.SidecarRow{
			SidecarId: device.Bytes(), AdmissionSigners: [][]byte{net.owner.sidecarId.Bytes()}, AdmittedAt: 1, LiveSince: 1,
			IdentityPublicKey: testConfigDeviceKey("preview").Public().(ed25519.PublicKey), IdentityAlg: configIdentityAlgEd25519,
			MemberId: member.Bytes(),
		})
	}
	rows.Acl = testConfigMarshal(t, &protocol.AclRows{
		HasDocument: true,
		Repos:       []*protocol.AclRepo{{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}},
	})
	if verdict := net.pushBase(net.owner, rows, net.n, 2, 0); !verdict.Accepted() {
		t.Fatalf("the base: %v", verdict.Refusal)
	}
	extra := net.device("preview the 1,001st", member)
	net.admitDevice(net.owner, extra, 0)
	state := net.log.State()
	policy := `{
  "grants": [ { "src": ["autogroup:member"], "dst": ["evs:data"], "allow": ["read"] } ],
  "tests": [ { "src": "member@tests.example", "accept": ["evs:data#read"] } ],
}`
	resolver := &aclTestResolver{members: map[string]Id{"member@tests.example": member}}
	plan, err := PlanAclSave(context.Background(), &AclSaveInput{
		Policy: []byte(policy), Head: aclTestsHead(t, net, map[string]Id{"data": repoId}), State: state, Resolver: resolver,
		Random: &aclTestCounterReader{}, Now: time.UnixMilli(state.TimeMs()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Tests.Passed() {
		t.Fatalf("tests: %v", plan.Tests.Err())
	}
	preview := plan.Preview
	if len(preview.Readers) != 1 || preview.Readers[0].RepoId != repoId || len(preview.Readers[0].Added) != aclRepoSeatCount+1 || len(preview.Readers[0].Removed) != 0 {
		t.Errorf("readers %+v", len(preview.Readers))
	}
	if len(preview.Unseated) != 1 || preview.Unseated[0].RepoId != repoId || preview.Unseated[0].ReaderCount != aclRepoSeatCount+1 ||
		!slices.Equal(preview.Unseated[0].SidecarIds, []Id{extra.sidecarId}) {
		t.Errorf("unseated %+v", preview.Unseated)
	}
	if len(preview.Resolutions) != 1 || preview.Resolutions[0].Kind != "user" || preview.Resolutions[0].Id != member ||
		preview.Resolutions[0].Role != bridge.MemberRole_MEMBER_ROLE_MEMBER || len(preview.Resolutions[0].SidecarIds) != aclRepoSeatCount {
		t.Errorf("resolutions %+v", preview.Resolutions)
	}
}
