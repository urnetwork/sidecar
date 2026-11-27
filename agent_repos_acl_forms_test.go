//go:build !sidecar_http && !ios_extension

// QD-1433's rule over every agent repo and QD-1434's keyed label across the readers (agent-repos-acl-forms;
// DESIGN-COMPUTE §16.5, §20.4, §20.7; DESIGN §8.4, §8.5):
//
//	readers     the rows' evs:kind:agent rule gives a deposit into each agent repo the rows hold, one created after the
//	            base included, and the same answer at the state, at evs's and gkm's gates (AclHonorScope, what
//	            AclGateCache.HonorScope answers from the newest verified state) and at the engine's Check, which
//	            Sidecar.Authorize and MCP's acl_check run; the save's tests (AclPolicyTestRun, which PlanAclSave runs
//	            before a head is signed) judge an agent repo by the same rows
//	narrowing   a Team's document that names one agent's repo in place of the kind deposits there alone
//	wildcards   * and evs:* reach no agent repo, as DESIGN §8.4 holds for §8.5's kinds
//	api's view  what api sequences and what its rows-only fold keeps hold an agent repo's 16 opaque bytes and neither
//	            the agent's name nor a key that recomputes one, and another network's api another label for one name

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Holds every reader to one answer for a sidecar's deposit into and read of a repo at now: the state's EvsAccess, evs's
// and gkm's gates, and, where engine is not nil, the engine's Check.
func testAgentKindReaders(t *testing.T, label string, state *AclState, engine *AclEngine, sidecarId Id, repoId Id, now time.Time, deposit bool, read bool) {
	t.Helper()
	subject := AclSidecarSubject(sidecarId)
	rights := state.EvsAccess(subject, repoId, AclTokenAudienceEvs, now).Rights
	for _, c := range []struct {
		right  AclEvsRights
		action protocol.AclAction
		want   bool
	}{
		{right: AclEvsDeposit, action: protocol.AclAction_ACL_ACTION_DEPOSIT, want: deposit},
		{right: AclEvsRead, action: protocol.AclAction_ACL_ACTION_READ, want: read},
	} {
		answers := []struct {
			reader  string
			allowed bool
		}{
			{reader: "the state", allowed: rights.Has(c.right)},
			{reader: "evs's gate", allowed: AclHonorScope(state, sidecarId, repoId, c.right, AclTokenAudienceEvs, now) == AclScopeHonored},
			{reader: "gkm's gate", allowed: AclHonorScope(state, sidecarId, repoId, c.right, AclTokenAudienceGkm, now) == AclScopeHonored},
		}
		if engine != nil {
			check := engine.Check(subject, c.action, AclResource{Kind: AclResourceRepo, RepoId: repoId}, now)
			answers = append(answers, struct {
				reader  string
				allowed bool
			}{reader: "Check", allowed: check.Allowed})
		}
		for _, answer := range answers {
			if answer.allowed != c.want {
				t.Errorf("%s, %s at %s: %t, want %t", label, c.action, answer.reader, answer.allowed, c.want)
			}
		}
	}
}

// An engine of sidecarId's over state, its rows' checks standing alone, which judges at the time it is given.
func testAgentKindEngine(t *testing.T, sidecarId Id, state *AclState) *AclEngine {
	t.Helper()
	engine := NewAclEngine(sidecarId, nil, nil, &AclEngineSettings{ClockSkew: 0})
	if err := engine.Install(state, nil); err != nil {
		t.Fatal(err)
	}
	return engine
}

// Team's starting document with agent_repos on, its rule over every agent repo: at every reader another member's
// device, the Owner's and dana's own device that no consent names deposit into dana's agent repos and read nothing
// there, the repo the compile saw and one the rows gain after it alike, Check naming the starting document's rule;
// dana's consented device reads, writes and deposits; a tagged sidecar and an ephemeral device take nothing. Check
// over the kind itself, a set of repos, allows nothing.
func TestAgentRepoKindRuleEveryReader(t *testing.T) {
	team := newAclTeamWorld(t, string(AclTeamStartDocumentFor(AuthFeatureAgentRepos)))
	world := team.world
	recurd := world.agent("amir's recurd agent", team.amir, "recurd")
	burner := world.device("amir's burner", team.amir)
	world.ephemeral[burner] = true
	scoutId := world.repo("agent/scout", protocol.RepoKind_REPO_KIND_AGENT, team.dana)
	testAgentsWorldRepos(world, team.danaFirst)
	input := world.input()
	input.AuthFeatures = AuthFeatureAgentRepos
	rows, err := CompileAcl(input)
	if err != nil {
		t.Fatal(err)
	}
	// a repo created after the base: the rows gain its row as the fold keeps it, and no rule names it
	laterId := world.id("repo agent/later")
	rows.Repos = append(rows.Repos, &protocol.AclRepo{RepoId: laterId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_AGENT,
		OwnerMemberId: team.dana.Bytes(), ConsentedSidecarIds: [][]byte{team.danaFirst.Bytes()}, LabelMac: testAgentRepoLabelMac("later")})
	view := world.view()
	view.pin = aclTestEnginePin(1, "agent kind readers")
	state, err := NewAclState(rows, view)
	if err != nil {
		t.Fatal(err)
	}
	engine := testAgentKindEngine(t, team.amirDevice, state)
	ruleId := world.documentRuleId(t, "grant", 2)
	for _, repoId := range []Id{scoutId, laterId} {
		for _, c := range []struct {
			name      string
			sidecarId Id
			deposit   bool
			read      bool
		}{
			{name: "dana's consented device", sidecarId: team.danaFirst, deposit: true, read: true},
			{name: "dana's device that no consent names", sidecarId: team.danaSecond, deposit: true},
			{name: "amir's device", sidecarId: team.amirDevice, deposit: true},
			{name: "the Owner's device", sidecarId: team.ownerDevice, deposit: true},
			{name: "amir's recurd agent", sidecarId: recurd},
			{name: "amir's ephemeral device", sidecarId: burner},
		} {
			testAgentKindReaders(t, c.name+" on "+repoId.String(), state, engine, c.sidecarId, repoId, aclTestNow, c.deposit, c.read)
		}
		check := engine.Check(AclSidecarSubject(team.amirDevice), protocol.AclAction_ACL_ACTION_DEPOSIT, AclResource{Kind: AclResourceRepo, RepoId: repoId}, aclTestNow)
		if !check.Allowed || !bytes.Equal(check.GrantId, ruleId.Bytes()) {
			t.Errorf("amir's deposit on %s names %x, not the starting document's rule %x", repoId, check.GrantId, ruleId.Bytes())
		}
	}
	kind := AclResource{Kind: AclResourceRepoKind, RepoKind: protocol.RepoKind_REPO_KIND_AGENT}
	if check := engine.Check(AclSidecarSubject(team.amirDevice), protocol.AclAction_ACL_ACTION_DEPOSIT, kind, aclTestNow); check.Allowed {
		t.Fatalf("Check allowed a deposit into a set of repos: %+v", check)
	}
}

// The save's tests judge agent repos by the rows' rules (AclPolicyTestRun): under the rule over every agent repo a
// member's device deposits into each and reads or writes none, and a tagged sidecar deposits into none; a Team's
// document that narrows the deposit to scout's repo passes tests that hold exactly that and fails one that still
// expects reviewer's deposit, naming the test and check by index; the narrowed document validates on Team, and every
// reader then gives amir's device scout's deposit alone.
func TestAgentRepoKindRuleSaveTestsAndNarrowing(t *testing.T) {
	team := newAclTeamWorld(t, string(AclTeamStartDocumentFor(AuthFeatureAgentRepos)))
	world := team.world
	world.agent("amir's recurd agent", team.amir, "recurd")
	scoutId := world.repo("agent/scout", protocol.RepoKind_REPO_KIND_AGENT, team.dana)
	reviewerId := world.repo("agent/reviewer", protocol.RepoKind_REPO_KIND_AGENT, team.dana)
	testAgentsWorldRepos(world, team.danaFirst)
	scout, reviewer := "evs:"+scoutId.String(), "evs:"+reviewerId.String()
	document := func(destination string, tests string) string {
		return `{
  "tagOwners": { "tag:recurd": ["autogroup:member"] },
  "grants": [ { "src": ["autogroup:member"], "dst": ["` + destination + `"], "allow": ["deposit"] } ],
  "tests": [ ` + tests + ` ],
}`
	}
	input := func(source string) *AclCompileInput {
		world.setPolicy(t, source)
		input := world.input()
		input.AuthFeatures = AuthFeatureAgentRepos
		return input
	}
	run := func(source string) *AclPolicyTestReport {
		report, err := AclPolicyTestRun(&AclPolicyTestInput{Compile: input(source), View: world.view(), Now: aclTestNow})
		if err != nil {
			t.Fatal(err)
		}
		return report
	}

	everyAgent := `{ "src": "amir@team.example", "accept": ["` + scout + `#deposit", "` + reviewer + `#deposit"],
      "deny": ["` + scout + `#read", "` + reviewer + `#write"] },
    { "src": "tag:recurd", "deny": ["` + scout + `#deposit", "` + reviewer + `#deposit"] }`
	if report := run(document("evs:kind:agent", everyAgent)); !report.Passed() || report.TestCount != 2 || report.CheckCount != 6 {
		t.Fatalf("the rule over every agent repo: %+v, %v", report, report.Err())
	}
	narrowed := `{ "src": "amir@team.example", "accept": ["` + scout + `#deposit"], "deny": ["` + reviewer + `#deposit", "` + scout + `#read"] }`
	if report := run(document(scout, narrowed)); !report.Passed() || report.TestCount != 1 || report.CheckCount != 3 {
		t.Fatalf("the document narrowed to scout: %+v, %v", report, report.Err())
	}
	stale := `{ "src": "amir@team.example", "accept": ["` + scout + `#deposit", "` + reviewer + `#deposit"] }`
	report := run(document(scout, stale))
	if report.Passed() || len(report.Failures) != 1 || report.Failures[0].Test != 0 || report.Failures[0].List != "accept" ||
		report.Failures[0].Check != 1 {
		t.Fatalf("a test still expecting reviewer's deposit: %+v", report)
	}

	narrowedInput := input(document(scout, narrowed))
	if err := ValidateAclPolicy(&AclValidateInput{Compile: narrowedInput, Limits: aclTestTeamLimits()}); err != nil {
		t.Fatalf("the narrowed document's validation: %v", err)
	}
	rows, err := CompileAcl(narrowedInput)
	if err != nil {
		t.Fatal(err)
	}
	view := world.view()
	view.pin = aclTestEnginePin(1, "agent kind narrowed")
	state, err := NewAclState(rows, view)
	if err != nil {
		t.Fatal(err)
	}
	engine := testAgentKindEngine(t, team.amirDevice, state)
	testAgentKindReaders(t, "amir's device on scout's repo", state, engine, team.amirDevice, scoutId, aclTestNow, true, false)
	testAgentKindReaders(t, "amir's device on reviewer's repo", state, engine, team.amirDevice, reviewerId, aclTestNow, false, false)
	testAgentKindReaders(t, "dana's consented device on reviewer's repo", state, engine, team.danaFirst, reviewerId, aclTestNow, true, true)
}

// DESIGN §8.4's rule stands beside the kind's form (QD-1433): a document giving every member * and write and admin on
// evs:*, and every tagged subject deposit on evs:*, gives another member's device and a tagged sidecar nothing in
// dana's agent repo or agents repo at any reader, while a general repo takes those rights; a rule naming the kind adds
// the deposit into the agent repo alone, and nothing to the agents repo or to the tagged sidecar.
func TestAgentRepoKindWildcardsReachNoAgentRepo(t *testing.T) {
	team := newAclTeamWorld(t, string(AclTeamStartDocument()))
	world := team.world
	recurd := world.agent("amir's recurd agent", team.amir, "recurd")
	agentId := world.repo("agent/scout", protocol.RepoKind_REPO_KIND_AGENT, team.dana)
	agentsId := world.repo("agents", protocol.RepoKind_REPO_KIND_AGENTS, team.dana)
	generalId := world.repo("shared", protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	testAgentsWorldRepos(world, team.danaFirst)
	wildcards := `
    { "src": ["autogroup:member", "autogroup:untagged"], "dst": ["*"], "allow": ["*"] },
    { "src": ["autogroup:member"], "dst": ["evs:*"], "allow": ["write", "admin"] },
    { "src": ["autogroup:tagged"], "dst": ["evs:*"], "allow": ["deposit"] }`
	for _, c := range []struct {
		name   string
		grants string
		// amir's deposit into dana's agent repo
		agentDeposit bool
	}{
		{name: "the wildcards alone", grants: wildcards},
		{name: "the wildcards and the kind's rule", grants: wildcards + `,
    { "src": ["autogroup:member"], "dst": ["evs:kind:agent"], "allow": ["deposit"] }`, agentDeposit: true},
	} {
		world.setPolicy(t, `{
  "tagOwners": { "tag:recurd": ["autogroup:member"] },
  "grants": [`+c.grants+` ],
}`)
		input := world.input()
		input.AuthFeatures = AuthFeatureAgentRepos
		rows, err := CompileAcl(input)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		view := world.view()
		view.pin = aclTestEnginePin(1, "agent kind wildcards "+c.name)
		state, err := NewAclState(rows, view)
		if err != nil {
			t.Fatal(err)
		}
		engine := testAgentKindEngine(t, team.amirDevice, state)
		testAgentKindReaders(t, c.name+", amir's device on the agent repo", state, engine, team.amirDevice, agentId, aclTestNow, c.agentDeposit, false)
		testAgentKindReaders(t, c.name+", amir's device on the agents repo", state, engine, team.amirDevice, agentsId, aclTestNow, false, false)
		testAgentKindReaders(t, c.name+", the recurd agent on the agent repo", state, engine, recurd, agentId, aclTestNow, false, false)
		testAgentKindReaders(t, c.name+", the recurd agent on the agents repo", state, engine, recurd, agentsId, aclTestNow, false, false)
		testAgentKindReaders(t, c.name+", amir's device on the general repo", state, engine, team.amirDevice, generalId, aclTestNow, true, true)
		testAgentKindReaders(t, c.name+", the recurd agent on the general repo", state, engine, recurd, generalId, aclTestNow, true, false)
	}
}

// A network with agent_repos on whose member's consented device created an agent repo for each name, each RepoCreate
// filing the name's label under the network's K_label; K_label derives from a key of the net's own config repo, one
// rk1Text fixes, and its K_ref and K_label bytes are what api must never see.
type testAgentApiNet struct {
	net      *testConfigNet
	memberId Id
	labelKey *AgentRepoLabelKey
	refKey   []byte
	repoIds  map[AgentName]Id
}

func newTestAgentApiNet(t *testing.T, networkLabel string, rk1Text string, names []AgentName) *testAgentApiNet {
	t.Helper()
	net := newTestConfigNetOf(t, networkLabel)
	memberId, device := net.consentedMember(networkLabel + " member")
	base := testFeatureBase(t, net, AuthFeatureAgentRepos)
	if _, err := net.log.Apply(base, net.source); err != nil {
		t.Fatal(err)
	}
	net.statesAt[net.n] = net.log.State()
	net.verdicts[net.n] = ConfigVerdict{Kind: bridge.AuthEntryKindBase}

	configRepoId := Id(net.log.State().Genesis().GetConfigRepoId())
	rk1 := sha256.Sum256([]byte(rk1Text))
	configKey := &EvsRepoKey{repoId: configRepoId, generation: 1, repoKey: rk1[:], firstRepoKey: rk1[:]}
	refKey, err := configKey.DeriveKey(EvsKeyPurposeRef, nil)
	if err != nil {
		t.Fatal(err)
	}
	labelKey, err := NewAgentRepoLabelKey(net.networkId, configRepoId, configKey)
	if err != nil {
		t.Fatal(err)
	}
	self := &testAgentApiNet{net: net, memberId: memberId, labelKey: labelKey, refKey: refKey, repoIds: map[AgentName]Id{}}
	for _, name := range names {
		repoId := testConfigId(networkLabel + " agent repo " + string(name))
		net.mustPost(device, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(),
			Kind: protocol.RepoKind_REPO_KIND_AGENT, LabelMac: labelKey.Mac(name)})
		self.repoIds[name] = repoId
	}
	return self
}

// api's view of agent repos (QD-1434; DESIGN-COMPUTE §20.4, §20.7): every entry api sequenced, the RepoCreates among
// them, and the rows its rows-only fold keeps, which a gate reads, hold each agent repo's label as the 16 bytes its
// creating device filed and nothing else of it: not the agent's name, not agent/<name>, and neither the config repo's
// K_ref nor K_label, so api cannot recompute a label from a guessed name. A second network's api, its config key the
// same bytes, holds another label for each name, so a label links nothing across networks. A device of the network,
// which derives K_label, recomputes each label and finds the repo the member's agent/<name>, refusing another name's.
func TestAgentRepoApiViewHoldsNoName(t *testing.T) {
	names := []AgentName{"inbox-scout", "code-review-2"}
	first := newTestAgentApiNet(t, "api view", "agent repos acl forms rk1", names)
	api := first.net.apiAtTip().State()
	views := append([][]byte{testConfigMarshal(t, api.Rows())}, first.net.entries...)
	for i, view := range views {
		for _, name := range names {
			for _, text := range []string{string(name), agentRepoLabelPrefix + string(name)} {
				if bytes.Contains(view, []byte(text)) {
					t.Errorf("api's view %d holds %q", i, text)
				}
			}
		}
		for _, secret := range [][]byte{first.refKey, first.labelKey.key} {
			if bytes.Contains(view, secret) {
				t.Errorf("api's view %d holds a key that recomputes a label", i)
			}
		}
	}
	for _, name := range names {
		row := api.Repo(first.repoIds[name])
		if row == nil || row.GetKind() != protocol.RepoKind_REPO_KIND_AGENT || len(row.GetLabelMac()) != AgentRepoLabelMacByteCount ||
			!bytes.Equal(row.GetLabelMac(), first.labelKey.Mac(name)) || !bytes.Equal(row.GetOwnerMemberId(), first.memberId.Bytes()) {
			t.Fatalf("api's row of %s's repo: %v", name, row)
		}
	}

	device, err := first.net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		repoId := first.repoIds[name]
		if !device.MemberAgentRepoLabeled(first.memberId, repoId, first.labelKey.Mac(name)) {
			t.Errorf("the device does not find %s's repo labeled %s", name, name)
		}
		for _, other := range append(names, "inbox-scout-2") {
			if other != name && device.MemberAgentRepoLabeled(first.memberId, repoId, first.labelKey.Mac(other)) {
				t.Errorf("%s's repo takes %s's label", name, other)
			}
		}
	}

	second := newTestAgentApiNet(t, "api view other", "agent repos acl forms rk1", names)
	secondApi := second.net.apiAtTip().State()
	for _, name := range names {
		if bytes.Equal(api.Repo(first.repoIds[name]).GetLabelMac(), secondApi.Repo(second.repoIds[name]).GetLabelMac()) {
			t.Errorf("two networks' api hold one label for %s", name)
		}
	}
}

// The rule over every agent repo reaches a repo created after its base at once, on the log (QD-1433): past a base whose
// rows hold autogroup:member to evs:kind:agent, as Team's starting document compiles it, the agent repo dana's device
// creates takes amir's device's and the owner's deposits, reading nothing, at the device's state with its engine's
// Check and at the gate over api's rows-only fold alike; dana's device reads and writes it; and amir's ephemeral
// device deposits nowhere, §8.6's ceiling holding it out of a rule that does not name it.
func TestAgentRepoKindRuleOnTheLogAtOnce(t *testing.T) {
	net := newTestConfigNet(t)
	dana, danaDevice := net.consentedMember("kind rule dana")
	_, amirDevice := net.consentedMember("kind rule amir")
	burner := net.device("kind rule amir burner", amirDevice.memberId)
	net.mustPost(amirDevice, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(burner, nil, true, net.timeMs+60*60*1000, 0))
	base := testFeatureBase(t, net, AuthFeatureAgentRepos)
	if _, err := net.log.Apply(base, net.source); err != nil {
		t.Fatal(err)
	}
	net.statesAt[net.n] = net.log.State()
	net.verdicts[net.n] = ConfigVerdict{Kind: bridge.AuthEntryKindBase}

	// a base whose head keeps agent_repos on and whose rows hold the rule over every agent repo
	ruleId := testConfigId("kind rule")
	state := net.log.State()
	configVersion := state.Base().GetConfigVersion() + 1
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = &protocol.ServiceSettings{AuthFeatures: uint32(AuthFeatureAgentRepos)}
	rows := state.Rows()
	aclRows := &protocol.AclRows{}
	if state.aclRows != nil {
		aclRows = proto.Clone(state.aclRows).(*protocol.AclRows)
	}
	aclRows.HasDocument = true
	aclRows.Rules = append(aclRows.Rules, &protocol.AclRule{
		RuleId:   ruleId.Bytes(),
		SrcAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
		Targets:  []*protocol.AclTarget{{RepoKind: protocol.RepoKind_REPO_KIND_AGENT}},
		Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_DEPOSIT)},
	})
	rows.Acl = testConfigMarshal(t, aclRows)
	if verdict := net.pushBase(net.owner, rows, net.n, configVersion, state.threshold); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}

	// after the base dana's device creates an agent repo, which no rule names
	repoId := testConfigId("kind rule agent repo")
	net.mustPost(danaDevice, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(),
		Kind: protocol.RepoKind_REPO_KIND_AGENT, LabelMac: testAgentRepoLabelMac("kind rule")})
	now := time.UnixMilli(net.timeMs)
	device, err := net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	if !device.MemberAgentRepo(dana, repoId) {
		t.Fatal("the fold does not bind the repo to dana")
	}
	gate, err := net.apiAtTip().State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	engine := testAgentKindEngine(t, amirDevice.sidecarId, device)
	for _, reader := range []struct {
		name   string
		state  *AclState
		engine *AclEngine
	}{
		{name: "the device", state: device, engine: engine},
		{name: "the gate over api's fold", state: gate},
	} {
		for _, c := range []struct {
			name      string
			sidecarId Id
			deposit   bool
			read      bool
		}{
			{name: "amir's device", sidecarId: amirDevice.sidecarId, deposit: true},
			{name: "the owner's device", sidecarId: net.owner.sidecarId, deposit: true},
			{name: "dana's device", sidecarId: danaDevice.sidecarId, deposit: true, read: true},
			{name: "amir's ephemeral device", sidecarId: burner.sidecarId},
		} {
			testAgentKindReaders(t, reader.name+", "+c.name, reader.state, reader.engine, c.sidecarId, repoId, now, c.deposit, c.read)
		}
	}
	if check := engine.Check(AclSidecarSubject(amirDevice.sidecarId), protocol.AclAction_ACL_ACTION_DEPOSIT, AclResource{Kind: AclResourceRepo, RepoId: repoId}, now); !bytes.Equal(check.GrantId, ruleId.Bytes()) {
		t.Errorf("amir's deposit names %x, not the base's rule", check.GrantId)
	}
}
