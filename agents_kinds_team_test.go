//go:build !sidecar_http && !ios_extension

// SKILL-M11-01 on Team's starting document (DESIGN-COMPUTE §16.5's Team column; QD-1433): the member deposit rule into
// every agent repo stands in the document a writer saves only where its head turns agent_repos on, so a Team created
// before the feature saves a document every reader compiles; with it, members' devices deposit into each other's agent
// repos and a tagged sidecar does not, and a Team's own document narrows the deposit per agent.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The starting document with agent_repos on, as a hex golden of its rows over Team's world.
const testAgentReposTeamStartRowsPath = "testdata/agents/rows/team_start_agent_repos_rows.hex"

// The starting document holds agent_repos' block only where its features turn the feature on, and never a marker line;
// the binary's source keeps its blocks well formed, and a source that opens one inside another, names no feature,
// closes one that is not open or leaves one open is refused.
func TestAclTeamStartFeatureBlocks(t *testing.T) {
	off := AclTeamStartDocumentFor(0)
	if !bytes.Equal(off, AclTeamStartDocument()) {
		t.Fatal("AclTeamStartDocument is not the document for no feature")
	}
	on := AclTeamStartDocumentFor(AuthFeatureAgentRepos)
	for _, document := range [][]byte{off, on} {
		if bytes.Contains(document, []byte("// +")) || bytes.Contains(document, []byte("// -")) {
			t.Fatalf("a marker line in the document:\n%s", document)
		}
	}
	if bytes.Contains(off, []byte("evs:kind:")) || !bytes.Contains(on, []byte(`"evs:kind:agent"`)) {
		t.Fatal("agent_repos' rule stands where the feature is off, or not where it is on")
	}
	offPolicy, err := ParseAclPolicy(off)
	if err != nil {
		t.Fatal(err)
	}
	onPolicy, err := ParseAclPolicy(on)
	if err != nil {
		t.Fatal(err)
	}
	if len(offPolicy.Grants) != 2 || len(onPolicy.Grants) != 3 || len(offPolicy.Requests) != len(onPolicy.Requests) ||
		len(offPolicy.Tests) != len(onPolicy.Tests) {
		t.Fatalf("grants %d and %d", len(offPolicy.Grants), len(onPolicy.Grants))
	}
	deposit := onPolicy.Grants[2]
	if len(deposit.Src) != 1 || deposit.Src[0].String() != "autogroup:member" || len(deposit.Dst) != 1 ||
		deposit.Dst[0] != (AclResource{Kind: AclResourceRepoKind, RepoKind: protocol.RepoKind_REPO_KIND_AGENT}) ||
		!slices.Equal(deposit.Allow, []protocol.AclAction{protocol.AclAction_ACL_ACTION_DEPOSIT}) {
		t.Fatalf("agent_repos' rule: %+v", deposit)
	}
	// every feature but agent_repos adds nothing to the document
	if !bytes.Equal(AclTeamStartDocumentFor(AuthFeatureComputePolicy|AuthFeatureListeners|AuthFeatureEnclaves), off) {
		t.Fatal("a feature with no block changed the document")
	}
	for _, source := range []string{
		"a\n// +agent_repos\nb\n// +listeners\nc\n// -listeners\n// -agent_repos\n",
		"a\n// +agent_repo\nb\n// -agent_repo\n",
		"a\n// -agent_repos\n",
		"a\n// +agent_repos\nb\n",
		"a\n// +agent_repos\nb\n// -listeners\n",
	} {
		if _, err := aclTeamStartDocumentFor([]byte(source), AuthFeatureAgentRepos); err == nil {
			t.Errorf("a malformed source taken: %q", source)
		}
	}
	if document, err := aclTeamStartDocumentFor([]byte("a\n  // +agent_repos\nb\n  // -agent_repos\nc"), 0); err != nil || string(document) != "a\nc" {
		t.Fatalf("a block dropped: %q, %v", document, err)
	}
}

// With agent_repos on, the starting document compiles to its golden, the base rows and agent_repos' rule, validates on
// Team and passes its own tests; with it off the compile refuses it. Members' devices deposit into another member's
// agent repo, reading nothing, a tagged sidecar and an ephemeral one deposit nowhere, and a Team's own document narrows
// the deposit to one agent's repo.
func TestAgentReposTeamStartDeposit(t *testing.T) {
	team := newAclTeamWorld(t, string(AclTeamStartDocumentFor(AuthFeatureAgentRepos)))
	world := team.world
	recurd := world.agent("amir's cloud agent", team.amir, "recurd")
	burner := world.device("amir's burner", team.amir)
	world.ephemeral[burner] = true
	scoutId := world.repo("agent/scout", protocol.RepoKind_REPO_KIND_AGENT, team.dana)
	reviewerId := world.repo("agent/reviewer", protocol.RepoKind_REPO_KIND_AGENT, team.dana)
	agentsId := world.repo("agents", protocol.RepoKind_REPO_KIND_AGENTS, team.dana)
	testAgentsWorldRepos(world, team.danaFirst)

	if _, err := CompileAcl(world.input()); !errors.Is(err, ErrAclCompile) {
		t.Fatalf("the document with agent_repos' rule compiled on a head that does not turn the feature on: %v", err)
	}
	input := world.input()
	input.AuthFeatures = AuthFeatureAgentRepos
	rows, err := CompileAcl(input)
	if err != nil {
		t.Fatal(err)
	}
	if !rows.GetHasDocument() || len(rows.GetRules()) != 3 || len(rows.GetRequests()) != 1 {
		t.Fatalf("has_document %t, %d rules, %d requests", rows.GetHasDocument(), len(rows.GetRules()), len(rows.GetRequests()))
	}
	testAgentsRowsGolden(t, testAgentReposTeamStartRowsPath, rows)
	if err := ValidateAclPolicy(&AclValidateInput{Compile: input, Limits: aclTestTeamLimits()}); err != nil {
		t.Fatalf("validation on Team: %v", err)
	}
	report, err := AclPolicyTestRun(&AclPolicyTestInput{Compile: input, View: world.view(), Now: aclTestNow})
	if err != nil || !report.Passed() || report.TestCount != 2 || report.CheckCount != 6 {
		t.Fatalf("its tests: %+v, %v", report, err)
	}

	state, err := NewAclState(rows, world.view())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name      string
		sidecarId Id
		agent     AclEvsRights
	}{
		// the repos' rows name no admin, so dana's consented device reads and writes alone
		{name: "dana's device", sidecarId: team.danaFirst, agent: AclEvsRead | AclEvsWrite | AclEvsDeposit},
		{name: "amir's device", sidecarId: team.amirDevice, agent: AclEvsDeposit},
		{name: "the Owner's device", sidecarId: team.ownerDevice, agent: AclEvsDeposit},
		{name: "amir's cloud agent", sidecarId: recurd, agent: 0},
		{name: "amir's ephemeral device", sidecarId: burner, agent: 0},
	} {
		for _, repoId := range []Id{scoutId, reviewerId} {
			if rights := aclTestRights(state, c.sidecarId, repoId, AclTokenAudienceEvs); rights != c.agent {
				t.Errorf("%s on %s: %b, want %b", c.name, repoId, rights, c.agent)
			}
		}
		if rights := aclTestRights(state, c.sidecarId, agentsId, AclTokenAudienceEvs); c.sidecarId != team.danaFirst && rights != 0 {
			t.Errorf("%s reaches dana's agents repo: %b", c.name, rights)
		}
	}

	// a Team narrows the deposit to one agent: its document names scout's repo and no longer every agent repo
	narrowed := strings.Replace(string(AclTeamStartDocumentFor(AuthFeatureAgentRepos)), `"evs:kind:agent"`, `"evs:`+scoutId.String()+`"`, 1)
	world.setPolicy(t, narrowed)
	input = world.input()
	input.AuthFeatures = AuthFeatureAgentRepos
	rows, err = CompileAcl(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAclPolicy(&AclValidateInput{Compile: input, Limits: aclTestTeamLimits()}); err != nil {
		t.Fatalf("the narrowed document's validation: %v", err)
	}
	state, err = NewAclState(rows, world.view())
	if err != nil {
		t.Fatal(err)
	}
	if rights := aclTestRights(state, team.amirDevice, scoutId, AclTokenAudienceEvs); rights != AclEvsDeposit {
		t.Errorf("amir's device on the agent the Team names: %b", rights)
	}
	if rights := aclTestRights(state, team.amirDevice, reviewerId, AclTokenAudienceEvs); rights != 0 {
		t.Errorf("amir's device on an agent the Team does not name: %b", rights)
	}
}
