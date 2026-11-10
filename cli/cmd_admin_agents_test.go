// ur admin agents and ur admin delegations (TEAM-M2-18): the plan printed to the terminal naming the agent, the
// Delegation's shared key and its admission authority apart before the person answers; a yes acts and a no does not;
// a pipe with no /dev/tty acts on nothing; and the act methods Confirm ones, so MCP and unconfirmed calls never reach
// them (FS-82).

package main

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A daemon target whose agents and Delegations a test sets.
type testUrAdminTarget struct {
	testUrDaemonTarget
	plan        *sidecar.AgentRevokePlan
	acts        []string
	delegations []*sidecar.DelegationState
	revokes     []string
}

func (self *testUrAdminTarget) planAgentAct(agentId sidecar.Id, act sidecar.AgentAct, compromise bool, sinceN uint64) (*sidecar.AgentRevokePlan, error) {
	plan := *self.plan
	plan.Act = act
	return &plan, nil
}

func (self *testUrAdminTarget) signAgentAct(ctx context.Context, agentId sidecar.Id, act sidecar.AgentAct, compromise bool, sinceN uint64) error {
	self.acts = append(self.acts, string(act)+" "+agentId.String())
	return nil
}

func (self *testUrAdminTarget) resolveAgent(nameOrId string) (sidecar.Id, error) {
	return sidecar.ParseId(nameOrId)
}

func (self *testUrAdminTarget) delegationStates() ([]*sidecar.DelegationState, error) {
	return self.delegations, nil
}

func (self *testUrAdminTarget) revokeDelegation(ctx context.Context, delegationId []byte, leaked bool, sinceN uint64, since time.Time) error {
	self.revokes = append(self.revokes, hex.EncodeToString(delegationId))
	return nil
}

// FS-102 part 2's plan through ur: a Suspend of a Delegation's agent names the key as retiring with the agent that then
// reads by its own ReaderWrap and the repo that rotates, the Delegation as still admitting with the command that ends
// it; only a yes on the terminal acts.
func TestAdminAgentsPrintsThePlanAndActsOnAYes(t *testing.T) {
	agentId, otherId, repoId := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	delegationId := make([]byte, 32)
	delegationId[0] = 0xd
	target := &testUrAdminTarget{plan: &sidecar.AgentRevokePlan{
		AgentId: agentId,
		TagIds:  []sidecar.Id{sidecar.NewId()},
		Delegation: &sidecar.AgentDelegationPlan{
			DelegationId:     delegationId,
			KeyRetires:       true,
			AgentsOnOwnWraps: []sidecar.Id{otherId},
			ReposRotating:    []sidecar.Id{repoId},
			AdmissionsLeft:   3,
			NotAfter:         time.UnixMilli(1_900_000_000_000),
		},
		Offer: "ur admin delegations revoke " + hex.EncodeToString(delegationId) + " [--leaked --since <time|position>]",
	}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)

	// no terminal: nothing is acted on
	if code := cli.main(context.Background(), []string{"ur", "admin", "agents", "suspend", agentId.String()}); code == urExitOk || len(target.acts) != 0 {
		t.Fatalf("with no terminal: exit %d, %v", code, target.acts)
	}

	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "admin", "agents", "suspend", agentId.String()}); code != urExitOk || len(target.acts) != 0 {
		t.Fatalf("a no acted: exit %d, %v", code, target.acts)
	}
	shown := tty.written.String()
	for _, want := range []string{agentId.String(), "shared reader key retires", otherId.String(), repoId.String(), "still admits, 3 admission(s) left", "ur admin delegations revoke"} {
		if !strings.Contains(shown, want) {
			t.Errorf("the plan does not show %q:\n%s", want, shown)
		}
	}
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), []string{"ur", "admin", "agents", "suspend", agentId.String()}); code != urExitOk || len(target.acts) != 1 ||
		target.acts[0] != "suspend "+agentId.String() {
		t.Fatalf("a yes: exit %d, %v: %s", code, target.acts, stdout.String())
	}
}

// The act methods are Confirm methods: only a confirmed control call runs them, never MCP or an unconfirmed call
// (FS-82); the plan and list methods are not.
func TestAdminActMethodsAreConfirmOnly(t *testing.T) {
	target := &testUrAdminTarget{}
	methods := append(urAdminAgentMethods(target), urAdminDelegationMethods(target)...)
	confirmed := map[string]bool{}
	for _, method := range methods {
		confirmed[method.Name] = method.Confirm
	}
	if !confirmed[urMethodAdminAgentAct] || !confirmed[urMethodAdminDelegationRevoke] {
		t.Error("an act runs unconfirmed")
	}
	if confirmed[urMethodAdminAgentPlan] || confirmed[urMethodAdminDelegations] {
		t.Error("a read asks for a confirmation")
	}
	if methods := urAdminAgentMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no Sidecar serves the agents methods")
	}
}

// ur admin delegations lists each Delegation's key and authority; a revoke takes --since only with --leaked.
func TestAdminDelegationsListsAndRevokes(t *testing.T) {
	delegationId := make([]byte, 32)
	delegationId[0] = 0xa
	target := &testUrAdminTarget{delegations: []*sidecar.DelegationState{{DelegationId: delegationId, At: 7, AdmissionsLeft: 2, AgentIds: []sidecar.Id{sidecar.NewId()}}}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "admin", "delegations"}); code != urExitOk || !strings.Contains(stdout.String(), hex.EncodeToString(delegationId)) ||
		!strings.Contains(stdout.String(), "admits 2 more") {
		t.Fatalf("the list: exit %d: %s", code, stdout.String())
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "admin", "delegations", "revoke", hex.EncodeToString(delegationId), "--since", "9"}); code == urExitOk {
		t.Error("--since without --leaked")
	}
	if code := cli.main(context.Background(), []string{"ur", "admin", "delegations", "revoke", hex.EncodeToString(delegationId), "--leaked", "--since", "9"}); code != urExitOk ||
		len(target.revokes) != 1 {
		t.Fatalf("a leaked bundle's revoke: exit %d, %v", code, target.revokes)
	}
}

// A daemon target whose indexer designations a test reads.
type testUrIndexerTarget struct {
	testUrDaemonTarget
	designated [][]protocol.IndexerService
}

func (self *testUrIndexerTarget) listIndexers() ([]sidecar.ConfigIndexer, error) {
	return nil, nil
}

func (self *testUrIndexerTarget) designateIndexer(ctx context.Context, scope protocol.IndexerScope, services []protocol.IndexerService) error {
	self.designated = append(self.designated, services)
	return nil
}

func (self *testUrIndexerTarget) retireIndexerScope(ctx context.Context, scope protocol.IndexerScope) error {
	return nil
}

// ur indexer add takes --services as mail, mirror and search, refuses another word before asking, and signs only on a
// yes; its designate method is a Confirm one.
func TestIndexerAddConfirmsAndNamesItsServices(t *testing.T) {
	target := &testUrIndexerTarget{}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, _ := newTestUrCli(daemon.socketPath)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "indexer", "add", "--services=mail,files"}); code == urExitOk || len(target.designated) != 0 {
		t.Fatalf("an unknown service: exit %d, %v", code, target.designated)
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "indexer", "add", "--services=search"}); code != urExitOk || len(target.designated) != 0 {
		t.Fatalf("a no: exit %d, %v", code, target.designated)
	}
	for _, method := range urIndexerDesignationMethods(target) {
		if method.Name != urMethodIndexerList && !method.Confirm {
			t.Errorf("%s runs unconfirmed", method.Name)
		}
	}
}

// --rules' JSON: kinds by name, on and off, and every reader's checks.
func TestVersioningRulesParse(t *testing.T) {
	rules, err := urParseVersioningRules(`{"rules": [{"kinds": ["general"], "path_glob": "build/**", "size_above_bytes": 1048576, "versioning": "off"}]}`)
	if err != nil || len(rules.GetRules()) != 1 || rules.GetRules()[0].GetVersioning() != protocol.VersioningMode_VERSIONING_MODE_OFF ||
		rules.GetRules()[0].GetKinds()[0] != uint32(protocol.RepoKind_REPO_KIND_GENERAL) {
		t.Fatalf("the rules: %v %v", rules, err)
	}
	if text := urFormatVersioningRules(rules); !strings.Contains(text, `"kinds":["general"]`) || !strings.Contains(text, `"versioning":"off"`) {
		t.Errorf("formatted: %s", text)
	}
	for _, bad := range []string{`{"rules": [{"versioning": "sometimes"}]}`, `{"rules": [{"kinds": ["nothing"], "versioning": "on"}]}`, `{"rules": [{"path_glob": "[", "versioning": "on"}]}`} {
		if _, err := urParseVersioningRules(bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}
