//go:build !ios_extension && !sidecar_http

// Registration (§20.5's steps 1 to 3): two devices' agents racing one name each learn the name they got, an agent
// registering again keeps its card and repo, a child started in its parent's Harness lands in its nearest ancestor's
// repo, a tagged sidecar waits for its member's agents repo, and nothing is read or written while agent_repos is off.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

func TestRegisterSuffixOnCollision(t *testing.T) {
	world := newTestAgentCardsWorld(t)
	laptop, phone := world.client(world.laptop), world.client(world.phone)
	// the member's agents repo stands first, so the two race on the card alone
	if _, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "setup", Harness: "ur-harness 1.0"}); err != nil {
		t.Fatal(err)
	}
	var first *AgentRegistration
	world.beforeWrite = func() {
		// the phone read cards/fix.json as absent; the laptop's agent claims it before the phone's write lands
		registration, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "fix", Harness: "ur-harness 1.0"})
		if err != nil {
			t.Errorf("the laptop's registration: %v", err)
		}
		first = registration
	}
	second, err := phone.Register(world.ctx, &AgentRegisterArgs{Name: "fix", Harness: "ur-harness 1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if first == nil || first.Name != "fix" || second.Name != "fix-2" || first.AgentId == second.AgentId {
		t.Fatalf("the race's names: %v and %v", first, second)
	}
	for _, registration := range []*AgentRegistration{first, second} {
		view, err := laptop.Card(world.ctx, registration.Name)
		if err != nil {
			t.Fatal(err)
		}
		if view.Card.AgentId != registration.AgentId || view.Card.AgentRepo == (Id{}) || view.Card.AgentRepo != registration.InboxRepoId ||
			!registration.Created {
			t.Errorf("%s's card: %+v", registration.Name, view.Card)
		}
	}
	if world.alarmCount() != 0 {
		t.Fatalf("%d alarms in an honest race", world.alarmCount())
	}
}

func TestRegisterAgainKeepsItsCardAndRepo(t *testing.T) {
	world := newTestAgentCardsWorld(t)
	laptop := world.client(world.laptop)
	first, err := laptop.Register(world.ctx, &AgentRegisterArgs{Task: "Fix the rate limiter in api", Harness: "ur-harness 1.0", Model: "local-gemma"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Name != "fix-the-rate-limiter" {
		t.Fatalf("the derived name %q", first.Name)
	}
	createdBefore, writesBefore := len(world.created), world.writeCount
	again, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "fix-the-rate-limiter", Harness: "ur-harness 1.0", Model: "local-gemma"})
	if err != nil {
		t.Fatal(err)
	}
	// one repo per durable agent_id, never per session (§20.14): nothing new is made or written
	if again.Name != first.Name || again.AgentId != first.AgentId || again.Created || again.Card.AgentRepo != first.Card.AgentRepo ||
		len(world.created) != createdBefore || world.writeCount != writesBefore {
		t.Fatalf("a registration again: %+v, %d repos and %d writes since", again, len(world.created)-createdBefore, world.writeCount-writesBefore)
	}
	// a session with another model rewrites its own card, keeping its repo and start
	moved, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "fix-the-rate-limiter", Harness: "ur-harness 1.0", Model: "chutes-model-tee-high"})
	if err != nil {
		t.Fatal(err)
	}
	if moved.Card.Model != "chutes-model-tee-high" || moved.Card.AgentRepo != first.Card.AgentRepo || !moved.Card.Started.Equal(first.Card.Started) {
		t.Fatalf("the rewritten card %+v", moved.Card)
	}
}

func TestRegisterChildUsesAncestorRepo(t *testing.T) {
	world := newTestAgentCardsWorld(t)
	laptop := world.client(world.laptop)
	parent, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "orchestrator", Harness: "ur-harness 1.0"})
	if err != nil {
		t.Fatal(err)
	}
	child, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "tests", Parent: "orchestrator", ChildOfHarness: true, Harness: "ur-harness 1.0"})
	if err != nil {
		t.Fatal(err)
	}
	grandchild, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "flaky", Parent: "tests", ChildOfHarness: true, Harness: "ur-harness 1.0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, registration := range []*AgentRegistration{child, grandchild} {
		if registration.Card.AgentRepo != (Id{}) || registration.InboxRepoId != parent.Card.AgentRepo {
			t.Errorf("%s: its own repo %s, its messages land in %s", registration.Name, registration.Card.AgentRepo, registration.InboxRepoId)
		}
		if repoId, err := laptop.AgentRepo(world.ctx, registration.Name); err != nil || repoId != parent.Card.AgentRepo {
			t.Errorf("%s's messages land in %s, %v", registration.Name, repoId, err)
		}
	}
	agentRepos := 0
	for _, kind := range world.created {
		if kind == protocol.RepoKind_REPO_KIND_AGENT {
			agentRepos += 1
		}
	}
	if agentRepos != 1 {
		t.Fatalf("%d agent repos for one parent and its children", agentRepos)
	}
	// a child that is no Harness's gets its own
	own, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "review", Parent: "orchestrator", Harness: "codex 0.80"})
	if err != nil || own.Card.AgentRepo == (Id{}) || own.InboxRepoId != own.Card.AgentRepo || own.Card.Parent != "orchestrator" {
		t.Fatalf("a launched agent outside the Harness: %+v, %v", own, err)
	}
}

func TestRegisterTaggedSidecarWaitsForTheAgentsRepo(t *testing.T) {
	world := newTestAgentCardsWorld(t)
	cloud := world.client(world.cloud)
	if _, err := cloud.Register(world.ctx, &AgentRegisterArgs{Name: "ci", Harness: "codex 0.80"}); !errors.Is(err, ErrAgentsRepoAbsent) {
		t.Fatalf("a tagged sidecar before its member's agents repo: %v", err)
	}
	if len(world.created) != 0 {
		t.Fatalf("a tagged sidecar created %v", world.created)
	}
	if _, err := world.client(world.laptop).Register(world.ctx, &AgentRegisterArgs{Name: "local", Harness: "ur-harness 1.0"}); err != nil {
		t.Fatal(err)
	}
	registration, err := cloud.Register(world.ctx, &AgentRegisterArgs{Name: "ci", Harness: "codex 0.80"})
	if err != nil {
		t.Fatal(err)
	}
	// its card is its own, read as its sidecar's; no agent repo a tagged creator can make
	view, err := world.client(world.phone).Card(world.ctx, "ci")
	if err != nil || view.Card.SidecarId != world.cloud || registration.Card.AgentRepo != (Id{}) || view.Host != "host of "+world.cloud.String()[:8] {
		t.Fatalf("the cloud agent's card %+v, %v", view, err)
	}
}

func TestRegisterRefusedWhileAgentReposOff(t *testing.T) {
	world := newTestAgentCardsWorld(t)
	world.featureOn = false
	laptop := world.client(world.laptop)
	_, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "fix", Harness: "ur-harness 1.0"})
	required := &AuthFeatureRequiredError{}
	if !errors.Is(err, ErrAgentReposOff) || !errors.As(err, &required) || !slices.Equal(required.AdminMemberIds, []Id{world.member}) {
		t.Fatalf("a registration while agent_repos is off: %v", err)
	}
	if _, err := laptop.RegisterMe(world.ctx, nil); !errors.Is(err, ErrAgentReposOff) {
		t.Fatalf("me while agent_repos is off: %v", err)
	}
	if _, err := laptop.Cards(world.ctx, true); !errors.Is(err, ErrAgentReposOff) {
		t.Fatalf("a listing while agent_repos is off: %v", err)
	}
	if len(world.created) != 0 || world.writeCount != 0 {
		t.Fatalf("%d repos made and %d writes while off", len(world.created), world.writeCount)
	}
	// a name out of the grammar is refused, never rewritten
	world.featureOn = true
	if _, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "Fix_It"}); !errors.Is(err, ErrAgentNameInvalid) {
		t.Fatalf("a name out of the grammar: %v", err)
	}
}

// An agent repo's RepoCreate files its name's keyed label under the network's K_label (QD-1434), the person's me repo
// labeled me alike, and a reader recomputing it finds the repo the member's agent/<name> and no other name's or
// member's; with no K_label the agent repo is not made, its card naming none, and no label is checked; while
// agent_repos is off the check answers ErrAgentReposOff.
func TestRegisterFilesAgentRepoLabel(t *testing.T) {
	world := newTestAgentCardsWorld(t)
	laptop := world.client(world.laptop)
	scout, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "scout", Harness: "ur-harness 1.0"})
	if err != nil {
		t.Fatal(err)
	}
	me, err := laptop.RegisterMe(world.ctx, &AgentRegisterMeArgs{Harness: "ur-harness 1.0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, registration := range []struct {
		name   AgentName
		repoId Id
	}{{name: scout.Name, repoId: scout.Card.AgentRepo}, {name: me.Name, repoId: me.Card.AgentRepo}} {
		if !bytes.Equal(world.agentRepoLabels[registration.repoId], world.labelKey.Mac(registration.name)) {
			t.Fatalf("%s's repo filed %x", registration.name, world.agentRepoLabels[registration.repoId])
		}
		labeled, err := laptop.AgentRepoLabeled(world.ctx, world.member, registration.name, registration.repoId)
		if err != nil || !labeled {
			t.Fatalf("%s's repo: %t, %v", registration.name, labeled, err)
		}
	}
	for _, c := range []struct {
		name     string
		memberId Id
		agent    AgentName
	}{
		{name: "another name", memberId: world.member, agent: "reviewer"},
		{name: "another member", memberId: world.otherMember, agent: scout.Name},
	} {
		if labeled, err := laptop.AgentRepoLabeled(world.ctx, c.memberId, c.agent, scout.Card.AgentRepo); err != nil || labeled {
			t.Errorf("%s: %t, %v", c.name, labeled, err)
		}
	}
	if _, err := laptop.AgentRepoLabeled(world.ctx, world.member, "Not A Name", scout.Card.AgentRepo); !errors.Is(err, ErrAgentNameInvalid) {
		t.Errorf("a name out of the grammar: %v", err)
	}

	// no K_label: no unlabeled agent repo is made, and no label is checked
	world.stateLock.Lock()
	world.labelKey = nil
	createdBefore := len(world.created)
	world.stateLock.Unlock()
	if _, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "builder", Harness: "ur-harness 1.0"}); !errors.Is(err, ErrAgentsUnavailable) {
		t.Fatalf("a registration with no label key: %v", err)
	}
	if len(world.created) != createdBefore {
		t.Fatalf("%d repos made with no label key", len(world.created)-createdBefore)
	}
	if view, err := laptop.Card(world.ctx, "builder"); err != nil || view.Card.AgentRepo != (Id{}) {
		t.Fatalf("builder's card: %+v, %v", view, err)
	}
	if _, err := laptop.AgentRepoLabeled(world.ctx, world.member, scout.Name, scout.Card.AgentRepo); !errors.Is(err, ErrAgentsUnavailable) {
		t.Fatalf("a check with no label key: %v", err)
	}
	world.stateLock.Lock()
	world.featureOn = false
	world.stateLock.Unlock()
	if _, err := laptop.AgentRepoLabeled(world.ctx, world.member, scout.Name, scout.Card.AgentRepo); !errors.Is(err, ErrAgentReposOff) {
		t.Fatalf("a check while agent_repos is off: %v", err)
	}
}
