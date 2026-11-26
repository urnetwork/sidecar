//go:build !ios_extension && !sidecar_http

// The person's own agent (§20.7, D-SKILL-9): the member's first device creates me and its repo, every other joins it,
// a race between two leaves one card and no me-2, a tagged sidecar writes none, and no agent takes the name.

package sidecar

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

func TestMeJoinedAcrossDevices(t *testing.T) {
	world := newTestAgentCardsWorld(t)
	laptop, phone := world.client(world.laptop), world.client(world.phone)
	first, err := laptop.RegisterMe(world.ctx, &AgentRegisterMeArgs{Harness: "ur-harness 1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || first.Name != AgentNameMe || !first.Card.Person() || first.Card.MemberId != world.member ||
		first.InboxRepoId == (Id{}) || first.InboxRepoId != first.Card.AgentRepo {
		t.Fatalf("the first device's me: %+v", first)
	}
	joined, err := phone.RegisterMe(world.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if joined.Created || joined.InboxRepoId != first.InboxRepoId || joined.Card.MemberId != world.member {
		t.Fatalf("the second device's me: %+v", joined)
	}
	cards, err := phone.Cards(world.ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 1 || cards[0].Card.Name != AgentNameMe || cards[0].Host != "" {
		t.Fatalf("the member's cards: %d", len(cards))
	}
	agentRepos := 0
	for _, kind := range world.created {
		if kind == protocol.RepoKind_REPO_KIND_AGENT {
			agentRepos += 1
		}
	}
	if agentRepos != 1 {
		t.Fatalf("%d me repos", agentRepos)
	}
	// an agent asking for the name takes me-2, never the person's
	agent, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: AgentNameMe, Harness: "ur-harness 1.0"})
	if err != nil || agent.Name != "me-2" {
		t.Fatalf("an agent named me: %+v, %v", agent, err)
	}
	// a tagged sidecar writes no me
	if _, err := world.client(world.cloud).RegisterMe(world.ctx, nil); !errors.Is(err, ErrAgentsNotWriter) {
		t.Fatalf("a tagged sidecar's me: %v", err)
	}
}

func TestMeRaceLeavesOneCard(t *testing.T) {
	world := newTestAgentCardsWorld(t)
	laptop, phone := world.client(world.laptop), world.client(world.phone)
	if _, err := laptop.Register(world.ctx, &AgentRegisterArgs{Name: "setup", Harness: "ur-harness 1.0"}); err != nil {
		t.Fatal(err)
	}
	var first *AgentMeRegistration
	world.beforeWrite = func() {
		registration, err := laptop.RegisterMe(world.ctx, nil)
		if err != nil {
			t.Errorf("the laptop's me: %v", err)
		}
		first = registration
	}
	second, err := phone.RegisterMe(world.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first == nil || !first.Created || second.Created || second.InboxRepoId != first.InboxRepoId {
		t.Fatalf("the race: %+v and %+v", first, second)
	}
	if view, err := phone.Card(world.ctx, "me-2"); !errors.Is(err, ErrAgentCardAbsent) {
		t.Fatalf("a me-2 card: %+v, %v", view, err)
	}
}
