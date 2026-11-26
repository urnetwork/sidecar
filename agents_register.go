//go:build !ios_extension && !sidecar_http

// Registration (DESIGN-COMPUTE §20.5's steps 1 to 3, R-SKILL-2, R-SKILL-4; SKILL-M11-02): an agent's name, its card
// and its agent repo, at a session's start, through AgentsClient.Register:
//
//	agents    the member's agents repo, which the member's first device that runs the skill creates: an untagged
//	          consented device of the member, since the kind is owner-bound to its creator's member; any other sidecar
//	          answers ErrAgentsRepoAbsent until one has (§20.4)
//	1 name    the launch's (ur harness --agent, an app, the parent's agent_launch), else the harness config's default,
//	          else derived from the task's first words (DeriveAgentName); the person's me is never an agent's, so a
//	          registration asking for it takes me-2 (agents_me.go registers the person's)
//	2 card    cards/<name>.json by a create-only write (EvsPathWrite.IfVersion 0); a card that stands for another agent
//	          is taken, so it tries <name>-2, -3 up to SkillSettings.NameSuffixMax and the agent learns the name it
//	          got. The agent_id compared is this sidecar's for the candidate name, its label (Sidecar.ResolveAgentId),
//	          so two devices' agents racing one name each learn the name they got; a card that stands for this agent
//	          is its own, re-registered (un-retired where it had retired); one retired NameReuseAfter ago is taken
//	          over (§20.5's reuse)
//	3 repo    agent/<name>, kind agent, created when this agent_id's card names none, and the card rewritten to name
//	          it: one repo per durable agent_id, never per session (§20.14). A child agent_launch started in its
//	          parent's Harness gets none until its first agent_send (SKILL-M11-04), its card naming its parent, so
//	          its messages meanwhile land in its nearest ancestor's repo (AgentsClient.AgentRepo); a tagged sidecar,
//	          which no RepoCreate of the kind takes, is left without one until the enclaves feature's evs_member
//	          (CACL-M14-01)
//
// §20.5's step 4, the leases on agents:inbox/ and agent/<name>:inbox/, is SKILL-M11-05's (delivery).
//
// On the compute legs. Safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// What a registration asks.
type AgentRegisterArgs struct {
	// The launch's name, "" for none.
	Name string
	// The harness config's default name, "" for none.
	DefaultName string
	// The task, whose first words name an agent neither of the above names.
	Task string
	// The card's own fields: the harness and its version, the model's canonical name, and the writer's word for where
	// it runs.
	Harness string
	Model   string
	Host    string
	// The agent that launched this one, "" for none.
	Parent string
	// agent_launch started it in its parent's Harness: it gets no repo of its own until its first agent_send.
	ChildOfHarness bool
}

// What a registration got.
type AgentRegistration struct {
	// The name the agent got, which may carry a suffix.
	Name    AgentName
	AgentId Id
	// The card as written or as it stood, and the card path's newest version then, the next write's base.
	Card        *AgentCard
	CardVersion uint64
	// The member's agents repo, and where messages to the agent land: its own repo, or its nearest ancestor's.
	AgentsRepoId Id
	InboxRepoId  Id
	// Whether this registration created the card, rather than finding this agent's own.
	Created bool
}

// The first name registration tries: the launch's, else the harness config's, else the task's (step 1). A name given
// that is out of the grammar is refused, never rewritten.
func (self *AgentsClient) registerBaseName(args *AgentRegisterArgs) (AgentName, error) {
	for _, given := range []string{args.Name, args.DefaultName} {
		if given == "" {
			continue
		}
		return ParseAgentName(given, self.settings)
	}
	return DeriveAgentName(args.Task, self.settings), nil
}

// The member's agents repo, created where none stands by this sidecar when it is an untagged consented device of the
// member (§20.4), the state's first one in log order taken where another device's creation landed first.
func (self *AgentsClient) ensureAgentsRepo(ctx context.Context, place *agentsPlace) error {
	if place.agentsRepo != nil {
		return nil
	}
	if self.args.CreateRepo == nil || !place.authority.UntaggedConsented(place.sidecarId, place.memberId) {
		return ErrAgentsRepoAbsent
	}
	memberId := place.memberId
	createdId, err := self.args.CreateRepo(ctx, &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_AGENTS, OwnerMemberId: &memberId})
	if err != nil {
		return fmt.Errorf("agents: the member's agents repo: %w", err)
	}
	place.agentsRepoId = createdId
	if authority, err := self.args.Authority(); err == nil {
		if first, found := authority.AgentsRepo(memberId); found {
			place.authority, place.agentsRepoId = authority, first
		}
	}
	place.agentsRepo = self.args.Repo(place.agentsRepoId)
	if place.agentsRepo == nil {
		return ErrAgentsUnavailable
	}
	return nil
}

// §20.5's steps 1 to 3: see the file header. Writes nothing while the feature is off (ErrAgentReposOff).
func (self *AgentsClient) Register(ctx context.Context, args *AgentRegisterArgs) (*AgentRegistration, error) {
	if args == nil || self.args.AgentId == nil {
		return nil, fmt.Errorf("%w: a registration's args", errInvalidSettings)
	}
	place, err := self.place()
	if err != nil {
		return nil, err
	}
	base, err := self.registerBaseName(args)
	if err != nil {
		return nil, err
	}
	var parent AgentName
	if args.Parent != "" {
		if parent, err = ParseAgentName(args.Parent, self.settings); err != nil {
			return nil, err
		}
	}
	if err := self.ensureAgentsRepo(ctx, place); err != nil {
		return nil, err
	}
	registration, err := self.claimName(ctx, place, base, func(name AgentName, agentId Id) *AgentCard {
		return &AgentCard{
			Name: name, AgentId: agentId, SidecarId: place.sidecarId, Host: args.Host, Harness: args.Harness,
			Model: args.Model, Started: self.clock.Now(), Parent: parent,
		}
	})
	if err != nil {
		return nil, err
	}
	if registration.Card.AgentRepo == (Id{}) && !args.ChildOfHarness {
		if err := self.ensureAgentRepo(ctx, place, registration); err != nil {
			return nil, err
		}
	}
	registration.AgentsRepoId = place.agentsRepoId
	registration.InboxRepoId = registration.Card.AgentRepo
	if registration.InboxRepoId == (Id{}) {
		// a child with no repo yet: its nearest ancestor's, where one stands; none leaves it zero
		if repoId, err := self.AgentRepo(ctx, registration.Name); err == nil {
			registration.InboxRepoId = repoId
		}
	}
	return registration, nil
}

// Step 2: the first of base, base-2, ... up to NameSuffixMax that is free or this agent's own, its card written by
// newCard for a name and the agent_id this sidecar keeps for it. The person's me is skipped.
func (self *AgentsClient) claimName(ctx context.Context, place *agentsPlace, base AgentName,
	newCard func(name AgentName, agentId Id) *AgentCard) (*AgentRegistration, error) {
	for suffix := 1; suffix <= max(self.settings.NameSuffixMax, 1); suffix += 1 {
		name := base
		if 1 < suffix {
			name = AgentNameWithSuffix(base, suffix, self.settings)
		}
		if name == AgentNameMe {
			continue
		}
		registration, taken, err := self.claimOne(ctx, place, name, newCard)
		if err != nil {
			return nil, err
		}
		if !taken {
			return registration, nil
		}
	}
	return nil, fmt.Errorf("%w: %s and its suffixes to %d", ErrAgentNameTaken, base, self.settings.NameSuffixMax)
}

// One candidate name: the registration where it is free or this agent's own, else taken. A write another landed
// before reads the path again, up to CardWriteAttemptCount tries in all, then takes the name as taken.
func (self *AgentsClient) claimOne(ctx context.Context, place *agentsPlace, name AgentName,
	newCard func(name AgentName, agentId Id) *AgentCard) (*AgentRegistration, bool, error) {
	agentId, err := self.args.AgentId(string(name))
	if err != nil {
		return nil, false, err
	}
	for range max(self.settings.CardWriteAttemptCount, 1) {
		read, err := self.readCard(ctx, place, name)
		if err != nil {
			return nil, false, err
		}
		now := self.clock.Now()
		card := newCard(name, agentId)
		created := true
		switch standing := read.Card; {
		case standing == nil:
		case standing.AgentId == agentId && standing.SidecarId == place.sidecarId:
			// this agent's own card: kept, un-retired and with this session's harness and model
			created = false
			card.AgentRepo, card.Started = standing.AgentRepo, standing.Started
			if !standing.IsRetired() && standing.Harness == card.Harness && standing.Model == card.Model && standing.Host == card.Host &&
				standing.Parent == card.Parent {
				return &AgentRegistration{Name: name, AgentId: agentId, Card: standing, CardVersion: read.Newest}, false, nil
			}
		case self.reusable(standing, now):
			// a retired card past its reuse: another agent takes the name
		default:
			return nil, true, nil
		}
		version, err := self.writeCard(ctx, place, card, read.Newest)
		if agentsWriteConflict(err) {
			continue
		}
		if err != nil {
			return nil, false, err
		}
		return &AgentRegistration{Name: name, AgentId: agentId, Card: card, CardVersion: version, Created: created}, false, nil
	}
	return nil, true, nil
}

// Step 3: the agent's own repo, created and named on its card, where this sidecar may create one: an untagged consented
// device of the member. A tagged sidecar's agent is left with none.
func (self *AgentsClient) ensureAgentRepo(ctx context.Context, place *agentsPlace, registration *AgentRegistration) error {
	if self.args.CreateRepo == nil || !place.authority.UntaggedConsented(place.sidecarId, place.memberId) {
		return nil
	}
	memberId := place.memberId
	repoId, err := self.args.CreateRepo(ctx, &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_AGENT, OwnerMemberId: &memberId})
	if err != nil {
		return fmt.Errorf("agents: %s's agent repo: %w", registration.Name, err)
	}
	for range max(self.settings.CardWriteAttemptCount, 1) {
		card := *registration.Card
		card.AgentRepo = repoId
		version, err := self.writeCard(ctx, place, &card, registration.CardVersion)
		if agentsWriteConflict(err) {
			read, readErr := self.readCard(ctx, place, registration.Name)
			if readErr != nil {
				return readErr
			}
			if read.Card == nil || !agentCardSameAgent(read.Card, registration.Card) {
				return fmt.Errorf("%w: %s moved while its repo was made", ErrAgentsNotWriter, registration.Name)
			}
			registration.Card, registration.CardVersion = read.Card, read.Newest
			continue
		}
		if err != nil {
			return err
		}
		registration.Card, registration.CardVersion = &card, version
		return nil
	}
	return fmt.Errorf("%w: %s kept moving", ErrAgentsNotWriter, registration.Name)
}
