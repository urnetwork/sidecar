//go:build !ios_extension && !sidecar_http

// The person's own agent, me (DESIGN-COMPUTE §20.7's person in a thread, D-SKILL-9; SKILL-M11-02): the member's, not a
// device's. Its card names the member in place of a sidecar and an agent; any untagged consented device of the member
// writes it, and readers check it so (agents_reader.go); the first of the member's devices to run the default Harness
// creates it and its agent/me repo, and every other joins it rather than take §20.5's me-2, so a report to me shows on
// every device of the member. The person may pick another name, which is held to the same rules. Leases on the threads
// that name it are SKILL-M11-05's.
//
// On the compute legs. Safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// What registering the person's agent asks.
type AgentRegisterMeArgs struct {
	// The name the person picked, "" for me.
	Name string
	// The harness this device runs, the card's harness where this device creates it.
	Harness string
}

// What it got.
type AgentMeRegistration struct {
	Name     AgentName
	MemberId Id
	Card     *AgentCard
	// The card path's newest version as read or written, the next write's base.
	CardVersion  uint64
	AgentsRepoId Id
	// The me repo, agent/<name>, where the person's threads land.
	InboxRepoId Id
	// Whether this device created the card, rather than joining the member's.
	Created bool
}

// The person's own agent on this device: joined where the member's card stands, created with its repo where none
// does, and its repo made and named where an earlier device's creation was cut short. Only an untagged consented device
// of the member registers it (ErrAgentsNotWriter); a name another agent of the member holds is ErrAgentNameTaken.
func (self *AgentsClient) RegisterMe(ctx context.Context, args *AgentRegisterMeArgs) (*AgentMeRegistration, error) {
	if args == nil {
		args = &AgentRegisterMeArgs{}
	}
	place, err := self.place()
	if err != nil {
		return nil, err
	}
	if !place.authority.UntaggedConsented(place.sidecarId, place.memberId) {
		return nil, fmt.Errorf("%w: the person's agent is written by an untagged consented device of the member", ErrAgentsNotWriter)
	}
	name := AgentName(AgentNameMe)
	if args.Name != "" {
		if name, err = ParseAgentName(args.Name, self.settings); err != nil {
			return nil, err
		}
	}
	if err := self.ensureAgentsRepo(ctx, place); err != nil {
		return nil, err
	}
	registration := &AgentMeRegistration{Name: name, MemberId: place.memberId, AgentsRepoId: place.agentsRepoId}
	for range max(self.settings.CardWriteAttemptCount, 1) {
		read, err := self.readCard(ctx, place, name)
		if err != nil {
			return nil, err
		}
		if standing := read.Card; standing != nil {
			if !standing.Person() || standing.MemberId != place.memberId {
				return nil, fmt.Errorf("%w: %s is another agent's", ErrAgentNameTaken, name)
			}
			registration.Card, registration.CardVersion = standing, read.Newest
			break
		}
		card := &AgentCard{Name: name, MemberId: place.memberId, Harness: args.Harness, Started: self.clock.Now()}
		version, err := self.writeCard(ctx, place, card, read.Newest)
		if agentsWriteConflict(err) {
			// another of the member's devices created it first: join it
			continue
		}
		if err != nil {
			return nil, err
		}
		registration.Card, registration.CardVersion, registration.Created = card, version, true
		break
	}
	if registration.Card == nil {
		return nil, fmt.Errorf("%w: %s kept moving", ErrAgentsNotWriter, name)
	}
	if registration.Card.AgentRepo == (Id{}) || !place.authority.MemberAgentRepo(place.memberId, registration.Card.AgentRepo) {
		if err := self.ensureMeRepo(ctx, place, registration); err != nil {
			return nil, err
		}
	}
	registration.InboxRepoId = registration.Card.AgentRepo
	return registration, nil
}

// The me card's repo, made and named on the card by this device, where the card names none; a card another device
// named one on meanwhile is taken as it stands.
func (self *AgentsClient) ensureMeRepo(ctx context.Context, place *agentsPlace, registration *AgentMeRegistration) error {
	if self.args.CreateRepo == nil {
		return ErrAgentsUnavailable
	}
	memberId := place.memberId
	repoId, err := self.args.CreateRepo(ctx, &EvsCreateRepoArgs{Kind: protocol.RepoKind_REPO_KIND_AGENT, OwnerMemberId: &memberId})
	if err != nil {
		return fmt.Errorf("agents: the person's agent repo: %w", err)
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
			if read.Card == nil || !read.Card.Person() {
				return fmt.Errorf("%w: %s moved while its repo was made", ErrAgentsNotWriter, registration.Name)
			}
			registration.Card, registration.CardVersion = read.Card, read.Newest
			if read.Card.AgentRepo != (Id{}) && place.authority.MemberAgentRepo(place.memberId, read.Card.AgentRepo) {
				// another device named its repo first: that one is the member's me repo
				return nil
			}
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
