//go:build !ios_extension && !sidecar_http

// Support notices in an agent's inbox (DESIGN-COMPUTE §28.9's inbox row, §20.7's support row, CO-45; SKILL-M11-05):
// for an agent whose run is closed, whose host is down or that runs on another device, the receiving device writes the
// support client's update into the agent's own agent repo (a child with none yet, its nearest ancestor's) as a message
// of kind support, from {"support": "urnetwork"}, bound to no run, its thread derived from the product and entry and
// its id from the product, entry and seq (AgentSupportThreadId, AgentSupportNoticeId), so every device of the member
// writes the one create-only path, and a device that finds it written by another device of the member counts it
// written. It carries the update's enumerated fields alone, never a reply's text, so taking it taints nothing; the
// Harness takes it when the run reopens, as it takes any thread's message (agents_deliver.go), and a wake for it counts
// support as one sender (Q-SUP-11).
//
// SupportNotices writes one for each agent an update names whose run is not open here, off the support client's
// listener goroutine through a queue of its own, so the support loop never waits on a write. It is dark with the rest
// of the support skill: a Sidecar's support client exists only while SupportSettings.ServiceEnabled is on.
//
// On the compute legs. Safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"
	"sync"
)

// The notice of update for the agent at name: see the file header.
func (self *AgentsClient) WriteSupportNotice(ctx context.Context, name AgentName, update *SupportUpdate) (*AgentSendResult, error) {
	if update == nil || update.Product != SupportProductUrnetwork || update.Entry == "" {
		return nil, fmt.Errorf("%w: a support notice names its product and entry", errInvalidSettings)
	}
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	read, err := self.readCard(ctx, place, name)
	if err != nil {
		return nil, err
	}
	if read.Card == nil || read.Card.IsRetired() {
		return nil, fmt.Errorf("%w: %s", ErrAgentCardAbsent, name)
	}
	repoId, err := self.AgentRepo(ctx, name)
	if err != nil {
		return nil, err
	}
	message := &AgentMessage{
		Id:      AgentSupportNoticeId(update.Product, update.Entry, update.Seq),
		Thread:  AgentSupportThreadId(update.Product, update.Entry),
		Seq:     uint64(max(update.Seq, 1)),
		From:    AgentMessageFrom{Support: true},
		To:      &AgentAddress{MemberId: place.memberId, Name: name, RepoId: read.Card.AgentRepo},
		Kind:    AgentMessageKindSupport,
		Created: self.clock.Now(),
		Support: &AgentMessageSupport{
			Product: update.Product, Entry: update.Entry, Seq: update.Seq, Type: update.Type, Status: update.Status,
			FixedIn: update.FixedIn, Final: update.Final,
		},
	}
	data, err := EncodeAgentMessage(message, self.settings)
	if err != nil {
		return nil, err
	}
	repo := self.args.Repo(repoId)
	if repo == nil {
		return nil, ErrAgentsUnavailable
	}
	if err := self.outboxPut(repoId, message, data, nil, false); err != nil {
		return nil, err
	}
	duplicate, err := self.landMessage(ctx, repoId, repo, message, data, nil, false)
	if err != nil {
		return nil, err
	}
	return &AgentSendResult{Message: message, RepoId: repoId, Path: message.Path(), Duplicate: duplicate}, nil
}

// Whether first, the path's first version, is the same notice another device of the member wrote: a support notice
// of the same product, entry and seq, signed by a device of the member.
func (self *AgentsClient) sameSupportNotice(first *agentMessageFirst, message *AgentMessage) bool {
	if message.Kind != AgentMessageKindSupport || message.Support == nil {
		return false
	}
	standing, err := ParseAgentMessage(first.data, self.settings)
	if err != nil || standing.Kind != AgentMessageKindSupport || standing.Support == nil {
		return false
	}
	authority, err := self.args.Authority()
	if err != nil {
		return false
	}
	memberId, found := authority.MemberOf(first.version.SignerSidecarId)
	ownMember, ownFound := Id{}, false
	if self.args.Self != nil {
		if sidecarId, err := self.args.Self(); err == nil {
			ownMember, ownFound = authority.MemberOf(sidecarId)
		}
	}
	return found && ownFound && memberId == ownMember && standing.Id == message.Id && standing.Thread == message.Thread &&
		*standing.Support == *message.Support
}

// The support client's updates written as notices for the agents they name whose run is not open here (see the file
// header): runOpen nil writes one for each. The answer stops it, waiting for a write in flight.
func (self *AgentsClient) SupportNotices(support *SupportClient, runOpen func(name AgentName) bool) func() {
	ctx, cancel := context.WithCancel(context.Background())
	queue := make(chan *SupportUpdate, max(self.settings.OutboxMaxCount, 1))
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case update := <-queue:
				for _, agent := range update.Agents {
					name, err := ParseAgentName(agent, self.settings)
					if err != nil || (runOpen != nil && runOpen(name)) {
						continue
					}
					self.WriteSupportNotice(ctx, name, update)
				}
			}
		}
	}()
	remove := support.AddListener(func(update *SupportUpdate) {
		copied := *update
		select {
		case queue <- &copied:
		default:
			// past the queue the update is dropped here; the conversation keeps it, and the next update's notice reads it
		}
	})
	stopOnce := sync.Once{}
	return func() {
		stopOnce.Do(func() {
			remove()
			cancel()
			<-done
		})
	}
}
