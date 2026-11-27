//go:build !ios_extension && !sidecar_http

// The device's sealed outbox of messages (DESIGN-COMPUTE §20.7's ids row, R2-05; SKILL-M11-04): a message is composed
// whole, its id included, and kept here from before its first write until that write lands, so a crash or a lost
// answer between composing and landing writes the same file again and never a second one. One file a message,
// outbox/<id>.json in the agents directory of the device's sealed store (AgentsClientArgs.Store), holding the repo it
// goes to, its bytes and the push's agent and tainted bit, so a retry after a restart seals what the first try would
// have. At most SkillSettings.OutboxMaxCount wait; past it a send is refused until some land. Nothing is created in the
// store until a message is composed, so a locked or failed sidecar's state directory stays empty.
//
// On the compute legs. Safe for concurrent use: each call reads and writes the store anew.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// The outbox's directory in the agents store, and an entry's suffix.
const (
	agentsOutboxDirectory  = "outbox"
	agentsOutboxFileSuffix = ".json"
)

var (
	// The device keeps no sealed store, so no message is composed: nothing was written.
	ErrAgentsOutboxUnavailable = errors.New("agents: the device's sealed store is not available, so no message is sent")
	// SkillSettings.OutboxMaxCount messages wait already.
	ErrAgentsOutboxFull = errors.New("agents: the outbox is full until some messages land")
)

// One message waiting to land.
type agentsOutboxEntry struct {
	RepoId  string `json:"repo"`
	Message []byte `json:"message"`
	AgentId string `json:"agent_id,omitempty"`
	Tainted bool   `json:"tainted"`
	// ms since the epoch
	ComposedMs int64 `json:"composed_ms"`
}

// The outbox's directory, nothing created until a file is.
func (self *AgentsClient) outbox() (SidecarStore, error) {
	if self.args.Store == nil {
		return nil, ErrAgentsOutboxUnavailable
	}
	store, err := self.args.Store()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAgentsOutboxUnavailable, err)
	}
	return store.Directory(agentsOutboxDirectory, "")
}

// Keeps a message, fsynced by the store's commit, before its first write.
func (self *AgentsClient) outboxPut(repoId Id, message *AgentMessage, data []byte, agentId *Id, tainted bool) error {
	store, err := self.outbox()
	if err != nil {
		return err
	}
	name := message.Id.String() + agentsOutboxFileSuffix
	entries, err := store.List("")
	if err != nil {
		return err
	}
	standing := false
	for _, entry := range entries {
		standing = standing || entry.Name == name
	}
	if !standing && self.settings.OutboxMaxCount <= len(entries) {
		return ErrAgentsOutboxFull
	}
	entry := &agentsOutboxEntry{RepoId: agentCardIdText(repoId), Message: data, Tainted: tainted, ComposedMs: self.clock.Now().UnixMilli()}
	if agentId != nil {
		entry.AgentId = agentCardIdText(*agentId)
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	writer, err := store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	return writer.Commit()
}

// Drops a message that landed.
func (self *AgentsClient) outboxRemove(id AgentMessageId) error {
	store, err := self.outbox()
	if err != nil {
		return err
	}
	return store.Remove(id.String() + agentsOutboxFileSuffix)
}

// One waiting message, read back.
type agentsOutboxMessage struct {
	repoId   Id
	message  *AgentMessage
	data     []byte
	agentId  *Id
	tainted  bool
	composed time.Time
}

// The messages waiting, in id order; an entry that does not read is left for the person to see, never sent.
func (self *AgentsClient) outboxList() ([]*agentsOutboxMessage, error) {
	store, err := self.outbox()
	if err != nil {
		return nil, err
	}
	entries, err := store.List("")
	if err != nil {
		return nil, err
	}
	waiting := []*agentsOutboxMessage{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name, agentsOutboxFileSuffix) {
			continue
		}
		reader, err := store.Open(entry.Name)
		if errors.Is(err, ErrSidecarStoreAbsent) {
			continue
		}
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			return nil, err
		}
		stored := &agentsOutboxEntry{}
		if json.Unmarshal(data, stored) != nil {
			continue
		}
		repoId, err := parseAgentCardId(stored.RepoId, "repo", false)
		if err != nil {
			continue
		}
		message, err := ParseAgentMessage(stored.Message, self.settings)
		if err != nil {
			continue
		}
		waiting = append(waiting, &agentsOutboxMessage{repoId: repoId, message: message, data: stored.Message,
			tainted: stored.Tainted, composed: time.UnixMilli(stored.ComposedMs).UTC()})
		if stored.AgentId != "" {
			if agentId, err := parseAgentCardId(stored.AgentId, "agent_id", false); err == nil {
				waiting[len(waiting)-1].agentId = &agentId
			}
		}
	}
	return waiting, nil
}

// Writes every message the outbox still holds, as a restart's first act: each lands once, a lost answer's included,
// and leaves the outbox. Answers the messages that landed; one that fails stays for the next flush.
func (self *AgentsClient) FlushOutbox(ctx context.Context) ([]*AgentMessage, error) {
	waiting, err := self.outboxList()
	if err != nil {
		return nil, err
	}
	landed := []*AgentMessage{}
	var firstErr error
	for _, entry := range waiting {
		repo := self.args.Repo(entry.repoId)
		if repo == nil {
			continue
		}
		if _, err := self.landMessage(ctx, entry.repoId, repo, entry.message, entry.data, entry.agentId, entry.tainted); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		landed = append(landed, entry.message)
	}
	return landed, firstErr
}
