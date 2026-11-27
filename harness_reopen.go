//go:build !ios_extension && !sidecar_http

// Reopening the runs a daemon held open (DESIGN-COMPUTE §7.7's resume, §20.7, §24.7; HARN-M11-08): every agent's run
// stays open until its agent closes it (§20.7), so a daemon that stops, or is stopped, leaves runs that were open, and
// at its restart takes each up again, read back from the record, under the same agent and run:
//
//	registry  each open run's agent, run, name, model, profile, tools, budget, parent and depth, one record a run in the
//	          Harness's sealed store, written when the agent starts and removed when it closes; it holds no item of
//	          the run, which the record holds
//	reopen    Harness.Reopen reads each registered run's nodes back (CTXH's SessionReader on a Sidecar), restores its
//	          session tree to the agent, its leaf the last node the run journaled on its path and its system node the
//	          system message in force there, and the run's taint and marks from its run file, which never lose a bit;
//	          the time the daemon was down is the run's downtime gap, never silence (D-HARN-3). A run whose nodes do
//	          not read back stays registered and is refused, so a later reopen can take it, and nothing of it is sent
//	inbox     a reopened agent's messages its runs have not taken wait in its inbox (§20.7's where agents wait row);
//	          taking them is SKILL's delivery into the Harness (AgentsClient.Untaken), which installs through
//	          HarnessSources.Untaken and is called once each agent is open again
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
)

var (
	// A registered run whose nodes do not read back: it stays registered for a later reopen.
	ErrHarnessReopenUnread = errors.New("the run's nodes did not read back, so it is not reopened yet")
)

// One open run as the registry keeps it.
type harnessOpenRun struct {
	AgentId      Id             `json:"agent_id"`
	RunId        Id             `json:"run_id"`
	Name         string         `json:"name"`
	Model        string         `json:"model"`
	Profile      HarnessProfile `json:"profile"`
	Tools        []string       `json:"tools,omitempty"`
	Budget       *HarnessBudget `json:"budget,omitempty"`
	MaxTurnCount int            `json:"max_turn_count,omitempty"`
	Parent       *Id            `json:"parent,omitempty"`
	Depth        int            `json:"depth,omitempty"`
}

// The registry of open runs: a sealed store's files on a Sidecar, or a test's.
type HarnessOpenRuns interface {
	Put(run *harnessOpenRun) error
	Remove(runId Id) error
	List() ([]*harnessOpenRun, error)
}

// A run's journaled nodes read back: CTXH's SessionReader on a Sidecar, or a test's. Each node's entry, trust and
// sender as the loop journaled them, in the order they were journaled.
type HarnessRunReader interface {
	Nodes(ctx context.Context, runId Id) ([]*HarnessJournalNode, error)
}

// A journal that takes a reopened run's nodes back: the session journal's, whose renders read them.
type harnessJournalReopener interface {
	Reopened(ctx context.Context, runId Id, nodes []*HarnessJournalNode) error
}

// SKILL's delivery of the messages a reopened agent's runs have not taken (§20.7), nil while none installs.
type HarnessUntaken interface {
	Take(ctx context.Context, agent HarnessAgent) error
}

// The registry as a sealed store's files, one a run, named by its id.
type harnessStoreOpenRuns struct {
	store func() (SidecarStore, error)

	stateLock sync.Mutex
}

// The prefix of a run's file name.
const harnessOpenRunPrefix = "run-"

// A run's file name.
func harnessOpenRunName(runId Id) string {
	return harnessOpenRunPrefix + runId.String()
}

// Writes run's record, replacing any before.
func (self *harnessStoreOpenRuns) Put(run *harnessOpenRun) error {
	encoded, err := json.Marshal(run)
	if err != nil {
		return err
	}
	store, err := self.store()
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	writer, err := store.Create(harnessOpenRunName(run.RunId))
	if err != nil {
		return err
	}
	if _, err := writer.Write(encoded); err != nil {
		writer.Close()
		return err
	}
	if err := writer.Commit(); err != nil {
		writer.Close()
		return err
	}
	return writer.Close()
}

// Removes a closed run's record; a record that is not there removes nothing.
func (self *harnessStoreOpenRuns) Remove(runId Id) error {
	store, err := self.store()
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return store.Remove(harnessOpenRunName(runId))
}

// Every record, in the store's order; one that does not read is left out.
func (self *harnessStoreOpenRuns) List() ([]*harnessOpenRun, error) {
	store, err := self.store()
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entries, err := store.List(harnessOpenRunPrefix)
	if err != nil {
		return nil, err
	}
	runs := []*harnessOpenRun{}
	for _, listed := range entries {
		reader, err := store.Open(listed.Name)
		if err != nil {
			continue
		}
		encoded, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			continue
		}
		run := &harnessOpenRun{}
		if json.Unmarshal(encoded, run) == nil && run.RunId != (Id{}) {
			runs = append(runs, run)
		}
	}
	return runs, nil
}

// Registers agent's run as open, where a registry is wired; a registry that does not write is logged, the run going on
// with a later reopen unable to take it.
func (self *Harness) openRunStarted(agent *harnessAgent) {
	if self.openRuns == nil {
		return
	}
	run := &harnessOpenRun{AgentId: agent.id, RunId: agent.run.Id(), Name: agent.name, Model: agent.currentModel(),
		Profile: agent.profile, Tools: slices.Clone(agent.spec.Tools), Budget: agent.spec.Budget, MaxTurnCount: agent.spec.MaxTurnCount,
		Depth: agent.depth}
	if agent.parent != nil {
		parentId := agent.parent.id
		run.Parent = &parentId
	}
	if err := self.openRuns.Put(run); err != nil {
		self.log.Warningf("[harness]an open run was not registered: %v", err)
	}
}

// Removes a closed agent's run from the registry.
func (self *Harness) openRunClosed(agent *harnessAgent) {
	if self.openRuns == nil {
		return
	}
	if err := self.openRuns.Remove(agent.run.Id()); err != nil {
		self.log.Warningf("[harness]a closed run was not removed from the registry: %v", err)
	}
}

// Takes up each run the registry holds that this Harness has not open, as the file header says: the agents it reopened,
// and the first error among those it could not, which stay registered.
func (self *Harness) Reopen(ctx context.Context) ([]HarnessAgent, error) {
	if self.openRuns == nil || self.runReader == nil {
		return nil, nil
	}
	runs, err := self.openRuns.List()
	if err != nil {
		return nil, err
	}
	reopened := []HarnessAgent{}
	var firstErr error
	for _, run := range runs {
		if _, open := self.agentOf(run.AgentId); open {
			continue
		}
		agent, err := self.reopen(ctx, run)
		if err != nil {
			self.log.Warningf("[harness]a run was not reopened: %v", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		reopened = append(reopened, agent)
	}
	for _, agent := range reopened {
		if self.untaken != nil {
			if err := self.untaken.Take(ctx, agent); err != nil {
				self.log.Warningf("[harness]a reopened agent's inbox was not read: %v", err)
			}
		}
	}
	return reopened, firstErr
}

// One run reopened under its agent and run: its nodes read back and restored, its downtime counted.
func (self *Harness) reopen(ctx context.Context, open *harnessOpenRun) (*harnessAgent, error) {
	if self.skill == nil {
		return nil, ErrHarnessSkillUnavailable
	}
	if self.journal == nil {
		return nil, ErrHarnessJournalUnavailable
	}
	nodes, err := self.runReader.Nodes(ctx, open.RunId)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHarnessReopenUnread, err)
	}
	keyNodes := map[string]*HarnessJournalNode{}
	order := []string{}
	for _, node := range nodes {
		if node == nil || node.Entry == nil {
			continue
		}
		keyNodes[node.Entry.Id()] = node
		order = append(order, node.Entry.Id())
	}
	// the leaf: the last node the run journaled that is no failed call's output beside the path
	leafKey := ""
	for i := len(order) - 1; 0 <= i; i-- {
		entry := keyNodes[order[i]].Entry
		if message := entry.Message(); message != nil && message.Role() == HarnessPiRoleAssistant &&
			(message.StopReason() == HarnessPiStopError || message.StopReason() == HarnessPiStopAborted) {
			continue
		}
		leafKey = order[i]
		break
	}
	path := []*HarnessJournalNode{}
	for key := leafKey; key != ""; {
		node, ok := keyNodes[key]
		if !ok {
			// a parent this run did not journal: a continuation's root, whose context the continued run holds
			break
		}
		path = append(path, node)
		key, _ = node.Entry.ParentId()
	}
	slices.Reverse(path)
	systemKey := ""
	for _, node := range path {
		if message := node.Entry.Message(); message != nil && message.Role() == HarnessPiRoleSystem {
			systemKey = node.Entry.Id()
		}
	}
	if leafKey == "" || systemKey == "" {
		return nil, fmt.Errorf("%w: no system message on the run's path", ErrHarnessReopenUnread)
	}
	profile := open.Profile
	if profile == "" {
		profile = HarnessProfileLocal
	}
	skillText, err := self.skill.Text(profile)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHarnessSkillUnavailable, err)
	}
	resolution, err := self.modelEntry(ctx, open.Model)
	if err != nil {
		return nil, err
	}
	toolSet, err := newHarnessToolSet(self.settings, self.tools, profile, open.Tools, skillText, harnessToolBudget(self.settings, resolution.Entry))
	if err != nil {
		return nil, err
	}
	run, err := NewHarnessRun(ctx, &HarnessRunArgs{RunId: open.RunId, AgentId: open.AgentId, Runs: self.runs, Gate: self.gate,
		Approvals: self.approvals, AutoVerdicts: self.autoVerdicts, Emit: self.Emit})
	if err != nil {
		return nil, err
	}
	if adder, ok := self.runs.(interface {
		AddGap(ctx context.Context, runId Id, code string) error
	}); ok {
		// the daemon was down: the run's downtime, never silence
		if err := adder.AddGap(ctx, open.RunId, RecordCoverageGapDowntime); err != nil {
			self.log.Warningf("[harness]a reopened run's downtime was not counted: %v", err)
		}
	}
	workspace, err := newHarnessWorkspace(self.workspaceArgs())
	if err != nil {
		return nil, err
	}
	spec := &HarnessAgentSpec{Name: open.Name, Model: resolution.Name, Profile: profile, Tools: open.Tools, Parent: open.Parent,
		Budget: open.Budget, MaxTurnCount: open.MaxTurnCount}
	maxTurns := spec.MaxTurnCount
	if maxTurns == 0 {
		maxTurns = self.settings.MaxTurnCount
	}
	lifeCtx, lifeCancel := context.WithCancel(context.Background())
	agent := &harnessAgent{
		harness:      self,
		id:           open.AgentId,
		name:         open.Name,
		spec:         spec,
		profile:      profile,
		run:          run,
		workspace:    workspace,
		toolSet:      toolSet,
		subscribers:  newHarnessSubscribers(self.settings, self.log),
		maxTurns:     maxTurns,
		lifeCtx:      lifeCtx,
		lifeCancel:   lifeCancel,
		model:        resolution.Name,
		idle:         make(chan struct{}),
		depth:        max(open.Depth, 1),
		systemNodeId: systemKey,
		leafNodeId:   leafKey,
	}
	close(agent.idle)
	if open.Parent != nil {
		agent.parent, _ = self.agentOf(*open.Parent)
	}
	systemSeen := false
	for _, node := range path {
		if node.Entry.Id() == systemKey {
			systemSeen = true
			continue
		}
		if systemSeen {
			agent.contextNodes = append(agent.contextNodes, &harnessContextNode{entry: node.Entry, tokens: agent.entryTokens(node.Entry)})
		}
	}
	if reopener, ok := self.journal.(harnessJournalReopener); ok {
		// the journal takes the run's nodes back, so the reopened run's next call renders from them
		if err := reopener.Reopened(ctx, open.RunId, nodes); err != nil {
			workspace.Remove()
			lifeCancel()
			return nil, err
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.agents[agent.id] = agent
	}()
	self.listenSupport()
	return agent, nil
}
