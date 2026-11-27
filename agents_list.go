//go:build !ios_extension && !sidecar_http

// What a member's agents are doing now (DESIGN-COMPUTE §20.8's first question, §20.10's agent_list, R-SKILL-6,
// D-SKILL-6; SKILL-M11-07): AgentsClient.List, the one read behind agent_list in the Harness and over MCP, ur agents ls
// and the sdk's Agents().List, over ReadAgents (agents_stub.go): every card of the member's agents repo with its status
// and newest summary, each held to its writer, in name order, from EVS alone.
//
//	model     for a model (AgentListArgs.ForModel), an agent whose card, status or summary a writer IC-12 does not
//	          trust wrote (a tainted run, a tagged sidecar, another member) is its stub alone: state, its age, model,
//	          host, run and parent, held to their grammars, between untrusted-data markers, which taint nothing; its
//	          text only with untrusted: include, which taints the run first (TaintFirst), write-ahead
//	person    a person's view (ur agents ls at a terminal, the app's cards) shows every agent's text, since it feeds no
//	          model; ur agents ls off a terminal reads as a model's, withholding it (§16.10's cli rule)
//	host      the client name the config gives a card's sidecar_id, never the card's own host text (§20.6)
//	retired   left out unless include_retired asks (§20.5)
//	cap       other writers' stubs at most SkillSettings.StubByteCount a result, the rest counted with a cursor
//
// In a Team network agent_list adds the directory's live runs for the member (directory_list, DESIGN §16.11), which
// the tools' AgentsToolsArgs.DirectoryRuns reads; until it is wired the list holds the member's cards alone.
//
// On the compute legs. Safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// What a list reads.
type AgentListArgs struct {
	// Retired cards too (§20.5's include_retired).
	IncludeRetired bool
	// The answer feeds a model: other writers' text as stubs unless Include.
	ForModel bool
	// untrusted: include: the text itself, once TaintFirst tainted the caller's run.
	Include    bool
	TaintFirst func(ctx context.Context) error
	// A previous answer's cursor: agents from that name on.
	Cursor string
}

// One agent's stub as a list carries it: identifier fields held to their grammars, (withheld) where one fails, and the
// writer the config names; Text is the stub as a model reads it, between untrusted-data markers.
type AgentListStub struct {
	Name   string `json:"name"`
	Host   string `json:"host"`
	Model  string `json:"model"`
	State  string `json:"state"`
	Age    int64  `json:"age_seconds"`
	Run    string `json:"run"`
	Parent string `json:"parent"`
	Writer string `json:"writer"`
	Text   string `json:"text"`
}

// One agent as a list shows it. For an untrusted writer's agent in a model's list only Name and Stub are set.
type AgentListEntry struct {
	Name string `json:"name"`
	// The person's own agent, the member's (§20.7).
	Person bool `json:"person,omitempty"`
	// The client name the config gives the card's sidecar, "" for none and for the person's me.
	Host    string `json:"host,omitempty"`
	Harness string `json:"harness,omitempty"`
	Model   string `json:"model,omitempty"`
	Parent  string `json:"parent,omitempty"`
	// The agent's own repo, "" for a child with none yet.
	AgentRepo string `json:"agent_repo,omitempty"`
	Started   string `json:"started,omitempty"`
	Retired   string `json:"retired,omitempty"`
	// The status: its state (offline past SkillSettings.OfflineAfter, "" for none written), how old it is, what the
	// agent does and its task, and its run.
	State      string `json:"state,omitempty"`
	StatusAge  int64  `json:"status_age_seconds,omitempty"`
	Activity   string `json:"activity,omitempty"`
	Task       string `json:"task,omitempty"`
	Run        string `json:"run,omitempty"`
	Updated    string `json:"updated,omitempty"`
	Summary    string `json:"summary,omitempty"`
	SummaryAge int64  `json:"summary_age_seconds,omitempty"`
	// agent or harness: who wrote the summary's words (§20.6).
	SummarySource string `json:"summary_source,omitempty"`
	// Whether every text of the agent is a writer's IC-12 trusts.
	Trusted bool `json:"trusted"`
	// A model's view of an untrusted writer's agent.
	Stub *AgentListStub `json:"stub,omitempty"`
}

// A list's answer.
type AgentList struct {
	Agents []*AgentListEntry `json:"agents"`
	// Agents past the stub cap, counted and not listed, and the cursor that lists them next; 0 and "" for none.
	More   int    `json:"more,omitempty"`
	Cursor string `json:"cursor,omitempty"`
	// How many agents' texts a model's list withheld as stubs.
	UntrustedWithheld int `json:"untrusted_withheld"`
	// The answer holds an untrusted writer's text: the caller's run was tainted first.
	Untrusted bool `json:"untrusted"`
	// The answer's time, which ages are counted to.
	Now time.Time `json:"-"`
}

// Seconds of d, rounded down, never negative.
func agentListSeconds(d time.Duration) int64 {
	return max(int64(d/time.Second), 0)
}

// One agent's entry from read, its text whole.
func agentListEntryOf(read *AgentRead, now time.Time) *AgentListEntry {
	card := read.Card.Card
	entry := &AgentListEntry{
		Name: string(card.Name), Person: card.Person(), Host: read.Card.Host, Harness: card.Harness, Model: card.Model,
		Parent: string(card.Parent), AgentRepo: agentCardIdText(card.AgentRepo), Started: agentCardTimeText(card.Started),
		Trusted: read.Trusted,
	}
	if card.IsRetired() {
		entry.Retired = agentCardTimeText(card.Retired)
	}
	if status := read.Status; status != nil && status.Status != nil {
		entry.State, entry.StatusAge = string(status.State), agentListSeconds(status.Age)
		entry.Activity, entry.Task = status.Status.Activity, status.Status.Task
		entry.Updated = agentCardTimeText(status.Time)
		if status.Status.RunId != (Id{}) {
			entry.Run = agentCardIdText(status.Status.RunId)
		}
	}
	if summary := read.Summary; summary != nil && summary.Summary != nil {
		entry.Summary, entry.SummarySource = summary.Summary.Text, string(summary.Summary.Source)
		entry.SummaryAge = agentListSeconds(now.Sub(summary.Time))
	}
	return entry
}

// The list's stub of stub.
func agentListStubOf(stub *AgentStub) *AgentListStub {
	return &AgentListStub{
		Name: stub.Name, Host: stub.Host, Model: stub.Model, State: stub.State, Age: agentListSeconds(stub.Age), Run: stub.Run,
		Parent: stub.Parent, Writer: stub.Writer, Text: stub.Text(),
	}
}

// Every agent of the member with its status and newest summary (see the file header).
func (self *AgentsClient) List(ctx context.Context, args *AgentListArgs) (*AgentList, error) {
	if args == nil {
		args = &AgentListArgs{}
	}
	cursor := AgentName("")
	if args.Cursor != "" {
		name, err := ParseAgentName(args.Cursor, self.settings)
		if err != nil {
			return nil, fmt.Errorf("%w: the cursor is no agent's name", errInvalidSettings)
		}
		cursor = name
	}
	read, err := self.ReadAgents(ctx, &AgentsReadArgs{
		IncludeRetired: args.IncludeRetired, ForModel: args.ForModel, Include: args.Include, TaintFirst: args.TaintFirst, Cursor: cursor,
	})
	if err != nil {
		return nil, err
	}
	now := self.clock.Now()
	list := &AgentList{Agents: []*AgentListEntry{}, More: read.More, Cursor: string(read.Cursor), Untrusted: read.Untrusted, Now: now}
	for _, agent := range read.Agents {
		if agent.Stub != nil {
			list.Agents = append(list.Agents, &AgentListEntry{Name: string(agent.Card.Name), Stub: agentListStubOf(agent.Stub)})
			list.UntrustedWithheld += 1
			continue
		}
		list.Agents = append(list.Agents, agentListEntryOf(agent, now))
	}
	return list, nil
}

// The list as a model reads it: a line per agent with its state, activity, task and status age, and its newest summary
// below, trusted writers' text as it stands and every other writer's as its stub between untrusted-data markers, or,
// once the run was tainted for it, its text between them, labeled with the agent. fence puts text between the markers.
func (self *AgentList) ModelText(fence func(sender string, text string) string) string {
	if len(self.Agents) == 0 {
		return "No agents are registered in your member's agents repo."
	}
	builder := strings.Builder{}
	for i, agent := range self.Agents {
		if 0 < i {
			builder.WriteString("\n")
		}
		if agent.Stub != nil {
			builder.WriteString(agent.Stub.Text)
			builder.WriteString("\n")
			continue
		}
		block := agentListEntryText(agent)
		if !agent.Trusted && fence != nil {
			block = fence("agent "+agent.Name, block)
		}
		builder.WriteString(block)
		builder.WriteString("\n")
	}
	if 0 < self.More {
		builder.WriteString(fmt.Sprintf("\n%d more agents written by untrusted writers are not listed: call agent_list with cursor %s.\n", self.More, self.Cursor))
	}
	if 0 < self.UntrustedWithheld {
		builder.WriteString(fmt.Sprintf("\n%d agents' text is withheld as stubs, since untrusted writers wrote it; untrusted: include returns it and taints your run.\n", self.UntrustedWithheld))
	}
	return strings.TrimRight(builder.String(), "\n")
}

// One agent's lines: its name, host, model and state, its activity and task, and its summary.
func agentListEntryText(agent *AgentListEntry) string {
	head := agent.Name
	details := []string{}
	if agent.Person {
		details = append(details, "your person")
	}
	if agent.Host != "" {
		details = append(details, "on "+agent.Host)
	}
	if agent.Model != "" {
		details = append(details, "model "+agent.Model)
	}
	switch {
	case agent.State == "":
		details = append(details, "no status yet")
	default:
		details = append(details, fmt.Sprintf("%s, status %s old", agent.State, time.Duration(agent.StatusAge)*time.Second))
	}
	if agent.Parent != "" {
		details = append(details, "launched by "+agent.Parent)
	}
	if agent.Retired != "" {
		details = append(details, "retired "+agent.Retired)
	}
	lines := []string{head + " (" + strings.Join(details, ", ") + ")"}
	if agent.Activity != "" {
		lines = append(lines, "  activity: "+agent.Activity)
	}
	if agent.Task != "" {
		lines = append(lines, "  task: "+agent.Task)
	}
	if agent.Summary != "" {
		source := ""
		if agent.SummarySource == string(AgentSummarySourceHarness) {
			source = ", written by the Harness"
		}
		lines = append(lines, fmt.Sprintf("  summary (%s old%s):", time.Duration(agent.SummaryAge)*time.Second, source))
		for _, line := range strings.Split(agent.Summary, "\n") {
			lines = append(lines, "    "+line)
		}
	}
	return strings.Join(lines, "\n")
}
