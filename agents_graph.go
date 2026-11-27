//go:build !ios_extension && !sidecar_http

// The agent graph (DESIGN-COMPUTE §20.8's agent graph, CO-19, R-SKILL-6, R-SKILL-9; SKILL-M11-08): AgentsClient.Graph,
// what the apps' recURd view, ur.io's and the sdk's Agents().Graph draw, built on the device from the member's agents
// repo and the inboxes it can read, with no request beyond EVS's own sync, so no server learns the graph.
//
//	nodes     each card: its name, the host the config gives its sidecar (never the card's own host text), harness,
//	          model, status and newest summary, as the person's view reads them (AgentsClient.List); the person's me
//	          among them; retired agents only when asked, greyed (retired set)
//	launches  an edge from a card's parent to the card, both drawn
//	threads   an edge from a message's verified sender to its recipient, one a thread and direction, with its count
//	          and newest time, the person's me for the person's words; a message to every agent draws to "*"; a
//	          message whose sender does not hold is counted, not drawn, since its from is the writer's word
//	cap       at most SkillSettings.GraphEdgeMaxCount edges, launches first and then the newest conversations
//	agent     choosing an agent (AgentsGraphArgs.Agent) adds its summaries, each a version (§20.6), newest first, and
//	          its threads; its runs are HARN's and CTXH's SidecarHarness.Runs (§24.10), which the app reads beside
//
// The graph is a person's view: it feeds no model, so every agent's text is in it. A surface that may feed one (the
// daemon's agents.graph to a caller that is no person's terminal) asks for stubs (AgentsGraphArgs.ForModel), as
// agent_list does. An enclave's node with its agents inside it is SKILL-M14-01's.
//
// On the compute legs. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// The graph's edge kinds.
const (
	AgentsGraphEdgeLaunch       = "launch"
	AgentsGraphEdgeConversation = "conversation"
)

// What a graph reads.
type AgentsGraphArgs struct {
	// Retired agents too, greyed (§20.8: asked for past agents).
	Retired bool
	// One agent's view as well: its summaries and threads. Empty for none.
	Agent string
	// The answer may feed a model: other writers' text as stubs unless Include, which taints first.
	ForModel   bool
	Include    bool
	TaintFirst func(ctx context.Context) error
}

// One node: an agent as the list shows it.
type AgentsGraphNode struct {
	*AgentListEntry
}

// One edge.
type AgentsGraphEdge struct {
	// launch or conversation.
	Kind string `json:"kind"`
	// The parent or the sender, and the child or the recipient, "*" for every agent.
	From string `json:"from"`
	To   string `json:"to"`
	// A conversation's thread and the repo it lives in, its messages that way and the newest one's time.
	Thread   string `json:"thread,omitempty"`
	Repo     string `json:"repo,omitempty"`
	Messages int    `json:"messages,omitempty"`
	Latest   string `json:"latest,omitempty"`
	// Whether every message of the edge is a trusted writer's (§20.7's (a) or (b)).
	Trusted bool `json:"trusted"`
	latest  time.Time
}

// One summary version of an agent's view.
type AgentsGraphSummary struct {
	Version uint64 `json:"version"`
	Time    string `json:"time"`
	Source  string `json:"source"`
	Text    string `json:"text"`
	Trusted bool   `json:"trusted"`
	// Its text was withheld from a caller that may feed a model: an untrusted writer's run wrote it.
	Withheld bool `json:"withheld,omitempty"`
}

// One chosen agent's view: its summaries, each a version, newest first, and the threads it is in.
type AgentsGraphAgent struct {
	Name      string                `json:"name"`
	Summaries []*AgentsGraphSummary `json:"summaries"`
	// Its threads, by id, each with the repo it lives in.
	Threads []*AgentsGraphThread `json:"threads"`
}

// A thread an agent is in.
type AgentsGraphThread struct {
	Thread   string `json:"thread"`
	Repo     string `json:"repo"`
	Messages int    `json:"messages"`
	Closed   bool   `json:"closed,omitempty"`
}

// The graph.
type AgentsGraph struct {
	Nodes []*AgentsGraphNode `json:"nodes"`
	Edges []*AgentsGraphEdge `json:"edges"`
	// Edges past the cap, and messages whose sender did not hold, counted and not drawn.
	MoreEdges  int `json:"more_edges,omitempty"`
	Unverified int `json:"unverified,omitempty"`
	// The chosen agent's view, nil where none was asked.
	Agent *AgentsGraphAgent `json:"agent,omitempty"`
	// The graph holds an untrusted writer's text for a model: the caller's run was tainted first.
	Untrusted bool `json:"untrusted,omitempty"`
}

// The graph of the member's agents (see the file header).
func (self *AgentsClient) Graph(ctx context.Context, args *AgentsGraphArgs) (*AgentsGraph, error) {
	if args == nil {
		args = &AgentsGraphArgs{}
	}
	var chosen AgentName
	if args.Agent != "" {
		name, err := ParseAgentName(args.Agent, self.settings)
		if err != nil {
			return nil, err
		}
		chosen = name
	}
	list, err := self.List(ctx, &AgentListArgs{IncludeRetired: args.Retired, ForModel: args.ForModel, Include: args.Include, TaintFirst: args.TaintFirst})
	if err != nil {
		return nil, err
	}
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	graph := &AgentsGraph{Nodes: []*AgentsGraphNode{}, Edges: []*AgentsGraphEdge{}, Untrusted: list.Untrusted}
	drawn := map[string]bool{}
	person := AgentName("")
	for _, entry := range list.Agents {
		graph.Nodes = append(graph.Nodes, &AgentsGraphNode{AgentListEntry: entry})
		drawn[entry.Name] = true
		if entry.Person {
			person = AgentName(entry.Name)
		}
	}
	if person == "" {
		person = AgentNameMe
	}
	launches := []*AgentsGraphEdge{}
	for _, entry := range list.Agents {
		parent := entry.Parent
		if entry.Stub != nil {
			parent = entry.Stub.Parent
		}
		if parent != "" && drawn[parent] {
			// the parent is the child card's word, held to a name's grammar: trusted as the card is
			launches = append(launches, &AgentsGraphEdge{Kind: AgentsGraphEdgeLaunch, From: parent, To: entry.Name, Trusted: entry.Trusted})
		}
	}
	slices.SortFunc(launches, func(a *AgentsGraphEdge, b *AgentsGraphEdge) int {
		return strings.Compare(a.From+"\x00"+a.To, b.From+"\x00"+b.To)
	})
	conversations, agentThreads, unverified, err := self.graphConversations(ctx, place, person, drawn, chosen)
	if err != nil {
		return nil, err
	}
	graph.Unverified = unverified
	edges := append(launches, conversations...)
	if self.settings.GraphEdgeMaxCount < len(edges) {
		graph.MoreEdges = len(edges) - self.settings.GraphEdgeMaxCount
		edges = edges[:self.settings.GraphEdgeMaxCount]
	}
	graph.Edges = edges
	if chosen != "" {
		if !drawn[string(chosen)] {
			return nil, fmt.Errorf("%w: %s", ErrAgentCardAbsent, chosen)
		}
		agent := &AgentsGraphAgent{Name: string(chosen), Summaries: []*AgentsGraphSummary{}, Threads: agentThreads}
		if agent.Summaries, err = self.Summaries(ctx, chosen); err != nil {
			return nil, err
		}
		if args.ForModel && slices.ContainsFunc(agent.Summaries, func(summary *AgentsGraphSummary) bool { return !summary.Trusted }) {
			switch {
			case !args.Include:
				// a version an untrusted writer's run wrote reaches a model only as withheld
				for _, summary := range agent.Summaries {
					if !summary.Trusted {
						summary.Text, summary.Withheld = "", true
					}
				}
			case !graph.Untrusted:
				// the taint goes first, write-ahead: a failure returns nothing
				if args.TaintFirst == nil {
					return nil, ErrAgentsTaintFirst
				}
				if err := args.TaintFirst(ctx); err != nil {
					return nil, fmt.Errorf("%w: %w", ErrAgentsTaintFirst, err)
				}
				graph.Untrusted = true
			}
		}
		graph.Agent = agent
	}
	return graph, nil
}

// The conversations among the member's inboxes: an edge a thread and direction, newest first, and the chosen agent's
// threads; how many messages' senders did not hold.
func (self *AgentsClient) graphConversations(ctx context.Context, place *agentsPlace, person AgentName, drawn map[string]bool,
	chosen AgentName) ([]*AgentsGraphEdge, []*AgentsGraphThread, int, error) {
	repoIds, err := agentsMemberRepos(ctx, self, place)
	if err != nil {
		return nil, nil, 0, err
	}
	edges := []*AgentsGraphEdge{}
	threads := []*AgentsGraphThread{}
	unverified := 0
	for _, repoId := range repoIds {
		repo := self.args.Repo(repoId)
		if repo == nil {
			continue
		}
		threadIds, err := self.threadIds(ctx, repo)
		if err != nil {
			return nil, nil, 0, err
		}
		for _, threadId := range threadIds {
			thread, err := self.readThread(ctx, place, repoId, repo, threadId)
			if err != nil {
				return nil, nil, 0, err
			}
			byDirection := map[string]*AgentsGraphEdge{}
			involved := false
			for _, message := range thread.Messages {
				from := ""
				trust := message.Trust
				switch {
				case trust.Class == AgentMessageTrustPerson:
					from = string(person)
				case trust.Class == AgentMessageTrustSupport:
					continue
				case trust.FromVerified && trust.Sender.Name != "":
					from = string(trust.Sender.Name)
				default:
					unverified += 1
					continue
				}
				to := agentMessageToAll
				if message.Message.To != nil {
					to = string(message.Message.To.Name)
				}
				involved = involved || from == string(chosen) || to == string(chosen)
				if !drawn[from] || (to != agentMessageToAll && !drawn[to]) {
					continue
				}
				key := from + "\x00" + to
				edge := byDirection[key]
				if edge == nil {
					edge = &AgentsGraphEdge{Kind: AgentsGraphEdgeConversation, From: from, To: to, Thread: threadId.String(),
						Repo: agentCardIdText(repoId), Trusted: true}
					byDirection[key] = edge
				}
				edge.Messages += 1
				edge.Trusted = edge.Trusted && trust.Trusted()
				if message.Time.After(edge.latest) {
					edge.latest = message.Time
				}
			}
			for _, edge := range byDirection {
				edge.Latest = agentCardTimeText(edge.latest)
				edges = append(edges, edge)
			}
			if chosen != "" && involved {
				threads = append(threads, &AgentsGraphThread{Thread: threadId.String(), Repo: agentCardIdText(repoId),
					Messages: len(thread.Messages), Closed: thread.Closed})
			}
		}
	}
	slices.SortFunc(edges, func(a *AgentsGraphEdge, b *AgentsGraphEdge) int {
		if !a.latest.Equal(b.latest) {
			return b.latest.Compare(a.latest)
		}
		return strings.Compare(a.Thread+a.From+a.To, b.Thread+b.From+b.To)
	})
	return edges, threads, unverified, nil
}

// The summaries of the agent at name, each a version its writer pushed, newest first, at most
// SkillSettings.SummaryVersionListCount; a version another writer pushed is passed over, as the newest's read does.
func (self *AgentsClient) Summaries(ctx context.Context, name AgentName) ([]*AgentsGraphSummary, error) {
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	card, err := self.readCard(ctx, place, name)
	if err != nil {
		return nil, err
	}
	summaries := []*AgentsGraphSummary{}
	if card.Card == nil || card.Card.Person() {
		return summaries, nil
	}
	path := AgentSummaryPath(name)
	history, err := place.agentsRepo.History(ctx, &EvsReadArgs{Path: path})
	if errors.Is(err, ErrEvsPathAbsent) {
		return summaries, nil
	}
	if err != nil {
		return nil, err
	}
	for i, version := range history.Versions {
		if self.settings.SummaryHistoryMaxCount <= i || self.settings.SummaryVersionListCount <= len(summaries) {
			break
		}
		if version.Removed || version.Ignored || !agentCardWriter(place.authority, place.memberId, card.Card, version.SignerSidecarId) {
			self.alarm(place.agentsRepoId, version)
			continue
		}
		buffer := &agentCardBuffer{maxByteCount: self.settings.SummaryByteCount}
		info, err := place.agentsRepo.ReadHead(ctx, &EvsReadArgs{Path: path, Version: version.Version, Provenance: true}, buffer)
		if errors.Is(err, errAgentCardOversize) || errors.Is(err, ErrEvsPathAbsent) || errors.Is(err, ErrEvsCollected) {
			continue
		}
		if err != nil {
			return nil, err
		}
		summary, err := ParseAgentSummary(buffer.data, self.settings)
		if err != nil {
			self.alarm(place.agentsRepoId, version)
			continue
		}
		var provenance *EvsPushProvenance
		if info != nil {
			provenance = info.Provenance
		}
		summaries = append(summaries, &AgentsGraphSummary{
			Version: version.Version, Time: agentCardTimeText(version.Time), Source: string(summary.Source), Text: summary.Text,
			Trusted: agentsTextTrusted(place.authority, place.memberId, version.SignerSidecarId, provenance),
		})
	}
	return summaries, nil
}

// The thread_message card (§7.6): one message of a thread the person's view shows, with its sender and trust, which
// the threads view renders with a reply box; the terminal draws its sender, its trust and its subject.
const HarnessEventThreadMessage HarnessEventType = "thread_message"

// Registers the card with its terminal rendering.
func init() {
	RegisterHarnessEventType(HarnessEventThreadMessage, harnessRenderThreadMessage)
}

// The card of message, its fields the person's view's (AgentThreadMessage).
func NewHarnessThreadMessageEvent(message *AgentThreadMessage) (*HarnessEvent, error) {
	event := NewHarnessEvent(HarnessEventThreadMessage)
	for _, field := range []struct {
		name  string
		value any
	}{
		{name: "thread", value: message.ThreadHex}, {name: "id", value: message.IdHex}, {name: "repo", value: message.RepoId.String()},
		{name: "seq", value: message.Seq}, {name: "kind", value: message.Kind}, {name: "senderName", value: message.SenderName},
		{name: "senderPerson", value: message.SenderPerson}, {name: "trust", value: message.Trust}, {name: "toAll", value: message.ToAll},
		{name: "toName", value: message.ToName}, {name: "subject", value: message.Subject}, {name: "body", value: message.Body},
	} {
		if err := event.SetField(field.name, field.value); err != nil {
			return nil, err
		}
	}
	return event, nil
}

// The terminal's line of a thread_message card: its sender, its trust and its subject, the subject made safe.
func harnessRenderThreadMessage(event *HarnessEvent) ([]string, error) {
	thread, subject, sender, trust, kind := "", "", "", "", ""
	person := false
	if !event.Decode("thread", &thread) {
		return nil, fmt.Errorf("%w: a thread message names no thread", ErrHarnessEventInvalid)
	}
	event.Decode("subject", &subject)
	event.Decode("senderName", &sender)
	event.Decode("senderPerson", &person)
	event.Decode("trust", &trust)
	event.Decode("kind", &kind)
	switch {
	case person:
		sender = "you"
	case sender == "":
		sender = "an unverified sender"
	}
	line := fmt.Sprintf("%s from %s (%s) in thread %s", kind, sender, trust, thread)
	if subject != "" {
		line += ": " + HarnessSanitizeLine(subject)
	}
	return []string{line}, nil
}
