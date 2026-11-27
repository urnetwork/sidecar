//go:build !ios_extension && !sidecar_http

// Other writers' text as stubs (DESIGN-COMPUTE §20.6, D-SKILL-6, IC-12, I-9, D-MCP-23; SKILL-M11-03). A card's,
// status's or summary's text is trusted only on IC-12's terms: its push signed by an untagged consented device of the
// member, sealing an untainted run's bit (agentsTextTrusted). The member's own enclave counts too from M14 (CO-43);
// until the enclaves feature an enclave's incarnation is no member device here, so its text reads untrusted. Any other
// writer's text, another member's agent or enclave, a tagged sidecar or a tainted run, reaches a model only as an
// AgentStub:
//
//	fields    the identifier fields alone, each held to its grammar or shown (withheld): the name and parent by §20.5's,
//	          the model by §6.3's (InferParseModelName), the state by its enum with its age, the run by an id's hex,
//	          and the host the client name the config gives the card's sidecar_id, never the card's own host text
//	markers   between the untrusted-data markers (HarnessUntrustedText), labeled with the writer the config names,
//	          which taints nothing
//	cap       one result carries at most SkillSettings.StubByteCount bytes of such fields; the agents past it are
//	          counted, not listed, and the result's cursor lists them next
//	include   the text itself only with untrusted: include, and only once the caller's TaintFirst has tainted its run,
//	          write-ahead; a TaintFirst that is nil or fails returns nothing (D-MCP-23, §16.11's rule)
//	person    a person's view (AgentsReadArgs.ForModel false) shows it all, since it feeds no model
//
// AgentsClient.ReadAgents is what agent_list, agent_find, ur agents ls and the sdk's Agents().List read (SKILL-M11-07,
// SKILL-M11-08): every card in name order with its status and newest summary, each held to its writer.
//
// On the compute legs. Package-level functions are safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// What a stub shows for a field out of its grammar (§20.6).
const AgentStubWithheld = "(withheld)"

// A read that would return untrusted text without a taint first.
var ErrAgentsTaintFirst = errors.New("agents: untrusted text is returned only once the run is tainted")

// Whether text a version carries is trusted on IC-12's terms: see the file header. A version whose provenance evs gave
// none of reads untrusted, as no untainted run's word.
func agentsTextTrusted(authority AgentsAuthority, memberId Id, signer Id, provenance *EvsPushProvenance) bool {
	if provenance == nil || provenance.Tainted || provenance.Imported || provenance.Refused {
		return false
	}
	return authority.UntaggedConsented(signer, memberId)
}

// One agent's identifier fields as a model may read another writer's: see the file header. Each field is its value
// held to its grammar or AgentStubWithheld.
type AgentStub struct {
	Name   string
	Host   string
	Model  string
	State  string
	Age    time.Duration
	Run    string
	Parent string
	// The writer the config names, which labels the markers.
	Writer string
}

// The stub's lines between the untrusted-data markers, labeled with its writer.
func (self *AgentStub) Text() string {
	lines := []string{
		"name: " + self.Name,
		"host: " + self.Host,
		"model: " + self.Model,
		"state: " + self.State,
	}
	if self.State != AgentStubWithheld && self.State != "" {
		lines[len(lines)-1] += fmt.Sprintf(", %s ago", self.Age.Truncate(time.Second))
	}
	lines = append(lines, "run: "+self.Run, "parent: "+self.Parent)
	return HarnessUntrustedText("agent card by "+self.Writer, strings.Join(lines, "\n"))
}

// A free field the config gives, such as a client name: printable ASCII within the card's field bound, else withheld.
func agentStubText(text string, settings *SkillSettings) string {
	if text == "" || checkAgentCardText(text, "text", settings) != nil {
		return AgentStubWithheld
	}
	return text
}

// The stub of read's agent: its card's fields held to their grammars, the host from the config, the status's state
// and run. writer labels it.
func (self *AgentsClient) stub(read *AgentRead, writer string) *AgentStub {
	card := read.Card.Card
	stub := &AgentStub{
		Name:   AgentStubWithheld,
		Host:   AgentStubWithheld,
		Model:  AgentStubWithheld,
		State:  AgentStubWithheld,
		Run:    AgentStubWithheld,
		Parent: "none",
		Writer: agentStubText(writer, self.settings),
	}
	if name, err := ParseAgentName(string(card.Name), self.settings); err == nil {
		stub.Name = string(name)
	}
	stub.Host = agentStubText(read.Card.Host, self.settings)
	if _, err := InferParseModelName(card.Model, self.inferSettings()); err == nil {
		stub.Model = card.Model
	}
	if card.Parent != "" {
		stub.Parent = AgentStubWithheld
		if parent, err := ParseAgentName(string(card.Parent), self.settings); err == nil {
			stub.Parent = string(parent)
		}
	}
	if status := read.Status; status != nil && status.Status != nil {
		if status.State.valid() {
			stub.State, stub.Age = string(status.State), status.Age
		}
		if status.Status.RunId != (Id{}) {
			stub.Run = agentCardIdText(status.Status.RunId)
		}
	}
	return stub
}

// The model names' grammar's settings.
func (self *AgentsClient) inferSettings() *InferSettings {
	if self.args.InferSettings != nil {
		return self.args.InferSettings
	}
	return DefaultInferSettings()
}

// The label a stub names a writer by: the client name the config gives it, else its id.
func (self *AgentsClient) writerLabel(sidecarId Id) string {
	if self.args.HostName != nil {
		if name := self.args.HostName(sidecarId); name != "" {
			return name
		}
	}
	return "sidecar " + sidecarId.String()
}

// What ReadAgents reads.
type AgentsReadArgs struct {
	// Retired cards too (§20.5's include_retired).
	IncludeRetired bool
	// The result feeds a model: other writers' text as stubs unless Include. False for a person's view, which shows
	// all of it.
	ForModel bool
	// untrusted: include: the text itself, once TaintFirst tainted the caller's run.
	Include    bool
	TaintFirst func(ctx context.Context) error
	// The name a previous result's cursor gave: agents from it on, by name.
	Cursor AgentName
}

// One agent as a read shows it.
type AgentRead struct {
	Card    *AgentCardView
	Status  *AgentStatusRead
	Summary *AgentSummaryRead
	// Whether every text the agent shows is a trusted writer's: its card's, its status's and its summary's.
	Trusted bool
	// For a model, an untrusted writer's agent's identifier fields; its card's, status's and summary's text are then
	// left out.
	Stub *AgentStub
}

// What ReadAgents found.
type AgentsRead struct {
	Agents []*AgentRead
	// Agents past the stub cap, counted and not listed, and the name a next read starts from; zero and "" for none.
	More   int
	Cursor AgentName
	// The result carries an untrusted writer's text: the caller's TaintFirst ran.
	Untrusted bool
}

// Every card in this member's agents repo with its status and newest summary, each held to its writer, in name order:
// see the file header.
func (self *AgentsClient) ReadAgents(ctx context.Context, args *AgentsReadArgs) (*AgentsRead, error) {
	if args == nil {
		args = &AgentsReadArgs{}
	}
	if args.ForModel && args.Include && args.TaintFirst == nil {
		return nil, ErrAgentsTaintFirst
	}
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	names, err := self.cardNames(ctx, place)
	if err != nil {
		return nil, err
	}
	now := self.clock.Now()
	alarm := func(version *EvsHistoryVersion) { self.alarm(place.agentsRepoId, version) }
	result := &AgentsRead{Agents: []*AgentRead{}}
	reads := []*AgentRead{}
	for _, name := range names {
		if args.Cursor != "" && name < args.Cursor {
			continue
		}
		card, err := self.readCard(ctx, place, name)
		if errors.Is(err, ErrAgentCardWithheld) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if card.Card == nil || (card.Card.IsRetired() && !args.IncludeRetired) {
			continue
		}
		read := &AgentRead{Card: self.view(card)}
		if read.Status, err = agentsReadStatus(ctx, place.agentsRepo, place.authority, place.memberId, card.Card, self.settings, now, alarm); err != nil {
			return nil, err
		}
		if read.Summary, err = agentsReadSummary(ctx, place.agentsRepo, place.authority, place.memberId, card.Card, self.settings, alarm); err != nil {
			return nil, err
		}
		read.Trusted = agentsTextTrusted(place.authority, place.memberId, card.WriterSidecarId, card.Provenance) &&
			(read.Status.Status == nil || read.Status.Trusted) && (read.Summary.Summary == nil || read.Summary.Trusted)
		reads = append(reads, read)
	}
	if !args.ForModel {
		result.Agents = reads
		return result, nil
	}
	if args.Include {
		untrusted := false
		for _, read := range reads {
			untrusted = untrusted || !read.Trusted
		}
		if untrusted {
			// the taint goes first, write-ahead: a failure returns nothing
			if err := args.TaintFirst(ctx); err != nil {
				return nil, fmt.Errorf("%w: %w", ErrAgentsTaintFirst, err)
			}
			result.Untrusted = true
		}
		result.Agents = reads
		return result, nil
	}
	stubBytes := 0
	for i, read := range reads {
		if read.Trusted {
			result.Agents = append(result.Agents, read)
			continue
		}
		writer := read.Card.WriterSidecarId
		if read.Status.Status != nil && !read.Status.Trusted {
			writer = read.Status.WriterSidecarId
		} else if read.Summary.Summary != nil && !read.Summary.Trusted {
			writer = read.Summary.WriterSidecarId
		}
		stub := self.stub(read, self.writerLabel(writer))
		if self.settings.StubByteCount < stubBytes+len(stub.Text()) {
			// past the cap: counted, and listed from here by the next read
			result.More = len(reads) - i
			result.Cursor = read.Card.Name
			break
		}
		stubBytes += len(stub.Text())
		result.Agents = append(result.Agents, &AgentRead{Card: &AgentCardView{AgentCardRead: &AgentCardRead{Name: read.Card.Name}}, Stub: stub})
	}
	return result, nil
}
