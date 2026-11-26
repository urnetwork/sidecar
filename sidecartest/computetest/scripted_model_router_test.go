//go:build sidecar_testhooks

package computetest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The context journal a Harness runs on here, as HARN-M11-08 wires CTXH's on a Sidecar: each node kept in memory under
// its Pi entry id with the item sidecar.SessionNodeOfHarness gives it, and each call rendered from its path by
// harness-1, CTXH's own renderer, so the request the model records is the one the Harness's renderer sends.
type scriptedTestJournal struct {
	stateLock  sync.Mutex
	runIdNodes map[sidecar.Id]map[string]*scriptedTestNode
	turnEnds   int
}

// One journaled node: its parent's key and what harness-1 renders it from.
type scriptedTestNode struct {
	parentKey string
	render    *sidecar.SessionRenderNode
}

func newScriptedTestJournal() *scriptedTestJournal {
	return &scriptedTestJournal{runIdNodes: map[sidecar.Id]map[string]*scriptedTestNode{}}
}

// Keeps node under its key, its item as the session journal would record it.
func (self *scriptedTestJournal) Journal(ctx context.Context, node *sidecar.HarnessJournalNode) error {
	_, sessionNode, err := sidecar.SessionNodeOfHarness(node, nil)
	if err != nil {
		return err
	}
	item, err := sidecar.CanonicalJson(sessionNode.Item)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	nodes, ok := self.runIdNodes[node.RunId]
	if !ok {
		nodes = map[string]*scriptedTestNode{}
		self.runIdNodes[node.RunId] = nodes
	}
	if _, journaled := nodes[sessionNode.Key]; journaled {
		return fmt.Errorf("node %s journaled twice", sessionNode.Key)
	}
	nodes[sessionNode.Key] = &scriptedTestNode{
		parentKey: sessionNode.ParentKey,
		render:    &sidecar.SessionRenderNode{NodeId: sidecar.NewId(), Type: sessionNode.Type, Item: item},
	}
	return nil
}

// The call's request, by harness-1 from the path ending at its input node.
func (self *scriptedTestJournal) Render(ctx context.Context, args *sidecar.HarnessRenderArgs) (*sidecar.InferRequest, error) {
	renderer, err := sidecar.SessionRendererOf(sidecar.SessionRendererHarness1)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	nodes := self.runIdNodes[args.RunId]
	path := []*sidecar.SessionRenderNode{}
	for key := args.InputNodeId; key != ""; {
		node, ok := nodes[key]
		if !ok {
			return nil, fmt.Errorf("node %s is not journaled", key)
		}
		path = append([]*sidecar.SessionRenderNode{node.render}, path...)
		key = node.parentKey
	}
	var systemNodeId *sidecar.Id
	if args.SystemNodeId != "" {
		system, ok := nodes[args.SystemNodeId]
		if !ok {
			return nil, fmt.Errorf("system node %s is not journaled", args.SystemNodeId)
		}
		systemNodeId = &system.render.NodeId
	}
	nodeOf := func(nodeId sidecar.Id) (*sidecar.SessionRenderNode, bool) {
		for _, node := range nodes {
			if node.render.NodeId == nodeId {
				return node.render, true
			}
		}
		return nil, false
	}
	input, err := renderer.Context(path, systemNodeId, nodeOf)
	if err != nil {
		return nil, err
	}
	params := map[string]any{"model": args.Model}
	if 0 < args.MaxOutput {
		params["max_output"] = args.MaxOutput
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	if input.Params, err = sidecar.CanonicalJson(encoded); err != nil {
		return nil, err
	}
	return sidecar.SessionRenderRequest(renderer, input)
}

// Counts a turn's end.
func (self *scriptedTestJournal) TurnEnd(ctx context.Context, runId sidecar.Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.turnEnds += 1
	return nil
}

// The recURd skill as a test fixes it: its text, and the name each agent asks for.
type scriptedTestSkill struct {
	text string
}

func (self *scriptedTestSkill) Text(profile sidecar.HarnessProfile) (string, error) {
	return self.text, nil
}

func (self *scriptedTestSkill) Register(ctx context.Context, registration *sidecar.HarnessAgentRegistration) (string, error) {
	if registration.Name == "" {
		return "agent", nil
	}
	return registration.Name, nil
}

// A read tool answering every lookup the same, recording each call's arguments.
type scriptedTestLookup struct {
	stateLock sync.Mutex
	argsTexts []string
}

func (self *scriptedTestLookup) Name() string        { return "lookup" }
func (self *scriptedTestLookup) Description() string { return "Looks a question up." }
func (self *scriptedTestLookup) Mode() string        { return sidecar.HarnessToolParallel }
func (self *scriptedTestLookup) Tier() string        { return sidecar.HarnessToolTierRead }
func (self *scriptedTestLookup) Schema() []byte {
	return []byte(`{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}`)
}

func (self *scriptedTestLookup) Execute(ctx context.Context, callId string, args []byte, update func(*sidecar.HarnessToolUpdate)) (*sidecar.HarnessToolResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.argsTexts = append(self.argsTexts, string(args))
	return &sidecar.HarnessToolResult{Text: "the answer is 42", Trust: sidecar.HarnessToolTrusted}, nil
}

// A Harness turn with one tool call and its result, through INFER's own router with the model behind it as its local
// engine: the Harness resolves the model in the router's catalog, sends each call through the router's checks and
// stream, runs the tool the model called, and the model, which matched each call on its last message, saw the
// Harness's whole context each time: the skill and instructions first, the tool, the run and agent, then the person's
// prompt, and at the second call the tool's result answering its call.
func TestScriptedModelBehindTheRouter(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	model, err := NewScriptedModel(&ScriptedModelArgs{Clock: clock, Turns: []*ScriptedTurn{
		{
			Match:     &ScriptedMatch{Model: ScriptedModelDefaultName, UserText: "What is the answer?"},
			ToolCalls: []*ScriptedToolCall{{Id: "call_1", Name: "lookup", Arguments: `{"q":"answer"}`}},
			Usage:     &sidecar.InferUsage{InputTokens: 20, OutputTokens: 5},
		},
		{
			Match: &ScriptedMatch{ToolCallId: "call_1", ToolResultText: "the answer is 42"},
			Text:  []string{"It is ", "42."},
			Usage: &sidecar.InferUsage{InputTokens: 30, OutputTokens: 4},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	router, err := model.Router(nil)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := sidecar.NewRunStore(sidecartest.NewFakeStore().Root(), sidecar.DefaultSidecarSettings().Mcp, clock)
	if err != nil {
		t.Fatal(err)
	}
	lookup := &scriptedTestLookup{}
	skill := &scriptedTestSkill{text: "You are an agent of the person's network. Register, summarize, read your inbox."}
	journal := newScriptedTestJournal()
	harness, err := sidecar.NewHarness(&sidecar.HarnessArgs{
		Clock:   clock,
		Router:  router,
		Journal: journal,
		Skill:   skill,
		Runs:    runs,
		Tools: map[string]*sidecar.HarnessToolSpec{"lookup": {
			Name:     "lookup",
			Profiles: []sidecar.HarnessProfile{sidecar.HarnessProfileLocal},
			New: func(harness *sidecar.Harness) (sidecar.HarnessTool, error) {
				return lookup, nil
			},
		}},
		TurnHooks:       map[string]sidecar.HarnessTurnHook{},
		WorkspaceParent: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(harness.Close)
	agent, err := harness.NewAgent(context.Background(), &sidecar.HarnessAgentSpec{
		Name:         "researcher",
		Model:        ScriptedModelDefaultName,
		Instructions: "Answer briefly.",
	})
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan *sidecar.HarnessEvent, 4096)
	t.Cleanup(agent.Subscribe(func(event *sidecar.HarnessEvent) {
		events <- event
	}))
	if err := agent.Prompt(context.Background(), "What is the answer?", nil); err != nil {
		t.Fatal(err)
	}
	seen := []*sidecar.HarnessEvent{}
	guard := time.After(60 * time.Second)
	for settled := false; !settled; {
		select {
		case event := <-events:
			seen = append(seen, event)
			settled = event.Type == sidecar.HarnessEventAgentSettled
		case <-guard:
			t.Fatalf("no agent_settled after %d events", len(seen))
		}
	}

	stopReason := ""
	seen[len(seen)-1].Decode("stopReason", &stopReason)
	if stopReason != sidecar.HarnessStopEnded {
		t.Fatalf("the run settled with %q", stopReason)
	}
	toolEnded, reply := false, ""
	for _, event := range seen {
		switch event.Type {
		case sidecar.HarnessEventToolExecutionEnd:
			callId, toolName, isError := "", "", true
			event.Decode("toolCallId", &callId)
			event.Decode("toolName", &toolName)
			event.Decode("isError", &isError)
			toolEnded = toolEnded || (callId == "call_1" && toolName == "lookup" && !isError)
		case sidecar.HarnessEventMessageEnd:
			if message := event.Message(); message != nil && message.Role() == sidecar.HarnessPiRoleAssistant {
				reply = message.Text()
			}
		}
	}
	if !toolEnded {
		t.Fatal("no tool_execution_end of call_1's lookup")
	}
	if reply != "It is 42." {
		t.Fatalf("the reply was %q", reply)
	}
	lookup.stateLock.Lock()
	argsTexts := lookup.argsTexts
	lookup.stateLock.Unlock()
	if len(argsTexts) != 1 || argsTexts[0] != `{"q":"answer"}` {
		t.Fatalf("the tool ran with %v", argsTexts)
	}

	calls := model.Calls()
	if len(calls) != 2 || calls[0].Turn != 0 || calls[1].Turn != 1 || model.Remaining() != 0 {
		t.Fatalf("%d calls took turns, %d left", len(calls), model.Remaining())
	}
	for i, call := range calls {
		if call.Err != nil || call.Name != ScriptedModelDefaultName || call.Effort != sidecar.InferEffortOff {
			t.Fatalf("call %d: %v, %s %s", i+1, call.Err, call.Name, call.Effort)
		}
		request := call.Request
		if request.RunId == nil || *request.RunId != agent.Run().Id() || request.AgentId == nil || *request.AgentId != agent.Id() {
			t.Fatalf("call %d names another run or agent", i+1)
		}
		system := request.Messages[0]
		if system.Role != sidecar.InferRoleSystem || !strings.HasPrefix(system.Text(), skill.text) || !strings.Contains(system.Text(), "Answer briefly.") {
			t.Fatalf("call %d's system text: %q", i+1, system.Text())
		}
		if len(request.Tools) != 1 || request.Tools[0].Name != "lookup" {
			t.Fatalf("call %d offered %d tools", i+1, len(request.Tools))
		}
	}
	first := calls[0].Request.Messages
	if last := first[len(first)-1]; last.Role != sidecar.InferRoleUser || last.Text() != "What is the answer?" {
		t.Fatalf("the first call ends with %+v", last)
	}
	second := calls[1].Request.Messages
	called, answered := second[len(second)-2], second[len(second)-1]
	if called.Role != sidecar.InferRoleAssistant || len(called.ToolCalls) != 1 || called.ToolCalls[0].Id != "call_1" ||
		called.ToolCalls[0].Name != "lookup" || called.ToolCalls[0].Arguments != `{"q":"answer"}` {
		t.Fatalf("the second call's assistant turn: %+v", called)
	}
	if answered.Role != sidecar.InferRoleTool || answered.ToolCallId != "call_1" || answered.Text() != "the answer is 42" {
		t.Fatalf("the second call ends with %+v", answered)
	}
}

// Through INFER's router the model's local entry is listed available and resolves, a scripted answer streams as the
// model played it, and a call the script does not answer ends in the router's error event, engine_failed, naming the
// script's refusal and the model.
func TestScriptedModelRouterErrorNamesTheRefusal(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	model := newTestScriptedModel(t, clock, &ScriptedTurn{Text: []string{"hello"}})
	router, err := model.Router(nil)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := router.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := catalog.Resolve(ScriptedModelDefaultName, "")
	if err != nil || resolution.Entry.Unavailable != "" {
		t.Fatalf("the router's catalog: %v, %+v", err, resolution)
	}
	read := func() []*sidecar.InferEvent {
		stream, err := router.Infer(context.Background(), &sidecar.InferRequest{
			Model:    ScriptedModelDefaultName,
			Messages: []*sidecar.InferMessage{scriptedTestUser("hi")},
		})
		if err != nil {
			t.Fatal(err)
		}
		events := []*sidecar.InferEvent{}
		guard := time.After(60 * time.Second)
		for {
			select {
			case event, ok := <-stream:
				if !ok {
					return events
				}
				events = append(events, event)
			case <-guard:
				t.Fatal("the stream never closed")
			}
		}
	}
	answered := read()
	if len(answered) != 3 || answered[0].Kind != sidecar.InferEventStart || answered[1].Text != "hello" || answered[2].Kind != sidecar.InferEventEnd {
		t.Fatalf("the scripted answer through the router: %+v", answered)
	}
	refused := read()
	last := refused[len(refused)-1]
	if last.Kind != sidecar.InferEventError || last.Error.Code != sidecar.InferErrorEngineFailed ||
		!strings.Contains(last.Error.Message, ErrScriptedModelExhausted.Error()) || last.Error.Model != ScriptedModelDefaultName {
		t.Fatalf("the refusal through the router: %+v", last.Error)
	}
	// a remote name has no path behind this router
	if _, err := router.Infer(context.Background(), &sidecar.InferRequest{Model: "engy-testmodel-high", Messages: []*sidecar.InferMessage{scriptedTestUser("hi")}}); sidecar.InferErrorCodeOf(err) != sidecar.InferErrorModelRefused {
		t.Fatalf("a remote name answered %v", err)
	}
	if len(model.Calls()) != 2 {
		t.Fatalf("%d calls reached the model", len(model.Calls()))
	}
}
