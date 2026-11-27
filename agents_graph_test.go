//go:build !ios_extension && !sidecar_http

// The agent graph (§20.8, CO-19; M11's exit): nodes from the cards, launch edges from parents and conversation edges
// from threads between inboxes, sender to recipient by verified provenance; retired agents only when asked; a chosen
// agent's summaries, each a version, and its threads; and nothing read but EVS, no write, no repo made and no request
// beyond what a read syncs. The person's live view tells each new message once, with its notification, after a
// device's first view takes what stands as its baseline, and tells a change of the cards, statuses or summaries.

package sidecar

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"
)

// The edge kind from to in a thread, nil for none.
func testGraphEdge(graph *AgentsGraph, kind string, from string, to string) *AgentsGraphEdge {
	for _, edge := range graph.Edges {
		if edge.Kind == kind && edge.From == from && edge.To == to {
			return edge
		}
	}
	return nil
}

// The node of name, nil for none.
func testGraphNode(graph *AgentsGraph, name string) *AgentsGraphNode {
	for _, node := range graph.Nodes {
		if node.Name == name {
			return node
		}
	}
	return nil
}

// The tools' world with a child fix launched, the person's me, and threads: fix to helper and helper's reply, the
// person to docs, and fix's broadcast with docs' reply.
func newTestAgentsGraphEnv(t *testing.T) *testAgentToolsEnv {
	t.Helper()
	env := newTestAgentToolsEnv(t)
	ctx := env.world.ctx
	if _, err := env.laptop.Register(ctx, &AgentRegisterArgs{Name: "child", Harness: "ur-harness 1.0", Model: "local-gemma", Parent: "fix", ChildOfHarness: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.phone.RegisterMe(ctx, &AgentRegisterMeArgs{}); err != nil {
		t.Fatal(err)
	}
	fix, helper, docs := &testAgentsCaller{}, &testAgentsCaller{}, &testAgentsCaller{}
	sent, err := env.tools.Send(ctx, fix.caller("fix"), &AgentSendToolArgs{To: "helper", Body: "Review the limiter."})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.tools.Send(ctx, helper.caller("helper"), &AgentSendToolArgs{Thread: sent.Data.(*AgentSendToolResult).Thread, Body: "Done."}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.phone.SendAsPerson(ctx, &AgentPersonSendArgs{To: "docs", Body: "Add Linux."}); err != nil {
		t.Fatal(err)
	}
	all, err := env.tools.Broadcast(ctx, fix.caller("fix"), &AgentBroadcastToolArgs{Body: "Wrap up."})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.toolsOf(t, env.phone).Send(ctx, docs.caller("docs"), &AgentSendToolArgs{Thread: all.Data.(*AgentSendToolResult).Thread, Body: "Wrapped."}); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestGraphLaunchAndThreadEdges(t *testing.T) {
	env := newTestAgentsGraphEnv(t)
	ctx := env.world.ctx
	graph, err := env.phone.Graph(ctx, &AgentsGraphArgs{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fix", "helper", "docs", "scraper", "child", AgentNameMe} {
		if testGraphNode(graph, name) == nil {
			t.Fatalf("no node %s", name)
		}
	}
	if me := testGraphNode(graph, AgentNameMe); !me.Person || me.Host != "" {
		t.Fatalf("the person's me: %+v", me.AgentListEntry)
	}
	if fix := testGraphNode(graph, "fix"); fix.Host != "host of "+env.world.laptop.String()[:8] || fix.State != string(AgentStateWorking) || fix.Summary == "" {
		t.Fatalf("fix's node: %+v", fix.AgentListEntry)
	}
	for _, launch := range [][2]string{{"fix", "child"}, {"fix", "scraper"}} {
		if testGraphEdge(graph, AgentsGraphEdgeLaunch, launch[0], launch[1]) == nil {
			t.Fatalf("no launch %v: %+v", launch, graph.Edges)
		}
	}
	for _, conversation := range [][2]string{{"fix", "helper"}, {"helper", "fix"}, {AgentNameMe, "docs"}, {"fix", "*"}, {"docs", "fix"}} {
		edge := testGraphEdge(graph, AgentsGraphEdgeConversation, conversation[0], conversation[1])
		if edge == nil || edge.Messages != 1 || edge.Thread == "" || edge.Repo == "" || !edge.Trusted {
			t.Fatalf("the conversation %v: %+v in %+v", conversation, edge, graph.Edges)
		}
	}
	// a thread from fix to helper and its reply share a thread, in helper's repo
	there, back := testGraphEdge(graph, AgentsGraphEdgeConversation, "fix", "helper"), testGraphEdge(graph, AgentsGraphEdgeConversation, "helper", "fix")
	helperRepo, err := env.laptop.AgentRepo(ctx, "helper")
	if err != nil || there.Thread != back.Thread || there.Repo != agentCardIdText(helperRepo) {
		t.Fatalf("the thread's edges: %+v, %+v, %v", there, back, err)
	}
	// a chosen agent: its summaries, each a version, and its threads
	if err := env.laptop.WriteSummary(ctx, &AgentSummaryWrite{Name: "fix", Summary: &AgentSummary{Source: AgentSummarySourceAgent, Text: "## Completed\n- the refill"}}); err != nil {
		t.Fatal(err)
	}
	chosen, err := env.phone.Graph(ctx, &AgentsGraphArgs{Agent: "fix"})
	if err != nil {
		t.Fatal(err)
	}
	if chosen.Agent == nil || len(chosen.Agent.Summaries) != 2 || chosen.Agent.Summaries[0].Text != "## Completed\n- the refill" ||
		!chosen.Agent.Summaries[0].Trusted || len(chosen.Agent.Threads) != 2 {
		t.Fatalf("fix's view: %+v", chosen.Agent)
	}
}

func TestGraphRetiredOnlyWhenAsked(t *testing.T) {
	env := newTestAgentsGraphEnv(t)
	ctx := env.world.ctx
	if _, err := env.laptop.Retire(ctx, "helper"); err != nil {
		t.Fatal(err)
	}
	graph, err := env.phone.Graph(ctx, &AgentsGraphArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if testGraphNode(graph, "helper") != nil || testGraphEdge(graph, AgentsGraphEdgeConversation, "fix", "helper") != nil ||
		testGraphEdge(graph, AgentsGraphEdgeConversation, "helper", "fix") != nil {
		t.Fatalf("a retired agent drawn unasked: %+v", graph)
	}
	past, err := env.phone.Graph(ctx, &AgentsGraphArgs{Retired: true})
	if err != nil {
		t.Fatal(err)
	}
	helper := testGraphNode(past, "helper")
	if helper == nil || helper.Retired == "" || testGraphEdge(past, AgentsGraphEdgeConversation, "fix", "helper") == nil {
		t.Fatalf("asked for past agents: %+v", past)
	}
}

// What a recording reach of the agents' repos saw: each call by its method.
type testAgentsRecorder struct {
	stateLock sync.Mutex
	calls     map[string]int
}

func (self *testAgentsRecorder) record(method string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls[method] += 1
}

// A repo reach that records each call and passes it on.
type testAgentsRecordingRepo struct {
	repo     AgentsRepoAccess
	recorder *testAgentsRecorder
}

func (self *testAgentsRecordingRepo) History(ctx context.Context, args *EvsReadArgs) (*EvsHistory, error) {
	self.recorder.record("History")
	return self.repo.History(ctx, args)
}

func (self *testAgentsRecordingRepo) ReadHead(ctx context.Context, args *EvsReadArgs, out io.Writer) (*EvsFileInfo, error) {
	self.recorder.record("ReadHead")
	return self.repo.ReadHead(ctx, args, out)
}

func (self *testAgentsRecordingRepo) WritePaths(ctx context.Context, args *EvsWritePathsArgs) (*EvsWritePathsResult, error) {
	self.recorder.record("WritePaths")
	return self.repo.WritePaths(ctx, args)
}

func (self *testAgentsRecordingRepo) List(ctx context.Context, args *EvsReadArgs) (*EvsListing, error) {
	self.recorder.record("List")
	return self.repo.List(ctx, args)
}

// The graph is built on the device from what EVS holds: every call it makes is a read of a repo, and it writes
// nothing, makes no repo, derives no label key and asks no search.
func TestGraphMakesNoServerRequest(t *testing.T) {
	env := newTestAgentsGraphEnv(t)
	recorder := &testAgentsRecorder{calls: map[string]int{}}
	client := env.world.client(env.world.phone)
	repoOf := client.args.Repo
	client.args.Repo = func(repoId Id) AgentsRepoAccess {
		recorder.record("Repo")
		return &testAgentsRecordingRepo{repo: repoOf(repoId), recorder: recorder}
	}
	client.args.CreateRepo = func(ctx context.Context, args *EvsCreateRepoArgs) (Id, error) {
		recorder.record("CreateRepo")
		return Id{}, ErrAgentsUnavailable
	}
	client.args.LabelKey = func(ctx context.Context) (*AgentRepoLabelKey, error) {
		recorder.record("LabelKey")
		return nil, ErrAgentsUnavailable
	}
	client.args.Store = func() (SidecarStore, error) {
		recorder.record("Store")
		return nil, ErrAgentsUnavailable
	}
	writes := env.world.writeCount
	if _, err := client.Graph(env.world.ctx, &AgentsGraphArgs{Retired: true, Agent: "fix"}); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"WritePaths", "CreateRepo", "LabelKey", "Store"} {
		if recorder.calls[method] != 0 {
			t.Errorf("the graph called %s %d times", method, recorder.calls[method])
		}
	}
	if recorder.calls["History"] == 0 || recorder.calls["List"] == 0 || env.world.writeCount != writes {
		t.Fatalf("the graph's calls: %v, %d writes", recorder.calls, env.world.writeCount-writes)
	}
}

// What a person's watch told.
type testAgentsPersonHeard struct {
	stateLock     sync.Mutex
	messages      []*AgentThreadMessage
	notifications []*AgentNotification
	changes       int
}

func (self *testAgentsPersonHeard) heard() ([]*AgentThreadMessage, []*AgentNotification, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.messages), slices.Clone(self.notifications), self.changes
}

// A person's watch on client whose passes the test hears.
func newTestAgentsPersonWatch(t *testing.T, client *AgentsClient) (*testAgentsPersonHeard, chan error) {
	t.Helper()
	heard := &testAgentsPersonHeard{}
	passed := make(chan error, 64)
	watch, err := client.WatchPerson(context.Background(), &AgentPersonWatchArgs{
		Message: func(message *AgentThreadMessage, notification *AgentNotification) {
			heard.stateLock.Lock()
			defer heard.stateLock.Unlock()
			heard.messages = append(heard.messages, message)
			if notification != nil {
				heard.notifications = append(heard.notifications, notification)
			}
		},
		Changed: func() {
			heard.stateLock.Lock()
			defer heard.stateLock.Unlock()
			heard.changes += 1
		},
		Passed: func(err error) { passed <- err },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(watch.Close)
	if err := <-passed; err != nil {
		t.Fatal(err)
	}
	return heard, passed
}

// A device's first view takes what stands as its baseline; each message after is told once, an agent's reply to the
// person with its notification, the person's own words with none; a status write is a change.
func TestPersonWatchTellsEachMessageOnce(t *testing.T) {
	env := newTestAgentsGraphEnv(t)
	ctx := env.world.ctx
	env.world.settings.WatchPassMinInterval = 0
	heard, passed := newTestAgentsPersonWatch(t, env.phone)
	if messages, _, _ := heard.heard(); len(messages) != 0 {
		t.Fatalf("the baseline told %d messages", len(messages))
	}
	opened, err := env.phone.SendAsPerson(ctx, &AgentPersonSendArgs{To: "fix", Subject: "status?", Body: "How is it going?"})
	if err != nil {
		t.Fatal(err)
	}
	fix := &testAgentsCaller{}
	if _, err := env.tools.Send(ctx, fix.caller("fix"), &AgentSendToolArgs{Thread: opened.Thread, Subject: "going well", Body: "Tests pass."}); err != nil {
		t.Fatal(err)
	}
	if err := <-passed; err != nil {
		t.Fatal(err)
	}
	// a pass may have run between the two writes: wait for the one that saw both
	for messages, _, _ := heard.heard(); len(messages) < 2; messages, _, _ = heard.heard() {
		if err := <-passed; err != nil {
			t.Fatal(err)
		}
	}
	messages, notifications, _ := heard.heard()
	if len(messages) != 2 || !messages[0].SenderPerson || messages[1].SenderName != "fix" {
		t.Fatalf("the messages: %+v", messages)
	}
	if len(notifications) != 1 || notifications[0].Sender != "fix" || notifications[0].Subject != "going well" ||
		!notifications[0].ToPerson || notifications[0].Trust != string(AgentMessageTrustMemberRun) {
		t.Fatalf("the notifications: %+v", notifications)
	}
	// a status write changes the view
	if err := env.laptop.WriteStatus(ctx, &AgentStatusWrite{Name: "fix", Status: &AgentStatus{State: AgentStateIdle, Updated: env.world.now()}}); err != nil {
		t.Fatal(err)
	}
	for _, _, changes := heard.heard(); changes == 0; _, _, changes = heard.heard() {
		if err := <-passed; err != nil {
			t.Fatal(err)
		}
	}
	if messages, _, _ := heard.heard(); len(messages) != 2 {
		t.Fatalf("a message told twice: %d", len(messages))
	}
}

// The person's reply and close in a thread answer the client's refusal as an error, never a result: a thread holding
// as many messages as a thread may refuses both, and nothing is written.
func TestPersonContinueAnswersTheRefusal(t *testing.T) {
	env := newTestAgentToolsEnv(t)
	ctx := env.world.ctx
	opened, err := env.phone.SendAsPerson(ctx, &AgentPersonSendArgs{To: "fix", Body: "How close?"})
	if err != nil {
		t.Fatal(err)
	}
	env.world.settings.ThreadMessageMax = 1
	writes := env.world.writeCount
	for _, args := range []*AgentPersonSendArgs{{Thread: opened.Thread, Close: true}, {Thread: opened.Thread, To: "fix", Body: "again"}} {
		result, err := env.phone.SendAsPerson(ctx, args)
		if !errors.Is(err, ErrAgentThreadFull) || result != nil {
			t.Fatalf("%+v answered %+v, %v", args, result, err)
		}
	}
	if env.world.writeCount != writes {
		t.Fatalf("refused sends wrote %d times", env.world.writeCount-writes)
	}
}

// A chosen agent's summary versions an untrusted writer's run wrote reach a caller that may feed a model withheld, or,
// with include, once its runs were tainted first; the person's view shows them all.
func TestGraphChosenAgentHoldsUntrustedVersions(t *testing.T) {
	env := newTestAgentToolsEnv(t)
	ctx := env.world.ctx
	scraper := testAgentToolsInjection
	if err := env.laptop.WriteSummary(ctx, &AgentSummaryWrite{Name: "fix", Summary: &AgentSummary{Source: AgentSummarySourceAgent, Text: scraper}, Tainted: true}); err != nil {
		t.Fatal(err)
	}
	if err := env.laptop.WriteSummary(ctx, &AgentSummaryWrite{Name: "fix", Summary: &AgentSummary{Source: AgentSummarySourceAgent, Text: "## Completed\n- merged"}}); err != nil {
		t.Fatal(err)
	}
	person, err := env.phone.Graph(ctx, &AgentsGraphArgs{Agent: "fix"})
	if err != nil || len(person.Agent.Summaries) != 3 || person.Agent.Summaries[1].Text != scraper || person.Agent.Summaries[1].Trusted {
		t.Fatalf("the person's view: %+v, %v", person.Agent, err)
	}
	model, err := env.phone.Graph(ctx, &AgentsGraphArgs{Agent: "fix", ForModel: true})
	if err != nil {
		t.Fatal(err)
	}
	if summary := model.Agent.Summaries[1]; summary.Text != "" || !summary.Withheld || model.Agent.Summaries[0].Text != "## Completed\n- merged" {
		t.Fatalf("a model's view: %+v", model.Agent.Summaries)
	}
	taints := 0
	included, err := env.phone.Graph(ctx, &AgentsGraphArgs{Agent: "fix", ForModel: true, Include: true, TaintFirst: func(ctx context.Context) error {
		taints += 1
		return nil
	}})
	if err != nil || included.Agent.Summaries[1].Text != scraper || !included.Untrusted || taints != 1 {
		t.Fatalf("include: %+v, %v, %d taints", included, err, taints)
	}
}
