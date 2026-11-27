//go:build !ios_extension && !sidecar_http && !js

// The recURd tools (§20.10, §20.8, M11's exit): their tiers, registered for both profiles with the skill; agent_inbox
// tainting before a message that taints reaches the answer, and taking each message once; agent_send's threads,
// replies by provenance and kind 24's refusals; and the default Harness answering the three questions from EVS alone,
// a thread going several turns and a reply answered again, driven by a scripted model.
//
// The Harness here runs on HARN's scripted router (harness_test.go), the stand-in HARN-M11-04's tests use: CTEST's
// computetest.ScriptedModel imports the root, so an internal test of the root cannot drive it without a cycle.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// §20.10's tiers.
var testAgentToolTiers = map[string]string{
	AgentToolRegister: HarnessToolTierWrite, AgentToolSummary: HarnessToolTierWrite, AgentToolList: HarnessToolTierRead,
	AgentToolFind: HarnessToolTierRead, AgentToolSend: HarnessToolTierWrite, AgentToolBroadcast: HarnessToolTierWrite,
	AgentToolInbox: HarnessToolTierRead, AgentToolClose: HarnessToolTierWrite,
}

func TestAgentToolsTiers(t *testing.T) {
	specs := AgentToolSpecs()
	if len(specs) != len(testAgentToolTiers) {
		t.Fatalf("%d tools", len(specs))
	}
	for _, spec := range specs {
		if testAgentToolTiers[spec.Name] != spec.Tier {
			t.Errorf("%s is %s", spec.Name, spec.Tier)
		}
		if !json.Valid(spec.Schema) || spec.Description == "" {
			t.Errorf("%s's schema or description", spec.Name)
		}
		registered := harnessToolSpecs[spec.Name]
		if registered == nil || !registered.BuiltIn || len(registered.Profiles) != 2 {
			t.Errorf("%s's registration: %+v", spec.Name, registered)
		}
	}
	// a Harness whose skill is the recURd skill's lists them; any other leaves them out
	env := newTestAgentToolsEnv(t)
	world := newTestAgentsHarness(t, env.laptop)
	names := world.harness.tools.Names(HarnessProfileLocal)
	for name := range testAgentToolTiers {
		tool, _, ok := world.harness.tools.Tool(name, HarnessProfileLocal)
		if !ok || tool.Tier() != testAgentToolTiers[name] {
			t.Errorf("%s in the Harness: %v", name, names)
		}
		if _, _, ok := world.harness.tools.Tool(name, HarnessProfileEnclave); !ok {
			t.Errorf("%s left out of the enclave profile", name)
		}
	}
	other := newHarnessTestWorld(t, nil, testAgentsHarnessTools(), nil)
	if 0 < len(other.harness.tools.Names(HarnessProfileLocal)) {
		t.Fatalf("a Harness with another skill lists %v", other.harness.tools.Names(HarnessProfileLocal))
	}
}

// The agent_* registrations, the tools a test's Harness takes.
func testAgentsHarnessTools() map[string]*HarnessToolSpec {
	tools := map[string]*HarnessToolSpec{}
	for name := range testAgentToolTiers {
		tools[name] = harnessToolSpecs[name]
	}
	return tools
}

func TestAgentRegisterTool(t *testing.T) {
	env := newTestAgentToolsEnv(t)
	ctx := env.world.ctx
	session := &testAgentsCaller{}
	// a fixed name answers itself, and refuses another
	answer, err := env.tools.Register(ctx, session.caller("fix"), &AgentRegisterToolArgs{})
	if err != nil || answer.Data.(*AgentRegisterToolResult).Name != "fix" || answer.Data.(*AgentRegisterToolResult).AgentRepo == "" {
		t.Fatalf("fix: %+v, %v", answer, err)
	}
	if _, err := env.tools.Register(ctx, session.caller("fix"), &AgentRegisterToolArgs{Name: "other"}); !errors.Is(err, ErrAgentToolRegisterOther) {
		t.Fatalf("another name for a fixed session: %v", err)
	}
	// a session with no agent registers the name it asks, and keeps it
	answer, err = env.tools.Register(ctx, session.caller(""), &AgentRegisterToolArgs{Name: "reviewer"})
	if err != nil || answer.Data.(*AgentRegisterToolResult).Name != "reviewer" || len(session.registered) != 1 || session.registered[0] != "reviewer" {
		t.Fatalf("reviewer: %+v, %v, %v", answer, err, session.registered)
	}
	// a write of a session with no agent registers one first, its harness's name, taken past another's card
	bare := session.caller("")
	bare.DefaultName = "fix"
	if _, err := env.tools.Summary(ctx, bare, &AgentSummaryToolArgs{Text: "## Completed\n- nothing yet"}); err != nil {
		t.Fatal(err)
	}
	if len(session.registered) != 2 || session.registered[1] != "fix" {
		// this sidecar's own fix is its agent: the same name, the same card
		t.Fatalf("the registered names: %v", session.registered)
	}
	phone := &testAgentsCaller{}
	phoneTools := env.toolsOf(t, env.phone)
	answer, err = phoneTools.Register(ctx, phone.caller(""), &AgentRegisterToolArgs{Name: "fix"})
	if err != nil || answer.Data.(*AgentRegisterToolResult).Name != "fix-2" {
		t.Fatalf("another device's fix: %+v, %v", answer, err)
	}
	summary, err := env.laptop.Summary(ctx, "fix")
	if err != nil || summary.Summary == nil || summary.Summary.Text != "## Completed\n- nothing yet" || !summary.Trusted {
		t.Fatalf("the summary: %+v, %v", summary, err)
	}
	if _, err := env.tools.Summary(ctx, session.caller("fix"), &AgentSummaryToolArgs{Text: strings.Repeat("x", 9*1024)}); !errors.Is(err, ErrAgentToolArguments) {
		t.Fatalf("a summary past its bound: %v", err)
	}
}

func TestAgentInboxTaintsPerTrust(t *testing.T) {
	env := newTestAgentToolsEnv(t)
	ctx := env.world.ctx
	// fix's inbox: the person's message from the phone (kind a), helper's from an untainted run (kind b)
	if _, err := env.phone.Send(ctx, &AgentSendArgs{Person: true, To: "fix", Subject: "status?", Body: "How is the limiter?"}); err != nil {
		t.Fatal(err)
	}
	helper := &testAgentsCaller{}
	if _, err := env.tools.Send(ctx, helper.caller("helper"), &AgentSendToolArgs{To: "fix", Body: "The review is done."}); err != nil {
		t.Fatal(err)
	}
	fix := &testAgentsCaller{}
	answer, err := env.tools.Inbox(ctx, fix.caller("fix"), &AgentInboxToolArgs{}, HarnessUntrustedText)
	if err != nil {
		t.Fatal(err)
	}
	inbox := answer.Data.(*AgentInboxResult)
	if len(inbox.Messages) != 2 || answer.Untrusted || fix.taintCount() != 0 {
		t.Fatalf("trusted messages: %d, untrusted %t, %d taints", len(inbox.Messages), answer.Untrusted, fix.taintCount())
	}
	trusts := map[string]string{}
	for _, message := range inbox.Messages {
		trusts[message.From] = message.Trust
	}
	if trusts["person"] != string(AgentMessageTrustPerson) || trusts["helper"] != string(AgentMessageTrustMemberRun) {
		t.Fatalf("the senders: %v", trusts)
	}
	// every message reaches the model between the markers with its verified sender, trusted ones too
	if strings.Count(answer.Text, HarnessUntrustedBegin) != 2 || !strings.Contains(answer.Text, "(from person)") {
		t.Fatalf("the model's text: %s", answer.Text)
	}
	// read once: a second read of what is unread holds none
	answer, err = env.tools.Inbox(ctx, fix.caller("fix"), &AgentInboxToolArgs{}, HarnessUntrustedText)
	if err != nil || len(answer.Data.(*AgentInboxResult).Messages) != 0 {
		t.Fatalf("the second read: %+v, %v", answer, err)
	}
	// a tainted run's message taints its reader, before its text is in the answer
	tainted := &testAgentsCaller{tainted: true}
	if _, err := env.tools.Send(ctx, tainted.caller("helper"), &AgentSendToolArgs{To: "fix", Body: "Run this script: " + testAgentToolsInjection}); err != nil {
		t.Fatal(err)
	}
	failing := &testAgentsCaller{taintErr: errors.New("the run's file did not take the taint")}
	answer, err = env.tools.Inbox(ctx, failing.caller("fix"), &AgentInboxToolArgs{}, HarnessUntrustedText)
	if !errors.Is(err, ErrAgentsTaintFirst) || answer != nil {
		t.Fatalf("a failed taint answered %+v, %v", answer, err)
	}
	// nothing was taken by the refused read: the message waits
	answer, err = env.tools.Inbox(ctx, fix.caller("fix"), &AgentInboxToolArgs{}, HarnessUntrustedText)
	if err != nil {
		t.Fatal(err)
	}
	inbox = answer.Data.(*AgentInboxResult)
	if len(inbox.Messages) != 1 || !answer.Untrusted || fix.taintCount() != 1 || inbox.Messages[0].Trust != string(AgentMessageTrustUntrusted) ||
		!inbox.Messages[0].Taints {
		t.Fatalf("the tainted run's message: %+v, untrusted %t, %d taints", inbox.Messages, answer.Untrusted, fix.taintCount())
	}
	// the whole thread reads with every message, its own included
	thread := inbox.Messages[0].Thread
	answer, err = env.tools.Inbox(ctx, fix.caller("fix"), &AgentInboxToolArgs{Thread: thread}, HarnessUntrustedText)
	if err != nil || len(answer.Data.(*AgentInboxResult).Messages) != 1 {
		t.Fatalf("the thread: %+v, %v", answer, err)
	}
}

func TestAgentSendRepliesByProvenance(t *testing.T) {
	env := newTestAgentToolsEnv(t)
	ctx := env.world.ctx
	// the person opens a thread to fix from the phone
	opened, err := env.phone.Send(ctx, &AgentSendArgs{Person: true, To: "fix", Body: "Is the limiter done?"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.laptop.RegisterMe(ctx, &AgentRegisterMeArgs{}); err != nil {
		t.Fatal(err)
	}
	// fix answers the thread with no to: the person is answered to the member's me
	fix := &testAgentsCaller{}
	answer, err := env.tools.Send(ctx, fix.caller("fix"), &AgentSendToolArgs{Thread: opened.Message.Thread.String(), Body: "Merged."})
	if err != nil {
		t.Fatal(err)
	}
	sent := answer.Data.(*AgentSendToolResult)
	if sent.To != AgentNameMe || sent.Seq != 2 || sent.Kind != string(AgentMessageKindReply) || sent.Repo != agentCardIdText(opened.RepoId) {
		t.Fatalf("the reply: %+v", sent)
	}
	// a Harness run's message id derives from its run and call (§20.7's ids), which a resumed run repeats
	runCaller := fix.caller("fix")
	runCaller.RunId, runCaller.ToolCallId = testConfigId("fix run"), "call-1"
	first, err := env.tools.Send(ctx, runCaller, &AgentSendToolArgs{To: "helper", Body: "Please review."})
	if err != nil {
		t.Fatal(err)
	}
	if want := AgentMessageIdForCall(testConfigId("fix run"), "call-1").String(); first.Data.(*AgentSendToolResult).Id != want {
		t.Fatalf("the id: %s", first.Data.(*AgentSendToolResult).Id)
	}
	// a broadcast's thread: replies to it, and answers to one or all
	broadcast, err := env.tools.Broadcast(ctx, fix.caller("fix"), &AgentBroadcastToolArgs{Subject: "wrap up", Body: "Write your summaries."})
	if err != nil {
		t.Fatal(err)
	}
	all := broadcast.Data.(*AgentSendToolResult)
	if all.To != agentMessageToAll || all.Repo != agentCardIdText(env.world.agentsRepos[env.world.member]) {
		t.Fatalf("the broadcast: %+v", all)
	}
	helper := &testAgentsCaller{}
	reply, err := env.tools.Send(ctx, helper.caller("helper"), &AgentSendToolArgs{Thread: all.Thread, Body: "Written."})
	if err != nil || reply.Data.(*AgentSendToolResult).To != "fix" {
		t.Fatalf("helper's reply: %+v, %v", reply, err)
	}
	toAll, err := env.tools.Send(ctx, fix.caller("fix"), &AgentSendToolArgs{Thread: all.Thread, To: "*", Body: "Thanks, all."})
	if err != nil || toAll.Data.(*AgentSendToolResult).To != agentMessageToAll || toAll.Data.(*AgentSendToolResult).Seq != 3 {
		t.Fatalf("an answer to all: %+v, %v", toAll, err)
	}
	if _, err := env.tools.Send(ctx, fix.caller("fix"), &AgentSendToolArgs{To: "*", Body: "No thread."}); !errors.Is(err, ErrAgentToolArguments) {
		t.Fatalf("to all with no thread: %v", err)
	}
	if _, err := env.tools.Broadcast(ctx, fix.caller("fix"), &AgentBroadcastToolArgs{Body: "x", Scope: AgentFindScopeTeam}); !errors.Is(err, ErrAgentBroadcastScope) {
		t.Fatalf("scope team: %v", err)
	}
	// closing a thread writes kind close to its other side
	closed, err := env.tools.Close(ctx, fix.caller("fix"), &AgentCloseToolArgs{Thread: opened.Message.Thread.String()})
	if err != nil || closed.Data.(*AgentSendToolResult).Kind != string(AgentMessageKindClose) {
		t.Fatalf("the close: %+v, %v", closed, err)
	}
	read, err := env.laptop.Thread(ctx, opened.RepoId, opened.Message.Thread)
	if err != nil || !read.Closed || len(read.Messages) != 3 {
		t.Fatalf("the closed thread: %+v, %v", read, err)
	}
}

// A tainted run's send that leaves the member's untagged devices' agents is kind 24's, refused until it is built:
// to an agent on a tagged sidecar, a broadcast while one runs, and a reply in a thread to all; the same sends from an
// untainted run go, and a tainted run's send to a local agent is W.
func TestAgentSendTaintedOutwardRefused(t *testing.T) {
	env := newTestAgentToolsEnv(t)
	ctx := env.world.ctx
	tainted := &testAgentsCaller{tainted: true}
	if _, err := env.tools.Send(ctx, tainted.caller("fix"), &AgentSendToolArgs{To: "scraper", Body: "hi"}); !errors.Is(err, ErrAgentSendOutward) {
		t.Fatalf("a tainted send to a tagged sidecar's agent: %v", err)
	}
	if _, err := env.tools.Broadcast(ctx, tainted.caller("fix"), &AgentBroadcastToolArgs{Body: "hi"}); !errors.Is(err, ErrAgentSendOutward) {
		t.Fatalf("a tainted broadcast reaching one: %v", err)
	}
	writes := env.world.writeCount
	if _, err := env.tools.Send(ctx, tainted.caller("fix"), &AgentSendToolArgs{To: "helper", Body: "hi"}); err != nil {
		t.Fatalf("a tainted send to a local agent: %v", err)
	}
	if env.world.writeCount != writes+1 {
		t.Fatalf("%d writes", env.world.writeCount-writes)
	}
	clean := &testAgentsCaller{}
	answer, err := env.tools.Broadcast(ctx, clean.caller("fix"), &AgentBroadcastToolArgs{Body: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.tools.Send(ctx, tainted.caller("helper"), &AgentSendToolArgs{Thread: answer.Data.(*AgentSendToolResult).Thread, Body: "hi"}); !errors.Is(err, ErrAgentSendOutward) {
		t.Fatalf("a tainted reply in a thread to all: %v", err)
	}
	if _, err := env.tools.Send(ctx, clean.caller("fix"), &AgentSendToolArgs{To: "scraper", Body: "hi"}); err != nil {
		t.Fatalf("an untainted send to a tagged sidecar's agent: %v", err)
	}
}

// A Harness on the recURd skill over client, with the agent_* tools and HARN's scripted router.
type testAgentsHarnessWorld struct {
	router  *harnessScriptedRouter
	runs    *RunStore
	harness *Harness
}

func newTestAgentsHarness(t *testing.T, client *AgentsClient) *testAgentsHarnessWorld {
	t.Helper()
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	router := newHarnessScriptedRouter(t)
	tools, err := NewAgentsTools(&AgentsToolsArgs{Client: func() (*AgentsClient, error) { return client, nil }})
	if err != nil {
		t.Fatal(err)
	}
	skill := NewAgentsHarnessSkill(&AgentsHarnessSkillArgs{Client: func() (*AgentsClient, error) { return client, nil }, Tools: tools, Harness: "ur-harness test"})
	harness, err := NewHarness(&HarnessArgs{
		Router: router, Journal: newHarnessTestJournal(t), Skill: skill, Runs: runs, Clock: newHarnessTestClock(),
		Tools: testAgentsHarnessTools(), TurnHooks: map[string]HarnessTurnHook{}, WorkspaceParent: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(harness.Close)
	return &testAgentsHarnessWorld{router: router, runs: runs, harness: harness}
}

// Prompts agent once it is idle and waits for the run to settle again.
func (self *testAgentsHarnessWorld) ask(t *testing.T, agent HarnessAgent, text string) {
	t.Helper()
	harnessPromptIdle(t, agent, text)
	if err := agent.WaitForIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// The tool results the model read in the newest request, by tool call id.
func (self *testAgentsHarnessWorld) toolResults(t *testing.T) map[string]string {
	t.Helper()
	made := self.router.made()
	if len(made) == 0 {
		t.Fatal("no request")
	}
	results := map[string]string{}
	for _, message := range made[len(made)-1].Messages {
		if message.Role == InferRoleTool {
			results[message.ToolCallId] = message.Text()
		}
	}
	return results
}

// The thread of repoId's inbox other than the ones in known, failing where there is not exactly one.
func testAgentsNewThread(t *testing.T, client *AgentsClient, repoId Id, known ...AgentThreadId) AgentThreadId {
	t.Helper()
	threads, err := client.Threads(context.Background(), repoId)
	if err != nil {
		t.Fatal(err)
	}
	found := []AgentThreadId{}
	for _, thread := range threads {
		isKnown := false
		for _, old := range known {
			isKnown = isKnown || old == thread
		}
		if !isKnown {
			found = append(found, thread)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d new threads", len(found))
	}
	return found[0]
}

// M11's exit: the default Harness answers what the member's agents are doing, messages the one working on X, and
// messages all of them, from EVS alone; the thread goes several turns, and a reply is answered again.
func TestThreeQuestionsInTheHarness(t *testing.T) {
	env := newTestAgentToolsEnv(t)
	ctx := env.world.ctx
	// the bot's own world: no cloud agent's words in its way for the questions themselves
	if _, err := env.cloud.Retire(ctx, "scraper"); err != nil {
		t.Fatal(err)
	}
	world := newTestAgentsHarness(t, env.laptop)
	bot, err := world.harness.NewAgent(ctx, &HarnessAgentSpec{Name: "bot", Model: harnessTestModel})
	if err != nil {
		t.Fatal(err)
	}
	if bot.Name() != "bot" {
		t.Fatalf("the bot registered as %s", bot.Name())
	}
	if view, err := env.phone.Card(ctx, "bot"); err != nil || view.Card.Harness != "ur-harness test" || view.Card.Model != harnessTestModel {
		t.Fatalf("the bot's card: %+v, %v", view, err)
	}

	// 1. what are my agents doing right now
	world.router.script(harnessToolsCall([3]string{"list-1", AgentToolList, `{}`}), harnessTextCall("fix runs the limiter tests; docs drafts the macOS section."))
	world.ask(t, bot, "What are my agents doing right now?")
	listed := world.toolResults(t)["list-1"]
	for _, want := range []string{"fix", "running the limiter tests", "docs", "drafting the macOS section", "helper"} {
		if !strings.Contains(listed, want) {
			t.Fatalf("agent_list's answer lacks %q: %s", want, listed)
		}
	}
	if bot.Run().Tainted() {
		t.Fatal("listing trusted agents tainted the bot")
	}

	// 2. message the agent working on the rate limiter: find, then send
	world.router.script(
		harnessToolsCall([3]string{"find-1", AgentToolFind, `{"task":"rate limiter"}`}),
		harnessToolsCall([3]string{"send-1", AgentToolSend, `{"to":"fix","subject":"limiter","body":"How close is the limiter fix?"}`}),
		harnessTextCall("I asked fix."))
	world.ask(t, bot, "Send a message to the agent working on the rate limiter: how close is it?")
	fixRepo, err := env.laptop.AgentRepo(ctx, "fix")
	if err != nil {
		t.Fatal(err)
	}
	thread := testAgentsNewThread(t, env.laptop, fixRepo)
	opened, err := env.laptop.Thread(ctx, fixRepo, thread)
	if err != nil || len(opened.Messages) != 1 || opened.Messages[0].Trust.Sender.Name != "bot" || opened.Messages[0].Trust.Class != AgentMessageTrustMemberRun {
		t.Fatalf("the opened thread: %+v, %v", opened, err)
	}
	// fix's run answers in the thread, the bot reads it and replies again
	fix := &testAgentsCaller{}
	if _, err := env.tools.Send(ctx, fix.caller("fix"), &AgentSendToolArgs{Thread: thread.String(), Body: "Tests pass; merging soon."}); err != nil {
		t.Fatal(err)
	}
	world.router.script(
		harnessToolsCall([3]string{"inbox-1", AgentToolInbox, `{}`}),
		harnessToolsCall([3]string{"send-2", AgentToolSend, `{"thread":"` + thread.String() + `","body":"Great: tell me once merged."}`}),
		harnessTextCall("fix is merging soon; I asked to hear when it is merged."))
	world.ask(t, bot, "Did fix answer?")
	if inbox := world.toolResults(t)["inbox-1"]; !strings.Contains(inbox, "Tests pass; merging soon.") || !strings.Contains(inbox, "(from fix)") {
		t.Fatalf("the bot's inbox: %s", inbox)
	}
	if _, err := env.tools.Send(ctx, fix.caller("fix"), &AgentSendToolArgs{Thread: thread.String(), Body: "Merged."}); err != nil {
		t.Fatal(err)
	}
	world.router.script(harnessToolsCall([3]string{"inbox-2", AgentToolInbox, `{}`}), harnessTextCall("fix merged it."))
	world.ask(t, bot, "And now?")
	if inbox := world.toolResults(t)["inbox-2"]; !strings.Contains(inbox, "Merged.") || strings.Contains(inbox, "merging soon") {
		t.Fatalf("the second read holds what was read already: %s", inbox)
	}
	conversation, err := env.laptop.Thread(ctx, fixRepo, thread)
	if err != nil || len(conversation.Messages) != 4 {
		t.Fatalf("the thread: %+v, %v", conversation, err)
	}
	for i, message := range conversation.Messages {
		if message.Message.Seq != uint64(i+1) {
			t.Fatalf("message %d has seq %d", i, message.Message.Seq)
		}
	}
	if to := conversation.Messages[2].Message.To; to == nil || to.Name != "fix" {
		t.Fatalf("the bot's reply went to %+v", to)
	}

	// 3. message all agents: replies come back in the thread, and the bot answers one agent and all
	world.router.script(harnessToolsCall([3]string{"all-1", AgentToolBroadcast, `{"subject":"wrap up","body":"Please write your summaries."}`}),
		harnessTextCall("I asked every agent."))
	world.ask(t, bot, "Tell all my agents to write their summaries.")
	agentsRepo := env.world.agentsRepos[env.world.member]
	all := testAgentsNewThread(t, env.laptop, agentsRepo)
	docs := &testAgentsCaller{}
	if _, err := env.toolsOf(t, env.phone).Send(ctx, docs.caller("docs"), &AgentSendToolArgs{Thread: all.String(), Body: "Written; the macOS section is short."}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.tools.Send(ctx, fix.caller("fix"), &AgentSendToolArgs{Thread: all.String(), Body: "Written."}); err != nil {
		t.Fatal(err)
	}
	world.router.script(
		harnessToolsCall([3]string{"inbox-3", AgentToolInbox, `{"thread":"` + all.String() + `"}`}),
		harnessToolsCall([3]string{"send-3", AgentToolSend, `{"thread":"` + all.String() + `","to":"docs","body":"Please add the Linux section too."}`}),
		harnessToolsCall([3]string{"send-4", AgentToolSend, `{"thread":"` + all.String() + `","to":"*","body":"Thanks, everyone."}`}),
		harnessTextCall("Both wrote their summaries; I asked docs for the Linux section."))
	world.ask(t, bot, "What did they say?")
	if inbox := world.toolResults(t)["inbox-3"]; !strings.Contains(inbox, "the macOS section is short") || !strings.Contains(inbox, "Written.") {
		t.Fatalf("the replies to all: %s", inbox)
	}
	broadcast, err := env.laptop.Thread(ctx, agentsRepo, all)
	if err != nil || len(broadcast.Messages) != 5 {
		t.Fatalf("the thread to all: %+v, %v", broadcast, err)
	}
	if to := broadcast.Messages[3].Message.To; to == nil || to.Name != "docs" {
		t.Fatalf("the answer to one agent went to %+v", to)
	}
	if !broadcast.Messages[4].Message.ToAll() {
		t.Fatal("the answer to all named one agent")
	}
	if bot.Run().Tainted() {
		t.Fatal("trusted conversations tainted the bot")
	}
}

// In the Harness, untrusted: include taints the run's file before the answer reaches the model, and the answer is
// untrusted: the taint is the run store's, which a restart reads back.
func TestAgentListIncludeTaintsTheHarnessRun(t *testing.T) {
	env := newTestAgentToolsEnv(t)
	ctx := env.world.ctx
	world := newTestAgentsHarness(t, env.laptop)
	bot, err := world.harness.NewAgent(ctx, &HarnessAgentSpec{Name: "bot", Model: harnessTestModel})
	if err != nil {
		t.Fatal(err)
	}
	world.router.script(harnessToolsCall([3]string{"list-1", AgentToolList, `{}`}), harnessTextCall("listed"))
	world.ask(t, bot, "What are my agents doing?")
	if listed := world.toolResults(t)["list-1"]; strings.Contains(listed, testAgentToolsInjection) || bot.Run().Tainted() {
		t.Fatalf("stubs tainted the run or carried the text: %s", listed)
	}
	world.router.script(harnessToolsCall([3]string{"list-2", AgentToolList, `{"untrusted":"include"}`}), harnessTextCall("listed"))
	world.ask(t, bot, "Show me scraper's own words.")
	listed := world.toolResults(t)["list-2"]
	if !strings.Contains(listed, testAgentToolsInjection) || !strings.Contains(listed, HarnessUntrustedBegin) {
		t.Fatalf("include: %s", listed)
	}
	file, err := world.runs.Get(bot.Run().Id())
	if err != nil || !file.Tainted {
		t.Fatalf("the run's file after include: %+v, %v", file, err)
	}
}
