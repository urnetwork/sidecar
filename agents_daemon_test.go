//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// ur daemon's agents methods (§15.1's ur agents rows, §20.7's person in a thread and trust rows): a send confirmed on
// the terminal with no harness among the caller's ancestors is the person's own message, kind (a), which readers trust;
// under a harness it is that run's agent's message, tainted, whatever the terminal answered; neither is refused and
// writes nothing. Untrusted text reaches a caller only once its runs are tainted. The watch answers what lands past the
// caller's cursor.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// The method of name among methods.
func testDaemonAgentsMethod(t *testing.T, methods []*DaemonMethod, name string) *DaemonMethod {
	t.Helper()
	for _, method := range methods {
		if method.Name == name {
			return method
		}
	}
	t.Fatalf("no method %s", name)
	return nil
}

// What the methods' backends saw of their callers.
type testDaemonAgentsCaller struct {
	underHarness bool
	taints       int
	taintErr     error
}

// The methods over client, the caller's ancestry and taint as caller sets them.
func (self *testDaemonAgentsCaller) methods(client *AgentsClient) []*DaemonMethod {
	return DaemonAgentsMethods(&DaemonAgentsBackends{
		UnderHarness: func(ctx context.Context, call *DaemonCall) bool { return self.underHarness },
		TaintAncestors: func(ctx context.Context, call *DaemonCall) error {
			if self.taintErr != nil {
				return self.taintErr
			}
			self.taints += 1
			return nil
		},
		Client: func(sidecar *Sidecar) (*AgentsClient, error) { return client, nil },
	})
}

// A call of params, its network's Sidecar a stand-in the client function ignores.
func testDaemonAgentsCall(t *testing.T, params any, confirmed bool, agent string) *DaemonCall {
	t.Helper()
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	call := &DaemonCall{Params: encoded, Confirmed: confirmed, Sidecar: &Sidecar{}}
	if agent != "" {
		call.Agent = &SidecarAgent{Label: agent}
	}
	return call
}

// The newest message of fix's inbox as fix's device reads it.
func testDaemonAgentsNewest(t *testing.T, env *testAgentToolsEnv) *AgentMessageRead {
	t.Helper()
	messages, err := env.tools.inboxMessages(env.world.ctx, env.laptop, "fix", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) == 0 {
		t.Fatal("no message")
	}
	return messages[len(messages)-1]
}

func TestAgentsSendFromTtyIsPersonKindA(t *testing.T) {
	env := newTestAgentToolsEnv(t)
	ctx := env.world.ctx
	caller := &testDaemonAgentsCaller{}
	send := testDaemonAgentsMethod(t, caller.methods(env.phone), DaemonMethodAgentsSend)
	// confirmed on the terminal, no harness among the caller's ancestors: the person's own words
	reply, err := send.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsSendParams{To: "fix", Subject: "status?", Body: "How close?"}, true, ""))
	if err != nil {
		t.Fatal(err)
	}
	if sent := reply.(*DaemonAgentsSendReply); !sent.Person || sent.To != "fix" || sent.Seq != 1 {
		t.Fatalf("the reply: %+v", sent)
	}
	message := testDaemonAgentsNewest(t, env)
	if message.Trust.Class != AgentMessageTrustPerson || !message.Message.From.Person || message.Trust.Taints() {
		t.Fatalf("the person's message reads %+v", message.Trust)
	}
	// with no terminal and no harness, the person's path is refused, and nothing is written
	writes := env.world.writeCount
	if _, err := send.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsSendParams{To: "fix", Body: "again"}, false, "")); !errors.Is(err, ErrDaemonAgentsUnconfirmed) {
		t.Fatalf("an unconfirmed send: %v", err)
	}
	if env.world.writeCount != writes {
		t.Fatalf("a refused send wrote %d times", env.world.writeCount-writes)
	}
	// the person's reply in the thread with no to answers fix; a broadcast and a close too
	if _, err := env.tools.Send(ctx, (&testAgentsCaller{}).caller("fix"), &AgentSendToolArgs{Thread: message.Message.Thread.String(), Body: "Close."}); err != nil {
		t.Fatal(err)
	}
	reply, err = send.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsSendParams{Thread: message.Message.Thread.String(), Body: "Thanks."}, true, ""))
	if err != nil || reply.(*DaemonAgentsSendReply).To != "fix" || reply.(*DaemonAgentsSendReply).Seq != 3 {
		t.Fatalf("the person's reply: %+v, %v", reply, err)
	}
	reply, err = send.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsSendParams{Broadcast: true, Body: "Wrap up."}, true, ""))
	if err != nil || reply.(*DaemonAgentsSendReply).To != agentMessageToAll || !reply.(*DaemonAgentsSendReply).Person {
		t.Fatalf("the person's broadcast: %+v, %v", reply, err)
	}
	reply, err = send.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsSendParams{Thread: message.Message.Thread.String(), Close: true}, true, ""))
	if err != nil || reply.(*DaemonAgentsSendReply).Kind != string(AgentMessageKindClose) {
		t.Fatalf("the person's close: %+v, %v", reply, err)
	}
}

func TestAgentsSendUnderHarnessIsRunMessage(t *testing.T) {
	env := newTestAgentToolsEnv(t)
	ctx := env.world.ctx
	caller := &testDaemonAgentsCaller{underHarness: true}
	send := testDaemonAgentsMethod(t, caller.methods(env.laptop), DaemonMethodAgentsSend)
	// confirmed or not, under a harness it is the run's agent's message, tainted
	reply, err := send.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsSendParams{To: "fix", Body: "Run the tests."}, true, "helper"))
	if err != nil {
		t.Fatal(err)
	}
	if sent := reply.(*DaemonAgentsSendReply); sent.Person || sent.To != "fix" {
		t.Fatalf("the reply: %+v", sent)
	}
	message := testDaemonAgentsNewest(t, env)
	if message.Message.From.Person || message.Trust.Sender.Name != "helper" || message.Trust.Class != AgentMessageTrustUntrusted || !message.Trust.Taints() {
		t.Fatalf("the run's message reads %+v, from %+v", message.Trust, message.Message.From)
	}
	// a session naming no agent is refused, writing nothing
	writes := env.world.writeCount
	if _, err := send.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsSendParams{To: "fix", Body: "x"}, true, "")); !errors.Is(err, ErrDaemonAgentsNoAgent) {
		t.Fatalf("no agent: %v", err)
	}
	// a tainted run's message to an agent on a tagged sidecar is kind 24's, refused
	if _, err := send.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsSendParams{To: "scraper", Body: "x"}, true, "helper")); !errors.Is(err, ErrAgentSendOutward) {
		t.Fatalf("to a tagged sidecar's agent: %v", err)
	}
	if env.world.writeCount != writes {
		t.Fatalf("refused sends wrote %d times", env.world.writeCount-writes)
	}
}

// Untrusted text reaches a caller only once the runs its ancestry binds are tainted: withhold, the default, answers
// stubs and taints nothing; include taints first, and a taint that fails answers nothing.
func TestAgentsListIncludeTaintsTheCallersRunsFirst(t *testing.T) {
	env := newTestAgentToolsEnv(t)
	ctx := env.world.ctx
	caller := &testDaemonAgentsCaller{}
	methods := caller.methods(env.phone)
	list := testDaemonAgentsMethod(t, methods, DaemonMethodAgentsList)
	answer, err := list.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsListParams{}, false, ""))
	if err != nil || caller.taints != 0 {
		t.Fatalf("withhold: %v, %d taints", err, caller.taints)
	}
	if scraper := testAgentListEntry(answer.(*AgentList), "scraper"); scraper == nil || scraper.Stub == nil || scraper.Activity != "" {
		t.Fatalf("withheld: %+v", scraper)
	}
	answer, err = list.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsListParams{Untrusted: "include"}, false, ""))
	if err != nil || caller.taints != 1 {
		t.Fatalf("include: %v, %d taints", err, caller.taints)
	}
	if scraper := testAgentListEntry(answer.(*AgentList), "scraper"); scraper == nil || scraper.Activity != testAgentToolsInjection {
		t.Fatalf("included: %+v", scraper)
	}
	caller.taintErr = errors.New("the run's file did not take the taint")
	for _, name := range []string{DaemonMethodAgentsList, DaemonMethodAgentsGraph} {
		params := map[string]string{"untrusted": "include"}
		if answer, err := testDaemonAgentsMethod(t, methods, name).Handler(ctx, testDaemonAgentsCall(t, params, false, "")); !errors.Is(err, ErrAgentsTaintFirst) || answer != nil {
			t.Fatalf("%s with a failed taint: %+v, %v", name, answer, err)
		}
	}
	// the inbox withholds an untrusted writer's message's text off a terminal
	if _, err := env.tools.Send(ctx, (&testAgentsCaller{tainted: true}).caller("helper"), &AgentSendToolArgs{To: AgentNameMe, Body: testAgentToolsInjection}); err == nil {
		t.Fatal("a send to a me nobody registered landed")
	}
	if _, err := env.phone.RegisterMe(ctx, &AgentRegisterMeArgs{}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.tools.Send(ctx, (&testAgentsCaller{tainted: true}).caller("helper"), &AgentSendToolArgs{To: AgentNameMe, Body: testAgentToolsInjection}); err != nil {
		t.Fatal(err)
	}
	caller.taintErr = nil
	inbox := testDaemonAgentsMethod(t, methods, DaemonMethodAgentsInbox)
	answer, err = inbox.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsInboxParams{}, false, ""))
	if err != nil {
		t.Fatal(err)
	}
	read := answer.(*AgentPersonInbox)
	if read.Withheld != 1 || len(read.Threads) != 1 || read.Threads[0].Messages[0].Body != "" || !read.Threads[0].Messages[0].Withheld {
		t.Fatalf("the withheld inbox: %+v", read)
	}
	answer, err = inbox.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsInboxParams{Untrusted: "include"}, false, ""))
	if err != nil || answer.(*AgentPersonInbox).Threads[0].Messages[0].Body != testAgentToolsInjection || caller.taints != 2 {
		t.Fatalf("the included inbox: %+v, %v, %d taints", answer, err, caller.taints)
	}
}

// agents.watch: a first call answers the cursor alone; a message that lands after it comes back at the next, with its
// notification; params it does not know are refused.
func TestAgentsWatchAnswersPastTheCursor(t *testing.T) {
	env := newTestAgentsGraphEnv(t)
	ctx := env.world.ctx
	env.world.settings.WatchPassMinInterval = 0
	// the phone's person view takes its baseline first, at its first pass, so the message below is told whenever the
	// daemon's watch passes
	passed := make(chan error, 8)
	baseline, err := env.phone.WatchPerson(ctx, &AgentPersonWatchArgs{Passed: func(err error) { passed <- err }})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-passed; err != nil {
		t.Fatal(err)
	}
	baseline.Close()
	caller := &testDaemonAgentsCaller{}
	watch := testDaemonAgentsMethod(t, caller.methods(env.phone), DaemonMethodAgentsWatch)
	first, err := watch.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsWatchParams{}, false, ""))
	if err != nil {
		t.Fatal(err)
	}
	cursor := first.(*DaemonAgentsWatchReply).Cursor
	if len(first.(*DaemonAgentsWatchReply).Messages) != 0 || cursor == "" {
		t.Fatalf("the first call: %+v", first)
	}
	answered := make(chan *DaemonAgentsWatchReply, 1)
	go func() {
		reply, err := watch.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsWatchParams{Cursor: cursor, Untrusted: "include"}, false, ""))
		if err != nil {
			answered <- nil
			return
		}
		answered <- reply.(*DaemonAgentsWatchReply)
	}()
	if _, err := env.tools.Send(ctx, (&testAgentsCaller{}).caller("fix"), &AgentSendToolArgs{To: AgentNameMe, Subject: "done", Body: "Merged."}); err != nil {
		t.Fatal(err)
	}
	reply := <-answered
	if reply == nil {
		t.Fatal("the watch failed")
	}
	// a pass may land between the call's start and the message: read on from the cursor until it shows
	for len(reply.Messages) == 0 {
		next, err := watch.Handler(ctx, testDaemonAgentsCall(t, &DaemonAgentsWatchParams{Cursor: reply.Cursor, Untrusted: "include"}, false, ""))
		if err != nil {
			t.Fatal(err)
		}
		reply = next.(*DaemonAgentsWatchReply)
	}
	if len(reply.Messages) != 1 || reply.Messages[0].Message.Body != "Merged." || reply.Messages[0].Notification == nil ||
		reply.Messages[0].Notification.Sender != "fix" || !reply.Messages[0].Notification.ToPerson {
		t.Fatalf("the watch's answer: %+v", reply)
	}
	if _, err := watch.Handler(ctx, testDaemonAgentsCall(t, map[string]string{"after": "1"}, false, "")); !errors.Is(err, ErrDaemonAgentsParams) {
		t.Fatalf("a param it does not know: %v", err)
	}
}
