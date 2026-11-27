//go:build !ios_extension && !sidecar_http

// Threads (§20.7, R2-05, R-SKILL-9): a thread opened in the recipient's repo and answered any number of times in the
// same directory; two of a member's devices answering as me without seeing each other land two files under their own
// ids, every reader ordering them alike in both landing orders; a retry after a lost answer writes no second file, and
// the outbox lands a message composed before a crash once; a file's first version is the message, later ones alarmed;
// a path another message holds gives up the id, alarmed.

package sidecar

import (
	"errors"
	"testing"
)

// The laptop's agent fix, its agent orchestrator, and the person's me on the laptop and the phone.
type testAgentThreadEnv struct {
	world  *testAgentCardsWorld
	laptop *AgentsClient
	phone  *AgentsClient
	me     *AgentMeRegistration
	fix    *AgentRegistration
	boss   *AgentRegistration
}

func newTestAgentThreadEnv(t *testing.T) *testAgentThreadEnv {
	t.Helper()
	world := newTestAgentCardsWorld(t)
	env := &testAgentThreadEnv{world: world, laptop: world.client(world.laptop), phone: world.client(world.phone)}
	var err error
	if env.me, err = env.laptop.RegisterMe(world.ctx, &AgentRegisterMeArgs{Harness: "ur-harness 1.0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.phone.RegisterMe(world.ctx, &AgentRegisterMeArgs{Harness: "ur-harness 1.0"}); err != nil {
		t.Fatal(err)
	}
	if env.fix, err = env.laptop.Register(world.ctx, &AgentRegisterArgs{Name: "fix", Harness: "ur-harness 1.0", Model: "local-gemma"}); err != nil {
		t.Fatal(err)
	}
	if env.boss, err = env.laptop.Register(world.ctx, &AgentRegisterArgs{Name: "orchestrator", Harness: "ur-harness 1.0", Model: "local-gemma"}); err != nil {
		t.Fatal(err)
	}
	return env
}

// The files a thread's directory holds in repoId.
func (self *testAgentThreadEnv) fileCount(repoId Id, thread AgentThreadId) int {
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	count := 0
	for path := range self.world.repo(repoId).paths {
		if parsed, _, ok := ParseAgentMessagePath(path); ok && parsed == thread {
			count += 1
		}
	}
	return count
}

func TestSendOpensAndRepliesInOneThread(t *testing.T) {
	env := newTestAgentThreadEnv(t)
	world := env.world
	sent, err := env.laptop.Send(world.ctx, &AgentSendArgs{From: "orchestrator", To: "fix", Subject: "tests", Body: "run them",
		RunId: testConfigId("boss run"), ToolCallId: "call_1"})
	if err != nil {
		t.Fatal(err)
	}
	if sent.RepoId != env.fix.InboxRepoId || sent.Message.Seq != 1 || sent.Message.Kind != AgentMessageKindMessage ||
		sent.Message.To.Name != "fix" || sent.Message.To.RepoId != env.fix.InboxRepoId {
		t.Fatalf("the opening message: %+v in %s", sent.Message, sent.RepoId)
	}
	for i := 0; i < 3; i += 1 {
		from, to := AgentName("fix"), AgentName("orchestrator")
		if i%2 == 1 {
			from, to = to, from
		}
		reply, err := env.laptop.Send(world.ctx, &AgentSendArgs{From: from, To: to, Thread: sent.Message.Thread, ThreadRepoId: sent.RepoId, Body: "again"})
		if err != nil {
			t.Fatal(err)
		}
		if reply.RepoId != sent.RepoId || reply.Message.Seq != uint64(i+2) || reply.Message.Kind != AgentMessageKindReply {
			t.Fatalf("reply %d: %+v in %s", i, reply.Message, reply.RepoId)
		}
	}
	closed, err := env.laptop.Close(world.ctx, &AgentCloseArgs{From: "fix", To: "orchestrator", Thread: sent.Message.Thread, RepoId: sent.RepoId})
	if err != nil {
		t.Fatal(err)
	}
	thread, err := env.phone.Thread(world.ctx, sent.RepoId, sent.Message.Thread)
	if err != nil {
		t.Fatal(err)
	}
	if len(thread.Messages) != 5 || !thread.Closed || thread.HighestSeq != 5 || closed.Message.Seq != 5 {
		t.Fatalf("the thread: %d messages, closed %t, highest %d", len(thread.Messages), thread.Closed, thread.HighestSeq)
	}
	for i, message := range thread.Messages {
		if message.Message.Seq != uint64(i+1) || !message.Trust.Trusted() || !message.Trust.FromVerified {
			t.Errorf("message %d: seq %d, %+v", i, message.Message.Seq, message.Trust)
		}
	}
	// a broadcast opens a thread to every agent in the agents repo
	all, err := env.laptop.Broadcast(world.ctx, &AgentSendArgs{From: "orchestrator", Subject: "status", Body: "report"})
	if err != nil {
		t.Fatal(err)
	}
	if all.RepoId != env.fix.AgentsRepoId || !all.Message.ToAll() {
		t.Fatalf("the broadcast: %+v in %s", all.Message, all.RepoId)
	}
	if _, err := env.laptop.Send(world.ctx, &AgentSendArgs{From: "orchestrator", To: "nobody", Body: "x"}); !errors.Is(err, ErrAgentCardAbsent) {
		t.Fatalf("a send to no card: %v", err)
	}
	if _, err := env.phone.Send(world.ctx, &AgentSendArgs{From: "fix", To: "orchestrator", Body: "x"}); !errors.Is(err, ErrAgentsNotWriter) {
		t.Fatalf("a send from another sidecar's agent: %v", err)
	}
}

func TestTwoDevicesReplyAsMeDisconnected(t *testing.T) {
	for _, laptopFirst := range []bool{true, false} {
		env := newTestAgentThreadEnv(t)
		world := env.world
		report, err := env.laptop.Send(world.ctx, &AgentSendArgs{From: "fix", To: "me", Subject: "done", Body: "the limiter passes"})
		if err != nil {
			t.Fatal(err)
		}
		first, second := env.laptop, env.phone
		if !laptopFirst {
			first, second = second, first
		}
		reply := func(client *AgentsClient) *AgentSendResult {
			result, err := client.Send(world.ctx, &AgentSendArgs{Person: true, To: "fix", Thread: report.Message.Thread,
				ThreadRepoId: report.RepoId, Body: "thanks"})
			if err != nil {
				t.Fatal(err)
			}
			return result
		}
		// the second device writes while the first's write is in flight: neither saw the other's reply
		var late *AgentSendResult
		func() {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			world.beforeWrite = func() { late = reply(second) }
		}()
		early := reply(first)
		if early.Message.Seq != 2 || late.Message.Seq != 2 || early.Message.Id == late.Message.Id {
			t.Fatalf("two replies as me: seqs %d %d, ids %s %s", early.Message.Seq, late.Message.Seq, early.Message.Id, late.Message.Id)
		}
		if count := env.fileCount(report.RepoId, report.Message.Thread); count != 3 {
			t.Fatalf("%d files in the thread", count)
		}
		// every reader shows one order: by seq, equal seqs by id
		orders := [][]AgentMessageId{}
		for _, reader := range []*AgentsClient{env.laptop, env.phone} {
			thread, err := reader.Thread(world.ctx, report.RepoId, report.Message.Thread)
			if err != nil {
				t.Fatal(err)
			}
			order := []AgentMessageId{}
			for _, message := range thread.Messages {
				order = append(order, message.Message.Id)
				if message.Message.From.Person && message.Trust.Class != AgentMessageTrustPerson {
					t.Errorf("a person's reply reads %s", message.Trust.Class)
				}
			}
			orders = append(orders, order)
		}
		if len(orders[0]) != 3 || orders[0][1] != orders[1][1] || orders[0][2] != orders[1][2] {
			t.Fatalf("two readers' orders: %v and %v", orders[0], orders[1])
		}
		lower, higher := early.Message.Id, late.Message.Id
		if string(higher[:]) < string(lower[:]) {
			lower, higher = higher, lower
		}
		if orders[0][1] != lower || orders[0][2] != higher {
			t.Fatalf("equal seqs out of id order: %v", orders[0])
		}
	}
}

func TestRetryAfterLostReplyWritesNoSecondFile(t *testing.T) {
	env := newTestAgentThreadEnv(t)
	world := env.world
	// the write lands and its answer is lost: the retry reads the path, finds its own bytes and writes nothing
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.loseAnswers = 1
	}()
	sent, err := env.laptop.Send(world.ctx, &AgentSendArgs{From: "orchestrator", To: "fix", Body: "once", RunId: testConfigId("run"), ToolCallId: "call_1"})
	if err != nil {
		t.Fatal(err)
	}
	if !sent.Duplicate || env.fileCount(sent.RepoId, sent.Message.Thread) != 1 {
		t.Fatalf("a retry after a lost answer: duplicate %t, %d files", sent.Duplicate, env.fileCount(sent.RepoId, sent.Message.Thread))
	}
	world.stateLock.Lock()
	versions := len(world.repo(sent.RepoId).paths[sent.Path])
	world.stateLock.Unlock()
	if versions != 1 {
		t.Fatalf("%d versions of the message", versions)
	}
	// a message composed before a crash, kept in the outbox, lands once at the next flush, and the outbox empties
	composed := &AgentMessage{Id: AgentMessageIdForCall(testConfigId("run"), "call_2"), Thread: sent.Message.Thread, Seq: 2,
		From: sent.Message.From, To: &AgentAddress{MemberId: world.member, Name: "fix", RepoId: env.fix.InboxRepoId},
		Kind: AgentMessageKindReply, Body: "after the crash", Created: world.now()}
	data, err := EncodeAgentMessage(composed, world.settings)
	if err != nil {
		t.Fatal(err)
	}
	agentId := env.boss.AgentId
	if err := env.laptop.outboxPut(sent.RepoId, composed, data, &agentId, false); err != nil {
		t.Fatal(err)
	}
	landed, err := env.laptop.FlushOutbox(world.ctx)
	if err != nil || len(landed) != 1 || landed[0].Id != composed.Id {
		t.Fatalf("the flush: %v, %v", landed, err)
	}
	if again, err := env.laptop.FlushOutbox(world.ctx); err != nil || len(again) != 0 {
		t.Fatalf("a second flush: %v, %v", again, err)
	}
	thread, err := env.phone.Thread(world.ctx, sent.RepoId, sent.Message.Thread)
	if err != nil || len(thread.Messages) != 2 || thread.Messages[1].Message.Body != "after the crash" {
		t.Fatalf("the thread after the flush: %+v, %v", thread, err)
	}
}

func TestFirstVersionIsTheMessage(t *testing.T) {
	env := newTestAgentThreadEnv(t)
	world := env.world
	sent, err := env.laptop.Send(world.ctx, &AgentSendArgs{From: "orchestrator", To: "fix", Body: "the first words"})
	if err != nil {
		t.Fatal(err)
	}
	rewritten := *sent.Message
	rewritten.Body = "the words changed after the message was sent"
	data, err := EncodeAgentMessage(&rewritten, world.settings)
	if err != nil {
		t.Fatal(err)
	}
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.repo(sent.RepoId).put(world.phone, sent.Path, data)
	}()
	thread, err := env.phone.Thread(world.ctx, sent.RepoId, sent.Message.Thread)
	if err != nil {
		t.Fatal(err)
	}
	if len(thread.Messages) != 1 || thread.Messages[0].Message.Body != "the first words" || len(thread.Messages[0].Rewritten) != 1 {
		t.Fatalf("the message past a rewrite: %+v", thread.Messages[0])
	}
	if world.alarmCount() != 1 {
		t.Fatalf("%d alarms for one rewrite", world.alarmCount())
	}
}

func TestCreateOnlyCollisionAlarms(t *testing.T) {
	env := newTestAgentThreadEnv(t)
	world := env.world
	sent, err := env.laptop.Send(world.ctx, &AgentSendArgs{From: "orchestrator", To: "fix", Body: "mine", RunId: testConfigId("run"), ToolCallId: "call_1"})
	if err != nil {
		t.Fatal(err)
	}
	// the same run and call composing other words: the path holds another message, so the id is given up
	_, err = env.laptop.Send(world.ctx, &AgentSendArgs{From: "orchestrator", To: "fix", Body: "other words", RunId: testConfigId("run"),
		ToolCallId: "call_1", Thread: sent.Message.Thread, ThreadRepoId: sent.RepoId})
	if !errors.Is(err, ErrAgentMessageIdTaken) {
		t.Fatalf("a collision: %v", err)
	}
	if env.fileCount(sent.RepoId, sent.Message.Thread) != 1 || world.alarmCount() != 1 || world.alarms[0].Reason != SidecarRecordAlarmIdReuse {
		t.Fatalf("after the collision: %d files, alarms %+v", env.fileCount(sent.RepoId, sent.Message.Thread), world.alarms)
	}
	if waiting, err := env.laptop.outboxList(); err != nil || len(waiting) != 0 {
		t.Fatalf("the outbox kept a message whose id is taken: %d, %v", len(waiting), err)
	}
}
