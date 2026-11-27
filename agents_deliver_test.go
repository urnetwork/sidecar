//go:build !ios_extension && !sidecar_http

// Delivery (§20.7's notify, where agents wait and loops rows, D-SKILL-8, D-SKILL-11): a watch leases the agents repo's
// and each agent's inbox, and at each change hands what names an agent to the Harness's delivery, once; a message to a
// closed run waits and is taken once when the run reopens, a late one whose seq falls below the last taken included; a
// thread to every agent wakes every watched agent, and a message in it naming one wakes that one alone; a report to me
// shows on every device of the member and wakes no agent; a send answers its recipient's state; a support notice is
// written once on every device and taken as support's, tainting nothing.

package sidecar

import (
	"context"
	"sync"
	"testing"
	"time"
)

// The Harness's delivery as a test sees it: which runs are open, and what it was handed.
type testAgentsDelivery struct {
	stateLock sync.Mutex
	open      map[AgentName]bool
	delivered chan *AgentDelivery
}

func newTestAgentsDelivery(open ...AgentName) *testAgentsDelivery {
	delivery := &testAgentsDelivery{open: map[AgentName]bool{}, delivered: make(chan *AgentDelivery, 64)}
	for _, name := range open {
		delivery.open[name] = true
	}
	return delivery
}

func (self *testAgentsDelivery) RunOpen(name AgentName) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.open[name]
}

func (self *testAgentsDelivery) setOpen(name AgentName, open bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.open[name] = open
}

func (self *testAgentsDelivery) Deliver(ctx context.Context, delivery *AgentDelivery) error {
	self.delivered <- delivery
	return nil
}

// What was delivered so far, without waiting.
func (self *testAgentsDelivery) drain() []*AgentDelivery {
	drained := []*AgentDelivery{}
	for {
		select {
		case delivery := <-self.delivered:
			drained = append(drained, delivery)
		default:
			return drained
		}
	}
}

// A watch whose passes the test hears, each pass right after the one before.
type testAgentsWatch struct {
	watch  *AgentInboxWatch
	passed chan error
}

func newTestAgentsWatch(t *testing.T, client *AgentsClient, args *AgentWatchArgs) *testAgentsWatch {
	t.Helper()
	passed := make(chan error, 64)
	args.Passed = func(err error) { passed <- err }
	watch, err := client.Watch(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(watch.Close)
	test := &testAgentsWatch{watch: watch, passed: passed}
	test.pass(t)
	return test
}

// Waits for the watch's next pass.
func (self *testAgentsWatch) pass(t *testing.T) {
	t.Helper()
	if err := <-self.passed; err != nil {
		t.Fatalf("a pass: %v", err)
	}
}

// The thread env with passes back to back.
func newTestAgentDeliverEnv(t *testing.T) *testAgentThreadEnv {
	t.Helper()
	env := newTestAgentThreadEnv(t)
	env.world.settings.WatchPassMinInterval = 0
	return env
}

func TestWatchDeliversOnLease(t *testing.T) {
	env := newTestAgentDeliverEnv(t)
	world := env.world
	delivery := newTestAgentsDelivery("fix")
	watch := newTestAgentsWatch(t, env.laptop, &AgentWatchArgs{Agents: []AgentName{"fix"}, Delivery: delivery})
	if world.watcherCount(env.fix.InboxRepoId) != 1 || world.watcherCount(env.fix.AgentsRepoId) != 1 {
		t.Fatalf("leases: %d on the agent repo, %d on the agents repo", world.watcherCount(env.fix.InboxRepoId), world.watcherCount(env.fix.AgentsRepoId))
	}
	sent, err := env.laptop.Send(world.ctx, &AgentSendArgs{From: "orchestrator", To: "fix", Body: "run the tests"})
	if err != nil {
		t.Fatal(err)
	}
	watch.pass(t)
	delivered := delivery.drain()
	if len(delivered) != 1 || delivered[0].Agent != "fix" || delivered[0].Message.Message.Id != sent.Message.Id || !delivered[0].Wake || delivered[0].Taints {
		t.Fatalf("the delivery: %+v", delivered)
	}
	// a sync that delivers the same file again takes nothing twice
	watch.watch.Poke()
	watch.pass(t)
	if again := delivery.drain(); len(again) != 0 {
		t.Fatalf("%d deliveries of a message already taken", len(again))
	}
	// the agent's own message, and a message to another agent, are not its
	if _, err := env.laptop.Send(world.ctx, &AgentSendArgs{From: "fix", To: "orchestrator", Thread: sent.Message.Thread, ThreadRepoId: sent.RepoId, Body: "done"}); err != nil {
		t.Fatal(err)
	}
	watch.pass(t)
	if own := delivery.drain(); len(own) != 0 {
		t.Fatalf("an agent was handed its own message: %+v", own)
	}
	watch.watch.Close()
	if world.watcherCount(env.fix.InboxRepoId) != 0 {
		t.Fatal("a closed watch kept its lease")
	}
}

func TestClosedRunTakesOnceOnReopen(t *testing.T) {
	env := newTestAgentDeliverEnv(t)
	world := env.world
	delivery := newTestAgentsDelivery("fix")
	watch := newTestAgentsWatch(t, env.laptop, &AgentWatchArgs{Agents: []AgentName{"fix"}, Delivery: delivery})
	opened, err := env.laptop.Send(world.ctx, &AgentSendArgs{From: "orchestrator", To: "fix", Body: "one"})
	if err != nil {
		t.Fatal(err)
	}
	watch.pass(t)
	// a reply at seq 3 lands and is taken while the run is open
	third := &AgentMessage{Id: AgentMessageIdForCall(testConfigId("boss run"), "third"), Thread: opened.Message.Thread, Seq: 3,
		From: opened.Message.From, To: opened.Message.To, Kind: AgentMessageKindReply, Body: "three", Created: world.now()}
	land := func(message *AgentMessage) {
		t.Helper()
		data, err := EncodeAgentMessage(message, world.settings)
		if err != nil {
			t.Fatal(err)
		}
		agentId := env.boss.AgentId
		if _, err := env.laptop.landMessage(world.ctx, opened.RepoId, env.laptop.args.Repo(opened.RepoId), message, data, &agentId, false); err != nil {
			t.Fatal(err)
		}
	}
	land(third)
	watch.pass(t)
	if taken := delivery.drain(); len(taken) != 2 {
		t.Fatalf("%d deliveries while open", len(taken))
	}
	// the host goes down: a late message whose seq falls below the last taken lands and waits
	delivery.setOpen("fix", false)
	late := *third
	late.Id, late.Seq, late.Body = AgentMessageIdForCall(testConfigId("boss run"), "late"), 2, "two, late"
	land(&late)
	watch.pass(t)
	if waiting := delivery.drain(); len(waiting) != 0 {
		t.Fatalf("a closed run was handed %d messages", len(waiting))
	}
	untaken, err := env.laptop.Untaken(world.ctx, &AgentUntakenArgs{Agent: "fix"})
	if err != nil {
		t.Fatal(err)
	}
	if len(untaken) != 1 || untaken[0].Message.Id != late.Id {
		t.Fatalf("untaken at reopening: %d messages", len(untaken))
	}
	// the run reopens: the watch takes it once, and nothing is untaken after
	delivery.setOpen("fix", true)
	watch.watch.Poke()
	watch.pass(t)
	reopened := delivery.drain()
	if len(reopened) != 1 || reopened[0].Message.Message.Id != late.Id {
		t.Fatalf("at reopening: %+v", reopened)
	}
	watch.watch.Poke()
	watch.pass(t)
	if again := delivery.drain(); len(again) != 0 {
		t.Fatalf("taken twice: %d", len(again))
	}
	if untaken, err := env.laptop.Untaken(world.ctx, &AgentUntakenArgs{Agent: "fix"}); err != nil || len(untaken) != 0 {
		t.Fatalf("untaken after the reopening: %d, %v", len(untaken), err)
	}
}

func TestStarThreadWakesOnlyNamedAgent(t *testing.T) {
	env := newTestAgentDeliverEnv(t)
	world := env.world
	if _, err := env.laptop.Register(world.ctx, &AgentRegisterArgs{Name: "docs", Harness: "ur-harness 1.0", Model: "local-gemma"}); err != nil {
		t.Fatal(err)
	}
	delivery := newTestAgentsDelivery("fix", "docs")
	watch := newTestAgentsWatch(t, env.laptop, &AgentWatchArgs{Agents: []AgentName{"fix", "docs"}, Delivery: delivery})
	all, err := env.phone.Broadcast(world.ctx, &AgentSendArgs{Person: true, Subject: "status", Body: "what are you doing"})
	if err != nil {
		t.Fatal(err)
	}
	watch.pass(t)
	delivered := delivery.drain()
	names := map[AgentName]bool{}
	for _, delivery := range delivered {
		names[delivery.Agent] = true
	}
	if len(delivered) != 2 || !names["fix"] || !names["docs"] {
		t.Fatalf("a thread to every agent: %+v", delivered)
	}
	// the person answers fix alone in the same thread: only fix wakes, though docs can read it
	if _, err := env.phone.Send(world.ctx, &AgentSendArgs{Person: true, To: "fix", Thread: all.Message.Thread, ThreadRepoId: all.RepoId, Body: "you, go on"}); err != nil {
		t.Fatal(err)
	}
	watch.pass(t)
	named := delivery.drain()
	if len(named) != 1 || named[0].Agent != "fix" {
		t.Fatalf("a message naming one agent in a thread to all: %+v", named)
	}
}

func TestMeReportShowsOnEveryDevice(t *testing.T) {
	env := newTestAgentDeliverEnv(t)
	world := env.world
	shown := map[Id]chan *AgentThreadMessage{world.laptop: make(chan *AgentThreadMessage, 8), world.phone: make(chan *AgentThreadMessage, 8)}
	watches := map[Id]*testAgentsWatch{}
	for _, device := range []struct {
		sidecarId Id
		client    *AgentsClient
	}{{sidecarId: world.laptop, client: env.laptop}, {sidecarId: world.phone, client: env.phone}} {
		sink := shown[device.sidecarId]
		watches[device.sidecarId] = newTestAgentsWatch(t, device.client, &AgentWatchArgs{Me: "me", Person: func(message *AgentThreadMessage) { sink <- message }})
	}
	delivery := newTestAgentsDelivery("fix", "orchestrator")
	agents := newTestAgentsWatch(t, env.laptop, &AgentWatchArgs{Agents: []AgentName{"fix", "orchestrator"}, Delivery: delivery})
	report, err := env.laptop.Send(world.ctx, &AgentSendArgs{From: "fix", To: "me", Subject: "done", Body: "the limiter passes"})
	if err != nil {
		t.Fatal(err)
	}
	for sidecarId, watch := range watches {
		watch.pass(t)
		select {
		case message := <-shown[sidecarId]:
			if message.MessageId != report.Message.Id || message.Body != "the limiter passes" || message.Trust != AgentMessageTrustMemberRun {
				t.Errorf("the report on %s: %+v", sidecarId, message)
			}
		default:
			t.Errorf("the report did not show on %s", sidecarId)
		}
	}
	// the report's repo is no agent's lease: read again by hand, and nothing is handed to an agent
	agents.watch.Poke()
	agents.pass(t)
	if woken := delivery.drain(); len(woken) != 0 {
		t.Fatalf("a report to me woke %d agents", len(woken))
	}
}

func TestSendAnswersOfflineState(t *testing.T) {
	env := newTestAgentDeliverEnv(t)
	world := env.world
	world.timers = newHarnessTestClock()
	laptop := world.client(world.laptop)
	sent, err := laptop.Send(world.ctx, &AgentSendArgs{From: "orchestrator", To: "fix", Body: "are you there"})
	if err != nil {
		t.Fatal(err)
	}
	if sent.RecipientState != AgentStateOffline {
		t.Fatalf("an agent with no status: %s", sent.RecipientState)
	}
	if err := laptop.WriteStatus(world.ctx, &AgentStatusWrite{Name: "fix", Status: &AgentStatus{State: AgentStateWorking, Updated: world.now()}}); err != nil {
		t.Fatal(err)
	}
	if sent, err = laptop.Send(world.ctx, &AgentSendArgs{From: "orchestrator", To: "fix", Body: "again"}); err != nil || sent.RecipientState != AgentStateWorking {
		t.Fatalf("an agent at work: %s, %v", sent.RecipientState, err)
	}
	world.timers.Advance(world.settings.OfflineAfter)
	if sent, err = laptop.Send(world.ctx, &AgentSendArgs{From: "orchestrator", To: "fix", Body: "and again"}); err != nil || sent.RecipientState != AgentStateOffline {
		t.Fatalf("an agent quiet past the bound: %s, %v", sent.RecipientState, err)
	}
	if all, err := laptop.Broadcast(world.ctx, &AgentSendArgs{From: "orchestrator", Body: "everyone"}); err != nil || all.RecipientState != "" {
		t.Fatalf("a broadcast's state: %q, %v", all.RecipientState, err)
	}
}

func TestSupportNoticeWrittenOnceAndTakenAsSupport(t *testing.T) {
	env := newTestAgentDeliverEnv(t)
	world := env.world
	update := &SupportUpdate{Product: SupportProductUrnetwork, Entry: "100171", Seq: 2, Type: "note", Status: "in_progress"}
	first, err := env.laptop.WriteSupportNotice(world.ctx, "fix", update)
	if err != nil {
		t.Fatal(err)
	}
	// another device of the member writes the same notice: the one path, counted written, nothing alarmed
	second, err := env.phone.WriteSupportNotice(world.ctx, "fix", update)
	if err != nil || !second.Duplicate || second.Path != first.Path {
		t.Fatalf("the second device's notice: %+v, %v", second, err)
	}
	if world.alarmCount() != 0 {
		t.Fatalf("%d alarms for one notice", world.alarmCount())
	}
	delivery := newTestAgentsDelivery("fix")
	newTestAgentsWatch(t, env.laptop, &AgentWatchArgs{Agents: []AgentName{"fix"}, Delivery: delivery})
	delivered := delivery.drain()
	if len(delivered) != 1 || delivered[0].Taints || delivered[0].Message.Trust.Class != AgentMessageTrustSupport ||
		delivered[0].Message.Message.Support.Entry != "100171" {
		t.Fatalf("the notice's delivery: %+v", delivered)
	}
}

// Within the hour, a sender's sixth wake is refused, and the hour's twenty-first from any sender; the window slides,
// and a person's input starts the counts again; a thread past its bound wakes nothing.
func TestWakeLimitsPerHourPerSenderPerThread(t *testing.T) {
	settings := DefaultSkillSettings()
	limiter := NewAgentWakeLimiter(settings)
	start := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	at := func(minutes int) time.Time { return start.Add(time.Duration(minutes) * time.Minute) }
	for i := 0; i < settings.MaxWakesPerSender; i += 1 {
		if allowed, refusal := limiter.Allow("fix", "sidecar a", 1, at(i)); !allowed {
			t.Fatalf("wake %d of one sender: %s", i+1, refusal)
		}
	}
	if allowed, refusal := limiter.Allow("fix", "sidecar a", 1, at(6)); allowed || refusal != AgentWakeRefusalSender {
		t.Fatalf("a sixth wake from one sender: %t %s", allowed, refusal)
	}
	for i := 0; i < settings.MaxWakesPerHour-settings.MaxWakesPerSender; i += 1 {
		sender := []string{"sidecar b", "sidecar c", "sidecar d", AgentWakeSenderSupport}[i%4]
		if allowed, refusal := limiter.Allow("fix", sender, 1, at(10)); !allowed {
			t.Fatalf("wake %d of the hour: %s", settings.MaxWakesPerSender+i+1, refusal)
		}
	}
	if allowed, refusal := limiter.Allow("fix", "sidecar e", 1, at(20)); allowed || refusal != AgentWakeRefusalHour {
		t.Fatalf("the hour's twenty-first wake: %t %s", allowed, refusal)
	}
	if limiter.Count("fix", at(20)) != settings.MaxWakesPerHour {
		t.Fatalf("%d wakes counted", limiter.Count("fix", at(20)))
	}
	// an hour after the first wakes, they no longer count
	if allowed, _ := limiter.Allow("fix", "sidecar a", 1, at(61)); !allowed {
		t.Fatal("the window did not slide")
	}
	limiter.PersonInput("fix")
	if limiter.Count("fix", at(61)) != 0 {
		t.Fatal("a person's input left the counts")
	}
	if allowed, refusal := limiter.Allow("fix", "sidecar a", settings.ThreadMessageMax+1, at(62)); allowed || refusal != AgentWakeRefusalThread {
		t.Fatalf("a thread past its bound: %t %s", allowed, refusal)
	}
	// another agent's counts are its own
	if allowed, _ := limiter.Allow("docs", "sidecar a", 1, at(62)); !allowed {
		t.Fatal("one agent's wakes counted against another")
	}
}

// Through a watch: past the sender's limit the delivery stops queuing, the status hears why, and the message waits.
func TestWatchStopsQueuingPastWakeLimit(t *testing.T) {
	env := newTestAgentDeliverEnv(t)
	world := env.world
	world.settings.MaxWakesPerSender = 1
	limited := make(chan AgentWakeRefusal, 8)
	delivery := newTestAgentsDelivery("fix")
	watch := newTestAgentsWatch(t, env.laptop, &AgentWatchArgs{Agents: []AgentName{"fix"}, Delivery: delivery,
		Limited: func(agent AgentName, refusal AgentWakeRefusal) { limited <- refusal }})
	for i := 0; i < 2; i += 1 {
		if _, err := env.laptop.Send(world.ctx, &AgentSendArgs{From: "orchestrator", To: "fix", Body: "ping"}); err != nil {
			t.Fatal(err)
		}
		watch.pass(t)
	}
	if delivered := delivery.drain(); len(delivered) != 1 {
		t.Fatalf("%d deliveries past one wake", len(delivered))
	}
	select {
	case refusal := <-limited:
		if refusal != AgentWakeRefusalSender {
			t.Fatalf("the status heard %s", refusal)
		}
	default:
		t.Fatal("the status heard nothing")
	}
	// the person's input: what waited is taken
	watch.watch.PersonInput("fix")
	watch.pass(t)
	if delivered := delivery.drain(); len(delivered) != 1 {
		t.Fatalf("after the person's input: %d deliveries", len(delivered))
	}
}
