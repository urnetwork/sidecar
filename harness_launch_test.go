//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// The sub-agent tools' registrations, by name, for a test world.
func harnessAgentTestSpecs() map[string]*HarnessToolSpec {
	specs := map[string]*HarnessToolSpec{}
	for _, name := range []string{HarnessToolAgentLaunch, HarnessToolAgentPrompt, HarnessToolAgentWait, HarnessToolAgentStop} {
		specs[name] = harnessToolSpecs[name]
	}
	return specs
}

// A world whose agents hold the sub-agent tools.
func newHarnessLaunchTestWorld(t *testing.T, router *harnessScriptedRouter, args *HarnessArgs) *harnessTestWorld {
	t.Helper()
	return newHarnessTestWorld(t, router, harnessAgentTestSpecs(), args)
}

// The launch's refusal, failing where err is none.
func harnessLaunchRefusal(t *testing.T, err error) *HarnessLaunchError {
	t.Helper()
	refused := &HarnessLaunchError{}
	if !errors.As(err, &refused) {
		t.Fatalf("not a launch refusal: %v", err)
	}
	return refused
}

// The events an agent's subscribers got so far, without waiting.
func (self *harnessEventLog) drain() []*HarnessEvent {
	events := []*HarnessEvent{}
	for {
		select {
		case event := <-self.events:
			events = append(events, event)
		default:
			return events
		}
	}
}

// A launch whose model the floor refuses fails with model_refused before the child starts: nothing registered, no run
// opened, no agent_spawned, the parent's tree unchanged.
func TestHarnessLaunchRefusesModelBelowFloor(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	router.check = func(request *InferRequest) error {
		if request.RunId != nil {
			return &InferError{Code: InferErrorModelRefused, Reason: "floor", Model: request.Model, Message: "below the network's floor"}
		}
		return nil
	}
	world := newHarnessLaunchTestWorld(t, router, nil)
	parent := world.agent(t, &HarnessAgentSpec{Name: "lead"})
	log := harnessCollect(t, parent)
	_, err := world.harness.Launch(context.Background(), parent.Id(), &HarnessLaunchSpec{Name: "helper", Model: harnessTestModel,
		Instructions: "find the bug"})
	refused := harnessLaunchRefusal(t, err)
	if refused.Code != HarnessLaunchModelRefused || InferErrorCodeOf(refused) != InferErrorModelRefused {
		t.Fatalf("the refusal: %+v", refused)
	}
	if len(world.skill.registrations) != 1 || len(world.harness.agents) != 1 || len(log.drain()) != 0 {
		t.Fatalf("a refused launch left a card: %d registrations, %d agents", len(world.skill.registrations), len(world.harness.agents))
	}
	if checked := router.made(); len(checked) != 0 {
		t.Fatalf("a refused launch called the model")
	}
}

// A model the person's allow refuses, and one the parent's limited_use mark keeps from the run, are model_refused too:
// the check runs under the parent's run, whose marks the child would take.
func TestHarnessLaunchRefusesModelOutsideAllow(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	world := newHarnessLaunchTestWorld(t, router, nil)
	parent := world.agent(t, &HarnessAgentSpec{Name: "lead"})
	checkedRuns := []Id{}
	router.check = func(request *InferRequest) error {
		if request.RunId == nil {
			return nil
		}
		checkedRuns = append(checkedRuns, *request.RunId)
		marks, _ := world.runs.Marks(*request.RunId)
		if slices.Contains(marks, "limited_use") {
			return &InferError{Code: InferErrorServiceModel, Model: request.Model, Message: "a connected service's data stays off this model"}
		}
		return &InferError{Code: InferErrorModelRefused, Reason: "allow", Model: request.Model, Message: "outside the person's allow"}
	}
	_, err := world.harness.Launch(context.Background(), parent.Id(), &HarnessLaunchSpec{Name: "helper", Model: harnessTestModel})
	if refused := harnessLaunchRefusal(t, err); refused.Code != HarnessLaunchModelRefused || !strings.Contains(refused.Message, "allow") {
		t.Fatalf("outside the allow: %+v", refused)
	}
	if err := parent.Run().Mark(context.Background(), HarnessMarkLimitedUse); err != nil {
		t.Fatal(err)
	}
	_, err = world.harness.Launch(context.Background(), parent.Id(), &HarnessLaunchSpec{Name: "helper", Model: harnessTestModel})
	if refused := harnessLaunchRefusal(t, err); refused.Code != HarnessLaunchModelRefused || InferErrorCodeOf(refused) != InferErrorServiceModel {
		t.Fatalf("the parent's limited_use: %+v", refused)
	}
	if len(checkedRuns) != 2 || checkedRuns[0] != parent.Run().Id() || checkedRuns[1] != parent.Run().Id() {
		t.Fatalf("the checks ran under %v", checkedRuns)
	}
}

// A none model whose disclosure is not acknowledged raises the disclosure request in the launching run while the person
// is attached to it, its id and version alone; once the person acknowledges, the child starts.
func TestHarnessLaunchNoneModelAsksAttachedRun(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	acks := newHarnessTestAcks()
	world := newHarnessLaunchTestWorld(t, router, &HarnessArgs{Acks: acks})
	parent := world.agent(t, &HarnessAgentSpec{Name: "lead"})
	router.check = func(request *InferRequest) error {
		if request.RunId != nil && request.Model == harnessTestModel {
			return &InferError{Code: InferErrorDisclosureRequired, Reason: InferDisclosureReasonUnacknowledged, Model: request.Model,
				DisclosureId: "provider-engy", DisclosureVersion: 3}
		}
		return nil
	}
	detach := world.harness.UiBroker().AttachPerson(parent.Run().Id())
	defer detach()
	log := harnessCollect(t, parent)
	type launched struct {
		child HarnessAgent
		err   error
	}
	done := make(chan *launched, 1)
	go func() {
		child, err := world.harness.Launch(context.Background(), parent.Id(), &HarnessLaunchSpec{Name: "helper", Model: harnessTestModel})
		done <- &launched{child: child, err: err}
	}()
	events := log.until(t, HarnessEventUiRequest)
	request := events[len(events)-1].UiRequest()
	if request == nil || request.Method != HarnessUiDisclosure || request.DisclosureId != "provider-engy" || request.DisclosureVersion != 3 ||
		request.Title != "" || request.Message != "" {
		t.Fatalf("the request: %+v", request)
	}
	acks.acknowledge("provider-engy", 3)
	got := <-done
	if got.err != nil || got.child == nil {
		t.Fatalf("the launch after the acknowledgment: %v", got.err)
	}
}

// Unattached, the same launch fails with disclosure_required, naming the disclosure, and asks nothing.
func TestHarnessLaunchNoneModelUnattachedDisclosureRequired(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	world := newHarnessLaunchTestWorld(t, router, &HarnessArgs{Acks: newHarnessTestAcks()})
	parent := world.agent(t, &HarnessAgentSpec{Name: "lead"})
	router.check = func(request *InferRequest) error {
		if request.RunId != nil {
			return &InferError{Code: InferErrorDisclosureRequired, Reason: InferDisclosureReasonUnacknowledged, Model: request.Model,
				DisclosureId: "provider-engy", DisclosureVersion: 3}
		}
		return nil
	}
	log := harnessCollect(t, parent)
	_, err := world.harness.Launch(context.Background(), parent.Id(), &HarnessLaunchSpec{Name: "helper", Model: harnessTestModel})
	refused := harnessLaunchRefusal(t, err)
	if refused.Code != HarnessLaunchDisclosureRequired || refused.DisclosureId != "provider-engy" || refused.DisclosureVersion != 3 {
		t.Fatalf("the refusal: %+v", refused)
	}
	if events := log.drain(); len(events) != 0 || len(world.harness.agents) != 1 {
		t.Fatalf("an unattached refusal asked or left a card: %v", harnessEventTypesOf(events))
	}
}

// A child launched by a tainted run starts tainted, before any of its own calls, and its instructions, the tainted run's
// text, reach its model between untrusted-data markers naming the parent's tainted run.
func TestHarnessTaintedParentChildStartsTainted(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	world := newHarnessLaunchTestWorld(t, router, nil)
	parent := world.agent(t, &HarnessAgentSpec{Name: "lead"})
	if err := parent.Run().Taint(context.Background(), RunTaintUntrustedData); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	router.script(&harnessScriptedCall{events: harnessTextCall("on it").events, release: release})
	child, err := world.harness.Launch(context.Background(), parent.Id(), &HarnessLaunchSpec{Name: "helper", Model: harnessTestModel,
		Instructions: "summarize what the page said"})
	if err != nil {
		t.Fatal(err)
	}
	if !child.Run().Tainted() {
		t.Fatalf("the child of a tainted run started untainted")
	}
	request := <-router.called
	last := request.Messages[len(request.Messages)-1]
	if !strings.HasPrefix(last.Text(), HarnessUntrustedBegin+" (from a tainted run of agent "+parent.Id().String()+")") ||
		!strings.Contains(last.Text(), "summarize what the page said") {
		t.Fatalf("the child's first prompt: %q", last.Text())
	}
	close(release)
	if err := child.WaitForIdle(context.Background()); err != nil {
		t.Fatal(err)
	}

	// an untainted parent's child starts untainted, its instructions trusted
	other := world.agent(t, &HarnessAgentSpec{Name: "clean"})
	cleanChild, err := world.harness.Launch(context.Background(), other.Id(), &HarnessLaunchSpec{Name: "helper2", Model: harnessTestModel})
	if err != nil {
		t.Fatal(err)
	}
	if cleanChild.Run().Tainted() {
		t.Fatalf("an untainted parent's child started tainted")
	}
}

// Agents launch at most AgentDepthCount levels deep, counted along the parent chain the Harness holds; and at most
// AgentConcurrentCount agents are at work at once, a prompt past them accepted but waiting its turn, starting once one
// settles.
func TestHarnessLaunchLimitsEightAtWorkFourDeep(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	world := newHarnessLaunchTestWorld(t, router, nil)
	root := world.agent(t, &HarnessAgentSpec{Name: "root"})
	parentId := root.Id()
	for depth := 2; depth <= 4; depth++ {
		child, err := world.harness.Launch(context.Background(), parentId, &HarnessLaunchSpec{Name: "level", Model: harnessTestModel})
		if err != nil {
			t.Fatalf("depth %d: %v", depth, err)
		}
		parentId = child.Id()
	}
	_, err := world.harness.Launch(context.Background(), parentId, &HarnessLaunchSpec{Name: "too-deep", Model: harnessTestModel})
	if refused := harnessLaunchRefusal(t, err); refused.Code != HarnessLaunchDepthLimit {
		t.Fatalf("the fifth level: %+v", refused)
	}

	releases := []chan struct{}{}
	for i := 0; i < 8; i++ {
		release := make(chan struct{})
		releases = append(releases, release)
		router.script(&harnessScriptedCall{events: harnessTextCall("working").events, release: release})
	}
	router.script(harnessTextCall("my turn"))
	workers := []HarnessAgent{}
	for i := 0; i < 8; i++ {
		worker := world.agent(t, &HarnessAgentSpec{Name: "worker"})
		workers = append(workers, worker)
		if err := worker.Prompt(context.Background(), "work", nil); err != nil {
			t.Fatal(err)
		}
		<-router.called
	}
	waiting := world.agent(t, &HarnessAgentSpec{Name: "waiting"})
	waitingLog := harnessCollect(t, waiting)
	if err := waiting.Prompt(context.Background(), "work too", nil); err != nil {
		t.Fatal(err)
	}
	if len(world.harness.workSlots) != 8 || !waiting.Running() {
		t.Fatalf("%d slots taken, the ninth running %t", len(world.harness.workSlots), waiting.Running())
	}
	// every slot is taken, so the ninth cannot have started
	for _, event := range waitingLog.drain() {
		if event.Type == HarnessEventAgentStart {
			t.Fatalf("the ninth agent started past the limit")
		}
	}
	close(releases[0])
	<-router.called
	waitingLog.until(t, HarnessEventAgentSettled)
	for _, release := range releases[1:] {
		close(release)
	}
	for _, worker := range workers {
		if err := worker.WaitForIdle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

// A child's budget comes out of its parent's: asking none it takes the parent's, the run's what the parent's run has
// left, under the parent's budget's id, which its calls carry; asking more than the parent has on any period is
// refused before it starts.
func TestHarnessChildBudgetFromParent(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	world := newHarnessLaunchTestWorld(t, router, nil)
	budget := &HarnessBudget{Id: NewId(), DayNanoUsd: 5_000_000_000, RunNanoUsd: 1_000_000_000}
	parent := world.agent(t, &HarnessAgentSpec{Name: "lead", Budget: budget})
	_, err := world.harness.Launch(context.Background(), parent.Id(), &HarnessLaunchSpec{Name: "greedy", Model: harnessTestModel,
		Budget: &HarnessBudget{DayNanoUsd: 10_000_000_000}})
	if refused := harnessLaunchRefusal(t, err); refused.Code != HarnessLaunchBudgetLimit {
		t.Fatalf("a child asking more: %+v", refused)
	}
	_, err = world.harness.Launch(context.Background(), parent.Id(), &HarnessLaunchSpec{Name: "greedy", Model: harnessTestModel,
		Budget: &HarnessBudget{RunNanoUsd: 2_000_000_000}})
	if refused := harnessLaunchRefusal(t, err); refused.Code != HarnessLaunchBudgetLimit {
		t.Fatalf("a child asking more run budget: %+v", refused)
	}
	router.script(harnessTextCall("done"))
	child, err := world.harness.Launch(context.Background(), parent.Id(), &HarnessLaunchSpec{Name: "helper", Model: harnessTestModel,
		Instructions: "go"})
	if err != nil {
		t.Fatal(err)
	}
	inner := child.(*harnessAgent)
	if inner.spec.Budget.Id != budget.Id || inner.spec.Budget.DayNanoUsd != budget.DayNanoUsd || inner.spec.Budget.RunNanoUsd != budget.RunNanoUsd {
		t.Fatalf("the child's budget: %+v", inner.spec.Budget)
	}
	request := <-router.called
	if request.Budget == nil || request.Budget.Id != budget.Id {
		t.Fatalf("the child's call carries budget %+v", request.Budget)
	}
	if err := child.WaitForIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	smaller, err := world.harness.Launch(context.Background(), parent.Id(), &HarnessLaunchSpec{Name: "modest", Model: harnessTestModel,
		Budget: &HarnessBudget{DayNanoUsd: 1_000_000_000}})
	if err != nil {
		t.Fatal(err)
	}
	if got := smaller.(*harnessAgent).spec.Budget; got.Id != budget.Id || got.DayNanoUsd != 1_000_000_000 || got.RunNanoUsd != budget.RunNanoUsd {
		t.Fatalf("a smaller child's budget: %+v", got)
	}
}

// A child's events reach its parent's subscribers nested under agent_spawned, naming the child, its model and where it
// runs; agent_exited follows when the child closes.
func TestHarnessChildEventsNestUnderSpawned(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	world := newHarnessLaunchTestWorld(t, router, nil)
	parent := world.agent(t, &HarnessAgentSpec{Name: "lead"})
	log := harnessCollect(t, parent)
	router.script(harnessTextCall("found it"))
	child, err := world.harness.Launch(context.Background(), parent.Id(), &HarnessLaunchSpec{Name: "helper", Model: harnessTestModel,
		Instructions: "find it"})
	if err != nil {
		t.Fatal(err)
	}
	events := log.until(t, HarnessEventAgentSettled)
	spawned := events[0]
	childId, where, run := "", "", ""
	spawned.Decode("child", &childId)
	spawned.Decode("where", &where)
	spawned.Decode("run", &run)
	if spawned.Type != HarnessEventAgentSpawned || spawned.Agent != parent.Id().String() || childId != child.Id().String() ||
		where != HarnessLaunchWhereLocal || run != child.Run().Id().String() {
		t.Fatalf("the first event: %+v", spawned)
	}
	for _, event := range events[1:] {
		if event.Agent != child.Id().String() {
			t.Fatalf("a nested event of agent %s", event.Agent)
		}
	}
	if err := child.WaitForIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	child.Close()
	exited := log.until(t, HarnessEventAgentExited)
	last := exited[len(exited)-1]
	stopReason := ""
	last.Decode("stopReason", &stopReason)
	if last.Agent != parent.Id().String() || stopReason != HarnessStopEnded {
		t.Fatalf("agent_exited: %+v", last)
	}
}

// The parent's tree takes a link naming the child's agent, run and place; the child's first node is a link back, a
// root naming the parent's run and the node it launched from, and the child's request carries none of the parent's
// context.
func TestHarnessLinkKeepsContextsApart(t *testing.T) {
	router := newHarnessScriptedRouter(t)
	world := newHarnessLaunchTestWorld(t, router, nil)
	parent := world.agent(t, &HarnessAgentSpec{Name: "lead"})
	router.script(harnessTextCall("the parent's own answer"))
	if err := parent.Prompt(context.Background(), "the parent's private context", nil); err != nil {
		t.Fatal(err)
	}
	<-router.called
	if err := parent.WaitForIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	parentLeaf := parent.(*harnessAgent).leafNodeId
	router.script(harnessTextCall("child's answer"))
	child, err := world.harness.Launch(context.Background(), parent.Id(), &HarnessLaunchSpec{Name: "helper", Model: harnessTestModel,
		Instructions: "the child's task"})
	if err != nil {
		t.Fatal(err)
	}
	request := <-router.called
	for _, message := range request.Messages {
		if strings.Contains(message.Text(), "the parent's private context") || strings.Contains(message.Text(), "the parent's own answer") {
			t.Fatalf("the child's request carries the parent's context: %q", message.Text())
		}
	}
	if err := child.WaitForIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	// the child's root
	var childRoot *HarnessJournalNode
	var parentLink *HarnessJournalNode
	world.journal.stateLock.Lock()
	for _, node := range world.journal.runNodes[child.Run().Id()] {
		if _, hasParent := node.Entry.ParentId(); !hasParent {
			childRoot = node
		}
	}
	for _, node := range world.journal.runNodes[parent.Run().Id()] {
		if node.Entry.Type() == HarnessPiEntryLink {
			parentLink = node
		}
	}
	world.journal.stateLock.Unlock()
	if childRoot == nil || childRoot.Entry.Type() != HarnessPiEntryLink || childRoot.ParentRunId != nil {
		t.Fatalf("the child's root: %+v", childRoot)
	}
	to, runId, nodeId := "", "", ""
	childRoot.Entry.object.decode("to", &to)
	childRoot.Entry.object.decode("runId", &runId)
	childRoot.Entry.object.decode("nodeId", &nodeId)
	if to != "parent" || runId != parent.Run().Id().String() || nodeId != parentLeaf {
		t.Fatalf("the child's root link: to %q run %q node %q, want %q", to, runId, nodeId, parentLeaf)
	}
	if parentLink == nil {
		t.Fatalf("the parent's tree names no child")
	}
	parentLink.Entry.object.decode("to", &to)
	parentLink.Entry.object.decode("runId", &runId)
	if parentId, _ := parentLink.Entry.ParentId(); to != "child" || runId != child.Run().Id().String() || parentId != parentLeaf {
		t.Fatalf("the parent's link: to %q run %q hangs from %q", to, runId, parentId)
	}
}
