//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"errors"
	"testing"
)

// A run carrying limited_use reaches a remote model only where the policy's limited_use line lists it, whatever its
// label, AP included, and is refused service_model before anyone is asked a disclosure; a listed model runs, and so
// does a local one; an unmarked run reaches every model.
func TestCheckLimitedUseRefusesUnlistedModel(t *testing.T) {
	markedRun := NewId()
	world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.marks.runs[markedRun] = []string{"tainted", inferMarkLimitedUse}
		world.asker.attached[markedRun] = true
		world.asker.answer = func(ask *InferDisclosureAsk) (bool, error) {
			world.acks.acknowledge(ask.DisclosureId, ask.DisclosureVersion)
			return true, nil
		}
	})
	for _, model := range []string{"chutes-qwen3.8-27b-tee-high", "tinfoil-gpt-oss-120b-high", "engy-glm-5.2-off"} {
		testInferErrorOf(t, world.infer(t, testInferRunRequest(model, markedRun)), InferErrorServiceModel)
		testInferErrorOf(t, world.router.Check(context.Background(), testInferRunRequest(model, markedRun)), InferErrorServiceModel)
	}
	if len(world.asker.asked()) != 0 || world.dispatched() != 0 {
		t.Fatalf("a refused marked call asked %d times or ran", len(world.asker.asked()))
	}
	if err := world.infer(t, testInferRunRequest("engy-deepseek-v4.1-flash-off", markedRun)); err != nil {
		t.Errorf("a listed model on a marked run: %v", err)
	}
	if err := world.infer(t, testInferRunRequest("local-gemma-4-e4b-off", markedRun)); err != nil {
		t.Errorf("a local model on a marked run: %v", err)
	}
	if err := world.infer(t, testInferRunRequest("chutes-qwen3.8-27b-tee-high", NewId())); err != nil {
		t.Errorf("an unmarked run: %v", err)
	}
}

// A gateway call is checked against the union of the marks of every run its binding may name, which the binder answers,
// never the marks of the run its headers name alone; a binding whose marks do not read fails closed.
func TestCheckGatewayBindingUnionOfMarks(t *testing.T) {
	quietRun := NewId()
	world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.bindingMark("codex-1", inferMarkLimitedUse)
		world.bindingMark("", inferMarkLimitedUse)
	})
	bound := testInferRunRequest("chutes-qwen3.8-27b-tee-high", quietRun)
	bound.Binding = &InferBinding{GrantId: NewId(), Handle: "codex-1"}
	testInferErrorOf(t, world.infer(t, bound), InferErrorServiceModel)
	unbound := testInferRequest("chutes-qwen3.8-27b-tee-high", "")
	unbound.Binding = &InferBinding{GrantId: NewId()}
	testInferErrorOf(t, world.infer(t, unbound), InferErrorServiceModel)
	other := testInferRunRequest("chutes-qwen3.8-27b-tee-high", quietRun)
	other.Binding = &InferBinding{GrantId: NewId(), Handle: "claude-2"}
	if err := world.infer(t, other); err != nil {
		t.Errorf("a binding with no mark: %v", err)
	}
	if err := world.infer(t, testInferRunRequest("chutes-qwen3.8-27b-tee-high", quietRun)); err != nil {
		t.Errorf("the Harness's call on the quiet run: %v", err)
	}

	unreadable := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.marks.err = errors.New("the binder cannot say")
	})
	for _, request := range []*InferRequest{bound, testInferRunRequest("chutes-qwen3.8-27b-tee-high", quietRun)} {
		refused := testInferErrorOf(t, unreadable.infer(t, request), InferErrorModelRefused)
		if refused.Reason != InferRefusedRuleMarks {
			t.Errorf("marks that do not read: %+v", refused)
		}
	}
	if unreadable.dispatched() != 0 {
		t.Error("a call whose marks do not read ran")
	}
	if err := unreadable.infer(t, testInferRunRequest("local-gemma-4-e4b-off", quietRun)); err != nil {
		t.Errorf("a local call with marks that do not read: %v", err)
	}
}

// Marks handle with mark in world's fake binder.
func (self *testInferCheckWorld) bindingMark(handle string, mark string) {
	self.marks.stateLock.Lock()
	defer self.marks.stateLock.Unlock()
	self.marks.bindings[handle] = append(self.marks.bindings[handle], mark)
}

// Check answers what a retry would meet before the gateway joins or replays another call (§8.5): it passes what Infer
// would dispatch, and refuses once a mark or a missing acknowledgment would, dispatching nothing either way.
func TestCheckBeforeJoinOrReplay(t *testing.T) {
	runId := NewId()
	world := newTestInferCheckWorld(t, func(world *testInferCheckWorld) {
		world.acks.versions["inference:engy"] = 2
	})
	request := testInferRunRequest("engy-glm-5.2-off", runId)
	request.Binding = &InferBinding{GrantId: NewId(), Handle: "codex-1"}
	if err := world.router.Check(context.Background(), request); err != nil {
		t.Fatalf("before the mark: %v", err)
	}
	world.bindingMark("codex-1", inferMarkLimitedUse)
	testInferErrorOf(t, world.router.Check(context.Background(), request), InferErrorServiceModel)
	world.acks.acknowledge("inference:engy", 0)
	unmarked := testInferRunRequest("engy-glm-5.2-off", NewId())
	testInferErrorOf(t, world.router.Check(context.Background(), unmarked), InferErrorDisclosureRequired)
	if world.dispatched() != 0 {
		t.Error("Check dispatched")
	}
}
