//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

// Calls on one engine wait in arrival order between whole calls: with the slot held, a second and a third call take
// their places in turn, and each release hands the slot to the first in line.
func TestEngineShareArrivalOrder(t *testing.T) {
	share := newInferEngineShare(1)
	waited := make(chan struct{})
	share.waited = func() {
		waited <- struct{}{}
	}
	if err := share.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	granted := make(chan string, 2)
	for _, name := range []string{"second", "third"} {
		go func() {
			if err := share.acquire(context.Background()); err == nil {
				granted <- name
			}
		}()
		<-waited
	}
	if share.waiting() != 2 {
		t.Fatalf("%d waiting", share.waiting())
	}
	order := []string{}
	for range 2 {
		share.release()
		select {
		case name := <-granted:
			order = append(order, name)
		case <-time.After(testInferWait):
			t.Fatal("a release granted no one")
		}
	}
	if !slices.Equal(order, []string{"second", "third"}) {
		t.Errorf("granted in the order %v", order)
	}
	share.release()
	if err := share.acquire(context.Background()); err != nil {
		t.Errorf("a free slot: %v", err)
	}
}

// A waiting call whose context ends gives up its place, and the call behind it takes the slot.
func TestEngineShareWaiterGivesUpItsPlace(t *testing.T) {
	share := newInferEngineShare(1)
	waited := make(chan struct{})
	share.waited = func() {
		waited <- struct{}{}
	}
	if err := share.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	gaveUp := make(chan error, 1)
	go func() {
		gaveUp <- share.acquire(ctx)
	}()
	<-waited
	granted := make(chan error, 1)
	go func() {
		granted <- share.acquire(context.Background())
	}()
	<-waited
	cancel()
	if err := <-gaveUp; !errors.Is(err, context.Canceled) {
		t.Fatalf("the canceled waiter: %v", err)
	}
	share.release()
	select {
	case err := <-granted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(testInferWait):
		t.Fatal("the call behind the canceled one was not granted")
	}
	if share.waiting() != 0 {
		t.Errorf("%d still waiting", share.waiting())
	}
}

// Two agents on a model with one engine take turns on it: each turn closes the other's conversation, and an agent's
// next turn reopens its own from its saved messages; with an engine each, each continues its own.
func TestEngineShareEvictsHandleUnderMemory(t *testing.T) {
	for _, instances := range []int{1, 2} {
		backend := &testInferEngineBackend{answer: testInferEngineEcho}
		world := newTestInferEngineHelperWorld(t, backend, nil)
		handle := world.load(t, instances)
		turn := func(agent string, messages []*InferMessage) {
			id := world.send(t, inferEngineMethodGenerate, &inferEngineGenerateParams{Handle: handle, Conversation: agent, Messages: messages, Effort: InferEffortOff})
			if events := world.stream(t, id); events[len(events)-1].Kind != InferEventEnd {
				t.Fatalf("%s's turn ended %v", agent, testInferKinds(events))
			}
		}
		turn("agent-a", []*InferMessage{testInferUserMessage("a1")})
		turn("agent-b", []*InferMessage{testInferUserMessage("b1")})
		turn("agent-a", []*InferMessage{
			testInferUserMessage("a1"),
			{Role: InferRoleAssistant, Parts: []*InferPart{{Kind: InferPartText, Text: "echo: a1"}}},
			testInferUserMessage("a2"),
		})
		want := []string{"load gemma-4-e4b.litertlm", "open 0 plain 0", "send plain", "close", "open 0 plain 0", "send plain", "close", "open 0 plain 2", "send plain"}
		if instances == 2 {
			want = []string{"load gemma-4-e4b.litertlm", "open 0 plain 0", "send plain", "open 1 plain 0", "send plain", "send plain"}
		}
		if !slices.Equal(backend.recorded(), want) {
			t.Errorf("with %d engines the engine saw %v, want %v", instances, backend.recorded(), want)
		}
	}
}
