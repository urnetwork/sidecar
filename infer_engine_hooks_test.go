//go:build sidecar_testhooks && !ios_extension && !sidecar_http && !js

// The helper's ordering against the daemon's share, on its barriers.

package sidecar

import (
	"sync"
	"testing"
)

// A generate gives its engine back before it writes its last event, so the model's next call, which the daemon grants
// the moment that event arrives, finds the engine free while the first call's goroutine is still held after its last
// event. Before the fix the engine was given back after the last event, and the next call answered capacity.
func TestEngineFreesItsEngineBeforeItsLastEvent(t *testing.T) {
	answered := make(chan struct{})
	release := make(chan struct{})
	once := sync.Once{}
	SetTestHooks(&TestHooks{
		Barrier: func(name string, key string) {
			if name == "infer_engine.generate.answered" {
				once.Do(func() {
					close(answered)
					<-release
				})
			}
		},
	})
	t.Cleanup(func() {
		SetTestHooks(nil)
	})
	world := newTestInferEngineHelperWorld(t, &testInferEngineBackend{answer: testInferEngineEcho}, nil)
	handle := world.load(t, 1)
	first := world.send(t, inferEngineMethodGenerate, &inferEngineGenerateParams{Handle: handle, Conversation: "agent-a", Messages: []*InferMessage{testInferUserMessage("one")}, Effort: InferEffortOff})
	if events := world.stream(t, first); events[len(events)-1].Kind != InferEventEnd {
		t.Fatalf("the first call ended %v", testInferKinds(events))
	}
	<-answered
	second := world.send(t, inferEngineMethodGenerate, &inferEngineGenerateParams{Handle: handle, Conversation: "agent-b", Messages: []*InferMessage{testInferUserMessage("two")}, Effort: InferEffortOff})
	events := world.stream(t, second)
	close(release)
	if last := events[len(events)-1]; last.Kind != InferEventEnd {
		t.Errorf("the next call, granted at the first's last event, ended %+v", last.Error)
	}
}
