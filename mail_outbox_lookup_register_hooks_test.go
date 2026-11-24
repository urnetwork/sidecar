//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// Kind mail's Lookup on §16.6's gate (record_effect.go), which refuses a kind with no registered Lookup before its
// Reserve, on its barriers: a send racing the first Bind on a gate, whose registration of kind mail is held inside the
// gate, waits on it at mail.outbox.lookup.wait and then passes the gate, where it once took the mark the Bind set
// before registering and went to the gate with no Lookup there (mail_send_queue.go's registerOutboxLookup). Nothing
// sleeps: the registration is held inside its gate until the test lets it go.

package sidecar

import (
	"sync"
	"testing"
	"time"
)

// One send's answer.
type testMailOutboxSendAnswer struct {
	result *MailSendResult
	err    error
}

// The first Bind on a new gate holds its registration of kind mail inside the gate while a send naming outside
// recipients runs through that gate: the send waits for the registration at mail.outbox.lookup.wait, and once the
// registration is let go it passes the gate and queues its outside recipients. Before the fix the Bind marked the gate
// as registered before it registered, the send took the mark, reached mail.send.gate.before with no Lookup on the gate,
// and the gate refused it before its Reserve.
func TestMailSendRacingTheFirstBindOnAGateWaitsForItsLookup(t *testing.T) {
	world, _, _ := newMailSendTestWorld(t)
	gate := newTestMailOutboxGate(true)
	binding := testMailOutboxBinding(t, world.client, gate)

	// the send's wait on the registration in flight, or its going to the gate without one
	waiting, atGate := make(chan struct{}), make(chan struct{})
	var waitingOnce, atGateOnce sync.Once
	SetTestHooks(&TestHooks{Barrier: func(name string, key string) {
		switch name {
		case "mail.outbox.lookup.wait":
			waitingOnce.Do(func() { close(waiting) })
		case "mail.send.gate.before":
			atGateOnce.Do(func() { close(atGate) })
		}
	}})
	t.Cleanup(func() { SetTestHooks(nil) })

	bound := make(chan struct{})
	go func() {
		defer close(bound)
		world.client.Bind(binding)
	}()
	testAwait(t, gate.arrived, "the Bind's registration of kind mail")
	answers := make(chan testMailOutboxSendAnswer, 1)
	go func() {
		result, err := world.client.Send(t.Context(), testMailSubmitDraft())
		answers <- testMailOutboxSendAnswer{result: result, err: err}
	}()
	raced := false
	select {
	case <-waiting:
	case <-atGate:
		raced = true
	case <-time.After(testSubprotocolAwaitTimeout):
		t.Fatal("the send neither waited on the Bind's registration nor went to the gate")
	}
	close(gate.release)
	answer := testAwait(t, answers, "the send's answer")
	testAwait(t, bound, "the Bind's end")
	if raced {
		t.Fatalf("the send went to the gate while the Bind's registration of kind mail was in flight, and answered %v", answer.err)
	}
	if answer.err != nil {
		t.Fatalf("a send racing the first Bind on its gate: %v", answer.err)
	}
	if !testMailOutboxDraftQueued(answer.result) {
		t.Fatalf("the send's recipients %+v", answer.result.Recipients)
	}
	if !testMailGateHoldsMailLookup(gate.mailConfigTestGate) || testMailGateHoldsMailLookup(world.gate) ||
		gate.mailRegisterCount.Load() != 1 || testMailOutboxMarked(world.client) != gate {
		t.Fatal("kind mail's Lookup does not stand once, and marked, on the gate the client is bound to")
	}
}
