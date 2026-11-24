//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// The client's Lookups on §16.6's gate (record_effect.go), which refuses a kind with no registered Lookup before its
// Reserve, on its barriers. A send racing the first Bind on a gate, whose registration of kind mail is held inside
// the gate: the send waits on it at mail.outbox.lookup.wait and then passes the gate, where it once took the mark the
// Bind set before registering and went to the gate with no Lookup there (mail_send_queue.go's registerOutboxLookup).
// And a rebind held at mail.client.bind.after, after it dropped the mailcfg reader a first use installed and before it
// closes that reader, while the use waits at mail.client.config.install.after to register it and a later use builds,
// installs and registers the reader that stands: only registerConfigLookups' check that a reader is still the kept one
// keeps the dropped reader from registering in its place, and its close from then taking the kinds off the gate.
// Nothing sleeps: each step is held at its barrier, or inside its gate, until the test lets it go.

package sidecar

import (
	"sync"
	"testing"
	"time"
)

// What testHoldMailBarriers holds at one barrier: the index of each arrival held, and the release of each.
type testMailBarrierHold struct {
	arrived  chan int
	releases []chan struct{}
}

// testHoldMailBarrier over several barriers at once: at each name, the first count arrivals are held, each until its
// release is closed; every later arrival, and every other barrier, passes. Removed with the test.
func testHoldMailBarriers(t *testing.T, counts map[string]int) map[string]*testMailBarrierHold {
	t.Helper()
	holds := map[string]*testMailBarrierHold{}
	for name, count := range counts {
		hold := &testMailBarrierHold{arrived: make(chan int, count), releases: make([]chan struct{}, count)}
		for index := range hold.releases {
			hold.releases[index] = make(chan struct{})
		}
		holds[name] = hold
	}
	var stateLock sync.Mutex
	arrivals := map[string]int{}
	SetTestHooks(&TestHooks{Barrier: func(name string, key string) {
		hold := holds[name]
		if hold == nil {
			return
		}
		index := func() int {
			stateLock.Lock()
			defer stateLock.Unlock()
			index := arrivals[name]
			arrivals[name] += 1
			return index
		}()
		if index < len(hold.releases) {
			hold.arrived <- index
			<-hold.releases[index]
		}
	}})
	t.Cleanup(func() { SetTestHooks(nil) })
	return holds
}

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

// A first use of the client's mailcfg reader installs it and is held at mail.client.config.install.after, before it
// registers; a rebind to another engine drops that reader and is held at mail.client.bind.after, before it closes
// it; a later use builds, installs and registers the reader that stands. Let go, the first use registers nothing,
// since the client no longer keeps its reader, and the rebind's close of that reader leaves the standing one's alias
// Lookups on the gate, so an alias creation passes it. Without registerConfigLookups' check the dropped reader, not
// yet closed, registered in place of the standing one, and its close then took both alias kinds off the gate.
func TestMailClientRebindBetweenInstallAndRegistrationLeavesTheKeptReadersLookups(t *testing.T) {
	world, client, gate := newTestMailConfigInstallWorld(t)
	binding, _, err := client.bound()
	if err != nil {
		t.Fatal(err)
	}
	// the same state through another engine: a change of state, so the rebind drops what was built over the old one
	engine := NewAclEngine(world.device, nil, nil, nil)
	if err := engine.Install(world.repos.state(), nil); err != nil {
		t.Fatal(err)
	}
	rebound := *binding
	rebound.Engine = engine
	installAfter, bindAfter := "mail.client.config.install.after", "mail.client.bind.after"
	holds := testHoldMailBarriers(t, map[string]int{installAfter: 1, bindAfter: 1})

	answers := make(chan testMailConfigAnswer, 1)
	go func() {
		config, err := client.mailConfig()
		answers <- testMailConfigAnswer{config: config, err: err}
	}()
	testAwait(t, holds[installAfter].arrived, "the first use after its install")
	dropped := func() *MailConfig {
		client.stateLock.Lock()
		defer client.stateLock.Unlock()
		return client.config
	}()
	if dropped == nil {
		t.Fatal("the first use installed no reader")
	}
	bound := make(chan struct{})
	go func() {
		defer close(bound)
		client.Bind(&rebound)
	}()
	testAwait(t, holds[bindAfter].arrived, "the rebind after its install")

	kept, err := client.mailConfig()
	if err != nil {
		t.Fatalf("a use after the rebind: %v", err)
	}
	if kept == dropped || !gate.holdsAliasLookups() {
		t.Fatal("the use after the rebind did not build and register a reader of its own")
	}

	close(holds[installAfter].releases[0])
	testAwait(t, answers, "the first use's answer")
	close(holds[bindAfter].releases[0])
	testAwait(t, bound, "the rebind's end")
	if len(dropped.unregisters) != 0 {
		t.Error("the reader the rebind dropped registered its Lookups after it was dropped")
	}
	if !gate.holdsAliasLookups() || len(kept.unregisters) != 2 {
		t.Fatal("the gate lost the standing reader's alias Lookups as the dropped reader closed")
	}
	alias, err := client.CreateAlias(t.Context(), &MailAliasCreateArgs{LocalPart: "bo"})
	if err != nil {
		t.Fatalf("an alias creation after the rebind: %v", err)
	}
	if !alias.Known || alias.Address != testMailIngestRecipient {
		t.Fatalf("the alias %+v", alias)
	}
}
