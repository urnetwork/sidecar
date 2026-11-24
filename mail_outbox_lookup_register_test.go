//go:build !sidecar_http && !js && !ios_extension

// Kind mail's Lookup on the client's gate (mail_send_queue.go's registerOutboxLookup), which §16.6's gate needs before
// it reserves a send's use (record_effect.go), on MAIL-M7-18's send world: registered once a gate however many Binds
// and sends ask, moved with a Bind to another gate, taken off at the client's close and never registered again by a
// closed client, whose send the gate then refuses with nothing queued; and a registration the client closes under
// takes back what it added. mail_outbox_lookup_register_hooks_test.go races a send with the first Bind on a gate on
// the barriers. Nothing sleeps: a registration is held inside its gate until the test lets it go.

package sidecar

import (
	"sync"
	"sync/atomic"
	"testing"
)

// The world's test gate, counting its registrations of kind mail; where hold is set, the first of them is held inside
// RegisterEffectLookup, arrived closed as it is, until release is closed: a Bind's registration in flight.
type testMailOutboxGate struct {
	*mailConfigTestGate
	mailRegisterCount atomic.Int32
	hold              bool
	arrived           chan struct{}
	release           chan struct{}
	holdOnce          sync.Once
}

func newTestMailOutboxGate(hold bool) *testMailOutboxGate {
	return &testMailOutboxGate{
		mailConfigTestGate: newMailConfigTestGate(),
		hold:               hold,
		arrived:            make(chan struct{}),
		release:            make(chan struct{}),
	}
}

func (self *testMailOutboxGate) RegisterEffectLookup(kind SidecarActionKind, lookup SidecarEffectLookup) func() {
	if kind == SidecarActionMail {
		self.mailRegisterCount.Add(1)
		if self.hold {
			self.holdOnce.Do(func() {
				close(self.arrived)
				<-self.release
			})
		}
	}
	return self.mailConfigTestGate.RegisterEffectLookup(kind, lookup)
}

// Whether gate holds a Lookup for kind mail.
func testMailGateHoldsMailLookup(gate *mailConfigTestGate) bool {
	gate.stateLock.Lock()
	defer gate.stateLock.Unlock()
	return gate.lookups[SidecarActionMail] != nil
}

// The client's binding as it stands, but for its gate.
func testMailOutboxBinding(t *testing.T, client *MailClient, gate MailConfigGate) *MailBinding {
	t.Helper()
	binding, _, err := client.bound()
	if err != nil {
		t.Fatal(err)
	}
	copied := *binding
	copied.Gate = gate
	return &copied
}

// The gate the client marks as holding kind mail's Lookup, nil for none.
func testMailOutboxMarked(client *MailClient) MailConfigGate {
	client.stateLock.Lock()
	defer client.stateLock.Unlock()
	return client.outboxLookupGate
}

// Whether a send's result queued each outside recipient of testMailSubmitDraft and delivered its member one.
func testMailOutboxDraftQueued(result *MailSendResult) bool {
	outcomes := map[string]MailSendOutcome{}
	for _, recipient := range result.Recipients {
		outcomes[recipient.Address] = recipient.Outcome
	}
	return len(outcomes) == 3 && outcomes[testMailIngestRecipient] == MailSendDelivered &&
		outcomes["someone@outside.example"] == MailSendQueued && outcomes["hidden@elsewhere.example"] == MailSendQueued
}

// A Bind to a new gate registers kind mail's Lookup there once and takes it off the gate before; Binds to the same
// gate and a send through it register nothing more, and the send passes the gate; a Bind to a third gate moves it
// again.
func TestMailClientRegistersTheOutboxLookupOnceAGate(t *testing.T) {
	world, _, _ := newMailSendTestWorld(t)
	first := newTestMailOutboxGate(false)
	world.client.Bind(testMailOutboxBinding(t, world.client, first))
	if !testMailGateHoldsMailLookup(first.mailConfigTestGate) || testMailGateHoldsMailLookup(world.gate) {
		t.Fatal("a Bind to a new gate left kind mail's Lookup where it was")
	}
	if testMailOutboxMarked(world.client) != first {
		t.Fatal("the client marks another gate than the one it registered on")
	}
	world.client.Bind(testMailOutboxBinding(t, world.client, first))
	result, err := world.client.Send(t.Context(), testMailSubmitDraft())
	if err != nil {
		t.Fatalf("a send through the gate kind mail's Lookup stands on: %v", err)
	}
	if !testMailOutboxDraftQueued(result) {
		t.Fatalf("the send's recipients %+v", result.Recipients)
	}
	if count := first.mailRegisterCount.Load(); count != 1 {
		t.Fatalf("%d registrations of kind mail on one gate", count)
	}

	second := newTestMailOutboxGate(false)
	world.client.Bind(testMailOutboxBinding(t, world.client, second))
	if testMailGateHoldsMailLookup(first.mailConfigTestGate) || !testMailGateHoldsMailLookup(second.mailConfigTestGate) ||
		second.mailRegisterCount.Load() != 1 || testMailOutboxMarked(world.client) != second {
		t.Fatal("a Bind to a third gate did not move kind mail's Lookup there")
	}
}

// The client's close takes kind mail's Lookup off its gate, and a closed client registers none again: neither a Bind,
// to a new gate or to the one it held, nor a send. Before, a Bind after the close registered a Lookup nothing would
// take back. The send is refused at the gate, as §16.6's gate refuses a kind with no Lookup, and queues nothing.
func TestMailClientClosedRegistersNoOutboxLookup(t *testing.T) {
	world, _, _ := newMailSendTestWorld(t)
	if !testMailGateHoldsMailLookup(world.gate) {
		t.Fatal("no Lookup for kind mail on the bound gate")
	}
	queued := len(testMailSendOutbox(t, world))
	world.client.Close()
	if testMailGateHoldsMailLookup(world.gate) || testMailOutboxMarked(world.client) != nil {
		t.Fatal("the close left kind mail's Lookup on the gate")
	}

	later := newTestMailOutboxGate(false)
	world.client.Bind(testMailOutboxBinding(t, world.client, later))
	world.client.Bind(testMailOutboxBinding(t, world.client, world.gate))
	if later.mailRegisterCount.Load() != 0 || testMailGateHoldsMailLookup(world.gate) || testMailOutboxMarked(world.client) != nil {
		t.Fatal("a closed client's Bind registered kind mail's Lookup")
	}
	if _, err := world.client.Send(t.Context(), testMailSubmitDraft()); err == nil {
		t.Fatal("a closed client's send to outside recipients passed the gate")
	}
	if testMailGateHoldsMailLookup(world.gate) || len(testMailSendOutbox(t, world)) != queued {
		t.Fatal("a closed client's send registered kind mail's Lookup or queued")
	}
}

// A client closed while a Bind's registration of kind mail is in flight keeps no Lookup: the registration, let go
// after the close, takes back what it added, and no gate is marked.
func TestMailClientClosedUnderAnOutboxRegistrationKeepsNoLookup(t *testing.T) {
	world, _, _ := newMailSendTestWorld(t)
	gate := newTestMailOutboxGate(true)
	binding := testMailOutboxBinding(t, world.client, gate)
	bound := make(chan struct{})
	go func() {
		defer close(bound)
		world.client.Bind(binding)
	}()
	testAwait(t, gate.arrived, "the Bind's registration of kind mail")
	world.client.Close()
	close(gate.release)
	testAwait(t, bound, "the Bind's end")
	if testMailGateHoldsMailLookup(gate.mailConfigTestGate) || testMailGateHoldsMailLookup(world.gate) {
		t.Fatal("a client closed under its registration of kind mail left the Lookup on a gate")
	}
	if testMailOutboxMarked(world.client) != nil {
		t.Fatal("a closed client marks a gate as holding kind mail's Lookup")
	}
}
