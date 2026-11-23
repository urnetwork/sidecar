package sidecartest

// The Net joins every connect client it ends, so nothing it ran is running once Close returns (QD-1224): a client of
// the exchange's, a resident's and a sidecar's each join within NetSettings.ClientCloseTimeout, and whatever does not is
// reported (NetSettings.CloseFailed), the Net panicking with it where nothing takes it. A test that reconciles connect's
// process-wide pool after a Net depends on this: before it a Net cancelled its clients without joining them, so their
// workers ran on past Close and returned buffers they took earlier inside the next test's window ("pool: 4 buffers taken
// and 5 returned", tip-check's red at ad4cc180).
//
// A wedged join here is a callback held until the test lets it go, which it does only after the join's bound has
// passed, so the join times out whatever the bound; the bound is a millisecond only to keep the test quick.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/pushservice"
)

// One goroutine of a runtime.Stack dump: its id and state as its header gives them, and its whole stack.
type netCloseGoroutine struct {
	id    string
	state string
	stack string
}

// Every goroutine running now.
func netCloseGoroutines() []*netCloseGoroutine {
	goroutines := []*netCloseGoroutine{}
	for _, stack := range goroutineStacks(DefaultNetSettings().CloseDumpByteCount) {
		header, _, _ := strings.Cut(stack, "\n")
		after, found := strings.CutPrefix(header, "goroutine ")
		if !found {
			continue
		}
		id, rest, _ := strings.Cut(after, " ")
		_, state, _ := strings.Cut(rest, "[")
		state, _, _ = strings.Cut(state, "]")
		state, _, _ = strings.Cut(state, ",")
		goroutines = append(goroutines, &netCloseGoroutine{id: id, state: state, stack: stack})
	}
	return goroutines
}

// The ids of every goroutine running now.
func netCloseGoroutineIds() map[string]bool {
	ids := map[string]bool{}
	for _, goroutine := range netCloseGoroutines() {
		ids[goroutine.id] = true
	}
	return ids
}

// The stack of every goroutine running connect's code that is not among before and waits on something, a channel, a
// lock or a timer: a client's worker nobody joined. One running or runnable is left out, since a worker a join has
// just let go of may still be returning, while a worker nobody joined waits for what it serves.
func netCloseLeftovers(before map[string]bool) []string {
	leftovers := []string{}
	for _, goroutine := range netCloseGoroutines() {
		if before[goroutine.id] || goroutine.state == "running" || goroutine.state == "runnable" {
			continue
		}
		if strings.Contains(goroutine.stack, connectFramePrefix) {
			leftovers = append(leftovers, goroutine.stack)
		}
	}
	return leftovers
}

// A Net with each kind of connect client it ends: a sidecar Online, its generation's client on the exchange, with a
// resident whose publisher's reset it has acked; two clients that each sent the other a sealed message; and a third
// that sent one and was then cancelled by hand while still on the exchange, as a bridge world cancels a window's
// client. Closes the Net, failing t first if any of it does not come up.
func runNetCloseJoinWorld(t *testing.T) {
	t.Helper()
	net := NewNet(t.Context(), nil)
	closed := false
	defer func() {
		if !closed {
			net.Close()
		}
	}()
	laptop, err := net.AddSidecar("laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	resident, err := net.AddResident(laptop.Client().ClientId)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resident.StartPublisher(nil, NewFakeClock(net.Clock().Now())); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), net.settings.SendTimeout)
	defer cancel()
	// the publisher's reset, of an empty ver, has reached the sidecar's client
	if err := resident.AwaitAcked(ctx, 1); err != nil {
		t.Fatal(err)
	}

	a := net.AddClient("a", nil)
	b := net.AddClient("b", nil)
	c := net.AddClient("c", nil)
	aMessages := make(chan *NetMessage, 16)
	defer a.ReceiveMessages(aMessages)()
	bMessages := make(chan *NetMessage, 16)
	defer b.ReceiveMessages(bMessages)()
	type send struct {
		source      *NetClient
		destination *NetClient
		messages    chan *NetMessage
	}
	for _, send := range []send{{source: a, destination: b, messages: bMessages}, {source: b, destination: a, messages: aMessages}, {source: c, destination: b, messages: bMessages}} {
		if err := send.source.SendMessage(send.destination.ClientId, send.source.Name); err != nil {
			t.Fatal(err)
		}
		message, err := net.AwaitMessage(ctx, send.messages)
		if err != nil {
			t.Fatal(err)
		}
		if message.Source != send.source.ClientId || message.Content != send.source.Name {
			t.Fatalf("%s heard %+v, want %s's message", send.destination.Name, message, send.source.Name)
		}
	}
	c.Client.Cancel()
	closed = true
	net.Close()
}

// After Close nothing of the Net's clients runs on and connect's pool is as it was: every buffer a client took came
// back before Close returned, none twice. The Net is built once first, so what connect starts once a process runs a
// client is running before the measured one starts.
func TestNetCloseLeavesNoClientRunningAndThePoolBalanced(t *testing.T) {
	runNetCloseJoinWorld(t)
	before := netCloseGoroutineIds()
	takenBefore, returnedBefore, _ := connect.MessagePoolCounts()
	violationsBefore := connect.MessagePoolViolationCount()
	runNetCloseJoinWorld(t)
	takenAfter, returnedAfter, _ := connect.MessagePoolCounts()
	if takenAfter-takenBefore != returnedAfter-returnedBefore {
		t.Errorf("pool: %d buffers taken and %d returned across the Net", takenAfter-takenBefore, returnedAfter-returnedBefore)
	}
	if violations := connect.MessagePoolViolationCount() - violationsBefore; violations != 0 {
		t.Errorf("pool: %d ownership violations across the Net", violations)
	}
	if leftovers := netCloseLeftovers(before); 0 < len(leftovers) {
		t.Errorf("%d of connect's goroutines still waiting after Close:\n\n%s", len(leftovers), strings.Join(leftovers, "\n\n"))
	}
}

// A Net whose joins are bounded at a millisecond, reporting to closeFailed, with a client named wedged whose receive
// callback holds the client's worker on the test's message until release, which also joins the client so nothing of
// it outlives the test. The client that sent the message has joined already, so wedged's is the one join left.
func newNetCloseWedgedClient(t *testing.T, closeFailed func(err error)) (net *Net, wedged *NetClient, release func()) {
	t.Helper()
	settings := DefaultNetSettings()
	settings.ClientCloseTimeout = time.Millisecond
	settings.CloseFailed = closeFailed
	net = NewNet(t.Context(), settings)
	a := net.AddClient("a", nil)
	wedged = net.AddClient("wedged", nil)
	entered := make(chan struct{}, 1)
	held := make(chan struct{})
	wedged.Client.AddReceiveCallback(func(source connect.TransferPath, frames []*connectprotocol.Frame, peer connect.Peer) {
		for _, frame := range frames {
			message, err := connect.FromFrame(frame)
			if err != nil {
				continue
			}
			if simple, ok := message.(*connectprotocol.SimpleMessage); ok && simple.Content == "hold" {
				select {
				case entered <- struct{}{}:
				default:
				}
				<-held
			}
		}
	})
	release = func() {
		t.Helper()
		close(held)
		ctx, cancel := context.WithTimeout(context.Background(), DefaultNetSettings().ClientCloseTimeout)
		defer cancel()
		if err := wedged.Client.CloseAndWait(ctx); err != nil {
			t.Fatalf("the wedged client did not join once let go: %v", err)
		}
	}
	if err := a.SendMessage(wedged.ClientId, "hold"); err != nil {
		release()
		net.Close()
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(settings.SendTimeout):
		release()
		net.Close()
		t.Fatal("the wedged client's callback was never reached")
	}
	ctx, cancel := context.WithTimeout(context.Background(), DefaultNetSettings().ClientCloseTimeout)
	defer cancel()
	if err := a.Client.CloseAndWait(ctx); err != nil {
		release()
		net.Close()
		t.Fatalf("the sender did not join: %v", err)
	}
	return net, wedged, release
}

// Whether err reports name's join, or close, as one that ran out its bound.
func netCloseReports(err error, name string) bool {
	return err != nil && errors.Is(err, context.DeadlineExceeded) && strings.Contains(err.Error(), name)
}

// A client of the exchange's whose join cannot end within its bound is reported at the end of Close, by name, as one
// its bound ran out on, rather than left running unsaid.
func TestNetCloseReportsAClientWhoseJoinDoesNotEnd(t *testing.T) {
	failures := make(chan error, 4)
	net, _, release := newNetCloseWedgedClient(t, func(err error) {
		failures <- err
	})
	net.Close()
	release()
	select {
	case err := <-failures:
		if !netCloseReports(err, `"wedged"`) {
			t.Errorf("Close reported %v, not the wedged client's join", err)
		}
	default:
		t.Fatal("Close returned with a client still running and reported nothing")
	}
	select {
	case err := <-failures:
		t.Errorf("Close reported twice: %v", err)
	default:
	}
}

// With nothing to take a report, Close panics with it, naming the client and carrying connect's goroutines still
// running, once it has ended everything else and taken the hooks off, so another Net opens after it.
func TestNetClosePanicsWithAJoinThatDoesNotEndWhenNothingTakesIt(t *testing.T) {
	net, _, release := newNetCloseWedgedClient(t, nil)
	recovered := func() (recovered any) {
		defer func() {
			recovered = recover()
		}()
		net.Close()
		return nil
	}()
	release()
	err, ok := recovered.(error)
	if !ok {
		t.Fatalf("Close panicked with %v, not an error reporting the wedged client", recovered)
	}
	if !netCloseReports(err, `"wedged"`) {
		t.Errorf("Close panicked with %v, not the wedged client's join", err)
	}
	if !strings.Contains(err.Error(), connectFramePrefix) {
		t.Errorf("the panic carries no stack of connect's: %v", err)
	}
	// a second open Net panics under the hooks, so this opening says the first took them off before its panic
	NewNet(t.Context(), nil).Close()
}

// A component whose Close holds until the test lets it go, so the sidecar's close waits on it.
type netCloseHeldComponent struct {
	// closes once Close has begun
	closing chan struct{}
	held    chan struct{}
}

func (self *netCloseHeldComponent) Name() string {
	return "net-close-held"
}

func (self *netCloseHeldComponent) Attach(env *sidecar.SidecarEnv) error {
	return nil
}

func (self *netCloseHeldComponent) Close() {
	close(self.closing)
	<-self.held
}

// Adds a held component to running, and answers it and what lets it go and waits for running to close, so nothing of
// the sidecar outlives the test.
func addNetCloseHeldComponent(t *testing.T, running *sidecar.Sidecar) (component *netCloseHeldComponent, release func()) {
	t.Helper()
	component = &netCloseHeldComponent{closing: make(chan struct{}), held: make(chan struct{})}
	if _, err := running.AddComponent(component); err != nil {
		t.Fatal(err)
	}
	release = func() {
		t.Helper()
		close(component.held)
		ctx, cancel := context.WithTimeout(context.Background(), DefaultNetSettings().ClientCloseTimeout)
		defer cancel()
		if err := running.CloseAndWait(ctx); err != nil {
			t.Fatalf("the sidecar did not close once its component let go: %v", err)
		}
	}
	return component, release
}

// A sidecar whose close cannot end within its bound is not restarted on the state it still runs on: Restart answers
// its stop's error, naming it. Still running at the Net's end, it is reported there.
func TestSidecarRestartAndCloseReportASidecarThatDoesNotStop(t *testing.T) {
	failures := make(chan error, 4)
	settings := DefaultNetSettings()
	settings.ClientCloseTimeout = time.Millisecond
	settings.CloseFailed = func(err error) {
		failures <- err
	}
	net := NewNet(t.Context(), settings)
	closed := false
	defer func() {
		if !closed {
			net.Close()
		}
	}()
	laptop, err := net.AddSidecar("laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	running := laptop.Sidecar()
	component, release := addNetCloseHeldComponent(t, running)
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	if err := laptop.Restart(); !netCloseReports(err, "laptop") {
		t.Fatalf("Restart of a sidecar that did not stop answered %v", err)
	}
	select {
	case <-component.closing:
	case <-time.After(settings.SidecarOnlineTimeout):
		t.Fatal("the sidecar's close never reached its component")
	}
	if laptop.Sidecar() != running {
		t.Fatal("Restart started a sidecar on the state its predecessor still runs on")
	}
	closed = true
	net.Close()
	released = true
	release()
	select {
	case err := <-failures:
		if !netCloseReports(err, "laptop") {
			t.Errorf("Close reported %v, not the sidecar's", err)
		}
	default:
		t.Fatal("Close returned with a sidecar still closing and reported nothing")
	}
}

// As for one sidecar, for an instance's: Restart answers the stop's error, and Close, before the Net's, has the Net
// report it at its end.
func TestInstanceRestartAndCloseReportASidecarThatDoesNotStop(t *testing.T) {
	failures := make(chan error, 4)
	settings := DefaultNetSettings()
	settings.ClientCloseTimeout = time.Millisecond
	settings.CloseFailed = func(err error) {
		failures <- err
	}
	net := NewNet(t.Context(), settings)
	closed := false
	defer func() {
		if !closed {
			net.Close()
		}
	}()
	instance, err := net.StartInstance("daemon", nil)
	if err != nil {
		t.Fatal(err)
	}
	networkId := net.DefaultNetworkId()
	running, err := instance.AddSidecarIn(networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, release := addNetCloseHeldComponent(t, running)
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	if err := instance.Restart(); !netCloseReports(err, fmt.Sprintf("network %s", networkId)) {
		t.Fatalf("Restart of an instance whose sidecar did not stop answered %v", err)
	}
	instance.Close()
	closed = true
	net.Close()
	released = true
	release()
	select {
	case err := <-failures:
		if !netCloseReports(err, fmt.Sprintf("network %s", networkId)) {
			t.Errorf("Close reported %v, not the instance's sidecar", err)
		}
	default:
		t.Fatal("the Net's Close reported nothing of an instance whose sidecar was still closing")
	}
}

// A resident's Close joins its client: one held by an ack callback past the join's bound is reported at the end of the
// Net's Close, by its resident's name, and Close returns once the bound has run out.
func TestNetResidentCloseReportsAClientWhoseJoinDoesNotEnd(t *testing.T) {
	failures := make(chan error, 4)
	settings := DefaultNetSettings()
	settings.ClientCloseTimeout = time.Millisecond
	settings.CloseFailed = func(err error) {
		failures <- err
	}
	net := NewNet(t.Context(), settings)
	closed := false
	defer func() {
		if !closed {
			net.Close()
		}
	}()
	client := net.AddClient("client", nil)
	resident, err := net.AddResident(client.ClientId)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 1)
	held := make(chan struct{})
	released := false
	release := func() {
		released = true
		close(held)
		ctx, cancel := context.WithTimeout(context.Background(), DefaultNetSettings().ClientCloseTimeout)
		defer cancel()
		if err := resident.netClient.Client.CloseAndWait(ctx); err != nil {
			t.Fatalf("the resident's client did not join once let go: %v", err)
		}
	}
	defer func() {
		if !released {
			release()
		}
	}()
	frame, err := pushservice.PushFrame(protocol.MessageType_PUSH_RESET, &protocol.PushReset{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !resident.Send(frame, func(err error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-held
	}) {
		connect.MessagePoolReturn(frame.MessageBytes)
		t.Fatal("the resident's client refused the frame")
	}
	select {
	case <-entered:
	case <-time.After(settings.SendTimeout):
		t.Fatal("the frame's ack never came")
	}
	resident.Close()
	select {
	case err := <-failures:
		t.Fatalf("a join reported before the Net's Close: %v", err)
	default:
	}
	closed = true
	net.Close()
	release()
	select {
	case err := <-failures:
		if !netCloseReports(err, fmt.Sprintf("resident(%s)", client.ClientId)) {
			t.Errorf("Close reported %v, not the resident's client", err)
		}
	default:
		t.Fatal("the Net's Close reported nothing of a resident whose client was still running")
	}
}
