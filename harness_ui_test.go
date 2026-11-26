//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// The events a broker emitted, in order, and a signal for each.
type harnessUiTestEmitter struct {
	stateLock sync.Mutex
	events    []*HarnessEvent
	emitted   chan *HarnessEvent
}

func newHarnessUiTestEmitter() *harnessUiTestEmitter {
	return &harnessUiTestEmitter{emitted: make(chan *HarnessEvent, 64)}
}

func (self *harnessUiTestEmitter) emit(agentId Id, event *HarnessEvent) error {
	if !HarnessEventTypeRegistered(event.Type) {
		return ErrHarnessEventUnregistered
	}
	self.stateLock.Lock()
	self.events = append(self.events, event)
	self.stateLock.Unlock()
	self.emitted <- event
	return nil
}

// The next event emitted, failing the test past a guard.
func (self *harnessUiTestEmitter) next(t *testing.T) *HarnessEvent {
	t.Helper()
	select {
	case event := <-self.emitted:
		return event
	case <-time.After(60 * time.Second):
		t.Fatal("no event was emitted")
		return nil
	}
}

// CTRUST's store as a test steers it: Await returns once the test acknowledges the id and version.
type harnessTestAcks struct {
	stateLock   sync.Mutex
	acked       map[string]uint32
	ackedSignal chan struct{}
}

func newHarnessTestAcks() *harnessTestAcks {
	return &harnessTestAcks{acked: map[string]uint32{}, ackedSignal: make(chan struct{})}
}

func (self *harnessTestAcks) Await(ctx context.Context, id string, version uint32) error {
	for {
		covered, signal := func() (bool, chan struct{}) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return version <= self.acked[id], self.ackedSignal
		}()
		if covered {
			return nil
		}
		select {
		case <-signal:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// The person's acknowledgment landing in the store.
func (self *harnessTestAcks) acknowledge(id string, version uint32) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.acked[id] = version
	close(self.ackedSignal)
	self.ackedSignal = make(chan struct{})
}

// What one Ask came to.
type harnessUiAnswer struct {
	response *HarnessUiResponse
	err      error
}

// Runs Ask on its own goroutine, answering on the channel.
func harnessAskAsync(broker *HarnessUiBroker, runId Id, agentId Id, request *HarnessUiRequest) chan *harnessUiAnswer {
	answers := make(chan *harnessUiAnswer, 1)
	go func() {
		response, err := broker.Ask(context.Background(), runId, agentId, request)
		answers <- &harnessUiAnswer{response: response, err: err}
	}()
	return answers
}

func harnessAwaitAnswer(t *testing.T, answers chan *harnessUiAnswer) *harnessUiAnswer {
	t.Helper()
	select {
	case answer := <-answers:
		return answer
	case <-time.After(60 * time.Second):
		t.Fatal("Ask did not answer")
		return nil
	}
}

// A disclosure's request carries its id, method, disclosure id and version and nothing else, whatever its asker set,
// and the person's acknowledgment landing in the store answers it.
func TestHarnessDisclosureRequestCarriesIdAndVersionOnly(t *testing.T) {
	emitter := newHarnessUiTestEmitter()
	acks := newHarnessTestAcks()
	broker := NewHarnessUiBroker(&HarnessUiBrokerArgs{Emit: emitter.emit, Acks: acks})
	runId, agentId := NewId(), NewId()
	defer broker.AttachPerson(runId)()

	answers := harnessAskAsync(broker, runId, agentId, &HarnessUiRequest{
		Method:            HarnessUiDisclosure,
		Title:             "a title the asker wrote",
		Message:           "text that must never ride a disclosure",
		Options:           []string{"accept"},
		DisclosureId:      "inference:none",
		DisclosureVersion: 3,
	})
	request := emitter.next(t)
	if request.Type != HarnessEventUiRequest {
		t.Fatalf("emitted %s", request.Type)
	}
	names := request.FieldNames()
	if len(names) != 4 || names[0] != "id" || names[1] != "method" || names[2] != "disclosureId" || names[3] != "disclosureVersion" {
		t.Fatalf("a disclosure request carries %v", names)
	}
	raised := request.UiRequest()
	if raised.Method != HarnessUiDisclosure || raised.DisclosureId != "inference:none" || raised.DisclosureVersion != 3 ||
		raised.Title != "" || raised.Message != "" || raised.Options != nil {
		t.Fatalf("raised %+v", raised)
	}
	acks.acknowledge("inference:none", 3)
	answer := harnessAwaitAnswer(t, answers)
	if answer.err != nil || !answer.response.Acknowledged {
		t.Fatalf("acknowledged disclosure answered %+v, %v", answer.response, answer.err)
	}
	if closed := emitter.next(t); closed.Type != HarnessEventUiResponse {
		t.Fatalf("the dialog closed with %s", closed.Type)
	}
}

// A ui_response never acknowledges a disclosure: an accept is refused and the call keeps waiting; "Not now" declines
// it, failing the call waiting on it with disclosure_required, reason declined.
func TestHarnessUiResponseOnlyDeclinesDisclosure(t *testing.T) {
	emitter := newHarnessUiTestEmitter()
	broker := NewHarnessUiBroker(&HarnessUiBrokerArgs{Emit: emitter.emit, Acks: newHarnessTestAcks()})
	runId, agentId := NewId(), NewId()
	defer broker.AttachPerson(runId)()

	answers := harnessAskAsync(broker, runId, agentId, &HarnessUiRequest{Method: HarnessUiDisclosure,
		DisclosureId: "search:parallel", DisclosureVersion: 1})
	request := emitter.next(t).UiRequest()
	accept := "accept"
	confirmed := true
	for _, refused := range []*HarnessUiResponse{
		{Id: request.Id, Confirmed: &confirmed},
		{Id: request.Id, Value: &accept},
		{Id: request.Id, Acknowledged: true},
	} {
		if err := broker.Respond(refused); !errors.Is(err, ErrHarnessUiAnswerRefused) {
			t.Fatalf("%+v answered a disclosure: %v", refused, err)
		}
	}
	select {
	case answer := <-answers:
		t.Fatalf("a refused answer ended the wait: %+v", answer)
	default:
	}
	notNow := HarnessUiDisclosureDecline
	if err := broker.Respond(&HarnessUiResponse{Id: request.Id, Value: &notNow}); err != nil {
		t.Fatal(err)
	}
	answer := harnessAwaitAnswer(t, answers)
	inferError := &InferError{}
	if !errors.As(answer.err, &inferError) || inferError.Code != InferErrorDisclosureRequired ||
		inferError.Reason != InferDisclosureReasonDeclined || inferError.DisclosureId != "search:parallel" {
		t.Fatalf("a declined disclosure answered %+v, %v", answer.response, answer.err)
	}
}

// A request on a run no person's view watches fails at once: disclosure_required for a disclosure, unattached for a
// dialog, and nothing is raised. A view that detaches leaves the run unattached again.
func TestHarnessUiRequestOnUnattachedRunFailsAtOnce(t *testing.T) {
	emitter := newHarnessUiTestEmitter()
	broker := NewHarnessUiBroker(&HarnessUiBrokerArgs{Emit: emitter.emit, Acks: newHarnessTestAcks()})
	runId, agentId := NewId(), NewId()
	ctx := context.Background()

	if _, err := broker.Ask(ctx, runId, agentId, &HarnessUiRequest{Method: HarnessUiConfirm, Title: "Go on?"}); !errors.Is(err, ErrHarnessUiUnattached) {
		t.Fatalf("a confirm on an unattached run: %v", err)
	}
	_, err := broker.Ask(ctx, runId, agentId, &HarnessUiRequest{Method: HarnessUiDisclosure, DisclosureId: "inference:none", DisclosureVersion: 1})
	if InferErrorCodeOf(err) != InferErrorDisclosureRequired {
		t.Fatalf("a disclosure on an unattached run: %v", err)
	}
	detach := broker.AttachPerson(runId)
	if !broker.Attached(runId) {
		t.Fatal("an attached run reads unattached")
	}
	detach()
	detach()
	if broker.Attached(runId) {
		t.Fatal("a detached run reads attached")
	}
	if _, err := broker.Ask(ctx, runId, agentId, &HarnessUiRequest{Method: HarnessUiSelect, Options: []string{"a"}}); !errors.Is(err, ErrHarnessUiUnattached) {
		t.Fatalf("a select after detaching: %v", err)
	}
	if len(emitter.events) != 0 {
		t.Fatalf("a refused request emitted %d events", len(emitter.events))
	}

	// with no acknowledgment store wired, an attached run's disclosure answers disclosure_required at once
	unwired := NewHarnessUiBroker(&HarnessUiBrokerArgs{Emit: emitter.emit})
	defer unwired.AttachPerson(runId)()
	_, err = unwired.Ask(ctx, runId, agentId, &HarnessUiRequest{Method: HarnessUiDisclosure, DisclosureId: "inference:none", DisclosureVersion: 1})
	if InferErrorCodeOf(err) != InferErrorDisclosureRequired {
		t.Fatalf("a disclosure with no store: %v", err)
	}
}

// A connect is answered only by its handler, the person's own input on this device: a ui_response is refused, and with
// no handler the request is refused.
func TestHarnessConnectAnsweredOnlyByPersonInput(t *testing.T) {
	emitter := newHarnessUiTestEmitter()
	handlerStarted := make(chan *HarnessUiRequest, 1)
	personAnswered := make(chan string, 1)
	handler := func(ctx context.Context, runId Id, request *HarnessUiRequest) (*HarnessUiResponse, error) {
		handlerStarted <- request
		value := <-personAnswered
		return &HarnessUiResponse{Value: &value, Acknowledged: true}, nil
	}
	broker := NewHarnessUiBroker(&HarnessUiBrokerArgs{Emit: emitter.emit,
		Handlers: map[HarnessUiKind]HarnessUiHandler{HarnessUiConnect: handler}})
	runId, agentId := NewId(), NewId()
	defer broker.AttachPerson(runId)()

	answers := harnessAskAsync(broker, runId, agentId, &HarnessUiRequest{Method: HarnessUiConnect, Title: "Connect a calendar",
		Connect: json.RawMessage(`{"service":"example-calendar"}`)})
	request := <-handlerStarted
	if raised := emitter.next(t); raised.Type != HarnessEventUiRequest || raised.UiRequest().Id != request.Id {
		t.Fatalf("raised %s", raised.Type)
	}
	connected := "connected"
	if err := broker.Respond(&HarnessUiResponse{Id: request.Id, Value: &connected}); err == nil {
		t.Fatal("a ui_response answered a connect")
	}
	personAnswered <- "connected"
	answer := harnessAwaitAnswer(t, answers)
	if answer.err != nil || answer.response.Value == nil || *answer.response.Value != "connected" || answer.response.Acknowledged {
		t.Fatalf("the person's input answered %+v, %v", answer.response, answer.err)
	}

	unhandled := NewHarnessUiBroker(&HarnessUiBrokerArgs{Emit: emitter.emit, Handlers: map[HarnessUiKind]HarnessUiHandler{}})
	defer unhandled.AttachPerson(runId)()
	if _, err := unhandled.Ask(context.Background(), runId, agentId, &HarnessUiRequest{Method: HarnessUiConnect}); !errors.Is(err, ErrHarnessUiNoHandler) {
		t.Fatalf("a connect with no handler: %v", err)
	}
}

// Pi's dialogs: a select takes only an offered option, a confirm only confirmed, a cancel ends any; a timeout reads
// cancelled on the broker's clock.
func TestHarnessUiDialogsTakeFittingAnswers(t *testing.T) {
	emitter := newHarnessUiTestEmitter()
	clock := newHarnessTestClock()
	broker := NewHarnessUiBroker(&HarnessUiBrokerArgs{Emit: emitter.emit, Clock: clock})
	runId, agentId := NewId(), NewId()
	defer broker.AttachPerson(runId)()

	answers := harnessAskAsync(broker, runId, agentId, &HarnessUiRequest{Method: HarnessUiSelect, Title: "Pick",
		Options: []string{"retry", "local"}})
	request := emitter.next(t).UiRequest()
	other := "another model"
	if err := broker.Respond(&HarnessUiResponse{Id: request.Id, Value: &other}); !errors.Is(err, ErrHarnessUiAnswerInvalid) {
		t.Fatalf("an option not offered: %v", err)
	}
	if pending := broker.Pending(runId); len(pending) != 1 || pending[0].Id != request.Id {
		t.Fatalf("pending: %+v", pending)
	}
	local := "local"
	if err := broker.Respond(&HarnessUiResponse{Id: request.Id, Value: &local}); err != nil {
		t.Fatal(err)
	}
	if answer := harnessAwaitAnswer(t, answers); answer.err != nil || *answer.response.Value != "local" {
		t.Fatalf("select: %+v, %v", answer.response, answer.err)
	}
	emitter.next(t)

	answers = harnessAskAsync(broker, runId, agentId, &HarnessUiRequest{Method: HarnessUiConfirm, Title: "Go on?", TimeoutMs: 5000})
	request = emitter.next(t).UiRequest()
	if err := clock.AwaitTimers(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(5 * time.Second)
	if answer := harnessAwaitAnswer(t, answers); answer.err != nil || !answer.response.Cancelled {
		t.Fatalf("a timed-out confirm: %+v, %v", answer.response, answer.err)
	}
	if err := broker.Respond(&HarnessUiResponse{Id: request.Id, Cancelled: true}); !errors.Is(err, ErrHarnessUiAnswerInvalid) {
		t.Fatalf("an answer after the request ended: %v", err)
	}
}

// A dialog its asker stopped waiting on, an aborted run's, closes in every view: a ui_response, cancelled, goes out, the
// call answers its context's error, and a late answer finds nothing waiting.
func TestHarnessUiDialogClosesWhenItsAskerStops(t *testing.T) {
	emitter := newHarnessUiTestEmitter()
	broker := NewHarnessUiBroker(&HarnessUiBrokerArgs{Emit: emitter.emit})
	runId, agentId := NewId(), NewId()
	defer broker.AttachPerson(runId)()
	ctx, cancel := context.WithCancel(context.Background())
	asked := make(chan error, 1)
	go func() {
		_, err := broker.Ask(ctx, runId, agentId, &HarnessUiRequest{Method: HarnessUiConfirm, Title: "Go on?"})
		asked <- err
	}()
	raised := emitter.next(t)
	if raised.Type != HarnessEventUiRequest {
		t.Fatalf("emitted %s", raised.Type)
	}
	requestId := raised.UiRequest().Id
	cancel()
	closed := emitter.next(t)
	closedId, cancelled := "", false
	closed.Decode("id", &closedId)
	closed.Decode("cancelled", &cancelled)
	if closed.Type != HarnessEventUiResponse || closedId != requestId || !cancelled {
		t.Fatalf("the dialog closed with %s %q, cancelled %v", closed.Type, closedId, cancelled)
	}
	select {
	case err := <-asked:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the stopped call answered %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Ask did not answer")
	}
	confirmed := true
	if err := broker.Respond(&HarnessUiResponse{Id: requestId, Confirmed: &confirmed}); !errors.Is(err, ErrHarnessUiAnswerInvalid) {
		t.Fatalf("a late answer: %v", err)
	}
}
