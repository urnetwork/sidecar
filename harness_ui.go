//go:build !ios_extension && !sidecar_http

// The ui broker (DESIGN-COMPUTE §7.6, D-HARN-10, §2.8, §25.5): a tool's or the router's question to the person, raised
// on a run as a ui_request event while the run waits for its answer.
//
//   - select, confirm and input, Pi's dialogs, are answered by a ui_response from the person's view: the app's UI or
//     `ur harness` on /dev/tty (Respond).
//   - disclosure names a disclosure's id and version and nothing else. Only the person's acknowledgment answers it,
//     landed in CTRUST's store (AckDisclosure from the app's UI, `ur harness` on /dev/tty), which the broker awaits; a
//     ui_response may only decline it ("Not now"), which fails the call waiting on it with disclosure_required, reason
//     declined. Until CTRUST's store is wired every disclosure request answers disclosure_required at once.
//   - connect takes only the person's own input, through the handler CONN registers (RegisterHarnessUiHandler); a
//     ui_response never answers it, and with no handler it is refused.
//
// A request on a run no person's view watches fails at once: disclosure_required for a disclosure, ErrHarnessUiUnattached
// for the rest. Attached says whether one does: the app's UI with a listener on the agent, or `ur harness` reading
// /dev/tty with no harness process among its ancestors (AttachPerson, which their hosts call).
//
// Safe for concurrent use. Calls out (the emit function, the store, a handler) hold no lock.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// What a request asks (§7.6): Pi's three dialogs and sidecar's two.
type HarnessUiKind string

const (
	HarnessUiSelect     HarnessUiKind = "select"
	HarnessUiConfirm    HarnessUiKind = "confirm"
	HarnessUiInput      HarnessUiKind = "input"
	HarnessUiConnect    HarnessUiKind = "connect"
	HarnessUiDisclosure HarnessUiKind = "disclosure"
)

// The value a view sends to decline a disclosure, beside cancelled (§2.8's "Not now").
const HarnessUiDisclosureDecline = "Not now"

var (
	// No person's view watches the run, so a dialog cannot be raised.
	ErrHarnessUiUnattached = errors.New("no person is attached to the run")
	// The answer does not fit its request: an option not offered, a select answered as a confirm, an unknown id.
	ErrHarnessUiAnswerInvalid = errors.New("the answer does not fit the request")
	// A ui_response tried to answer what only the person's own act answers: a disclosure's acknowledgment, a connect.
	ErrHarnessUiAnswerRefused = errors.New("a ui_response cannot answer this request")
	// No handler is registered for the kind, so the request is refused.
	ErrHarnessUiNoHandler = errors.New("no handler answers this kind of request")
)

// A question raised on a run: Pi's extension_ui_request members, in Pi's order, with sidecar's disclosure and connect.
type HarnessUiRequest struct {
	Id     string
	Method HarnessUiKind
	// A dialog's title, a confirm's message, a select's options, an input's placeholder.
	Title       string
	Message     string
	Options     []string
	Placeholder string
	// A dialog's timeout in milliseconds, past which it reads cancelled, as Pi's auto-resolve; 0 for none.
	TimeoutMs int64
	// A disclosure's id and version, the only text its request carries.
	DisclosureId      string
	DisclosureVersion uint32
	// A connect's request body, CONN's (§25.7).
	Connect json.RawMessage
}

// The request in Pi's member order. A disclosure's carries its id, method, disclosure id and version alone.
func (self *HarnessUiRequest) object() harnessPiObject {
	object := harnessPiObject{}
	object.set("id", self.Id)
	object.set("method", self.Method)
	if self.Method == HarnessUiDisclosure {
		object.set("disclosureId", self.DisclosureId)
		object.set("disclosureVersion", self.DisclosureVersion)
		return object
	}
	if self.Title != "" {
		object.set("title", self.Title)
	}
	if self.Message != "" {
		object.set("message", self.Message)
	}
	if self.Options != nil {
		object.set("options", self.Options)
	}
	if self.Placeholder != "" {
		object.set("placeholder", self.Placeholder)
	}
	if 0 < self.TimeoutMs {
		object.set("timeout", self.TimeoutMs)
	}
	if self.Connect != nil {
		if compacted, err := harnessPiCompact(self.Connect); err == nil {
			object.setRaw("connect", compacted)
		}
	}
	return object
}

func (self *HarnessUiRequest) MarshalJSON() ([]byte, error) {
	return self.object().MarshalJSON()
}

func (self *HarnessUiRequest) UnmarshalJSON(data []byte) error {
	object := harnessPiObject{}
	if err := object.UnmarshalJSON(data); err != nil {
		return err
	}
	request := HarnessUiRequest{
		Id:           object.str("id"),
		Method:       HarnessUiKind(object.str("method")),
		Title:        object.str("title"),
		Message:      object.str("message"),
		Placeholder:  object.str("placeholder"),
		DisclosureId: object.str("disclosureId"),
		Connect:      object.get("connect"),
	}
	object.decode("options", &request.Options)
	object.decode("timeout", &request.TimeoutMs)
	object.decode("disclosureVersion", &request.DisclosureVersion)
	*self = request
	return nil
}

// An answer: Pi's extension_ui_response members. Acknowledged is set by the broker alone, once a disclosure's
// acknowledgment landed in CTRUST's store; a view never sets it.
type HarnessUiResponse struct {
	Id           string
	Value        *string
	Confirmed    *bool
	Cancelled    bool
	Acknowledged bool
}

// The answer in Pi's member order.
func (self *HarnessUiResponse) object() harnessPiObject {
	object := harnessPiObject{}
	object.set("id", self.Id)
	if self.Value != nil {
		object.set("value", *self.Value)
	}
	if self.Confirmed != nil {
		object.set("confirmed", *self.Confirmed)
	}
	if self.Cancelled {
		object.set("cancelled", true)
	}
	if self.Acknowledged {
		object.set("acknowledged", true)
	}
	return object
}

func (self *HarnessUiResponse) MarshalJSON() ([]byte, error) {
	return self.object().MarshalJSON()
}

func (self *HarnessUiResponse) UnmarshalJSON(data []byte) error {
	object := harnessPiObject{}
	if err := object.UnmarshalJSON(data); err != nil {
		return err
	}
	response := HarnessUiResponse{Id: object.str("id")}
	if object.has("value") {
		value := ""
		if !object.decode("value", &value) {
			return fmt.Errorf("%w: value is no string", ErrHarnessUiAnswerInvalid)
		}
		response.Value = &value
	}
	if object.has("confirmed") {
		confirmed := false
		if !object.decode("confirmed", &confirmed) {
			return fmt.Errorf("%w: confirmed is no boolean", ErrHarnessUiAnswerInvalid)
		}
		response.Confirmed = &confirmed
	}
	object.decode("cancelled", &response.Cancelled)
	object.decode("acknowledged", &response.Acknowledged)
	*self = response
	return nil
}

// CTRUST's acknowledgment store as the broker reads it (§2.8): ComputeDisclosureAcks.Await.
type HarnessDisclosureAcks interface {
	// Returns once an acknowledgment covering version of id has landed, made on this device or synced from another of
	// the member's; at once where one already covers it. An error once ctx ends. Nothing but the store wakes it.
	Await(ctx context.Context, id string, version uint32) error
}

// Answers a kind only the person's own input answers (connect, §25.5): runs the person-facing flow on this device and
// returns the answer, or an error that fails the call. CONN registers it.
type HarnessUiHandler func(ctx context.Context, runId Id, request *HarnessUiRequest) (*HarnessUiResponse, error)

// The handlers by kind, written only during the package's init.
var harnessUiHandlers = map[HarnessUiKind]HarnessUiHandler{}

// Registers the handler for a kind only the person's own input answers, from an init function in its owner's file
// (CONN's connect). Only connect takes a handler; a kind registered twice or a nil handler is a build error, which
// panics.
func RegisterHarnessUiHandler(kind HarnessUiKind, handler HarnessUiHandler) {
	if _, registered := harnessUiHandlers[kind]; kind != HarnessUiConnect || registered || handler == nil {
		panic(fmt.Sprintf("harness ui handler %q registered twice, without a handler, or for a kind a view answers", kind))
	}
	harnessUiHandlers[kind] = handler
}

// What a broker is built on.
type HarnessUiBrokerArgs struct {
	// Emits a ui_request or ui_response as agentId's. Required.
	Emit func(agentId Id, event *HarnessEvent) error
	// CTRUST's store; nil answers every disclosure request disclosure_required.
	Acks HarnessDisclosureAcks
	// The kinds' handlers; nil takes the registered ones.
	Handlers map[HarnessUiKind]HarnessUiHandler
	// A dialog's timeout runs on it; nil for real time.
	Clock Clock
}

// One request waiting for its answer.
type harnessUiPending struct {
	runId   Id
	agentId Id
	request *HarnessUiRequest
	// takes the one answer; buffered, so the answerer never waits
	answer chan *HarnessUiResponse
}

// A Harness's ui broker: one per Harness.
type HarnessUiBroker struct {
	emit     func(agentId Id, event *HarnessEvent) error
	acks     HarnessDisclosureAcks
	handlers map[HarnessUiKind]HarnessUiHandler
	clock    Clock

	stateLock sync.Mutex
	// how many of the person's views watch each run
	runIdAttachedCounts map[Id]int
	idPendings          map[string]*harnessUiPending
}

// A broker over args.
func NewHarnessUiBroker(args *HarnessUiBrokerArgs) *HarnessUiBroker {
	handlers := args.Handlers
	if handlers == nil {
		handlers = harnessUiHandlers
	}
	return &HarnessUiBroker{
		emit:                args.Emit,
		acks:                args.Acks,
		handlers:            handlers,
		clock:               clockOrReal(args.Clock),
		runIdAttachedCounts: map[Id]int{},
		idPendings:          map[string]*harnessUiPending{},
	}
}

// Whether a person's view watches the run: the app's UI, or `ur harness` on /dev/tty with no harness ancestor.
func (self *HarnessUiBroker) Attached(runId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return 0 < self.runIdAttachedCounts[runId]
}

// Marks a person's view watching the run, until the answer detaches it. The host calls it only for a view that is the
// person's own: the app's UI, or `ur harness` reading /dev/tty with no harness process among its ancestors.
func (self *HarnessUiBroker) AttachPerson(runId Id) (detach func()) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.runIdAttachedCounts[runId] += 1
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.runIdAttachedCounts[runId] -= 1
			if self.runIdAttachedCounts[runId] <= 0 {
				delete(self.runIdAttachedCounts, runId)
			}
		})
	}
}

// The requests waiting on the run, for a view that attaches after they were raised.
func (self *HarnessUiBroker) Pending(runId Id) []*HarnessUiRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	requests := []*HarnessUiRequest{}
	for _, pending := range self.idPendings {
		if pending.runId == runId {
			request := *pending.request
			requests = append(requests, &request)
		}
	}
	slices.SortFunc(requests, func(a *HarnessUiRequest, b *HarnessUiRequest) int {
		switch {
		case a.Id < b.Id:
			return -1
		case b.Id < a.Id:
			return 1
		}
		return 0
	})
	return requests
}

// The error a disclosure request answers where no acknowledgment can come: disclosure_required with reason.
func harnessDisclosureRequired(request *HarnessUiRequest, reason string, message string) *InferError {
	return &InferError{
		Code:              InferErrorDisclosureRequired,
		Message:           message,
		Reason:            reason,
		DisclosureId:      request.DisclosureId,
		DisclosureVersion: request.DisclosureVersion,
	}
}

// Raises request on the run as agentId's and waits for its answer: a select, confirm or input's ui_response from the
// person's view, a disclosure's acknowledgment (Acknowledged set), or a connect's answer from its handler. Fails at once
// on a run no person watches; a disclosure then, or wherever no acknowledgment can come, with disclosure_required, and a
// declined disclosure with disclosure_required, reason declined. A dialog past its timeout answers cancelled; ctx's end
// answers ctx's error. request's Id is set where empty.
func (self *HarnessUiBroker) Ask(ctx context.Context, runId Id, agentId Id, request *HarnessUiRequest) (*HarnessUiResponse, error) {
	if request == nil {
		return nil, ErrHarnessUiAnswerInvalid
	}
	asked := *request
	switch asked.Method {
	case HarnessUiSelect, HarnessUiConfirm, HarnessUiInput, HarnessUiConnect:
	case HarnessUiDisclosure:
		if asked.DisclosureId == "" {
			return nil, fmt.Errorf("%w: a disclosure request names no disclosure", ErrHarnessUiAnswerInvalid)
		}
		// nothing but the id and version rides a disclosure's request, whatever the asker set
		asked = HarnessUiRequest{Id: asked.Id, Method: HarnessUiDisclosure, DisclosureId: asked.DisclosureId,
			DisclosureVersion: asked.DisclosureVersion}
	default:
		return nil, fmt.Errorf("%w: no kind %q", ErrHarnessUiAnswerInvalid, asked.Method)
	}
	if asked.Id == "" {
		asked.Id = NewId().String()
	}
	if !self.Attached(runId) {
		if asked.Method == HarnessUiDisclosure {
			return nil, harnessDisclosureRequired(&asked, InferDisclosureReasonUnacknowledged,
				"no person is attached to the run to acknowledge the disclosure")
		}
		return nil, ErrHarnessUiUnattached
	}
	switch asked.Method {
	case HarnessUiConnect:
		return self.askConnect(ctx, runId, agentId, &asked)
	case HarnessUiDisclosure:
		if self.acks == nil {
			return nil, harnessDisclosureRequired(&asked, InferDisclosureReasonUnacknowledged,
				"this build reads no acknowledgment store, so the disclosure cannot be acknowledged here")
		}
	}

	pending := &harnessUiPending{runId: runId, agentId: agentId, request: &asked, answer: make(chan *HarnessUiResponse, 1)}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.idPendings[asked.Id] = pending
	}()
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.idPendings, asked.Id)
	}()
	if err := self.emit(agentId, NewHarnessUiRequestEvent(&asked)); err != nil {
		return nil, err
	}

	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if asked.Method == HarnessUiDisclosure {
		go func() {
			if err := self.acks.Await(waitCtx, asked.DisclosureId, asked.DisclosureVersion); err != nil {
				return
			}
			select {
			case pending.answer <- &HarnessUiResponse{Id: asked.Id, Acknowledged: true}:
			default:
			}
		}()
	}
	var timeout <-chan time.Time
	if 0 < asked.TimeoutMs && asked.Method != HarnessUiDisclosure {
		timeout = self.clock.After(time.Duration(asked.TimeoutMs) * time.Millisecond)
	}

	var answer *HarnessUiResponse
	select {
	case answer = <-pending.answer:
	case <-timeout:
		answer = &HarnessUiResponse{Id: asked.Id, Cancelled: true}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// every view closes the dialog
	self.emit(agentId, NewHarnessUiResponseEvent(answer))
	if asked.Method == HarnessUiDisclosure && !answer.Acknowledged {
		return nil, harnessDisclosureRequired(&asked, InferDisclosureReasonDeclined, "the person declined the disclosure for now")
	}
	return answer, nil
}

// A connect request, answered only by its handler: the person's own input on this device (§25.5).
func (self *HarnessUiBroker) askConnect(ctx context.Context, runId Id, agentId Id, request *HarnessUiRequest) (*HarnessUiResponse, error) {
	handler := self.handlers[HarnessUiConnect]
	if handler == nil {
		return nil, ErrHarnessUiNoHandler
	}
	if err := self.emit(agentId, NewHarnessUiRequestEvent(request)); err != nil {
		return nil, err
	}
	answer, err := handler(ctx, runId, request)
	if err != nil {
		return nil, err
	}
	if answer == nil {
		answer = &HarnessUiResponse{Cancelled: true}
	}
	answer.Id = request.Id
	answer.Acknowledged = false
	self.emit(agentId, NewHarnessUiResponseEvent(answer))
	return answer, nil
}

// Takes a ui_response from the person's view: answers a waiting select, confirm or input whose answer fits it, and
// declines a disclosure ("Not now", or cancelled), which fails the call waiting on it. Anything else is refused: an
// acknowledgment or acceptance of a disclosure (only the person's acknowledgment in CTRUST's store answers one), an
// answer to a connect, an unknown id, an option not offered.
func (self *HarnessUiBroker) Respond(response *HarnessUiResponse) error {
	if response == nil || response.Id == "" {
		return ErrHarnessUiAnswerInvalid
	}
	pending := func() *harnessUiPending {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.idPendings[response.Id]
	}()
	if pending == nil {
		return fmt.Errorf("%w: no request %s waits", ErrHarnessUiAnswerInvalid, response.Id)
	}
	if response.Acknowledged {
		return fmt.Errorf("%w: only the person's acknowledgment answers a disclosure", ErrHarnessUiAnswerRefused)
	}
	answer := &HarnessUiResponse{Id: response.Id}
	switch pending.request.Method {
	case HarnessUiDisclosure:
		declined := response.Cancelled || (response.Value != nil && *response.Value == HarnessUiDisclosureDecline)
		if !declined || response.Confirmed != nil {
			return fmt.Errorf("%w: a ui_response only declines a disclosure", ErrHarnessUiAnswerRefused)
		}
		answer.Cancelled = true
	case HarnessUiConnect:
		return fmt.Errorf("%w: only the person's own input answers a connect", ErrHarnessUiAnswerRefused)
	default:
		if response.Cancelled {
			answer.Cancelled = true
			break
		}
		switch pending.request.Method {
		case HarnessUiSelect:
			if response.Value == nil || response.Confirmed != nil ||
				!slices.Contains(pending.request.Options, *response.Value) {
				return fmt.Errorf("%w: a select takes one of its options", ErrHarnessUiAnswerInvalid)
			}
			value := *response.Value
			answer.Value = &value
		case HarnessUiConfirm:
			if response.Confirmed == nil || response.Value != nil {
				return fmt.Errorf("%w: a confirm takes confirmed", ErrHarnessUiAnswerInvalid)
			}
			confirmed := *response.Confirmed
			answer.Confirmed = &confirmed
		case HarnessUiInput:
			if response.Value == nil || response.Confirmed != nil {
				return fmt.Errorf("%w: an input takes a value", ErrHarnessUiAnswerInvalid)
			}
			value := *response.Value
			answer.Value = &value
		}
	}
	select {
	case pending.answer <- answer:
		return nil
	default:
		return fmt.Errorf("%w: request %s is already answered", ErrHarnessUiAnswerInvalid, response.Id)
	}
}
