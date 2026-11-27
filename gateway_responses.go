//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The gateway's fronts and the Responses front (DESIGN-COMPUTE §8.4, §8.5; R-GW-1, R-GW-2, R-GW-3, R-GW-5, D-GW-1,
// D-GW-2, D-GW-4, D-GW-6, CF-3; GW-M12-03). MountFronts puts the fronts' routes on a GatewayServer, behind its listener
// check and its token (gateway_listener.go, gateway_token.go). Every call passes, in order:
//
//	read       the body, at most GatewaySettings.RequestByteCount (the guard's bound), else 413
//	search     SRCH's filter drops hosted web search (gateway_search.go, §21.7)
//	route      what needs stored state refused 400, the gateway's reasoning blobs opened, images re-encoded
//	           (gateway_translate.go); the routed body is what the model receives and what the call records
//	translate  one InferRequest (§6.4)
//	grant      a grant with a model list admits only the canonical names its globs match (§16.4), else 403
//	           model_not_in_grant; the grant is the router's budget (InferBudgetRef)
//	bind       the token's run handle binds the call's run and the union of marks the router checks (§8.9,
//	           gateway_bind.go), a refusal there a 503: nothing goes upstream unbound
//	check      the router checks the call as it would dispatch it (§6.4): a refusal answers in the API's words before
//	           anything is recorded or sent, disclosure_required among them, naming the id, its summary line and the
//	           fix (D-GW-6); the gateway never prompts, since no person is attached to a harness's call
//	record     the recorder journals the request's items before the call goes upstream (IC-19): with no recorder, or a
//	           Begin that fails, the call is refused 503
//	dispatch   the router's stream, mapped to the API's events (§8.5's table) by the front's producer, each response
//	           item journaled before the event that completes it; a stream always ends with a terminal event, the
//	           failure after the model's output began carrying a code Codex does not retry (gateway_errors.go)
//
// A call a run handle binds runs under the fronts' life rather than its request's, so a caller that left does not cut
// it: its answer is kept for a retry that joins it (§8.5, gateway_retry.go). Nothing is ever sent to another model,
// provider or label on any error (R-GW-5).
//
// The Responses front: POST /v1/responses, Open Responses' 2026-04-24 revision as the conformance target, stateless
// (store true and previous_response_id answer 400 unsupported_parameter, Q-CTXH-9), streaming and not. Its stream is
// response.created and response.in_progress, then each output item's lifecycle (output_item.added, its parts' added,
// deltas and done, output_item.done carrying the whole item), and a terminal response.completed with the response's id
// and integer usage, or response.failed with error.code; reasoning is a reasoning item's summary text, its
// encrypted_content the gateway's own blob naming the session node that recorded it, where the request's include asks.
//
// Safe for concurrent use: stateLock guards the recorder, the drain and the count of calls running.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The routes, the ids' prefixes and the fronts' daemon method: format values.
const (
	GatewayRouteResponses = "POST /v1/responses"

	gatewayResponseIdPrefix     = "resp_"
	gatewayMessageItemIdPrefix  = "msg_"
	gatewayReasoningIdPrefix    = "rs_"
	gatewayFunctionCallIdPrefix = "fc_"

	DaemonMethodGatewayFronts = "gateway.fronts"

	gatewayResponsesObject           = "response"
	gatewayResponsesStatusInProgress = "in_progress"
	gatewayResponsesStatusCompleted  = "completed"
	gatewayResponsesStatusFailed     = "failed"
)

// What the fronts read of a network beyond GatewayNetwork: the router its calls go through (§6.4). *Sidecar is one.
type GatewayFrontNetwork interface {
	InferRouter() (InferRouter, error)
}

// What MountFronts takes.
type GatewayFrontsArgs struct {
	// SRCH's filter, whose notice ur status shows (§21.7); nil builds one on the gateway's clock.
	HostedSearch *GatewayHostedSearch
	// The recorder (GW-M12-06); nil refuses every call until SetRecorder, since none could be journaled (IC-19).
	Recorder GatewayRecorder
	// What the gateway's ids, blobs' nonces and nothing else are drawn from: the server's, crypto/rand's when nil.
	Random io.Reader
	// The keepalives' and first events' clock: the server's when nil.
	Clock Clock
}

// The fronts on one GatewayServer (see the file header).
type GatewayFronts struct {
	server       *GatewayServer
	settings     *GatewaySettings
	clock        Clock
	log          Logger
	random       io.Reader
	hostedSearch *GatewayHostedSearch
	// the fronts' life: a call whose caller may come back runs under it, not under its request
	ctx    context.Context
	cancel context.CancelFunc
	// each frame a caller wrote, for a test to steer; nil in a daemon
	followWritten func(frame []byte)

	stateLock sync.Mutex
	recorder  GatewayRecorder
	draining  bool
	// calls whose producers run, which a planned restart waits on
	running        int
	runningChanged chan struct{}
}

// Puts the fronts' routes on the server and answers them: POST /v1/responses here, and each later front's from its own
// file (gatewayFrontRoutes).
func (self *GatewayServer) MountFronts(args *GatewayFrontsArgs) *GatewayFronts {
	if args == nil {
		args = &GatewayFrontsArgs{}
	}
	clock := self.clock
	if args.Clock != nil {
		clock = args.Clock
	}
	random := args.Random
	if random == nil {
		random = self.random
	}
	if random == nil {
		random = rand.Reader
	}
	hostedSearch := args.HostedSearch
	if hostedSearch == nil {
		hostedSearch = NewGatewayHostedSearch(&GatewayHostedSearchArgs{Settings: self.settings.HostedSearch, Clock: clock})
	}
	ctx, cancel := context.WithCancel(context.Background())
	fronts := &GatewayFronts{
		server:         self,
		settings:       self.settings,
		clock:          clock,
		log:            self.log,
		random:         random,
		hostedSearch:   hostedSearch,
		ctx:            ctx,
		cancel:         cancel,
		recorder:       args.Recorder,
		runningChanged: make(chan struct{}),
	}
	self.Handle(GatewayRouteResponses, func(writer http.ResponseWriter, request *http.Request, caller *GatewayCaller) {
		fronts.serve(writer, request, caller, gatewayResponsesFront{})
	})
	for _, route := range gatewayFrontRoutes {
		self.Handle(route.pattern, func(writer http.ResponseWriter, request *http.Request, caller *GatewayCaller) {
			route.serve(fronts, writer, request, caller)
		})
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.fronts = fronts
	}()
	return fronts
}

// A later front's route, registered from its own file at init (the Chat Completions front, the catalog's endpoints).
type gatewayFrontRoute struct {
	pattern string
	serve   func(fronts *GatewayFronts, writer http.ResponseWriter, request *http.Request, caller *GatewayCaller)
}

// The later fronts' routes. Written only at init.
var gatewayFrontRoutes = []*gatewayFrontRoute{}

// Sets the recorder (GW-M12-06), which the daemon builds after the gateway; nil refuses every call again.
func (self *GatewayFronts) SetRecorder(recorder GatewayRecorder) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.recorder = recorder
}

// The recorder, nil while none is set.
func (self *GatewayFronts) currentRecorder() GatewayRecorder {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.recorder
}

// SRCH's filter, whose notice ur status shows.
func (self *GatewayFronts) HostedSearch() *GatewayHostedSearch {
	return self.hostedSearch
}

// A planned restart (§8.5's crash paragraph): new calls are refused 503 with BusyRetryAfter, and this waits for the
// calls running, up to GatewaySettings.PlannedRestartWait or ctx's end, answering how many still ran. The fronts serve
// nothing new after.
func (self *GatewayFronts) Drain(ctx context.Context) int {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.draining = true
	}()
	var deadline <-chan time.Time
	if 0 < self.settings.PlannedRestartWait {
		deadline = self.clock.After(self.settings.PlannedRestartWait)
	}
	for {
		running, changed := func() (int, chan struct{}) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.running, self.runningChanged
		}()
		if running == 0 || deadline == nil {
			return running
		}
		select {
		case <-changed:
		case <-deadline:
			return running
		case <-ctx.Done():
			return running
		}
	}
}

// Ends every call still running: the daemon's end, after Drain.
func (self *GatewayFronts) Close() {
	self.cancel()
}

// Whether a planned restart has begun.
func (self *GatewayFronts) isDraining() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.draining
}

// Counts a call's producer in, or out once it ends.
func (self *GatewayFronts) countRunning(delta int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.running += delta
	close(self.runningChanged)
	self.runningChanged = make(chan struct{})
}

// What gateway.fronts answers, for ur status: the calls running, and hosted search's warnings (§21.7). Never a body,
// a token or a model's words.
type GatewayFrontsStatus struct {
	Running  int  `json:"running,omitempty"`
	Draining bool `json:"draining,omitempty"`
	// Calls kept for a retry, in flight and ended (gateway_retry.go).
	Kept int `json:"kept,omitempty"`
	// A line each harness that still sends hosted search, named ones first (GatewayHostedSearchNotice).
	HostedSearchWarnings []string `json:"hosted_search_warnings,omitempty"`
	// Whether a recorder is set; with none every call is refused (IC-19).
	Recording bool `json:"recording"`
}

// The fronts as ur status reads them.
func (self *GatewayFronts) Status() *GatewayFrontsStatus {
	status := &GatewayFrontsStatus{HostedSearchWarnings: self.hostedSearch.Notice().Warnings(), Kept: self.keptCount()}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status.Running, status.Draining, status.Recording = self.running, self.draining, self.recorder != nil
	return status
}

// The fronts' control methods: gateway.fronts, which ur status reads.
func (self *GatewayFronts) DaemonMethods() []*DaemonMethod {
	return []*DaemonMethod{
		{
			Name: DaemonMethodGatewayFronts,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				return self.Status(), nil
			},
		},
	}
}

// A made-up id: prefix and IdRandomByteCount random bytes in hex.
func (self *GatewayFronts) newId(prefix string) (string, error) {
	raw := make([]byte, max(self.settings.IdRandomByteCount, 1))
	if _, err := io.ReadFull(self.random, raw); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw), nil
}

// What a front is to the shared pipeline: its API, its renderer, its search filter, its route and translation, and
// the producer that maps the router's events onto its answer.
type gatewayFront interface {
	api() SessionGatewayApi
	renderer() string
	responseIdPrefix() string
	filter(hostedSearch *GatewayHostedSearch, harness string, body []byte) ([]byte, error)
	route(settings *GatewaySettings, body []byte, key []byte) ([]byte, *gatewayError)
	translate(body []byte) (*InferRequest, *gatewayRequestOptions, *gatewayError)
	newProducer(run *gatewayCallRun) gatewayProducer
	keepaliveFrame() []byte
}

// What maps one call's events onto its answer (see each front's producer). Called from the call's run alone.
type gatewayProducer interface {
	// The frames that open a stream, once its head is decided.
	open() [][]byte
	// One event's frames, an item recorded before the frame that completes it; an error where recording failed,
	// which ends the call before the item is sent.
	event(ctx context.Context, event *InferEvent) ([][]byte, error)
	// A completed call's last frames, every item still open completed and recorded first: a stream's closing events
	// and terminal, or a whole answer's one body; an error where recording failed.
	complete(ctx context.Context) ([][]byte, error)
	// A failed call's terminal frame on a stream that began: began says whether the model's output had.
	fail(failure *gatewayError, began bool) [][]byte
	// Whether the model's output began: any text, reasoning or tool call.
	began() bool
	// What the call used, and its attestations, for its model_call.
	usage() (*InferUsage, []*protocol.AttestationResult)
}

// One call prepared for dispatch: everything the pipeline read of its request.
type gatewayPreparedCall struct {
	front   gatewayFront
	caller  *GatewayCaller
	router  InferRouter
	binding *GatewayBinding
	request *InferRequest
	options *gatewayRequestOptions
	// the body as the model receives it, which the call records
	routed []byte
	// SHA-256 of the body as its caller sent it, which a retry is matched by (gateway_retry.go)
	bodySha256 [32]byte
	// the caller's Idempotency-Key, empty for none
	idempotencyKey string
	// the network's reasoning key, nil where it gives none; cleared when the call ends
	key []byte
}

// Serves one request of front for caller (see the file header's order).
func (self *GatewayFronts) serve(writer http.ResponseWriter, request *http.Request, caller *GatewayCaller, front gatewayFront) {
	api := front.api()
	if self.isDraining() {
		refusal := gatewayUnavailable(GatewayErrorCodeDraining, "the daemon is restarting: send the request again in a moment")
		refusal.RetryAfter = max(time.Second, self.settings.BusyRetryAfter)
		refusal.write(writer, api)
		return
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		gatewayReadError(err, self.settings.RequestByteCount).write(writer, api)
		return
	}
	prepared, refusal := self.prepare(request, caller, front, body)
	if refusal != nil {
		refusal.write(writer, api)
		return
	}
	answer, call, refusal := self.answer(request.Context(), prepared)
	if refusal != nil {
		clear(prepared.key)
		refusal.write(writer, api)
		return
	}
	delivered := answer.follow(request.Context(), writer, &gatewayFollow{
		clock:          self.clock,
		keepalive:      self.settings.KeepaliveInterval,
		keepaliveFrame: front.keepaliveFrame(),
		written:        self.followWritten,
	})
	if call != nil {
		call.followed(delivered)
	}
}

// Reads, routes, translates, binds and checks a request (see the file header's order up to check). A refusal is the
// gatewayError the caller is answered with; nothing has been recorded or sent.
func (self *GatewayFronts) prepare(request *http.Request, caller *GatewayCaller, front gatewayFront, body []byte) (*gatewayPreparedCall, *gatewayError) {
	ctx := request.Context()
	prepared := &gatewayPreparedCall{front: front, caller: caller, bodySha256: sha256.Sum256(body)}
	idempotencyKey, refusal := gatewayIdempotencyKey(request, self.settings)
	if refusal != nil {
		return nil, refusal
	}
	prepared.idempotencyKey = idempotencyKey
	filtered, err := front.filter(self.hostedSearch, caller.Grant.Harness, body)
	if err != nil {
		return nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, "", "%s", err.Error())
	}
	if keys, ok := caller.Network.(GatewayKeyNetwork); ok {
		if key, err := keys.GatewayKey(gatewayKeyReasoning); err == nil {
			prepared.key = key
		} else if self.log.V(1).Enabled() {
			self.log.Infof("[gateway]no reasoning key, so no reasoning blob opens or is sealed: %s", err)
		}
	}
	keep := false
	defer func() {
		if !keep {
			clear(prepared.key)
		}
	}()
	routed, refusal := front.route(self.settings, filtered, prepared.key)
	if refusal != nil {
		return nil, refusal
	}
	prepared.routed = routed
	inferRequest, options, refusal := front.translate(routed)
	if refusal != nil {
		return nil, refusal
	}
	prepared.request, prepared.options = inferRequest, options
	network, ok := caller.Network.(GatewayFrontNetwork)
	if !ok {
		return nil, gatewayUnavailable(GatewayErrorCodeRouterUnavailable, "the network serves no model calls here")
	}
	router, err := network.InferRouter()
	if err != nil {
		return nil, gatewayUnavailable(GatewayErrorCodeRouterUnavailable, "the network's router is not available now")
	}
	prepared.router = router
	if refusal := self.checkGrantModel(ctx, caller.Grant, router, inferRequest); refusal != nil {
		return nil, refusal
	}
	sessionId := ""
	if header := self.settings.HarnessSessionHeaders[caller.Grant.Harness]; header != "" {
		sessionId = request.Header.Get(header)
	}
	binding, err := self.server.BindCall(ctx, caller, sessionId)
	if err != nil {
		return nil, gatewayUnavailable(GatewayErrorCodeBindingUnavailable, "the call could not be bound to its run, so it is not sent: %s", err)
	}
	prepared.binding = binding
	runId, agentId := binding.RunId, caller.Grant.AgentId
	inferRequest.RunId, inferRequest.AgentId = &runId, &agentId
	inferRequest.Binding = binding.InferBinding()
	inferRequest.Budget = &InferBudgetRef{Kind: InferBudgetGrant, Id: caller.Grant.GrantId}
	if err := router.Check(ctx, inferRequest); err != nil {
		return nil, gatewayErrorOfInfer(ctx, inferErrorOf(err), caller.Network, self.clock.Now())
	}
	keep = true
	return prepared, nil
}

// A grant with a model list admits only the canonical names its globs match (§16.4): the name the request's model
// resolves to in the router's catalog, or the name as asked where it resolves to none, which the router refuses.
func (self *GatewayFronts) checkGrantModel(ctx context.Context, grant *GatewayGrant, router InferRouter, request *InferRequest) *gatewayError {
	if len(grant.Models) == 0 {
		return nil
	}
	name := request.Model
	if catalog, err := router.Catalog(ctx); err == nil {
		if resolution, err := catalog.Resolve(request.Model, request.Reasoning); err == nil {
			name = resolution.Name
		}
	}
	if grant.AllowsModel(name) {
		return nil
	}
	return &gatewayError{
		Status:       http.StatusForbidden,
		Type:         gatewayErrorTypeInvalidRequest,
		Code:         GatewayErrorCodeModelNotInGrant,
		Param:        "model",
		MessagesType: gatewayErrorTypePermission,
		Message: fmt.Sprintf("%s is not among the models this harness's grant allows; ur install-harness %s --gateway sets them",
			name, grant.Harness),
	}
}

// The answer to a prepared call: a call in flight or kept that the request repeats, joined after the router's check,
// or a new call (gateway_retry.go's table decides). call is the table's entry the caller follows, nil where none is
// kept. A refusal is answered whole.
func (self *GatewayFronts) answer(ctx context.Context, prepared *gatewayPreparedCall) (*gatewayAnswer, *gatewayCallEntry, *gatewayError) {
	entry, joined, refusal := self.lookup(ctx, prepared)
	if refusal != nil {
		return nil, nil, refusal
	}
	if joined {
		// the same operation: nothing new is recorded or charged
		clear(prepared.key)
		return entry.answer, entry, nil
	}
	answer, refusal := self.dispatch(ctx, prepared, entry)
	if refusal != nil {
		self.forget(entry)
		return nil, nil, refusal
	}
	return answer, entry, nil
}

// Records and dispatches a new call, and starts its run: the answer its callers follow. entry is the table's, nil
// where the call is not kept.
func (self *GatewayFronts) dispatch(ctx context.Context, prepared *gatewayPreparedCall, entry *gatewayCallEntry) (*gatewayAnswer, *gatewayError) {
	recorder := self.currentRecorder()
	if recorder == nil {
		return nil, gatewayUnavailable(GatewayErrorCodeRecordUnavailable, "the gateway records each call before it goes upstream, and it cannot record now (IC-19)")
	}
	responseId, err := self.newId(prepared.front.responseIdPrefix())
	if err != nil {
		return nil, gatewayUnavailable(GatewayErrorCodeRouterUnavailable, "no id could be drawn")
	}
	caller := prepared.caller
	record, err := recorder.Begin(ctx, &GatewayRecordBegin{
		NetworkId:  caller.NetworkId,
		Network:    caller.Network,
		Harness:    caller.Grant.Harness,
		Binding:    prepared.binding,
		Api:        prepared.front.api(),
		Renderer:   prepared.front.renderer(),
		Body:       prepared.routed,
		ResponseId: responseId,
		Model:      prepared.request.Model,
	})
	if err != nil {
		return nil, gatewayUnavailable(GatewayErrorCodeRecordUnavailable, "the call's context could not be recorded, so it is not sent (IC-19)")
	}
	// a call a run handle binds may be joined by its retry, so it runs on when its caller leaves (§8.5)
	base := ctx
	if prepared.binding.Handle != "" {
		base = self.ctx
	}
	callCtx, cancelCall := context.WithCancel(base)
	events, err := prepared.router.Infer(callCtx, prepared.request)
	if err != nil {
		cancelCall()
		inferError := inferErrorOf(err)
		record.End(ctx, &GatewayRecordEnd{Outcome: GatewayRecordFailed, Error: inferError})
		return nil, gatewayErrorOfInfer(ctx, inferError, caller.Network, self.clock.Now())
	}
	run := &gatewayCallRun{
		fronts:     self,
		prepared:   prepared,
		record:     record,
		responseId: responseId,
		createdAt:  self.clock.Now(),
		ctx:        callCtx,
		cancel:     cancelCall,
	}
	if entry != nil {
		run.answer = entry.answer
		run.entry = entry
	} else {
		run.answer = newGatewayAnswer()
	}
	producer := prepared.front.newProducer(run)
	self.countRunning(1)
	go func() {
		defer self.countRunning(-1)
		run.run(events, producer)
	}()
	return run.answer, nil
}

// One call's run: the router's stream through its front's producer onto its answer.
type gatewayCallRun struct {
	fronts     *GatewayFronts
	prepared   *gatewayPreparedCall
	record     GatewayRecordCall
	answer     *gatewayAnswer
	entry      *gatewayCallEntry
	responseId string
	createdAt  time.Time
	ctx        context.Context
	cancel     context.CancelFunc
}

// Reads events to the terminal (see the file header's dispatch row). A stream's head is decided at the first event,
// or once FirstEventWait passes, so a failure that is the first event is answered in the API's HTTP status.
func (self *gatewayCallRun) run(events <-chan *InferEvent, producer gatewayProducer) {
	defer self.cancel()
	defer clear(self.prepared.key)
	settings := self.fronts.settings
	stream := self.prepared.options.Stream
	var firstWait <-chan time.Time
	if stream {
		if 0 < settings.FirstEventWait {
			firstWait = self.fronts.clock.After(settings.FirstEventWait)
		} else {
			self.open(producer)
		}
	}
	for {
		select {
		case <-firstWait:
			firstWait = nil
			self.open(producer)
		case event, ok := <-events:
			if !ok {
				self.fail(producer, newInferError(InferErrorEngineFailed, "the model's stream ended without its last event"))
				return
			}
			switch event.Kind {
			case InferEventError:
				self.fail(producer, event.Error)
				return
			case InferEventEnd:
				frames, err := producer.complete(self.ctx)
				if err != nil {
					self.failRecording(producer, err)
					return
				}
				self.end(producer, GatewayRecordCompleted, nil)
				if !self.answer.isHeaded() {
					self.answer.head(http.StatusOK, self.contentType(), "")
				}
				self.keep(frames)
				self.answer.end()
				if self.entry != nil {
					self.fronts.kept(self.entry)
				}
				return
			}
			if stream {
				self.open(producer)
			}
			frames, err := producer.event(self.ctx, event)
			if err != nil {
				self.failRecording(producer, err)
				return
			}
			self.keep(frames)
		}
	}
}

// The content type of a whole answer, or a stream's.
func (self *gatewayCallRun) contentType() string {
	if self.prepared.options.Stream {
		return gatewayContentTypeEventStream
	}
	return gatewayContentTypeJson
}

// Opens the stream, once: its head and its opening frames.
func (self *gatewayCallRun) open(producer gatewayProducer) {
	if self.answer.isHeaded() {
		return
	}
	self.answer.head(http.StatusOK, gatewayContentTypeEventStream, "")
	self.keep(producer.open())
}

// Appends frames to the answer, which the table keeps while they fit (gateway_retry.go).
func (self *gatewayCallRun) keep(frames [][]byte) {
	if len(frames) == 0 {
		return
	}
	self.answer.append(frames...)
	if self.entry != nil {
		self.fronts.kept(self.entry)
	}
}

// Ends the call's record: its model_call's outcome and usage.
func (self *gatewayCallRun) end(producer gatewayProducer, outcome GatewayRecordOutcome, failure *InferError) {
	usage, attestations := producer.usage()
	err := self.record.End(self.ctx, &GatewayRecordEnd{Outcome: outcome, Usage: usage, Attestations: attestations, Error: failure})
	if err != nil {
		self.fronts.log.Warningf("[gateway]a call's model_call was not written: %s", err)
	}
}

// The call failed: before its stream's head, its API's error answered whole; after, the stream's terminal frame.
func (self *gatewayCallRun) fail(producer gatewayProducer, failure *InferError) {
	if failure == nil {
		failure = newInferError(InferErrorEngineFailed, "the model failed")
	}
	self.end(producer, GatewayRecordFailed, failure)
	refusal := gatewayErrorOfInfer(self.ctx, failure, self.prepared.caller.Network, self.fronts.clock.Now())
	self.finishFailed(producer, refusal)
}

// A response item could not be journaled: the call ends before the item is sent (IC-19).
func (self *gatewayCallRun) failRecording(producer gatewayProducer, err error) {
	self.cancel()
	failure := newInferError(InferErrorEngineFailed, "the answer could not be recorded, so it was ended (IC-19)")
	self.end(producer, GatewayRecordFailed, failure)
	if self.fronts.log.V(1).Enabled() {
		self.fronts.log.Infof("[gateway]a response item was not recorded: %s", err)
	}
	self.finishFailed(producer, gatewayUnavailable(GatewayErrorCodeRecordUnavailable, "%s", failure.Message))
}

// Answers refusal: whole where the head is not decided, else the stream's terminal frame.
func (self *gatewayCallRun) finishFailed(producer gatewayProducer, refusal *gatewayError) {
	if !self.answer.isHeaded() {
		retryAfter := ""
		if 0 < refusal.RetryAfter {
			retryAfter = strconv.FormatInt(int64((refusal.RetryAfter+time.Second-1)/time.Second), 10)
		}
		self.answer.head(refusal.Status, gatewayContentTypeJson, retryAfter)
		self.answer.append(refusal.body(self.prepared.front.api()))
	} else {
		self.keep(producer.fail(refusal, producer.began()))
	}
	self.answer.end()
	if self.entry != nil {
		self.fronts.kept(self.entry)
	}
}

// An ordered JSON object, so an answer's members read in the APIs' own order.
type gatewayJsonObject []gatewayJsonMember

// One member of a gatewayJsonObject.
type gatewayJsonMember struct {
	Key   string
	Value any
}

// See json.Marshaler.
func (self gatewayJsonObject) MarshalJSON() ([]byte, error) {
	buffer := &bytes.Buffer{}
	buffer.WriteByte('{')
	for i, member := range self {
		if 0 < i {
			buffer.WriteByte(',')
		}
		key, err := json.Marshal(member.Key)
		if err != nil {
			return nil, err
		}
		buffer.Write(key)
		buffer.WriteByte(':')
		value, err := gatewayMarshal(member.Value)
		if err != nil {
			return nil, err
		}
		buffer.Write(value)
	}
	buffer.WriteByte('}')
	return buffer.Bytes(), nil
}

// The Responses front (see the file header).
type gatewayResponsesFront struct{}

// See gatewayFront.
func (gatewayResponsesFront) api() SessionGatewayApi {
	return SessionGatewayApiResponses
}

// See gatewayFront.
func (gatewayResponsesFront) renderer() string {
	return GatewayRendererResponses
}

// See gatewayFront.
func (gatewayResponsesFront) responseIdPrefix() string {
	return gatewayResponseIdPrefix
}

// See gatewayFront: SRCH's filter for Responses.
func (gatewayResponsesFront) filter(hostedSearch *GatewayHostedSearch, harness string, body []byte) ([]byte, error) {
	return hostedSearch.FilterResponses(harness, body)
}

// See gatewayFront.
func (gatewayResponsesFront) route(settings *GatewaySettings, body []byte, key []byte) ([]byte, *gatewayError) {
	return gatewayRouteResponses(settings, body, key)
}

// See gatewayFront.
func (gatewayResponsesFront) translate(body []byte) (*InferRequest, *gatewayRequestOptions, *gatewayError) {
	return gatewayTranslateResponses(body)
}

// See gatewayFront: a `: ping` comment.
func (gatewayResponsesFront) keepaliveFrame() []byte {
	return []byte(gatewaySseKeepaliveComment)
}

// See gatewayFront.
func (gatewayResponsesFront) newProducer(run *gatewayCallRun) gatewayProducer {
	return &gatewayResponsesProducer{run: run, toolItems: map[string]*gatewayResponsesItemState{}}
}

// One output item while it streams.
type gatewayResponsesItemState struct {
	id          string
	outputIndex int
	itemType    string
	// a message's text or a reasoning item's summary, as it streamed
	text bytes.Buffer
	// a function call's
	callId    string
	name      string
	arguments bytes.Buffer
}

// The Responses front's producer: §8.5's Responses column.
type gatewayResponsesProducer struct {
	run            *gatewayCallRun
	sequenceNumber int
	nextIndex      int
	// the completed items, in order, as the terminal's output carries them
	output    []any
	reasoning *gatewayResponsesItemState
	message   *gatewayResponsesItemState
	toolItems map[string]*gatewayResponsesItemState
	toolOrder []string
	used      *InferUsage
	attested  []*protocol.AttestationResult
	begun     bool
}

// One event's frame, its sequence number the next.
func (self *gatewayResponsesProducer) frame(eventType string, members ...gatewayJsonMember) []byte {
	object := gatewayJsonObject{{Key: "type", Value: eventType}, {Key: "sequence_number", Value: self.sequenceNumber}}
	object = append(object, members...)
	self.sequenceNumber++
	encoded, _ := object.MarshalJSON()
	return gatewaySseEvent(eventType, encoded)
}

// The response object with status, its output so far, its usage and its error.
func (self *gatewayResponsesProducer) response(status string, output []any, usage any, failure any) gatewayJsonObject {
	run := self.run
	if output == nil {
		output = []any{}
	}
	return gatewayJsonObject{
		{Key: "id", Value: run.responseId},
		{Key: "object", Value: gatewayResponsesObject},
		{Key: "created_at", Value: run.createdAt.Unix()},
		{Key: "status", Value: status},
		{Key: "error", Value: failure},
		{Key: "incomplete_details", Value: nil},
		{Key: "model", Value: run.prepared.request.Model},
		{Key: "output", Value: output},
		{Key: "parallel_tool_calls", Value: true},
		{Key: "previous_response_id", Value: nil},
		{Key: "store", Value: false},
		{Key: "usage", Value: usage},
	}
}

// The usage object: integers alone, zeros where the router gave none (Codex reads them as integers).
func (self *gatewayResponsesProducer) usageObject() gatewayJsonObject {
	usage := self.used
	if usage == nil {
		usage = &InferUsage{}
	}
	return gatewayJsonObject{
		{Key: "input_tokens", Value: usage.InputTokens},
		{Key: "input_tokens_details", Value: gatewayJsonObject{{Key: "cached_tokens", Value: usage.CachedTokens}}},
		{Key: "output_tokens", Value: usage.OutputTokens},
		{Key: "output_tokens_details", Value: gatewayJsonObject{{Key: "reasoning_tokens", Value: usage.ReasoningTokens}}},
		{Key: "total_tokens", Value: usage.InputTokens + usage.OutputTokens},
	}
}

// See gatewayProducer.
func (self *gatewayResponsesProducer) open() [][]byte {
	return [][]byte{
		self.frame("response.created", gatewayJsonMember{Key: "response", Value: self.response(gatewayResponsesStatusInProgress, nil, nil, nil)}),
		self.frame("response.in_progress", gatewayJsonMember{Key: "response", Value: self.response(gatewayResponsesStatusInProgress, nil, nil, nil)}),
	}
}

// See gatewayProducer.
func (self *gatewayResponsesProducer) began() bool {
	return self.begun
}

// See gatewayProducer.
func (self *gatewayResponsesProducer) usage() (*InferUsage, []*protocol.AttestationResult) {
	return self.used, self.attested
}

// Whether the answer streams: a whole answer has no frames until its end.
func (self *gatewayResponsesProducer) streaming() bool {
	return self.run.prepared.options.Stream
}

// A new output item of itemType, its id drawn and its index the next.
func (self *gatewayResponsesProducer) newItem(itemType string, prefix string) (*gatewayResponsesItemState, error) {
	id, err := self.run.fronts.newId(prefix)
	if err != nil {
		return nil, err
	}
	item := &gatewayResponsesItemState{id: id, outputIndex: self.nextIndex, itemType: itemType}
	self.nextIndex++
	return item, nil
}

// See gatewayProducer.
func (self *gatewayResponsesProducer) event(ctx context.Context, event *InferEvent) ([][]byte, error) {
	frames := [][]byte{}
	switch event.Kind {
	case InferEventReasoning:
		self.begun = true
		closed, err := self.closeMessage(ctx)
		if err != nil {
			return nil, err
		}
		frames = append(frames, closed...)
		if self.reasoning == nil {
			item, err := self.newItem(gatewayItemTypeReasoning, gatewayReasoningIdPrefix)
			if err != nil {
				return nil, err
			}
			self.reasoning = item
			frames = append(frames,
				self.frame("response.output_item.added",
					gatewayJsonMember{Key: "output_index", Value: item.outputIndex},
					gatewayJsonMember{Key: "item", Value: gatewayJsonObject{
						{Key: "id", Value: item.id}, {Key: "type", Value: gatewayItemTypeReasoning},
						{Key: "status", Value: gatewayResponsesStatusInProgress}, {Key: "summary", Value: []any{}},
					}}),
				self.frame("response.reasoning_summary_part.added",
					gatewayJsonMember{Key: "item_id", Value: item.id},
					gatewayJsonMember{Key: "output_index", Value: item.outputIndex},
					gatewayJsonMember{Key: "summary_index", Value: 0},
					gatewayJsonMember{Key: "part", Value: gatewayJsonObject{{Key: "type", Value: gatewayPartTypeSummaryText}, {Key: "text", Value: ""}}}),
			)
		}
		self.reasoning.text.WriteString(event.Text)
		frames = append(frames, self.frame("response.reasoning_summary_text.delta",
			gatewayJsonMember{Key: "item_id", Value: self.reasoning.id},
			gatewayJsonMember{Key: "output_index", Value: self.reasoning.outputIndex},
			gatewayJsonMember{Key: "summary_index", Value: 0},
			gatewayJsonMember{Key: "delta", Value: event.Text}))
	case InferEventText:
		self.begun = true
		closed, err := self.closeReasoning(ctx)
		if err != nil {
			return nil, err
		}
		frames = append(frames, closed...)
		if self.message == nil {
			item, err := self.newItem(gatewayItemTypeMessage, gatewayMessageItemIdPrefix)
			if err != nil {
				return nil, err
			}
			self.message = item
			frames = append(frames,
				self.frame("response.output_item.added",
					gatewayJsonMember{Key: "output_index", Value: item.outputIndex},
					gatewayJsonMember{Key: "item", Value: gatewayJsonObject{
						{Key: "id", Value: item.id}, {Key: "type", Value: gatewayItemTypeMessage},
						{Key: "status", Value: gatewayResponsesStatusInProgress}, {Key: "role", Value: gatewayRoleAssistant},
						{Key: "content", Value: []any{}},
					}}),
				self.frame("response.content_part.added",
					gatewayJsonMember{Key: "item_id", Value: item.id},
					gatewayJsonMember{Key: "output_index", Value: item.outputIndex},
					gatewayJsonMember{Key: "content_index", Value: 0},
					gatewayJsonMember{Key: "part", Value: gatewayResponsesTextPart("")}),
			)
		}
		self.message.text.WriteString(event.Text)
		frames = append(frames, self.frame("response.output_text.delta",
			gatewayJsonMember{Key: "item_id", Value: self.message.id},
			gatewayJsonMember{Key: "output_index", Value: self.message.outputIndex},
			gatewayJsonMember{Key: "content_index", Value: 0},
			gatewayJsonMember{Key: "delta", Value: event.Text},
			gatewayJsonMember{Key: "logprobs", Value: []any{}}))
	case InferEventToolCallStart:
		self.begun = true
		closed, err := self.closeOpen(ctx)
		if err != nil {
			return nil, err
		}
		frames = append(frames, closed...)
		if _, open := self.toolItems[event.ToolCall.Id]; open {
			break
		}
		item, err := self.newItem(gatewayItemTypeFunctionCall, gatewayFunctionCallIdPrefix)
		if err != nil {
			return nil, err
		}
		item.callId, item.name = event.ToolCall.Id, event.ToolCall.Name
		self.toolItems[item.callId] = item
		self.toolOrder = append(self.toolOrder, item.callId)
		frames = append(frames, self.frame("response.output_item.added",
			gatewayJsonMember{Key: "output_index", Value: item.outputIndex},
			gatewayJsonMember{Key: "item", Value: gatewayJsonObject{
				{Key: "id", Value: item.id}, {Key: "type", Value: gatewayItemTypeFunctionCall},
				{Key: "status", Value: gatewayResponsesStatusInProgress}, {Key: "call_id", Value: item.callId},
				{Key: "name", Value: item.name}, {Key: "arguments", Value: ""},
			}}))
	case InferEventToolCallArgs:
		item, open := self.toolItems[event.ToolCall.Id]
		if !open {
			// arguments of a call that never started are no item's
			break
		}
		item.arguments.WriteString(event.ToolCall.Arguments)
		frames = append(frames, self.frame("response.function_call_arguments.delta",
			gatewayJsonMember{Key: "item_id", Value: item.id},
			gatewayJsonMember{Key: "output_index", Value: item.outputIndex},
			gatewayJsonMember{Key: "delta", Value: event.ToolCall.Arguments}))
	case InferEventToolCallEnd:
		item, open := self.toolItems[event.ToolCall.Id]
		if !open {
			break
		}
		if event.ToolCall.Name != "" {
			item.name = event.ToolCall.Name
		}
		// the end's arguments are whole, whatever the deltas carried
		item.arguments.Reset()
		item.arguments.WriteString(event.ToolCall.Arguments)
		done, err := self.closeTool(ctx, item)
		if err != nil {
			return nil, err
		}
		frames = append(frames, done...)
	case InferEventUsage:
		usage := *event.Usage
		self.used = &usage
	case InferEventAttestation:
		self.attested = append(self.attested, event.Attest)
	}
	if !self.streaming() {
		// a whole answer keeps its items and sends nothing until its end
		return nil, nil
	}
	return frames, nil
}

// An output_text part.
func gatewayResponsesTextPart(text string) gatewayJsonObject {
	return gatewayJsonObject{
		{Key: "type", Value: gatewayPartTypeOutputText}, {Key: "text", Value: text},
		{Key: "annotations", Value: []any{}}, {Key: "logprobs", Value: []any{}},
	}
}

// Records item, whole, before the frame that completes it is sent (IC-19): its node.
func (self *gatewayResponsesProducer) recordItem(ctx context.Context, item gatewayJsonObject) (Id, error) {
	encoded, err := item.MarshalJSON()
	if err != nil {
		return Id{}, err
	}
	return self.run.record.ResponseItem(ctx, encoded)
}

// Completes the open reasoning item: its done events, recorded, its blob sealed naming its node where the request
// asked for it.
func (self *gatewayResponsesProducer) closeReasoning(ctx context.Context) ([][]byte, error) {
	item := self.reasoning
	if item == nil {
		return nil, nil
	}
	self.reasoning = nil
	text := item.text.String()
	summary := []any{gatewayJsonObject{{Key: "type", Value: gatewayPartTypeSummaryText}, {Key: "text", Value: text}}}
	done := gatewayJsonObject{
		{Key: "id", Value: item.id}, {Key: "type", Value: gatewayItemTypeReasoning},
		{Key: "status", Value: gatewayResponsesStatusCompleted}, {Key: "summary", Value: summary},
	}
	nodeId, err := self.recordItem(ctx, done)
	if err != nil {
		return nil, err
	}
	run := self.run
	if run.prepared.options.IncludeReasoningBlob && run.prepared.key != nil {
		blob, err := (&GatewayReasoningBlob{NodeId: nodeId, Text: text}).Seal(run.prepared.key, run.fronts.random)
		if err != nil {
			return nil, err
		}
		done = append(done, gatewayJsonMember{Key: "encrypted_content", Value: blob})
	}
	self.output = append(self.output, done)
	return [][]byte{
		self.frame("response.reasoning_summary_text.done",
			gatewayJsonMember{Key: "item_id", Value: item.id},
			gatewayJsonMember{Key: "output_index", Value: item.outputIndex},
			gatewayJsonMember{Key: "summary_index", Value: 0},
			gatewayJsonMember{Key: "text", Value: text}),
		self.frame("response.reasoning_summary_part.done",
			gatewayJsonMember{Key: "item_id", Value: item.id},
			gatewayJsonMember{Key: "output_index", Value: item.outputIndex},
			gatewayJsonMember{Key: "summary_index", Value: 0},
			gatewayJsonMember{Key: "part", Value: gatewayJsonObject{{Key: "type", Value: gatewayPartTypeSummaryText}, {Key: "text", Value: text}}}),
		self.frame("response.output_item.done",
			gatewayJsonMember{Key: "output_index", Value: item.outputIndex},
			gatewayJsonMember{Key: "item", Value: done}),
	}, nil
}

// Completes the open message item: its done events, recorded.
func (self *gatewayResponsesProducer) closeMessage(ctx context.Context) ([][]byte, error) {
	item := self.message
	if item == nil {
		return nil, nil
	}
	self.message = nil
	text := item.text.String()
	done := gatewayJsonObject{
		{Key: "id", Value: item.id}, {Key: "type", Value: gatewayItemTypeMessage},
		{Key: "status", Value: gatewayResponsesStatusCompleted}, {Key: "role", Value: gatewayRoleAssistant},
		{Key: "content", Value: []any{gatewayResponsesTextPart(text)}},
	}
	if _, err := self.recordItem(ctx, done); err != nil {
		return nil, err
	}
	self.output = append(self.output, done)
	return [][]byte{
		self.frame("response.output_text.done",
			gatewayJsonMember{Key: "item_id", Value: item.id},
			gatewayJsonMember{Key: "output_index", Value: item.outputIndex},
			gatewayJsonMember{Key: "content_index", Value: 0},
			gatewayJsonMember{Key: "text", Value: text},
			gatewayJsonMember{Key: "logprobs", Value: []any{}}),
		self.frame("response.content_part.done",
			gatewayJsonMember{Key: "item_id", Value: item.id},
			gatewayJsonMember{Key: "output_index", Value: item.outputIndex},
			gatewayJsonMember{Key: "content_index", Value: 0},
			gatewayJsonMember{Key: "part", Value: gatewayResponsesTextPart(text)}),
		self.frame("response.output_item.done",
			gatewayJsonMember{Key: "output_index", Value: item.outputIndex},
			gatewayJsonMember{Key: "item", Value: done}),
	}, nil
}

// Completes a function call item: its arguments' done and its item's, recorded.
func (self *gatewayResponsesProducer) closeTool(ctx context.Context, item *gatewayResponsesItemState) ([][]byte, error) {
	delete(self.toolItems, item.callId)
	arguments := item.arguments.String()
	done := gatewayJsonObject{
		{Key: "id", Value: item.id}, {Key: "type", Value: gatewayItemTypeFunctionCall},
		{Key: "status", Value: gatewayResponsesStatusCompleted}, {Key: "call_id", Value: item.callId},
		{Key: "name", Value: item.name}, {Key: "arguments", Value: arguments},
	}
	if _, err := self.recordItem(ctx, done); err != nil {
		return nil, err
	}
	self.output = append(self.output, done)
	return [][]byte{
		self.frame("response.function_call_arguments.done",
			gatewayJsonMember{Key: "item_id", Value: item.id},
			gatewayJsonMember{Key: "output_index", Value: item.outputIndex},
			gatewayJsonMember{Key: "arguments", Value: arguments}),
		self.frame("response.output_item.done",
			gatewayJsonMember{Key: "output_index", Value: item.outputIndex},
			gatewayJsonMember{Key: "item", Value: done}),
	}, nil
}

// Completes the open reasoning and message items, in that order.
func (self *gatewayResponsesProducer) closeOpen(ctx context.Context) ([][]byte, error) {
	reasoning, err := self.closeReasoning(ctx)
	if err != nil {
		return nil, err
	}
	message, err := self.closeMessage(ctx)
	if err != nil {
		return nil, err
	}
	return append(reasoning, message...), nil
}

// See gatewayProducer: every item still open completed, in the order they opened, then response.completed; or, for a
// whole answer, the response object alone.
func (self *gatewayResponsesProducer) complete(ctx context.Context) ([][]byte, error) {
	frames, err := self.closeOpen(ctx)
	if err != nil {
		return nil, err
	}
	for _, callId := range self.toolOrder {
		item, open := self.toolItems[callId]
		if !open {
			continue
		}
		done, err := self.closeTool(ctx, item)
		if err != nil {
			return nil, err
		}
		frames = append(frames, done...)
	}
	response := self.response(gatewayResponsesStatusCompleted, self.output, self.usageObject(), nil)
	if !self.streaming() {
		encoded, err := response.MarshalJSON()
		if err != nil {
			return nil, err
		}
		return [][]byte{encoded}, nil
	}
	return append(frames, self.frame("response.completed", gatewayJsonMember{Key: "response", Value: response})), nil
}

// See gatewayProducer: response.failed, its output the items completed, its error's code one Codex does not retry once
// the model's output began.
func (self *gatewayResponsesProducer) fail(failure *gatewayError, began bool) [][]byte {
	errorObject := gatewayJsonObject{{Key: "code", Value: failure.streamCode(began)}, {Key: "message", Value: failure.Message}}
	response := self.response(gatewayResponsesStatusFailed, self.output, self.usageObject(), errorObject)
	return [][]byte{self.frame("response.failed", gatewayJsonMember{Key: "response", Value: response})}
}
