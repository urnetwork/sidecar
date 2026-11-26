//go:build !ios_extension && !sidecar_http

// The router (DESIGN-COMPUTE §6.4, R-INFER-3, R-INFER-4, D-INFER-1, CF-1, CF-3): the one way the Harness and the gateway
// reach a model, local or remote, through Sidecar.InferRouter, so both see one catalog and one set of checks. A call:
//
//  1. resolves its name against the catalog (§6.3): a full name runs at its own effort, never one the model does not
//     list, and an alias at the request's effort mapped to the nearest the model lists, else the model's default
//     (Q-INFER-5);
//  2. passes the checks before a route is chosen (infer_check.go), the same Check runs without dispatching for the
//     gateway before a retry joins or replays another call (§8.5) and for the Harness's agent_launch and SetModel;
//  3. dispatches by its entry's kind: local to the InferLocalEngine set on the Sidecar (INFER-M11-04's helper process on
//     a desktop, an app's host on a phone, INFER-M11-06), tee and direct to the InferRemotePath registered for the kind
//     (infer_remote.go), a kind with none answering model_refused naming it.
//
// It never changes the model, its provider or its label, on any error (R-INFER-3, Q-INFER-1): a local model that fails
// or lacks the memory answers its error, and the Harness offers the person the switch (§7.4). Its own files never name a
// path or a provider, so the remote paths only register.
//
// A refusal before dispatch is Infer's error, an *InferError, and nothing has been sent. A dispatched call is one stream:
// the engine's or path's events as they come, each holding only its kind's fields (inferEventEmitted), a start before
// any other, then exactly one end or error, after which the channel closes. A cancelled context answers canceled at
// once, whatever the engine has not yet said. A reader slower than the engine never blocks it: past the channel's buffer
// (InferSettings.EventBufferCount) the router holds the events, folding text, reasoning and argument deltas, and stops a
// call whose reader falls more than InferSettings.EventPendingMaxByteCount behind, answering canceled.
//
// The router is safe for concurrent use: its local engine and the local view built for it sit under stateLock, and the
// rest is fixed when it is built.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// The router's surface (§6.4, D-INFER-1), the same for the Harness and the gateway.
type InferRouter interface {
	// The catalog this device sees (§6.3): every local and remote model and search endpoint, each the checks refuse
	// listed unavailable with why. Errs only with ctx.
	Catalog(ctx context.Context) (*InferCatalog, error)
	// Resolves, checks and dispatches request. A refusal is an *InferError and sends nothing; otherwise the call's one
	// stream, which its reader reads until it closes after the end or error event, or abandons by ending ctx.
	Infer(ctx context.Context, request *InferRequest) (<-chan *InferEvent, error)
	// Resolves and checks request as Infer would, dispatching nothing: nil where Infer would dispatch it now, else the
	// *InferError Infer would answer.
	Check(ctx context.Context, request *InferRequest) error
}

// The local engine (§6.5): ur-engine's process client on a desktop (INFER-M11-04), an app's host on a phone
// (INFER-M11-06). Its methods are safe for concurrent use.
type InferLocalEngine interface {
	// What this device can run a local model on, which judges the local catalog.
	Capabilities(ctx context.Context) (*InferDeviceCapabilities, error)
	// Runs one local call: emits start once the call has the engine, waiting its turn where another holds it (§6.5),
	// then its events, and returns nil at its end, or why it failed, an *InferError where it can say which, a crash or
	// a hostile model file answering engine_failed. Returns promptly once ctx ends.
	Generate(ctx context.Context, call *InferCall, emit InferEmit) error
}

// The checks every call passes before a route is chosen (infer_check.go). Safe for concurrent use.
type inferChecker interface {
	// Nil where call may be dispatched now; else an *InferError, nothing having left the device. Sets call.Policy to
	// the policy a remote call's checks read.
	check(ctx context.Context, call *InferCall) error
	// The catalog, each entry the checks would refuse whatever the call listed unavailable with why (§6.3).
	limit(ctx context.Context, catalog *InferCatalog) *InferCatalog
}

// What newInferRouter builds on.
type inferRouterArgs struct {
	// Required.
	Settings *InferSettings
	// Nil logs nothing.
	Log Logger
	// The release manifest, nil to read this build's; ManifestErr says why the build's did not read.
	Manifest    *InferManifest
	ManifestErr error
	// The remote paths built for this router; nil has none.
	RemotePaths *inferRemotePaths
	// The remote catalog, nil for none; RemoteCatalogErr says why the registered one did not construct.
	RemoteCatalog    InferRemoteCatalog
	RemoteCatalogErr error
	// Required: the checks.
	Checker inferChecker
	// Nil for real time: the background's grants run on it (infer_background.go).
	Clock Clock
}

// §6.4's router.
type inferRouter struct {
	settings         *InferSettings
	log              Logger
	manifest         *InferManifest
	manifestErr      error
	remotePaths      *inferRemotePaths
	remoteCatalog    InferRemoteCatalog
	remoteCatalogErr error
	checker          inferChecker

	// the app's lifecycle: calls in flight, and whether the app is in the background (infer_background.go)
	background *inferBackground

	stateLock   sync.Mutex
	localEngine InferLocalEngine
	// the local view judged for localEngine's device, built at first need and kept until the engine changes
	localView *InferCatalog
}

// A router over args.
func newInferRouter(args *inferRouterArgs) (*inferRouter, error) {
	if args == nil || args.Settings == nil || args.Checker == nil {
		return nil, errors.New("inference router: settings and checks")
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	remotePaths := args.RemotePaths
	if remotePaths == nil {
		remotePaths = newInferRemotePaths(nil, args.Settings, nil)
	}
	manifest, manifestErr := args.Manifest, args.ManifestErr
	if manifest == nil && manifestErr == nil {
		manifest, manifestErr = InferReleaseManifest(args.Settings)
	}
	return &inferRouter{
		settings:         args.Settings,
		log:              log,
		manifest:         manifest,
		manifestErr:      manifestErr,
		remotePaths:      remotePaths,
		remoteCatalog:    args.RemoteCatalog,
		remoteCatalogErr: args.RemoteCatalogErr,
		checker:          args.Checker,
		background:       newInferBackground(args.Settings, args.Clock),
	}, nil
}

// Sets the local engine every later local call runs on, nil for none, and drops the local view judged for the last.
// The caller keeps the engine: the router never closes it.
func (self *inferRouter) setLocalEngine(engine InferLocalEngine) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.localEngine = engine
	self.localView = nil
}

// The local engine, or nil.
func (self *inferRouter) engine() InferLocalEngine {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.localEngine
}

// A catalog of no entry, saying why it lists no local one.
func (self *inferRouter) emptyCatalog(localUnavailable string) *InferCatalog {
	// with no entry nothing can fail
	catalog, _ := newInferCatalog(nil, nil, localUnavailable, self.settings)
	return catalog
}

// The local view (§6.3, §6.5): the release manifest's models judged for the local engine's device, built once for an
// engine and kept; with no engine, no manifest or no capabilities, a catalog of no local entry saying why.
func (self *inferRouter) local(ctx context.Context) *InferCatalog {
	engine, view := func() (InferLocalEngine, *InferCatalog) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.localEngine, self.localView
	}()
	if view != nil {
		return view
	}
	switch {
	case self.manifestErr != nil:
		return self.emptyCatalog("this build's release manifest does not read: " + self.manifestErr.Error())
	case engine == nil:
		return self.emptyCatalog("no local engine runs on this host")
	}
	capabilities, err := engine.Capabilities(ctx)
	if err != nil {
		// not kept: a later call asks again
		return self.emptyCatalog("the local engine does not say what this device can run: " + err.Error())
	}
	view, err = NewInferLocalCatalog(self.manifest, capabilities, self.settings)
	if err != nil {
		return self.emptyCatalog("the local view does not build: " + err.Error())
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		// kept only for the engine it was judged for
		if self.localEngine == engine {
			self.localView = view
		}
	}()
	return view
}

// The catalog before the checks: the local view, joined with the remote catalog's entries where there is one. A remote
// catalog that fails or is refused leaves the local view, saying why no remote entry is offered.
func (self *inferRouter) base(ctx context.Context) *InferCatalog {
	local := self.local(ctx)
	switch {
	case self.remoteCatalogErr != nil:
		return inferCatalogWithRemoteUnavailable(local, "the remote catalog did not construct here: "+self.remoteCatalogErr.Error())
	case self.remoteCatalog == nil:
		return local
	}
	entries, err := self.remoteCatalog.Entries(ctx)
	if err != nil {
		return inferCatalogWithRemoteUnavailable(local, "the remote catalog does not read: "+err.Error())
	}
	joined, err := local.Join(entries)
	if err != nil {
		return inferCatalogWithRemoteUnavailable(local, "the remote catalog was refused: "+err.Error())
	}
	return joined
}

// catalog, its entries shared, saying why it offers no remote entry.
func inferCatalogWithRemoteUnavailable(catalog *InferCatalog, reason string) *InferCatalog {
	derived := catalog.derive(func(entry *InferCatalogEntry) *InferCatalogEntry {
		return entry
	})
	derived.remoteUnavailable = reason
	return derived
}

// See InferRouter.
func (self *inferRouter) Catalog(ctx context.Context) (*InferCatalog, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return self.checker.limit(ctx, self.base(ctx)), nil
}

// See InferRouter.
func (self *inferRouter) Check(ctx context.Context, request *InferRequest) error {
	call, err := self.prepare(ctx, request)
	if err != nil {
		return err
	}
	_, err = self.source(call)
	return err
}

// See InferRouter.
func (self *inferRouter) Infer(ctx context.Context, request *InferRequest) (<-chan *InferEvent, error) {
	call, err := self.prepare(ctx, request)
	if err != nil {
		return nil, err
	}
	source, err := self.source(call)
	if err != nil {
		return nil, err
	}
	return self.dispatch(ctx, call, source, self.onGpu(ctx, call)), nil
}

// The call request makes, resolved and checked; else the *InferError Infer answers.
func (self *inferRouter) prepare(ctx context.Context, request *InferRequest) (*InferCall, error) {
	if ctx.Err() != nil {
		return nil, newInferError(InferErrorCanceled, "the call's context ended before it was sent")
	}
	if request == nil {
		return nil, newInferError(InferErrorModelRefused, "no request")
	}
	if refused := self.background.refusal(request.Model); refused != nil {
		return nil, refused
	}
	if request.MaxOutput < 0 {
		return nil, &InferError{Code: InferErrorModelRefused, Model: request.Model, Message: "a negative maximum output"}
	}
	catalog := self.base(ctx)
	resolution, err := catalog.Resolve(request.Model, request.Reasoning)
	if err != nil {
		return nil, self.refusal(catalog, request.Model, err)
	}
	call := &InferCall{
		Request: request,
		Entry:   resolution.Entry,
		Effort:  resolution.Effort,
		Name:    resolution.Name,
	}
	if err := self.checker.check(ctx, call); err != nil {
		refused := inferErrorOf(err)
		if refused.Model == "" {
			refused.Model = call.Name
		}
		return nil, refused
	}
	return call, nil
}

// model_refused for a name the catalog does not resolve, saying why: a local name on a host that lists no local model
// says why it lists none.
func (self *inferRouter) refusal(catalog *InferCatalog, model string, err error) *InferError {
	refused := &InferError{Code: InferErrorModelRefused, Model: model, Message: err.Error()}
	if errors.Is(err, ErrInferModelNameInvalid) {
		// a name outside the grammar is not repeated
		refused.Model = ""
	}
	parsed, parseErr := InferParseModelName(model, self.settings)
	if parseErr == nil && parsed.Provider == computeLocalProvider && errors.Is(err, ErrInferModelUnknown) &&
		catalog.LocalUnavailable() != "" {
		refused.Message = "no local model here: " + catalog.LocalUnavailable()
	}
	return refused
}

// What runs call: the local engine for a local entry, the path registered for a remote one's kind; else model_refused
// naming why there is none. A search endpoint is no model, and Resolve never answers one.
func (self *inferRouter) source(call *InferCall) (func(ctx context.Context, call *InferCall, emit InferEmit) error, error) {
	refused := func(inferError *InferError) error {
		inferError.Model = call.Name
		return inferError
	}
	switch call.Entry.Kind {
	case InferCatalogKindLocal:
		engine := self.engine()
		if engine == nil {
			return nil, refused(newInferError(InferErrorModelRefused, "no local engine runs on this host"))
		}
		return engine.Generate, nil
	case InferCatalogKindTee, InferCatalogKindDirect:
		path, inferError := self.remotePaths.path(call.Entry.Kind)
		if inferError != nil {
			return nil, refused(inferError)
		}
		return path.Infer, nil
	}
	return nil, refused(newInferError(InferErrorModelRefused, "the catalog kind %s is no model's", call.Entry.Kind))
}

// Starts call on source and returns its stream: the source on its own goroutine, under a context that ends with ctx,
// with the call or when its reader falls too far behind; and the stream's relay on another, which ends once the
// terminal event is delivered.
func (self *inferRouter) dispatch(ctx context.Context, call *InferCall, source func(ctx context.Context, call *InferCall, emit InferEmit) error, gpu bool) <-chan *InferEvent {
	callCtx, cancelCall := context.WithCancel(ctx)
	stream := newInferStream(self.settings, call.Name, cancelCall)
	// tracked for the app's lifecycle until the source returns (infer_background.go)
	tracked := self.background.track(gpu, cancelCall)
	testHookBarrier("infer.dispatch.before", string(call.Entry.Kind))
	go func() {
		defer tracked()
		defer cancelCall()
		err := source(callCtx, call, stream.emit)
		stream.finish(err)
	}()
	go stream.run(ctx)
	return stream.out
}

// One call's stream (§6.4): what its engine or path emits, held until its reader takes it, then its one terminal event.
// emit and finish run on the engine's goroutines, run on its own; the fields below stateLock are its.
type inferStream struct {
	out      chan *InferEvent
	settings *InferSettings
	// the canonical name a terminal error names
	name string
	// ends the engine's or path's context
	cancelCall context.CancelFunc

	stateLock sync.Mutex
	// events not yet handed to out, in order, deltas folded
	pending []*inferPendingEvent
	// the bytes pending holds
	pendingByteCount int
	// whether a start is in pending or out already
	started bool
	// the stream's last event once decided; nil while the call runs
	terminal *InferEvent
	// closed and replaced at each change to the fields above, which run waits on
	changed chan struct{}
}

// One held event, its delta, text or arguments, in a builder, so folding many deltas copies each once.
type inferPendingEvent struct {
	event *InferEvent
	delta strings.Builder
	// what it counts toward the stream's pendingByteCount, every event folded into it included
	byteCount int
}

// The held event as it leaves: its delta in its field.
func (self *inferPendingEvent) materialize() *InferEvent {
	switch self.event.Kind {
	case InferEventText, InferEventReasoning:
		self.event.Text = self.delta.String()
	case InferEventToolCallArgs:
		self.event.ToolCall.Arguments = self.delta.String()
	}
	return self.event
}

// A held event for event, which inferEventEmitted made, so no one else holds it.
func newInferPendingEvent(event *InferEvent) *inferPendingEvent {
	pending := &inferPendingEvent{event: event, byteCount: inferEventByteCount(event)}
	switch event.Kind {
	case InferEventText, InferEventReasoning:
		pending.delta.WriteString(event.Text)
		event.Text = ""
	case InferEventToolCallArgs:
		pending.delta.WriteString(event.ToolCall.Arguments)
		event.ToolCall.Arguments = ""
	}
	return pending
}

// Folds event into this one where both are deltas of one thing, answering whether it did: text after text, reasoning
// after reasoning, one tool call's arguments after its arguments.
func (self *inferPendingEvent) fold(event *InferEvent) bool {
	if self.event.Kind != event.Kind {
		return false
	}
	switch event.Kind {
	case InferEventText, InferEventReasoning:
		self.delta.WriteString(event.Text)
		self.byteCount += len(event.Text)
		return true
	case InferEventToolCallArgs:
		if self.event.ToolCall.Id != event.ToolCall.Id {
			return false
		}
		self.delta.WriteString(event.ToolCall.Arguments)
		self.byteCount += len(event.ToolCall.Arguments)
		return true
	}
	return false
}

// A stream for one call. The channel holds EventBufferCount events, at least one, so the terminal always has a place
// once the relay has emptied it.
func newInferStream(settings *InferSettings, name string, cancelCall context.CancelFunc) *inferStream {
	return &inferStream{
		out:        make(chan *InferEvent, max(settings.EventBufferCount, 1)),
		settings:   settings,
		name:       name,
		cancelCall: cancelCall,
		changed:    make(chan struct{}),
	}
}

// Wakes run. Called with stateLock held, after a change.
func (self *inferStream) notifyWithLock() {
	close(self.changed)
	self.changed = make(chan struct{})
}

// See InferEmit: holds the event for the reader, never blocking. An event after the terminal is dropped. A reader more
// than EventPendingMaxByteCount behind ends the call, canceled, and drops what it held.
func (self *inferStream) emit(event *InferEvent) {
	event = inferEventEmitted(event)
	if event == nil {
		return
	}
	behind := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.terminal != nil {
			return false
		}
		if event.Kind == InferEventStart {
			if self.started {
				return false
			}
		} else if !self.started {
			start := newInferPendingEvent(&InferEvent{Kind: InferEventStart})
			self.pending = append(self.pending, start)
			self.pendingByteCount += start.byteCount
		}
		self.started = true
		folded := false
		if last := len(self.pending) - 1; 0 <= last {
			before := self.pending[last].byteCount
			if folded = self.pending[last].fold(event); folded {
				self.pendingByteCount += self.pending[last].byteCount - before
			}
		}
		if !folded {
			held := newInferPendingEvent(event)
			self.pending = append(self.pending, held)
			self.pendingByteCount += held.byteCount
		}
		defer self.notifyWithLock()
		if self.pendingByteCount <= self.settings.EventPendingMaxByteCount {
			return false
		}
		self.pending = nil
		self.pendingByteCount = 0
		self.terminal = &InferEvent{Kind: InferEventError, Error: &InferError{
			Code:    InferErrorCanceled,
			Model:   self.name,
			Message: fmt.Sprintf("the reader fell more than %d bytes behind the model", self.settings.EventPendingMaxByteCount),
		}}
		return true
	}()
	if behind {
		self.cancelCall()
	}
}

// The engine or path returned err: the terminal is end for nil, else err's error, unless one was decided already.
func (self *inferStream) finish(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.terminal != nil {
		return
	}
	if err == nil {
		self.terminal = &InferEvent{Kind: InferEventEnd}
	} else {
		inferError := inferErrorOf(err)
		if inferError.Model == "" {
			inferError.Model = self.name
		}
		self.terminal = &InferEvent{Kind: InferEventError, Error: inferError}
	}
	self.notifyWithLock()
}

// Hands each held event to out in order, then the terminal, then closes out. Once ctx ends, it answers canceled at
// once: what out still holds and what is held is moot to a reader that ended its context, so it is dropped to make the
// terminal's place, and the call's context ends.
func (self *inferStream) run(ctx context.Context) {
	defer close(self.out)
	for {
		if ctx.Err() != nil {
			self.endCanceled()
			return
		}
		next, terminal, changed := func() (*InferEvent, *InferEvent, chan struct{}) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if 0 < len(self.pending) {
				pending := self.pending[0]
				self.pending[0] = nil
				self.pending = self.pending[1:]
				self.pendingByteCount -= pending.byteCount
				return pending.materialize(), nil, self.changed
			}
			return nil, self.terminal, self.changed
		}()
		switch {
		case next != nil:
			select {
			case self.out <- next:
			case <-ctx.Done():
			}
		case terminal != nil:
			testHookBarrier("infer.terminal.before", string(terminal.Kind))
			if ctx.Err() != nil {
				self.endCanceled()
				return
			}
			select {
			case self.out <- terminal:
				return
			case <-ctx.Done():
			}
		default:
			select {
			case <-changed:
			case <-ctx.Done():
			}
		}
	}
}

// Ends the stream canceled: drops what is held and what out holds, ends the call, and sends canceled, which cannot
// wait, since run is out's only sender and out was just emptied.
func (self *inferStream) endCanceled() {
	terminal := &InferEvent{Kind: InferEventError, Error: &InferError{
		Code:    InferErrorCanceled,
		Model:   self.name,
		Message: "the call's context ended",
	}}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.pending = nil
		self.pendingByteCount = 0
		self.terminal = terminal
		self.notifyWithLock()
	}()
	self.cancelCall()
	for drained := false; !drained; {
		select {
		case <-self.out:
		default:
			drained = true
		}
	}
	self.out <- terminal
}

// The name the router's component registers under (compute_sidecar.go).
const computeInferComponentName = "infer"

// Registers the router's component, which every Sidecar on a compute leg then constructs.
func init() {
	registerComputeComponent(computeInferComponentName, newSidecarInfer, nil)
}

// Inference's component on a Sidecar: its one router.
type sidecarInfer struct {
	router *inferRouter
}

// The router over sidecar's settings and log, with every registered remote path and the remote catalog built for it.
// Reads nothing of the network: each path and the checks read what they need at use.
func newSidecarInfer(sidecar *Sidecar) (*sidecarInfer, error) {
	settings := sidecar.settings.Infer
	if settings == nil {
		settings = DefaultInferSettings()
	}
	args := &inferRouterArgs{
		Settings:    settings,
		Log:         sidecar.log,
		Clock:       sidecar.clock,
		RemotePaths: newInferRemotePaths(sidecar, settings, inferRemotePathRegistrations),
		Checker:     newInferSidecarChecker(sidecar, settings),
	}
	if inferRemoteCatalogRegistration != nil {
		args.RemoteCatalog, args.RemoteCatalogErr = inferRemoteCatalogRegistration(sidecar, settings)
		if args.RemoteCatalog == nil && args.RemoteCatalogErr == nil {
			args.RemoteCatalogErr = errComputeComponentNil
		}
	}
	router, err := newInferRouter(args)
	if err != nil {
		return nil, err
	}
	return &sidecarInfer{router: router}, nil
}

// This Sidecar's router (D-INFER-1), the one the Harness and the gateway share, or an error wrapping
// ErrComputeComponentUnavailable that says why there is none.
func (self *Sidecar) InferRouter() (InferRouter, error) {
	infer, err := sidecarComputeComponent[sidecarInfer](self, computeInferComponentName)
	if err != nil {
		return nil, err
	}
	return infer.router, nil
}

// Sets the local engine this Sidecar's router runs local calls on: the daemon's ur-engine process client on a desktop
// (INFER-M11-04), an app's host on a phone (INFER-M11-06); nil for none, which leaves the catalog with no local entry.
// The caller keeps the engine and closes it. Errs where the router is not constructed, as before the Sidecar starts.
func (self *Sidecar) SetInferLocalEngine(engine InferLocalEngine) error {
	infer, err := sidecarComputeComponent[sidecarInfer](self, computeInferComponentName)
	if err != nil {
		return err
	}
	infer.router.setLocalEngine(engine)
	return nil
}
