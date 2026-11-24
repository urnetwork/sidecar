//go:build !ios_extension && !sidecar_http

// The engine helper's loop (DESIGN-COMPUTE §6.5, D-INFER-2): what ur-engine runs on its stdio, over an
// inferEngineBackend, LiteRT-LM's C API in the shipped helper (infer_engine_litert.go, build tag ur_engine) and a
// stand-in in tests. Only the binding and the helper's main need the tag, so ur links no binding; the loop has none, so
// the protocol's tests run in every build.
//
// It reads one request a line and answers each by its id (infer_engine_protocol.go): capabilities and cancel at once,
// load, generate, unload and every extension method on a goroutine of their own, so a cancel reaches a generate that
// runs. A load checks every file it names against its SHA-256 before the backend opens any, so a library or a model off
// its pin is never loaded. A generate takes an idle engine of its model (inferEnginePool), continues its agent's
// conversation where the engine holds it with exactly the call's earlier turns, and otherwise opens one from the call's
// own messages; it sends the last message and answers the chunks as InferEvents, a start first and exactly one end or
// error last. A call that has both tools and a schema runs its tools first, holding that turn's events, and where the
// model calls no tool, runs the schema on a final turn in a conversation of its own, since one conversation takes one
// of the two modes (§6.5); the held turn's text is then dropped. A cancel stops the send and closes the conversation,
// never reusing it (#2807); the agent's next turn reopens it from its messages.
//
// Extension methods register through registerInferEngineMethod, SAFE's classifier's from its own file in the same
// process (§27.5), each answering a result or an error.
//
// The loop ends at its input's end, its context's end or a line past its bound, ending every call first. An answer it
// cannot write ends it too: the daemon is gone.

package sidecar

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
)

// An extension method of the helper: runs on its own goroutine, its result the method's answer. params is the
// request's, never parsed by the loop.
type InferEngineMethod func(ctx context.Context, params json.RawMessage) (json.RawMessage, error)

// The extension methods, by name, registered at init by their owners' files. Read without a lock after init.
var inferEngineMethods = map[string]InferEngineMethod{}

// Registers an extension method of the helper under name, from an init function in its owner's file, such as SAFE's
// classify methods. A built-in method's name, an empty one, a nil method or a name registered twice is a build error,
// which panics.
func registerInferEngineMethod(name string, method InferEngineMethod) {
	_, registered := inferEngineMethods[name]
	if name == "" || method == nil || registered || slices.Contains(inferEngineBuiltInMethods, name) {
		panic(fmt.Sprintf("engine method %q registered twice, without a method or over a built-in", name))
	}
	inferEngineMethods[name] = method
}

// A file whose bytes differ from its pin, or that does not read.
var errInferEngineFileOffPin = errors.New("engine file off its pin")

// Checks the file at file.Path against file.Sha256 before it is loaded (§6.5), reading it through and hashing every
// byte. The file is opened read only. The check and the load are two opens of one path, which only the user that runs
// the helper can write; the helper's confinement makes its directory read only to it (INFER-M11-05).
func inferEngineCheckFile(file *inferEngineFile) error {
	if file == nil || file.Path == "" || !inferManifestSha256Pattern.MatchString(file.Sha256) {
		return fmt.Errorf("%w: a file without a path or a pin", errInferEngineFileOffPin)
	}
	opened, err := os.Open(file.Path)
	if err != nil {
		return fmt.Errorf("%w: %s does not open", errInferEngineFileOffPin, file.Path)
	}
	defer opened.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, opened); err != nil {
		return fmt.Errorf("%w: %s does not read", errInferEngineFileOffPin, file.Path)
	}
	if hex.EncodeToString(hash.Sum(nil)) != file.Sha256 {
		return fmt.Errorf("%w: %s is not the file its SHA-256 names", errInferEngineFileOffPin, file.Path)
	}
	return nil
}

// A generate in flight, which a cancel stops.
type inferEngineRunning struct {
	cancel context.CancelFunc

	stateLock sync.Mutex
	// the conversation sending now, nil between turns
	conversation inferEngineConversation
	canceled     bool
}

// Stops the call: its context, and the send in flight.
func (self *inferEngineRunning) stop() {
	self.cancel()
	conversation := func() inferEngineConversation {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.canceled = true
		return self.conversation
	}()
	if conversation != nil {
		conversation.cancel()
	}
}

// Marks conversation as the one sending, or nil for none; false where the call was stopped already, which then sends
// nothing.
func (self *inferEngineRunning) sending(conversation inferEngineConversation) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.conversation = conversation
	return !self.canceled
}

// The helper over its backend.
type inferEngineHelper struct {
	ctx      context.Context
	backend  inferEngineBackend
	methods  map[string]InferEngineMethod
	settings *InferSettings
	writer   *inferEngineLineWriter
	// every goroutine the loop started
	work sync.WaitGroup

	stateLock  sync.Mutex
	pools      map[uint64]*inferEnginePool
	nextHandle uint64
	running    map[uint64]*inferEngineRunning
}

// Serves the helper's protocol on in and out over backend, with the extension methods methods, until in ends, ctx ends
// or the protocol breaks. Returns nil at in's end, else why it stopped.
func inferEngineHelperServe(ctx context.Context, in io.Reader, out io.Writer, backend inferEngineBackend, methods map[string]InferEngineMethod, settings *InferSettings) error {
	ctx, cancel := context.WithCancel(ctx)
	helper := &inferEngineHelper{
		ctx:      ctx,
		backend:  backend,
		methods:  methods,
		settings: settings,
		writer:   newInferEngineLineWriter(out, settings.EngineAnswerMaxByteCount),
		pools:    map[uint64]*inferEnginePool{},
		running:  map[uint64]*inferEngineRunning{},
	}
	defer func() {
		cancel()
		// a send ends only at its conversation's cancel, never at a context's end
		for _, running := range helper.runningCalls() {
			running.stop()
		}
		helper.work.Wait()
		helper.unloadAll()
	}()
	reader := bufio.NewReader(in)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line, err := inferEngineReadLine(reader, settings.EngineRequestMaxByteCount)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		request := &inferEngineRequest{}
		if err := json.Unmarshal(line, request); err != nil || request.Id == 0 {
			return errors.New("a request that is not one of the protocol's")
		}
		if err := helper.serve(request); err != nil {
			return err
		}
	}
}

// Every generate in flight.
func (self *inferEngineHelper) runningCalls() []*inferEngineRunning {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	runningCalls := []*inferEngineRunning{}
	for _, running := range self.running {
		runningCalls = append(runningCalls, running)
	}
	return runningCalls
}

// Writes one answer; an error where it cannot, which ends the loop's work.
func (self *inferEngineHelper) answer(answer *inferEngineAnswer) error {
	return self.writer.write(answer)
}

// Answers id with result's JSON, or with err as an InferError.
func (self *inferEngineHelper) answerResult(id uint64, result any, err error) {
	if err != nil {
		self.answer(&inferEngineAnswer{Id: id, Error: inferEngineError(err)})
		return
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		self.answer(&inferEngineAnswer{Id: id, Error: newInferError(InferErrorEngineFailed, "the result does not encode")})
		return
	}
	self.answer(&inferEngineAnswer{Id: id, Result: encoded})
}

// err as the protocol answers it: an *InferError as it is, a canceled call canceled, anything else engine_failed with
// its text.
func inferEngineError(err error) *InferError {
	var inferError *InferError
	switch {
	case errors.As(err, &inferError):
		return inferError.clone()
	case errors.Is(err, errInferEngineCanceled), errors.Is(err, context.Canceled):
		return newInferError(InferErrorCanceled, "the call was canceled")
	}
	return newInferError(InferErrorEngineFailed, "%s", err)
}

// Starts or answers one request. An error ends the loop.
func (self *inferEngineHelper) serve(request *inferEngineRequest) error {
	run := func(work func()) {
		self.work.Go(work)
	}
	switch request.Method {
	case inferEngineMethodCapabilities:
		capabilities, err := inferEngineDeviceCapabilities()
		self.answerResult(request.Id, capabilities, err)
	case inferEngineMethodCancel:
		params := &inferEngineCancelParams{}
		if err := json.Unmarshal(request.Params, params); err != nil {
			self.answerResult(request.Id, nil, newInferError(InferErrorEngineFailed, "cancel's params do not read"))
			return nil
		}
		running := func() *inferEngineRunning {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.running[params.Id]
		}()
		if running != nil {
			running.stop()
		}
		self.answerResult(request.Id, struct{}{}, nil)
	case inferEngineMethodLoad:
		run(func() {
			handle, err := self.load(request.Params)
			self.answerResult(request.Id, &inferEngineLoadResult{Handle: handle}, err)
		})
	case inferEngineMethodGenerate:
		ctx, cancel := context.WithCancel(self.ctx)
		running := &inferEngineRunning{cancel: cancel}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.running[request.Id] = running
		}()
		run(func() {
			defer func() {
				cancel()
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				delete(self.running, request.Id)
			}()
			self.generate(ctx, request.Id, request.Params, running)
		})
	case inferEngineMethodUnload:
		run(func() {
			self.answerResult(request.Id, struct{}{}, self.unload(request.Params))
		})
	default:
		method, ok := self.methods[request.Method]
		if !ok {
			self.answerResult(request.Id, nil, newInferError(InferErrorEngineFailed, "no method %q", request.Method))
			return nil
		}
		run(func() {
			result, err := method(self.ctx, request.Params)
			if err != nil {
				self.answerResult(request.Id, nil, err)
				return
			}
			self.answer(&inferEngineAnswer{Id: request.Id, Result: result})
		})
	}
	return nil
}

// Checks every file load's params name against its pin, then loads the model into its engines, answering its handle.
func (self *inferEngineHelper) load(rawParams json.RawMessage) (uint64, error) {
	params := &inferEngineLoadParams{}
	if err := json.Unmarshal(rawParams, params); err != nil || params.Model == nil || params.Settings == nil || len(params.Libraries) == 0 {
		return 0, newInferError(InferErrorEngineFailed, "load's params do not read")
	}
	files := slices.Concat(params.Libraries, params.GpuPlugins, []*inferEngineFile{params.Model})
	if params.Dawn != nil {
		files = append(files, params.Dawn)
	}
	for _, file := range files {
		if err := inferEngineCheckFile(file); err != nil {
			return 0, newInferError(InferErrorEngineFailed, "%s", err)
		}
	}
	if params.Settings.InstanceCount < 1 {
		return 0, newInferError(InferErrorEngineFailed, "a load of no engine")
	}
	models, err := self.backend.load(params)
	if err != nil {
		return 0, newInferError(InferErrorEngineFailed, "the engine does not load: %s", err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nextHandle += 1
	self.pools[self.nextHandle] = newInferEnginePool(models)
	return self.nextHandle, nil
}

// Frees the engines of unload's handle, refusing while a call holds one.
func (self *inferEngineHelper) unload(rawParams json.RawMessage) error {
	params := &inferEngineUnloadParams{}
	if err := json.Unmarshal(rawParams, params); err != nil {
		return newInferError(InferErrorEngineFailed, "unload's params do not read")
	}
	pool := func() *inferEnginePool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.pools[params.Handle]
	}()
	if pool == nil {
		return newInferError(InferErrorEngineFailed, "no engine of handle %d", params.Handle)
	}
	instances, ok := pool.takeAll()
	if !ok {
		return newInferError(InferErrorCapacity, "a call holds an engine of handle %d", params.Handle)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.pools, params.Handle)
	}()
	for _, instance := range instances {
		instance.closeConversation()
		instance.model.close()
	}
	return nil
}

// Frees every engine, as the loop ends and every call has.
func (self *inferEngineHelper) unloadAll() {
	pools := func() map[uint64]*inferEnginePool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		pools := self.pools
		self.pools = map[uint64]*inferEnginePool{}
		return pools
	}()
	for _, pool := range pools {
		instances, _ := pool.takeAll()
		for _, instance := range instances {
			instance.closeConversation()
			instance.model.close()
		}
	}
}

// One turn's outcome: the events it answered and the assistant message the conversation now ends with.
type inferEngineTurn struct {
	events  []*InferEvent
	message *inferEngineMessage
	called  bool
	usage   *InferUsage
}

// A fresh tool call id: random, so no two calls of a run share one.
func inferEngineToolCallId() string {
	id := make([]byte, 8)
	rand.Read(id)
	return "call-" + hex.EncodeToString(id)
}

// Runs one turn of a generate on instance in mode, giving each event to emit, and answers it. The conversation is
// continued where the instance holds key's in mode with exactly these earlier turns, and opened from them otherwise. A
// turn that fails or is stopped closes its conversation, never to be reused (#2807).
func (self *inferEngineHelper) turn(running *inferEngineRunning, instance *inferEngineInstance, params *inferEngineGenerateParams,
	system string, history []*inferEngineMessage, last *inferEngineMessage, mode inferEngineMode, emit func(event *InferEvent)) (*inferEngineTurn, error) {
	historyHash, err := inferEngineHistoryHash(system, history)
	if err != nil {
		return nil, err
	}
	if instance.conversation == nil || instance.key != params.Conversation || instance.mode != mode || instance.history != historyHash {
		instance.closeConversation()
		config := &inferEngineConversationConfig{System: system, Mode: mode, Thinking: params.Effort != InferEffortOff}
		if 0 < len(history) {
			config.History, err = json.Marshal(history)
			if err != nil {
				return nil, err
			}
		}
		switch mode {
		case inferEngineModeTools:
			config.Tools, err = inferEngineToolsJson(params.Tools)
			if err != nil {
				return nil, err
			}
		case inferEngineModeSchema:
			config.Schema = params.Schema
		}
		testHookBarrier("infer_engine.conversation.open.before", string(mode))
		conversation, err := instance.model.open(config)
		if err != nil {
			return nil, err
		}
		instance.conversation, instance.key, instance.mode = conversation, params.Conversation, mode
	}
	message, err := json.Marshal(last)
	if err != nil {
		return nil, err
	}
	args := &inferEngineSendArgs{MaxOutput: params.MaxOutput, Sampling: params.Sampling}
	if mode == inferEngineModeTools {
		args.ToolChoice = params.ToolChoice
	}
	if !running.sending(instance.conversation) {
		instance.closeConversation()
		return nil, errInferEngineCanceled
	}
	turn := &inferEngineTurn{message: &inferEngineMessage{Role: string(InferRoleAssistant)}}
	text := strings.Builder{}
	usage, err := instance.conversation.send(message, args, func(chunk *inferEngineChunk) {
		if chunk.Reasoning != "" {
			emit(&InferEvent{Kind: InferEventReasoning, Text: chunk.Reasoning})
		}
		if chunk.Text != "" {
			text.WriteString(chunk.Text)
			emit(&InferEvent{Kind: InferEventText, Text: chunk.Text})
		}
		for _, call := range chunk.ToolCalls {
			id := inferEngineToolCallId()
			arguments := string(call.Arguments)
			turn.called = true
			turn.message.ToolCalls = append(turn.message.ToolCalls, &inferEngineFunctionCall{
				Id:       id,
				Type:     "function",
				Function: inferEngineFunctionCallBody{Name: call.Name, Arguments: inferEngineArguments(arguments)},
			})
			emit(&InferEvent{Kind: InferEventToolCallStart, ToolCall: &InferToolCall{Id: id, Name: call.Name}})
			emit(&InferEvent{Kind: InferEventToolCallArgs, ToolCall: &InferToolCall{Id: id, Arguments: arguments}})
			emit(&InferEvent{Kind: InferEventToolCallEnd, ToolCall: &InferToolCall{Id: id, Name: call.Name, Arguments: arguments}})
		}
	})
	running.sending(nil)
	if err != nil {
		instance.closeConversation()
		return nil, err
	}
	if 0 < text.Len() {
		turn.message.Content = []*inferEngineContentPart{{Type: "text", Text: text.String()}}
	}
	// the conversation now holds the earlier turns, the message sent and the answer
	instance.history, err = inferEngineHistoryHash(system, slices.Concat(history, []*inferEngineMessage{last, turn.message}))
	if err != nil {
		instance.closeConversation()
		return nil, err
	}
	turn.usage = usage
	return turn, nil
}

// Runs one generate and answers its stream: a start once it holds an engine, then the turns' events, its usage, and
// exactly one end or error. The engine is given back before the last event is written: the daemon grants the model's
// next call the moment that event arrives, and the call must find the engine free.
func (self *inferEngineHelper) generate(ctx context.Context, id uint64, rawParams json.RawMessage, running *inferEngineRunning) {
	emit := func(event *InferEvent) {
		self.answer(&inferEngineAnswer{Id: id, Event: event})
	}
	defer testHookBarrier("infer_engine.generate.answered", "")
	usage, err := self.run(ctx, rawParams, running, emit)
	if err != nil {
		emit(&InferEvent{Kind: InferEventError, Error: inferEngineError(err)})
		return
	}
	if usage != nil {
		emit(&InferEvent{Kind: InferEventUsage, Usage: usage})
	}
	emit(&InferEvent{Kind: InferEventEnd})
}

// The body of a generate: its turns on an engine it holds until it returns, their events given to emit as they come,
// and their usage, or why it failed.
func (self *inferEngineHelper) run(ctx context.Context, rawParams json.RawMessage, running *inferEngineRunning, emit func(event *InferEvent)) (*InferUsage, error) {
	params := &inferEngineGenerateParams{}
	if err := json.Unmarshal(rawParams, params); err != nil {
		return nil, newInferError(InferErrorEngineFailed, "generate's params do not read")
	}
	system, history, last, err := inferEngineConversationOf(params.Messages)
	if err != nil {
		return nil, newInferError(InferErrorEngineFailed, "the conversation does not convert: %s", err)
	}
	pool := func() *inferEnginePool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.pools[params.Handle]
	}()
	if pool == nil {
		return nil, newInferError(InferErrorEngineFailed, "no engine of handle %d", params.Handle)
	}
	instance := pool.acquire(params.Conversation)
	if instance == nil {
		return nil, newInferError(InferErrorCapacity, "every engine of the model runs a call")
	}
	defer pool.release(instance)
	if ctx.Err() != nil {
		return nil, errInferEngineCanceled
	}
	emit(&InferEvent{Kind: InferEventStart})
	mode := inferEngineModePlain
	switch {
	case 0 < len(params.Tools):
		mode = inferEngineModeTools
	case params.Schema != nil:
		mode = inferEngineModeSchema
	}
	schemaAfter := mode == inferEngineModeTools && params.Schema != nil
	held := []*InferEvent{}
	turnEmit := emit
	if schemaAfter {
		turnEmit = func(event *InferEvent) {
			held = append(held, event)
		}
	}
	turn, err := self.turn(running, instance, params, system, history, last, mode, turnEmit)
	if err != nil {
		return nil, err
	}
	if schemaAfter && !turn.called {
		// the model answered without a tool, so the answer is the schema's, on a final turn
		final, err := self.turn(running, instance, params, system, history, last, inferEngineModeSchema, emit)
		if err != nil {
			return nil, err
		}
		return inferEngineUsageSum(turn.usage, final.usage), nil
	}
	for _, event := range held {
		emit(event)
	}
	return turn.usage, nil
}

// Both turns' usage together, either nil.
func inferEngineUsageSum(first *InferUsage, second *InferUsage) *InferUsage {
	switch {
	case first == nil:
		return second
	case second == nil:
		return first
	}
	return &InferUsage{
		InputTokens:     first.InputTokens + second.InputTokens,
		OutputTokens:    first.OutputTokens + second.OutputTokens,
		CachedTokens:    first.CachedTokens + second.CachedTokens,
		ReasoningTokens: first.ReasoningTokens + second.ReasoningTokens,
	}
}
