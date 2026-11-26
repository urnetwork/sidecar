//go:build !ios_extension && !sidecar_http

// The daemon's side of the desktop engine (DESIGN-COMPUTE §6.5, D-INFER-2): InferEngineProcess, the InferLocalEngine
// ur's daemon sets on its Sidecar's router, which runs each local model in an ur-engine helper process of its own and
// speaks the helper's protocol to it (infer_engine_protocol.go).
//
// A helper starts beside ur (InferEngineProcessArgs.HelperPath; inside ur.app on macOS), confined by its OS to reading
// its engine and model files (infer_engine_confine.go), with only the arguments and the environment its args name, the
// confinement's directories before them, no descriptor but its stdio, and no key, token or keychain access: nothing the
// daemon holds reaches it but paths, pins and the conversation it answers. Where this host cannot confine one, as a
// Linux kernel without Landlock, Capabilities says why and the router lists no local model. One helper
// runs one loaded model, up to InferSettings.EngineProcessMaxCount at once, the least recently used idle one stopped to
// make room. A model's calls share its engines (infer_engine_share.go): up to one a desktop engine, two engines where
// the device has the memory for both, the rest waiting in arrival order, each call's start sent once it holds a slot.
//
// A crash, a leak, a hostile model file or a line past its bound ends the helper, never the daemon: every call on it
// answers engine_failed, and the model's next call starts a new helper. A canceled call returns at once; its slot is
// freed once the helper answers the cancel, or once EngineCancelTimeout passes, when the helper is ended.
//
// Call runs one of the helper's extension methods, such as SAFE's classifier's, on a helper of its own with no model.
//
// Safe for concurrent use.

package sidecar

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"
)

// The helper's executable's name beside ur, with Windows' suffix.
func inferEngineHelperName() string {
	if runtime.GOOS == "windows" {
		return "ur-engine.exe"
	}
	return "ur-engine"
}

// What NewInferEngineProcess builds on.
type InferEngineProcessArgs struct {
	// The helper's executable; empty for ur-engine beside the running executable.
	HelperPath string
	// The helper's arguments and its whole environment: nothing else is passed. Nil is none.
	HelperArgs []string
	HelperEnv  []string
	// Where the engine's libraries and the models are pulled to (INFER-M11-06), each file named as the release
	// manifest names it.
	EngineDirectory string
	ModelDirectory  string
	// The instance's state directory, which holds the two and which the helper must not read: once confined it proves
	// it cannot list it before it serves (infer_engine_confine.go).
	StateDirectory string
	// The release manifest; nil for this build's.
	Manifest *InferManifest
	// The device; nil to read it from the OS.
	Capabilities *InferDeviceCapabilities
	// Nil for the defaults.
	Settings *InferSettings
	// Nil for real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
}

// The desktop engine (§6.5): see the file comment.
type InferEngineProcess struct {
	helperPath      string
	helperArgs      []string
	helperEnv       []string
	engineDirectory string
	modelDirectory  string
	confinement     *inferEngineConfinement
	// whether this host can confine a helper: inferEngineConfineAvailable, a test's seam
	confineAvailable func() error
	manifest         *InferManifest
	capabilities     *InferDeviceCapabilities
	settings         *InferSettings
	clock            Clock
	log              Logger

	stateLock sync.Mutex
	// the helper running each loaded model, by the model file's path
	models map[string]*inferEngineModelProcess
	// the helper Call uses, started at its first call
	methods *inferEngineHelperProcess
	// counts uses, for least recently used
	count  uint64
	closed bool
}

// One loaded model's helper.
type inferEngineModelProcess struct {
	helper *inferEngineHelperProcess
	share  *inferEngineShare
	// closed once the load answered; handle and loadErr are set before
	loaded  chan struct{}
	handle  uint64
	loadErr error
	// calls holding or waiting for a slot, and when one last began
	users int
	used  uint64
}

// The desktop engine over args. Starts no helper until a call needs one.
func NewInferEngineProcess(args *InferEngineProcessArgs) (*InferEngineProcess, error) {
	if args == nil || args.EngineDirectory == "" || args.ModelDirectory == "" || args.StateDirectory == "" {
		return nil, errors.New("engine process: an engine, a model and a state directory")
	}
	confinement := &inferEngineConfinement{
		EngineDirectory: filepath.Clean(args.EngineDirectory),
		ModelDirectory:  filepath.Clean(args.ModelDirectory),
		DeniedDirectory: filepath.Clean(args.StateDirectory),
	}
	if err := confinement.validate(); err != nil {
		return nil, fmt.Errorf("engine process: %w", err)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultInferSettings()
	}
	helperPath := args.HelperPath
	if helperPath == "" {
		executable, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("engine process: where ur runs from: %w", err)
		}
		helperPath = inferEngineDefaultHelperPath(executable)
	}
	manifest := args.Manifest
	if manifest == nil {
		var err error
		manifest, err = InferReleaseManifest(settings)
		if err != nil {
			return nil, err
		}
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &InferEngineProcess{
		helperPath:       helperPath,
		helperArgs:       slices.Clone(args.HelperArgs),
		helperEnv:        slices.Clone(args.HelperEnv),
		engineDirectory:  confinement.EngineDirectory,
		modelDirectory:   confinement.ModelDirectory,
		confinement:      confinement,
		confineAvailable: inferEngineConfineAvailable,
		manifest:         manifest,
		capabilities:     args.Capabilities,
		settings:         settings,
		clock:            clockOrReal(args.Clock),
		log:              log,
		models:           map[string]*inferEngineModelProcess{},
	}, nil
}

// See InferLocalEngine: the device as the args gave it, else as its OS reports it; an error where this host cannot run
// a confined helper, so the router lists local inference unavailable with why (§6.5).
func (self *InferEngineProcess) Capabilities(ctx context.Context) (*InferDeviceCapabilities, error) {
	if err := self.confineAvailable(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(self.helperPath); err != nil {
		return nil, fmt.Errorf("no ur-engine helper at its place beside ur, so this build runs no local model: %w", err)
	}
	if self.capabilities != nil {
		return self.capabilities.clone(), nil
	}
	return inferEngineDeviceCapabilities()
}

// What runs one local model on this device: the backend, the model's file and the engine's files, and how many engines
// of it the device has the memory for.
type inferEnginePlan struct {
	backend   string
	instances int
	params    *inferEngineLoadParams
}

// The plan for call's model, or model_refused where its files are not on this device.
func (self *InferEngineProcess) plan(ctx context.Context, call *InferCall) (*inferEnginePlan, error) {
	device, err := self.Capabilities(ctx)
	if err != nil {
		return nil, newInferError(InferErrorEngineFailed, "this device's capabilities do not read: %s", err)
	}
	local := call.Entry.Local
	if local == nil {
		return nil, newInferError(InferErrorModelRefused, "no local model")
	}
	engine := self.manifest.Engine(device.Platform)
	if engine == nil || len(engine.Libraries) == 0 {
		return nil, newInferError(InferErrorModelRefused, "this build pins no engine for %s", device.Platform)
	}
	backend := string(InferAcceleratorCpu)
	if slices.Contains(device.Accelerators, InferAcceleratorGpu) && slices.Contains(local.Accelerators, InferAcceleratorGpu) {
		backend = string(InferAcceleratorGpu)
	}
	// the build for the backend's accelerator, else the one every accelerator loads
	var modelFile *InferManifestModelFile
	for _, file := range local.Files {
		if string(file.Accelerator) == backend || (file.Accelerator == "" && modelFile == nil) {
			modelFile = file
		}
	}
	if modelFile == nil {
		return nil, newInferError(InferErrorModelRefused, "no build of %s runs on this device's %s", call.Name, backend)
	}
	pinned := func(directory string, file *InferManifestFile) (*inferEngineFile, error) {
		path := filepath.Join(directory, file.Name)
		if _, err := os.Stat(path); err != nil {
			return nil, newInferError(InferErrorModelRefused, "%s is not on this device yet: pull it first", file.Name)
		}
		return &inferEngineFile{Path: path, Sha256: file.Sha256}, nil
	}
	params := &inferEngineLoadParams{Settings: &inferEngineLoadSettings{
		Backend:       backend,
		MaxTokenCount: call.Entry.ContextWindow,
	}}
	for _, library := range engine.Libraries {
		file, err := pinned(self.engineDirectory, library)
		if err != nil {
			return nil, err
		}
		params.Libraries = append(params.Libraries, file)
	}
	if backend == string(InferAcceleratorGpu) {
		for _, plugin := range engine.GpuPlugins {
			file, err := pinned(self.engineDirectory, plugin)
			if err != nil {
				return nil, err
			}
			params.GpuPlugins = append(params.GpuPlugins, file)
		}
	}
	if engine.Dawn != nil {
		params.Dawn, err = pinned(self.engineDirectory, engine.Dawn)
		if err != nil {
			return nil, err
		}
	}
	params.Model, err = pinned(self.modelDirectory, &modelFile.InferManifestFile)
	if err != nil {
		return nil, err
	}
	// a second engine only where the device holds the model twice over
	instances := 1
	for count := 2; count <= self.settings.EngineInstanceMaxCount; count += 1 {
		if int64(count)*local.MinMemoryByteCount <= device.MemoryByteCount {
			instances = count
		}
	}
	params.Settings.InstanceCount = instances
	return &inferEnginePlan{backend: backend, instances: instances, params: params}, nil
}

// The daemon's opaque key for a call's conversation: a hash of its agent's id, else its run's, so the helper learns
// neither; a fresh one for a call with neither, which continues nothing.
func inferEngineConversationKey(request *InferRequest) string {
	hash := sha256.New()
	switch {
	case request.AgentId != nil:
		hash.Write([]byte("agent"))
		hash.Write(request.AgentId[:])
	case request.RunId != nil:
		hash.Write([]byte("run"))
		hash.Write(request.RunId[:])
	default:
		hash.Write([]byte(inferEngineToolCallId()))
	}
	return hex.EncodeToString(hash.Sum(nil)[:16])
}

// The loaded model's helper for plan, started and loading where none runs; it counts the caller as a user until done
// is called. Stops the least recently used idle helper past EngineProcessMaxCount, and refuses capacity where none is
// idle. A model's helper is read only once its load has answered, which its loaded channel says.
func (self *InferEngineProcess) modelProcess(plan *inferEnginePlan) (*inferEngineModelProcess, func(), error) {
	key := plan.params.Model.Path
	// a helper found ended is replaced once; one that ends again at once answers its error
	for attempt := 0; ; attempt += 1 {
		model, start, stop, err := func() (*inferEngineModelProcess, bool, *inferEngineModelProcess, error) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.closed {
				return nil, false, nil, newInferError(InferErrorEngineFailed, "the engine process is closed")
			}
			self.count += 1
			if model, ok := self.models[key]; ok {
				model.users += 1
				model.used = self.count
				return model, false, nil, nil
			}
			var stop *inferEngineModelProcess
			if self.settings.EngineProcessMaxCount <= len(self.models) {
				// an idle helper's load has answered, since its loader stays a user until then
				for _, model := range self.models {
					if model.users == 0 && (stop == nil || model.used < stop.used) {
						stop = model
					}
				}
				if stop == nil {
					return nil, false, nil, newInferError(InferErrorCapacity, "every engine process runs a call")
				}
				for modelKey, model := range self.models {
					if model == stop {
						delete(self.models, modelKey)
					}
				}
			}
			model := &inferEngineModelProcess{
				share:  newInferEngineShare(plan.instances),
				loaded: make(chan struct{}),
				users:  1,
				used:   self.count,
			}
			self.models[key] = model
			return model, true, stop, nil
		}()
		if err != nil {
			return nil, nil, err
		}
		if stop != nil {
			stop.helper.stop(self.settings.EngineStopTimeout)
		}
		if start {
			self.load(model, plan)
		} else {
			<-model.loaded
		}
		done := func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			model.users -= 1
		}
		if model.loadErr == nil && !model.helper.ended() {
			return model, done, nil
		}
		done()
		// a helper that failed or ended leaves the map, so a later call starts another
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.models[key] == model {
				delete(self.models, key)
			}
		}()
		if model.loadErr != nil {
			return nil, nil, model.loadErr
		}
		if 0 < attempt {
			return nil, nil, newInferError(InferErrorEngineFailed, "the engine process ended")
		}
	}
}

// Starts model's helper and loads plan's model in it, bounded by EngineLoadTimeout, then says the load answered.
func (self *InferEngineProcess) load(model *inferEngineModelProcess, plan *inferEnginePlan) {
	defer close(model.loaded)
	helper, err := startInferEngineHelperProcess(self.childSpec(), self.settings, self.clock, self.log)
	if err != nil {
		model.helper, model.loadErr = startInferEngineEndedHelper(err), err
		return
	}
	model.helper = helper
	result := &inferEngineLoadResult{}
	ctx, cancel := context.WithCancel(context.Background())
	stopTimer := self.clock.AfterFunc(self.settings.EngineLoadTimeout, cancel)
	err = helper.call(ctx, inferEngineMethodLoad, plan.params, nil, result)
	stopTimer()
	cancel()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = newInferError(InferErrorEngineFailed, "the model did not load within %s", self.settings.EngineLoadTimeout)
		}
		helper.stop(self.settings.EngineStopTimeout)
		model.loadErr = err
		return
	}
	model.handle = result.Handle
}

// See InferLocalEngine: runs call on its model's helper, waiting in arrival order for one of its engines and sending
// start once it holds one.
func (self *InferEngineProcess) Generate(ctx context.Context, call *InferCall, emit InferEmit) error {
	plan, err := self.plan(ctx, call)
	if err != nil {
		return err
	}
	model, done, err := self.modelProcess(plan)
	if err != nil {
		return err
	}
	if err := model.share.acquire(ctx); err != nil {
		done()
		return err
	}
	release := func() {
		model.share.release()
		done()
	}
	request := call.Request
	params := &inferEngineGenerateParams{
		Handle:       model.handle,
		Conversation: inferEngineConversationKey(request),
		Messages:     request.Messages,
		Tools:        request.Tools,
		ToolChoice:   request.ToolChoice,
		Schema:       request.Schema,
		MaxOutput:    request.MaxOutput,
		Sampling:     request.Sampling,
		Effort:       call.Effort,
	}
	pending, err := model.helper.start(inferEngineMethodGenerate, params, emit)
	if err != nil {
		release()
		return err
	}
	select {
	case answer := <-pending.done:
		release()
		if answer.Error != nil {
			return answer.Error
		}
		return nil
	case <-ctx.Done():
	}
	// answered at once; the slot is freed once the helper has stopped the call, or ended
	model.helper.cancel(pending)
	go func() {
		defer release()
		select {
		case <-pending.done:
		case <-self.clock.After(self.settings.EngineCancelTimeout):
			model.helper.stop(self.settings.EngineStopTimeout)
			<-pending.done
		}
	}()
	return ctx.Err()
}

// Runs the helper's extension method on Call's own helper, which starts at the first call: params encoded as JSON, the
// result decoded into result where it is not nil. A built-in method is refused.
func (self *InferEngineProcess) Call(ctx context.Context, method string, params any, result any) error {
	if slices.Contains(inferEngineBuiltInMethods, method) {
		return fmt.Errorf("engine process: %s is the protocol's own", method)
	}
	helper, err := func() (*inferEngineHelperProcess, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return nil, newInferError(InferErrorEngineFailed, "the engine process is closed")
		}
		if self.methods != nil && !self.methods.ended() {
			return self.methods, nil
		}
		helper, err := startInferEngineHelperProcess(self.childSpec(), self.settings, self.clock, self.log)
		if err != nil {
			return nil, err
		}
		self.methods = helper
		return helper, nil
	}()
	if err != nil {
		return err
	}
	return helper.call(ctx, method, params, nil, result)
}

// Ends every helper: each is asked to exit and ended past EngineStopTimeout, once its load has answered. Calls after
// it refuse.
func (self *InferEngineProcess) Close() {
	models, methods := func() ([]*inferEngineModelProcess, *inferEngineHelperProcess) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		models := []*inferEngineModelProcess{}
		for _, model := range self.models {
			models = append(models, model)
		}
		methods := self.methods
		self.models = map[string]*inferEngineModelProcess{}
		self.methods = nil
		return models, methods
	}()
	for _, model := range models {
		<-model.loaded
		model.helper.stop(self.settings.EngineStopTimeout)
	}
	if methods != nil {
		methods.stop(self.settings.EngineStopTimeout)
	}
}

// One request in flight on a helper.
type inferEnginePending struct {
	id uint64
	// a generate's events but its last; nil for a method
	onEvent func(event *InferEvent)
	// the last answer: a generate's end or error event as Error, a method's result or error; buffered
	done chan *inferEngineAnswer
}

// How every helper of this process is started: its executable, arguments and environment, in the engine's directory,
// confined to the two directories.
func (self *InferEngineProcess) childSpec() *inferEngineChildSpec {
	return &inferEngineChildSpec{
		Path:        self.helperPath,
		Args:        self.helperArgs,
		Env:         self.helperEnv,
		Directory:   self.engineDirectory,
		Confinement: self.confinement,
	}
}

// One running helper process and its protocol: a goroutine reads its answers and hands each to its request, never
// waiting on a reader, since a generate's events go to the router's InferEmit, which never blocks.
type inferEngineHelperProcess struct {
	child    *inferEngineChild
	writer   *inferEngineLineWriter
	stdin    io.Closer
	settings *InferSettings
	clock    Clock
	log      Logger
	// closed once the process has ended and every request was answered
	exited chan struct{}

	stateLock sync.Mutex
	nextId    uint64
	pending   map[uint64]*inferEnginePending
	// why the helper ended, once it has
	endErr error
}

// A helper that has already ended with err, standing in for one that failed to start or load, so a model's waiters
// see its error.
func startInferEngineEndedHelper(err error) *inferEngineHelperProcess {
	helper := &inferEngineHelperProcess{exited: make(chan struct{}), pending: map[uint64]*inferEnginePending{}, endErr: err}
	close(helper.exited)
	return helper
}

// Starts the helper as spec says (inferEngineStartChild: confined, with spec's environment alone and no descriptor but
// its stdio), its stderr kept to the settings' bound.
func startInferEngineHelperProcess(spec *inferEngineChildSpec, settings *InferSettings, clock Clock, log Logger) (*inferEngineHelperProcess, error) {
	stderr := &inferEngineBoundedBuffer{maxByteCount: settings.EngineStderrMaxByteCount}
	started := *spec
	started.Stderr = stderr
	child, err := inferEngineStartChild(&started)
	if err != nil {
		return nil, newInferError(InferErrorEngineFailed, "the engine helper does not start: %s", err)
	}
	helper := &inferEngineHelperProcess{
		child:    child,
		writer:   newInferEngineLineWriter(child.stdin, settings.EngineRequestMaxByteCount),
		stdin:    child.stdin,
		settings: settings,
		clock:    clock,
		log:      log,
		exited:   make(chan struct{}),
		pending:  map[uint64]*inferEnginePending{},
	}
	go func() {
		err := helper.read(child.stdout)
		// the process is ended for good, whatever ended the reading
		child.kill()
		waitErr := child.wait()
		if err == nil {
			err = waitErr
		}
		if err == nil {
			err = errors.New("the engine helper exited")
		}
		if 0 < stderr.Len() && log.V(1).Enabled() {
			log.Infof("[infer]the engine helper ended (%s); its last words: %s", err, stderr.String())
		}
		helper.end(err)
	}()
	return helper, nil
}

// Reads answers until the output ends or breaks the protocol, handing each to its request.
func (self *inferEngineHelperProcess) read(stdout io.Reader) error {
	reader := bufio.NewReader(stdout)
	for {
		line, err := inferEngineReadLine(reader, self.settings.EngineAnswerMaxByteCount)
		if err != nil {
			return err
		}
		answer := &inferEngineAnswer{}
		if err := json.Unmarshal(line, answer); err != nil {
			return errors.New("an answer that is not one of the protocol's")
		}
		pending := func() *inferEnginePending {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.pending[answer.Id]
		}()
		if pending == nil {
			// a straggler of a request already answered
			continue
		}
		last := answer.Event == nil
		if answer.Event != nil {
			switch answer.Event.Kind {
			case InferEventEnd:
				last = true
				answer = &inferEngineAnswer{Id: answer.Id}
			case InferEventError:
				last = true
				inferError := answer.Event.Error
				if inferError == nil {
					inferError = newInferError(InferErrorEngineFailed, "the engine failed")
				}
				answer = &inferEngineAnswer{Id: answer.Id, Error: inferError}
			default:
				if pending.onEvent != nil {
					pending.onEvent(answer.Event)
				}
			}
		}
		if last {
			self.finish(pending, answer)
		}
	}
}

// Answers pending with answer, once.
func (self *inferEngineHelperProcess) finish(pending *inferEnginePending, answer *inferEngineAnswer) {
	answered := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if _, ok := self.pending[pending.id]; !ok {
			return false
		}
		delete(self.pending, pending.id)
		return true
	}()
	if answered {
		pending.done <- answer
	}
}

// The helper ended with err: every request in flight answers engine_failed, and later ones refuse.
func (self *inferEngineHelperProcess) end(err error) {
	pendings := func() []*inferEnginePending {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.endErr = err
		pendings := []*inferEnginePending{}
		for _, pending := range self.pending {
			pendings = append(pendings, pending)
		}
		self.pending = map[uint64]*inferEnginePending{}
		return pendings
	}()
	for _, pending := range pendings {
		pending.done <- &inferEngineAnswer{Id: pending.id, Error: newInferError(InferErrorEngineFailed, "the engine process ended")}
	}
	close(self.exited)
}

// Whether the helper has ended.
func (self *inferEngineHelperProcess) ended() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.endErr != nil
}

// Sends a request of method with params, onEvent taking a generate's events but its last, and answers its pending
// request.
func (self *inferEngineHelperProcess) start(method string, params any, onEvent func(event *InferEvent)) (*inferEnginePending, error) {
	encoded, err := json.Marshal(params)
	if err != nil {
		return nil, newInferError(InferErrorEngineFailed, "the request does not encode")
	}
	pending, err := func() (*inferEnginePending, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.endErr != nil {
			return nil, newInferError(InferErrorEngineFailed, "the engine process ended")
		}
		self.nextId += 1
		pending := &inferEnginePending{id: self.nextId, onEvent: onEvent, done: make(chan *inferEngineAnswer, 1)}
		self.pending[pending.id] = pending
		return pending, nil
	}()
	if err != nil {
		return nil, err
	}
	if err := self.writer.write(&inferEngineRequest{Id: pending.id, Method: method, Params: encoded}); err != nil {
		// a helper that takes no request is ended, which answers this one too
		self.stop(0)
		return pending, nil
	}
	return pending, nil
}

// Sends a request and waits for its answer, decoding a result into result where it is not nil. ctx's end answers at
// once, the request canceled where it is a generate's.
func (self *inferEngineHelperProcess) call(ctx context.Context, method string, params any, onEvent func(event *InferEvent), result any) error {
	pending, err := self.start(method, params, onEvent)
	if err != nil {
		return err
	}
	select {
	case answer := <-pending.done:
		if answer.Error != nil {
			return answer.Error
		}
		if result != nil && answer.Result != nil {
			if err := json.Unmarshal(answer.Result, result); err != nil {
				return newInferError(InferErrorEngineFailed, "the result does not decode")
			}
		}
		return nil
	case <-ctx.Done():
		self.cancel(pending)
		return ctx.Err()
	}
}

// Asks the helper to stop pending's call.
func (self *inferEngineHelperProcess) cancel(pending *inferEnginePending) {
	if _, err := self.start(inferEngineMethodCancel, &inferEngineCancelParams{Id: pending.id}, nil); err != nil && self.log.V(2).Enabled() {
		self.log.Infof("[infer]a cancel was not sent: %s", err)
	}
}

// Ends the helper: closes its input, which it exits at, and past timeout kills it; returns once it has ended.
func (self *inferEngineHelperProcess) stop(timeout time.Duration) {
	if self.child == nil {
		<-self.exited
		return
	}
	self.stdin.Close()
	select {
	case <-self.exited:
		return
	case <-self.clock.After(timeout):
	}
	self.child.kill()
	<-self.exited
}

// A buffer keeping the first maxByteCount bytes written to it, for the helper's stderr. Safe for concurrent use.
type inferEngineBoundedBuffer struct {
	stateLock    sync.Mutex
	buffer       bytes.Buffer
	maxByteCount int
}

// Keeps what fits; always reports the whole write taken, so the helper never blocks on its stderr.
func (self *inferEngineBoundedBuffer) Write(data []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if room := self.maxByteCount - self.buffer.Len(); 0 < room {
		self.buffer.Write(data[:min(room, len(data))])
	}
	return len(data), nil
}

// What it kept.
func (self *inferEngineBoundedBuffer) String() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.buffer.String()
}

// How much it kept.
func (self *inferEngineBoundedBuffer) Len() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.buffer.Len()
}
