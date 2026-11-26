//go:build !ios_extension && !sidecar_http

// The app's host as the router's local engine (DESIGN-COMPUTE §6.5; INFER-M11-06): inferHostEngine, an InferLocalEngine
// over the app's SidecarLocalInferenceHost (infer_host.go), the phone's and the macOS app's counterpart of the desktop's
// InferEngineProcess.
//
//   - Capabilities is the host's JSON, read strictly and bounded, so the catalog's local view is judged for the device
//     the app reports.
//   - A call runs on the model's whole file, which the pull's download alone marks whole (InferModelFile.OpenWhole): a
//     model not pulled, or a part, is refused model_refused, naming the pull, and never loaded.
//   - A model loads once, at its first call, with its backend (the GPU build where the device and the model have one)
//     and FP32 activations on iOS's GPUs and Adreno's (#3913, #4001), and stays loaded; past HostLoadedModelMaxCount
//     models the least recently used idle one is unloaded first.
//   - Its calls share one engine in arrival order between whole calls, one at a time on a phone (§6.5), each emitting
//     start once it holds the engine, so the Harness reads waiting until then.
//   - The host's events come to a listener of the call's own, as InferEvent JSON bounded by EngineAnswerMaxByteCount;
//     the first end or error ends the call, and anything after it, or after the call was canceled, is dropped, so a
//     host's late event never reaches another call.
//   - A canceled call answers at once, the host told to Cancel; the engine is freed once the host ends the generation,
//     or past EngineCancelTimeout, when the model is unloaded, since a host that does not stop cannot be trusted with
//     the next call.
//
// No host call is made under a lock, the router's or this engine's (§6.5's trap), and nothing here sends a request to a
// server (IC-5). Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
)

// The app host's capabilities, as its Capabilities JSON gives them: the device, and its GPU's name.
type inferHostCapabilities struct {
	InferDeviceCapabilities
	// The GPU's name, as the platform reports it, such as "Adreno 750" or "Apple A18 Pro GPU"; empty for none.
	Gpu string `json:"gpu,omitempty"`
}

// What a host's Load configures (§6.5).
type inferHostLoadSettings struct {
	// cpu or gpu.
	Backend string `json:"backend"`
	// The model's context window, in tokens.
	MaxTokenCount int64 `json:"max_token_count"`
	// fp32 where the GPU's FP16 activations corrupt digits (#3913, #4001): iOS's GPUs and Adreno's; empty leaves the
	// engine's own.
	Activations string `json:"activations,omitempty"`
}

// The activations a load sets where FP16 corrupts.
const inferHostActivationsFp32 = "fp32"

// What a host's Generate takes: the desktop helper's generate params without the handle.
type inferHostRequest struct {
	Conversation string          `json:"conversation"`
	Messages     []*InferMessage `json:"messages"`
	Tools        []*InferTool    `json:"tools,omitempty"`
	ToolChoice   string          `json:"tool_choice,omitempty"`
	Schema       json.RawMessage `json:"schema,omitempty"`
	MaxOutput    int             `json:"max_output,omitempty"`
	Sampling     *InferSampling  `json:"sampling,omitempty"`
	Effort       InferEffort     `json:"effort"`
}

// What finds a local model's whole file, for a local engine: InferPull, over the download every pull of its directory
// takes.
type InferModelFiles interface {
	// The path of file's whole file, checked whole; ErrInferModelNotWhole while it is not, or a pull of it runs.
	WholePath(ctx context.Context, file *InferManifestModelFile) (string, error)
}

// What newInferHostEngine builds on.
type inferHostEngineArgs struct {
	Host     SidecarLocalInferenceHost
	Models   InferModelFiles
	Settings *InferSettings
	// Nil for real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
}

// One loaded model: its handle, and the share of its engine.
type inferHostModel struct {
	share *inferEngineShare
	// closed once the load answered; handle and loadErr are set before
	loaded  chan struct{}
	handle  int64
	loadErr error
	// calls holding or waiting for the engine, and when one last began
	users int
	used  uint64
}

// The app's host as an InferLocalEngine: see the file comment.
type inferHostEngine struct {
	host     SidecarLocalInferenceHost
	models   InferModelFiles
	settings *InferSettings
	clock    Clock
	log      Logger

	stateLock sync.Mutex
	// each loaded model, by its whole file's path
	pathModels map[string]*inferHostModel
	count      uint64
	closed     bool
}

// An engine over args' host.
func newInferHostEngine(args *inferHostEngineArgs) *inferHostEngine {
	settings := args.Settings
	if settings == nil {
		settings = DefaultInferSettings()
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &inferHostEngine{
		host:       args.Host,
		models:     args.Models,
		settings:   settings,
		clock:      clockOrReal(args.Clock),
		log:        log,
		pathModels: map[string]*inferHostModel{},
	}
}

// The host's capabilities, read strictly: its JSON within EngineAnswerMaxByteCount, a known class, a platform and
// accelerators the manifest's grammar knows.
func (self *inferHostEngine) hostCapabilities() (*inferHostCapabilities, error) {
	text := self.host.Capabilities()
	if self.settings.EngineAnswerMaxByteCount < len(text) {
		return nil, newInferError(InferErrorEngineFailed, "the app's engine reported capabilities past %d bytes", self.settings.EngineAnswerMaxByteCount)
	}
	capabilities := &inferHostCapabilities{}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(capabilities); err != nil {
		return nil, newInferError(InferErrorEngineFailed, "the app's engine reported capabilities that do not read")
	}
	if capabilities.Platform == "" || inferManifestPlatformFault(capabilities.Platform) != "" {
		return nil, newInferError(InferErrorEngineFailed, "the app's engine reported a platform the manifest does not name")
	}
	if !slices.Contains([]InferDeviceClass{InferDeviceClassPhone, InferDeviceClassLaptop, InferDeviceClassDesktop}, capabilities.Class) {
		return nil, newInferError(InferErrorEngineFailed, "the app's engine reported no device class")
	}
	for _, accelerator := range capabilities.Accelerators {
		if !slices.Contains(inferAccelerators, accelerator) {
			return nil, newInferError(InferErrorEngineFailed, "the app's engine reported an accelerator the manifest does not name")
		}
	}
	return capabilities, nil
}

// See InferLocalEngine: the device as the app reports it.
func (self *inferHostEngine) Capabilities(ctx context.Context) (*InferDeviceCapabilities, error) {
	capabilities, err := self.hostCapabilities()
	if err != nil {
		return nil, err
	}
	return capabilities.InferDeviceCapabilities.clone(), nil
}

// The settings a model's load takes on capabilities' device, its backend backend.
func inferHostLoadSettingsFor(capabilities *inferHostCapabilities, backend InferAccelerator, contextWindow int64) *inferHostLoadSettings {
	settings := &inferHostLoadSettings{Backend: string(backend), MaxTokenCount: contextWindow}
	if backend == InferAcceleratorGpu {
		platform, _, _ := strings.Cut(capabilities.Platform, "/")
		if platform == "ios" || strings.Contains(strings.ToLower(capabilities.Gpu), "adreno") {
			settings.Activations = inferHostActivationsFp32
		}
	}
	return settings
}

// The loaded model at path, loading it with settings where it is not; it counts the caller a user until done is
// called. Past HostLoadedModelMaxCount models the least recently used idle one is unloaded first, and capacity is
// refused where every one is in use.
func (self *inferHostEngine) model(path string, settings *inferHostLoadSettings) (*inferHostModel, func(), error) {
	model, load, evict, err := func() (*inferHostModel, bool, *inferHostModel, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return nil, false, nil, newInferError(InferErrorEngineFailed, "the app's local engine was let go")
		}
		self.count += 1
		if model, ok := self.pathModels[path]; ok {
			model.users += 1
			model.used = self.count
			return model, false, nil, nil
		}
		var evict *inferHostModel
		if max(self.settings.HostLoadedModelMaxCount, 1) <= len(self.pathModels) {
			for _, model := range self.pathModels {
				if model.users == 0 && (evict == nil || model.used < evict.used) {
					evict = model
				}
			}
			if evict == nil {
				return nil, false, nil, newInferError(InferErrorCapacity, "every model the app's engine holds runs a call")
			}
			for evictPath, model := range self.pathModels {
				if model == evict {
					delete(self.pathModels, evictPath)
				}
			}
		}
		// a phone runs one call at a time (§6.5)
		model := &inferHostModel{share: newInferEngineShare(1), loaded: make(chan struct{}), users: 1, used: self.count}
		self.pathModels[path] = model
		return model, true, evict, nil
	}()
	if err != nil {
		return nil, nil, err
	}
	if evict != nil {
		<-evict.loaded
		if evict.loadErr == nil {
			self.host.Unload(evict.handle)
		}
	}
	if load {
		func() {
			defer close(model.loaded)
			encoded, err := json.Marshal(settings)
			if err != nil {
				model.loadErr = newInferError(InferErrorEngineFailed, "the load's settings do not encode")
				return
			}
			handle, err := self.host.Load(path, string(encoded))
			if err != nil {
				model.loadErr = newInferError(InferErrorEngineFailed, "the app's engine did not load the model: %s", err)
				return
			}
			model.handle = handle
		}()
	} else {
		<-model.loaded
	}
	done := func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		model.users -= 1
	}
	if model.loadErr != nil {
		done()
		self.forget(path, model)
		return nil, nil, model.loadErr
	}
	return model, done, nil
}

// Takes model out of the engine where it is still the one at path, so the next call loads it again.
func (self *inferHostEngine) forget(path string, model *inferHostModel) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.pathModels[path] != model {
		return false
	}
	delete(self.pathModels, path)
	return true
}

// One call's listener: its events to the call's emit until its first end or error, which it hands the call once;
// anything after, or after the call let it go, is dropped.
type inferHostListener struct {
	emit     InferEmit
	settings *InferSettings
	// the terminal: nil for end, else the call's error; buffered, sent once
	terminal chan error

	stateLock sync.Mutex
	ended     bool
}

// See SidecarLocalInferenceListener. Never blocks the host: emit holds what the router's reader has not taken.
func (self *inferHostListener) OnEvent(eventJson string) {
	ended := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.ended
	}()
	if ended {
		return
	}
	var event *InferEvent
	if len(eventJson) <= self.settings.EngineAnswerMaxByteCount {
		event = &InferEvent{}
		if json.Unmarshal([]byte(eventJson), event) != nil {
			event = nil
		}
	}
	switch {
	case event == nil:
		self.end(newInferError(InferErrorEngineFailed, "the app's engine sent an event that does not read"))
	case event.Kind == InferEventEnd:
		self.end(nil)
	case event.Kind == InferEventError:
		inferError := event.Error
		if inferError == nil {
			inferError = newInferError(InferErrorEngineFailed, "the app's engine failed")
		}
		self.end(inferError.clone())
	default:
		self.emit(event)
	}
}

// Ends the call with err, once: nil for its end.
func (self *inferHostListener) end(err error) {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.ended {
			return false
		}
		self.ended = true
		return true
	}()
	if first {
		self.terminal <- err
	}
}

// See InferLocalEngine: runs call on the app's engine.
func (self *inferHostEngine) Generate(ctx context.Context, call *InferCall, emit InferEmit) error {
	capabilities, err := self.hostCapabilities()
	if err != nil {
		return err
	}
	modelFile, backend, err := inferLocalModelFile(call.Entry, &capabilities.InferDeviceCapabilities)
	if err != nil {
		return err
	}
	if self.models == nil {
		return newInferError(InferErrorModelRefused, "no pulled model is reachable here")
	}
	path, err := self.models.WholePath(ctx, modelFile)
	if err != nil {
		if errors.Is(err, ErrInferModelNotWhole) {
			return newInferError(InferErrorModelRefused, "%s is not on this device yet: pull it first", call.Name)
		}
		return newInferError(InferErrorEngineFailed, "the model's file does not read: %s", err)
	}
	model, done, err := self.model(path, inferHostLoadSettingsFor(capabilities, backend, call.Entry.ContextWindow))
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
	encoded, err := json.Marshal(&inferHostRequest{
		Conversation: inferEngineConversationKey(request),
		Messages:     request.Messages,
		Tools:        request.Tools,
		ToolChoice:   request.ToolChoice,
		Schema:       request.Schema,
		MaxOutput:    request.MaxOutput,
		Sampling:     request.Sampling,
		Effort:       call.Effort,
	})
	if err != nil || self.settings.EngineRequestMaxByteCount < len(encoded) {
		release()
		return newInferError(InferErrorContextLength, "the request does not fit the app's engine")
	}
	emit(&InferEvent{Kind: InferEventStart})
	listener := &inferHostListener{emit: emit, settings: self.settings, terminal: make(chan error, 1)}
	generated := make(chan error, 1)
	go func() {
		generated <- self.host.Generate(model.handle, string(encoded), listener)
	}()
	for canceled := false; !canceled; {
		select {
		case err := <-listener.terminal:
			release()
			return err
		case err := <-generated:
			if err != nil {
				listener.end(newInferError(InferErrorEngineFailed, "the app's engine did not run the call: %s", err))
			}
			// a host whose Generate returns before its stream ends still sends its end
			generated = nil
		case <-ctx.Done():
			canceled = true
		}
	}
	// answered at once; the engine is freed once the host ends the generation, or past the cancel's bound
	self.host.Cancel(model.handle)
	go func() {
		select {
		case <-listener.terminal:
			release()
		case <-self.clock.After(self.settings.EngineCancelTimeout):
			// a host that does not stop is not trusted with the next call: the model is loaded again
			listener.end(nil)
			if self.forget(path, model) {
				self.host.Unload(model.handle)
			}
			release()
		}
	}()
	return newInferError(InferErrorCanceled, "the call's context ended")
}

// Lets the host go: every model unloaded once no call holds it, and calls after refused.
func (self *inferHostEngine) close() {
	models := func() []*inferHostModel {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		models := []*inferHostModel{}
		for _, model := range self.pathModels {
			models = append(models, model)
		}
		self.pathModels = map[string]*inferHostModel{}
		return models
	}()
	for _, model := range models {
		<-model.loaded
		if model.loadErr == nil {
			// in-flight calls end first: the host is asked to stop them, and the engine to free the model
			self.host.Cancel(model.handle)
			self.host.Unload(model.handle)
		}
	}
}
