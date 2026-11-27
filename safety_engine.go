//go:build !ios_extension && !sidecar_http

// The daemon's classifier on a desktop or in an enclave (DESIGN-COMPUTE §27.5's desktop and enclave rows; SAFE-M13-03):
// SafetyEngineScorer, the SafetyScorer over the ur-engine helper's classify methods (infer_engine_classify.go), which
// INFER's InferEngineProcess starts and speaks to (its Call), confined as §6.5 has the helper.
//
//   - One helper runs while classifications do. It starts at the first Load or Classify, and is ended once
//     SafetySettings.EngineIdleTimeout passes with none in flight; the next starts another (§27.5's "gone after 10 idle
//     minutes").
//   - The runtime library and the model are loaded into a helper only by their verified paths and pins, the
//     SafetyEngineFiles the release's store gives (SAFE-M13-05), and the helper checks each SHA-256 again before it
//     opens the file; a model is loaded into each new helper at its first classification there, so a handle outlives
//     the helper it was loaded in.
//   - A crash, a load or call the helper refuses, an answer that does not decode, a load past EngineLoadTimeout and a
//     call past DecisionTimeout each answer unavailable, never an allow, and end that helper; the next call starts a
//     new one. A caller's own cancel answers unavailable too, and leaves the helper to its other calls.
//   - A text's windows go in calls of at most EngineWindowMaxCount each.
//
// Nothing here reads a text: windows of ids come in, logits go out (R-SAFE-4). Safe for concurrent use; no helper call
// is made under the scorer's lock.

package sidecar

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// What the engine scorer runs a helper through: InferEngineProcess, whose Call starts its helper at the first call and
// whose Close ends it. One is made for each helper, and ended by Close.
type SafetyEngineProcess interface {
	// Runs one of the helper's extension methods: params encoded as JSON, the result decoded into result.
	Call(ctx context.Context, method string, params any, result any) error
	// Ends the helper, returning once it has.
	Close()
}

// The runtime library a device's classifier loads, verified on disk.
type SafetyRuntimeFile struct {
	// Its path, in the engine's directory the helper may read.
	Path string
	// Its SHA-256, the manifest's, in lowercase hex.
	Sha256 string
	// The OrtApi version the release pins.
	ApiVersion uint32
}

// The verified files the engine scorer loads, which the release's store gives (SafetyModelStore).
type SafetyEngineFiles interface {
	// The runtime library this device runs, verified; ErrSafetyUnavailable while there is none.
	Runtime(ctx context.Context) (*SafetyRuntimeFile, error)
	// The SHA-256 of the verified model at path; ErrSafetyUnavailable where path is not this device's verified model.
	ModelSha256(ctx context.Context, path string) (string, error)
}

// What NewSafetyEngineScorer builds on.
type SafetyEngineScorerArgs struct {
	// Makes a helper's process: the daemon's InferEngineProcess over the instance's engine and model directories, a
	// new one each time.
	NewProcess func() (SafetyEngineProcess, error)
	// The verified runtime and model.
	Files SafetyEngineFiles
	// Nil for the defaults.
	Settings *SafetySettings
	// Nil for real time.
	Clock Clock
	// Nil logs to connect's default logger.
	Log Logger
}

// The engine helper's classifier (see the file comment).
type SafetyEngineScorer struct {
	newProcess func() (SafetyEngineProcess, error)
	files      SafetyEngineFiles
	settings   *SafetySettings
	clock      Clock
	log        Logger

	stateLock sync.Mutex
	// the models Load readied, by handle
	models     map[int64]*safetyEngineModel
	nextHandle int64
	// the helper running, nil while none
	helper *safetyEngineHelper
	// the loads and calls in flight on helper
	callCount int
	// stops the idle timer, nil while none is set
	stopIdle func() bool
	// counts the idle timers set, so a timer set before the last call ends nothing
	idleGeneration uint64
	closed         bool
	// helpers being ended, which Close waits for
	ending sync.WaitGroup
}

// A model Load readied: its verified file.
type safetyEngineModel struct {
	path   string
	sha256 string
}

// One helper and the models loaded into it.
type safetyEngineHelper struct {
	process SafetyEngineProcess
	// each model's load in this helper, by the scorer's handle
	loads map[int64]*safetyEngineLoad
}

// One model's load in one helper: done closes once it answered.
type safetyEngineLoad struct {
	done   chan struct{}
	handle uint64
	err    error
}

// The scorer over args; it starts no helper until a model is loaded.
func NewSafetyEngineScorer(args *SafetyEngineScorerArgs) (*SafetyEngineScorer, error) {
	if args == nil || args.NewProcess == nil || args.Files == nil {
		return nil, safetyUnavailable("an engine scorer with no process or files")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultSafetySettings()
	}
	return &SafetyEngineScorer{
		newProcess: args.NewProcess,
		files:      args.Files,
		settings:   settings,
		clock:      clockOrReal(args.Clock),
		log:        loggerOrDefault(args.Log),
		models:     map[int64]*safetyEngineModel{},
	}, nil
}

// See SafetyScorer: the model at modelPath, if it is this device's verified model, loaded into the helper now, so a
// fault shows here; its handle reloads it into a later helper.
func (self *SafetyEngineScorer) Load(ctx context.Context, modelPath string) (int64, error) {
	sha256, err := self.files.ModelSha256(ctx, modelPath)
	if err != nil {
		return 0, safetyUnavailable("the model is not verified: %s", err)
	}
	handle, err := func() (int64, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return 0, safetyUnavailable("the engine scorer is closed")
		}
		self.nextHandle += 1
		self.models[self.nextHandle] = &safetyEngineModel{path: modelPath, sha256: sha256}
		return self.nextHandle, nil
	}()
	if err != nil {
		return 0, err
	}
	helper, _, err := self.acquire(ctx, handle)
	if err != nil {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.models, handle)
		}()
		return 0, err
	}
	self.release(helper, false)
	return handle, nil
}

// See SafetyScorer: windows in calls of at most EngineWindowMaxCount, each past DecisionTimeout ending the helper.
func (self *SafetyEngineScorer) Classify(ctx context.Context, handle int64, windows [][]int64) ([]SafetyLogits, error) {
	if len(windows) == 0 {
		return nil, safetyUnavailable("no windows")
	}
	logits := make([]SafetyLogits, 0, len(windows))
	for start := 0; start < len(windows); start += self.settings.EngineWindowMaxCount {
		batch := windows[start:min(start+self.settings.EngineWindowMaxCount, len(windows))]
		if err := safetyCheckWindows(batch, self.settings); err != nil {
			return nil, err
		}
		batchLogits, err := self.classify(ctx, handle, batch)
		if err != nil {
			return nil, err
		}
		logits = append(logits, batchLogits...)
	}
	return logits, nil
}

// One call of batch on the helper.
func (self *SafetyEngineScorer) classify(ctx context.Context, handle int64, batch [][]int64) ([]SafetyLogits, error) {
	helper, helperHandle, err := self.acquire(ctx, handle)
	if err != nil {
		return nil, err
	}
	windowsJson, err := safetyWindowsJson(batch)
	if err != nil {
		self.release(helper, false)
		return nil, err
	}
	result := &inferEngineClassifyResult{}
	timedOut, err := self.call(ctx, helper, self.settings.DecisionTimeout, inferEngineMethodClassify,
		&inferEngineClassifyParams{Handle: helperHandle, Windows: json.RawMessage(windowsJson)}, result)
	var logits []SafetyLogits
	if err == nil {
		logits, err = parseSafetyLogitsJson(result.Logits, len(batch))
	}
	// the helper is suspect after any failure but the caller's own cancel
	self.release(helper, err != nil && (timedOut || ctx.Err() == nil))
	if err != nil {
		if timedOut {
			return nil, safetyUnavailable("a classification past %s", self.settings.DecisionTimeout)
		}
		return nil, safetyUnavailable("the engine did not classify: %s", err)
	}
	return logits, nil
}

// Calls method on helper, bounded by timeout on the scorer's clock and by ctx; timedOut where the timeout ended it.
func (self *SafetyEngineScorer) call(ctx context.Context, helper *safetyEngineHelper, timeout time.Duration, method string, params any, result any) (timedOut bool, err error) {
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	expired := make(chan struct{})
	stop := self.clock.AfterFunc(timeout, func() {
		close(expired)
		cancel()
	})
	err = helper.process.Call(callCtx, method, params, result)
	// a call that answered stands, however late the timer
	if !stop() && err != nil {
		select {
		case <-expired:
			timedOut = true
		default:
		}
	}
	return timedOut, err
}

// The helper to call on, started where none runs, with handle's model loaded in it, and the model's handle there;
// counted as in flight until release. Waits for a load another call began.
func (self *SafetyEngineScorer) acquire(ctx context.Context, handle int64) (*safetyEngineHelper, uint64, error) {
	helper, model, err := self.take(handle)
	if err != nil {
		return nil, 0, err
	}
	if helper == nil {
		process, err := self.newProcess()
		if err != nil {
			self.untake()
			return nil, 0, safetyUnavailable("the engine helper does not start: %s", err)
		}
		helper = self.install(process)
	}
	load, first := func() (*safetyEngineLoad, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if load, ok := helper.loads[handle]; ok {
			return load, false
		}
		load := &safetyEngineLoad{done: make(chan struct{})}
		helper.loads[handle] = load
		return load, true
	}()
	if first {
		self.load(ctx, helper, model, load)
	}
	select {
	case <-load.done:
	case <-ctx.Done():
		self.release(helper, false)
		return nil, 0, safetyUnavailable("the classification was canceled")
	}
	if load.err != nil {
		// a failed load is the helper's, which goes; the next call starts another
		self.release(helper, true)
		return nil, 0, load.err
	}
	return helper, load.handle, nil
}

// The helper running, or nil where a new one is needed, and handle's model, counting the caller in flight.
func (self *SafetyEngineScorer) take(handle int64) (*safetyEngineHelper, *safetyEngineModel, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, nil, safetyUnavailable("the engine scorer is closed")
	}
	model, ok := self.models[handle]
	if !ok {
		return nil, nil, safetyUnavailable("no model of handle %d", handle)
	}
	self.callCount += 1
	self.idleGeneration += 1
	if self.stopIdle != nil {
		self.stopIdle()
		self.stopIdle = nil
	}
	return self.helper, model, nil
}

// Uncounts a caller whose helper never started.
func (self *SafetyEngineScorer) untake() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.callCount -= 1
	self.armIdleWithLock()
}

// Makes process the running helper, unless another call made one first, whose helper it answers instead, ending
// process.
func (self *SafetyEngineScorer) install(process SafetyEngineProcess) *safetyEngineHelper {
	helper, spare := func() (*safetyEngineHelper, SafetyEngineProcess) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.helper != nil {
			return self.helper, process
		}
		self.helper = &safetyEngineHelper{process: process, loads: map[int64]*safetyEngineLoad{}}
		return self.helper, nil
	}()
	if spare != nil {
		spare.Close()
	}
	return helper
}

// Loads model into helper as load, bounded by EngineLoadTimeout, then says it answered.
func (self *SafetyEngineScorer) load(ctx context.Context, helper *safetyEngineHelper, model *safetyEngineModel, load *safetyEngineLoad) {
	defer close(load.done)
	runtime, err := self.files.Runtime(ctx)
	if err != nil {
		load.err = safetyUnavailable("the runtime is not verified: %s", err)
		return
	}
	params := &inferEngineClassifyLoadParams{
		Runtime:            &inferEngineFile{Path: runtime.Path, Sha256: runtime.Sha256},
		Model:              &inferEngineFile{Path: model.path, Sha256: model.sha256},
		ApiVersion:         runtime.ApiVersion,
		IntraOpThreadCount: self.settings.EngineIntraOpThreadCount,
	}
	result := &inferEngineClassifyLoadResult{}
	timedOut, err := self.call(context.Background(), helper, self.settings.EngineLoadTimeout, inferEngineMethodClassifyLoad, params, result)
	switch {
	case timedOut:
		load.err = safetyUnavailable("the model did not load within %s", self.settings.EngineLoadTimeout)
	case err != nil:
		load.err = safetyUnavailable("the model does not load: %s", err)
	default:
		load.handle = result.Handle
	}
}

// Uncounts a caller of helper; failed ends helper, where it is still the one running, so the next call starts
// another. The last caller out sets the idle timer.
func (self *SafetyEngineScorer) release(helper *safetyEngineHelper, failed bool) {
	ended := func() *safetyEngineHelper {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.callCount -= 1
		var ended *safetyEngineHelper
		if failed && self.helper == helper {
			ended = helper
			self.helper = nil
		}
		self.armIdleWithLock()
		return ended
	}()
	if ended != nil {
		self.end(ended)
	}
}

// Sets the idle timer where no call is in flight and a helper runs. Called with stateLock held.
func (self *SafetyEngineScorer) armIdleWithLock() {
	if 0 < self.callCount || self.helper == nil || self.closed || self.stopIdle != nil {
		return
	}
	helper := self.helper
	self.idleGeneration += 1
	generation := self.idleGeneration
	// the clock may call on this goroutine, which holds the lock, so the check goes to a goroutine of its own
	self.stopIdle = self.clock.AfterFunc(self.settings.EngineIdleTimeout, func() {
		go self.idle(helper, generation)
	})
}

// Ends helper where it is still the one running, no call is in flight and no call came since the timer of generation
// was set: its idle time passed.
func (self *SafetyEngineScorer) idle(helper *safetyEngineHelper, generation uint64) {
	idle := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.helper != helper || 0 < self.callCount || self.closed || self.idleGeneration != generation {
			return false
		}
		self.helper = nil
		self.stopIdle = nil
		return true
	}()
	if idle {
		if self.log.V(2).Enabled() {
			self.log.Infof("[safety]the classifier's helper was idle %s, so it ends", self.settings.EngineIdleTimeout)
		}
		self.end(helper)
	}
}

// Ends helper's process on a goroutine of its own, which Close waits for, so a caller answers at once.
func (self *SafetyEngineScorer) end(helper *safetyEngineHelper) {
	self.ending.Add(1)
	go func() {
		defer self.ending.Done()
		helper.process.Close()
	}()
}

// See SafetyScorer: the model's handle gone, and the model unloaded from the helper running, where it is loaded there.
func (self *SafetyEngineScorer) Unload(handle int64) {
	helper, load := func() (*safetyEngineHelper, *safetyEngineLoad) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.models, handle)
		helper := self.helper
		if helper == nil {
			return nil, nil
		}
		load := helper.loads[handle]
		delete(helper.loads, handle)
		if load == nil {
			return nil, nil
		}
		self.callCount += 1
		self.idleGeneration += 1
		if self.stopIdle != nil {
			self.stopIdle()
			self.stopIdle = nil
		}
		return helper, load
	}()
	if helper == nil {
		return
	}
	<-load.done
	failed := false
	if load.err == nil {
		_, err := self.call(context.Background(), helper, self.settings.DecisionTimeout, inferEngineMethodClassifyUnload,
			&inferEngineClassifyUnloadParams{Handle: load.handle}, nil)
		failed = err != nil
	}
	self.release(helper, failed)
}

// Ends the helper running and every helper being ended; later calls answer unavailable.
func (self *SafetyEngineScorer) Close() {
	helper := func() *safetyEngineHelper {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		if self.stopIdle != nil {
			self.stopIdle()
			self.stopIdle = nil
		}
		helper := self.helper
		self.helper = nil
		return helper
	}()
	if helper != nil {
		self.end(helper)
	}
	self.ending.Wait()
}
