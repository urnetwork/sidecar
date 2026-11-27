//go:build !ios_extension && !sidecar_http

// The safety classifier in the engine helper (DESIGN-COMPUTE §27.5's desktop row, §6.5; SAFE-M13-03): ONNX Runtime
// scoring token windows with the release's Prompt Guard 2 export, in the ur-engine helper beside LiteRT-LM, under the
// helper's confinement: it holds no key, reads only its engine and model files, and has no network (question
// compute-plan-safe-engine-binary, QD-1370: the helper's methods, not a second engine process in ur). The daemon's side
// is SafetyEngineScorer (safety_engine.go).
//
// The helper's extension methods (infer_engine_helper.go's registry), over its JSON lines:
//
//	classify_load    {runtime, model, api_version, intra_op_thread_count} → {handle}: ONNX Runtime's C library and
//	                 the model file, each with the SHA-256 the release pins, which the helper checks before it opens
//	                 either; the API version the release pins; and the threads a classification computes with
//	classify         {handle, windows} → {logits}: windows of token ids, SafetyScorer's JSON, one [benign, malicious]
//	                 pair a window
//	classify_unload  {handle} → {}
//
// The runtime is ONNX Runtime's C API: its OrtGetApiBase, then the OrtApi function table at the pinned version, which a
// library older than that answers with nothing and is refused; an environment once a helper, then a session a model,
// with intra-op threads from the load. Each window runs alone, batch 1, so no padding enters a score: input_ids and
// attention_mask int64 tensors of [1, n], the ids and n ones, allocated by the runtime's own allocator, and the logits
// output, which must be float [1, 2]. Every tensor and shape a run makes is released before the next, whatever failed,
// and a status the runtime answers is read and released.
//
// The function table is ortApi, Go functions over the C API's arguments: the binding fills it from the library through
// purego (infer_engine_classify_ort.go, only under the ur_engine build tag, which the helper's executable sets, so ur and
// the sdk link no binding), and the tests from a stand-in table. This file holds the classify methods' logic and links
// on every compute leg; only the ur_engine build registers the methods, from the binding's file.
//
// Safe for concurrent use: the helper runs each method call on its own goroutine. Loads run one at a time; a model's
// classifications run one at a time on its session, and its unload waits for the one in flight.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// The classify methods' names.
const (
	inferEngineMethodClassifyLoad   = "classify_load"
	inferEngineMethodClassify       = "classify"
	inferEngineMethodClassifyUnload = "classify_unload"
)

// The model's tensors, by the names Prompt Guard 2's export gives them.
const (
	ortInputIdsName      = "input_ids"
	ortAttentionMaskName = "attention_mask"
	ortLogitsName        = "logits"
)

// ONNX Runtime's enum values the binding passes and reads: ONNXTensorElementDataType's float and int64, and
// OrtLoggingLevel's error, so only errors reach the helper's stderr.
const (
	ortElementTypeFloat  = 1
	ortElementTypeInt64  = 7
	ortLoggingLevelError = 3
)

// The environment's log id.
const ortLogId = "ur-engine-classify"

// ONNX Runtime's C API as the classify methods call it: each function the OrtApi table holds that they use, with Go's
// types for C's, and two readers of the runtime's memory. Statuses are OrtStatus pointers, 0 for success; every other
// uintptr is the runtime's own object.
type ortApi struct {
	getErrorCode                   func(status uintptr) int32
	getErrorMessage                func(status uintptr) string
	releaseStatus                  func(status uintptr)
	createEnv                      func(logLevel int32, logId string, env *uintptr) uintptr
	disableTelemetryEvents         func(env uintptr) uintptr
	releaseEnv                     func(env uintptr)
	createSessionOptions           func(options *uintptr) uintptr
	setIntraOpNumThreads           func(options uintptr, threadCount int32) uintptr
	releaseSessionOptions          func(options uintptr)
	createSession                  func(env uintptr, modelPath string, options uintptr, session *uintptr) uintptr
	sessionGetInputCount           func(session uintptr, count *uintptr) uintptr
	sessionGetOutputCount          func(session uintptr, count *uintptr) uintptr
	releaseSession                 func(session uintptr)
	getAllocatorWithDefaultOptions func(allocator *uintptr) uintptr
	createTensorAsOrtValue         func(allocator uintptr, shape []int64, elementType int32, value *uintptr) uintptr
	getTensorMutableData           func(value uintptr, data *uintptr) uintptr
	getTensorTypeAndShape          func(value uintptr, info *uintptr) uintptr
	getTensorElementType           func(info uintptr, elementType *int32) uintptr
	getDimensionsCount             func(info uintptr, count *uintptr) uintptr
	getDimensions                  func(info uintptr, dimensions []int64) uintptr
	releaseTensorTypeAndShapeInfo  func(info uintptr)
	run                            func(session uintptr, inputNames []string, inputs []uintptr, outputNames []string, outputs []uintptr) uintptr
	releaseValue                   func(value uintptr)
	// count values at data, the runtime's memory, which stays its own
	int64s   func(data uintptr, count int) []int64
	float32s func(data uintptr, count int) []float32
}

// What the binding opens a runtime library as: its OrtApiBase, and how its OrtApi table at an address becomes an
// ortApi.
type ortLibrary struct {
	// The OrtApi table at version, or 0 where the library does not offer it: one older than the version.
	getApi func(version uint32) uintptr
	// The library's own version, for a refusal's words.
	versionString func() string
	bind          func(api uintptr) (*ortApi, error)
}

// Nil for a status of 0; else the runtime's code and message for call, the status released.
func (self *ortApi) check(call string, status uintptr) error {
	if status == 0 {
		return nil
	}
	code := self.getErrorCode(status)
	message := self.getErrorMessage(status)
	self.releaseStatus(status)
	return fmt.Errorf("onnx runtime's %s answered %d: %s", call, code, message)
}

// classify_load's params.
type inferEngineClassifyLoadParams struct {
	// ONNX Runtime's C library, which the helper loads with purego.
	Runtime *inferEngineFile `json:"runtime"`
	// The exported model.
	Model *inferEngineFile `json:"model"`
	// The OrtApi version the release pins.
	ApiVersion uint32 `json:"api_version"`
	// ONNX Runtime's intra-op threads for the model's session.
	IntraOpThreadCount int `json:"intra_op_thread_count"`
}

// classify_load's result.
type inferEngineClassifyLoadResult struct {
	Handle uint64 `json:"handle"`
}

// classify's params.
type inferEngineClassifyParams struct {
	Handle  uint64          `json:"handle"`
	Windows json.RawMessage `json:"windows"`
}

// classify's result: SafetyScorer's logits JSON.
type inferEngineClassifyResult struct {
	Logits json.RawMessage `json:"logits"`
}

// classify_unload's params.
type inferEngineClassifyUnloadParams struct {
	Handle uint64 `json:"handle"`
}

// The classify methods over one helper's runtime (see the file comment).
type inferEngineClassify struct {
	// opens the runtime's library at a checked path: the binding's, or a test's stand-in
	open     func(path string) (*ortLibrary, error)
	settings *SafetySettings

	// loads run one at a time, the first binding the runtime
	loadLock sync.Mutex
	// the runtime loaded, set once by the first load
	runtime *inferEngineClassifyRuntime

	stateLock  sync.Mutex
	sessions   map[uint64]*inferEngineClassifySession
	nextHandle uint64
}

// The runtime a helper loaded: its library's file, the version bound, the table and the environment.
type inferEngineClassifyRuntime struct {
	file       inferEngineFile
	apiVersion uint32
	api        *ortApi
	env        uintptr
	allocator  uintptr
}

// One model's session; its classifications run one at a time.
type inferEngineClassifySession struct {
	runLock sync.Mutex
	session uintptr
	// released by its unload; a classification after it refuses
	released bool
}

// The classify methods, which open a runtime through open, bounded by settings.
func newInferEngineClassify(open func(path string) (*ortLibrary, error), settings *SafetySettings) *inferEngineClassify {
	return &inferEngineClassify{open: open, settings: settings, sessions: map[uint64]*inferEngineClassifySession{}}
}

// The methods by their names, for the helper's registry.
func (self *inferEngineClassify) methods() map[string]InferEngineMethod {
	return map[string]InferEngineMethod{
		inferEngineMethodClassifyLoad: func(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
			handle, err := self.load(params)
			if err != nil {
				return nil, err
			}
			return json.Marshal(&inferEngineClassifyLoadResult{Handle: handle})
		},
		inferEngineMethodClassify: func(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
			logits, err := self.classify(params)
			if err != nil {
				return nil, err
			}
			return json.Marshal(&inferEngineClassifyResult{Logits: json.RawMessage(logits)})
		},
		inferEngineMethodClassifyUnload: func(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
			if err := self.unload(params); err != nil {
				return nil, err
			}
			return json.Marshal(struct{}{})
		},
	}
}

// A classify method's failure, as the helper answers it.
func inferEngineClassifyError(format string, a ...any) error {
	return newInferError(InferErrorEngineFailed, "%s", fmt.Sprintf(format, a...))
}

// Checks load's files against their pins, binds the runtime where none is yet, and opens a session on the model.
func (self *inferEngineClassify) load(rawParams json.RawMessage) (uint64, error) {
	params := &inferEngineClassifyLoadParams{}
	if err := json.Unmarshal(rawParams, params); err != nil || params.Runtime == nil || params.Model == nil || params.ApiVersion == 0 || params.IntraOpThreadCount < 1 {
		return 0, inferEngineClassifyError("classify_load's params do not read")
	}
	for _, file := range []*inferEngineFile{params.Runtime, params.Model} {
		if err := inferEngineCheckFile(file); err != nil {
			return 0, inferEngineClassifyError("%s", err)
		}
	}
	self.loadLock.Lock()
	defer self.loadLock.Unlock()
	runtime, err := self.bind(params)
	if err != nil {
		return 0, err
	}
	api := runtime.api
	options := uintptr(0)
	if err := api.check("CreateSessionOptions", api.createSessionOptions(&options)); err != nil {
		return 0, inferEngineClassifyError("%s", err)
	}
	defer api.releaseSessionOptions(options)
	if err := api.check("SetIntraOpNumThreads", api.setIntraOpNumThreads(options, int32(params.IntraOpThreadCount))); err != nil {
		return 0, inferEngineClassifyError("%s", err)
	}
	session := uintptr(0)
	if err := api.check("CreateSession", api.createSession(runtime.env, params.Model.Path, options, &session)); err != nil {
		return 0, inferEngineClassifyError("%s", err)
	}
	inputCount, outputCount := uintptr(0), uintptr(0)
	err = errors.Join(api.check("SessionGetInputCount", api.sessionGetInputCount(session, &inputCount)),
		api.check("SessionGetOutputCount", api.sessionGetOutputCount(session, &outputCount)))
	if err == nil && (inputCount != 2 || outputCount < 1) {
		err = fmt.Errorf("a model of %d inputs and %d outputs, not input_ids and attention_mask to logits", inputCount, outputCount)
	}
	if err != nil {
		api.releaseSession(session)
		return 0, inferEngineClassifyError("%s", err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nextHandle += 1
	self.sessions[self.nextHandle] = &inferEngineClassifySession{session: session}
	return self.nextHandle, nil
}

// The helper's runtime: params' library bound at its version by the first load, its environment made; a later load
// must name the same library and version, since one helper binds one. Called under loadLock.
func (self *inferEngineClassify) bind(params *inferEngineClassifyLoadParams) (*inferEngineClassifyRuntime, error) {
	if self.runtime != nil {
		if self.runtime.file != *params.Runtime || self.runtime.apiVersion != params.ApiVersion {
			return nil, inferEngineClassifyError("a second runtime in one helper")
		}
		return self.runtime, nil
	}
	library, err := self.open(params.Runtime.Path)
	if err != nil {
		return nil, inferEngineClassifyError("the runtime does not open: %s", err)
	}
	address := library.getApi(params.ApiVersion)
	if address == 0 {
		return nil, inferEngineClassifyError("the runtime, version %s, offers no API version %d, which the release pins", library.versionString(), params.ApiVersion)
	}
	api, err := library.bind(address)
	if err != nil {
		return nil, inferEngineClassifyError("the runtime does not bind: %s", err)
	}
	runtime := &inferEngineClassifyRuntime{file: *params.Runtime, apiVersion: params.ApiVersion, api: api}
	if err := api.check("CreateEnv", api.createEnv(ortLoggingLevelError, ortLogId, &runtime.env)); err != nil {
		return nil, inferEngineClassifyError("%s", err)
	}
	if err := errors.Join(api.check("DisableTelemetryEvents", api.disableTelemetryEvents(runtime.env)),
		api.check("GetAllocatorWithDefaultOptions", api.getAllocatorWithDefaultOptions(&runtime.allocator))); err != nil {
		api.releaseEnv(runtime.env)
		return nil, inferEngineClassifyError("%s", err)
	}
	self.runtime = runtime
	return runtime, nil
}

// Scores classify's windows on its handle's session, one at a time.
func (self *inferEngineClassify) classify(rawParams json.RawMessage) (string, error) {
	params := &inferEngineClassifyParams{}
	if err := json.Unmarshal(rawParams, params); err != nil {
		return "", inferEngineClassifyError("classify's params do not read")
	}
	windows, err := parseSafetyWindowsJson(params.Windows, self.settings)
	if err != nil {
		return "", inferEngineClassifyError("%s", err)
	}
	session := func() *inferEngineClassifySession {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.sessions[params.Handle]
	}()
	if session == nil {
		return "", inferEngineClassifyError("no model of handle %d", params.Handle)
	}
	session.runLock.Lock()
	defer session.runLock.Unlock()
	if session.released {
		return "", inferEngineClassifyError("no model of handle %d", params.Handle)
	}
	logits := make([]SafetyLogits, 0, len(windows))
	for _, window := range windows {
		pair, err := self.runWindow(session.session, window)
		if err != nil {
			return "", inferEngineClassifyError("%s", err)
		}
		logits = append(logits, pair)
	}
	return safetyLogitsJson(logits)
}

// One window through the model: its two tensors in, the logits out, every value released before it returns.
func (self *inferEngineClassify) runWindow(session uintptr, window []int64) (SafetyLogits, error) {
	runtime := self.runtime
	api := runtime.api
	values := []uintptr{}
	defer func() {
		for _, value := range values {
			api.releaseValue(value)
		}
	}()
	tensor := func(fill func(data []int64)) (uintptr, error) {
		value := uintptr(0)
		if err := api.check("CreateTensorAsOrtValue", api.createTensorAsOrtValue(runtime.allocator, []int64{1, int64(len(window))}, ortElementTypeInt64, &value)); err != nil {
			return 0, err
		}
		values = append(values, value)
		data := uintptr(0)
		if err := api.check("GetTensorMutableData", api.getTensorMutableData(value, &data)); err != nil {
			return 0, err
		}
		fill(api.int64s(data, len(window)))
		return value, nil
	}
	inputIds, err := tensor(func(data []int64) {
		copy(data, window)
	})
	if err != nil {
		return SafetyLogits{}, err
	}
	attentionMask, err := tensor(func(data []int64) {
		for i := range data {
			data[i] = 1
		}
	})
	if err != nil {
		return SafetyLogits{}, err
	}
	outputs := []uintptr{0}
	status := api.run(session, []string{ortInputIdsName, ortAttentionMaskName}, []uintptr{inputIds, attentionMask}, []string{ortLogitsName}, outputs)
	if outputs[0] != 0 {
		values = append(values, outputs[0])
	}
	if err := api.check("Run", status); err != nil {
		return SafetyLogits{}, err
	}
	if outputs[0] == 0 {
		return SafetyLogits{}, errors.New("the model answered no logits")
	}
	info := uintptr(0)
	if err := api.check("GetTensorTypeAndShape", api.getTensorTypeAndShape(outputs[0], &info)); err != nil {
		return SafetyLogits{}, err
	}
	elementType, dimensionCount := int32(0), uintptr(0)
	err = errors.Join(api.check("GetTensorElementType", api.getTensorElementType(info, &elementType)),
		api.check("GetDimensionsCount", api.getDimensionsCount(info, &dimensionCount)))
	dimensions := []int64{}
	if err == nil && dimensionCount == 2 {
		dimensions = make([]int64, 2)
		err = api.check("GetDimensions", api.getDimensions(info, dimensions))
	}
	api.releaseTensorTypeAndShapeInfo(info)
	if err != nil {
		return SafetyLogits{}, err
	}
	if elementType != ortElementTypeFloat || len(dimensions) != 2 || dimensions[0] != 1 || dimensions[1] != 2 {
		return SafetyLogits{}, fmt.Errorf("logits of type %d and shape %v, not float [1 2]", elementType, dimensions)
	}
	data := uintptr(0)
	if err := api.check("GetTensorMutableData", api.getTensorMutableData(outputs[0], &data)); err != nil {
		return SafetyLogits{}, err
	}
	pair := api.float32s(data, 2)
	logits := SafetyLogits{Benign: float64(pair[0]), Malicious: float64(pair[1])}
	if _, err := logits.MaliciousBasisPoints(); err != nil {
		return SafetyLogits{}, err
	}
	return logits, nil
}

// Releases unload's handle's session once a classification in flight on it ends.
func (self *inferEngineClassify) unload(rawParams json.RawMessage) error {
	params := &inferEngineClassifyUnloadParams{}
	if err := json.Unmarshal(rawParams, params); err != nil {
		return inferEngineClassifyError("classify_unload's params do not read")
	}
	session := func() *inferEngineClassifySession {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		session := self.sessions[params.Handle]
		delete(self.sessions, params.Handle)
		return session
	}()
	if session == nil {
		return inferEngineClassifyError("no model of handle %d", params.Handle)
	}
	session.runLock.Lock()
	defer session.runLock.Unlock()
	session.released = true
	self.runtime.api.releaseSession(session.session)
	return nil
}
