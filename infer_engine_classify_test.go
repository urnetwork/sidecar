//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The classify methods in the engine helper (infer_engine_classify.go; SAFE-M13-03), over a stand-in for ONNX
// Runtime's function table that keeps every object it hands out, so a test sees each tensor's shape and that nothing a
// call makes outlives it; and over the helper's own protocol, JSON lines through infer_engine_helper.go's loop. The
// binding itself, purego over a real library, runs only in a hand run on each desktop (External).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// One tensor the stand-in made.
type testOrtTensor struct {
	shape       []int64
	elementType int32
	int64s      []int64
	float32s    []float32
}

// A stand-in for ONNX Runtime: the API versions up to version, objects by kind, and the logits score gives a window.
type testOrt struct {
	version uint32
	// the logits a window gets, by its ids
	score func(ids []int64) (benign float32, malicious float32)

	stateLock sync.Mutex
	next      uintptr
	// every live object, by its kind: env, options, session, value, info, status
	live     map[uintptr]string
	tensors  map[uintptr]*testOrtTensor
	infos    map[uintptr]*testOrtTensor
	statuses map[uintptr]string
	// what was asked of it
	opened      []string
	threads     []int32
	sessionPath []string
	runShapes   [][]int64
	// a Run answering this message as a status; empty runs
	failRun string
	// the logits' shape and type a Run answers
	logitsShape []int64
	logitsType  int32
	// the inputs a session reports
	inputCount uintptr
}

// The stand-in offering versions up to version, scoring a window as malicious by its ids' sum.
func newTestOrt(version uint32) *testOrt {
	return &testOrt{
		version: version,
		score: func(ids []int64) (float32, float32) {
			sum := int64(0)
			for _, id := range ids {
				sum += id
			}
			return float32(-sum % 7), float32(sum % 5)
		},
		next:        0x1000,
		live:        map[uintptr]string{},
		tensors:     map[uintptr]*testOrtTensor{},
		infos:       map[uintptr]*testOrtTensor{},
		statuses:    map[uintptr]string{},
		logitsShape: []int64{1, 2},
		logitsType:  ortElementTypeFloat,
		inputCount:  2,
	}
}

// A new object of kind. Called with stateLock held.
func (self *testOrt) objectWithLock(kind string) uintptr {
	self.next += 16
	self.live[self.next] = kind
	return self.next
}

// A status answering message. Called with stateLock held.
func (self *testOrt) statusWithLock(message string) uintptr {
	status := self.objectWithLock("status")
	self.statuses[status] = message
	return status
}

// The live objects of kind.
func (self *testOrt) liveCount(kind string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, liveKind := range self.live {
		if liveKind == kind {
			count += 1
		}
	}
	return count
}

// Releases object, failing on one not live or of another kind.
func (self *testOrt) release(kind string, object uintptr) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.live[object] != kind {
		panic(fmt.Sprintf("released %d as a %s, which is a %q", object, kind, self.live[object]))
	}
	delete(self.live, object)
	delete(self.tensors, object)
	delete(self.infos, object)
	delete(self.statuses, object)
}

// The stand-in as the library the binding would open.
func (self *testOrt) open(path string) (*ortLibrary, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.opened = append(self.opened, path)
	return &ortLibrary{
		getApi: func(version uint32) uintptr {
			if self.version < version {
				return 0
			}
			return 0xa91
		},
		versionString: func() string {
			return fmt.Sprintf("1.%d.0", self.version)
		},
		bind: func(api uintptr) (*ortApi, error) {
			if api != 0xa91 {
				return nil, errors.New("not the table GetApi answered")
			}
			return self.api(), nil
		},
	}, nil
}

// The stand-in's function table.
func (self *testOrt) api() *ortApi {
	locked := func(work func() uintptr) uintptr {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return work()
	}
	return &ortApi{
		getErrorCode: func(status uintptr) int32 {
			return 1
		},
		getErrorMessage: func(status uintptr) string {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.statuses[status]
		},
		releaseStatus: func(status uintptr) {
			self.release("status", status)
		},
		createEnv: func(logLevel int32, logId string, env *uintptr) uintptr {
			return locked(func() uintptr {
				*env = self.objectWithLock("env")
				return 0
			})
		},
		disableTelemetryEvents: func(env uintptr) uintptr {
			return 0
		},
		releaseEnv: func(env uintptr) {
			self.release("env", env)
		},
		createSessionOptions: func(options *uintptr) uintptr {
			return locked(func() uintptr {
				*options = self.objectWithLock("options")
				return 0
			})
		},
		setIntraOpNumThreads: func(options uintptr, threadCount int32) uintptr {
			return locked(func() uintptr {
				self.threads = append(self.threads, threadCount)
				return 0
			})
		},
		releaseSessionOptions: func(options uintptr) {
			self.release("options", options)
		},
		createSession: func(env uintptr, modelPath string, options uintptr, session *uintptr) uintptr {
			return locked(func() uintptr {
				if self.live[env] != "env" || self.live[options] != "options" {
					return self.statusWithLock("no environment or options")
				}
				self.sessionPath = append(self.sessionPath, modelPath)
				*session = self.objectWithLock("session")
				return 0
			})
		},
		sessionGetInputCount: func(session uintptr, count *uintptr) uintptr {
			return locked(func() uintptr {
				*count = self.inputCount
				return 0
			})
		},
		sessionGetOutputCount: func(session uintptr, count *uintptr) uintptr {
			*count = 1
			return 0
		},
		releaseSession: func(session uintptr) {
			self.release("session", session)
		},
		getAllocatorWithDefaultOptions: func(allocator *uintptr) uintptr {
			*allocator = 0xa110c
			return 0
		},
		createTensorAsOrtValue: func(allocator uintptr, shape []int64, elementType int32, value *uintptr) uintptr {
			return locked(func() uintptr {
				if allocator != 0xa110c || elementType != ortElementTypeInt64 {
					return self.statusWithLock("not the allocator or not int64")
				}
				count := int64(1)
				for _, dimension := range shape {
					count *= dimension
				}
				*value = self.objectWithLock("value")
				self.tensors[*value] = &testOrtTensor{shape: slices.Clone(shape), elementType: elementType, int64s: make([]int64, count)}
				return 0
			})
		},
		getTensorMutableData: func(value uintptr, data *uintptr) uintptr {
			return locked(func() uintptr {
				if self.live[value] != "value" {
					return self.statusWithLock("no such value")
				}
				*data = value
				return 0
			})
		},
		int64s: func(data uintptr, count int) []int64 {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.tensors[data].int64s[:count]
		},
		float32s: func(data uintptr, count int) []float32 {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.tensors[data].float32s[:count]
		},
		run: func(session uintptr, inputNames []string, inputs []uintptr, outputNames []string, outputs []uintptr) uintptr {
			return locked(func() uintptr {
				if self.live[session] != "session" {
					return self.statusWithLock("no session")
				}
				if !slices.Equal(inputNames, []string{ortInputIdsName, ortAttentionMaskName}) || !slices.Equal(outputNames, []string{ortLogitsName}) || len(outputs) != 1 {
					return self.statusWithLock("not the model's names")
				}
				ids, mask := self.tensors[inputs[0]], self.tensors[inputs[1]]
				if ids == nil || mask == nil || !slices.Equal(ids.shape, mask.shape) {
					return self.statusWithLock("inputs of two shapes")
				}
				self.runShapes = append(self.runShapes, slices.Clone(ids.shape))
				for _, one := range mask.int64s {
					if one != 1 {
						return self.statusWithLock("a mask that is not all ones")
					}
				}
				if self.failRun != "" {
					return self.statusWithLock(self.failRun)
				}
				benign, malicious := self.score(ids.int64s)
				outputs[0] = self.objectWithLock("value")
				self.tensors[outputs[0]] = &testOrtTensor{shape: slices.Clone(self.logitsShape), elementType: self.logitsType, float32s: []float32{benign, malicious}}
				return 0
			})
		},
		getTensorTypeAndShape: func(value uintptr, info *uintptr) uintptr {
			return locked(func() uintptr {
				*info = self.objectWithLock("info")
				self.infos[*info] = self.tensors[value]
				return 0
			})
		},
		getTensorElementType: func(info uintptr, elementType *int32) uintptr {
			return locked(func() uintptr {
				*elementType = self.infos[info].elementType
				return 0
			})
		},
		getDimensionsCount: func(info uintptr, count *uintptr) uintptr {
			return locked(func() uintptr {
				*count = uintptr(len(self.infos[info].shape))
				return 0
			})
		},
		getDimensions: func(info uintptr, dimensions []int64) uintptr {
			return locked(func() uintptr {
				copy(dimensions, self.infos[info].shape)
				return 0
			})
		},
		releaseTensorTypeAndShapeInfo: func(info uintptr) {
			self.release("info", info)
		},
		releaseValue: func(value uintptr) {
			self.release("value", value)
		},
	}
}

// A file at directory/name holding content, and its pin.
func testSafetyPinnedFile(t testing.TB, directory string, name string, content string) *inferEngineFile {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(content))
	return &inferEngineFile{Path: path, Sha256: hex.EncodeToString(digest[:])}
}

// A runtime library's and a model's files and classify_load's params over them at apiVersion.
func testSafetyClassifyLoadParams(t testing.TB, apiVersion uint32) *inferEngineClassifyLoadParams {
	t.Helper()
	directory := t.TempDir()
	return &inferEngineClassifyLoadParams{
		Runtime:            testSafetyPinnedFile(t, directory, "libonnxruntime.test", "runtime library"),
		Model:              testSafetyPinnedFile(t, directory, "Llama-Prompt-Guard-2-22M-ur-int8.onnx", "model weights"),
		ApiVersion:         apiVersion,
		IntraOpThreadCount: 3,
	}
}

// The windows' logits as the stand-in scores them.
func testOrtLogits(ort *testOrt, windows [][]int64) []SafetyLogits {
	logits := []SafetyLogits{}
	for _, window := range windows {
		benign, malicious := ort.score(window)
		logits = append(logits, SafetyLogits{Benign: float64(benign), Malicious: float64(malicious)})
	}
	return logits
}

// The protocol over the helper's loop: a load, two windows scored with their two tensors each of [1, n] and the logits
// read, the runtime bound once with its threads, every value, shape and status released, then an unload releasing the
// session and refusing the handle after it.
func TestEngineClassifyProtocol(t *testing.T) {
	ort := newTestOrt(20)
	classify := newInferEngineClassify(ort.open, DefaultSafetySettings())
	world := newTestInferEngineHelperWorld(t, &testInferEngineBackend{}, classify.methods())
	params := testSafetyClassifyLoadParams(t, 20)
	loaded := &inferEngineClassifyLoadResult{}
	world.result(t, world.send(t, inferEngineMethodClassifyLoad, params), loaded)
	if loaded.Handle == 0 || !slices.Equal(ort.opened, []string{params.Runtime.Path}) || !slices.Equal(ort.sessionPath, []string{params.Model.Path}) {
		t.Fatalf("handle %d, opened %v, sessions %v", loaded.Handle, ort.opened, ort.sessionPath)
	}
	if !slices.Equal(ort.threads, []int32{3}) {
		t.Errorf("intra-op threads %v", ort.threads)
	}
	windows := [][]int64{{1, 40, 41, 2}, {1, 2}}
	windowsJson, _ := safetyWindowsJson(windows)
	result := &inferEngineClassifyResult{}
	world.result(t, world.send(t, inferEngineMethodClassify, &inferEngineClassifyParams{Handle: loaded.Handle, Windows: json.RawMessage(windowsJson)}), result)
	logits, err := parseSafetyLogitsJson(result.Logits, 2)
	if err != nil || !slices.Equal(logits, testOrtLogits(ort, windows)) {
		t.Fatalf("logits %v, %v", logits, err)
	}
	if !slices.EqualFunc(ort.runShapes, [][]int64{{1, 4}, {1, 2}}, slices.Equal) {
		t.Errorf("run shapes %v", ort.runShapes)
	}
	for _, kind := range []string{"value", "info", "status", "options"} {
		if count := ort.liveCount(kind); count != 0 {
			t.Errorf("%d %s left live", count, kind)
		}
	}
	// a second model binds no second runtime
	second := testSafetyClassifyLoadParams(t, 20)
	second.Runtime = params.Runtime
	world.result(t, world.send(t, inferEngineMethodClassifyLoad, second), &inferEngineClassifyLoadResult{})
	if len(ort.opened) != 1 || ort.liveCount("env") != 1 || ort.liveCount("session") != 2 {
		t.Errorf("opened %v, %d environments, %d sessions", ort.opened, ort.liveCount("env"), ort.liveCount("session"))
	}
	world.result(t, world.send(t, inferEngineMethodClassifyUnload, &inferEngineClassifyUnloadParams{Handle: loaded.Handle}), nil)
	if ort.liveCount("session") != 1 {
		t.Errorf("%d sessions after an unload", ort.liveCount("session"))
	}
	id := world.send(t, inferEngineMethodClassify, &inferEngineClassifyParams{Handle: loaded.Handle, Windows: json.RawMessage(windowsJson)})
	if answer := world.next(t); answer.Id != id || answer.Error == nil || answer.Error.Code != InferErrorEngineFailed {
		t.Errorf("a classification after the unload: %+v", answer)
	}
}

// A library whose API base offers no table at the pinned version is refused, and so is a second runtime in one helper.
func TestEngineClassifyRefusesARuntimeBelowItsPin(t *testing.T) {
	ort := newTestOrt(18)
	classify := newInferEngineClassify(ort.open, DefaultSafetySettings())
	raw, _ := json.Marshal(testSafetyClassifyLoadParams(t, 20))
	if _, err := classify.load(raw); err == nil || !strings.Contains(err.Error(), "offers no API version 20") {
		t.Errorf("a library below the pin: %v", err)
	}
	if ort.liveCount("env") != 0 || ort.liveCount("session") != 0 {
		t.Errorf("a refused library left objects")
	}
	ort.version = 20
	if _, err := classify.load(raw); err != nil {
		t.Fatal(err)
	}
	other, _ := json.Marshal(testSafetyClassifyLoadParams(t, 20))
	if _, err := classify.load(other); err == nil || !strings.Contains(err.Error(), "second runtime") {
		t.Errorf("a second runtime: %v", err)
	}
}

// A file off its pin is refused before anything opens it: the runtime and the model each.
func TestEngineClassifyRefusesAFileOffItsPin(t *testing.T) {
	for _, change := range []func(params *inferEngineClassifyLoadParams){
		func(params *inferEngineClassifyLoadParams) {
			params.Model.Sha256 = strings.Repeat("0", 64)
		},
		func(params *inferEngineClassifyLoadParams) {
			params.Runtime.Sha256 = strings.Repeat("0", 64)
		},
		func(params *inferEngineClassifyLoadParams) {
			os.WriteFile(params.Model.Path, []byte("other weights"), 0o600)
		},
	} {
		ort := newTestOrt(20)
		classify := newInferEngineClassify(ort.open, DefaultSafetySettings())
		params := testSafetyClassifyLoadParams(t, 20)
		change(params)
		raw, _ := json.Marshal(params)
		if _, err := classify.load(raw); err == nil || !strings.Contains(err.Error(), "pin") {
			t.Errorf("a file off its pin: %v", err)
		}
		if len(ort.opened) != 0 {
			t.Errorf("a file off its pin was opened")
		}
	}
}

// A status the runtime answers fails the classification with its message, and the call's tensors and the status are
// released all the same; so are logits of another shape or type, and a model of other inputs.
func TestEngineClassifyRuntimeFaults(t *testing.T) {
	windowsJson, _ := safetyWindowsJson([][]int64{{1, 7, 2}})
	faults := []struct {
		name  string
		fault func(ort *testOrt)
		want  string
	}{
		{name: "a status", fault: func(ort *testOrt) { ort.failRun = "out of memory" }, want: "out of memory"},
		{name: "logits of three", fault: func(ort *testOrt) { ort.logitsShape = []int64{1, 3} }, want: "not float [1 2]"},
		{name: "logits of doubles", fault: func(ort *testOrt) { ort.logitsType = 11 }, want: "not float [1 2]"},
	}
	for _, fault := range faults {
		ort := newTestOrt(20)
		classify := newInferEngineClassify(ort.open, DefaultSafetySettings())
		raw, _ := json.Marshal(testSafetyClassifyLoadParams(t, 20))
		handle, err := classify.load(raw)
		if err != nil {
			t.Fatal(err)
		}
		fault.fault(ort)
		params, _ := json.Marshal(&inferEngineClassifyParams{Handle: handle, Windows: json.RawMessage(windowsJson)})
		if _, err := classify.classify(params); err == nil || !strings.Contains(err.Error(), fault.want) {
			t.Errorf("%s: %v", fault.name, err)
		}
		for _, kind := range []string{"value", "info", "status"} {
			if count := ort.liveCount(kind); count != 0 {
				t.Errorf("%s: %d %s left live", fault.name, count, kind)
			}
		}
	}
	ort := newTestOrt(20)
	ort.inputCount = 3
	classify := newInferEngineClassify(ort.open, DefaultSafetySettings())
	raw, _ := json.Marshal(testSafetyClassifyLoadParams(t, 20))
	if _, err := classify.load(raw); err == nil || !strings.Contains(err.Error(), "3 inputs") {
		t.Errorf("a model of three inputs: %v", err)
	}
	if ort.liveCount("session") != 0 {
		t.Errorf("a refused model's session left live")
	}
}

// Windows the helper may not be given are refused before the runtime sees them.
func TestEngineClassifyRefusesWindowsPastTheirBounds(t *testing.T) {
	ort := newTestOrt(20)
	classify := newInferEngineClassify(ort.open, DefaultSafetySettings())
	raw, _ := json.Marshal(testSafetyClassifyLoadParams(t, 20))
	handle, err := classify.load(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, windows := range []string{"[]", "[[1]]", "[[1,-3,2]]", "[[1," + strings.Repeat("5,", 512) + "2]]"} {
		params, _ := json.Marshal(&inferEngineClassifyParams{Handle: handle, Windows: json.RawMessage(windows)})
		if _, err := classify.classify(params); err == nil {
			t.Errorf("%.40s: classified", windows)
		}
	}
	if len(ort.runShapes) != 0 {
		t.Errorf("the runtime ran %d windows", len(ort.runShapes))
	}
}
