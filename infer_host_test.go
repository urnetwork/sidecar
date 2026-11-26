//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The app's host as the router's local engine (infer_host.go, infer_host_engine.go; INFER-M11-06): a call through the
// router reaching a stand-in host with the model's whole file and the load settings §6.5 asks, the host's events
// streamed back, FP32 activations on iOS's GPUs and Adreno's alone, a model not pulled refused before any load, a
// host's late event after a cancel dropped, a model loaded once and unloaded past the bound, and no request reaching a
// server for a local call (IC-5).

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// One load the stand-in host took.
type testInferHostLoad struct {
	path     string
	settings *inferHostLoadSettings
}

// A stand-in for an app's LiteRT-LM: it reports capabilities, records each load, request, cancel and unload, and runs
// each generation on a goroutine of its own, as an app's engine calls back on its own thread.
type testInferHost struct {
	capabilities string

	stateLock  sync.Mutex
	loads      []*testInferHostLoad
	requests   []*inferHostRequest
	cancels    []int64
	unloads    []int64
	nextHandle int64
	// each generation's listener, in order
	listeners []SidecarLocalInferenceListener
	// what each generation does: nil sends "hello", usage and end
	generate func(handle int64, request *inferHostRequest, listener SidecarLocalInferenceListener)
	// closed at each cancel
	canceled chan struct{}
}

// A host on device, its GPU gpu.
func newTestInferHost(device *InferDeviceCapabilities, gpu string) *testInferHost {
	encoded, _ := json.Marshal(&inferHostCapabilities{InferDeviceCapabilities: *device.clone(), Gpu: gpu})
	return &testInferHost{capabilities: string(encoded), canceled: make(chan struct{}, 16)}
}

func (self *testInferHost) Capabilities() string {
	return self.capabilities
}

func (self *testInferHost) Load(modelPath string, settingsJson string) (int64, error) {
	settings := &inferHostLoadSettings{}
	if err := json.Unmarshal([]byte(settingsJson), settings); err != nil {
		return 0, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nextHandle += 1
	self.loads = append(self.loads, &testInferHostLoad{path: modelPath, settings: settings})
	return self.nextHandle, nil
}

func (self *testInferHost) Generate(handle int64, requestJson string, listener SidecarLocalInferenceListener) error {
	request := &inferHostRequest{}
	if err := json.Unmarshal([]byte(requestJson), request); err != nil {
		return err
	}
	generate := func() func(handle int64, request *inferHostRequest, listener SidecarLocalInferenceListener) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requests = append(self.requests, request)
		self.listeners = append(self.listeners, listener)
		return self.generate
	}()
	go func() {
		if generate != nil {
			generate(handle, request, listener)
			return
		}
		listener.OnEvent(`{"kind":"text","text":"hello"}`)
		listener.OnEvent(`{"kind":"usage","usage":{"input_tokens":3,"output_tokens":1,"cached_tokens":0,"reasoning_tokens":0}}`)
		listener.OnEvent(`{"kind":"end"}`)
	}()
	return nil
}

func (self *testInferHost) Cancel(handle int64) {
	self.stateLock.Lock()
	self.cancels = append(self.cancels, handle)
	self.stateLock.Unlock()
	self.canceled <- struct{}{}
}

func (self *testInferHost) Unload(handle int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.unloads = append(self.unloads, handle)
}

// What the host took.
func (self *testInferHost) taken() ([]*testInferHostLoad, []*inferHostRequest, []int64, []int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.loads), slices.Clone(self.requests), slices.Clone(self.cancels), slices.Clone(self.unloads)
}

// Model files by their SHA-256: a path for each one pulled whole, ErrInferModelNotWhole for any other.
type testInferModelFiles struct {
	stateLock sync.Mutex
	paths     map[string]string
}

// See InferModelFiles.
func (self *testInferModelFiles) WholePath(ctx context.Context, file *InferManifestModelFile) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	path, ok := self.paths[file.Sha256]
	if !ok {
		return "", ErrInferModelNotWhole
	}
	return path, nil
}

// A router whose local engine is host's engine over files, with checks that pass every call.
func newTestInferHostRouter(t *testing.T, host *testInferHost, files InferModelFiles, settings *InferSettings) (*inferRouter, *inferHostEngine) {
	t.Helper()
	if settings == nil {
		settings = DefaultInferSettings()
	}
	router, err := newInferRouter(&inferRouterArgs{Settings: settings, Manifest: testInferManifest(), Checker: &testInferPassChecker{}})
	if err != nil {
		t.Fatal(err)
	}
	engine := newInferHostEngine(&inferHostEngineArgs{Host: host, Models: files, Settings: settings})
	router.setLocalEngine(engine)
	t.Cleanup(engine.close)
	return router, engine
}

// The files of model a device of platform loads: its GPU build on the phones, else the file every accelerator loads.
func testInferHostFiles(model string, platform string) *testInferModelFiles {
	manifestModel := testInferManifest().Model(model)
	paths := map[string]string{}
	for _, file := range manifestModel.Files {
		if file.servesPlatform(platform) {
			paths[file.Sha256] = "/data/app/models/" + file.Sha256
		}
	}
	return &testInferModelFiles{paths: paths}
}

// A local call through the router reaches the app's engine with the whole file of the build this device loads, the
// load settings it asks and the conversation, and its events come back in order; a second call loads nothing again.
func TestHostEngineRoundTrip(t *testing.T) {
	device := testInferDevice("android/arm64", InferDeviceClassPhone, 8, false, InferAcceleratorGpu)
	host := newTestInferHost(device, "Mali-G715")
	files := testInferHostFiles("gemma-4-e2b", "android/arm64")
	router, _ := newTestInferHostRouter(t, host, files, nil)
	runId := NewId()
	request := testInferRequest("local-gemma-4-e2b-off", "")
	request.RunId = &runId
	for range 2 {
		events, err := router.Infer(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		all := testInferDrain(t, events)
		if kinds := testInferKinds(all); !slices.Equal(kinds, []InferEventKind{InferEventStart, InferEventText, InferEventUsage, InferEventEnd}) {
			t.Fatalf("events %v", kinds)
		}
		if testInferText(all) != "hello" {
			t.Errorf("text %q", testInferText(all))
		}
	}
	loads, requests, _, _ := host.taken()
	gpuFile := testInferManifest().Model("gemma-4-e2b").Files[1]
	if len(loads) != 1 || loads[0].path != "/data/app/models/"+gpuFile.Sha256 {
		t.Fatalf("loads %+v", loads)
	}
	if loads[0].settings.Backend != "gpu" || loads[0].settings.MaxTokenCount != 32*1024 || loads[0].settings.Activations != "" {
		t.Errorf("load settings %+v", loads[0].settings)
	}
	if len(requests) != 2 || len(requests[0].Messages) != 1 || requests[0].Messages[0].Text() != "hello" || requests[0].Effort != InferEffortOff {
		t.Fatalf("requests %+v", requests)
	}
	// the conversation is an opaque key, the same for the run's two calls, and never the run's id
	if requests[0].Conversation == "" || requests[0].Conversation != requests[1].Conversation ||
		strings.Contains(requests[0].Conversation, runId.String()) {
		t.Errorf("conversation %q, %q", requests[0].Conversation, requests[1].Conversation)
	}
	// the catalog's local view is the app's device
	catalog, err := router.Catalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if device := catalog.Device(); device == nil || device.Platform != "android/arm64" || device.Class != InferDeviceClassPhone {
		t.Errorf("the catalog's device %+v", catalog.Device())
	}
}

// FP32 activations exactly where FP16 corrupts digits: iOS's GPU and Adreno's; another GPU, and any CPU, keep the
// engine's own (#3913, #4001).
func TestHostSettingsFp32OnIosAndAdreno(t *testing.T) {
	cases := []struct {
		platform    string
		gpu         string
		accelerator []InferAccelerator
		backend     string
		activations string
	}{
		{platform: "ios/arm64", gpu: "Apple A18 Pro GPU", accelerator: []InferAccelerator{InferAcceleratorGpu}, backend: "gpu", activations: "fp32"},
		{platform: "android/arm64", gpu: "Adreno (TM) 750", accelerator: []InferAccelerator{InferAcceleratorGpu}, backend: "gpu", activations: "fp32"},
		{platform: "android/arm64", gpu: "Mali-G715", accelerator: []InferAccelerator{InferAcceleratorGpu}, backend: "gpu", activations: ""},
		{platform: "ios/arm64", gpu: "", accelerator: nil, backend: "cpu", activations: ""},
		{platform: "android/arm64", gpu: "Adreno (TM) 750", accelerator: nil, backend: "cpu", activations: ""},
	}
	for i, c := range cases {
		device := testInferDevice(c.platform, InferDeviceClassPhone, 8, c.platform == "ios/arm64", c.accelerator...)
		host := newTestInferHost(device, c.gpu)
		router, _ := newTestInferHostRouter(t, host, testInferHostFiles("gemma-4-e2b", c.platform), nil)
		events, err := router.Infer(context.Background(), testInferRequest("local-gemma-4-e2b-off", ""))
		if err != nil {
			t.Fatal(err)
		}
		testInferDrain(t, events)
		loads, _, _, _ := host.taken()
		if len(loads) != 1 || loads[0].settings.Backend != c.backend || loads[0].settings.Activations != c.activations {
			t.Errorf("case %d: loads %+v", i, loads)
		}
	}
}

// A model whose file is not whole is refused, naming the pull, and nothing loads.
func TestHostModelNotPulledRefused(t *testing.T) {
	device := testInferDevice("ios/arm64", InferDeviceClassPhone, 8, true, InferAcceleratorGpu)
	host := newTestInferHost(device, "Apple A18 Pro GPU")
	router, _ := newTestInferHostRouter(t, host, &testInferModelFiles{paths: map[string]string{}}, nil)
	events, err := router.Infer(context.Background(), testInferRequest("local-gemma-4-e2b-off", ""))
	if err != nil {
		t.Fatal(err)
	}
	all := testInferDrain(t, events)
	last := all[len(all)-1]
	if last.Kind != InferEventError || last.Error.Code != InferErrorModelRefused || !strings.Contains(last.Error.Message, "pull") {
		t.Fatalf("a model not pulled: %+v", last)
	}
	if loads, _, _, _ := host.taken(); len(loads) != 0 {
		t.Errorf("a model not pulled was loaded: %+v", loads)
	}
}

// A canceled call answers at once; the host is told to stop, and what it sends after, whatever it is, reaches no call:
// the next call gets its own events alone.
func TestHostLateEventAfterCancelDropped(t *testing.T) {
	device := testInferDevice("ios/arm64", InferDeviceClassPhone, 8, true, InferAcceleratorGpu)
	host := newTestInferHost(device, "Apple A18 Pro GPU")
	started := make(chan SidecarLocalInferenceListener, 1)
	host.generate = func(handle int64, request *inferHostRequest, listener SidecarLocalInferenceListener) {
		started <- listener
	}
	router, _ := newTestInferHostRouter(t, host, testInferHostFiles("gemma-4-e2b", "ios/arm64"), nil)
	ctx, cancel := context.WithCancel(context.Background())
	events, err := router.Infer(ctx, testInferRequest("local-gemma-4-e2b-off", ""))
	if err != nil {
		t.Fatal(err)
	}
	var first SidecarLocalInferenceListener
	select {
	case first = <-started:
	case <-time.After(testInferWait):
		t.Fatal("the host was never asked to generate")
	}
	first.OnEvent(`{"kind":"text","text":"before"}`)
	cancel()
	all := testInferDrain(t, events)
	if last := all[len(all)-1]; last.Kind != InferEventError || last.Error.Code != InferErrorCanceled {
		t.Fatalf("a canceled call ended %+v", last)
	}
	select {
	case <-host.canceled:
	case <-time.After(testInferWait):
		t.Fatal("the host was never told to cancel")
	}
	// the host's late events, an end among them, free the engine and reach nothing
	host.generate = nil
	first.OnEvent(`{"kind":"text","text":"late"}`)
	first.OnEvent(`{"kind":"error","error":{"code":"canceled","message":"stopped"}}`)
	events, err = router.Infer(context.Background(), testInferRequest("local-gemma-4-e2b-off", ""))
	if err != nil {
		t.Fatal(err)
	}
	next := testInferDrain(t, events)
	if testInferText(next) != "hello" || next[len(next)-1].Kind != InferEventEnd {
		t.Errorf("the next call got %+v", next)
	}
}

// A second model's call unloads the first once it is idle, a phone holding one model (HostLoadedModelMaxCount).
func TestHostEngineUnloadsPastItsBound(t *testing.T) {
	device := testInferDevice("android/arm64", InferDeviceClassPhone, 16, false)
	host := newTestInferHost(device, "")
	files := testInferHostFiles("gemma-4-e2b", "android/arm64")
	for sha, path := range testInferHostFiles("gemma-4-e4b", "android/arm64").paths {
		files.paths[sha] = path
	}
	router, _ := newTestInferHostRouter(t, host, files, nil)
	for _, model := range []string{"local-gemma-4-e2b-off", "local-gemma-4-e4b-off"} {
		events, err := router.Infer(context.Background(), testInferRequest(model, ""))
		if err != nil {
			t.Fatal(err)
		}
		if all := testInferDrain(t, events); all[len(all)-1].Kind != InferEventEnd {
			t.Fatalf("%s ended %+v", model, all[len(all)-1])
		}
	}
	loads, _, _, unloads := host.taken()
	if len(loads) != 2 || !slices.Equal(unloads, []int64{1}) {
		t.Errorf("loads %d, unloads %v", len(loads), unloads)
	}
}

// Capabilities that do not read, or name a platform or class the manifest does not, leave no local model listed, with
// the reason.
func TestHostCapabilitiesReadStrictly(t *testing.T) {
	for _, capabilities := range []string{
		`not json`,
		`{"platform":"plan9/amd64","class":"phone","memory_byte_count":1,"accelerators":[]}`,
		`{"platform":"ios/arm64","class":"watch","memory_byte_count":1,"accelerators":[]}`,
		`{"platform":"ios/arm64","class":"phone","memory_byte_count":1,"accelerators":["tpu"]}`,
		`{"platform":"ios/arm64","class":"phone","memory_byte_count":1,"accelerators":[],"secret":"x"}`,
	} {
		host := &testInferHost{capabilities: capabilities, canceled: make(chan struct{}, 1)}
		router, engine := newTestInferHostRouter(t, host, &testInferModelFiles{}, nil)
		if _, err := engine.Capabilities(context.Background()); !errors.Is(err, &InferError{Code: InferErrorEngineFailed}) {
			t.Errorf("%s was read: %v", capabilities, err)
		}
		catalog, err := router.Catalog(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(catalog.Entries()) != 0 || catalog.LocalUnavailable() == "" {
			t.Errorf("%s listed %d local models", capabilities, len(catalog.Entries()))
		}
	}
}
