//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The environment variable that makes this test binary an engine helper, naming what its stand-in does.
const testInferEngineHelperVariable = "UR_TEST_INFER_ENGINE_HELPER"

// Not a test: InferEngineProcess's tests start this binary as ur-engine with -test.run naming it, and it serves the
// helper's protocol over the stand-in, then exits. A message "crash" ends the process mid-stream; "block" waits for its
// cancel; any other is echoed. test_environment answers the process's whole environment.
func TestInferEngineHelperProcess(t *testing.T) {
	if os.Getenv(testInferEngineHelperVariable) == "" {
		return
	}
	backend := &testInferEngineBackend{}
	backend.answer = func(conversation *testInferEngineConversation, message *inferEngineMessage, chunk func(chunk *inferEngineChunk)) (*InferUsage, error) {
		switch message.Content[0].Text {
		case "crash":
			chunk(&inferEngineChunk{Text: "partial"})
			os.Exit(3)
		case "block":
			chunk(&inferEngineChunk{Text: "waiting"})
			<-conversation.canceled
			return nil, errInferEngineCanceled
		}
		return testInferEngineEcho(conversation, message, chunk)
	}
	methods := map[string]InferEngineMethod{
		"test_environment": func(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
			return json.Marshal(os.Environ())
		},
	}
	if err := inferEngineHelperServe(context.Background(), os.Stdin, os.Stdout, backend, methods, DefaultInferSettings()); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// A desktop engine whose helper is this test binary, over a manifest of one model whose files are pulled, and the
// call that runs it.
type testInferEngineProcessWorld struct {
	process *InferEngineProcess
	call    *InferCall
	model   string
}

// The world on this platform; skips a platform no engine is built for.
func newTestInferEngineProcessWorld(t *testing.T, pulled bool) *testInferEngineProcessWorld {
	t.Helper()
	platform := runtime.GOOS + "/" + runtime.GOARCH
	if !slices.Contains(inferDesktopPlatforms, platform) {
		t.Skipf("no engine runs on %s", platform)
	}
	engineDirectory, modelDirectory := t.TempDir(), t.TempDir()
	write := func(directory string, name string, content string) InferManifestFile {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		file := testInferManifestFile(name, int64(len(content)))
		file.Sha256 = testInferSha256(content)
		return file
	}
	library := write(engineDirectory, "liblitert-lm.bin", "engine library")
	modelFile := write(modelDirectory, "test-model.litertlm", "model weights")
	if !pulled {
		os.Remove(filepath.Join(modelDirectory, modelFile.Name))
	}
	model := testInferManifestModel("test-model", 1, 32*1024)
	model.Files = []*InferManifestModelFile{{InferManifestFile: modelFile}}
	manifest := &InferManifest{
		Version: 1,
		Engines: []*InferManifestEngine{{Platform: platform, Version: "v0.19.1", Libraries: []*InferManifestFile{&library}}},
		Models:  []*InferManifestModel{model},
	}
	device := testInferDevice(platform, InferDeviceClassDesktop, 64, false)
	process, err := NewInferEngineProcess(&InferEngineProcessArgs{
		HelperPath:      os.Args[0],
		HelperArgs:      []string{"-test.run=^TestInferEngineHelperProcess$"},
		HelperEnv:       []string{testInferEngineHelperVariable + "=on"},
		EngineDirectory: engineDirectory,
		ModelDirectory:  modelDirectory,
		Manifest:        manifest,
		Capabilities:    device,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(process.Close)
	catalog, err := NewInferLocalCatalog(manifest, device, DefaultInferSettings())
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := catalog.Resolve("local-test-model-off", "")
	if err != nil {
		t.Fatal(err)
	}
	return &testInferEngineProcessWorld{
		process: process,
		call:    &InferCall{Entry: resolution.Entry, Effort: resolution.Effort, Name: resolution.Name},
		model:   "local-test-model-off",
	}
}

// Events a Generate emits, kept for the test.
type testInferEmitted struct {
	stateLock sync.Mutex
	events    []*InferEvent
	// closed at the first event of kind first
	first     chan struct{}
	firstKind InferEventKind
	firstOnce sync.Once
}

// See InferEmit.
func (self *testInferEmitted) emit(event *InferEvent) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, event)
	if self.first != nil && event.Kind == self.firstKind {
		self.firstOnce.Do(func() {
			close(self.first)
		})
	}
}

// What was emitted.
func (self *testInferEmitted) all() []*InferEvent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

// A call of world's model with one user message.
func (self *testInferEngineProcessWorld) callWith(text string) *InferCall {
	call := *self.call
	agentId := NewId()
	call.Request = &InferRequest{Model: self.model, Messages: []*InferMessage{testInferUserMessage(text)}, AgentId: &agentId}
	return &call
}

// A call runs on the model's helper process: start once it holds an engine, the answer, its usage; a second call reuses
// the helper, one a loaded model.
func TestEngineProcessGeneratesOnItsHelper(t *testing.T) {
	world := newTestInferEngineProcessWorld(t, true)
	for _, text := range []string{"hello", "again"} {
		emitted := &testInferEmitted{}
		if err := world.process.Generate(context.Background(), world.callWith(text), emitted.emit); err != nil {
			t.Fatal(err)
		}
		if testInferText(emitted.all()) != "echo: "+text || testInferKinds(emitted.all())[0] != InferEventStart {
			t.Errorf("answered %v %q", testInferKinds(emitted.all()), testInferText(emitted.all()))
		}
	}
	if len(world.process.models) != 1 {
		t.Errorf("%d helpers for one model", len(world.process.models))
	}
}

// A helper that crashes mid-call answers engine_failed, and the daemon runs on: the model's next call starts a new
// helper and is answered.
func TestEngineHelperCrashAnswersEngineFailed(t *testing.T) {
	world := newTestInferEngineProcessWorld(t, true)
	emitted := &testInferEmitted{}
	err := world.process.Generate(context.Background(), world.callWith("crash"), emitted.emit)
	if code := InferErrorCodeOf(err); code != InferErrorEngineFailed {
		t.Fatalf("a crashed helper answered %v", err)
	}
	emitted = &testInferEmitted{}
	if err := world.process.Generate(context.Background(), world.callWith("after"), emitted.emit); err != nil {
		t.Fatalf("the next call: %v", err)
	}
	if testInferText(emitted.all()) != "echo: after" {
		t.Errorf("the next call answered %q", testInferText(emitted.all()))
	}
}

// A canceled call returns at once, and its engine is free again once the helper has stopped it: the next call runs.
func TestEngineProcessCancelReturnsAtOnce(t *testing.T) {
	world := newTestInferEngineProcessWorld(t, true)
	// one engine, so the next call runs only once the canceled one has given it back
	world.process.settings.EngineInstanceMaxCount = 1
	ctx, cancel := context.WithCancel(context.Background())
	emitted := &testInferEmitted{first: make(chan struct{}), firstKind: InferEventText}
	returned := make(chan error, 1)
	go func() {
		returned <- world.process.Generate(ctx, world.callWith("block"), emitted.emit)
	}()
	select {
	case <-emitted.first:
	case <-time.After(testInferWait):
		t.Fatal("the call did not start")
	}
	cancel()
	select {
	case err := <-returned:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("the canceled call returned %v", err)
		}
	case <-time.After(testInferWait):
		t.Fatal("the canceled call did not return")
	}
	next := &testInferEmitted{}
	if err := world.process.Generate(context.Background(), world.callWith("next"), next.emit); err != nil {
		t.Fatalf("the next call: %v", err)
	}
	if testInferText(next.all()) != "echo: next" {
		t.Errorf("the next call answered %q", testInferText(next.all()))
	}
}

// The helper gets the environment its args name and nothing of the daemon's.
func TestEngineProcessPassesOnlyItsEnvironment(t *testing.T) {
	world := newTestInferEngineProcessWorld(t, true)
	t.Setenv("UR_TEST_INFER_ENGINE_SECRET", "a value the helper must not see")
	environment := []string{}
	if err := world.process.Call(context.Background(), "test_environment", struct{}{}, &environment); err != nil {
		t.Fatal(err)
	}
	for _, variable := range environment {
		name, _, _ := strings.Cut(variable, "=")
		if name != testInferEngineHelperVariable && !(runtime.GOOS == "windows" && strings.EqualFold(name, "SYSTEMROOT")) {
			t.Errorf("the helper sees %s", name)
		}
	}
	if err := world.process.Call(context.Background(), inferEngineMethodLoad, struct{}{}, nil); err == nil {
		t.Error("Call ran a built-in method")
	}
}

// A model whose file is not on the device is refused, the person told to pull it, and no helper starts.
func TestEngineProcessRefusesAModelNotPulled(t *testing.T) {
	world := newTestInferEngineProcessWorld(t, false)
	err := world.process.Generate(context.Background(), world.callWith("hello"), (&testInferEmitted{}).emit)
	if code := InferErrorCodeOf(err); code != InferErrorModelRefused || !strings.Contains(err.Error(), "pull") {
		t.Errorf("a model not pulled: %v", err)
	}
	if len(world.process.models) != 0 {
		t.Error("a helper started for a model not pulled")
	}
}
