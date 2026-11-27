//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The daemon's engine classifier (safety_engine.go; SAFE-M13-03): over helpers that run the real classify methods on
// the stand-in runtime, in this process or, once, as INFER's InferEngineProcess starts them, this test binary as
// ur-engine; with a clock the test moves, so the idle exit and a decision past its time happen when the test says.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// A Clock a test moves: each AfterFunc is reported on armed with its timeout, and runs once Advance passes it.
type testSafetyClock struct {
	stateLock sync.Mutex
	now       time.Time
	timers    []*testSafetyTimer
	armed     chan time.Duration
}

// One timer of a testSafetyClock.
type testSafetyTimer struct {
	at       time.Time
	function func()
	done     bool
}

// A fixed start, so a test repeats.
func newTestSafetyClock() *testSafetyClock {
	return &testSafetyClock{now: time.Date(2026, time.November, 27, 9, 0, 0, 0, time.UTC), armed: make(chan time.Duration, 1024)}
}

func (self *testSafetyClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *testSafetyClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	self.AfterFunc(timeout, func() {
		fired <- self.Now()
	})
	return fired
}

func (self *testSafetyClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	timer := func() *testSafetyTimer {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		timer := &testSafetyTimer{at: self.now.Add(timeout), function: function}
		self.timers = append(self.timers, timer)
		return timer
	}()
	self.armed <- timeout
	return func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if timer.done {
			return false
		}
		timer.done = true
		return true
	}
}

// Moves the clock by, running each timer it passes, outside the clock's lock.
func (self *testSafetyClock) Advance(by time.Duration) {
	due := func() []*testSafetyTimer {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.now = self.now.Add(by)
		due := []*testSafetyTimer{}
		for _, timer := range self.timers {
			if !timer.done && !self.now.Before(timer.at) {
				timer.done = true
				due = append(due, timer)
			}
		}
		return due
	}()
	for _, timer := range due {
		timer.function()
	}
}

// Waits until a timer of timeout is armed, passing over others.
func (self *testSafetyClock) awaitArmed(t *testing.T, timeout time.Duration) {
	t.Helper()
	for {
		select {
		case armed := <-self.armed:
			if armed == timeout {
				return
			}
		case <-time.After(testInferWait):
			t.Fatalf("no timer of %s armed", timeout)
		}
	}
}

// Helpers that run the classify methods in this process, one stand-in runtime each, with a crash, a hang and a
// mangled answer a test can set.
type testSafetyProcesses struct {
	stateLock sync.Mutex
	started   []*testSafetyProcess
	// methods called, in order, across helpers
	methods []string
	// the next call ends its helper as a crash would
	crash bool
	// a classify waits for its context's end
	hang bool
	// a classify's logits lose their last pair
	short bool
	// closed once per helper ended
	ended chan *testSafetyProcess
}

// One in-process helper.
type testSafetyProcess struct {
	processes *testSafetyProcesses
	ort       *testOrt
	classify  *inferEngineClassify

	stateLock sync.Mutex
	closed    bool
}

func newTestSafetyProcesses() *testSafetyProcesses {
	return &testSafetyProcesses{ended: make(chan *testSafetyProcess, 64)}
}

// See SafetyEngineScorerArgs.NewProcess.
func (self *testSafetyProcesses) newProcess() (SafetyEngineProcess, error) {
	ort := newTestOrt(20)
	process := &testSafetyProcess{processes: self, ort: ort, classify: newInferEngineClassify(ort.open, DefaultSafetySettings())}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.started = append(self.started, process)
	return process, nil
}

// How many helpers were started, and the methods called.
func (self *testSafetyProcesses) seen() (int, []string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.started), slices.Clone(self.methods)
}

// Sets a fault under the lock.
func (self *testSafetyProcesses) set(fault func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	fault()
}

// Waits for the next helper to end.
func (self *testSafetyProcesses) awaitEnded(t *testing.T) *testSafetyProcess {
	t.Helper()
	select {
	case process := <-self.ended:
		return process
	case <-time.After(testInferWait):
		t.Fatal("no helper ended")
	}
	return nil
}

// See SafetyEngineProcess: the method run in this process, as InferEngineProcess.Call would on its helper.
func (self *testSafetyProcess) Call(ctx context.Context, method string, params any, result any) error {
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.closed
	}()
	if closed {
		return newInferError(InferErrorEngineFailed, "the engine process is closed")
	}
	crash, hang, short := false, false, false
	self.processes.set(func() {
		self.processes.methods = append(self.processes.methods, method)
		crash, hang, short = self.processes.crash, self.processes.hang, self.processes.short
	})
	if crash {
		return newInferError(InferErrorEngineFailed, "the engine process ended")
	}
	if hang && method == inferEngineMethodClassify {
		<-ctx.Done()
		return ctx.Err()
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		return err
	}
	answer, err := self.classify.methods()[method](ctx, encoded)
	if err != nil {
		return err
	}
	if short && method == inferEngineMethodClassify {
		answered := &inferEngineClassifyResult{}
		json.Unmarshal(answer, answered)
		pairs := [][]float64{}
		json.Unmarshal(answered.Logits, &pairs)
		answered.Logits, _ = json.Marshal(pairs[:len(pairs)-1])
		answer, _ = json.Marshal(answered)
	}
	if result != nil {
		return json.Unmarshal(answer, result)
	}
	return nil
}

// See SafetyEngineProcess.
func (self *testSafetyProcess) Close() {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		first := !self.closed
		self.closed = true
		return first
	}()
	if first {
		self.processes.ended <- self
	}
}

// The verified files as a store would give them: the runtime and one model, at their pins.
type testSafetyEngineFiles struct {
	runtime *SafetyRuntimeFile
	model   *inferEngineFile
}

func newTestSafetyEngineFiles(t testing.TB) *testSafetyEngineFiles {
	t.Helper()
	params := testSafetyClassifyLoadParams(t, 20)
	return &testSafetyEngineFiles{
		runtime: &SafetyRuntimeFile{Path: params.Runtime.Path, Sha256: params.Runtime.Sha256, ApiVersion: 20},
		model:   params.Model,
	}
}

func (self *testSafetyEngineFiles) Runtime(ctx context.Context) (*SafetyRuntimeFile, error) {
	return self.runtime, nil
}

func (self *testSafetyEngineFiles) ModelSha256(ctx context.Context, path string) (string, error) {
	if path != self.model.Path {
		return "", safetyUnavailable("not the verified model")
	}
	return self.model.Sha256, nil
}

// A scorer over in-process helpers, on a moved clock, at settings, closed at the test's end.
func newTestSafetyEngineScorer(t *testing.T, settings *SafetySettings) (*SafetyEngineScorer, *testSafetyProcesses, *testSafetyEngineFiles, *testSafetyClock) {
	t.Helper()
	processes := newTestSafetyProcesses()
	files := newTestSafetyEngineFiles(t)
	clock := newTestSafetyClock()
	scorer, err := NewSafetyEngineScorer(&SafetyEngineScorerArgs{NewProcess: processes.newProcess, Files: files, Settings: settings, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(scorer.Close)
	return scorer, processes, files, clock
}

// windows of n ids each, the specials around them.
func testSafetyEngineWindows(count int) [][]int64 {
	windows := [][]int64{}
	for i := range count {
		windows = append(windows, []int64{1, int64(100 + i), int64(200 + 3*i), 2})
	}
	return windows
}

// A load and a classification: one helper, the model loaded once, the windows in calls of the settings' bound, and the
// logits in their order.
func TestSafetyEngineScorerClassifies(t *testing.T) {
	settings := DefaultSafetySettings()
	settings.EngineWindowMaxCount = 2
	scorer, processes, files, _ := newTestSafetyEngineScorer(t, settings)
	handle, err := scorer.Load(context.Background(), files.model.Path)
	if err != nil {
		t.Fatal(err)
	}
	windows := testSafetyEngineWindows(5)
	logits, err := scorer.Classify(context.Background(), handle, windows)
	if err != nil {
		t.Fatal(err)
	}
	started, methods := processes.seen()
	if !slices.Equal(logits, testOrtLogits(processes.started[0].ort, windows)) {
		t.Errorf("logits %v", logits)
	}
	want := []string{inferEngineMethodClassifyLoad, inferEngineMethodClassify, inferEngineMethodClassify, inferEngineMethodClassify}
	if started != 1 || !slices.Equal(methods, want) {
		t.Errorf("%d helpers, methods %v", started, methods)
	}
	if _, err := scorer.Load(context.Background(), files.model.Path+".other"); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("a model that is not the verified one: %v", err)
	}
}

// Idle for EngineIdleTimeout, the helper ends; the next classification starts another and loads the model in it again,
// under the same handle.
func TestSafetyEngineScorerIdleExitAndRestart(t *testing.T) {
	settings := DefaultSafetySettings()
	scorer, processes, files, clock := newTestSafetyEngineScorer(t, settings)
	handle, err := scorer.Load(context.Background(), files.model.Path)
	if err != nil {
		t.Fatal(err)
	}
	clock.awaitArmed(t, settings.EngineIdleTimeout)
	clock.Advance(settings.EngineIdleTimeout - time.Second)
	select {
	case <-processes.ended:
		t.Fatal("the helper ended before its idle time")
	default:
	}
	clock.Advance(time.Second)
	ended := processes.awaitEnded(t)
	if ended != processes.started[0] {
		t.Fatal("another helper ended")
	}
	windows := testSafetyEngineWindows(1)
	logits, err := scorer.Classify(context.Background(), handle, windows)
	if err != nil {
		t.Fatal(err)
	}
	started, methods := processes.seen()
	if started != 2 || !slices.Equal(methods, []string{inferEngineMethodClassifyLoad, inferEngineMethodClassifyLoad, inferEngineMethodClassify}) {
		t.Errorf("%d helpers, methods %v", started, methods)
	}
	if !slices.Equal(logits, testOrtLogits(processes.started[1].ort, windows)) {
		t.Errorf("logits %v", logits)
	}
}

// A crash answers unavailable and ends the helper; the next classification starts another.
func TestSafetyEngineScorerCrashAnswersUnavailable(t *testing.T) {
	scorer, processes, files, _ := newTestSafetyEngineScorer(t, DefaultSafetySettings())
	handle, err := scorer.Load(context.Background(), files.model.Path)
	if err != nil {
		t.Fatal(err)
	}
	processes.set(func() { processes.crash = true })
	if _, err := scorer.Classify(context.Background(), handle, testSafetyEngineWindows(1)); !errors.Is(err, ErrSafetyUnavailable) {
		t.Fatalf("a crash: %v", err)
	}
	processes.awaitEnded(t)
	processes.set(func() { processes.crash = false })
	if _, err := scorer.Classify(context.Background(), handle, testSafetyEngineWindows(1)); err != nil {
		t.Fatal(err)
	}
	if started, _ := processes.seen(); started != 2 {
		t.Errorf("%d helpers", started)
	}
}

// A classification past DecisionTimeout answers unavailable and ends the helper; the next starts another.
func TestSafetyEngineScorerTimeoutAnswersUnavailable(t *testing.T) {
	settings := DefaultSafetySettings()
	scorer, processes, files, clock := newTestSafetyEngineScorer(t, settings)
	handle, err := scorer.Load(context.Background(), files.model.Path)
	if err != nil {
		t.Fatal(err)
	}
	processes.set(func() { processes.hang = true })
	answered := make(chan error, 1)
	go func() {
		_, err := scorer.Classify(context.Background(), handle, testSafetyEngineWindows(1))
		answered <- err
	}()
	clock.awaitArmed(t, settings.DecisionTimeout)
	clock.Advance(settings.DecisionTimeout)
	select {
	case err := <-answered:
		if !errors.Is(err, ErrSafetyUnavailable) || !strings.Contains(err.Error(), "past") {
			t.Fatalf("a classification past its time: %v", err)
		}
	case <-time.After(testInferWait):
		t.Fatal("no answer at the decision's time")
	}
	processes.awaitEnded(t)
	processes.set(func() { processes.hang = false })
	if _, err := scorer.Classify(context.Background(), handle, testSafetyEngineWindows(1)); err != nil {
		t.Fatal(err)
	}
	if started, _ := processes.seen(); started != 2 {
		t.Errorf("%d helpers", started)
	}
}

// The caller's own cancel answers unavailable and leaves the helper to its other calls.
func TestSafetyEngineScorerCallerCancelKeepsTheHelper(t *testing.T) {
	settings := DefaultSafetySettings()
	scorer, processes, files, clock := newTestSafetyEngineScorer(t, settings)
	handle, err := scorer.Load(context.Background(), files.model.Path)
	if err != nil {
		t.Fatal(err)
	}
	processes.set(func() { processes.hang = true })
	ctx, cancel := context.WithCancel(context.Background())
	answered := make(chan error, 1)
	go func() {
		_, err := scorer.Classify(ctx, handle, testSafetyEngineWindows(1))
		answered <- err
	}()
	clock.awaitArmed(t, settings.DecisionTimeout)
	cancel()
	if err := <-answered; !errors.Is(err, ErrSafetyUnavailable) {
		t.Fatalf("a canceled classification: %v", err)
	}
	processes.set(func() { processes.hang = false })
	if _, err := scorer.Classify(context.Background(), handle, testSafetyEngineWindows(1)); err != nil {
		t.Fatal(err)
	}
	if started, _ := processes.seen(); started != 1 {
		t.Errorf("%d helpers after a caller's cancel", started)
	}
}

// Logits that do not answer every window answer unavailable and end the helper.
func TestSafetyEngineScorerDecodeErrorAnswersUnavailable(t *testing.T) {
	scorer, processes, files, _ := newTestSafetyEngineScorer(t, DefaultSafetySettings())
	handle, err := scorer.Load(context.Background(), files.model.Path)
	if err != nil {
		t.Fatal(err)
	}
	processes.set(func() { processes.short = true })
	if _, err := scorer.Classify(context.Background(), handle, testSafetyEngineWindows(3)); !errors.Is(err, ErrSafetyUnavailable) {
		t.Fatalf("logits short of their windows: %v", err)
	}
	processes.awaitEnded(t)
}

// A model whose pin the store gives does not match its file: the helper refuses the load, which answers unavailable
// and ends the helper; a runtime off its pin likewise.
func TestSafetyEngineScorerRefusesAFileOffItsPin(t *testing.T) {
	scorer, processes, files, _ := newTestSafetyEngineScorer(t, DefaultSafetySettings())
	files.model.Sha256 = strings.Repeat("0", 64)
	if _, err := scorer.Load(context.Background(), files.model.Path); !errors.Is(err, ErrSafetyUnavailable) || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("a model off its pin: %v", err)
	}
	processes.awaitEnded(t)
	scorer, processes, files, _ = newTestSafetyEngineScorer(t, DefaultSafetySettings())
	files.runtime.Sha256 = strings.Repeat("0", 64)
	if _, err := scorer.Load(context.Background(), files.model.Path); !errors.Is(err, ErrSafetyUnavailable) {
		t.Fatalf("a runtime off its pin: %v", err)
	}
	processes.awaitEnded(t)
}

// An unload unloads the model from the helper, and its handle classifies nothing after; a closed scorer ends its helper
// and answers unavailable.
func TestSafetyEngineScorerUnloadAndClose(t *testing.T) {
	scorer, processes, files, _ := newTestSafetyEngineScorer(t, DefaultSafetySettings())
	handle, err := scorer.Load(context.Background(), files.model.Path)
	if err != nil {
		t.Fatal(err)
	}
	scorer.Unload(handle)
	if _, methods := processes.seen(); !slices.Equal(methods, []string{inferEngineMethodClassifyLoad, inferEngineMethodClassifyUnload}) {
		t.Errorf("methods %v", methods)
	}
	if processes.started[0].ort.liveCount("session") != 0 {
		t.Errorf("the session outlived its unload")
	}
	if _, err := scorer.Classify(context.Background(), handle, testSafetyEngineWindows(1)); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("a classification after the unload: %v", err)
	}
	other, err := scorer.Load(context.Background(), files.model.Path)
	if err != nil {
		t.Fatal(err)
	}
	scorer.Close()
	processes.awaitEnded(t)
	if _, err := scorer.Classify(context.Background(), other, testSafetyEngineWindows(1)); !errors.Is(err, ErrSafetyUnavailable) {
		t.Errorf("a classification after Close: %v", err)
	}
}

// The environment variable that makes this test binary the classifier's engine helper.
const testSafetyEngineHelperVariable = "UR_TEST_SAFETY_ENGINE_HELPER"

// The id a window holds to make the helper this test binary runs crash mid-call.
const testSafetyEngineCrashId = 666

// Not a test: TestSafetyEngineThroughTheHelperProcess starts this binary as ur-engine with -test.run naming it, and it
// serves the helper's protocol with the classify methods over the stand-in runtime, then exits; a window holding
// testSafetyEngineCrashId ends it mid-call.
func TestSafetyEngineHelperProcess(t *testing.T) {
	if os.Getenv(testSafetyEngineHelperVariable) == "" {
		return
	}
	ort := newTestOrt(20)
	score := ort.score
	ort.score = func(ids []int64) (float32, float32) {
		if slices.Contains(ids, testSafetyEngineCrashId) {
			os.Exit(3)
		}
		return score(ids)
	}
	methods := newInferEngineClassify(ort.open, DefaultSafetySettings()).methods()
	if err := inferEngineHelperServe(context.Background(), os.Stdin, os.Stdout, &testInferEngineBackend{}, methods, DefaultInferSettings()); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// Through INFER's InferEngineProcess, which starts this test binary as the helper: a load and a classification over
// the helper's JSON lines, a crash mid-call answering unavailable, and the next classification on a new helper.
func TestSafetyEngineThroughTheHelperProcess(t *testing.T) {
	files := newTestSafetyEngineFiles(t)
	engineDirectory, modelDirectory, stateDirectory := t.TempDir(), t.TempDir(), t.TempDir()
	newProcess := func() (SafetyEngineProcess, error) {
		return NewInferEngineProcess(&InferEngineProcessArgs{
			HelperPath:      os.Args[0],
			HelperArgs:      []string{"-test.run=^TestSafetyEngineHelperProcess$"},
			HelperEnv:       []string{testSafetyEngineHelperVariable + "=on"},
			EngineDirectory: engineDirectory,
			ModelDirectory:  modelDirectory,
			StateDirectory:  stateDirectory,
			Manifest:        &InferManifest{Version: 1},
		})
	}
	scorer, err := NewSafetyEngineScorer(&SafetyEngineScorerArgs{NewProcess: newProcess, Files: files})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(scorer.Close)
	handle, err := scorer.Load(context.Background(), files.model.Path)
	if err != nil {
		t.Fatal(err)
	}
	windows := testSafetyEngineWindows(3)
	logits, err := scorer.Classify(context.Background(), handle, windows)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(logits, testOrtLogits(newTestOrt(20), windows)) {
		t.Errorf("logits %v", logits)
	}
	crash := [][]int64{{1, testSafetyEngineCrashId, 2}}
	if _, err := scorer.Classify(context.Background(), handle, crash); !errors.Is(err, ErrSafetyUnavailable) {
		t.Fatalf("a crash mid-call: %v", err)
	}
	logits, err = scorer.Classify(context.Background(), handle, windows)
	if err != nil || !slices.Equal(logits, testOrtLogits(newTestOrt(20), windows)) {
		t.Fatalf("after the crash, on a new helper: %v, %v", logits, err)
	}
}
