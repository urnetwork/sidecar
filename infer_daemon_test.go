//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package sidecar

// The daemon's model and inference methods (infer_daemon.go; INFER-M11-08): infer.run opening a run, streaming its
// events and recording the call as a model_call, refusing to run with no record to keep it in, and answering a
// refusal as its reply; models.pull following a pull to its end through INFER-M11-11's download, a chunk failing its
// check every time naming it, an ended pull answered once; models.set's change, its confirmation and its harness guard.

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A record writer that keeps each draft.
type testInferDaemonWriter struct {
	stateLock sync.Mutex
	drafts    []*RecordDraft
	err       error
}

// See RecordWriter.
func (self *testInferDaemonWriter) Append(draft *RecordDraft) ([]*RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return nil, self.err
	}
	self.drafts = append(self.drafts, draft)
	return []*RecordEntryRef{{EntryId: NewId(), Seq: uint64(len(self.drafts))}}, nil
}

// infer.run's host over router, keeping the runs it opens and the drafts it appends.
type testInferDaemonHost struct {
	host   *daemonInferRunHost
	writer *testInferDaemonWriter
	runs   []*RunFile
	// notifications, in order
	events []*InferEvent
}

func newTestInferDaemonHost(router InferRouter) *testInferDaemonHost {
	self := &testInferDaemonHost{writer: &testInferDaemonWriter{}}
	self.host = &daemonInferRunHost{
		router: func() (InferRouter, error) { return router, nil },
		openRun: func(ctx context.Context, run *RunFile) error {
			self.runs = append(self.runs, run)
			return nil
		},
		writer: func() (RecordWriter, error) { return self.writer, nil },
	}
	return self
}

// Collects infer.run's notifications.
func (self *testInferDaemonHost) notify(method string, params any) error {
	if method == DaemonNotifyInferEvent {
		self.events = append(self.events, params.(*InferEvent))
	}
	return nil
}

// A prompt runs in a run of its own, its events reach the caller, and its call is recorded there as a model_call
// through InferModelCall: the canonical name, route local, the usage, source observed.
func TestDaemonInferRunRecordsModelCall(t *testing.T) {
	world := newTestInferRouterWorld(t, nil)
	host := newTestInferDaemonHost(world.router)
	reply, err := daemonInferRun(context.Background(), host.host, &DaemonInferRunParams{Model: "local-gemma-4-e4b", Prompt: "hello"}, host.notify)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Error != nil || !reply.Recorded || reply.Model != "local-gemma-4-e4b-off" {
		t.Fatalf("reply %+v", reply)
	}
	if len(host.runs) != 1 || host.runs[0].RunId != reply.RunId || host.runs[0].Harness != daemonInferRunHarness {
		t.Errorf("runs %+v", host.runs)
	}
	if testInferText(host.events) != "local" {
		t.Errorf("the caller heard %+v", host.events)
	}
	if len(host.writer.drafts) != 1 {
		t.Fatalf("%d drafts", len(host.writer.drafts))
	}
	draft := host.writer.drafts[0]
	body, ok := draft.Body.(*protocol.ModelCallBody)
	if draft.Kind != RecordKindModelCall || draft.Source != RecordSourceObserved || draft.RunId == nil || *draft.RunId != reply.RunId || !ok {
		t.Fatalf("draft %+v", draft)
	}
	if body.Model != "local-gemma-4-e4b-off" || body.Route != RecordModelCallRouteLocal || body.Provider != "local" ||
		body.InputTokens != 3 || body.OutputTokens != 1 || body.RequestId == "" {
		t.Errorf("body %+v", body)
	}
	// the engine had the prompt, in the run
	calls := world.engine.called()
	if len(calls) != 1 || calls[0].Request.RunId == nil || *calls[0].Request.RunId != reply.RunId || calls[0].Request.Messages[0].Text() != "hello" {
		t.Errorf("the engine had %+v", calls)
	}
}

// With no record to keep the call in, nothing runs and no run opens.
func TestDaemonInferRunRefusesWithoutARecord(t *testing.T) {
	world := newTestInferRouterWorld(t, nil)
	host := newTestInferDaemonHost(world.router)
	host.host.writer = func() (RecordWriter, error) { return nil, ErrSidecarStoreLocked }
	if _, err := daemonInferRun(context.Background(), host.host, &DaemonInferRunParams{Model: "local-gemma-4-e4b-off", Prompt: "hello"}, nil); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Fatalf("no record: %v", err)
	}
	if len(host.runs) != 0 || len(world.engine.called()) != 0 {
		t.Errorf("a call ran with no record: %d runs, %d calls", len(host.runs), len(world.engine.called()))
	}
	if _, err := daemonInferRun(context.Background(), host.host, &DaemonInferRunParams{Model: "local-gemma-4-e4b-off"}, nil); !errors.Is(err, errDaemonInferParams) {
		t.Errorf("no prompt: %v", err)
	}
}

// Checks that refuse every remote model with disclosure_required, as a model labeled none waiting for its provider's
// disclosure is refused.
type testInferDisclosureChecker struct{}

func (self *testInferDisclosureChecker) check(ctx context.Context, call *InferCall) error {
	if call.Entry.Kind == InferCatalogKindLocal {
		return nil
	}
	return &InferError{Code: InferErrorDisclosureRequired, Model: call.Name, Reason: InferDisclosureReasonUnacknowledged,
		Message: "acknowledge it", DisclosureId: "inference:" + call.Entry.Provider, DisclosureVersion: 2}
}

func (self *testInferDisclosureChecker) limit(ctx context.Context, catalog *InferCatalog) *InferCatalog {
	return catalog
}

// A refusal is infer.run's reply, not an rpc error, so ur infer can act on it: disclosure_required with its id and
// version, and model_refused for a name no model answers; nothing is recorded for a call that never ran.
func TestDaemonInferRunAnswersARefusal(t *testing.T) {
	world := newTestInferRouterWorld(t, func(world *testInferRouterWorld) {
		world.checker = &testInferDisclosureChecker{}
	})
	host := newTestInferDaemonHost(world.router)
	reply, err := daemonInferRun(context.Background(), host.host, &DaemonInferRunParams{Model: "engy-glm-5.2-high", Prompt: "hello"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Error == nil || reply.Error.Code != InferErrorDisclosureRequired || reply.Error.DisclosureId != "inference:engy" ||
		reply.Error.DisclosureVersion != 2 || reply.Recorded {
		t.Fatalf("a disclosure refusal answered %+v", reply)
	}
	reply, err = daemonInferRun(context.Background(), host.host, &DaemonInferRunParams{Model: "local-nothing-off", Prompt: "hello"}, nil)
	if err != nil || reply.Error == nil || reply.Error.Code != InferErrorModelRefused {
		t.Fatalf("an unknown model answered %+v, %v", reply, err)
	}
	if len(host.writer.drafts) != 0 {
		t.Errorf("a refused call was recorded: %+v", host.writer.drafts)
	}
}

// The pulls of a daemon over world's model for an Android phone.
func newTestDaemonInferPulls(t *testing.T, world *testInferDownloadWorld) *InferPulls {
	t.Helper()
	device := testInferDevice("android/arm64", InferDeviceClassPhone, 8, false)
	pull, _ := newTestInferPull(t, world, testInferPullManifest(world, nil), device, false)
	return NewInferPulls(context.Background(), pull.Pull, world.settings)
}

// A call that follows a pull, its notifications kept.
type testInferDaemonFollower struct {
	stateLock sync.Mutex
	heard     []*DaemonModelsPullReply
}

func (self *testInferDaemonFollower) call() *DaemonCall {
	return &DaemonCall{Notify: func(method string, params any) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if method == DaemonNotifyModelsPullProgress {
			copied := *params.(*DaemonModelsPullReply)
			self.heard = append(self.heard, &copied)
		}
		return nil
	}}
}

// A followed pull streams its progress by chunks and answers done once it ends; its state is answered once, so the
// daemon keeps none after.
func TestDaemonModelsPullFollowsAndAnswersOnce(t *testing.T) {
	world := newTestInferDownloadWorld(t, 3*4096+5, 4096)
	world.settings.ModelChunkFetchConcurrency = 1
	pulls := newTestDaemonInferPulls(t, world)
	follower := &testInferDaemonFollower{}
	reply, err := daemonModelsPull(context.Background(), pulls, follower.call(), &DaemonModelsPullParams{Name: "local-test-model-off", Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	if reply.State != DaemonModelsPullDone || reply.Error != nil {
		t.Fatalf("the pull answered %+v", reply)
	}
	done := []int{}
	for _, heard := range follower.heard {
		if heard.Progress != nil && heard.Progress.Phase == InferPullPhaseModel {
			done = append(done, heard.Progress.DoneChunkCount)
		}
	}
	if !slices.IsSorted(done) || len(done) == 0 {
		t.Errorf("chunks done heard %v", done)
	}
	if len(pulls.nameStates) != 0 {
		t.Errorf("an answered pull kept %d states", len(pulls.nameStates))
	}
	// the model is whole: an unfollowed call joins a new pull, which ends at once
	reply, err = daemonModelsPull(context.Background(), pulls, &DaemonCall{}, &DaemonModelsPullParams{Name: "local-test-model-off"})
	if err != nil || (reply.State != DaemonModelsPullRunning && reply.State != DaemonModelsPullDone) {
		t.Errorf("an unfollowed pull answered %+v, %v", reply, err)
	}
}

// A chunk that fails its check every time stops the pull with download_corrupt naming it, which the reply carries.
func TestDaemonModelsPullReportsCorruptChunk(t *testing.T) {
	world := newTestInferDownloadWorld(t, 3*4096+5, 4096)
	world.settings.ModelChunkFetchConcurrency = 1
	world.setAnswer(func(asked string, attempt int) testInferDownloadAnswer {
		if asked == "api chunk 1" || asked == "hub chunk 1" {
			return testInferDownloadAlter
		}
		return testInferDownloadServe
	})
	pulls := newTestDaemonInferPulls(t, world)
	reply, err := daemonModelsPull(context.Background(), pulls, (&testInferDaemonFollower{}).call(), &DaemonModelsPullParams{Name: "local-test-model-off", Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	if reply.State != DaemonModelsPullFailed || reply.Error == nil || reply.Error.Code != string(InferDownloadErrorCorrupt) ||
		reply.Error.Chunk == nil || *reply.Error.Chunk != 1 {
		t.Fatalf("a corrupt chunk answered %+v", reply)
	}
	encoded, _ := json.Marshal(reply)
	if !json.Valid(encoded) {
		t.Error("the reply does not encode")
	}
}

// models.set changes what it names and nothing else, a harness's tier by all three of its parts; it runs only
// confirmed, and never for a caller the daemon cannot place outside a harness.
func TestDaemonModelsSetChange(t *testing.T) {
	key := &HarnessModelsKey{Default: "local-gemma-4-e4b-off", Allow: []string{"local-*"}}
	teeOnly := true
	mode := string(HarnessSignInMailAllow)
	allow := []string{"chutes-*", "local-*"}
	if err := (&InferModelsChange{TeeOnly: &teeOnly, SignInMail: &mode, Allow: &allow,
		Harness: HarnessModelsCodex, Tier: HarnessModelsTierModel, Model: "chutes-qwen3.8-27b-tee-high"}).Apply(key); err != nil {
		t.Fatal(err)
	}
	if key.Default != "local-gemma-4-e4b-off" || !key.TeeOnly || key.SignInMail != HarnessSignInMailAllow ||
		!slices.Equal(key.Allow, allow) || key.Harness[HarnessModelsCodex][HarnessModelsTierModel] != "chutes-qwen3.8-27b-tee-high" {
		t.Errorf("the key is %+v", key)
	}
	if err := (&InferModelsChange{Harness: HarnessModelsCodex}).Apply(key); !errors.Is(err, ErrModelsKeyInvalid) {
		t.Errorf("half a tier was taken: %v", err)
	}
	var set *DaemonMethod
	for _, method := range DaemonInferMethods(nil) {
		if method.Name == DaemonMethodModelsSet {
			set = method
		}
	}
	if set == nil || !set.Confirm {
		t.Fatalf("models.set is %+v, not a Confirm method", set)
	}
	if _, err := set.Handler(context.Background(), &DaemonCall{Params: json.RawMessage(`{"tee_only":true}`)}); !errors.Is(err, errDaemonModelsSetUnconfirmed) {
		t.Errorf("an unconfirmed set: %v", err)
	}
	for _, call := range []*DaemonCall{{}, {Hello: &DaemonHello{}}, {Hello: &DaemonHello{PeerPid: 42}}} {
		if !daemonInferUnderHarness(context.Background(), call) {
			t.Errorf("a caller the daemon cannot place was taken as no harness's: %+v", call.Hello)
		}
	}
}
