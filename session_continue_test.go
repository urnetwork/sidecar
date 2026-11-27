//go:build !ios_extension && !sidecar_http && !js

// CTXH-M11-05's continue and fork (DESIGN-COMPUTE §24.7, §24.16's Continue and fork row; R-CTXH-4, D-CTXH-5, D-CTXH-9)
// on sidecartest's streams: a run journaled on one device of the member, as the Harness journals it, continued on
// another from the vault alone in that device's own Harness, its first node hanging from the old run's tip and its call
// rebuilt on a third device to its request_sha256 across the run boundary; a continuation on a smaller model naming the
// old one in its model_change; a continue refused while the run is live and while its liveness cannot be read, a fork
// never; flagged nodes, nodes a tagged sidecar wrote with their bit clear, and marked nodes carried into the new run as
// taint and the private mark; and a source run's erasure read as erased nodes in its fork's rebuild. External, on
// session_journal_test.go's and session_rebuild_test.go's worlds.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The models a continuing host's catalog holds: the run's, and a smaller one a phone runs.
const (
	testSessionContinueModel      = "engy-glm-5.2-high"
	testSessionContinueSmallModel = "engy-glm-4.5-air-high"
)

// A remote catalog entry, as INFER's tests build one.
func testSessionContinueEntry(model string, window int64) *sidecar.InferCatalogEntry {
	return &sidecar.InferCatalogEntry{
		Provider: "engy", Model: model, Kind: sidecar.InferCatalogKindDirect, Label: sidecar.ComputeLabelNone,
		Efforts: []sidecar.InferEffort{sidecar.InferEffortHigh}, DefaultEffort: sidecar.InferEffortHigh,
		ContextWindow: window, MaxOutput: 8 * 1024, Tools: true, StructuredOutput: true,
		Modalities: []sidecar.InferModality{sidecar.InferModalityText}, License: "Apache-2.0",
		Remote: &sidecar.InferRemoteModel{ProviderModelId: model, InputNanoUsdPerMillion: 45_000_000, OutputNanoUsdPerMillion: 300_000_000},
	}
}

// A router that answers each call with the next text, keeping every request and each model checked.
type testSessionRouter struct {
	catalog *sidecar.InferCatalog

	stateLock sync.Mutex
	requests  []*sidecar.InferRequest
	checked   []string
	answers   []string
}

func newTestSessionRouter(t *testing.T) *testSessionRouter {
	t.Helper()
	catalog, err := sidecar.NewInferCatalog([]*sidecar.InferCatalogEntry{
		testSessionContinueEntry("glm-5.2", 128*1024), testSessionContinueEntry("glm-4.5-air", 32*1024),
	}, sidecar.DefaultInferSettings())
	if err != nil {
		t.Fatal(err)
	}
	return &testSessionRouter{catalog: catalog}
}

func (self *testSessionRouter) Catalog(ctx context.Context) (*sidecar.InferCatalog, error) {
	return self.catalog, nil
}

func (self *testSessionRouter) Infer(ctx context.Context, request *sidecar.InferRequest) (<-chan *sidecar.InferEvent, error) {
	answer := func() string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.requests = append(self.requests, request)
		if len(self.answers) == 0 {
			return "done"
		}
		answer := self.answers[0]
		self.answers = self.answers[1:]
		return answer
	}()
	events := make(chan *sidecar.InferEvent, 4)
	events <- &sidecar.InferEvent{Kind: sidecar.InferEventStart}
	events <- &sidecar.InferEvent{Kind: sidecar.InferEventText, Text: answer}
	events <- &sidecar.InferEvent{Kind: sidecar.InferEventUsage, Usage: &sidecar.InferUsage{InputTokens: 10, OutputTokens: 2}}
	events <- &sidecar.InferEvent{Kind: sidecar.InferEventEnd}
	close(events)
	return events, nil
}

func (self *testSessionRouter) Check(ctx context.Context, request *sidecar.InferRequest) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.checked = append(self.checked, request.Model)
	return nil
}

// The requests made so far.
func (self *testSessionRouter) made() []*sidecar.InferRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.requests)
}

// The recURd skill as these tests fix it.
type testSessionSkill struct{}

func (testSessionSkill) Text(profile sidecar.HarnessProfile) (string, error) {
	return "You are an agent of the person's network.", nil
}

func (testSessionSkill) Register(ctx context.Context, registration *sidecar.HarnessAgentRegistration) (string, error) {
	if registration.Name == "" {
		return "continued", nil
	}
	return registration.Name, nil
}

// An agent status a test sets: the run's agent's state, or why it cannot be read.
type testSessionLiveness struct {
	stateLock sync.Mutex
	state     sidecar.AgentState
	err       error
}

func (self *testSessionLiveness) set(state sidecar.AgentState, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.state, self.err = state, err
}

func (self *testSessionLiveness) RunState(ctx context.Context, agentId sidecar.Id, runId sidecar.Id) (sidecar.AgentState, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state, self.err
}

// The record's run view over the Harness's run store: a run's header bit is its run file's taint, as on a Sidecar.
type testSessionRunStoreView struct {
	runs *sidecar.RunStore
}

func (self testSessionRunStoreView) RunTainted(runId sidecar.Id) bool {
	return self.runs.Tainted(runId)
}

// The device's record, its runs read from runs rather than the world's view.
func (self *testRecordDevice) openOver(runs sidecar.RecordRunView) *sidecar.SidecarRecord {
	self.t.Helper()
	record, err := sidecar.NewSidecarRecord(&sidecar.SidecarRecordArgs{
		SidecarId:         self.sidecarId,
		IdentityPublicKey: self.key.Public().(ed25519.PublicKey),
		Store:             self.store,
		Sign:              self.sign,
		Spool:             self.spool,
		Runs:              runs,
		Gap:               func(runId sidecar.Id, code string) {},
		Streams:           self.tap,
		Auth:              func() sidecar.RecordAuthView { return self.world.auth.Tip() },
		Alarm: func(alarm *sidecar.RecordAlarm) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.alarms = append(self.alarms, alarm)
		},
		Clock:    self.world.clock,
		Settings: self.settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	if err := record.PrepareDirectWrites(self.t.Context()); err != nil {
		self.t.Fatal(err)
	}
	return record
}

// A device of the member running a Harness over its own record and session journal, as a Sidecar wires one
// (harness_component.go, harness_record.go), and a continuer over its vault.
type testSessionHarnessHost struct {
	t         *testing.T
	device    *testRecordDevice
	record    *sidecar.SidecarRecord
	journal   *sidecar.SessionJournal
	runs      *sidecar.RunStore
	router    *testSessionRouter
	harness   *sidecar.Harness
	live      *testSessionLiveness
	continues *sidecar.SessionContinue
}

// A host on a new consented device of world, a phone's where mobile.
func newTestSessionHarnessHost(t *testing.T, world *testRecordWorld, mobile bool) *testSessionHarnessHost {
	t.Helper()
	device := world.device(true)
	files := sidecartest.NewFakeStore()
	runs, err := sidecar.NewRunStore(files.Root(), sidecar.DefaultSidecarSettings().Mcp, world.clock)
	if err != nil {
		t.Fatal(err)
	}
	record := device.openOver(testSessionRunStoreView{runs: runs})
	store, err := files.Root().Directory("session", "session")
	if err != nil {
		t.Fatal(err)
	}
	redactor, err := sidecar.NewRedactor(bytes.NewReader(bytes.Repeat([]byte{0x53}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	journal, err := sidecar.NewSessionJournal(&sidecar.SessionJournalArgs{Record: record, Store: store, Redactor: redactor, Clock: world.clock})
	if err != nil {
		t.Fatal(err)
	}
	router := newTestSessionRouter(t)
	sources := sidecar.NewSessionHarnessSources(&sidecar.SessionHarnessSourcesArgs{
		Journal: journal, Writer: record.Writer(), Redactor: redactor, Runs: runs, Version: "1.0.0", Clock: world.clock, Catalog: router.Catalog,
	})
	harness, err := sidecar.NewHarness(&sidecar.HarnessArgs{
		Router: router, Journal: sources.Journal, Observer: sources.Observer, Skill: testSessionSkill{}, Runs: runs,
		Tools: map[string]*sidecar.HarnessToolSpec{}, TurnHooks: map[string]sidecar.HarnessTurnHook{}, WorkspaceParent: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(harness.Close)
	sources.Bind(harness)
	harness.SetHost(&testSessionHost{mobile: mobile, directory: t.TempDir()})
	live := &testSessionLiveness{}
	continues, err := sidecar.NewSessionContinue(&sidecar.SessionContinueArgs{Reader: record.SessionReader(), Harness: harness, Live: live})
	if err != nil {
		t.Fatal(err)
	}
	return &testSessionHarnessHost{t: t, device: device, record: record, journal: journal, runs: runs, router: router, harness: harness,
		live: live, continues: continues}
}

// An app's host: a phone's or a desktop's, always in the foreground.
type testSessionHost struct {
	mobile    bool
	directory string
}

func (self *testSessionHost) WorkspaceDirectory() string { return self.directory }
func (self *testSessionHost) Mobile() bool               { return self.mobile }
func (self *testSessionHost) Foreground() bool           { return true }

// Prompts agent and waits for its run to settle.
func (self *testSessionHarnessHost) prompt(agent sidecar.HarnessAgent, text string) {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(self.t.Context(), 60*time.Second)
	defer cancel()
	if err := agent.Prompt(ctx, text, nil); err != nil {
		self.t.Fatal(err)
	}
	if err := agent.WaitForIdle(ctx); err != nil {
		self.t.Fatal(err)
	}
}

// A run journaled as the Harness journals one, on the world's own device: its system message, its model, a prompt and
// the model's answer, with the call's model_call; answering the recorder and the answer's key, the run's tip.
func testSessionContinueSource(t *testing.T, world *testSessionJournalWorld, prompt string, answer string) (*testSessionRecorder, string) {
	t.Helper()
	recorder := newTestSessionRecorder(t, world)
	recorder.model = testSessionContinueModel
	system := recorder.message("", testSessionRebuildSystem("Plan the launch."), "")
	change := sidecar.NewHarnessPiEntryId()
	recorder.journal(sidecar.NewHarnessPiModelChangeEntry(change, system, recorder.now(), &sidecar.HarnessPiModelChange{
		Provider: "engy", ModelId: recorder.model, ChangedBy: sidecar.HarnessModelChangedByPerson}), "", nil)
	user := recorder.message(change, testSessionRebuildUser(prompt), "")
	recorder.call(user, system)
	tip := recorder.message(user, testSessionRebuildAssistant(answer, ""), "")
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	return recorder, tip
}

// The texts of request's messages after its system message.
func testSessionContinueTexts(request *sidecar.InferRequest) []string {
	texts := []string{}
	for _, message := range request.Messages {
		if message.Role == sidecar.InferRoleSystem {
			continue
		}
		texts = append(texts, message.Text())
	}
	return texts
}

// The session_entry bodies of runId in a reader that opened it.
func testSessionContinueRoot(t *testing.T, view *sidecar.SessionRunView) *protocol.SessionEntryBody {
	t.Helper()
	for _, node := range view.Nodes {
		if node.Body != nil && len(node.Body.GetParentRunId()) != 0 {
			return node.Body
		}
	}
	t.Fatalf("run %s has no node hanging from another run", view.RunId)
	return nil
}

// A run journaled on one desktop continues on a second from the vault alone: the new run's request carries the old
// run's prompt and answer, then its own; in the vault its first node hangs from the old run's tip by a parent link,
// its stage-2 context entry names the old run and the tip's session_entry, and on a third device its call rebuilds to
// its request_sha256 across the run boundary, verified, no byte of the old run copied into the new.
func TestSessionContinueOnSecondDevice(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	source, tip := testSessionContinueSource(t, world, "Which venue fits forty people?", "The loft on Fifth Street.")
	desktop := newTestSessionHarnessHost(t, world.world, false)
	plan, err := desktop.continues.Plan(t.Context(), &sidecar.SessionContinueSpec{RunId: source.run.RunId})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Act != sidecar.SessionContinueActContinue || plan.Model != testSessionContinueModel || plan.PreviousModel != "" ||
		!plan.PreviousModelHere || plan.NodeId != source.nodes[tip].journaled.NodeId || plan.Tainted || plan.Private || plan.Cut {
		t.Fatalf("the plan: %+v", plan)
	}
	continued, err := desktop.continues.Continue(t.Context(), &sidecar.SessionContinueSpec{RunId: source.run.RunId})
	if err != nil {
		t.Fatal(err)
	}
	if continued.NewRunId == source.run.RunId {
		t.Fatal("a continuation kept the old run's id")
	}
	agent, ok := desktop.harness.Agent(continued.AgentId)
	if !ok || agent.Run().Tainted() {
		t.Fatalf("the continued agent: %v, tainted %v", ok, ok && agent.Run().Tainted())
	}
	desktop.prompt(agent, "Book it for Friday.")
	requests := desktop.router.made()
	if len(requests) != 1 {
		t.Fatalf("%d requests", len(requests))
	}
	if texts := testSessionContinueTexts(requests[0]); !slices.Equal(texts, []string{"Which venue fits forty people?", "The loft on Fifth Street.", "Book it for Friday."}) {
		t.Fatalf("the continued request: %q", texts)
	}
	if err := desktop.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}

	// a third device reads the new run from the vault
	reader := world.world.device(true).open()
	sessions := reader.SessionReader()
	view, err := sessions.Open(t.Context(), world.world.vaultId, continued.NewRunId)
	if err != nil {
		t.Fatal(err)
	}
	root := testSessionContinueRoot(t, view)
	if !bytes.Equal(root.GetParentRunId(), source.run.RunId.Bytes()) || !bytes.Equal(root.GetParentNodeId(), plan.NodeId.Bytes()) {
		t.Fatal("the new run's first node does not hang from the old run's tip")
	}
	tipNode := source.nodes[tip].journaled
	if !bytes.Equal(root.GetItem(), []byte{}) && bytes.Contains(root.GetItem(), []byte("Fifth Street")) {
		t.Fatal("the new run's first node holds the old run's bytes")
	}
	for _, node := range view.Nodes {
		if node.Body != nil && bytes.Contains(node.Body.GetItem(), []byte("Fifth Street")) {
			t.Fatal("a node of the new run copies the old run's answer")
		}
	}
	contexts, _ := reader.Reader().EntriesOfKinds(world.world.vaultId, 0, sidecar.RecordKindContext)
	named := false
	for _, entry := range contexts {
		if !bytes.Equal(entry.Header.Header.GetRunId(), continued.NewRunId.Bytes()) || entry.Body == nil {
			continue
		}
		body := &protocol.ContextBody{}
		if err := proto.Unmarshal(entry.Body, body); err != nil {
			t.Fatal(err)
		}
		if body.GetStage() == 2 && bytes.Equal(body.GetContinuesRunId(), source.run.RunId.Bytes()) && bytes.Equal(body.GetContinuesEntryId(), plan.EntryId.Bytes()) {
			named = true
		}
	}
	if !named || tipNode.Entry == nil || plan.EntryId != tipNode.Entry.EntryId {
		t.Fatalf("no stage-2 context entry names the continued run and its tip's entry (%v)", named)
	}
	call, ok := view.Call(1)
	if !ok {
		t.Fatalf("the new run holds %d calls", len(view.Calls))
	}
	rebuilt, err := sidecar.SessionRebuild(t.Context(), &sidecar.SessionRebuildArgs{Run: view, Call: call,
		OtherRun: func(ctx context.Context, runId sidecar.Id) (*sidecar.SessionRunView, error) {
			return sessions.Open(ctx, world.world.vaultId, runId)
		}})
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Check != sidecar.SessionCheckVerified {
		t.Fatalf("the continued call rebuilds %s (%s): %+v", rebuilt.Check, rebuilt.Fault, rebuilt.Path)
	}
	crossed := 0
	for _, node := range rebuilt.Path {
		if node.RunId == source.run.RunId {
			crossed += 1
		}
	}
	if crossed == 0 {
		t.Fatal("the rebuild did not cross into the continued run")
	}
}

// A phone continues a desktop's run on a smaller model: the new run's model_change names the new model and the one it
// replaced, changed by the person, and its first call goes to the smaller model through the router, which checks it.
func TestSessionContinueOnPhoneHostSmallerModelRecordsModelChange(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	source, _ := testSessionContinueSource(t, world, "Draft the invite.", "Here is a draft.")
	phone := newTestSessionHarnessHost(t, world.world, true)
	spec := &sidecar.SessionContinueSpec{RunId: source.run.RunId, Model: testSessionContinueSmallModel}
	plan, err := phone.continues.Plan(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Model != testSessionContinueSmallModel || plan.PreviousModel != testSessionContinueModel {
		t.Fatalf("the plan's models: %+v", plan)
	}
	continued, err := phone.continues.Continue(t.Context(), spec)
	if err != nil {
		t.Fatal(err)
	}
	agent, _ := phone.harness.Agent(continued.AgentId)
	phone.prompt(agent, "Shorter, please.")
	requests := phone.router.made()
	if len(requests) != 1 || requests[0].Model != testSessionContinueSmallModel {
		t.Fatalf("the first call: %d requests", len(requests))
	}
	if err := phone.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	view, err := world.world.device(true).open().SessionReader().Open(t.Context(), world.world.vaultId, continued.NewRunId)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, node := range view.Nodes {
		if node.Body == nil || sidecar.SessionNodeType(node.Body.GetType()) != sidecar.SessionNodeModelChange {
			continue
		}
		change := struct {
			ModelId         string `json:"modelId"`
			PreviousModelId string `json:"previousModelId"`
			ChangedBy       string `json:"changedBy"`
		}{}
		if err := json.Unmarshal(node.Body.GetItem(), &change); err != nil {
			t.Fatal(err)
		}
		found = change.ModelId == testSessionContinueSmallModel && change.PreviousModelId == testSessionContinueModel &&
			change.ChangedBy == sidecar.HarnessModelChangedByPerson
	}
	if !found {
		t.Fatal("no model_change names the smaller model and the one it replaced")
	}
}

// A continue is refused while the run's agent is working, waiting or blocked, and while its status cannot be read; an
// idle agent's open run, waiting for its inbox, continues.
func TestSessionContinueRefusedWhileLiveElsewhere(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	source, _ := testSessionContinueSource(t, world, "Count the RSVPs.", "Twelve so far.")
	desktop := newTestSessionHarnessHost(t, world.world, false)
	spec := &sidecar.SessionContinueSpec{RunId: source.run.RunId}
	for _, state := range []sidecar.AgentState{sidecar.AgentStateWorking, sidecar.AgentStateWaiting, sidecar.AgentStateBlocked} {
		desktop.live.set(state, nil)
		plan, err := desktop.continues.Plan(t.Context(), spec)
		if err != nil || !plan.Live || plan.LiveState != state {
			t.Fatalf("%s: the plan %+v, %v", state, plan, err)
		}
		if _, err := desktop.continues.Continue(t.Context(), spec); !errors.Is(err, sidecar.ErrSessionContinueLive) {
			t.Fatalf("%s: a live run continued: %v", state, err)
		}
	}
	desktop.live.set("", errors.New("the agents repo is not reachable"))
	if _, err := desktop.continues.Continue(t.Context(), spec); !errors.Is(err, sidecar.ErrSessionContinueLive) {
		t.Fatalf("a run whose liveness is unread continued: %v", err)
	}
	if len(desktop.harness.Agents()) != 0 {
		t.Fatal("a refused continue started an agent")
	}
	desktop.live.set(sidecar.AgentStateIdle, nil)
	if _, err := desktop.continues.Continue(t.Context(), spec); err != nil {
		t.Fatalf("an idle run's continue: %v", err)
	}
}

// A fork is never refused for liveness: a working run forks at any node this device reads, its new run hanging from
// that node, and a clone forks at the tip.
func TestSessionForkNotRefusedWhileLive(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	source, tip := testSessionContinueSource(t, world, "List the caterers.", "Three answered.")
	desktop := newTestSessionHarnessHost(t, world.world, false)
	desktop.live.set(sidecar.AgentStateWorking, nil)
	userKey := ""
	for key, recorded := range source.nodes {
		if message := recorded.entry.Message(); message != nil && message.Role() == sidecar.HarnessPiRoleUser {
			userKey = key
		}
	}
	at := source.nodes[userKey].journaled.NodeId
	forked, err := desktop.continues.Continue(t.Context(), &sidecar.SessionContinueSpec{RunId: source.run.RunId, Act: sidecar.SessionContinueActFork,
		At: strings.ReplaceAll(at.String(), "-", "")[:12]})
	if err != nil {
		t.Fatal(err)
	}
	if forked.Plan.NodeId != at || forked.Plan.Live {
		t.Fatalf("the fork: %+v", forked.Plan)
	}
	agent, _ := desktop.harness.Agent(forked.AgentId)
	desktop.prompt(agent, "And their prices?")
	if texts := testSessionContinueTexts(desktop.router.made()[0]); !slices.Equal(texts, []string{"List the caterers.", "And their prices?"}) {
		t.Fatalf("the fork's request: %q", texts)
	}
	cloned, err := desktop.continues.Continue(t.Context(), &sidecar.SessionContinueSpec{RunId: source.run.RunId, Act: sidecar.SessionContinueActClone})
	if err != nil || cloned.Plan.NodeId != source.nodes[tip].journaled.NodeId {
		t.Fatalf("the clone: %+v, %v", cloned, err)
	}
	if _, err := desktop.continues.Continue(t.Context(), &sidecar.SessionContinueSpec{RunId: source.run.RunId, Act: sidecar.SessionContinueActFork}); !errors.Is(err, sidecar.ErrSessionContinueInvalid) {
		t.Fatalf("a fork naming no node: %v", err)
	}
}

// A node whose header is flagged taints the continuation: the plan counts it, and the new run starts tainted, its
// reason inherited, wherever it runs.
func TestSessionFlaggedNodeTaintsContinuation(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	recorder := newTestSessionRecorder(t, world)
	recorder.model = testSessionContinueModel
	system := recorder.message("", testSessionRebuildSystem("Summarize the thread."), "")
	user := recorder.message(system, testSessionRebuildUser("Read the forwarded message."), "")
	// the run read untrusted content: every node from here on carries the bit
	world.world.runs.Taint(recorder.run.RunId)
	answer := recorder.message(user, testSessionRebuildAssistant("It asks for the invoice.", ""), "")
	recorder.call(answer, system)
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	desktop := newTestSessionHarnessHost(t, world.world, false)
	continued, err := desktop.continues.Continue(t.Context(), &sidecar.SessionContinueSpec{RunId: recorder.run.RunId, Model: testSessionContinueModel})
	if err != nil {
		t.Fatal(err)
	}
	if !continued.Plan.Tainted || continued.Plan.FlaggedCount == 0 {
		t.Fatalf("the plan: %+v", continued.Plan)
	}
	if !desktop.runs.Tainted(continued.NewRunId) || !slices.Contains(desktop.runs.TaintReasons(continued.NewRunId), sidecar.RunTaintInherited) {
		t.Fatal("a continuation of flagged nodes did not start tainted")
	}
}

// Nodes another member's enclave wrote, a tagged sidecar other than the member's own, with their bit clear, are
// untrusted to the continuation: it starts tainted though no node is flagged.
func TestSessionOtherMembersEnclaveNodeWithBitClearedTaints(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	tagged := world.world.taggedDevice()
	taggedRecord := tagged.open()
	runId := sidecar.NewId()
	world.world.runs.StartRun(runId)
	var parentNodeId []byte
	// a root's parent counts as 32 zero bytes
	parentChain := make([]byte, 32)
	for i, text := range []string{`{"id":"0000000a","message":{"content":"an enclave agent's text","role":"user","timestamp":1800000000000},"parentId":null,"timestamp":"2027-01-15T08:00:00.000Z","type":"message"}`,
		`{"id":"0000000b","message":{"content":[{"text":"its answer","type":"text"}],"role":"assistant","stopReason":"stop","timestamp":1800000000000},"parentId":"0000000a","timestamp":"2027-01-15T08:00:01.000Z","type":"message"}`} {
		item := []byte(text)
		itemSha256 := testSessionSha256(text)
		chain := testSessionChain(parentChain, itemSha256[:])
		nodeId := sidecar.NewId()
		body := &protocol.SessionEntryBody{NodeId: nodeId.Bytes(), Type: uint32(sidecar.SessionNodeMessage), Item: item, ItemSha256: itemSha256[:], ChainSha256: chain[:]}
		if 0 < i {
			body.ParentNodeId = parentNodeId
		}
		if _, err := taggedRecord.Writer().Append(&sidecar.RecordDraft{Kind: sidecar.RecordKindSessionEntry, Source: sidecar.RecordSourceObserved, RunId: &runId, Body: body}); err != nil {
			t.Fatal(err)
		}
		parentNodeId, parentChain = nodeId.Bytes(), chain[:]
	}
	if err := taggedRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := world.record.Ingester().Ingest(t.Context(), world.world.vaultId); err != nil {
		t.Fatal(err)
	}
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	desktop := newTestSessionHarnessHost(t, world.world, false)
	desktop.live.set(sidecar.AgentStateIdle, nil)
	continued, err := desktop.continues.Continue(t.Context(), &sidecar.SessionContinueSpec{RunId: runId, Model: testSessionContinueModel})
	if err != nil {
		t.Fatal(err)
	}
	if continued.Plan.FlaggedCount != 0 || continued.Plan.UntrustedCount != 2 || !continued.Plan.Tainted {
		t.Fatalf("the plan: %+v", continued.Plan)
	}
	if !desktop.runs.Tainted(continued.NewRunId) {
		t.Fatal("a continuation of a tagged writer's nodes started untainted")
	}
}

// A node carrying the private mark gives it to the continuation, and the limited_use mark likewise.
func TestSessionMarkedNodeCarriesPrivate(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	recorder := newTestSessionRecorder(t, world)
	recorder.model = testSessionContinueModel
	system := recorder.message("", testSessionRebuildSystem("Answer from the mailbox."), "")
	// the run read the person's mail: every node from here on carries the private mark (§7.8)
	user := sidecar.NewHarnessPiEntryId()
	entry := sidecar.NewHarnessPiMessageEntry(user, system, recorder.now(), testSessionRebuildUser("What did my landlord say?"))
	run, node, err := sidecar.SessionNodeOfHarness(&sidecar.HarnessJournalNode{RunId: recorder.run.RunId, AgentId: *recorder.run.AgentId,
		Entry: entry, Marks: sidecar.HarnessMarkPrivate}, nil)
	if err != nil {
		t.Fatal(err)
	}
	journaled := world.journalNodes(run, node)[0]
	recorder.nodes[user] = &testSessionRecorded{entry: entry, journaled: journaled}
	recorder.nodeIds[journaled.NodeId] = recorder.nodes[user]
	recorder.call(user, system)
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	desktop := newTestSessionHarnessHost(t, world.world, false)
	desktop.live.set(sidecar.AgentStateIdle, nil)
	continued, err := desktop.continues.Continue(t.Context(), &sidecar.SessionContinueSpec{RunId: recorder.run.RunId})
	if err != nil {
		t.Fatal(err)
	}
	if !continued.Plan.Private || continued.Plan.LimitedUse {
		t.Fatalf("the plan's marks: %+v", continued.Plan)
	}
	marks, err := desktop.runs.Marks(continued.NewRunId)
	if err != nil || !slices.Contains(marks, "private") {
		t.Fatalf("the new run's marks: %v, %v", marks, err)
	}
}

// Erasing a source run shows erased nodes in its fork's rebuild: the fork's own nodes stand, the path crosses into the
// erased run, reads erased there, and the call is unverifiable, with no alarm.
func TestSessionErasedSourceShowsErasedInForks(t *testing.T) {
	recordWorld := newTestRecordWorld(t)
	eraser, _ := recordWorld.eraserDevice()
	world := &testSessionJournalWorld{t: t, world: recordWorld, device: eraser, store: testSessionStore(t), ingest: sidecar.DefaultSidecarSettings().Ingest}
	world.open(nil)
	source, tip := testSessionContinueSource(t, world, "Which band for the party?", "The jazz trio.")
	desktop := newTestSessionHarnessHost(t, recordWorld, false)
	desktop.live.set(sidecar.AgentStateIdle, nil)
	forked, err := desktop.continues.Continue(t.Context(), &sidecar.SessionContinueSpec{RunId: source.run.RunId, Act: sidecar.SessionContinueActFork,
		At: source.nodes[tip].journaled.NodeId.String()})
	if err != nil {
		t.Fatal(err)
	}
	agent, _ := desktop.harness.Agent(forked.AgentId)
	desktop.prompt(agent, "Book them.")
	if err := desktop.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	// every entry of the source run erased, a person's act on its own device
	if err := world.record.Reader().Sync(t.Context(), recordWorld.vaultId); err != nil {
		t.Fatal(err)
	}
	entryIds := []sidecar.Id{}
	for _, entry := range world.record.Reader().Entries(recordWorld.vaultId) {
		if bytes.Equal(entry.Header.Header.GetRunId(), source.run.RunId.Bytes()) {
			entryIds = append(entryIds, entry.EntryId)
		}
	}
	if _, err := world.record.Eraser().Erase(t.Context(), &sidecar.RecordEraseArgs{LogId: recordWorld.vaultId, EntryIds: entryIds,
		Reason: sidecar.RecordErasureReasonPerson, Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	readerDevice := recordWorld.device(true)
	sessions := readerDevice.open().SessionReader()
	view, err := sessions.Open(t.Context(), recordWorld.vaultId, forked.NewRunId)
	if err != nil {
		t.Fatal(err)
	}
	call, ok := view.Call(1)
	if !ok {
		t.Fatal("the fork made no call")
	}
	rebuilt, err := sidecar.SessionRebuild(t.Context(), &sidecar.SessionRebuildArgs{Run: view, Call: call,
		OtherRun: func(ctx context.Context, runId sidecar.Id) (*sidecar.SessionRunView, error) {
			return sessions.Open(ctx, recordWorld.vaultId, runId)
		}})
	if err != nil {
		t.Fatal(err)
	}
	erased := slices.ContainsFunc(rebuilt.Path, func(node *sidecar.SessionRebuiltNode) bool {
		return node.RunId == source.run.RunId && node.State == sidecar.RecordEntryErased
	})
	if rebuilt.Check != sidecar.SessionCheckUnverifiable || !erased {
		t.Fatalf("the fork's rebuild after its source's erasure: %s, %+v", rebuilt.Check, rebuilt.Path)
	}
	for _, reason := range readerDevice.alarmReasons() {
		t.Errorf("an alarm: %s", reason)
	}
}

// A session journal world's sealed store, for a world built on another device.
func testSessionStore(t *testing.T) sidecar.SidecarStore {
	t.Helper()
	store, err := sidecartest.NewFakeStore().Root().Directory("session", "session")
	if err != nil {
		t.Fatal(err)
	}
	return store
}
