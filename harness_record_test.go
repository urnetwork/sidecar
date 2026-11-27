//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A record a test reads back: every draft its writer took, the session journal's and the recorder's, in order, each
// given an entry id, a log, a seq and a commitment.
type harnessTestRecordLog struct {
	logId Id

	stateLock sync.Mutex
	drafts    []*RecordDraft
	refs      []*RecordEntryRef
}

func newHarnessTestRecordLog() *harnessTestRecordLog {
	return &harnessTestRecordLog{logId: NewId()}
}

func (self *harnessTestRecordLog) Append(draft *RecordDraft) ([]*RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	commitment := [sha256.Size]byte{}
	rand.Read(commitment[:])
	ref := &RecordEntryRef{LogId: self.logId, EntryId: NewId(), Seq: uint64(len(self.drafts) + 1), Commitment: commitment}
	self.drafts = append(self.drafts, draft)
	self.refs = append(self.refs, ref)
	return []*RecordEntryRef{ref}, nil
}

func (self *harnessTestRecordLog) Writer() RecordWriter {
	return self
}

func (self *harnessTestRecordLog) ReleaseRides() {
}

func (self *harnessTestRecordLog) SetRideInterval(interval time.Duration) {
}

// The drafts of kind, with their refs.
func (self *harnessTestRecordLog) ofKind(kind RecordKind) ([]*RecordDraft, []*RecordEntryRef) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	drafts, refs := []*RecordDraft{}, []*RecordEntryRef{}
	for i, draft := range self.drafts {
		if draft.Kind == kind {
			drafts = append(drafts, draft)
			refs = append(refs, self.refs[i])
		}
	}
	return drafts, refs
}

// The kinds of every draft, in order.
func (self *harnessTestRecordLog) kinds() []RecordKind {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kinds := []RecordKind{}
	for _, draft := range self.drafts {
		kinds = append(kinds, draft.Kind)
	}
	return kinds
}

// A world whose Harness records through CTXH's real session journal and the recorder, on the test record.
type harnessRecordTestWorld struct {
	*harnessTestWorld
	record   *harnessTestRecordLog
	sessions *SessionJournal
	journal  *harnessSessionJournal
	recorder *harnessRecorder
}

func newHarnessRecordTestWorld(t *testing.T, router *harnessScriptedRouter, tools map[string]*HarnessToolSpec) *harnessRecordTestWorld {
	t.Helper()
	instance, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	store, err := instance.Store(&testNetworkId).Directory(sessionComponentName, sessionComponentName)
	if err != nil {
		t.Fatal(err)
	}
	record := newHarnessTestRecordLog()
	redactor, err := NewRedactor(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := NewSessionJournal(&SessionJournalArgs{Record: record, Store: store, Redactor: redactor,
		Settings: DefaultSessionSettings(), Ingest: DefaultSidecarSettings().Ingest})
	if err != nil {
		t.Fatal(err)
	}
	journal := newHarnessSessionJournal(func() (harnessSessionStore, error) { return sessions, nil })
	if router == nil {
		router = newHarnessScriptedRouter(t, testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortHigh),
			testInferRemoteEntry("chutes", "kimi-3", ComputeLabelNone, InferEffortHigh))
	}
	recorder := newHarnessRecorder(&harnessRecorderArgs{
		Writer:   func() (RecordWriter, error) { return record, nil },
		Redactor: func() (*Redactor, error) { return redactor, nil },
		Runs:     runs,
		Version:  "test-1",
		Catalog:  router.Catalog,
	}, journal)
	world := newHarnessTestWorld(t, router, tools, &HarnessArgs{Observer: journal.observe})
	// the world's run store is its own: the recorder reads the same one
	recorder.args.Runs = world.runs
	recorder.bind(world.harness)
	// the loop journals through the session journal, not the test journal
	world.harness.journal = journal
	return &harnessRecordTestWorld{harnessTestWorld: world, record: record, sessions: sessions, journal: journal, recorder: recorder}
}

// The body of a draft, decoded into body.
func harnessRecordBody[T proto.Message](t *testing.T, draft *RecordDraft, body T) T {
	t.Helper()
	encoded, err := proto.Marshal(draft.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(encoded, body); err != nil {
		t.Fatal(err)
	}
	return body
}

// A prompt, a tool call and a reply: the record takes a stage-1 context before any model_call, a tool_call, one
// model_call a call, each after the session entries of its context and its response, and at the idle a coverage
// entry of source harness and a cost entry.
func TestHarnessRunRecordsContextToolCallModelCall(t *testing.T) {
	router := newHarnessScriptedRouter(t, testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortHigh))
	tools := map[string]*HarnessToolSpec{"lookup": harnessLoopTool("lookup", "", HarnessToolTierRead,
		func(ctx context.Context, args []byte) (*HarnessToolResult, error) {
			return &HarnessToolResult{Text: "42", Trust: HarnessToolTrusted}, nil
		})}
	world := newHarnessRecordTestWorld(t, router, tools)
	router.script(harnessToolsCall([3]string{"call_1", "lookup", `{}`}), harnessTextCall("It is 42."))
	agent := world.agent(t, &HarnessAgentSpec{Name: "researcher"})
	log := harnessCollect(t, agent)
	if err := agent.Prompt(context.Background(), "What is the answer?", nil); err != nil {
		t.Fatal(err)
	}
	log.until(t, HarnessEventAgentSettled)
	if err := agent.WaitForIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	kinds := world.record.kinds()
	contextAt := slices.Index(kinds, RecordKindContext)
	modelCallAt := slices.Index(kinds, RecordKindModelCall)
	if contextAt < 0 || modelCallAt < 0 || modelCallAt < contextAt || !slices.Contains(kinds, RecordKindToolCall) ||
		!slices.Contains(kinds, RecordKindCoverage) || !slices.Contains(kinds, RecordKindCost) {
		t.Fatalf("the kinds: %v", kinds)
	}
	contexts, _ := world.record.ofKind(RecordKindContext)
	contextBody := harnessRecordBody(t, contexts[0], &protocol.ContextBody{})
	if contextBody.GetStage() != 1 || contextBody.GetHarness() != HarnessRunHarnessName || contextBody.GetHarnessVersion() != "test-1" ||
		contextBody.GetAgentLabel() != "researcher" || contextBody.GetModel() != harnessTestModel || contextBody.GetTitle() != "What is the answer?" {
		t.Fatalf("the context: %v", contextBody)
	}
	modelCalls, _ := world.record.ofKind(RecordKindModelCall)
	if len(modelCalls) != 2 {
		t.Fatalf("%d model calls", len(modelCalls))
	}
	sessionDrafts, sessionRefs := world.record.ofKind(RecordKindSessionEntry)
	for _, modelCall := range modelCalls {
		body := harnessRecordBody(t, modelCall, &protocol.ModelCallBody{})
		call := body.GetContext()
		if body.GetModel() != harnessTestModel || call == nil || call.GetRenderer() != SessionRendererHarness1 || len(call.GetRequestSha256()) != 32 ||
			!call.GetExact() || len(call.GetOutputNodeIds()) != 1 || *modelCall.RunId != agent.Run().Id() {
			t.Fatalf("a model_call: %v", body)
		}
		// its input and output nodes are journaled session entries, written before it
		found := 0
		for _, draft := range sessionDrafts {
			entry := harnessRecordBody(t, draft, &protocol.SessionEntryBody{})
			if string(entry.GetNodeId()) == string(call.GetInputNodeId()) || string(entry.GetNodeId()) == string(call.GetOutputNodeIds()[0]) {
				found += 1
			}
		}
		if found != 2 {
			t.Fatalf("a model_call names nodes the journal did not write: %d found", found)
		}
	}
	_ = sessionRefs
	coverages, _ := world.record.ofKind(RecordKindCoverage)
	coverage := harnessRecordBody(t, coverages[len(coverages)-1], &protocol.Coverage{})
	if !slices.Contains(coverage.GetSources(), RecordCoverageSourceHarness) || coverage.GetHarness() != HarnessRunHarnessName ||
		coverage.GetFirstSeq() == 0 || coverage.GetLastSeq() < coverage.GetFirstSeq() {
		t.Fatalf("the coverage: %v", coverage)
	}
}

// A tool call's tool_call has empty input and output, its action id the run's and the call's, and its header's content
// names the session entry that holds its result.
func TestHarnessToolCallNamesResultNode(t *testing.T) {
	router := newHarnessScriptedRouter(t, testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortHigh))
	tools := map[string]*HarnessToolSpec{"lookup": harnessLoopTool("lookup", "", HarnessToolTierRead,
		func(ctx context.Context, args []byte) (*HarnessToolResult, error) {
			return &HarnessToolResult{Text: "the result text", Details: []byte(`{"rows":3}`), Trust: HarnessToolTrusted}, nil
		})}
	world := newHarnessRecordTestWorld(t, router, tools)
	router.script(harnessToolsCall([3]string{"call_7", "lookup", `{}`}), harnessTextCall("ok"))
	agent := world.agent(t, &HarnessAgentSpec{Name: "researcher"})
	log := harnessCollect(t, agent)
	if err := agent.Prompt(context.Background(), "look", nil); err != nil {
		t.Fatal(err)
	}
	log.until(t, HarnessEventAgentSettled)
	toolCalls, _ := world.record.ofKind(RecordKindToolCall)
	if len(toolCalls) != 1 {
		t.Fatalf("%d tool calls", len(toolCalls))
	}
	draft := toolCalls[0]
	body := harnessRecordBody(t, draft, &protocol.ToolCallBody{})
	actionId, _ := RecordToolActionId(agent.Run().Id(), "call_7")
	if body.GetToolName() != "lookup" || body.GetToolUseId() != "call_7" || len(body.GetInput()) != 0 || len(body.GetOutput()) != 0 ||
		string(draft.ActionId) != string(actionId[:]) || len(draft.Content) != 1 {
		t.Fatalf("the tool_call: %v, action %x, content %v", body, draft.ActionId, draft.Content)
	}
	sessionDrafts, sessionRefs := world.record.ofKind(RecordKindSessionEntry)
	for i, sessionDraft := range sessionDrafts {
		if sessionRefs[i].EntryId != draft.Content[0].EntryId {
			continue
		}
		entry := harnessRecordBody(t, sessionDraft, &protocol.SessionEntryBody{})
		if !strings.Contains(string(entry.GetItem()), "the result text") || !strings.Contains(string(entry.GetItem()), `"call_7"`) {
			t.Fatalf("the named entry holds %s", entry.GetItem())
		}
		return
	}
	t.Fatalf("the tool_call's content names no session entry")
}

// A model change writes a stage-2 context carrying the run's prompts, redacted.
func TestHarnessModelChangeWritesStageTwoWithPrompts(t *testing.T) {
	world := newHarnessRecordTestWorld(t, nil, nil)
	router := world.router
	router.script(harnessTextCall("first"), harnessTextCall("second"))
	agent := world.agent(t, &HarnessAgentSpec{Name: "switcher"})
	if err := agent.Prompt(context.Background(), "one", nil); err != nil {
		t.Fatal(err)
	}
	if err := agent.WaitForIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-router.called
	if err := agent.SetModel("chutes-kimi-3-high"); err != nil {
		t.Fatal(err)
	}
	harnessPromptIdle(t, agent, "two")
	<-router.called
	if err := agent.WaitForIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	contexts, _ := world.record.ofKind(RecordKindContext)
	if len(contexts) != 2 {
		t.Fatalf("%d contexts", len(contexts))
	}
	stage2 := harnessRecordBody(t, contexts[1], &protocol.ContextBody{})
	if stage2.GetStage() != 2 || stage2.GetModel() != "chutes-kimi-3-high" || !slices.Equal(stage2.GetPrompts(), []string{"one", "two"}) {
		t.Fatalf("the stage-2 context: %v", stage2)
	}
}

// A built-in's keep: false result, a web search's, is journaled as its stub: the session entry holds neither its text
// nor its details, and its call is not exact.
func TestHarnessWebSearchResultRecordedAsStub(t *testing.T) {
	router := newHarnessScriptedRouter(t, testInferRemoteEntry("engy", "glm-5.2", ComputeLabelNone, InferEffortHigh))
	search := &harnessTestTool{name: "web_search", execute: func(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
		return &HarnessToolResult{Text: "provider result text 9c1e", Details: []byte(`{"kind":"web_search","keep":false,"results":["9c1e"]}`),
			Trust: HarnessToolUntrusted}, nil
	}}
	world := newHarnessRecordTestWorld(t, router, map[string]*HarnessToolSpec{"web_search": harnessTestSpec(search, true, HarnessProfileLocal)})
	router.script(harnessToolsCall([3]string{"call_s", "web_search", `{"objective":"x"}`}), harnessTextCall("found"))
	agent := world.agent(t, &HarnessAgentSpec{Name: "searcher"})
	log := harnessCollect(t, agent)
	if err := agent.Prompt(context.Background(), "search", nil); err != nil {
		t.Fatal(err)
	}
	log.until(t, HarnessEventAgentSettled)
	sessionDrafts, _ := world.record.ofKind(RecordKindSessionEntry)
	stubbed := false
	for _, draft := range sessionDrafts {
		entry := harnessRecordBody(t, draft, &protocol.SessionEntryBody{})
		if strings.Contains(string(entry.GetItem()), "9c1e") {
			t.Fatalf("a session entry keeps the search's results: %s", entry.GetItem())
		}
		if 0 < entry.GetStubs() {
			stubbed = true
		}
	}
	modelCalls, _ := world.record.ofKind(RecordKindModelCall)
	last := harnessRecordBody(t, modelCalls[len(modelCalls)-1], &protocol.ModelCallBody{})
	if !stubbed || last.GetContext().GetExact() {
		t.Fatalf("stubbed %t, the next call exact %t", stubbed, last.GetContext().GetExact())
	}
	// the model read the results all the same
	requests := router.made()
	if text := requests[len(requests)-1].Messages[len(requests[len(requests)-1].Messages)-1].Text(); !strings.Contains(text, "provider result text 9c1e") {
		t.Fatalf("the model read %q", text)
	}
}

// A prompt holding what reads as a secret is redacted before the context entry seals.
func TestHarnessRedactionBeforeSeal(t *testing.T) {
	world := newHarnessRecordTestWorld(t, nil, nil)
	world.router.script(harnessTextCall("ok"))
	agent := world.agent(t, &HarnessAgentSpec{Name: "careful"})
	secret := "AKIAZ3MSJV4WWNKWW5FG"
	if err := agent.Prompt(context.Background(), "use the key "+secret+" for the upload", nil); err != nil {
		t.Fatal(err)
	}
	if err := agent.WaitForIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	contexts, _ := world.record.ofKind(RecordKindContext)
	body := harnessRecordBody(t, contexts[0], &protocol.ContextBody{})
	encoded, _ := json.Marshal(body.GetTitle())
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("the title keeps the secret: %s", encoded)
	}
	for _, draft := range world.record.drafts {
		if encoded, err := proto.Marshal(draft.Body); err == nil && strings.Contains(string(encoded), secret) {
			t.Fatalf("a %s entry keeps the secret", draft.Kind)
		}
	}
}

// The coverage entry names the harness source and the run's gaps, a missed write among them.
func TestHarnessCoverageNamesHarnessSource(t *testing.T) {
	world := newHarnessRecordTestWorld(t, nil, nil)
	world.router.script(harnessTextCall("ok"))
	agent := world.agent(t, &HarnessAgentSpec{Name: "covered"})
	if err := world.runs.AddGap(context.Background(), agent.Run().Id(), RecordCoverageGapDowntime); err != nil {
		t.Fatal(err)
	}
	if err := agent.Prompt(context.Background(), "go", nil); err != nil {
		t.Fatal(err)
	}
	if err := agent.WaitForIdle(context.Background()); err != nil {
		t.Fatal(err)
	}
	coverages, _ := world.record.ofKind(RecordKindCoverage)
	coverage := harnessRecordBody(t, coverages[len(coverages)-1], &protocol.Coverage{})
	if !slices.Equal(coverage.GetSources(), []string{RecordCoverageSourceHarness}) || !slices.Contains(coverage.GetGaps(), RecordCoverageGapDowntime) ||
		string(coverage.GetRunId()) != string(agent.Run().Id().Bytes()) {
		t.Fatalf("the coverage: %v", coverage)
	}
}
