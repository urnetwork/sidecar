//go:build !ios_extension && !sidecar_http && !js

// CTXH-M12-01's recording of the gateway's calls (DESIGN-COMPUTE §24.8, §24.16; R-CTXH-5, D-CTXH-9, IC-19; R2-04's
// acceptance for the record) on session_journal_test.go's world: two sessions of one grant sending the same bytes kept
// as two runs sharing nothing; a cut call's retry landing on the same context node with nothing written twice; an
// unbound call's entries flagged whether or not a live run of its grant is tainted; each item durable before the event
// that completes it, across a kill; a hook's model_call the gateway never saw counting context_partial; a call's
// request_sha256 rebuilt from the vault by its renderer; a renderer this build does not hold recording none; a request
// naming stored context refused; a redacted item reading the call inexact; and the index across a restart and past its
// window. External, as session_journal_test.go.

package sidecar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// The renderer these tests name: every node's recorded item as one message's text, the system node's first, and the
// params as the schema, so request_sha256 covers each byte of the context as recorded. A pure function, as §24.6 asks.
const testSessionGatewayRendererId = "gateway-ctxhtest-1"

type testSessionGatewayRenderer struct{}

func (testSessionGatewayRenderer) Id() string {
	return testSessionGatewayRendererId
}

func (testSessionGatewayRenderer) Context(path []*sidecar.SessionRenderNode, systemNodeId *sidecar.Id, nodeOf func(nodeId sidecar.Id) (*sidecar.SessionRenderNode, bool)) (*sidecar.SessionRenderInput, error) {
	input := &sidecar.SessionRenderInput{Nodes: path}
	if systemNodeId != nil {
		node, ok := nodeOf(*systemNodeId)
		if !ok {
			return nil, errors.New("no system node")
		}
		input.System = []*sidecar.SessionRenderNode{node}
	}
	return input, nil
}

func (testSessionGatewayRenderer) Render(context *sidecar.SessionRenderContext) (*sidecar.InferRequest, error) {
	request := &sidecar.InferRequest{Model: "ctxhtest", Schema: json.RawMessage(context.Params)}
	for _, node := range context.System {
		request.Messages = append(request.Messages, &sidecar.InferMessage{Role: sidecar.InferRoleSystem,
			Parts: []*sidecar.InferPart{{Kind: sidecar.InferPartText, Text: string(node.Item)}}})
	}
	for _, node := range context.Nodes {
		request.Messages = append(request.Messages, &sidecar.InferMessage{Role: sidecar.InferRoleUser,
			Parts: []*sidecar.InferPart{{Kind: sidecar.InferPartText, Text: string(node.Item)}}})
	}
	return request, nil
}

func init() {
	sidecar.RegisterSessionRenderer(testSessionGatewayRenderer{})
}

// The world's fake run view as the recorder takes it.
type testSessionGatewayRuns struct {
	runs *sidecartest.FakeRunView

	stateLock sync.Mutex
	taints    []string
}

func (self *testSessionGatewayRuns) RunTainted(runId sidecar.Id) bool {
	return self.runs.RunTainted(runId)
}

func (self *testSessionGatewayRuns) TaintRun(ctx context.Context, runId sidecar.Id, reason sidecar.RunTaintReason) error {
	self.runs.Taint(runId)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.taints = append(self.taints, runId.String()+" "+string(reason))
	return nil
}

// The gateway's recorder over a journal world: the member's device, its runs on the world's fake run view, one grant.
type testSessionGatewayWorld struct {
	t        *testing.T
	journal  *testSessionJournalWorld
	runs     *testSessionGatewayRuns
	store    sidecar.SidecarStore
	recorder *sidecar.SessionGatewayRecorder
	grantId  sidecar.Id
	// the served set of web_search hashes and its store, nil until a test asks for them (session_stub_test.go)
	servedHashes *sidecar.SessionServedHashes
	servedStore  sidecar.SidecarStore

	stateLock sync.Mutex
	gaps      []string
}

func newTestSessionGatewayWorld(t *testing.T) *testSessionGatewayWorld {
	t.Helper()
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("session_gateway", "session")
	if err != nil {
		t.Fatal(err)
	}
	self := &testSessionGatewayWorld{
		t: t, journal: journalWorld, runs: &testSessionGatewayRuns{runs: journalWorld.world.runs}, store: store, grantId: sidecar.NewId(),
	}
	self.open()
	return self
}

// A new process's recorder over the journal world's journal and the index's store.
func (self *testSessionGatewayWorld) open() {
	self.t.Helper()
	recorder, err := sidecar.NewSessionGatewayRecorder(&sidecar.SessionGatewayRecorderArgs{
		Journal: self.journal.journal, Runs: self.runs, Store: self.store, Clock: self.journal.world.clock, Served: self.servedHashes,
		Gap: func(runId sidecar.Id, code string) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.gaps = append(self.gaps, runId.String()+" "+code)
		},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.recorder = recorder
}

// The gaps the recorder counted, taken.
func (self *testSessionGatewayWorld) takeGaps() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	gaps := self.gaps
	self.gaps = nil
	return gaps
}

// A binding under a run handle of a new run of the world's grant, its run file untainted.
func (self *testSessionGatewayWorld) bound() *sidecar.SessionGatewayBinding {
	runId := sidecar.NewId()
	agentId := sidecar.NewId()
	self.journal.world.runs.StartRun(runId)
	return &sidecar.SessionGatewayBinding{RunId: runId, AgentId: &agentId, GrantId: self.grantId, Handle: "handle-" + runId.String()}
}

// Begins a call of api on binding, which must take.
func (self *testSessionGatewayWorld) begin(binding *sidecar.SessionGatewayBinding, api sidecar.SessionGatewayApi, body []byte) *sidecar.SessionGatewayCall {
	self.t.Helper()
	call, err := self.recorder.Begin(self.t.Context(), binding, &sidecar.SessionGatewayRequest{Api: api, Renderer: testSessionGatewayRendererId, Body: body})
	if err != nil {
		self.t.Fatal(err)
	}
	return call
}

// One whole Responses call: Begin, each output item, End naming requestId. Answers the call, its end and the output
// nodes.
func (self *testSessionGatewayWorld) call(binding *sidecar.SessionGatewayBinding, body []byte, requestId string, outputs ...string) (*sidecar.SessionGatewayCall, *sidecar.SessionGatewayEnded, []sidecar.Id) {
	self.t.Helper()
	return self.callOf(binding, sidecar.SessionGatewayApiResponses, body, requestId, outputs...)
}

// callOf for any front.
func (self *testSessionGatewayWorld) callOf(binding *sidecar.SessionGatewayBinding, api sidecar.SessionGatewayApi, body []byte, requestId string, outputs ...string) (*sidecar.SessionGatewayCall, *sidecar.SessionGatewayEnded, []sidecar.Id) {
	self.t.Helper()
	call := self.begin(binding, api, body)
	nodeIds := []sidecar.Id{}
	for _, output := range outputs {
		nodeId, err := call.ResponseItem(self.t.Context(), []byte(output))
		if err != nil {
			self.t.Fatal(err)
		}
		nodeIds = append(nodeIds, nodeId)
	}
	ended, err := call.End(self.t.Context(), &sidecar.SessionGatewayEnd{RequestId: requestId})
	if err != nil {
		self.t.Fatal(err)
	}
	return call, ended, nodeIds
}

// A JSON string.
func testGatewayString(text string) string {
	encoded, _ := json.Marshal(text)
	return string(encoded)
}

// A Responses request: Codex's instructions and a shell tool, the input items given, stateless as Codex sends it.
func testResponsesBody(instructions string, items ...string) []byte {
	return []byte(`{"model":"local-test-model-high","instructions":` + testGatewayString(instructions) +
		`,"tools":[{"type":"function","name":"shell","description":"Run a command.","parameters":{"type":"object","properties":{"command":{"type":"array"}}}}]` +
		`,"tool_choice":"auto","parallel_tool_calls":false,"store":false,"stream":true,"include":["reasoning.encrypted_content"]` +
		`,"input":[` + strings.Join(items, ",") + `]}`)
}

// A user message as a request carries it.
func testResponsesUser(text string) string {
	return `{"type":"message","role":"user","content":[{"type":"input_text","text":` + testGatewayString(text) + `}]}`
}

// An assistant message as the gateway completes it, and as Codex carries it back.
func testResponsesAssistantDone(n int, text string) string {
	return fmt.Sprintf(`{"type":"message","id":"msg_%d","role":"assistant","status":"completed","content":[{"type":"output_text","text":%s,"annotations":[]}]}`, n, testGatewayString(text))
}

func testResponsesAssistant(text string) string {
	return `{"type":"message","role":"assistant","content":[{"type":"output_text","text":` + testGatewayString(text) + `}]}`
}

// A function call as the gateway completes it, and as Codex carries it back.
func testResponsesCallDone(n int, arguments string) string {
	return fmt.Sprintf(`{"type":"function_call","id":"fc_%d","call_id":"call_%d","name":"shell","arguments":%s,"status":"completed"}`, n, n, testGatewayString(arguments))
}

func testResponsesCall(n int, arguments string) string {
	return fmt.Sprintf(`{"type":"function_call","call_id":"call_%d","name":"shell","arguments":%s}`, n, testGatewayString(arguments))
}

// A function call's output.
func testResponsesCallOutput(n int, output string) string {
	return fmt.Sprintf(`{"type":"function_call_output","call_id":"call_%d","output":%s}`, n, testGatewayString(output))
}

// A reasoning item as the gateway completes it, its encrypted_content the gateway's sealed blob, which Codex carries
// back as it got it.
func testResponsesReasoning(n int, text string, blob string) string {
	return fmt.Sprintf(`{"type":"reasoning","id":"rs_%d","summary":[{"type":"summary_text","text":%s}],"encrypted_content":%s}`, n, testGatewayString(text), testGatewayString(blob))
}

// The vault's session entries of runId, by node id, and every session entry with its body.
func (self *testSessionGatewayWorld) stored(runId sidecar.Id) (map[sidecar.Id]*protocol.SessionEntryBody, []*sidecar.RecordReadEntry) {
	self.t.Helper()
	nodes, _, entries := self.journal.stored()
	of := map[sidecar.Id]*protocol.SessionEntryBody{}
	runEntries := []*sidecar.RecordReadEntry{}
	for _, entry := range entries {
		if entry.Kind() != sidecar.RecordKindSessionEntry || !bytes.Equal(entry.Header.Header.GetRunId(), runId.Bytes()) {
			continue
		}
		body := &protocol.SessionEntryBody{}
		if err := proto.Unmarshal(entry.Body, body); err != nil {
			self.t.Fatal(err)
		}
		of[sidecar.Id(body.GetNodeId())] = nodes[sidecar.Id(body.GetNodeId())]
		runEntries = append(runEntries, entry)
	}
	return of, runEntries
}

// Two sessions of one grant sending the same bytes are two runs sharing nothing (R2-04's acceptance): each run its own
// nodes and call contexts, no node of one named in the other, no parent link between them, and each answer journaled
// in its own run alone.
func TestSessionGatewayTwoSessionsIdenticalBytesTwoRuns(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	first, second := world.bound(), world.bound()
	body := testResponsesBody("You are Codex.", testResponsesUser("list the synthetic files"))
	outputs := []string{testResponsesReasoning(1, "Run ls.", "blob-1"), testResponsesCallDone(1, `{"command":["ls"]}`)}
	_, firstEnded, firstOutputs := world.call(first, body, "req-first", outputs...)
	_, secondEnded, secondOutputs := world.call(second, body, "req-second", outputs...)
	firstNodes, _ := world.stored(first.RunId)
	secondNodes, _ := world.stored(second.RunId)
	if len(firstNodes) != 4 || len(secondNodes) != 4 {
		t.Fatalf("%d and %d nodes, not a system node, the prompt and two answers each", len(firstNodes), len(secondNodes))
	}
	for nodeId, body := range secondNodes {
		if firstNodes[nodeId] != nil {
			t.Errorf("node %s in both runs", nodeId)
		}
		if len(body.GetParentRunId()) != 0 || len(body.GetSameAs()) != 0 {
			t.Error("a node of the second run names another run's or holds a same_as")
		}
	}
	for _, ended := range []*sidecar.SessionGatewayEnded{firstEnded, secondEnded} {
		if ended.Continues != nil {
			t.Error("a session continues another with no resume reported")
		}
	}
	nameOf := func(nodes map[sidecar.Id]*protocol.SessionEntryBody, context *protocol.CallContext) bool {
		ids := append([][]byte{context.GetInputNodeId(), context.GetSystemNodeId()}, context.GetOutputNodeIds()...)
		for _, id := range ids {
			if nodes[sidecar.Id(id)] == nil {
				return false
			}
		}
		return true
	}
	if !nameOf(firstNodes, firstEnded.Context) || !nameOf(secondNodes, secondEnded.Context) {
		t.Error("a call context names a node outside its own run")
	}
	if slices.ContainsFunc(firstOutputs, func(nodeId sidecar.Id) bool { return slices.Contains(secondOutputs, nodeId) }) {
		t.Error("an answer's node is shared across runs")
	}
}

// A cut call's retry is a second call on the same context node (§8.5, §24.8's order row): nothing of the request is
// written again, an answer item that repeats the cut call's is that node again, and only what is new is journaled.
func TestSessionGatewayCutCallRetryRecordedOnce(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	body := testResponsesBody("You are Codex.", testResponsesUser("run the synthetic tests"))
	// the cut call: its reasoning journaled, then the stream cut before the function call completed
	cut := world.begin(binding, sidecar.SessionGatewayApiResponses, body)
	cutReasoning, err := cut.ResponseItem(t.Context(), []byte(testResponsesReasoning(1, "Run the tests.", "blob-1")))
	if err != nil {
		t.Fatal(err)
	}
	cutEnded, err := cut.End(t.Context(), &sidecar.SessionGatewayEnd{})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := world.stored(binding.RunId)
	// the harness re-runs the turn: the same request, then the whole answer
	retry, retryEnded, outputs := world.call(binding, body, "req-retry",
		testResponsesReasoning(2, "Run the tests.", "blob-2"), testResponsesCallDone(2, `{"command":["go","test"]}`))
	if !slices.Equal(retry.InputNodeIds(), cut.InputNodeIds()) || !bytes.Equal(retryEnded.Context.GetInputNodeId(), cutEnded.Context.GetInputNodeId()) {
		t.Error("the retry's context is not the cut call's node")
	}
	if outputs[0] != cutReasoning {
		t.Error("a repeated answer item was journaled again")
	}
	after, _ := world.stored(binding.RunId)
	if len(after) != len(before)+1 {
		t.Errorf("%d nodes after the retry, %d before: only the function call is new", len(after), len(before))
	}
}

// A call bound by time alone records its entries flagged while any live run of its grant is tainted, and, its binding
// being inferred, flagged when none is too, so a reader takes them untrusted (D-CTXH-9); a bound call of an untainted
// run is not flagged.
func TestSessionGatewayUnboundCallFlaggedWhileAnyLiveRunTainted(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	bound := world.bound()
	world.call(bound, testResponsesBody("You are a harness.", testResponsesUser("a bound prompt")), "req-bound", testResponsesAssistantDone(1, "a bound answer"))
	for _, tainted := range []bool{true, false} {
		unbound := world.bound()
		unbound.Handle = ""
		unbound.Tainted = tainted
		world.call(unbound, testResponsesBody("You are a harness.", testResponsesUser(fmt.Sprintf("an unbound prompt %v", tainted))), "", testResponsesAssistantDone(2, "an unbound answer"))
		_, entries := world.stored(unbound.RunId)
		if len(entries) == 0 {
			t.Fatal("the unbound call recorded nothing")
		}
		for _, entry := range entries {
			if !entry.Flagged {
				t.Errorf("an unbound call's entry not flagged (union tainted %v)", tainted)
			}
		}
	}
	_, entries := world.stored(bound.RunId)
	for _, entry := range entries {
		if entry.Flagged {
			t.Error("a bound call of an untainted run flagged")
		}
	}
	if !slices.ContainsFunc(world.runs.taints, func(taint string) bool { return strings.HasSuffix(taint, string(sidecar.RunTaintUntrustedData)) }) {
		t.Errorf("an inferred run was not tainted untrusted: %v", world.runs.taints)
	}
}

// Each item is durable before the event that completes it (IC-19): killed once ResponseItem answered, as a tool Codex
// starts from response.output_item.done runs, the next life's record holds the item, as it holds the request Begin
// journaled before the call went upstream; and the run's next call finds them.
func TestSessionGatewayItemJournaledBeforeOutputItemDone(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	call := world.begin(binding, sidecar.SessionGatewayApiResponses, testResponsesBody("You are Codex.", testResponsesUser("read the synthetic notes")))
	itemNodeId, err := call.ResponseItem(t.Context(), []byte(testResponsesCallDone(1, `{"command":["cat","notes.md"]}`)))
	if err != nil {
		t.Fatal(err)
	}
	// the kill, before End and before the event went: a new life of the record, the journal and the recorder
	world.journal.open(nil)
	world.open()
	nodes, _ := world.stored(binding.RunId)
	if nodes[itemNodeId] == nil || nodes[call.InputNodeIds()[0]] == nil {
		t.Fatal("an item journaled before its event is not in the record after the kill")
	}
	// the turn goes on: the next request carries the call and its output, and only the output is new
	next := world.begin(binding, sidecar.SessionGatewayApiResponses, testResponsesBody("You are Codex.",
		testResponsesUser("read the synthetic notes"), testResponsesCall(1, `{"command":["cat","notes.md"]}`), testResponsesCallOutput(1, "the synthetic notes")))
	if inputs := next.InputNodeIds(); len(inputs) != 3 || inputs[1] != itemNodeId {
		t.Fatalf("the next call's context %v does not take the item journaled before the kill", inputs)
	}
	after, _ := world.stored(binding.RunId)
	if len(after) != len(nodes)+1 {
		t.Errorf("%d nodes after the next call, %d before", len(after), len(nodes))
	}
}

// A hook's or telemetry's model_call whose request id the gateway answered merges; one it never saw counts the run's
// gap context_partial and names its harness for ur status, until the window passes.
func TestSessionGatewayHookModelCallUnseenMarksContextPartial(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	world.call(binding, testResponsesBody("You are Codex.", testResponsesUser("a prompt")), "req-seen", testResponsesAssistantDone(1, "an answer"))
	if seen, err := world.recorder.HookModelCall(t.Context(), "codex", binding.RunId, "req-seen"); err != nil || !seen {
		t.Fatalf("a call the gateway answered: %v, %v", seen, err)
	}
	if gaps := world.takeGaps(); len(gaps) != 0 {
		t.Errorf("a merged call counted %v", gaps)
	}
	harnessRun := world.bound()
	if seen, err := world.recorder.HookModelCall(t.Context(), "claude-code", harnessRun.RunId, "req-unseen"); err != nil || seen {
		t.Fatalf("a call the gateway never saw: %v, %v", seen, err)
	}
	if gaps := world.takeGaps(); !slices.Equal(gaps, []string{harnessRun.RunId.String() + " " + sidecar.RecordCoverageGapContextPartial}) {
		t.Errorf("the unseen call counted %v", gaps)
	}
	partials := world.recorder.ContextPartial()
	if len(partials) != 1 || partials[0].Harness != "claude-code" || partials[0].RunId != harnessRun.RunId {
		t.Fatalf("partials %+v", partials)
	}
	if recorded, err := world.recorder.Recorded(binding.RunId); err != nil || !recorded {
		t.Errorf("a run the gateway recorded in reads %v, %v", recorded, err)
	}
	if recorded, _ := world.recorder.Recorded(harnessRun.RunId); recorded {
		t.Error("a run the gateway never recorded in reads recorded")
	}
	// a restart keeps what the index wrote; the window's end drops it
	world.open()
	if seen, err := world.recorder.HookModelCall(t.Context(), "codex", binding.RunId, "req-seen"); err != nil || !seen {
		t.Errorf("after a restart: %v, %v", seen, err)
	}
	world.journal.world.clock.Advance(25 * time.Hour)
	if err := world.recorder.Index().Sweep(); err != nil {
		t.Fatal(err)
	}
	if seen, _ := world.recorder.HookModelCall(t.Context(), "codex", binding.RunId, "req-seen"); seen {
		t.Error("a request id seen past the window")
	}
	if partials := world.recorder.ContextPartial(); len(partials) != 1 || partials[0].Harness != "codex" {
		t.Errorf("partials past the window %+v", partials)
	}
}

// End's request_sha256 is the renderer's hash of the context as recorded, which a rebuild from the vault on another
// device of the member verifies; a call with a redacted secret in its input reads inexact, and one with nothing
// marked exact.
func TestSessionGatewayRequestSha256Rebuilds(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	write := func(ended *sidecar.SessionGatewayEnded) {
		if ended.Unrendered != nil {
			t.Fatal(ended.Unrendered)
		}
		if _, err := world.journal.record.Writer().Append(&sidecar.RecordDraft{
			Kind: sidecar.RecordKindModelCall, Source: sidecar.RecordSourceObserved, RunId: &binding.RunId, AgentId: binding.AgentId,
			Body: &protocol.ModelCallBody{Model: "local-test-model-high", Provider: "local", Route: sidecar.RecordModelCallRouteLocal, Context: ended.Context},
		}); err != nil {
			t.Fatal(err)
		}
	}
	large := strings.Repeat("a synthetic log line of the build\n", 900)
	first := testResponsesBody("You are Codex.", testResponsesUser("why does the synthetic build fail?"), testResponsesCallOutput(1, large))
	_, ended, _ := world.call(binding, first, "req-1", testResponsesAssistantDone(1, "A symbol is missing."))
	if !ended.Context.GetExact() || ended.Context.GetRenderer() != testSessionGatewayRendererId || len(ended.Context.GetRequestSha256()) != 32 {
		t.Fatalf("a clean call's context %+v", ended.Context)
	}
	write(ended)
	secret := "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	second := testResponsesBody("You are Codex.", testResponsesUser("why does the synthetic build fail?"), testResponsesCallOutput(1, large),
		testResponsesAssistant("A symbol is missing."), testResponsesUser("the key is "+secret))
	_, redacted, _ := world.call(binding, second, "req-2", testResponsesAssistantDone(2, "Do not paste keys."))
	if redacted.Context.GetExact() {
		t.Error("a call carrying a redacted secret reads exact")
	}
	write(redacted)
	_, _, view := world.journal.openOn(t, binding.RunId)
	if len(view.Calls) != 2 {
		t.Fatalf("%d calls in the vault", len(view.Calls))
	}
	for n, want := range []sidecar.SessionCheck{sidecar.SessionCheckVerified, sidecar.SessionCheckInexact} {
		call, _ := view.Call(n + 1)
		rebuilt, err := sidecar.SessionRebuild(t.Context(), &sidecar.SessionRebuildArgs{Run: view, Call: call})
		if err != nil {
			t.Fatal(err)
		}
		if rebuilt.Check != want {
			t.Errorf("call %d rebuilt %s (%s), not %s", n+1, rebuilt.Check, rebuilt.Fault, want)
		}
	}
	for _, node := range view.Nodes {
		if node.Body != nil && bytes.Contains(node.Body.GetItem(), []byte(secret)) {
			t.Error("the secret reached a node")
		}
	}
}

// A renderer this build does not hold records none: the call's context names no renderer and no request_sha256, so a
// rebuild reads it unverifiable and never alarms once the renderer registers.
func TestSessionGatewayUnknownRendererRecordsNone(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	call, err := world.recorder.Begin(t.Context(), binding, &sidecar.SessionGatewayRequest{
		Api: sidecar.SessionGatewayApiResponses, Renderer: "gateway-responses-99", Body: testResponsesBody("You are Codex.", testResponsesUser("a prompt")),
	})
	if err != nil {
		t.Fatal(err)
	}
	ended, err := call.End(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(ended.Unrendered, sidecar.ErrSessionGatewayUnrendered) || ended.Context.GetRenderer() != "" || len(ended.Context.GetRequestSha256()) != 0 {
		t.Errorf("an unknown renderer: %v, %+v", ended.Unrendered, ended.Context)
	}
	if _, err := call.End(t.Context(), nil); !errors.Is(err, sidecar.ErrSessionGatewayCallEnded) {
		t.Errorf("a second End: %v", err)
	}
	if _, err := call.ResponseItem(t.Context(), []byte(testResponsesAssistantDone(1, "late"))); !errors.Is(err, sidecar.ErrSessionGatewayCallEnded) {
		t.Errorf("an item after End: %v", err)
	}
}

// A request naming stored context, previous_response_id or a conversation, does not carry its context and records
// nothing (Q-CTXH-9: the gateway stays stateless); nor does a request of a front this build does not record, or one
// with an item that is no object.
func TestSessionGatewayRefusesWhatItCannotRecordWhole(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	for _, request := range []*sidecar.SessionGatewayRequest{
		{Api: sidecar.SessionGatewayApiResponses, Body: []byte(`{"model":"m","previous_response_id":"resp_1","input":[]}`)},
		{Api: sidecar.SessionGatewayApiResponses, Body: []byte(`{"model":"m","conversation":"conv_1","input":"hi"}`)},
		{Api: sidecar.SessionGatewayApiResponses, Body: []byte(`{"model":"m","input":["not an object"]}`)},
		{Api: sidecar.SessionGatewayApiResponses, Body: []byte(`[]`)},
		{Api: "gemini", Body: []byte(`{"contents":[]}`)},
	} {
		if _, err := world.recorder.Begin(t.Context(), binding, request); !errors.Is(err, sidecar.ErrSessionGatewayRefused) {
			t.Errorf("%s: %v", request.Body, err)
		}
	}
	if _, err := world.recorder.Begin(t.Context(), &sidecar.SessionGatewayBinding{GrantId: world.grantId}, &sidecar.SessionGatewayRequest{
		Api: sidecar.SessionGatewayApiResponses, Body: testResponsesBody("x"),
	}); !errors.Is(err, sidecar.ErrSessionGatewayRefused) {
		t.Errorf("a binding with no run: %v", err)
	}
	if nodes, _ := world.stored(binding.RunId); len(nodes) != 0 {
		t.Errorf("a refused request recorded %d nodes", len(nodes))
	}
}

// The index across a restart and past its window: a restarted recorder finds the run's prefix and knows its nodes,
// so a call reads exact; past the window the run's segments are gone, its next request still lands on the nodes the
// journal holds, nothing written twice, and reads inexact, its nodes' exactness unknown.
func TestSessionGatewayIndexAcrossRestartAndWindow(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	items := []string{testResponsesUser("a synthetic prompt")}
	world.call(binding, testResponsesBody("You are Codex.", items...), "req-1", testResponsesAssistantDone(1, "an answer"))
	items = append(items, testResponsesAssistant("an answer"), testResponsesUser("a second prompt"))
	world.open()
	call, ended, _ := world.call(binding, testResponsesBody("You are Codex.", items...), "req-2", testResponsesAssistantDone(2, "a second answer"))
	if !ended.Context.GetExact() || len(call.InputNodeIds()) != 3 {
		t.Fatalf("after a restart: exact %v, %d inputs", ended.Context.GetExact(), len(call.InputNodeIds()))
	}
	before, _ := world.stored(binding.RunId)
	world.journal.world.clock.Advance(25 * time.Hour)
	if err := world.recorder.Index().Sweep(); err != nil {
		t.Fatal(err)
	}
	if entries, err := world.store.List(""); err != nil || len(entries) != 0 {
		t.Fatalf("segments past the window: %d, %v", len(entries), err)
	}
	items = append(items, testResponsesAssistant("a second answer"), testResponsesUser("a third prompt"))
	later, ended, _ := world.call(binding, testResponsesBody("You are Codex.", items...), "req-3")
	after, _ := world.stored(binding.RunId)
	if len(after) != len(before)+1 || later.InputNodeIds()[0] != call.InputNodeIds()[0] {
		t.Errorf("%d nodes past the window, %d before", len(after), len(before))
	}
	if ended.Context.GetExact() {
		t.Error("a call over nodes the index forgot reads exact")
	}
}

// A run of one grant is never recorded into under another.
func TestSessionGatewayRunOfAnotherGrantRefused(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	world.call(binding, testResponsesBody("You are Codex.", testResponsesUser("a prompt")), "req-1")
	other := *binding
	other.GrantId = sidecar.NewId()
	if _, err := world.recorder.Begin(t.Context(), &other, &sidecar.SessionGatewayRequest{
		Api: sidecar.SessionGatewayApiResponses, Body: testResponsesBody("You are Codex.", testResponsesUser("a prompt")),
	}); !errors.Is(err, sidecar.ErrSessionGatewayRefused) {
		t.Errorf("another grant's call into the run: %v", err)
	}
}
