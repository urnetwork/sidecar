//go:build !ios_extension && !sidecar_http && !js

// CTXH-M11-04's rebuilds (DESIGN-COMPUTE §24.6, §24.16's Rebuild row; R-CTXH-2, D-CTXH-4) on sidecartest's streams: a
// corpus run journaled as the Harness journals it, every call's CallContext rendered by harness-1 from the nodes as
// recorded, and every call rebuilt on another device of the member from the vault to its request_sha256: compactions,
// a branch, model and effort changes, a sub-agent's run beside its parent's, a retry, an untrusted result and a part
// past the item cap among them; calls with a redaction or a stub reading inexact and differing from what was sent
// exactly at their marked nodes; a part not held or a node not held reading unverifiable with no alarm; a piece that
// fails its part's hash alarming; and a mail reference re-rendered from its mailbox, its message's erasure reading the
// call inexact. External, on session_journal_test.go's world.

package sidecar_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One node a recorder journaled: the entry as the Harness built it, what the journal answered, and its trust.
type testSessionRecorded struct {
	entry     *sidecar.HarnessPiEntry
	journaled *sidecar.SessionJournaled
	untrusted bool
	sender    string
}

// A run journaled as HARN's loop journals it (HARN-M11-08's wiring, which a test stands in for here), each call's
// model_call carrying its CallContext.
type testSessionRecorder struct {
	t       *testing.T
	world   *testSessionJournalWorld
	run     *sidecar.SessionRun
	model   string
	nodes   map[string]*testSessionRecorded
	nodeIds map[sidecar.Id]*testSessionRecorded
	// the CallContexts written, in order
	contexts []*protocol.CallContext
	clock    time.Time
}

// A recorder of a new run, its run file written untainted, as a Harness run starts.
func newTestSessionRecorder(t *testing.T, world *testSessionJournalWorld) *testSessionRecorder {
	agentId := sidecar.NewId()
	runId := sidecar.NewId()
	world.world.runs.StartRun(runId)
	return &testSessionRecorder{
		t: t, world: world, run: &sidecar.SessionRun{RunId: runId, AgentId: &agentId}, model: "local-test-model-high",
		nodes: map[string]*testSessionRecorded{}, nodeIds: map[sidecar.Id]*testSessionRecorded{}, clock: time.UnixMilli(1_800_000_000_000),
	}
}

// The recorder's next timestamp.
func (self *testSessionRecorder) now() time.Time {
	self.clock = self.clock.Add(time.Second)
	return self.clock
}

// Journals entry, untrusted where sender is set, with tool's form for a tool result.
func (self *testSessionRecorder) journal(entry *sidecar.HarnessPiEntry, sender string, tool *sidecar.SessionToolResult) *testSessionRecorded {
	self.t.Helper()
	run, node, err := sidecar.SessionNodeOfHarness(&sidecar.HarnessJournalNode{
		RunId: self.run.RunId, AgentId: *self.run.AgentId, Entry: entry, Untrusted: sender != "", Sender: sender,
	}, tool)
	if err != nil {
		self.t.Fatal(err)
	}
	journaled := self.world.journalNodes(run, node)[0]
	recorded := &testSessionRecorded{entry: entry, journaled: journaled, untrusted: sender != "", sender: sender}
	self.nodes[entry.Id()] = recorded
	self.nodeIds[journaled.NodeId] = recorded
	return recorded
}

// A message entry journaled under parent.
func (self *testSessionRecorder) message(parent string, message *sidecar.HarnessPiMessage, sender string) string {
	self.t.Helper()
	id := sidecar.NewHarnessPiEntryId()
	self.journal(sidecar.NewHarnessPiMessageEntry(id, parent, self.now(), message), sender, nil)
	return id
}

// The node a render reads of recorded, as recorded or as sent.
func (self *testSessionRecorder) renderNode(recorded *testSessionRecorded, asSent bool) *sidecar.SessionRenderNode {
	self.t.Helper()
	journaled := recorded.journaled
	node := &sidecar.SessionRenderNode{NodeId: journaled.NodeId, Type: sidecar.SessionNodeTypeOfPi(recorded.entry.Type())}
	if asSent {
		raw, err := sidecar.SessionHarnessEntryWithTrust(recorded.entry, recorded.untrusted, recorded.sender).Json()
		if err != nil {
			self.t.Fatal(err)
		}
		if node.Item, err = sidecar.CanonicalJson(raw); err != nil {
			self.t.Fatal(err)
		}
		return node
	}
	node.Item = journaled.Item
	parts := journaled
	if journaled.SameAs != nil {
		parts = self.nodeIds[*journaled.SameAs].journaled
	}
	node.Parts = parts.Parts
	return node
}

// The path from input to its root, each node in the form asked.
func (self *testSessionRecorder) path(input string, asSent bool) []*sidecar.SessionRenderNode {
	self.t.Helper()
	path := []*sidecar.SessionRenderNode{}
	for id := input; id != ""; {
		recorded := self.nodes[id]
		if recorded == nil {
			self.t.Fatalf("no node %s", id)
		}
		path = append([]*sidecar.SessionRenderNode{self.renderNode(recorded, asSent)}, path...)
		id, _ = recorded.entry.ParentId()
	}
	return path
}

// The params of a call on the recorder's model.
func (self *testSessionRecorder) params() []byte {
	self.t.Helper()
	encoded, err := json.Marshal(&sidecar.InferRequest{Model: self.model, MaxOutput: 2048, RunId: &self.run.RunId, AgentId: self.run.AgentId})
	if err != nil {
		self.t.Fatal(err)
	}
	params, err := sidecar.CanonicalJson(encoded)
	if err != nil {
		self.t.Fatal(err)
	}
	return params
}

// The input of a call at input under the system node system, its nodes in the form asked.
func (self *testSessionRecorder) input(input string, system string, asSent bool) *sidecar.SessionRenderInput {
	self.t.Helper()
	renderer, err := sidecar.SessionRendererOf(sidecar.SessionRendererHarness1)
	if err != nil {
		self.t.Fatal(err)
	}
	systemNodeId := self.nodes[system].journaled.NodeId
	rendered, err := renderer.Context(self.path(input, asSent), &systemNodeId, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	rendered.Params = self.params()
	return rendered
}

// One model call at input under system: its CallContext, request_sha256 rendered by harness-1 from the nodes as
// recorded, exact where nothing it carries was redacted, stubbed or omitted, written in a model_call as the Harness
// writes it only after its context's nodes.
func (self *testSessionRecorder) call(input string, system string) *protocol.CallContext {
	self.t.Helper()
	renderer, err := sidecar.SessionRendererOf(sidecar.SessionRendererHarness1)
	if err != nil {
		self.t.Fatal(err)
	}
	recorded := self.input(input, system, false)
	sum, err := sidecar.SessionRequestSha256(renderer, recorded)
	if err != nil {
		self.t.Fatal(err)
	}
	exact := true
	for id := input; id != ""; {
		journaled := self.nodes[id].journaled
		if 0 < journaled.Redactions || 0 < journaled.Stubs {
			exact = false
		}
		for _, part := range journaled.Parts {
			if part.GetOmitted() {
				exact = false
			}
		}
		id, _ = self.nodes[id].entry.ParentId()
	}
	context := &protocol.CallContext{
		InputNodeId: self.nodes[input].journaled.NodeId.Bytes(), SystemNodeId: self.nodes[system].journaled.NodeId.Bytes(),
		RequestSha256: sum[:], Exact: exact, Renderer: sidecar.SessionRendererHarness1, Params: recorded.Params,
	}
	if _, err := self.world.record.Writer().Append(&sidecar.RecordDraft{
		Kind: sidecar.RecordKindModelCall, Source: sidecar.RecordSourceObserved, RunId: &self.run.RunId, AgentId: self.run.AgentId,
		Body: &protocol.ModelCallBody{Model: self.model, Provider: "local", Route: sidecar.RecordModelCallRouteLocal, Context: context},
	}); err != nil {
		self.t.Fatal(err)
	}
	self.contexts = append(self.contexts, context)
	return context
}

// An agent's first system message: the skill, its instructions and a tool.
func testSessionRebuildSystem(instructions string) *sidecar.HarnessPiMessage {
	return sidecar.NewHarnessPiSystemMessage(
		[]*sidecar.HarnessPiSection{{Name: "skill", Text: "You are an agent of ur."}, {Name: "instructions", Text: instructions}},
		[]*sidecar.HarnessPiTool{{Name: "evs_read", Description: "Read a file.", Parameters: json.RawMessage(`{"type":"object"}`)}},
		1_800_000_000_000)
}

// An assistant message with text and tool calls.
func testSessionRebuildAssistant(text string, thinking string, toolCalls ...*sidecar.HarnessPiToolCall) *sidecar.HarnessPiMessage {
	blocks := []*sidecar.HarnessPiBlock{}
	if thinking != "" {
		blocks = append(blocks, sidecar.NewHarnessPiThinkingBlock(thinking))
	}
	if text != "" {
		blocks = append(blocks, sidecar.NewHarnessPiTextBlock(text))
	}
	for _, toolCall := range toolCalls {
		blocks = append(blocks, sidecar.NewHarnessPiToolCallBlock(toolCall))
	}
	return sidecar.NewHarnessPiAssistantMessage(&sidecar.HarnessPiAssistant{Content: blocks, Api: sidecar.HarnessPiApi, Provider: "local",
		Model: "local-test-model-high", StopReason: sidecar.HarnessPiStopStop, TimestampMs: 1_800_000_000_000})
}

// A user message.
func testSessionRebuildUser(text string) *sidecar.HarnessPiMessage {
	return sidecar.NewHarnessPiUserMessage(text, nil, 1_800_000_000_000)
}

// A tool's result message.
func testSessionRebuildResult(callId string, tool string, text string) *sidecar.HarnessPiMessage {
	return sidecar.NewHarnessPiToolResultMessage(callId, tool, []*sidecar.HarnessPiBlock{sidecar.NewHarnessPiTextBlock(text)}, nil, false, 1_800_000_000_000)
}

// Another consented device of the member: the run read from the vault, every body fetched as it opens.
func (self *testSessionJournalWorld) openOn(t *testing.T, runId sidecar.Id) (*testRecordDevice, *sidecar.SidecarRecord, *sidecar.SessionRunView) {
	t.Helper()
	if err := self.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	device := self.world.device(true)
	record := device.open()
	view, err := record.SessionReader().Open(t.Context(), self.world.vaultId, runId)
	if err != nil {
		t.Fatal(err)
	}
	return device, record, view
}

// A corpus of Harness runs, each call rebuilt on another device of the member from the vault to its request_sha256:
// a prompt and a tool call, an untrusted result past the item cap kept as a part, its retry, a model and an effort
// change, a branch from an earlier answer, a compaction's own call and the call after it, a system message's patch,
// and a sub-agent's run, whose first node is a link root naming its parent's run and node.
func TestSessionRebuildCorpusMatchesRequestHashes(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	parent := newTestSessionRecorder(t, world)
	system := parent.message("", testSessionRebuildSystem("Fix the build."), "")
	change := sidecar.NewHarnessPiEntryId()
	parent.journal(sidecar.NewHarnessPiModelChangeEntry(change, system, parent.now(), &sidecar.HarnessPiModelChange{Provider: "local", ModelId: parent.model, ChangedBy: sidecar.HarnessModelChangedByPerson}), "", nil)
	prompt := parent.message(change, testSessionRebuildUser("Why does the build fail?"), "")
	parent.call(prompt, system)
	asked := parent.message(prompt, testSessionRebuildAssistant("Reading the log.", "Look at the log.",
		&sidecar.HarnessPiToolCall{Id: "call_1", Name: "evs_read", Arguments: json.RawMessage(`{"path":"build.log"}`)}), "")
	result := parent.message(asked, testSessionRebuildResult("call_1", "evs_read", strings.Repeat("error: a missing symbol\n", 1200)), "evs:build.log")
	if len(parent.nodes[result].journaled.Parts) == 0 {
		t.Fatal("the large result kept no part")
	}
	parent.call(result, system)
	// a cut call's retry: a second call on the same context node
	parent.call(result, system)
	answer := parent.message(result, testSessionRebuildAssistant("A symbol is missing.", ""), "")
	effort := sidecar.NewHarnessPiEntryId()
	parent.journal(sidecar.NewHarnessPiThinkingLevelChangeEntry(effort, answer, parent.now(), "low"), "", nil)
	switched := sidecar.NewHarnessPiEntryId()
	parent.journal(sidecar.NewHarnessPiModelChangeEntry(switched, effort, parent.now(), &sidecar.HarnessPiModelChange{Provider: "local", ModelId: "local-smaller-model-low", PreviousModelId: parent.model, ChangedBy: sidecar.HarnessModelChangedByAgent}), "", nil)
	parent.model = "local-smaller-model-low"
	fix := parent.message(switched, testSessionRebuildUser("Fix it."), "")
	parent.call(fix, system)
	// a branch: another prompt from the same answer
	branch := parent.message(answer, testSessionRebuildUser("Explain it instead."), "")
	parent.call(branch, system)
	// a compaction: its call renders from the instruction off the path, then the summary joins the path
	fixed := parent.message(fix, testSessionRebuildAssistant("Fixed.", ""), "")
	instruction := sidecar.NewHarnessPiEntryId()
	parent.journal(sidecar.NewHarnessPiCustomMessageEntry(instruction, fixed, parent.now(), "ur-harness-compaction", "Summarize the conversation above.", false), "", nil)
	parent.call(instruction, system)
	compaction := sidecar.NewHarnessPiEntryId()
	parent.journal(sidecar.NewHarnessPiCompactionEntry(compaction, fixed, parent.now(), "The build missed a symbol; it is fixed.", fix, 4000), "", nil)
	after := parent.message(compaction, testSessionRebuildUser("Run the tests."), "")
	parent.call(after, system)
	// a system message's patch, in force from the next call
	patch := parent.message(after, sidecar.NewHarnessPiSystemMessage([]*sidecar.HarnessPiSection{{Name: "instructions", Text: "Run only the fast tests."}},
		[]*sidecar.HarnessPiTool{{Name: "evs_write", Description: "Write a file.", Parameters: json.RawMessage(`{"type":"object"}`)}}, 1_800_000_000_000), "")
	patched := parent.message(patch, testSessionRebuildUser("Go on."), "")
	parent.call(patched, patch)
	// a sub-agent: a link in the parent's tree, and the child's own run from a link root naming the parent's node
	child := newTestSessionRecorder(t, world)
	parent.journal(sidecar.NewHarnessPiLinkEntry(sidecar.NewHarnessPiEntryId(), patched, parent.now(), &sidecar.HarnessPiLink{To: sidecar.HarnessPiLinkChild, AgentId: *child.run.AgentId, RunId: child.run.RunId, Place: "local"}), "", nil)
	root := sidecar.NewHarnessPiEntryId()
	child.journal(sidecar.NewHarnessPiLinkEntry(root, "", child.now(), &sidecar.HarnessPiLink{To: sidecar.HarnessPiLinkParent, AgentId: *parent.run.AgentId, RunId: parent.run.RunId, Place: "local", NodeId: patched}), "", nil)
	childSystem := child.message(root, testSessionRebuildSystem("Run the fast tests."), "")
	childPrompt := child.message(childSystem, testSessionRebuildUser("Run them."), "")
	child.call(childPrompt, childSystem)

	device, _, view := world.openOn(t, parent.run.RunId)
	if len(view.Calls) != len(parent.contexts) || view.Fetched == 0 {
		t.Fatalf("the vault holds %d calls of %d, %d bodies fetched", len(view.Calls), len(parent.contexts), view.Fetched)
	}
	for n := range parent.contexts {
		call, _ := view.Call(n + 1)
		rebuilt, err := sidecar.SessionRebuild(t.Context(), &sidecar.SessionRebuildArgs{Run: view, Call: call})
		if err != nil {
			t.Fatal(err)
		}
		if rebuilt.Check != sidecar.SessionCheckVerified || !bytes.Equal(rebuilt.RequestSha256[:], parent.contexts[n].GetRequestSha256()) || rebuilt.Request == nil {
			t.Errorf("call %d rebuilt %s (%s) to %x, not %x", n+1, rebuilt.Check, rebuilt.Fault, rebuilt.RequestSha256, parent.contexts[n].GetRequestSha256())
			for _, node := range rebuilt.Path {
				if node.Check != sidecar.SessionCheckVerified {
					t.Logf("  node %x: %s %s", node.NodeId[:4], node.Check, node.Why)
				}
			}
		}
	}
	// the compaction's later call reads the summary first, then the kept messages
	call, _ := view.Call(7)
	rebuilt, err := sidecar.SessionRebuild(t.Context(), &sidecar.SessionRebuildArgs{Run: view, Call: call})
	if err != nil || rebuilt.Request == nil || len(rebuilt.Request.Messages) < 3 || !strings.Contains(rebuilt.Request.Messages[1].Text(), "it is fixed") {
		t.Fatalf("the call after the compaction: %+v, %v", rebuilt, err)
	}
	childView, err := device.open().SessionReader().Open(t.Context(), world.world.vaultId, child.run.RunId)
	if err != nil {
		t.Fatal(err)
	}
	childCall, _ := childView.Call(1)
	childRebuilt, err := sidecar.SessionRebuild(t.Context(), &sidecar.SessionRebuildArgs{Run: childView, Call: childCall})
	if err != nil || childRebuilt.Check != sidecar.SessionCheckVerified {
		t.Fatalf("the sub-agent's call: %+v, %v", childRebuilt, err)
	}
	for _, reason := range device.alarmReasons() {
		t.Errorf("an alarm: %s", reason)
	}
}

// A call whose context holds a redacted secret and a web search's stub reads inexact: the rebuild is the recorded
// form, its counts naming one redaction and one stub, and it differs from the request as sent exactly at the two
// marked nodes' messages, every other message equal.
func TestSessionRedactedAndStubbedDifferOnlyAtMarkedNodes(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	recorder := newTestSessionRecorder(t, world)
	system := recorder.message("", testSessionRebuildSystem("Help."), "")
	secret := "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	prompt := recorder.message(system, testSessionRebuildUser("My token is "+secret+"; search the docs."), "")
	asked := recorder.message(prompt, testSessionRebuildAssistant("", "", &sidecar.HarnessPiToolCall{Id: "call_s", Name: "web_search", Arguments: json.RawMessage(`{"query":"docs"}`)}), "")
	searched := sidecar.NewHarnessPiEntryId()
	recorder.journal(sidecar.NewHarnessPiMessageEntry(searched, asked, recorder.now(), testSessionRebuildResult("call_s", "web_search", "Result one; result two.")), "web_search",
		&sidecar.SessionToolResult{Name: "web_search", BuiltIn: true, KeepFalse: true})
	answer := recorder.message(searched, testSessionRebuildAssistant("Here is what I found.", ""), "")
	next := recorder.message(answer, testSessionRebuildUser("Thanks."), "")
	context := recorder.call(next, system)
	if context.GetExact() {
		t.Fatal("a call with a redaction and a stub is exact")
	}

	_, _, view := world.openOn(t, recorder.run.RunId)
	call, _ := view.Call(1)
	rebuilt, err := sidecar.SessionRebuild(t.Context(), &sidecar.SessionRebuildArgs{Run: view, Call: call})
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Check != sidecar.SessionCheckInexact || rebuilt.Redactions != 1 || rebuilt.Stubs != 1 || rebuilt.Request == nil {
		t.Fatalf("the rebuild: %s, %d redactions, %d stubs", rebuilt.Check, rebuilt.Redactions, rebuilt.Stubs)
	}
	renderer, err := sidecar.SessionRendererOf(sidecar.SessionRendererHarness1)
	if err != nil {
		t.Fatal(err)
	}
	sent, err := sidecar.SessionRenderRequest(renderer, recorder.input(next, system, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(sent.Messages) != len(rebuilt.Request.Messages) {
		t.Fatalf("%d messages sent, %d rebuilt", len(sent.Messages), len(rebuilt.Request.Messages))
	}
	differ := []int{}
	for i := range sent.Messages {
		if sent.Messages[i].Text() != rebuilt.Request.Messages[i].Text() {
			differ = append(differ, i)
		}
	}
	// the system message, the prompt with its secret, the call, the search's result, the answer, the thanks
	if len(differ) != 2 || differ[0] != 1 || differ[1] != 3 {
		t.Fatalf("messages %v differ", differ)
	}
	if strings.Contains(rebuilt.Request.Messages[1].Text(), secret) || !strings.Contains(rebuilt.Request.Messages[1].Text(), "[REDACTED:") ||
		strings.Contains(rebuilt.Request.Messages[3].Text(), "result two") {
		t.Fatalf("the rebuilt marked nodes: %q, %q", rebuilt.Request.Messages[1].Text(), rebuilt.Request.Messages[3].Text())
	}
}

// A part this device does not hold, its pieces not fetched, reads unverifiable at its node, the call's hash still
// checked and equal, with no alarm; a node whose body is not held cuts the path, the call unverifiable at it, again
// with no alarm.
func TestSessionPrunedOrErasedReadsUnverifiableWithoutAlarm(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	recorder := newTestSessionRecorder(t, world)
	system := recorder.message("", testSessionRebuildSystem("Read."), "")
	prompt := recorder.message(system, testSessionRebuildUser("Read big.txt."), "")
	asked := recorder.message(prompt, testSessionRebuildAssistant("", "", &sidecar.HarnessPiToolCall{Id: "call_b", Name: "evs_read", Arguments: json.RawMessage(`{"path":"big.txt"}`)}), "")
	result := recorder.message(asked, testSessionRebuildResult("call_b", "evs_read", strings.Repeat("a large line\n", 2000)), "")
	recorder.call(result, system)
	if err := world.record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}

	// the nodes fetched, the blobs not: the part is not held
	device := world.world.device(true)
	record := device.open()
	reader := record.SessionReader()
	if _, err := reader.Headers(t.Context(), world.world.vaultId, recorder.run.RunId); err != nil {
		t.Fatal(err)
	}
	if _, err := record.Reader().FetchBodies(t.Context(), world.world.vaultId, func(entry *sidecar.RecordReadEntry) bool {
		return entry.Kind() == sidecar.RecordKindSessionEntry
	}); err != nil {
		t.Fatal(err)
	}
	view, err := reader.Headers(t.Context(), world.world.vaultId, recorder.run.RunId)
	if err != nil {
		t.Fatal(err)
	}
	call, _ := view.Call(1)
	rebuilt, err := sidecar.SessionRebuild(t.Context(), &sidecar.SessionRebuildArgs{Run: view, Call: call})
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Check != sidecar.SessionCheckUnverifiable || rebuilt.Fault != "" || !bytes.Equal(rebuilt.RequestSha256[:], recorder.contexts[0].GetRequestSha256()) {
		t.Fatalf("a part not held: %s (%s), hash %x", rebuilt.Check, rebuilt.Fault, rebuilt.RequestSha256)
	}
	marked := false
	for _, node := range rebuilt.Path {
		marked = marked || strings.Contains(node.Why, "[pruned: ")
	}
	if !marked || rebuilt.Request == nil || !strings.Contains(rebuilt.Request.Messages[len(rebuilt.Request.Messages)-1].Text(), "[pruned: ") {
		t.Fatalf("the pruned part is not shown by its marker: %+v", rebuilt.Path)
	}

	// a node whose body is not held: the result's
	other := world.world.device(true)
	otherRecord := other.open()
	otherReader := otherRecord.SessionReader()
	if _, err := otherReader.Headers(t.Context(), world.world.vaultId, recorder.run.RunId); err != nil {
		t.Fatal(err)
	}
	resultEntryId := recorder.nodes[result].journaled.Entry.EntryId
	if _, err := otherRecord.Reader().FetchBodies(t.Context(), world.world.vaultId, func(entry *sidecar.RecordReadEntry) bool {
		return entry.EntryId != resultEntryId
	}); err != nil {
		t.Fatal(err)
	}
	cut, err := otherReader.Headers(t.Context(), world.world.vaultId, recorder.run.RunId)
	if err != nil {
		t.Fatal(err)
	}
	cutCall, _ := cut.Call(1)
	rebuilt, err = sidecar.SessionRebuild(t.Context(), &sidecar.SessionRebuildArgs{Run: cut, Call: cutCall})
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Check != sidecar.SessionCheckUnverifiable || rebuilt.Fault != "" || rebuilt.Request != nil {
		t.Fatalf("a node not held: %s (%s)", rebuilt.Check, rebuilt.Fault)
	}
	for _, reasons := range [][]sidecar.SidecarRecordAlarm{device.alarmReasons(), other.alarmReasons()} {
		for _, reason := range reasons {
			t.Errorf("an alarm: %s", reason)
		}
	}
}

// A blob whose piece is not its part's bytes: the reader shows its node invalid and alarms bad_entry, and the call's
// rebuild is an integrity alarm.
func TestSessionTamperedBlobAlarms(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	recorder := newTestSessionRecorder(t, world)
	system := recorder.message("", testSessionRebuildSystem("Read."), "")
	prompt := recorder.message(system, testSessionRebuildUser("Read big.txt."), "")
	result := recorder.message(prompt, testSessionRebuildResult("call_t", "evs_read", strings.Repeat("a large line\n", 2000)), "")
	journaled := recorder.nodes[result].journaled
	part := journaled.Parts[0]
	// a piece of another part's bytes, under the honest part's hash, filed in the run beside the honest one
	forged, err := world.record.Writer().Append(&sidecar.RecordDraft{
		Kind: sidecar.RecordKindSessionBlob, Source: sidecar.RecordSourceObserved, RunId: &recorder.run.RunId, AgentId: recorder.run.AgentId, Rides: true,
		Body: &protocol.SessionBlobBody{PartSha256: part.GetSha256(), Index: 0, Count: 1, Content: bytes.Repeat([]byte("x"), int(part.GetSize()))},
	})
	if err != nil {
		t.Fatal(err)
	}
	// a node naming the forged piece for its part: the journal never writes one, so it is filed by hand
	item := journaled.Item
	body := &protocol.SessionEntryBody{
		NodeId: sidecar.NewId().Bytes(), ParentNodeId: journaled.NodeId.Bytes(), Type: uint32(sidecar.SessionNodeMessage), Item: item,
		Parts:      []*protocol.SessionPart{{Pointer: part.GetPointer(), Sha256: part.GetSha256(), Size: part.GetSize(), MediaType: part.GetMediaType(), BlobEntryIds: [][]byte{forged[0].EntryId.Bytes()}}},
		ItemSha256: journaled.ItemSha256[:],
	}
	chain := testSessionChain(journaled.ChainSha256[:], journaled.ItemSha256[:])
	body.ChainSha256 = chain[:]
	if _, err := world.record.Writer().Append(&sidecar.RecordDraft{
		Kind: sidecar.RecordKindSessionEntry, Source: sidecar.RecordSourceObserved, RunId: &recorder.run.RunId, AgentId: recorder.run.AgentId, Rides: true, Body: body,
	}); err != nil {
		t.Fatal(err)
	}
	device, _, view := world.openOn(t, recorder.run.RunId)
	invalid := 0
	for _, read := range view.Nodes {
		if read.Invalid != nil && errors.Is(read.Invalid, sidecar.ErrSessionPartInvalid) {
			invalid += 1
		}
	}
	if invalid != 1 {
		t.Fatalf("%d nodes invalid for a forged piece", invalid)
	}
	alarmed := false
	for _, reason := range device.alarmReasons() {
		alarmed = alarmed || reason == sidecar.SidecarRecordAlarmBadEntry
	}
	if !alarmed {
		t.Fatal("no bad_entry for a forged piece")
	}
	// a call whose input is the forged node alarms as an integrity fault
	context := &protocol.CallContext{InputNodeId: body.GetNodeId(), SystemNodeId: recorder.nodes[system].journaled.NodeId.Bytes(),
		RequestSha256: bytes.Repeat([]byte{1}, 32), Exact: true, Renderer: sidecar.SessionRendererHarness1, Params: recorder.params()}
	rebuilt, err := sidecar.SessionRebuild(t.Context(), &sidecar.SessionRebuildArgs{Run: view, Call: &sidecar.SessionReadCall{Body: &protocol.ModelCallBody{Context: context}}})
	if err != nil || rebuilt.Check != sidecar.SessionCheckAlarm || rebuilt.Fault != sidecar.SessionFaultIntegrity {
		t.Fatalf("the forged node's call: %+v, %v", rebuilt, err)
	}
}

// chain_sha256 of a node under a parent.
func testSessionChain(parentChain []byte, itemSha256 []byte) [32]byte {
	digest := testSessionSha256(string(append(append([]byte{}, parentChain...), itemSha256...)))
	return digest
}

// MAILCAL's restorer as a test sets it: the text each mailbox serves, or an erasure.
type testSessionMail struct {
	text   string
	erased bool
}

func (self *testSessionMail) Restore(ctx context.Context, reference *sidecar.SessionMailReference) (string, error) {
	if self.erased {
		return "", sidecar.ErrSessionMailErased
	}
	return self.text, nil
}

// A mail tool's result is kept by reference, never as text: its call is exact, and its rebuild re-renders the text
// from the mailbox and verifies; once DESIGN §15.7's erasure took the message, the node reads erased and the call
// inexact; with no restorer it reads unverifiable; a mailbox serving other text than the call read alarms.
func TestSessionMailReferenceErasedReadsInexact(t *testing.T) {
	world := newTestSessionJournalWorld(t, nil, nil)
	recorder := newTestSessionRecorder(t, world)
	system := recorder.message("", testSessionRebuildSystem("Summarize my mail."), "")
	prompt := recorder.message(system, testSessionRebuildUser("What is unread?"), "")
	asked := recorder.message(prompt, testSessionRebuildAssistant("", "", &sidecar.HarnessPiToolCall{Id: "call_m", Name: "mail_read", Arguments: json.RawMessage(`{"id":"m1"}`)}), "")
	text := "From: someone@example.com\nSubject: lunch\n\nLunch at noon?"
	read := sidecar.NewHarnessPiEntryId()
	recorder.journal(sidecar.NewHarnessPiMessageEntry(read, asked, recorder.now(), testSessionRebuildResult("call_m", "mail_read", text)), "",
		&sidecar.SessionToolResult{Name: "mail_read", BuiltIn: true, MailReference: &sidecar.SessionMailReference{RepoId: sidecar.NewId(), MessageIds: []string{"m1"}, MaxChars: 4000}})
	answer := recorder.message(read, testSessionRebuildAssistant("Lunch at noon.", ""), "")
	// the call renders from the mail text the model read: its recorded form re-renders it
	context := testSessionMailCall(t, recorder, answer, system, text)
	if !context.GetExact() {
		t.Fatal("a mail reference made the call inexact")
	}
	_, _, view := world.openOn(t, recorder.run.RunId)
	call, _ := view.Call(1)
	for _, c := range []struct {
		mail  sidecar.SessionMailRestorer
		check sidecar.SessionCheck
		fault string
	}{
		{mail: &testSessionMail{text: text}, check: sidecar.SessionCheckVerified},
		{mail: &testSessionMail{erased: true}, check: sidecar.SessionCheckInexact},
		{mail: nil, check: sidecar.SessionCheckUnverifiable},
		{mail: &testSessionMail{text: text + " (edited)"}, check: sidecar.SessionCheckAlarm, fault: sidecar.SessionFaultIntegrity},
	} {
		rebuilt, err := sidecar.SessionRebuild(t.Context(), &sidecar.SessionRebuildArgs{Run: view, Call: call, Mail: c.mail})
		if err != nil {
			t.Fatal(err)
		}
		if rebuilt.Check != c.check || rebuilt.Fault != c.fault {
			t.Errorf("with %+v: %s (%s), want %s", c.mail, rebuilt.Check, rebuilt.Fault, c.check)
		}
		if c.check == sidecar.SessionCheckInexact {
			erased := false
			for _, node := range rebuilt.Path {
				erased = erased || node.State == sidecar.RecordEntryErased
			}
			if !erased {
				t.Error("the erased message's node does not read erased")
			}
		}
	}
}

// A call whose context holds a mail reference: its request_sha256 renders the recorded nodes with the mail text the
// model read put back, as the Harness's own render of the call carried it.
func testSessionMailCall(t *testing.T, recorder *testSessionRecorder, input string, system string, text string) *protocol.CallContext {
	t.Helper()
	renderer, err := sidecar.SessionRendererOf(sidecar.SessionRendererHarness1)
	if err != nil {
		t.Fatal(err)
	}
	rendered := recorder.input(input, system, false)
	for _, node := range rendered.Nodes {
		if !bytes.Contains(node.Item, []byte("mail_reference")) {
			continue
		}
		value := map[string]any{}
		if err := json.Unmarshal(node.Item, &value); err != nil {
			t.Fatal(err)
		}
		message := value["message"].(map[string]any)
		message["content"] = []any{map[string]any{"type": "text", "text": text}}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if node.Item, err = sidecar.CanonicalJson(encoded); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := sidecar.SessionRequestSha256(renderer, rendered)
	if err != nil {
		t.Fatal(err)
	}
	context := &protocol.CallContext{
		InputNodeId: recorder.nodes[input].journaled.NodeId.Bytes(), SystemNodeId: recorder.nodes[system].journaled.NodeId.Bytes(),
		RequestSha256: sum[:], Exact: true, Renderer: sidecar.SessionRendererHarness1, Params: rendered.Params,
	}
	if _, err := recorder.world.record.Writer().Append(&sidecar.RecordDraft{
		Kind: sidecar.RecordKindModelCall, Source: sidecar.RecordSourceObserved, RunId: &recorder.run.RunId, AgentId: recorder.run.AgentId,
		Body: &protocol.ModelCallBody{Model: recorder.model, Context: context},
	}); err != nil {
		t.Fatal(err)
	}
	recorder.contexts = append(recorder.contexts, context)
	return context
}
