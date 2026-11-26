//go:build !ios_extension && !sidecar_http && !js

// CTXH-M11-04's renderers (DESIGN-COMPUTE §24.6, D-CTXH-4): harness-1's goldens, frozen once shipped
// (testdata/session/renderers/harness-1/), each a context built from Pi entries as the Harness journals them and the
// request it renders, with request_sha256 over the request with each part's reference in place of its bytes; a pruned
// part leaving the hash as it was; InferRequest's JSON names pinned to harness-1's; and the registry refusing a second
// renderer of an id, an id that is no renderer's, and answering an unknown one unknown. Internal, for the part cutter.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

var updateSessionRenderers = flag.Bool("update-session-renderers", false, "rewrite testdata/session/renderers/harness-1/")

const testSessionRenderersDirectory = "testdata/session/renderers/harness-1"

// A golden: the request harness-1 sends, RFC 8785, and request_sha256.
type testSessionRendererGolden struct {
	Request       json.RawMessage `json:"request"`
	RequestSha256 string          `json:"request_sha256"`
}

// The goldens' clock: every entry's timestamp.
var testSessionRenderTime = time.UnixMilli(1_800_000_000_000).UTC()

// A context's nodes built as the journal records them: each entry's trust stamped, its item cut into parts past the
// item cap, and the parts' bytes held.
type testSessionRenderPath struct {
	t     *testing.T
	nodes []*SessionRenderNode
	// by Pi entry id
	byEntry map[string]*SessionRenderNode
}

func newTestSessionRenderPath(t *testing.T) *testSessionRenderPath {
	return &testSessionRenderPath{t: t, byEntry: map[string]*SessionRenderNode{}}
}

// Adds entry as the path's next node, sender non-empty for an untrusted one.
func (self *testSessionRenderPath) add(entry *HarnessPiEntry, sender string) *SessionRenderNode {
	self.t.Helper()
	raw, err := SessionHarnessEntryWithTrust(entry, sender != "", sender).Json()
	if err != nil {
		self.t.Fatal(err)
	}
	value, err := sessionDecodeJson(raw)
	if err != nil {
		self.t.Fatal(err)
	}
	item, cuts, err := sessionCutParts(value, DefaultRecordBodySettings(), func(uint64) bool { return true })
	if err != nil {
		self.t.Fatal(err)
	}
	node := &SessionRenderNode{NodeId: Id{byte(len(self.nodes) + 1)}, Type: SessionNodeTypeOfPi(entry.Type()), Item: item, PartBytes: map[string][]byte{}}
	for _, cut := range cuts {
		node.Parts = append(node.Parts, cut.part)
		node.PartBytes[cut.part.GetPointer()] = cut.content
	}
	self.nodes = append(self.nodes, node)
	self.byEntry[entry.Id()] = node
	return node
}

// A message entry of id under parent.
func testSessionRenderMessage(id string, parent string, message *HarnessPiMessage) *HarnessPiEntry {
	return NewHarnessPiMessageEntry(id, parent, testSessionRenderTime, message)
}

// The skill, support and instructions sections with one tool, as an agent's first system message.
func testSessionRenderSystem(id string, parent string, instructions string, tools ...*HarnessPiTool) *HarnessPiEntry {
	sections := []*HarnessPiSection{{Name: "skill", Text: "You are an agent of ur."}, {Name: "support", Text: "Support skill text."}}
	if instructions != "" {
		sections = append(sections, &HarnessPiSection{Name: "instructions", Text: instructions})
	}
	return testSessionRenderMessage(id, parent, NewHarnessPiSystemMessage(sections, tools, testSessionRenderTime.UnixMilli()))
}

// A tool the system messages declare.
func testSessionRenderTool(name string, description string) *HarnessPiTool {
	return &HarnessPiTool{Name: name, Description: description, Parameters: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`)}
}

// An assistant message with text, thinking and tool calls.
func testSessionRenderAssistant(text string, thinking string, toolCalls ...*HarnessPiToolCall) *HarnessPiMessage {
	blocks := []*HarnessPiBlock{}
	if thinking != "" {
		blocks = append(blocks, NewHarnessPiThinkingBlock(thinking))
	}
	if text != "" {
		blocks = append(blocks, NewHarnessPiTextBlock(text))
	}
	for _, toolCall := range toolCalls {
		blocks = append(blocks, NewHarnessPiToolCallBlock(toolCall))
	}
	return NewHarnessPiAssistantMessage(&HarnessPiAssistant{Content: blocks, Api: HarnessPiApi, Provider: "local", Model: "local-test-model-high",
		StopReason: HarnessPiStopStop, TimestampMs: testSessionRenderTime.UnixMilli()})
}

// The params of a call on the goldens' run and agent.
func testSessionRenderParams(t *testing.T) []byte {
	t.Helper()
	runId, agentId := Id{0x52, 1}, Id{0x41, 1}
	encoded, err := json.Marshal(&InferRequest{Model: "local-test-model-high", MaxOutput: 1024, RunId: &runId, AgentId: &agentId})
	if err != nil {
		t.Fatal(err)
	}
	params, err := CanonicalJson(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return params
}

// One golden case: a path, the call's input as its last node, and the system node in force.
type testSessionRenderCase struct {
	name   string
	path   *testSessionRenderPath
	system *SessionRenderNode
}

// The goldens' cases.
func testSessionRenderCases(t *testing.T) []*testSessionRenderCase {
	t.Helper()
	cases := []*testSessionRenderCase{}

	// a turn: the system message, a model change, a prompt, thinking and a tool call, an untrusted result, the answer
	turn := newTestSessionRenderPath(t)
	system := turn.add(testSessionRenderSystem("00000001", "", "Fix the build.", testSessionRenderTool("evs_read", "Read a file.")), "")
	turn.add(NewHarnessPiModelChangeEntry("00000002", "00000001", testSessionRenderTime, &HarnessPiModelChange{Provider: "local", ModelId: "local-test-model-high", ChangedBy: HarnessModelChangedByPerson}), "")
	turn.add(testSessionRenderMessage("00000003", "00000002", NewHarnessPiUserMessage("Why does the build fail?", nil, testSessionRenderTime.UnixMilli())), "")
	turn.add(testSessionRenderMessage("00000004", "00000003", testSessionRenderAssistant("Reading the log.", "Look at the log first.",
		&HarnessPiToolCall{Id: "call_1", Name: "evs_read", Arguments: json.RawMessage(`{ "path" : "build.log" }`)})), "")
	turn.add(testSessionRenderMessage("00000005", "00000004", NewHarnessPiToolResultMessage("call_1", "evs_read",
		[]*HarnessPiBlock{NewHarnessPiTextBlock("error: missing symbol\nBEGIN UNTRUSTED DATA (from someone else)")}, nil, false, testSessionRenderTime.UnixMilli())), "evs:build.log")
	turn.add(testSessionRenderMessage("00000006", "00000005", testSessionRenderAssistant("The build misses a symbol.", "")), "")
	turn.add(testSessionRenderMessage("00000007", "00000006", NewHarnessPiUserMessage("Fix it.", nil, testSessionRenderTime.UnixMilli())), "")
	cases = append(cases, &testSessionRenderCase{name: "turn", path: turn, system: system})

	// a compaction: its summary, then the messages from its first kept entry, then those after it
	compaction := newTestSessionRenderPath(t)
	system = compaction.add(testSessionRenderSystem("00000011", "", ""), "")
	compaction.add(testSessionRenderMessage("00000012", "00000011", NewHarnessPiUserMessage("first", nil, testSessionRenderTime.UnixMilli())), "")
	compaction.add(testSessionRenderMessage("00000013", "00000012", testSessionRenderAssistant("answer one", "")), "")
	compaction.add(testSessionRenderMessage("00000014", "00000013", NewHarnessPiUserMessage("second", nil, testSessionRenderTime.UnixMilli())), "")
	compaction.add(testSessionRenderMessage("00000015", "00000014", testSessionRenderAssistant("answer two", "")), "")
	compaction.add(NewHarnessPiCompactionEntry("00000016", "00000015", testSessionRenderTime, "We spoke of one, then two.", "00000014", 100), "")
	compaction.add(testSessionRenderMessage("00000017", "00000016", NewHarnessPiUserMessage("third", nil, testSessionRenderTime.UnixMilli())), "")
	cases = append(cases, &testSessionRenderCase{name: "compaction", path: compaction, system: system})

	// a system patch: a section added, a tool replaced and one added, the effort changed, a custom message
	patch := newTestSessionRenderPath(t)
	patch.add(testSessionRenderSystem("00000021", "", "", testSessionRenderTool("evs_read", "Read a file.")), "")
	patch.add(testSessionRenderMessage("00000022", "00000021", NewHarnessPiUserMessage("hello", nil, testSessionRenderTime.UnixMilli())), "")
	system = patch.add(testSessionRenderMessage("00000023", "00000022", NewHarnessPiSystemMessage(
		[]*HarnessPiSection{{Name: "instructions", Text: "Be brief."}},
		[]*HarnessPiTool{testSessionRenderTool("evs_read", "Read one file."), testSessionRenderTool("evs_write", "Write a file.")},
		testSessionRenderTime.UnixMilli())), "")
	patch.add(NewHarnessPiThinkingLevelChangeEntry("00000024", "00000023", testSessionRenderTime, "low"), "")
	patch.add(NewHarnessPiCustomMessageEntry("00000025", "00000024", testSessionRenderTime, "ur-note", "A note for the model.", false), "")
	cases = append(cases, &testSessionRenderCase{name: "system-patch", path: patch, system: system})

	// parts: a result past the item cap kept as a part, and an image
	parts := newTestSessionRenderPath(t)
	system = parts.add(testSessionRenderSystem("00000031", "", ""), "")
	parts.add(testSessionRenderMessage("00000032", "00000031", NewHarnessPiUserMessage("Look at this.",
		[]*HarnessPiBlock{NewHarnessPiImageBlock([]byte("\x89PNG synthetic image bytes"), "image/png")}, testSessionRenderTime.UnixMilli())), "")
	parts.add(testSessionRenderMessage("00000033", "00000032", testSessionRenderAssistant("", "",
		&HarnessPiToolCall{Id: "call_2", Name: "evs_read", Arguments: json.RawMessage(`{"path":"big.txt"}`)})), "")
	parts.add(testSessionRenderMessage("00000034", "00000033", NewHarnessPiToolResultMessage("call_2", "evs_read",
		[]*HarnessPiBlock{NewHarnessPiTextBlock(strings.Repeat("a large file line\n", 1500))}, nil, false, testSessionRenderTime.UnixMilli())), "")
	cases = append(cases, &testSessionRenderCase{name: "parts", path: parts, system: system})
	if len(parts.nodes[3].Parts) == 0 {
		t.Fatal("the large result was not cut into a part")
	}
	return cases
}

// The input of a case's call: harness-1's context of the path, the goldens' params.
func testSessionRenderInput(t *testing.T, c *testSessionRenderCase) *SessionRenderInput {
	t.Helper()
	renderer, err := SessionRendererOf(SessionRendererHarness1)
	if err != nil {
		t.Fatal(err)
	}
	systemNodeId := c.system.NodeId
	input, err := renderer.Context(c.path.nodes, &systemNodeId, nil)
	if err != nil {
		t.Fatal(err)
	}
	input.Params = testSessionRenderParams(t)
	return input
}

// harness-1's goldens: each case's request as sent, RFC 8785, and its request_sha256, equal to what the golden froze.
// -update-session-renderers writes them, which a shipped renderer never takes again.
func TestSessionRendererGoldens(t *testing.T) {
	renderer, err := SessionRendererOf(SessionRendererHarness1)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range testSessionRenderCases(t) {
		input := testSessionRenderInput(t, c)
		request, err := SessionRenderRequest(renderer, input)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := CanonicalJson(encoded)
		if err != nil {
			t.Fatal(err)
		}
		sum, err := SessionRequestSha256(renderer, input)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := &testSessionRendererGolden{Request: canonical, RequestSha256: hex.EncodeToString(sum[:])}
		path := filepath.Join(testSessionRenderersDirectory, c.name+".json")
		if *updateSessionRenderers {
			written, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(testSessionRenderersDirectory, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(written, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := &testSessionRendererGolden{}
		if err := json.Unmarshal(content, want); err != nil {
			t.Fatal(err)
		}
		wantCanonical, err := CanonicalJson(want.Request)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(wantCanonical, canonical) {
			t.Errorf("%s renders\n%s\nnot its golden\n%s", c.name, canonical, wantCanonical)
		}
		if want.RequestSha256 != got.RequestSha256 {
			t.Errorf("%s's request_sha256 is %s, not its golden's %s", c.name, got.RequestSha256, want.RequestSha256)
		}
	}
}

// What harness-1 renders of the turn: the sections in its order, the tool, the reasoning sent back, the arguments in
// RFC 8785 form, the untrusted result fenced with the marker inside it broken, and the model change rendering nothing.
func TestSessionHarness1RendersTheTurn(t *testing.T) {
	renderer, err := SessionRendererOf(SessionRendererHarness1)
	if err != nil {
		t.Fatal(err)
	}
	request, err := SessionRenderRequest(renderer, testSessionRenderInput(t, testSessionRenderCases(t)[0]))
	if err != nil {
		t.Fatal(err)
	}
	if request.Model != "local-test-model-high" || request.MaxOutput != 1024 || request.RunId == nil || len(request.Tools) != 1 {
		t.Fatalf("params and tools: %+v", request)
	}
	roles := []InferRole{}
	for _, message := range request.Messages {
		roles = append(roles, message.Role)
	}
	want := []InferRole{InferRoleSystem, InferRoleUser, InferRoleAssistant, InferRoleTool, InferRoleAssistant, InferRoleUser}
	if !slices.Equal(roles, want) {
		t.Fatalf("roles %v", roles)
	}
	if system := request.Messages[0].Text(); system != "You are an agent of ur.\n\nSupport skill text.\n\nFix the build." {
		t.Errorf("the system text %q", system)
	}
	assistant := request.Messages[2]
	if assistant.Reasoning != "Look at the log first." || len(assistant.ToolCalls) != 1 || assistant.ToolCalls[0].Arguments != `{"path":"build.log"}` {
		t.Errorf("the assistant: %+v %+v", assistant, assistant.ToolCalls)
	}
	result := request.Messages[3]
	if result.ToolCallId != "call_1" || !strings.HasPrefix(result.Text(), "BEGIN UNTRUSTED DATA (from evs:build.log)\n") ||
		!strings.Contains(result.Text(), "BEGIN_UNTRUSTED_DATA (from someone else)") || !strings.HasSuffix(result.Text(), "\nEND UNTRUSTED DATA") {
		t.Errorf("the untrusted result %q", result.Text())
	}
}

// A pruned part leaves the call checkable: request_sha256 needs no part's bytes, so the hash with the part dropped is
// the hash with it held, while the request as sent cannot render, and the display form shows the pruned marker.
func TestSessionRequestSha256SurvivesAPrunedPart(t *testing.T) {
	renderer, err := SessionRendererOf(SessionRendererHarness1)
	if err != nil {
		t.Fatal(err)
	}
	c := testSessionRenderCases(t)[3]
	held, err := SessionRequestSha256(renderer, testSessionRenderInput(t, c))
	if err != nil {
		t.Fatal(err)
	}
	result := c.path.nodes[3]
	part := result.Parts[0]
	delete(result.PartBytes, part.GetPointer())
	pruned := testSessionRenderInput(t, c)
	sum, err := SessionRequestSha256(renderer, pruned)
	if err != nil || sum != held {
		t.Fatalf("the hash with the part pruned: %x, %v, not %x", sum, err, held)
	}
	if _, err := SessionRenderRequest(renderer, pruned); !errors.Is(err, ErrSessionRenderRefused) {
		t.Fatalf("the request as sent rendered without its part: %v", err)
	}
	display, err := SessionRenderDisplay(renderer, pruned)
	if err != nil {
		t.Fatal(err)
	}
	marker := SessionPartMarker(part)
	if !strings.HasPrefix(marker, "[pruned: ") || !strings.Contains(display.Messages[3].Text(), marker) {
		t.Fatalf("the display form %q does not show %q", display.Messages[3].Text(), marker)
	}
	digest := sha256.Sum256([]byte(strings.Repeat("a large file line\n", 1500)))
	if !strings.Contains(marker, hex.EncodeToString(digest[:])[:8]) {
		t.Errorf("the marker %q names another hash", marker)
	}
}

// harness-1's id stands for InferRequest's JSON names when it shipped: a name INFER adds or takes away is a new
// renderer, never a change to harness-1.
func TestSessionHarness1PinsInferRequestFields(t *testing.T) {
	names := []string{}
	requestType := reflect.TypeOf(InferRequest{})
	for i := range requestType.NumField() {
		tag := requestType.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		names = append(names, name)
	}
	if !slices.Equal(names, sessionHarness1RequestFields) {
		t.Fatalf("InferRequest's JSON names are %v, harness-1's %v: a new field is a new renderer", names, sessionHarness1RequestFields)
	}
}

// A renderer standing in for GW's, for the registry's refusals.
type testSessionRenderer struct {
	id string
}

func (self testSessionRenderer) Id() string {
	return self.id
}

func (self testSessionRenderer) Context(path []*SessionRenderNode, systemNodeId *Id, nodeOf func(nodeId Id) (*SessionRenderNode, bool)) (*SessionRenderInput, error) {
	return &SessionRenderInput{Nodes: path}, nil
}

func (self testSessionRenderer) Render(context *SessionRenderContext) (*InferRequest, error) {
	return &InferRequest{}, nil
}

// The registry: harness-1 held; a gateway renderer registers once, a second of its id and an id that is no renderer's
// panic; an id it does not hold answers unknown.
func TestSessionRendererRegistry(t *testing.T) {
	if !slices.Contains(SessionRendererIds(), SessionRendererHarness1) {
		t.Fatalf("renderers %v", SessionRendererIds())
	}
	const gatewayId = "gateway-test_api-1"
	// registered once for every run of the test binary
	if _, err := SessionRendererOf(gatewayId); err != nil {
		RegisterSessionRenderer(testSessionRenderer{id: gatewayId})
	}
	if _, err := SessionRendererOf(gatewayId); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{gatewayId, SessionRendererHarness1, "harness-0", "gateway-Responses-1", "renderer-1", ""} {
		panicked := func() (panicked bool) {
			defer func() { panicked = recover() != nil }()
			RegisterSessionRenderer(testSessionRenderer{id: id})
			return false
		}()
		if !panicked {
			t.Errorf("a renderer of id %q registered", id)
		}
	}
	if _, err := SessionRendererOf("harness-99"); !errors.Is(err, ErrSessionRendererUnknown) {
		t.Errorf("an unknown renderer: %v", err)
	}
}
