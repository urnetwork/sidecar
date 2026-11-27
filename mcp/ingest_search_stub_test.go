//go:build !js && !ios && !android && !sdk_mobile_bind

// CTXH-M13-01's search stubs in the ingest and the MCP call sink (DESIGN-COMPUTE §24.9, §24.16's Web search row;
// R-CTXH-7, D-CTXH-7, CO-26, CONTRACTS C-31): a harness's transcript line holding a web_search result replaced whole,
// the tail's line framing kept, Claude Code's and Codex's forms both, the call a line names carrying to a later tail
// and across a restart; a hook payload's result stubbed in place, a pasted served text in a prompt by its hash; and a
// tool result carrying a RecordStub recorded as the stub, its text nowhere in the record.

package mcp

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The marker strings a synthetic result carries, none of which may reach the record.
var testIngestSearchMarkers = []string{"MARKER-2b7e-excerpt", "MARKER-55c1-title"}

// Whether data holds a marker.
func testIngestHoldsMarker(data []byte) bool {
	for _, marker := range testIngestSearchMarkers {
		if bytes.Contains(data, []byte(marker)) {
			return true
		}
	}
	return false
}

// The text the MCP web_search tool serves of a synthetic answer: the whitelist, fenced.
func testIngestServed(n int) string {
	return "BEGIN UNTRUSTED DATA\n[1] " + testIngestSearchMarkers[1] + " — https://synthetic.example/" + strings.Repeat("x", n) +
		" (2026-11-01)\n" + testIngestSearchMarkers[0] + ": a synthetic excerpt\nEND UNTRUSTED DATA"
}

// The transcript entries' lines joined, and their line count.
func (self *ingestTestEnv) transcriptLines() ([]byte, uint32) {
	lines := []byte{}
	count := uint32(0)
	for _, draft := range self.writer.of(sidecar.RecordKindTranscript) {
		body := draft.Body.(*protocol.TranscriptBody)
		lines = append(lines, body.Lines...)
		count += body.LineCount
	}
	return lines, count
}

// A transcript line holding a web_search result is replaced whole, the line count kept: Claude Code's tool_result
// line by the tool_use a line before named, Codex's mcp_tool_call_end by its invocation; the call carries to a line a
// later tail reads, and across the ingest's restart through the network's served set; every other line is kept.
func TestIngestTranscriptSearchResultStubbedWhole(t *testing.T) {
	env := newIngestTestEnv(t)
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	path := env.writeTranscript("s1", `{"type":"user","message":{"role":"user","content":"search for the synthetic thing"}}`+"\n"+
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_s","name":"mcp__ur__web_search","input":{"objective":"synthetic"}}]}}`+"\n"+
		`{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_s","content":[{"type":"text","text":"`+testIngestSearchMarkers[0]+`"}]}]},"toolUseResult":{"title":"`+testIngestSearchMarkers[1]+`"}}`+"\n"+
		`{"type":"event_msg","payload":{"type":"mcp_tool_call_end","call_id":"c9","invocation":{"server":"ur","tool":"web_search","arguments":{}},"result":{"Ok":{"content":[{"type":"text","text":"`+testIngestSearchMarkers[0]+`"}]}}}}`+"\n"+
		`{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"I found a synthetic thing."}]}}`+"\n")
	if err := harness.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	if err := harness.Hook(harness.Payload("s1", "Stop", map[string]any{})); err != nil {
		t.Fatal(err)
	}
	lines, count := env.transcriptLines()
	if count != 5 || testIngestHoldsMarker(lines) || bytes.Count(lines, []byte("\n")) != 5 {
		t.Fatalf("%d lines read: %s", count, lines)
	}
	if !bytes.Contains(lines, []byte(`"ur_stub":"web_search"`)) || !bytes.Contains(lines, []byte("I found a synthetic thing.")) || !bytes.Contains(lines, []byte("mcp__ur__web_search")) {
		t.Errorf("the lines kept: %s", lines)
	}
	// a restart, then a later line holding the same call's result: the call is the served set's now
	env.restartIngest()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	file.WriteString(`{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_s","content":"` + testIngestSearchMarkers[0] + ` again"}]}}` + "\n")
	file.Close()
	if err := harness.SessionEnd("s1", "exit"); err != nil {
		t.Fatal(err)
	}
	lines, count = env.transcriptLines()
	if count != 6 || testIngestHoldsMarker(lines) {
		t.Errorf("after the restart, %d lines: %s", count, lines)
	}
}

// A PostToolUse payload of ur's web_search keeps its call and stubs its result in place, so its tool_call entry holds
// the stub; a prompt pasting a text the tool served in the run is stubbed by its hash.
func TestIngestHookPayloadSearchResultStubbed(t *testing.T) {
	env := newIngestTestEnv(t)
	harness := env.harnessIn(sidecartest.FakeHarnessClaudeCode)
	if err := harness.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	runId := env.runOf(sidecartest.FakeHarnessClaudeCode, "s1")
	served, err := env.network.SessionServedHashes()
	if err != nil {
		t.Fatal(err)
	}
	text := testIngestServed(12)
	if err := served.Serve(runId, [][]byte{[]byte(text)}, []byte(`{"results":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := harness.Hook(harness.Payload("s1", "PostToolUse", map[string]any{
		"tool_name": "mcp__ur__web_search", "tool_input": map[string]any{"objective": "synthetic"}, "tool_use_id": "toolu_w",
		"tool_response": []any{map[string]any{"type": "text", "text": text[:40]}},
	})); err != nil {
		t.Fatal(err)
	}
	if err := harness.Hook(harness.Payload("s1", "UserPromptSubmit", map[string]any{"prompt": text})); err != nil {
		t.Fatal(err)
	}
	calls := env.writer.of(sidecar.RecordKindToolCall)
	if len(calls) != 1 {
		t.Fatalf("%d tool calls", len(calls))
	}
	body := calls[0].Body.(*protocol.ToolCallBody)
	if testIngestHoldsMarker(body.Output) || !bytes.Contains(body.Output, []byte("[web_search result not kept")) || !bytes.Contains(body.Input, []byte("synthetic")) {
		t.Errorf("the tool call: input %s, output %s", body.Input, body.Output)
	}
	for _, kind := range []sidecar.RecordKind{sidecar.RecordKindContext, sidecar.RecordKindHookEvent} {
		for _, draft := range env.writer.of(kind) {
			if encoded, _ := proto.Marshal(draft.Body); testIngestHoldsMarker(encoded) {
				t.Errorf("a %v entry holds a marker", kind)
			}
		}
	}
}

// A tool result carrying a RecordStub is recorded as the stub, whatever the tool's tier, and its text is nowhere in
// the record; the caller still gets the result (C-31).
func TestMcpResultRecordStubRecordedInPlaceOfResult(t *testing.T) {
	stub := []byte(`{"call":{"objective":"synthetic"},"results":1}`)
	env := newTestToolEnvWith(t, func(catalog *McpCatalog) {
		AddTool(catalog, &McpToolSpec[testToolIn]{
			Name: "test_search_stub", Tier: McpTierRead, Description: "serves a synthetic search",
			Access: func(call *McpCall, in *testToolIn) ([]McpAccess, error) { return nil, nil },
		}, func(ctx context.Context, call *McpCall, in *testToolIn, result *McpResult) (*testToolOut, error) {
			result.RecordStub(stub)
			return &testToolOut{Text: testIngestSearchMarkers[0] + " " + in.Text}, nil
		})
	})
	conn := env.conn("2025-06-18")
	envelope := testEnvelopeOf(t, env.callTool(conn, "2025-06-18", "test_search_stub", map[string]any{"text": "query"}))
	if !bytes.Contains(envelope.Data, []byte(testIngestSearchMarkers[0])) {
		t.Fatalf("the caller's result: %s", envelope.Data)
	}
	sunk := env.sink.sunk()
	if len(sunk) != 1 || sunk[0].toolName != "test_search_stub" || !bytes.Equal(sunk[0].result, stub) || testIngestHoldsMarker(sunk[0].result) {
		t.Errorf("the sink recorded %+v", sunk)
	}
}
