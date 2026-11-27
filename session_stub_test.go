//go:build !ios_extension && !sidecar_http && !js

// CTXH-M13-01's search stubs (DESIGN-COMPUTE §24.9, §24.16's Web search row; R-CTXH-7, D-CTXH-7, CO-26) on
// session_gateway_test.go's world: synthetic results in Parallel's documented shape (§21.11), carrying marker strings,
// reach no node or blob through the Harness's own tool, nor through the MCP tool whose results fake Codex and Claude
// Code carry into their later requests through the gateway, whole, cut short or pasted elsewhere; a result cut short
// is matched by the call that carried it; served hashes are run-scoped, a resumed run's included; a transcript line
// holding a result is replaced whole and the calls a line names carry to the lines after it; and the served set's
// caps. The ingest's transcript lines and hook payloads, and the MCP call sink, are mcp/ingest_search_stub_test.go's.

package sidecar_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The marker strings each synthetic result carries, none of which may reach the record.
var testSearchMarkers = []string{"MARKER-7f3c-excerpt-alpha", "MARKER-9a21-title-beta", "MARKER-c4d0-url-gamma"}

// A synthetic search answer in Parallel's documented shape (search_id, results with url, title, excerpts and
// publish_date, warnings, usage), and the text the MCP tool serves of it, the whitelist SRCH renders (§21.6).
func testSearchAnswer(n int) ([]byte, string) {
	answer := fmt.Sprintf(`{"search_id":"search_%d","results":[{"url":"https://%s.example/%d","title":"%s %d","excerpts":["%s: a synthetic excerpt %d"],"publish_date":"2026-11-01"}],"warnings":[],"usage":[{"name":"sku_search","count":1}]}`,
		n, strings.ToLower(testSearchMarkers[2]), n, testSearchMarkers[1], n, testSearchMarkers[0], n)
	served := fmt.Sprintf("BEGIN UNTRUSTED DATA\n[1] %s %d — https://%s.example/%d (2026-11-01)\n%s: a synthetic excerpt %d\nEND UNTRUSTED DATA",
		testSearchMarkers[1], n, strings.ToLower(testSearchMarkers[2]), n, testSearchMarkers[0], n)
	return []byte(answer), served
}

// §21.6's stub of search n: the call, the number of results, the answer's hash, the payment and the charge.
func testSearchStub(n int) []byte {
	return []byte(fmt.Sprintf(`{"call":{"objective":"synthetic objective %d","queries":["synthetic query"],"mode":"one-shot"},"results":1,"answer_sha256":"%064x","nonce":"%d","price_nano_usd":5000000}`, n, n, n))
}

// Whether any marker is in data.
func testHoldsMarker(data []byte) bool {
	for _, marker := range testSearchMarkers {
		if bytes.Contains(bytes.ToLower(data), bytes.ToLower([]byte(marker))) {
			return true
		}
	}
	return false
}

// The world's served set over a store of its own.
func (self *testSessionGatewayWorld) served() *sidecar.SessionServedHashes {
	self.t.Helper()
	if self.servedHashes != nil {
		return self.servedHashes
	}
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("session_served", "session")
	if err != nil {
		self.t.Fatal(err)
	}
	self.servedStore = store
	served, err := sidecar.NewSessionServedHashes(store, nil, self.journal.world.clock)
	if err != nil {
		self.t.Fatal(err)
	}
	self.servedHashes = served
	self.open()
	return served
}

// No node, blob or entry of the vault holds a marker.
func (self *testSessionGatewayWorld) assertNoMarker() {
	self.t.Helper()
	_, _, entries := self.journal.stored()
	for _, entry := range entries {
		if testHoldsMarker(entry.Body) {
			self.t.Errorf("a %v entry holds a search result's marker", entry.Kind())
		}
	}
}

// Synthetic results with marker strings reach no node, blob or entry through the Harness's own tool, kept as its stub,
// nor through the MCP tool, whose served text Codex carries back in a function call's output, whole and cut short,
// and Claude Code in a tool_result block, and which a harness pastes into a later prompt: each copy is the stub, the
// call stays in the record, and the calls carrying one read inexact.
func TestSessionSyntheticResultsInNoEntryThroughHarnessAndMcp(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	served := world.served()
	// the Harness's own web_search: its result keep: false, SRCH's stub in its place
	harnessRun := testSessionRun()
	_, harnessServed := testSearchAnswer(0)
	world.journal.journalNodes(harnessRun, testSessionToolResult("search", "", "web_search", harnessServed, `{"kind":"web_search","results":["`+testSearchMarkers[0]+`"]}`,
		&sidecar.SessionToolResult{Name: "web_search", BuiltIn: true, KeepFalse: true, SearchStub: testSearchStub(0)}))

	// Codex through the gateway: the MCP tool served search 1 in its run
	codex := world.bound()
	_, codexServed := testSearchAnswer(1)
	if err := served.Serve(codex.RunId, [][]byte{[]byte(codexServed)}, testSearchStub(1)); err != nil {
		t.Fatal(err)
	}
	call := `{"type":"function_call","call_id":"call_s1","name":"ur__web_search","arguments":"{\"objective\":\"synthetic objective 1\"}"}`
	whole := testResponsesBody("You are Codex.", testResponsesUser("search for the synthetic thing"), call,
		`{"type":"function_call_output","call_id":"call_s1","output":`+testGatewayString(codexServed)+`}`)
	_, wholeEnded, _ := world.call(codex, whole, "req-codex-1", testResponsesAssistantDone(1, "I found one synthetic result."))
	// cut short by the harness: no hash names it, its call does
	cut := testResponsesBody("You are Codex.", testResponsesUser("search for the synthetic thing"), call,
		`{"type":"function_call_output","call_id":"call_s1","output":`+testGatewayString(codexServed[:60])+`}`)
	world.call(codex, cut, "req-codex-2")
	// pasted into a later prompt whole: its hash names it
	pasted := testResponsesBody("You are Codex.", testResponsesUser(codexServed))
	world.call(codex, pasted, "req-codex-3")
	if wholeEnded.Context.GetExact() {
		t.Error("a call carrying a stubbed result reads exact")
	}

	// Claude Code through the gateway: the MCP tool served search 2 in its run
	claude := world.bound()
	_, claudeServed := testSearchAnswer(2)
	if err := served.Serve(claude.RunId, [][]byte{[]byte(claudeServed)}, testSearchStub(2)); err != nil {
		t.Fatal(err)
	}
	messages := `{"model":"local-test-model-high","max_tokens":4096,"system":[{"type":"text","text":"You are Claude Code."}],"messages":[` +
		`{"role":"user","content":"search for the synthetic thing"},` +
		`{"role":"assistant","content":[{"type":"tool_use","id":"toolu_s2","name":"mcp__ur__web_search","input":{"objective":"synthetic objective 2"}}]},` +
		`{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_s2","content":[{"type":"text","text":` + testGatewayString(claudeServed) + `}]}]}]}`
	world.callOf(claude, sidecar.SessionGatewayApiMessages, []byte(messages), "msg_claude_1", `{"type":"text","text":"One synthetic result."}`)

	world.assertNoMarker()
	nodes, _ := world.stored(codex.RunId)
	stubbed := 0
	for _, node := range nodes {
		if 0 < node.GetStubs() {
			stubbed += 1
			if !bytes.Contains(node.GetItem(), []byte("[web_search result not kept")) {
				t.Errorf("a stubbed node holds no stub: %s", node.GetItem())
			}
		}
	}
	if stubbed != 3 {
		t.Errorf("%d of Codex's nodes stubbed, not the whole output, the cut one and the pasted prompt", stubbed)
	}
	if !bytes.Contains(nodesItems(nodes), []byte(`ur__web_search`)) {
		t.Error("the search's call is not in the record")
	}
}

// Each node's item, joined.
func nodesItems(nodes map[sidecar.Id]*protocol.SessionEntryBody) []byte {
	joined := []byte{}
	for _, node := range nodes {
		joined = append(joined, node.GetItem()...)
	}
	return joined
}

// A result cut short, which no served hash names, is stubbed by the call that carried it, in every front's form; a
// result of another tool, or of a call this request does not name, is kept whole.
func TestSessionStubMatchedByToolCallWhenTruncated(t *testing.T) {
	stubber := sidecar.NewSessionStubber(nil, sidecar.NewId())
	items := []map[string]any{}
	for _, raw := range []string{
		`{"type":"function_call","call_id":"c1","name":"ur__web_search","arguments":"{}"}`,
		`{"type":"function_call_output","call_id":"c1","output":"` + testSearchMarkers[0] + ` cut sh"}`,
		`{"role":"assistant","tool_calls":[{"id":"c2","type":"function","function":{"name":"ur_web_search","arguments":"{}"}}]}`,
		`{"role":"tool","tool_call_id":"c2","content":"` + testSearchMarkers[1] + `"}`,
		`{"role":"assistant","block":{"type":"tool_use","id":"c3","name":"mcp__ur__web_search","input":{}}}`,
		`{"role":"user","block":{"type":"tool_result","tool_use_id":"c3","content":[{"type":"text","text":"` + testSearchMarkers[2] + `"}]}}`,
		`{"type":"function_call","call_id":"c4","name":"shell","arguments":"{}"}`,
		`{"type":"function_call_output","call_id":"c4","output":"MARKER-kept-shell-output"}`,
	} {
		item := map[string]any{}
		if err := json.Unmarshal([]byte(raw), &item); err != nil {
			t.Fatal(err)
		}
		items = append(items, item)
	}
	counts, err := stubber.StubItems(items)
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{0, 1, 0, 1, 0, 1, 0, 0}; fmt.Sprint(counts) != fmt.Sprint(want) {
		t.Errorf("counts %v, not %v", counts, want)
	}
	encoded, _ := json.Marshal(items)
	if testHoldsMarker(encoded) || !bytes.Contains(encoded, []byte("MARKER-kept-shell-output")) {
		t.Errorf("the items after stubbing: %s", encoded)
	}
}

// Served hashes are the run's: a run that did not serve a text keeps a copy of it, and a run that resumes the one
// that did stubs it; the set outlives a restart and is dropped past its life.
func TestSessionServedHashesRunScoped(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	served := world.served()
	origin := world.bound()
	_, text := testSearchAnswer(3)
	if err := served.Serve(origin.RunId, [][]byte{[]byte(text), []byte("short")}, testSearchStub(3)); err != nil {
		t.Fatal(err)
	}
	other := world.bound()
	world.call(other, testResponsesBody("You are Codex.", testResponsesUser(text)), "req-other")
	otherNodes, _ := world.stored(other.RunId)
	if !testHoldsMarker(nodesItems(otherNodes)) {
		t.Fatal("another run's copy was stubbed by a hash it did not serve")
	}
	resumed := world.bound()
	resumed.Resumes = []sidecar.Id{origin.RunId}
	world.call(resumed, testResponsesBody("You are Codex.", testResponsesUser(text)), "req-resumed")
	resumedNodes, _ := world.stored(resumed.RunId)
	if testHoldsMarker(nodesItems(resumedNodes)) {
		t.Error("a resumed run's copy of its origin's result was kept")
	}
	// a restart reads the set back; a short text was never kept
	reread, err := sidecar.NewSessionServedHashes(world.servedStore, nil, world.journal.world.clock)
	if err != nil {
		t.Fatal(err)
	}
	stubber := sidecar.NewSessionStubber(reread, origin.RunId)
	items := []map[string]any{{"role": "user", "content": text}, {"role": "user", "content": "short"}}
	if counts, err := stubber.StubItems(items); err != nil || counts[0] != 1 || counts[1] != 0 {
		t.Errorf("after a restart: %v, %v", counts, err)
	}
	world.journal.world.clock.Advance(31 * 24 * time.Hour)
	if err := reread.Sweep(); err != nil {
		t.Fatal(err)
	}
	if entries, _ := world.servedStore.List(""); len(entries) != 0 {
		t.Errorf("%d segments past the set's life", len(entries))
	}
}

// A transcript line holding a result is replaced whole by the stub line, its newline kept; the call a line names
// carries to the lines after it, across a new stubber over the same set; a line that is no JSON is matched by its
// hash, and by a call it names in text.
func TestSessionStubLineWholeAndNoted(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	served := world.served()
	runId := sidecar.NewId()
	_, text := testSearchAnswer(4)
	if err := served.Serve(runId, [][]byte{[]byte(text)}, testSearchStub(4)); err != nil {
		t.Fatal(err)
	}
	stubber := sidecar.NewSessionStubber(served, runId)
	use := []byte(`{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_9","name":"mcp__ur__web_search","input":{}}]}}` + "\n")
	if out, stubbed, err := stubber.StubLine(use); err != nil || stubbed || !bytes.Equal(out, use) {
		t.Fatalf("the call's own line: %s %v %v", out, stubbed, err)
	}
	result := []byte(`{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_9","content":"` + testSearchMarkers[0] + ` cut"}]},"toolUseResult":{"x":"` + testSearchMarkers[1] + `"}}` + "\n")
	later := sidecar.NewSessionStubber(served, runId)
	out, stubbed, err := later.StubLine(result)
	if err != nil || !stubbed || testHoldsMarker(out) || !bytes.HasSuffix(out, []byte("\n")) || bytes.Count(out, []byte("\n")) != 1 {
		t.Fatalf("the result's line: %s %v %v", out, stubbed, err)
	}
	if out, stubbed, err := later.StubLine([]byte(text)); err != nil || !stubbed || testHoldsMarker(out) || bytes.HasSuffix(out, []byte("\n")) {
		t.Errorf("a served text as a line of its own: %s %v %v", out, stubbed, err)
	}
	cutLine := []byte(`{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_9","content":"` + testSearchMarkers[2])
	if out, stubbed, err := later.StubLine(cutLine); err != nil || !stubbed || testHoldsMarker(out) {
		t.Errorf("a line cut short naming the call: %s %v %v", out, stubbed, err)
	}
	plain := []byte(`{"type":"user","message":{"role":"user","content":"an unrelated synthetic prompt"}}` + "\n")
	if out, stubbed, err := later.StubLine(plain); err != nil || stubbed || !bytes.Equal(out, plain) {
		t.Errorf("an unrelated line: %s %v %v", out, stubbed, err)
	}
}

// The served set refuses past its caps, so the tool serves nothing the record could not stub, and a stub that is no
// JSON object.
func TestSessionServedHashesFullRefuses(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("session_served", "session")
	if err != nil {
		t.Fatal(err)
	}
	settings := sidecar.DefaultSessionSettings()
	settings.ServedRunHashCount = 2
	settings.ServedRunCallCount = 1
	served, err := sidecar.NewSessionServedHashes(store, settings, world.journal.world.clock)
	if err != nil {
		t.Fatal(err)
	}
	runId := sidecar.NewId()
	long := func(n int) []byte { return []byte(fmt.Sprintf("%s a served text of some length %d", testSearchMarkers[0], n)) }
	if err := served.Serve(runId, [][]byte{long(1), long(2)}, nil); err != nil {
		t.Fatal(err)
	}
	if err := served.Serve(runId, [][]byte{long(3)}, nil); !errors.Is(err, sidecar.ErrSessionServedFull) {
		t.Errorf("past the hash cap: %v", err)
	}
	if err := served.NoteCall(runId, "a"); err != nil {
		t.Fatal(err)
	}
	if err := served.NoteCall(runId, "b"); !errors.Is(err, sidecar.ErrSessionServedFull) {
		t.Errorf("past the call cap: %v", err)
	}
	if err := served.Serve(runId, nil, []byte(`[1,2]`)); !errors.Is(err, sidecar.ErrSessionStubInvalid) {
		t.Errorf("a stub that is no object: %v", err)
	}
}
