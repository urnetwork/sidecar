//go:build !ios_extension && !sidecar_http && !js

// CTXH-M12-01's deduplication (DESIGN-COMPUTE §24.8's match, system and resume rows, §24.16's Deduplication row;
// R-CTXH-6, D-CTXH-2, D-CTXH-6) on session_gateway_test.go's world: a long Codex-shaped session storing each item once,
// its recorded bytes within 1.2 times the distinct items'; a compaction and a cleared tool result branching at their
// first changed item, an item the run holds elsewhere a same_as node; a replayed reasoning item landing on the node its
// blob names; a side request a tree of its own; a second session in the same directory starting its own tree unless
// its harness reports a resume, which then hangs from the earlier run by a parent link alone; a Chat Completions
// session recorded and deduplicated; and two Codex-shaped turns from testdata/session/gateway/ lining up, the second
// carrying the first's answer back as Codex does.

package sidecar_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A synthetic tool output of about byteCount bytes, distinct for n.
func testGatewayOutput(n int, byteCount int) string {
	line := fmt.Sprintf("synthetic output %d of the build: a line of a log\n", n)
	return strings.Repeat(line, max(byteCount/len(line), 1))
}

// A 200-call Codex-shaped session through the gateway stores each item once (§24.16): every call carries the whole
// history, the instructions and the tools, and adds a tool's output, the model answering with its reasoning and a
// function call, the last with a message; the run holds one node per distinct item and a system node, no item twice,
// and its recorded bytes, the sealed bodies of its entries and blobs, are within 1.2 times the distinct items'.
func TestSessionGatewayLongCodexSessionStoresItemsOnce(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	const callCount = 200
	// Codex's instructions and AGENTS.md: past the item cap, so a part of the system node
	instructions := strings.Repeat("You are Codex, a coding agent. Follow the repository's synthetic rules.\n", 300)
	history := []string{}
	for n := range callCount {
		if n == 0 {
			history = append(history, testResponsesUser("make the synthetic build pass"))
		} else {
			history = append(history, testResponsesCallOutput(n-1, testGatewayOutput(n, 1800)))
		}
		reasoning := fmt.Sprintf("Step %d: read the output and decide the next command for the synthetic build. %s", n, strings.Repeat("Think. ", 60))
		outputs := []string{testResponsesReasoning(n, reasoning, fmt.Sprintf("sealed-blob-%d", n))}
		replays := []string{testResponsesReasoning(n, reasoning, fmt.Sprintf("sealed-blob-%d", n))}
		if n < callCount-1 {
			arguments := fmt.Sprintf(`{"command":["go","test","./step%d/..."],"workdir":"/tmp/synthetic"}`, n)
			outputs = append(outputs, testResponsesCallDone(n, arguments))
			replays = append(replays, testResponsesCall(n, arguments))
		} else {
			outputs = append(outputs, testResponsesAssistantDone(n, "The synthetic build passes."))
			replays = append(replays, testResponsesAssistant("The synthetic build passes."))
		}
		call, _, _ := world.call(binding, testResponsesBody(instructions, history...), fmt.Sprintf("req-%d", n), outputs...)
		if got := len(call.InputNodeIds()); got != len(history) {
			t.Fatalf("call %d: %d input nodes of %d items", n, got, len(history))
		}
		history = append(history, replays...)
	}
	nodes, blobs, entries := world.journal.stored()
	recordedByteCount := 0
	distinct := map[[32]byte]int{}
	nodeCount := 0
	for _, entry := range entries {
		switch entry.Kind() {
		case sidecar.RecordKindSessionEntry:
			body := &protocol.SessionEntryBody{}
			if err := proto.Unmarshal(entry.Body, body); err != nil {
				t.Fatal(err)
			}
			recordedByteCount += len(entry.Body)
			nodeCount += 1
			if len(body.GetSameAs()) != 0 {
				t.Error("a same_as node in a session that repeats no item")
				continue
			}
			size := len(body.GetItem())
			for _, part := range body.GetParts() {
				size += int(part.GetSize())
			}
			if _, held := distinct[[32]byte(body.GetItemSha256())]; held {
				t.Error("an item stored twice")
			}
			distinct[[32]byte(body.GetItemSha256())] = size
		case sidecar.RecordKindSessionBlob:
			recordedByteCount += len(entry.Body)
		}
	}
	// a system node, the prompt, 199 outputs, 200 reasoning items, 199 function calls and one message
	if want := 1 + 1 + (callCount - 1) + callCount + (callCount - 1) + 1; nodeCount != want || len(nodes) != want {
		t.Fatalf("%d nodes, not %d", nodeCount, want)
	}
	if len(blobs) == 0 {
		t.Error("the system node's instructions kept no part")
	}
	distinctByteCount := 0
	for _, size := range distinct {
		distinctByteCount += size
	}
	if float64(distinctByteCount)*1.2 < float64(recordedByteCount) {
		t.Errorf("recorded %d bytes for %d distinct, past 1.2 times", recordedByteCount, distinctByteCount)
	}
	t.Logf("recorded %d bytes for %d distinct items' %d", recordedByteCount, len(distinct), distinctByteCount)
}

// A compaction keeps the items before it and replaces those after with its summary: its request branches at its
// first changed item, the summary's parent the last item kept, nothing before it written again.
func TestSessionGatewayCompactionBranchesAtFirstChange(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	head := []string{testResponsesUser("the synthetic task"), testResponsesCall(1, `{"command":["ls"]}`)}
	tail := []string{testResponsesCallOutput(1, testGatewayOutput(1, 4000)), testResponsesUser("go on"), testResponsesAssistant("Done reading.")}
	whole, _, _ := world.call(binding, testResponsesBody("You are Codex.", append(append([]string{}, head...), tail...)...), "req-1")
	before, _ := world.stored(binding.RunId)
	summary := testResponsesUser("Summary of the work so far: the synthetic files were listed.")
	compacted, _, _ := world.call(binding, testResponsesBody("You are Codex.", append(append([]string{}, head...), summary, testResponsesUser("continue"))...), "req-2")
	after, _ := world.stored(binding.RunId)
	if len(after) != len(before)+2 {
		t.Fatalf("%d nodes after the compaction, %d before: only the summary and the prompt are new", len(after), len(before))
	}
	inputs := compacted.InputNodeIds()
	if inputs[0] != whole.InputNodeIds()[0] || inputs[1] != whole.InputNodeIds()[1] {
		t.Error("the compaction's kept items were written again")
	}
	if !bytes.Equal(after[inputs[2]].GetParentNodeId(), inputs[1].Bytes()) {
		t.Error("the summary does not hang from the last item kept")
	}
}

// A harness that clears a tool result rewrites its context: the request branches at the cleared result, and the items
// after it that the run holds already are same_as nodes, a header each and no bytes.
func TestSessionGatewayClearedToolResultBranches(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	prompt, call, later := testResponsesUser("the synthetic task"), testResponsesCall(1, `{"command":["cat","big.log"]}`), testResponsesUser("now fix it")
	first, _, _ := world.call(binding, testResponsesBody("You are Codex.", prompt, call, testResponsesCallOutput(1, testGatewayOutput(1, 6000)), later), "req-1")
	cleared, _, _ := world.call(binding, testResponsesBody("You are Codex.", prompt, call, testResponsesCallOutput(1, "[cleared]"), later, testResponsesUser("and test it")), "req-2")
	nodes, _ := world.stored(binding.RunId)
	inputs := cleared.InputNodeIds()
	if inputs[1] != first.InputNodeIds()[1] || inputs[2] == first.InputNodeIds()[2] {
		t.Fatal("the cleared result did not branch after the call")
	}
	if !bytes.Equal(nodes[inputs[2]].GetParentNodeId(), inputs[1].Bytes()) {
		t.Error("the branch does not hang from the call")
	}
	repeated := nodes[inputs[3]]
	if !bytes.Equal(repeated.GetSameAs(), first.InputNodeIds()[3].Bytes()) || len(repeated.GetItem()) != 0 {
		t.Error("the prompt the run holds elsewhere is no same_as node")
	}
	if len(nodes[inputs[4]].GetSameAs()) != 0 {
		t.Error("a new prompt is a same_as node")
	}
}

// The reasoning the router streamed is recorded in the response's node, which the gateway's sealed blob names (§8.5);
// Codex carries the item back with that blob, and the request lands on the same node, nothing written again.
func TestSessionGatewayReasoningBlobMatchesNode(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	prompt := testResponsesUser("the synthetic task")
	reasoning := testResponsesReasoning(1, "List the files first.", "sealed-blob-naming-the-node")
	_, _, outputs := world.call(binding, testResponsesBody("You are Codex.", prompt), "req-1", reasoning, testResponsesCallDone(1, `{"command":["ls"]}`))
	blobNodeId := outputs[0]
	next, _, _ := world.call(binding, testResponsesBody("You are Codex.", prompt, reasoning, testResponsesCall(1, `{"command":["ls"]}`), testResponsesCallOutput(1, "a.go b.go")), "req-2")
	if next.InputNodeIds()[1] != blobNodeId {
		t.Fatal("the replayed reasoning item is not the node its blob names")
	}
	nodes, _ := world.stored(binding.RunId)
	if !bytes.Contains(nodes[blobNodeId].GetItem(), []byte("List the files first.")) || bytes.Contains(nodes[blobNodeId].GetItem(), []byte("sealed-blob")) {
		t.Error("the reasoning node holds the blob, or not the reasoning text")
	}
}

// A side request, a sub-agent or a title request that shares no prefix with the session, is a tree of its own in the
// run: a root, its system node its own where its instructions differ.
func TestSessionGatewaySideRequestOwnTree(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	main, _, _ := world.call(binding, testResponsesBody("You are Codex.", testResponsesUser("the synthetic task")), "req-1")
	side, _, _ := world.call(binding, testResponsesBody("Write a title for the conversation.", testResponsesUser("Title this: the synthetic task, in five words.")), "req-side")
	nodes, _ := world.stored(binding.RunId)
	root := nodes[side.InputNodeIds()[0]]
	if len(root.GetParentNodeId()) != 0 || len(root.GetParentRunId()) != 0 {
		t.Error("the side request hangs from the session")
	}
	mainSystem, _ := main.SystemNodeId()
	sideSystem, _ := side.SystemNodeId()
	if mainSystem == sideSystem || len(nodes[sideSystem].GetParentNodeId()) != 0 {
		t.Error("the side request's instructions are not a system node of their own")
	}
}

// Sessions opened in one directory share their first items: a second session of the grant starts its own tree, not a
// resume, unless its harness reports one, when its first new node hangs from the earlier run's node by a parent link
// alone, none of the earlier run's items written again, and the call names the run it continues.
func TestSessionGatewaySameDirectoryNewSessionNotResume(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	environment := testResponsesUser("<environment_context><cwd>/tmp/synthetic</cwd></environment_context>")
	agents := testResponsesUser("# AGENTS.md\nRun the synthetic tests before you finish.")
	first := world.bound()
	firstCall, _, _ := world.call(first, testResponsesBody("You are Codex.", environment, agents, testResponsesUser("fix the parser")), "req-1")
	fresh := world.bound()
	freshCall, freshEnded, _ := world.call(fresh, testResponsesBody("You are Codex.", environment, agents, testResponsesUser("write the docs")), "req-2")
	freshNodes, _ := world.stored(fresh.RunId)
	if len(freshNodes) != 4 || freshEnded.Continues != nil || len(freshNodes[freshCall.InputNodeIds()[0]].GetParentRunId()) != 0 {
		t.Fatalf("a new session in the same directory: %d nodes, continues %v", len(freshNodes), freshEnded.Continues)
	}
	resumed := world.bound()
	resumed.Resumes = []sidecar.Id{first.RunId}
	resumedCall, resumedEnded, _ := world.call(resumed, testResponsesBody("You are Codex.", environment, agents, testResponsesUser("fix the parser"), testResponsesUser("and the lexer")), "req-3")
	resumedNodes, _ := world.stored(resumed.RunId)
	inputs := resumedCall.InputNodeIds()
	if inputs[0] != firstCall.InputNodeIds()[0] || inputs[2] != firstCall.InputNodeIds()[2] {
		t.Fatal("the resumed session's prefix is not the earlier run's nodes")
	}
	if runIds := resumedCall.InputRunIds(); runIds[2] != first.RunId || runIds[3] != resumed.RunId {
		t.Errorf("the resumed call's runs %v", runIds)
	}
	link := resumedNodes[inputs[3]]
	if len(resumedNodes) != 2 || !bytes.Equal(link.GetParentRunId(), first.RunId.Bytes()) || !bytes.Equal(link.GetParentNodeId(), inputs[2].Bytes()) {
		t.Fatalf("the resumed run holds %d nodes, its first hanging from %x", len(resumedNodes), link.GetParentNodeId())
	}
	if continues := resumedEnded.Continues; continues == nil || continues.RunId != first.RunId || continues.NodeId != inputs[2] || continues.EntryId == nil {
		t.Errorf("the call continues %+v", resumedEnded.Continues)
	}
	// the resumed run's next call finds its prefix across both runs
	again, _, _ := world.call(resumed, testResponsesBody("You are Codex.", environment, agents, testResponsesUser("fix the parser"), testResponsesUser("and the lexer"), testResponsesUser("and the tests")), "req-4")
	after, _ := world.stored(resumed.RunId)
	if len(after) != len(resumedNodes)+1 || again.InputNodeIds()[3] != inputs[3] {
		t.Errorf("the resumed run's next call wrote %d nodes", len(after)-len(resumedNodes))
	}
}

// A Chat Completions request's leading system message and tools are its system node, its other messages its items,
// the assistant's message completed at finish_reason one node, which the next request carries back and lands on.
func TestSessionGatewayChatCompletionsRecorded(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	body := func(messages ...string) []byte {
		return []byte(`{"model":"local-test-model-high","stream":true,"temperature":0.2,"tools":[{"type":"function","function":{"name":"read","parameters":{"type":"object"}}}],` +
			`"messages":[{"role":"system","content":"You are a synthetic coding agent."},` + strings.Join(messages, ",") + `]}`)
	}
	prompt := `{"role":"user","content":"read the synthetic notes"}`
	answer := `{"role":"assistant","content":null,"refusal":null,"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"read","arguments":"{\"path\":\"notes.md\"}"}}]}`
	carried := `{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"read","arguments":"{\"path\":\"notes.md\"}"}}]}`
	result := `{"role":"tool","tool_call_id":"call_1","content":"the synthetic notes"}`
	first, firstEnded, outputs := world.callOf(binding, sidecar.SessionGatewayApiChatCompletions, body(prompt), "chatcmpl-1", answer)
	second, _, _ := world.callOf(binding, sidecar.SessionGatewayApiChatCompletions, body(prompt, carried, result), "chatcmpl-2",
		`{"role":"assistant","content":"The notes say nothing."}`)
	nodes, _ := world.stored(binding.RunId)
	if len(nodes) != 5 {
		t.Fatalf("%d nodes, not a system node, the prompt, the call, its result and the answer", len(nodes))
	}
	systemNodeId, ok := first.SystemNodeId()
	if !ok || !bytes.Contains(nodes[systemNodeId].GetItem(), []byte("You are a synthetic coding agent.")) || !bytes.Contains(nodes[systemNodeId].GetItem(), []byte(`"tools"`)) {
		t.Fatal("the system message and tools are not the system node")
	}
	if second.InputNodeIds()[1] != outputs[0] {
		t.Error("the carried-back assistant message is not the answer's node")
	}
	if !bytes.Contains(firstEnded.Context.GetParams(), []byte(`"temperature":0.2`)) || bytes.Contains(firstEnded.Context.GetParams(), []byte(`"messages"`)) {
		t.Errorf("params %s", firstEnded.Context.GetParams())
	}
}

// Two Codex-shaped turns (testdata/session/gateway/codex_turns.json): the second request carries the first's output
// items back without their ids and statuses, with the reasoning's sealed blob and a null content, and the message
// without its empty annotations and logprobs; each lands on the node its item completed as, the system node is the
// first's, and only the function call's output is new.
func TestSessionGatewayCodexShapedTurnsLineUp(t *testing.T) {
	content, err := os.ReadFile("testdata/session/gateway/codex_turns.json")
	if err != nil {
		t.Fatal(err)
	}
	turns := struct {
		FirstRequest  json.RawMessage   `json:"first_request"`
		FirstOutputs  []json.RawMessage `json:"first_outputs"`
		SecondRequest json.RawMessage   `json:"second_request"`
	}{}
	if err := json.Unmarshal(content, &turns); err != nil {
		t.Fatal(err)
	}
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	outputs := []string{}
	for _, output := range turns.FirstOutputs {
		outputs = append(outputs, string(output))
	}
	first, _, outputNodeIds := world.call(binding, turns.FirstRequest, "resp_000001", outputs...)
	before, _ := world.stored(binding.RunId)
	second, ended, _ := world.call(binding, turns.SecondRequest, "resp_000002")
	inputs := second.InputNodeIds()
	if len(inputs) != 7 || !slices.Equal(inputs[:3], first.InputNodeIds()) || !slices.Equal(inputs[3:6], outputNodeIds) {
		t.Fatalf("the second turn's context %v does not take the first's request %v and answer %v", inputs, first.InputNodeIds(), outputNodeIds)
	}
	firstSystem, _ := first.SystemNodeId()
	secondSystem, _ := second.SystemNodeId()
	after, _ := world.stored(binding.RunId)
	if firstSystem != secondSystem || len(after) != len(before)+1 {
		t.Errorf("%d nodes after the second turn, %d before", len(after), len(before))
	}
	if !ended.Context.GetExact() || !bytes.Contains(ended.Context.GetParams(), []byte(`"prompt_cache_key"`)) || bytes.Contains(ended.Context.GetParams(), []byte(`"input"`)) {
		t.Errorf("the second turn's context: exact %v, params %s", ended.Context.GetExact(), ended.Context.GetParams())
	}
}

// A run of another grant named as resumed is passed over: the session starts its own tree, sharing nothing with it.
func TestSessionGatewayResumeOfAnotherGrantPassedOver(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	prompt := testResponsesUser("a synthetic prompt both sessions send")
	other := world.bound()
	other.GrantId = sidecar.NewId()
	world.call(other, testResponsesBody("You are Codex.", prompt), "req-other")
	resumed := world.bound()
	resumed.Resumes = []sidecar.Id{other.RunId}
	call, ended, _ := world.call(resumed, testResponsesBody("You are Codex.", prompt, testResponsesUser("and more")), "req-resumed")
	if ended.Continues != nil || call.InputRunIds()[0] != resumed.RunId {
		t.Errorf("a session resumed another grant's run: %+v, %v", ended.Continues, call.InputRunIds())
	}
}
