//go:build !ios_extension && !sidecar_http && !js

// CTXH-M13-01's Messages recording (DESIGN-COMPUTE §24.8, §24.16's Deduplication row; R-CTXH-5, D-CTXH-6) on
// session_gateway_test.go's world: Claude Code-shaped calls through the gateway, the answer's content blocks each
// journaled as it completes, cache_control moving from block to block between calls and a thinking block's signature
// changing without breaking the match, a replayed thinking block landing on the node its signature names, and Claude
// Code's clearing of an old tool result branching there, the blocks after it the run holds as same_as nodes.

package sidecar_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A Claude Code-shaped Messages request: its system blocks and tools, cache_control on the last of each as Claude Code
// places it, and the messages given.
func testMessagesBody(messages ...string) []byte {
	return []byte(`{"model":"local-test-model-high","max_tokens":32000,"stream":true,"thinking":{"type":"adaptive"},` +
		`"metadata":{"user_id":"synthetic-user"},` +
		`"system":[{"type":"text","text":"You are Claude Code, a synthetic coding agent."},{"type":"text","text":"Follow the synthetic repository's rules.","cache_control":{"type":"ephemeral"}}],` +
		`"tools":[{"name":"Read","description":"Reads a file.","input_schema":{"type":"object"}},{"name":"mcp__ur__evs_read","description":"Reads an evs file.","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral"}}],` +
		`"messages":[` + strings.Join(messages, ",") + `]}`)
}

// Claude Code-shaped calls are recorded block by block and deduplicated: the second call carries the first's answer
// back with cache_control moved onto its last block and the thinking block's signature as the gateway sealed it, and
// lands on the blocks the first wrote, only its tool result new; the system node holds the system text and tools
// whatever cache_control marks; and a later call that clears the old tool result branches at it, the prompt after it a
// same_as node.
func TestSessionGatewayMessagesRecordedAndDeduplicated(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	binding := world.bound()
	prompt := `{"role":"user","content":[{"type":"text","text":"why does the synthetic build fail?","cache_control":{"type":"ephemeral"}}]}`
	first, _, blocks := world.callOf(binding, sidecar.SessionGatewayApiMessages, testMessagesBody(prompt), "msg_1",
		`{"type":"thinking","thinking":"Read the log first.","signature":"sealed-signature-1"}`,
		`{"type":"text","text":"Reading the log."}`,
		`{"type":"tool_use","id":"toolu_1","name":"Read","input":{"file_path":"/tmp/synthetic/build.log"}}`)
	if len(blocks) != 3 || len(first.InputNodeIds()) != 1 {
		t.Fatalf("%d blocks, %d inputs", len(blocks), len(first.InputNodeIds()))
	}
	carried := `{"role":"user","content":[{"type":"text","text":"why does the synthetic build fail?"}]},` +
		`{"role":"assistant","content":[{"type":"thinking","thinking":"Read the log first.","signature":"sealed-signature-1"},{"type":"text","text":"Reading the log."},` +
		`{"type":"tool_use","id":"toolu_1","name":"Read","input":{"file_path":"/tmp/synthetic/build.log"},"cache_control":{"type":"ephemeral"}}]}`
	result := `{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"` + strings.Repeat("error: a missing synthetic symbol\\n", 40) + `","cache_control":{"type":"ephemeral"}}]}`
	before, _ := world.stored(binding.RunId)
	second, ended, _ := world.callOf(binding, sidecar.SessionGatewayApiMessages, testMessagesBody(carried, result), "msg_2", `{"type":"text","text":"A symbol is missing."}`)
	inputs := second.InputNodeIds()
	if len(inputs) != 5 || inputs[0] != first.InputNodeIds()[0] || inputs[1] != blocks[0] || inputs[2] != blocks[1] || inputs[3] != blocks[2] {
		t.Fatalf("the second call's context %v does not take the first's prompt and blocks %v", inputs, blocks)
	}
	after, _ := world.stored(binding.RunId)
	if len(after) != len(before)+2 {
		t.Errorf("%d nodes after the second call, %d before: the tool result and the answer are new", len(after), len(before))
	}
	firstSystem, _ := first.SystemNodeId()
	secondSystem, _ := second.SystemNodeId()
	if firstSystem != secondSystem || bytes.Contains(after[firstSystem].GetItem(), []byte("cache_control")) || !bytes.Contains(after[firstSystem].GetItem(), []byte("mcp__ur__evs_read")) {
		t.Error("the system node moved with cache_control, or lost the tools")
	}
	if bytes.Contains(after[blocks[0]].GetItem(), []byte("sealed-signature")) || !bytes.Contains(after[blocks[0]].GetItem(), []byte("Read the log first.")) {
		t.Error("the thinking block's node holds the signature, or not the thinking")
	}
	if !ended.Context.GetExact() || !bytes.Contains(ended.Context.GetParams(), []byte(`"max_tokens"`)) || bytes.Contains(ended.Context.GetParams(), []byte(`"messages"`)) {
		t.Errorf("the second call's context: exact %v, params %s", ended.Context.GetExact(), ended.Context.GetParams())
	}
	// Claude Code clears the old tool result: a branch at it, the prompt after it held already
	cleared := `{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"[Old tool result content cleared]"}]}`
	answer := `{"role":"assistant","content":[{"type":"text","text":"A symbol is missing."}]}`
	third, _, _ := world.callOf(binding, sidecar.SessionGatewayApiMessages, testMessagesBody(carried, cleared, answer,
		`{"role":"user","content":"now fix it"}`), "msg_3")
	nodes, _ := world.stored(binding.RunId)
	thirdInputs := third.InputNodeIds()
	if thirdInputs[3] != inputs[3] || thirdInputs[4] == inputs[4] || !bytes.Equal(nodes[thirdInputs[4]].GetParentNodeId(), inputs[3].Bytes()) {
		t.Fatal("the cleared result does not branch after the tool use")
	}
	if len(nodes[thirdInputs[5]].GetSameAs()) == 0 {
		t.Error("the answer the run holds already is no same_as node on the branch")
	}
}

// A request's blocks keep their messages' bounds: two user messages of one block each are not one message of two
// blocks, and a string content is one text block.
func TestSessionGatewayMessagesKeepMessageBounds(t *testing.T) {
	world := newTestSessionGatewayWorld(t)
	two, _, _ := world.callOf(world.bound(), sidecar.SessionGatewayApiMessages, testMessagesBody(
		`{"role":"user","content":"first"}`, `{"role":"user","content":[{"type":"text","text":"second"}]}`), "msg_a")
	one, _, _ := world.callOf(world.bound(), sidecar.SessionGatewayApiMessages, testMessagesBody(
		`{"role":"user","content":[{"type":"text","text":"first"},{"type":"text","text":"second"}]}`), "msg_b")
	twoNodes, _ := world.stored(two.InputRunIds()[0])
	oneNodes, _ := world.stored(one.InputRunIds()[0])
	if !bytes.Contains(twoNodes[two.InputNodeIds()[1]].GetItem(), []byte(`"start":true`)) || bytes.Contains(oneNodes[one.InputNodeIds()[1]].GetItem(), []byte(`"start":true`)) {
		t.Error("a message's bounds are lost")
	}
	if !bytes.Equal(twoNodes[two.InputNodeIds()[0]].GetItemSha256(), oneNodes[one.InputNodeIds()[0]].GetItemSha256()) {
		t.Error("a string content and one text block record apart")
	}
}
