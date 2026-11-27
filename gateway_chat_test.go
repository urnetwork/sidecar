//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension && !windows

package sidecar

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// GW-M12-04's Chat Completions front (DESIGN-COMPUTE §8.5's Chat Completions column): goldens streaming and not, tool
// calls interleaved and each chunk carrying its index; an error mid-stream; the translation; and the renderer. Requests
// are shaped from what OpenCode and Aider send (research_notes' gateway_harness_compat.md); everything is synthetic.

// A Chat Completions request as OpenCode sends one: a system message, the person's text, a bash tool, usage asked for.
func testGatewayChatBody(stream bool, extra ...string) string {
	members := []string{
		`"model":"chutes-kimi-k3-tee-high"`,
		`"messages":[{"role":"system","content":"synthetic system"},{"role":"user","content":"list the files"}]`,
		`"tools":[{"type":"function","function":{"name":"bash","description":"runs a command","parameters":{"type":"object","properties":{"command":{"type":"string"}}}}}]`,
		`"tool_choice":"auto"`,
		`"temperature":0.2`,
		`"max_tokens":1000`,
		`"stream":` + strconv.FormatBool(stream),
	}
	if stream {
		members = append(members, `"stream_options":{"include_usage":true}`)
	}
	return "{" + strings.Join(append(members, extra...), ",") + "}"
}

// The data of each chunk of a Chat Completions stream, failing on a frame that is no data line; [DONE] answered as
// nil, last.
func testGatewayChatChunks(t *testing.T, stream string) []map[string]any {
	t.Helper()
	chunks := []map[string]any{}
	for _, frame := range strings.Split(strings.TrimSuffix(stream, "\n\n"), "\n\n") {
		if frame == "" || strings.HasPrefix(frame, ":") {
			continue
		}
		data, ok := strings.CutPrefix(frame, "data: ")
		if !ok {
			t.Fatalf("a frame that is no data line: %q", frame)
		}
		if data == gatewayChatDone {
			chunks = append(chunks, nil)
			continue
		}
		chunk := map[string]any{}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			t.Fatalf("a chunk that is no JSON object: %q", data)
		}
		chunks = append(chunks, chunk)
	}
	return chunks
}

// Chat Completions' rules for a stream: the first chunk carries the role; every tool call delta its index; one chunk
// carries finish_reason, with usage, and [DONE] comes last.
func testGatewayChatConformance(t *testing.T, stream string) {
	t.Helper()
	chunks := testGatewayChatChunks(t, stream)
	if len(chunks) < 2 || chunks[len(chunks)-1] != nil {
		t.Fatalf("a stream that does not end with [DONE]")
	}
	finishes := 0
	for i, chunk := range chunks[:len(chunks)-1] {
		if chunk["object"] != gatewayChatObjectChunk || !strings.HasPrefix(chunk["id"].(string), gatewayChatIdPrefix) {
			t.Errorf("chunk %d: %v", i, chunk)
		}
		choices, _ := chunk["choices"].([]any)
		if len(choices) != 1 {
			t.Fatalf("chunk %d's choices: %v", i, choices)
		}
		choice := choices[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		if i == 0 && delta["role"] != gatewayRoleAssistant {
			t.Errorf("the first chunk carries no role: %v", delta)
		}
		if calls, ok := delta["tool_calls"].([]any); ok {
			for _, call := range calls {
				if _, indexed := call.(map[string]any)["index"].(float64); !indexed {
					t.Errorf("chunk %d: a tool call delta without its index: %v", i, call)
				}
			}
		}
		if choice["finish_reason"] != nil {
			finishes++
			usage, _ := chunk["usage"].(map[string]any)
			for _, member := range []string{"prompt_tokens", "completion_tokens", "total_tokens"} {
				if value, ok := usage[member].(float64); !ok || value != float64(int64(value)) {
					t.Errorf("usage.%s: %v", member, usage[member])
				}
			}
		}
	}
	if finishes != 1 {
		t.Errorf("%d chunks carry a finish_reason", finishes)
	}
}

// Goldens of scripted streams: text alone, reasoning then text, and two tool calls whose events interleave, each
// delta carrying its call's index; and the whole answer, the message, its tool calls and usage. The assistant message
// is recorded whole before the chunk carrying finish_reason.
func TestChatGoldenTranscripts(t *testing.T) {
	interleaved := []*InferEvent{
		{Kind: InferEventToolCallStart, ToolCall: &InferToolCall{Id: "call_a", Name: "bash"}},
		{Kind: InferEventToolCallStart, ToolCall: &InferToolCall{Id: "call_b", Name: "bash"}},
		{Kind: InferEventToolCallArgs, ToolCall: &InferToolCall{Id: "call_a", Arguments: `{"command":`}},
		{Kind: InferEventToolCallArgs, ToolCall: &InferToolCall{Id: "call_b", Arguments: `{"command":"pwd"}`}},
		{Kind: InferEventToolCallArgs, ToolCall: &InferToolCall{Id: "call_a", Arguments: `"ls"}`}},
		{Kind: InferEventToolCallEnd, ToolCall: &InferToolCall{Id: "call_a", Name: "bash", Arguments: `{"command":"ls"}`}},
		{Kind: InferEventToolCallEnd, ToolCall: &InferToolCall{Id: "call_b", Name: "bash", Arguments: `{"command":"pwd"}`}},
	}
	cases := []struct {
		name   string
		stream bool
		turn   *testGatewayTurn
	}{
		{name: "text.sse", stream: true, turn: &testGatewayTurn{text: []string{"Here ", "they are."}, usage: &InferUsage{InputTokens: 50, OutputTokens: 3, CachedTokens: 32}}},
		{name: "reasoning.sse", stream: true, turn: &testGatewayTurn{reasoning: []string{"A listing ", "is asked."}, text: []string{"Listing."}, usage: &InferUsage{InputTokens: 50, OutputTokens: 9, ReasoningTokens: 6}}},
		{name: "tool_calls_interleaved.sse", stream: true, turn: &testGatewayTurn{events: interleaved, usage: &InferUsage{InputTokens: 60, OutputTokens: 14}}},
		{name: "not_streaming.json", stream: false, turn: &testGatewayTurn{reasoning: []string{"Short."}, text: []string{"Done."}, events: interleaved[:1], usage: &InferUsage{InputTokens: 5, OutputTokens: 4}}},
	}
	for _, each := range cases {
		world := newTestGatewayFrontWorld(t, nil)
		if each.name == "not_streaming.json" {
			// a call whose arguments stream no delta still answers them whole
			each.turn.events = append(slices.Clone(each.turn.events), &InferEvent{Kind: InferEventToolCallEnd, ToolCall: &InferToolCall{Id: "call_a", Name: "bash", Arguments: `{"command":"ls"}`}})
		}
		world.router.script(each.turn)
		answer := world.serve(gatewayChatFront{}, testGatewayChatBody(each.stream), nil)
		if answer.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", each.name, answer.Code, answer.Body.String())
		}
		testGatewayGolden(t, "chat", each.name, answer.Body.Bytes())
		if each.stream {
			testGatewayChatConformance(t, answer.Body.String())
		}
		order := world.order.all()
		recorded := slices.Index(order, "record:")
		finished := slices.IndexFunc(order, func(entry string) bool {
			return strings.HasPrefix(entry, "frame:") && strings.Contains(entry, "finish")
		})
		if recorded < 0 || (each.stream && 0 <= finished && finished < recorded) {
			t.Errorf("%s: the message was not recorded before its finish: %v", each.name, order)
		}
		_, items, ends := world.recorder.snapshot()
		if len(items) != 1 || len(ends) != 1 || ends[0].Outcome != GatewayRecordCompleted {
			t.Errorf("%s: %d items, ends %+v", each.name, len(items), ends)
		}
	}
}

// A failure after the stream began is an error chunk whose code a harness does not retry, then [DONE]; one before it
// is answered in the API's status.
func TestChatErrorMidStream(t *testing.T) {
	world := newTestGatewayFrontWorld(t, nil)
	world.router.script(&testGatewayTurn{
		text:      []string{"partial ", "answer"},
		fail:      &InferError{Code: InferErrorEngineFailed, Message: "the provider's stream broke"},
		failAfter: 1,
	})
	answer := world.serve(gatewayChatFront{}, testGatewayChatBody(true), nil)
	chunks := testGatewayChatChunks(t, answer.Body.String())
	if len(chunks) < 3 || chunks[len(chunks)-1] != nil {
		t.Fatalf("the stream: %s", answer.Body.String())
	}
	failure, _ := chunks[len(chunks)-2]["error"].(map[string]any)
	if failure["code"] != gatewayErrorCodeNotRetried || !strings.Contains(failure["message"].(string), "stream broke") {
		t.Errorf("the error chunk: %v", chunks[len(chunks)-2])
	}
	world.router.script(&testGatewayTurn{first: &InferError{Code: InferErrorTeeUnverified, Model: "chutes-kimi-k3-tee-high", Message: "no instance verified"}})
	first := world.serve(gatewayChatFront{}, testGatewayChatBody(true), nil)
	if first.Code != http.StatusServiceUnavailable || !strings.Contains(first.Body.String(), `"code":"tee_unverified"`) {
		t.Errorf("a first-event failure: %d %s", first.Code, first.Body.String())
	}
}

// The translation: system and developer messages, the person's parts, an assistant's text and tool calls, tool
// results naming their call, the legacy functions and function_call, stop as one string or several, response_format,
// max_completion_tokens before max_tokens, and an assistant's reasoning_content never given back.
func TestChatTranslation(t *testing.T) {
	body := `{"model":"engy-glm-5.2","reasoning_effort":"high","messages":[` +
		`{"role":"developer","content":"synthetic developer"},` +
		`{"role":"user","content":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo=","detail":"low"}}]},` +
		`{"role":"assistant","content":null,"reasoning_content":"earlier thoughts","tool_calls":[{"id":"call_1","type":"function","function":{"name":"bash","arguments":"{\"command\":\"ls\"}"}}]},` +
		`{"role":"tool","tool_call_id":"call_1","content":"main.go"},` +
		`{"role":"function","name":"legacy","content":"legacy result"}],` +
		`"functions":[{"name":"legacy","parameters":{"type":"object"}}],"function_call":{"name":"legacy"},` +
		`"stop":"END","response_format":{"type":"json_schema","json_schema":{"name":"x","schema":{"type":"object"}}},` +
		`"max_tokens":10,"max_completion_tokens":20}`
	request, options, refusal := gatewayTranslateChat([]byte(body))
	if refusal != nil {
		t.Fatal(refusal)
	}
	if options.Stream || len(request.Messages) != 5 || request.Messages[0].Role != InferRoleSystem ||
		request.Messages[1].Parts[1].Kind != InferPartImage || request.Messages[2].Reasoning != "" ||
		request.Messages[2].ToolCalls[0].Id != "call_1" || request.Messages[3].ToolCallId != "call_1" ||
		request.Messages[4].Role != InferRoleTool || request.Messages[4].ToolCallId != "legacy" {
		encoded, _ := json.Marshal(request)
		t.Fatalf("the messages: %s", encoded)
	}
	if request.ToolChoice != "legacy" || len(request.Tools) != 1 || request.MaxOutput != 20 || request.Reasoning != "high" ||
		request.Sampling == nil || len(request.Sampling.Stops) != 1 || string(request.Schema) != `{"type":"object"}` {
		t.Errorf("the fields: %+v", request)
	}
	several, _, refusal := gatewayTranslateChat([]byte(`{"model":"engy-glm-5.2","messages":[{"role":"user","content":"x"}],"stop":["A","B"]}`))
	if refusal != nil || len(several.Sampling.Stops) != 2 {
		t.Errorf("stop as an array: %+v %v", several, refusal)
	}
	if _, refusal := gatewayRouteChat(DefaultGatewaySettings(), []byte(`{"model":"engy-glm-5.2","n":2,"messages":[{"role":"user","content":"x"}]}`)); refusal == nil || refusal.Param != "n" {
		t.Errorf("n past 1: %+v", refusal)
	}
	if _, refusal := gatewayRouteChat(DefaultGatewaySettings(), []byte(`{"model":"engy-glm-5.2","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://images.example/x.png"}}]}]}`)); refusal == nil || refusal.Code != GatewayErrorCodeInvalidImage {
		t.Errorf("an image to fetch: %+v", refusal)
	}
}

// The Chat renderer, rebuilding the body from the recorded form (its leading system messages in its system item),
// gives the request the translation gave.
func TestChatRendererMatchesTranslation(t *testing.T) {
	routed := []byte(testGatewayChatBody(true, `"stop":["END"]`))
	request, _, refusal := gatewayTranslateChat(routed)
	if refusal != nil {
		t.Fatal(refusal)
	}
	items, err := sessionGatewayItemsOf(SessionGatewayApiChatCompletions, routed)
	if err != nil {
		t.Fatal(err)
	}
	canonical := func(value any) []byte {
		t.Helper()
		encoded, _ := json.Marshal(value)
		canonical, err := CanonicalJson(encoded)
		if err != nil {
			t.Fatal(err)
		}
		return canonical
	}
	context := &SessionRenderContext{Params: canonical(items.params)}
	if items.system != nil {
		context.System = []*SessionRenderItem{{Item: canonical(items.system)}}
	}
	for _, item := range items.input {
		context.Nodes = append(context.Nodes, &SessionRenderItem{Item: canonical(item)})
	}
	renderer, err := SessionRendererOf(GatewayRendererChatCompletions)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := renderer.Render(context)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := SessionRequestSha256Of(request)
	got, _ := SessionRequestSha256Of(rendered)
	if want != got {
		a, _ := json.Marshal(request)
		b, _ := json.Marshal(rendered)
		t.Errorf("the render differs:\n%s\n%s", a, b)
	}
}
