//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// GW-M12-03's translation (DESIGN-COMPUTE §8.5): a Codex-shaped history becomes one InferRequest, an assistant's
// reasoning, text and tool calls gathered into its turn, tool results naming their calls; the tool choice and text
// format forms; and the session renderer, which rebuilds the body from the recorded items, translating to the same
// request.

// A Codex history: its base instructions as a developer message, the person's text and screenshot, a turn of reasoning,
// text and two tool calls, their outputs, and a second turn.
const testGatewayHistory = `{
  "model": "chutes-kimi-k3-tee-high",
  "instructions": "synthetic top-level instructions",
  "input": [
    {"type":"message","id":"msg_harness_1","role":"developer","content":[{"type":"input_text","text":"synthetic base instructions"}]},
    {"type":"message","role":"user","content":[{"type":"input_text","text":"fix the build"},{"type":"input_image","image_url":"data:image/png;base64,iVBORw0KGgo=","detail":"auto"}]},
    {"type":"reasoning","id":"rs_harness_2","summary":[{"type":"summary_text","text":"Look first."}]},
    {"type":"message","role":"assistant","content":[{"type":"output_text","text":"Looking.","annotations":[]}]},
    {"type":"function_call","id":"fc_harness_3","call_id":"call_a","name":"shell","arguments":"{\"command\":[\"ls\"]}"},
    {"type":"function_call","call_id":"call_b","name":"shell","arguments":"{\"command\":[\"pwd\"]}"},
    {"type":"function_call_output","call_id":"call_a","output":"main.go"},
    {"type":"function_call_output","call_id":"call_b","output":[{"type":"input_text","text":"/synthetic"}]},
    {"type":"message","role":"assistant","content":[{"type":"output_text","text":"Found main.go."}]},
    {"role":"user","content":"thanks"}
  ],
  "tools": [{"type":"function","name":"shell","description":"runs a command","parameters":{"type":"object"}}],
  "tool_choice": "auto",
  "reasoning": {"effort": "high"},
  "max_output_tokens": 4096,
  "temperature": 0.25,
  "text": {"format": {"type": "json_schema", "name": "answer", "schema": {"type": "object"}}},
  "stream": true,
  "include": ["reasoning.encrypted_content"]
}`

// The history translates to the system texts, the person's parts, one assistant turn holding its reasoning, text and
// both calls, two tool results and the next turn, with its tools, choice, effort, maxima, sampling and schema.
func TestTranslateResponsesConversation(t *testing.T) {
	request, options, refusal := gatewayTranslateResponses([]byte(testGatewayHistory))
	if refusal != nil {
		t.Fatal(refusal)
	}
	if !options.Stream || !options.IncludeReasoningBlob {
		t.Errorf("options %+v", options)
	}
	roles := []InferRole{}
	for _, message := range request.Messages {
		roles = append(roles, message.Role)
	}
	want := []InferRole{InferRoleSystem, InferRoleSystem, InferRoleUser, InferRoleAssistant, InferRoleTool, InferRoleTool, InferRoleAssistant, InferRoleUser}
	if len(roles) != len(want) {
		t.Fatalf("roles %v, want %v", roles, want)
	}
	for i := range want {
		if roles[i] != want[i] {
			t.Fatalf("roles %v, want %v", roles, want)
		}
	}
	user := request.Messages[2]
	if len(user.Parts) != 2 || user.Parts[0].Text != "fix the build" || user.Parts[1].Kind != InferPartImage ||
		user.Parts[1].MediaType != "image/png" || !bytes.HasPrefix(user.Parts[1].Data, []byte("\x89PNG")) {
		t.Errorf("the person's parts: %+v", user.Parts)
	}
	turn := request.Messages[3]
	if turn.Reasoning != "Look first." || turn.Text() != "Looking." || len(turn.ToolCalls) != 2 ||
		turn.ToolCalls[0].Id != "call_a" || turn.ToolCalls[1].Arguments != `{"command":["pwd"]}` {
		t.Errorf("the assistant's turn: %+v %+v", turn, turn.ToolCalls)
	}
	if request.Messages[4].ToolCallId != "call_a" || request.Messages[4].Text() != "main.go" ||
		request.Messages[5].ToolCallId != "call_b" || request.Messages[5].Text() != "/synthetic" {
		t.Errorf("the tool results: %+v %+v", request.Messages[4], request.Messages[5])
	}
	if request.Messages[7].Text() != "thanks" {
		t.Errorf("an easy input message: %+v", request.Messages[7])
	}
	if len(request.Tools) != 1 || request.ToolChoice != "auto" || request.Reasoning != "high" || request.MaxOutput != 4096 ||
		request.Sampling == nil || *request.Sampling.Temperature != 0.25 || string(request.Schema) != `{"type": "object"}` {
		t.Errorf("the request's fields: %+v", request)
	}
}

// tool_choice's forms: the words, a function the model is offered, one it is not (auto), allowed_tools as a hard
// constraint, and a hosted tool's choice (auto).
func TestTranslateToolChoice(t *testing.T) {
	tools := []*InferTool{{Name: "shell"}, {Name: "read"}}
	for _, each := range []struct {
		choice string
		want   string
		kept   int
	}{
		{choice: `"none"`, want: "none", kept: 2},
		{choice: `"required"`, want: "required", kept: 2},
		{choice: `{"type":"function","name":"read"}`, want: "read", kept: 2},
		{choice: `{"type":"function","name":"absent"}`, want: "auto", kept: 2},
		{choice: `{"type":"allowed_tools","mode":"required","tools":[{"type":"function","name":"shell"}]}`, want: "required", kept: 1},
		{choice: `{"type":"allowed_tools","mode":"auto","tools":[{"type":"mcp","server_label":"x"}]}`, want: "none", kept: 0},
		{choice: `{"type":"web_search_preview"}`, want: "auto", kept: 2},
		{choice: `{"type":"function","function":{"name":"shell"}}`, want: "shell", kept: 2},
	} {
		choice, kept, refusal := gatewayInferToolChoice(json.RawMessage(each.choice), tools)
		if refusal != nil || choice != each.want || len(kept) != each.kept {
			t.Errorf("%s: %q %d %v", each.choice, choice, len(kept), refusal)
		}
	}
	if _, _, refusal := gatewayInferToolChoice(json.RawMessage(`"sometimes"`), tools); refusal == nil {
		t.Error("an unknown word was taken")
	}
}

// The text formats: json_schema's schema, json_object's object, text's none.
func TestTranslateTextFormat(t *testing.T) {
	for _, each := range []struct {
		format string
		want   string
	}{
		{format: `{"type":"json_schema","name":"x","schema":{"type":"array"}}`, want: `{"type":"array"}`},
		{format: `{"type":"json_object"}`, want: `{"type":"object"}`},
		{format: `{"type":"text"}`, want: ``},
	} {
		schema, refusal := gatewayInferSchema(json.RawMessage(each.format))
		if refusal != nil || string(schema) != each.want {
			t.Errorf("%s: %s %v", each.format, schema, refusal)
		}
	}
	if _, refusal := gatewayInferSchema(json.RawMessage(`{"type":"json_schema","name":"x"}`)); refusal == nil {
		t.Error("a json_schema format without its schema was taken")
	}
}

// A request without a model or input, or whose members are not the API's shape, is refused 400 naming the member.
func TestTranslateRefusesMalformed(t *testing.T) {
	for _, each := range []struct {
		body  string
		param string
	}{
		{body: `{"input":"hi"}`, param: "model"},
		{body: `{"model":"chutes-kimi-k3-tee-high"}`, param: "input"},
		{body: `{"model":"chutes-kimi-k3-tee-high","input":"hi","max_output_tokens":-1}`, param: "max_output_tokens"},
		{body: `{"model":"chutes-kimi-k3-tee-high","input":[{"type":"message","role":"user","content":7}]}`, param: "input[0]"},
	} {
		_, _, refusal := gatewayTranslateResponses([]byte(each.body))
		if refusal == nil || refusal.Param != each.param || refusal.Status != 400 {
			t.Errorf("%s: %+v", each.body, refusal)
		}
	}
	if _, refusal := gatewayRouteResponses(DefaultGatewaySettings(), []byte(`[1]`), nil); refusal == nil {
		t.Error("a body that is no object was routed")
	}
}

// The routed body records and translates the same: the renderer, rebuilding the body from the recorded form's system
// item, input items and params, gives the request the translation gave, so request_sha256 is what was sent.
func TestRendererMatchesTranslation(t *testing.T) {
	routed := []byte(testGatewayHistory)
	request, _, refusal := gatewayTranslateResponses(routed)
	if refusal != nil {
		t.Fatal(refusal)
	}
	items, err := sessionGatewayItemsOf(SessionGatewayApiResponses, routed)
	if err != nil {
		t.Fatal(err)
	}
	canonical := func(value any) []byte {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
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
	renderer, err := SessionRendererOf(GatewayRendererResponses)
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
		t.Errorf("the render differs from the translation:\n%s\n%s", a, b)
	}
	// a part kept apart renders from its reference's text, not refused
	context.Nodes[1].Item = []byte(strings.Replace(string(context.Nodes[1].Item), "data:image/png;base64,iVBORw0KGgo=", `{\"pointer\":\"/content/1/image_url\"}`, 1))
	if _, err := renderer.Render(context); err != nil {
		t.Errorf("a part's reference: %v", err)
	}
}
