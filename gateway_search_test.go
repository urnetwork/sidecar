//go:build !ios_extension && !sidecar_http

// SRCH-M12-01's tests: the gateway serves no hosted web search (DESIGN-COMPUTE §21.7 and §8.5's hosted web search;
// R-SRCH-5, D-SRCH-5, CO-26). Each request is shaped from what its harness sends, as research_notes/Brave web search
// tool/hosted_search_in_harnesses.md read it (Codex 0.171.0, Claude Code 2.1.330): Codex's hosted tool with its
// external_web_access, Claude Code's WebSearch side request with its one web_search_20250305 tool forced by
// tool_choice. The answer's goldens follow the Messages API's documented shapes, and a test folds the stream back into
// the message as a client does. Every model name and address is synthetic.

package sidecar_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A reader of the big-endian 64-bit words 0, 1, 2 and on, so a made-up id's characters are the alphabet in order: the
// message id's 0 to L, the server_tool_use id's M to h. Safe for concurrent use.
type gatewaySearchTestCounter struct {
	stateLock sync.Mutex
	next      uint64
	pending   []byte
}

func (self *gatewaySearchTestCounter) Read(buffer []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for len(self.pending) < len(buffer) {
		self.pending = binary.BigEndian.AppendUint64(self.pending, self.next)
		self.next++
	}
	count := copy(buffer, self.pending)
	self.pending = self.pending[count:]
	return count, nil
}

// A filter on the default settings, the counter's ids and a fake clock.
func newGatewaySearchTest(settings *sidecar.GatewayHostedSearchSettings) (*sidecar.GatewayHostedSearch, *sidecartest.FakeClock) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	hostedSearch := sidecar.NewGatewayHostedSearch(&sidecar.GatewayHostedSearchArgs{
		Settings: settings,
		Clock:    clock,
		Random:   &gatewaySearchTestCounter{},
	})
	return hostedSearch, clock
}

// What a front's encoding/json decoder would take from a filtered body: every tool's type, include, and Chat
// Completions' web_search_options.
type gatewaySearchTestDecoded struct {
	Tools []struct {
		Type string `json:"type"`
	} `json:"tools"`
	ToolChoice       json.RawMessage `json:"tool_choice"`
	Include          []string        `json:"include"`
	WebSearchOptions json.RawMessage `json:"web_search_options"`
}

// Fails where a front's decoder would still find hosted search in body, filtered for api: a hosted tool or
// tool_choice in any API, an include entry in Responses, web_search_options in Chat Completions.
func assertGatewaySearchNoneLeft(t *testing.T, api sidecar.GatewayHostedSearchApi, body []byte) {
	t.Helper()
	decoded := &gatewaySearchTestDecoded{}
	if err := json.Unmarshal(body, decoded); err != nil {
		t.Fatalf("the filtered body does not decode: %v\n%s", err, body)
	}
	for _, tool := range decoded.Tools {
		if strings.HasPrefix(tool.Type, "web_search") {
			t.Errorf("%s: a decoder still takes a %s tool from %s", api, tool.Type, body)
		}
	}
	if bytes.Contains(decoded.ToolChoice, []byte("web_search_preview")) || bytes.Contains(decoded.ToolChoice, []byte(`"type":"web_search"`)) {
		t.Errorf("%s: a decoder still takes a hosted tool_choice from %s", api, body)
	}
	if api == sidecar.GatewayHostedSearchApiResponses {
		for _, entry := range decoded.Include {
			if strings.HasPrefix(entry, "web_search_call.") {
				t.Errorf("%s: a decoder still takes include %s from %s", api, entry, body)
			}
		}
	}
	if api == sidecar.GatewayHostedSearchApiChatCompletions && len(decoded.WebSearchOptions) != 0 {
		t.Errorf("%s: a decoder still takes web_search_options from %s", api, body)
	}
}

// Codex's tools as a Responses request carries them, each kept one with spacing and escapes of its own, so a test can
// hold its bytes.
const (
	gatewaySearchTestShell     = `{"type": "function", "name": "shell", "parameters": {"type":"object"}, "strict" :false}`
	gatewaySearchTestFunction  = `{"type":"function","name":"web_search","description":"a function of the harness's own named web_search","parameters":{}}`
	gatewaySearchTestMcpTool   = `{"type":"function","name":"mcp__ur__web_search","description":"URnetwork\u2019s MCP tool \u2014 kept","parameters":{"type":"object","properties":{"queries":{"type":"array"}}}}`
	gatewaySearchTestMcpServer = `{"type":"mcp","server_label":"web_search","server_url":"https://mcp.example/","allowed_tools":["web_search"]}`
	gatewaySearchTestHosted    = `{"type":"web_search","external_web_access":false}`
	gatewaySearchTestPreview   = `{"type":"web_search_preview","search_context_size":"high"}`
	gatewaySearchTestDated     = `{"type":"web_search_20260318","max_uses":8}`
)

// Responses: web_search, web_search_preview and a dated web_search_20260318 dropped; a tool_choice naming one auto;
// include's web_search_call. entries gone; a function named web_search, URnetwork's MCP tool (mcp__ur__web_search) and
// a hosted MCP server labeled web_search kept byte for byte, being matched by type, never by name.
func TestGatewayHostedSearchDropsResponsesTools(t *testing.T) {
	hostedSearch, _ := newGatewaySearchTest(nil)
	body := []byte(`{
  "model": "chutes-example-model-tee-high",
  "instructions": "synthetic",
  "input": [{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}],
  "tools": [
    ` + gatewaySearchTestShell + `,
    ` + gatewaySearchTestHosted + `,
    ` + gatewaySearchTestPreview + `,
    ` + gatewaySearchTestDated + `,
    ` + gatewaySearchTestFunction + `,
    ` + gatewaySearchTestMcpTool + `,
    ` + gatewaySearchTestMcpServer + `
  ],
  "tool_choice": {"type":"web_search_preview"},
  "include": ["reasoning.encrypted_content", "web_search_call.action.sources", "web_search_call.results"],
  "store": false,
  "stream": true
}
`)
	want := `{"model": "chutes-example-model-tee-high",` +
		`"instructions": "synthetic",` +
		`"input": [{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}],` +
		`"tools": [` + gatewaySearchTestShell + `,` + gatewaySearchTestFunction + `,` + gatewaySearchTestMcpTool + `,` + gatewaySearchTestMcpServer + `],` +
		`"tool_choice": "auto",` +
		`"include": ["reasoning.encrypted_content"],` +
		`"store": false,` +
		`"stream": true}`
	got, err := hostedSearch.FilterResponses("codex", body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("filtered\n%s\nwant\n%s", got, want)
	}
	for _, kept := range []string{gatewaySearchTestShell, gatewaySearchTestFunction, gatewaySearchTestMcpTool, gatewaySearchTestMcpServer} {
		if !bytes.Contains(got, []byte(kept)) {
			t.Errorf("a kept tool lost its bytes: %s", kept)
		}
	}
	assertGatewaySearchNoneLeft(t, sidecar.GatewayHostedSearchApiResponses, got)

	recent := hostedSearch.Notice().Snapshot().Recent
	if len(recent) != 1 {
		t.Fatalf("%d notice entries, want 1", len(recent))
	}
	wantItems := []string{
		"web_search", "web_search_preview", "web_search_20260318", "tool_choice web_search_preview",
		"include web_search_call.action.sources", "include web_search_call.results",
	}
	entry := recent[0]
	if entry.Harness != "codex" || entry.Api != sidecar.GatewayHostedSearchApiResponses || entry.Answered ||
		entry.ItemCount != len(wantItems) || !reflect.DeepEqual(entry.Items, wantItems) {
		t.Errorf("notice entry %+v, want codex's responses items %v", entry, wantItems)
	}
}

// Chat Completions: web_search_options dropped, since only OpenAI's search models read it and the catalog holds none;
// a function named web_search kept. A web_search_options of null is left out too, and counts as no refusal.
func TestGatewayHostedSearchDropsChatSearchOptions(t *testing.T) {
	hostedSearch, _ := newGatewaySearchTest(nil)
	function := `{"type":"function","function":{"name":"web_search","description":"the harness's own","parameters":{"type":"object"}}}`
	body := []byte(`{"model":"local-example-model-off","messages":[{"role":"user","content":"hi"}],` +
		`"web_search_options":{"search_context_size":"low","user_location":{"type":"approximate","approximate":{"city":"Example"}}},` +
		`"tools":[` + function + `],"stream":false}`)
	want := `{"model":"local-example-model-off","messages":[{"role":"user","content":"hi"}],"tools":[` + function + `],"stream":false}`
	got, err := hostedSearch.FilterChatCompletions("opencode", body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("filtered\n%s\nwant\n%s", got, want)
	}
	assertGatewaySearchNoneLeft(t, sidecar.GatewayHostedSearchApiChatCompletions, got)
	recent := hostedSearch.Notice().Snapshot().Recent
	if len(recent) != 1 || recent[0].Api != sidecar.GatewayHostedSearchApiChatCompletions ||
		!reflect.DeepEqual(recent[0].Items, []string{"web_search_options"}) {
		t.Errorf("notice %+v, want one chat_completions entry naming web_search_options", recent)
	}

	nullOptions := []byte(`{"model":"local-example-model-off","messages":[],"web_search_options":null}`)
	got, err = hostedSearch.FilterChatCompletions("opencode", nullOptions)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"model":"local-example-model-off","messages":[]}` {
		t.Errorf("a null web_search_options stayed: %s", got)
	}
	if count := len(hostedSearch.Notice().Snapshot().Recent); count != 1 {
		t.Errorf("a null web_search_options counted as a refusal: %d entries", count)
	}
}

// Claude Code's WebSearch side request (2.1.330): one web_search_20250305 server tool, forced by tool_choice, thinking
// off, streaming.
func gatewaySearchTestSideRequest(stream bool) []byte {
	streamText := "false"
	if stream {
		streamText = "true"
	}
	return []byte(`{"model":"local-example-model-off","max_tokens":32000,` +
		`"system":[{"type":"text","text":"You run a web search for another Claude model, which is waiting on the result and can search again. Search once, then reply with a brief summary of the results."}],` +
		`"messages":[{"role":"user","content":"Perform a web search for the query: synthetic query words"}],` +
		`"tools":[{"type":"web_search_20250305","name":"web_search","max_uses":8}],` +
		`"tool_choice":{"type":"tool","name":"web_search"},"thinking":{"type":"disabled"},"stream":` + streamText + `}`)
}

// The answer's goldens, with the counter's ids: the message id drawn first, the server_tool_use's second.
const (
	gatewaySearchTestMessageId = "msg_010123456789ABCDEFGHIJKL"
	gatewaySearchTestToolUseId = "srvtoolu_01MNOPQRSTUVWXYZabcdefgh"
	gatewaySearchTestUsage     = `{"input_tokens":0,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":0,"server_tool_use":{"web_search_requests":0}}`
	gatewaySearchTestToolUse   = `{"type":"server_tool_use","id":"` + gatewaySearchTestToolUseId + `","name":"web_search","input":{}}`
	gatewaySearchTestResult    = `{"type":"web_search_tool_result","tool_use_id":"` + gatewaySearchTestToolUseId + `","content":{"type":"web_search_tool_result_error","error_code":"unavailable"}}`

	gatewaySearchTestJsonGolden = `{"id":"` + gatewaySearchTestMessageId + `","type":"message","role":"assistant","model":"local-example-model-off",` +
		`"content":[` + gatewaySearchTestToolUse + `,` + gatewaySearchTestResult + `],` +
		`"stop_reason":"end_turn","stop_sequence":null,"usage":` + gatewaySearchTestUsage + `}`

	gatewaySearchTestSseGolden = "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"` + gatewaySearchTestMessageId + `","type":"message","role":"assistant","model":"local-example-model-off","content":[],"stop_reason":null,"stop_sequence":null,"usage":` + gatewaySearchTestUsage + "}}\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":` + gatewaySearchTestToolUse + "}\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":0}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":1,"content_block":` + gatewaySearchTestResult + "}\n\n" +
		"event: content_block_stop\n" +
		`data: {"type":"content_block_stop","index":1}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":` + gatewaySearchTestUsage + "}\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"
)

// The side request is answered at once, as JSON or as the API's events, against goldens of the documented shapes: a
// server_tool_use named web_search with a srvtoolu_ id, and a web_search_tool_result naming it whose content is the
// error unavailable, end_turn, the request's model and zero usage. Nothing is left to route, so no router call, hold or
// charge follows, and the stream folds back into the same message a client reads.
func TestGatewayHostedSearchAnswersMessagesUnavailable(t *testing.T) {
	for _, stream := range []bool{false, true} {
		hostedSearch, _ := newGatewaySearchTest(nil)
		answer, routeBody, err := hostedSearch.AnswerMessages("claude-code", gatewaySearchTestSideRequest(stream))
		if err != nil {
			t.Fatal(err)
		}
		// what a front does: route only a body it was given
		routerCalls := 0
		if routeBody != nil {
			routerCalls++
		}
		if answer == nil || routerCalls != 0 {
			t.Fatalf("stream %v: answer %v, %d router calls; want an answer and none", stream, answer, routerCalls)
		}
		if answer.Stream != stream {
			t.Errorf("stream %v: the answer's Stream is %v", stream, answer.Stream)
		}
		if string(answer.Json) != gatewaySearchTestJsonGolden {
			t.Errorf("stream %v: json\n%s\nwant\n%s", stream, answer.Json, gatewaySearchTestJsonGolden)
		}
		sse := ""
		for _, event := range answer.Events {
			sse += "event: " + event.Name + "\ndata: " + string(event.Data) + "\n\n"
		}
		if sse != gatewaySearchTestSseGolden {
			t.Errorf("stream %v: events\n%s\nwant\n%s", stream, sse, gatewaySearchTestSseGolden)
		}
		wantBody, wantType := gatewaySearchTestJsonGolden, "application/json"
		if stream {
			wantBody, wantType = gatewaySearchTestSseGolden, "text/event-stream"
		}
		if string(answer.Bytes()) != wantBody || answer.ContentType() != wantType {
			t.Errorf("stream %v: the HTTP body or its %s is not the golden", stream, answer.ContentType())
		}

		// the message, read as a client reads it
		message := map[string]any{}
		if err := json.Unmarshal(answer.Json, &message); err != nil {
			t.Fatal(err)
		}
		content := message["content"].([]any)
		toolUse := content[0].(map[string]any)
		result := content[1].(map[string]any)
		if message["type"] != "message" || message["role"] != "assistant" || message["model"] != "local-example-model-off" ||
			message["stop_reason"] != "end_turn" || len(content) != 2 {
			t.Errorf("stream %v: the message is not an end_turn assistant message of two blocks: %v", stream, message)
		}
		if toolUse["type"] != "server_tool_use" || toolUse["name"] != "web_search" ||
			!regexp.MustCompile(`^srvtoolu_01[0-9A-Za-z]{22}$`).MatchString(toolUse["id"].(string)) {
			t.Errorf("stream %v: the first block is not a server_tool_use named web_search: %v", stream, toolUse)
		}
		errorObject := map[string]any{"type": "web_search_tool_result_error", "error_code": "unavailable"}
		if result["type"] != "web_search_tool_result" || result["tool_use_id"] != toolUse["id"] ||
			!reflect.DeepEqual(result["content"], errorObject) {
			t.Errorf("stream %v: the second block is not the unavailable result naming the first: %v", stream, result)
		}
		usage := message["usage"].(map[string]any)
		for _, key := range []string{"input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"} {
			if usage[key] != float64(0) {
				t.Errorf("stream %v: usage %s is %v, want 0: nothing is charged", stream, key, usage[key])
			}
		}
		if usage["server_tool_use"].(map[string]any)["web_search_requests"] != float64(0) {
			t.Errorf("stream %v: a search is counted: %v", stream, usage)
		}

		// the stream folded into a message as a client folds it equals the JSON answer
		folded := map[string]any{}
		foldedContent := []any{}
		for index, event := range answer.Events {
			data := map[string]any{}
			if err := json.Unmarshal(event.Data, &data); err != nil {
				t.Fatal(err)
			}
			if data["type"] != event.Name {
				t.Errorf("stream %v: event %d is %s with data of type %v", stream, index, event.Name, data["type"])
			}
			switch event.Name {
			case "message_start":
				folded = data["message"].(map[string]any)
			case "content_block_start":
				if int(data["index"].(float64)) != len(foldedContent) {
					t.Errorf("stream %v: block %v starts out of order", stream, data["index"])
				}
				foldedContent = append(foldedContent, data["content_block"])
			case "content_block_stop":
				if int(data["index"].(float64)) != len(foldedContent)-1 {
					t.Errorf("stream %v: block %v stops out of order", stream, data["index"])
				}
			case "message_delta":
				delta := data["delta"].(map[string]any)
				folded["stop_reason"] = delta["stop_reason"]
				folded["stop_sequence"] = delta["stop_sequence"]
				folded["usage"] = data["usage"]
			case "message_stop":
				if index != len(answer.Events)-1 {
					t.Errorf("stream %v: message_stop is not last", stream)
				}
			default:
				t.Errorf("stream %v: an event the API does not send here: %s", stream, event.Name)
			}
		}
		folded["content"] = foldedContent
		if !reflect.DeepEqual(folded, message) {
			t.Errorf("stream %v: the stream folds to\n%v\nnot the message\n%v", stream, folded, message)
		}

		snapshot := hostedSearch.Notice().Snapshot()
		if len(snapshot.Harnesses) != 1 || snapshot.Harnesses[0].Harness != "claude-code" ||
			snapshot.Harnesses[0].Answered != 1 || snapshot.Harnesses[0].Dropped != 0 ||
			len(snapshot.Recent) != 1 || !snapshot.Recent[0].Answered ||
			!reflect.DeepEqual(snapshot.Recent[0].Items, []string{"web_search_20250305"}) {
			t.Errorf("stream %v: notice %+v, want one answered claude-code side request", stream, snapshot)
		}
	}
}

// A web_search_* server tool among other tools is dropped, never answered, and the request routed with the rest, every
// kept tool's bytes as they were; a tool_choice naming the dropped tool becomes auto, keeping its
// disable_parallel_tool_use, while one naming a kept tool or asking for any stays.
func TestGatewayHostedSearchDropsAmongOtherTools(t *testing.T) {
	hostedSearch, _ := newGatewaySearchTest(nil)
	bash := `{"name":"Bash","description":"runs a command","input_schema":{"type":"object","properties":{"command":{"type":"string"}}}}`
	mcpTool := `{"name":"mcp__ur__web_search","description":"URnetwork's MCP web_search","input_schema":{"type":"object"}}`
	custom := `{"type":"custom","name":"WebFetch","input_schema":{"type":"object"}}`
	server := `{"type":"web_search_20250305","name":"web_search","max_uses":8}`
	newer := `{"type":"web_search_20260318","name":"web_search","response_inclusion":"excluded"}`
	tools := `"tools":[` + bash + `,` + server + `,` + mcpTool + `,` + newer + `,` + custom + `]`
	keptTools := `"tools":[` + bash + `,` + mcpTool + `,` + custom + `]`
	head := `{"model":"local-example-model-off","max_tokens":1024,"messages":[{"role":"user","content":"hi"}],`

	cases := []struct {
		choice     string
		wantChoice string
	}{
		{choice: `{"type":"tool","name":"web_search","disable_parallel_tool_use":true}`, wantChoice: `{"type":"auto","disable_parallel_tool_use":true}`},
		{choice: `{"type":"tool","name":"web_search"}`, wantChoice: `{"type":"auto"}`},
		{choice: `{"type":"tool","name":"Bash"}`, wantChoice: `{"type":"tool","name":"Bash"}`},
		{choice: `{"type":"any"}`, wantChoice: `{"type":"any"}`},
	}
	for _, c := range cases {
		body := []byte(head + tools + `,"tool_choice":` + c.choice + `,"stream":true}`)
		want := head + keptTools + `,"tool_choice":` + c.wantChoice + `,"stream":true}`
		answer, got, err := hostedSearch.AnswerMessages("claude-code", body)
		if err != nil {
			t.Fatal(err)
		}
		if answer != nil {
			t.Fatalf("tool_choice %s: answered a request with other tools", c.choice)
		}
		if string(got) != want {
			t.Errorf("tool_choice %s: filtered\n%s\nwant\n%s", c.choice, got, want)
		}
		assertGatewaySearchNoneLeft(t, sidecar.GatewayHostedSearchApiMessages, got)
	}
	snapshot := hostedSearch.Notice().Snapshot()
	if len(snapshot.Harnesses) != 1 || snapshot.Harnesses[0].Dropped != uint64(len(cases)) || snapshot.Harnesses[0].Answered != 0 {
		t.Errorf("notice %+v, want %d drops and no answer", snapshot.Harnesses, len(cases))
	}
	for _, entry := range snapshot.Recent {
		if entry.Answered || !reflect.DeepEqual(entry.Items, []string{"web_search_20250305", "web_search_20260318"}) {
			t.Errorf("notice entry %+v, want both server tools dropped", entry)
		}
	}
}

// The notice counts each refusal by harness, harnesses past NoticeHarnessCount together, keeps the latest
// NoticeRingCount in its ring oldest first with at most NoticeItemCount items cut to NoticeItemByteCount bytes, reads
// times from its clock, and counts nothing for a request with no hosted search. Its warnings name each harness, its
// counts, its last time and the fix, and its snapshot travels as JSON, as a daemon method sends it.
func TestGatewayHostedSearchNoticeCounts(t *testing.T) {
	hostedSearch, clock := newGatewaySearchTest(&sidecar.GatewayHostedSearchSettings{
		NoticeRingCount:     3,
		NoticeHarnessCount:  2,
		NoticeItemCount:     2,
		NoticeItemByteCount: 12,
		IdRandomCharCount:   22,
	})
	start := clock.Now()
	at := func(minutes int) time.Time {
		return start.Add(time.Duration(minutes) * time.Minute)
	}
	responses := func(tools string, include string) []byte {
		return []byte(`{"model":"m","input":[],"tools":[` + tools + `],"include":[` + include + `]}`)
	}
	step := func(name string, call func() error) {
		t.Helper()
		if err := call(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		clock.Advance(time.Minute)
	}
	step("codex drops one", func() error {
		_, err := hostedSearch.FilterResponses("codex", responses(gatewaySearchTestHosted, ""))
		return err
	})
	step("claude-code's side request", func() error {
		_, _, err := hostedSearch.AnswerMessages("claude-code", gatewaySearchTestSideRequest(true))
		return err
	})
	step("codex drops three items", func() error {
		_, err := hostedSearch.FilterResponses("codex", responses(gatewaySearchTestPreview+`,`+gatewaySearchTestHosted, `"web_search_call.results"`))
		return err
	})
	step("a third harness", func() error {
		_, err := hostedSearch.FilterChatCompletions("opencode", []byte(`{"model":"m","messages":[],"web_search_options":{}}`))
		return err
	})
	step("codex sends none", func() error {
		_, err := hostedSearch.FilterResponses("codex", responses(gatewaySearchTestShell, `"reasoning.encrypted_content"`))
		return err
	})
	step("claude-code among other tools", func() error {
		_, _, err := hostedSearch.AnswerMessages("claude-code",
			[]byte(`{"model":"m","messages":[],"tools":[{"name":"Bash","input_schema":{}},{"type":"web_search_20250305","name":"web_search"}]}`))
		return err
	})

	snapshot := hostedSearch.Notice().Snapshot()
	wantHarnesses := []*sidecar.GatewayHostedSearchHarnessCount{
		{Harness: "claude-code", Dropped: 1, Answered: 1, Last: at(5)},
		{Harness: "codex", Dropped: 2, Answered: 0, Last: at(2)},
	}
	if !reflect.DeepEqual(snapshot.Harnesses, wantHarnesses) {
		t.Errorf("harnesses %+v, want %+v", snapshot.Harnesses, wantHarnesses)
	}
	wantOther := &sidecar.GatewayHostedSearchHarnessCount{Dropped: 1, Last: at(3)}
	if !reflect.DeepEqual(snapshot.Other, wantOther) {
		t.Errorf("other %+v, want %+v", snapshot.Other, wantOther)
	}
	wantRecent := []*sidecar.GatewayHostedSearchNoticeEntry{
		{Time: at(2), Harness: "codex", Api: sidecar.GatewayHostedSearchApiResponses, Items: []string{"web_search_p…", "web_search"}, ItemCount: 3},
		{Time: at(3), Harness: "opencode", Api: sidecar.GatewayHostedSearchApiChatCompletions, Items: []string{"web_search_o…"}, ItemCount: 1},
		{Time: at(5), Harness: "claude-code", Api: sidecar.GatewayHostedSearchApiMessages, Items: []string{"web_search_2…"}, ItemCount: 1},
	}
	if !reflect.DeepEqual(snapshot.Recent, wantRecent) {
		got, _ := json.Marshal(snapshot.Recent)
		t.Errorf("ring %s, want the latest three, oldest first, with cut items", got)
	}

	warnings := hostedSearch.Notice().Warnings()
	if len(warnings) != 3 {
		t.Fatalf("%d warnings, want one for each named harness and one for the rest: %q", len(warnings), warnings)
	}
	wantWarnings := []string{
		"claude-code sent hosted web search", "1 requests had it dropped and 1 were answered unavailable",
		"`ur install-harness claude-code --gateway`",
	}
	for _, want := range wantWarnings {
		if !strings.Contains(warnings[0], want) {
			t.Errorf("claude-code's warning lacks %q: %s", want, warnings[0])
		}
	}
	if !strings.Contains(warnings[1], "codex sent hosted web search") || !strings.Contains(warnings[1], at(2).UTC().Format(time.RFC3339)) ||
		!strings.Contains(warnings[1], "MCP's web_search") || !strings.HasPrefix(warnings[2], "other harnesses") {
		t.Errorf("warnings %q do not name codex's last time, MCP's web_search and the other harnesses", warnings)
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	decoded := &sidecar.GatewayHostedSearchNoticeSnapshot{}
	if err := json.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, snapshot) {
		t.Errorf("the snapshot does not survive JSON: %s", encoded)
	}
	if strings.Contains(string(encoded), "synthetic query words") {
		t.Errorf("the notice holds a request's text: %s", encoded)
	}
}

// A refusal whose grant names no harness counts under the empty name, and its warning gives the fix with a placeholder
// for the harness, never an empty command.
func TestGatewayHostedSearchWarnsForAnUnnamedHarness(t *testing.T) {
	hostedSearch, _ := newGatewaySearchTest(nil)
	if _, err := hostedSearch.FilterResponses("", []byte(`{"tools":[{"type":"web_search"}]}`)); err != nil {
		t.Fatal(err)
	}
	warnings := hostedSearch.Notice().Warnings()
	if len(warnings) != 1 || !strings.HasPrefix(warnings[0], "a harness with no name sent hosted web search") ||
		!strings.Contains(warnings[0], "`ur install-harness <harness> --gateway`") || strings.Contains(warnings[0], "  ") {
		t.Errorf("warnings %q, want one naming no harness with the fix's placeholder", warnings)
	}
}

// A request with no hosted search goes on as the same bytes, the same slice, and counts nothing: a function or MCP
// tool named web_search, a Messages request without tools, and a Chat Completions request.
func TestGatewayHostedSearchLeavesOtherRequestsAsTheyAre(t *testing.T) {
	hostedSearch, _ := newGatewaySearchTest(nil)
	responses := []byte(`{"model":"m","input":[],"tools":[` + gatewaySearchTestShell + `,` + gatewaySearchTestFunction + `,` +
		gatewaySearchTestMcpTool + `],"tool_choice":{"type":"function","name":"web_search"},"include":["reasoning.encrypted_content"]}`)
	got, err := hostedSearch.FilterResponses("codex", responses)
	if err != nil {
		t.Fatal(err)
	}
	if &got[0] != &responses[0] || len(got) != len(responses) {
		t.Errorf("a Responses request without hosted search was rewritten: %s", got)
	}
	chat := []byte(`{"model":"m","messages":[],"tools":[{"type":"function","function":{"name":"web_search"}}],"tool_choice":"required"}`)
	got, err = hostedSearch.FilterChatCompletions("opencode", chat)
	if err != nil {
		t.Fatal(err)
	}
	if &got[0] != &chat[0] || len(got) != len(chat) {
		t.Errorf("a Chat Completions request without hosted search was rewritten: %s", got)
	}
	for _, messages := range [][]byte{
		[]byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":true}`),
		[]byte(`{"model":"m","messages":[],"tools":[],"tool_choice":{"type":"any"}}`),
		[]byte(`{"model":"m","messages":[],"tools":null}`),
		[]byte(`{"model":"m","messages":[],"tools":[{"name":"web_search","input_schema":{}},{"type":"custom","name":"mcp__ur__web_search","input_schema":{}}]}`),
	} {
		answer, got, err := hostedSearch.AnswerMessages("claude-code", messages)
		if err != nil {
			t.Fatal(err)
		}
		if answer != nil || &got[0] != &messages[0] || len(got) != len(messages) {
			t.Errorf("a Messages request without hosted search was answered or rewritten: %s", messages)
		}
	}
	snapshot := hostedSearch.Notice().Snapshot()
	if len(snapshot.Harnesses) != 0 || snapshot.Other != nil || len(snapshot.Recent) != 0 || len(hostedSearch.Notice().Warnings()) != 0 {
		t.Errorf("requests without hosted search counted: %+v", snapshot)
	}
}

// No spelling or repetition of a key carries a hosted tool past the filter to a front's decoder: a key in another
// case or with escapes, the Unicode letters that fold to its own, a tools member twice, and a tool with a second type
// member all are filtered, each body first shown to carry hosted search to encoding/json unfiltered (but for the one a
// first-wins decoder would take). Spellings with underscores or dashes, which only encoding/json/v2's case:ignore
// matching takes, are filtered too.
func TestGatewayHostedSearchMatchesEveryKeyADecoderTakes(t *testing.T) {
	hostedSearch, _ := newGatewaySearchTest(nil)
	firstWins := `{"tools":[{"type":"web_search"}],"tools":[{"type":"function","name":"f"}]}`
	bodies := []string{
		`{"Tools":[{"type":"web_search"}]}`,
		`{"TOOLS":[{"type":"function","name":"f"},{"type":"web_search_preview"}]}`,
		`{"\u0074ools":[{"type":"web\u005fsearch"}]}`,
		// U+017F, the long s, folds to s, and encoding/json matches it so
		`{"toolſ":[{"type":"web_search"}]}`,
		`{"tools":[{"type":"function","name":"f"}],"tools":[{"type":"web_search"}]}`,
		firstWins,
		`{"tools":[{"type":"function","Type":"web_search","name":"f"}]}`,
		`{"tools":[{"TYPE":"web_search_2025_08_26"}]}`,
		`{"tools":[{"type":"function","name":"f"}],"Include":["web_search_call.results"],"include":["web_search_call.action.sources"]}`,
		`{"tools":[{"type":"function","name":"f"}],"Web_Search_Options":{},"web_search_options":{}}`,
	}
	for _, body := range bodies {
		unfiltered := &gatewaySearchTestDecoded{}
		if err := json.Unmarshal([]byte(body), unfiltered); err != nil {
			t.Fatal(err)
		}
		carries := len(unfiltered.WebSearchOptions) != 0
		for _, tool := range unfiltered.Tools {
			carries = carries || strings.HasPrefix(tool.Type, "web_search")
		}
		for _, entry := range unfiltered.Include {
			carries = carries || strings.HasPrefix(entry, "web_search_call.")
		}
		if !carries && body != firstWins {
			t.Errorf("encoding/json takes no hosted search from %s, so the case proves nothing", body)
		}
		responses, err := hostedSearch.FilterResponses("codex", []byte(body))
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		assertGatewaySearchNoneLeft(t, sidecar.GatewayHostedSearchApiResponses, responses)
		chat, err := hostedSearch.FilterChatCompletions("opencode", []byte(body))
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		assertGatewaySearchNoneLeft(t, sidecar.GatewayHostedSearchApiChatCompletions, chat)
		if bytes.Contains(responses, []byte(`{"type":"web_search`)) || bytes.Contains(chat, []byte(`{"type":"web_search`)) {
			t.Errorf("a hosted tool is left in %s or %s", responses, chat)
		}
	}
	if got, err := hostedSearch.FilterResponses("codex", []byte(firstWins)); err != nil || string(got) != `{"tools":[],"tools":[{"type":"function","name":"f"}]}` {
		t.Errorf("both tools members are not filtered: %s, %v", got, err)
	}

	// spellings only encoding/json/v2's case:ignore takes
	for _, body := range []string{
		`{"too_ls":[{"type":"web_search"}]}`,
		`{"Tool-S":[{"type":"web_search_preview"}],"include":["reasoning.encrypted_content"],"In_Clude":["web_search_call.results"]}`,
		`{"tools":[{"ty_pe":"web_search","name":"f"}]}`,
	} {
		got, err := hostedSearch.FilterResponses("codex", []byte(body))
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if bytes.Contains(got, []byte("web_search")) {
			t.Errorf("%s keeps hosted search: %s", body, got)
		}
	}
	got, err := hostedSearch.FilterChatCompletions("opencode", []byte(`{"messages":[],"websearch-options":{},"WebSearchOptions":{}}`))
	if err != nil || string(got) != `{"messages":[]}` {
		t.Errorf("web_search_options spelled for case:ignore stays: %s, %v", got, err)
	}

	// the side request keyed in another case is still answered
	answer, _, err := hostedSearch.AnswerMessages("claude-code", []byte(`{"Model":"m","TOOLS":[{"Type":"web_search_20250305","name":"web_search"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if answer == nil || !bytes.Contains(answer.Json, []byte(`"model":"m"`)) {
		t.Errorf("the side request keyed in another case was not answered: %v", answer)
	}
}

// A body the filter cannot read is refused, wrapping ErrGatewayHostedSearchMalformed, so the front answers 400 and the
// request goes nowhere: not JSON, not an object, tools or include not an array, a tool not an object, a type not a
// string, and a side request whose model or stream does not read as one value.
func TestGatewayHostedSearchRefusesMalformedBodies(t *testing.T) {
	hostedSearch, _ := newGatewaySearchTest(nil)
	shared := []string{
		`not json`,
		`{"tools":[]} trailing`,
		`[{"type":"web_search"}]`,
		`null`,
		`{"tools":{"type":"web_search"}}`,
		`{"tools":"web_search"}`,
		`{"tools":["web_search"]}`,
		`{"tools":[{"type":["web_search"]}]}`,
		`{"tools":[{"type":"function","type":7}]}`,
	}
	for _, body := range shared {
		if got, err := hostedSearch.FilterResponses("codex", []byte(body)); !errors.Is(err, sidecar.ErrGatewayHostedSearchMalformed) || got != nil {
			t.Errorf("responses %s: %v, %s; want malformed", body, err, got)
		}
		if got, err := hostedSearch.FilterChatCompletions("opencode", []byte(body)); !errors.Is(err, sidecar.ErrGatewayHostedSearchMalformed) || got != nil {
			t.Errorf("chat %s: %v, %s; want malformed", body, err, got)
		}
		if answer, got, err := hostedSearch.AnswerMessages("claude-code", []byte(body)); !errors.Is(err, sidecar.ErrGatewayHostedSearchMalformed) || got != nil || answer != nil {
			t.Errorf("messages %s: %v, %s; want malformed", body, err, got)
		}
	}
	if _, err := hostedSearch.FilterResponses("codex", []byte(`{"include":"web_search_call.results"}`)); !errors.Is(err, sidecar.ErrGatewayHostedSearchMalformed) {
		t.Errorf("an include that is not an array: %v", err)
	}
	tool := `"tools":[{"type":"web_search_20250305","name":"web_search"}]`
	for _, body := range []string{
		`{` + tool + `}`,
		`{"model":7,` + tool + `}`,
		`{"model":"m","Model":"n",` + tool + `}`,
		`{"model":"m",` + tool + `,"stream":"yes"}`,
		`{"model":"m",` + tool + `,"stream":true,"Stream":false}`,
	} {
		if answer, got, err := hostedSearch.AnswerMessages("claude-code", []byte(body)); !errors.Is(err, sidecar.ErrGatewayHostedSearchMalformed) || got != nil || answer != nil {
			t.Errorf("side request %s: %v; want malformed", body, err)
		}
	}
	if snapshot := hostedSearch.Notice().Snapshot(); len(snapshot.Recent) != 0 {
		t.Errorf("refused bodies counted: %+v", snapshot.Recent)
	}
}

// tool_choice in each API's forms: a Responses allowed_tools list loses its hosted entries, becoming auto only once
// none is left; required becomes auto once every tool went; Chat Completions' nested allowed_tools list is cut the
// same way; a function tool_choice named web_search stays, since a kept function goes by that name.
func TestGatewayHostedSearchToolChoiceForms(t *testing.T) {
	hostedSearch, _ := newGatewaySearchTest(nil)
	function := `{"type":"function","name":"f","parameters":{}}`
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "responses allowed_tools cut",
			body: `{"tools":[` + function + `,{"type":"web_search"}],"tool_choice":{"type":"allowed_tools","mode":"required","tools":[{"type":"function","name":"f"},{"type":"web_search"}]}}`,
			want: `{"tools":[` + function + `],"tool_choice":{"type":"allowed_tools","mode":"required","tools":[{"type":"function","name":"f"}]}}`,
		},
		{
			name: "responses allowed_tools emptied",
			body: `{"tools":[` + function + `,{"type":"web_search_preview"}],"tool_choice":{"type":"allowed_tools","mode":"auto","tools":[{"type":"web_search_preview"}]}}`,
			want: `{"tools":[` + function + `],"tool_choice":"auto"}`,
		},
		{
			name: "responses required with none left",
			body: `{"tools":[{"type":"web_search"}],"tool_choice":"required"}`,
			want: `{"tools":[],"tool_choice":"auto"}`,
		},
		{
			name: "responses required with a function left",
			body: `{"tools":[` + function + `,{"type":"web_search"}],"tool_choice":"required"}`,
			want: `{"tools":[` + function + `],"tool_choice":"required"}`,
		},
		{
			name: "responses function named web_search",
			body: `{"tools":[` + gatewaySearchTestFunction + `,{"type":"web_search"}],"tool_choice":{"type":"function","name":"web_search"}}`,
			want: `{"tools":[` + gatewaySearchTestFunction + `],"tool_choice":{"type":"function","name":"web_search"}}`,
		},
	}
	for _, c := range cases {
		got, err := hostedSearch.FilterResponses("codex", []byte(c.body))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if string(got) != c.want {
			t.Errorf("%s: filtered\n%s\nwant\n%s", c.name, got, c.want)
		}
		assertGatewaySearchNoneLeft(t, sidecar.GatewayHostedSearchApiResponses, got)
	}

	chatFunction := `{"type":"function","function":{"name":"f","parameters":{}}}`
	chat := `{"tools":[` + chatFunction + `,{"type":"web_search"}],"tool_choice":{"type":"allowed_tools","allowed_tools":{"mode":"auto","tools":[{"type":"function","function":{"name":"f"}},{"type":"web_search"}]}}}`
	want := `{"tools":[` + chatFunction + `],"tool_choice":{"type":"allowed_tools","allowed_tools":{"mode":"auto","tools":[{"type":"function","function":{"name":"f"}}]}}}`
	got, err := hostedSearch.FilterChatCompletions("opencode", []byte(chat))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("chat allowed_tools: filtered\n%s\nwant\n%s", got, want)
	}
}

// Ids drawn from crypto/rand's reader, the default, take the Messages API's forms and differ from answer to answer.
func TestGatewayHostedSearchIdsFromCryptoRand(t *testing.T) {
	hostedSearch := sidecar.NewGatewayHostedSearch(nil)
	ids := map[string]bool{}
	for range 2 {
		answer, _, err := hostedSearch.AnswerMessages("claude-code", gatewaySearchTestSideRequest(false))
		if err != nil {
			t.Fatal(err)
		}
		message := struct {
			Id      string `json:"id"`
			Content []struct {
				Id        string `json:"id"`
				ToolUseId string `json:"tool_use_id"`
			} `json:"content"`
		}{}
		if err := json.Unmarshal(answer.Json, &message); err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^msg_01[0-9A-Za-z]{22}$`).MatchString(message.Id) ||
			!regexp.MustCompile(`^srvtoolu_01[0-9A-Za-z]{22}$`).MatchString(message.Content[0].Id) ||
			message.Content[1].ToolUseId != message.Content[0].Id {
			t.Errorf("ids %s and %s are not the API's forms, or the result names another", message.Id, message.Content[0].Id)
		}
		ids[message.Id] = true
		ids[message.Content[0].Id] = true
	}
	if len(ids) != 4 {
		t.Errorf("ids repeat across answers: %v", ids)
	}
}

// GatewaySettings carries the refusal's settings, set from their defaults, as the plan's GW's settings carry.
func TestDefaultGatewaySettingsCarryHostedSearch(t *testing.T) {
	settings := sidecar.DefaultSidecarSettings()
	if settings.Gateway == nil || !reflect.DeepEqual(settings.Gateway.HostedSearch, sidecar.DefaultGatewayHostedSearchSettings()) {
		t.Errorf("the gateway's settings carry %+v, not the hosted search defaults", settings.Gateway)
	}
	defaults := sidecar.DefaultGatewayHostedSearchSettings()
	if defaults.NoticeRingCount <= 0 || defaults.NoticeHarnessCount <= 0 || defaults.NoticeItemCount <= 0 ||
		defaults.NoticeItemByteCount <= 0 || defaults.IdRandomCharCount != 22 {
		t.Errorf("defaults %+v", defaults)
	}
}
