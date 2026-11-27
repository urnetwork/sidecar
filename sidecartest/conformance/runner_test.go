package conformance

// CTEST-M12-03's runner held to what it must catch, against planted gateways on loopback: a conforming stream passes;
// a stream with no response.completed fails, as does a stored response answered where store true must be refused, and
// each other breach of Codex's contract; a live run on a host with no binary reads open, never passed; and the Codex
// transcripts are Codex's shape, synthetic in every value.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A transcript of one session holding requests, for a planted gateway.
func testTranscript(requests ...*TranscriptRequest) *Transcript {
	return &Transcript{
		Manifest: &TranscriptManifest{
			Harness:       HarnessCodex,
			Version:       "planted",
			Pin:           "planted",
			Role:          TranscriptRoleCurrent,
			Api:           "responses",
			Path:          "/v1/responses",
			SessionHeader: "session-id",
		},
		Sessions: []*TranscriptSession{{Id: "0d0c0de0-0000-4000-8000-000000000001", Requests: requests}},
	}
}

// A Codex-shaped request body, store as given.
func testRequestBody(store bool) json.RawMessage {
	body, _ := json.Marshal(map[string]any{
		"model":   "local-scripted-off",
		"input":   []any{map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": "hello"}}}},
		"store":   store,
		"stream":  true,
		"include": []string{"reasoning.encrypted_content"},
	})
	return body
}

// A conforming stream's events: created, a reasoning item and a message, each added and done, and completed.
func testConformingEvents() []map[string]any {
	response := func(status string) map[string]any {
		return map[string]any{"id": "resp_planted", "object": "response", "status": status}
	}
	reasoning := map[string]any{"type": "reasoning", "id": "rs_planted", "status": "completed", "summary": []any{}, "encrypted_content": "planted-blob"}
	message := map[string]any{"type": "message", "id": "msg_planted", "status": "completed", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": "hi", "annotations": []any{}}}}
	completed := response("completed")
	completed["usage"] = map[string]any{"input_tokens": 3, "output_tokens": 1, "total_tokens": 4}
	return []map[string]any{
		{"type": "response.created", "response": response("in_progress")},
		{"type": "response.in_progress", "response": response("in_progress")},
		{"type": "response.output_item.added", "output_index": 0, "item": map[string]any{"type": "reasoning", "id": "rs_planted", "status": "in_progress", "summary": []any{}}},
		{"type": "response.output_item.done", "output_index": 0, "item": reasoning},
		{"type": "response.output_item.added", "output_index": 1, "item": map[string]any{"type": "message", "id": "msg_planted", "status": "in_progress", "role": "assistant", "content": []any{}}},
		{"type": "response.output_text.delta", "item_id": "msg_planted", "output_index": 1, "content_index": 0, "delta": "hi", "logprobs": []any{}},
		{"type": "response.output_item.done", "output_index": 1, "item": message},
		{"type": "response.completed", "response": completed},
	}
}

// A planted gateway answering every request with events, each its event field its type unless field says otherwise,
// numbered by sequence_number.
func plantStream(t *testing.T, events []map[string]any, field func(index int, eventType string) string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		for index, event := range events {
			numbered := map[string]any{"sequence_number": index}
			for key, value := range event {
				numbered[key] = value
			}
			data, _ := json.Marshal(numbered)
			eventType := event["type"].(string)
			if field != nil {
				eventType = field(index, eventType)
			}
			fmt.Fprintf(writer, "event: %s\ndata: %s\n\n", eventType, data)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// A target on server, its token fixed.
func plantedTarget(server *httptest.Server) *Target {
	return &Target{
		BaseUrl: server.URL,
		Token: func(ctx context.Context, session *TranscriptSession) (string, error) {
			return "ur_gw_planted", nil
		},
	}
}

// Fails unless report failed with a failure holding want, or passed where want is empty.
func requireReport(t *testing.T, label string, report *Report, want string) {
	t.Helper()
	failures := report.Failures()
	if want == "" {
		if len(failures) != 0 {
			t.Fatalf("%s: %v", label, failures)
		}
		return
	}
	if !slices.ContainsFunc(failures, func(failure string) bool { return strings.Contains(failure, want) }) {
		t.Fatalf("%s: want a failure holding %q, got %v", label, want, failures)
	}
}

// The request a conforming answer is checked against.
func testAnswerRequest() *TranscriptRequest {
	return &TranscriptRequest{
		Name:   "turn-1",
		Body:   testRequestBody(false),
		Expect: &TranscriptExpect{Status: http.StatusOK, Output: []string{"reasoning", "message"}},
	}
}

// A conforming stream passes, and one that ends with no response.completed fails, naming the missing terminal: Codex
// fails such a stream as "stream closed before response.completed" and re-runs the turn.
func TestConformanceFailsAMissingCompletedEvent(t *testing.T) {
	ctx := context.Background()
	report, err := Run(ctx, testTranscript(testAnswerRequest()), plantedTarget(plantStream(t, testConformingEvents(), nil)))
	if err != nil {
		t.Fatal(err)
	}
	requireReport(t, "a conforming stream", report, "")
	events := testConformingEvents()
	report, err = Run(ctx, testTranscript(testAnswerRequest()), plantedTarget(plantStream(t, events[:len(events)-1], nil)))
	if err != nil {
		t.Fatal(err)
	}
	requireReport(t, "a stream with no completed event", report, "no terminal event")
}

// store true must be refused 400 unsupported_parameter naming store, before any model: a planted gateway that answers
// it as a stored response fails, and one that refuses it as Codex reads a refusal passes.
func TestConformanceFailsAStoredResponse(t *testing.T) {
	ctx := context.Background()
	stored := &TranscriptRequest{
		Name:   "stored",
		Body:   testRequestBody(true),
		Expect: &TranscriptExpect{Status: http.StatusBadRequest, ErrorCode: "unsupported_parameter", ErrorParam: "store"},
	}
	report, err := Run(ctx, testTranscript(stored), plantedTarget(plantStream(t, testConformingEvents(), nil)))
	if err != nil {
		t.Fatal(err)
	}
	requireReport(t, "a stored response answered", report, "answered 200, want 400")
	refusing := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte(`{"error":{"message":"store is not supported","type":"invalid_request_error","param":"store","code":"unsupported_parameter"}}`))
	}))
	t.Cleanup(refusing.Close)
	report, err = Run(ctx, testTranscript(stored), plantedTarget(refusing))
	if err != nil {
		t.Fatal(err)
	}
	requireReport(t, "store true refused", report, "")
	wrongParam := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadRequest)
		writer.Write([]byte(`{"error":{"message":"no","type":"invalid_request_error","param":"input","code":"unsupported_parameter"}}`))
	}))
	t.Cleanup(wrongParam.Close)
	report, err = Run(ctx, testTranscript(stored), plantedTarget(wrongParam))
	if err != nil {
		t.Fatal(err)
	}
	requireReport(t, "a refusal naming another param", report, `naming param "input"`)
}

// Each other breach of Codex's contract a gateway could make is a failure naming it.
func TestConformanceFailsEachBreachOfCodexsContract(t *testing.T) {
	ctx := context.Background()
	mutate := func(change func(events []map[string]any) []map[string]any) []map[string]any {
		return change(testConformingEvents())
	}
	cases := []struct {
		label  string
		events []map[string]any
		field  func(index int, eventType string) string
		want   string
	}{
		{label: "an event field that is not its type", events: testConformingEvents(), field: func(index int, eventType string) string {
			if index == 5 {
				return "message"
			}
			return eventType
		}, want: "is not its type"},
		{label: "usage that is not an integer", events: mutate(func(events []map[string]any) []map[string]any {
			events[len(events)-1]["response"].(map[string]any)["usage"].(map[string]any)["output_tokens"] = 1.5
			return events
		}), want: "usage.output_tokens"},
		{label: "no usage", events: mutate(func(events []map[string]any) []map[string]any {
			delete(events[len(events)-1]["response"].(map[string]any), "usage")
			return events
		}), want: "no usage"},
		{label: "an item done before it was added", events: mutate(func(events []map[string]any) []map[string]any {
			return append(events[:2], events[3:]...)
		}), want: "done before it was added"},
		{label: "reasoning with no encrypted_content", events: mutate(func(events []map[string]any) []map[string]any {
			delete(events[3]["item"].(map[string]any), "encrypted_content")
			return events
		}), want: "no encrypted_content"},
		{label: "an event after the terminal", events: mutate(func(events []map[string]any) []map[string]any {
			return append(events, events[1])
		}), want: "follow the terminal"},
		{label: "a completed id that is not the created one", events: mutate(func(events []map[string]any) []map[string]any {
			events[len(events)-1]["response"].(map[string]any)["id"] = "resp_another"
			return events
		}), want: "not the created one"},
		{label: "a stream that does not start with response.created", events: mutate(func(events []map[string]any) []map[string]any {
			return events[1:]
		}), want: "not response.created"},
	}
	for _, c := range cases {
		report, err := Run(ctx, testTranscript(testAnswerRequest()), plantedTarget(plantStream(t, c.events, c.field)))
		if err != nil {
			t.Fatal(err)
		}
		requireReport(t, c.label, report, c.want)
	}

	// a function call whose arguments are no JSON text, and a quota failure in a code Codex retries
	call := testAnswerRequest()
	call.Expect = &TranscriptExpect{Status: http.StatusOK, Output: []string{"function_call"}, FunctionCalls: []*TranscriptToolCall{{Id: "call_planted", Name: "shell"}}}
	events := testConformingEvents()
	events = append(events[:2], events[7])
	events = slices.Insert(events, 2,
		map[string]any{"type": "response.output_item.added", "output_index": 0, "item": map[string]any{"type": "function_call", "id": "fc_planted", "status": "in_progress", "call_id": "call_planted", "name": "shell", "arguments": ""}},
		map[string]any{"type": "response.output_item.done", "output_index": 0, "item": map[string]any{"type": "function_call", "id": "fc_planted", "status": "completed", "call_id": "call_planted", "name": "shell", "arguments": "{not json"}},
	)
	report, err := Run(ctx, testTranscript(call), plantedTarget(plantStream(t, events, nil)))
	if err != nil {
		t.Fatal(err)
	}
	requireReport(t, "a function call's arguments", report, "arguments as JSON text")
	quota := testAnswerRequest()
	quota.Expect = &TranscriptExpect{Status: http.StatusOK, ErrorCode: "insufficient_quota"}
	failed := testConformingEvents()[:2]
	failed = append(failed, map[string]any{"type": "response.failed", "response": map[string]any{"id": "resp_planted", "object": "response", "status": "failed", "error": map[string]any{"code": "server_error", "message": "x"}}})
	report, err = Run(ctx, testTranscript(quota), plantedTarget(plantStream(t, failed, nil)))
	if err != nil {
		t.Fatal(err)
	}
	requireReport(t, "a quota failure in a retried code", report, "a code Codex retries")
}

// A live run on a host with no harness binary reads open, never pass: with UR_CONFORMANCE_HARNESS unset, and naming a
// binary that is not there.
func TestConformanceLiveReadsOpenWithoutABinary(t *testing.T) {
	t.Setenv(ConformanceHarnessEnv, "")
	args := &LiveHarnessArgs{Harness: HarnessCodex, BaseUrl: "http://127.0.0.1:1", Token: "ur_gw_unused", Model: "local-scripted-off", Prompt: "hello", Directory: t.TempDir()}
	for _, binary := range []string{"", filepath.Join(t.TempDir(), "no-codex-here")} {
		args.Binary = binary
		result := NewLiveHarness(args).Run(context.Background())
		if result.Result != LiveResultOpen || result.Reason == "" {
			t.Fatalf("binary %q read %+v", binary, result)
		}
	}
	t.Setenv(ConformanceHarnessEnv, filepath.Join(t.TempDir(), "no-codex-either"))
	args.Binary = ""
	if result := NewLiveHarness(args).Run(context.Background()); result.Result != LiveResultOpen {
		t.Fatalf("an env naming no binary read %+v", result)
	}
}

// Every Codex transcript is Codex's shape at its pin: both pins present, the current and the previous; every request
// a stateless full history, store false and include reasoning.encrypted_content, but those that ask what the gateway
// refuses; its version in its path; every host synthetic.
func TestConformanceCodexTranscriptsAreCodexShaped(t *testing.T) {
	transcripts, err := LoadTranscripts("testdata", HarnessCodex)
	if err != nil {
		t.Fatal(err)
	}
	if TranscriptOfRole(transcripts, TranscriptRoleCurrent) == nil || TranscriptOfRole(transcripts, TranscriptRolePrevious) == nil || len(transcripts) != 2 {
		t.Fatalf("%d Codex transcripts, want the current and the previous pins", len(transcripts))
	}
	for _, transcript := range transcripts {
		if transcript.Manifest.Pin != "rust-v"+transcript.Manifest.Version || transcript.Manifest.SessionHeader != "session-id" || transcript.Manifest.Path != "/v1/responses" {
			t.Errorf("%s's manifest: %+v", transcript.Directory, transcript.Manifest)
		}
		for _, session := range transcript.Sessions {
			for _, request := range session.Requests {
				body := map[string]any{}
				if err := json.Unmarshal(request.Body, &body); err != nil {
					t.Fatal(err)
				}
				refusal := request.Expect.Status != http.StatusOK
				store, _ := body["store"].(bool)
				include, _ := body["include"].([]any)
				if !refusal && (store || body["stream"] != true || !slices.Contains(include, any("reasoning.encrypted_content")) || body["previous_response_id"] != nil) {
					t.Errorf("%s/%s is not a stateless Codex request", session.Id, request.Name)
				}
				if request.Expect.Status == http.StatusOK && request.Model == nil {
					t.Errorf("%s/%s answers 200 with no model turn", session.Id, request.Name)
				}
			}
		}
	}
	// no real host or address in any file
	err = filepath.Walk(filepath.Join("testdata", HarnessCodex), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, needle := range []string{"openai.com", "chatgpt.com", "anthropic.com", "https://", "sk-", "Bearer "} {
			if strings.Contains(string(data), needle) {
				t.Errorf("%s holds %q", path, needle)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
