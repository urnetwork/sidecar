// Codex's profile (DESIGN-COMPUTE §8.3's Codex row, from gateway_harness_compat.md's reading of openai/codex at
// 5f645d73 and hosted_search_in_harnesses.md's of rust-v0.171.0): what Codex needs of each answer to a Responses
// request, which Codex sends as stateless full histories, store false, include reasoning.encrypted_content, carrying
// item ids the gateway never issued:
//
//	refusal    a non-200 answers OpenAI's {"error": {"message", "type", "param", "code"}}, its code the expectation's:
//	           store true and previous_response_id 400 unsupported_parameter (Q-CTXH-9); an empty balance
//	           insufficient_quota, a code Codex does not retry
//	stream     Content-Type text/event-stream; each event's event field its data's type (Open Responses); a
//	           strictly rising sequence_number where one is given; response.created first, carrying the response's
//	           id; each item's output_item.added before its output_item.done, which carries the whole item, since
//	           Codex takes complete items from there (a message's output_text parts, a function_call's call_id, name
//	           and arguments as JSON text, a reasoning item's summary and, where include asks, its encrypted_content);
//	           each text delta naming its item; exactly one terminal, last: response.completed with the created id and
//	           integer usage.input_tokens, output_tokens and total_tokens (Codex fails a ResponseCompleted it cannot
//	           parse), or response.failed whose error.code Codex reads, the expectation's where it names one
//	answer     a 200 to stream false answers the Response object whole, held to the same item and usage rules
//
// The model's words are never compared: the items' types and order, the function calls' names and call ids are.

package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// Codex's harness name, as ur install-harness and the transcripts' path name it.
const HarnessCodex = "codex"

// The terminal events of a Responses stream.
var responsesTerminalEvents = []string{"response.completed", "response.failed", "response.incomplete"}

// The codes Codex does not retry, a quota's among them (codex-api's error.rs at 5f645d73).
var codexNotRetriedCodes = []string{"insufficient_quota", "credit_balance_exhausted", "usage_not_included", "invalid_prompt", "context_length_exceeded"}

func init() {
	registerHarnessProfile(HarnessCodex, &codexProfile{})
}

// See the file header.
type codexProfile struct{}

// A JSON object decoded with its numbers kept exact, nil where data is no object.
func decodeObject(data []byte) map[string]any {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	object := map[string]any{}
	if err := decoder.Decode(&object); err != nil {
		return nil
	}
	return object
}

// Whether value is a JSON integer of zero or more.
func isCount(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	count, err := number.Int64()
	return err == nil && 0 <= count && !strings.ContainsAny(number.String(), ".eE")
}

// The string at object's key, "" for none.
func stringOf(object map[string]any, key string) string {
	value, _ := object[key].(string)
	return value
}

// The object at object's key, nil for none.
func objectOf(object map[string]any, key string) map[string]any {
	value, _ := object[key].(map[string]any)
	return value
}

// Whether the sent body's include asks for reasoning's encrypted_content.
func asksEncryptedReasoning(sent map[string]any) bool {
	include, _ := sent["include"].([]any)
	return slices.Contains(include, any("reasoning.encrypted_content"))
}

// See HarnessProfile and the file header.
func (self *codexProfile) Check(request *TranscriptRequest, sent []byte, answer *Answer) *Checked {
	checked := &Checked{}
	fail := func(format string, a ...any) {
		checked.Failures = append(checked.Failures, fmt.Sprintf(format, a...))
	}
	expect := request.Expect
	sentBody := decodeObject(sent)
	if sentBody == nil {
		fail("the request's body is no JSON object")
		return checked
	}
	if answer.Status != expect.Status {
		fail("answered %d, want %d: %s", answer.Status, expect.Status, firstBytes(answer.Body))
		return checked
	}
	if expect.Status != http.StatusOK {
		apiError := readOpenAiError(answer.Body)
		switch {
		case apiError == nil:
			fail("a refusal with no error in OpenAI's shape: %s", firstBytes(answer.Body))
		case apiError.Code != expect.ErrorCode:
			fail("refused with code %q, want %q", apiError.Code, expect.ErrorCode)
		case expect.ErrorParam != "" && apiError.Param != expect.ErrorParam:
			fail("refused naming param %q, want %q", apiError.Param, expect.ErrorParam)
		case apiError.Message == "" || apiError.Type == "":
			fail("a refusal with no message or type")
		}
		return checked
	}
	stream, _ := sentBody["stream"].(bool)
	if !stream {
		response := decodeObject(answer.Body)
		if response == nil || stringOf(response, "object") != "response" {
			fail("a whole answer that is no Response object: %s", firstBytes(answer.Body))
			return checked
		}
		checked.ResponseId = stringOf(response, "id")
		items, _ := response["output"].([]any)
		self.checkItems(checked, fail, sentBody, items, expect)
		self.checkUsage(fail, objectOf(response, "usage"))
		return checked
	}
	if !strings.HasPrefix(answer.Header.Get("Content-Type"), "text/event-stream") {
		fail("a stream answered as %q", answer.Header.Get("Content-Type"))
		return checked
	}
	self.checkStream(checked, fail, sentBody, answer, expect)
	return checked
}

// A stream's rules (see the file header).
func (self *codexProfile) checkStream(checked *Checked, fail func(string, ...any), sentBody map[string]any, answer *Answer, expect *TranscriptExpect) {
	if len(answer.Events) == 0 {
		fail("a stream of no event")
		return
	}
	lastSequence := int64(-1)
	added := map[string]bool{}
	doneItems := []any{}
	terminalIndexes := []int{}
	var terminal map[string]any
	for index, event := range answer.Events {
		data := decodeObject(event.Data)
		if data == nil {
			fail("event %d's data is no JSON object: %s", index, firstBytes(event.Data))
			continue
		}
		eventType := stringOf(data, "type")
		if event.Event != eventType {
			fail("event %d's field %q is not its type %q", index, event.Event, eventType)
		}
		if sequence, ok := data["sequence_number"].(json.Number); ok {
			value, err := sequence.Int64()
			if err != nil || value <= lastSequence {
				fail("event %d's sequence_number %s does not rise", index, sequence)
			}
			lastSequence = value
		}
		if index == 0 {
			response := objectOf(data, "response")
			if eventType != "response.created" || response == nil || stringOf(response, "id") == "" {
				fail("the stream starts with %q, not response.created carrying the response's id", eventType)
			} else {
				checked.ResponseId = stringOf(response, "id")
			}
		}
		switch eventType {
		case "response.output_item.added":
			item := objectOf(data, "item")
			if item == nil || stringOf(item, "id") == "" {
				fail("event %d adds an item with no id", index)
				continue
			}
			added[stringOf(item, "id")] = true
		case "response.output_item.done":
			item := objectOf(data, "item")
			if item == nil {
				fail("event %d completes no item", index)
				continue
			}
			if !added[stringOf(item, "id")] {
				fail("item %q is done before it was added", stringOf(item, "id"))
			}
			doneItems = append(doneItems, item)
		case "response.output_text.delta":
			if stringOf(data, "item_id") == "" {
				fail("event %d is a text delta naming no item", index)
			}
			if _, ok := data["delta"].(string); !ok {
				fail("event %d is a text delta with no delta", index)
			}
		}
		if slices.Contains(responsesTerminalEvents, eventType) {
			terminalIndexes = append(terminalIndexes, index)
			terminal = data
		}
	}
	switch {
	case len(terminalIndexes) == 0:
		fail("the stream ends with no terminal event (response.completed, response.failed or response.incomplete)")
		return
	case 1 < len(terminalIndexes):
		fail("the stream holds %d terminal events", len(terminalIndexes))
	case terminalIndexes[0] != len(answer.Events)-1:
		fail("events follow the terminal event")
	}
	response := objectOf(terminal, "response")
	terminalType := stringOf(terminal, "type")
	if response == nil || stringOf(response, "id") != checked.ResponseId {
		fail("the terminal event's response is not the created one")
	}
	if expect.ErrorCode != "" {
		code := stringOf(objectOf(response, "error"), "code")
		if terminalType != "response.failed" || code != expect.ErrorCode {
			fail("ended %s with code %q, want response.failed with %q", terminalType, code, expect.ErrorCode)
		}
		if slices.Contains(codexNotRetriedCodes, expect.ErrorCode) && !slices.Contains(codexNotRetriedCodes, code) {
			fail("ended with a code Codex retries, %q, where the call must not be run again", code)
		}
		return
	}
	if terminalType != "response.completed" {
		fail("ended %s, want response.completed: %v", terminalType, objectOf(response, "error"))
		return
	}
	self.checkUsage(fail, objectOf(response, "usage"))
	self.checkItems(checked, fail, sentBody, doneItems, expect)
}

// The usage's integers Codex parses.
func (self *codexProfile) checkUsage(fail func(string, ...any), usage map[string]any) {
	if usage == nil {
		fail("the response carries no usage")
		return
	}
	for _, key := range []string{"input_tokens", "output_tokens", "total_tokens"} {
		if !isCount(usage[key]) {
			fail("usage.%s is %v, not an integer", key, usage[key])
		}
	}
}

// The completed items' rules, and the expectation's types and function calls.
func (self *codexProfile) checkItems(checked *Checked, fail func(string, ...any), sentBody map[string]any, items []any, expect *TranscriptExpect) {
	types := []string{}
	calls := []*TranscriptToolCall{}
	for index, rawItem := range items {
		item, _ := rawItem.(map[string]any)
		if item == nil {
			fail("item %d is no object", index)
			continue
		}
		itemType := stringOf(item, "type")
		types = append(types, itemType)
		if stringOf(item, "id") == "" || stringOf(item, "status") == "" {
			fail("item %d (%s) carries no id or status", index, itemType)
		}
		switch itemType {
		case "message":
			content, _ := item["content"].([]any)
			if stringOf(item, "role") != "assistant" || len(content) == 0 {
				fail("message %d is no assistant's or holds no content", index)
			}
			for _, rawPart := range content {
				part, _ := rawPart.(map[string]any)
				if stringOf(part, "type") != "output_text" {
					fail("message %d holds a %q part", index, stringOf(part, "type"))
				} else if _, ok := part["text"].(string); !ok {
					fail("message %d's output_text holds no text", index)
				}
			}
		case "function_call":
			arguments, ok := item["arguments"].(string)
			if stringOf(item, "call_id") == "" || stringOf(item, "name") == "" || !ok || !json.Valid([]byte(arguments)) {
				fail("function call %d lacks its call_id, its name or arguments as JSON text", index)
			}
			calls = append(calls, &TranscriptToolCall{Id: stringOf(item, "call_id"), Name: stringOf(item, "name"), Arguments: arguments})
		case "reasoning":
			if _, ok := item["summary"].([]any); !ok {
				fail("reasoning %d holds no summary", index)
			}
			if asksEncryptedReasoning(sentBody) {
				encrypted := stringOf(item, "encrypted_content")
				if encrypted == "" {
					fail("reasoning %d carries no encrypted_content, which include asked", index)
				} else {
					checked.Reasoning = append(checked.Reasoning, encrypted)
				}
			}
		default:
			fail("item %d is of a type Codex does not take here: %q", index, itemType)
		}
	}
	if expect.Output != nil && !slices.Equal(types, expect.Output) {
		fail("the output items are %v, want %v", types, expect.Output)
	}
	if expect.FunctionCalls != nil {
		if len(calls) != len(expect.FunctionCalls) {
			fail("%d function calls, want %d", len(calls), len(expect.FunctionCalls))
			return
		}
		for i, want := range expect.FunctionCalls {
			if calls[i].Name != want.Name || calls[i].Id != want.Id {
				fail("function call %d is %s %s, want %s %s", i, calls[i].Name, calls[i].Id, want.Name, want.Id)
			}
		}
	}
}

// At most the first 256 bytes of body, for a failure's text.
func firstBytes(body []byte) string {
	if len(body) <= 256 {
		return string(body)
	}
	return string(body[:256]) + "…"
}
