//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The lines of a golden file, each one JSON value.
func harnessGoldenLines(t *testing.T, path string) [][]byte {
	t.Helper()
	file, err := os.Open(filepath.FromSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	lines := [][]byte{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		if line := scanner.Bytes(); 0 < len(line) {
			lines = append(lines, bytes.Clone(line))
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

// An event's JSON, failing the test where it does not marshal.
func harnessEventJson(t *testing.T, event *HarnessEvent) string {
	t.Helper()
	encoded, err := event.Json()
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// The assistant message of PiG's TestRPCEventBytesMatchPi, built through the Harness's constructors.
func harnessGoldenAssistant() *HarnessPiMessage {
	return NewHarnessPiAssistantMessage(&HarnessPiAssistant{
		Content:     []*HarnessPiBlock{NewHarnessPiTextBlock("ok")},
		Api:         "openai-completions",
		Provider:    "custom",
		Model:       "custom-model",
		Usage:       &HarnessPiUsage{},
		StopReason:  HarnessPiStopStop,
		TimestampMs: 1,
	})
}

// Every Pi 1.5.0 golden reads and writes back byte for byte, and the Harness's constructors build each one byte for
// byte from its values.
func TestHarnessEventGoldensMatchPi150(t *testing.T) {
	lines := harnessGoldenLines(t, "testdata/harness/pi-1.5.0/events.jsonl")
	userMessage := NewHarnessPiUserMessage("Review this repository", nil, 1733234401000)
	built := []*HarnessEvent{
		NewHarnessAgentStartEvent(),
		NewHarnessTurnStartEvent(),
		NewHarnessMessageStartEvent(userMessage),
		NewHarnessMessageEndEvent(userMessage),
		NewHarnessMessageStartEvent(harnessGoldenAssistant()),
		NewHarnessMessageUpdateEvent(&HarnessPiUsage{}, &HarnessAssistantMessageEvent{
			Type: HarnessAssistantEventTextDelta, ContentIndex: 0, Delta: "ok"}),
		NewHarnessMessageUpdateEvent(&HarnessPiUsage{Input: 100, Output: 1, TotalTokens: 101}, &HarnessAssistantMessageEvent{
			Type: HarnessAssistantEventTextDelta, ContentIndex: 0, Delta: "Hello "}),
		NewHarnessMessageEndEvent(harnessGoldenAssistant()),
		NewHarnessTurnEndEvent(harnessGoldenAssistant(), nil),
		NewHarnessAgentEndEvent([]*HarnessPiMessage{harnessGoldenAssistant()}, false),
		NewHarnessAgentSettledEvent(false, ""),
		NewHarnessToolExecutionStartEvent("call_abc123", "bash", json.RawMessage(`{"command":"ls -la"}`)),
		NewHarnessToolExecutionUpdateEvent("call_abc123", "bash", json.RawMessage(`{"command":"ls -la"}`),
			&HarnessToolResultPayload{Content: []*HarnessPiBlock{NewHarnessPiTextBlock("partial output")}, Details: json.RawMessage(`{}`)}),
		NewHarnessToolExecutionEndEvent("call_abc123", "bash",
			&HarnessToolResultPayload{Content: []*HarnessPiBlock{NewHarnessPiTextBlock("complete output")}, Details: json.RawMessage(`{}`)},
			false, nil),
		NewHarnessToolExecutionEndEvent("c1", "bash", &HarnessToolResultPayload{Details: json.RawMessage(`{}`)}, false,
			func() *int64 { d := int64(4200); return &d }()),
		NewHarnessQueueUpdateEvent([]string{"What is 20+22?"}, nil),
		NewHarnessCompactionStartEvent(HarnessCompactionThreshold),
		NewHarnessCompactionEndEvent(HarnessCompactionThreshold, &HarnessCompactionResult{
			Summary: "Summary of conversation...", FirstKeptEntryId: "abc123", TokensBefore: 150000, EstimatedTokensAfter: 32000,
		}, false, false, ""),
		NewHarnessAutoRetryStartEvent(1, 3, 2000, "529 overloaded"),
		NewHarnessAutoRetryEndEvent(true, 2, ""),
	}
	if len(lines) != len(built) {
		t.Fatalf("%d golden lines for %d built events", len(lines), len(built))
	}
	for i, line := range lines {
		event := &HarnessEvent{}
		if err := json.Unmarshal(line, event); err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		if !harnessEventIsPi(event.Type) {
			t.Errorf("line %d: %s is not one of Pi's", i+1, event.Type)
		}
		if got := harnessEventJson(t, event); got != string(line) {
			t.Errorf("line %d read back:\n got %s\nwant %s", i+1, got, line)
		}
		if got := harnessEventJson(t, built[i]); got != string(line) {
			t.Errorf("line %d built:\n got %s\nwant %s", i+1, got, line)
		}
	}
}

// Every Pi type of the union has a golden line.
func TestHarnessEventGoldensCoverPiUnion(t *testing.T) {
	covered := map[HarnessEventType]bool{}
	for _, line := range harnessGoldenLines(t, "testdata/harness/pi-1.5.0/events.jsonl") {
		event := &HarnessEvent{}
		if err := json.Unmarshal(line, event); err != nil {
			t.Fatal(err)
		}
		covered[event.Type] = true
	}
	for name := range harnessEventTypes {
		if harnessEventIsPi(name) && !covered[name] {
			t.Errorf("Pi's %s has no golden line", name)
		}
	}
}

// message_update's nested events carry json.md's members in Pi's order (rpc_events.go's rpcAssistantEventFields).
func TestHarnessAssistantMessageEventsFollowPi(t *testing.T) {
	cases := []struct {
		nested *HarnessAssistantMessageEvent
		want   string
	}{
		{&HarnessAssistantMessageEvent{Type: HarnessAssistantEventTextStart, ContentIndex: 0}, `{"type":"text_start","contentIndex":0}`},
		{&HarnessAssistantMessageEvent{Type: HarnessAssistantEventTextEnd, ContentIndex: 0, Content: "Hello"}, `{"type":"text_end","contentIndex":0,"content":"Hello"}`},
		{&HarnessAssistantMessageEvent{Type: HarnessAssistantEventThinkingStart, ContentIndex: 1}, `{"type":"thinking_start","contentIndex":1}`},
		{&HarnessAssistantMessageEvent{Type: HarnessAssistantEventThinkingDelta, ContentIndex: 1, Delta: "hm"}, `{"type":"thinking_delta","contentIndex":1,"delta":"hm"}`},
		{&HarnessAssistantMessageEvent{Type: HarnessAssistantEventThinkingEnd, ContentIndex: 1, Content: "hm"}, `{"type":"thinking_end","contentIndex":1,"content":"hm"}`},
		{&HarnessAssistantMessageEvent{Type: HarnessAssistantEventToolCallStart, ContentIndex: 2, Id: "call_1", ToolName: "read"}, `{"type":"toolcall_start","contentIndex":2,"id":"call_1","toolName":"read"}`},
		{&HarnessAssistantMessageEvent{Type: HarnessAssistantEventToolCallDelta, ContentIndex: 2, Delta: `{"pa`}, `{"type":"toolcall_delta","contentIndex":2,"delta":"{\"pa"}`},
		{&HarnessAssistantMessageEvent{Type: HarnessAssistantEventToolCallEnd, ContentIndex: 2, ToolCall: &HarnessPiToolCall{Id: "call_1", Name: "read", Arguments: json.RawMessage(`{"path":"a.txt"}`)}},
			`{"type":"toolcall_end","contentIndex":2,"toolCall":{"type":"toolCall","id":"call_1","name":"read","arguments":{"path":"a.txt"}}}`},
	}
	for _, c := range cases {
		event := NewHarnessMessageUpdateEvent(nil, c.nested)
		if got := string(event.Field("assistantMessageEvent")); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.nested.Type, got, c.want)
		}
		read := event.AssistantMessageEvent()
		if read == nil || read.Type != c.nested.Type || read.ContentIndex != c.nested.ContentIndex {
			t.Errorf("%s read back as %+v", c.nested.Type, read)
		}
	}
}

// sidecar's events come after Pi's: each is registered as sidecar's, none takes a Pi name, each writes type first,
// and each matches its golden, which freezes its members' names and order.
func TestHarnessSidecarEventsFollowPiUnion(t *testing.T) {
	approvalId, _ := ParseId("019a0000-0000-7000-8000-000000000001")
	childId, _ := ParseId("019a0000-0000-7000-8000-000000000002")
	runId, _ := ParseId("019a0000-0000-7000-8000-000000000003")
	built := []*HarnessEvent{
		NewHarnessApprovalPendingEvent(&HarnessApprovalPending{ApprovalId: approvalId, Kind: "tainted_send",
			Text: "request: tainted_send", Evidence: []string{"device", "presence"}, Tainted: true}),
		NewHarnessApprovalResolvedEvent(&HarnessApprovalResolved{ApprovalId: approvalId, State: "approved", Channels: []string{"device"}}),
		NewHarnessApprovalResolvedEvent(&HarnessApprovalResolved{ApprovalId: approvalId, State: "approved", Channels: []string{"auto"},
			Auto: &HarnessAutoVerdict{Reason: "nothing_injected", Score: 0.02}}),
		NewHarnessAttestationEvent("prov-model-high", ComputeLabel("A1"), &protocol.AttestationResult{}),
		NewHarnessAttestationEvent("prov-model-high", ComputeLabel("none"), nil),
		NewHarnessUsageEvent(&HarnessUsage{Model: "prov-model-high", InputTokens: 10, OutputTokens: 5, ChargeNanoUsd: 1200, RunNanoUsd: 3400}),
		NewHarnessAgentSpawnedEvent(&HarnessAgentLink{ChildId: childId, Name: "reviewer", Model: "local-gemma-4-e2b-off", Where: "local", RunId: runId}),
		NewHarnessAgentExitedEvent(&HarnessAgentLink{ChildId: childId, Name: "reviewer", Model: "local-gemma-4-e2b-off", Where: "local", RunId: runId}, HarnessStopEnded),
		NewHarnessAttachStatusEvent(HarnessAttachAttached, "ur", HarnessAttachModeManage),
		NewHarnessUiRequestEvent(&HarnessUiRequest{Id: "ui-1", Method: HarnessUiSelect, Title: "The model failed", Options: []string{"retry", "local"}}),
		NewHarnessUiRequestEvent(&HarnessUiRequest{Id: "ui-2", Method: HarnessUiDisclosure, DisclosureId: "inference:none", DisclosureVersion: 2}),
		NewHarnessUiResponseEvent(&HarnessUiResponse{Id: "ui-1", Value: func() *string { v := "retry"; return &v }()}),
		NewHarnessUiResponseEvent(&HarnessUiResponse{Id: "ui-2", Acknowledged: true}),
	}
	lines := harnessGoldenLines(t, "testdata/harness/events/sidecar.jsonl")
	if len(lines) != len(built) {
		t.Fatalf("%d golden lines for %d built events", len(lines), len(built))
	}
	for i, event := range built {
		registration, registered := harnessEventTypes[event.Type]
		if !registered || registration.origin != harnessEventOriginSidecar {
			t.Errorf("%s is not registered as sidecar's", event.Type)
		}
		got := harnessEventJson(t, event)
		if !strings.HasPrefix(got, `{"type":"`+string(event.Type)+`"`) {
			t.Errorf("%s does not write its type first: %s", event.Type, got)
		}
		if got != string(lines[i]) {
			t.Errorf("line %d:\n got %s\nwant %s", i+1, got, lines[i])
		}
	}
	// the envelope follows the type, ahead of the members
	event := NewHarnessUsageEvent(&HarnessUsage{Model: "m"})
	event.Agent = runId.String()
	event.Seq = 7
	event.Enclave = "build-box"
	if got := harnessEventJson(t, event); !strings.HasPrefix(got, `{"type":"usage","agent":"`+runId.String()+`","seq":7,"enclave":"build-box","model":"m"`) {
		t.Errorf("envelope: %s", got)
	}
}

// A type no file registered is refused at emit, and a second registration of a name panics.
func TestHarnessUnregisteredEventTypeRefused(t *testing.T) {
	stamper := newHarnessEventStamper()
	agentId := NewId()
	event := NewHarnessEvent("mystery_card")
	event.SetField("text", "hello")
	if err := stamper.stamp(agentId, event); !errors.Is(err, ErrHarnessEventUnregistered) {
		t.Fatalf("an unregistered type stamped: %v", err)
	}
	if event.Seq != 0 || event.Agent != "" {
		t.Fatalf("a refused event was stamped: %+v", event)
	}
	if err := stamper.stamp(agentId, NewHarnessAgentStartEvent()); err != nil {
		t.Fatal(err)
	}
	second := NewHarnessTurnStartEvent()
	if err := stamper.stamp(agentId, second); err != nil || second.Seq != 2 || second.Agent != agentId.String() {
		t.Fatalf("seq %d agent %q: %v", second.Seq, second.Agent, err)
	}

	panicked := func(register func()) (panicked bool) {
		defer func() {
			panicked = recover() != nil
		}()
		register()
		return false
	}
	render := func(event *HarnessEvent) ([]string, error) { return []string{"card"}, nil }
	if !panicked(func() { RegisterHarnessEventType(HarnessEventAgentStart, render) }) {
		t.Fatal("re-registering Pi's agent_start did not panic")
	}
	if !panicked(func() { RegisterHarnessEventType("harness_test_card", nil) }) {
		t.Fatal("a card without a terminal rendering did not panic")
	}
	RegisterHarnessEventType("harness_test_card", render)
	defer delete(harnessEventTypes, "harness_test_card")
	if !panicked(func() { RegisterHarnessEventType("harness_test_card", render) }) {
		t.Fatal("a second registration of a card did not panic")
	}
	card := NewHarnessEvent("harness_test_card")
	if err := stamper.stamp(agentId, card); err != nil {
		t.Fatalf("a registered card was refused: %v", err)
	}
	if HarnessEventTerminalRendering("harness_test_card") == nil {
		t.Fatal("a registered card has no terminal rendering")
	}
}

// A member a remote Harness sends that this build does not know is kept, in its place, and passed on, nested ones
// included; the envelope reads back as the envelope.
func TestHarnessUnknownEventFieldKept(t *testing.T) {
	line := `{"type":"tool_execution_end","agent":"a-1","seq":42,"enclave":"box","toolCallId":"c1","futureMember":{"z":1,"a":[true,null]},"toolName":"read","result":{"content":[],"details":{"zeta":1,"alpha":2},"later":"kept"},"isError":false,"parentToolCallId":"p1"}`
	event := &HarnessEvent{}
	if err := json.Unmarshal([]byte(line), event); err != nil {
		t.Fatal(err)
	}
	if event.Agent != "a-1" || event.Seq != 42 || event.Enclave != "box" {
		t.Fatalf("envelope: %+v", event)
	}
	if got := harnessEventJson(t, event); got != line {
		t.Fatalf("passed on:\n got %s\nwant %s", got, line)
	}
	if names := strings.Join(event.FieldNames(), ","); names != "toolCallId,futureMember,toolName,result,isError,parentToolCallId" {
		t.Fatalf("members: %s", names)
	}
	// an unknown type reads too, and only the sink refuses it
	unknown := &HarnessEvent{}
	if err := json.Unmarshal([]byte(`{"type":"from_a_newer_build","x":1}`), unknown); err != nil {
		t.Fatal(err)
	}
	if got := harnessEventJson(t, unknown); got != `{"type":"from_a_newer_build","x":1}` {
		t.Fatalf("unknown type: %s", got)
	}
}

// JSON.stringify's string form: no HTML escapes, and U+2028 and U+2029 as themselves, an escaped backslash kept.
func TestHarnessEventStringsAsJsonStringify(t *testing.T) {
	event := NewHarnessQueueUpdateEvent([]string{"<b>&</b>", "a\u2028b\u2029c", `\u2028 stays`}, nil)
	want := "{\"type\":\"queue_update\",\"steering\":[\"<b>&</b>\",\"a\u2028b\u2029c\",\"\\\\u2028 stays\"],\"followUp\":[]}"
	if got := harnessEventJson(t, event); got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
	read := &HarnessEvent{}
	if err := json.Unmarshal([]byte(want), read); err != nil {
		t.Fatal(err)
	}
	if got := harnessEventJson(t, read); got != want {
		t.Fatalf("read back:\n got %s\nwant %s", got, want)
	}
}

// message_end carries the whole message: the text every delta built, its thinking and its tool calls, whatever a view
// dropped of the updates.
func TestHarnessMessageEndCarriesWholeMessage(t *testing.T) {
	settings := DefaultHarnessSettings()
	clock := newHarnessTestClock()
	received := []*HarnessEvent{}
	batcher := NewHarnessEventBatcher(settings, clock, func(event *HarnessEvent) {
		received = append(received, event)
	})
	agent := NewId().String()
	whole := ""
	for i := 0; i < 50; i += 1 {
		delta := string(rune('a' + i%26))
		whole += delta
		update := NewHarnessMessageUpdateEvent(nil, &HarnessAssistantMessageEvent{Type: HarnessAssistantEventTextDelta, Delta: delta})
		update.Agent = agent
		batcher.Add(update)
		clock.Advance(time.Millisecond)
	}
	message := NewHarnessPiAssistantMessage(&HarnessPiAssistant{
		Content: []*HarnessPiBlock{
			NewHarnessPiThinkingBlock("planning"),
			NewHarnessPiTextBlock(whole),
			NewHarnessPiToolCallBlock(&HarnessPiToolCall{Id: "call_1", Name: "read", Arguments: json.RawMessage(`{"path":"a.txt"}`)}),
		},
		Model:      "local-gemma-4-e2b-off",
		StopReason: HarnessPiStopToolUse,
	})
	end := NewHarnessMessageEndEvent(message)
	end.Agent = agent
	batcher.Add(end)

	last := received[len(received)-1]
	if last.Type != HarnessEventMessageEnd {
		t.Fatalf("the last event is %s", last.Type)
	}
	updateCount := 0
	for _, event := range received[:len(received)-1] {
		if event.Type == HarnessEventMessageUpdate {
			updateCount += 1
		}
	}
	if 50 <= updateCount {
		t.Fatalf("%d updates passed for 50 deltas in 50 ms", updateCount)
	}
	carried := last.Message()
	if carried == nil || carried.Text() != whole || carried.StopReason() != HarnessPiStopToolUse {
		t.Fatalf("message_end carried %+v", carried)
	}
	blocks := carried.Blocks()
	if len(blocks) != 3 || blocks[0].Type() != HarnessPiBlockThinking || blocks[0].Text() != "planning" {
		t.Fatalf("blocks: %d", len(blocks))
	}
	toolCalls := carried.ToolCalls()
	if len(toolCalls) != 1 || toolCalls[0].Name != "read" || string(toolCalls[0].Arguments) != `{"path":"a.txt"}` {
		t.Fatalf("tool calls: %+v", toolCalls)
	}
}

// The batcher passes at most EventRate updates a second for one agent on the fake clock, folding the deltas between
// them so their joined text is the stream's, and passes every other event at once, in order, after what it held.
func TestHarnessEventBatcherThirtyASecond(t *testing.T) {
	settings := DefaultHarnessSettings()
	clock := newHarnessTestClock()
	received := []*HarnessEvent{}
	batcher := NewHarnessEventBatcher(settings, clock, func(event *HarnessEvent) {
		received = append(received, event)
	})
	agent := NewId().String()
	other := NewId().String()
	text := ""
	otherText := ""
	// 1,000 deltas over one second for each of two agents
	for i := 0; i < 1000; i += 1 {
		delta := string(rune('a' + i%26))
		text += delta
		update := NewHarnessMessageUpdateEvent(nil, &HarnessAssistantMessageEvent{Type: HarnessAssistantEventTextDelta, Delta: delta})
		update.Agent = agent
		update.Seq = uint64(i + 1)
		batcher.Add(update)
		otherDelta := string(rune('A' + i%26))
		otherText += otherDelta
		otherUpdate := NewHarnessMessageUpdateEvent(nil, &HarnessAssistantMessageEvent{Type: HarnessAssistantEventTextDelta, Delta: otherDelta})
		otherUpdate.Agent = other
		batcher.Add(otherUpdate)
		clock.Advance(time.Millisecond)
	}
	end := NewHarnessMessageEndEvent(NewHarnessPiAssistantMessage(&HarnessPiAssistant{Content: []*HarnessPiBlock{NewHarnessPiTextBlock(text)}}))
	end.Agent = agent
	batcher.Add(end)
	batcher.Flush()

	agentTexts := map[string]string{}
	agentUpdateCounts := map[string]int{}
	endAt := -1
	for i, event := range received {
		if nested, isDelta := harnessEventIsDelta(event); isDelta {
			agentTexts[event.Agent] += nested.Delta
			agentUpdateCounts[event.Agent] += 1
			if event.Agent == agent && 0 <= endAt {
				t.Fatalf("a delta of the agent passed after its message_end")
			}
		}
		if event.Type == HarnessEventMessageEnd {
			endAt = i
		}
	}
	// one second at 30 a second: the first at once, then one an interval, and the last flushed
	for _, key := range []string{agent, other} {
		if count := agentUpdateCounts[key]; 32 < count || count < 25 {
			t.Errorf("agent %s: %d updates in one second", key, count)
		}
	}
	if agentTexts[agent] != text || agentTexts[other] != otherText {
		t.Fatalf("folded deltas lost text: %d of %d, %d of %d", len(agentTexts[agent]), len(text), len(agentTexts[other]), len(otherText))
	}
	if endAt < 0 {
		t.Fatal("message_end did not pass")
	}

	// deltas of different blocks fold only with their own kind and index
	received = nil
	clock.Advance(time.Second)
	first := NewHarnessMessageUpdateEvent(nil, &HarnessAssistantMessageEvent{Type: HarnessAssistantEventThinkingDelta, ContentIndex: 0, Delta: "a"})
	first.Agent = agent
	batcher.Add(first)
	for _, nested := range []*HarnessAssistantMessageEvent{
		{Type: HarnessAssistantEventThinkingDelta, ContentIndex: 0, Delta: "b"},
		{Type: HarnessAssistantEventTextDelta, ContentIndex: 1, Delta: "c"},
		{Type: HarnessAssistantEventTextDelta, ContentIndex: 1, Delta: "d"},
	} {
		update := NewHarnessMessageUpdateEvent(nil, nested)
		update.Agent = agent
		batcher.Add(update)
	}
	clock.Advance(time.Second)
	got := []string{}
	for _, event := range received {
		nested := event.AssistantMessageEvent()
		got = append(got, nested.Type+":"+nested.Delta)
	}
	if strings.Join(got, ",") != "thinking_delta:a,thinking_delta:b,text_delta:cd" {
		t.Fatalf("folded: %v", got)
	}
}
