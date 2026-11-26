package computetest

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The events one Generate emitted, in order, for a test to read while the call runs.
type scriptedTestEvents struct {
	stateLock sync.Mutex
	events    []*sidecar.InferEvent
}

// Takes one event, as the router's emit does: never blocking.
func (self *scriptedTestEvents) emit(event *sidecar.InferEvent) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, event)
}

// Each event as its kind, a delta with its text or arguments after a colon.
func (self *scriptedTestEvents) trace() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	trace := []string{}
	for _, event := range self.events {
		switch event.Kind {
		case sidecar.InferEventText, sidecar.InferEventReasoning:
			trace = append(trace, string(event.Kind)+":"+event.Text)
		case sidecar.InferEventToolCallStart:
			trace = append(trace, string(event.Kind)+":"+event.ToolCall.Id+" "+event.ToolCall.Name)
		case sidecar.InferEventToolCallArgs:
			trace = append(trace, string(event.Kind)+":"+event.ToolCall.Arguments)
		case sidecar.InferEventToolCallEnd:
			trace = append(trace, string(event.Kind)+":"+event.ToolCall.Id+" "+event.ToolCall.Arguments)
		default:
			trace = append(trace, string(event.Kind))
		}
	}
	return trace
}

// The text deltas, joined.
func (self *scriptedTestEvents) text() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	text := ""
	for _, event := range self.events {
		if event.Kind == sidecar.InferEventText {
			text += event.Text
		}
	}
	return text
}

// A model on a fixed clock with turns, which must build.
func newTestScriptedModel(t *testing.T, clock sidecar.Clock, turns ...*ScriptedTurn) *ScriptedModel {
	t.Helper()
	model, err := NewScriptedModel(&ScriptedModelArgs{Clock: clock, Turns: turns})
	if err != nil {
		t.Fatal(err)
	}
	return model
}

// A person's message.
func scriptedTestUser(text string) *sidecar.InferMessage {
	return &sidecar.InferMessage{Role: sidecar.InferRoleUser, Parts: []*sidecar.InferPart{{Kind: sidecar.InferPartText, Text: text}}}
}

// A tool's result answering the call of id.
func scriptedTestToolResult(id string, text string) *sidecar.InferMessage {
	return &sidecar.InferMessage{Role: sidecar.InferRoleTool, ToolCallId: id, Parts: []*sidecar.InferPart{{Kind: sidecar.InferPartText, Text: text}}}
}

// A call to name, as the router hands one to its engine.
func scriptedTestCall(name string, messages ...*sidecar.InferMessage) *sidecar.InferCall {
	return &sidecar.InferCall{
		Request: &sidecar.InferRequest{Model: name, Messages: messages},
		Name:    name,
		Effort:  sidecar.InferEffortOff,
	}
}

// Generate on a fresh event log, which must not fail.
func scriptedTestAnswer(t *testing.T, model *ScriptedModel, call *sidecar.InferCall) *scriptedTestEvents {
	t.Helper()
	events := &scriptedTestEvents{}
	if err := model.Generate(context.Background(), call, events.emit); err != nil {
		t.Fatal(err)
	}
	return events
}

// Each call takes the first turn not yet taken, in script order, whose match holds: an unmatched turn waits for a call
// it matches, a call no turn left matches is refused with a named error and takes nothing, and once every turn is
// taken a call is refused as the script having run out.
func TestScriptedModelMatchesTurnsInOrder(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	model := newTestScriptedModel(t, clock,
		&ScriptedTurn{Text: []string{"one"}},
		&ScriptedTurn{Match: &ScriptedMatch{UserText: "beta"}, Text: []string{"two"}},
		&ScriptedTurn{Match: &ScriptedMatch{UserText: "alpha"}, Text: []string{"three"}},
		&ScriptedTurn{Match: &ScriptedMatch{ToolCallId: "call_7", ToolResultText: "42"}, Text: []string{"four"}},
		&ScriptedTurn{Match: &ScriptedMatch{Model: "local-other-off"}, Text: []string{"five"}},
	)
	cases := []struct {
		call *sidecar.InferCall
		text string
		turn int
	}{
		// the first turn matches any call
		{call: scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("say alpha")), text: "one", turn: 0},
		// beta's turn waits; alpha's is the first that holds
		{call: scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("say alpha")), text: "three", turn: 2},
		{call: scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("now beta")), text: "two", turn: 1},
		{call: scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("look it up"), scriptedTestToolResult("call_7", "it is 42")), text: "four", turn: 3},
	}
	for i, c := range cases {
		if text := scriptedTestAnswer(t, model, c.call).text(); text != c.text {
			t.Fatalf("call %d answered %q, not %q", i+1, text, c.text)
		}
	}
	// a tool result of another call, and the person's text, match no turn left: only local-other-off's remains
	for _, call := range []*sidecar.InferCall{
		scriptedTestCall(ScriptedModelDefaultName, scriptedTestToolResult("call_8", "it is 42")),
		scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("anything")),
	} {
		events := &scriptedTestEvents{}
		err := model.Generate(context.Background(), call, events.emit)
		if !errors.Is(err, ErrScriptedModelUnmatched) {
			t.Fatalf("an unmatched call answered %v", err)
		}
		if trace := events.trace(); len(trace) != 0 {
			t.Fatalf("a refused call emitted %v", trace)
		}
	}
	if remaining := model.Remaining(); remaining != 1 {
		t.Fatalf("%d turns left, not 1", remaining)
	}
	if text := scriptedTestAnswer(t, model, scriptedTestCall("local-other-off", scriptedTestUser("anything"))).text(); text != "five" {
		t.Fatalf("the model's turn answered %q", text)
	}
	if err := model.Generate(context.Background(), scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("more")), (&scriptedTestEvents{}).emit); !errors.Is(err, ErrScriptedModelExhausted) {
		t.Fatalf("a call past the script answered %v", err)
	}
	turns := []int{}
	for _, call := range model.Calls() {
		turns = append(turns, call.Turn)
	}
	if want := []int{0, 2, 1, 3, -1, -1, 4, -1}; !slices.Equal(turns, want) {
		t.Fatalf("the calls took turns %v, not %v", turns, want)
	}
}

// Every call the model took is recorded whole, refused ones too, each request a deep copy its caller's later change
// does not reach, stamped from the model's clock; Saw finds a byte anywhere a model reads it and nowhere else.
func TestScriptedModelRecordsEveryRequest(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	model := newTestScriptedModel(t, clock, &ScriptedTurn{Text: []string{"seen"}})
	canary := "canary-5c1f0e7d2b9a"
	temperature := 0.2
	runId, agentId := sidecar.NewId(), sidecar.NewId()
	request := &sidecar.InferRequest{
		Model: ScriptedModelDefaultName,
		Messages: []*sidecar.InferMessage{
			{Role: sidecar.InferRoleSystem, Parts: []*sidecar.InferPart{{Kind: sidecar.InferPartText, Text: "Be brief."}}},
			{Role: sidecar.InferRoleUser, Parts: []*sidecar.InferPart{
				{Kind: sidecar.InferPartText, Text: "What is in the picture?"},
				{Kind: sidecar.InferPartImage, MediaType: "image/png", Data: []byte("png bytes " + canary)},
			}},
			{Role: sidecar.InferRoleAssistant, Reasoning: "look first", ToolCalls: []*sidecar.InferToolCall{
				{Id: "call_1", Name: "lookup", Arguments: `{"q":"picture"}`},
			}},
			scriptedTestToolResult("call_1", "a cat"),
		},
		Tools:    []*sidecar.InferTool{{Name: "lookup", Description: "Looks it up.", Schema: json.RawMessage(`{"type":"object"}`)}},
		Sampling: &sidecar.InferSampling{Temperature: &temperature, Stops: []string{"STOP"}},
		RunId:    &runId,
		AgentId:  &agentId,
	}
	snapshot := scriptedCloneRequest(request)
	call := &sidecar.InferCall{Request: request, Name: ScriptedModelDefaultName, Effort: sidecar.InferEffortOff}
	scriptedTestAnswer(t, model, call)
	firstAt := clock.Now()
	clock.Advance(time.Minute)
	// the caller changes what it sent: the record keeps what came
	request.Messages[1].Parts[1].Data[0] = 'X'
	request.Messages[3].Parts[0].Text = "a dog"
	*request.Sampling.Temperature = 0.9
	request.Tools[0].Schema[2] = 'X'
	if err := model.Generate(context.Background(), scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("again")), (&scriptedTestEvents{}).emit); !errors.Is(err, ErrScriptedModelExhausted) {
		t.Fatalf("the second call answered %v", err)
	}

	calls := model.Calls()
	if len(calls) != 2 {
		t.Fatalf("%d calls recorded", len(calls))
	}
	if !reflect.DeepEqual(calls[0].Request, snapshot) {
		t.Fatalf("the record changed with its caller's request:\n got %+v\nwant %+v", calls[0].Request, snapshot)
	}
	if calls[0].Turn != 0 || calls[0].Err != nil || calls[0].Name != ScriptedModelDefaultName || calls[0].Effort != sidecar.InferEffortOff ||
		!calls[0].At.Equal(firstAt) {
		t.Fatalf("the first record: turn %d, err %v, %s %s at %s", calls[0].Turn, calls[0].Err, calls[0].Name, calls[0].Effort, calls[0].At)
	}
	if calls[1].Turn != -1 || !errors.Is(calls[1].Err, ErrScriptedModelExhausted) || !calls[1].At.Equal(firstAt.Add(time.Minute)) ||
		calls[1].Request.Messages[0].Text() != "again" {
		t.Fatalf("the refused record: turn %d, err %v, at %s", calls[1].Turn, calls[1].Err, calls[1].At)
	}
	// a record handed out is a copy
	calls[0].Request.Messages[0].Parts[0].Text = "changed"
	if model.Calls()[0].Request.Messages[0].Text() != "Be brief." {
		t.Fatal("a record handed out shares the model's")
	}
	for _, seen := range []string{canary, "a cat", "look first", `{"q":"picture"}`, "Looks it up.", "STOP", "Be brief.", "again"} {
		if !model.Saw([]byte(seen)) {
			t.Errorf("the model did not see %q", seen)
		}
	}
	for _, unseen := range []string{"a dog", "never sent"} {
		if model.Saw([]byte(unseen)) {
			t.Errorf("the model saw %q", unseen)
		}
	}
}

// A cut ends the stream after the deltas it names, text, reasoning and argument deltas alike, nothing after it going
// out, and the call fails with ErrScriptedStreamCut, the code its cut names, engine_failed by default.
func TestScriptedModelCutsTheStreamWhereTold(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	cases := []struct {
		turn  *ScriptedTurn
		trace []string
		code  sidecar.InferErrorCode
	}{
		{
			turn:  &ScriptedTurn{Text: []string{"a", "b", "c"}, Usage: &sidecar.InferUsage{OutputTokens: 3}, Cut: &ScriptedCut{AfterDeltas: 2}},
			trace: []string{"start", "text:a", "text:b"},
			code:  sidecar.InferErrorEngineFailed,
		},
		{
			turn: &ScriptedTurn{
				Reasoning: []string{"think"},
				ToolCalls: []*ScriptedToolCall{{Id: "call_x", Name: "lookup", Arguments: `{"q":1}`, ArgumentDeltas: []string{`{"q":`, `1}`}}},
				Cut:       &ScriptedCut{AfterDeltas: 2, Code: sidecar.InferErrorCapacity},
			},
			trace: []string{"start", "reasoning:think", "tool_call_start:call_x lookup", `tool_call_args:{"q":`},
			code:  sidecar.InferErrorCapacity,
		},
		{
			turn:  &ScriptedTurn{Text: []string{"a"}, Cut: &ScriptedCut{AfterDeltas: 0}},
			trace: []string{"start"},
			code:  sidecar.InferErrorEngineFailed,
		},
		{
			// a cut after the last delta withholds the usage and the end
			turn:  &ScriptedTurn{Text: []string{"a"}, Usage: &sidecar.InferUsage{OutputTokens: 1}, Cut: &ScriptedCut{AfterDeltas: 1}},
			trace: []string{"start", "text:a"},
			code:  sidecar.InferErrorEngineFailed,
		},
	}
	for i, c := range cases {
		model := newTestScriptedModel(t, clock, c.turn)
		events := &scriptedTestEvents{}
		err := model.Generate(context.Background(), scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("go")), events.emit)
		if !errors.Is(err, ErrScriptedStreamCut) {
			t.Fatalf("case %d answered %v", i, err)
		}
		inferError := &sidecar.InferError{}
		if !errors.As(err, &inferError) || inferError.Code != c.code || !strings.Contains(inferError.Message, ErrScriptedStreamCut.Error()) {
			t.Fatalf("case %d's error: %+v", i, inferError)
		}
		if trace := events.trace(); !slices.Equal(trace, c.trace) {
			t.Fatalf("case %d emitted %v, not %v", i, trace, c.trace)
		}
		if recorded := model.Calls()[0].Err; !errors.Is(recorded, ErrScriptedStreamCut) {
			t.Fatalf("case %d's record holds %v", i, recorded)
		}
	}
	// a turn's own failure goes out after its deltas and usage
	model := newTestScriptedModel(t, clock, &ScriptedTurn{
		Text:  []string{"partial"},
		Usage: &sidecar.InferUsage{OutputTokens: 1},
		Fail:  &sidecar.InferError{Code: sidecar.InferErrorContextLength, Message: "too long"},
	})
	events := &scriptedTestEvents{}
	err := model.Generate(context.Background(), scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("go")), events.emit)
	if sidecar.InferErrorCodeOf(err) != sidecar.InferErrorContextLength {
		t.Fatalf("the failing turn answered %v", err)
	}
	if trace := events.trace(); !slices.Equal(trace, []string{"start", "text:partial", "usage"}) {
		t.Fatalf("the failing turn emitted %v", trace)
	}
}

// A stall holds the stream after the deltas it names until the test releases it, with nothing past it out meanwhile,
// and the call then plays on whole; a call whose context ends at a stall answers its context's end.
func TestScriptedModelStallsUntilReleased(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	stall := NewScriptedStall(1)
	canceledStall := NewScriptedStall(0)
	model := newTestScriptedModel(t, clock,
		&ScriptedTurn{Text: []string{"a", "b"}, Usage: &sidecar.InferUsage{OutputTokens: 2}, Stall: stall},
		&ScriptedTurn{Text: []string{"never"}, Stall: canceledStall},
	)
	events := &scriptedTestEvents{}
	done := make(chan error, 1)
	go func() {
		done <- model.Generate(context.Background(), scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("go")), events.emit)
	}()
	select {
	case <-stall.Reached():
	case <-time.After(60 * time.Second):
		t.Fatal("the stream never reached its stall")
	}
	if trace := events.trace(); !slices.Equal(trace, []string{"start", "text:a"}) {
		t.Fatalf("at the stall the stream had emitted %v", trace)
	}
	select {
	case err := <-done:
		t.Fatalf("the call ended at its stall: %v", err)
	default:
	}
	stall.Release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the released call never ended")
	}
	if trace := events.trace(); !slices.Equal(trace, []string{"start", "text:a", "text:b", "usage"}) {
		t.Fatalf("the released call emitted %v", trace)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	canceledEvents := &scriptedTestEvents{}
	go func() {
		done <- model.Generate(ctx, scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("go")), canceledEvents.emit)
	}()
	select {
	case <-canceledStall.Reached():
	case <-time.After(60 * time.Second):
		t.Fatal("the second stream never reached its stall")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the canceled call answered %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the canceled call never ended")
	}
	if trace := canceledEvents.trace(); !slices.Equal(trace, []string{"start"}) {
		t.Fatalf("the canceled call emitted %v", trace)
	}
}

// A script that runs out answers ErrScriptedModelExhausted, an InferError engine_failed whose message names it, as
// does a call past the most calls, ErrScriptedModelCallLimit, which is not recorded.
func TestScriptedModelRunsOutWithANamedError(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	model := newTestScriptedModel(t, clock, &ScriptedTurn{Text: []string{"only"}})
	scriptedTestAnswer(t, model, scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("first")))
	events := &scriptedTestEvents{}
	err := model.Generate(context.Background(), scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("second")), events.emit)
	if !errors.Is(err, ErrScriptedModelExhausted) {
		t.Fatalf("a call past the script answered %v", err)
	}
	inferError := &sidecar.InferError{}
	if !errors.As(err, &inferError) || inferError.Code != sidecar.InferErrorEngineFailed ||
		!strings.Contains(inferError.Message, ErrScriptedModelExhausted.Error()) {
		t.Fatalf("its InferError: %+v", inferError)
	}
	if trace := events.trace(); len(trace) != 0 {
		t.Fatalf("a refused call emitted %v", trace)
	}

	settings := DefaultScriptedModelSettings()
	settings.CallMaxCount = 2
	limited, err := NewScriptedModel(&ScriptedModelArgs{Settings: settings, Clock: clock, Turns: []*ScriptedTurn{
		{Text: []string{"one"}}, {Text: []string{"two"}}, {Text: []string{"three"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		scriptedTestAnswer(t, limited, scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("go")))
	}
	err = limited.Generate(context.Background(), scriptedTestCall(ScriptedModelDefaultName, scriptedTestUser("go")), (&scriptedTestEvents{}).emit)
	if !errors.Is(err, ErrScriptedModelCallLimit) || sidecar.InferErrorCodeOf(err) != sidecar.InferErrorEngineFailed {
		t.Fatalf("a call past the most answered %v", err)
	}
	if calls := limited.Calls(); len(calls) != 2 || limited.Remaining() != 1 {
		t.Fatalf("%d calls recorded and %d turns left past the most", len(calls), limited.Remaining())
	}
}

// The manifest lists each model as INFER's format reads it, a fresh copy for each caller, and INFER's local view of it
// on the model's device lists each model available, on a phone too, and on a platform with no engine build none.
func TestScriptedModelManifestListsItsModels(t *testing.T) {
	settings := sidecar.DefaultInferSettings()
	second := ScriptedManifestModel("second")
	second.ContextWindow = 128 * 1024
	model, err := NewScriptedModel(&ScriptedModelArgs{Models: []*sidecar.InferManifestModel{ScriptedManifestModel(ScriptedModelDefault), second}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := model.Manifest()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sidecar.ParseInferManifest(encoded, settings); err != nil {
		t.Fatalf("the manifest does not parse: %v", err)
	}
	manifest.Models[0].Model = "changed"
	if model.Manifest().Models[0].Model != ScriptedModelDefault {
		t.Fatal("a manifest handed out shares the model's")
	}
	device, err := model.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	phone := &sidecar.InferDeviceCapabilities{Platform: "ios/arm64", Class: sidecar.InferDeviceClassPhone, MemoryByteCount: 8 * 1024 * 1024 * 1024}
	for _, capabilities := range []*sidecar.InferDeviceCapabilities{device, phone} {
		catalog, err := sidecar.NewInferLocalCatalog(model.Manifest(), capabilities, settings)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{ScriptedModelDefaultName, "local-second-off", "local-second"} {
			resolution, err := catalog.Resolve(name, "")
			if err != nil {
				t.Fatalf("%s on %s: %v", name, capabilities.Platform, err)
			}
			if resolution.Entry.Unavailable != "" || resolution.Entry.Kind != sidecar.InferCatalogKindLocal {
				t.Fatalf("%s on %s: %q %s", name, capabilities.Platform, resolution.Entry.Unavailable, resolution.Entry.Kind)
			}
		}
	}
	unbuilt := &sidecar.InferDeviceCapabilities{Platform: "darwin/amd64", Class: sidecar.InferDeviceClassLaptop, MemoryByteCount: 16 * 1024 * 1024 * 1024}
	catalog, err := sidecar.NewInferLocalCatalog(model.Manifest(), unbuilt, settings)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.LocalUnavailable() == "" || len(catalog.Entries()) != 0 {
		t.Fatalf("a platform with no engine build lists %d local models: %q", len(catalog.Entries()), catalog.LocalUnavailable())
	}
	// a model that is not whole is refused at the start
	broken := ScriptedManifestModel("broken")
	broken.License = ""
	if _, err := NewScriptedModel(&ScriptedModelArgs{Models: []*sidecar.InferManifestModel{broken}}); !errors.Is(err, sidecar.ErrInferManifestInvalid) {
		t.Fatalf("a model with no license answered %v", err)
	}
}

// A turn the model cannot play is refused with ErrScriptedTurnInvalid, and a refused Script adds none of its turns.
func TestScriptedModelRefusesATurnItCannotPlay(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	shared := NewScriptedStall(0)
	model := newTestScriptedModel(t, clock, &ScriptedTurn{Text: []string{"a"}, Stall: shared})
	cases := []*ScriptedTurn{
		nil,
		{Text: []string{"a", ""}},
		{Reasoning: []string{""}},
		{ToolCalls: []*ScriptedToolCall{{Id: "call_1", Arguments: "{}"}}},
		{ToolCalls: []*ScriptedToolCall{{Name: "lookup", Arguments: `{"q":1}`, ArgumentDeltas: []string{`{"q":`}}}},
		{ToolCalls: []*ScriptedToolCall{{Name: "lookup", Arguments: `{}`, ArgumentDeltas: []string{"", `{}`}}}},
		{Text: []string{"a"}, Cut: &ScriptedCut{AfterDeltas: 2}},
		{Text: []string{"a"}, Cut: &ScriptedCut{AfterDeltas: -1}},
		{Text: []string{"a"}, Stall: NewScriptedStall(2)},
		{Text: []string{"a", "b"}, Stall: NewScriptedStall(2), Cut: &ScriptedCut{AfterDeltas: 1}},
		{Text: []string{"a"}, Stall: shared},
		{Text: []string{"a"}, Stall: &ScriptedStall{AfterDeltas: 0}},
		{Text: []string{"a"}, Fail: &sidecar.InferError{Message: "no code"}},
	}
	for i, turn := range cases {
		err := model.Script(&ScriptedTurn{Text: []string{"fine"}}, turn)
		if !errors.Is(err, ErrScriptedTurnInvalid) {
			t.Fatalf("case %d answered %v", i, err)
		}
		if remaining := model.Remaining(); remaining != 1 {
			t.Fatalf("case %d left %d turns, not the one scripted before", i, remaining)
		}
	}
	if _, err := NewScriptedModel(&ScriptedModelArgs{Turns: []*ScriptedTurn{{Text: []string{""}}}}); !errors.Is(err, ErrScriptedTurnInvalid) {
		t.Fatalf("a model built on a turn it cannot play answered %v", err)
	}
}
