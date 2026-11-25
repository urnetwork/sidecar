//go:build !ios_extension && !sidecar_http && !js

package sidecar

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// A stand-in for LiteRT-LM's C API: it records what the helper does to it, and answers each send by its answer.
type testInferEngineBackend struct {
	stateLock sync.Mutex
	events    []string
	answer    func(conversation *testInferEngineConversation, message *inferEngineMessage, chunk func(chunk *inferEngineChunk)) (*InferUsage, error)
}

// Records event.
func (self *testInferEngineBackend) record(event string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, event)
}

// What it recorded, in order.
func (self *testInferEngineBackend) recorded() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

// See inferEngineBackend.
func (self *testInferEngineBackend) load(params *inferEngineLoadParams) ([]inferEngineModel, error) {
	self.record("load " + filepath.Base(params.Model.Path))
	models := []inferEngineModel{}
	for index := range params.Settings.InstanceCount {
		models = append(models, &testInferEngineModel{backend: self, index: index})
	}
	return models, nil
}

// One stand-in engine.
type testInferEngineModel struct {
	backend *testInferEngineBackend
	index   int
}

// See inferEngineModel: records the engine, the mode and how many earlier turns the conversation opens with.
func (self *testInferEngineModel) open(config *inferEngineConversationConfig) (inferEngineConversation, error) {
	history := []json.RawMessage{}
	if config.History != nil {
		if err := json.Unmarshal(config.History, &history); err != nil {
			return nil, err
		}
	}
	self.backend.record(fmt.Sprintf("open %d %s %d", self.index, config.Mode, len(history)))
	return &testInferEngineConversation{backend: self.backend, config: config, canceled: make(chan struct{})}, nil
}

// See inferEngineModel.
func (self *testInferEngineModel) close() {
	self.backend.record(fmt.Sprintf("unload %d", self.index))
}

// One stand-in conversation.
type testInferEngineConversation struct {
	backend    *testInferEngineBackend
	config     *inferEngineConversationConfig
	canceled   chan struct{}
	cancelOnce sync.Once
}

// See inferEngineConversation.
func (self *testInferEngineConversation) send(message json.RawMessage, args *inferEngineSendArgs, chunk func(chunk *inferEngineChunk)) (*InferUsage, error) {
	decoded := &inferEngineMessage{}
	if err := json.Unmarshal(message, decoded); err != nil {
		return nil, err
	}
	self.backend.record("send " + string(self.config.Mode))
	return self.backend.answer(self, decoded, chunk)
}

// See inferEngineConversation.
func (self *testInferEngineConversation) cancel() {
	self.backend.record("cancel")
	self.cancelOnce.Do(func() {
		close(self.canceled)
	})
}

// See inferEngineConversation.
func (self *testInferEngineConversation) close() {
	self.backend.record("close")
}

// An answer that echoes the message's text in two chunks.
func testInferEngineEcho(conversation *testInferEngineConversation, message *inferEngineMessage, chunk func(chunk *inferEngineChunk)) (*InferUsage, error) {
	text := ""
	for _, part := range message.Content {
		text += part.Text
	}
	chunk(&inferEngineChunk{Text: "echo: "})
	chunk(&inferEngineChunk{Text: text})
	return &InferUsage{InputTokens: uint64(len(text)), OutputTokens: 2}, nil
}

// An in-process helper over a stand-in, spoken to over pipes as the daemon speaks to ur-engine.
type testInferEngineHelperWorld struct {
	backend  *testInferEngineBackend
	settings *InferSettings
	requests io.WriteCloser
	answers  chan *inferEngineAnswer
	served   chan error
	nextId   uint64
}

// The helper over backend with the extension methods methods, ended at the test's end.
func newTestInferEngineHelperWorld(t *testing.T, backend *testInferEngineBackend, methods map[string]InferEngineMethod) *testInferEngineHelperWorld {
	t.Helper()
	requestsReader, requestsWriter := io.Pipe()
	answersReader, answersWriter := io.Pipe()
	world := &testInferEngineHelperWorld{
		backend:  backend,
		settings: DefaultInferSettings(),
		requests: requestsWriter,
		answers:  make(chan *inferEngineAnswer, 1024),
		served:   make(chan error, 1),
	}
	go func() {
		world.served <- inferEngineHelperServe(context.Background(), requestsReader, answersWriter, backend, methods, world.settings)
		answersWriter.Close()
	}()
	go func() {
		defer close(world.answers)
		reader := bufio.NewReader(answersReader)
		for {
			line, err := inferEngineReadLine(reader, world.settings.EngineAnswerMaxByteCount)
			if err != nil {
				return
			}
			answer := &inferEngineAnswer{}
			if err := json.Unmarshal(line, answer); err != nil {
				return
			}
			world.answers <- answer
		}
	}()
	t.Cleanup(func() {
		requestsWriter.Close()
		select {
		case <-world.served:
		case <-time.After(testInferWait):
			t.Error("the helper did not end with its input")
		}
	})
	return world
}

// Sends a request, answering its id.
func (self *testInferEngineHelperWorld) send(t *testing.T, method string, params any) uint64 {
	t.Helper()
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	self.nextId += 1
	line, err := json.Marshal(&inferEngineRequest{Id: self.nextId, Method: method, Params: encoded})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := self.requests.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	return self.nextId
}

// The next answer, failing a test that waits past testInferWait.
func (self *testInferEngineHelperWorld) next(t *testing.T) *inferEngineAnswer {
	t.Helper()
	select {
	case answer, ok := <-self.answers:
		if !ok {
			t.Fatal("the helper's answers ended")
		}
		return answer
	case <-time.After(testInferWait):
		t.Fatal("no answer")
	}
	return nil
}

// Every event of generate id until its end or error, the last included.
func (self *testInferEngineHelperWorld) stream(t *testing.T, id uint64) []*InferEvent {
	t.Helper()
	events := []*InferEvent{}
	for {
		answer := self.next(t)
		if answer.Id != id || answer.Event == nil {
			t.Fatalf("an answer of another request: %+v", answer)
		}
		events = append(events, answer.Event)
		if answer.Event.Kind == InferEventEnd || answer.Event.Kind == InferEventError {
			return events
		}
	}
}

// The result of method id, failing on its error.
func (self *testInferEngineHelperWorld) result(t *testing.T, id uint64, result any) {
	t.Helper()
	answer := self.next(t)
	if answer.Id != id {
		t.Fatalf("an answer of another request: %+v", answer)
	}
	if answer.Error != nil {
		t.Fatalf("answered %v", answer.Error)
	}
	if result != nil {
		if err := json.Unmarshal(answer.Result, result); err != nil {
			t.Fatal(err)
		}
	}
}

// Files of the given names and contents in a fresh directory, each pinned by its SHA-256.
func testInferEngineFiles(t *testing.T, contents map[string]string) map[string]*inferEngineFile {
	t.Helper()
	directory := t.TempDir()
	files := map[string]*inferEngineFile{}
	for name, content := range contents {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(content))
		files[name] = &inferEngineFile{Path: path, Sha256: hex.EncodeToString(sum[:])}
	}
	return files
}

// load's params for a model with instances engines, every file on its pin.
func testInferEngineLoadParams(t *testing.T, instances int) *inferEngineLoadParams {
	t.Helper()
	files := testInferEngineFiles(t, map[string]string{
		"liblitert-lm.so":         "engine library bytes",
		"libwebgpu_dawn.so":       "dawn bytes",
		"gemma-4-e4b.litertlm":    "model bytes",
		"libLiteRtGpuAccelerator": "plugin bytes",
	})
	return &inferEngineLoadParams{
		Libraries:  []*inferEngineFile{files["liblitert-lm.so"]},
		Dawn:       files["libwebgpu_dawn.so"],
		GpuPlugins: []*inferEngineFile{files["libLiteRtGpuAccelerator"]},
		Model:      files["gemma-4-e4b.litertlm"],
		Settings:   &inferEngineLoadSettings{Backend: "cpu", MaxTokenCount: 32 * 1024, InstanceCount: instances},
	}
}

// Loads a model with instances engines, answering its handle.
func (self *testInferEngineHelperWorld) load(t *testing.T, instances int) uint64 {
	t.Helper()
	result := &inferEngineLoadResult{}
	self.result(t, self.send(t, inferEngineMethodLoad, testInferEngineLoadParams(t, instances)), result)
	return result.Handle
}

// A user's message of text.
func testInferUserMessage(text string) *InferMessage {
	return &InferMessage{Role: InferRoleUser, Parts: []*InferPart{{Kind: InferPartText, Text: text}}}
}

// The protocol end to end over the stand-in: capabilities, a load whose files are on their pins, a generate streamed as
// InferEvents from start to end with its usage, and an unload.
func TestEngineProtocolRoundTrip(t *testing.T) {
	backend := &testInferEngineBackend{answer: testInferEngineEcho}
	world := newTestInferEngineHelperWorld(t, backend, nil)

	id := world.send(t, inferEngineMethodCapabilities, struct{}{})
	answer := world.next(t)
	if answer.Id != id || (answer.Result == nil && answer.Error == nil) {
		t.Fatalf("capabilities answered %+v", answer)
	}

	handle := world.load(t, 1)
	id = world.send(t, inferEngineMethodGenerate, &inferEngineGenerateParams{
		Handle:       handle,
		Conversation: "agent-a",
		Messages:     []*InferMessage{{Role: InferRoleSystem, Parts: []*InferPart{{Kind: InferPartText, Text: "be brief"}}}, testInferUserMessage("hello")},
		Effort:       InferEffortOff,
	})
	events := world.stream(t, id)
	if want := []InferEventKind{InferEventStart, InferEventText, InferEventText, InferEventUsage, InferEventEnd}; !slices.Equal(testInferKinds(events), want) {
		t.Fatalf("events %v", testInferKinds(events))
	}
	if testInferText(events) != "echo: hello" || events[3].Usage.InputTokens != 5 {
		t.Errorf("answered %q, usage %+v", testInferText(events), events[3].Usage)
	}
	world.result(t, world.send(t, inferEngineMethodUnload, &inferEngineUnloadParams{Handle: handle}), nil)
	if want := []string{"load gemma-4-e4b.litertlm", "open 0 plain 0", "send plain", "close", "unload 0"}; !slices.Equal(backend.recorded(), want) {
		t.Errorf("the engine saw %v", backend.recorded())
	}
}

// A load naming a library, a plugin, Dawn or a model whose bytes are off its pin is refused before the backend loads
// anything.
func TestEngineRefusesLibraryOffItsPin(t *testing.T) {
	backend := &testInferEngineBackend{answer: testInferEngineEcho}
	world := newTestInferEngineHelperWorld(t, backend, nil)
	for _, spoil := range []func(params *inferEngineLoadParams){
		func(params *inferEngineLoadParams) { params.Libraries[0].Sha256 = strings.Repeat("0", 64) },
		func(params *inferEngineLoadParams) { params.Dawn.Sha256 = strings.Repeat("1", 64) },
		func(params *inferEngineLoadParams) { params.GpuPlugins[0].Sha256 = strings.Repeat("2", 64) },
		func(params *inferEngineLoadParams) { params.Model.Sha256 = strings.Repeat("3", 64) },
		func(params *inferEngineLoadParams) { params.Model.Sha256 = "not hex" },
		func(params *inferEngineLoadParams) {
			params.Libraries[0].Path = filepath.Join(t.TempDir(), "missing.so")
		},
	} {
		params := testInferEngineLoadParams(t, 1)
		spoil(params)
		id := world.send(t, inferEngineMethodLoad, params)
		answer := world.next(t)
		if answer.Id != id || answer.Error == nil || answer.Error.Code != InferErrorEngineFailed || !strings.Contains(answer.Error.Message, "off its pin") {
			t.Errorf("a file off its pin: %+v", answer)
		}
	}
	if len(backend.recorded()) != 0 {
		t.Errorf("the backend loaded: %v", backend.recorded())
	}
}

// A cancel stops the send in flight, the stream ends canceled, and the conversation is closed, never reused (#2807):
// the agent's next turn reopens it from its messages, all but the last as the earlier turns.
func TestEngineCancelReopensFromSavedMessages(t *testing.T) {
	sending := make(chan struct{}, 1)
	backend := &testInferEngineBackend{}
	backend.answer = func(conversation *testInferEngineConversation, message *inferEngineMessage, chunk func(chunk *inferEngineChunk)) (*InferUsage, error) {
		if message.Content[0].Text == "wait" {
			chunk(&inferEngineChunk{Text: "thinking"})
			sending <- struct{}{}
			<-conversation.canceled
			return nil, errInferEngineCanceled
		}
		return testInferEngineEcho(conversation, message, chunk)
	}
	world := newTestInferEngineHelperWorld(t, backend, nil)
	handle := world.load(t, 1)
	first := []*InferMessage{testInferUserMessage("wait")}
	id := world.send(t, inferEngineMethodGenerate, &inferEngineGenerateParams{Handle: handle, Conversation: "agent-a", Messages: first, Effort: InferEffortOff})
	<-sending
	cancelId := world.send(t, inferEngineMethodCancel, &inferEngineCancelParams{Id: id})
	events := []*InferEvent{}
	cancelAnswered := false
	for len(events) == 0 || (events[len(events)-1].Kind != InferEventError && events[len(events)-1].Kind != InferEventEnd) || !cancelAnswered {
		answer := world.next(t)
		switch answer.Id {
		case cancelId:
			cancelAnswered = true
		case id:
			events = append(events, answer.Event)
		}
	}
	if last := events[len(events)-1]; last.Kind != InferEventError || last.Error.Code != InferErrorCanceled {
		t.Fatalf("the canceled stream ended %+v", last)
	}
	second := []*InferMessage{
		testInferUserMessage("wait"),
		{Role: InferRoleAssistant, Parts: []*InferPart{{Kind: InferPartText, Text: "thinking"}}},
		testInferUserMessage("go on"),
	}
	id = world.send(t, inferEngineMethodGenerate, &inferEngineGenerateParams{Handle: handle, Conversation: "agent-a", Messages: second, Effort: InferEffortOff})
	if last := world.stream(t, id); last[len(last)-1].Kind != InferEventEnd {
		t.Fatalf("the next turn ended %v", testInferKinds(last))
	}
	want := []string{"load gemma-4-e4b.litertlm", "open 0 plain 0", "send plain", "cancel", "close", "open 0 plain 2", "send plain"}
	if !slices.Equal(backend.recorded(), want) {
		t.Errorf("the engine saw %v, want %v", backend.recorded(), want)
	}
}

// A call that continues its agent's conversation with exactly its earlier turns and the engine's own answer sends only
// its new message; one whose earlier turns differ reopens.
func TestEngineContinuesItsConversation(t *testing.T) {
	backend := &testInferEngineBackend{answer: testInferEngineEcho}
	world := newTestInferEngineHelperWorld(t, backend, nil)
	handle := world.load(t, 1)
	generate := func(messages []*InferMessage) {
		id := world.send(t, inferEngineMethodGenerate, &inferEngineGenerateParams{Handle: handle, Conversation: "agent-a", Messages: messages, Effort: InferEffortOff})
		world.stream(t, id)
	}
	generate([]*InferMessage{testInferUserMessage("one")})
	generate([]*InferMessage{
		testInferUserMessage("one"),
		{Role: InferRoleAssistant, Parts: []*InferPart{{Kind: InferPartText, Text: "echo: one"}}, Reasoning: "not sent back"},
		testInferUserMessage("two"),
	})
	generate([]*InferMessage{testInferUserMessage("edited"), testInferUserMessage("three")})
	want := []string{"load gemma-4-e4b.litertlm", "open 0 plain 0", "send plain", "send plain", "close", "open 0 plain 1", "send plain"}
	if !slices.Equal(backend.recorded(), want) {
		t.Errorf("the engine saw %v, want %v", backend.recorded(), want)
	}
}

// A call with both tools and a schema runs its tools first; where the model calls no tool, the schema runs on a final
// turn in a conversation of its own, and only that turn's answer is streamed; where it calls one, the call is the answer.
func TestEngineToolsThenSchemaOnFinalTurn(t *testing.T) {
	callTool := false
	backend := &testInferEngineBackend{}
	backend.answer = func(conversation *testInferEngineConversation, message *inferEngineMessage, chunk func(chunk *inferEngineChunk)) (*InferUsage, error) {
		switch conversation.config.Mode {
		case inferEngineModeTools:
			if callTool {
				chunk(&inferEngineChunk{ToolCalls: []*inferEngineToolCall{{Name: "read", Arguments: json.RawMessage(`{"path":"notes.md"}`)}}})
			} else {
				chunk(&inferEngineChunk{Text: "a free-form answer"})
			}
			return &InferUsage{InputTokens: 10, OutputTokens: 4}, nil
		case inferEngineModeSchema:
			if conversation.config.Schema == nil {
				return nil, errors.New("a schema turn with no schema")
			}
			chunk(&inferEngineChunk{Text: `{"answer":42}`})
			return &InferUsage{InputTokens: 10, OutputTokens: 3}, nil
		}
		return nil, errors.New("a plain turn")
	}
	world := newTestInferEngineHelperWorld(t, backend, nil)
	handle := world.load(t, 1)
	params := &inferEngineGenerateParams{
		Handle:       handle,
		Conversation: "agent-a",
		Messages:     []*InferMessage{testInferUserMessage("answer in JSON")},
		Tools:        []*InferTool{{Name: "read", Schema: json.RawMessage(`{"type":"object"}`)}},
		Schema:       json.RawMessage(`{"type":"object","properties":{"answer":{"type":"integer"}}}`),
		Effort:       InferEffortOff,
	}
	events := world.stream(t, world.send(t, inferEngineMethodGenerate, params))
	if testInferText(events) != `{"answer":42}` {
		t.Errorf("answered %q", testInferText(events))
	}
	var usage *InferUsage
	for _, event := range events {
		if event.Kind == InferEventUsage {
			usage = event.Usage
		}
	}
	if usage == nil || usage.InputTokens != 20 || usage.OutputTokens != 7 {
		t.Errorf("usage %+v, both turns' wanted", usage)
	}
	if want := []string{"load gemma-4-e4b.litertlm", "open 0 tools 0", "send tools", "close", "open 0 schema 0", "send schema"}; !slices.Equal(backend.recorded(), want) {
		t.Errorf("the engine saw %v", backend.recorded())
	}

	callTool = true
	events = world.stream(t, world.send(t, inferEngineMethodGenerate, params))
	kinds := testInferKinds(events)
	if !slices.Contains(kinds, InferEventToolCallEnd) || testInferText(events) != "" {
		t.Errorf("a tool call's turn answered %v, %q", kinds, testInferText(events))
	}
	for _, event := range events {
		if event.Kind == InferEventToolCallEnd && (event.ToolCall.Name != "read" || event.ToolCall.Arguments != `{"path":"notes.md"}` || !strings.HasPrefix(event.ToolCall.Id, "call-")) {
			t.Errorf("the tool call %+v", event.ToolCall)
		}
	}
}

// An extension method registered for the helper runs in it and answers its result, as SAFE's classifier's do; a method
// no one registered answers an error.
func TestEngineExtensionMethodDispatched(t *testing.T) {
	methods := map[string]InferEngineMethod{
		"classify": func(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
			return json.RawMessage(`{"logits":[0.1,0.9],"params":` + string(params) + `}`), nil
		},
	}
	world := newTestInferEngineHelperWorld(t, &testInferEngineBackend{answer: testInferEngineEcho}, methods)
	result := &struct {
		Logits []float64       `json:"logits"`
		Params json.RawMessage `json:"params"`
	}{}
	world.result(t, world.send(t, "classify", map[string]string{"window": "text"}), result)
	if !slices.Equal(result.Logits, []float64{0.1, 0.9}) || string(result.Params) != `{"window":"text"}` {
		t.Errorf("result %+v", result)
	}
	id := world.send(t, "unregistered", struct{}{})
	if answer := world.next(t); answer.Id != id || answer.Error == nil {
		t.Errorf("an unregistered method: %+v", answer)
	}

	registered := inferEngineMethods
	t.Cleanup(func() {
		inferEngineMethods = registered
	})
	inferEngineMethods = map[string]InferEngineMethod{}
	method := func(ctx context.Context, params json.RawMessage) (json.RawMessage, error) {
		return nil, nil
	}
	testInferPanics(t, "a built-in name", func() { registerInferEngineMethod(inferEngineMethodGenerate, method) })
	testInferPanics(t, "a nil method", func() { registerInferEngineMethod("classify", nil) })
	registerInferEngineMethod("classify", method)
	testInferPanics(t, "a second registration", func() { registerInferEngineMethod("classify", method) })
}

// Lines are bounded: one past its bound is refused, a helper given one ends, and a line at its bound reads whole.
func TestEngineLinesBounded(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("a", 64)+"\n"+strings.Repeat("b", 65)+"\nlast"), 16)
	if line, err := inferEngineReadLine(reader, 64); err != nil || len(line) != 64 {
		t.Errorf("a line at its bound: %d bytes, %v", len(line), err)
	}
	if _, err := inferEngineReadLine(reader, 64); !errors.Is(err, errInferEngineLineTooLong) {
		t.Errorf("a line past its bound: %v", err)
	}

	settings := DefaultInferSettings()
	settings.EngineRequestMaxByteCount = 128
	input := strings.NewReader(`{"id":1,"method":"capabilities","params":"` + strings.Repeat("x", 200) + `"}` + "\n")
	err := inferEngineHelperServe(context.Background(), input, io.Discard, &testInferEngineBackend{}, nil, settings)
	if !errors.Is(err, errInferEngineLineTooLong) {
		t.Errorf("a helper given a line past its bound: %v", err)
	}
}
