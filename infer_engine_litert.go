//go:build ur_engine && !ios_extension && !sidecar_http

// LiteRT-LM's C API through purego (DESIGN-COMPUTE §6.5, D-INFER-2): the backend the ur-engine helper drives, and the
// helper's main. Only the ur_engine build tag builds this file, which cli/ur-engine/main.go sets, so ur and the sdk link
// no binding and no LiteRT-LM symbol, and nothing here runs with the daemon's keys. There is no cgo: purego loads the C
// library and calls it, and one callback, made once, carries every stream's chunks by an integer key.
//
// What it holds to (§6.5):
//
//   - The helper checked every file against its pin before load is called (infer_engine_helper.go); load then opens
//     Dawn's library and the GPU plugins it pins first, by their checked paths, so the engine's own loads of them by
//     name find those, and the engine's C library last.
//   - The library must answer litert_lm_get_api_version with major version 1, the C API 1.0.0's (C API versioning:
//     a library that does not export it is older than 1.0.0 and incompatible). Every symbol the binding uses is
//     resolved before the first call, so a library without one is refused whole at load, never at a later call.
//   - One conversation lives on one engine and an engine runs one call at a time (#2807): the helper's pool keeps it so.
//     A cancel calls litert_lm_conversation_cancel_process, the one call a stream allows from outside it, and the
//     conversation is then only deleted.
//   - No speculative decoding, so never multi-token prediction with clone (#4641), and no clone.
//
// The symbols and their signatures are the C API's as the research notes give c/engine.h and c/conversation.h
// (research_notes/Compute extension building blocks/litert_lm.md, section 2): functions that can fail return a
// LiteRtLmStatusCode, 0 for success, with results in out parameters. The notes elide the stream chunk accessors' prefix
// and the callback's arguments after its callback_data; this binding reads them as litert_lm_conversation_stream_chunk_*
// and (callback_data, chunk). The 1.0.0 header and a hand run on each desktop confirm them (External, INFER-M11-04):
// until then a mismatch fails the load naming the symbol, or crashes the helper, never the daemon. Structured output
// waits for the header's constraint calls and answers engine_failed; tokens are not counted, so a local call reports
// no usage.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/ebitengine/purego"
)

// LiteRtLmStatusCode's success.
const inferEngineLiteRtStatusOk = 0

// The C API's major version this binding speaks.
const inferEngineLiteRtApiMajor = 1

// The C API's functions this binding calls.
type inferEngineLiteRtApi struct {
	getApiVersion                 func(major *int32, minor *int32, patch *int32) int32
	engineSettingsCreate          func(modelPath string, backend string, visionBackend string, audioBackend string, out *uintptr) int32
	engineSettingsSetMaxNumTokens func(settings uintptr, maxNumTokens int32) int32
	engineSettingsSetNumThreads   func(settings uintptr, threadCount int32) int32
	engineSettingsDelete          func(settings uintptr)
	engineCreate                  func(settings uintptr, out *uintptr) int32
	engineDelete                  func(engine uintptr)
	conversationConfigCreate      func(engine uintptr, out *uintptr) int32
	conversationConfigSetSystem   func(config uintptr, json string) int32
	conversationConfigSetMessages func(config uintptr, json string) int32
	conversationConfigSetTools    func(config uintptr, json string) int32
	conversationConfigSetDecoding func(config uintptr, enable bool) int32
	conversationConfigDelete      func(config uintptr)
	conversationCreate            func(engine uintptr, config uintptr, out *uintptr) int32
	conversationDelete            func(conversation uintptr)
	conversationSendStream        func(conversation uintptr, message string, args uintptr, callback uintptr, callbackData uintptr) int32
	conversationCancel            func(conversation uintptr)
	optionalArgsCreate            func(out *uintptr) int32
	optionalArgsSetMaxOutput      func(args uintptr, maxOutputTokens int32) int32
	optionalArgsSetToolChoice     func(args uintptr, toolChoice string) int32
	optionalArgsDelete            func(args uintptr)
	chunkGetText                  func(chunk uintptr) string
	chunkIsFinal                  func(chunk uintptr) bool
	chunkGetError                 func(chunk uintptr) string
	lastErrorMessage              func() string
}

// Each function's symbol, by the field it fills.
func (self *inferEngineLiteRtApi) symbols() []struct {
	name     string
	function any
} {
	return []struct {
		name     string
		function any
	}{
		{name: "litert_lm_get_api_version", function: &self.getApiVersion},
		{name: "litert_lm_engine_settings_create", function: &self.engineSettingsCreate},
		{name: "litert_lm_engine_settings_set_max_num_tokens", function: &self.engineSettingsSetMaxNumTokens},
		{name: "litert_lm_engine_settings_set_num_threads", function: &self.engineSettingsSetNumThreads},
		{name: "litert_lm_engine_settings_delete", function: &self.engineSettingsDelete},
		{name: "litert_lm_engine_create", function: &self.engineCreate},
		{name: "litert_lm_engine_delete", function: &self.engineDelete},
		{name: "litert_lm_conversation_config_create", function: &self.conversationConfigCreate},
		{name: "litert_lm_conversation_config_set_system_message", function: &self.conversationConfigSetSystem},
		{name: "litert_lm_conversation_config_set_messages", function: &self.conversationConfigSetMessages},
		{name: "litert_lm_conversation_config_set_tools", function: &self.conversationConfigSetTools},
		{name: "litert_lm_conversation_config_set_enable_constrained_decoding", function: &self.conversationConfigSetDecoding},
		{name: "litert_lm_conversation_config_delete", function: &self.conversationConfigDelete},
		{name: "litert_lm_conversation_create", function: &self.conversationCreate},
		{name: "litert_lm_conversation_delete", function: &self.conversationDelete},
		{name: "litert_lm_conversation_send_message_stream", function: &self.conversationSendStream},
		{name: "litert_lm_conversation_cancel_process", function: &self.conversationCancel},
		{name: "litert_lm_conversation_optional_args_create", function: &self.optionalArgsCreate},
		{name: "litert_lm_conversation_optional_args_set_max_output_tokens", function: &self.optionalArgsSetMaxOutput},
		{name: "litert_lm_conversation_optional_args_set_tool_choice", function: &self.optionalArgsSetToolChoice},
		{name: "litert_lm_conversation_optional_args_delete", function: &self.optionalArgsDelete},
		{name: "litert_lm_conversation_stream_chunk_get_text", function: &self.chunkGetText},
		{name: "litert_lm_conversation_stream_chunk_is_final", function: &self.chunkIsFinal},
		{name: "litert_lm_conversation_stream_chunk_get_error", function: &self.chunkGetError},
		{name: "litert_lm_get_last_error_message", function: &self.lastErrorMessage},
	}
}

// The C library's last error on this thread, for an error's text.
func (self *inferEngineLiteRtApi) failed(call string, status int32) error {
	return fmt.Errorf("%s answered %d: %s", call, status, self.lastErrorMessage())
}

// The backend: the C API, bound at the first load, and the one stream callback.
type inferEngineLiteRt struct {
	stateLock sync.Mutex
	api       *inferEngineLiteRtApi
	// the one callback every stream shares, made once, since purego never frees one
	callback uintptr
	// each stream in flight, by the key its callback_data carries
	streams   map[uintptr]*inferEngineLiteRtStream
	nextKey   uintptr
	libraries []uintptr
}

// The backend, with nothing loaded.
func newInferEngineLiteRt() *inferEngineLiteRt {
	return &inferEngineLiteRt{streams: map[uintptr]*inferEngineLiteRtStream{}}
}

// Binds the C API from the checked library at params' paths, once a helper.
func (self *inferEngineLiteRt) bind(params *inferEngineLoadParams) (*inferEngineLiteRtApi, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.api != nil {
		return self.api, nil
	}
	// Dawn and the plugins first, by their checked paths, so the engine's own loads by name find them
	preloads := []*inferEngineFile{}
	if params.Dawn != nil {
		preloads = append(preloads, params.Dawn)
	}
	preloads = append(preloads, params.GpuPlugins...)
	preloads = append(preloads, params.Libraries[1:]...)
	for _, file := range preloads {
		handle, err := inferEngineLiteRtOpen(file.Path)
		if err != nil {
			return nil, err
		}
		self.libraries = append(self.libraries, handle)
	}
	library, err := inferEngineLiteRtOpen(params.Libraries[0].Path)
	if err != nil {
		return nil, err
	}
	self.libraries = append(self.libraries, library)
	api := &inferEngineLiteRtApi{}
	for _, symbol := range api.symbols() {
		address, err := inferEngineLiteRtSymbol(library, symbol.name)
		if err != nil {
			return nil, fmt.Errorf("the engine library has no %s, which C API 1.0.0 exports", symbol.name)
		}
		purego.RegisterFunc(symbol.function, address)
	}
	major, minor, patch := int32(0), int32(0), int32(0)
	if status := api.getApiVersion(&major, &minor, &patch); status != inferEngineLiteRtStatusOk || major != inferEngineLiteRtApiMajor {
		return nil, fmt.Errorf("the engine library's C API is %d.%d.%d, not %d.x", major, minor, patch, inferEngineLiteRtApiMajor)
	}
	self.callback = purego.NewCallback(self.chunk)
	self.api = api
	return api, nil
}

// See inferEngineBackend: one engine of the model a backend asks, each its own engine handle.
func (self *inferEngineLiteRt) load(params *inferEngineLoadParams) ([]inferEngineModel, error) {
	api, err := self.bind(params)
	if err != nil {
		return nil, err
	}
	models := []inferEngineModel{}
	for range params.Settings.InstanceCount {
		model, err := self.loadOne(api, params)
		if err != nil {
			for _, loaded := range models {
				loaded.close()
			}
			return nil, err
		}
		models = append(models, model)
	}
	return models, nil
}

// One engine over the model.
func (self *inferEngineLiteRt) loadOne(api *inferEngineLiteRtApi, params *inferEngineLoadParams) (*inferEngineLiteRtModel, error) {
	settings := uintptr(0)
	if status := api.engineSettingsCreate(params.Model.Path, params.Settings.Backend, "", "", &settings); status != inferEngineLiteRtStatusOk {
		return nil, api.failed("litert_lm_engine_settings_create", status)
	}
	defer api.engineSettingsDelete(settings)
	if status := api.engineSettingsSetMaxNumTokens(settings, int32(params.Settings.MaxTokenCount)); status != inferEngineLiteRtStatusOk {
		return nil, api.failed("litert_lm_engine_settings_set_max_num_tokens", status)
	}
	if 0 < params.Settings.ThreadCount {
		if status := api.engineSettingsSetNumThreads(settings, int32(params.Settings.ThreadCount)); status != inferEngineLiteRtStatusOk {
			return nil, api.failed("litert_lm_engine_settings_set_num_threads", status)
		}
	}
	engine := uintptr(0)
	if status := api.engineCreate(settings, &engine); status != inferEngineLiteRtStatusOk {
		return nil, api.failed("litert_lm_engine_create", status)
	}
	return &inferEngineLiteRtModel{backend: self, api: api, engine: engine}, nil
}

// One stream in flight: its chunks go to chunk until its final one, then done closes, once.
type inferEngineLiteRtStream struct {
	chunk func(chunk *inferEngineChunk)
	done  chan struct{}
	once  sync.Once
	err   error
}

// The one callback: hands a chunk to the stream its callback_data names. It returns at once, as the C API asks, since
// its thread serves every stream of an engine.
func (self *inferEngineLiteRt) chunk(callbackData uintptr, chunk uintptr) uintptr {
	stream := func() *inferEngineLiteRtStream {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.streams[callbackData]
	}()
	if stream == nil || chunk == 0 {
		return 0
	}
	failed := ""
	if message := self.api.chunkGetError(chunk); message != "" {
		failed = message
	} else if text := self.api.chunkGetText(chunk); text != "" {
		stream.chunk(inferEngineLiteRtChunkOf(text))
	}
	if self.api.chunkIsFinal(chunk) || failed != "" {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.streams, callbackData)
		}()
		stream.once.Do(func() {
			if failed != "" {
				stream.err = errors.New(failed)
			}
			close(stream.done)
		})
	}
	return 0
}

// A chunk's text as the conversation streams it: a message delta, its tool calls parsed whole by the engine, or text.
func inferEngineLiteRtChunkOf(text string) *inferEngineChunk {
	message := &struct {
		Content   string                     `json:"content"`
		Thinking  string                     `json:"thinking"`
		ToolCalls []*inferEngineFunctionCall `json:"tool_calls"`
	}{}
	if err := json.Unmarshal([]byte(text), message); err != nil {
		return &inferEngineChunk{Text: text}
	}
	chunk := &inferEngineChunk{Text: message.Content, Reasoning: message.Thinking}
	for _, call := range message.ToolCalls {
		chunk.ToolCalls = append(chunk.ToolCalls, &inferEngineToolCall{Name: call.Function.Name, Arguments: call.Function.Arguments})
	}
	return chunk
}

// One engine.
type inferEngineLiteRtModel struct {
	backend *inferEngineLiteRt
	api     *inferEngineLiteRtApi
	engine  uintptr
}

// See inferEngineModel.
func (self *inferEngineLiteRtModel) open(config *inferEngineConversationConfig) (inferEngineConversation, error) {
	if config.Mode == inferEngineModeSchema {
		return nil, errors.New("structured output waits for the C API's constraint calls, which this binding does not yet bind")
	}
	api := self.api
	conversationConfig := uintptr(0)
	if status := api.conversationConfigCreate(self.engine, &conversationConfig); status != inferEngineLiteRtStatusOk {
		return nil, api.failed("litert_lm_conversation_config_create", status)
	}
	defer api.conversationConfigDelete(conversationConfig)
	if config.System != "" {
		system, err := json.Marshal(&inferEngineMessage{Role: string(InferRoleSystem), Content: []*inferEngineContentPart{{Type: "text", Text: config.System}}})
		if err != nil {
			return nil, err
		}
		if status := api.conversationConfigSetSystem(conversationConfig, string(system)); status != inferEngineLiteRtStatusOk {
			return nil, api.failed("litert_lm_conversation_config_set_system_message", status)
		}
	}
	if config.History != nil {
		if status := api.conversationConfigSetMessages(conversationConfig, string(config.History)); status != inferEngineLiteRtStatusOk {
			return nil, api.failed("litert_lm_conversation_config_set_messages", status)
		}
	}
	if config.Mode == inferEngineModeTools {
		if status := api.conversationConfigSetTools(conversationConfig, string(config.Tools)); status != inferEngineLiteRtStatusOk {
			return nil, api.failed("litert_lm_conversation_config_set_tools", status)
		}
		if status := api.conversationConfigSetDecoding(conversationConfig, true); status != inferEngineLiteRtStatusOk {
			return nil, api.failed("litert_lm_conversation_config_set_enable_constrained_decoding", status)
		}
	}
	conversation := uintptr(0)
	if status := api.conversationCreate(self.engine, conversationConfig, &conversation); status != inferEngineLiteRtStatusOk {
		return nil, api.failed("litert_lm_conversation_create", status)
	}
	return &inferEngineLiteRtConversation{model: self, conversation: conversation}, nil
}

// See inferEngineModel.
func (self *inferEngineLiteRtModel) close() {
	self.api.engineDelete(self.engine)
}

// One conversation.
type inferEngineLiteRtConversation struct {
	model        *inferEngineLiteRtModel
	conversation uintptr
}

// See inferEngineConversation.
func (self *inferEngineLiteRtConversation) send(message json.RawMessage, args *inferEngineSendArgs, chunk func(chunk *inferEngineChunk)) (*InferUsage, error) {
	api := self.model.api
	backend := self.model.backend
	optionalArgs := uintptr(0)
	if status := api.optionalArgsCreate(&optionalArgs); status != inferEngineLiteRtStatusOk {
		return nil, api.failed("litert_lm_conversation_optional_args_create", status)
	}
	defer api.optionalArgsDelete(optionalArgs)
	if 0 < args.MaxOutput {
		if status := api.optionalArgsSetMaxOutput(optionalArgs, int32(args.MaxOutput)); status != inferEngineLiteRtStatusOk {
			return nil, api.failed("litert_lm_conversation_optional_args_set_max_output_tokens", status)
		}
	}
	if args.ToolChoice != "" {
		if status := api.optionalArgsSetToolChoice(optionalArgs, args.ToolChoice); status != inferEngineLiteRtStatusOk {
			return nil, api.failed("litert_lm_conversation_optional_args_set_tool_choice", status)
		}
	}
	stream := &inferEngineLiteRtStream{chunk: chunk, done: make(chan struct{})}
	key := func() uintptr {
		backend.stateLock.Lock()
		defer backend.stateLock.Unlock()
		backend.nextKey += 1
		backend.streams[backend.nextKey] = stream
		return backend.nextKey
	}()
	if status := api.conversationSendStream(self.conversation, string(message), optionalArgs, backend.callback, key); status != inferEngineLiteRtStatusOk {
		func() {
			backend.stateLock.Lock()
			defer backend.stateLock.Unlock()
			delete(backend.streams, key)
		}()
		return nil, api.failed("litert_lm_conversation_send_message_stream", status)
	}
	<-stream.done
	if stream.err != nil {
		return nil, stream.err
	}
	return nil, nil
}

// See inferEngineConversation: the stream ends with a final chunk, after which the conversation is only deleted.
func (self *inferEngineLiteRtConversation) cancel() {
	self.model.api.conversationCancel(self.conversation)
}

// See inferEngineConversation.
func (self *inferEngineLiteRtConversation) close() {
	self.model.api.conversationDelete(self.conversation)
}

// The ur-engine helper's main (cli/ur-engine): serves the protocol on its stdio over LiteRT-LM until its input ends, and
// answers the process's exit code. Its settings are the defaults, whose protocol bounds the daemon's share.
func InferEngineHelperMain() int {
	settings := DefaultInferSettings()
	err := inferEngineHelperServe(context.Background(), os.Stdin, os.Stdout, newInferEngineLiteRt(), inferEngineMethods, settings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ur-engine: %s\n", err)
		return 1
	}
	return 0
}
