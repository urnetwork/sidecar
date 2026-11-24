//go:build !ios_extension && !sidecar_http

// The local engine on desktops (DESIGN-COMPUTE §6.5, D-INFER-2, R-INFER-2): LiteRT-LM runs in ur-engine, a second
// executable beside ur, never linked into ur or the sdk, so a crash, a leak or a hostile model file takes the helper and
// never the daemon that holds the keys, and the engine's C++ parses model files and untrusted text with no key, no
// token and no network. The daemon's side is infer_engine_process.go, the helper's protocol infer_engine_protocol.go,
// its loop infer_engine_helper.go, and LiteRT-LM's C API through purego infer_engine_litert.go, which only the ur_engine
// build tag builds, so ur links no binding.
//
// This file holds what the helper's loop drives, the shape of LiteRT-LM's C API (§6.5: OpenAI-style JSON messages and
// tools, a streaming callback, cancel): an inferEngineBackend loads a model into engines, an engine opens conversations,
// and a conversation sends a message and streams the answer's chunks. Its rules come from the engine's known faults
// (§6.5, [Rpt:bb], v0.19.1): a conversation lives on one engine, which runs one call at a time with one live
// conversation, since interleaved conversations lose state (#2807); a conversation is only closed after a cancel, never
// reused; a conversation takes tools or a schema, never both; multi-token prediction is never used with clone (#4641),
// and nothing here clones.
//
// It also turns a call into the engine's JSON: §6.4's messages as OpenAI-style messages, the tools as OpenAI's function
// tools, the effort as thinking on or off.

package sidecar

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// A conversation's mode: one per conversation (§6.5).
type inferEngineMode string

const (
	inferEngineModePlain  inferEngineMode = "plain"
	inferEngineModeTools  inferEngineMode = "tools"
	inferEngineModeSchema inferEngineMode = "schema"
)

// What a conversation opens with.
type inferEngineConversationConfig struct {
	// The system text, every system message's text joined.
	System string
	// The messages before the one sent, OpenAI-style JSON array; nil for none.
	History json.RawMessage
	Mode    inferEngineMode
	// tools: OpenAI-style function tools, JSON array, their call syntax constrained.
	Tools json.RawMessage
	// schema: the JSON schema the answer follows (LLGuidance).
	Schema json.RawMessage
	// Whether the model reasons (thinking), from the call's effort.
	Thinking bool
}

// One send's arguments.
type inferEngineSendArgs struct {
	// The most tokens the answer may hold; 0 for the model's own maximum.
	MaxOutput int
	// auto, none, required or a tool's name; tools mode only.
	ToolChoice string
	Sampling   *InferSampling
}

// One chunk of a streamed answer: a delta of its text or reasoning, or whole tool calls, which the engine parses before
// it delivers them.
type inferEngineChunk struct {
	Text      string
	Reasoning string
	ToolCalls []*inferEngineToolCall
}

// A tool call as the engine parses it: its name and its arguments, a JSON object.
type inferEngineToolCall struct {
	Name      string
	Arguments json.RawMessage
}

// What loads a model: LiteRT-LM's C API (infer_engine_litert.go), or a test's stand-in.
type inferEngineBackend interface {
	// Loads the library params names, already checked against its pins, and the model into instance engines.
	load(params *inferEngineLoadParams) ([]inferEngineModel, error)
}

// One engine over a loaded model. Not safe for concurrent use: the helper's pool gives an engine one call at a time.
type inferEngineModel interface {
	open(config *inferEngineConversationConfig) (inferEngineConversation, error)
	close()
}

// One conversation on an engine. send and close run on the caller's goroutine one at a time; cancel may run from any
// goroutine while send runs.
type inferEngineConversation interface {
	// Sends message, an OpenAI-style JSON message, streaming the answer's chunks, and returns its usage at its end.
	send(message json.RawMessage, args *inferEngineSendArgs, chunk func(chunk *inferEngineChunk)) (*InferUsage, error)
	// Stops a send in flight, which then returns errInferEngineCanceled; the conversation is then only closed.
	cancel()
	close()
}

// What a send stopped by cancel returns.
var errInferEngineCanceled = errors.New("the engine's call was canceled")

// One OpenAI-style content part.
type inferEngineContentPart struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	MimeType string `json:"mime_type,omitempty"`
	// an image's bytes in base64
	Data string `json:"data,omitempty"`
}

// One OpenAI-style function call in an assistant message.
type inferEngineFunctionCall struct {
	Id       string                      `json:"id,omitempty"`
	Type     string                      `json:"type"`
	Function inferEngineFunctionCallBody `json:"function"`
}

// A function call's name and arguments.
type inferEngineFunctionCallBody struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// One OpenAI-style message, as the engine's conversation takes it.
type inferEngineMessage struct {
	Role       string                     `json:"role"`
	Content    []*inferEngineContentPart  `json:"content,omitempty"`
	ToolCalls  []*inferEngineFunctionCall `json:"tool_calls,omitempty"`
	ToolCallId string                     `json:"tool_call_id,omitempty"`
}

// One OpenAI-style function tool.
type inferEngineTool struct {
	Type     string              `json:"type"`
	Function inferEngineToolBody `json:"function"`
}

// A function tool's name, description and argument schema.
type inferEngineToolBody struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// A tool call's arguments as a JSON object, as the engine takes them: the text itself where it is JSON, else the text
// as a JSON string.
func inferEngineArguments(arguments string) json.RawMessage {
	if arguments != "" && json.Valid([]byte(arguments)) {
		return json.RawMessage(arguments)
	}
	quoted, _ := json.Marshal(arguments)
	return quoted
}

// message as the engine takes it. An assistant's reasoning is not sent back: the engine's thinking channel is its own,
// and a sent-back think prefix confuses long conversations (#3445).
func inferEngineMessageOf(message *InferMessage) (*inferEngineMessage, error) {
	switch message.Role {
	case InferRoleUser, InferRoleAssistant, InferRoleTool:
	default:
		return nil, fmt.Errorf("a %q message among the conversation's turns", message.Role)
	}
	converted := &inferEngineMessage{Role: string(message.Role), ToolCallId: message.ToolCallId}
	for _, part := range message.Parts {
		switch {
		case part == nil:
		case part.Kind == InferPartText:
			converted.Content = append(converted.Content, &inferEngineContentPart{Type: "text", Text: part.Text})
		case part.Kind == InferPartImage:
			converted.Content = append(converted.Content, &inferEngineContentPart{
				Type:     "image",
				MimeType: part.MediaType,
				Data:     base64.StdEncoding.EncodeToString(part.Data),
			})
		default:
			return nil, fmt.Errorf("a part of kind %q", part.Kind)
		}
	}
	for _, call := range message.ToolCalls {
		if call == nil {
			continue
		}
		converted.ToolCalls = append(converted.ToolCalls, &inferEngineFunctionCall{
			Id:       call.Id,
			Type:     "function",
			Function: inferEngineFunctionCallBody{Name: call.Name, Arguments: inferEngineArguments(call.Arguments)},
		})
	}
	return converted, nil
}

// A call's conversation as the engine takes it: the system text, every system message's joined; the turns before the
// last; and the last, which is sent. A call whose last message is not the person's or a tool's has nothing to answer.
func inferEngineConversationOf(messages []*InferMessage) (string, []*inferEngineMessage, *inferEngineMessage, error) {
	system := ""
	turns := []*inferEngineMessage{}
	for _, message := range messages {
		if message == nil {
			continue
		}
		if message.Role == InferRoleSystem {
			if system != "" {
				system += "\n\n"
			}
			system += message.Text()
			continue
		}
		turn, err := inferEngineMessageOf(message)
		if err != nil {
			return "", nil, nil, err
		}
		turns = append(turns, turn)
	}
	if len(turns) == 0 {
		return "", nil, nil, errors.New("no message to answer")
	}
	last := turns[len(turns)-1]
	if last.Role != string(InferRoleUser) && last.Role != string(InferRoleTool) {
		return "", nil, nil, errors.New("the last message is the model's own")
	}
	return system, turns[:len(turns)-1], last, nil
}

// The tools as the engine takes them, a JSON array.
func inferEngineToolsJson(tools []*InferTool) (json.RawMessage, error) {
	converted := []*inferEngineTool{}
	for _, tool := range tools {
		if tool == nil {
			continue
		}
		converted = append(converted, &inferEngineTool{
			Type:     "function",
			Function: inferEngineToolBody{Name: tool.Name, Description: tool.Description, Parameters: tool.Schema},
		})
	}
	return json.Marshal(converted)
}

// A hash of a conversation's turns as the engine holds them, so a call that continues it is told from one that does not:
// its system text and each turn's JSON, reasoning left out as the engine never takes it.
func inferEngineHistoryHash(system string, turns []*inferEngineMessage) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(struct {
		System string                `json:"system"`
		Turns  []*inferEngineMessage `json:"turns"`
	}{System: system, Turns: turns})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
