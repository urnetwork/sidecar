//go:build !ios_extension && !sidecar_http

// The router's request and its events (DESIGN-COMPUTE §6.4): one InferRequest a call, as the Harness and the gateway
// build it, and one stream of InferEvents a request, ending in exactly one end or error (infer_router.go). These are the
// shapes every engine and path speaks: the desktop engine's helper sends its events as JSON lines
// (infer_engine_protocol.go) and an app's host as JSON (§6.5's SidecarLocalInferenceListener), so each type carries its
// JSON names.
//
// A request is its caller's: the router reads it and never changes it, and what it resolves and checks rides beside it
// in an InferCall.
//
// A value here is not safe for concurrent change; the router copies what it keeps.

package sidecar

import (
	"encoding/json"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Who wrote a message (§6.4): the system text, the person or the run, the model, or a tool's result.
type InferRole string

const (
	InferRoleSystem    InferRole = "system"
	InferRoleUser      InferRole = "user"
	InferRoleAssistant InferRole = "assistant"
	InferRoleTool      InferRole = "tool"
)

// What one part of a message holds.
type InferPartKind string

const (
	InferPartText  InferPartKind = "text"
	InferPartImage InferPartKind = "image"
)

// One part of a message's content, in order: text, or an image.
type InferPart struct {
	Kind InferPartKind `json:"kind"`
	// A text part's text.
	Text string `json:"text,omitempty"`
	// An image part's media type, such as image/png, and its bytes, already at the model's input size (§8.5).
	MediaType string `json:"media_type,omitempty"`
	Data      []byte `json:"data,omitempty"`
}

// One message of a request (§6.4): the system text, a user's text and images, an assistant's answer with its reasoning
// and tool calls, or a tool's result naming the call it answers.
type InferMessage struct {
	Role InferRole `json:"role"`
	// The content, in order.
	Parts []*InferPart `json:"parts,omitempty"`
	// An assistant's reasoning, where the model gave it and the request sends it back.
	Reasoning string `json:"reasoning,omitempty"`
	// An assistant's tool calls, each whole.
	ToolCalls []*InferToolCall `json:"tool_calls,omitempty"`
	// A tool result's call id.
	ToolCallId string `json:"tool_call_id,omitempty"`
}

// The message's text parts, joined in order.
func (self *InferMessage) Text() string {
	text := ""
	for _, part := range self.Parts {
		if part != nil && part.Kind == InferPartText {
			text += part.Text
		}
	}
	return text
}

// A tool a request offers the model: its name, what it does, and the JSON schema of its arguments.
type InferTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Schema      json.RawMessage `json:"schema,omitempty"`
}

// A request's sampling: each nil or empty leaves the engine's or provider's own default.
type InferSampling struct {
	Temperature *float64 `json:"temperature,omitempty"`
	TopP        *float64 `json:"top_p,omitempty"`
	Stops       []string `json:"stops,omitempty"`
}

// A gateway call's run handle (§8.9): the grant its token belongs to and the harness process the token binds, which the
// router hands to its mark source for the union of the marks of every run the handle may name. Opaque to the router.
type InferBinding struct {
	// The gateway grant the call's token belongs to (§8.6).
	GrantId Id `json:"grant_id"`
	// The gateway's key for the harness process the token binds; empty for an unbound token, whose calls are checked
	// against every run of the grant's live harness processes.
	Handle string `json:"handle,omitempty"`
}

// Whose budget a call spends (§16.4).
type InferBudgetKind string

const (
	// A gateway grant's budget (§8.6).
	InferBudgetGrant InferBudgetKind = "grant"
	// A Harness agent's budget (§7.4's HarnessBudget).
	InferBudgetHarness InferBudgetKind = "harness"
)

// The budget a call spends (§16.4): a gateway grant's or a Harness agent's, which the device-side budget gate reads.
// Opaque to the router.
type InferBudgetRef struct {
	Kind InferBudgetKind `json:"kind"`
	// The grant's id, or the Harness budget's.
	Id Id `json:"id"`
}

// One call to a model (§6.4).
type InferRequest struct {
	// A canonical name, <provider>-<model>-<effort>, or an alias without the effort (§6.3).
	Model string `json:"model"`
	// The conversation, in order.
	Messages []*InferMessage `json:"messages"`
	// The tools the model may call.
	Tools []*InferTool `json:"tools,omitempty"`
	// auto, none, required or a tool's name; empty reads auto.
	ToolChoice string `json:"tool_choice,omitempty"`
	// A JSON schema the answer must follow, or nil.
	Schema json.RawMessage `json:"schema,omitempty"`
	// The request's effort, none to max (§6.3): an alias runs at it, mapped to the nearest the model lists; a full
	// name's own effort wins over it (Q-INFER-5).
	Reasoning string `json:"reasoning,omitempty"`
	// The most tokens the answer may hold; 0 for the model's own maximum.
	MaxOutput int            `json:"max_output,omitempty"`
	Sampling  *InferSampling `json:"sampling,omitempty"`
	// The run and the agent the call belongs to (DESIGN §5.5), or nil.
	RunId   *Id `json:"run_id,omitempty"`
	AgentId *Id `json:"agent_id,omitempty"`
	// A gateway call's run handle, or nil for a call of the Harness's (§8.9).
	Binding *InferBinding `json:"binding,omitempty"`
	// The budget it spends, or nil (§16.4).
	Budget *InferBudgetRef `json:"budget,omitempty"`
}

// A tool call the model makes: its id, the tool's name, and its arguments as JSON text, whole on tool_call_end and a
// delta on tool_call_args.
type InferToolCall struct {
	Id        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

// What a call used: tokens in, out, read from a cache and spent reasoning, and for a remote call what the broker
// charged, in nano-USD (§9.6).
type InferUsage struct {
	InputTokens     uint64 `json:"input_tokens"`
	OutputTokens    uint64 `json:"output_tokens"`
	CachedTokens    uint64 `json:"cached_tokens"`
	ReasoningTokens uint64 `json:"reasoning_tokens"`
	ChargeNanoUsd   uint64 `json:"charge_nano_usd,omitempty"`
}

// What an event is (§6.4).
type InferEventKind string

const (
	// The engine or path began the call: until it, a local call waits its turn at a shared engine (§6.5).
	InferEventStart InferEventKind = "start"
	// A delta of the answer's text.
	InferEventText InferEventKind = "text"
	// A delta of the model's reasoning.
	InferEventReasoning InferEventKind = "reasoning"
	// A tool call began: its id and name.
	InferEventToolCallStart InferEventKind = "tool_call_start"
	// A delta of a tool call's arguments.
	InferEventToolCallArgs InferEventKind = "tool_call_args"
	// A tool call is whole: its id, name and arguments.
	InferEventToolCallEnd InferEventKind = "tool_call_end"
	// The call's usage, and a remote call's charge.
	InferEventUsage InferEventKind = "usage"
	// A remote call's verified attestation, before its first token (§5.8).
	InferEventAttestation InferEventKind = "attestation"
	// The call failed: the stream's last event.
	InferEventError InferEventKind = "error"
	// The call finished: the stream's last event.
	InferEventEnd InferEventKind = "end"
)

// The kinds an engine or a path may emit; error and end are the router's alone.
var inferEmittedEventKinds = []InferEventKind{
	InferEventStart,
	InferEventText,
	InferEventReasoning,
	InferEventToolCallStart,
	InferEventToolCallArgs,
	InferEventToolCallEnd,
	InferEventUsage,
	InferEventAttestation,
}

// One event of a call's stream (§6.4). Each kind carries only its own fields: Text for text and reasoning, ToolCall
// for the tool call kinds, Usage, Attest and Error for theirs; start and end carry none.
type InferEvent struct {
	Kind     InferEventKind              `json:"kind"`
	Text     string                      `json:"text,omitempty"`
	ToolCall *InferToolCall              `json:"tool_call,omitempty"`
	Usage    *InferUsage                 `json:"usage,omitempty"`
	Attest   *protocol.AttestationResult `json:"attest,omitempty"`
	Error    *InferError                 `json:"error,omitempty"`
}

// The event with only its kind's fields, each copied, so nothing a provider or a server sent rides outside the field
// its kind names; nil for a kind an engine or path may not emit, for a delta with nothing in it, and for a tool call
// event without the call's id.
func inferEventEmitted(event *InferEvent) *InferEvent {
	if event == nil {
		return nil
	}
	switch event.Kind {
	case InferEventStart:
		return &InferEvent{Kind: InferEventStart}
	case InferEventText, InferEventReasoning:
		if event.Text == "" {
			return nil
		}
		return &InferEvent{Kind: event.Kind, Text: event.Text}
	case InferEventToolCallStart, InferEventToolCallArgs, InferEventToolCallEnd:
		if event.ToolCall == nil || event.ToolCall.Id == "" {
			return nil
		}
		toolCall := &InferToolCall{Id: event.ToolCall.Id}
		switch event.Kind {
		case InferEventToolCallStart:
			toolCall.Name = event.ToolCall.Name
		case InferEventToolCallArgs:
			if event.ToolCall.Arguments == "" {
				return nil
			}
			toolCall.Arguments = event.ToolCall.Arguments
		case InferEventToolCallEnd:
			toolCall.Name = event.ToolCall.Name
			toolCall.Arguments = event.ToolCall.Arguments
		}
		return &InferEvent{Kind: event.Kind, ToolCall: toolCall}
	case InferEventUsage:
		if event.Usage == nil {
			return nil
		}
		usage := *event.Usage
		return &InferEvent{Kind: InferEventUsage, Usage: &usage}
	case InferEventAttestation:
		if event.Attest == nil {
			return nil
		}
		return &InferEvent{Kind: InferEventAttestation, Attest: proto.Clone(event.Attest).(*protocol.AttestationResult)}
	}
	// error and end are the router's, and an unknown kind carries nothing a reader knows
	return nil
}

// Roughly the bytes an event holds, for the bound on what a slow reader may leave waiting: its strings, and a fixed
// share for its structure.
func inferEventByteCount(event *InferEvent) int {
	// a pointer, a kind and a small struct or two
	byteCount := 64 + len(event.Text)
	if event.ToolCall != nil {
		byteCount += len(event.ToolCall.Id) + len(event.ToolCall.Name) + len(event.ToolCall.Arguments)
	}
	if event.Attest != nil {
		byteCount += proto.Size(event.Attest)
	}
	if event.Error != nil {
		byteCount += len(event.Error.Message)
	}
	return byteCount
}

// The event next folded into last, where both are deltas of one thing: text after text, reasoning after reasoning, or
// one tool call's arguments after its arguments. nil where they do not fold. Neither is changed: the fold is a new event,
// since last may already be on its way to the reader.
func inferEventFold(last *InferEvent, next *InferEvent) *InferEvent {
	if last == nil || last.Kind != next.Kind {
		return nil
	}
	switch next.Kind {
	case InferEventText, InferEventReasoning:
		return &InferEvent{Kind: next.Kind, Text: last.Text + next.Text}
	case InferEventToolCallArgs:
		if last.ToolCall.Id != next.ToolCall.Id {
			return nil
		}
		return &InferEvent{Kind: next.Kind, ToolCall: &InferToolCall{
			Id:        next.ToolCall.Id,
			Arguments: last.ToolCall.Arguments + next.ToolCall.Arguments,
		}}
	}
	return nil
}
