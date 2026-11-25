//go:build !ios_extension && !sidecar_http

// The Harness's events (DESIGN-COMPUTE §7.6, R-HARN-2, D-HARN-1): Pi 1.5.0's event JSON, field for field, so a
// component that renders a Pi or PiG session renders the Harness's, with sidecar's events after them
// (harness_event_sidecar.go) and the cards other areas own, which register here (RegisterHarnessEventType).
//
// Every event is one JSON object: its type, then the agent's id and a per-agent seq, which the sink stamps, the
// enclave a relayed event came from, then the event's own members in Pi's order (PiG's rpc_events.go, which holds
// Pi's). An event this Harness did not write, a remote Harness's, keeps every member it carried, those this build
// does not know included, and passes them on (harness_json.go). No event carries a disclosure's text, only its id and
// version (D-HARN-10).
//
// An event is a value its emitter builds and the sink stamps once; views read it and never change it.

package sidecar

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// An event's type.
type HarnessEventType string

// Pi 1.5.0's events (json.md, rpc_events.go).
const (
	HarnessEventAgentStart          HarnessEventType = "agent_start"
	HarnessEventAgentEnd            HarnessEventType = "agent_end"
	HarnessEventAgentSettled        HarnessEventType = "agent_settled"
	HarnessEventTurnStart           HarnessEventType = "turn_start"
	HarnessEventTurnEnd             HarnessEventType = "turn_end"
	HarnessEventMessageStart        HarnessEventType = "message_start"
	HarnessEventMessageUpdate       HarnessEventType = "message_update"
	HarnessEventMessageEnd          HarnessEventType = "message_end"
	HarnessEventToolExecutionStart  HarnessEventType = "tool_execution_start"
	HarnessEventToolExecutionUpdate HarnessEventType = "tool_execution_update"
	HarnessEventToolExecutionEnd    HarnessEventType = "tool_execution_end"
	HarnessEventQueueUpdate         HarnessEventType = "queue_update"
	HarnessEventCompactionStart     HarnessEventType = "compaction_start"
	HarnessEventCompactionEnd       HarnessEventType = "compaction_end"
	HarnessEventAutoRetryStart      HarnessEventType = "auto_retry_start"
	HarnessEventAutoRetryEnd        HarnessEventType = "auto_retry_end"
)

// message_update's nested assistantMessageEvent types (json.md).
const (
	HarnessAssistantEventTextStart     = "text_start"
	HarnessAssistantEventTextDelta     = "text_delta"
	HarnessAssistantEventTextEnd       = "text_end"
	HarnessAssistantEventThinkingStart = "thinking_start"
	HarnessAssistantEventThinkingDelta = "thinking_delta"
	HarnessAssistantEventThinkingEnd   = "thinking_end"
	HarnessAssistantEventToolCallStart = "toolcall_start"
	HarnessAssistantEventToolCallDelta = "toolcall_delta"
	HarnessAssistantEventToolCallEnd   = "toolcall_end"
)

// compaction_start's reasons.
const (
	HarnessCompactionManual    = "manual"
	HarnessCompactionThreshold = "threshold"
	HarnessCompactionOverflow  = "overflow"
)

var (
	// An event whose type no file registered (RegisterHarnessEventType): refused at emit.
	ErrHarnessEventUnregistered = errors.New("harness event type not registered")
	// An event the sink cannot take: nil, or with no type.
	ErrHarnessEventInvalid = errors.New("harness event is malformed")
)

// Where an event type comes from.
type harnessEventOrigin int

const (
	// Pi's union, field for field.
	harnessEventOriginPi harnessEventOrigin = iota + 1
	// sidecar's own, after Pi's (§7.6).
	harnessEventOriginSidecar
	// a card another area owns, registered from its own file.
	harnessEventOriginCard
)

// How a terminal shows a registered card (§7.11): its lines, untrusted text in them already sanitized by the card's
// own renderer, which HARN-M11-09's renderer prints as given.
type HarnessEventTerminalRender func(event *HarnessEvent) ([]string, error)

// One registered type.
type harnessEventRegistration struct {
	origin harnessEventOrigin
	// a card's terminal rendering; Pi's and sidecar's own the renderer draws itself
	render HarnessEventTerminalRender
}

// Every event type the Harness emits: Pi's and sidecar's here, each card from its owner's file. Written at
// declaration and during the package's init, so read without a lock after it.
var harnessEventTypes = map[HarnessEventType]*harnessEventRegistration{
	HarnessEventAgentStart:          {origin: harnessEventOriginPi},
	HarnessEventAgentEnd:            {origin: harnessEventOriginPi},
	HarnessEventAgentSettled:        {origin: harnessEventOriginPi},
	HarnessEventTurnStart:           {origin: harnessEventOriginPi},
	HarnessEventTurnEnd:             {origin: harnessEventOriginPi},
	HarnessEventMessageStart:        {origin: harnessEventOriginPi},
	HarnessEventMessageUpdate:       {origin: harnessEventOriginPi},
	HarnessEventMessageEnd:          {origin: harnessEventOriginPi},
	HarnessEventToolExecutionStart:  {origin: harnessEventOriginPi},
	HarnessEventToolExecutionUpdate: {origin: harnessEventOriginPi},
	HarnessEventToolExecutionEnd:    {origin: harnessEventOriginPi},
	HarnessEventQueueUpdate:         {origin: harnessEventOriginPi},
	HarnessEventCompactionStart:     {origin: harnessEventOriginPi},
	HarnessEventCompactionEnd:       {origin: harnessEventOriginPi},
	HarnessEventAutoRetryStart:      {origin: harnessEventOriginPi},
	HarnessEventAutoRetryEnd:        {origin: harnessEventOriginPi},

	HarnessEventApprovalPending:  {origin: harnessEventOriginSidecar},
	HarnessEventApprovalResolved: {origin: harnessEventOriginSidecar},
	HarnessEventAttestation:      {origin: harnessEventOriginSidecar},
	HarnessEventUsage:            {origin: harnessEventOriginSidecar},
	HarnessEventAgentSpawned:     {origin: harnessEventOriginSidecar},
	HarnessEventAgentExited:      {origin: harnessEventOriginSidecar},
	HarnessEventAttachStatus:     {origin: harnessEventOriginSidecar},
	HarnessEventUiRequest:        {origin: harnessEventOriginSidecar},
	HarnessEventUiResponse:       {origin: harnessEventOriginSidecar},
}

// Registers a card another area owns (thread_message, mail_summary, calendar_event, connection, enclave_status,
// support_update) with its terminal rendering, from an init function in the area's own file, as registerMcpTools
// does. A name registered twice, Pi's and sidecar's own among them, an empty name or a nil rendering is a build error,
// which panics.
func RegisterHarnessEventType(name HarnessEventType, render HarnessEventTerminalRender) {
	if _, registered := harnessEventTypes[name]; name == "" || registered || render == nil {
		panic(fmt.Sprintf("harness event type %q registered twice or without a terminal rendering", name))
	}
	harnessEventTypes[name] = &harnessEventRegistration{origin: harnessEventOriginCard, render: render}
}

// Whether name is a registered type.
func HarnessEventTypeRegistered(name HarnessEventType) bool {
	_, registered := harnessEventTypes[name]
	return registered
}

// A registered card's terminal rendering, or nil for Pi's and sidecar's own and for an unregistered name.
func HarnessEventTerminalRendering(name HarnessEventType) HarnessEventTerminalRender {
	registration, registered := harnessEventTypes[name]
	if !registered {
		return nil
	}
	return registration.render
}

// Whether name is one of Pi 1.5.0's events.
func harnessEventIsPi(name HarnessEventType) bool {
	registration, registered := harnessEventTypes[name]
	return registered && registration.origin == harnessEventOriginPi
}

// What any area emits through: the Harness. Safe for concurrent use.
type HarnessEventSink interface {
	// Emits event as agentId's: stamps its agent and its next seq and hands it to the agent's subscribers, refusing a
	// type no file registered and a malformed event. The sink keeps the event; the caller does not change it after.
	Emit(agentId Id, event *HarnessEvent) error
}

// One event: its type, the envelope the sink stamps, and its own members in order.
type HarnessEvent struct {
	Type HarnessEventType
	// The agent's id, stamped by the sink.
	Agent string
	// The agent's sequence, from 1, stamped by the sink.
	Seq uint64
	// The enclave a relayed event came from (§7.10); empty for this Harness's own.
	Enclave string

	fields harnessPiObject
}

// An event of type with no members yet.
func NewHarnessEvent(eventType HarnessEventType) *HarnessEvent {
	return &HarnessEvent{Type: eventType}
}

// The member named name, as written, or nil.
func (self *HarnessEvent) Field(name string) json.RawMessage {
	return self.fields.get(name)
}

// Decodes the member named name into v; false where there is none or it does not decode.
func (self *HarnessEvent) Decode(name string, v any) bool {
	return self.fields.decode(name, v)
}

// The members' names, in order, the envelope's aside.
func (self *HarnessEvent) FieldNames() []string {
	return self.fields.names()
}

// Sets the member named name where it stands, or appends it. A name the envelope holds is refused.
func (self *HarnessEvent) SetField(name string, value any) error {
	switch name {
	case "type", "agent", "seq", "enclave":
		return fmt.Errorf("%w: %s is the envelope's", ErrHarnessEventInvalid, name)
	}
	return self.fields.set(name, value)
}

// Sets the member named name to raw, which must be JSON.
func (self *HarnessEvent) SetFieldRaw(name string, raw json.RawMessage) error {
	compacted, err := harnessPiCompact(raw)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrHarnessEventInvalid, name, err)
	}
	switch name {
	case "type", "agent", "seq", "enclave":
		return fmt.Errorf("%w: %s is the envelope's", ErrHarnessEventInvalid, name)
	}
	self.fields.setRaw(name, compacted)
	return nil
}

// A copy sharing nothing.
func (self *HarnessEvent) Clone() *HarnessEvent {
	clone := *self
	clone.fields = self.fields.clone()
	return &clone
}

// The event as Pi writes a line: JSON.stringify's bytes, which every view that writes the stream (the sdk's OnEvent,
// `ur harness --json`, the RPC link) sends. json.Marshal of an event gives the same value with Go's HTML escapes.
func (self *HarnessEvent) Json() ([]byte, error) {
	return self.MarshalJSON()
}

// The event's JSON: type, then agent, seq and enclave where set, then its members in order.
func (self *HarnessEvent) MarshalJSON() ([]byte, error) {
	object := harnessPiObject{}
	if err := object.set("type", self.Type); err != nil {
		return nil, err
	}
	if self.Agent != "" {
		object.set("agent", self.Agent)
	}
	if self.Seq != 0 {
		object.set("seq", self.Seq)
	}
	if self.Enclave != "" {
		object.set("enclave", self.Enclave)
	}
	object = append(object, self.fields...)
	return object.MarshalJSON()
}

// Reads an event, keeping every member as written, those this build does not know included. Refuses one with no
// type; an unregistered type reads, and is refused only at emit.
func (self *HarnessEvent) UnmarshalJSON(data []byte) error {
	object := harnessPiObject{}
	if err := object.UnmarshalJSON(data); err != nil {
		return err
	}
	event := HarnessEvent{}
	for _, field := range object {
		switch field.name {
		case "type":
			if json.Unmarshal(field.value, &event.Type) != nil {
				return fmt.Errorf("%w: its type is no string", ErrHarnessEventInvalid)
			}
		case "agent":
			if json.Unmarshal(field.value, &event.Agent) != nil {
				return fmt.Errorf("%w: its agent is no string", ErrHarnessEventInvalid)
			}
		case "seq":
			if json.Unmarshal(field.value, &event.Seq) != nil {
				return fmt.Errorf("%w: its seq is no count", ErrHarnessEventInvalid)
			}
		case "enclave":
			if json.Unmarshal(field.value, &event.Enclave) != nil {
				return fmt.Errorf("%w: its enclave is no string", ErrHarnessEventInvalid)
			}
		default:
			event.fields = append(event.fields, field)
		}
	}
	if event.Type == "" {
		return fmt.Errorf("%w: no type", ErrHarnessEventInvalid)
	}
	*self = event
	return nil
}

// An event built from members in order, for the constructors below, which only fail on a value that does not encode.
func newHarnessEventOf(eventType HarnessEventType, members ...any) *HarnessEvent {
	event := NewHarnessEvent(eventType)
	for i := 0; i+1 < len(members); i += 2 {
		name := members[i].(string)
		if raw, ok := members[i+1].(json.RawMessage); ok {
			if raw == nil {
				raw = json.RawMessage("null")
			}
			event.fields.setRaw(name, raw)
			continue
		}
		if err := event.fields.set(name, members[i+1]); err != nil {
			// a value that does not encode stays out, and the event says so rather than carry a guess
			event.fields.set(name, nil)
		}
	}
	return event
}

// agent_start.
func NewHarnessAgentStartEvent() *HarnessEvent {
	return NewHarnessEvent(HarnessEventAgentStart)
}

// agent_end: the messages the low-level run generated, and whether a retry follows.
func NewHarnessAgentEndEvent(messages []*HarnessPiMessage, willRetry bool) *HarnessEvent {
	if messages == nil {
		messages = []*HarnessPiMessage{}
	}
	return newHarnessEventOf(HarnessEventAgentEnd, "messages", messages, "willRetry", willRetry)
}

// The Harness's stop reasons, which agent_settled carries beside Pi's aborted (§7.4).
const (
	// The run's work ended: no tool call, steer or follow-up remained.
	HarnessStopEnded = "ended"
	// Abort ended the turn.
	HarnessStopAborted = "aborted"
	// MaxTurnCount turns ran for one prompt.
	HarnessStopMaxTurns = "max_turns"
	// The model failed and the person chose nothing more, or no one was attached to choose.
	HarnessStopError = "error"
	// A none model waits for a disclosure no attached person acknowledged (§2.8): the reason names it.
	HarnessStopDisclosureRequired = "disclosure_required"
	// The app left the foreground and the agent paused at an item boundary (§6.5, §20.7).
	HarnessStopBackgrounded = "backgrounded"
)

// agent_settled: no automatic work remains. aborted is Pi's; stopReason is the Harness's (§7.4), appended where
// set, which a Pi reader ignores.
func NewHarnessAgentSettledEvent(aborted bool, stopReason string) *HarnessEvent {
	event := newHarnessEventOf(HarnessEventAgentSettled, "aborted", aborted)
	if stopReason != "" {
		event.fields.set("stopReason", stopReason)
	}
	return event
}

// turn_start, which Pi's wire writes bare.
func NewHarnessTurnStartEvent() *HarnessEvent {
	return NewHarnessEvent(HarnessEventTurnStart)
}

// turn_end: the assistant message and the tool results it led to.
func NewHarnessTurnEndEvent(message *HarnessPiMessage, toolResults []*HarnessPiMessage) *HarnessEvent {
	if toolResults == nil {
		toolResults = []*HarnessPiMessage{}
	}
	return newHarnessEventOf(HarnessEventTurnEnd, "message", message, "toolResults", toolResults)
}

// message_start: the message as it begins.
func NewHarnessMessageStartEvent(message *HarnessPiMessage) *HarnessEvent {
	return newHarnessEventOf(HarnessEventMessageStart, "message", message)
}

// message_end: the whole message, authoritative, so a view that dropped an update loses nothing.
func NewHarnessMessageEndEvent(message *HarnessPiMessage) *HarnessEvent {
	return newHarnessEventOf(HarnessEventMessageEnd, "message", message)
}

// One of message_update's nested events (json.md): its type, the content block's index, and the members its type
// carries.
type HarnessAssistantMessageEvent struct {
	Type         string
	ContentIndex int
	// a delta's text, a text or thinking end's content
	Delta   string
	Content string
	// a toolcall_start's call id and tool name, a toolcall_end's whole call
	Id       string
	ToolName string
	ToolCall *HarnessPiToolCall
}

// The nested event in Pi's member order (rpc_events.go's rpcAssistantEventFields and rpcMessageUpdate).
func (self *HarnessAssistantMessageEvent) object() harnessPiObject {
	object := harnessPiObject{}
	object.set("type", self.Type)
	object.set("contentIndex", self.ContentIndex)
	switch self.Type {
	case HarnessAssistantEventTextDelta, HarnessAssistantEventThinkingDelta, HarnessAssistantEventToolCallDelta:
		object.set("delta", self.Delta)
	case HarnessAssistantEventTextEnd, HarnessAssistantEventThinkingEnd:
		object.set("content", self.Content)
	case HarnessAssistantEventToolCallStart:
		object.set("id", self.Id)
		object.set("toolName", self.ToolName)
	case HarnessAssistantEventToolCallEnd:
		toolCall := self.ToolCall
		if toolCall == nil {
			toolCall = &HarnessPiToolCall{}
		}
		encoded, _ := NewHarnessPiToolCallBlock(toolCall).MarshalJSON()
		object.setRaw("toolCall", encoded)
	}
	return object
}

// message_update: the assistant message's usage so far and one nested event, deltas only (no partial).
func NewHarnessMessageUpdateEvent(usage *HarnessPiUsage, assistantEvent *HarnessAssistantMessageEvent) *HarnessEvent {
	if usage == nil {
		usage = &HarnessPiUsage{}
	}
	nested, _ := assistantEvent.object().MarshalJSON()
	return newHarnessEventOf(HarnessEventMessageUpdate, "usage", usage, "assistantMessageEvent", json.RawMessage(nested))
}

// The nested event of a message_update, or nil.
func (self *HarnessEvent) AssistantMessageEvent() *HarnessAssistantMessageEvent {
	if self.Type != HarnessEventMessageUpdate {
		return nil
	}
	object := harnessPiObject{}
	if !self.fields.decode("assistantMessageEvent", &object) {
		return nil
	}
	nested := &HarnessAssistantMessageEvent{
		Type:     object.str("type"),
		Delta:    object.str("delta"),
		Content:  object.str("content"),
		Id:       object.str("id"),
		ToolName: object.str("toolName"),
	}
	object.decode("contentIndex", &nested.ContentIndex)
	block := &HarnessPiBlock{}
	if object.decode("toolCall", block) {
		nested.ToolCall = block.ToolCall()
	}
	return nested
}

// The message a message_start, message_end or turn_end carries, or nil.
func (self *HarnessEvent) Message() *HarnessPiMessage {
	message := &HarnessPiMessage{}
	if !self.fields.decode("message", message) {
		return nil
	}
	return message
}

// What a tool returned (Pi's AgentToolResult): the content the model reads, and details for the UI, nil for none.
type HarnessToolResultPayload struct {
	Content []*HarnessPiBlock
	Details json.RawMessage
}

// The payload in Pi's member order: content, then details where set.
func (self *HarnessToolResultPayload) raw() json.RawMessage {
	object := harnessPiObject{}
	content := self.Content
	if content == nil {
		content = []*HarnessPiBlock{}
	}
	object.set("content", content)
	if self.Details != nil {
		if compacted, err := harnessPiCompact(self.Details); err == nil {
			object.setRaw("details", compacted)
		}
	}
	encoded, _ := object.MarshalJSON()
	return encoded
}

// args as the event carries them: the model's JSON, or an empty object where there is none or it does not parse.
func harnessEventArgs(args json.RawMessage) json.RawMessage {
	if args == nil {
		return json.RawMessage("{}")
	}
	compacted, err := harnessPiCompact(args)
	if err != nil {
		encoded, _ := harnessPiMarshal(string(args))
		return encoded
	}
	return compacted
}

// tool_execution_start: the call's id, the tool and its arguments.
func NewHarnessToolExecutionStartEvent(toolCallId string, toolName string, args json.RawMessage) *HarnessEvent {
	return newHarnessEventOf(HarnessEventToolExecutionStart, "toolCallId", toolCallId, "toolName", toolName,
		"args", harnessEventArgs(args))
}

// tool_execution_update: the tool's partial result so far.
func NewHarnessToolExecutionUpdateEvent(toolCallId string, toolName string, args json.RawMessage, partial *HarnessToolResultPayload) *HarnessEvent {
	return newHarnessEventOf(HarnessEventToolExecutionUpdate, "toolCallId", toolCallId, "toolName", toolName,
		"args", harnessEventArgs(args), "partialResult", partial.raw())
}

// tool_execution_end: the final result, whether the call failed, and how long the tool ran where it ran.
func NewHarnessToolExecutionEndEvent(toolCallId string, toolName string, result *HarnessToolResultPayload, isError bool, durationMs *int64) *HarnessEvent {
	event := newHarnessEventOf(HarnessEventToolExecutionEnd, "toolCallId", toolCallId, "toolName", toolName,
		"result", result.raw(), "isError", isError)
	if durationMs != nil {
		event.fields.set("durationMs", *durationMs)
	}
	return event
}

// queue_update: both queues whole.
func NewHarnessQueueUpdateEvent(steering []string, followUp []string) *HarnessEvent {
	if steering == nil {
		steering = []string{}
	}
	if followUp == nil {
		followUp = []string{}
	}
	return newHarnessEventOf(HarnessEventQueueUpdate, "steering", steering, "followUp", followUp)
}

// compaction_start: why compaction began.
func NewHarnessCompactionStartEvent(reason string) *HarnessEvent {
	return newHarnessEventOf(HarnessEventCompactionStart, "reason", reason)
}

// A compaction's result (json.md's compaction_end result).
type HarnessCompactionResult struct {
	Summary              string
	FirstKeptEntryId     string
	TokensBefore         int64
	EstimatedTokensAfter int64
	Usage                *HarnessPiUsage
}

// compaction_end: its result where it succeeded, whether it aborted, whether a retry follows, and why it failed.
func NewHarnessCompactionEndEvent(reason string, result *HarnessCompactionResult, aborted bool, willRetry bool, errorMessage string) *HarnessEvent {
	event := newHarnessEventOf(HarnessEventCompactionEnd, "reason", reason)
	if result != nil {
		object := harnessPiObject{}
		object.set("summary", result.Summary)
		object.set("firstKeptEntryId", result.FirstKeptEntryId)
		object.set("tokensBefore", result.TokensBefore)
		object.set("estimatedTokensAfter", result.EstimatedTokensAfter)
		if result.Usage != nil {
			object.set("usage", result.Usage)
		}
		encoded, _ := object.MarshalJSON()
		event.fields.setRaw("result", encoded)
	}
	event.fields.set("aborted", aborted)
	event.fields.set("willRetry", willRetry)
	if errorMessage != "" {
		event.fields.set("errorMessage", errorMessage)
	}
	return event
}

// auto_retry_start: the attempt, the most there will be, the wait and why.
func NewHarnessAutoRetryStartEvent(attempt int, maxAttempts int, delayMs int64, errorMessage string) *HarnessEvent {
	return newHarnessEventOf(HarnessEventAutoRetryStart, "attempt", attempt, "maxAttempts", maxAttempts,
		"delayMs", delayMs, "errorMessage", errorMessage)
}

// auto_retry_end: whether the retry succeeded, its attempt, and the final error where it did not.
func NewHarnessAutoRetryEndEvent(success bool, attempt int, finalError string) *HarnessEvent {
	event := newHarnessEventOf(HarnessEventAutoRetryEnd, "success", success, "attempt", attempt)
	if finalError != "" {
		event.fields.set("finalError", finalError)
	}
	return event
}

// The stamp a sink puts on each event: the agent's id and its next seq, from 1, once per event. Safe for
// concurrent use.
type harnessEventStamper struct {
	stateLock sync.Mutex
	agentSeqs map[Id]uint64
}

func newHarnessEventStamper() *harnessEventStamper {
	return &harnessEventStamper{agentSeqs: map[Id]uint64{}}
}

// Stamps event as agentId's next, refusing a malformed event and a type no file registered (the event is then left
// as it was).
func (self *harnessEventStamper) stamp(agentId Id, event *HarnessEvent) error {
	if event == nil || event.Type == "" {
		return ErrHarnessEventInvalid
	}
	if !HarnessEventTypeRegistered(event.Type) {
		return fmt.Errorf("%w: %s", ErrHarnessEventUnregistered, event.Type)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	seq := self.agentSeqs[agentId] + 1
	self.agentSeqs[agentId] = seq
	event.Agent = agentId.String()
	event.Seq = seq
	return nil
}
