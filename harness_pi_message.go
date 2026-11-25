//go:build !ios_extension && !sidecar_http

// Pi 1.5.0's AgentMessage values and their content blocks (message-types.md, DESIGN-COMPUTE §7.3, §7.6), which the
// Harness's events carry and its session entries hold: system, user, assistant, toolResult, bashExecution, custom,
// branchSummary and compactionSummary messages, with text, thinking, image and toolCall blocks. Each is built here in
// the member order Pi writes (PiG's rpc_events.go, which holds Pi's own), and one read from another writer keeps
// every member as written, its unknown ones included (harness_json.go).
//
// A message or block is a value: a change goes to a copy (clone) where another holds it.

package sidecar

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Who wrote a message (message-types.md).
type HarnessPiRole string

const (
	HarnessPiRoleSystem            HarnessPiRole = "system"
	HarnessPiRoleUser              HarnessPiRole = "user"
	HarnessPiRoleAssistant         HarnessPiRole = "assistant"
	HarnessPiRoleToolResult        HarnessPiRole = "toolResult"
	HarnessPiRoleBashExecution     HarnessPiRole = "bashExecution"
	HarnessPiRoleCustom            HarnessPiRole = "custom"
	HarnessPiRoleBranchSummary     HarnessPiRole = "branchSummary"
	HarnessPiRoleCompactionSummary HarnessPiRole = "compactionSummary"
)

// An assistant message's stop reasons (message-types.md).
const (
	HarnessPiStopPending = "pending"
	HarnessPiStopStop    = "stop"
	HarnessPiStopLength  = "length"
	HarnessPiStopToolUse = "toolUse"
	HarnessPiStopError   = "error"
	HarnessPiStopAborted = "aborted"
)

// A content block's types.
const (
	HarnessPiBlockText     = "text"
	HarnessPiBlockThinking = "thinking"
	HarnessPiBlockImage    = "image"
	HarnessPiBlockToolCall = "toolCall"
)

// The api the Harness's assistant messages name: its own router (§6.4), whatever path served the call.
const HarnessPiApi = "ur-router"

// Pi's Usage (message-types.md), in the member order OpenAI's provider writes, reasoning before totalTokens.
type HarnessPiUsage struct {
	Input      int64 `json:"input"`
	Output     int64 `json:"output"`
	CacheRead  int64 `json:"cacheRead"`
	CacheWrite int64 `json:"cacheWrite"`
	// Already counted in Output; nil where the model reported none.
	Reasoning   *int64             `json:"reasoning,omitempty"`
	TotalTokens int64              `json:"totalTokens"`
	Cost        HarnessPiUsageCost `json:"cost"`
}

// Pi's usage cost, in US dollars.
type HarnessPiUsageCost struct {
	Input      float64 `json:"input"`
	Output     float64 `json:"output"`
	CacheRead  float64 `json:"cacheRead"`
	CacheWrite float64 `json:"cacheWrite"`
	Total      float64 `json:"total"`
}

// A tool call a model made: its id, the tool's name and its arguments, a JSON object as the model wrote it.
type HarnessPiToolCall struct {
	Id        string
	Name      string
	Arguments json.RawMessage
}

// One content block, its members in Pi's order.
type HarnessPiBlock struct {
	object harnessPiObject
}

// A text block.
func NewHarnessPiTextBlock(text string) *HarnessPiBlock {
	block := &HarnessPiBlock{}
	block.object.set("type", HarnessPiBlockText)
	block.object.set("text", text)
	return block
}

// A thinking block, the model's reasoning as streamed.
func NewHarnessPiThinkingBlock(thinking string) *HarnessPiBlock {
	block := &HarnessPiBlock{}
	block.object.set("type", HarnessPiBlockThinking)
	block.object.set("thinking", thinking)
	return block
}

// An image block, data base64-encoded as Pi holds it.
func NewHarnessPiImageBlock(data []byte, mimeType string) *HarnessPiBlock {
	block := &HarnessPiBlock{}
	block.object.set("type", HarnessPiBlockImage)
	block.object.set("data", base64.StdEncoding.EncodeToString(data))
	block.object.set("mimeType", mimeType)
	return block
}

// A toolCall block. arguments that are not a JSON object are kept as written, as Pi keeps them, and the call fails
// when it runs.
func NewHarnessPiToolCallBlock(toolCall *HarnessPiToolCall) *HarnessPiBlock {
	block := &HarnessPiBlock{}
	block.object.set("type", HarnessPiBlockToolCall)
	block.object.set("id", toolCall.Id)
	block.object.set("name", toolCall.Name)
	arguments := toolCall.Arguments
	if compacted, err := harnessPiCompact(arguments); err == nil {
		arguments = compacted
	} else {
		// what the model wrote, kept as a string so the block stays JSON
		arguments, _ = harnessPiMarshal(string(toolCall.Arguments))
	}
	block.object.setRaw("arguments", arguments)
	return block
}

// The block's type.
func (self *HarnessPiBlock) Type() string {
	return self.object.str("type")
}

// A text block's text, or a thinking block's thinking; empty for the rest.
func (self *HarnessPiBlock) Text() string {
	switch self.Type() {
	case HarnessPiBlockText:
		return self.object.str("text")
	case HarnessPiBlockThinking:
		return self.object.str("thinking")
	}
	return ""
}

// A toolCall block's call, or nil.
func (self *HarnessPiBlock) ToolCall() *HarnessPiToolCall {
	if self.Type() != HarnessPiBlockToolCall {
		return nil
	}
	return &HarnessPiToolCall{
		Id:        self.object.str("id"),
		Name:      self.object.str("name"),
		Arguments: self.object.get("arguments"),
	}
}

// An image block's bytes and media type, or nil.
func (self *HarnessPiBlock) Image() ([]byte, string) {
	if self.Type() != HarnessPiBlockImage {
		return nil, ""
	}
	data, err := base64.StdEncoding.DecodeString(self.object.str("data"))
	if err != nil {
		return nil, ""
	}
	return data, self.object.str("mimeType")
}

// A copy.
func (self *HarnessPiBlock) clone() *HarnessPiBlock {
	return &HarnessPiBlock{object: self.object.clone()}
}

// The block in Pi's member order.
func (self *HarnessPiBlock) MarshalJSON() ([]byte, error) {
	return self.object.MarshalJSON()
}

// Reads a block, keeping every member as written.
func (self *HarnessPiBlock) UnmarshalJSON(data []byte) error {
	return self.object.UnmarshalJSON(data)
}

// One AgentMessage, its members in Pi's order.
type HarnessPiMessage struct {
	object harnessPiObject
}

// A user message: content a string, or blocks where there are images (the text first).
func NewHarnessPiUserMessage(text string, images []*HarnessPiBlock, timestampMs int64) *HarnessPiMessage {
	message := &HarnessPiMessage{}
	message.object.set("role", HarnessPiRoleUser)
	if len(images) == 0 {
		message.object.set("content", text)
	} else {
		blocks := []*HarnessPiBlock{NewHarnessPiTextBlock(text)}
		blocks = append(blocks, images...)
		message.object.set("content", blocks)
	}
	message.object.set("timestamp", timestampMs)
	return message
}

// What an assistant message holds (message-types.md), which NewHarnessPiAssistantMessage writes in Pi's order.
type HarnessPiAssistant struct {
	Content []*HarnessPiBlock
	// The api, provider and canonical model name (§6.3) that answered.
	Api      string
	Provider string
	Model    string
	Usage    *HarnessPiUsage
	// One of the stop reasons; empty while it streams is written as pending.
	StopReason  string
	TimestampMs int64
	// A failed call's error, in the router's words (§6.4).
	ErrorMessage string
	// How long the call took, where measured.
	DurationMs *int64
	// The effort it ran at (§6.3), Pi's thinkingLevel.
	ThinkingLevel string
}

// An assistant message, in Pi's member order (rpc_events.go's rpcAgentMessage).
func NewHarnessPiAssistantMessage(assistant *HarnessPiAssistant) *HarnessPiMessage {
	message := &HarnessPiMessage{}
	message.object.set("role", HarnessPiRoleAssistant)
	content := assistant.Content
	if content == nil {
		content = []*HarnessPiBlock{}
	}
	message.object.set("content", content)
	message.object.set("api", assistant.Api)
	message.object.set("provider", assistant.Provider)
	message.object.set("model", assistant.Model)
	usage := assistant.Usage
	if usage == nil {
		usage = &HarnessPiUsage{}
	}
	message.object.set("usage", usage)
	stopReason := assistant.StopReason
	if stopReason == "" {
		stopReason = HarnessPiStopPending
	}
	message.object.set("stopReason", stopReason)
	message.object.set("timestamp", assistant.TimestampMs)
	if assistant.ErrorMessage != "" {
		message.object.set("errorMessage", assistant.ErrorMessage)
	}
	if assistant.DurationMs != nil {
		message.object.set("durationMs", *assistant.DurationMs)
	}
	if assistant.ThinkingLevel != "" {
		message.object.set("thinkingLevel", assistant.ThinkingLevel)
	}
	return message
}

// A tool's result message. details, JSON for the UI, nil for none; an image block may sit beside the text.
func NewHarnessPiToolResultMessage(toolCallId string, toolName string, content []*HarnessPiBlock, details json.RawMessage, isError bool, timestampMs int64) *HarnessPiMessage {
	message := &HarnessPiMessage{}
	message.object.set("role", HarnessPiRoleToolResult)
	message.object.set("toolCallId", toolCallId)
	message.object.set("toolName", toolName)
	if content == nil {
		content = []*HarnessPiBlock{}
	}
	message.object.set("content", content)
	if details != nil {
		if compacted, err := harnessPiCompact(details); err == nil {
			message.object.setRaw("details", compacted)
		}
	}
	message.object.set("isError", isError)
	message.object.set("timestamp", timestampMs)
	return message
}

// One tool a system message declares (message-types.md's toolsAdded): its name, description and JSON schema.
type HarnessPiTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// A named section of a system message, in order (Pi's sections).
type HarnessPiSection struct {
	Name string
	Text string
}

// Pi's versioned system message: content empty, the prompt in named sections, and the tools it adds. The Harness's
// first one carries every section and tool; a later one patches by name.
func NewHarnessPiSystemMessage(sections []*HarnessPiSection, tools []*HarnessPiTool, timestampMs int64) *HarnessPiMessage {
	message := &HarnessPiMessage{}
	message.object.set("role", HarnessPiRoleSystem)
	message.object.set("content", "")
	sectionObject := harnessPiObject{}
	for _, section := range sections {
		sectionObject.set(section.Name, section.Text)
	}
	encoded, _ := sectionObject.MarshalJSON()
	message.object.setRaw("sections", encoded)
	if tools == nil {
		tools = []*HarnessPiTool{}
	}
	message.object.set("toolsAdded", tools)
	message.object.set("timestamp", timestampMs)
	return message
}

// A custom message (Pi's extension-injected context), which the model reads as user text.
func NewHarnessPiCustomMessage(customType string, content string, display bool, details json.RawMessage, timestampMs int64) *HarnessPiMessage {
	message := &HarnessPiMessage{}
	message.object.set("role", HarnessPiRoleCustom)
	message.object.set("customType", customType)
	message.object.set("content", content)
	message.object.set("display", display)
	if details != nil {
		if compacted, err := harnessPiCompact(details); err == nil {
			message.object.setRaw("details", compacted)
		}
	}
	message.object.set("timestamp", timestampMs)
	return message
}

// A compaction's summary as a context message, built from a compaction entry.
func NewHarnessPiCompactionSummaryMessage(summary string, tokensBefore int64, timestampMs int64) *HarnessPiMessage {
	message := &HarnessPiMessage{}
	message.object.set("role", HarnessPiRoleCompactionSummary)
	message.object.set("summary", summary)
	message.object.set("tokensBefore", tokensBefore)
	message.object.set("timestamp", timestampMs)
	return message
}

// The message's role.
func (self *HarnessPiMessage) Role() HarnessPiRole {
	return HarnessPiRole(self.object.str("role"))
}

// The content's blocks; a string content reads as one text block.
func (self *HarnessPiMessage) Blocks() []*HarnessPiBlock {
	content := self.object.get("content")
	if content == nil {
		return nil
	}
	text := ""
	if json.Unmarshal(content, &text) == nil {
		return []*HarnessPiBlock{NewHarnessPiTextBlock(text)}
	}
	blocks := []*HarnessPiBlock{}
	if json.Unmarshal(content, &blocks) != nil {
		return nil
	}
	return blocks
}

// The text the content's text blocks hold, joined in order; a compaction or branch summary's summary.
func (self *HarnessPiMessage) Text() string {
	switch self.Role() {
	case HarnessPiRoleCompactionSummary, HarnessPiRoleBranchSummary:
		return self.object.str("summary")
	case HarnessPiRoleBashExecution:
		return self.object.str("output")
	}
	parts := []string{}
	for _, block := range self.Blocks() {
		if block.Type() == HarnessPiBlockText {
			parts = append(parts, block.Text())
		}
	}
	return strings.Join(parts, "")
}

// An assistant message's tool calls, in order.
func (self *HarnessPiMessage) ToolCalls() []*HarnessPiToolCall {
	toolCalls := []*HarnessPiToolCall{}
	for _, block := range self.Blocks() {
		if toolCall := block.ToolCall(); toolCall != nil {
			toolCalls = append(toolCalls, toolCall)
		}
	}
	return toolCalls
}

// An assistant message's stop reason.
func (self *HarnessPiMessage) StopReason() string {
	return self.object.str("stopReason")
}

// An assistant message's model, its canonical name.
func (self *HarnessPiMessage) Model() string {
	return self.object.str("model")
}

// An assistant message's usage, or nil.
func (self *HarnessPiMessage) Usage() *HarnessPiUsage {
	usage := &HarnessPiUsage{}
	if !self.object.decode("usage", usage) {
		return nil
	}
	return usage
}

// A tool result's call id.
func (self *HarnessPiMessage) ToolCallId() string {
	return self.object.str("toolCallId")
}

// A tool result's tool.
func (self *HarnessPiMessage) ToolName() string {
	return self.object.str("toolName")
}

// A tool result's error flag.
func (self *HarnessPiMessage) IsError() bool {
	isError := false
	self.object.decode("isError", &isError)
	return isError
}

// A tool result's or custom message's details, or nil.
func (self *HarnessPiMessage) Details() json.RawMessage {
	return self.object.get("details")
}

// The message's timestamp, Unix milliseconds.
func (self *HarnessPiMessage) TimestampMs() int64 {
	timestampMs := int64(0)
	self.object.decode("timestamp", &timestampMs)
	return timestampMs
}

// The member named name, as written, or nil: for a reader of a member this build has no accessor for.
func (self *HarnessPiMessage) Field(name string) json.RawMessage {
	return self.object.get(name)
}

// Sets the member named name where it stands, or appends it.
func (self *HarnessPiMessage) SetField(name string, value any) error {
	return self.object.set(name, value)
}

// A copy.
func (self *HarnessPiMessage) clone() *HarnessPiMessage {
	return &HarnessPiMessage{object: self.object.clone()}
}

// The message in Pi's member order.
func (self *HarnessPiMessage) MarshalJSON() ([]byte, error) {
	return self.object.MarshalJSON()
}

// Reads a message, refusing one with no role.
func (self *HarnessPiMessage) UnmarshalJSON(data []byte) error {
	object := harnessPiObject{}
	if err := object.UnmarshalJSON(data); err != nil {
		return err
	}
	if object.str("role") == "" {
		return fmt.Errorf("a message with no role")
	}
	self.object = object
	return nil
}
