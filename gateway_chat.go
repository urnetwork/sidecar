//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The Chat Completions front (DESIGN-COMPUTE §8.3, §8.4, §8.5's Chat Completions column; R-GW-1, D-GW-1; GW-M12-04):
// POST /v1/chat/completions for OpenCode, Goose, Aider, Zed, Continue, Cline, Roo and pi, streaming and not, on the
// same pipeline, errors and refusals as the Responses front (gateway_responses.go), in this API's words.
//
//	request   messages (system and developer, user with text and images, assistant with its text and tool_calls,
//	          tool results naming their call), tools (and the legacy functions), tool_choice (and function_call),
//	          response_format, reasoning_effort, max_completion_tokens or max_tokens, temperature, top_p and stop.
//	          An assistant's reasoning_content in the history is kept in what the call records but never given to the
//	          model, as a Responses reasoning item without the gateway's blob is not (§8.5: a reasoning text from
//	          anywhere else is ignored); n past 1 is refused 400, since a call answers one choice
//	stream    a first chunk with the role; delta.content; delta.reasoning_content; delta.tool_calls, each chunk
//	          carrying its call's index; a final chunk with finish_reason and usage, the assistant message recorded
//	          whole before it (IC-19); then data: [DONE]. A failure after the stream began is an error chunk, then
//	          [DONE]; a `: ping` every KeepaliveInterval
//	whole     one chat.completion: the message, its tool calls and its usage
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/urnetwork/sidecar/protocol"
)

// The route, the ids' prefix and the API's members and values: format values.
const (
	GatewayRouteChatCompletions = "POST /v1/chat/completions"

	gatewayChatIdPrefix         = "chatcmpl-"
	gatewayChatObjectChunk      = "chat.completion.chunk"
	gatewayChatObjectCompletion = "chat.completion"
	gatewayChatFinishStop       = "stop"
	gatewayChatFinishToolCalls  = "tool_calls"
	gatewayChatDone             = "[DONE]"
	gatewayChatRoleTool         = "tool"
	gatewayChatRoleFunction     = "function"
	gatewayChatPartImageUrl     = "image_url"
	gatewayChatPartFile         = "file"
)

// Registers the front's route and its session renderer.
func init() {
	gatewayFrontRoutes = append(gatewayFrontRoutes, &gatewayFrontRoute{
		pattern: GatewayRouteChatCompletions,
		serve: func(fronts *GatewayFronts, writer http.ResponseWriter, request *http.Request, caller *GatewayCaller) {
			fronts.serve(writer, request, caller, gatewayChatFront{})
		},
	})
	RegisterSessionRenderer(gatewayChatRenderer{})
}

// One message of a Chat Completions request, as the translation reads it.
type gatewayChatMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	Name       string          `json:"name"`
	ToolCallId string          `json:"tool_call_id"`
	ToolCalls  []*struct {
		Id       string `json:"id"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	} `json:"tool_calls"`
	FunctionCall *struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function_call"`
}

// A Chat Completions request as the translation reads it. Every other member is accepted and ignored.
type gatewayChatRequest struct {
	Model     string                `json:"model"`
	Messages  []*gatewayChatMessage `json:"messages"`
	Tools     []*gatewayTool        `json:"tools"`
	Functions []*struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"functions"`
	ToolChoice          json.RawMessage `json:"tool_choice"`
	FunctionCall        json.RawMessage `json:"function_call"`
	ResponseFormat      json.RawMessage `json:"response_format"`
	ReasoningEffort     string          `json:"reasoning_effort"`
	MaxTokens           *int64          `json:"max_tokens"`
	MaxCompletionTokens *int64          `json:"max_completion_tokens"`
	Temperature         *float64        `json:"temperature"`
	TopP                *float64        `json:"top_p"`
	Stop                json.RawMessage `json:"stop"`
	Stream              bool            `json:"stream"`
	StreamOptions       *struct {
		IncludeUsage bool `json:"include_usage"`
	} `json:"stream_options"`
}

// The routed body of a Chat Completions request: n past 1 refused, its images re-encoded, any other input refused
// (gateway_translate.go's route row); the request's own bytes where nothing changed.
func gatewayRouteChat(settings *GatewaySettings, body []byte) ([]byte, *gatewayError) {
	value, err := gatewayDecodeValue(body)
	if err != nil {
		return nil, gatewayInvalidRequest(GatewayErrorCodeInvalidJson, "", "the request's body is not JSON")
	}
	request, ok := value.(map[string]any)
	if !ok {
		return nil, gatewayInvalidRequest(GatewayErrorCodeInvalidJson, "", "the request's body is not a JSON object")
	}
	if n, ok := request["n"].(json.Number); ok && n.String() != "1" {
		return nil, gatewayUnsupportedParameter("n", "a call answers one choice")
	}
	messages, ok := request[gatewayChatMemberMessages].([]any)
	if !ok {
		return body, nil
	}
	changed := false
	for index, element := range messages {
		message, ok := element.(map[string]any)
		if !ok {
			continue
		}
		parts, ok := message["content"].([]any)
		if !ok {
			continue
		}
		partsChanged, refusal := gatewayRoutedParts(settings, parts, fmt.Sprintf("messages[%d].content", index))
		if refusal != nil {
			return nil, refusal
		}
		changed = changed || partsChanged
	}
	if !changed {
		return body, nil
	}
	encoded, err := gatewayMarshal(request)
	if err != nil {
		return nil, gatewayInvalidRequest(GatewayErrorCodeInvalidJson, "", "the request does not encode again")
	}
	return encoded, nil
}

// The InferRequest a routed Chat Completions body asks for, and the front's options. Pure, as the Responses
// translation is, so the session renderer gives the same request from the recorded items.
func gatewayTranslateChat(body []byte) (*InferRequest, *gatewayRequestOptions, *gatewayError) {
	request := &gatewayChatRequest{}
	if err := json.Unmarshal(body, request); err != nil {
		return nil, nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, "", "the request does not read as Chat Completions: %s", gatewayJsonErrorText(err))
	}
	if request.Model == "" {
		return nil, nil, gatewayInvalidRequest(GatewayErrorCodeMissingParameter, "model", "the request names no model")
	}
	if len(request.Messages) == 0 {
		return nil, nil, gatewayInvalidRequest(GatewayErrorCodeMissingParameter, gatewayChatMemberMessages, "the request has no messages")
	}
	options := &gatewayRequestOptions{Stream: request.Stream}
	if request.StreamOptions != nil {
		options.IncludeUsage = request.StreamOptions.IncludeUsage
	}
	builder := &gatewayMessageBuilder{}
	for index, message := range request.Messages {
		if message == nil {
			continue
		}
		parts, err := gatewayInferParts(message.Content)
		if err != nil {
			return nil, nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, fmt.Sprintf("messages[%d].content", index), "the content does not read")
		}
		switch message.Role {
		case gatewayRoleSystem, gatewayRoleDeveloper:
			builder.add(&InferMessage{Role: InferRoleSystem, Parts: parts})
		case gatewayRoleAssistant:
			// an assistant message is one turn, its reasoning_content never given back (see the file header)
			assistant := &InferMessage{Role: InferRoleAssistant, Parts: parts}
			for _, toolCall := range message.ToolCalls {
				if toolCall == nil {
					continue
				}
				assistant.ToolCalls = append(assistant.ToolCalls, &InferToolCall{Id: toolCall.Id, Name: toolCall.Function.Name, Arguments: toolCall.Function.Arguments})
			}
			if message.FunctionCall != nil {
				assistant.ToolCalls = append(assistant.ToolCalls, &InferToolCall{Name: message.FunctionCall.Name, Arguments: message.FunctionCall.Arguments})
			}
			builder.add(assistant)
		case gatewayChatRoleTool:
			builder.add(&InferMessage{Role: InferRoleTool, Parts: parts, ToolCallId: message.ToolCallId})
		case gatewayChatRoleFunction:
			builder.add(&InferMessage{Role: InferRoleTool, Parts: parts, ToolCallId: message.Name})
		default:
			builder.add(&InferMessage{Role: InferRoleUser, Parts: parts})
		}
	}
	inferRequest := &InferRequest{Model: request.Model, Messages: builder.messages, Reasoning: request.ReasoningEffort}
	tools := gatewayInferTools(request.Tools)
	for _, function := range request.Functions {
		if function != nil && function.Name != "" {
			tools = append(tools, &InferTool{Name: function.Name, Description: function.Description, Schema: function.Parameters})
		}
	}
	choiceRaw := request.ToolChoice
	if len(bytes.TrimSpace(choiceRaw)) == 0 && len(bytes.TrimSpace(request.FunctionCall)) != 0 {
		// the legacy function_call: none, auto, or {name}
		legacy := &struct {
			Name string `json:"name"`
		}{}
		if json.Unmarshal(request.FunctionCall, legacy) == nil && legacy.Name != "" {
			choiceRaw, _ = gatewayMarshal(map[string]any{"type": gatewayToolTypeFunction, "name": legacy.Name})
		} else {
			choiceRaw = request.FunctionCall
		}
	}
	choice, tools, refusal := gatewayInferToolChoice(choiceRaw, tools)
	if refusal != nil {
		return nil, nil, refusal
	}
	if 0 < len(tools) {
		inferRequest.Tools = tools
	}
	inferRequest.ToolChoice = choice
	schema, refusal := gatewayInferSchema(request.ResponseFormat)
	if refusal != nil {
		refusal.Param = "response_format"
		return nil, nil, refusal
	}
	inferRequest.Schema = schema
	maxOutput := request.MaxCompletionTokens
	if maxOutput == nil {
		maxOutput = request.MaxTokens
	}
	if maxOutput != nil {
		if *maxOutput < 0 {
			return nil, nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, "max_completion_tokens", "max_completion_tokens is negative")
		}
		inferRequest.MaxOutput = int(*maxOutput)
	}
	stops := []string{}
	if stop := bytes.TrimSpace(request.Stop); 0 < len(stop) && !bytes.Equal(stop, []byte("null")) {
		if stop[0] == '"' {
			one := ""
			if err := json.Unmarshal(stop, &one); err != nil {
				return nil, nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, "stop", "stop does not read")
			}
			stops = append(stops, one)
		} else if err := json.Unmarshal(stop, &stops); err != nil {
			return nil, nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, "stop", "stop does not read")
		}
	}
	if request.Temperature != nil || request.TopP != nil || 0 < len(stops) {
		inferRequest.Sampling = &InferSampling{Temperature: request.Temperature, TopP: request.TopP}
		if 0 < len(stops) {
			inferRequest.Sampling.Stops = stops
		}
	}
	return inferRequest, options, nil
}

// The session renderer of the Chat Completions front: the translation of the body its recorded items rebuild, its
// leading system messages from its system item.
type gatewayChatRenderer struct{}

// See SessionRenderer.
func (gatewayChatRenderer) Id() string {
	return GatewayRendererChatCompletions
}

// See SessionRenderer.
func (gatewayChatRenderer) Context(path []*SessionRenderNode, systemNodeId *Id, nodeOf func(nodeId Id) (*SessionRenderNode, bool)) (*SessionRenderInput, error) {
	return gatewaySessionContext(path, systemNodeId, nodeOf)
}

// See SessionRenderer.
func (gatewayChatRenderer) Render(context *SessionRenderContext) (*InferRequest, error) {
	body, err := gatewayRecordedBody(context, gatewayChatMemberMessages)
	if err != nil {
		return nil, err
	}
	request, _, refusal := gatewayTranslateChat(body)
	if refusal != nil {
		return nil, fmt.Errorf("%w: %s", ErrSessionRenderRefused, refusal.Message)
	}
	return request, nil
}

// The Chat Completions front (see the file header).
type gatewayChatFront struct{}

// See gatewayFront.
func (gatewayChatFront) api() SessionGatewayApi {
	return SessionGatewayApiChatCompletions
}

// See gatewayFront.
func (gatewayChatFront) renderer() string {
	return GatewayRendererChatCompletions
}

// See gatewayFront.
func (gatewayChatFront) responseIdPrefix() string {
	return gatewayChatIdPrefix
}

// See gatewayFront: SRCH's filter for Chat Completions.
func (gatewayChatFront) filter(hostedSearch *GatewayHostedSearch, harness string, body []byte) ([]byte, error) {
	return hostedSearch.FilterChatCompletions(harness, body)
}

// See gatewayFront: no reasoning blob rides Chat Completions, so key opens nothing here.
func (gatewayChatFront) route(settings *GatewaySettings, body []byte, key []byte) ([]byte, *gatewayError) {
	return gatewayRouteChat(settings, body)
}

// See gatewayFront.
func (gatewayChatFront) translate(body []byte) (*InferRequest, *gatewayRequestOptions, *gatewayError) {
	return gatewayTranslateChat(body)
}

// See gatewayFront: a `: ping` comment.
func (gatewayChatFront) keepaliveFrame() []byte {
	return []byte(gatewaySseKeepaliveComment)
}

// See gatewayFront.
func (gatewayChatFront) newProducer(run *gatewayCallRun) gatewayProducer {
	return &gatewayChatProducer{run: run, toolIndexes: map[string]int{}}
}

// One tool call while it streams.
type gatewayChatToolCall struct {
	id        string
	name      string
	arguments bytes.Buffer
}

// The Chat Completions front's producer: §8.5's Chat Completions column.
type gatewayChatProducer struct {
	run         *gatewayCallRun
	text        bytes.Buffer
	reasoning   bytes.Buffer
	toolCalls   []*gatewayChatToolCall
	toolIndexes map[string]int
	used        *InferUsage
	attested    []*protocol.AttestationResult
	begun       bool
}

// Whether the answer streams.
func (self *gatewayChatProducer) streaming() bool {
	return self.run.prepared.options.Stream
}

// One chunk whose choice carries delta and finishReason (nil for none yet), with usage where given.
func (self *gatewayChatProducer) chunk(delta gatewayJsonObject, finishReason any, usage any) []byte {
	run := self.run
	choice := gatewayJsonObject{
		{Key: "index", Value: 0},
		{Key: "delta", Value: delta},
		{Key: "logprobs", Value: nil},
		{Key: "finish_reason", Value: finishReason},
	}
	object := gatewayJsonObject{
		{Key: "id", Value: run.responseId},
		{Key: "object", Value: gatewayChatObjectChunk},
		{Key: "created", Value: run.createdAt.Unix()},
		{Key: "model", Value: run.prepared.request.Model},
		{Key: "choices", Value: []any{choice}},
	}
	if usage != nil {
		object = append(object, gatewayJsonMember{Key: "usage", Value: usage})
	}
	encoded, _ := object.MarshalJSON()
	return gatewaySseData(encoded)
}

// The usage object: integers alone, zeros where the router gave none.
func (self *gatewayChatProducer) usageObject() gatewayJsonObject {
	usage := self.used
	if usage == nil {
		usage = &InferUsage{}
	}
	return gatewayJsonObject{
		{Key: "prompt_tokens", Value: usage.InputTokens},
		{Key: "completion_tokens", Value: usage.OutputTokens},
		{Key: "total_tokens", Value: usage.InputTokens + usage.OutputTokens},
		{Key: "prompt_tokens_details", Value: gatewayJsonObject{{Key: "cached_tokens", Value: usage.CachedTokens}}},
		{Key: "completion_tokens_details", Value: gatewayJsonObject{{Key: "reasoning_tokens", Value: usage.ReasoningTokens}}},
	}
}

// See gatewayProducer: the first chunk, carrying the role.
func (self *gatewayChatProducer) open() [][]byte {
	return [][]byte{self.chunk(gatewayJsonObject{{Key: "role", Value: gatewayRoleAssistant}, {Key: "content", Value: ""}}, nil, nil)}
}

// See gatewayProducer.
func (self *gatewayChatProducer) began() bool {
	return self.begun
}

// See gatewayProducer.
func (self *gatewayChatProducer) usage() (*InferUsage, []*protocol.AttestationResult) {
	return self.used, self.attested
}

// The tool call's delta: its index on every chunk, its id, type and name on its first.
func gatewayChatToolDelta(index int, toolCall *gatewayChatToolCall, first bool, arguments string) gatewayJsonObject {
	function := gatewayJsonObject{}
	if first {
		function = append(function, gatewayJsonMember{Key: "name", Value: toolCall.name})
	}
	function = append(function, gatewayJsonMember{Key: "arguments", Value: arguments})
	call := gatewayJsonObject{{Key: "index", Value: index}}
	if first {
		call = append(call, gatewayJsonMember{Key: "id", Value: toolCall.id}, gatewayJsonMember{Key: "type", Value: gatewayToolTypeFunction})
	}
	call = append(call, gatewayJsonMember{Key: "function", Value: function})
	return gatewayJsonObject{{Key: "tool_calls", Value: []any{call}}}
}

// See gatewayProducer.
func (self *gatewayChatProducer) event(ctx context.Context, event *InferEvent) ([][]byte, error) {
	frames := [][]byte{}
	switch event.Kind {
	case InferEventText:
		self.begun = true
		self.text.WriteString(event.Text)
		frames = append(frames, self.chunk(gatewayJsonObject{{Key: "content", Value: event.Text}}, nil, nil))
	case InferEventReasoning:
		self.begun = true
		self.reasoning.WriteString(event.Text)
		frames = append(frames, self.chunk(gatewayJsonObject{{Key: "reasoning_content", Value: event.Text}}, nil, nil))
	case InferEventToolCallStart:
		self.begun = true
		if _, open := self.toolIndexes[event.ToolCall.Id]; open {
			break
		}
		toolCall := &gatewayChatToolCall{id: event.ToolCall.Id, name: event.ToolCall.Name}
		index := len(self.toolCalls)
		self.toolCalls = append(self.toolCalls, toolCall)
		self.toolIndexes[toolCall.id] = index
		frames = append(frames, self.chunk(gatewayChatToolDelta(index, toolCall, true, ""), nil, nil))
	case InferEventToolCallArgs:
		index, open := self.toolIndexes[event.ToolCall.Id]
		if !open {
			break
		}
		self.toolCalls[index].arguments.WriteString(event.ToolCall.Arguments)
		frames = append(frames, self.chunk(gatewayChatToolDelta(index, self.toolCalls[index], false, event.ToolCall.Arguments), nil, nil))
	case InferEventToolCallEnd:
		index, open := self.toolIndexes[event.ToolCall.Id]
		if !open {
			break
		}
		toolCall := self.toolCalls[index]
		if event.ToolCall.Name != "" {
			toolCall.name = event.ToolCall.Name
		}
		// what the deltas left out of the whole arguments, where they were its start
		streamed := toolCall.arguments.String()
		if whole := event.ToolCall.Arguments; streamed != whole {
			if rest, ok := bytes.CutPrefix([]byte(whole), []byte(streamed)); ok && 0 < len(rest) {
				frames = append(frames, self.chunk(gatewayChatToolDelta(index, toolCall, false, string(rest)), nil, nil))
			}
			toolCall.arguments.Reset()
			toolCall.arguments.WriteString(whole)
		}
	case InferEventUsage:
		usage := *event.Usage
		self.used = &usage
	case InferEventAttestation:
		self.attested = append(self.attested, event.Attest)
	}
	if !self.streaming() {
		return nil, nil
	}
	return frames, nil
}

// The assistant message the call answered, as a later request carries it back.
func (self *gatewayChatProducer) message() gatewayJsonObject {
	var content any
	if 0 < self.text.Len() {
		content = self.text.String()
	}
	message := gatewayJsonObject{{Key: "role", Value: gatewayRoleAssistant}, {Key: "content", Value: content}}
	if 0 < self.reasoning.Len() {
		message = append(message, gatewayJsonMember{Key: "reasoning_content", Value: self.reasoning.String()})
	}
	if 0 < len(self.toolCalls) {
		calls := []any{}
		for _, toolCall := range self.toolCalls {
			calls = append(calls, gatewayJsonObject{
				{Key: "id", Value: toolCall.id},
				{Key: "type", Value: gatewayToolTypeFunction},
				{Key: "function", Value: gatewayJsonObject{{Key: "name", Value: toolCall.name}, {Key: "arguments", Value: toolCall.arguments.String()}}},
			})
		}
		message = append(message, gatewayJsonMember{Key: "tool_calls", Value: calls})
	}
	return message
}

// The finish reason: tool_calls where the model called any.
func (self *gatewayChatProducer) finishReason() string {
	if 0 < len(self.toolCalls) {
		return gatewayChatFinishToolCalls
	}
	return gatewayChatFinishStop
}

// See gatewayProducer: the assistant message recorded whole, then the final chunk with its finish reason and usage and
// [DONE]; or the whole completion.
func (self *gatewayChatProducer) complete(ctx context.Context) ([][]byte, error) {
	message := self.message()
	encoded, err := message.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if _, err := self.run.record.ResponseItem(ctx, encoded); err != nil {
		return nil, err
	}
	if self.streaming() {
		return [][]byte{
			self.chunk(gatewayJsonObject{}, self.finishReason(), self.usageObject()),
			gatewaySseData([]byte(gatewayChatDone)),
		}, nil
	}
	run := self.run
	completion := gatewayJsonObject{
		{Key: "id", Value: run.responseId},
		{Key: "object", Value: gatewayChatObjectCompletion},
		{Key: "created", Value: run.createdAt.Unix()},
		{Key: "model", Value: run.prepared.request.Model},
		{Key: "choices", Value: []any{gatewayJsonObject{
			{Key: "index", Value: 0},
			{Key: "message", Value: message},
			{Key: "logprobs", Value: nil},
			{Key: "finish_reason", Value: self.finishReason()},
		}}},
		{Key: "usage", Value: self.usageObject()},
	}
	body, err := completion.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return [][]byte{body}, nil
}

// See gatewayProducer: an error chunk, its code one a harness does not retry once the model's output began, then
// [DONE].
func (self *gatewayChatProducer) fail(failure *gatewayError, began bool) [][]byte {
	errorObject := gatewayJsonObject{{Key: "error", Value: gatewayJsonObject{
		{Key: "message", Value: failure.Message},
		{Key: "type", Value: failure.Type},
		{Key: "param", Value: nil},
		{Key: "code", Value: failure.streamCode(began)},
	}}}
	encoded, _ := errorObject.MarshalJSON()
	return [][]byte{gatewaySseData(encoded), gatewaySseData([]byte(gatewayChatDone))}
}
