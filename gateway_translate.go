//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The gateway's translation (DESIGN-COMPUTE §8.5; R-GW-3, D-GW-1, D-GW-2; GW-M12-03): every front maps its API onto one
// InferRequest (§6.4), so the gateway is a second front on the router, never a second router. A request passes two
// steps, in order:
//
//	route      the body as the model will receive it, which the call records (IC-19): what needs state the gateway does
//	           not keep refused 400 unsupported_parameter (store true, previous_response_id, conversation, background,
//	           a stored prompt, an item_reference: Q-CTXH-9, D-GW-2); each reasoning item whose encrypted_content is
//	           the gateway's own blob given the blob's text as its summary, and every other reasoning item dropped, a
//	           blob from anywhere else ignored (gateway_reasoning.go); each image re-encoded to the input size
//	           (gateway_images.go), an image that is no data URL refused, since the gateway fetches nothing
//	translate  the routed body to the InferRequest, a pure function of it, which the front's session renderer runs on
//	           the recorded items too (gateway-responses-1), so the recorded request_sha256 is what was sent by
//	           construction (§24.6)
//
// Open Responses' 2026-04-24 revision is the conformance target. Unknown members are accepted and ignored, never
// refused, since a refusal makes a harness retry without each one. A function tool is the only tool a model is
// offered: hosted search is SRCH's filter's to drop (gateway_search.go), and every other hosted or custom tool never
// reaches a model, so Codex's freeform apply_patch, which the generated catalog does not enable, is never offered
// (§8.8). Item ids are opaque: none is read as the gateway's. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

// The members, item types and part types of an Open Responses request the translation reads: format values.
const (
	gatewayResponsesMemberModel              = "model"
	gatewayResponsesMemberInput              = "input"
	gatewayResponsesMemberStore              = "store"
	gatewayResponsesMemberPreviousResponseId = "previous_response_id"
	gatewayResponsesMemberConversation       = "conversation"
	gatewayResponsesMemberBackground         = "background"
	gatewayResponsesMemberPrompt             = "prompt"

	gatewayItemTypeMessage              = "message"
	gatewayItemTypeReasoning            = "reasoning"
	gatewayItemTypeFunctionCall         = "function_call"
	gatewayItemTypeFunctionCallOutput   = "function_call_output"
	gatewayItemTypeCustomToolCall       = "custom_tool_call"
	gatewayItemTypeCustomToolCallOutput = "custom_tool_call_output"
	gatewayItemTypeItemReference        = "item_reference"

	gatewayPartTypeInputText   = "input_text"
	gatewayPartTypeOutputText  = "output_text"
	gatewayPartTypeText        = "text"
	gatewayPartTypeRefusal     = "refusal"
	gatewayPartTypeInputImage  = "input_image"
	gatewayPartTypeInputFile   = "input_file"
	gatewayPartTypeInputAudio  = "input_audio"
	gatewayPartTypeSummaryText = "summary_text"

	gatewayRoleUser      = "user"
	gatewayRoleAssistant = "assistant"
	gatewayRoleSystem    = "system"
	gatewayRoleDeveloper = "developer"

	gatewayToolTypeFunction     = "function"
	gatewayToolChoiceAllowed    = "allowed_tools"
	gatewayTextFormatJsonSchema = "json_schema"
	gatewayTextFormatJsonObject = "json_object"

	gatewayIncludeReasoningBlob = "reasoning.encrypted_content"

	// Chat Completions' messages member, whose leading system messages its recorded system item holds
	gatewayChatMemberMessages = "messages"
)

// What a front reads of a request beside its InferRequest.
type gatewayRequestOptions struct {
	// The answer streams.
	Stream bool
	// Responses: the caller asked for reasoning items' encrypted_content.
	IncludeReasoningBlob bool
	// Chat Completions: the final chunk carries usage (stream_options.include_usage).
	IncludeUsage bool
}

// A JSON value decoded with its numbers as written.
func gatewayDecodeValue(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("bytes after the JSON value")
	}
	return value, nil
}

// Whether a decoded member holds something: present, not null, not false, and not an empty string.
func gatewayMemberSet(object map[string]any, member string) bool {
	switch value := object[member].(type) {
	case nil:
		return false
	case bool:
		return value
	case string:
		return value != ""
	}
	return true
}

// The image parts of a content array re-encoded to the input size, and every part refused that the gateway cannot
// send: an image that is no data URL, a file id, an input file or audio. changed says whether any part changed.
func gatewayRoutedParts(settings *GatewaySettings, parts []any, param string) (bool, *gatewayError) {
	changed := false
	for _, element := range parts {
		part, ok := element.(map[string]any)
		if !ok {
			continue
		}
		partType, _ := part["type"].(string)
		switch partType {
		case gatewayPartTypeInputFile, gatewayPartTypeInputAudio:
			return false, gatewayInvalidRequest(GatewayErrorCodeUnsupportedParameter, param, "the gateway takes text and images; %s is not sent to a model", partType)
		case gatewayPartTypeInputImage:
			if gatewayMemberSet(part, "file_id") {
				return false, gatewayUnsupportedParameter(param+".file_id", "the gateway keeps no files")
			}
			url, _ := part["image_url"].(string)
			changedImage, routedUrl, err := gatewayRoutedImageUrl(settings, url, param)
			if err != nil {
				return false, err
			}
			if changedImage {
				part["image_url"] = routedUrl
				changed = true
			}
		}
	}
	return changed, nil
}

// An image URL as it is sent: a data URL re-encoded to the input size where it passes it. Anything but a base64 data
// URL is refused, since the gateway fetches nothing.
func gatewayRoutedImageUrl(settings *GatewaySettings, url string, param string) (bool, string, *gatewayError) {
	_, data, ok := gatewayParseDataUrl(url)
	if !ok {
		return false, "", gatewayInvalidRequest(GatewayErrorCodeInvalidImage, param,
			"an image is sent as a base64 data URL; the gateway fetches no URL")
	}
	mediaType, encoded, err := gatewayReencodeImage(settings, data)
	if err != nil {
		if gatewayErr, ok := err.(*gatewayError); ok {
			gatewayErr.Param = param
			return false, "", gatewayErr
		}
		return false, "", gatewayInvalidRequest(GatewayErrorCodeInvalidImage, param, "%s", err.Error())
	}
	if bytes.Equal(encoded, data) {
		return false, url, nil
	}
	return true, gatewayDataUrl(mediaType, encoded), nil
}

// The routed body of a Responses request (see the file header's route row): the request's own bytes where nothing
// changed. key is the network's reasoning key; nil opens no blob, so every reasoning item is dropped.
func gatewayRouteResponses(settings *GatewaySettings, body []byte, key []byte) ([]byte, *gatewayError) {
	value, err := gatewayDecodeValue(body)
	if err != nil {
		return nil, gatewayInvalidRequest(GatewayErrorCodeInvalidJson, "", "the request's body is not JSON")
	}
	request, ok := value.(map[string]any)
	if !ok {
		return nil, gatewayInvalidRequest(GatewayErrorCodeInvalidJson, "", "the request's body is not a JSON object")
	}
	if store, ok := request[gatewayResponsesMemberStore].(bool); ok && store {
		return nil, gatewayUnsupportedParameter(gatewayResponsesMemberStore, "the gateway stores no response; send store: false and the whole history")
	}
	for _, member := range []string{gatewayResponsesMemberPreviousResponseId, gatewayResponsesMemberConversation, gatewayResponsesMemberBackground, gatewayResponsesMemberPrompt} {
		if gatewayMemberSet(request, member) {
			return nil, gatewayUnsupportedParameter(member, "the gateway keeps no state between calls; send the whole history")
		}
	}
	items, ok := request[gatewayResponsesMemberInput].([]any)
	if !ok {
		return body, nil
	}
	changed := false
	routed := make([]any, 0, len(items))
	for index, element := range items {
		item, ok := element.(map[string]any)
		if !ok {
			routed = append(routed, element)
			continue
		}
		param := fmt.Sprintf("input[%d]", index)
		itemType, _ := item["type"].(string)
		switch itemType {
		case gatewayItemTypeItemReference:
			return nil, gatewayUnsupportedParameter(param, "an item_reference names a stored item, and the gateway keeps none")
		case gatewayItemTypeReasoning:
			blob, _ := item["encrypted_content"].(string)
			opened, authentic := (*GatewayReasoningBlob)(nil), false
			if key != nil && blob != "" {
				opened, authentic = OpenGatewayReasoningBlob(key, blob)
			}
			if !authentic {
				// a blob from anywhere else gives the model nothing
				changed = true
				continue
			}
			summary := []any{map[string]any{"type": gatewayPartTypeSummaryText, "text": opened.Text}}
			if text, held := gatewayResponsesSummaryText(item["summary"]); !held || text != opened.Text || item["content"] != nil {
				item["summary"] = summary
				delete(item, "content")
				changed = true
			}
		case gatewayItemTypeFunctionCallOutput:
			if parts, ok := item["output"].([]any); ok {
				partsChanged, err := gatewayRoutedParts(settings, parts, param+".output")
				if err != nil {
					return nil, err
				}
				changed = changed || partsChanged
			}
		default:
			if parts, ok := item["content"].([]any); ok {
				partsChanged, err := gatewayRoutedParts(settings, parts, param+".content")
				if err != nil {
					return nil, err
				}
				changed = changed || partsChanged
			}
		}
		routed = append(routed, item)
	}
	if !changed {
		return body, nil
	}
	request[gatewayResponsesMemberInput] = routed
	encoded, err := gatewayMarshal(request)
	if err != nil {
		return nil, gatewayInvalidRequest(GatewayErrorCodeInvalidJson, "", "the request does not encode again")
	}
	return encoded, nil
}

// The text of a reasoning item's summary when it is exactly one summary_text part, and whether it is.
func gatewayResponsesSummaryText(summary any) (string, bool) {
	parts, ok := summary.([]any)
	if !ok || len(parts) != 1 {
		return "", false
	}
	part, ok := parts[0].(map[string]any)
	if !ok || len(part) != 2 || part["type"] != gatewayPartTypeSummaryText {
		return "", false
	}
	text, ok := part["text"].(string)
	return text, ok
}

// One content part of a message, or of a function call's output, as the translation reads it.
type gatewayContentPart struct {
	Type     string          `json:"type"`
	Text     string          `json:"text"`
	Refusal  string          `json:"refusal"`
	ImageUrl json.RawMessage `json:"image_url"`
}

// One input item of a Responses request, as the translation reads it.
type gatewayResponsesItem struct {
	Type      string                `json:"type"`
	Role      string                `json:"role"`
	Content   json.RawMessage       `json:"content"`
	Summary   []*gatewayContentPart `json:"summary"`
	CallId    string                `json:"call_id"`
	Name      string                `json:"name"`
	Arguments string                `json:"arguments"`
	Input     string                `json:"input"`
	Output    json.RawMessage       `json:"output"`
}

// One tool of a request: Responses' {type, name, description, parameters}, or Chat Completions' {type, function}.
type gatewayTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
	Function    *struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

// A Responses request as the translation reads it. Every other member is accepted and ignored.
type gatewayResponsesRequest struct {
	Model        string          `json:"model"`
	Instructions json.RawMessage `json:"instructions"`
	Input        json.RawMessage `json:"input"`
	Tools        []*gatewayTool  `json:"tools"`
	ToolChoice   json.RawMessage `json:"tool_choice"`
	Text         *struct {
		Format json.RawMessage `json:"format"`
	} `json:"text"`
	Reasoning *struct {
		Effort string `json:"effort"`
	} `json:"reasoning"`
	MaxOutputTokens *int64   `json:"max_output_tokens"`
	Temperature     *float64 `json:"temperature"`
	TopP            *float64 `json:"top_p"`
	Stream          bool     `json:"stream"`
	Include         []string `json:"include"`
}

// The parts of content, a string or an array of parts: text, refusals and images, in order; every other part is
// ignored. An image that is no data URL, as a recorded part's reference is in a request hash's render, is taken as
// opaque bytes, so the render is a function of what was recorded.
func gatewayInferParts(content json.RawMessage) ([]*InferPart, error) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	if trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return nil, err
		}
		return []*InferPart{{Kind: InferPartText, Text: text}}, nil
	}
	parts := []*gatewayContentPart{}
	if err := json.Unmarshal(trimmed, &parts); err != nil {
		return nil, err
	}
	inferParts := []*InferPart{}
	for _, part := range parts {
		if part == nil {
			continue
		}
		switch part.Type {
		case gatewayPartTypeInputText, gatewayPartTypeOutputText, gatewayPartTypeText, gatewayPartTypeSummaryText:
			inferParts = append(inferParts, &InferPart{Kind: InferPartText, Text: part.Text})
		case gatewayPartTypeRefusal:
			inferParts = append(inferParts, &InferPart{Kind: InferPartText, Text: part.Refusal})
		case gatewayPartTypeInputImage, "image_url":
			url, err := gatewayImageUrlOf(part.ImageUrl)
			if err != nil {
				return nil, err
			}
			mediaType, data, ok := gatewayParseDataUrl(url)
			if !ok {
				mediaType, data = "", []byte(url)
			}
			inferParts = append(inferParts, &InferPart{Kind: InferPartImage, MediaType: mediaType, Data: data})
		}
	}
	return inferParts, nil
}

// An image part's URL: Responses' string, or Chat Completions' {url, detail}.
func gatewayImageUrlOf(raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", nil
	}
	if trimmed[0] == '"' {
		var url string
		err := json.Unmarshal(trimmed, &url)
		return url, err
	}
	object := &struct {
		Url string `json:"url"`
	}{}
	err := json.Unmarshal(trimmed, object)
	return object.Url, err
}

// The InferTools of tools: function tools alone, in order; every hosted or custom tool never reaches a model.
func gatewayInferTools(tools []*gatewayTool) []*InferTool {
	inferTools := []*InferTool{}
	for _, tool := range tools {
		if tool == nil || tool.Type != gatewayToolTypeFunction {
			continue
		}
		name, description, parameters := tool.Name, tool.Description, tool.Parameters
		if tool.Function != nil {
			name, description, parameters = tool.Function.Name, tool.Function.Description, tool.Function.Parameters
		}
		if name == "" {
			continue
		}
		if bytes.Equal(bytes.TrimSpace(parameters), []byte("null")) {
			parameters = nil
		}
		inferTools = append(inferTools, &InferTool{Name: name, Description: description, Schema: parameters})
	}
	return inferTools
}

// A tool_choice as the router reads it: auto, none, required or a tool's name, and the tools it leaves the model.
// A choice naming a tool the model is not offered, a hosted or custom tool among them, is auto; allowed_tools keeps
// only the function tools it names, a hard constraint.
func gatewayInferToolChoice(raw json.RawMessage, tools []*InferTool) (string, []*InferTool, *gatewayError) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return "", tools, nil
	}
	if trimmed[0] == '"' {
		var choice string
		if err := json.Unmarshal(trimmed, &choice); err != nil {
			return "", nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, "tool_choice", "tool_choice does not read")
		}
		switch choice {
		case "auto", "none", "required":
			return choice, tools, nil
		}
		return "", nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, "tool_choice", "tool_choice %q is none of auto, none and required", choice)
	}
	object := &struct {
		Type     string `json:"type"`
		Name     string `json:"name"`
		Mode     string `json:"mode"`
		Function *struct {
			Name string `json:"name"`
		} `json:"function"`
		Tools []*gatewayTool `json:"tools"`
	}{}
	if err := json.Unmarshal(trimmed, object); err != nil {
		return "", nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, "tool_choice", "tool_choice does not read")
	}
	offered := func(name string) bool {
		return slices.ContainsFunc(tools, func(tool *InferTool) bool { return tool.Name == name })
	}
	switch object.Type {
	case gatewayToolTypeFunction:
		name := object.Name
		if object.Function != nil {
			name = object.Function.Name
		}
		if offered(name) {
			return name, tools, nil
		}
	case gatewayToolChoiceAllowed:
		allowed := []string{}
		for _, tool := range object.Tools {
			if tool == nil || tool.Type != gatewayToolTypeFunction {
				continue
			}
			name := tool.Name
			if tool.Function != nil {
				name = tool.Function.Name
			}
			allowed = append(allowed, name)
		}
		kept := []*InferTool{}
		for _, tool := range tools {
			if slices.Contains(allowed, tool.Name) {
				kept = append(kept, tool)
			}
		}
		mode := object.Mode
		if mode != "required" {
			mode = "auto"
		}
		if len(kept) == 0 {
			mode = "none"
		}
		return mode, kept, nil
	}
	return "auto", tools, nil
}

// The schema a text format asks the answer to follow: json_schema's schema, json_object's any object, else none.
func gatewayInferSchema(format json.RawMessage) (json.RawMessage, *gatewayError) {
	trimmed := bytes.TrimSpace(format)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	object := &struct {
		Type       string          `json:"type"`
		Schema     json.RawMessage `json:"schema"`
		JsonSchema *struct {
			Schema json.RawMessage `json:"schema"`
		} `json:"json_schema"`
	}{}
	if err := json.Unmarshal(trimmed, object); err != nil {
		return nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, "text.format", "the text format does not read")
	}
	switch object.Type {
	case gatewayTextFormatJsonSchema:
		schema := object.Schema
		if object.JsonSchema != nil {
			schema = object.JsonSchema.Schema
		}
		if len(bytes.TrimSpace(schema)) == 0 {
			return nil, gatewayInvalidRequest(GatewayErrorCodeMissingParameter, "text.format.schema", "a json_schema format names its schema")
		}
		return schema, nil
	case gatewayTextFormatJsonObject:
		return json.RawMessage(`{"type":"object"}`), nil
	}
	return nil, nil
}

// The messages of a conversation as items arrive: an assistant's reasoning, text and tool calls gather into one
// assistant message until another role's item comes.
type gatewayMessageBuilder struct {
	messages []*InferMessage
	// the assistant message items are gathering into, nil once another role's came
	assistant *InferMessage
}

// The assistant message the next assistant item joins.
func (self *gatewayMessageBuilder) assistantMessage() *InferMessage {
	if self.assistant == nil {
		self.assistant = &InferMessage{Role: InferRoleAssistant}
		self.messages = append(self.messages, self.assistant)
	}
	return self.assistant
}

// Adds a message of another role, which ends the assistant's gathering.
func (self *gatewayMessageBuilder) add(message *InferMessage) {
	self.assistant = nil
	self.messages = append(self.messages, message)
}

// The InferRequest a routed Responses body asks for, and the front's options (see the file header's translate row).
// Pure: the same body always translates to the same request, which the session renderer relies on.
func gatewayTranslateResponses(body []byte) (*InferRequest, *gatewayRequestOptions, *gatewayError) {
	request := &gatewayResponsesRequest{}
	if err := json.Unmarshal(body, request); err != nil {
		return nil, nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, "", "the request does not read as Open Responses: %s", gatewayJsonErrorText(err))
	}
	if request.Model == "" {
		return nil, nil, gatewayInvalidRequest(GatewayErrorCodeMissingParameter, gatewayResponsesMemberModel, "the request names no model")
	}
	options := &gatewayRequestOptions{
		Stream:               request.Stream,
		IncludeReasoningBlob: slices.Contains(request.Include, gatewayIncludeReasoningBlob),
	}
	builder := &gatewayMessageBuilder{}
	if instructions := bytes.TrimSpace(request.Instructions); 0 < len(instructions) && !bytes.Equal(instructions, []byte("null")) {
		text := ""
		if err := json.Unmarshal(instructions, &text); err != nil {
			return nil, nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, "instructions", "instructions is not a string")
		}
		if text != "" {
			builder.add(&InferMessage{Role: InferRoleSystem, Parts: []*InferPart{{Kind: InferPartText, Text: text}}})
		}
	}
	input := bytes.TrimSpace(request.Input)
	switch {
	case len(input) == 0 || bytes.Equal(input, []byte("null")):
		return nil, nil, gatewayInvalidRequest(GatewayErrorCodeMissingParameter, gatewayResponsesMemberInput, "the request has no input")
	case input[0] == '"':
		text := ""
		if err := json.Unmarshal(input, &text); err != nil {
			return nil, nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, gatewayResponsesMemberInput, "input does not read")
		}
		builder.add(&InferMessage{Role: InferRoleUser, Parts: []*InferPart{{Kind: InferPartText, Text: text}}})
	default:
		items := []*gatewayResponsesItem{}
		if err := json.Unmarshal(input, &items); err != nil {
			return nil, nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, gatewayResponsesMemberInput, "input does not read: %s", gatewayJsonErrorText(err))
		}
		for index, item := range items {
			if item == nil {
				continue
			}
			if err := gatewayTranslateResponsesItem(builder, item); err != nil {
				return nil, nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, fmt.Sprintf("input[%d]", index), "the item does not read: %s", gatewayJsonErrorText(err))
			}
		}
	}
	inferRequest := &InferRequest{Model: request.Model, Messages: builder.messages}
	tools := gatewayInferTools(request.Tools)
	choice, tools, choiceErr := gatewayInferToolChoice(request.ToolChoice, tools)
	if choiceErr != nil {
		return nil, nil, choiceErr
	}
	if 0 < len(tools) {
		inferRequest.Tools = tools
	}
	inferRequest.ToolChoice = choice
	if request.Text != nil {
		schema, err := gatewayInferSchema(request.Text.Format)
		if err != nil {
			return nil, nil, err
		}
		inferRequest.Schema = schema
	}
	if request.Reasoning != nil {
		inferRequest.Reasoning = request.Reasoning.Effort
	}
	if request.MaxOutputTokens != nil {
		if *request.MaxOutputTokens < 0 {
			return nil, nil, gatewayInvalidRequest(GatewayErrorCodeInvalidValue, "max_output_tokens", "max_output_tokens is negative")
		}
		inferRequest.MaxOutput = int(*request.MaxOutputTokens)
	}
	if request.Temperature != nil || request.TopP != nil {
		inferRequest.Sampling = &InferSampling{Temperature: request.Temperature, TopP: request.TopP}
	}
	return inferRequest, options, nil
}

// One input item into the conversation (see gatewayMessageBuilder); an item type the gateway does not send to a model
// (a hosted tool's call, provider state such as a compaction) is ignored.
func gatewayTranslateResponsesItem(builder *gatewayMessageBuilder, item *gatewayResponsesItem) error {
	itemType := item.Type
	if itemType == "" && item.Role != "" {
		itemType = gatewayItemTypeMessage
	}
	switch itemType {
	case gatewayItemTypeMessage:
		parts, err := gatewayInferParts(item.Content)
		if err != nil {
			return err
		}
		switch item.Role {
		case gatewayRoleAssistant:
			message := builder.assistantMessage()
			message.Parts = append(message.Parts, parts...)
		case gatewayRoleSystem, gatewayRoleDeveloper:
			builder.add(&InferMessage{Role: InferRoleSystem, Parts: parts})
		default:
			builder.add(&InferMessage{Role: InferRoleUser, Parts: parts})
		}
	case gatewayItemTypeReasoning:
		text := ""
		for _, part := range item.Summary {
			if part != nil {
				text += part.Text
			}
		}
		if text != "" {
			message := builder.assistantMessage()
			message.Reasoning += text
		}
	case gatewayItemTypeFunctionCall:
		message := builder.assistantMessage()
		message.ToolCalls = append(message.ToolCalls, &InferToolCall{Id: item.CallId, Name: item.Name, Arguments: item.Arguments})
	case gatewayItemTypeCustomToolCall:
		// a freeform call from a session that began elsewhere: its input as one string argument
		arguments, err := gatewayMarshal(map[string]string{"input": item.Input})
		if err != nil {
			return err
		}
		message := builder.assistantMessage()
		message.ToolCalls = append(message.ToolCalls, &InferToolCall{Id: item.CallId, Name: item.Name, Arguments: string(arguments)})
	case gatewayItemTypeFunctionCallOutput, gatewayItemTypeCustomToolCallOutput:
		parts, err := gatewayInferParts(item.Output)
		if err != nil {
			return err
		}
		builder.add(&InferMessage{Role: InferRoleTool, Parts: parts, ToolCallId: item.CallId})
	}
	return nil
}

// A JSON error's words without the bytes it read, which may be anything the request held.
func gatewayJsonErrorText(err error) string {
	switch typed := err.(type) {
	case *json.UnmarshalTypeError:
		return fmt.Sprintf("%s is not a %s", typed.Field, typed.Type)
	case *json.SyntaxError:
		return fmt.Sprintf("not JSON at byte %d", typed.Offset)
	}
	return "not the API's shape"
}

// The session renderer of the Responses front (session_render.go): a recorded call's request is the translation of
// the body its recorded items rebuild, its params with its system node's instructions and tools and its input items.
type gatewayResponsesRenderer struct{}

// Registers the Responses front's session renderer.
func init() {
	RegisterSessionRenderer(gatewayResponsesRenderer{})
}

// See SessionRenderer.
func (gatewayResponsesRenderer) Id() string {
	return GatewayRendererResponses
}

// See SessionRenderer: the path whole, its root first, and the call's system node, which sits off the chain.
func (gatewayResponsesRenderer) Context(path []*SessionRenderNode, systemNodeId *Id, nodeOf func(nodeId Id) (*SessionRenderNode, bool)) (*SessionRenderInput, error) {
	return gatewaySessionContext(path, systemNodeId, nodeOf)
}

// See SessionRenderer.
func (gatewayResponsesRenderer) Render(context *SessionRenderContext) (*InferRequest, error) {
	body, err := gatewayRecordedBody(context, gatewayResponsesMemberInput)
	if err != nil {
		return nil, err
	}
	request, _, gatewayErr := gatewayTranslateResponses(body)
	if gatewayErr != nil {
		return nil, fmt.Errorf("%w: %s", ErrSessionRenderRefused, gatewayErr.Message)
	}
	return request, nil
}

// A gateway call's context: its input path whole and its system node, which a gateway call's chain does not hold.
func gatewaySessionContext(path []*SessionRenderNode, systemNodeId *Id, nodeOf func(nodeId Id) (*SessionRenderNode, bool)) (*SessionRenderInput, error) {
	input := &SessionRenderInput{Nodes: slices.Clone(path)}
	if systemNodeId != nil {
		node, ok := nodeOf(*systemNodeId)
		if !ok {
			return nil, fmt.Errorf("%w: the call's system node is not in its run", ErrSessionRenderRefused)
		}
		input.System = []*SessionRenderNode{node}
	}
	return input, nil
}

// The body a recorded call's items rebuild: its params, each member of its system items, the last one's winning, and
// its nodes' items as the member itemsMember.
func gatewayRecordedBody(context *SessionRenderContext, itemsMember string) ([]byte, error) {
	body := map[string]any{}
	if 0 < len(context.Params) {
		value, err := gatewayDecodeValue(context.Params)
		if err != nil {
			return nil, fmt.Errorf("%w: params that are no JSON", ErrSessionRenderRefused)
		}
		params, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: params that are no object", ErrSessionRenderRefused)
		}
		body = params
	}
	for _, system := range context.System {
		value, err := gatewayDecodeValue(system.Item)
		if err != nil {
			return nil, fmt.Errorf("%w: a system item that is no JSON", ErrSessionRenderRefused)
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: a system item that is no object", ErrSessionRenderRefused)
		}
		for member, memberValue := range object {
			body[member] = memberValue
		}
	}
	items := []any{}
	for _, node := range context.Nodes {
		value, err := gatewayDecodeValue(node.Item)
		if err != nil {
			return nil, fmt.Errorf("%w: an item that is no JSON", ErrSessionRenderRefused)
		}
		items = append(items, value)
	}
	if itemsMember == gatewayChatMemberMessages {
		// Chat Completions' leading system messages sit in its system item
		if leading, ok := body[itemsMember].([]any); ok {
			items = append(slices.Clone(leading), items...)
		}
	}
	body[itemsMember] = items
	encoded, err := gatewayMarshal(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionRenderRefused, err)
	}
	return encoded, nil
}
