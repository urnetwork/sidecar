//go:build !ios_extension && !sidecar_http

// The gateway's items as its recorder takes them (CTXH-M12-01; DESIGN-COMPUTE §24.8's items row, §8.3, §8.5): a request
// of one of §8.4's fronts cut into its system item, its input items in order and its params, and a response's items
// as GW hands them on completing each, every one in the form a later request of the same session carries it, so the
// chain hashes of a session's calls line up.
//
//	system    the request's instructions or system text and its tools, one object: Responses' instructions and
//	          tools; Chat Completions' leading system and developer messages, tools and functions; none when the
//	          request holds neither
//	input     Responses' input, a string read as one user message; Chat Completions' messages after the leading
//	          system ones
//	params    every other member of the request, as sent (CallContext.params)
//	moves     what a harness may drop or change between the call that answered an item and the request that carries it
//	          back, and what no model reads, is left out: an item's id and status, a reasoning item's
//	          encrypted_content (the gateway's own sealed blob, §8.5, whose text the item holds already), empty
//	          annotations and logprobs, an item's null members and a streamed tool call's index; an item_reference
//	          keeps its id, which is its content
//	refused   a request that does not carry its whole context, previous_response_id or a conversation (Q-CTXH-9:
//	          the gateway stays stateless), or one whose items are not objects, records nothing: a call whose context
//	          cannot be journaled is not made (IC-19)
//
// The Messages front's items are CTXH-M13-01's; until they land a Messages call is refused, recording nothing.
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// The front a call came through (§8.4), which sets how its items are taken.
type SessionGatewayApi string

const (
	// POST /v1/responses: Codex's.
	SessionGatewayApiResponses SessionGatewayApi = "responses"
	// POST /v1/chat/completions: OpenCode's, Goose's, Aider's and the other open harnesses'.
	SessionGatewayApiChatCompletions SessionGatewayApi = "chat_completions"
)

// The members and values of the fronts' request bodies the recorder reads: format values.
const (
	sessionResponsesInput              = "input"
	sessionResponsesInstructions       = "instructions"
	sessionResponsesTools              = "tools"
	sessionResponsesPreviousResponseId = "previous_response_id"
	sessionResponsesConversation       = "conversation"
	sessionResponsesTypeMessage        = "message"
	sessionResponsesTypeReasoning      = "reasoning"
	sessionResponsesTypeItemReference  = "item_reference"
	sessionChatMessages                = "messages"
	sessionChatTools                   = "tools"
	sessionChatFunctions               = "functions"
	sessionChatToolCalls               = "tool_calls"
	sessionChatRoleSystem              = "system"
	sessionChatRoleDeveloper           = "developer"
	sessionItemType                    = "type"
	sessionItemRole                    = "role"
	sessionItemContent                 = "content"
	sessionItemId                      = "id"
	sessionItemStatus                  = "status"
	sessionItemEncryptedContent        = "encrypted_content"
	sessionItemAnnotations             = "annotations"
	sessionItemLogprobs                = "logprobs"
	sessionItemIndex                   = "index"
	sessionRoleUser                    = "user"
	sessionRoleAssistant               = "assistant"
)

// A request the recorder cannot take whole: it records nothing, and GW does not make the call (IC-19).
var ErrSessionGatewayRefused = errors.New("session gateway refused")

// A request cut into what the recorder records of it.
type sessionGatewayItems struct {
	// nil for a request with no system text and no tools
	system map[string]any
	input  []map[string]any
	params map[string]any
}

// A JSON object decoded with its numbers kept as written.
func sessionGatewayObjectOf(data []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("%w: no JSON: %v", ErrSessionGatewayRefused, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: bytes after the JSON value", ErrSessionGatewayRefused)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: no JSON object", ErrSessionGatewayRefused)
	}
	return object, nil
}

// The request body of api cut into its items (see the file header).
func sessionGatewayItemsOf(api SessionGatewayApi, body []byte) (*sessionGatewayItems, error) {
	request, err := sessionGatewayObjectOf(body)
	if err != nil {
		return nil, err
	}
	switch api {
	case SessionGatewayApiResponses:
		return sessionResponsesItems(request)
	case SessionGatewayApiChatCompletions:
		return sessionChatCompletionsItems(request)
	}
	return nil, fmt.Errorf("%w: front %q", ErrSessionGatewayRefused, api)
}

// A response item of api, as GW hands it on completing it, in the form a later request carries it back: Responses'
// output item; Chat Completions' assistant message, whole at the chunk carrying finish_reason; a Messages content
// block (CTXH-M13-01), first saying whether it opens its response.
func sessionGatewayOutputOf(api SessionGatewayApi, item []byte, first bool) (map[string]any, error) {
	object, err := sessionGatewayObjectOf(item)
	if err != nil {
		return nil, err
	}
	switch api {
	case SessionGatewayApiResponses:
		return sessionResponsesNormalize(object), nil
	case SessionGatewayApiChatCompletions:
		return sessionChatNormalize(object), nil
	}
	return nil, fmt.Errorf("%w: front %q", ErrSessionGatewayRefused, api)
}

// Whether a member holds something: present, and neither null nor an empty string.
func sessionGatewayHolds(object map[string]any, member string) bool {
	value, ok := object[member]
	if !ok || value == nil {
		return false
	}
	if text, ok := value.(string); ok && text == "" {
		return false
	}
	return true
}

// Each element of a JSON array as an object, refused where one is not.
func sessionGatewayObjects(value any, what string) ([]map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	elements, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s is no array", ErrSessionGatewayRefused, what)
	}
	objects := make([]map[string]any, 0, len(elements))
	for _, element := range elements {
		object, ok := element.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: an element of %s is no object", ErrSessionGatewayRefused, what)
		}
		objects = append(objects, object)
	}
	return objects, nil
}

// Takes member out of object where it is an empty array.
func sessionGatewayDropEmpty(object map[string]any, member string) {
	if elements, ok := object[member].([]any); ok && len(elements) == 0 {
		delete(object, member)
	}
}

// An Open Responses request's items (see the file header).
func sessionResponsesItems(request map[string]any) (*sessionGatewayItems, error) {
	if sessionGatewayHolds(request, sessionResponsesPreviousResponseId) || sessionGatewayHolds(request, sessionResponsesConversation) {
		// the context is not in the request: the gateway stays stateless (Q-CTXH-9, D-GW-2)
		return nil, fmt.Errorf("%w: a request naming stored context", ErrSessionGatewayRefused)
	}
	items := &sessionGatewayItems{params: map[string]any{}}
	system := map[string]any{}
	for member, value := range request {
		switch member {
		case sessionResponsesInstructions, sessionResponsesTools:
			if value != nil {
				system[member] = value
			}
		case sessionResponsesInput:
		default:
			items.params[member] = value
		}
	}
	if 0 < len(system) {
		items.system = system
	}
	switch input := request[sessionResponsesInput].(type) {
	case nil:
	case string:
		items.input = []map[string]any{{sessionItemType: sessionResponsesTypeMessage, sessionItemRole: sessionRoleUser, sessionItemContent: input}}
	default:
		objects, err := sessionGatewayObjects(input, sessionResponsesInput)
		if err != nil {
			return nil, err
		}
		for _, object := range objects {
			items.input = append(items.input, sessionResponsesNormalize(object))
		}
	}
	return items, nil
}

// A Responses item as a later request carries it (the file header's moves row), changed in place.
func sessionResponsesNormalize(item map[string]any) map[string]any {
	itemType, _ := item[sessionItemType].(string)
	if itemType == "" {
		if _, ok := item[sessionItemRole]; ok {
			// an easy input message is a message item
			itemType = sessionResponsesTypeMessage
			item[sessionItemType] = itemType
		}
	}
	if itemType == sessionResponsesTypeItemReference {
		return item
	}
	for member, value := range item {
		if value == nil {
			delete(item, member)
		}
	}
	delete(item, sessionItemId)
	delete(item, sessionItemStatus)
	if itemType == sessionResponsesTypeReasoning {
		delete(item, sessionItemEncryptedContent)
	}
	if parts, ok := item[sessionItemContent].([]any); ok {
		for _, part := range parts {
			if object, ok := part.(map[string]any); ok {
				sessionGatewayDropEmpty(object, sessionItemAnnotations)
				sessionGatewayDropEmpty(object, sessionItemLogprobs)
			}
		}
	}
	return item
}

// A Chat Completions request's items (see the file header).
func sessionChatCompletionsItems(request map[string]any) (*sessionGatewayItems, error) {
	items := &sessionGatewayItems{params: map[string]any{}}
	system := map[string]any{}
	for member, value := range request {
		switch member {
		case sessionChatTools, sessionChatFunctions:
			if value != nil {
				system[member] = value
			}
		case sessionChatMessages:
		default:
			items.params[member] = value
		}
	}
	messages, err := sessionGatewayObjects(request[sessionChatMessages], sessionChatMessages)
	if err != nil {
		return nil, err
	}
	leading := []any{}
	for len(messages) != 0 {
		role, _ := messages[0][sessionItemRole].(string)
		if role != sessionChatRoleSystem && role != sessionChatRoleDeveloper {
			break
		}
		leading = append(leading, sessionChatNormalize(messages[0]))
		messages = messages[1:]
	}
	if 0 < len(leading) {
		system[sessionChatMessages] = leading
	}
	if 0 < len(system) {
		items.system = system
	}
	for _, message := range messages {
		items.input = append(items.input, sessionChatNormalize(message))
	}
	return items, nil
}

// A Chat Completions message as a later request carries it (the file header's moves row), changed in place.
func sessionChatNormalize(message map[string]any) map[string]any {
	for member, value := range message {
		if value == nil {
			delete(message, member)
		}
	}
	sessionGatewayDropEmpty(message, sessionItemAnnotations)
	if calls, ok := message[sessionChatToolCalls].([]any); ok {
		for _, call := range calls {
			if object, ok := call.(map[string]any); ok {
				delete(object, sessionItemIndex)
			}
		}
	}
	return message
}
