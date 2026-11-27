//go:build !ios_extension && !sidecar_http

// The Messages front's items as the gateway's recorder takes them (CTXH-M13-01; DESIGN-COMPUTE §24.8's items row, §8.3,
// §8.5): Claude Code's requests, POST /v1/messages, cut so that the chain hashes of a session's calls line up with the
// content blocks the gateway completes one at a time.
//
//	system    the request's system text, a string or blocks, and its tools, one object
//	input     one item a content block, {"role": <the message's>, "block": <the block>}, the first block of each
//	          message carrying "start": true, so a message's bounds survive; a string content is one text block. An
//	          answer's blocks are the same items, each completed at the chunk carrying its content_block_stop and the
//	          first starting the message, so the request that carries the answer back lands on the blocks it wrote
//	params    every other member, as sent
//	moves     cache_control, a hint whose place moves from call to call (§24.8), is left out of every system block,
//	          tool and content block, a tool_result's own blocks among them; a thinking block's signature, the
//	          gateway's own sealed blob (§8.5) whose text the block holds already, is left out as Responses'
//	          encrypted_content is
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"fmt"
)

// The members and values of a Messages request the recorder reads: format values.
const (
	sessionMessagesSystem       = "system"
	sessionMessagesTools        = "tools"
	sessionMessagesMessages     = "messages"
	sessionMessagesCacheControl = "cache_control"
	sessionMessagesSignature    = "signature"
	sessionMessagesBlock        = "block"
	sessionMessagesStart        = "start"
	sessionMessagesText         = "text"
	sessionMessagesTypeThinking = "thinking"
)

// A Messages request's items (see the file header).
func sessionMessagesItems(request map[string]any) (*sessionGatewayItems, error) {
	items := &sessionGatewayItems{params: map[string]any{}}
	system := map[string]any{}
	for member, value := range request {
		switch member {
		case sessionMessagesSystem:
			if value != nil {
				system[member] = sessionMessagesStripSystem(value)
			}
		case sessionMessagesTools:
			if value != nil {
				tools, err := sessionGatewayObjects(value, sessionMessagesTools)
				if err != nil {
					return nil, err
				}
				stripped := []any{}
				for _, tool := range tools {
					delete(tool, sessionMessagesCacheControl)
					stripped = append(stripped, tool)
				}
				system[member] = stripped
			}
		case sessionMessagesMessages:
		default:
			items.params[member] = value
		}
	}
	if 0 < len(system) {
		items.system = system
	}
	messages, err := sessionGatewayObjects(request[sessionMessagesMessages], sessionMessagesMessages)
	if err != nil {
		return nil, err
	}
	for _, message := range messages {
		role, _ := message[sessionItemRole].(string)
		blocks, err := sessionMessagesBlocks(message[sessionItemContent])
		if err != nil {
			return nil, err
		}
		for index, block := range blocks {
			items.input = append(items.input, sessionMessagesItem(role, block, index == 0))
		}
	}
	return items, nil
}

// A system text as recorded: a string as it is, blocks without cache_control.
func sessionMessagesStripSystem(value any) any {
	blocks, ok := value.([]any)
	if !ok {
		return value
	}
	for _, block := range blocks {
		if object, ok := block.(map[string]any); ok {
			delete(object, sessionMessagesCacheControl)
		}
	}
	return blocks
}

// A message's content as blocks: a string is one text block.
func sessionMessagesBlocks(content any) ([]map[string]any, error) {
	switch typed := content.(type) {
	case nil:
		return nil, nil
	case string:
		return []map[string]any{{sessionItemType: sessionMessagesText, sessionMessagesText: typed}}, nil
	}
	blocks, err := sessionGatewayObjects(content, sessionItemContent)
	if err != nil {
		return nil, fmt.Errorf("%w: a message's content", err)
	}
	return blocks, nil
}

// One content block as an item (the file header's input row), its moves left out (its moves row).
func sessionMessagesItem(role string, block map[string]any, start bool) map[string]any {
	sessionMessagesStripBlock(block)
	item := map[string]any{sessionItemRole: role, sessionMessagesBlock: block}
	if start {
		item[sessionMessagesStart] = true
	}
	return item
}

// A block without cache_control, a thinking block without its signature, a tool_result's own blocks too.
func sessionMessagesStripBlock(block map[string]any) {
	delete(block, sessionMessagesCacheControl)
	if kind, _ := block[sessionItemType].(string); kind == sessionMessagesTypeThinking {
		delete(block, sessionMessagesSignature)
	}
	if inner, ok := block[sessionItemContent].([]any); ok {
		for _, element := range inner {
			if object, ok := element.(map[string]any); ok {
				delete(object, sessionMessagesCacheControl)
			}
		}
	}
}

// A content block of the answer as GW completes it, at its content_block_stop, as an item: the assistant's, the
// first starting the message.
func sessionMessagesOutput(block map[string]any, first bool) map[string]any {
	return sessionMessagesItem(sessionRoleAssistant, block, first)
}
