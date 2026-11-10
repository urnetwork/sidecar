//go:build !js && !ios && !android && !sdk_mobile_bind

// Codex's hook payloads (§16.7's table; https://learn.chatgpt.com/docs/hooks.md, read 2026-11-03 and 2026-11-05):
// ~/.codex/hooks.json's command hooks get one JSON object of Claude Code's shape, session_id, cwd, transcript_path and
// hook_event_name, with PermissionRequest, PreToolUse and PostToolUse for its shell, apply_patch and MCP tools, and
// SessionEnd. Its shell tool's command may be a list of words, and apply_patch carries its patch in
// tool_input.command; its MCP tools are mcp__<server>__<tool>. Version 1.
//
// Codex reports no session's start in the table §16.7 read, so a session's first event opens its run, which inherits
// its harness process's taint (plan-MCP-taint-new-session). A SessionStart it does send reads as Claude Code's does.

package mcp

import (
	"encoding/json"

	"github.com/urnetwork/sidecar"
)

// `ur hook`'s argument for Codex.
const codexHookHarness = "codex"

// Codex's adapter, version 1.
type codexHookAdapter struct{}

func (self *codexHookAdapter) Harness() string {
	return codexHookHarness
}

func (self *codexHookAdapter) Version() int {
	return 1
}

// Codex's hooks name no session start.
func (self *codexHookAdapter) ReportsSessionStart() bool {
	return false
}

// Codex's events by its names.
var codexHookEventKinds = map[string]HookEventKind{
	"SessionStart":      HookEventSessionStart,
	"SessionEnd":        HookEventSessionEnd,
	"UserPromptSubmit":  HookEventUserPrompt,
	"PreToolUse":        HookEventPreToolUse,
	"PostToolUse":       HookEventPostToolUse,
	"PermissionRequest": HookEventPermissionRequest,
	"Stop":              HookEventStop,
}

func (self *codexHookAdapter) Parse(payload []byte, ingest *sidecar.SidecarIngestSettings) (*HookEvent, error) {
	read := &claudeHookPayload{}
	if err := json.Unmarshal(payload, read); err != nil {
		return nil, hookPayloadError("json")
	}
	if read.SessionId == "" {
		return nil, hookPayloadError("session_id")
	}
	if read.HookEventName == "" {
		return nil, hookPayloadError("hook_event_name")
	}
	event := &HookEvent{
		Harness:        codexHookHarness,
		AdapterVersion: self.Version(),
		HarnessEvent:   read.HookEventName,
		Kind:           HookEventOther,
		SessionId:      read.SessionId,
		Cwd:            read.Cwd,
		TranscriptPath: read.TranscriptPath,
		PermissionMode: read.PermissionMode,
	}
	if kind, ok := codexHookEventKinds[read.HookEventName]; ok {
		event.Kind = kind
	}
	model := ""
	if json.Unmarshal(read.Model, &model) == nil {
		event.Model = model
	}
	if event.Kind == HookEventSessionStart {
		switch read.Source {
		case "startup", "clear":
			event.Start = HookStartFresh
		default:
			event.Start = HookStartResumed
		}
	}
	if read.ToolName != "" {
		hookFillTool(event, read.ToolName, read.ToolInput, ingest)
		event.ToolUseId = read.ToolUseId
	}
	return event, nil
}
