//go:build !js && !ios && !android && !sdk_mobile_bind

// Codex's hook payloads (§16.7's table; https://learn.chatgpt.com/docs/hooks.md, read 2026-11-03 and 2026-11-05):
// ~/.codex/hooks.json's command hooks get one JSON object of Claude Code's shape, session_id, cwd, transcript_path and
// hook_event_name, with PermissionRequest, PreToolUse and PostToolUse for its shell, apply_patch and MCP tools, and
// SessionEnd. Its shell tool's command may be a list of words, and apply_patch carries its patch in
// tool_input.command; its MCP tools are mcp__<server>__<tool>. Version 1.
//
// Codex reports no session's start in the table §16.7 read, so a session's first event opens its run, which inherits
// its harness process's taint (plan-MCP-taint-new-session). A SessionStart it does send reads as Claude Code's does.
//
// PostModelRequest is §16.18's model call, Codex's one source of them (QD-835): ur install-harness hooks it
// (harness_install_codex.go), and Ingest records each as one model_call entry with its request id, tokens and
// duration while Ingest.ModelCalls is on (ingest_model.go). Its own fields, provider, request_id, duration_ms and
// usage, with model among the common ones, are the plan's names (MCP-M6-03), not a pinned build's: MCP-M3-28's
// recorded session carries them (testdata/harness/codex/), and the live conformance run in review pins them against a
// Codex build, until which a field Codex adds is drift, a hook_failure gap that taints the run like any other event's.

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

// The schema this version was written to (§16.7's sources, read 2026-11-03 and 2026-11-05; MCP-M3-28's recorded
// payloads, testdata/harness/codex/): the fields every event carries, then each event's own, by the event's name. An
// event this version does not name reads other, Unknown, and a field outside its event's lists is drift.
var codexHookCommonFields = []string{"session_id", "transcript_path", "cwd", "hook_event_name", "permission_mode", "model"}

var codexHookEventFields = map[string][]string{
	"SessionStart":      {"source"},
	"SessionEnd":        {"reason"},
	"UserPromptSubmit":  {"prompt"},
	"PreToolUse":        {"tool_name", "tool_input", "tool_use_id"},
	"PostToolUse":       {"tool_name", "tool_input", "tool_response", "tool_use_id"},
	"PermissionRequest": {"tool_name", "tool_input", "tool_use_id"},
	"Stop":              {"stop_hook_active"},
	// §16.18's model calls (MCP-M6-03; QD-835): the plan's names until the live conformance run pins them
	"PostModelRequest": {"provider", "request_id", "duration_ms", "usage"},
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
	"PostModelRequest":  HookEventModelCall,
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
	fields, known := codexHookEventFields[read.HookEventName]
	event.Unknown = !known
	event.Drifted = known && hookPayloadDrifted(payload, codexHookCommonFields, fields)
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
