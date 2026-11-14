//go:build !js && !ios && !android && !sdk_mobile_bind

// Claude Code's hook payloads (§16.7's table; https://code.claude.com/docs/en/hooks, read 2026-11-03 and 2026-11-05):
// one JSON object on stdin with session_id, transcript_path, cwd, hook_event_name and permission_mode, then the event's
// own fields: SessionStart's source (startup, resume, clear, compact) and model, a tool event's tool_name, tool_input
// and tool_use_id (PermissionRequest carries none, REC:179). Its MCP tools are mcp__<server>__<tool>. Version 1.
//
// SessionStart's startup and clear open a new session; resume, compact, fork and any source this version does not know
// carry earlier context, the closed reading. An event this version does not name reads other, Unknown, and still binds;
// a field outside its event's schema below is drift (MCP-M3-28).

package mcp

import (
	"encoding/json"

	"github.com/urnetwork/sidecar"
)

// `ur hook`'s argument for Claude Code.
const claudeHookHarness = "claude-code"

// Claude Code's adapter, version 1.
type claudeHookAdapter struct{}

func (self *claudeHookAdapter) Harness() string {
	return claudeHookHarness
}

func (self *claudeHookAdapter) Version() int {
	return 1
}

// Claude Code reports every session's start.
func (self *claudeHookAdapter) ReportsSessionStart() bool {
	return true
}

// The fields this version reads.
type claudeHookPayload struct {
	SessionId      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	Cwd            string          `json:"cwd"`
	HookEventName  string          `json:"hook_event_name"`
	PermissionMode string          `json:"permission_mode"`
	Source         string          `json:"source"`
	Model          json.RawMessage `json:"model"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolUseId      string          `json:"tool_use_id"`
}

// The schema this version was written to (§16.7's sources, read 2026-11-03 and 2026-11-05; MCP-M3-28's recorded
// payloads, testdata/harness/claude-code/): the fields every event carries, then each event's own, by the event's
// name. InstructionsLoaded is read for the context alone (ingest_context.go), so it reads other but is no unknown
// event.
var claudeHookCommonFields = []string{"session_id", "transcript_path", "cwd", "hook_event_name", "permission_mode", "agent_id", "agent_type"}

var claudeHookEventFields = map[string][]string{
	"SessionStart":       {"source", "model", "session_title"},
	"SessionEnd":         {"reason"},
	"UserPromptSubmit":   {"prompt", "session_title"},
	"PreToolUse":         {"tool_name", "tool_input", "tool_use_id"},
	"PostToolUse":        {"tool_name", "tool_input", "tool_response", "tool_use_id"},
	"PermissionRequest":  {"tool_name", "tool_input", "tool_use_id", "permission_suggestions"},
	"Notification":       {"message", "title", "notification_type"},
	"Stop":               {"stop_hook_active"},
	"SubagentStop":       {"stop_hook_active", "agent_transcript_path"},
	"PreCompact":         {"trigger", "custom_instructions"},
	"InstructionsLoaded": {"file_path", "memory_type", "load_reason", "trigger_file_path", "parent_file_path", "globs"},
}

// Claude Code's events by its names.
var claudeHookEventKinds = map[string]HookEventKind{
	"SessionStart":      HookEventSessionStart,
	"SessionEnd":        HookEventSessionEnd,
	"UserPromptSubmit":  HookEventUserPrompt,
	"PreToolUse":        HookEventPreToolUse,
	"PostToolUse":       HookEventPostToolUse,
	"PermissionRequest": HookEventPermissionRequest,
	"Stop":              HookEventStop,
	"SubagentStop":      HookEventStop,
	"PreCompact":        HookEventCompact,
	"Notification":      HookEventNotification,
}

func (self *claudeHookAdapter) Parse(payload []byte, ingest *sidecar.SidecarIngestSettings) (*HookEvent, error) {
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
		Harness:        claudeHookHarness,
		AdapterVersion: self.Version(),
		HarnessEvent:   read.HookEventName,
		Kind:           HookEventOther,
		SessionId:      read.SessionId,
		Cwd:            read.Cwd,
		TranscriptPath: read.TranscriptPath,
		PermissionMode: read.PermissionMode,
	}
	if kind, ok := claudeHookEventKinds[read.HookEventName]; ok {
		event.Kind = kind
	}
	fields, known := claudeHookEventFields[read.HookEventName]
	event.Unknown = !known
	event.Drifted = known && hookPayloadDrifted(payload, claudeHookCommonFields, fields)
	model := ""
	if json.Unmarshal(read.Model, &model) == nil {
		event.Model = model
	} else {
		event.Model = hookObjectString(read.Model, "id")
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
