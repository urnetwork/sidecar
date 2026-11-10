//go:build !js && !ios && !android && !sdk_mobile_bind

// Claude Code's hook payloads (§16.7's table; https://code.claude.com/docs/en/hooks, read 2026-11-03 and 2026-11-05):
// one JSON object on stdin with session_id, transcript_path, cwd, hook_event_name and permission_mode, then the event's
// own fields: SessionStart's source (startup, resume, clear, compact) and model, a tool event's tool_name, tool_input
// and tool_use_id (PermissionRequest carries none, REC:179). Its MCP tools are mcp__<server>__<tool>. Version 1.
//
// SessionStart's startup and clear open a new session; resume, compact, fork and any source this version does not know
// carry earlier context, the closed reading. An event this version does not name reads other, and still binds.

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
