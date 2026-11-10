//go:build !js && !ios && !android && !sdk_mobile_bind

// Cursor's hook payloads (§16.7's table; https://cursor.com/docs/agent/hooks, read 2026-11-03 and 2026-11-05):
// ~/.cursor/hooks.json version 1, one JSON object on stdin with conversation_id, generation_id, hook_event_name,
// workspace_roots and transcript_path (null when transcripts are off), and the event's own fields: beforeMCPExecution's
// and afterMCPExecution's tool_name, tool_input and the server's command or url, afterShellExecution's command, and
// afterFileEdit's file_path and edits. The conversation is the session. Version 1.
//
// Cursor reports no session's start, so a conversation's first event opens its run, which inherits its harness
// process's taint (plan-MCP-taint-new-session). beforeMCPExecution answers `ask` for ur's outward tools from the
// catalog built into this binary, so the answer needs no daemon (CursorHookAnswer).

package mcp

import (
	"encoding/json"
	"path"
	"strings"
	"sync/atomic"

	"github.com/urnetwork/sidecar"
)

// `ur hook`'s argument for Cursor.
const cursorHookHarness = "cursor"

// The MCP server name ur installs as, and the binary it runs (§16.7, §4.10).
const (
	urMcpServerName = "ur"
	urBinaryName    = "ur"
)

// Cursor's adapter, version 1.
type cursorHookAdapter struct{}

func (self *cursorHookAdapter) Harness() string {
	return cursorHookHarness
}

func (self *cursorHookAdapter) Version() int {
	return 1
}

// Cursor's hooks name no session start.
func (self *cursorHookAdapter) ReportsSessionStart() bool {
	return false
}

// The fields this version reads.
type cursorHookPayload struct {
	ConversationId string          `json:"conversation_id"`
	HookEventName  string          `json:"hook_event_name"`
	WorkspaceRoots []string        `json:"workspace_roots"`
	TranscriptPath *string         `json:"transcript_path"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	Command        string          `json:"command"`
	Url            string          `json:"url"`
	Server         string          `json:"server"`
	FilePath       string          `json:"file_path"`
	Model          string          `json:"model"`
}

func (self *cursorHookAdapter) Parse(payload []byte, ingest *sidecar.SidecarIngestSettings) (*HookEvent, error) {
	read := &cursorHookPayload{}
	if err := json.Unmarshal(payload, read); err != nil {
		return nil, hookPayloadError("json")
	}
	if read.ConversationId == "" {
		return nil, hookPayloadError("conversation_id")
	}
	if read.HookEventName == "" {
		return nil, hookPayloadError("hook_event_name")
	}
	event := &HookEvent{
		Harness:        cursorHookHarness,
		AdapterVersion: self.Version(),
		HarnessEvent:   read.HookEventName,
		Kind:           HookEventOther,
		SessionId:      read.ConversationId,
		Model:          read.Model,
	}
	if 0 < len(read.WorkspaceRoots) {
		event.Cwd = read.WorkspaceRoots[0]
	}
	if read.TranscriptPath != nil {
		event.TranscriptPath = *read.TranscriptPath
	}
	switch read.HookEventName {
	case "beforeMCPExecution", "afterMCPExecution":
		event.Kind = HookEventPreToolUse
		if read.HookEventName == "afterMCPExecution" {
			event.Kind = HookEventPostToolUse
		}
		event.ToolKind = HookToolMcp
		event.ToolName = read.ToolName
		event.ToolServer = cursorMcpServer(read)
		if server, tool, ok := hookMcpToolName(read.ToolName); ok {
			event.ToolServer = server
			event.ToolName = tool
		}
		// Cursor may give the arguments as a JSON string of them
		input := read.ToolInput
		text := ""
		if json.Unmarshal(read.ToolInput, &text) == nil {
			input = json.RawMessage(text)
		}
		event.ToolInputSha256 = hookToolInputSha256(input)
	case "beforeShellExecution", "afterShellExecution":
		event.Kind = HookEventPreToolUse
		if read.HookEventName == "afterShellExecution" {
			event.Kind = HookEventPostToolUse
		}
		event.ToolKind = HookToolShell
		event.ToolName = "shell"
		event.WebTool = hookShellWebTool(read.Command, ingest.WebToolNames)
	case "afterFileEdit":
		event.Kind = HookEventPostToolUse
		event.ToolKind = HookToolEdit
		event.ToolName = "edit"
		if read.FilePath != "" {
			event.Paths = []string{read.FilePath}
		}
	case "beforeSubmitPrompt":
		event.Kind = HookEventUserPrompt
	case "stop":
		event.Kind = HookEventStop
	}
	return event, nil
}

// The MCP server of a Cursor MCP event: its name where the payload gives one, else ur's where its command runs the ur
// binary, else empty, which no rule reads as ur's.
func cursorMcpServer(read *cursorHookPayload) string {
	if read.Server != "" {
		return read.Server
	}
	if read.Url != "" {
		// ur's MCP is stdio alone
		return ""
	}
	fields := strings.Fields(read.Command)
	if len(fields) == 0 {
		return ""
	}
	program := strings.ToLower(path.Base(strings.ReplaceAll(strings.Trim(fields[0], `"'`), `\`, "/")))
	if strings.TrimSuffix(program, ".exe") == urBinaryName {
		return urMcpServerName
	}
	return ""
}

// Whether a tool of ur's is outward, and whether the catalog names it: MCP-M3-12's catalog, built into this binary,
// sets it at init. With none set no tool's tier is known.
var hookToolTiers atomic.Pointer[func(name string) (outward bool, known bool)]

// Sets the catalog's tier lookup, which beforeMCPExecution's answer reads (MCP-M3-12).
func SetHookToolTiers(tierOf func(name string) (outward bool, known bool)) {
	hookToolTiers.Store(&tierOf)
}

// The line `ur hook cursor` prints for event, with no daemon: for a beforeMCPExecution of ur's, permission ask for a
// tool the catalog names outward or does not name at all, the closed direction while the catalog is not built; nil,
// printing nothing, for any other event or tool, which leaves Cursor's own rule to decide.
func CursorHookAnswer(event *HookEvent) []byte {
	if event.Harness != cursorHookHarness || event.HarnessEvent != "beforeMCPExecution" || event.ToolServer != urMcpServerName {
		return nil
	}
	if tierOf := hookToolTiers.Load(); tierOf != nil {
		if outward, known := (*tierOf)(event.ToolName); known && !outward {
			return nil
		}
	}
	return []byte(`{"permission":"ask"}`)
}
