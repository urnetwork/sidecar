//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's tool calls, hook events and permissions (RECORD.md sections 4.4 and 6.4):
//
//	tool_call    a PostToolUse-family event, source hook, with the harness's tool_use_id as the action's id; the
//	             daemon's own MCP calls, source observed, through RecordMcpCall, which MCP-M3-12's McpCallSink fills.
//	             A harness event with no tool_use_id takes 32 random bytes for its action_id and counts no_tool_id.
//	             input and output are the payload's tool_input and tool_response (Cursor: its own fields), redacted,
//	             at most PayloadByteCount together, the rest cut with truncated set and a truncation gap
//	hook_event   every other event, the payload redacted whole, within PayloadByteCount
//	permission   a PermissionRequest: asked, by nobody yet, under its mode, with the tool's class, name and the
//	             arguments hash §16.6 checks

package mcp

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// PermissionBody's and ToolCallBody's tool_class numbers.
const (
	ingestToolClassShell = 1
	ingestToolClassEdit  = 2
	ingestToolClassMcp   = 3
	ingestToolClassWeb   = 4
	ingestToolClassOther = 5
)

// PermissionBody's decision and decided_by for a PermissionRequest as the hook sees it: asked, by nobody yet.
const (
	ingestPermissionAsked     = 1
	ingestPermissionUndecided = 0
)

// A tool's class number.
func ingestToolClass(kind HookToolKind) uint32 {
	switch kind {
	case HookToolShell:
		return ingestToolClassShell
	case HookToolEdit:
		return ingestToolClassEdit
	case HookToolMcp:
		return ingestToolClassMcp
	case HookToolWeb:
		return ingestToolClassWeb
	}
	return ingestToolClassOther
}

// The tool's action_id: RECORD.md section 4.4's, or 32 random bytes with a no_tool_id gap when the event names none.
func (self *Ingest) toolActionIdWithLock(ctx context.Context, run *ingestRun, toolUseId string, countGap bool) []byte {
	if toolUseId != "" {
		if actionId, err := sidecar.RecordToolActionId(run.runId, toolUseId); err == nil {
			return actionId[:]
		}
	}
	if countGap {
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapNoToolId)
	}
	actionId := make([]byte, 32)
	rand.Read(actionId)
	return actionId
}

// input and output cut to PayloadByteCount together, output first: a truncation gap where cut.
func (self *Ingest) cutToolBodyWithLock(ctx context.Context, run *ingestRun, input []byte, output []byte) ([]byte, []byte, bool) {
	cap := self.settings.PayloadByteCount
	if int64(len(input)+len(output)) <= cap {
		return input, output, false
	}
	truncated := false
	if int64(len(input)) < cap {
		output, _ = ingestCut(output, cap-int64(len(input)))
		truncated = true
	} else {
		input, _ = ingestCut(input, cap)
		output = nil
		truncated = true
	}
	self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapTruncation)
	return input, output, truncated
}

// A PostToolUse-family event as a tool_call entry, source hook.
func (self *Ingest) captureToolCallWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, event *HookEvent, payload []byte) {
	state := run.state
	name := event.ToolName
	if event.ToolServer != "" {
		name = event.ToolServer + "/" + event.ToolName
	}
	if name != "" {
		state.ToolCounts[name] += 1
	}
	for _, path := range event.Paths {
		self.touchWithLock(run, path)
	}
	input, output := ingestToolInputOutput(event, payload)
	input = self.redact(ctx, run, redactor, input)
	output = self.redact(ctx, run, redactor, output)
	input, output, truncated := self.cutToolBodyWithLock(ctx, run, input, output)
	paths := []string{}
	for _, path := range event.Paths {
		paths = append(paths, self.relativeToCwd(state.Cwd, path))
	}
	if 256 < len(paths) {
		paths = paths[:256]
		if !truncated {
			self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapTruncation)
		}
		truncated = true
	}
	now := self.clock.Now().UnixMilli()
	toolName, _ := ingestCut([]byte(name), 64)
	self.appendWithLock(ctx, run, &ingestEntry{
		kind:     sidecar.RecordKindToolCall,
		source:   sidecar.RecordSourceHook,
		actionId: self.toolActionIdWithLock(ctx, run, event.ToolUseId, true),
		body: &protocol.ToolCallBody{
			ToolName:      string(toolName),
			ToolUseId:     event.ToolUseId,
			ToolClass:     ingestToolClass(event.ToolKind),
			Input:         input,
			Output:        output,
			StartedMillis: now,
			EndedMillis:   now,
			Paths:         paths,
			Truncated:     truncated,
		},
		byteCount:      int64(len(input) + len(output)),
		coverageSource: sidecar.RecordCoverageSourceHooks,
	})
}

// The payload's input and output of a tool event: Claude Code's and Codex's tool_input and tool_response, Cursor's
// tool_input, command and output, each as JSON or text.
func ingestToolInputOutput(event *HookEvent, payload []byte) ([]byte, []byte) {
	raw := json.RawMessage(payload)
	switch event.Harness {
	case cursorHookHarness:
		input := hookObjectRaw(raw, "tool_input")
		if input == nil {
			if command := hookObjectRaw(raw, "command"); command != nil {
				input = command
			}
		}
		output := hookObjectRaw(raw, "result")
		if output == nil {
			output = hookObjectRaw(raw, "output")
		}
		return ingestValueText(input), ingestValueText(output)
	}
	return hookObjectRaw(raw, "tool_input"), hookObjectRaw(raw, "tool_response")
}

// Any other event as a hook_event entry: the payload redacted whole.
func (self *Ingest) captureHookEventWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, event *HookEvent, payload []byte) {
	if event.Kind == HookEventPreToolUse {
		for _, path := range event.Paths {
			self.touchWithLock(run, path)
		}
	}
	redacted := self.redact(ctx, run, redactor, payload)
	redacted, cut := ingestCut(redacted, self.settings.PayloadByteCount)
	if cut {
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapTruncation)
	}
	self.appendWithLock(ctx, run, &ingestEntry{
		kind:   sidecar.RecordKindHookEvent,
		source: sidecar.RecordSourceHook,
		body: &protocol.HookEventBody{
			Event:           event.HarnessEvent,
			Payload:         redacted,
			ArgumentsSha256: event.ToolInputSha256,
		},
		byteCount:      int64(len(redacted)),
		coverageSource: sidecar.RecordCoverageSourceHooks,
	})
}

// A PermissionRequest as a permission entry: a harness's own step, never an I-8 decision.
func (self *Ingest) capturePermissionWithLock(ctx context.Context, run *ingestRun, event *HookEvent) {
	toolName, _ := ingestCut([]byte(event.ToolName), 64)
	mode, _ := ingestCut([]byte(event.PermissionMode), 32)
	self.appendWithLock(ctx, run, &ingestEntry{
		kind:   sidecar.RecordKindPermission,
		source: sidecar.RecordSourceHook,
		body: &protocol.PermissionBody{
			Decision:        ingestPermissionAsked,
			DecidedBy:       ingestPermissionUndecided,
			PermissionMode:  string(mode),
			ToolClass:       ingestToolClass(event.ToolKind),
			ToolName:        string(toolName),
			ArgumentsSha256: event.ToolInputSha256,
		},
		coverageSource: sidecar.RecordCoverageSourceHooks,
	})
}

// One of the daemon's own MCP calls, source observed: what MCP-M3-12's tool wrapper reports for every W call through
// McpCallSink. The arguments and result are redacted here, and the call's action_id links nothing a hook could name,
// so it takes random bytes and no gap. Nothing while the call's run is unbound, since its placeholder is no run file.
func (self *Ingest) RecordMcpCall(ctx context.Context, call *McpCall, toolName string, arguments []byte, result []byte, startedMillis int64, endedMillis int64, callErr error) {
	if call == nil || call.RunId == (sidecar.Id{}) {
		return
	}
	runs, err := call.Network.Runs()
	if err != nil {
		return
	}
	if _, err := runs.Get(call.RunId); err != nil {
		// an unbound session's placeholder: no run holds the call
		return
	}
	run, err := self.runFor(ctx, call.Network, call.NetworkId, call.RunId)
	if err != nil {
		return
	}
	run.runLock.Lock()
	defer run.runLock.Unlock()
	defer self.saveRunWithLock(run)
	redactor, err := self.redactor(call.Network)
	if err != nil {
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
		return
	}
	run.state.ToolCounts[urMcpServerName+"/"+toolName] += 1
	run.state.LastActivityMillis = self.clock.Now().UnixMilli()
	run.dirty = true
	input := self.redact(ctx, run, redactor, arguments)
	output := self.redact(ctx, run, redactor, result)
	input, output, truncated := self.cutToolBodyWithLock(ctx, run, input, output)
	exitCode := int32(0)
	if callErr != nil {
		exitCode = 1
	}
	name, _ := ingestCut([]byte(urMcpServerName+"/"+toolName), 64)
	self.appendWithLock(ctx, run, &ingestEntry{
		kind:     sidecar.RecordKindToolCall,
		source:   sidecar.RecordSourceObserved,
		actionId: self.toolActionIdWithLock(ctx, run, "", false),
		body: &protocol.ToolCallBody{
			ToolName:      string(name),
			ToolClass:     ingestToolClassMcp,
			Input:         input,
			Output:        output,
			StartedMillis: startedMillis,
			EndedMillis:   endedMillis,
			ExitCode:      exitCode,
			Truncated:     truncated,
		},
		byteCount:      int64(len(input) + len(output)),
		coverageSource: sidecar.RecordCoverageSourceMcp,
	})
}

// Notes a touched path for the run card, relative to the worktree, up to RunCardPathCount.
func (self *Ingest) touchWithLock(run *ingestRun, path string) {
	relative := self.relativeToCwd(run.state.Cwd, path)
	if relative == "" || slices.Contains(run.state.TouchedPaths, relative) {
		return
	}
	if self.settings.RunCardPathCount <= len(run.state.TouchedPaths) {
		return
	}
	run.state.TouchedPaths = append(run.state.TouchedPaths, relative)
	run.dirty = true
}

// A path relative to the run's cwd with / between segments, or as given when outside it.
func (self *Ingest) relativeToCwd(cwd string, path string) string {
	if cwd == "" || !filepath.IsAbs(path) {
		return filepath.ToSlash(path)
	}
	relative, err := filepath.Rel(cwd, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(relative)
}
