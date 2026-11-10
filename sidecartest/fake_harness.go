//go:build !js && !ios && !android && !sdk_mobile_bind

// sidecartest.FakeHarness (MCP-M3-15): a harness that runs hooks and MCP sessions the way Claude Code, Codex and
// Cursor do, over a FakeProcessTable, so the run rules' ancestry (§16.7; plan-MCP-taint-new-session) runs against a
// process tree a test builds, pid reuse and shells included. Pinned real harnesses are external (MCP-M3-28); this is
// their stand-in.
//
// A hook runs as a harness runs one: `ur hook` in a shell the harness spawned, its payload the harness's own JSON for
// the event, handed to a FakeHookSink, the daemon's hook.event in process, with the hello the daemon would read, its
// PeerPid the hook process's. An MCP session's hello is `ur mcp` spawned by the harness itself. A forger is any
// process a test spawns under the harness, which sends what it likes.
//
// Every value is synthetic: session ids, paths under /tmp/sidecartest, hosts under .example. Safe for concurrent use.

package sidecartest

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
)

// A process tree a test builds: pid 1 first, each spawn a fresh pid unless a test asks for one again, each start time
// later than any before, so a reused pid is another process. Safe for concurrent use.
type FakeProcessTable struct {
	stateLock       sync.Mutex
	clock           Clock
	nextPid         int
	lastStartMillis int64
	pidProcesses    map[int]*sidecar.ProcessInfo
}

// A table holding the system's first process, pid 1, on clock's time.
func NewFakeProcessTable(clock Clock) *FakeProcessTable {
	self := &FakeProcessTable{clock: clock, nextPid: 100, pidProcesses: map[int]*sidecar.ProcessInfo{}}
	self.SpawnPid(1, 0, "launchd")
	return self
}

// The process of pid, or sidecar.ErrProcessUnknown.
func (self *FakeProcessTable) Process(pid int) (*sidecar.ProcessInfo, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	process, ok := self.pidProcesses[pid]
	if !ok {
		return nil, sidecar.ErrProcessUnknown
	}
	copied := *process
	return &copied, nil
}

// A new process of name under parentPid, at a fresh pid.
func (self *FakeProcessTable) Spawn(parentPid int, name string) *sidecar.ProcessInfo {
	self.stateLock.Lock()
	for {
		self.nextPid += 1
		if _, taken := self.pidProcesses[self.nextPid]; !taken {
			break
		}
	}
	pid := self.nextPid
	self.stateLock.Unlock()
	return self.SpawnPid(pid, parentPid, name)
}

// A new process of name under parentPid at pid, which replaces any process there: the system handing a pid out again.
func (self *FakeProcessTable) SpawnPid(pid int, parentPid int, name string) *sidecar.ProcessInfo {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	startMillis := self.clock.Now().UnixMilli()
	if startMillis <= self.lastStartMillis {
		startMillis = self.lastStartMillis + 1
	}
	self.lastStartMillis = startMillis
	process := &sidecar.ProcessInfo{
		Identity:  sidecar.ProcessIdentity{Pid: pid, StartMillis: startMillis},
		ParentPid: parentPid,
		Name:      name,
	}
	self.pidProcesses[pid] = process
	copied := *process
	return &copied
}

// Ends pid's process. Its children keep their parent's pid, as Windows leaves them.
func (self *FakeProcessTable) Exit(pid int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.pidProcesses, pid)
}

// What hands a hook's payload to the daemon: its hook.event, in process.
type FakeHookSink func(hello *sidecar.DaemonHello, payload []byte) error

// The harnesses `ur hook` names.
const (
	FakeHarnessClaudeCode = "claude-code"
	FakeHarnessCodex      = "codex"
	FakeHarnessCursor     = "cursor"
)

// One harness process and the hooks and sessions it runs.
type FakeHarness struct {
	harness string
	table   *FakeProcessTable
	cwd     string
	sink    FakeHookSink
	process *sidecar.ProcessInfo
}

// A harness of kind harness, its process spawned under parentPid (a terminal's shell, say), working in cwd, its hooks
// handed to sink.
func NewFakeHarness(table *FakeProcessTable, parentPid int, harness string, cwd string, sink FakeHookSink) *FakeHarness {
	name := map[string]string{
		FakeHarnessClaudeCode: "claude",
		FakeHarnessCodex:      "codex",
		FakeHarnessCursor:     "Cursor Helper",
	}[harness]
	return &FakeHarness{harness: harness, table: table, cwd: cwd, sink: sink, process: table.Spawn(parentPid, name)}
}

// The harness process.
func (self *FakeHarness) Process() *sidecar.ProcessInfo {
	copied := *self.process
	return &copied
}

// The harness process exits.
func (self *FakeHarness) Exit() {
	self.table.Exit(self.process.Identity.Pid)
}

// A process the harness's agent runs through a shell, such as a ur command: a shell under the harness, the process
// under it. The caller exits it.
func (self *FakeHarness) ShellChild(name string) *sidecar.ProcessInfo {
	shell := self.table.Spawn(self.process.Identity.Pid, "bash")
	return self.table.Spawn(shell.Identity.Pid, name)
}

// The hello an MCP relay the harness spawned sends: `ur mcp`, a child of the harness, as the daemon reads it.
func (self *FakeHarness) RelayHello(agent string) *sidecar.DaemonHello {
	relay := self.table.Spawn(self.process.Identity.Pid, "ur")
	return &sidecar.DaemonHello{
		Mode:    sidecar.DaemonModeMcp,
		Version: sidecar.Version,
		Harness: self.harness,
		Agent:   agent,
		Cwd:     self.cwd,
		Pid:     int64(relay.Identity.Pid),
		PeerPid: int64(relay.Identity.Pid),
	}
}

// Runs one hook as the harness does: a shell under the harness running `ur hook`, the payload handed to the sink with
// the hook process's hello, then both exit. The sink's answer is the hook's.
func (self *FakeHarness) Hook(payload []byte) error {
	shell := self.table.Spawn(self.process.Identity.Pid, "sh")
	hook := self.table.Spawn(shell.Identity.Pid, "ur")
	defer self.table.Exit(shell.Identity.Pid)
	defer self.table.Exit(hook.Identity.Pid)
	return self.sink(self.hookHello(hook), payload)
}

// Runs a hook from a process of the test's, as a forger under the harness would: same payload form, any process.
func (self *FakeHarness) HookFrom(process *sidecar.ProcessInfo, payload []byte) error {
	return self.sink(self.hookHello(process), payload)
}

// A hook process's hello, as the daemon reads it.
func (self *FakeHarness) hookHello(process *sidecar.ProcessInfo) *sidecar.DaemonHello {
	return &sidecar.DaemonHello{
		Mode:    sidecar.DaemonModeHook,
		Version: sidecar.Version,
		Harness: self.harness,
		Cwd:     self.cwd,
		Pid:     int64(process.Identity.Pid),
		PeerPid: int64(process.Identity.Pid),
	}
}

// The harness's payload for an event of sessionId, with fields beside its common ones. Claude Code and Codex share a
// shape; Cursor's names its session conversation_id and its directory workspace_roots.
func (self *FakeHarness) Payload(sessionId string, event string, fields map[string]any) []byte {
	payload := map[string]any{}
	switch self.harness {
	case FakeHarnessCursor:
		payload["conversation_id"] = sessionId
		payload["generation_id"] = "generation-" + sessionId
		payload["workspace_roots"] = []string{self.cwd}
		payload["transcript_path"] = nil
	default:
		payload["session_id"] = sessionId
		payload["cwd"] = self.cwd
		payload["transcript_path"] = self.cwd + "/.transcripts/" + sessionId + ".jsonl"
		payload["permission_mode"] = "default"
	}
	payload["hook_event_name"] = event
	for name, value := range fields {
		payload[name] = value
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(fmt.Sprintf("a fake harness payload: %s", err))
	}
	return encoded
}

// A SessionStart of source: startup, resume, clear or compact. Claude Code's alone; the others report none.
func (self *FakeHarness) SessionStart(sessionId string, source string) error {
	return self.Hook(self.Payload(sessionId, "SessionStart", map[string]any{"source": source, "model": "test-model"}))
}

// A SessionEnd of reason.
func (self *FakeHarness) SessionEnd(sessionId string, reason string) error {
	if self.harness == FakeHarnessCursor {
		return self.Hook(self.Payload(sessionId, "stop", map[string]any{"status": reason}))
	}
	return self.Hook(self.Payload(sessionId, "SessionEnd", map[string]any{"reason": reason}))
}

// A tool call's hook before (pre) or after the tool runs, in the harness's own events: Claude Code's and Codex's
// PreToolUse and PostToolUse, Cursor's MCP, shell and file-edit events. An MCP tool of ur's is mcp__ur__<tool>.
func (self *FakeHarness) ToolCall(sessionId string, pre bool, toolName string, toolInput map[string]any) error {
	return self.Hook(self.ToolPayload(sessionId, pre, toolName, toolInput))
}

// ToolCall's payload.
func (self *FakeHarness) ToolPayload(sessionId string, pre bool, toolName string, toolInput map[string]any) []byte {
	if self.harness != FakeHarnessCursor {
		event := "PostToolUse"
		if pre {
			event = "PreToolUse"
		}
		return self.Payload(sessionId, event, map[string]any{
			"tool_name":   toolName,
			"tool_input":  toolInput,
			"tool_use_id": "toolu_" + sessionId,
		})
	}
	if tool, ok := strings.CutPrefix(toolName, "mcp__ur__"); ok {
		event := "afterMCPExecution"
		if pre {
			event = "beforeMCPExecution"
		}
		encodedInput, _ := json.Marshal(toolInput)
		return self.Payload(sessionId, event, map[string]any{
			"tool_name":  tool,
			"tool_input": string(encodedInput),
			"command":    "/tmp/sidecartest/bin/ur mcp",
		})
	}
	if toolName == "Bash" {
		event := "afterShellExecution"
		if pre {
			event = "beforeShellExecution"
		}
		return self.Payload(sessionId, event, map[string]any{"command": toolInput["command"]})
	}
	return self.Payload(sessionId, "afterFileEdit", map[string]any{"file_path": toolInput["file_path"]})
}
