//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's hooks (R-MCP-2, R-MCP-4, D-MCP-5, D-MCP-16, I-9): `ur hook <harness>` passes a harness's hook payload to the
// daemon (hello mode hook, method hook.event), and the daemon reads it through that harness's HookAdapter as one
// HookEvent, binds it to a run (hook_bind.go), taints the run for a web tool before it answers, and notes it for the
// coverage rules (hook_coverage.go). Every record made of a hook event says source hook.
//
// An adapter is versioned, written to its harness's published schema at the version MCP-M3-28's conformance pins
// (testdata/harness/<harness>/<version>/): the events it reads and each event's fields. A payload over
// Ingest.PayloadByteCount, or one it cannot read, is a coverage gap (oversize, hook_failure) on the runs of the hook's
// harness process; an event of a name the version does not read is a missed event (missed_event), and a payload naming
// a field its event's schema does not, as a harness that added one sends, is drift (hook_failure). Each is a lapse in
// the run's hook coverage, which taints it (I-9), and never an error to the harness: hooks fail open (D-MCP-5). An
// event that drifted or that the version does not read still binds, and never stands as harness evidence. Nothing here
// echoes a payload's text in an error or a log (I-7, I-13): an error names a field, never a value.
//
// The ack waits for what the event needs first: a web tool's taint, fsynced (§16.6's write-ahead row), and, for a
// PreToolUse naming paths, the restore point's holds of their bytes (MCP-M3-20's, through SetHookHolds). While the
// network is Locked a taint goes to the spool, fsynced, as the ack's precondition, and the binder applies it at unlock
// before any session's next call. A forged event is the disclosed residual for harness evidence, never for taint: an
// event can only add taint, bind a session to the taint its harness process already holds, or open a run that
// inherits it.

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
)

// The daemon method a hook calls (§5.8's hook mode). A reading: §16.7 names the mode, not the method.
const McpHookMethod = "hook.event"

// A payload an adapter cannot read. The error names the field, never a value.
var ErrHookPayload = errors.New("hook payload unreadable")

// What a hook event is, across the harnesses.
type HookEventKind string

const (
	HookEventSessionStart      HookEventKind = "session_start"
	HookEventSessionEnd        HookEventKind = "session_end"
	HookEventUserPrompt        HookEventKind = "user_prompt"
	HookEventPreToolUse        HookEventKind = "pre_tool_use"
	HookEventPostToolUse       HookEventKind = "post_tool_use"
	HookEventPermissionRequest HookEventKind = "permission_request"
	HookEventStop              HookEventKind = "stop"
	HookEventCompact           HookEventKind = "compact"
	HookEventNotification      HookEventKind = "notification"
	// A model call the harness reports: Codex's PostModelRequest (§16.18; MCP-M6-03).
	HookEventModelCall HookEventKind = "model_call"
	// An event the adapter's version reads only for coverage, or one it does not read at all (HookEvent.Unknown): it
	// still binds.
	HookEventOther HookEventKind = "other"
)

// What a SessionStart reports of the session's history (RECORD.md section 4.3's resumed row).
type HookStart string

const (
	// Not a SessionStart.
	HookStartNone HookStart = ""
	// A new session: a harness's startup, or the new session a clear opens.
	HookStartFresh HookStart = "fresh"
	// A session that carries earlier context by the harness's own report: a resume, a compact or a fork. A report this
	// adapter does not know reads resumed, the closed direction.
	HookStartResumed HookStart = "resumed"
)

// What a tool event's tool is.
type HookToolKind string

const (
	HookToolNone  HookToolKind = ""
	HookToolMcp   HookToolKind = "mcp"
	HookToolShell HookToolKind = "shell"
	HookToolEdit  HookToolKind = "edit"
	HookToolWeb   HookToolKind = "web"
	HookToolOther HookToolKind = "other"
)

// One harness hook event, as every adapter reads its harness's payload (§16.7). Paths, prompts and commands are the
// person's own and stay local; nothing here is logged.
type HookEvent struct {
	Harness        string
	AdapterVersion int
	// The harness's own name for the event.
	HarnessEvent string
	Kind         HookEventKind
	SessionId    string
	Start        HookStart
	Cwd          string
	// The transcript the harness keeps, empty when it keeps none.
	TranscriptPath string
	PermissionMode string
	Model          string
	ToolKind       HookToolKind
	// The tool, the harness's MCP prefix stripped.
	ToolName string
	// The MCP server the tool is of, empty for the harness's own tool.
	ToolServer string
	ToolUseId  string
	// SHA-256 of the RFC 8785 form of the tool's arguments, which the hook and the MCP call alike compute (MCP.md's
	// reading 2). Nil with no arguments, or arguments that do not canonicalize.
	ToolInputSha256 []byte
	// The paths the call names, as the payload gives them.
	Paths []string
	// A web tool by Ingest.WebToolNames: by its name, or by a shell call's stage's first word (MCP.md's reading 12).
	WebTool bool
	// No event of this name is one the adapter's version reads: what it carried is missed, a lapse that taints the
	// run's members with a missed_event gap (MCP-M3-28).
	Unknown bool
	// The payload names a field the schema the adapter's version was written to does not give its event, as a harness
	// that added a field would send: what was read may not be all the event meant, a lapse that taints the run's
	// members with a hook_failure gap, and an asking event that drifted is no harness evidence (MCP-M3-28).
	Drifted bool
}

// One harness's reading of its hook payloads, at one version.
type HookAdapter interface {
	// `ur hook`'s argument: claude-code, codex or cursor.
	Harness() string
	Version() int
	// Whether the harness reports each session's start, so an event of a session never seen whose first is no
	// SessionStart missed it (plan-MCP-taint-new-session).
	ReportsSessionStart() bool
	// The event, or ErrHookPayload naming the field it could not read.
	Parse(payload []byte, ingest *sidecar.SidecarIngestSettings) (*HookEvent, error)
}

// The adapters, by harness.
var hookAdapters = map[string]HookAdapter{
	claudeHookHarness: &claudeHookAdapter{},
	codexHookHarness:  &codexHookAdapter{},
	cursorHookHarness: &cursorHookAdapter{},
}

// The adapter of a harness `ur hook` names.
func HookAdapterFor(harness string) (HookAdapter, bool) {
	adapter, ok := hookAdapters[harness]
	return adapter, ok
}

// The harnesses `ur hook` takes, sorted.
func HookHarnesses() []string {
	harnesses := []string{}
	for harness := range hookAdapters {
		harnesses = append(harnesses, harness)
	}
	slices.Sort(harnesses)
	return harnesses
}

// The refusal of a payload's field.
func hookPayloadError(field string) error {
	return fmt.Errorf("%w: %s", ErrHookPayload, field)
}

// Whether payload, one JSON object, names a field outside common and its event's own: the schema it was written to
// has moved past the adapter version's (MCP-M3-28). A payload that is no object drifted.
func hookPayloadDrifted(payload []byte, common []string, fields []string) bool {
	object := map[string]json.RawMessage{}
	if json.Unmarshal(payload, &object) != nil {
		return true
	}
	for name := range object {
		if !slices.Contains(common, name) && !slices.Contains(fields, name) {
			return true
		}
	}
	return false
}

// SHA-256 of the RFC 8785 form of a tool's arguments; nil for none or for arguments that do not canonicalize.
func hookToolInputSha256(input json.RawMessage) []byte {
	trimmed := strings.TrimSpace(string(input))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	canonical, err := sidecar.CanonicalJson([]byte(trimmed))
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(canonical)
	return sum[:]
}

// A harness's MCP tool name, mcp__<server>__<tool>, split; ok false for a name of another form.
func hookMcpToolName(name string) (server string, tool string, ok bool) {
	rest, found := strings.CutPrefix(name, "mcp__")
	if !found {
		return "", "", false
	}
	server, tool, found = strings.Cut(rest, "__")
	if !found || server == "" || tool == "" {
		return "", "", false
	}
	return server, tool, true
}

// Whether a shell command reaches a web tool: the first word of any pipeline stage, past leading NAME=value
// assignments, by its base name. A wrapped call such as `python -c` goes unseen (MCP.md's reading 12).
func hookShellWebTool(command string, webToolNames []string) bool {
	stages := strings.FieldsFunc(command, func(r rune) bool {
		return r == '|' || r == '&' || r == ';' || r == '\n' || r == '(' || r == ')' || r == '`'
	})
	for _, stage := range stages {
		for _, word := range strings.Fields(stage) {
			word = strings.Trim(word, `"'`)
			if strings.Contains(word, "=") && !strings.HasPrefix(word, "=") && !strings.Contains(word, "/") {
				// an assignment before the command
				continue
			}
			if slices.Contains(webToolNames, path.Base(strings.ReplaceAll(word, `\`, "/"))) {
				return true
			}
			break
		}
	}
	return false
}

// The paths a unified patch of apply_patch's form names: its Add, Update, Delete and Move to headers.
func hookPatchPaths(patch string) []string {
	paths := []string{}
	for _, line := range strings.Split(patch, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range []string{"*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "} {
			if rest, found := strings.CutPrefix(line, prefix); found && rest != "" && !slices.Contains(paths, rest) {
				paths = append(paths, rest)
			}
		}
	}
	return paths
}

// A JSON value that is one string, or a list of strings joined by spaces, as a shell tool's command may be; empty for
// any other.
func hookStringOrWords(value json.RawMessage) string {
	text := ""
	if json.Unmarshal(value, &text) == nil {
		return text
	}
	words := []string{}
	if json.Unmarshal(value, &words) == nil {
		return strings.Join(words, " ")
	}
	return ""
}

// The shell command a shell tool runs: the string itself, or, for a list of words, the script of a shell the list
// starts, as `bash -lc <script>`, else the words joined.
func hookShellCommand(value json.RawMessage, shellNames []string) string {
	words := []string{}
	if json.Unmarshal(value, &words) != nil {
		return hookStringOrWords(value)
	}
	if 3 <= len(words) {
		program := strings.TrimSuffix(strings.ToLower(path.Base(strings.ReplaceAll(words[0], `\`, "/"))), ".exe")
		flags := words[len(words)-2]
		if slices.Contains(shellNames, program) && strings.HasPrefix(flags, "-") && strings.Contains(flags, "c") {
			return words[len(words)-1]
		}
	}
	return strings.Join(words, " ")
}

// The string at name in an object, empty when absent or not a string.
func hookObjectString(object json.RawMessage, name string) string {
	fields := map[string]json.RawMessage{}
	if json.Unmarshal(object, &fields) != nil {
		return ""
	}
	text := ""
	json.Unmarshal(fields[name], &text)
	return text
}

// Fills a tool event's kind, name, server, arguments' hash, paths and web bit from a Claude Code style tool_name and
// tool_input, which Codex shares.
func hookFillTool(event *HookEvent, toolName string, toolInput json.RawMessage, ingest *sidecar.SidecarIngestSettings) {
	event.ToolInputSha256 = hookToolInputSha256(toolInput)
	if server, tool, ok := hookMcpToolName(toolName); ok {
		event.ToolKind = HookToolMcp
		event.ToolServer = server
		event.ToolName = tool
		return
	}
	event.ToolName = toolName
	switch toolName {
	case "Bash", "shell", "local_shell", "exec_command", "container.exec":
		event.ToolKind = HookToolShell
		event.WebTool = hookShellWebTool(hookShellCommand(json.RawMessage(hookObjectRaw(toolInput, "command")), ingest.ShellNames), ingest.WebToolNames)
	case "Edit", "Write", "MultiEdit":
		event.ToolKind = HookToolEdit
		if filePath := hookObjectString(toolInput, "file_path"); filePath != "" {
			event.Paths = []string{filePath}
		}
	case "NotebookEdit":
		event.ToolKind = HookToolEdit
		if notebookPath := hookObjectString(toolInput, "notebook_path"); notebookPath != "" {
			event.Paths = []string{notebookPath}
		}
	case "apply_patch":
		event.ToolKind = HookToolEdit
		patch := hookStringOrWords(json.RawMessage(hookObjectRaw(toolInput, "command")))
		if patch == "" {
			patch = hookObjectString(toolInput, "input")
		}
		event.Paths = hookPatchPaths(patch)
	default:
		event.ToolKind = HookToolOther
	}
	if slices.Contains(ingest.WebToolNames, toolName) {
		event.ToolKind = HookToolWeb
		event.WebTool = true
	}
}

// The raw value at name in an object, nil when absent.
func hookObjectRaw(object json.RawMessage, name string) []byte {
	fields := map[string]json.RawMessage{}
	if json.Unmarshal(object, &fields) != nil {
		return nil
	}
	return fields[name]
}

// What a PreToolUse's paths are held by before its tool runs: MCP-M3-20's restore point. Nil holds nothing, so a
// path's before stays unknown, the closed direction for restore.
type HookHolds func(ctx context.Context, network McpNetwork, networkId sidecar.Id, runId sidecar.Id, event *HookEvent) error

// hook.event's params: the payload as the harness wrote it, or, past Ingest.PayloadByteCount, its size alone.
type HookEventParams struct {
	Payload   json.RawMessage `json:"payload,omitempty"`
	ByteCount int64           `json:"byte_count"`
	Oversize  bool            `json:"oversize,omitempty"`
}

// What captures a hook event once it is bound, tainted and held (MCP-M3-19's Ingest). It runs after the ack's
// preconditions, and its error is its own: the hook is acked whatever it answers.
type HookCapture func(ctx context.Context, captured *HookCaptured) error

// The daemon's hook state: the holds and capture seams, and where status notes go, under its own lock.
type mcpHooks struct {
	stateLock sync.Mutex
	holds     HookHolds
	capture   HookCapture
	// the network's status writer, nil for hookStatusWriterOf
	statusWriterOf func(network McpNetwork) (HookStatusWriter, bool)
}

// Sets what holds a PreToolUse's paths (MCP-M3-20).
func (self *McpServer) SetHookHolds(holds HookHolds) {
	self.hooks.stateLock.Lock()
	defer self.hooks.stateLock.Unlock()
	self.hooks.holds = holds
}

// Sets what captures each bound event (MCP-M3-19). Nil captures nothing.
func (self *McpServer) SetHookCapture(capture HookCapture) {
	self.hooks.stateLock.Lock()
	defer self.hooks.stateLock.Unlock()
	self.hooks.capture = capture
}

// The capture seam as set.
func (self *McpServer) hookCapture() HookCapture {
	self.hooks.stateLock.Lock()
	defer self.hooks.stateLock.Unlock()
	return self.hooks.capture
}

// The daemon methods the server adds beside its mcp mode: hook.event, which every `ur hook` calls, acting on the
// network of its cwd's `.ur`, else the only one.
func (self *McpServer) DaemonMethods() []*sidecar.DaemonMethod {
	return []*sidecar.DaemonMethod{{
		Name:    McpHookMethod,
		Network: true,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &HookEventParams{}
			if len(call.Params) != 0 {
				if err := json.Unmarshal(call.Params, params); err != nil {
					return nil, hookPayloadError("params")
				}
			}
			return nil, self.HandleHook(ctx, call.Hello, call.NetworkId, call.Sidecar, params)
		},
	}}
}

// One hook event of hello's harness on a network: read, bound, tainted for a web tool and noted, all before the
// answer. An error fails the ack, which `ur hook` passes over, failing open.
func (self *McpServer) HandleHook(ctx context.Context, hello *sidecar.DaemonHello, networkId sidecar.Id, network McpNetwork, params *HookEventParams) error {
	adapter, ok := HookAdapterFor(hello.Harness)
	if !ok {
		return hookPayloadError("harness")
	}
	caller := self.binder.callerProcessOf(hello)
	if params.Oversize || self.settings.Ingest.PayloadByteCount < int64(len(params.Payload)) {
		return self.binder.gapProcess(ctx, network, caller, "oversize")
	}
	event, err := adapter.Parse(params.Payload, self.settings.Ingest)
	if err != nil {
		if gapErr := self.binder.gapProcess(ctx, network, caller, "hook_failure"); gapErr != nil {
			return gapErr
		}
		return err
	}
	// the caller's hello rides with the event: the directory lifecycle reads the session's claims from it
	if err := self.binder.ingestEvent(withHookHello(ctx, hello), network, networkId, adapter, caller, event, params.Payload); err != nil {
		return err
	}
	self.noteHookStatus(network, hello, adapter, event)
	return nil
}

// A network that writes its agents' status lines (DESIGN-COMPUTE §20.6): *sidecar.Sidecar is one, and so is each tool
// view over one, which embeds it.
type HookStatusNetwork interface {
	AgentStatus() (*sidecar.AgentStatusWriter, error)
}

// Where a hook's status notes go: an *sidecar.AgentStatusWriter, which writes them at its own pace.
type HookStatusWriter interface {
	Note(note *sidecar.AgentStatusNote)
	Settings() *sidecar.SkillSettings
}

// The network's status writer, false for a network that writes none.
func hookStatusWriterOf(network McpNetwork) (HookStatusWriter, bool) {
	statusNetwork, ok := network.(HookStatusNetwork)
	if !ok {
		return nil, false
	}
	writer, err := statusNetwork.AgentStatus()
	if err != nil {
		return nil, false
	}
	return writer, true
}

// The status writer of network the server notes into.
func (self *McpServer) hookStatusWriter(network McpNetwork) (HookStatusWriter, bool) {
	statusWriterOf := func() func(network McpNetwork) (HookStatusWriter, bool) {
		self.hooks.stateLock.Lock()
		defer self.hooks.stateLock.Unlock()
		return self.hooks.statusWriterOf
	}()
	if statusWriterOf == nil {
		statusWriterOf = hookStatusWriterOf
	}
	return statusWriterOf(network)
}

// The status an event sets, and whether it sets one: SessionStart and Stop waiting for the person, PreToolUse working
// on its tool, SessionEnd offline (§20.6's external harnesses row).
func hookStatusOf(event *HookEvent) (sidecar.AgentState, string, bool) {
	switch event.Kind {
	case HookEventSessionStart:
		return sidecar.AgentStateWaiting, "session started", true
	case HookEventPreToolUse:
		return sidecar.AgentStateWorking, "running " + event.ToolName, true
	case HookEventStop:
		return sidecar.AgentStateWaiting, "waiting for the person", true
	case HookEventSessionEnd:
		return sidecar.AgentStateOffline, "session ended", true
	}
	return "", "", false
}

// The session agent's label for a hook: the hello's, else the project's `.ur` default, as a session's agent is
// (session.go); "" for none.
func hookAgentLabel(hello *sidecar.DaemonHello, event *HookEvent) string {
	if hello != nil && hello.Agent != "" {
		return hello.Agent
	}
	cwd := event.Cwd
	if cwd == "" && hello != nil {
		cwd = hello.Cwd
	}
	found, err := sidecar.FindSidecarProject(cwd, "")
	if err != nil || found == nil {
		return ""
	}
	return found.Agent
}

// The run the event's session is bound to, zero for none.
func (self *RunBinder) sessionRunId(runs *sidecar.RunStore, event *HookEvent) sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	index, ok := self.storeIndexes[runs]
	if !ok {
		return sidecar.Id{}
	}
	return index.sessionRunIds[runSessionKey{harness: event.Harness, sessionId: event.SessionId}]
}

// Notes the session agent's status line at a hook event (§20.6; SKILL-M11-03): at SessionStart, PreToolUse and Stop,
// and offline at SessionEnd, into the network's status writer, which writes at most once a StatusMinInterval, the push
// sealing the run's taint, and registers the agent first where it has no card. A session with no agent, or one whose
// label is no agent name, a Locked network and a network that writes no status lines note nothing. It never waits on a
// write and never fails the ack: hooks fail open (D-MCP-5).
func (self *McpServer) noteHookStatus(network McpNetwork, hello *sidecar.DaemonHello, adapter HookAdapter, event *HookEvent) {
	state, activity, sets := hookStatusOf(event)
	if !sets || network.Status().State == sidecar.SidecarStateLocked {
		return
	}
	writer, ok := self.hookStatusWriter(network)
	if !ok {
		return
	}
	label := hookAgentLabel(hello, event)
	if label == "" {
		return
	}
	name, err := sidecar.ParseAgentName(label, writer.Settings())
	if err != nil {
		return
	}
	runId, tainted := sidecar.Id{}, true
	if runs, err := network.Runs(); err == nil {
		runId = self.binder.sessionRunId(runs, event)
		if runId != (sidecar.Id{}) {
			tainted = runs.Tainted(runId)
		}
	}
	settings := writer.Settings()
	writer.Note(&sidecar.AgentStatusNote{
		Name: name,
		Status: &sidecar.AgentStatus{
			State:    state,
			Activity: sidecar.AgentStatusText(activity, settings.StatusActivityCharCount),
			Updated:  self.clock.Now(),
			RunId:    runId,
		},
		Tainted: tainted,
		Register: &sidecar.AgentRegisterArgs{
			Name:    string(name),
			Harness: sidecar.AgentCardFieldText(adapter.Harness(), settings),
			Model:   sidecar.AgentCardFieldText(event.Model, settings),
		},
	})
}
