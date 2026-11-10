//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's hooks and §16.6's run rules on sidecartest's FakeHarness and FakeProcessTable: each adapter's reading, runs
// bound by session and by harness process, taint that no forged event launders and no restart loses (FS-27's core), a
// web tool's taint fsynced before the ack, a Locked taint applied before the next call, coverage lapses on the fake
// clock, and a reused pid that binds nothing.

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The project directory every fake harness works in.
const hookTestCwd = "/tmp/sidecartest/project"

// A daemon's MCP server with one Online network, a fake process tree under a terminal, and harnesses whose hooks reach
// the server's hook.event in process.
type hookTestEnv struct {
	t         *testing.T
	clock     *sidecartest.FakeClock
	table     *sidecartest.FakeProcessTable
	daemon    *fakeMcpDaemon
	networkId sidecar.Id
	network   *fakeMcpNetwork
	server    *McpServer
	terminal  *sidecar.ProcessInfo
}

// The env, every harness config reading unchanged unless a test says otherwise.
func newHookTestEnv(t *testing.T) *hookTestEnv {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	table := sidecartest.NewFakeProcessTable(clock)
	daemon := newFakeMcpDaemon()
	networkId, network := daemon.host(t, sidecar.SidecarStateOnline, clock)
	env := &hookTestEnv{t: t, clock: clock, table: table, daemon: daemon, networkId: networkId, network: network}
	env.server = env.newServer()
	env.terminal = table.Spawn(1, "zsh")
	return env
}

// A server over the env's daemon, as a restarted daemon makes one.
func (self *hookTestEnv) newServer() *McpServer {
	settings := NewMcpServerSettings(sidecar.DefaultSidecarSettings(), sidecar.Version)
	settings.Clock = self.clock
	settings.Processes = self.table
	server := NewMcpServer(self.daemon, settings)
	server.Binder().SetConfigCheck(func(ctx context.Context, harness string, cwd string) (bool, error) {
		return false, nil
	})
	return server
}

// A daemon's restart: a new server, and a run store with nothing in memory over the same files.
func (self *hookTestEnv) restart() {
	self.t.Helper()
	self.network.reopenRuns(self.t, self.clock)
	self.server = self.newServer()
}

// A harness of kind under the terminal, its hooks handed to the current server.
func (self *hookTestEnv) harness(kind string) *sidecartest.FakeHarness {
	return sidecartest.NewFakeHarness(self.table, self.terminal.Identity.Pid, kind, hookTestCwd, self.sink)
}

// hook.event in process.
func (self *hookTestEnv) sink(hello *sidecar.DaemonHello, payload []byte) error {
	return self.server.HandleHook(context.Background(), hello, self.networkId, self.network,
		&HookEventParams{Payload: payload, ByteCount: int64(len(payload))})
}

// The run (harness, sessionId) is bound to; fails when there is none.
func (self *hookTestEnv) runOf(harness string, sessionId string) sidecar.Id {
	self.t.Helper()
	index, err := self.server.binder.indexFor(context.Background(), self.network.runs)
	if err != nil {
		self.t.Fatal(err)
	}
	self.server.binder.stateLock.Lock()
	defer self.server.binder.stateLock.Unlock()
	runId, ok := index.sessionRunIds[runSessionKey{harness: harness, sessionId: sessionId}]
	if !ok {
		self.t.Fatalf("no run for %s %s", harness, sessionId)
	}
	return runId
}

// Whether a run's file, read by a store with nothing in memory, says tainted: what a restart would read.
func (self *hookTestEnv) taintedOnDisk(runId sidecar.Id) bool {
	self.t.Helper()
	runs, err := sidecar.NewRunStore(self.network.store.Root(), sidecar.DefaultSidecarSettings().Mcp, self.clock)
	if err != nil {
		self.t.Fatal(err)
	}
	run, err := runs.Get(runId)
	if err != nil {
		self.t.Fatalf("run %s's file: %s", runId, err)
	}
	return run.Tainted
}

// One call of an MCP session of hello, readied as the server readies a tools/call: its session made once per hello.
func (self *hookTestEnv) call(session *McpSession) *McpCall {
	self.t.Helper()
	call := &McpCall{Session: session, NetworkId: self.networkId, Network: self.network}
	if err := self.server.binder.readyCall(context.Background(), call); err != nil {
		self.t.Fatalf("readyCall: %s", err)
	}
	return call
}

// A seed payload of testdata/harness.
func harnessSeed(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "testdata", "harness", name))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// A tool input's hash, as the adapters compute it.
func canonicalSha256(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := sidecar.CanonicalJson(encoded)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	return sum[:]
}

func TestClaudeAdapterReadsEvents(t *testing.T) {
	ingest := sidecar.DefaultSidecarSettings().Ingest
	adapter, _ := HookAdapterFor("claude-code")
	parse := func(name string) *HookEvent {
		t.Helper()
		event, err := adapter.Parse(harnessSeed(t, name), ingest)
		if err != nil {
			t.Fatalf("%s: %s", name, err)
		}
		return event
	}
	start := parse("claude-code-session-start.json")
	if start.Kind != HookEventSessionStart || start.Start != HookStartFresh || start.Model != "test-model" || start.Cwd != hookTestCwd {
		t.Errorf("SessionStart: %+v", start)
	}
	if resume := parse("claude-code-session-resume.json"); resume.Start != HookStartResumed || resume.PermissionMode != "acceptEdits" {
		t.Errorf("a resume: %+v", resume)
	}
	webfetch := parse("claude-code-pre-tool-use-webfetch.json")
	if webfetch.Kind != HookEventPreToolUse || !webfetch.WebTool || webfetch.ToolKind != HookToolWeb || webfetch.ToolUseId != "toolu_01webfetch" {
		t.Errorf("WebFetch: %+v", webfetch)
	}
	mcp := parse("claude-code-pre-tool-use-mcp.json")
	if mcp.ToolKind != HookToolMcp || mcp.ToolServer != "ur" || mcp.ToolName != "evs_read" || mcp.WebTool ||
		string(mcp.ToolInputSha256) != string(canonicalSha256(t, map[string]any{"path": "plan.md", "repo": "notes"})) {
		t.Errorf("an MCP call: %+v", mcp)
	}
	if edit := parse("claude-code-pre-tool-use-edit.json"); !slices.Equal(edit.Paths, []string{hookTestCwd + "/main.go"}) || edit.ToolKind != HookToolEdit {
		t.Errorf("Edit: %+v", edit)
	}
	if bash := parse("claude-code-post-tool-use-bash.json"); !bash.WebTool || bash.ToolKind != HookToolShell {
		t.Errorf("a Bash call reaching curl past an assignment: %+v", bash)
	}
	if permission := parse("claude-code-permission-request.json"); permission.Kind != HookEventPermissionRequest || permission.ToolUseId != "" || permission.ToolName != "mail_send" {
		t.Errorf("PermissionRequest: %+v", permission)
	}
	if end := parse("claude-code-session-end.json"); end.Kind != HookEventSessionEnd {
		t.Errorf("SessionEnd: %+v", end)
	}
	for _, payload := range []string{`{}`, `{"session_id":"x"}`, `{"hook_event_name":"Stop"}`, `[1,2]`, `not json`} {
		if _, err := adapter.Parse([]byte(payload), ingest); err == nil {
			t.Errorf("%s read", payload)
		}
	}
}

func TestCodexAdapterReadsEvents(t *testing.T) {
	ingest := sidecar.DefaultSidecarSettings().Ingest
	adapter, _ := HookAdapterFor("codex")
	if adapter.ReportsSessionStart() {
		t.Error("Codex reports a session's start")
	}
	shell, err := adapter.Parse(harnessSeed(t, "codex-pre-tool-use-shell.json"), ingest)
	if err != nil || !shell.WebTool || shell.ToolKind != HookToolShell {
		t.Errorf("a shell call of words reaching wget: %+v %v", shell, err)
	}
	patch, err := adapter.Parse(harnessSeed(t, "codex-pre-tool-use-apply-patch.json"), ingest)
	if err != nil || !slices.Equal(patch.Paths, []string{"main.go", "notes/new.md"}) || patch.ToolKind != HookToolEdit {
		t.Errorf("apply_patch: %+v %v", patch, err)
	}
	mcp, err := adapter.Parse(harnessSeed(t, "codex-post-tool-use-mcp.json"), ingest)
	if err != nil || mcp.ToolServer != "ur" || mcp.ToolName != "team_members" || mcp.Kind != HookEventPostToolUse {
		t.Errorf("an MCP call: %+v %v", mcp, err)
	}
}

func TestCursorAdapterReadsEvents(t *testing.T) {
	ingest := sidecar.DefaultSidecarSettings().Ingest
	adapter, _ := HookAdapterFor("cursor")
	before, err := adapter.Parse(harnessSeed(t, "cursor-before-mcp-execution.json"), ingest)
	if err != nil || before.Kind != HookEventPreToolUse || before.ToolServer != "ur" || before.ToolName != "mail_send" ||
		before.SessionId != "c0ffee-conversation" || before.Cwd != hookTestCwd || before.TranscriptPath != "" {
		t.Fatalf("beforeMCPExecution: %+v %v", before, err)
	}
	// the arguments hash alike whether a harness sends them as an object or as a string of one (MCP.md's reading 2)
	if string(before.ToolInputSha256) != string(canonicalSha256(t, map[string]any{"subject": "hi", "to": []string{"someone@mail.example"}})) {
		t.Error("a string of arguments hashed apart from its object")
	}
	if shell, err := adapter.Parse(harnessSeed(t, "cursor-after-shell-execution.json"), ingest); err != nil || !shell.WebTool {
		t.Errorf("afterShellExecution reaching curl: %+v %v", shell, err)
	}
	if edit, err := adapter.Parse(harnessSeed(t, "cursor-after-file-edit.json"), ingest); err != nil || !slices.Equal(edit.Paths, []string{hookTestCwd + "/main.go"}) {
		t.Errorf("afterFileEdit: %+v %v", edit, err)
	}
	if after, err := adapter.Parse(harnessSeed(t, "cursor-after-mcp-execution.json"), ingest); err != nil || after.TranscriptPath == "" {
		t.Errorf("afterMCPExecution: %+v %v", after, err)
	}
}

// beforeMCPExecution asks for ur's outward tools from the binary's own catalog, with no daemon: every ur tool while no
// catalog is set, and none of another server's.
func TestCursorAsksForOutwardTools(t *testing.T) {
	ingest := sidecar.DefaultSidecarSettings().Ingest
	adapter, _ := HookAdapterFor("cursor")
	event, err := adapter.Parse(harnessSeed(t, "cursor-before-mcp-execution.json"), ingest)
	if err != nil {
		t.Fatal(err)
	}
	if answer := string(CursorHookAnswer(event)); answer != `{"permission":"ask"}` {
		t.Errorf("with no catalog: %q", answer)
	}
	defer hookToolTiers.Store(nil)
	SetHookToolTiers(func(name string) (bool, bool) { return name == "mail_send", name == "mail_send" || name == "evs_read" })
	if answer := string(CursorHookAnswer(event)); answer != `{"permission":"ask"}` {
		t.Errorf("an outward tool: %q", answer)
	}
	event.ToolName = "evs_read"
	if answer := CursorHookAnswer(event); answer != nil {
		t.Errorf("a read tool: %q", answer)
	}
	event.ToolName = "not_in_catalog"
	if answer := string(CursorHookAnswer(event)); answer != `{"permission":"ask"}` {
		t.Errorf("a tool the catalog does not name: %q", answer)
	}
	event.ToolName = "mail_send"
	event.ToolServer = "another"
	if answer := CursorHookAnswer(event); answer != nil {
		t.Errorf("another server's tool: %q", answer)
	}
}

// A SessionStart reporting a fresh start opens an untainted run under its harness process; an MCP session the harness
// spawned joins it.
func TestFreshSessionStartOpensUntaintedRun(t *testing.T) {
	env := newHookTestEnv(t)
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	if err := claude.SessionStart("s1", "startup"); err != nil {
		t.Fatal(err)
	}
	runId := env.runOf("claude-code", "s1")
	if env.network.runs.Tainted(runId) {
		t.Fatal("a fresh session's run is tainted")
	}
	run, _ := env.network.runs.Get(runId)
	if run.ProcessId != claude.Process().Identity.Pid || run.ProcessStartMillis != claude.Process().Identity.StartMillis || run.Worktree != hookTestCwd {
		t.Errorf("the run's file: %+v", run)
	}
	session := env.server.newSession(claude.RelayHello("builder"))
	call := env.call(session)
	if call.RunId != runId || call.Tainted() {
		t.Errorf("the MCP session acts in %s, tainted %t", call.RunId, call.Tainted())
	}
}

// TS1 against a forged SessionStart (plan-MCP-taint-new-session): once a run of a harness process is tainted, a
// SessionStart for a new session from any process under it opens a run that starts tainted, and the MCP session stays
// tainted.
func TestForgedSessionStartCannotLaunderTaint(t *testing.T) {
	env := newHookTestEnv(t)
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	claude.SessionStart("s1", "startup")
	session := env.server.newSession(claude.RelayHello(""))
	if err := claude.ToolCall("s1", true, "WebFetch", map[string]any{"url": "https://docs.example/x"}); err != nil {
		t.Fatal(err)
	}
	if !env.call(session).Tainted() {
		t.Fatal("a web tool left the run untainted")
	}
	forger := claude.ShellChild("python3")
	if err := claude.HookFrom(forger, claude.Payload("s2", "SessionStart", map[string]any{"source": "startup"})); err != nil {
		t.Fatal(err)
	}
	forgedRunId := env.runOf("claude-code", "s2")
	if !env.taintedOnDisk(forgedRunId) {
		t.Error("a forged SessionStart opened an untainted run under a tainted harness")
	}
	call := env.call(session)
	if !call.Tainted() {
		t.Errorf("the MCP session acts in %s untainted", call.RunId)
	}
	fresh := env.server.newSession(claude.RelayHello(""))
	if !env.call(fresh).Tainted() {
		t.Error("a new MCP session under the harness is untainted")
	}
}

// A forger that slips a process of its own between the harness and its `ur hook` or `ur mcp` stays under the
// harness's taint: its runs start with it, and catch up to taint the harness takes later.
func TestForgerBetweenHarnessAndHookInherits(t *testing.T) {
	env := newHookTestEnv(t)
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	claude.SessionStart("s1", "startup")
	forger := claude.ShellChild("python3")
	forgedHook := env.table.Spawn(forger.Identity.Pid, "ur")
	if err := claude.HookFrom(forgedHook, claude.Payload("s2", "SessionStart", map[string]any{"source": "startup"})); err != nil {
		t.Fatal(err)
	}
	forgedRunId := env.runOf("claude-code", "s2")
	forgedRelay := env.table.Spawn(forger.Identity.Pid, "ur")
	forgedSession := env.server.newSession(&sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp, Harness: "claude-code", PeerPid: int64(forgedRelay.Identity.Pid)})
	if call := env.call(forgedSession); call.RunId != forgedRunId || call.Tainted() {
		t.Fatalf("the forger's session acts in %s, tainted %t, before any taint", call.RunId, call.Tainted())
	}
	// the harness reads untrusted data after the forger's run opened
	if err := claude.ToolCall("s1", true, "WebFetch", map[string]any{"url": "https://docs.example/later"}); err != nil {
		t.Fatal(err)
	}
	if call := env.call(forgedSession); !call.Tainted() || !env.taintedOnDisk(forgedRunId) {
		t.Error("the forger's run did not catch up to its harness's taint")
	}
	// and a run the forger opens now starts tainted
	again := env.table.Spawn(forger.Identity.Pid, "ur")
	claude.HookFrom(again, claude.Payload("s3", "SessionStart", map[string]any{"source": "startup"}))
	if !env.taintedOnDisk(env.runOf("claude-code", "s3")) {
		t.Error("a forger's new run under a tainted harness started untainted")
	}
	// taint the forger's session takes reaches the harness's run too
	other := env.harness(sidecartest.FakeHarnessClaudeCode)
	other.SessionStart("o1", "startup")
	child := other.ShellChild("node")
	childRelay := env.table.Spawn(child.Identity.Pid, "ur")
	childHook := env.table.Spawn(child.Identity.Pid, "ur")
	other.HookFrom(childHook, other.Payload("o2", "SessionStart", map[string]any{"source": "startup"}))
	childCall := env.call(env.server.newSession(&sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp, Harness: "claude-code", PeerPid: int64(childRelay.Identity.Pid)}))
	if err := childCall.Taint(context.Background(), sidecar.RunTaintUntrustedData); err != nil {
		t.Fatal(err)
	}
	if !env.taintedOnDisk(env.runOf("claude-code", "o1")) {
		t.Error("a child's untrusted read left its harness's run untainted")
	}
}

// SessionEnd clears nothing: the run stays tainted, and a later session of the same harness process starts tainted.
func TestForgedSessionEndKeepsTaint(t *testing.T) {
	env := newHookTestEnv(t)
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	claude.SessionStart("s1", "startup")
	claude.ToolCall("s1", false, "Bash", map[string]any{"command": "curl https://api.example/data"})
	runId := env.runOf("claude-code", "s1")
	if err := claude.SessionEnd("s1", "other"); err != nil {
		t.Fatal(err)
	}
	if !env.taintedOnDisk(runId) {
		t.Fatal("SessionEnd cleared the taint")
	}
	claude.SessionStart("s3", "clear")
	if !env.taintedOnDisk(env.runOf("claude-code", "s3")) {
		t.Error("a new session after SessionEnd started untainted under the same process")
	}
}

// FS-27's core: an untrusted read, the daemon and its relay gone, a restart with nothing in memory, a benign hook:
// the session rejoins its run by (harness, session_id), still tainted, and the MCP session reads tainted.
func TestRestartRejoinKeepsTaint(t *testing.T) {
	env := newHookTestEnv(t)
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	claude.SessionStart("s1", "startup")
	runId := env.runOf("claude-code", "s1")
	session := env.server.newSession(claude.RelayHello(""))
	call := env.call(session)
	if err := call.Taint(context.Background(), sidecar.RunTaintUntrustedData); err != nil {
		t.Fatal(err)
	}

	env.restart()
	if err := claude.ToolCall("s1", false, "Edit", map[string]any{"file_path": hookTestCwd + "/a.go"}); err != nil {
		t.Fatal(err)
	}
	if rejoined := env.runOf("claude-code", "s1"); rejoined != runId {
		t.Fatalf("the session rejoined %s, not %s", rejoined, runId)
	}
	relayed := env.server.newSession(claude.RelayHello(""))
	call = env.call(relayed)
	if call.RunId != runId || !call.Tainted() {
		t.Errorf("after the restart the session acts in %s, tainted %t", call.RunId, call.Tainted())
	}
}

// FS-27's corrupt case: a run file that does not read is tainted, and a rejoin writes the taint on.
func TestCorruptRunFileIsTainted(t *testing.T) {
	env := newHookTestEnv(t)
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	claude.SessionStart("s1", "startup")
	runId := env.runOf("claude-code", "s1")
	env.network.corruptRun(t, runId)
	env.restart()
	if !env.network.runs.Tainted(runId) {
		t.Fatal("a corrupt run file reads untainted")
	}
	claude.ToolCall("s1", false, "Edit", map[string]any{"file_path": hookTestCwd + "/a.go"})
	if !env.network.runs.Tainted(runId) {
		t.Error("the rejoined run reads untainted")
	}
}

// Until a hook binds it a session is unbound, under a placeholder that reads tainted, and its call is a coverage
// lapse written to the placeholder; when a hook then binds its harness process, the taint comes with it.
func TestUnboundIsTainted(t *testing.T) {
	env := newHookTestEnv(t)
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	session := env.server.newSession(claude.RelayHello(""))
	call := env.call(session)
	if !call.Tainted() {
		t.Fatal("an unbound session's call is untainted")
	}
	if !env.network.runs.TaintRecorded(call.RunId) {
		t.Error("the lapse was not written to the placeholder")
	}
	run, err := env.network.runs.Get(call.RunId)
	if err != nil || !slices.Contains(run.Gaps, "missed_event") {
		t.Errorf("the placeholder's gaps: %+v %v", run, err)
	}
	claude.SessionStart("s1", "startup")
	bound := env.call(session)
	if bound.RunId != env.runOf("claude-code", "s1") || !bound.Tainted() {
		t.Errorf("binding moved the session to a less tainted state: %s tainted %t", bound.RunId, bound.Tainted())
	}
	// a session of another harness's tree stays unbound
	other := env.harness(sidecartest.FakeHarnessClaudeCode)
	if call := env.call(env.server.newSession(other.RelayHello(""))); call.RunId == bound.RunId || !call.Tainted() {
		t.Error("an unrelated harness's session bound to another's run")
	}
}

// A hook reporting a web tool is acked only once the taint is fsynced: a store with nothing in memory reads it.
func TestWebToolTaintedBeforeAck(t *testing.T) {
	for _, kind := range []string{sidecartest.FakeHarnessClaudeCode, sidecartest.FakeHarnessCodex, sidecartest.FakeHarnessCursor} {
		env := newHookTestEnv(t)
		harness := env.harness(kind)
		if kind == sidecartest.FakeHarnessClaudeCode {
			harness.SessionStart("s1", "startup")
		} else {
			harness.ToolCall("s1", false, "Edit", map[string]any{"file_path": hookTestCwd + "/a.go"})
		}
		runId := env.runOf(kind, "s1")
		if env.taintedOnDisk(runId) {
			t.Fatalf("%s: tainted before the web tool", kind)
		}
		if err := harness.ToolCall("s1", true, "Bash", map[string]any{"command": "cd x && curl -fsS https://api.example/a | jq ."}); err != nil {
			t.Fatalf("%s: %s", kind, err)
		}
		if !env.taintedOnDisk(runId) {
			t.Errorf("%s: the ack came before the taint was on disk", kind)
		}
	}
}

// A taint whose fsync fails fails the ack, and the run reads tainted in this process all the same.
func TestFailedFsyncFailsAck(t *testing.T) {
	env := newHookTestEnv(t)
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	claude.SessionStart("s1", "startup")
	runId := env.runOf("claude-code", "s1")
	env.network.store.FailWritesAfter(0)
	if err := claude.ToolCall("s1", true, "WebFetch", map[string]any{"url": "https://docs.example/y"}); err == nil {
		t.Fatal("the hook was acked with its taint unwritten")
	}
	if !env.network.runs.Tainted(runId) {
		t.Error("the run reads untainted after a failed taint")
	}
}

// §16.6's coverage rule on the fake clock: a call with a hook event within 60 s keeps its run clean, and one with
// none in 60 s either side taints the union and counts missed_event.
func TestLapseSixtySeconds(t *testing.T) {
	env := newHookTestEnv(t)
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	claude.SessionStart("s1", "startup")
	session := env.server.newSession(claude.RelayHello(""))
	runId := env.runOf("claude-code", "s1")
	if timeout := env.server.settings.Ingest.HookLapseTimeout; timeout != 60*time.Second {
		t.Fatalf("HookLapseTimeout is %s, want §16.6's 60 s", timeout)
	}
	claude.ToolCall("s1", true, "mcp__ur__evs_read", map[string]any{"repo": "notes"})
	env.call(session)
	env.clock.Advance(60 * time.Second)
	if env.taintedOnDisk(runId) {
		t.Fatal("a call with its hook tainted the run")
	}
	// the last hook is now 60 s old; a call with none after it
	env.clock.Advance(time.Second)
	env.call(session)
	env.clock.Advance(60*time.Second - time.Nanosecond)
	if env.taintedOnDisk(runId) {
		t.Fatal("tainted before the lapse's 60 s")
	}
	env.clock.Advance(time.Nanosecond)
	if !env.taintedOnDisk(runId) {
		t.Fatal("no taint 60 s after a call with no hook")
	}
	run, _ := env.network.runs.Get(runId)
	if !slices.Contains(run.TaintReasons, sidecar.RunTaintCoverageLapse) || !slices.ContainsFunc(run.Gaps, func(gap string) bool { return gap == "missed_event" || gap == "missed_event:2" }) {
		t.Errorf("the run's file: %+v", run)
	}
}

// A harness config hash that changed taints the run at SessionStart, and with no check installed every config reads
// changed, the closed direction until MCP-M3-16 seals hashes.
func TestConfigChangeTaints(t *testing.T) {
	env := newHookTestEnv(t)
	env.server.Binder().SetConfigCheck(func(ctx context.Context, harness string, cwd string) (bool, error) {
		return true, nil
	})
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	claude.SessionStart("s1", "startup")
	run, _ := env.network.runs.Get(env.runOf("claude-code", "s1"))
	if !run.Tainted || !slices.Contains(run.TaintReasons, sidecar.RunTaintConfigChanged) || !slices.Contains(run.Gaps, "config_changed") {
		t.Errorf("a changed config: %+v", run)
	}
	env.server.Binder().SetConfigCheck(nil)
	other := env.harness(sidecartest.FakeHarnessClaudeCode)
	other.SessionStart("s2", "startup")
	if !env.taintedOnDisk(env.runOf("claude-code", "s2")) {
		t.Error("with no check a run started untainted")
	}
}

// A pid the system handed out again is another process: a session under it binds none of the old process's runs,
// and a new run there inherits none of their taint.
func TestPidReuseDoesNotBind(t *testing.T) {
	env := newHookTestEnv(t)
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	claude.SessionStart("s1", "startup")
	claude.ToolCall("s1", true, "WebFetch", map[string]any{"url": "https://docs.example/z"})
	oldRunId := env.runOf("claude-code", "s1")
	oldPid := claude.Process().Identity.Pid
	claude.Exit()
	env.clock.Advance(time.Minute)
	reused := env.table.SpawnPid(oldPid, env.terminal.Identity.Pid, "claude")
	relay := env.table.Spawn(reused.Identity.Pid, "ur")
	session := env.server.newSession(&sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp, Harness: "claude-code", PeerPid: int64(relay.Identity.Pid)})
	call := env.call(session)
	if call.RunId == oldRunId {
		t.Fatal("a session under a reused pid bound the old process's run")
	}
	hook := env.table.Spawn(reused.Identity.Pid, "ur")
	hookHello := &sidecar.DaemonHello{Mode: sidecar.DaemonModeHook, Harness: "claude-code", PeerPid: int64(hook.Identity.Pid)}
	start := []byte(`{"session_id":"s9","cwd":"` + hookTestCwd + `","hook_event_name":"SessionStart","source":"startup"}`)
	if err := env.server.HandleHook(context.Background(), hookHello, env.networkId, env.network, &HookEventParams{Payload: start}); err != nil {
		t.Fatal(err)
	}
	if env.taintedOnDisk(env.runOf("claude-code", "s9")) {
		t.Error("a run under a reused pid inherited the old process's taint")
	}
}

// A resume in a new harness process joins that process's union: the resumed run keeps its taint, and the process's
// next session starts with it.
func TestResumeInNewProcessJoinsUnion(t *testing.T) {
	env := newHookTestEnv(t)
	first := env.harness(sidecartest.FakeHarnessClaudeCode)
	first.SessionStart("s1", "startup")
	first.ToolCall("s1", true, "WebSearch", map[string]any{"query": "x"})
	runId := env.runOf("claude-code", "s1")
	first.Exit()
	second := env.harness(sidecartest.FakeHarnessClaudeCode)
	if err := second.SessionStart("s1", "resume"); err != nil {
		t.Fatal(err)
	}
	if env.runOf("claude-code", "s1") != runId {
		t.Fatal("a resume opened another run")
	}
	run, _ := env.network.runs.Get(runId)
	if run.ProcessId != second.Process().Identity.Pid || !run.Tainted {
		t.Fatalf("the resumed run: %+v", run)
	}
	second.SessionStart("s2", "clear")
	if !env.taintedOnDisk(env.runOf("claude-code", "s2")) {
		t.Error("the new process's next session started untainted")
	}
}

// A resume report of a session this daemon never saw, and a Claude Code session first seen mid-way, both start
// tainted: none of their history is here.
func TestUnseenHistoryStartsTainted(t *testing.T) {
	env := newHookTestEnv(t)
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	claude.SessionStart("resumed", "resume")
	if !env.taintedOnDisk(env.runOf("claude-code", "resumed")) {
		t.Error("an unseen resume started untainted")
	}
	other := env.harness(sidecartest.FakeHarnessClaudeCode)
	other.ToolCall("midway", true, "Read", map[string]any{"file_path": hookTestCwd + "/a.go"})
	if !env.taintedOnDisk(env.runOf("claude-code", "midway")) {
		t.Error("a session first seen mid-way started untainted")
	}
	// Codex and Cursor report no start, so a first event opens a clean run
	codex := env.harness(sidecartest.FakeHarnessCodex)
	codex.ToolCall("c1", true, "apply_patch", map[string]any{"command": "*** Update File: a.go\n"})
	if env.taintedOnDisk(env.runOf("codex", "c1")) {
		t.Error("a Codex session's first event opened a tainted run")
	}
}

// A payload past the cap, or one no adapter reads, is a gap on its harness process's runs, never a taint.
func TestUnreadablePayloadIsGap(t *testing.T) {
	env := newHookTestEnv(t)
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	claude.SessionStart("s1", "startup")
	runId := env.runOf("claude-code", "s1")
	hook := claude.ShellChild("ur")
	hello := &sidecar.DaemonHello{Mode: sidecar.DaemonModeHook, Harness: "claude-code", PeerPid: int64(hook.Identity.Pid)}
	if err := env.server.HandleHook(context.Background(), hello, env.networkId, env.network, &HookEventParams{ByteCount: 2 * 1024 * 1024, Oversize: true}); err != nil {
		t.Fatal(err)
	}
	env.server.HandleHook(context.Background(), hello, env.networkId, env.network, &HookEventParams{Payload: json.RawMessage(`{"cwd":"x"}`)})
	run, _ := env.network.runs.Get(runId)
	if run.Tainted || !slices.Contains(run.Gaps, "oversize") || !slices.Contains(run.Gaps, "hook_failure") {
		t.Errorf("the run's file: %+v", run)
	}
}

// A control-mode caller's run is its harness ancestor's newest; one outside every harness has none.
func TestRunForPidFindsHarnessRun(t *testing.T) {
	env := newHookTestEnv(t)
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	claude.SessionStart("s1", "startup")
	claude.SessionStart("s2", "clear")
	command := claude.ShellChild("ur")
	runId, err := env.server.Binder().RunForPid(context.Background(), env.network, command.Identity.Pid)
	if err != nil || runId == nil || *runId != env.runOf("claude-code", "s2") {
		t.Errorf("an agent's command acts in %v: %v", runId, err)
	}
	typed := env.table.Spawn(env.terminal.Identity.Pid, "ur")
	if runId, err := env.server.Binder().RunForPid(context.Background(), env.network, typed.Identity.Pid); err != nil || runId != nil {
		t.Errorf("a typed command acts in %v: %v", runId, err)
	}
}

// A harness started inside another's shell: its session's lapse before its hooks bind stays its own, and its
// untrusted read reaches the outer harness's run, whose agent sees what it prints.
func TestNestedHarnessTaintFlowsUp(t *testing.T) {
	env := newHookTestEnv(t)
	outer := env.harness(sidecartest.FakeHarnessClaudeCode)
	outer.SessionStart("outer", "startup")
	outerRunId := env.runOf("claude-code", "outer")
	shell := env.table.Spawn(outer.Process().Identity.Pid, "bash")
	inner := sidecartest.NewFakeHarness(env.table, shell.Identity.Pid, sidecartest.FakeHarnessClaudeCode, hookTestCwd, env.sink)
	session := env.server.newSession(inner.RelayHello(""))
	if call := env.call(session); !call.Tainted() || call.RunId == outerRunId {
		t.Fatalf("an unbound nested session acts in %s, tainted %t", call.RunId, call.Tainted())
	}
	if env.taintedOnDisk(outerRunId) {
		t.Fatal("a nested session's lapse tainted the outer harness's run")
	}
	inner.SessionStart("inner", "startup")
	innerRunId := env.runOf("claude-code", "inner")
	call := env.call(session)
	if call.RunId != innerRunId {
		t.Fatalf("the nested session acts in %s, not its harness's run", call.RunId)
	}
	if err := call.Taint(context.Background(), sidecar.RunTaintUntrustedData); err != nil {
		t.Fatal(err)
	}
	if !env.taintedOnDisk(innerRunId) || !env.taintedOnDisk(outerRunId) {
		t.Error("a nested session's untrusted read did not reach both harnesses' runs")
	}
}
