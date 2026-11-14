//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-26 (§22.8; §16.7's attribution and restorable rows, D-MCP-8, D-MCP-15, RV1, FI-8; MCP-M3-27) on T2, and the
// restore world FS-115 shares: one daemon's hooks, ingest and restore points over a real git worktree, which
// sidecartest's FakeHarness drives as harnesses do and a person's hand writes beside them.
//
// The world composes what a daemon composes, each part the real one: mcp's server and RunBinder on a fake process
// table, mcp's Ingest sealing what it captures on a writer that keeps the drafts, and mcp's RestorePoints, whose
// holds, scans and attribution run behind every hook. A harness is a FakeHarness whose hooks reach the running
// server's HandleHook, each edit a tool call's PreToolUse, the write and its PostToolUse in the harness's own events:
// Claude Code's Edit and Write, Codex's apply_patch, Cursor's afterFileEdit with its edits. Restore runs on the
// daemon from the run's local point: a dry run, then the apply of its preview (restore_plan.go, restore_apply.go),
// as run_restore's W path does. A daemon's kill drops its server, binder, ingest and points; its restart builds them
// again over the same local store and run files. FI-8's ledger (fi8.go) learns every write as it is made.
//
// FS-26, the refusal: run A and run B share one worktree. A edits a.txt and runs an unrelated tool; B edits f.txt and
// creates g.txt; a hand edits h.txt; the three are actors in the background, so the explorer's seeds fire each run's
// hooks around the others' edits. Then a hand edits k.txt and A edits k.txt in the same scan interval. A's dry run
// offers a.txt alone and names a reason for f.txt, g.txt, h.txt and k.txt, and the apply restores a.txt and leaves
// the rest as their writers left them. Then the daemon is killed and restarted, a hand edits m.txt and A edits m.txt
// in the first interval after it, and the restore after the restart never reverts it. The twin has no B and no hand:
// A's edits of a.txt and k.txt restore to their bases, and after the restart nothing is left to restore. The same
// schedules run with A under Codex's and Cursor's edit hooks (TestFs26EachHarness). FI-8 after every step.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The restore world's process and writer names.
const (
	fsRestoreDaemon = "daemon"
	// the run a schedule restores
	fsRestoreRunA = "A"
	fsRestoreRunB = "B"
	fsRestoreHand = "hand"
	// a process taking no daemon lock (FS-115)
	fsRestoreWriter = "writer"
)

var errFsRestoreNoDaemon = errors.New("no daemon is running")

// One daemon's memory: what a kill drops.
type fsRestoreProcess struct {
	ctx    context.Context
	server *mcp.McpServer
	points *mcp.RestorePoints
	runs   *sidecar.RunStore
}

// One harness of the world and its session.
type fsRestoreHarness struct {
	harness   *sidecartest.FakeHarness
	kind      string
	sessionId string
	runId     sidecar.Id
}

// See the file header.
type fsRestoreWorld struct {
	net       *Net
	dir       string
	outside   string
	networkId sidecar.Id
	store     *sidecartest.FakeStore
	table     *sidecartest.FakeProcessTable
	terminal  *sidecar.ProcessInfo
	writer    *fsHookWriter
	redactor  *sidecar.Redactor
	ledger    *RestoreLedger

	stateLock sync.Mutex
	process   *fsRestoreProcess
	harnesses map[string]*fsRestoreHarness
	// each restore's dry run and apply, by the name a schedule gave it
	plans   map[string]*mcp.RestorePlan
	results map[string]*mcp.RestoreApplyResult
	// the next tool_use_id's number
	nextToolUse int
	// handles a writer holds open, closed with the Net
	handles map[string]*os.File
}

// A worktree on net: a git repository whose first commit holds files, a directory outside it that FI-8 reads as never
// written, and the daemon started. Removed when net closes.
func newFsRestoreWorld(ctx context.Context, net *Net, files map[string]string) (*fsRestoreWorld, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, fmt.Errorf("git is not on PATH: %w", err)
	}
	parent, err := os.MkdirTemp("", "fs-restore-")
	if err != nil {
		return nil, err
	}
	context.AfterFunc(net.Context(), func() { os.RemoveAll(parent) })
	// macOS gives a symlinked temp dir, which git reports resolved
	if resolved, err := filepath.EvalSymlinks(parent); err == nil {
		parent = resolved
	}
	dir := filepath.Join(parent, "worktree")
	outside := filepath.Join(parent, "outside")
	for _, directory := range []string{dir, outside} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "n.txt"), []byte("outside the worktree\n"), 0o644); err != nil {
		return nil, err
	}
	redactor, err := sidecar.NewRedactor(strings.NewReader(strings.Repeat("fs restore redaction key ", 16)))
	if err != nil {
		return nil, err
	}
	table := sidecartest.NewFakeProcessTable(net.Clock())
	world := &fsRestoreWorld{
		net:       net,
		dir:       dir,
		outside:   outside,
		networkId: sidecartest.NewApprovalWorldIdOf("network restore"),
		store:     sidecartest.NewFakeStore(),
		table:     table,
		terminal:  table.Spawn(1, "zsh"),
		writer:    &fsHookWriter{logId: sidecartest.NewApprovalWorldIdOf("record log restore")},
		redactor:  redactor,
		harnesses: map[string]*fsRestoreHarness{},
		plans:     map[string]*mcp.RestorePlan{},
		results:   map[string]*mcp.RestoreApplyResult{},
		handles:   map[string]*os.File{},
	}
	context.AfterFunc(net.Context(), world.closeHandles)
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.email", "builder@test.example"},
		{"config", "user.name", "builder"},
		{"config", "commit.gpgsign", "false"},
	} {
		if err := world.git(ctx, args...); err != nil {
			return nil, err
		}
	}
	names := []string{}
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		absolute := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(absolute, []byte(files[name]), 0o644); err != nil {
			return nil, err
		}
	}
	if err := world.git(ctx, "add", "-A"); err != nil {
		return nil, err
	}
	if err := world.git(ctx, "commit", "-q", "-m", "first"); err != nil {
		return nil, err
	}
	ledger, err := NewRestoreLedger("restore worktree", dir, outside)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		ledger.Base(name, []byte(files[name]))
	}
	world.ledger = ledger
	AttachRestoreLedger(net, ledger)
	if _, err := net.AddProcess(fsRestoreDaemon, world.build); err != nil {
		return nil, err
	}
	return world, nil
}

func (self *fsRestoreWorld) git(ctx context.Context, args ...string) error {
	command := exec.CommandContext(ctx, "git", append([]string{"-C", self.dir}, args...)...)
	command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("git %s: %w: %s", args[0], err, output)
	}
	return nil
}

func (self *fsRestoreWorld) closeHandles() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, handle := range self.handles {
		handle.Close()
	}
}

// A daemon's start, or its restart from the local store and run files alone: the server on the fake process table,
// every harness config reading unchanged, the ingest over its restore points.
func (self *fsRestoreWorld) build(ctx context.Context, instance string) (any, error) {
	settings := mcp.NewMcpServerSettings(sidecar.DefaultSidecarSettings(), sidecar.Version)
	settings.Clock = self.net.Clock()
	settings.Processes = self.table
	runs, err := sidecar.NewRunStore(self.store.Root(), settings.Mcp, self.net.Clock())
	if err != nil {
		return nil, err
	}
	server := mcp.NewMcpServer(self, settings)
	server.Binder().SetConfigCheck(func(ctx context.Context, harness string, cwd string) (bool, error) {
		return false, nil
	})
	points := mcp.NewRestorePoints(&mcp.RestorePointsArgs{Clock: self.net.Clock(), Ingest: settings.Ingest})
	mcp.NewIngest(&mcp.IngestArgs{
		Server:    server,
		Writers:   func(network mcp.McpNetwork) (sidecar.RecordWriter, error) { return self.writer, nil },
		Redactors: func(network mcp.McpNetwork) (*sidecar.Redactor, error) { return self.redactor, nil },
		Restore:   points,
	})
	process := &fsRestoreProcess{ctx: ctx, server: server, points: points, runs: runs}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.process = process
	return process, nil
}

// The running daemon's memory, or errFsRestoreNoDaemon while it is killed.
func (self *fsRestoreWorld) running() (*fsRestoreProcess, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.process == nil || self.process.ctx.Err() != nil {
		return nil, errFsRestoreNoDaemon
	}
	return self.process, nil
}

// mcp.McpDaemon: one network, the world's.

func (self *fsRestoreWorld) ResolveNetwork(hello *sidecar.DaemonHello, network string) (sidecar.Id, error) {
	return self.networkId, nil
}

func (self *fsRestoreWorld) Network(networkId sidecar.Id) (mcp.McpNetwork, bool) {
	if networkId != self.networkId {
		return nil, false
	}
	return &fsRestoreNetwork{world: self}, true
}

func (self *fsRestoreWorld) Agent(hello *sidecar.DaemonHello) (*sidecar.SidecarAgent, error) {
	return nil, nil
}

// The world's network as the hooks and restore read it: Online, its run files the running daemon's store, its local
// state the world's, which outlives a daemon.
type fsRestoreNetwork struct {
	world *fsRestoreWorld
}

func (self *fsRestoreNetwork) Status() sidecar.SidecarStatus {
	return sidecar.SidecarStatus{State: sidecar.SidecarStateOnline}
}

func (self *fsRestoreNetwork) Runs() (*sidecar.RunStore, error) {
	process, err := self.world.running()
	if err != nil {
		return nil, sidecar.ErrSidecarStoreLocked
	}
	return process.runs, nil
}

func (self *fsRestoreNetwork) Spool() (*sidecar.Spool, error) {
	return nil, sidecar.ErrSidecarStoreLocked
}

func (self *fsRestoreNetwork) LocalStore() sidecar.SidecarStore {
	return self.world.store.Root()
}

func (self *fsRestoreWorld) network() mcp.McpNetwork {
	return &fsRestoreNetwork{world: self}
}

// hook.event on the running daemon, as `ur hook` delivers it: an error while no daemon runs.
func (self *fsRestoreWorld) sink(hello *sidecar.DaemonHello, payload []byte) error {
	process, err := self.running()
	if err != nil {
		return err
	}
	return process.server.HandleHook(process.ctx, hello, self.networkId, self.network(), &mcp.HookEventParams{Payload: payload, ByteCount: int64(len(payload))})
}

// Starts a harness of kind under the terminal, kept under name, and its session: Claude Code's SessionStart, or the
// prompt Codex and Cursor report first, which opens the run and walks its restore point's base.
func (self *fsRestoreWorld) startHarness(ctx context.Context, name string, kind string, sessionId string) error {
	harness := sidecartest.NewFakeHarness(self.table, self.terminal.Identity.Pid, kind, self.dir, self.sink)
	var err error
	switch kind {
	case sidecartest.FakeHarnessClaudeCode:
		err = harness.SessionStart(sessionId, "startup")
	case sidecartest.FakeHarnessCodex:
		err = harness.Hook(harness.Payload(sessionId, "UserPromptSubmit", map[string]any{"prompt": "a fixture task"}))
	default:
		err = harness.Hook(harness.Payload(sessionId, "beforeSubmitPrompt", map[string]any{"prompt": "a fixture task"}))
	}
	if err != nil {
		return err
	}
	runId, err := self.runOf(ctx, harness)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.harnesses[name] = &fsRestoreHarness{harness: harness, kind: kind, sessionId: sessionId, runId: runId}
	return nil
}

// The run a harness's hooks bound, as the running daemon's binder reads it from a shell under the harness.
func (self *fsRestoreWorld) runOf(ctx context.Context, harness *sidecartest.FakeHarness) (sidecar.Id, error) {
	process, err := self.running()
	if err != nil {
		return sidecar.Id{}, err
	}
	child := harness.ShellChild("probe")
	defer self.table.Exit(child.ParentPid)
	defer self.table.Exit(child.Identity.Pid)
	runId, err := process.server.Binder().RunForPid(ctx, self.network(), child.Identity.Pid)
	if err != nil {
		return sidecar.Id{}, err
	}
	if runId == nil {
		return sidecar.Id{}, errors.New("the harness's hooks bound no run")
	}
	return *runId, nil
}

func (self *fsRestoreWorld) harness(name string) (*fsRestoreHarness, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	harness, ok := self.harnesses[name]
	if !ok {
		return nil, fmt.Errorf("no harness %s", name)
	}
	return harness, nil
}

func (self *fsRestoreWorld) toolUseId() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nextToolUse += 1
	return fmt.Sprintf("toolu_fs_restore_%d", self.nextToolUse)
}

func (self *fsRestoreWorld) absolute(relative string) string {
	return filepath.Join(self.dir, filepath.FromSlash(relative))
}

// path's one line now, without its newline; absent false where no file is there.
func (self *fsRestoreWorld) line(relative string) (string, bool) {
	content, err := os.ReadFile(self.absolute(relative))
	if err != nil {
		return "", false
	}
	return strings.TrimSuffix(string(content), "\n"), true
}

// Notes the base of a path the world's first commit did not hold: absent.
func (self *fsRestoreWorld) noteNewPath(relative string) {
	if _, inBase := self.ledgerBase(relative); !inBase {
		self.ledger.Base(relative, nil)
	}
}

func (self *fsRestoreWorld) ledgerBase(relative string) ([]byte, bool) {
	self.ledger.stateLock.Lock()
	defer self.ledger.stateLock.Unlock()
	content, ok := self.ledger.pathBases[relative]
	return content, ok
}

// Writes path's one line as writer, noting it in FI-8's ledger; runEdit for the restored run's hooked edit.
func (self *fsRestoreWorld) writeLine(writer string, relative string, line string, runEdit bool) error {
	self.noteNewPath(relative)
	absolute := self.absolute(relative)
	if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		return err
	}
	content := []byte(line + "\n")
	if err := os.WriteFile(absolute, content, 0o644); err != nil {
		return err
	}
	self.ledger.Wrote(writer, relative, content, runEdit)
	return nil
}

// A person's edit, no hook seeing it.
func (self *fsRestoreWorld) handWrite(relative string, line string) error {
	return self.writeLine(fsRestoreHand, relative, line, false)
}

// One hooked edit of path to line by the harness kept as name, in its harness's own events: Claude Code's Edit (Write
// for a new file) between PreToolUse and PostToolUse, Codex's apply_patch the same way, Cursor's afterFileEdit after
// the write with the edit it made. A file holds one line, so each tool's input names it whole.
func (self *fsRestoreWorld) edit(name string, relative string, line string) error {
	harness, err := self.harness(name)
	if err != nil {
		return err
	}
	old, exists := self.line(relative)
	absolute := self.absolute(relative)
	runEdit := name == fsRestoreRunA
	write := func() error {
		return self.writeLine(name, relative, line, runEdit)
	}
	switch harness.kind {
	case sidecartest.FakeHarnessCursor:
		if !exists {
			return errors.New("a Cursor edit names a file that exists")
		}
		if err := write(); err != nil {
			return err
		}
		return harness.harness.Hook(harness.harness.Payload(harness.sessionId, "afterFileEdit", map[string]any{
			"file_path": absolute,
			"edits":     []map[string]any{{"old_string": old, "new_string": line}},
		}))
	case sidecartest.FakeHarnessCodex:
		patch := "*** Begin Patch\n*** Add File: " + relative + "\n+" + line + "\n*** End Patch\n"
		if exists {
			patch = "*** Begin Patch\n*** Update File: " + relative + "\n@@\n-" + old + "\n+" + line + "\n*** End Patch\n"
		}
		return self.toolCall(harness, "apply_patch", map[string]any{"command": patch}, write)
	default:
		if !exists {
			return self.toolCall(harness, "Write", map[string]any{"file_path": absolute, "content": line + "\n"}, write)
		}
		return self.toolCall(harness, "Edit", map[string]any{"file_path": absolute, "old_string": old, "new_string": line}, write)
	}
}

// A tool call of Claude Code's or Codex's shape: PreToolUse, the tool's work, PostToolUse, one tool_use_id.
func (self *fsRestoreWorld) toolCall(harness *fsRestoreHarness, toolName string, toolInput map[string]any, work func() error) error {
	toolUseId := self.toolUseId()
	fields := map[string]any{"tool_name": toolName, "tool_input": toolInput, "tool_use_id": toolUseId}
	if err := harness.harness.Hook(harness.harness.Payload(harness.sessionId, "PreToolUse", fields)); err != nil {
		return err
	}
	if err := work(); err != nil {
		return err
	}
	return harness.harness.Hook(harness.harness.Payload(harness.sessionId, "PostToolUse", fields))
}

// One hooked tool that names no path, unrelated to the worktree's files: Claude Code's Read of a file outside it,
// Codex's shell listing, Cursor's shell.
func (self *fsRestoreWorld) unrelatedTool(name string) error {
	harness, err := self.harness(name)
	if err != nil {
		return err
	}
	switch harness.kind {
	case sidecartest.FakeHarnessCursor:
		return harness.harness.Hook(harness.harness.Payload(harness.sessionId, "afterShellExecution", map[string]any{"command": "ls"}))
	case sidecartest.FakeHarnessCodex:
		return self.toolCall(harness, "shell", map[string]any{"command": []string{"ls"}}, func() error { return nil })
	default:
		return self.toolCall(harness, "Read", map[string]any{"file_path": filepath.Join(self.outside, "n.txt")}, func() error { return nil })
	}
}

// The restored run's point on the running daemon, read from the local store after a restart.
func (self *fsRestoreWorld) point(ctx context.Context, name string) (*mcp.RestorePoint, error) {
	process, err := self.running()
	if err != nil {
		return nil, err
	}
	harness, err := self.harness(name)
	if err != nil {
		return nil, err
	}
	return process.points.OpenExisting(ctx, self.network(), self.networkId, harness.runId)
}

// A dry run of the run kept as name over every path its point knows, or over named alone, kept as restoreName.
func (self *fsRestoreWorld) dryRun(ctx context.Context, restoreName string, name string, named []string) (*mcp.RestorePlan, error) {
	point, err := self.point(ctx, name)
	if err != nil {
		return nil, err
	}
	plan, err := point.Plan(ctx, named)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.plans[restoreName] = plan
	return plan, nil
}

// The apply of the dry run kept as restoreName, its answer noted in FI-8's ledger.
func (self *fsRestoreWorld) apply(ctx context.Context, restoreName string, name string) (*mcp.RestoreApplyResult, error) {
	plan, err := self.plan(restoreName)
	if err != nil {
		return nil, err
	}
	point, err := self.point(ctx, name)
	if err != nil {
		return nil, err
	}
	result, err := point.Apply(ctx, plan.PreviewId)
	if err != nil {
		return nil, err
	}
	pathResults := map[string]string{}
	for _, outcome := range result.Paths {
		pathResults[outcome.Path] = outcome.Result
	}
	self.ledger.Applied(pathResults, true)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.results[restoreName] = result
	return result, nil
}

func (self *fsRestoreWorld) plan(restoreName string) (*mcp.RestorePlan, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	plan, ok := self.plans[restoreName]
	if !ok {
		return nil, fmt.Errorf("no dry run %s", restoreName)
	}
	return plan, nil
}

func (self *fsRestoreWorld) result(restoreName string) (*mcp.RestoreApplyResult, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	result, ok := self.results[restoreName]
	if !ok {
		return nil, fmt.Errorf("no apply %s", restoreName)
	}
	return result, nil
}

// A step of actor's on the world, once a setup step has made it.
func fsRestoreStep(actor string, world **fsRestoreWorld, action func(ctx context.Context, world *fsRestoreWorld) error) *Step {
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		if *world == nil {
			return errors.New("the restore world was never made")
		}
		return action(ctx, *world)
	}}
}

// The same in the background, for the explorer to interleave.
func fsRestoreBackground(actor string, world **fsRestoreWorld, action func(ctx context.Context, world *fsRestoreWorld) error) *Step {
	step := fsRestoreStep(actor, world, action)
	step.Background = true
	return step
}

// Whether the dry run left path out, naming a reason, and never offered it.
func fsRestoreRefused(plan *mcp.RestorePlan, relative string) error {
	if slices.Contains(plan.Paths(), relative) {
		return fmt.Errorf("%s is in the preview", relative)
	}
	for _, refusal := range plan.Refusals {
		if refusal.Path == relative {
			if refusal.Reason == "" {
				return fmt.Errorf("%s is refused with no reason", relative)
			}
			return nil
		}
	}
	return fmt.Errorf("the dry run names no reason for %s: %v", relative, fsRestoreRefusals(plan))
}

// A dry run's refusals as path:reason, for a message.
func fsRestoreRefusals(plan *mcp.RestorePlan) []string {
	refusals := []string{}
	for _, refusal := range plan.Refusals {
		refusals = append(refusals, refusal.Path+":"+refusal.Reason)
	}
	return refusals
}

// Whether path holds line now.
func (self *fsRestoreWorld) wantLine(relative string, line string) error {
	got, ok := self.line(relative)
	if !ok {
		return fmt.Errorf("%s is absent, want %q", relative, line)
	}
	if got != line {
		return fmt.Errorf("%s holds %q, want %q", relative, got, line)
	}
	return nil
}

// The apply's outcome for path.
func fsRestoreOutcome(result *mcp.RestoreApplyResult, relative string) (*mcp.RestorePathResult, error) {
	for _, outcome := range result.Paths {
		if outcome.Path == relative {
			return outcome, nil
		}
	}
	return nil, fmt.Errorf("the apply answered nothing for %s: %+v", relative, result.Paths)
}

// FS-26's worktree: five files, one line each.
func fs26Files() map[string]string {
	return map[string]string{
		"a.txt": "a0\n",
		"f.txt": "f0\n",
		"h.txt": "h0\n",
		"k.txt": "k0\n",
		"m.txt": "m0\n",
	}
}

var Fs26 = Register("FS-26", "", []Tier{TierT2}, Twin(Fs26TwoRunsAndAHand, Fs26OwnEditsRestore))

// See the file header.
func Fs26TwoRunsAndAHand(net *Net) *Schedule {
	return fs26(sidecartest.FakeHarnessClaudeCode, true)
}

// See the file header.
func Fs26OwnEditsRestore(net *Net) *Schedule {
	return fs26(sidecartest.FakeHarnessClaudeCode, false)
}

// A under kind; interleaved is the refusal, with B and the hand, else its twin. A run's hooks are one actor's, as a
// harness runs its hooks one after another: two actors' hooks of one run would meet on its ingest lock, which a
// barrier inside it holds.
func fs26(kind string, interleaved bool) *Schedule {
	var world *fsRestoreWorld
	steps := []*Step{
		{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
			made, err := newFsRestoreWorld(ctx, net, fs26Files())
			if err != nil {
				return err
			}
			world = made
			if err := world.startHarness(ctx, fsRestoreRunA, kind, "sA"); err != nil {
				return err
			}
			if interleaved {
				return world.startHarness(ctx, fsRestoreRunB, sidecartest.FakeHarnessClaudeCode, "sB")
			}
			return nil
		}},
		fsRestoreBackground("runA", &world, func(ctx context.Context, world *fsRestoreWorld) error {
			if err := world.edit(fsRestoreRunA, "a.txt", "a1"); err != nil {
				return err
			}
			return world.unrelatedTool(fsRestoreRunA)
		}),
	}
	if interleaved {
		steps = append(steps,
			fsRestoreBackground("runB", &world, func(ctx context.Context, world *fsRestoreWorld) error {
				if err := world.edit(fsRestoreRunB, "f.txt", "f1"); err != nil {
					return err
				}
				return world.edit(fsRestoreRunB, "g.txt", "g1")
			}),
			fsRestoreBackground("hand", &world, func(ctx context.Context, world *fsRestoreWorld) error {
				return world.handWrite("h.txt", "h-hand")
			}),
		)
	}
	steps = append(steps,
		&Step{Actor: "runA", Join: true},
		&Step{Actor: "runB", Join: true},
		&Step{Actor: "hand", Join: true},
		// a hand edit of k.txt that A then edits in the same scan interval: no hook of A's between them
		fsRestoreStep("hand", &world, func(ctx context.Context, world *fsRestoreWorld) error {
			if !interleaved {
				return nil
			}
			return world.handWrite("k.txt", "k-hand")
		}),
		fsRestoreStep("runA", &world, func(ctx context.Context, world *fsRestoreWorld) error {
			return world.edit(fsRestoreRunA, "k.txt", "k-a")
		}),
		fsRestoreStep(fsRestoreDaemon, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			plan, err := world.dryRun(ctx, "first", fsRestoreRunA, nil)
			if err != nil {
				return err
			}
			if !interleaved {
				if !slices.Equal(plan.Paths(), []string{"a.txt", "k.txt"}) {
					return fmt.Errorf("A's own edits, offered: %v, refused %v", plan.Paths(), fsRestoreRefusals(plan))
				}
				return nil
			}
			errs := []error{}
			if !slices.Equal(plan.Paths(), []string{"a.txt"}) {
				errs = append(errs, fmt.Errorf("offered %v, want A's a.txt alone; refused %v", plan.Paths(), fsRestoreRefusals(plan)))
			}
			for _, relative := range []string{"f.txt", "g.txt", "h.txt", "k.txt"} {
				errs = append(errs, fsRestoreRefused(plan, relative))
			}
			return errors.Join(errs...)
		}),
		fsRestoreStep(fsRestoreDaemon, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			result, err := world.apply(ctx, "first", fsRestoreRunA)
			if err != nil {
				return err
			}
			plan, err := world.plan("first")
			if err != nil {
				return err
			}
			errs := []error{}
			for _, relative := range plan.Paths() {
				outcome, err := fsRestoreOutcome(result, relative)
				if err != nil {
					errs = append(errs, err)
				} else if outcome.Result != mcp.RestoreResultRestored {
					errs = append(errs, fmt.Errorf("%s: %s with no writer beside the apply", relative, outcome.Result))
				}
			}
			errs = append(errs, world.wantLine("a.txt", "a0"))
			if interleaved {
				errs = append(errs, world.wantLine("f.txt", "f1"), world.wantLine("g.txt", "g1"), world.wantLine("h.txt", "h-hand"), world.wantLine("k.txt", "k-a"))
			} else {
				errs = append(errs, world.wantLine("k.txt", "k0"))
			}
			return errors.Join(errs...)
		}),
		// again across a restart
		&Step{Actor: fsRestoreDaemon, Kill: true},
		&Step{Actor: fsRestoreDaemon, Restart: fsRestoreDaemon},
		fsRestoreStep("hand", &world, func(ctx context.Context, world *fsRestoreWorld) error {
			if !interleaved {
				return nil
			}
			return world.handWrite("m.txt", "m-hand")
		}),
		fsRestoreStep("runA", &world, func(ctx context.Context, world *fsRestoreWorld) error {
			if !interleaved {
				return world.unrelatedTool(fsRestoreRunA)
			}
			return world.edit(fsRestoreRunA, "m.txt", "m-a")
		}),
		fsRestoreStep(fsRestoreDaemon, &world, func(ctx context.Context, world *fsRestoreWorld) error {
			plan, err := world.dryRun(ctx, "second", fsRestoreRunA, nil)
			if err != nil {
				return err
			}
			if !interleaved {
				if len(plan.Paths()) != 0 {
					return fmt.Errorf("after the restore and a restart, offered %v", plan.Paths())
				}
				return nil
			}
			if err := fsRestoreRefused(plan, "m.txt"); err != nil {
				return fmt.Errorf("after the restart: %w", err)
			}
			if _, err := world.apply(ctx, "second", fsRestoreRunA); err != nil {
				return err
			}
			return world.wantLine("m.txt", "m-a")
		}),
	)
	schedule := &Schedule{
		Id:    "FS-26",
		Steps: steps,
		Check: []Invariant{FI(8)},
		Tiers: []Tier{TierT2},
	}
	if interleaved {
		schedule.Refuses = "a path another run or a hand edited since A's start, restored by A's restore, before and after a restart"
		schedule.Twin = func(net *Net) *Schedule { return fs26(kind, false) }
	}
	return schedule
}

// The restore schedules need git and the barriers.
func fsRestoreNeeds(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
}

func TestFs26(t *testing.T) {
	fsRestoreNeeds(t)
	RunRow(t, "FS-26", "", nil)
}

// One clause under the rules CheckRow runs for a registered case, for a builder no catalog case names, its traces
// written nowhere: the schedule, its twin, and the explorer's first seedCount seeds over the schedule.
func fsRestoreCheckClause(t *testing.T, builder Builder, seedCount int) {
	t.Helper()
	ctx := t.Context()
	settings := DefaultRuleSettings()
	settings.WriteTraces = false
	settings.Seeds = seedRange(seedCount)
	var fixed *Schedule
	result := runBuilt(ctx, func(net *Net) *Schedule {
		fixed = builder(net)
		return fixed
	}, settings.Net, nil)
	if result.Err != nil {
		t.Errorf("%s", result)
		return
	}
	if fixed.Refuses != "" {
		if fixed.Twin == nil {
			t.Errorf("%s refuses %s and names no twin", fixed.Id, fixed.Refuses)
		} else if twin := RunTwin(ctx, fixed, settings.Net); twin.Err != nil {
			t.Errorf("%s", twin)
		}
	}
	explore := Explore(ctx, builder, settings)
	for _, failure := range explore.Failures {
		t.Errorf("%s", failure)
	}
	for _, err := range explore.TraceErrors {
		t.Errorf("%v", err)
	}
	t.Logf("%s: %s", fixed.Id, explore)
}

// FS-26 with A under Codex's apply_patch and Cursor's afterFileEdit, each under the rules.
func TestFs26EachHarness(t *testing.T) {
	fsRestoreNeeds(t)
	for _, kind := range []string{sidecartest.FakeHarnessCodex, sidecartest.FakeHarnessCursor} {
		fsRestoreCheckClause(t, func(net *Net) *Schedule {
			schedule := fs26(kind, true)
			schedule.Id = "FS-26 under " + kind
			return schedule
		}, len(MergeSeeds()))
	}
}

// FI-8's own check finds a lost write: a hand's bytes moved where no copy keeps them.
func TestFi8FindsALostWrite(t *testing.T) {
	root := t.TempDir()
	ledger, err := NewRestoreLedger("lost", root, "")
	if err != nil {
		t.Fatal(err)
	}
	ledger.Base("p.txt", []byte("base\n"))
	if err := os.WriteFile(filepath.Join(root, "p.txt"), []byte("by hand\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ledger.Wrote(fsRestoreHand, "p.txt", []byte("by hand\n"), false)
	if err := ledger.Check(false); err != nil {
		t.Fatalf("the hand's bytes at the path: %v", err)
	}
	// kept beside the path as a conflict copy, they are not lost
	if err := os.Rename(filepath.Join(root, "p.txt"), filepath.Join(root, "p.txt.ur-conflict-01234567")); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Check(false); err != nil {
		t.Fatalf("the hand's bytes in a conflict copy: %v", err)
	}
	// restored over: the base's bytes at the path, the hand's nowhere
	if err := os.Remove(filepath.Join(root, "p.txt.ur-conflict-01234567")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "p.txt"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ledger.Applied(map[string]string{"p.txt": restoreLedgerResultRestored}, true)
	if err := ledger.Check(true); err == nil || !strings.Contains(err.Error(), "lost") {
		t.Errorf("a write restored over: %v", err)
	}
	// a restored copy that is not the base's bytes breaks RV2
	other := t.TempDir()
	copied, _ := NewRestoreLedger("copy", other, "")
	copied.Base("q.txt", []byte("base\n"))
	if err := os.WriteFile(filepath.Join(other, "q.txt.ur-restored-01234567"), []byte("not the base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	copied.Applied(map[string]string{"q.txt": "changed"}, true)
	if err := copied.Check(false); err == nil || !bytes.Contains([]byte(err.Error()), []byte("RV2")) {
		t.Errorf("a restored copy of other bytes: %v", err)
	}
}
