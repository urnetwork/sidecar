//go:build !js && !ios && !android && !sdk_mobile_bind

// §22.7's restore suite (MCP-M3-27; FS-26, FS-115, RV1-RV4, D-MCP-8, D-MCP-15) on the composed daemon: hooks reach the
// server's HandleHook from sidecartest's FakeHarness, the binder binds them, Ingest captures them and runs the restore
// points' holds and scans behind them, over a real git worktree; restore is the point's dry run and the apply of its
// preview, as run_restore's W path runs them. Each clause of the row is a test of its own:
//
//   - sessions A and B share one worktree: B's edit of f and new g between A's start and an unrelated A hook stay
//     untouched and are reported foreign (TestRestoreSuiteSharedWorktree);
//   - f edited through an Edit hook and then by hand is refused, changed-since until a hook of A's scans it and shell
//     after, A's tool being the only activity in that interval: §16.7's chain from the base is broken either way,
//     and the code names the reason it found (TestRestoreSuiteHookedThenHand);
//   - f edited by hand and then by A's hooked edit in one scan interval is not edit-attributed, so restore keeps the
//     hand edit, under Claude Code's Edit, Codex's apply_patch and Cursor's afterFileEdit (TestRestoreSuiteHandThenHooked);
//   - a file changed during the baseline walk is not exact, refused (TestRestoreSuiteChangedDuringWalk);
//   - a dirty file holding a synthetic secret restores byte-exact from the local copy while the vault's blob of it is
//     redacted, and no marker is written (TestRestoreSuiteSecretExactVaultRedacted);
//   - a file over the cap is hash-only, refused (TestRestoreSuiteOverCap);
//   - after a daemon restart mid-run, later changes are foreign (TestRestoreSuiteRestartForeign);
//   - a change between preview and apply conflicts, keeping the path's bytes and writing only the restored copy
//     beside it (TestRestoreSuiteChangeAfterPreview);
//   - a shell-attributed path is refused without paths, and joins a preview only as a shell path when named: the
//     decision it then needs is run_restore's, which TestShellPathRefusedWithoutPathsAndDecision holds
//     (TestRestoreSuiteShellPath);
//   - a writer taking no lock, an editor, a shell's redirect or a second harness, writing between apply's checks and
//     its install is never overwritten: its bytes stay at the path, and the path reports a conflict
//     (TestRestoreSuiteLocklessWriter).
//
// Beside the row, FS-26's regression: a Cursor edit, whose afterFileEdit never names a tool id, restores through the
// composed path, and only a gap that can hide a change reads the next interval foreign (TestCursorEditRestorable).

package mcp

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The daemon's hook path and ingest over a restore env's git worktree.
type restoreSuiteEnv struct {
	*ingestTestEnv
	repo *restoreTestEnv
	// the next tool_use_id's number
	toolUseCount int
}

// The composed env over a repository holding committed.txt and dir/nested.txt. wallClock nil reads the OS's.
func newRestoreSuiteEnv(t *testing.T, wallClock func() time.Time) *restoreSuiteEnv {
	t.Helper()
	repo := newRestoreTestEnv(t)
	env := newIngestTestEnv(t)
	env.cwd = repo.dir
	env.restore = NewRestorePoints(&RestorePointsArgs{Clock: env.clock, Ingest: env.server.settings.Ingest, WallClock: wallClock})
	env.install()
	return &restoreSuiteEnv{ingestTestEnv: env, repo: repo}
}

// A harness of kind in the worktree, its session started as its harness reports one: Claude Code's SessionStart,
// Codex's and Cursor's first prompt. The run is bound and its point's base walked.
func (self *restoreSuiteEnv) start(kind string, sessionId string) *sidecartest.FakeHarness {
	self.t.Helper()
	harness := self.harnessIn(kind)
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
		self.t.Fatal(err)
	}
	return harness
}

func (self *restoreSuiteEnv) nextToolUseId() string {
	self.toolUseCount += 1
	return fmt.Sprintf("toolu_suite_%d", self.toolUseCount)
}

// A tool call of Claude Code's or Codex's shape: PreToolUse, work, PostToolUse, one tool_use_id.
func (self *restoreSuiteEnv) toolCall(harness *sidecartest.FakeHarness, sessionId string, toolName string, toolInput map[string]any, work func()) {
	self.t.Helper()
	fields := map[string]any{"tool_name": toolName, "tool_input": toolInput, "tool_use_id": self.nextToolUseId()}
	if err := harness.Hook(harness.Payload(sessionId, "PreToolUse", fields)); err != nil {
		self.t.Fatal(err)
	}
	work()
	if err := harness.Hook(harness.Payload(sessionId, "PostToolUse", fields)); err != nil {
		self.t.Fatal(err)
	}
}

// A hooked edit of path's line oldLine to newLine in kind's own events: Claude Code's Edit, Codex's apply_patch,
// Cursor's afterFileEdit after the write.
func (self *restoreSuiteEnv) edit(harness *sidecartest.FakeHarness, kind string, sessionId string, relative string, oldLine string, newLine string) {
	self.t.Helper()
	absolute := filepath.Join(self.repo.dir, filepath.FromSlash(relative))
	before := string(self.repo.read(relative))
	if strings.Count(before, oldLine+"\n") != 1 {
		self.t.Fatalf("%s holds %q, which names %q not once", relative, before, oldLine)
	}
	after := strings.Replace(before, oldLine+"\n", newLine+"\n", 1)
	write := func() { self.repo.write(relative, after) }
	switch kind {
	case sidecartest.FakeHarnessCursor:
		write()
		if err := harness.Hook(harness.Payload(sessionId, "afterFileEdit", map[string]any{
			"file_path": absolute,
			"edits":     []map[string]any{{"old_string": oldLine, "new_string": newLine}},
		})); err != nil {
			self.t.Fatal(err)
		}
	case sidecartest.FakeHarnessCodex:
		patch := "*** Begin Patch\n*** Update File: " + relative + "\n@@\n-" + oldLine + "\n+" + newLine + "\n*** End Patch\n"
		self.toolCall(harness, sessionId, "apply_patch", map[string]any{"command": patch}, write)
	default:
		self.toolCall(harness, sessionId, "Edit", map[string]any{"file_path": absolute, "old_string": oldLine, "new_string": newLine}, write)
	}
}

// A hooked tool naming no path: Claude Code's Read of the transcript's directory, Codex's and Cursor's shell.
func (self *restoreSuiteEnv) unrelated(harness *sidecartest.FakeHarness, kind string, sessionId string) {
	self.t.Helper()
	switch kind {
	case sidecartest.FakeHarnessCursor:
		if err := harness.Hook(harness.Payload(sessionId, "afterShellExecution", map[string]any{"command": "ls"})); err != nil {
			self.t.Fatal(err)
		}
	case sidecartest.FakeHarnessCodex:
		self.toolCall(harness, sessionId, "shell", map[string]any{"command": []string{"ls"}}, func() {})
	default:
		self.toolCall(harness, sessionId, "Read", map[string]any{"file_path": "/tmp/sidecartest/elsewhere.txt"}, func() {})
	}
}

// The run's point, its dry run over every path.
func (self *restoreSuiteEnv) plan(kind string, sessionId string, named []string) (*RestorePoint, *RestorePlan) {
	self.t.Helper()
	runId := self.runOf(kind, sessionId)
	point, ok := self.restore.Point(self.networkId, runId)
	if !ok {
		self.t.Fatalf("no point for %s %s", kind, sessionId)
	}
	plan, err := point.Plan(context.Background(), named)
	if err != nil {
		self.t.Fatal(err)
	}
	return point, plan
}

// The dry run's reason for path, "" when it is offered or not named at all.
func restoreSuiteReason(plan *RestorePlan, relative string) string {
	for _, refusal := range plan.Refusals {
		if refusal.Path == relative {
			return refusal.Reason
		}
	}
	return ""
}

// Sessions A and B share one worktree: B's edit of committed.txt and new g.txt, between A's start and an unrelated A
// hook, stay untouched and are reported foreign to A; A's own edit restores beside them.
func TestRestoreSuiteSharedWorktree(t *testing.T) {
	env := newRestoreSuiteEnv(t, nil)
	claude := sidecartest.FakeHarnessClaudeCode
	a := env.start(claude, "sA")
	b := env.start(claude, "sB")
	env.edit(a, claude, "sA", "dir/nested.txt", "nested", "nested by A")
	env.edit(b, claude, "sB", "committed.txt", "two", "two by B")
	env.toolCall(b, "sB", "Write", map[string]any{"file_path": filepath.Join(env.repo.dir, "g.txt"), "content": "g by B\n"}, func() {
		env.repo.write("g.txt", "g by B\n")
	})
	env.unrelated(a, claude, "sA")
	point, plan := env.plan(claude, "sA", nil)
	if !slices.Equal(plan.Paths(), []string{"dir/nested.txt"}) {
		t.Fatalf("A's preview %v, refused %+v", plan.Paths(), plan.Refusals)
	}
	for _, relative := range []string{"committed.txt", "g.txt"} {
		if reason := restoreSuiteReason(plan, relative); reason != RestoreReasonForeign {
			t.Errorf("%s: %q, want foreign", relative, reason)
		}
	}
	result, err := point.Apply(context.Background(), plan.PreviewId)
	if err != nil || result.RestoredCount() != 1 {
		t.Fatalf("the apply: %+v %v", result, err)
	}
	if got := string(env.repo.read("committed.txt")); got != "one\ntwo by B\nthree\n" {
		t.Errorf("B's edit after A's restore: %q", got)
	}
	if got := string(env.repo.read("g.txt")); got != "g by B\n" {
		t.Errorf("B's new file after A's restore: %q", got)
	}
	if got := string(env.repo.read("dir/nested.txt")); got != "nested\n" {
		t.Errorf("A's own edit after A's restore: %q", got)
	}
}

// committed.txt edited through A's Edit hook and then by hand: refused, changed-since before a hook of A's scans it,
// shell after one does, and the apply of either preview leaves the hand's bytes.
func TestRestoreSuiteHookedThenHand(t *testing.T) {
	env := newRestoreSuiteEnv(t, nil)
	claude := sidecartest.FakeHarnessClaudeCode
	a := env.start(claude, "sA")
	env.edit(a, claude, "sA", "committed.txt", "two", "2")
	env.repo.write("committed.txt", "one\n2\nthree\nby hand\n")
	point, plan := env.plan(claude, "sA", nil)
	if len(plan.Paths()) != 0 || restoreSuiteReason(plan, "committed.txt") != RestoreReasonChangedSince {
		t.Fatalf("before a scan: %v %+v", plan.Paths(), plan.Refusals)
	}
	env.unrelated(a, claude, "sA")
	_, scanned := env.plan(claude, "sA", nil)
	if len(scanned.Paths()) != 0 || restoreSuiteReason(scanned, "committed.txt") != RestoreReasonShell {
		t.Fatalf("after A's next hook: %v %+v", scanned.Paths(), scanned.Refusals)
	}
	if _, err := point.Apply(context.Background(), scanned.PreviewId); err != nil {
		t.Fatal(err)
	}
	if got := string(env.repo.read("committed.txt")); got != "one\n2\nthree\nby hand\n" {
		t.Errorf("the hand's bytes after the apply: %q", got)
	}
}

// committed.txt edited by hand and then by A's hooked edit in one scan interval, under each harness's edit hook: not
// edit-attributed, so the restore keeps the hand edit.
func TestRestoreSuiteHandThenHooked(t *testing.T) {
	for _, kind := range []string{sidecartest.FakeHarnessClaudeCode, sidecartest.FakeHarnessCodex, sidecartest.FakeHarnessCursor} {
		env := newRestoreSuiteEnv(t, nil)
		a := env.start(kind, "sA")
		env.repo.write("committed.txt", "ONE\ntwo\nthree\n")
		env.edit(a, kind, "sA", "committed.txt", "two", "2")
		point, plan := env.plan(kind, "sA", nil)
		if len(plan.Paths()) != 0 || restoreSuiteReason(plan, "committed.txt") != RestoreReasonForeign {
			t.Errorf("%s: %v %+v", kind, plan.Paths(), plan.Refusals)
			continue
		}
		if _, err := point.Apply(context.Background(), plan.PreviewId); err != nil {
			t.Fatal(err)
		}
		if got := string(env.repo.read("committed.txt")); got != "ONE\n2\nthree\n" {
			t.Errorf("%s: the hand edit reverted: %q", kind, got)
		}
	}
}

// A file written while the baseline walk is under way has an unknown base: not exact, refused, and the apply moves
// nothing of it.
func TestRestoreSuiteChangedDuringWalk(t *testing.T) {
	// the OS stamps ctimes on its own clock, so start_ns is taken well before: the walk's write is then later
	env := newRestoreSuiteEnv(t, func() time.Time { return time.Now().Add(-time.Hour) })
	env.repo.write("dirty.txt", "dirty at the start\n")
	env.restore.walkHook = func(path string) {
		if path == "dirty.txt" {
			env.repo.write("dirty.txt", "changed during the walk\n")
		}
	}
	claude := sidecartest.FakeHarnessClaudeCode
	a := env.start(claude, "sA")
	env.restore.walkHook = nil
	env.edit(a, claude, "sA", "dirty.txt", "changed during the walk", "edited")
	point, plan := env.plan(claude, "sA", nil)
	if len(plan.Paths()) != 0 || restoreSuiteReason(plan, "dirty.txt") != RestoreReasonNotExact {
		t.Fatalf("%v %+v", plan.Paths(), plan.Refusals)
	}
	if _, err := point.Apply(context.Background(), plan.PreviewId); err != nil {
		t.Fatal(err)
	}
	if got := string(env.repo.read("dirty.txt")); got != "edited\n" {
		t.Errorf("dirty.txt %q", got)
	}
}

// A dirty file holding a synthetic secret restores byte-exact from the point's local copy, while the vault's blob of
// its edited bytes is redacted; no redaction marker reaches the worktree.
func TestRestoreSuiteSecretExactVaultRedacted(t *testing.T) {
	env := newRestoreSuiteEnv(t, nil)
	original := "token = " + ingestTestSecret + "\nline two\n"
	env.repo.write("secret.txt", original)
	claude := sidecartest.FakeHarnessClaudeCode
	a := env.start(claude, "sA")
	env.edit(a, claude, "sA", "secret.txt", "line two", "line 2")
	blobs := env.writer.of(sidecar.RecordKindBlob)
	if len(blobs) != 1 {
		t.Fatalf("%d blobs", len(blobs))
	}
	blob := blobs[0].Body.(*protocol.BlobBody)
	if !blob.Redacted || bytes.Contains(blob.Content, []byte(ingestTestSecret)) || !bytes.Contains(blob.Content, []byte("[REDACTED:")) {
		t.Fatalf("the vault's blob is not redacted: %q", blob.Content)
	}
	point, plan := env.plan(claude, "sA", nil)
	if !slices.Equal(plan.Paths(), []string{"secret.txt"}) {
		t.Fatalf("%v %+v", plan.Paths(), plan.Refusals)
	}
	result, err := point.Apply(context.Background(), plan.PreviewId)
	if err != nil || result.RestoredCount() != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	restored := env.repo.read("secret.txt")
	if string(restored) != original || bytes.Contains(restored, []byte("[REDACTED")) {
		t.Errorf("not byte-exact: %q", restored)
	}
}

// A file over Ingest.FileByteCount is hash-only at the start: not exact, refused.
func TestRestoreSuiteOverCap(t *testing.T) {
	env := newRestoreSuiteEnv(t, nil)
	env.server.settings.Ingest.FileByteCount = 16
	env.repo.write("large.txt", "line far past the cap\nanother\n")
	claude := sidecartest.FakeHarnessClaudeCode
	a := env.start(claude, "sA")
	env.edit(a, claude, "sA", "large.txt", "another", "changed")
	point, plan := env.plan(claude, "sA", nil)
	base, err := point.BaseOf(context.Background(), "large.txt")
	if err != nil || !base.HashOnly {
		t.Fatalf("the base %+v %v", base, err)
	}
	if len(plan.Paths()) != 0 || restoreSuiteReason(plan, "large.txt") != RestoreReasonNotExact {
		t.Errorf("%v %+v", plan.Paths(), plan.Refusals)
	}
}

// A daemon restart mid-run: the edit scanned before it stays restorable, and a change after it is foreign.
func TestRestoreSuiteRestartForeign(t *testing.T) {
	env := newRestoreSuiteEnv(t, nil)
	claude := sidecartest.FakeHarnessClaudeCode
	a := env.start(claude, "sA")
	env.edit(a, claude, "sA", "committed.txt", "two", "2")
	// the restart: a new server, ingest and restore points over the same stores
	env.ingest.detach()
	env.restart()
	env.restore = NewRestorePoints(&RestorePointsArgs{Clock: env.clock, Ingest: env.server.settings.Ingest})
	env.install()
	env.edit(a, claude, "sA", "dir/nested.txt", "nested", "nested after the restart")
	runId := env.runOf(claude, "sA")
	point, err := env.restore.OpenExisting(context.Background(), env.network, env.networkId, runId)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := point.Plan(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Paths(), []string{"committed.txt"}) || restoreSuiteReason(plan, "dir/nested.txt") != RestoreReasonForeign {
		t.Errorf("%v %+v", plan.Paths(), plan.Refusals)
	}
}

// A hand's write between the preview and the apply: changed, its bytes kept at the path, and only the restored copy
// written beside it.
func TestRestoreSuiteChangeAfterPreview(t *testing.T) {
	env := newRestoreSuiteEnv(t, nil)
	claude := sidecartest.FakeHarnessClaudeCode
	a := env.start(claude, "sA")
	env.edit(a, claude, "sA", "committed.txt", "two", "2")
	point, plan := env.plan(claude, "sA", nil)
	env.repo.write("committed.txt", "by hand after the preview\n")
	result, err := point.Apply(context.Background(), plan.PreviewId)
	if err != nil {
		t.Fatal(err)
	}
	outcome := restoreTestOutcome(t, result, "committed.txt")
	copyName := "committed.txt" + restoreRestoredInfix + hex.EncodeToString(point.RunId().Bytes())[:restoreCopyRunHexCount]
	if outcome.Result != RestoreConflictChanged || !slices.Equal(outcome.Copies, []string{copyName}) {
		t.Fatalf("%+v", outcome)
	}
	if got := string(env.repo.read("committed.txt")); got != "by hand after the preview\n" {
		t.Errorf("the path %q", got)
	}
	if got := string(env.repo.read(copyName)); got != "one\ntwo\nthree\n" {
		t.Errorf("the restored copy %q", got)
	}
}

// A change by A's shell tool is refused without paths, and joins a preview as a shell path only when named.
func TestRestoreSuiteShellPath(t *testing.T) {
	env := newRestoreSuiteEnv(t, nil)
	claude := sidecartest.FakeHarnessClaudeCode
	a := env.start(claude, "sA")
	env.toolCall(a, "sA", "Bash", map[string]any{"command": "sed -i s/two/2/ committed.txt"}, func() {
		env.repo.write("committed.txt", "one\n2\nthree\n")
	})
	_, plan := env.plan(claude, "sA", nil)
	if len(plan.Paths()) != 0 || restoreSuiteReason(plan, "committed.txt") != RestoreReasonShell {
		t.Fatalf("unnamed: %v %+v", plan.Paths(), plan.Refusals)
	}
	_, named := env.plan(claude, "sA", []string{"committed.txt"})
	if !slices.Equal(named.ShellPaths(), []string{"committed.txt"}) {
		t.Errorf("named: %+v", named.Entries)
	}
}

// A writer taking no lock writes the path between the apply's check and its install: an editor in place, a shell's
// redirect by a temporary file and a rename, a second harness's hooked edit. Its bytes stay at the path, and the path
// reports recreated with the restored copy beside it.
func TestRestoreSuiteLocklessWriter(t *testing.T) {
	writers := []string{"editor", "shell", "second harness"}
	for _, writer := range writers {
		env := newRestoreSuiteEnv(t, nil)
		claude := sidecartest.FakeHarnessClaudeCode
		a := env.start(claude, "sA")
		second := env.start(claude, "sOther")
		env.edit(a, claude, "sA", "committed.txt", "two", "2")
		point, plan := env.plan(claude, "sA", nil)
		want := ""
		testFs := &restoreTestFs{}
		testFs.beforeRename = func(from string, to string) error {
			if !restoreTestInstall(from, to) || to != "committed.txt" {
				return nil
			}
			testFs.beforeRename = nil
			switch writer {
			case "editor":
				want = "written in place by an editor\n"
				env.repo.write("committed.txt", want)
			case "shell":
				want = "redirected by a shell\n"
				env.repo.write("committed.txt.tmp", want)
				if err := os.Rename(filepath.Join(env.repo.dir, "committed.txt.tmp"), filepath.Join(env.repo.dir, "committed.txt")); err != nil {
					t.Fatal(err)
				}
			default:
				want = "written by another harness\n"
				absolute := filepath.Join(env.repo.dir, "committed.txt")
				env.toolCall(second, "sOther", "Write", map[string]any{"file_path": absolute, "content": want}, func() {
					env.repo.write("committed.txt", want)
				})
			}
			return nil
		}
		env.restore.fs = testFs.fs()
		result, err := point.Apply(context.Background(), plan.PreviewId)
		if err != nil {
			t.Fatal(err)
		}
		outcome := restoreTestOutcome(t, result, "committed.txt")
		if outcome.Result != RestoreConflictRecreated || len(outcome.Copies) != 1 {
			t.Errorf("%s: %+v", writer, outcome)
		}
		if got := string(env.repo.read("committed.txt")); got != want {
			t.Errorf("%s: the path holds %q", writer, got)
		}
	}
}

// A Cursor edit restores through the composed path though every afterFileEdit counts a no_tool_id gap, which hides no
// change; a missed_event gap, which can, makes the next interval foreign.
func TestCursorEditRestorable(t *testing.T) {
	env := newRestoreSuiteEnv(t, nil)
	cursor := sidecartest.FakeHarnessCursor
	a := env.start(cursor, "cA")
	env.edit(a, cursor, "cA", "committed.txt", "two", "2")
	runId := env.runOf(cursor, "cA")
	if !env.hasGap(runId, sidecar.RecordCoverageGapNoToolId) {
		t.Fatalf("no no_tool_id gap: %v", env.runFile(runId).Gaps)
	}
	point, plan := env.plan(cursor, "cA", nil)
	if !slices.Equal(plan.Paths(), []string{"committed.txt"}) {
		t.Fatalf("a Cursor edit: %v %+v", plan.Paths(), plan.Refusals)
	}
	result, err := point.Apply(context.Background(), plan.PreviewId)
	if err != nil || result.RestoredCount() != 1 || string(env.repo.read("committed.txt")) != "one\ntwo\nthree\n" {
		t.Fatalf("%+v %v", result, err)
	}
	// a gap that can hide a change: the next interval is foreign
	env.ingest.gap(context.Background(), env.network, env.networkId, runId, sidecar.RecordCoverageGapMissedEvent)
	env.edit(a, cursor, "cA", "dir/nested.txt", "nested", "nested by cursor")
	_, after := env.plan(cursor, "cA", nil)
	if restoreSuiteReason(after, "dir/nested.txt") != RestoreReasonForeign {
		t.Errorf("after a missed event: %v %+v", after.Paths(), after.Refusals)
	}
	for code, hides := range map[string]bool{
		sidecar.RecordCoverageGapMissedEvent:    true,
		sidecar.RecordCoverageGapHookFailure:    true,
		sidecar.RecordCoverageGapDowntime:       true,
		sidecar.RecordCoverageGapConfigChanged:  true,
		sidecar.RecordCoverageGapRunFileMissing: true,
		sidecar.RecordCoverageGapNoToolId:       false,
		sidecar.RecordCoverageGapRedaction:      false,
		sidecar.RecordCoverageGapOversize:       false,
		sidecar.RecordCoverageGapTruncation:     false,
		sidecar.RecordCoverageGapBypassMode:     false,
		sidecar.RecordCoverageGapSpoolDrop:      false,
	} {
		if ingestGapHidesChange(code) != hides {
			t.Errorf("%s hides a change: %t", code, !hides)
		}
	}
}
