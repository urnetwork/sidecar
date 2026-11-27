//go:build !js && !ios && !android && !sdk_mobile_bind

package mcp

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// DESIGN-COMPUTE §8.9's run handles over the daemon's run bindings (GW-M12-02) on sidecartest's FakeProcessTable: a
// credential command's harness process found as a hook's is, Codex's auth command, Claude Code's helper through its
// shell and a harness nested in another's; a call's run by its session, its process's newest, or a new one that inherits
// the taint above it and is found again after a restart; and the union of every run of the process and those above it,
// ended runs included, failing where a run's marks do not read.

// A handle of a harness process, with the processes above it as the table reads them.
func testGatewayHandleOf(t *testing.T, env *hookTestEnv, process *sidecar.ProcessInfo) *sidecar.GatewayRunHandle {
	t.Helper()
	found, err := env.server.Binder().GatewayRunBinder().HarnessProcess(context.Background(), env.network,
		env.table.Spawn(process.Identity.Pid, "ur").Identity.Pid)
	if err != nil || found == nil || found.Process.Identity != process.Identity {
		t.Fatalf("the harness process of a child of %s: %+v %v", process.Name, found, err)
	}
	return &sidecar.GatewayRunHandle{Process: found.Process.Identity, Above: found.Above}
}

// Codex runs its auth command itself, Claude Code its apiKeyHelper through a shell, and a harness Codex's shell tool
// started holds its own helper's tokens with Codex above it; a command whose ancestors are shells alone names none; a
// process a hook bound reads as known.
func TestCredentialCommandBindsHarnessProcess(t *testing.T) {
	env := newHookTestEnv(t)
	binder := env.server.Binder().GatewayRunBinder()
	ctx := context.Background()

	codex := env.harness(sidecartest.FakeHarnessCodex)
	authCommand := env.table.Spawn(codex.Process().Identity.Pid, "ur")
	found, err := binder.HarnessProcess(ctx, env.network, authCommand.Identity.Pid)
	if err != nil || found == nil || found.Process.Identity != codex.Process().Identity || found.Process.Name != "codex" || found.Known {
		t.Fatalf("Codex's auth command: %+v %v", found, err)
	}
	if !slices.Contains(found.Above, env.terminal.Identity) {
		t.Errorf("the processes above Codex: %+v", found.Above)
	}
	if err := codex.SessionStart("codex-session", "startup"); err != nil {
		t.Fatal(err)
	}
	if found, _ := binder.HarnessProcess(ctx, env.network, authCommand.Identity.Pid); found == nil || !found.Known {
		t.Errorf("a process a hook bound is not known: %+v", found)
	}

	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	helper := claude.ShellChild("ur")
	found, err = binder.HarnessProcess(ctx, env.network, helper.Identity.Pid)
	if err != nil || found == nil || found.Process.Identity != claude.Process().Identity {
		t.Fatalf("Claude Code's apiKeyHelper through its shell: %+v %v", found, err)
	}

	codexShell := env.table.Spawn(codex.Process().Identity.Pid, "bash")
	nested := sidecartest.NewFakeHarness(env.table, codexShell.Identity.Pid, sidecartest.FakeHarnessClaudeCode, hookTestCwd, env.sink)
	nestedHelper := nested.ShellChild("ur")
	found, err = binder.HarnessProcess(ctx, env.network, nestedHelper.Identity.Pid)
	if err != nil || found == nil || found.Process.Identity != nested.Process().Identity {
		t.Fatalf("a nested harness's helper: %+v %v", found, err)
	}
	if !slices.Contains(found.Above, codex.Process().Identity) {
		t.Errorf("Codex is not above the nested harness: %+v", found.Above)
	}

	atPrompt := env.table.Spawn(env.terminal.Identity.Pid, "ur")
	if found, err := binder.HarnessProcess(ctx, env.network, atPrompt.Identity.Pid); err != nil || found != nil {
		t.Errorf("a command under shells alone: %+v %v", found, err)
	}
	if found, err := binder.HarnessProcess(ctx, env.network, 999999); err != nil || found != nil {
		t.Errorf("a pid no process has: %+v %v", found, err)
	}
}

// A call that names a session the process's hooks reported takes that session's run; one naming a session no run
// holds opens it as a hook's first event would, tainted where the harness reports starts; one naming none takes the
// process's newest run; and a process with no run gets a new one, which takes the taint of the runs above it and is
// found again after a restart.
func TestGatewayBindRunBySessionHeader(t *testing.T) {
	env := newHookTestEnv(t)
	ctx := context.Background()
	claude := env.harness(sidecartest.FakeHarnessClaudeCode)
	if err := claude.SessionStart("claude-one", "startup"); err != nil {
		t.Fatal(err)
	}
	first := env.runOf(sidecartest.FakeHarnessClaudeCode, "claude-one")
	handle := testGatewayHandleOf(t, env, claude.Process())
	binder := env.server.Binder().GatewayRunBinder()
	runId, err := binder.BindRun(ctx, env.network, sidecartest.FakeHarnessClaudeCode, handle, "claude-one")
	if err != nil || runId != first {
		t.Fatalf("a reported session: %s %v, want %s", runId, err, first)
	}
	unseen, err := binder.BindRun(ctx, env.network, sidecartest.FakeHarnessClaudeCode, handle, "claude-unseen")
	if err != nil || unseen == first || env.runOf(sidecartest.FakeHarnessClaudeCode, "claude-unseen") != unseen {
		t.Fatalf("a session no run holds: %s %v", unseen, err)
	}
	if !env.network.runs.Tainted(unseen) || !slices.Contains(env.network.runs.TaintReasons(unseen), sidecar.RunTaintCoverageLapse) {
		t.Fatal("a session whose start this daemon missed is not tainted")
	}
	if newest, err := binder.BindRun(ctx, env.network, sidecartest.FakeHarnessClaudeCode, handle, ""); err != nil || newest != unseen {
		t.Fatalf("no session: %s %v, want the newest %s", newest, err, unseen)
	}

	inner := sidecartest.NewFakeHarness(env.table, claude.ShellChild("bash").Identity.Pid, sidecartest.FakeHarnessCodex, hookTestCwd, env.sink)
	innerHandle := testGatewayHandleOf(t, env, inner.Process())
	made, err := binder.BindRun(ctx, env.network, sidecartest.FakeHarnessCodex, innerHandle, "")
	if err != nil || made == unseen || made == first {
		t.Fatalf("a process with no run: %s %v", made, err)
	}
	if !env.network.runs.Tainted(made) || !slices.Contains(env.network.runs.TaintReasons(made), sidecar.RunTaintInherited) {
		t.Fatal("a new run did not take the taint of the runs above it")
	}
	run, err := env.network.runs.Get(made)
	if err != nil || run.ProcessId != inner.Process().Identity.Pid || len(run.SessionIds) != 0 {
		t.Fatalf("the new run's file: %+v %v", run, err)
	}
	env.restart()
	again, err := env.server.Binder().GatewayRunBinder().BindRun(ctx, env.network, sidecartest.FakeHarnessCodex, innerHandle, "")
	if err != nil || again != made {
		t.Fatalf("after a restart: %s %v, want %s", again, err, made)
	}
}

// The union a call is checked against holds every run of its process and of each process above it, ended runs
// included, never a run of an unrelated process; and a run whose marks do not read fails it.
func TestMarksUnionIncludesEndedRuns(t *testing.T) {
	env := newHookTestEnv(t)
	ctx := context.Background()
	codex := env.harness(sidecartest.FakeHarnessCodex)
	for _, sessionId := range []string{"codex-ended", "codex-live"} {
		if err := codex.SessionStart(sessionId, "startup"); err != nil {
			t.Fatal(err)
		}
	}
	if err := codex.SessionEnd("codex-ended", "exit"); err != nil {
		t.Fatal(err)
	}
	ended := env.runOf(sidecartest.FakeHarnessCodex, "codex-ended")
	if err := env.network.runs.Mark(ctx, ended, "limited_use"); err != nil {
		t.Fatal(err)
	}
	nested := sidecartest.NewFakeHarness(env.table, codex.ShellChild("bash").Identity.Pid, sidecartest.FakeHarnessClaudeCode, hookTestCwd, env.sink)
	if err := nested.SessionStart("nested", "startup"); err != nil {
		t.Fatal(err)
	}
	other := env.harness(sidecartest.FakeHarnessClaudeCode)
	if err := other.SessionStart("other", "startup"); err != nil {
		t.Fatal(err)
	}
	otherRun := env.runOf(sidecartest.FakeHarnessClaudeCode, "other")
	if err := env.network.runs.Mark(ctx, otherRun, "private"); err != nil {
		t.Fatal(err)
	}
	if err := env.network.runs.Taint(ctx, otherRun, sidecar.RunTaintUntrustedData); err != nil {
		t.Fatal(err)
	}
	binder := env.server.Binder().GatewayRunBinder()
	handle := testGatewayHandleOf(t, env, nested.Process())
	union, err := binder.Union(ctx, env.network, []*sidecar.GatewayRunHandle{handle})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(union.Marks, []string{"limited_use"}) || union.Tainted {
		t.Fatalf("the nested harness's union: %+v", union)
	}
	live := env.runOf(sidecartest.FakeHarnessCodex, "codex-live")
	if err := env.network.runs.Taint(ctx, live, sidecar.RunTaintWebTool); err != nil {
		t.Fatal(err)
	}
	if union, err := binder.Union(ctx, env.network, []*sidecar.GatewayRunHandle{handle}); err != nil || !union.Tainted {
		t.Fatalf("a tainted run above: %+v %v", union, err)
	}
	if union, err := binder.Union(ctx, env.network, nil); err != nil || union.Tainted || len(union.Marks) != 0 {
		t.Fatalf("no handle: %+v %v", union, err)
	}
	env.network.corruptRun(t, ended)
	if _, err := binder.Union(ctx, env.network, []*sidecar.GatewayRunHandle{handle}); !errors.Is(err, sidecar.ErrRunMarksUnread) {
		t.Fatalf("a run whose marks do not read: %v", err)
	}
}
