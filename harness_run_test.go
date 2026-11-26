//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// A Harness run on a fresh run store.
func newHarnessTestRun(t *testing.T, runs *RunStore, args *HarnessRunArgs) *HarnessRun {
	t.Helper()
	if args == nil {
		args = &HarnessRunArgs{}
	}
	args.Runs = runs
	if args.RunId == (Id{}) {
		args.RunId = NewId()
	}
	if args.AgentId == (Id{}) {
		args.AgentId = NewId()
	}
	run, err := NewHarnessRun(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

// A Harness run is a run store run of harness ur-harness with no harness process, starting untainted and unmarked,
// or with the taint and marks it is given, written before it returns.
func TestHarnessRunIsRunStoreRun(t *testing.T) {
	instance, runs, clock := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	run := newHarnessTestRun(t, runs, nil)
	file, err := runs.Get(run.Id())
	if err != nil {
		t.Fatal(err)
	}
	if file.Harness != HarnessRunHarnessName || file.ProcessId != 0 || file.Tainted || len(file.Marks) != 0 {
		t.Fatalf("run file: %+v", file)
	}
	if run.Tainted() {
		t.Fatal("a fresh run reads tainted")
	}
	if marks, err := run.Marks(); err != nil || marks != 0 {
		t.Fatalf("a fresh run's marks: %v, %v", marks, err)
	}

	child := newHarnessTestRun(t, runs, &HarnessRunArgs{TaintReasons: []RunTaintReason{RunTaintInherited},
		Marks: HarnessMarkPrivate})
	reopened := reopenTestRunStore(t, instance, clock)
	if !reopened.Tainted(child.Id()) || !slices.Equal(reopened.TaintReasons(child.Id()), []RunTaintReason{RunTaintInherited}) {
		t.Fatal("a run started tainted does not read tainted after a restart")
	}
	if names, err := reopened.Marks(child.Id()); err != nil || !slices.Equal(names, []string{"private"}) {
		t.Fatalf("a run started marked reads %v, %v after a restart", names, err)
	}
}

// A taint whose write fails fails the call that tainted, and the run reads tainted all the same.
func TestHarnessTaintWriteFailureFailsCall(t *testing.T) {
	backend := &runSyncFaultBackend{SidecarStoreBackend: NewSidecarMemoryBackend()}
	_, runs, _ := newTestRunStoreOn(t, backend)
	run := newHarnessTestRun(t, runs, nil)
	backend.setFailing(true)
	if err := run.Taint(context.Background(), RunTaintUntrustedData); err == nil {
		t.Fatal("a taint whose fsync failed answered nil")
	}
	if !run.Tainted() {
		t.Fatal("a run whose taint did not persist reads untainted")
	}
	if err := run.Mark(context.Background(), HarnessMarkPrivate); err == nil {
		t.Fatal("a mark whose fsync failed answered nil")
	}
	if marks, _ := run.Marks(); marks&HarnessMarkPrivate == 0 {
		t.Fatal("a run whose mark did not persist reads unmarked")
	}
}

// A mark is fsynced before Mark returns, reads after a restart, only accumulates, and a rewrite that would drop one
// is refused.
func TestHarnessMarkFsyncsAndNeverClears(t *testing.T) {
	instance, runs, clock := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	run := newHarnessTestRun(t, runs, nil)
	ctx := context.Background()
	if err := run.Mark(ctx, HarnessMarkPrivate); err != nil {
		t.Fatal(err)
	}
	if err := run.Mark(ctx, HarnessMarkLimitedUse); err != nil {
		t.Fatal(err)
	}
	if err := run.Mark(ctx, HarnessMarkPrivate); err != nil {
		t.Fatal(err)
	}
	reopened := reopenTestRunStore(t, instance, clock)
	names, err := reopened.Marks(run.Id())
	if err != nil || !slices.Equal(names, []string{"private", "limited_use"}) {
		t.Fatalf("after a restart: %v, %v", names, err)
	}
	if marks := HarnessMarkOf(names); marks != HarnessMarkPrivate|HarnessMarkLimitedUse {
		t.Fatalf("marks %b", marks)
	}
	// a rewrite keeps them, and one that drops a mark is refused
	if err := reopened.AddGap(ctx, run.Id(), "hook_failure"); err != nil {
		t.Fatal(err)
	}
	if names, _ := runs.Marks(run.Id()); len(names) != 2 {
		t.Fatalf("a rewrite dropped marks: %v", names)
	}
	err = reopened.update(ctx, run.Id(), func(file *RunFile) {
		file.Marks = []string{"limited_use"}
	})
	if !errors.Is(err, errRunUnmark) {
		t.Fatalf("a rewrite dropping a mark: %v", err)
	}
	// a taint's rewrite keeps the marks too
	if err := run.Taint(ctx, RunTaintUntrustedData); err != nil {
		t.Fatal(err)
	}
	if file, _ := runs.Get(run.Id()); len(file.Marks) != 2 || !file.Tainted {
		t.Fatalf("after a taint: %+v", file)
	}
	// a mark this build does not know reads as every mark
	if HarnessMarkOf([]string{"from_a_newer_build"}) != HarnessMarkLimitedUse|HarnessMarkPrivate {
		t.Fatal("an unknown mark does not read as every mark")
	}
}

// A run with no file, or an unreadable one, reads tainted and carrying every mark, so a restart never reopens egress;
// a mark on it is refused rather than writing a file that would read untainted.
func TestHarnessRunReadsTaintedWithoutFile(t *testing.T) {
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	runId := NewId()
	run := &HarnessRun{runId: runId, agentId: NewId(), runs: runs}
	if !run.Tainted() {
		t.Fatal("a run with no file reads untainted")
	}
	marks, err := run.Marks()
	if !errors.Is(err, ErrRunMarksUnread) || marks != harnessMarkAll {
		t.Fatalf("a run with no file: marks %b, %v", marks, err)
	}
	if err := run.Mark(context.Background(), HarnessMarkPrivate); !errors.Is(err, ErrRunUnknown) {
		t.Fatalf("a mark on a run with no file: %v", err)
	}
	if _, err := runs.Get(runId); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Fatalf("a refused mark wrote a file: %v", err)
	}
	if !run.Tainted() {
		t.Fatal("a refused mark left the run reading untainted")
	}
}
