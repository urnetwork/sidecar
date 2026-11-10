//go:build !js && !ios && !android && !sdk_mobile_bind

// The run rules' root half (record_run_ancestor.go): a control-mode read taints, fsynced, every run whose harness
// process is among its caller's ancestors and no other; List, TaintRecorded and SetProcess as the binder reads them.

package sidecar

import (
	"context"
	"testing"
)

func TestTaintAncestorRunsTaintsHarnessRuns(t *testing.T) {
	instance, runs, clock := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	table := testProcessTable{}
	table.add(10, 1, 100, "zsh")
	table.add(20, 10, 200, "claude")
	table.add(21, 10, 210, "codex")
	table.add(30, 20, 300, "bash")
	table.add(40, 30, 400, "ur")
	ctx := context.Background()
	underClaude := &RunFile{RunId: NewId(), Harness: "claude-code", ProcessId: 20, ProcessStartMillis: 200}
	underCodex := &RunFile{RunId: NewId(), Harness: "codex", ProcessId: 21, ProcessStartMillis: 210}
	// a run of an earlier process that held pid 20
	reused := &RunFile{RunId: NewId(), Harness: "claude-code", ProcessId: 20, ProcessStartMillis: 50}
	for _, run := range []*RunFile{underClaude, underCodex, reused} {
		if err := runs.Create(ctx, run); err != nil {
			t.Fatal(err)
		}
	}
	if err := taintAncestorRunsOn(ctx, runs, table, DefaultSidecarSettings().Ingest, 40); err != nil {
		t.Fatal(err)
	}
	restarted := reopenTestRunStore(t, instance, clock)
	if !restarted.TaintRecorded(underClaude.RunId) {
		t.Error("the caller's harness run is untainted on disk")
	}
	if restarted.TaintRecorded(underCodex.RunId) || restarted.TaintRecorded(reused.RunId) {
		t.Error("a run of another process was tainted")
	}
	// a caller under no harness, or with no ancestry, taints nothing
	table.add(50, 10, 500, "ur")
	if err := taintAncestorRunsOn(ctx, runs, table, DefaultSidecarSettings().Ingest, 50); err != nil {
		t.Fatal(err)
	}
	if err := taintAncestorRunsOn(ctx, runs, table, DefaultSidecarSettings().Ingest, 999); err != nil {
		t.Fatal(err)
	}
	if reopenTestRunStore(t, instance, clock).TaintRecorded(underCodex.RunId) {
		t.Error("a typed command tainted a run")
	}
}

// TaintRecorded answers false for an id with no file and no taint, where Tainted answers true; List reads each file;
// SetProcess moves a run and keeps its taint.
func TestRunStoreBinderReads(t *testing.T) {
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	ctx := context.Background()
	unknown := NewId()
	if runs.TaintRecorded(unknown) || !runs.Tainted(unknown) {
		t.Error("an unknown run's recorded taint, or its read taint")
	}
	run := &RunFile{RunId: NewId(), Harness: "claude-code", SessionIds: []string{"s1"}, ProcessId: 20, ProcessStartMillis: 200}
	if err := runs.Create(ctx, run); err != nil {
		t.Fatal(err)
	}
	if err := runs.Taint(ctx, run.RunId, RunTaintWebTool); err != nil {
		t.Fatal(err)
	}
	if err := runs.SetProcess(ctx, run.RunId, ProcessIdentity{Pid: 30, StartMillis: 300}); err != nil {
		t.Fatal(err)
	}
	files, err := runs.List(ctx)
	if err != nil || len(files) != 1 {
		t.Fatalf("List: %v %v", files, err)
	}
	if files[0].ProcessId != 30 || files[0].ProcessStartMillis != 300 || !files[0].Tainted || files[0].SessionIds[0] != "s1" {
		t.Errorf("the run's file: %+v", files[0])
	}
}
