//go:build !js && !ios && !android && !sdk_mobile_bind

// RECORD.md section 20's "a command under a harness process is refused", the ancestry half
// (record_disclose_ancestor.go): a caller is under a harness when a run's harness process is among its ancestors, a
// process that reused a harness's pid is not one, and a caller whose ancestry cannot be read is taken as under one.

package sidecar

import (
	"context"
	"testing"
)

func TestHarnessAncestorReadsTheCallersAncestry(t *testing.T) {
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	table := testProcessTable{}
	table.add(10, 1, 100, "zsh")
	table.add(20, 10, 200, "claude")
	table.add(30, 20, 300, "bash")
	table.add(40, 30, 400, "ur")
	table.add(50, 10, 500, "ur")
	ctx := context.Background()
	ingest := DefaultSidecarSettings().Ingest
	if harnessAncestorOn(ctx, runs, table, ingest, 40) {
		t.Fatal("a caller with no run among its ancestors reads as under a harness")
	}
	// a run of an earlier process that held pid 20 is no ancestor
	if err := runs.Create(ctx, &RunFile{RunId: NewId(), Harness: "claude-code", ProcessId: 20, ProcessStartMillis: 50}); err != nil {
		t.Fatal(err)
	}
	if harnessAncestorOn(ctx, runs, table, ingest, 40) {
		t.Fatal("a run of a process that held the pid before reads as an ancestor")
	}
	if err := runs.Create(ctx, &RunFile{RunId: NewId(), Harness: "claude-code", ProcessId: 20, ProcessStartMillis: 200}); err != nil {
		t.Fatal(err)
	}
	if !harnessAncestorOn(ctx, runs, table, ingest, 40) {
		t.Fatal("a command an agent's shell ran does not read as under its harness")
	}
	if harnessAncestorOn(ctx, runs, table, ingest, 50) {
		t.Fatal("a command a person typed beside the harness reads as under it")
	}
	// no readable ancestry: the closed reading
	if !harnessAncestorOn(ctx, runs, table, ingest, 999) || !harnessAncestorOn(ctx, runs, table, ingest, 0) {
		t.Fatal("a caller whose ancestry cannot be read is let through")
	}
}
