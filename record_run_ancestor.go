//go:build !js && !ios && !android && !sdk_mobile_bind

// The run rules' half in the root (§16.6's taint row, §16.7; plan-MCP-taint-new-session): what the daemon's run binder
// (mcp/hook_bind.go) reads of the run files, and the taint a control-mode caller's ancestry carries to them. A read of
// untrusted data by a ur command an agent's shell runs taints every run whose harness process is among that command's
// ancestors, fsynced, before the command's answer (Sidecar.TaintAncestorRuns), so a harness cannot launder taint by
// reading through a shell rather than MCP. A command with no harness among its ancestors, an app's or one a person
// typed, binds no run and taints none (§16.6: a nil run id means no harness at all).

package sidecar

import (
	"context"
	"errors"
	"slices"
)

// Every run file that reads, for the binder's index; a file that does not read is passed over, and reads tainted by
// Tainted all the same. ErrSidecarStoreLocked while Locked.
func (self *RunStore) List(ctx context.Context) ([]*RunFile, error) {
	entries, err := self.store.List("")
	if err != nil {
		return nil, err
	}
	runs := []*RunFile{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		runId, err := ParseId(entry.Name)
		if err != nil || runFileName(runId) != entry.Name {
			continue
		}
		run, err := self.Get(runId)
		if err != nil {
			continue
		}
		runs = append(runs, run)
	}
	return runs, nil
}

// Whether this store holds a taint for runId, in memory or in its file. Unlike Tainted, a run with neither answers
// false: the binder carries an unbound session's own taint to the runs it joins, never the taint an unknown id reads
// with.
func (self *RunStore) TaintRecorded(runId Id) bool {
	if tainted, _ := self.taintedInMemory(runId); tainted {
		return true
	}
	run, err := self.Get(runId)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return false
	}
	return err != nil || run.Tainted
}

// Moves a run to the harness process now running it, as a resume in a new process does (§16.7's rejoin), so the
// ancestry rules find it there.
func (self *RunStore) SetProcess(ctx context.Context, runId Id, process ProcessIdentity) error {
	return self.update(ctx, runId, func(run *RunFile) {
		run.ProcessId = process.Pid
		run.ProcessStartMillis = process.StartMillis
	})
}

// Taints, fsynced, every run of the network whose harness process is an ancestor of pid: what a control-mode read of
// untrusted data runs before it answers (§16.6's taint row, "by a ur command whose process ancestry binds it to the
// run"), failing that read when a taint fails. A pid with no readable ancestry names no run and taints none.
func (self *Sidecar) TaintAncestorRuns(ctx context.Context, pid int) error {
	runs, err := self.Runs()
	if err != nil {
		return err
	}
	return taintAncestorRunsOn(ctx, runs, SystemProcessTable(), self.settings.Ingest, pid)
}

// TaintAncestorRuns on a run store and a process table.
func taintAncestorRunsOn(ctx context.Context, runs *RunStore, table ProcessTable, ingest *SidecarIngestSettings, pid int) error {
	ancestors, err := ProcessAncestors(table, pid, ingest.AncestorDepthCount)
	if err != nil {
		return nil
	}
	identities := []ProcessIdentity{}
	for _, ancestor := range ancestors {
		identities = append(identities, ancestor.Identity)
	}
	files, err := runs.List(ctx)
	if err != nil {
		return err
	}
	errs := []error{}
	for _, file := range files {
		process := ProcessIdentity{Pid: file.ProcessId, StartMillis: file.ProcessStartMillis}
		if process.Known() && slices.Contains(identities, process) {
			errs = append(errs, runs.Taint(ctx, file.RunId, RunTaintUntrustedData))
		}
	}
	return errors.Join(errs...)
}
