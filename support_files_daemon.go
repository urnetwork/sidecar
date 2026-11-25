//go:build !ios_extension && !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The run a support message's caller's process ancestry binds (DESIGN-COMPUTE §28.8), on the legs that read process
// ancestry (daemon_proc.go): what ur support send from a harness's process sends as, its run's taint reasons on the
// message's action and its worktree the root its files are read beneath (support_files.go).

package sidecar

import (
	"context"
)

// The run the process pid's ancestry binds: the run file whose harness process is pid's nearest ancestor, nil where
// none is. Its worktree is where ur support send from a harness's process reads its files, and its taint reasons go on
// the message's action (§28.8).
func (self *Sidecar) SupportCallerRun(ctx context.Context, pid int) (*RunFile, error) {
	runs, err := self.Runs()
	if err != nil {
		return nil, err
	}
	return supportCallerRunOn(ctx, runs, SystemProcessTable(), self.settings.Ingest, pid)
}

// SupportCallerRun on a run store and a process table.
func supportCallerRunOn(ctx context.Context, runs *RunStore, table ProcessTable, ingest *SidecarIngestSettings, pid int) (*RunFile, error) {
	ancestors, err := ProcessAncestors(table, pid, ingest.AncestorDepthCount)
	if err != nil {
		return nil, err
	}
	files, err := runs.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, ancestor := range ancestors {
		for _, file := range files {
			process := ProcessIdentity{Pid: file.ProcessId, StartMillis: file.ProcessStartMillis}
			if process.Known() && process == ancestor.Identity {
				return file, nil
			}
		}
	}
	return nil, nil
}
