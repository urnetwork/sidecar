//go:build !js && !ios && !android && !sdk_mobile_bind

// Whether a control-mode caller runs under a harness, for the acts RECORD.md gives to a person alone: a disclosure,
// an opening and an export that needs a confirmation (sections 9 and 11's who rows). A caller is under a harness
// when a run file's harness process is among its ancestors, as Sidecar.TaintAncestorRuns reads it. A caller whose
// ancestry cannot be read is taken as under one: the closed reading, since a refusal costs a person one more try from
// a terminal and a pass would let a prompt-injected agent's shell build a packet.

package sidecar

import (
	"context"
	"slices"
)

// Whether pid has a harness process of one of this network's runs among its ancestors, itself included. True too
// when its ancestry or the run files cannot be read.
func (self *Sidecar) HarnessAncestor(ctx context.Context, pid int) bool {
	runs, err := self.Runs()
	if err != nil {
		return true
	}
	return harnessAncestorOn(ctx, runs, SystemProcessTable(), self.settings.Ingest, pid)
}

// HarnessAncestor on a run store and a process table.
func harnessAncestorOn(ctx context.Context, runs *RunStore, table ProcessTable, ingest *SidecarIngestSettings, pid int) bool {
	ancestors, err := ProcessAncestors(table, pid, ingest.AncestorDepthCount)
	if err != nil {
		return true
	}
	files, err := runs.List(ctx)
	if err != nil {
		return true
	}
	for _, file := range files {
		process := ProcessIdentity{Pid: file.ProcessId, StartMillis: file.ProcessStartMillis}
		if process.Known() && slices.ContainsFunc(ancestors, func(ancestor *ProcessInfo) bool { return ancestor.Identity == process }) {
			return true
		}
	}
	return false
}
