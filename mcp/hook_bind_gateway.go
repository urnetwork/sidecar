//go:build !js && !ios && !android && !sdk_mobile_bind

// The gateway's run handles over the daemon's run bindings (DESIGN-COMPUTE §8.9, D-GW-7, owner decision 448; GW-M12-02):
// sidecar.GatewayRunBinder's implementation, over RunBinder's index of harness processes and their runs (hook_bind.go),
// which lives here since the root cannot import mcp.
//
//	process  a minting command's harness process is found as a hook's is: the nearest of its ancestors that is no shell,
//	         by Ingest.ShellNames, with every process above it; Known where a run of the network names it already
//	run      a call that names a session binds as a hook event of that session would (bindEvent): the session's run,
//	         moved to the call's process as a resume moves it, or a new run, tainted coverage_lapse where the harness
//	         reports session starts and none came, since this daemon then holds none of its history. A call that names
//	         none takes the process's newest run, else a new run of the process, which starts with the taint of every run
//	         above it, fsynced (D-MCP-16), and is indexed by its process, though it holds no session
//	union    the taint and marks of every run of each handle's process and of the processes above it, as members reads
//	         them for a hook, ended runs included; a run whose marks do not read fails it
//
// A taint spooled while the network was Locked is applied before a call binds, as an MCP call's is. Safe for concurrent
// use, under RunBinder's locks.

package mcp

import (
	"context"
	"slices"

	"github.com/urnetwork/sidecar"
)

// The gateway's binder over self's index.
func (self *RunBinder) GatewayRunBinder() sidecar.GatewayRunBinder {
	return &gatewayRunBinder{binder: self}
}

// sidecar.GatewayRunBinder over a RunBinder.
type gatewayRunBinder struct {
	binder *RunBinder
}

// The index of network's runs, a taint spooled while it was Locked applied first.
func (self *gatewayRunBinder) index(ctx context.Context, network sidecar.GatewayRunNetwork) (*sidecar.RunStore, *runIndex, error) {
	if spooling, ok := network.(McpNetwork); ok {
		if err := self.binder.replaySpooledTaint(ctx, spooling); err != nil {
			return nil, nil, err
		}
	}
	runs, err := network.Runs()
	if err != nil {
		return nil, nil, err
	}
	index, err := self.binder.indexFor(ctx, runs)
	if err != nil {
		return nil, nil, err
	}
	return runs, index, nil
}

// See sidecar.GatewayRunBinder.
func (self *gatewayRunBinder) HarnessProcess(ctx context.Context, network sidecar.GatewayRunNetwork, pid int) (*sidecar.GatewayHarnessProcess, error) {
	ingest := self.binder.server.settings.Ingest
	ancestors, err := sidecar.ProcessAncestors(self.binder.server.processes, pid, ingest.AncestorDepthCount)
	if err != nil {
		return nil, nil
	}
	harness := sidecar.HarnessProcessOf(ancestors, ingest.ShellNames)
	if harness == nil {
		return nil, nil
	}
	found := &sidecar.GatewayHarnessProcess{Process: harness}
	above := false
	for _, ancestor := range ancestors {
		if above {
			found.Above = append(found.Above, ancestor.Identity)
		}
		above = above || ancestor.Identity == harness.Identity
	}
	// a network whose runs do not read knows no process, so the name alone decides, the narrower reading
	if _, index, err := self.index(ctx, network); err == nil {
		found.Known = 0 < len(self.binder.processRuns(index, harness.Identity))
	}
	return found, nil
}

// The caller a handle stands for: its process, and it and every process above it as the ancestry members reads.
func gatewayCallerOf(handle *sidecar.GatewayRunHandle) mcpCallerProcess {
	return mcpCallerProcess{
		harness:   handle.Process,
		ancestors: append([]sidecar.ProcessIdentity{handle.Process}, handle.Above...),
	}
}

// See sidecar.GatewayRunBinder.
func (self *gatewayRunBinder) BindRun(ctx context.Context, network sidecar.GatewayRunNetwork, harness string, handle *sidecar.GatewayRunHandle, sessionId string) (sidecar.Id, error) {
	runs, index, err := self.index(ctx, network)
	if err != nil {
		return sidecar.Id{}, err
	}
	caller := gatewayCallerOf(handle)
	if adapter, ok := HookAdapterFor(harness); ok && sessionId != "" {
		event := &HookEvent{Harness: harness, AdapterVersion: adapter.Version(), Kind: HookEventModelCall, SessionId: sessionId}
		return self.binder.bindEvent(ctx, runs, index, adapter, caller, event)
	}
	index.bindLock.Lock()
	defer index.bindLock.Unlock()
	if processRuns := self.binder.processRuns(index, handle.Process); 0 < len(processRuns) {
		return processRuns[len(processRuns)-1], nil
	}
	run := &sidecar.RunFile{
		RunId:              sidecar.NewId(),
		Harness:            harness,
		SessionIds:         []string{},
		ProcessId:          handle.Process.Pid,
		ProcessStartMillis: handle.Process.StartMillis,
	}
	if slices.ContainsFunc(self.binder.members(index, sidecar.Id{}, caller), runs.Tainted) {
		run.Tainted = true
		run.TaintReasons = []sidecar.RunTaintReason{sidecar.RunTaintInherited}
	}
	if err := runs.Create(ctx, run); err != nil {
		return sidecar.Id{}, err
	}
	self.binder.stateLock.Lock()
	defer self.binder.stateLock.Unlock()
	self.binder.addProcessRunWithLock(index, run.RunId, handle.Process)
	return run.RunId, nil
}

// See sidecar.GatewayRunBinder.
func (self *gatewayRunBinder) Union(ctx context.Context, network sidecar.GatewayRunNetwork, handles []*sidecar.GatewayRunHandle) (*sidecar.GatewayRunUnion, error) {
	runs, index, err := self.index(ctx, network)
	if err != nil {
		return nil, err
	}
	members := []sidecar.Id{}
	for _, handle := range handles {
		for _, member := range self.binder.members(index, sidecar.Id{}, gatewayCallerOf(handle)) {
			if !slices.Contains(members, member) {
				members = append(members, member)
			}
		}
	}
	union := &sidecar.GatewayRunUnion{Marks: []string{}}
	for _, member := range members {
		union.Tainted = union.Tainted || runs.Tainted(member)
		marks, err := runs.Marks(member)
		if err != nil {
			return nil, err
		}
		for _, mark := range marks {
			if !slices.Contains(union.Marks, mark) {
				union.Marks = append(union.Marks, mark)
			}
		}
	}
	return union, nil
}

// Notes a run that holds no session under its harness process alone, as indexFor does at a restart.
func (self *RunBinder) addProcessRunWithLock(index *runIndex, runId sidecar.Id, process sidecar.ProcessIdentity) {
	if process.Known() && !slices.Contains(index.processRunIds[process], runId) {
		index.processRunIds[process] = append(index.processRunIds[process], runId)
		index.runProcesses[runId] = process
	}
}
