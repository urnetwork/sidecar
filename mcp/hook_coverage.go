//go:build !js && !ios && !android && !sdk_mobile_bind

// Hook coverage (§16.6's taint row, D-MCP-5): a run whose hooks lapse is tainted and its coverage names the gap, so a
// removed or broken hook takes outward actions away rather than reopening them:
//
//	unbound      an MCP call while no hook event has bound the session: its placeholder is tainted, missed_event
//	quiet        a bound session's call with no hook event under its harness process within Ingest.HookLapseTimeout
//	             either side of it: the call's members tainted, missed_event, checked on the clock that far after the
//	             call
//	config       a harness config hash changed, checked at each run's start and SessionStart, and again at an event or
//	             a call once Ingest.ConfigCheckInterval has passed: the members tainted, config_changed; with no check
//	             installed every config reads changed until MCP-M3-16 seals hashes, the closed direction
//	payload      a payload past Ingest.PayloadByteCount, or one its adapter cannot read: oversize or hook_failure on
//	             the hook's harness process's runs, never an error to the harness
//
// A web tool's taint is fsynced before the hook's ack, and a failure fails the ack (§16.6's write-ahead row); while the
// network is Locked it goes to the spool instead, fsynced, and to this process's memory where the run is known. Time
// is the server's Clock.

package mcp

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/sidecar"
)

// One hook event, read: its run bound and caught up, a web tool's taint fsynced, the coverage rules run and its paths
// held, each before the answer. While the network is Locked only a web tool's taint is kept, in the spool.
func (self *RunBinder) ingestEvent(ctx context.Context, network McpNetwork, networkId sidecar.Id, adapter HookAdapter,
	caller mcpCallerProcess, event *HookEvent, payload []byte) error {
	now := self.server.clock.Now()
	if network.Status().State == sidecar.SidecarStateLocked {
		if err := self.ingestLocked(ctx, network, caller, event, now); err != nil {
			return err
		}
		if capture := self.server.hookCapture(); capture != nil {
			capture(ctx, &HookCaptured{Network: network, NetworkId: networkId, Event: event, Payload: payload, Locked: true})
		}
		return nil
	}
	if err := self.replaySpooledTaint(ctx, network); err != nil {
		return err
	}
	runs, err := network.Runs()
	if err != nil {
		return err
	}
	index, err := self.indexFor(ctx, runs)
	if err != nil {
		return err
	}
	isNew := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		_, known := index.sessionRunIds[runSessionKey{harness: event.Harness, sessionId: event.SessionId}]
		return !known
	}()
	runId, err := self.bindEvent(ctx, runs, index, adapter, caller, event)
	if err != nil {
		return err
	}
	if caller.harness.Known() {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			index.processHookTimes[caller.harness] = now
		}()
	}
	if runId == (sidecar.Id{}) {
		return nil
	}
	members := self.members(index, runId, caller)
	if event.WebTool {
		if err := self.taintMembers(ctx, runs, members, sidecar.RunTaintWebTool); err != nil {
			return err
		}
	}
	force := isNew || event.Kind == HookEventSessionStart
	if err := self.checkConfig(ctx, runs, index, members, caller.harness, event.Harness, event.Cwd, force); err != nil {
		return err
	}
	if event.Kind == HookEventPreToolUse && 0 < len(event.Paths) {
		holds := func() HookHolds {
			self.server.hooks.stateLock.Lock()
			defer self.server.hooks.stateLock.Unlock()
			return self.server.hooks.holds
		}()
		if holds != nil {
			if err := holds(ctx, network, networkId, runId, event); err != nil {
				self.server.log.Warningf("[mcp]a PreToolUse's paths were not held: %s", err)
			}
		}
	}
	if capture := self.server.hookCapture(); capture != nil {
		// after the ack's preconditions: its own failures are the capture's gaps, never the hook's
		if err := capture(ctx, &HookCaptured{Network: network, NetworkId: networkId, RunId: runId, Event: event, Payload: payload}); err != nil {
			self.server.log.Warningf("[mcp]a hook event was not captured: %s", err)
		}
	}
	return nil
}

// A hook event while network is Locked: its run files cannot be read or written, so a web tool's taint goes to the
// spool, fsynced, naming the run where the index knew it, and into this process's memory for each member the index
// names; the event otherwise binds nothing until unlock.
func (self *RunBinder) ingestLocked(ctx context.Context, network McpNetwork, caller mcpCallerProcess, event *HookEvent, now time.Time) error {
	runId := sidecar.Id{}
	members := []sidecar.Id{}
	runs, err := network.Runs()
	if err == nil {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			index, ok := self.storeIndexes[runs]
			if !ok {
				return
			}
			if caller.harness.Known() {
				index.processHookTimes[caller.harness] = now
			}
			runId = index.sessionRunIds[runSessionKey{harness: event.Harness, sessionId: event.SessionId}]
		}()
		if index, ok := func() (*runIndex, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			index, ok := self.storeIndexes[runs]
			return index, ok
		}(); ok {
			members = self.members(index, runId, caller)
		}
	}
	if !event.WebTool {
		return nil
	}
	if err := self.spoolTaint(network, runId, event, caller, sidecar.RunTaintWebTool); err != nil {
		return err
	}
	// the files refuse a write while Locked, and the store's memory still takes the taint first
	for _, member := range members {
		runs.Taint(ctx, member, sidecar.RunTaintWebTool)
	}
	return nil
}

// Counts a coverage gap on every run of a hook's harness process, as a payload no adapter could read is. Nothing
// while the network is Locked or the process unknown, since no run can be named.
func (self *RunBinder) gapProcess(ctx context.Context, network McpNetwork, caller mcpCallerProcess, code string) error {
	if !caller.harness.Known() || network.Status().State == sidecar.SidecarStateLocked {
		return nil
	}
	runs, err := network.Runs()
	if err != nil {
		return err
	}
	index, err := self.indexFor(ctx, runs)
	if err != nil {
		return err
	}
	errs := []error{}
	for _, runId := range self.processRuns(index, caller.harness) {
		errs = append(errs, runs.AddGap(ctx, runId, code))
	}
	return errors.Join(errs...)
}

// A call of an unbound session: a coverage lapse, so its placeholder is tainted, fsynced, before anything runs.
func (self *RunBinder) unboundCall(ctx context.Context, runs *sidecar.RunStore, call *McpCall) error {
	if err := runs.Taint(ctx, call.RunId, sidecar.RunTaintCoverageLapse); err != nil {
		return err
	}
	return runs.AddGap(ctx, call.RunId, "missed_event")
}

// A call of a bound session: its config checked when due, and a check set HookLapseTimeout on, which taints the
// call's members unless a hook event under the harness process came within that either side of the call.
func (self *RunBinder) boundCall(ctx context.Context, runs *sidecar.RunStore, index *runIndex, call *McpCall) error {
	session := call.Session
	process := session.caller.harness
	if err := self.checkConfig(ctx, runs, index, call.members, process, session.hello.Harness, session.hello.Cwd, false); err != nil {
		return err
	}
	callTime := self.server.clock.Now()
	timeout := self.server.settings.Ingest.HookLapseTimeout
	members := call.members
	self.server.clock.AfterFunc(timeout, func() {
		lapsed := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			hookTime, ok := index.processHookTimes[process]
			return !ok || hookTime.Before(callTime.Add(-timeout))
		}()
		if !lapsed {
			return
		}
		ctx := context.Background()
		if err := self.taintMembers(ctx, runs, members, sidecar.RunTaintCoverageLapse); err != nil {
			self.server.log.Warningf("[mcp]a coverage lapse's taint was not written: %s", err)
		}
		runs.AddGap(ctx, members[0], "missed_event")
	})
	return nil
}

// Checks a harness's config hashes when force says to or ConfigCheckInterval has passed since the process's last
// check, and taints members, config_changed, on a change, an error, or no check installed.
func (self *RunBinder) checkConfig(ctx context.Context, runs *sidecar.RunStore, index *runIndex, members []sidecar.Id,
	process sidecar.ProcessIdentity, harness string, cwd string, force bool) error {
	if len(members) == 0 {
		return nil
	}
	now := self.server.clock.Now()
	due, check := func() (bool, HarnessConfigCheck) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		checked, ok := index.processConfigTimes[process]
		due := force || !ok || !now.Before(checked.Add(self.server.settings.Ingest.ConfigCheckInterval))
		if due && process.Known() {
			index.processConfigTimes[process] = now
		}
		return due, self.configCheck
	}()
	if !due {
		return nil
	}
	changed := true
	if check != nil {
		checkChanged, err := check(ctx, harness, cwd)
		changed = checkChanged || err != nil
	}
	if !changed {
		return nil
	}
	if err := self.taintMembers(ctx, runs, members, sidecar.RunTaintConfigChanged); err != nil {
		return err
	}
	return runs.AddGap(ctx, members[0], "config_changed")
}
