//go:build !js && !ios && !android && !sdk_mobile_bind

// The daemon's run bindings (§16.6's rejoin and monotone rows, §16.7's How; plan-MCP-taint-new-session; RECORD.md
// section 4.3), one index per network's run store, rebuilt from its run files at first use, so a daemon's restart
// rejoins as a first start does:
//
//	process     a hook's or relay's harness process is the nearest of its ancestors that is no shell, by pid and
//	            start time, so a reused pid is another process; a new run keeps its hook's
//	members     a caller's runs are every run whose harness process is among its ancestors, its own harness
//	            process's included, so a process a harness spawns, a forger slipping one between the harness and its
//	            `ur hook` among them, stays under that harness's taint: plan-MCP-taint-new-session's union, at every
//	            depth
//	event       a hook event binds to its run by (harness, session_id); a run whose file is gone is written anew,
//	            tainted, run_file_missing (RECORD.md's binding row); a resume in another process moves the run there
//	new run     a session never seen opens one: a SessionStart reporting a fresh start untainted; one reporting a
//	            resume, or any first event of a harness that reports starts, tainted, since this daemon holds none of
//	            its history; a harness that reports none opens one at its first event; and every new run starts with
//	            its members' taint, fsynced
//	MCP session joins its relay's harness process's runs, found through the peer pid's ancestry, acting in the newest;
//	            until a hook opens one there it is unbound, under a placeholder run id the store never saw, which
//	            reads tainted, and a call made then is a coverage lapse (hook_coverage.go)
//	monotone    a run's taint is written to all its caller's members, each fsynced, and a call or event first
//	            catches its run up to any member's taint; binding carries a placeholder's recorded taint to the runs it
//	            joins, so a session never moves to a less tainted state; SessionEnd clears nothing
//
// While a network is Locked its run files cannot be read or written, so a taint goes to the spool, fsynced, naming the
// run where the index knows it and the session and harness process besides, and the first call or event after unlock
// applies every such record before anything else runs.
//
// Safe for concurrent use. Each index's bindLock orders binds on its store and is held across their fsyncs, never
// across a call out; stateLock guards the maps alone.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// A spooled taint's format version.
const hookSpooledTaintVersion = 1

// What stops a replay at the first capture record, which is another producer's to drain.
var errHookSpoolCapture = errors.New("a capture record: not the binder's to drain")

// A (harness, session_id) pair.
type runSessionKey struct {
	harness   string
	sessionId string
}

// A hook's or a relay's place in the process tree.
type mcpCallerProcess struct {
	// the nearest ancestor that is no shell; zero when the ancestry could not be read
	harness sidecar.ProcessIdentity
	// every ancestor, the caller itself first
	ancestors []sidecar.ProcessIdentity
}

// One run store's bindings.
type runIndex struct {
	// one bind at a time on this store, held across its fsyncs
	bindLock sync.Mutex

	// the rest under RunBinder.stateLock
	loaded        bool
	sessionRunIds map[runSessionKey]sidecar.Id
	processRunIds map[sidecar.ProcessIdentity][]sidecar.Id
	runProcesses  map[sidecar.Id]sidecar.ProcessIdentity
	// the newest hook event under each harness process, and its newest config check (hook_coverage.go)
	processHookTimes   map[sidecar.ProcessIdentity]time.Time
	processConfigTimes map[sidecar.ProcessIdentity]time.Time
}

// One MCP session's binding in one network.
type mcpSessionBinding struct {
	// the run the session acts in while unbound, which no store saw
	placeholderRunId sidecar.Id
	bound            bool
}

// Whether a harness's config changed since `ur install-harness` sealed its hashes (MCP-M3-16's HarnessConfigHashes),
// for a session working in cwd. An error reads changed.
type HarnessConfigCheck func(ctx context.Context, harness string, cwd string) (changed bool, err error)

// The daemon's run bindings, shared by its hook method and its MCP sessions.
type RunBinder struct {
	server *McpServer

	stateLock    sync.Mutex
	storeIndexes map[*sidecar.RunStore]*runIndex
	// networks whose spool holds no taint taken while Locked that this process has not applied
	replayDoneNetworks map[McpNetwork]bool
	// nil reads every config changed, the closed direction until MCP-M3-16 seals hashes
	configCheck HarnessConfigCheck
}

// A binder for server.
func newRunBinder(server *McpServer) *RunBinder {
	return &RunBinder{
		server:             server,
		storeIndexes:       map[*sidecar.RunStore]*runIndex{},
		replayDoneNetworks: map[McpNetwork]bool{},
	}
}

// Sets what checks a harness's config hashes (MCP-M3-16). Nil reads every config changed.
func (self *RunBinder) SetConfigCheck(check HarnessConfigCheck) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.configCheck = check
}

// The place of a session's or a hook's peer, by the pid the system reports. Empty when the system names no peer or
// its ancestry cannot be read; the hello's own pid is the caller's word, and no rule takes it.
func (self *RunBinder) callerProcessOf(hello *sidecar.DaemonHello) mcpCallerProcess {
	if hello.PeerPid <= 0 {
		return mcpCallerProcess{}
	}
	return self.callerProcessOfPid(int(hello.PeerPid))
}

// The place of a pid.
func (self *RunBinder) callerProcessOfPid(pid int) mcpCallerProcess {
	ingest := self.server.settings.Ingest
	ancestors, err := sidecar.ProcessAncestors(self.server.processes, pid, ingest.AncestorDepthCount)
	if err != nil {
		return mcpCallerProcess{}
	}
	caller := mcpCallerProcess{}
	for _, ancestor := range ancestors {
		caller.ancestors = append(caller.ancestors, ancestor.Identity)
	}
	if harness := sidecar.HarnessProcessOf(ancestors, ingest.ShellNames); harness != nil {
		caller.harness = harness.Identity
	}
	return caller
}

// runs' index, built from its files on first use. An error when they cannot be listed, Locked among the reasons.
func (self *RunBinder) indexFor(ctx context.Context, runs *sidecar.RunStore) (*runIndex, error) {
	index := func() *runIndex {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		index, ok := self.storeIndexes[runs]
		if !ok {
			index = &runIndex{
				sessionRunIds:      map[runSessionKey]sidecar.Id{},
				processRunIds:      map[sidecar.ProcessIdentity][]sidecar.Id{},
				runProcesses:       map[sidecar.Id]sidecar.ProcessIdentity{},
				processHookTimes:   map[sidecar.ProcessIdentity]time.Time{},
				processConfigTimes: map[sidecar.ProcessIdentity]time.Time{},
			}
			self.storeIndexes[runs] = index
		}
		return index
	}()
	loaded := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return index.loaded
	}()
	if loaded {
		return index, nil
	}
	index.bindLock.Lock()
	defer index.bindLock.Unlock()
	files, err := runs.List(ctx)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if index.loaded {
		return index, nil
	}
	for _, file := range files {
		key := runSessionKey{harness: file.Harness}
		process := sidecar.ProcessIdentity{Pid: file.ProcessId, StartMillis: file.ProcessStartMillis}
		for _, sessionId := range file.SessionIds {
			key.sessionId = sessionId
			self.addRunWithLock(index, file.RunId, key, process)
		}
	}
	index.loaded = true
	return index, nil
}

// Notes a run in the index, with its session and harness process.
func (self *RunBinder) addRunWithLock(index *runIndex, runId sidecar.Id, key runSessionKey, process sidecar.ProcessIdentity) {
	index.sessionRunIds[key] = runId
	if process.Known() && !slices.Contains(index.processRunIds[process], runId) {
		index.processRunIds[process] = append(index.processRunIds[process], runId)
		index.runProcesses[runId] = process
	}
}

// The runs of a harness process, oldest first.
func (self *RunBinder) processRuns(index *runIndex, process sidecar.ProcessIdentity) []sidecar.Id {
	if !process.Known() {
		return nil
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(index.processRunIds[process])
}

// runId first, then every run whose harness process is among caller's ancestors: the runs one taint reaches.
func (self *RunBinder) members(index *runIndex, runId sidecar.Id, caller mcpCallerProcess) []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	members := []sidecar.Id{}
	if runId != (sidecar.Id{}) {
		members = append(members, runId)
	}
	for _, ancestor := range caller.ancestors {
		for _, member := range index.processRunIds[ancestor] {
			if !slices.Contains(members, member) {
				members = append(members, member)
			}
		}
	}
	return members
}

// Taints every member, each fsynced (D-MCP-16): the first by reason, the others by inherited. Every member is tried;
// the answer joins their failures.
func (self *RunBinder) taintMembers(ctx context.Context, runs *sidecar.RunStore, members []sidecar.Id, reason sidecar.RunTaintReason) error {
	errs := []error{}
	for i, member := range members {
		memberReason := reason
		if 0 < i {
			memberReason = sidecar.RunTaintInherited
		}
		errs = append(errs, runs.Taint(ctx, member, memberReason))
	}
	return errors.Join(errs...)
}

// Catches members up to each other: when any reads tainted, each that holds no taint yet is tainted, inherited,
// fsynced. So a run reads the taint of every harness above its caller before anything acts in it.
func (self *RunBinder) syncMembers(ctx context.Context, runs *sidecar.RunStore, members []sidecar.Id) error {
	if !slices.ContainsFunc(members, runs.Tainted) {
		return nil
	}
	errs := []error{}
	for _, member := range members {
		if !runs.TaintRecorded(member) {
			errs = append(errs, runs.Taint(ctx, member, sidecar.RunTaintInherited))
		}
	}
	return errors.Join(errs...)
}

// Binds a hook event to its run, opening or rewriting one as the table above says, catches it up to its caller's
// members, and answers its id. Zero, and nothing bound, for an event that names no session.
func (self *RunBinder) bindEvent(ctx context.Context, runs *sidecar.RunStore, index *runIndex, adapter HookAdapter,
	caller mcpCallerProcess, event *HookEvent) (sidecar.Id, error) {
	if event.SessionId == "" {
		return sidecar.Id{}, nil
	}
	index.bindLock.Lock()
	defer index.bindLock.Unlock()
	key := runSessionKey{harness: event.Harness, sessionId: event.SessionId}
	runId, known, process := func() (sidecar.Id, bool, sidecar.ProcessIdentity) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		runId, known := index.sessionRunIds[key]
		return runId, known, index.runProcesses[runId]
	}()
	if known {
		if err := self.rejoin(ctx, runs, index, runId, process, caller.harness, key, event); err != nil {
			return sidecar.Id{}, err
		}
		return runId, self.syncMembers(ctx, runs, self.members(index, runId, caller))
	}
	run := &sidecar.RunFile{
		RunId:              sidecar.NewId(),
		Harness:            event.Harness,
		SessionIds:         []string{event.SessionId},
		Worktree:           event.Cwd,
		ProcessId:          caller.harness.Pid,
		ProcessStartMillis: caller.harness.StartMillis,
	}
	taint := func(reason sidecar.RunTaintReason) {
		run.Tainted = true
		if !slices.Contains(run.TaintReasons, reason) {
			run.TaintReasons = append(run.TaintReasons, reason)
		}
	}
	switch {
	case event.Kind == HookEventSessionStart && event.Start == HookStartFresh:
	case event.Kind == HookEventSessionStart, adapter.ReportsSessionStart():
		// a resume, or a session whose start this daemon missed: none of its history is here
		taint(sidecar.RunTaintCoverageLapse)
		run.Gaps = append(run.Gaps, "missed_event")
	}
	if slices.ContainsFunc(self.members(index, sidecar.Id{}, caller), runs.Tainted) {
		taint(sidecar.RunTaintInherited)
	}
	if err := runs.Create(ctx, run); err != nil {
		return sidecar.Id{}, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.addRunWithLock(index, run.RunId, key, caller.harness)
	return run.RunId, nil
}

// A known session's event: its run's file written anew, tainted, when it is gone, and the run moved to the harness
// process now running it, as a resume in another process does.
func (self *RunBinder) rejoin(ctx context.Context, runs *sidecar.RunStore, index *runIndex, runId sidecar.Id,
	process sidecar.ProcessIdentity, harnessProcess sidecar.ProcessIdentity, key runSessionKey, event *HookEvent) error {
	_, err := runs.Get(runId)
	if errors.Is(err, sidecar.ErrSidecarStoreAbsent) {
		err = runs.Create(ctx, &sidecar.RunFile{
			RunId:              runId,
			Harness:            event.Harness,
			SessionIds:         []string{event.SessionId},
			Worktree:           event.Cwd,
			Tainted:            true,
			TaintReasons:       []sidecar.RunTaintReason{sidecar.RunTaintFileMissing},
			Gaps:               []string{"run_file_missing"},
			ProcessId:          harnessProcess.Pid,
			ProcessStartMillis: harnessProcess.StartMillis,
		})
		if err != nil && !errors.Is(err, sidecar.ErrRunExists) {
			return err
		}
		self.moveRun(index, runId, key, harnessProcess)
		return nil
	}
	if err != nil {
		// a file that does not read: the run reads tainted, and the members catch up to it
		return runs.Taint(ctx, runId, sidecar.RunTaintFileMissing)
	}
	if !harnessProcess.Known() || process == harnessProcess {
		return nil
	}
	if err := runs.SetProcess(ctx, runId, harnessProcess); err != nil {
		return err
	}
	self.moveRun(index, runId, key, harnessProcess)
	return nil
}

// Files a run under a harness process in the index, and under no other.
func (self *RunBinder) moveRun(index *runIndex, runId sidecar.Id, key runSessionKey, process sidecar.ProcessIdentity) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if old, ok := index.runProcesses[runId]; ok {
		index.processRunIds[old] = slices.DeleteFunc(index.processRunIds[old], func(other sidecar.Id) bool { return other == runId })
		delete(index.runProcesses, runId)
	}
	self.addRunWithLock(index, runId, key, process)
}

// A session's binding in a network, made on first use with a fresh placeholder.
func (self *McpSession) bindingFor(networkId sidecar.Id) *mcpSessionBinding {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	binding, ok := self.networkIdBindings[networkId]
	if !ok {
		binding = &mcpSessionBinding{placeholderRunId: sidecar.NewId()}
		self.networkIdBindings[networkId] = binding
	}
	return binding
}

// Readies a call's run before any tool runs: a Locked taint applied first, the session bound where a hook has opened
// a run of its relay's harness process, the call's run chosen and caught up to its members, and the coverage rules
// run (hook_coverage.go). An error refuses the call, since its taint cannot be known.
func (self *RunBinder) readyCall(ctx context.Context, call *McpCall) error {
	if err := self.replaySpooledTaint(ctx, call.Network); err != nil {
		return err
	}
	runs, err := call.Network.Runs()
	if err != nil {
		return err
	}
	index, err := self.indexFor(ctx, runs)
	if err != nil {
		return err
	}
	session := call.Session
	binding := session.bindingFor(call.NetworkId)
	processRuns := self.processRuns(index, session.caller.harness)
	bound := func() bool {
		session.stateLock.Lock()
		defer session.stateLock.Unlock()
		return binding.bound
	}()
	if !bound && 0 < len(processRuns) {
		// what the session took while unbound comes with it
		if runs.TaintRecorded(binding.placeholderRunId) {
			members := self.members(index, processRuns[len(processRuns)-1], session.caller)
			if err := self.taintMembers(ctx, runs, members, sidecar.RunTaintInherited); err != nil {
				return err
			}
		}
		func() {
			session.stateLock.Lock()
			defer session.stateLock.Unlock()
			binding.bound = true
		}()
		bound = true
	}
	if !bound {
		// the placeholder reads tainted by itself, and its unknown id is no taint for the runs above it to take; an
		// untrusted read still reaches them, through Taint
		call.RunId = binding.placeholderRunId
		call.members = self.members(index, call.RunId, session.caller)
		return self.unboundCall(ctx, runs, call)
	}
	call.RunId = processRuns[len(processRuns)-1]
	call.members = self.members(index, call.RunId, session.caller)
	if err := self.syncMembers(ctx, runs, call.members); err != nil {
		return err
	}
	return self.boundCall(ctx, runs, index, call)
}

// Taints the call's run write-ahead (D-MCP-16), and every run of a harness above its session, each fsynced: what a
// tool runs before it returns untrusted data, failing the call when it fails.
func (self *McpCall) Taint(ctx context.Context, reason sidecar.RunTaintReason) error {
	runs, err := self.Network.Runs()
	if err != nil {
		return err
	}
	members := self.members
	if len(members) == 0 {
		members = []sidecar.Id{self.RunId}
	}
	return self.Session.server.binder.taintMembers(ctx, runs, members, reason)
}

// Whether the call's run is tainted: true when its store cannot answer, and for an unbound session's placeholder.
func (self *McpCall) Tainted() bool {
	runs, err := self.Network.Runs()
	if err != nil {
		return true
	}
	return runs.Tainted(self.RunId)
}

// The run a control-mode caller acts in, its SidecarAction.RunId: the newest run of the nearest of its ancestors that
// is a run's harness process, caught up to its members' taint, so an agent's shell cannot run an outward command
// outside its run's taint. Nil for none: an app, or a command a person typed outside any harness.
func (self *RunBinder) RunForPid(ctx context.Context, network McpNetwork, pid int) (*sidecar.Id, error) {
	runs, err := network.Runs()
	if err != nil {
		return nil, err
	}
	index, err := self.indexFor(ctx, runs)
	if err != nil {
		return nil, err
	}
	caller := self.callerProcessOfPid(pid)
	for _, ancestor := range caller.ancestors {
		processRuns := self.processRuns(index, ancestor)
		if len(processRuns) == 0 {
			continue
		}
		runId := processRuns[len(processRuns)-1]
		if err := self.syncMembers(ctx, runs, self.members(index, runId, caller)); err != nil {
			return nil, err
		}
		return &runId, nil
	}
	return nil, nil
}

// A taint taken while a network is Locked, as the spool keeps it: the session and the hook's ancestry, which a replay
// resolves to runs once the files read again, beside the run the record names where the index knew it.
type hookSpooledTaint struct {
	Version   int                       `json:"version"`
	Harness   string                    `json:"harness"`
	SessionId string                    `json:"session_id"`
	Ancestors []sidecar.ProcessIdentity `json:"ancestors"`
	Reason    sidecar.RunTaintReason    `json:"reason"`
}

// Spools a taint, fsynced, while network is Locked: the ack's precondition (§16.6's write-ahead row), applied at the
// next replay.
func (self *RunBinder) spoolTaint(network McpNetwork, runId sidecar.Id, event *HookEvent, caller mcpCallerProcess, reason sidecar.RunTaintReason) error {
	spool, err := network.Spool()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(&hookSpooledTaint{
		Version:   hookSpooledTaintVersion,
		Harness:   event.Harness,
		SessionId: event.SessionId,
		Ancestors: caller.ancestors,
		Reason:    reason,
	})
	if err != nil {
		return err
	}
	if err := spool.Append(&sidecar.SpoolRecord{Kind: sidecar.SpoolRecordTaint, RunId: runId, Bytes: encoded}); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.replayDoneNetworks, network)
	return nil
}

// Applies every taint the network's spool holds before anything else runs, once after each start and after each
// taint spooled while Locked; the drain stops at the first capture, another producer's. A network with no spool, one
// not enrolled, spooled nothing. The answer is an error when a taint did not apply, which refuses what waited on it.
func (self *RunBinder) replaySpooledTaint(ctx context.Context, network McpNetwork) error {
	done := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.replayDoneNetworks[network]
	}()
	if done {
		return nil
	}
	spool, err := network.Spool()
	if err == nil {
		runs, runsErr := network.Runs()
		if runsErr != nil {
			return runsErr
		}
		index, indexErr := self.indexFor(ctx, runs)
		if indexErr != nil {
			return indexErr
		}
		err = spool.Drain(ctx, self.spoolTaintHandler(ctx, runs, index))
		if errors.Is(err, errHookSpoolCapture) {
			err = nil
		}
	} else if errors.Is(err, sidecar.ErrSidecarStoreLocked) {
		err = nil
	}
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.replayDoneNetworks[network] = true
	return nil
}

// The taint handler RECORD-M3-02's SidecarRecord.SetSpoolHandlers takes, once a daemon composes the record component,
// so its drain applies the binder's spooled taint as a replay does; from then its drain, not the binder's, empties the
// spool. An error when the network's runs cannot be read.
func (self *RunBinder) SpoolTaintHandler(ctx context.Context, network McpNetwork) (func(id sidecar.SpoolRecordId, record *sidecar.SpoolRecord) error, error) {
	runs, err := network.Runs()
	if err != nil {
		return nil, err
	}
	index, err := self.indexFor(ctx, runs)
	if err != nil {
		return nil, err
	}
	return self.spoolTaintHandler(ctx, runs, index), nil
}

// The handler a drain hands taint records to: each applied to the run it names, its session's run and every run of
// the hook's ancestry, each fsynced. A capture record stops the drain, since it is not the binder's.
func (self *RunBinder) spoolTaintHandler(ctx context.Context, runs *sidecar.RunStore, index *runIndex) func(id sidecar.SpoolRecordId, record *sidecar.SpoolRecord) error {
	return func(id sidecar.SpoolRecordId, record *sidecar.SpoolRecord) error {
		if record.Kind != sidecar.SpoolRecordTaint {
			return errHookSpoolCapture
		}
		spooled := &hookSpooledTaint{}
		if err := json.Unmarshal(record.Bytes, spooled); err != nil || spooled.Version != hookSpooledTaintVersion {
			// no run can be named from it: what it named reads tainted only if its run's file says so
			return nil
		}
		reason := spooled.Reason
		if reason == "" {
			reason = sidecar.RunTaintUntrustedData
		}
		runId := record.RunId
		if runId == (sidecar.Id{}) {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				runId = index.sessionRunIds[runSessionKey{harness: spooled.Harness, sessionId: spooled.SessionId}]
			}()
		}
		members := self.members(index, runId, mcpCallerProcess{ancestors: spooled.Ancestors})
		return self.taintMembers(ctx, runs, members, reason)
	}
}

// Ends a session's bindings: a placeholder that holds a file starts its retention, so the sweep removes it in time.
func (self *McpSession) close() {
	bindings := func() map[sidecar.Id]*mcpSessionBinding {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.networkIdBindings
	}()
	for networkId, binding := range bindings {
		network, ok := self.server.daemon.Network(networkId)
		if !ok {
			continue
		}
		runs, err := network.Runs()
		if err != nil {
			continue
		}
		// no file answers ErrRunUnknown, and nothing is kept
		runs.Covered(context.Background(), binding.placeholderRunId, 0, 0, self.server.clock.Now().UnixMilli())
	}
}
