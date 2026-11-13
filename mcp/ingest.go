//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's ingest (R-MCP-2, R-MCP-4, R-MCP-6, R-MCP-8, D-MCP-5, I-9): the Ingested table as RECORD.md section 6.3's
// kinds, each entry a RecordDraft to RecordWriter.Append, which seals it with the writer's chain, a per-entry key and
// salt, the run's tainted label and the mode's routing, and returns once it is durable, with evs down or the daemon
// locked. This package supplies headers and redacted bodies:
//
//	transcript   ingest_transcript.go: transcript_path tailed at Stop, SubagentStop, PreCompact, SessionEnd and
//	             every Ingest.TranscriptTailInterval, line-framed, so a secret never splits across reads
//	tool_call    ingest_tools.go: the PostToolUse family, source hook, and the daemon's own MCP calls, source
//	             observed, each with RECORD.md section 4.4's tool action_id
//	hook_event   ingest_tools.go: PreToolUse, PermissionRequest and the lifecycle events, the payload redacted
//	permission   ingest_tools.go: PermissionRequest events and the modes they ran under
//	context      ingest_context.go: a stage 1 entry at SessionStart, stage 2 when the model or mode changes, with
//	             instruction files by hash and never their text, and the run title
//	change, blob ingest_context.go: each hook's scan of MCP-M3-20's restore point, with hashes and attribution, and
//	             the after bytes of each changed file within Ingest.FileByteCount as a blob
//	coverage     ingest_coverage.go: at SessionEnd or after Record.CoverageIdleTimeout idle, naming the sources,
//	             every gap counted where it occurred, and first_seq and last_seq
//
// Limits are Ingest's settings: a payload or tool body over PayloadByteCount is cut, a file over FileByteCount goes by
// hash and size, and a run past RunHourByteCount in an hour drops the rest of that hour's bodies. Every cut, missed
// event, redaction, bypass mode and changed config is a gap on the run's file (RunStore.AddGap), in RECORD.md's codes,
// counted where it occurs and never inferred at the end. Redaction runs before anything is sealed, with the network's
// spool redactor (MCP-M3-17); with none, nothing is sealed and the event is a gap, the closed direction. A run in a
// bypass mode is recorded and gapped bypass_mode; voiding its harness evidence is MCP-M3-10's.
//
// Run-level drafts carry the vault's fields; RECORD's RecordProjectForTeam strips them at M6, so nothing here
// branches on team mode. RunLifecycle is the seam MCP-M6-02 wires to DirectoryRuns, and RunCapture holds
// MCP-M10-02's run-card inputs.
//
// Safe for concurrent use: stateLock guards the run table, each run's own lock its state, and neither is held across
// Append, a scan or a call out.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
)

// §5.9's directory and class for the ingest's own state, and its file's version: format values.
const (
	ingestDirectoryName = "ingest"
	ingestClass         = "ingest"
	ingestStateVersion  = 1
)

// Nothing can be sealed: the network has no redactor (no spool), so the event is a gap.
var ErrIngestNoRedactor = errors.New("ingest has no redactor")

// §16.7's run lifecycle, which MCP-M6-02 wires to RECORD-M6-16's DirectoryRuns: SessionStart's title, project and
// branch, hook activity, and SessionEnd or Coverage. Nothing else of a session reaches it (I-20). Nil wires nothing.
type RunLifecycle interface {
	// A run's first bound SessionStart, with what §16.11's announcement takes.
	RunStarted(ctx context.Context, networkId sidecar.Id, start *RunLifecycleStart)
	// A hook event of a started run.
	RunMoved(ctx context.Context, networkId sidecar.Id, runId sidecar.Id)
	// SessionEnd, or the run's Coverage after idling.
	RunEnded(ctx context.Context, networkId sidecar.Id, runId sidecar.Id)
}

// What RunStarted carries.
type RunLifecycleStart struct {
	RunId   sidecar.Id
	Harness string
	// §16.10's run title, 120 B after redaction; empty until known.
	Title   string
	Project string
	Branch  string
}

// §16.10's run-card inputs, which MCP-M10-02 hands SEARCH-M10-29: all already redacted.
type RunCapture struct {
	RunId      sidecar.Id
	Harness    string
	AgentLabel string
	Model      string
	Project    string
	Branch     string
	// 120 B after redaction.
	Title string
	// Tool names with their counts.
	ToolCounts map[string]int
	// Up to Ingest.RunCardPathCount touched paths, relative to the worktree.
	TouchedPaths []string
	// The first Ingest.RunCardPromptByteCount of the user prompts, redacted.
	Prompts            string
	StartedMillis      int64
	LastActivityMillis int64
	EndedMillis        int64
}

// What Ingest needs.
type IngestArgs struct {
	Server *McpServer
	// The network's record writer: *sidecar.Sidecar's Record().Writer(). Nil reads McpRecordNetwork off the
	// network, and a network that is neither answers an error, so nothing is captured and every event is a gap.
	Writers func(network McpNetwork) (sidecar.RecordWriter, error)
	// The network's redactor, the spool's by default (MCP-M3-17), whose key turns with the spool's epoch. A network
	// with none seals nothing: each of its events is a gap.
	Redactors func(network McpNetwork) (*sidecar.Redactor, error)
	// MCP-M3-20's points; nil scans nothing, so no change or blob entry is written and the scan source is absent.
	Restore *RestorePoints
	// MCP-M6-02's seam; nil wires nothing.
	Lifecycle RunLifecycle
	// The person's home, for the instruction files there and `.ur`; empty reads none.
	Home string
	// §16.8's record settings, for CoverageIdleTimeout. Nil takes the defaults.
	Record *sidecar.SidecarRecordSettings
}

// A network whose record writer the daemon exposes: *sidecar.Sidecar through Record().Writer().
type McpRecordNetwork interface {
	Record() (*sidecar.SidecarRecord, error)
}

// §16.7's ingest. See the file's header.
type Ingest struct {
	server    *McpServer
	clock     sidecar.Clock
	log       sidecar.Logger
	settings  *sidecar.SidecarIngestSettings
	record    *sidecar.SidecarRecordSettings
	writers   func(network McpNetwork) (sidecar.RecordWriter, error)
	redactors func(network McpNetwork) (*sidecar.Redactor, error)
	restore   *RestorePoints
	lifecycle RunLifecycle
	home      string

	stateLock sync.Mutex
	runs      map[restorePointKey]*ingestRun
	// events seen while a network was Locked, by session, each a missed_event once its run binds
	lockedEvents map[restoreLockedKey]int
}

// Ingest over the server, installed on it: its hook capture and MCP-M3-20's holds.
func NewIngest(args *IngestArgs) *Ingest {
	server := args.Server
	record := args.Record
	if record == nil {
		record = sidecar.DefaultSidecarSettings().Record
	}
	writers := args.Writers
	if writers == nil {
		writers = func(network McpNetwork) (sidecar.RecordWriter, error) {
			recordNetwork, ok := network.(McpRecordNetwork)
			if !ok {
				return nil, errors.New("the network has no record writer")
			}
			record, err := recordNetwork.Record()
			if err != nil {
				return nil, err
			}
			return record.Writer(), nil
		}
	}
	redactors := args.Redactors
	if redactors == nil {
		redactors = func(network McpNetwork) (*sidecar.Redactor, error) {
			spool, err := network.Spool()
			if err != nil {
				return nil, err
			}
			redactor := spool.Redactor()
			if redactor == nil {
				return nil, ErrIngestNoRedactor
			}
			return redactor, nil
		}
	}
	self := &Ingest{
		server:       server,
		clock:        server.clock,
		log:          server.log,
		settings:     server.settings.Ingest,
		record:       record,
		writers:      writers,
		redactors:    redactors,
		restore:      args.Restore,
		lifecycle:    args.Lifecycle,
		home:         args.Home,
		runs:         map[restorePointKey]*ingestRun{},
		lockedEvents: map[restoreLockedKey]int{},
	}
	server.SetHookCapture(self.captureHook)
	if self.restore != nil {
		server.SetHookHolds(self.restore.HookHolds())
	}
	return self
}

// One run's ingest state, in memory and in ingest/<run_id>.
type ingestRun struct {
	networkId sidecar.Id
	runId     sidecar.Id
	network   McpNetwork

	// one event or tail at a time
	runLock sync.Mutex
	// the persisted part
	state *ingestRunState
	// the timers of a live run: the idle coverage and the transcript tail
	idleStop func() bool
	tailStop func() bool
	// whether the file needs writing
	dirty bool
}

// The persisted part of a run's ingest state: enough for a restart to resume the tail, keep the hour's budget and
// write the Coverage's range.
type ingestRunState struct {
	Version   int    `json:"version"`
	Harness   string `json:"harness"`
	SessionId string `json:"session_id"`
	Cwd       string `json:"cwd"`
	// the transcript and how far it was read: a byte offset and the next line's number, from 1
	TranscriptPath string `json:"transcript_path"`
	TranscriptAt   int64  `json:"transcript_at"`
	TranscriptLine uint64 `json:"transcript_line"`
	// the run-hour budget: the hour's start and what was captured in it
	HourStartMillis int64 `json:"hour_start_millis"`
	HourByteCount   int64 `json:"hour_byte_count"`
	// the writer's chain across this run's entries
	FirstSeq uint64 `json:"first_seq"`
	LastSeq  uint64 `json:"last_seq"`
	// the context entry's fields, for the stage 2 rule
	HarnessVersion string `json:"harness_version"`
	Model          string `json:"model"`
	PermissionMode string `json:"permission_mode"`
	Started        bool   `json:"started"`
	Bypass         bool   `json:"bypass"`
	// the run card's inputs
	Title              string         `json:"title"`
	AgentLabel         string         `json:"agent_label"`
	Project            string         `json:"project"`
	Branch             string         `json:"branch"`
	ToolCounts         map[string]int `json:"tool_counts"`
	TouchedPaths       []string       `json:"touched_paths"`
	Prompts            string         `json:"prompts"`
	StartedMillis      int64          `json:"started_millis"`
	LastActivityMillis int64          `json:"last_activity_millis"`
	EndedMillis        int64          `json:"ended_millis"`
	// the sources seen, for Coverage
	Sources []string `json:"sources"`
	// whether the newest Coverage is newer than the last event
	Covered bool `json:"covered"`
	// the after hashes already stored as blobs, hex, newest last
	BlobHashes []string `json:"blob_hashes"`
	// the transcript's missing path was counted once
	TranscriptGapped bool `json:"transcript_gapped"`
}

// The run's state, made or read on first use: read back from the store after a restart, which counts downtime.
func (self *Ingest) runFor(ctx context.Context, network McpNetwork, networkId sidecar.Id, runId sidecar.Id) (*ingestRun, error) {
	key := restorePointKey{networkId: networkId, runId: runId}
	run, ok := func() (*ingestRun, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		run, ok := self.runs[key]
		return run, ok
	}()
	if ok {
		return run, nil
	}
	run = &ingestRun{networkId: networkId, runId: runId, network: network}
	store, err := self.store(network)
	if err != nil {
		return nil, err
	}
	state := &ingestRunState{}
	found, err := readRestoreJson(store, runId.String(), state, self.settings.IngestStateByteCount)
	if err != nil {
		return nil, err
	}
	if found && state.Version == ingestStateVersion {
		run.state = state
		if !state.Covered {
			// a restart while the run lived: whatever came between is lost
			self.gap(ctx, network, networkId, runId, sidecar.RecordCoverageGapDowntime)
		}
	} else {
		run.state = &ingestRunState{Version: ingestStateVersion, ToolCounts: map[string]int{}}
		run.dirty = true
	}
	if run.state.ToolCounts == nil {
		run.state.ToolCounts = map[string]int{}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if existing, ok := self.runs[key]; ok {
		return existing, nil
	}
	self.runs[key] = run
	return run, nil
}

// ingest/ under the network's store.
func (self *Ingest) store(network McpNetwork) (sidecar.SidecarStore, error) {
	return network.LocalStore().Directory(ingestDirectoryName, ingestClass)
}

// Writes the run's state when it changed. The run's lock is held.
func (self *Ingest) saveRunWithLock(run *ingestRun) {
	if !run.dirty {
		return
	}
	store, err := self.store(run.network)
	if err != nil {
		return
	}
	if err := writeRestoreJson(store, run.runId.String(), run.state); err != nil {
		self.log.Warningf("[ingest]a run's state was not written: %s", err)
		return
	}
	run.dirty = false
}

// Counts a gap on the run's file, where it occurred, and tells the restore point its next interval is foreign.
func (self *Ingest) gap(ctx context.Context, network McpNetwork, networkId sidecar.Id, runId sidecar.Id, code string) {
	runs, err := network.Runs()
	if err != nil {
		return
	}
	if err := runs.AddGap(ctx, runId, code); err != nil && !errors.Is(err, sidecar.ErrRunUnknown) {
		self.log.Warningf("[ingest]a gap was not counted: %s", err)
	}
	if self.restore != nil {
		self.restore.NoteGap(networkId, runId)
	}
}

// The network's redactor, as the seam gives it.
func (self *Ingest) redactor(network McpNetwork) (*sidecar.Redactor, error) {
	return self.redactors(network)
}

// text redacted, each match a redaction gap on the run.
func (self *Ingest) redact(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor, text []byte) []byte {
	redacted, matches := redactor.Redact(text)
	for range matches {
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapRedaction)
	}
	return redacted
}

// One entry to append for a run.
type ingestEntry struct {
	kind   sidecar.RecordKind
	source sidecar.RecordSource
	// 32 bytes, or nil
	actionId []byte
	body     proto.Message
	// what the body costs against the run-hour budget
	byteCount int64
	// the source code the entry adds to Coverage
	coverageSource string
}

// Appends an entry for the run through the network's writer, within the run-hour budget: a budgeted entry past
// RunHourByteCount is dropped, oversize. The seq range the writer answers is kept for the Coverage. The run's lock is
// held. The answer is whether the entry was appended.
func (self *Ingest) appendWithLock(ctx context.Context, run *ingestRun, entry *ingestEntry) bool {
	_, ok := self.appendEntryWithLock(ctx, run, entry)
	return ok
}

// appendWithLock, answering beside it the first copy of the entry the writer sealed, nil where every copy waits in the
// spool.
func (self *Ingest) appendEntryWithLock(ctx context.Context, run *ingestRun, entry *ingestEntry) (*sidecar.RecordEntryRef, bool) {
	now := self.clock.Now()
	state := run.state
	if entry.byteCount != 0 && !self.budgetWithLock(ctx, run, entry.byteCount) {
		return nil, false
	}
	if entry.coverageSource != "" && !slices.Contains(state.Sources, entry.coverageSource) {
		state.Sources = append(state.Sources, entry.coverageSource)
		run.dirty = true
	}
	writer, err := self.writers(run.network)
	if err != nil {
		self.log.Warningf("[ingest]no record writer: %s", err)
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
		return nil, false
	}
	runId := run.runId
	refs, err := writer.Append(&sidecar.RecordDraft{
		Kind:       entry.kind,
		Source:     entry.source,
		RunId:      &runId,
		ActionId:   entry.actionId,
		TimeMillis: now.UnixMilli(),
		Body:       entry.body,
	})
	if err != nil {
		self.log.Warningf("[ingest]an entry was not appended: %s", err)
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
		return nil, false
	}
	var sealed *sidecar.RecordEntryRef
	for _, ref := range refs {
		if ref.Spooled {
			continue
		}
		if sealed == nil {
			sealed = ref
		}
		if state.FirstSeq == 0 || ref.Seq < state.FirstSeq {
			state.FirstSeq = ref.Seq
		}
		if state.LastSeq < ref.Seq {
			state.LastSeq = ref.Seq
		}
		run.dirty = true
	}
	return sealed, true
}

// The hook capture the server calls after each event's binding (hook_coverage.go): the event's entries, the
// transcript's tail where due, the scan, the lifecycle and the timers. An error is logged and counted as a gap,
// never returned to the hook, which acked what it needed first.
func (self *Ingest) captureHook(ctx context.Context, captured *HookCaptured) error {
	if captured.Locked || captured.RunId == (sidecar.Id{}) {
		// run files and the writer are closed: the writer would spool, but the run is unknown, so the event is
		// lost and counted at the next event (ingestLocked binds nothing)
		self.noteLockedEvent(captured)
		return nil
	}
	run, err := self.runFor(ctx, captured.Network, captured.NetworkId, captured.RunId)
	if err != nil {
		self.log.Warningf("[ingest]a run's state could not be read: %s", err)
		return nil
	}
	run.runLock.Lock()
	defer run.runLock.Unlock()
	defer self.saveRunWithLock(run)
	self.takeLockedGapsWithLock(ctx, run)
	self.takeSpoolDropsWithLock(ctx, run)
	now := self.clock.Now()
	event := captured.Event
	state := run.state
	state.LastActivityMillis = now.UnixMilli()
	if state.Harness == "" {
		state.Harness = event.Harness
	}
	state.SessionId = event.SessionId
	if event.Cwd != "" {
		state.Cwd = event.Cwd
	}
	if event.TranscriptPath != "" {
		state.TranscriptPath = event.TranscriptPath
	}
	run.dirty = true
	reopened := state.Covered
	state.Covered = false
	if !slices.Contains(state.Sources, sidecar.RecordCoverageSourceHooks) {
		state.Sources = append(state.Sources, sidecar.RecordCoverageSourceHooks)
	}
	redactor, err := self.redactor(captured.Network)
	if err != nil {
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
		self.armIdleWithLock(run)
		return nil
	}
	if event.PermissionMode != "" && slices.Contains(self.settings.BypassPermissionModes, event.PermissionMode) {
		if !state.Bypass || state.PermissionMode != event.PermissionMode {
			self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapBypassMode)
		}
		state.Bypass = true
	}
	self.captureContextWithLock(ctx, run, redactor, event, captured.Payload)
	switch event.Kind {
	case HookEventPostToolUse:
		self.captureToolCallWithLock(ctx, run, redactor, event, captured.Payload)
	default:
		captured.EventLeaf = self.captureHookEventWithLock(ctx, run, redactor, event, captured.Payload)
	}
	if event.Kind == HookEventPermissionRequest {
		self.capturePermissionWithLock(ctx, run, event)
	}
	if event.Kind == HookEventUserPrompt {
		self.capturePromptWithLock(ctx, run, redactor, captured.Payload)
	}
	self.captureScanWithLock(ctx, run, redactor, event, captured.Payload)
	switch event.Kind {
	case HookEventStop, HookEventCompact, HookEventSessionEnd:
		self.tailTranscriptWithLock(ctx, run, redactor)
	}
	if self.lifecycle != nil && state.Started && event.Kind != HookEventSessionStart && event.Kind != HookEventSessionEnd {
		self.lifecycle.RunMoved(ctx, run.networkId, run.runId)
	}
	if event.Kind == HookEventSessionEnd {
		self.coverWithLock(ctx, run, redactor)
		return nil
	}
	if reopened && self.lifecycle != nil && state.Started {
		// a run ended by idling moved again: its next Coverage supersedes (RECORD.md's re-open row)
		self.lifecycle.RunMoved(ctx, run.networkId, run.runId)
	}
	self.armIdleWithLock(run)
	self.armTailWithLock(run)
	return nil
}

// The spool's drops since the last event, each a spool_drop gap.
func (self *Ingest) takeSpoolDropsWithLock(ctx context.Context, run *ingestRun) {
	spool, err := run.network.Spool()
	if err != nil {
		return
	}
	for i := spool.TakeDropCount(); 0 < i; i -= 1 {
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapSpoolDrop)
	}
}

// What the server hands the capture for one hook event, after its binding.
type HookCaptured struct {
	Network   McpNetwork
	NetworkId sidecar.Id
	// Zero while the event bound nothing: a Locked network, or an event naming no session.
	RunId sidecar.Id
	Event *HookEvent
	// As the harness wrote it, within Ingest.PayloadByteCount.
	Payload []byte
	// The network was Locked, so nothing bound.
	Locked bool
	// The leaf of the hook_event entry the capture sealed for the event, nil where it sealed none or the entry waits in
	// the spool: what a harness decision on the event cites (RECORD.md section 5.1; MCP-M3-10).
	EventLeaf []byte
}

// Events seen while the network was Locked, by harness and session, each a missed_event gap on the run once it binds.
func (self *Ingest) noteLockedEvent(captured *HookCaptured) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := runSessionKey{harness: captured.Event.Harness, sessionId: captured.Event.SessionId}
	self.lockedEvents[restoreLockedKey{networkId: captured.NetworkId, session: key}] += 1
}

// A Locked event's key.
type restoreLockedKey struct {
	networkId sidecar.Id
	session   runSessionKey
}

// Counts the run's events seen while Locked as missed_event gaps, once it binds.
func (self *Ingest) takeLockedGapsWithLock(ctx context.Context, run *ingestRun) {
	count := func() int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		key := restoreLockedKey{networkId: run.networkId, session: runSessionKey{harness: run.state.Harness, sessionId: run.state.SessionId}}
		count := self.lockedEvents[key]
		delete(self.lockedEvents, key)
		return count
	}()
	for i := 0; i < count; i += 1 {
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
	}
}

// The run card's inputs for a run this process ingests, nil for one it does not know.
func (self *Ingest) Capture(networkId sidecar.Id, runId sidecar.Id) *RunCapture {
	run, ok := func() (*ingestRun, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		run, ok := self.runs[restorePointKey{networkId: networkId, runId: runId}]
		return run, ok
	}()
	if !ok {
		return nil
	}
	run.runLock.Lock()
	defer run.runLock.Unlock()
	state := run.state
	counts := map[string]int{}
	for name, count := range state.ToolCounts {
		counts[name] = count
	}
	return &RunCapture{
		RunId:              runId,
		Harness:            state.Harness,
		AgentLabel:         state.AgentLabel,
		Model:              state.Model,
		Project:            state.Project,
		Branch:             state.Branch,
		Title:              state.Title,
		ToolCounts:         counts,
		TouchedPaths:       slices.Clone(state.TouchedPaths),
		Prompts:            state.Prompts,
		StartedMillis:      state.StartedMillis,
		LastActivityMillis: state.LastActivityMillis,
		EndedMillis:        state.EndedMillis,
	}
}

// The raw JSON value at name in a payload, as a string where it is one.
func ingestPayloadString(payload []byte, name string) string {
	return hookObjectString(json.RawMessage(payload), name)
}

// The text of a JSON value, as a string where it is one and as its JSON otherwise.
func ingestValueText(raw []byte) []byte {
	if len(raw) == 0 {
		return nil
	}
	text := ""
	if json.Unmarshal(raw, &text) == nil {
		return []byte(text)
	}
	return raw
}

// text cut to byteCount at a rune boundary, and whether it was cut.
func ingestCut(text []byte, byteCount int64) ([]byte, bool) {
	if int64(len(text)) <= byteCount {
		return text, false
	}
	cut := text[:byteCount]
	for 0 < len(cut) && cut[len(cut)-1]&0xC0 == 0x80 {
		cut = cut[:len(cut)-1]
	}
	return cut, true
}
