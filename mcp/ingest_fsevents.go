//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.18's v1 filesystem capture (MCP-M6-03; R-MCP-4, D-MCP-5, D-MCP-15): file events narrow a run's scan intervals,
// so attribution sees smaller windows, and each is recorded as a file_event entry, source observed (RECORD.md's row
// 51), its Coverage naming file_events among its sources.
//
// A worktree a run's restore point holds is watched through IngestArgs.FileWatch, the daemon's (cli's fsnotify), once
// however many runs work in it. Each change of a path there runs, for each live run on the worktree whose harness names
// its tool calls before they run (Claude Code's and Codex's PreToolUse) and that has none in flight, a scan of the
// run's point then and there. Such a scan's interval holds no edit hook of the run, since none has come since its
// last scan, so its changes are shell or foreign by §16.7's rows and never edit: only an edit hook's hashes make a
// change the run's edit. A run with a tool in flight takes no file-event scan, since the change may be that tool's,
// which its PostToolUse attributes; a Cursor run takes none, since Cursor names no call before it runs and its
// afterFileEdit comes after the write.
//
// A watch the daemon could not keep, past Ingest.FileEventDirectoryCount directories or one whose watcher reports
// lost events, is a coverage gap, missed_event, on the worktree's runs, which reads their next interval foreign. Off
// unless Ingest.FileEvents is set and the daemon gives a watch: M6's capture, off by default.

package mcp

import (
	"context"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// What a change was: FileEventBody's op (RECORD.md's file_event row), format values.
type IngestFileOp uint32

const (
	IngestFileCreate IngestFileOp = 1
	IngestFileWrite  IngestFileOp = 2
	IngestFileDelete IngestFileOp = 3
	IngestFileRename IngestFileOp = 4
)

// One change a watch reports: the path, relative to the worktree's root with / between segments, and what happened.
type IngestFileChange struct {
	Path string
	Op   IngestFileOp
}

// Where a worktree's watch reports: each change, and that it lost some.
type IngestFileWatchSink struct {
	Change func(change *IngestFileChange)
	Lost   func()
}

// Watches root, a worktree's top level, and every directory under it but .git, until stop; past directoryCount
// directories it fails. The daemon's is cli's, over fsnotify; a test's reports what the test says.
type IngestFileWatch func(root string, directoryCount int, sink *IngestFileWatchSink) (stop func(), err error)

// The harnesses that name a tool call before it runs, so a file event between their hooks is no call's of theirs.
var ingestFileEventHarnesses = []string{claudeHookHarness, codexHookHarness}

// One worktree's watch and the runs working in it.
type ingestRootWatch struct {
	stop func()
	runs []restorePointKey
}

// The file events' state: each watched worktree, by its root.
type ingestFileEvents struct {
	stateLock   sync.Mutex
	rootWatches map[string]*ingestRootWatch
}

// Starts watching the worktree run's point holds, where file events are on, and joins the run to it.
func (self *Ingest) watchRunRoot(ctx context.Context, run *ingestRun) {
	if self.fileWatch == nil || !self.settings.FileEvents || self.restore == nil {
		return
	}
	point, ok := self.restore.Point(run.networkId, run.runId)
	if !ok {
		return
	}
	root := point.Root()
	if root == "" {
		return
	}
	key := restorePointKey{networkId: run.networkId, runId: run.runId}
	watch, started := func() (*ingestRootWatch, bool) {
		self.fileEvents.stateLock.Lock()
		defer self.fileEvents.stateLock.Unlock()
		watch, ok := self.fileEvents.rootWatches[root]
		if ok {
			if !slices.Contains(watch.runs, key) {
				watch.runs = append(watch.runs, key)
			}
			return watch, false
		}
		watch = &ingestRootWatch{runs: []restorePointKey{key}}
		self.fileEvents.rootWatches[root] = watch
		return watch, true
	}()
	if !started {
		return
	}
	stop, err := self.fileWatch(root, self.settings.FileEventDirectoryCount, &IngestFileWatchSink{
		Change: func(change *IngestFileChange) { self.fileChanged(context.Background(), root, change) },
		Lost:   func() { self.fileEventsLost(context.Background(), root) },
	})
	if err != nil {
		self.log.Warningf("[ingest]a worktree is not watched: %s", err)
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
		return
	}
	self.fileEvents.stateLock.Lock()
	defer self.fileEvents.stateLock.Unlock()
	watch.stop = stop
}

// The live runs working in root.
func (self *Ingest) rootRuns(root string) []*ingestRun {
	keys := func() []restorePointKey {
		self.fileEvents.stateLock.Lock()
		defer self.fileEvents.stateLock.Unlock()
		watch, ok := self.fileEvents.rootWatches[root]
		if !ok {
			return nil
		}
		return slices.Clone(watch.runs)
	}()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	runs := []*ingestRun{}
	for _, key := range keys {
		if run, ok := self.runs[key]; ok {
			runs = append(runs, run)
		}
	}
	return runs
}

// One change in root: for each of its runs that names its calls before they run and has none in flight, a scan now,
// its changes captured as a hook's scan's are, and the file_event entry.
func (self *Ingest) fileChanged(ctx context.Context, root string, change *IngestFileChange) {
	if restoreHiddenPath(change.Path) {
		// the apply's own names
		return
	}
	for _, run := range self.rootRuns(root) {
		func() {
			run.runLock.Lock()
			defer run.runLock.Unlock()
			defer self.saveRunWithLock(run)
			if !slices.Contains(ingestFileEventHarnesses, run.state.Harness) || run.state.EndedMillis != 0 {
				return
			}
			if self.restore.ToolInFlight(run.networkId, run.runId) {
				return
			}
			redactor, err := self.redactor(run.network)
			if err != nil {
				self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
				return
			}
			scan, err := self.restore.Scan(ctx, run.networkId, run.runId)
			if err != nil {
				self.log.Warningf("[ingest]a file event's scan did not run: %s", err)
				self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
				return
			}
			self.captureScanResultWithLock(ctx, run, redactor, scan)
			body := &protocol.FileEventBody{Path: change.Path, Op: uint32(change.Op), Millis: self.clock.Now().UnixMilli()}
			for _, scanned := range scan.Changes {
				if scanned.Path == change.Path && scanned.After != nil {
					body.AfterSha256 = scanned.After.Sha256
				}
			}
			self.appendWithLock(ctx, run, &ingestEntry{
				kind:           sidecar.RecordKindFileEvent,
				source:         sidecar.RecordSourceObserved,
				body:           body,
				coverageSource: sidecar.RecordCoverageSourceFileEvents,
			})
		}()
	}
}

// A watch lost events: a missed_event gap on each of root's runs, which reads its next interval foreign.
func (self *Ingest) fileEventsLost(ctx context.Context, root string) {
	for _, run := range self.rootRuns(root) {
		self.gap(ctx, run.network, run.networkId, run.runId, sidecar.RecordCoverageGapMissedEvent)
	}
}

// Stops every watch, at the ingest's close.
func (self *Ingest) stopFileWatches() {
	watches := func() []*ingestRootWatch {
		self.fileEvents.stateLock.Lock()
		defer self.fileEvents.stateLock.Unlock()
		watches := []*ingestRootWatch{}
		for root, watch := range self.fileEvents.rootWatches {
			watches = append(watches, watch)
			delete(self.fileEvents.rootWatches, root)
		}
		return watches
	}()
	for _, watch := range watches {
		if watch.stop != nil {
			watch.stop()
		}
	}
}
