//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's Coverage (§16.8; RECORD.md sections 4.3 and 6.4; MCP.md's reading 8): at SessionEnd, or after
// Record.CoverageIdleTimeout with no event, the run's coverage entry names its harness, ur's version, the sources
// that fed it, every gap the run file counted where it occurred, and first_seq and last_seq, the writer's chain
// across the run's entries. The run file notes the entry (RunStore.Covered), which starts its retention, and the
// lifecycle's RunEnded fires. A later event re-opens the run, and its next coverage supersedes; idling never clears
// taint (D-MCP-16). M3's exit says coverage names every gap, so none is inferred here: the list is the run file's.

package mcp

import (
	"context"
	"slices"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Arms the idle coverage, CoverageIdleTimeout from now. The run's lock is held.
func (self *Ingest) armIdleWithLock(run *ingestRun) {
	if run.idleStop != nil {
		run.idleStop()
	}
	run.idleStop = self.clock.AfterFunc(self.record.CoverageIdleTimeout, func() {
		self.idleTick(run)
	})
}

// The idle coverage: nothing when an event came meanwhile, which re-armed it.
func (self *Ingest) idleTick(run *ingestRun) {
	ctx := context.Background()
	run.runLock.Lock()
	defer run.runLock.Unlock()
	defer self.saveRunWithLock(run)
	if run.state.Covered {
		return
	}
	now := self.clock.Now().UnixMilli()
	if now-run.state.LastActivityMillis < self.record.CoverageIdleTimeout.Milliseconds() {
		return
	}
	redactor, err := self.redactor(run.network)
	if err != nil {
		return
	}
	self.tailTranscriptWithLock(ctx, run, redactor)
	self.coverWithLock(ctx, run, redactor)
}

// Seals the run's coverage entry and ends the run. The run's lock is held.
func (self *Ingest) coverWithLock(ctx context.Context, run *ingestRun, redactor *sidecar.Redactor) {
	state := run.state
	if run.idleStop != nil {
		run.idleStop()
		run.idleStop = nil
	}
	if run.tailStop != nil {
		run.tailStop()
		run.tailStop = nil
	}
	if self.restore != nil {
		if _, ok := self.restore.Point(run.networkId, run.runId); ok {
			// the last changes, which no hook followed
			if scan, err := self.restore.Scan(ctx, run.networkId, run.runId); err == nil && scan != nil {
				self.captureScanResultWithLock(ctx, run, redactor, scan)
			}
		}
	}
	gaps := []string{}
	if runs, err := run.network.Runs(); err == nil {
		if file, err := runs.Get(run.runId); err == nil {
			gaps = slices.Clone(file.Gaps)
		}
	}
	for i, gap := range gaps {
		if _, _, ok := sidecar.RecordCoverageGapParse(gap); !ok {
			// a code this build does not name: kept out, since the body refuses it
			gaps[i] = ""
		}
	}
	gaps = slices.DeleteFunc(gaps, func(gap string) bool { return gap == "" })
	sources := slices.Clone(state.Sources)
	slices.Sort(sources)
	runId := run.runId
	now := self.clock.Now().UnixMilli()
	state.EndedMillis = now
	state.Covered = true
	run.dirty = true
	// the range the entry names, before the entry itself extends it
	firstSeq, lastSeq := state.FirstSeq, state.LastSeq
	self.appendWithLock(ctx, run, &ingestEntry{
		kind:   sidecar.RecordKindCoverage,
		source: sidecar.RecordSourceObserved,
		body: &protocol.Coverage{
			RunId:    runId[:],
			Harness:  state.Harness,
			Version:  self.server.settings.Version,
			Sources:  sources,
			Gaps:     gaps,
			FirstSeq: firstSeq,
			LastSeq:  lastSeq,
		},
	})
	if runs, err := run.network.Runs(); err == nil {
		if err := runs.Covered(ctx, run.runId, firstSeq, lastSeq, now); err != nil {
			self.log.Warningf("[ingest]a run's coverage was not noted: %s", err)
		}
	}
	if self.lifecycle != nil && state.Started {
		self.lifecycle.RunEnded(ctx, run.networkId, run.runId)
	}
}

// Stops every run's timers without covering it: a test's stand-in for a process ending, after which the state on
// disk is what the next start reads.
func (self *Ingest) detach() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, run := range self.runs {
		run.runLock.Lock()
		if run.idleStop != nil {
			run.idleStop()
			run.idleStop = nil
		}
		if run.tailStop != nil {
			run.tailStop()
			run.tailStop = nil
		}
		run.runLock.Unlock()
	}
}

// Ends every live run now: what the daemon calls at shutdown, so each run's coverage is sealed rather than left to
// the next start's downtime gap.
func (self *Ingest) Close(ctx context.Context) {
	runs := func() []*ingestRun {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		runs := []*ingestRun{}
		for _, run := range self.runs {
			runs = append(runs, run)
		}
		return runs
	}()
	for _, run := range runs {
		func() {
			run.runLock.Lock()
			defer run.runLock.Unlock()
			defer self.saveRunWithLock(run)
			if run.state.Covered {
				return
			}
			redactor, err := self.redactor(run.network)
			if err != nil {
				return
			}
			self.tailTranscriptWithLock(ctx, run, redactor)
			self.coverWithLock(ctx, run, redactor)
		}()
	}
}
