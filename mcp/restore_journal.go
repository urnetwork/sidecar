//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's apply journal and restart row (D-MCP-8, RV4, FI-8): each apply keeps an append-only sealed log in its point,
// apply/<preview_id hex>, file class restore, every record fsynced before the step it names is taken (§5.9's
// SidecarStoreLog):
//
//	begin    the preview applied, whole, so the journal alone recovers and replays the apply
//	stage    a path's two hidden names, before the target is written under the first and probed to the second;
//	         each stage record starts the path's newest attempt
//	staged   how the probe found the volume renames: rename or link
//	aside    the hidden name p is about to be moved to
//	install  the staged name is about to be renamed to p
//	back     the moved bytes are about to go back to p
//	copy     a copy is about to be renamed beside p
//	remove   moved-aside bytes about to be removed, the preview's current ones at end
//	reset    recovery put the path back untouched: its attempt is over, and the next call takes it again
//	done     a path's outcome, and moved bytes awaiting end's rule
//	ended    a path's outcome after end's rule
//	end      the apply is over: a retry answers its recorded result and moves nothing
//
// The restart row, which a point's load and an apply that finds its journal open both run: a path journaled aside but
// neither installed nor back goes back the same way, or, p having reappeared, becomes recreated; a path whose install
// took finishes as restored; a finished path's moved-aside bytes take end's rule; every other staged name is removed.
// What a record could not say, whether a step it names was taken, is read from the disk: an aside name that exists
// was moved, a staged name that is gone, and that no copy record took, was installed. Nothing is removed that is not the apply's own staged copy of
// the target or the preview's current bytes. A path recovery puts back is untouched, so the apply's next call takes it
// again from its stage, and an apply never ends at a restart, only when a call finishes it.

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/urnetwork/sidecar"
)

// The journal's name and its records' operations, format values.
const (
	restoreJournalPrefix  = "apply/"
	restoreJournalBegin   = "begin"
	restoreJournalStage   = "stage"
	restoreJournalStaged  = "staged"
	restoreJournalAside   = "aside"
	restoreJournalInstall = "install"
	restoreJournalBack    = "back"
	restoreJournalCopy    = "copy"
	restoreJournalRemove  = "remove"
	restoreJournalReset   = "reset"
	restoreJournalDone    = "done"
	restoreJournalEnded   = "ended"
	restoreJournalEnd     = "end"
)

// One record of an apply's journal.
type restoreJournalRecord struct {
	Op    string `json:"op"`
	Index int    `json:"index,omitempty"`
	// The hidden names the step takes: stage's two, staged's one, aside's one, remove's one; done's moved bytes
	// awaiting end's rule.
	Names  []string `json:"names,omitempty"`
	Method string   `json:"method,omitempty"`
	// A copy's hidden name and the name it takes beside p.
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
	// done's and ended's outcome and copies.
	Result string   `json:"result,omitempty"`
	Copies []string `json:"copies,omitempty"`
	// begin's preview.
	Plan *RestorePlan `json:"plan,omitempty"`
}

// One path's steps as the journal holds them: its newest attempt's, and every staged name any attempt journaled.
type restoreJournalPath struct {
	stagedNames []string
	// the newest attempt's: whether one is in flight, staged and not yet reset
	inFlight   bool
	method     string
	aside      string
	installing bool
	// the hidden names a copy record took beside p
	copiedNames map[string]bool
	done        *restoreJournalRecord
	ended       *restoreJournalRecord
}

// The newest attempt's staged name: the probe's second, once staged named the method.
func (self *restoreJournalPath) staged() string {
	if self.method == "" || len(self.stagedNames) == 0 {
		return ""
	}
	return self.stagedNames[len(self.stagedNames)-1]
}

// One apply's journal, read back. Not safe for concurrent use: the worktree's apply lock is held across it.
type restoreJournal struct {
	log       sidecar.SidecarStoreLog
	plan      *RestorePlan
	paths     map[int]*restoreJournalPath
	beginSeen bool
	endSeen   bool
}

// The journal's name in the point.
func restoreJournalName(previewId []byte) string {
	return restoreJournalPrefix + hex.EncodeToString(previewId)
}

// The journal of the apply of previewId, read whole: empty for one never begun. A journal whose begin names another
// preview, or that does not read, is ErrSidecarStoreFailed.
func (self *RestorePoint) openJournal(previewId []byte) (*restoreJournal, error) {
	if len(previewId) != sha256.Size {
		return nil, ErrRestorePreviewUnknown
	}
	log, err := sidecar.OpenSidecarStoreLog(self.store, restoreJournalName(previewId))
	if err != nil {
		return nil, err
	}
	journal := &restoreJournal{log: log, paths: map[int]*restoreJournalPath{}}
	err = log.Read(func(index uint64, encoded []byte) error {
		record := &restoreJournalRecord{}
		if err := json.Unmarshal(encoded, record); err != nil {
			return fmt.Errorf("%w: a restore journal record that does not parse", sidecar.ErrSidecarStoreFailed)
		}
		journal.take(record)
		return nil
	})
	if errors.Is(err, sidecar.ErrSidecarStoreAbsent) {
		return journal, nil
	}
	if err != nil {
		return nil, err
	}
	if journal.beginSeen {
		if journal.plan == nil {
			return nil, fmt.Errorf("%w: a restore journal with no preview", sidecar.ErrSidecarStoreFailed)
		}
		if err := checkRestorePlan(journal.plan, self.runId, previewId); err != nil {
			return nil, err
		}
	}
	return journal, nil
}

// Whether the apply began.
func (self *restoreJournal) begun() bool {
	return self.beginSeen
}

// Whether the apply is over.
func (self *restoreJournal) ended() bool {
	return self.endSeen
}

// A path's steps, made empty on first use.
func (self *restoreJournal) path(index int) *restoreJournalPath {
	state, ok := self.paths[index]
	if !ok {
		state = &restoreJournalPath{}
		self.paths[index] = state
	}
	return state
}

// Folds one record into the journal's state.
func (self *restoreJournal) take(record *restoreJournalRecord) {
	switch record.Op {
	case restoreJournalBegin:
		self.beginSeen = true
		self.plan = record.Plan
		return
	case restoreJournalEnd:
		self.endSeen = true
		return
	}
	state := self.path(record.Index)
	switch record.Op {
	case restoreJournalStage, restoreJournalReset:
		state.stagedNames = append(state.stagedNames, record.Names...)
		state.inFlight = record.Op == restoreJournalStage
		state.method = ""
		state.aside = ""
		state.installing = false
		state.copiedNames = nil
	case restoreJournalCopy:
		if state.copiedNames == nil {
			state.copiedNames = map[string]bool{}
		}
		state.copiedNames[record.From] = true
	case restoreJournalStaged:
		state.method = record.Method
	case restoreJournalAside:
		if 0 < len(record.Names) {
			state.aside = record.Names[0]
		}
	case restoreJournalInstall:
		state.installing = true
	case restoreJournalDone:
		state.done = record
	case restoreJournalEnded:
		state.ended = record
	}
}

// Appends record, fsynced, before the step it names: on an error the step is not taken.
func (self *restoreJournal) append(record *restoreJournalRecord) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := self.log.Append(encoded); err != nil {
		return err
	}
	self.take(record)
	return nil
}

// The apply's result as the journal holds it: each path's ended outcome, else its done one, else error for a path
// never finished.
func (self *restoreJournal) result(runId sidecar.Id) *RestoreApplyResult {
	result := &RestoreApplyResult{RunId: runId, Paths: []*RestorePathResult{}}
	if self.plan == nil {
		return result
	}
	result.PreviewId = append([]byte{}, self.plan.PreviewId...)
	for index, entry := range self.plan.Entries {
		state := self.path(index)
		record := state.ended
		if record == nil {
			record = state.done
		}
		if record == nil {
			result.Paths = append(result.Paths, &RestorePathResult{Path: entry.Path, Result: RestoreConflictError})
			continue
		}
		result.Paths = append(result.Paths, &RestorePathResult{Path: entry.Path, Result: record.Result, Copies: append([]string{}, record.Copies...)})
	}
	return result
}

// Where an apply of previewId stands: whether it began and ended, and its result once ended. What the restore
// effect's Lookup reads (MCP-M3-22).
func (self *RestorePoint) ApplyState(previewId []byte) (begun bool, ended bool, result *RestoreApplyResult, err error) {
	unlock := self.points.lockApply(self.Root())
	defer unlock()
	journal, err := self.openJournal(previewId)
	if err != nil {
		return false, false, nil, err
	}
	if journal.ended() {
		result = journal.result(self.runId)
		result.Replayed = true
	}
	return journal.begun(), journal.ended(), result, nil
}

// The restart row over the apply's journal, before the apply goes on: each path journaled but not done is put back or
// finished as the disk shows. See the file's header.
func (self *restoreApply) recover() error {
	for index, entry := range self.plan.Entries {
		state := self.journal.path(index)
		if state.done != nil || !state.inFlight {
			continue
		}
		if err := self.recoverPath(index, entry, state); err != nil {
			return err
		}
	}
	return nil
}

// One path the journal holds in flight.
func (self *restoreApply) recoverPath(index int, entry *RestorePreviewEntry, state *restoreJournalPath) error {
	run := &restorePathRun{index: index, entry: entry, method: state.method}
	defer run.close()
	if conflict := self.resolve(run, false); conflict != "" {
		if state.aside == "" {
			// nothing of the path moved: it is taken again
			return nil
		}
		// moved bytes in a directory that cannot be reached now stay where they are, never removed
		return self.journal.append(&restoreJournalRecord{Op: restoreJournalDone, Index: index, Result: RestoreConflictError})
	}
	if state.installing && entry.Target.Kind != RestoreKindAbsent && state.staged() != "" {
		staged := state.staged()
		pInfo, pErr := run.parent.Lstat(run.name)
		stagedInfo, stagedErr := run.parent.Lstat(staged)
		installed := false
		switch {
		case pErr == nil && errors.Is(stagedErr, fs.ErrNotExist) && !state.copiedNames[staged]:
			// the rename took the staged name to p
			installed = true
		case pErr == nil && stagedErr == nil && os.SameFile(pInfo, stagedInfo):
			// linked to p, the staged name not yet removed
			installed = run.parent.Remove(staged) == nil
		}
		if installed {
			if state.aside != "" {
				if _, err := run.parent.Lstat(state.aside); err == nil {
					run.aside = state.aside
					run.pending = true
				}
			}
			self.removeStaged(run, state)
			return self.finish(run, RestoreResultRestored)
		}
	}
	if state.aside != "" {
		if _, err := run.parent.Lstat(state.aside); err == nil {
			run.aside = state.aside
			result, err := self.back(run, "")
			if err != nil {
				return err
			}
			if result != "" {
				// p reappeared before the moved bytes could go back
				self.removeStaged(run, state)
				return self.finish(run, result)
			}
		}
	}
	// nothing of the path is moved now: its staged names go, and the apply takes it again
	self.removeStaged(run, state)
	return self.journal.append(&restoreJournalRecord{Op: restoreJournalReset, Index: index})
}

// Removes each staged name the path's attempts journaled that is still there: the apply's own copies of the target,
// or empty probes.
func (self *restoreApply) removeStaged(run *restorePathRun, state *restoreJournalPath) {
	for _, name := range state.stagedNames {
		if !strings.HasPrefix(name, restoreHiddenPrefix) {
			continue
		}
		if _, err := run.parent.Lstat(name); err == nil {
			run.parent.Remove(name)
		}
	}
}

// The restart row over every apply of this point whose journal is open: each is recovered and its finished paths take
// end's rule, the journal left open for the call that finishes it.
func (self *RestorePoint) Recover(ctx context.Context) error {
	entries, err := self.store.List(restoreJournalPrefix)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		previewId, err := hex.DecodeString(strings.TrimPrefix(entry.Name, restoreJournalPrefix))
		if err != nil || strings.Contains(strings.TrimPrefix(entry.Name, restoreJournalPrefix), "/") {
			continue
		}
		if err := self.recoverJournal(previewId); err != nil {
			return err
		}
	}
	return nil
}

// One open journal's recovery, under the worktree's apply lock.
func (self *RestorePoint) recoverJournal(previewId []byte) error {
	unlock := self.points.lockApply(self.Root())
	defer unlock()
	journal, err := self.openJournal(previewId)
	if err != nil {
		return err
	}
	if !journal.begun() || journal.ended() {
		return nil
	}
	apply, err := self.newApply(journal.plan, journal)
	if err != nil {
		return err
	}
	defer apply.close()
	if err := apply.recover(); err != nil {
		return err
	}
	return apply.end()
}

// Recovers every point of the network an earlier process left an apply open in, once per network in this process,
// before any of its points is used: a point this process holds already was recovered at its load.
func (self *RestorePoints) recoverNetwork(ctx context.Context, network McpNetwork, networkId sidecar.Id) error {
	self.recoverLock.Lock()
	defer self.recoverLock.Unlock()
	if self.recoveredNetworkIds[networkId] {
		return nil
	}
	store, err := network.LocalStore().Directory(restoreDirectoryName, restoreClass)
	if err != nil {
		return err
	}
	entries, err := store.List("")
	if err != nil {
		return err
	}
	runIds := []sidecar.Id{}
	seen := map[sidecar.Id]bool{}
	for _, entry := range entries {
		runText, rest, found := strings.Cut(entry.Name, "/")
		if !found || !strings.HasPrefix(rest, restoreJournalPrefix) {
			continue
		}
		runId, err := sidecar.ParseId(runText)
		if err != nil || seen[runId] {
			continue
		}
		seen[runId] = true
		runIds = append(runIds, runId)
	}
	for _, runId := range runIds {
		if _, ok := self.Point(networkId, runId); ok {
			continue
		}
		if _, err := self.loadPoint(ctx, network, networkId, runId); err != nil {
			return err
		}
	}
	self.recoveredNetworkIds[networkId] = true
	return nil
}
