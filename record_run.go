// §16.6's run files and write-ahead taint (D-MCP-16, TS1, I-9): runs/<run_id> in the network's local store, file
// class run, one sealed JSON file per run, replaced whole through SidecarStore's atomic replace, which fsyncs the
// file and its directory before Commit returns.
//
// Taint is write-ahead: Taint sets the run's flag in memory first, so a gate racing it reads tainted, then fsyncs
// tainted = true and returns only after that; if the write fails it answers the error, so its caller fails the
// call that would have returned untrusted data. Tainted answers true for a run tainted in memory, a run whose file
// says so, and a run whose file is missing, unreadable or Failed, so a restart cannot reopen egress and an id this
// store never saw reads tainted. tainted never returns to false: every rewrite keeps it, and a Create over an
// existing file refuses.
//
// A new run starts untainted unless its caller says otherwise. When a run is new, and when it inherits another's
// taint (plan-MCP-taint-new-session), is MCP-M3-15's to decide. A nil run id means no harness at all, an app or a typed
// ur command, which this store never sees. record.taint.before and record.taint.after sit around a taint's fsync,
// outside the run's lock, so a held barrier stalls no other run (testhook.go).
//
// Marks (DESIGN-COMPUTE §7.8's private, §25.10's limited_use; HARN-M11-02, CONTRACTS C-32) are kept the same way: Mark
// sets the mark in memory first, then fsyncs it into the run's file before it returns, so the data that gave it leaves
// the daemon only after (§8.9's rule); a mark never clears, every rewrite keeps it, and Marks answers an error for a run
// whose file is missing or unreadable, which its readers take as every mark (the router refuses the call, a container
// tool refuses), so a restart cannot lose one. One store holds them for INFER's router, GW's run handle, CONN's
// limited_use and the Harness's private mark. record.mark.before and record.mark.after sit around a mark's fsync.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// §5.9's tree and file class for run files.
const (
	runDirectoryName = "runs"
	runClass         = "run"
)

var (
	// Create of a run whose file exists: the caller reads that file instead.
	ErrRunExists = errors.New("run exists")
	// A change to a run with no file.
	ErrRunUnknown = errors.New("run unknown")
	// A rewrite that would clear a run's taint, which only a bug asks for.
	errRunUntaint = errors.New("a run's taint never clears")
	// A rewrite that would clear one of a run's marks, which only a bug asks for.
	errRunUnmark = errors.New("a run's marks never clear")
	// The run's marks do not read: its file is missing or unreadable, so a reader takes it as carrying every mark.
	ErrRunMarksUnread = errors.New("the run's marks do not read")
)

// Why a run was tainted (§16.6's taint row). Callers may add codes; none carries a path or text.
type RunTaintReason string

const (
	// The run read untrusted data through ur: outside mail, files from outside or a tainted run, flagged entries,
	// untrusted search hits' text, the directory's prose.
	RunTaintUntrustedData RunTaintReason = "untrusted_data"
	// A hook reported a web tool (WebFetch, WebSearch, curl).
	RunTaintWebTool RunTaintReason = "web_tool"
	// Hook coverage lapsed: no hook event bound the session, or none came within 60 s of a tool call.
	RunTaintCoverageLapse RunTaintReason = "coverage_lapse"
	// A harness config hash changed.
	RunTaintConfigChanged RunTaintReason = "config_changed"
	// A run of the same harness process was tainted (plan-MCP-taint-new-session).
	RunTaintInherited RunTaintReason = "inherited"
	// The run's file was missing when its session bound again (RECORD.md section 4.3's binding row).
	RunTaintFileMissing RunTaintReason = "run_file_missing"
)

// §16.6's run file, with the harness process's identity (MCP.md's reading 6). Local only: none of it is shown or
// leaves the device.
type RunFile struct {
	RunId   Id     `json:"run_id"`
	Harness string `json:"harness"`
	// Every session id the run bound, each once.
	SessionIds []string `json:"session_ids"`
	Worktree   string   `json:"worktree"`
	Tainted    bool     `json:"tainted"`
	// Each reason once, in the order first given.
	TaintReasons []RunTaintReason `json:"taint_reasons"`
	// The run's marks (DESIGN-COMPUTE §7.8, §25.10), each once, in the order first given: never cleared.
	Marks []string `json:"marks,omitempty"`
	// RECORD.md section 6.4's codes, each "code" or "code:count".
	Gaps     []string `json:"gaps"`
	FirstSeq uint64   `json:"first_seq"`
	LastSeq  uint64   `json:"last_seq"`
	// The harness process, for the ancestry rules: its pid and start time. Zero when unknown.
	ProcessId          int   `json:"process_id"`
	ProcessStartMillis int64 `json:"process_start_millis"`
	// When the run's newest Coverage entry was sealed, in Unix milliseconds; 0 until then. Retention runs from here,
	// and a later Coverage starts it again (MCP.md's reading 8).
	CoverageMillis int64 `json:"coverage_millis"`
}

// A deep copy.
func (self *RunFile) clone() *RunFile {
	cloned := *self
	cloned.SessionIds = slices.Clone(self.SessionIds)
	cloned.TaintReasons = slices.Clone(self.TaintReasons)
	cloned.Marks = slices.Clone(self.Marks)
	cloned.Gaps = slices.Clone(self.Gaps)
	return &cloned
}

// gaps with code counted once more: "code" for one, "code:n" for n.
func addRunGap(gaps []string, code string) []string {
	for i, gap := range gaps {
		gapCode, countText, counted := strings.Cut(gap, ":")
		if gapCode != code {
			continue
		}
		count := 1
		if counted {
			if parsed, err := strconv.Atoi(countText); err == nil && 0 < parsed {
				count = parsed
			}
		}
		gaps[i] = fmt.Sprintf("%s:%d", code, count+1)
		return gaps
	}
	return append(gaps, code)
}

// The network's run files and their taint. One per Sidecar (Sidecar.Runs), so a taint set in memory is seen by every
// reader in the process. Safe for concurrent use.
type RunStore struct {
	// runs/, class run
	store    SidecarStore
	settings *SidecarMcpSettings
	clock    Clock

	stateLock sync.Mutex
	// runs tainted in this process, with their reasons, set before their file is written: never cleared
	taintedRunIdReasons map[Id][]RunTaintReason
	// runs marked in this process, with their marks, set before their file is written: never cleared
	markedRunIdMarks map[Id][]string
	// one rewrite of a run's file at a time
	runIdLocks map[Id]*sync.Mutex
}

// A run store over the network's local store (Sidecar.LocalStore).
func NewRunStore(localStore SidecarStore, settings *SidecarMcpSettings, clock Clock) (*RunStore, error) {
	store, err := localStore.Directory(runDirectoryName, runClass)
	if err != nil {
		return nil, err
	}
	return &RunStore{
		store:               store,
		settings:            settings,
		clock:               clockOrReal(clock),
		taintedRunIdReasons: map[Id][]RunTaintReason{},
		markedRunIdMarks:    map[Id][]string{},
		runIdLocks:          map[Id]*sync.Mutex{},
	}, nil
}

// The file's name: the run id, as §5.9's tree names ids.
func runFileName(runId Id) string {
	return runId.String()
}

// runId's rewrite lock.
func (self *RunStore) runLock(runId Id) *sync.Mutex {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lock, ok := self.runIdLocks[runId]
	if !ok {
		lock = &sync.Mutex{}
		self.runIdLocks[runId] = lock
	}
	return lock
}

// Whether this process tainted runId, and why.
func (self *RunStore) taintedInMemory(runId Id) (bool, []RunTaintReason) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reasons, tainted := self.taintedRunIdReasons[runId]
	return tainted, slices.Clone(reasons)
}

// Marks runId tainted in memory, for good, with reasons each once.
func (self *RunStore) markTainted(runId Id, reasons ...RunTaintReason) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kept := self.taintedRunIdReasons[runId]
	if kept == nil {
		kept = []RunTaintReason{}
	}
	for _, reason := range reasons {
		if !slices.Contains(kept, reason) {
			kept = append(kept, reason)
		}
	}
	self.taintedRunIdReasons[runId] = kept
}

// The marks this process gave runId.
func (self *RunStore) marksInMemory(runId Id) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.markedRunIdMarks[runId])
}

// Marks runId in memory, for good, with marks each once.
func (self *RunStore) markInMemory(runId Id, marks ...string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kept := self.markedRunIdMarks[runId]
	if kept == nil {
		kept = []string{}
	}
	for _, mark := range marks {
		if !slices.Contains(kept, mark) {
			kept = append(kept, mark)
		}
	}
	self.markedRunIdMarks[runId] = kept
}

// Writes into run the marks memory holds for it, which a failed write left out of the file.
func (self *RunStore) applyMemoryMarks(run *RunFile) {
	for _, mark := range self.marksInMemory(run.RunId) {
		if !slices.Contains(run.Marks, mark) {
			run.Marks = append(run.Marks, mark)
		}
	}
}

// Writes into run the taint memory holds for it, which a failed write left out of the file.
func (self *RunStore) applyMemoryTaint(run *RunFile) {
	tainted, reasons := self.taintedInMemory(run.RunId)
	if !tainted {
		return
	}
	run.Tainted = true
	for _, reason := range reasons {
		if !slices.Contains(run.TaintReasons, reason) {
			run.TaintReasons = append(run.TaintReasons, reason)
		}
	}
}

// The run's file as stored. ErrSidecarStoreAbsent when there is none.
func (self *RunStore) Get(runId Id) (*RunFile, error) {
	reader, err := self.store.Open(runFileName(runId))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	encoded, err := io.ReadAll(io.LimitReader(reader, int64(self.settings.RunFileByteCount)+1))
	if err != nil {
		return nil, err
	}
	if self.settings.RunFileByteCount < len(encoded) {
		return nil, fmt.Errorf("%w: a run file over its bound", ErrSidecarStoreFailed)
	}
	run := &RunFile{}
	if err := json.Unmarshal(encoded, run); err != nil || run.RunId != runId {
		return nil, fmt.Errorf("%w: a run file that does not decode", ErrSidecarStoreFailed)
	}
	return run, nil
}

// Writes run whole, durable when this returns: the file and its directory fsynced by Commit.
func (self *RunStore) write(run *RunFile) error {
	encoded, err := json.Marshal(run)
	if err != nil {
		return err
	}
	if self.settings.RunFileByteCount < len(encoded) {
		return fmt.Errorf("%w: a run file over its bound", ErrSidecarStoreFailed)
	}
	writer, err := self.store.Create(runFileName(run.RunId))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	return writer.Commit()
}

// Records a new run. Its file must not exist: a run tainted, or created, before keeps its file, and the caller reads
// it. A run this process tainted before its file existed starts tainted.
func (self *RunStore) Create(ctx context.Context, run *RunFile) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if run.RunId == (Id{}) {
		return errors.New("a run needs an id")
	}
	lock := self.runLock(run.RunId)
	lock.Lock()
	defer lock.Unlock()
	_, err := self.Get(run.RunId)
	if err == nil {
		return ErrRunExists
	}
	if !errors.Is(err, ErrSidecarStoreAbsent) {
		return err
	}
	created := run.clone()
	self.applyMemoryTaint(created)
	if created.Tainted {
		self.markTainted(run.RunId, created.TaintReasons...)
	}
	self.applyMemoryMarks(created)
	if 0 < len(created.Marks) {
		self.markInMemory(run.RunId, created.Marks...)
	}
	return self.write(created)
}

// Rewrites runId's file by edit, which must keep its taint, and writes in any taint memory holds that the file
// lacks. ErrRunUnknown when it has no file.
func (self *RunStore) update(ctx context.Context, runId Id, edit func(run *RunFile)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	lock := self.runLock(runId)
	lock.Lock()
	defer lock.Unlock()
	run, err := self.Get(runId)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return ErrRunUnknown
	}
	if err != nil {
		return err
	}
	edited := run.clone()
	edit(edited)
	if run.Tainted && !edited.Tainted {
		return errRunUntaint
	}
	for _, mark := range run.Marks {
		if !slices.Contains(edited.Marks, mark) {
			return errRunUnmark
		}
	}
	self.applyMemoryTaint(edited)
	self.applyMemoryMarks(edited)
	return self.write(edited)
}

// Adds a session the run bound, once.
func (self *RunStore) AddSession(ctx context.Context, runId Id, sessionId string) error {
	return self.update(ctx, runId, func(run *RunFile) {
		if !slices.Contains(run.SessionIds, sessionId) {
			run.SessionIds = append(run.SessionIds, sessionId)
		}
	})
}

// Counts one more of a coverage gap code (RECORD.md section 6.4).
func (self *RunStore) AddGap(ctx context.Context, runId Id, code string) error {
	return self.update(ctx, runId, func(run *RunFile) {
		run.Gaps = addRunGap(run.Gaps, code)
	})
}

// Notes the run's newest Coverage entry, sealed at millis over the chain from firstSeq to lastSeq: retention runs
// from here, and a later one starts it again.
func (self *RunStore) Covered(ctx context.Context, runId Id, firstSeq uint64, lastSeq uint64, millis int64) error {
	return self.update(ctx, runId, func(run *RunFile) {
		run.FirstSeq = firstSeq
		run.LastSeq = lastSeq
		run.CoverageMillis = millis
	})
}

// Taints the run for good, write-ahead (D-MCP-16): the flag in memory first, then tainted = true and reason fsynced
// before this returns. An error means the file may not say so, and the caller fails the call that taints, so no
// untrusted data leaves; the run reads tainted here all the same. A run with no file gets one, tainted. A file that
// already holds the taint and the reason is not written again.
func (self *RunStore) Taint(ctx context.Context, runId Id, reason RunTaintReason) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if runId == (Id{}) {
		return errors.New("a run needs an id")
	}
	self.markTainted(runId, reason)
	key := runId.String()
	testHookBarrier("record.taint.before", key)
	err := func() error {
		lock := self.runLock(runId)
		lock.Lock()
		defer lock.Unlock()
		run, err := self.Get(runId)
		if errors.Is(err, ErrSidecarStoreAbsent) {
			run = &RunFile{RunId: runId}
		} else if err != nil {
			return err
		}
		if run.Tainted && slices.Contains(run.TaintReasons, reason) {
			return nil
		}
		tainted := run.clone()
		self.applyMemoryTaint(tainted)
		self.applyMemoryMarks(tainted)
		return self.write(tainted)
	}()
	testHookBarrier("record.taint.after", key)
	return err
}

// Whether the run is tainted: true when this process tainted it, when its file says so, and when its file is
// missing, unreadable or Failed, an id this store never saw included. Fails closed by construction.
func (self *RunStore) Tainted(runId Id) bool {
	if tainted, _ := self.taintedInMemory(runId); tainted {
		return true
	}
	run, err := self.Get(runId)
	if err != nil {
		return true
	}
	if run.Tainted {
		self.markTainted(runId, run.TaintReasons...)
		return true
	}
	return false
}

// Why the run is tainted, each reason once: those this process gave it and those its file holds. Empty for a run that
// is not tainted, and for one that reads tainted only because its file is missing or unreadable.
func (self *RunStore) TaintReasons(runId Id) []RunTaintReason {
	_, reasons := self.taintedInMemory(runId)
	run, err := self.Get(runId)
	if err != nil {
		return reasons
	}
	for _, reason := range run.TaintReasons {
		if !slices.Contains(reasons, reason) {
			reasons = append(reasons, reason)
		}
	}
	return reasons
}

// Marks the run for good, write-ahead (§8.9's rule, as Taint is): the mark in memory first, then fsynced into the
// run's file before this returns, so the caller lets the data that gave it leave only after. An error means the file
// may not say so, and the caller fails the call that marks; the run reads marked here all the same. A run with no
// file answers ErrRunUnknown, since writing one would read the run untainted. A file that already holds the mark is not
// written again.
func (self *RunStore) Mark(ctx context.Context, runId Id, mark string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if runId == (Id{}) || mark == "" {
		return errors.New("a mark needs a run and a name")
	}
	self.markInMemory(runId, mark)
	key := runId.String()
	testHookBarrier("record.mark.before", key)
	err := func() error {
		lock := self.runLock(runId)
		lock.Lock()
		defer lock.Unlock()
		run, err := self.Get(runId)
		if errors.Is(err, ErrSidecarStoreAbsent) {
			return ErrRunUnknown
		} else if err != nil {
			return err
		}
		if slices.Contains(run.Marks, mark) {
			return nil
		}
		marked := run.clone()
		self.applyMemoryTaint(marked)
		self.applyMemoryMarks(marked)
		return self.write(marked)
	}()
	testHookBarrier("record.mark.after", key)
	return err
}

// The run's marks: those this process gave it and those its file holds, each once. ErrRunMarksUnread, with the marks
// memory holds, where its file is missing or unreadable, an id this store never saw included: a reader takes that as
// every mark, so fails closed.
func (self *RunStore) Marks(runId Id) ([]string, error) {
	marks := self.marksInMemory(runId)
	run, err := self.Get(runId)
	if err != nil {
		return marks, fmt.Errorf("%w: %w", ErrRunMarksUnread, err)
	}
	for _, mark := range run.Marks {
		if !slices.Contains(marks, mark) {
			marks = append(marks, mark)
		}
	}
	if 0 < len(run.Marks) {
		self.markInMemory(runId, run.Marks...)
	}
	return marks, nil
}

// Removes each run file RunFileRetention past its newest Coverage (§16.6's retention row). A run with no Coverage yet,
// or a file that does not read, is kept. A removed run reads tainted from then on. Answers how many went.
func (self *RunStore) Sweep(ctx context.Context) (int, error) {
	entries, err := self.store.List("")
	if err != nil {
		return 0, err
	}
	now := self.clock.Now()
	removedCount := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return removedCount, err
		}
		runId, err := ParseId(entry.Name)
		if err != nil || runFileName(runId) != entry.Name {
			continue
		}
		removed, err := func() (bool, error) {
			lock := self.runLock(runId)
			lock.Lock()
			defer lock.Unlock()
			run, err := self.Get(runId)
			if err != nil || run.CoverageMillis == 0 {
				return false, nil
			}
			if now.Before(time.UnixMilli(run.CoverageMillis).Add(self.settings.RunFileRetention)) {
				return false, nil
			}
			return true, self.store.Remove(runFileName(runId))
		}()
		if err != nil {
			return removedCount, err
		}
		if removed {
			removedCount += 1
		}
	}
	return removedCount, nil
}

// The network's run store. One per Sidecar, so a taint set in memory is every reader's. ErrSidecarStoreLocked before
// enrollment.
func (self *Sidecar) Runs() (*RunStore, error) {
	networkId := self.knownNetworkId()
	if self.instance == nil || networkId == nil {
		return nil, ErrSidecarStoreLocked
	}
	self.records.stateLock.Lock()
	defer self.records.stateLock.Unlock()
	self.records.forNetworkWithLock(*networkId)
	if self.records.runs == nil {
		runs, err := NewRunStore(self.LocalStore(), self.settings.Mcp, self.settings.ClockOrReal())
		if err != nil {
			return nil, err
		}
		self.records.runs = runs
	}
	return self.records.runs, nil
}

// Whether a run is tainted, for EVS2's provenance bit, SEARCH's trust and the record's sealing (RecordRunView): true
// before enrollment and whenever the run store cannot answer.
func (self *Sidecar) RunTainted(runId Id) bool {
	runs, err := self.Runs()
	if err != nil {
		return true
	}
	return runs.Tainted(runId)
}
