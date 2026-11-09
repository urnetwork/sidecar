// §16.6's run files (record_run.go): taint write-ahead and monotone, a missing, unknown or failed file tainted, and
// retention from the run's Coverage on a fake clock.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// A medium whose temp files' Syncs fail while armed, as an fsync's EIO does. Safe for concurrent use.
type runSyncFaultBackend struct {
	SidecarStoreBackend
	stateLock sync.Mutex
	failing   bool
}

// Every temp file's Sync fails while failing is set.
func (self *runSyncFaultBackend) setFailing(failing bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failing = failing
}

// A temp file that asks before it syncs.
func (self *runSyncFaultBackend) CreateTemp() (SidecarStoreBackendFile, error) {
	file, err := self.SidecarStoreBackend.CreateTemp()
	if err != nil {
		return nil, err
	}
	return &runSyncFaultFile{SidecarStoreBackendFile: file, backend: self}, nil
}

// A temp file of a runSyncFaultBackend.
type runSyncFaultFile struct {
	SidecarStoreBackendFile
	backend *runSyncFaultBackend
}

// Fails while the backend is failing.
func (self *runSyncFaultFile) Sync() error {
	self.backend.stateLock.Lock()
	failing := self.backend.failing
	self.backend.stateLock.Unlock()
	if failing {
		return fmt.Errorf("%w: an injected fsync fault", ErrSidecarStoreFailed)
	}
	return self.SidecarStoreBackendFile.Sync()
}

// An unlocked instance with testNetworkId enrolled on backend, and a run store on it.
func newTestRunStoreOn(t *testing.T, backend SidecarStoreBackend) (*SidecarInstance, *RunStore, *recordTestClock) {
	t.Helper()
	instance := newInstanceOn(t, backend, newFakeKeyStore())
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	enrollTestNetwork(t, instance, testNetworkId)
	clock := newRecordTestClock()
	runs, err := NewRunStore(instance.Store(&testNetworkId), defaultSidecarMcpSettings(), clock)
	if err != nil {
		t.Fatal(err)
	}
	return instance, runs, clock
}

// A second store on the same instance: what a restarted daemon reads, with nothing in memory.
func reopenTestRunStore(t *testing.T, instance *SidecarInstance, clock Clock) *RunStore {
	t.Helper()
	runs, err := NewRunStore(instance.Store(&testNetworkId), defaultSidecarMcpSettings(), clock)
	if err != nil {
		t.Fatal(err)
	}
	return runs
}

// Creates an untainted run, which must take.
func createTestRun(t *testing.T, runs *RunStore) Id {
	t.Helper()
	runId := NewId()
	err := runs.Create(context.Background(), &RunFile{RunId: runId, Harness: "claude-code", SessionIds: []string{"synthetic-session"}})
	if err != nil {
		t.Fatal(err)
	}
	return runId
}

func TestNewRunStartsUntainted(t *testing.T) {
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	runId := createTestRun(t, runs)
	if runs.Tainted(runId) {
		t.Error("a new run reads tainted")
	}
	if err := runs.Create(context.Background(), &RunFile{RunId: runId}); !errors.Is(err, ErrRunExists) {
		t.Errorf("a second create answered %v", err)
	}
}

// Taint returns only once the file is fsynced, and from its first step every reader sees the run tainted.
func TestTaintFsyncedBeforeReturn(t *testing.T) {
	backend := newGateBackend()
	instance, runs, clock := newTestRunStoreOn(t, backend)
	runId := createTestRun(t, runs)

	backend.armSync()
	returned := make(chan error, 1)
	go func() {
		returned <- runs.Taint(context.Background(), runId, RunTaintWebTool)
	}()
	<-backend.entered
	select {
	case err := <-returned:
		t.Fatalf("taint returned %v before its fsync", err)
	default:
	}
	if !runs.Tainted(runId) {
		t.Error("a racing reader read untainted while the taint was in flight")
	}
	close(backend.release)
	if err := <-returned; err != nil {
		t.Fatal(err)
	}
	run, err := reopenTestRunStore(t, instance, clock).Get(runId)
	if err != nil || !run.Tainted || len(run.TaintReasons) != 1 || run.TaintReasons[0] != RunTaintWebTool {
		t.Errorf("file %+v, err %v", run, err)
	}
}

// A taint whose fsync fails fails, and the run reads tainted anyway; the next taint writes it.
func TestFailedFsyncFailsTaint(t *testing.T) {
	backend := &runSyncFaultBackend{SidecarStoreBackend: NewSidecarMemoryBackend()}
	instance, runs, clock := newTestRunStoreOn(t, backend)
	runId := createTestRun(t, runs)
	backend.setFailing(true)
	if err := runs.Taint(context.Background(), runId, RunTaintUntrustedData); err == nil {
		t.Fatal("a taint whose fsync failed answered nil")
	}
	if !runs.Tainted(runId) {
		t.Error("a run whose taint failed to write reads untainted")
	}
	backend.setFailing(false)
	// a rewrite for something else writes the taint memory holds
	if err := runs.AddGap(context.Background(), runId, "missed_event"); err != nil {
		t.Fatal(err)
	}
	if run, err := reopenTestRunStore(t, instance, clock).Get(runId); err != nil || !run.Tainted {
		t.Errorf("file %+v, err %v", run, err)
	}
}

func TestMissingFileIsTainted(t *testing.T) {
	instance, runs, clock := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	runId := createTestRun(t, runs)
	store, err := instance.Store(&testNetworkId).Directory(runDirectoryName, runClass)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(runFileName(runId)); err != nil {
		t.Fatal(err)
	}
	if !reopenTestRunStore(t, instance, clock).Tainted(runId) {
		t.Error("a run with no file reads untainted")
	}
}

func TestUnknownRunIsTainted(t *testing.T) {
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	if !runs.Tainted(NewId()) {
		t.Error("an id this store never saw reads untainted")
	}
}

// FS-27's corrupt case: a run file that fails reads tainted.
func TestCorruptFileIsTainted(t *testing.T) {
	backend := NewSidecarMemoryBackend()
	instance, runs, clock := newTestRunStoreOn(t, backend)
	runId := createTestRun(t, runs)
	path := networkFilePath(testNetworkId, runDirectoryName+"/"+runFileName(runId))
	content := readBackend(t, backend, path)
	content[len(content)-1] ^= 0x01
	putBackendFile(t, backend, path, content)
	if !reopenTestRunStore(t, instance, clock).Tainted(runId) {
		t.Error("a corrupt run file reads untainted")
	}
}

// A locked keychain cannot vouch for a run, so the run reads tainted.
func TestLockedRunIsTainted(t *testing.T) {
	instance, runs, clock := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	runId := createTestRun(t, runs)
	instance.Lock()
	if !reopenTestRunStore(t, instance, clock).Tainted(runId) {
		t.Error("a run read while locked reads untainted")
	}
	if err := runs.Taint(context.Background(), runId, RunTaintWebTool); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("a taint while locked answered %v", err)
	}
	if !runs.Tainted(runId) {
		t.Error("a taint that could not write left the run untainted")
	}
}

// Taint never clears: not by a restart, not by a rewrite, and a Create over the file refuses.
func TestTaintedNeverClears(t *testing.T) {
	instance, runs, clock := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	runId := createTestRun(t, runs)
	if err := runs.Taint(context.Background(), runId, RunTaintCoverageLapse); err != nil {
		t.Fatal(err)
	}
	restarted := reopenTestRunStore(t, instance, clock)
	if !restarted.Tainted(runId) {
		t.Fatal("a restart cleared the taint")
	}
	if err := restarted.AddSession(context.Background(), runId, "another-session"); err != nil {
		t.Fatal(err)
	}
	if err := restarted.update(context.Background(), runId, func(run *RunFile) { run.Tainted = false }); !errors.Is(err, errRunUntaint) {
		t.Errorf("a rewrite clearing the taint answered %v", err)
	}
	if err := restarted.Create(context.Background(), &RunFile{RunId: runId}); !errors.Is(err, ErrRunExists) {
		t.Errorf("a create over a tainted run answered %v", err)
	}
	run, err := reopenTestRunStore(t, instance, clock).Get(runId)
	if err != nil || !run.Tainted || len(run.SessionIds) != 2 {
		t.Errorf("file %+v, err %v", run, err)
	}
}

// A taint of a run with no file writes one, tainted, and a later Create of that run refuses rather than start it
// clean.
func TestTaintBeforeCreateKeepsTheTaint(t *testing.T) {
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	runId := NewId()
	if err := runs.Taint(context.Background(), runId, RunTaintInherited); err != nil {
		t.Fatal(err)
	}
	if err := runs.Create(context.Background(), &RunFile{RunId: runId}); !errors.Is(err, ErrRunExists) {
		t.Errorf("create after taint answered %v", err)
	}
	if !runs.Tainted(runId) {
		t.Error("untainted")
	}
}

// Each reason once, each gap counted.
func TestRunFileListsAccumulate(t *testing.T) {
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	runId := createTestRun(t, runs)
	ctx := context.Background()
	for _, reason := range []RunTaintReason{RunTaintWebTool, RunTaintWebTool, RunTaintConfigChanged} {
		if err := runs.Taint(ctx, runId, reason); err != nil {
			t.Fatal(err)
		}
	}
	for _, gap := range []string{"redaction", "redaction", "missed_event", "redaction"} {
		if err := runs.AddGap(ctx, runId, gap); err != nil {
			t.Fatal(err)
		}
	}
	run, err := runs.Get(runId)
	if err != nil {
		t.Fatal(err)
	}
	if len(run.TaintReasons) != 2 || run.TaintReasons[0] != RunTaintWebTool || run.TaintReasons[1] != RunTaintConfigChanged {
		t.Errorf("reasons %v", run.TaintReasons)
	}
	if len(run.Gaps) != 2 || run.Gaps[0] != "redaction:3" || run.Gaps[1] != "missed_event" {
		t.Errorf("gaps %v", run.Gaps)
	}
	if err := runs.AddGap(ctx, NewId(), "redaction"); !errors.Is(err, ErrRunUnknown) {
		t.Errorf("a gap for no run answered %v", err)
	}
}

// Retention runs from the newest Coverage: kept until 30 days past it, a later Coverage restarting the count, and a
// run with none kept.
func TestRetentionAfterCoverage(t *testing.T) {
	_, runs, clock := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	ctx := context.Background()
	covered := createTestRun(t, runs)
	uncovered := createTestRun(t, runs)
	if err := runs.Covered(ctx, covered, 1, 5, clock.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	clock.advance(20 * 24 * time.Hour)
	// a later Coverage (reading 8) restarts the count
	if err := runs.Covered(ctx, covered, 1, 9, clock.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	clock.advance(29 * 24 * time.Hour)
	if removed, err := runs.Sweep(ctx); err != nil || removed != 0 {
		t.Fatalf("early sweep removed %d, err %v", removed, err)
	}
	clock.advance(2 * 24 * time.Hour)
	if removed, err := runs.Sweep(ctx); err != nil || removed != 1 {
		t.Fatalf("sweep removed %d, err %v", removed, err)
	}
	if _, err := runs.Get(covered); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Errorf("the swept run reads %v", err)
	}
	if !runs.Tainted(covered) {
		t.Error("a swept run reads untainted")
	}
	if run, err := runs.Get(uncovered); err != nil || run.Tainted {
		t.Errorf("the run with no coverage: %+v, %v", run, err)
	}
}

// A Sidecar answers taint for its runs, and tainted before it knows its network.
func TestSidecarRunTainted(t *testing.T) {
	instance, _, _ := enrolledInstance(t)
	sidecar := &Sidecar{instance: instance, settings: validSidecarSettings()}
	runId := NewId()
	if !sidecar.RunTainted(runId) {
		t.Error("a run reads untainted before enrollment")
	}
	networkId := testNetworkId
	sidecar.networkId = &networkId
	runs, err := sidecar.Runs()
	if err != nil {
		t.Fatal(err)
	}
	if err := runs.Create(context.Background(), &RunFile{RunId: runId}); err != nil {
		t.Fatal(err)
	}
	var view RecordRunView = sidecar
	if view.RunTainted(runId) {
		t.Error("a new run reads tainted")
	}
	if err := runs.Taint(context.Background(), runId, RunTaintWebTool); err != nil {
		t.Fatal(err)
	}
	if !view.RunTainted(runId) {
		t.Error("a tainted run reads untainted")
	}
	again, err := sidecar.Runs()
	if err != nil || again != runs {
		t.Errorf("a second run store: %v", err)
	}
}
