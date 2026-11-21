// Where a failing seed's trace goes (explore.go's record, replay.go's traceDestination): outside every source tree
// unless a setting or UR_FAULT_TRACE_DIR names a directory, the failure naming the file, while the traces committed to
// testdata/fault/seeds are read and replayed as before. A test that could reach a source tree runs in a stand-in for
// the monoroot: a server package's directory as the working directory, beside a sidecar checkout whose seeds a walk up
// from it finds, which is how server's packages once wrote every failing seed's trace into the sidecar checkout their
// go.mod replaces.

package fault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A stand-in monoroot: <root>/sidecar/testdata/fault/seeds holding a README and the traces committed, and
// <root>/server/api, which the test runs in, as a server package's test does. Returns the root and the seeds' directory.
func traceWritesTree(t *testing.T, committed ...*Trace) (string, string) {
	t.Helper()
	root := t.TempDir()
	seeds := filepath.Join(root, seedsSiblingName, filepath.FromSlash(seedsDirectoryPath))
	if err := os.MkdirAll(seeds, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(seeds, "README"), []byte("the stand-in's committed seeds\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, trace := range committed {
		if _, err := WriteTrace(seeds, trace); err != nil {
			t.Fatal(err)
		}
	}
	packageDirectory := filepath.Join(root, "server", "api")
	if err := os.MkdirAll(packageDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(packageDirectory)
	return root, seeds
}

// Every file under root, by its slash path from root, in order.
func traceWritesFiles(t *testing.T, root string) []string {
	t.Helper()
	files := []string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	return files
}

// Removes each directory made for traces that paths name when the test ends, and nothing else: one made by a
// traceDestination is named by its pattern.
func traceWritesCleanup(t *testing.T, paths []string) {
	t.Helper()
	for _, path := range paths {
		directory := filepath.Dir(path)
		if path != "" && strings.HasPrefix(filepath.Base(directory), traceTemporaryDirectoryPattern) {
			t.Cleanup(func() {
				os.RemoveAll(directory)
			})
		}
	}
}

// The trace of a merge seed on which the blind toy loses an increment, as a trace committed for rowId: the explorer
// finds one (TestExplorerFindsAPlantedLostUpdateWithinTenSeeds).
func traceWritesFailingTrace(t *testing.T, rowId string) *Trace {
	t.Helper()
	report := Explore(t.Context(), toyCounterBuilder(&toyCounter{blind: true}), toyRuleSettings(t))
	if len(report.Failures) == 0 {
		t.Fatalf("no seed failed: %s", report)
	}
	trace := TraceOf(report.Failures[0])
	trace.Id = rowId
	return trace
}

// The blind toy as a registration of FS-2's, which is on no unknown list and names no twin.
func traceWritesBlindRegistration() *Registration {
	return &Registration{Row: "FS-2", Tiers: []Tier{TierT2}, Build: toyCounterBuilder(&toyCounter{blind: true})}
}

// Each of explore's failures has its trace in directory, under its row's name and its seed, and names it.
func traceWritesInDirectory(t *testing.T, explore *ExploreReport, directory string, rowId string) {
	t.Helper()
	if len(explore.TracePaths) != len(explore.Failures) {
		t.Fatalf("%d trace paths for %d failures", len(explore.TracePaths), len(explore.Failures))
	}
	for index, failure := range explore.Failures {
		path := explore.TracePaths[index]
		if filepath.Dir(path) != directory || failure.TracePath != path {
			t.Errorf("seed %d's trace is %q, its failure names %q, want one in %s", failure.Seed, path, failure.TracePath, directory)
			continue
		}
		trace, err := ReadTrace(path)
		if err != nil || trace.Id != rowId || trace.Seed != failure.Seed || filepath.Base(path) != trace.FileName() {
			t.Errorf("%s: %+v, %v", path, trace, err)
		}
		if !strings.Contains(failure.String(), "its trace: "+path) || !strings.Contains(explore.String(), path) {
			t.Errorf("the failure does not name its trace %s:\n%s\n%s", path, failure, explore)
		}
	}
}

// A server package's test runs a row whose seeds fail, nothing naming a directory for traces. The trace committed in
// its sidecar sibling is found and replayed as before, failing as its seed did, and each failing seed's trace goes to
// one directory made for the explorer under the host's temporary directory and is named in the failure, the tree left
// as it was.
func TestAFailingSeedWithNoDirectoryNamedLeavesTheSourceTreeAndNamesItsTrace(t *testing.T) {
	committed := traceWritesFailingTrace(t, "FS-2")
	t.Setenv(traceDirectoryEnvironment, "")
	root, _ := traceWritesTree(t, committed)
	before := traceWritesFiles(t, root)

	settings := DefaultRuleSettings()
	if settings.SeedsDirectory != "" || settings.TraceDirectory != "" {
		t.Fatalf("the defaults name seeds %q and traces %q", settings.SeedsDirectory, settings.TraceDirectory)
	}
	report := CheckRow(t.Context(), traceWritesBlindRegistration(), settings)
	traceWritesCleanup(t, report.Explore.TracePaths)
	if after := traceWritesFiles(t, root); !slices.Equal(after, before) {
		t.Errorf("the tree held %v and holds %v", before, after)
	}
	if len(report.Replays) != 1 || report.Replays[0].Err == nil || !strings.Contains(report.Replays[0].Err.Error(), "an increment was lost") {
		t.Errorf("the committed trace was not replayed as its seed failed: %v", report.Replays)
	}
	if len(report.Explore.Failures) == 0 || 0 < len(report.Explore.TraceErrors) {
		t.Fatalf("failures %d, trace errors %v: %s", len(report.Explore.Failures), report.Explore.TraceErrors, report)
	}
	directory := filepath.Dir(report.Explore.TracePaths[0])
	if !strings.HasPrefix(filepath.Base(directory), traceTemporaryDirectoryPattern) || strings.HasPrefix(directory, root) {
		t.Fatalf("traces in %s, not a directory made for them", directory)
	}
	traceWritesInDirectory(t, report.Explore, directory, "FS-2")
	if !strings.Contains(report.String(), report.Explore.TracePaths[0]) {
		t.Errorf("the report does not name the trace: %s", report)
	}
}

// The same with the runs in child processes, which run in the parent's working directory, the server package's here:
// the race that trusts its preconditions fails seeds there, and the parent writes their traces to a directory made for
// them, the tree left as it was.
func TestRunsInChildProcessesWithNoDirectoryNamedLeaveTheSourceTree(t *testing.T) {
	t.Setenv(traceDirectoryEnvironment, "")
	root, _ := traceWritesTree(t)
	before := traceWritesFiles(t, root)

	settings := DefaultRuleSettings()
	settings.Processes.Count = 4
	// seeds enough to find the race (TestExplorerFindsARaceTheFixedOrderMisses)
	settings.Seeds = seedRange(40)
	report := checkToyRulesUnder(t, "race trusting preconditions", settings)
	t.Log(report.String())
	traceWritesCleanup(t, report.Explore.TracePaths)
	if after := traceWritesFiles(t, root); !slices.Equal(after, before) {
		t.Errorf("the tree held %v and holds %v", before, after)
	}
	if report.Costs.ChildProcesses == 0 || len(report.Explore.Failures) == 0 || 0 < len(report.Explore.TraceErrors) {
		t.Fatalf("%d child processes, failures %d, trace errors %v: %s", report.Costs.ChildProcesses, len(report.Explore.Failures), report.Explore.TraceErrors, report)
	}
	directory := filepath.Dir(report.Explore.TracePaths[0])
	if !strings.HasPrefix(filepath.Base(directory), traceTemporaryDirectoryPattern) || strings.HasPrefix(directory, root) {
		t.Fatalf("traces in %s, not a directory made for them", directory)
	}
	traceWritesInDirectory(t, report.Explore, directory, "toy-race")
}

// The opt-in: UR_FAULT_TRACE_DIR naming the sidecar checkout's own seeds, as a developer names them to commit what
// failed. Each failing seed's trace lands there under its row's name, and the row's next run, naming no directory,
// replays every one, the fixed toy passing them.
func TestUrFaultTraceDirTakesTheTracesAndTheNextRunReplaysThem(t *testing.T) {
	root, seeds := traceWritesTree(t)
	t.Setenv(traceDirectoryEnvironment, seeds)
	settings := DefaultRuleSettings()
	if settings.TraceDirectory != seeds {
		t.Fatalf("the defaults name traces %q, not UR_FAULT_TRACE_DIR's %q", settings.TraceDirectory, seeds)
	}
	failing := CheckRow(t.Context(), traceWritesBlindRegistration(), settings)
	if len(failing.Explore.Failures) == 0 || 0 < len(failing.Explore.TraceErrors) {
		t.Fatalf("failures %d, trace errors %v: %s", len(failing.Explore.Failures), failing.Explore.TraceErrors, failing)
	}
	traceWritesInDirectory(t, failing.Explore, seeds, "FS-2")
	files := []string{"sidecar/testdata/fault/seeds/README"}
	for _, failure := range failing.Explore.Failures {
		files = append(files, fmt.Sprintf("sidecar/testdata/fault/seeds/FS-2-%d.trace", failure.Seed))
	}
	slices.Sort(files)
	if after := traceWritesFiles(t, root); !slices.Equal(after, files) {
		t.Errorf("the tree holds %v, want %v", after, files)
	}

	t.Setenv(traceDirectoryEnvironment, "")
	fixed := CheckRow(t.Context(), &Registration{Row: "FS-2", Tiers: []Tier{TierT2}, Build: toyCounterBuilder(&toyCounter{})}, DefaultRuleSettings())
	if fixed.Failed() || len(fixed.Replays) != len(failing.Explore.Failures) {
		t.Errorf("%d replays of %d traces: %s", len(fixed.Replays), len(failing.Explore.Failures), fixed)
	}
	if after := traceWritesFiles(t, root); !slices.Equal(after, files) {
		t.Errorf("the run that passed changed the tree to %v", after)
	}
}

// A directory the settings name takes the trace whatever UR_FAULT_TRACE_DIR says, and is made if missing; the
// environment's directory is never made.
func TestATraceDirectorySettingTakesTheTraceOverUrFaultTraceDir(t *testing.T) {
	environment := filepath.Join(t.TempDir(), "environment")
	t.Setenv(traceDirectoryEnvironment, environment)
	settings := DefaultRuleSettings()
	settings.TraceDirectory = filepath.Join(t.TempDir(), "named", "deeper")
	report := Explore(t.Context(), toyCounterBuilder(&toyCounter{blind: true}), settings)
	if len(report.Failures) == 0 || 0 < len(report.TraceErrors) {
		t.Fatalf("failures %d, trace errors %v: %s", len(report.Failures), report.TraceErrors, report)
	}
	traceWritesInDirectory(t, report, settings.TraceDirectory, "toy-counter")
	if _, err := os.Stat(environment); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("UR_FAULT_TRACE_DIR's directory was made: %v", err)
	}
}

// WriteTrace finds no directory of its own, and a relative one, which go test would resolve in each package's own
// directory, takes no trace: each failure says why it has none, and the tree is left as it was.
func TestATraceIsWrittenNowhereWithoutAnAbsoluteDirectory(t *testing.T) {
	root, _ := traceWritesTree(t)
	before := traceWritesFiles(t, root)
	if path, err := WriteTrace("", &Trace{Id: "FS-2", Seed: 1}); err == nil {
		t.Errorf("a trace was written to %s", path)
	}

	t.Setenv(traceDirectoryEnvironment, filepath.FromSlash(seedsDirectoryPath))
	report := Explore(t.Context(), toyCounterBuilder(&toyCounter{blind: true}), DefaultRuleSettings())
	if len(report.Failures) == 0 || len(report.TraceErrors) != len(report.Failures) {
		t.Fatalf("failures %d, trace errors %v: %s", len(report.Failures), report.TraceErrors, report)
	}
	for index, failure := range report.Failures {
		if report.TracePaths[index] != "" || failure.TracePath != "" {
			t.Errorf("seed %d's trace was written to %q", failure.Seed, report.TracePaths[index])
		}
		if !strings.Contains(report.TraceErrors[index].Error(), "is not absolute") {
			t.Errorf("seed %d: %v", failure.Seed, report.TraceErrors[index])
		}
	}
	if after := traceWritesFiles(t, root); !slices.Equal(after, before) {
		t.Errorf("the tree held %v and holds %v", before, after)
	}
}
