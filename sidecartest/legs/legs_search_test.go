//go:build sidecar_legs

// The index vectors on every leg (SEARCH-M10-41; §22.9's Index determinism row, §4.7; D-TEST-15, FI-22): the root's
// vector tests, as testdata/index/README.md's table names them, and the runner's own, through the every-leg runner on
// each leg this host has: darwin/arm64 natively; linux/arm64 and linux/amd64 in a container of SIDECAR_LEGS_IMAGE
// (nothing here fetches one, so a host without a matching image reads not run); windows/amd64 compiled, with no
// attested runner; js/wasm and the sidecar_http page Worker in Node; and the gomobile legs by SDK-M10-06's cells. A
// leg passes only when every vector test it compiles passed there, so a test that stopped compiling on a leg does not
// pass by its absence. `make index-vectors` runs it. It sits in this package, not sidecartest, since a parent imports no
// child of its own (R-REPO-5).

package legs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The runner's own tests beside the table's: the directory against the table, the runtimes, and the headers.
var indexVectorRunnerTests = []string{
	"TestIndexVectorFilesAreAllReproduced",
	"TestIndexVectorsUnderEveryRuntime",
	"TestIndexHeadersRecordTheLinkedBuild",
}

// Tests a leg's build leaves out by design: remote search's sizes on the page Worker, which asks no indexer.
var indexVectorTestsOffLeg = map[string][]string{
	"sidecar_http js/wasm": {"TestSearchSizeVectors"},
}

// Tests that skip where no process can be started: the runtimes' runner on js/wasm.
var indexVectorTestsSkippedOnJs = []string{"TestIndexVectorsUnderEveryRuntime"}

// The one-pass extractor's conformance, each test in a process of its own: on js/wasm, in one process with the others,
// the merge vectors after them ran out of wasm's 4 GiB, and so did the file case after the mail case (2026-11-16), each
// passing alone; the stream extractor's 2 MiB key buffers a document, taken again for every split of every vector, are
// what fill it. A leg runs the table in three processes.
var indexVectorTestsApart = []string{"TestIndexStreamConformanceMail", "TestIndexStreamConformanceFile"}

// The tests the README's table names, read from its rows, which the root's TestIndexVectorFilesAreAllReproduced holds
// to the directory and to the root's own table.
func indexVectorTableTests(t *testing.T, top string) []string {
	t.Helper()
	readme, err := os.ReadFile(filepath.Join(top, "testdata", "index", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	name := regexp.MustCompile("`(Test[A-Za-z0-9]+)`")
	tests := []string{}
	for _, line := range strings.Split(string(readme), "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		for _, match := range name.FindAllStringSubmatch(line, -1) {
			if !slices.Contains(tests, match[1]) {
				tests = append(tests, match[1])
			}
		}
	}
	if len(tests) == 0 {
		t.Fatal("the README's table names no test: the legs would run nothing")
	}
	return tests
}

// The legs the vectors run on: the every-leg table's root legs narrowed to the root package, with linux/arm64's root
// added beside its engines, and no cgo leg, whose code here is the same.
func indexVectorLegs() []*Leg {
	vectorLegs := []*Leg{}
	for _, leg := range DefaultLegs() {
		if leg.Module != "." || leg.Cgo && leg.Runner != RunnerCells || leg.HasTag("ios_extension") {
			continue
		}
		copied := *leg
		copied.Packages = []string{"."}
		if leg.Name == "engines linux/arm64" {
			copied.Name = "root linux/arm64"
		}
		vectorLegs = append(vectorLegs, &copied)
	}
	return vectorLegs
}

// The legs cover every target §22.9's row names: darwin/arm64, linux amd64 and arm64, windows/amd64, js/wasm and the
// Worker, and the gomobile legs.
func TestIndexVectorLegsCoverEveryTarget(t *testing.T) {
	targets := map[string]bool{}
	for _, leg := range indexVectorLegs() {
		target := leg.Goos + "/" + leg.Goarch
		if leg.HasTag("sidecar_http") {
			target = "sidecar_http"
		}
		if leg.HasTag("sdk_mobile_bind") {
			target = "gomobile " + target
		}
		targets[target] = true
		if !slices.Equal(leg.Packages, []string{"."}) {
			t.Errorf("%s runs %v, not the root", leg.Name, leg.Packages)
		}
	}
	for _, want := range []string{
		"darwin/arm64", "linux/amd64", "linux/arm64", "windows/amd64", "js/wasm", "sidecar_http",
		"gomobile android/arm64", "gomobile ios/arm64",
	} {
		if !targets[want] {
			t.Errorf("no leg runs the vectors on %s", want)
		}
	}
}

// Whether output shows name ending as want ("PASS" or "SKIP") at least once.
func indexVectorEnded(output string, name string, want string) bool {
	return strings.Contains(output, "--- "+want+": "+name+" ")
}

// One leg's processes as one result: a pass only when every one passed, the outputs together.
func indexVectorJoin(results [][]*Result, index int) (*Result, string) {
	joined := &Result{Leg: results[0][index].Leg, Outcome: OutcomePass}
	output := ""
	for _, pass := range results {
		result := pass[index]
		joined.Packages = append(joined.Packages, result.Packages...)
		for _, packageResult := range result.Packages {
			output += packageResult.Output
		}
		if result.Outcome != OutcomePass && joined.Outcome == OutcomePass {
			joined.Outcome, joined.Why = result.Outcome, result.Why
		}
	}
	return joined, output
}

// Every leg this host has runs the vector tests: each it compiles passes, the runtimes' runner skipping only where no
// process starts. A leg that cannot run here reads not run with its reason, which is no pass.
func TestIndexVectorsOnEveryLeg(t *testing.T) {
	top := repositoryTop(t)
	tableTests := indexVectorTableTests(t, top)
	tests := slices.Concat(tableTests, indexVectorRunnerTests)
	together := slices.DeleteFunc(slices.Clone(tests), func(name string) bool { return slices.Contains(indexVectorTestsApart, name) })
	processes := [][]string{together}
	for _, name := range indexVectorTestsApart {
		if !slices.Contains(tableTests, name) {
			t.Fatalf("%s is run apart and the README's table does not name it", name)
		}
		processes = append(processes, []string{name})
	}
	vectorLegs := indexVectorLegs()
	results := [][]*Result{}
	for _, pattern := range processes {
		settings := DefaultRunSettings(top)
		if image := os.Getenv("SIDECAR_LEGS_IMAGE"); image != "" {
			settings.ContainerImage = image
		}
		settings.RunPattern = "^(" + strings.Join(pattern, "|") + ")$"
		results = append(results, Run(context.Background(), settings, vectorLegs))
	}
	passed := 0
	for index := range vectorLegs {
		result, output := indexVectorJoin(results, index)
		switch result.Outcome {
		case OutcomePass:
		case OutcomeFail:
			t.Errorf("%s", result)
			for _, packageResult := range result.Packages {
				if packageResult.Outcome == OutcomeFail {
					t.Logf("%s on %s:\n%s", packageResult.ImportPath, result.Leg.Name, packageResult.Output)
				}
			}
			continue
		default:
			t.Logf("%s: no pass", result)
			continue
		}
		missing := []string{}
		for _, name := range tests {
			if slices.Contains(indexVectorTestsOffLeg[result.Leg.Name], name) {
				continue
			}
			want := "PASS"
			if result.Leg.Goos == "js" && slices.Contains(indexVectorTestsSkippedOnJs, name) {
				want = "SKIP"
			}
			if !indexVectorEnded(output, name, want) {
				missing = append(missing, fmt.Sprintf("%s (%s)", name, strings.ToLower(want)))
			}
		}
		if 0 < len(missing) {
			t.Errorf("%s: the vector tests that did not end as they must there: %s", result.Leg.Name, strings.Join(missing, ", "))
			continue
		}
		passed += 1
		t.Logf("%s", result)
	}
	t.Logf("the vectors passed on %d of %d legs", passed, len(vectorLegs))
}
