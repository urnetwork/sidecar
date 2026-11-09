package legs

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The repository's top, two above this package.
func repositoryTop(t *testing.T) string {
	t.Helper()
	top, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return top
}

// The fixture's legs: the table's own darwin/arm64, js/wasm and windows/amd64, narrowed to the fixture
// package under its tag.
func fixtureLegs(names ...string) []*Leg {
	legs := []*Leg{}
	for _, leg := range LegsNamed(DefaultLegs(), names...) {
		copied := *leg
		copied.Packages = []string{"./sidecartest/legs/fixture"}
		copied.Tags = append(slices.Clone(leg.Tags), "sidecar_legs_fixture")
		legs = append(legs, &copied)
	}
	return legs
}

// Settings for a run of the fixture. A leg where the test itself cannot run the go command, js/wasm
// among them, runs nothing: the runner's own tests read not run there.
func fixtureSettings(t *testing.T) *RunSettings {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("not run: this leg cannot run the go command: %v", err)
	}
	settings := DefaultRunSettings(repositoryTop(t))
	settings.Go = goCommand()
	return settings
}

// The go command on PATH, which GOTOOLCHAIN=local holds to the one toolchain every leg builds with.
func goCommand() string {
	if path, err := exec.LookPath("go"); err == nil {
		return path
	}
	return "go"
}

// A package's output, or why there is none.
func firstOutput(result *Result) string {
	if len(result.Packages) == 0 {
		return result.Why
	}
	return result.Packages[0].Output
}

// Every leg's name is unique, its runner known, and a leg that does not pass on its own runner says why.
func TestDefaultLegsAreWellFormed(t *testing.T) {
	names := map[string]bool{}
	for _, leg := range DefaultLegs() {
		if names[leg.Name] {
			t.Errorf("%s is listed twice", leg.Name)
		}
		names[leg.Name] = true
		if len(leg.Packages) == 0 || leg.Module == "" || leg.Goos == "" || leg.Goarch == "" {
			t.Errorf("%s: no packages, module or target", leg.Name)
		}
		switch leg.Runner {
		case RunnerNative, RunnerContainer, RunnerNode:
		case RunnerCompileOnly, RunnerCells, RunnerNone:
			if leg.Why == "" {
				t.Errorf("%s cannot run here and says nothing of why", leg.Name)
			}
		default:
			t.Errorf("%s: runner %q", leg.Name, leg.Runner)
		}
	}
}

// A leg with no runner reads not run, and one with no attested runner compiled: neither is a pass.
func TestALegWithNoRunnerReadsNotRun(t *testing.T) {
	results := Run(context.Background(), fixtureSettings(t), append(
		LegsNamed(DefaultLegs(), "gomobile ios/arm64", "tests cgo windows/amd64"), fixtureLegs("tests windows/amd64")...))
	want := []Outcome{OutcomeNotRun, OutcomeNotRun, OutcomeCompiled}
	for index, result := range results {
		if result.Outcome != want[index] {
			t.Errorf("%s, want %s: %+v", result, want[index], result.Packages)
		}
		if result.Why == "" {
			t.Errorf("%s says nothing of why", result)
		}
	}
}

// The fixture passes natively and in Node, and its planted vector, whose bytes differ on wasm, fails
// the js/wasm leg alone, naming it.
func TestFixturePassesInNodeAndAMismatchNamesItsLeg(t *testing.T) {
	settings := fixtureSettings(t)
	settings.RunPattern = "^TestFixturePasses$"
	results := Run(context.Background(), settings, fixtureLegs("tests darwin/arm64", "tests js/wasm"))
	for _, result := range results {
		if result.Outcome == OutcomeNotRun {
			t.Skipf("not run: %s", result)
		}
		if result.Outcome != OutcomePass {
			t.Errorf("%s: %v", result, firstOutput(result))
		}
	}

	settings.RunPattern = "^TestFixtureVector$"
	results = Run(context.Background(), settings, fixtureLegs("tests darwin/arm64", "tests js/wasm"))
	if results[0].Outcome != OutcomePass {
		t.Errorf("the vector failed natively: %s: %s", results[0], firstOutput(results[0]))
	}
	if results[1].Outcome != OutcomeFail {
		t.Fatalf("the planted mismatch passed on wasm: %s", results[1])
	}
	if !strings.Contains(firstOutput(results[1]), "on leg tests js/wasm") {
		t.Errorf("the mismatch does not name its leg:\n%s", firstOutput(results[1]))
	}
}

// The fixture passes in a container. SIDECAR_LEGS_IMAGE names a linux image of this host's
// architecture; with none here, nothing is fetched and the run reads not run.
func TestFixturePassesInAContainer(t *testing.T) {
	settings := fixtureSettings(t)
	settings.RunPattern = "^TestFixturePasses$"
	if image := os.Getenv("SIDECAR_LEGS_IMAGE"); image != "" {
		settings.ContainerImage = image
	}
	leg := fixtureLegs("engines linux/arm64")[0]
	leg.Goarch = runtime.GOARCH
	result := Run(context.Background(), settings, []*Leg{leg})[0]
	if result.Outcome == OutcomeNotRun {
		t.Skipf("not run: %s", result)
	}
	if result.Outcome != OutcomePass {
		t.Errorf("%s: %v", result, result.Packages)
	}
}
