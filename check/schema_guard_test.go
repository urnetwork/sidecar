//go:build sidecar_check

// §22.7's schema guard in make check (I-18). The guard is sidecartest's, which T2 and T3 call after
// each scenario, and this package imports nothing of ours, so this runs its test through the go command
// and prints what a passing run leaned on, as the rest of make check does: the list's counts, the fields
// waiting on a question and the rows waiting on a milestone.

package check

import (
	"os/exec"
	"strings"
	"testing"
)

// Starts each line the guard's test logs for this report.
const schemaGuardReportPrefix = "schema guard: "

// What the test's run said: its logs for the report, and whether it ran at all, since a -run matching
// nothing passes.
func schemaGuardOutput(output string) ([]string, bool) {
	reports := []string{}
	passed := false
	for _, line := range strings.Split(output, "\n") {
		if _, report, found := strings.Cut(line, schemaGuardReportPrefix); found {
			reports = append(reports, report)
		}
		if strings.HasPrefix(line, "--- PASS: TestSchemaGuard ") {
			passed = true
		}
	}
	return reports, passed
}

func TestSchemaGuard(t *testing.T) {
	repository := openThisCheckout(t)
	command := exec.Command("go", "test", "-count=1", "-v", "-run", "^TestSchemaGuard$", "./sidecartest")
	command.Dir = repository.moduleDirectory
	command.Env = goEnvironment()
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("the schema guard fails: %v\n%s", err, output)
	}
	reports, passed := schemaGuardOutput(string(output))
	if !passed {
		t.Fatalf("the schema guard's test did not run:\n%s", output)
	}
	for _, report := range reports {
		repository.report("schema guard: %s", report)
	}
}

func TestSchemaGuardOutputReadsARun(t *testing.T) {
	reports, passed := schemaGuardOutput("=== RUN   TestSchemaGuard\n    schema_guard_test.go:25: schema guard: 2 rows\n--- PASS: TestSchemaGuard (0.01s)\nPASS\n")
	if !passed || len(reports) != 1 || reports[0] != "2 rows" {
		t.Errorf("read %q and %v", reports, passed)
	}
}

// A run that matched no test passes as far as the go command cares, so this must not call it one.
func TestSchemaGuardOutputRefusesARunOfNothing(t *testing.T) {
	if _, passed := schemaGuardOutput("testing: warning: no tests to run\nPASS\nok\n"); passed {
		t.Errorf("a run of no test read as a pass")
	}
}
