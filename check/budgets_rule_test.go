//go:build sidecar_check

// D-TEST-3's budget rule (TEST-M1-09): "22.5's gates and 22.9's budgets fail the build; raising one needs
// a reviewed change". testdata/budgets.yml is the ledger, and this rule holds it two ways:
//
//   - a limit raised above the sidecar branch's, removed, or a row dropped is a finding unless the same
//     change rewrites the row's reviewed line, as sdk/build/APPLE_EXTENSION_MEMORY_BUDGET.md records each
//     raise of its own ceilings; a cut needs nothing;
//   - each bench row of this module whose benchmark has landed runs here for its allocations and bytes,
//     which hold on any machine, so a regression fails make check; its time waits for a quiet T5 host.
//
// The size rows hold the numbers make size enforces, read from this package's settings, so the two never
// part. This package imports no first-party package (TestNoQuotedFirstPartyPathHere), so it reads the
// ledger's few fields it needs itself; sidecartest.ParseBudgets is the strict reader, and
// sidecartest.CheckBudget the full one, which T5 runs.

package check

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// What this rule reads of a row.
type budgetRow struct {
	Id       string             `yaml:"id"`
	Spec     string             `yaml:"spec"`
	Kind     string             `yaml:"kind"`
	Owner    string             `yaml:"owner"`
	Module   string             `yaml:"module"`
	Package  string             `yaml:"package"`
	Name     string             `yaml:"name"`
	Limits   map[string]float64 `yaml:"limits"`
	Reviewed string             `yaml:"reviewed"`
}

type budgetLedger struct {
	Budgets []*budgetRow `yaml:"budgets"`
}

func (self *budgetLedger) row(id string) *budgetRow {
	for _, row := range self.Budgets {
		if row.Id == id {
			return row
		}
	}
	return nil
}

func parseBudgetLedger(data []byte) (*budgetLedger, error) {
	ledger := &budgetLedger{}
	if err := yaml.Unmarshal(data, ledger); err != nil {
		return nil, fmt.Errorf("budgets: %w", err)
	}
	return ledger, nil
}

// The ledger, from the checkout's testdata.
func (self *repository) budgets(t testing.TB) *budgetLedger {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(self.moduleDirectory, "testdata", "budgets.yml"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := parseBudgetLedger(data)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

// What head loosens against base without review: a limit raised or removed, or a row dropped, where the
// row's reviewed line did not change with it.
func budgetRaiseFindings(base *budgetLedger, head *budgetLedger) []string {
	findings := []string{}
	for _, baseRow := range base.Budgets {
		headRow := head.row(baseRow.Id)
		if headRow == nil {
			findings = append(findings, findingf("budget %s was dropped, which drops its gate: keep the row and raise it with a reviewed line (D-TEST-3)", baseRow.Id))
			continue
		}
		if headRow.Reviewed != "" && headRow.Reviewed != baseRow.Reviewed {
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(baseRow.Limits)) {
			headValue, kept := headRow.Limits[name]
			switch {
			case !kept:
				findings = append(findings, findingf("budget %s's %s limit was removed with no new reviewed line (D-TEST-3)", baseRow.Id, name))
			case baseRow.Limits[name] < headValue:
				findings = append(findings, findingf("budget %s's %s rose from %v to %v with no new reviewed line (D-TEST-3)", baseRow.Id, name, baseRow.Limits[name], headValue))
			}
		}
	}
	return findings
}

// The ledger as the sidecar branch holds it at this checkout's merge base, or nil with why there is none
// to compare: no sidecar branch, as on a release tree, or no ledger there yet.
func (self *repository) baseBudgets() (*budgetLedger, string, error) {
	git := func(arguments ...string) (string, error) {
		command := exec.Command("git", arguments...)
		command.Dir = self.moduleDirectory
		command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		output, err := command.Output()
		if err != nil {
			var exitError *exec.ExitError
			if errors.As(err, &exitError) {
				return "", fmt.Errorf("git %s: %w %s", strings.Join(arguments, " "), err, strings.TrimSpace(string(exitError.Stderr)))
			}
			return "", err
		}
		return strings.TrimSpace(string(output)), nil
	}
	if _, err := git("rev-parse", "--verify", "--quiet", "refs/heads/sidecar"); err != nil {
		return nil, "no sidecar branch in this clone", nil
	}
	base, err := git("merge-base", "HEAD", "sidecar")
	if err != nil {
		return nil, "", err
	}
	prefix, err := git("rev-parse", "--show-prefix")
	if err != nil {
		return nil, "", err
	}
	data, err := git("show", base+":"+prefix+"testdata/budgets.yml")
	if err != nil {
		return nil, "the sidecar branch has no ledger at " + base, nil
	}
	ledger, err := parseBudgetLedger([]byte(data))
	if err != nil {
		return nil, "", fmt.Errorf("the ledger at %s: %w", base, err)
	}
	return ledger, "", nil
}

// This checkout raises no budget without its reviewed line.
func TestBudgetsRiseOnlyWithAReviewedLine(t *testing.T) {
	repository := openThisCheckout(t)
	head := repository.budgets(t)
	base, why, err := repository.baseBudgets()
	if err != nil {
		t.Fatal(err)
	}
	if base == nil {
		repository.report("budgets: nothing to compare the ledger with (%s), so no raise is checked here", why)
		return
	}
	for _, finding := range budgetRaiseFindings(base, head) {
		t.Error(finding)
	}
}

// A raise with no new reviewed line fails, and so do a removed limit and a dropped row; a raise whose
// reviewed line changed, a cut and a new row do not.
func TestBudgetsFailOnARaiseWithNoReviewedLine(t *testing.T) {
	parse := func(text string) *budgetLedger {
		t.Helper()
		ledger, err := parseBudgetLedger([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return ledger
	}
	base := parse(`budgets:
  - {id: gate, kind: bench, limits: {ns_per_op: 1000, allocs_per_op: 0}, reviewed: ""}
  - {id: find, kind: path, limits: {postgres: 0, redis_calls: 1}, reviewed: "kept"}
  - {id: size, kind: size, limits: {bytes: 1048576}}
`)
	raised := parse(`budgets:
  - {id: gate, kind: bench, limits: {ns_per_op: 1200, allocs_per_op: 0}, reviewed: ""}
  - {id: find, kind: path, limits: {postgres: 0}, reviewed: "kept"}
`)
	wantFindings(t, budgetRaiseFindings(base, raised),
		"budget gate's ns_per_op rose from 1000 to 1200 with no new reviewed line (D-TEST-3)",
		"budget find's redis_calls limit was removed with no new reviewed line (D-TEST-3)",
		"budget size was dropped, which drops its gate: keep the row and raise it with a reviewed line (D-TEST-3)",
	)
	reviewed := parse(`budgets:
  - {id: gate, kind: bench, limits: {ns_per_op: 1200, allocs_per_op: 0}, reviewed: "2026-11-09: a reviewer, for a reason"}
  - {id: find, kind: path, limits: {postgres: 0, redis_calls: 0}, reviewed: "kept"}
  - {id: size, kind: size, limits: {bytes: 1048576}}
  - {id: new, kind: size, limits: {bytes: 1}}
`)
	wantFindings(t, budgetRaiseFindings(base, reviewed))
}

// The size rows hold what make size enforces.
func TestBudgetSizeRowsHoldTheSizeGatesNumbers(t *testing.T) {
	repository := openThisCheckout(t)
	ledger := repository.budgets(t)
	settings := defaultCheckSettings()
	for id, want := range map[string]int64{
		"ios-extension-device-role": settings.iosExtensionAddedMaxByteCount,
		"page-worker-wasm":          settings.sidecarHttpGoalByteCount,
	} {
		row := ledger.row(id)
		if row == nil || row.Limits["bytes"] != float64(want) {
			t.Errorf("budget %s does not hold make size's %d B", id, want)
		}
	}
}

// One benchmark's line of a go test -bench -benchmem run: name, -N suffix, iterations, then value-unit
// pairs.
var budgetBenchLinePattern = regexp.MustCompile(`^(Benchmark[^\s]*?)(-[0-9]+)?\s+[0-9]+\s+(.*)$`)

// Each benchmark's allocs/op and B/op in a run's output, the worst of any repeats.
func budgetBenchAllocations(output []byte) (map[string]map[string]float64, error) {
	results := map[string]map[string]float64{}
	for _, line := range strings.Split(string(output), "\n") {
		match := budgetBenchLinePattern.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}
		fields := strings.Fields(match[3])
		values := map[string]float64{}
		for index := 0; index+1 < len(fields); index += 2 {
			value, err := strconv.ParseFloat(fields[index], 64)
			if err != nil {
				return nil, fmt.Errorf("%q: %w", line, err)
			}
			switch fields[index+1] {
			case "allocs/op":
				values["allocs_per_op"] = value
			case "B/op":
				values["bytes_per_op"] = value
			}
		}
		if len(values) != 2 {
			return nil, fmt.Errorf("%q: no allocs/op and B/op, so the run was not -benchmem", line)
		}
		if results[match[1]] == nil {
			results[match[1]] = values
			continue
		}
		for name, value := range values {
			results[match[1]][name] = max(results[match[1]][name], value)
		}
	}
	return results, nil
}

// Each bench row of this module whose benchmark has landed holds its allocations and bytes at every make
// check, over 100 iterations; time is t5's. A row whose benchmark has not landed is reported missing.
func TestBudgetBenchmarksHoldTheirAllocations(t *testing.T) {
	repository := openThisCheckout(t)
	ledger := repository.budgets(t)
	packageRows := map[string][]*budgetRow{}
	for _, row := range ledger.Budgets {
		if row.Kind == "bench" && row.Module == "sidecar" {
			packageRows[row.Package] = append(packageRows[row.Package], row)
		}
	}
	held := 0
	for _, packageName := range slices.Sorted(maps.Keys(packageRows)) {
		names := []string{}
		for _, row := range packageRows[packageName] {
			names = append(names, row.Name)
		}
		output, err := runGo(repository.moduleDirectory, goEnvironment(), "test", "-run", "^$", "-bench", "^("+strings.Join(names, "|")+")$", "-benchtime", "100x", "-benchmem", "-count", "1", "./"+packageName)
		if err != nil {
			t.Fatal(err)
		}
		results, err := budgetBenchAllocations(output)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range packageRows[packageName] {
			result, ran := results[row.Name]
			if !ran {
				repository.report("budgets: missing, which is never a pass: %s's %s did not run in %s (%s)", row.Id, row.Name, packageName, row.Owner)
				continue
			}
			_, allocsSet := row.Limits["allocs_per_op"]
			_, bytesSet := row.Limits["bytes_per_op"]
			if !allocsSet && !bytesSet {
				repository.report("budgets: missing, which is never a pass: %s's %s ran and %s has set no allocation limit", row.Id, row.Name, row.Owner)
				continue
			}
			rowHeld := true
			for _, name := range []string{"allocs_per_op", "bytes_per_op"} {
				if limit, set := row.Limits[name]; set && limit < result[name] {
					t.Errorf("budget %s: %s's %s is %v, over its %v (%s)", row.Id, row.Name, name, result[name], limit, row.Spec)
					rowHeld = false
				}
			}
			if rowHeld {
				held += 1
			}
		}
	}
	if held == 0 {
		t.Error("no budget held: the ledger's benchmarks did not run")
	}
}
