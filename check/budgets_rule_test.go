//go:build sidecar_check

// D-TEST-3's budget rule (TEST-M1-09): "22.5's gates and 22.9's budgets fail the build; raising one needs
// a reviewed change". testdata/budgets.yml is the ledger (sidecartest/budget.go reads it), and this
// rule holds it two ways:
//
//   - a limit raised above the sidecar branch's, removed, or a row dropped is a finding unless the same
//     change rewrites the row's reviewed line, as sdk/build/APPLE_EXTENSION_MEMORY_BUDGET.md records each
//     raise of its own ceilings; a cut needs nothing;
//   - each bench row whose benchmark has landed runs here for its allocations and bytes, which hold on
//     any machine, so a regression fails make check; its time waits for a quiet T5 host.
//
// The size rows hold the numbers make size enforces, read from this package's settings, so the two never
// part.

package check

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The ledger, from the checkout's testdata.
func (self *repository) budgets(t testing.TB) *sidecartest.BudgetLedger {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(self.moduleDirectory, "testdata", "budgets.yml"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := sidecartest.ParseBudgets(data)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

// Each limit a row holds, by its field's name.
func budgetLimitValues(limits *sidecartest.BudgetLimits) map[string]float64 {
	values := map[string]float64{}
	if limits == nil {
		return values
	}
	put := func(name string, value *int64) {
		if value != nil {
			values[name] = float64(*value)
		}
	}
	if limits.NsPerOp != nil {
		values["ns_per_op"] = *limits.NsPerOp
	}
	put("allocs_per_op", limits.AllocsPerOp)
	put("bytes_per_op", limits.BytesPerOp)
	put("postgres", limits.Postgres)
	put("redis_calls", limits.RedisCalls)
	put("bytes", limits.Bytes)
	return values
}

// What head loosens against base without review: a limit raised or removed, or a row dropped, where the
// row's reviewed line did not change with it.
func budgetRaiseFindings(base *sidecartest.BudgetLedger, head *sidecartest.BudgetLedger) []string {
	findings := []string{}
	for _, baseBudget := range base.Budgets {
		headBudget := head.Budget(baseBudget.Id)
		if headBudget == nil {
			findings = append(findings, findingf("budget %s was dropped, which drops its gate: keep the row and raise it with a reviewed line (D-TEST-3)", baseBudget.Id))
			continue
		}
		reviewed := headBudget.Reviewed != "" && headBudget.Reviewed != baseBudget.Reviewed
		baseValues := budgetLimitValues(baseBudget.Limits)
		headValues := budgetLimitValues(headBudget.Limits)
		for _, name := range slices.Sorted(maps.Keys(baseValues)) {
			headValue, kept := headValues[name]
			if kept && headValue <= baseValues[name] {
				continue
			}
			if reviewed {
				continue
			}
			if !kept {
				findings = append(findings, findingf("budget %s's %s limit was removed with no new reviewed line (D-TEST-3)", baseBudget.Id, name))
			} else {
				findings = append(findings, findingf("budget %s's %s rose from %v to %v with no new reviewed line (D-TEST-3)", baseBudget.Id, name, baseValues[name], headValue))
			}
		}
	}
	return findings
}

// The ledger as the sidecar branch holds it at this checkout's merge base, or nil with why there is none
// to compare: no sidecar branch, as on a release tree, or no ledger there yet.
func (self *repository) baseBudgets() (*sidecartest.BudgetLedger, string, error) {
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
	ledger, err := sidecartest.ParseBudgets([]byte(data))
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
	parse := func(text string) *sidecartest.BudgetLedger {
		t.Helper()
		ledger, err := sidecartest.ParseBudgets([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return ledger
	}
	base := parse(`budgets:
  - {id: gate, spec: s, kind: bench, owner: ACL-M2-02, module: sidecar, package: ".", name: BenchmarkGate, limits: {ns_per_op: 1000, allocs_per_op: 0}, reviewed: ""}
  - {id: find, spec: s, kind: path, owner: SOCK-M5-17, module: server, name: sockets.find, limits: {postgres: 0, redis_calls: 1}, reviewed: "kept"}
  - {id: size, spec: s, kind: size, owner: SDK-M4-01, module: sidecar, package: check, name: TestSizeGateIosExtension, limits: {bytes: 1048576}}
`)
	raised := parse(`budgets:
  - {id: gate, spec: s, kind: bench, owner: ACL-M2-02, module: sidecar, package: ".", name: BenchmarkGate, limits: {ns_per_op: 1200, allocs_per_op: 0}, reviewed: ""}
  - {id: find, spec: s, kind: path, owner: SOCK-M5-17, module: server, name: sockets.find, limits: {postgres: 0}, reviewed: "kept"}
`)
	wantFindings(t, budgetRaiseFindings(base, raised),
		"budget gate's ns_per_op rose from 1000 to 1200 with no new reviewed line (D-TEST-3)",
		"budget find's redis_calls limit was removed with no new reviewed line (D-TEST-3)",
		"budget size was dropped, which drops its gate: keep the row and raise it with a reviewed line (D-TEST-3)",
	)
	reviewed := parse(`budgets:
  - {id: gate, spec: s, kind: bench, owner: ACL-M2-02, module: sidecar, package: ".", name: BenchmarkGate, limits: {ns_per_op: 1200, allocs_per_op: 0}, reviewed: "2026-11-09: a reviewer, for a reason"}
  - {id: find, spec: s, kind: path, owner: SOCK-M5-17, module: server, name: sockets.find, limits: {postgres: 0, redis_calls: 0}, reviewed: "kept"}
  - {id: size, spec: s, kind: size, owner: SDK-M4-01, module: sidecar, package: check, name: TestSizeGateIosExtension, limits: {bytes: 1048576}}
  - {id: new, spec: s, kind: size, owner: SDK-M4-09, module: sidecar, package: check, name: TestSizeGateSidecarHttp, limits: {bytes: 1}}
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
		budget := ledger.Budget(id)
		if budget == nil || budget.Limits.Bytes == nil || *budget.Limits.Bytes != want {
			t.Errorf("budget %s does not hold make size's %d B", id, want)
		}
	}
}

// Each bench row of this module whose benchmark has landed holds its allocations and bytes at every make
// check: 100 iterations each, read through CheckBudget at the merge gate. A row whose benchmark has not
// landed is reported missing.
func TestBudgetBenchmarksHoldTheirAllocations(t *testing.T) {
	repository := openThisCheckout(t)
	ledger := repository.budgets(t)
	packageNames := map[string][]string{}
	for _, budget := range ledger.Budgets {
		if budget.Kind != sidecartest.BudgetKindBench || budget.Module != "sidecar" {
			continue
		}
		packageNames[budget.Package] = append(packageNames[budget.Package], budget.Name)
	}
	results := []*sidecartest.BenchResult{}
	for _, packageName := range slices.Sorted(maps.Keys(packageNames)) {
		pattern := "^(" + strings.Join(packageNames[packageName], "|") + ")$"
		output, err := runGo(repository.moduleDirectory, goEnvironment(), "test", "-run", "^$", "-bench", pattern, "-benchtime", "100x", "-benchmem", "-count", "1", "./"+packageName)
		if err != nil {
			t.Fatal(err)
		}
		packageResults, err := sidecartest.ParseBenchOutput(output)
		if err != nil {
			t.Fatal(err)
		}
		for _, result := range packageResults {
			// a release tree's module path reads as the ledger's
			result.Package = "github.com/urnetwork/sidecar" + strings.TrimPrefix(result.Package, repository.modulePath)
		}
		results = append(results, packageResults...)
	}
	report := sidecartest.CheckBudget(ledger, results, sidecartest.BudgetGateMerge)
	for _, finding := range report.Findings {
		t.Error(finding)
	}
	for _, missing := range report.Missing {
		repository.report("budgets: missing, which is never a pass: %s", missing)
	}
	if len(report.Held) == 0 {
		t.Error("no budget held: the ledger's benchmarks did not run")
	}
}
