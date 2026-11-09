package sidecartest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The repository's own ledger parses, and its size rows hold the size gate's numbers (§18.4, §18.10).
func TestTheBudgetLedgerParses(t *testing.T) {
	ledger, err := LoadBudgets()
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]int64{
		"ios-extension-device-role": 1024 * 1024,
		"page-worker-wasm":          41943040,
	} {
		budget := ledger.Budget(id)
		if budget == nil || budget.Limits.Bytes == nil || *budget.Limits.Bytes != want {
			t.Errorf("%s does not hold %d B", id, want)
		}
	}
	for _, budget := range ledger.Budgets {
		if budget.Kind == BudgetKindPath && (budget.Limits.Postgres == nil || *budget.Limits.Postgres != 0) {
			t.Errorf("%s lets an inline path reach PostgreSQL (I-12)", budget.Id)
		}
	}
}

// The parser is strict: each broken ledger fails, naming its row.
func TestTheBudgetLedgerRefusesWhatItDoesNotHold(t *testing.T) {
	row := func(fields string) string {
		return "budgets:\n  - {id: a-row, spec: s, kind: bench, owner: ACL-M2-02, module: sidecar, package: \".\", name: BenchmarkA, limits: {allocs_per_op: 0}" + fields + "}\n"
	}
	cases := []struct {
		yaml string
		want string
	}{
		{row(", unknown: 1"), "field unknown not found"},
		{row("") + "  - {id: a-row, spec: s, kind: bench, owner: ACL-M2-02, module: sidecar, name: BenchmarkB, limits: {allocs_per_op: 0}}\n", "a second row with this id"},
		{strings.Replace(row(""), "kind: bench", "kind: wall", 1), `kind "wall"`},
		{strings.Replace(row(""), "owner: ACL-M2-02", "owner: someone", 1), "is no task"},
		{strings.Replace(row(""), "module: sidecar", "module: connect", 1), `module "connect"`},
		{strings.Replace(row(""), "{allocs_per_op: 0}", "{bytes: 1}", 1), "a limit its kind does not take"},
		{strings.Replace(row(""), "name: BenchmarkA, ", "", 1), "no name says what measures it"},
		{"budgets:\n  - {id: a-path, spec: s, kind: path, owner: SOCK-M5-17, module: server, name: sockets.find, limits: {postgres: 1, redis_calls: 1}}\n", "I-12"},
		{"budgets:\n  - {id: a-path, spec: s, kind: path, owner: SOCK-M5-17, module: server, name: sockets.find, limits: {redis_calls: 1}}\n", "no limit of its kind"},
		{row("") + "---\nbudgets: []\n", "a second document"},
		{strings.Replace(row(""), "id: a-row", "id: A Row", 1), "lower case words"},
	}
	for _, c := range cases {
		if _, err := ParseBudgets([]byte(c.yaml)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.yaml, err, c.want)
		}
	}
	if _, err := ParseBudgets([]byte(row(""))); err != nil {
		t.Errorf("a whole row: %v", err)
	}
}

// A benchmark that allocates where its row allows none fails CheckBudget: the allocation is real, made by
// a benchmark testing.Benchmark runs here, and read back from go test's own output form.
func TestAPlantedAllocationFailsCheckBudget(t *testing.T) {
	sink := [][]byte{}
	allocating := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			sink = append(sink[:0], make([]byte, 64))
		}
	})
	clean := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		total := 0
		for index := range b.N {
			total += index
		}
		_ = total
	})
	output := fmt.Sprintf(
		"goos: darwin\npkg: github.com/urnetwork/sidecar/planted\nBenchmarkPlanted-8\t%s\t%s\nBenchmarkClean-8\t%s\t%s\nPASS\n",
		allocating.String(), allocating.MemString(), clean.String(), clean.MemString(),
	)
	results, err := ParseBenchOutput([]byte(output))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := ParseBudgets([]byte(`budgets:
  - {id: planted, spec: "§22.5", kind: bench, owner: ACL-M2-02, module: sidecar, package: planted, name: BenchmarkPlanted, limits: {allocs_per_op: 0}}
  - {id: clean, spec: "§22.5", kind: bench, owner: ACL-M2-02, module: sidecar, package: planted, name: BenchmarkClean, limits: {allocs_per_op: 0, ns_per_op: 0.001}}
  - {id: unset, spec: "§22.5", kind: bench, owner: PROTO-M5-05, module: sidecar, package: planted, name: BenchmarkUnset, limits: {}}
  - {id: elsewhere, spec: "§22.5", kind: bench, owner: ACL-M2-02, module: sidecar, package: other, name: BenchmarkElsewhere, limits: {allocs_per_op: 0}}
`))
	if err != nil {
		t.Fatal(err)
	}
	report := CheckBudget(ledger, results, BudgetGateMerge)
	if len(report.Findings) != 1 || !strings.Contains(report.Findings[0], "planted: BenchmarkPlanted makes 1 allocs/op, over its 0") {
		t.Errorf("findings %q", report.Findings)
	}
	if !slices.Equal(report.Held, []string{"clean"}) {
		t.Errorf("held %q: the clean row's time is not a merge's to judge", report.Held)
	}
	if len(report.Missing) != 1 || !strings.Contains(report.Missing[0], "unset: BenchmarkUnset did not run") {
		t.Errorf("missing %q", report.Missing)
	}
	// on T5 the clean row's time is judged too
	if report := CheckBudget(ledger, results, BudgetGateT5); len(report.Findings) != 2 {
		t.Errorf("t5 findings %q", report.Findings)
	}
	if report := CheckBudget(ledger, results, "nightly"); len(report.Findings) != 1 {
		t.Errorf("an unknown gate: %q", report.Findings)
	}
}

// A run without -benchmem is refused, and -count's repeats keep their worst.
func TestParseBenchOutputNeedsBenchmem(t *testing.T) {
	if _, err := ParseBenchOutput([]byte("pkg: x\nBenchmarkA-8   100   12.5 ns/op\n")); err == nil {
		t.Error("a run without -benchmem parsed")
	}
	results, err := ParseBenchOutput([]byte("pkg: x\nBenchmarkA-8 100 12.5 ns/op 0 B/op 0 allocs/op\nBenchmarkA-8 100 14.5 ns/op 16 B/op 1 allocs/op\nBenchmarkA 100 13.5 ns/op 0 B/op 0 allocs/op\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].NsPerOp != 14.5 || results[0].AllocsPerOp != 1 || results[0].BytesPerOp != 16 || results[0].Package != "x" {
		t.Errorf("results %+v", results[0])
	}
}

// The benchmark functions a directory's test files declare.
func declaredBenchmarks(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, entry.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil && strings.HasPrefix(function.Name.Name, "Benchmark") {
				names = append(names, function.Name.Name)
			}
		}
	}
	return names
}

// Each of this module's bench rows names a benchmark its package declares once its owner lands it, and
// a row whose benchmark is not there yet reads missing, never held. The rows whose owners have landed
// resolve now.
func TestEveryBenchRowResolvesOrReadsMissing(t *testing.T) {
	ledger, err := LoadBudgets()
	if err != nil {
		t.Fatal(err)
	}
	path, err := BudgetsPath()
	if err != nil {
		t.Fatal(err)
	}
	top := filepath.Dir(filepath.Dir(path))
	resolved := []string{}
	for _, budget := range ledger.Budgets {
		if budget.Kind != BudgetKindBench || budget.Module != "sidecar" {
			continue
		}
		if slices.Contains(declaredBenchmarks(t, filepath.Join(top, budget.Package)), budget.Name) {
			resolved = append(resolved, budget.Id)
			continue
		}
		t.Logf("missing, which is never a pass: %s's %s is not in %s yet (%s)", budget.Id, budget.Name, budget.Package, budget.Owner)
	}
	for _, id := range []string{"acl-gate-reach", "acl-gate-may-dial", "acl-gate-evs-access", "bridge-classify"} {
		if !slices.Contains(resolved, id) {
			t.Errorf("%s's benchmark has landed and the row does not resolve to it", id)
		}
	}
}
