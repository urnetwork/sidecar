// D-TEST-3's ledger, testdata/budgets.yml: §22.5's hot-path gates and §22.9's platform budgets, each with
// what measures it and the task that owns it. The file's header says what each field means.
//
// Each kind is held by its own tool: CheckBudget holds a go test -bench -benchmem run to the bench rows,
// server's sidecart3.InlinePath an inline path to its path row, make size the size rows, and T4's cells
// and T5 the memory rows. check/'s budgets rule fails a limit raised above the sidecar branch's with no
// new reviewed line, and runs the bench rows' benchmarks at every make check for their allocations.
//
// Time is held only at the t5 gate: a shared machine's clock says nothing about a path's cost, so a merge
// reads allocations, bytes and operation counts, which hold anywhere (R-TEST-2).

package sidecartest

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// What a row measures.
const (
	BudgetKindBench  = "bench"
	BudgetKindPath   = "path"
	BudgetKindSize   = "size"
	BudgetKindMemory = "memory"
)

// Where CheckBudget reads a run.
const (
	// Each merge: allocations, bytes and operation counts.
	BudgetGateMerge = "merge"
	// A quiet T5 host: time too.
	BudgetGateT5 = "t5"
)

// Where the ledger is, from the top of the sidecar repository.
const budgetsPath = "testdata/budgets.yml"

// The ledger.
type BudgetLedger struct {
	Budgets []*Budget `yaml:"budgets"`
}

// One gate.
type Budget struct {
	Id       string        `yaml:"id"`
	Spec     string        `yaml:"spec"`
	Kind     string        `yaml:"kind"`
	Owner    string        `yaml:"owner"`
	Module   string        `yaml:"module"`
	Package  string        `yaml:"package"`
	Name     string        `yaml:"name"`
	Settings string        `yaml:"settings"`
	Limits   *BudgetLimits `yaml:"limits"`
	Reviewed string        `yaml:"reviewed"`
	Note     string        `yaml:"note"`
}

// A row's limits. nil is a limit its owner has not set, which reads missing.
type BudgetLimits struct {
	NsPerOp     *float64 `yaml:"ns_per_op"`
	AllocsPerOp *int64   `yaml:"allocs_per_op"`
	BytesPerOp  *int64   `yaml:"bytes_per_op"`
	Postgres    *int64   `yaml:"postgres"`
	RedisCalls  *int64   `yaml:"redis_calls"`
	Bytes       *int64   `yaml:"bytes"`
}

var (
	budgetIdPattern    = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	budgetOwnerPattern = regexp.MustCompile(`^[A-Z0-9]+-M[0-9]+-[0-9]{2}$`)
	budgetKinds        = []string{BudgetKindBench, BudgetKindPath, BudgetKindSize, BudgetKindMemory}
	budgetModules      = []string{"sidecar", "server"}
)

// A ledger module's import path as the ledger reads it, for matching a run's packages. A release tree's
// module path carries its /v2026 suffix (§4.9), so a caller there maps its packages onto this first.
func BudgetModulePath(module string) string {
	return "github.com/urnetwork/" + module
}

// The row's package as an import path, empty when the row names none.
func (self *Budget) ImportPath() string {
	switch self.Package {
	case "":
		return ""
	case ".":
		return BudgetModulePath(self.Module)
	}
	return BudgetModulePath(self.Module) + "/" + self.Package
}

// The ledger in data, strictly: a field no row has, a second document, a duplicate id, an unknown kind,
// module or owner, a limit its kind does not take, and an inline path allowed a PostgreSQL acquisition
// (I-12) each fail.
func ParseBudgets(data []byte) (*BudgetLedger, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	ledger := &BudgetLedger{}
	if err := decoder.Decode(ledger); err != nil {
		return nil, fmt.Errorf("budgets: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("budgets: a second document")
	}
	ids := map[string]bool{}
	for index, budget := range ledger.Budgets {
		problem := budget.problem()
		if problem == "" && ids[budget.Id] {
			problem = "a second row with this id"
		}
		if problem != "" {
			return nil, fmt.Errorf("budgets: row %d (%s): %s", index+1, budget.Id, problem)
		}
		ids[budget.Id] = true
	}
	return ledger, nil
}

// What breaks the row's own rules, or empty.
func (self *Budget) problem() string {
	switch {
	case !budgetIdPattern.MatchString(self.Id):
		return "an id that is not lower case words joined by hyphens"
	case self.Spec == "":
		return "no spec says where the number comes from"
	case !slices.Contains(budgetKinds, self.Kind):
		return fmt.Sprintf("kind %q", self.Kind)
	case !budgetOwnerPattern.MatchString(self.Owner):
		return fmt.Sprintf("owner %q is no task", self.Owner)
	case !slices.Contains(budgetModules, self.Module):
		return fmt.Sprintf("module %q", self.Module)
	case self.Limits == nil:
		return "no limits"
	case self.Kind != BudgetKindMemory && self.Name == "":
		return "no name says what measures it"
	}
	limits := self.Limits
	allowed := map[string][]bool{
		BudgetKindBench:  {limits.NsPerOp != nil || limits.AllocsPerOp != nil || limits.BytesPerOp != nil, limits.Postgres == nil && limits.RedisCalls == nil && limits.Bytes == nil},
		BudgetKindPath:   {limits.Postgres != nil, limits.NsPerOp == nil && limits.AllocsPerOp == nil && limits.BytesPerOp == nil && limits.Bytes == nil},
		BudgetKindSize:   {limits.Bytes != nil, limits.NsPerOp == nil && limits.AllocsPerOp == nil && limits.BytesPerOp == nil && limits.Postgres == nil && limits.RedisCalls == nil},
		BudgetKindMemory: {limits.Bytes != nil, limits.NsPerOp == nil && limits.AllocsPerOp == nil && limits.BytesPerOp == nil && limits.Postgres == nil && limits.RedisCalls == nil},
	}[self.Kind]
	if !allowed[1] {
		return "a limit its kind does not take"
	}
	if !allowed[0] && self.Kind != BudgetKindBench {
		return "no limit of its kind"
	}
	if self.Kind == BudgetKindPath && *limits.Postgres != 0 {
		return "an inline path allowed a PostgreSQL acquisition (I-12)"
	}
	return ""
}

// The row with id, or nil.
func (self *BudgetLedger) Budget(id string) *Budget {
	for _, budget := range self.Budgets {
		if budget.Id == id {
			return budget
		}
	}
	return nil
}

// The row of kind measured by name, or nil.
func (self *BudgetLedger) Named(kind string, name string) *Budget {
	for _, budget := range self.Budgets {
		if budget.Kind == kind && budget.Name == name {
			return budget
		}
	}
	return nil
}

// Where the ledger is: testdata/budgets.yml in the nearest directory above the working directory that
// holds one, or in its sidecar sibling, which is how server's tests find it.
func BudgetsPath() (string, error) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for directory := workingDirectory; ; directory = filepath.Dir(directory) {
		for _, candidate := range []string{
			filepath.Join(directory, budgetsPath),
			filepath.Join(directory, "sidecar", budgetsPath),
		} {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
		}
		if directory == filepath.Dir(directory) {
			return "", fmt.Errorf("no %s above %s", budgetsPath, workingDirectory)
		}
	}
}

// The ledger BudgetsPath finds.
func LoadBudgets() (*BudgetLedger, error) {
	path, err := BudgetsPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseBudgets(data)
}

// One benchmark of a go test -bench -benchmem run.
type BenchResult struct {
	// Its package's import path, from the run's pkg: line.
	Package string
	// The benchmark's name without the -N GOMAXPROCS suffix.
	Name        string
	Iterations  int64
	NsPerOp     float64
	BytesPerOp  int64
	AllocsPerOp int64
}

var benchLinePattern = regexp.MustCompile(`^(Benchmark[^\s]*?)(-[0-9]+)?\s+([0-9]+)\s+(.*)$`)

// The benchmarks of a go test -bench -benchmem run, from its text. A benchmark line without B/op and
// allocs/op is an error, since a run without -benchmem says nothing of allocations. A benchmark run
// more than once (-count) is kept at its worst.
func ParseBenchOutput(output []byte) ([]*BenchResult, error) {
	results := []*BenchResult{}
	packagePath := ""
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if after, found := strings.CutPrefix(line, "pkg: "); found {
			packagePath = strings.TrimSpace(after)
			continue
		}
		match := benchLinePattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		iterations, err := strconv.ParseInt(match[3], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", line, err)
		}
		result := &BenchResult{Package: packagePath, Name: match[1], Iterations: iterations, BytesPerOp: -1, AllocsPerOp: -1}
		fields := strings.Fields(match[4])
		for index := 0; index+1 < len(fields); index += 2 {
			value, unit := fields[index], fields[index+1]
			switch unit {
			case "ns/op":
				result.NsPerOp, err = strconv.ParseFloat(value, 64)
			case "B/op":
				result.BytesPerOp, err = strconv.ParseInt(value, 10, 64)
			case "allocs/op":
				result.AllocsPerOp, err = strconv.ParseInt(value, 10, 64)
			}
			if err != nil {
				return nil, fmt.Errorf("%q: %w", line, err)
			}
		}
		if result.BytesPerOp < 0 || result.AllocsPerOp < 0 {
			return nil, fmt.Errorf("%q: no B/op and allocs/op, so the run was not -benchmem", line)
		}
		index := slices.IndexFunc(results, func(other *BenchResult) bool {
			return other.Package == result.Package && other.Name == result.Name
		})
		if index < 0 {
			results = append(results, result)
			continue
		}
		worst := results[index]
		worst.NsPerOp = max(worst.NsPerOp, result.NsPerOp)
		worst.BytesPerOp = max(worst.BytesPerOp, result.BytesPerOp)
		worst.AllocsPerOp = max(worst.AllocsPerOp, result.AllocsPerOp)
	}
	return results, scanner.Err()
}

// What a bench run says against the ledger.
type BudgetReport struct {
	// A limit a result exceeds, each a failure.
	Findings []string
	// A bench row of a package the run measured whose benchmark the run did not have, or one with a
	// limit its owner has not set: missing, which is never a pass.
	Missing []string
	// The rows held, each limit within.
	Held []string
}

// Holds results to the ledger's bench rows of the packages the run measured: at BudgetGateMerge their
// allocations and bytes, at BudgetGateT5 their time too. A row of a package outside the run is not
// reported here; a row of one inside it whose benchmark did not run reads missing.
func CheckBudget(ledger *BudgetLedger, results []*BenchResult, gate string) *BudgetReport {
	report := &BudgetReport{}
	if gate != BudgetGateMerge && gate != BudgetGateT5 {
		report.Findings = append(report.Findings, fmt.Sprintf("no gate %q: merge or t5", gate))
		return report
	}
	measured := map[string]bool{}
	for _, result := range results {
		measured[result.Package] = true
	}
	for _, budget := range ledger.Budgets {
		if budget.Kind != BudgetKindBench || !measured[budget.ImportPath()] {
			continue
		}
		index := slices.IndexFunc(results, func(result *BenchResult) bool {
			return result.Package == budget.ImportPath() && result.Name == budget.Name
		})
		if index < 0 {
			report.Missing = append(report.Missing, fmt.Sprintf("%s: %s did not run in %s", budget.Id, budget.Name, budget.ImportPath()))
			continue
		}
		result := results[index]
		limits := budget.Limits
		findings := []string{}
		if limits.AllocsPerOp != nil && *limits.AllocsPerOp < result.AllocsPerOp {
			findings = append(findings, fmt.Sprintf("%s: %s makes %d allocs/op, over its %d (%s)", budget.Id, budget.Name, result.AllocsPerOp, *limits.AllocsPerOp, budget.Spec))
		}
		if limits.BytesPerOp != nil && *limits.BytesPerOp < result.BytesPerOp {
			findings = append(findings, fmt.Sprintf("%s: %s allocates %d B/op, over its %d (%s)", budget.Id, budget.Name, result.BytesPerOp, *limits.BytesPerOp, budget.Spec))
		}
		if gate == BudgetGateT5 && limits.NsPerOp != nil && *limits.NsPerOp < result.NsPerOp {
			findings = append(findings, fmt.Sprintf("%s: %s takes %.1f ns/op, over its %.1f (%s)", budget.Id, budget.Name, result.NsPerOp, *limits.NsPerOp, budget.Spec))
		}
		if limits.AllocsPerOp == nil && limits.BytesPerOp == nil && limits.NsPerOp == nil {
			report.Missing = append(report.Missing, fmt.Sprintf("%s: %s ran, and its owner %s has set no limit", budget.Id, budget.Name, budget.Owner))
			continue
		}
		report.Findings = append(report.Findings, findings...)
		if len(findings) == 0 {
			report.Held = append(report.Held, budget.Id)
		}
	}
	return report
}
