// §23.8's gate sweeps as server/local/sidecar-gate runs them (TEST-M1-11; C-18): catalog.yml is the one
// source for which FS rows and cases each gate shows, and GateFile turns it into the tool's gates.yml, so the
// tool never reads §23.6 for itself. Beside the rows, each gate's sweep registers the tests no convention
// can name and the items a gate shows that are no FS row: exit criteria, design closure, checks. gate_m1.go
// is M1's sweep, and every later sweep adds its gate_m<n>.go the same way.
//
// A case's tests are named by convention, never registered: its T2 test is TestFs<n><Case> in this package
// under sidecar_testhooks, the thin test that calls RunRow, and its T3 test is TestFs<n><Case>OnT3 in
// server's sidecart3, run on the private stores, where <Case> is the case's name in camel case and empty for
// the main part. A test nobody wrote reads missing in the tool's report, never pass, so the file need not
// change as rows land. A sweep names a case's tests in place of the convention only for a row that is no
// schedule, such as OPS's FS-54 and FS-55, which server's own tests show.
//
// Gates are named as the tool takes them: G0; Mn-in for milestone n's entry review; Mn for its exit
// review, Mn-out in the catalog; every for each Gn-out (FS-55), every-out in the catalog; next before
// place_new names a new metadata cluster, next-cluster in the catalog.
//
// The file is the tool's to read, and server's TestGatesYmlIsTheCatalogsGateMap holds it equal to GateFile,
// regenerating it on request. Safe for concurrent use: sweeps register from package-level vars.

package fault

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// One go test on one package, as gates.yml writes it: repo and dir name the module's directory under the
// monoroot, package the package in it, names the tests, each of which must report PASS. Stores runs it
// through the private-store wrapper; args go after the package.
type GateTest struct {
	Repo    string   `yaml:"repo"`
	Dir     string   `yaml:"dir,omitempty"`
	Package string   `yaml:"package"`
	Tags    string   `yaml:"tags,omitempty"`
	Stores  bool     `yaml:"stores,omitempty"`
	Names   []string `yaml:"names,flow"`
	Args    []string `yaml:"args,omitempty,flow"`
}

// One check that is no go test, run in a repo's directory: exit 0 passes.
type GateCommand struct {
	Repo    string   `yaml:"repo"`
	Dir     string   `yaml:"dir,omitempty"`
	Command []string `yaml:"command,flow"`
}

// What a gate shows beside its FS rows, with what shows it. External names what outside the build it also
// waits on, hardware, production or people, so it reads open however its tests do: never pass.
type GateItem struct {
	Item     string         `yaml:"item"`
	Tests    []*GateTest    `yaml:"tests,omitempty"`
	Commands []*GateCommand `yaml:"commands,omitempty"`
	External string         `yaml:"external,omitempty"`
}

// One row of gates.yml: an FS row's case, or an item.
type GateRow struct {
	Row      string         `yaml:"row,omitempty"`
	Case     string         `yaml:"case,omitempty"`
	Item     string         `yaml:"item,omitempty"`
	Tests    []*GateTest    `yaml:"tests,omitempty"`
	Commands []*GateCommand `yaml:"commands,omitempty"`
	External string         `yaml:"external,omitempty"`
	// The case's T3 run reads LastModified and ttls that T3's store clock translates onto the schedule's clock
	// (catalog.yml's store_clock, QD-264), which the tool's report says beside its outcome.
	StoreClock bool `yaml:"store_clock,omitempty"`
}

// One gate's sweep: the tests that show a case in place of the convention, keyed by Case.String(), and its
// items.
type GateSweep struct {
	// The tool's gate name.
	Gate  string
	Cases map[string][]*GateTest
	Items []*GateItem
}

var (
	gateSweepLock sync.Mutex
	gateSweeps    = map[string]*GateSweep{}
)

// Adds sweep's cases and items to its gate, from a package-level var. A case the catalog does not hold at
// the gate, or one named by two sweeps, panics, since the file it would write is wrong where it was written.
func RegisterGateSweep(sweep *GateSweep) *GateSweep {
	catalogGate := gateCatalogName(sweep.Gate)
	if catalogGate == "" && sweep.Gate != "G0" {
		panic(fmt.Sprintf("gate %q is no gate the tool takes", sweep.Gate))
	}
	for caseName := range sweep.Cases {
		found := false
		for _, testCase := range DefaultCatalog().GateCases(catalogGate) {
			if testCase.String() == caseName {
				found = true
			}
		}
		if !found {
			panic(fmt.Sprintf("gate %s's sweep names %s, which the catalog does not hold at %s", sweep.Gate, caseName, catalogGate))
		}
	}
	gateSweepLock.Lock()
	defer gateSweepLock.Unlock()
	merged := gateSweeps[sweep.Gate]
	if merged == nil {
		merged = &GateSweep{Gate: sweep.Gate, Cases: map[string][]*GateTest{}}
		gateSweeps[sweep.Gate] = merged
	}
	// every case checked before any is taken, so a refused sweep leaves nothing behind
	for caseName := range sweep.Cases {
		if _, ok := merged.Cases[caseName]; ok {
			panic(fmt.Sprintf("gate %s's %s is named by two sweeps", sweep.Gate, caseName))
		}
	}
	for caseName, tests := range sweep.Cases {
		merged.Cases[caseName] = tests
	}
	merged.Items = append(merged.Items, sweep.Items...)
	return sweep
}

// The gate's registered sweep, or an empty one.
func gateSweep(gate string) *GateSweep {
	gateSweepLock.Lock()
	defer gateSweepLock.Unlock()
	if sweep := gateSweeps[gate]; sweep != nil {
		return sweep
	}
	return &GateSweep{Gate: gate, Cases: map[string][]*GateTest{}}
}

// The catalog's name for the tool's gate, or "" for G0 and a name the tool does not take.
func gateCatalogName(gate string) string {
	switch gate {
	case "every":
		return GateEveryOut
	case "next":
		return GateNextCluster
	}
	if match := catalogGatePattern.FindStringSubmatch(gate); match != nil && match[2] == "in" {
		return gate
	}
	if milestone, ok := strings.CutPrefix(gate, "M"); ok {
		if n, err := strconv.Atoi(milestone); err == nil && 0 <= n && n <= 10 && strconv.Itoa(n) == milestone {
			return gate + "-out"
		}
	}
	return ""
}

// The tool's gates in review order: G0; then each milestone's entry and exit; then every and next.
func GateNames() []string {
	names := []string{"G0"}
	for n := 0; n <= 10; n += 1 {
		names = append(names, fmt.Sprintf("M%d-in", n), fmt.Sprintf("M%d", n))
	}
	return append(names, "every", "next")
}

// A case's name in camel case, for its tests' names: config-read is ConfigRead, format-1 Format1.
func gateCaseCamel(caseName string) string {
	var camel strings.Builder
	for _, word := range strings.Split(caseName, "-") {
		if word == "" {
			continue
		}
		camel.WriteString(strings.ToUpper(word[:1]) + word[1:])
	}
	return camel.String()
}

// The thin T2 test a case's row writes in fs<n>_test.go, which calls RunRow.
func GateT2TestName(testCase *Case) string {
	return "TestFs" + strconv.Itoa(testCase.Row.Number) + gateCaseCamel(testCase.Name)
}

// The T3 test server's sidecart3 runs the case's registration through.
func GateT3TestName(testCase *Case) string {
	return GateT2TestName(testCase) + "OnT3"
}

// The tests that show a case by convention: its T2 test here and its T3 test in server, on the tiers it runs
// on, a forged case's twin carrying T3.
func gateConventionalTests(testCase *Case) []*GateTest {
	tests := []*GateTest{}
	tiers := testCase.TwinTiers()
	if slices.Contains(tiers, TierT2) {
		tests = append(tests, &GateTest{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{GateT2TestName(testCase)}})
	}
	if slices.Contains(tiers, TierT3) {
		tests = append(tests, &GateTest{Repo: "server", Package: "./sidecart3", Tags: "sidecar_testhooks,sidecar_pending", Stores: true, Names: []string{GateT3TestName(testCase)}})
	}
	return tests
}

// What a case at gate waits on besides its tests: the catalog's open, a T4 part the tool cannot run
// (plan-TEST-small-readings reading 10), and the later gate of a later-of case.
func gateCaseExternal(testCase *Case, catalogGate string) string {
	parts := []string{}
	if testCase.Open != "" {
		parts = append(parts, testCase.Open+", as catalog.yml marks the case")
	}
	if slices.Contains(testCase.Tiers(), TierT4) {
		parts = append(parts, "its T4 part, which SDK-M8-15's and SDK-M10-06's cells run and this tool does not")
	}
	if testCase.LaterOf {
		later := slices.MaxFunc(testCase.Gates, func(a string, b string) int { return gateOrder(a) - gateOrder(b) })
		if later != catalogGate {
			parts = append(parts, "the later of "+strings.Join(testCase.Gates, " and ")+", where it passes (§23.6)")
		}
	}
	return strings.Join(parts, "; ")
}

// D-ARCH-4's assembly check, which G0 and every entry review runs (TEST-M1-12; R-ARCH-1, R-PHASE-1, D-PHASE-2):
// server's gate tool rebuilds DESIGN.md from design/source in a scratch copy and says its outcome, missing for a
// superseded-option hit nobody has read.
var gateAssemblyItem = &GateItem{
	Item:     "D-ARCH-4's assembly check: DESIGN.md rebuilt from design/source equals the checked-in one, validate.json clean, every superseded-option hit read, <me> only in PLAN quotations, and the Q- items added since the last gate listed (TEST-M1-12)",
	Commands: []*GateCommand{{Repo: "server", Command: []string{"go", "run", "./local/sidecar-gate", "assembly"}}},
}

// Every row of gate: the catalog's cases at it, in row order, each with its conventional tests or its
// sweep's; at G0 and an entry review, the assembly check; then its sweep's items.
func GateRows(catalog *Catalog, gate string) []*GateRow {
	sweep := gateSweep(gate)
	rows := []*GateRow{}
	if catalogGate := gateCatalogName(gate); catalogGate != "" {
		for _, testCase := range catalog.GateCases(catalogGate) {
			tests := gateConventionalTests(testCase)
			if named, ok := sweep.Cases[testCase.String()]; ok {
				tests = named
			}
			rows = append(rows, &GateRow{
				Row:        testCase.Row.Id,
				Case:       testCase.Name,
				Tests:      tests,
				External:   gateCaseExternal(testCase, catalogGate),
				StoreClock: testCase.StoreClock,
			})
		}
	}
	items := sweep.Items
	if gate == "G0" || strings.HasSuffix(gate, "-in") {
		items = append([]*GateItem{gateAssemblyItem}, items...)
	}
	for _, item := range items {
		rows = append(rows, &GateRow{Item: item.Item, Tests: item.Tests, Commands: item.Commands, External: item.External})
	}
	return rows
}

// The header gates.yml carries, which says it is generated and from what.
const gateFileHeader = `# §23.8's gate sweeps (TEST-M1-11; OPS-M1-07's tool): generated by sidecar's sidecartest/fault.GateFile from
# sidecartest/fault/catalog.yml, the one source for which FS rows and cases each gate shows (C-18), and from each
# gate's sweep in sidecartest/fault/gate*.go. Do not edit it: server's TestGatesYmlIsTheCatalogsGateMap fails when
# it differs, and SIDECAR_REGENERATE_GATES=1 go test ./local/sidecar-gate -run '^TestGatesYmlIsTheCatalogsGateMap$'
# writes it.
#
# Gates: G0; Mn-in, milestone n's entry review; Mn, its exit review (Mn-out); every, each Gn-out (FS-55); next,
# before place_new names a new metadata cluster. A row is an FS row's case, or an item: repo and package name
# each test, names are the tests, each of which must report PASS, so a test that does not exist reads missing,
# never pass; tags, a build tag; stores: true runs it through the private-store wrapper SIDECAR_GATE_STORE_WRAPPER
# names; args go after the package, {base} and {group} filled from the run; commands run in a repo's directory
# and pass on exit 0, or read the outcome a last "sidecar-gate outcome: <outcome>" line names, a nonzero exit still
# failing. A row with nothing to run is missing. external says what outside the build (hardware,
# production, people) the row also waits on, or the later gate a later-of case passes at, and reads open.
# store_clock: true says the case's T3 run reads stored ages through T3's store clock (QD-264), which the report
# names beside its outcome. A case's T2 test is TestFs<n><Case> in sidecar's sidecartest/fault and its T3 test
# TestFs<n><Case>OnT3 in server's sidecart3, by convention, so this file does not change as rows land.
`

// gates.yml's bytes for catalog: every gate in review order, each with its rows.
func GateFile(catalog *Catalog) ([]byte, error) {
	gates := &yaml.Node{Kind: yaml.MappingNode}
	for _, gate := range GateNames() {
		rows := &yaml.Node{Kind: yaml.SequenceNode}
		for _, row := range GateRows(catalog, gate) {
			node := &yaml.Node{}
			if err := node.Encode(row); err != nil {
				return nil, err
			}
			// a test or a command on one line, as a reader scans them
			for index := 0; index+1 < len(node.Content); index += 2 {
				if key := node.Content[index].Value; key == "tests" || key == "commands" {
					for _, entry := range node.Content[index+1].Content {
						entry.Style = yaml.FlowStyle
					}
				}
			}
			rows.Content = append(rows.Content, node)
		}
		if len(rows.Content) == 0 {
			rows.Style = yaml.FlowStyle
		}
		gates.Content = append(gates.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: gate}, rows)
	}
	document := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{{Kind: yaml.ScalarNode, Value: "gates"}, gates}}
	var encoded bytes.Buffer
	encoded.WriteString(gateFileHeader)
	encoder := yaml.NewEncoder(&encoded)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	return encoded.Bytes(), nil
}
