package fault

// M10's exit sweep (TEST-M10-05; gate_m10_out.go): its rows name each test where it runs, its written item reads every
// case's builder as M10's entry reads its left column's, its TLC item asks every mode M10's exit needs of EvsCommit and
// IndexRollup, its fuzz item names every target the registry gives M10, its scenario items read each tier apart, and
// its items say what the exit shows and what waits on the world.

import (
	"errors"
	"flag"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The flags only sidecar-gate M10's commands pass (gate_m10_out.go): the written check, and the TLC check.
var (
	gateM10OutWrittenFlagValue = flag.Bool(GateM10OutWrittenFlag, false, "report M10's written item for sidecar-gate M10")
	gateM10OutTlcFlagValue     = flag.Bool(GateM10OutTlcFlag, false, "report M10's TLC item for sidecar-gate M10")
)

// The cases M10's exit reads failing on this tree beyond those its entry reads failing (gateM10InKnownFailing), each
// with the task whose builder it is: each registered schedule asserts in its steps and names no invariant in Check
// (TEST.md's contract for schedule authors, rule 4), so no FI is checked after its steps, and the gate reads it fail
// until its owner names the FI its row checks. The gate's command reads them fail; this list only keeps the merge's run
// below to new failures. A case here that reads written is logged, to come off the list.
var gateM10OutKnownFailing = map[string]string{
	"FS-99's cards": "RECORD-M10-06",
	"FS-107":        "SEARCH-M10-36",
	"FS-108":        "SEARCH-M10-36",
	"FS-111":        "SEARCH-M10-37",
}

// M10's written item: its reason and outcome on the last two lines, failing the run only when a case fails. Without the
// flag, every case M10's exit looks for is checked and logged, and the test fails only on a failing builder that
// neither known list names, since a missing builder is the gate's to report and a known failure its owner's.
func TestGateM10CasesWritten(t *testing.T) {
	cases := GateM10OutWrittenCases(DefaultCatalog())
	result := GateCasesWritten(t.Context(), cases, Lookup, nil)
	if *gateM10OutWrittenFlagValue {
		// the tool reads the last outcome line and the line before it, so they are printed last
		fmt.Print(result.Lines())
		if result.Outcome == GateOutcomeFail {
			t.Fail()
		}
		return
	}
	t.Logf("%s: %s", result.Outcome, result.Reason)
	knownOwner := func(caseName string) (string, bool) {
		if owner, known := gateM10InKnownFailing[caseName]; known {
			return owner, true
		}
		owner, known := gateM10OutKnownFailing[caseName]
		return owner, known
	}
	failed := []string{}
	for _, failure := range result.Failed {
		failed = append(failed, failure.Case.String())
		if owner, known := knownOwner(failure.Case.String()); known {
			t.Logf("%s reads fail at the gate until %s names the invariants its schedule checks", failure.Case, owner)
			continue
		}
		t.Errorf("%s", failure.Reason)
	}
	for caseName := range gateM10OutKnownFailing {
		if !slices.ContainsFunc(cases, func(testCase *Case) bool { return testCase.String() == caseName }) {
			t.Errorf("gateM10OutKnownFailing names %s, which M10's exit does not look for", caseName)
		}
		if _, ok := gateM10InKnownFailing[caseName]; ok {
			t.Errorf("gateM10OutKnownFailing names %s, which gateM10InKnownFailing names already", caseName)
		}
		if !slices.Contains(failed, caseName) {
			t.Logf("%s reads written now: take it off gateM10OutKnownFailing", caseName)
		}
	}
}

// The written check reads each outcome as the tool reports it: every case written passes; a case registered on T2 alone
// whose row runs on T3 too, and a case with no builder, read missing, naming the case and tier; a failing builder
// fails, the missing ones said beside it; a case that waits on the world reads open; and a T4 part is not looked for.
func TestGateCasesWrittenReadsEachOutcome(t *testing.T) {
	catalog := DefaultCatalog()
	fs64, fs89, fs77 := catalog.Case("FS-64", ""), catalog.Case("FS-89", ""), catalog.Case("FS-77", "")
	both := &Registration{Row: "FS-64", Tiers: []Tier{TierT2, TierT3}, Build: gateFixtureWritten}
	t2Only := &Registration{Row: "FS-64", Tiers: []Tier{TierT2}, Build: gateFixtureWritten}
	empty := &Registration{Row: "FS-89", Tiers: []Tier{TierT2, TierT3}, Build: func(net *Net) *Schedule { return &Schedule{} }}
	// FS-77 runs on T2 and T4: a T2 builder is all it needs here
	fs77Registration := &Registration{Row: "FS-77", Tiers: []Tier{TierT2}, Build: gateFixtureWritten}

	result := GateCasesWritten(t.Context(), []*Case{fs64, fs77}, gateFixtureLookup(both, fs77Registration), nil)
	if result.Outcome != GateOutcomePass || len(result.Written) != 2 || !strings.HasPrefix(result.Reason, "of 2 cases, 2 written") {
		t.Errorf("every case written: %+v", result)
	}
	result = GateCasesWritten(t.Context(), []*Case{fs64, fs89}, gateFixtureLookup(t2Only), nil)
	if result.Outcome != GateOutcomeMissing || !slices.Equal(result.Missing, []string{"FS-64 on T3, registered on T2 alone", "FS-89 on T2"}) || !strings.Contains(result.Reason, "no builder is registered for FS-64 on T3") {
		t.Errorf("a T3 run with no builder and an unregistered case: %+v", result)
	}
	result = GateCasesWritten(t.Context(), []*Case{fs64, fs89}, gateFixtureLookup(t2Only, empty), nil)
	if result.Outcome != GateOutcomeFail || len(result.Failed) != 1 || result.Failed[0].Case != fs89 || !strings.Contains(result.Reason, "an empty builder") || !strings.Contains(result.Reason, "FS-64 on T3") {
		t.Errorf("a failing builder beside a missing one: %+v", result)
	}
	production := catalog.Case("FS-40", "production")
	if production == nil || production.Open == "" {
		t.Fatalf("FS-40's production case: %+v", production)
	}
	result = GateCasesWritten(t.Context(), []*Case{fs64, production}, gateFixtureLookup(both), nil)
	if result.Outcome != GateOutcomeOpen || len(result.Open) != 1 || !strings.Contains(result.Reason, "FS-40's production") {
		t.Errorf("a case that waits on the world: %+v", result)
	}
	// the lines the tool reads: the outcome last, the reason before it
	lines := result.Lines()
	matches := gateToolOutcomePattern.FindAllStringSubmatch("=== RUN   TestGateM10CasesWritten\n"+lines+"--- PASS: TestGateM10CasesWritten (0.00s)\nPASS\n", -1)
	if len(matches) != 1 || matches[0][1] != GateOutcomeOpen {
		t.Errorf("the tool reads %v", matches)
	}
}

// M10's written item looks for every case M10's exit holds, later-of cases among them, but FS-73 and FS-114's purge and
// drop cases, which its sweep names by their tests in place of a builder; and each of those is named so.
func TestGateM10WrittenCasesAreTheExitsBuildableCases(t *testing.T) {
	catalog := DefaultCatalog()
	cases := GateM10OutWrittenCases(catalog)
	names := []string{}
	for _, testCase := range cases {
		names = append(names, testCase.String())
	}
	if want := len(catalog.GateCases(gateM10OutGate)) - len(gateM10NoBuilderCases); len(cases) != want {
		t.Errorf("the written item looks for %d cases, want %d", len(cases), want)
	}
	for _, unwanted := range gateM10NoBuilderCases {
		if slices.Contains(names, unwanted) {
			t.Errorf("the written item looks for %s, which no builder can cover", unwanted)
		}
		named, ok := gateM10Sweep.Cases[unwanted]
		if !ok || len(named) == 0 || slices.ContainsFunc(named, func(test *GateTest) bool { return test.Repo != "server" }) {
			t.Errorf("%s is named by %s, not by its T3 tests alone", unwanted, gateTestsStringForTest(named))
		}
	}
	for _, want := range []string{"FS-64", "FS-66's hold", "FS-76's mailbox", "FS-83's app-host", "FS-101's r-file", "FS-112", "FS-125", "FS-125's app-host"} {
		if !slices.Contains(names, want) {
			t.Errorf("the written item does not look for %s", want)
		}
	}
}

// M10's TLC item: TEST-M2-08's tests of EvsCommit and IndexRollup in gate mode at M10's exit, with no TLC, so each
// passes only on the runs modelled.yml records at its model's sources of every mode M10's exit needs. Runs only under
// the flag, since it builds and runs another package's tests.
func TestGateM10ModelsPassTlc(t *testing.T) {
	if !*gateM10OutTlcFlagValue {
		t.Skip("runs from sidecar-gate M10's TLC item, under -" + GateM10OutTlcFlag)
	}
	quoted := []string{}
	for _, name := range gateM10OutTlcTests {
		quoted = append(quoted, regexp.QuoteMeta(name))
	}
	command := exec.CommandContext(t.Context(), "go", "test", "-count=1", "-v", "-tags", "sidecar_tlc", "-run", "^("+strings.Join(quoted, "|")+")$", ".")
	command.Dir = filepath.Join("..", "model")
	command.Env = gateTlcEnviron(os.Environ(), gateM10OutTlcGate)
	output, runErr := command.CombinedOutput()
	t.Logf("%s", output)
	outcome, reason := GateM10OutTlcOutcome(output, runErr)
	fmt.Printf("%s\n%s%s\n", reason, GateOutcomeLinePrefix, outcome)
	if outcome == GateOutcomeFail {
		t.Fail()
	}
}

// The test TEST-M2-08 runs each recorded mode of a model in (sidecartest/model/model_test.go), by model and mode.
var gateModelModeTestsForTest = map[string]map[string]string{
	"EvsCommit": {
		"model": "TestEvsCommitPassesTlcAtItsBounds", "mutants": "TestEvsCommitMutantsFailTlc", "live": "TestEvsCommitLivenessHolds",
		"mutants-purge": "TestEvsCommitPurgerMutantsFailTlc", "stories-purge": "TestEvsCommitPurgerStoriesPassTlc",
		"mutants-drop": "TestEvsCommitDropMutantsFailTlc", "stories-drop": "TestEvsCommitDropStoriesPassTlc", "live-drop": "TestEvsCommitDropLivenessHolds",
	},
	"IndexRollup": {"model": "TestIndexRollupPassesTlcAtItsBounds", "mutants": "TestIndexRollupMutantsFailTlc", "live": "TestIndexRollupLivenessHolds"},
}

// What the model tests read of modelled.yml: each model's milestones.
type gateModelledForTest struct {
	Models []*struct {
		Spec       string `yaml:"spec"`
		Milestones []*struct {
			Gate  string   `yaml:"gate"`
			Modes []string `yaml:"modes"`
		} `yaml:"milestones"`
	} `yaml:"models"`
}

// M10's TLC item asks, at M10's exit, for the test of every mode modelled.yml's milestones give EvsCommit and
// IndexRollup up to M10's exit, the drop extension's mutants, stories and liveness among them (QD-1116, QD-1119), and
// for no other: not StoreSettle's, which are M2's exit's, so a mode added to a milestone fails here until the item runs
// its test. Each test is declared in the model package under sidecar_tlc, and the environment names the gate and no TLC.
func TestGateM10TlcItemNeedsEveryModeOfItsModels(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "model", "modelled.yml"))
	if err != nil {
		t.Fatal(err)
	}
	modelled := &gateModelledForTest{}
	if err := yaml.Unmarshal(data, modelled); err != nil {
		t.Fatal(err)
	}
	needed := []string{}
	for _, model := range modelled.Models {
		modeTests, ok := gateModelModeTestsForTest[model.Spec]
		if !ok {
			continue
		}
		for _, milestone := range model.Milestones {
			if gateOrder(gateCatalogName(gateM10OutTlcGate)) < gateOrder(gateCatalogName(milestone.Gate)) {
				continue
			}
			for _, mode := range milestone.Modes {
				name, ok := modeTests[mode]
				if !ok {
					t.Errorf("%s's %s, which %s needs, has no test this item knows", model.Spec, mode, milestone.Gate)
					continue
				}
				needed = append(needed, name)
			}
		}
	}
	slices.Sort(needed)
	got := slices.Sorted(slices.Values(gateM10OutTlcTests))
	if !slices.Equal(got, needed) {
		t.Errorf("M10's TLC item runs %v, and M10's exit needs %v", got, needed)
	}
	for _, name := range []string{"TestEvsCommitDropMutantsFailTlc", "TestEvsCommitDropStoriesPassTlc", "TestEvsCommitDropLivenessHolds", "TestEvsCommitPurgerStoriesPassTlc", "TestIndexRollupLivenessHolds"} {
		if !slices.Contains(gateM10OutTlcTests, name) {
			t.Errorf("M10's TLC item does not run %s", name)
		}
	}
	for _, name := range gateM10OutTlcTests {
		if strings.HasPrefix(name, "TestStoreSettle") {
			t.Errorf("M10's TLC item runs %s, M2's exit's", name)
		}
	}
	repoDirectory, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, err := range GateTestDeclared(repoDirectory, &GateTest{Repo: "sidecar", Package: "./sidecartest/model", Tags: "sidecar_tlc", Names: gateM10OutTlcTests}) {
		t.Error(err)
	}
	environ := gateTlcEnviron([]string{"TLC=java -cp tla2tools.jar tlc2.TLC", "SIDECAR_TLC_GATE=M10-in"}, gateM10OutTlcGate)
	if !slices.Equal(environ, []string{"SIDECAR_TLC_MODE=gate", "SIDECAR_TLC_GATE=M10"}) {
		t.Errorf("M10's TLC item runs its tests in %v", environ)
	}
}

// go test -v's output of M10's TLC run, each of the item's tests given its verdict and line, a verdict "" leaving the
// test out.
func gateM10OutTlcFixtureOutput(verdicts map[string]string, lines map[string]string) []byte {
	var output strings.Builder
	for _, name := range gateM10OutTlcTests {
		verdict, ok := verdicts[name]
		if !ok {
			verdict = "PASS"
		}
		if verdict == "" {
			continue
		}
		line, ok := lines[name]
		if !ok {
			line = "model_test.go:73: the sources are unchanged since the passing runs, which stand; TLC need not rerun it"
		}
		output.WriteString("=== RUN   " + name + "\n    " + line + "\n" + fmt.Sprintf("--- %s: %s (0.01s)\n", verdict, name))
	}
	output.WriteString("PASS\n")
	return []byte(output.String())
}

// M10's TLC item reads the drop extension's modes through TEST-M2-08's tests: every mode standing passes; a mode's
// record not standing at its sources with no TLC here, which EvsCommit's every test reports at M10's exit, reads open,
// naming the tests, never pass; a drop twin TLC did not refuse, any other failure, a test with no verdict, or a run
// that never built fails.
func TestGateM10OutTlcOutcomeReadsTheDropExtensionsModes(t *testing.T) {
	if outcome, reason := GateM10OutTlcOutcome(gateM10OutTlcFixtureOutput(nil, nil), nil); outcome != GateOutcomePass || !strings.Contains(reason, "TestEvsCommitDropLivenessHolds") {
		t.Errorf("every mode standing: %s %q", outcome, reason)
	}
	notRunLine := "model_test.go:77: EvsCommit has no passing mutants-drop, stories-drop run at these sources: they changed since its last passing runs, or none is recorded, and TLC has not run: no tla2tools.jar (set TLC to a command that runs tlc2.TLC)"
	verdicts, lines := map[string]string{}, map[string]string{}
	for _, name := range gateM10OutTlcTests {
		if strings.HasPrefix(name, "TestEvsCommit") {
			verdicts[name], lines[name] = "FAIL", notRunLine
		}
	}
	if outcome, reason := GateM10OutTlcOutcome(gateM10OutTlcFixtureOutput(verdicts, lines), errors.New("exit status 1")); outcome != GateOutcomeOpen || !strings.Contains(reason, "TLC has not run") || !strings.Contains(reason, "TestEvsCommitDropStoriesPassTlc") || strings.Contains(reason, "TestIndexRollup") {
		t.Errorf("the drop extension's runs not standing: %s %q", outcome, reason)
	}
	twin := gateM10OutTlcFixtureOutput(
		map[string]string{"TestEvsCommitDropMutantsFailTlc": "FAIL"},
		map[string]string{"TestEvsCommitDropMutantsFailTlc": "model_test.go:91: TLC d8fb231: EvsCommit twin-DropNoFence: expected I-EVS-15 violated, got exit 0"},
	)
	if outcome, reason := GateM10OutTlcOutcome(twin, errors.New("exit status 1")); outcome != GateOutcomeFail || !strings.Contains(reason, "TestEvsCommitDropMutantsFailTlc") {
		t.Errorf("a drop twin not refused: %s %q", outcome, reason)
	}
	for _, name := range []string{"TestEvsCommitDropLivenessHolds", "TestIndexRollupPassesTlcAtItsBounds"} {
		if outcome, reason := GateM10OutTlcOutcome(gateM10OutTlcFixtureOutput(map[string]string{name: ""}, nil), nil); outcome != GateOutcomeFail || !strings.Contains(reason, name) {
			t.Errorf("%s with no verdict: %s %q", name, outcome, reason)
		}
	}
	if outcome, reason := GateM10OutTlcOutcome([]byte("# github.com/urnetwork/sidecar/sidecartest/model\nsyntax error\nFAIL\n"), errors.New("exit status 1")); outcome != GateOutcomeFail || !strings.Contains(reason, "did not build or run") {
		t.Errorf("no build: %s %q", outcome, reason)
	}
}

// M10's rows name each test where it runs: the T3 runs in evshost and the root package under the convention's tags on
// the private stores, beside each case's T2 test; FS-74's and FS-75's thin tests by their own names; FS-73 and FS-114's
// purge and drop cases by their T3 tests alone, the suite on T3's clusters rather than the private stores; each later-of
// case as the held gate names it (gate_held.go); and each keeps the catalog's external and store clock.
func TestGateM10NamesEachRowsTestsWhereTheyRun(t *testing.T) {
	catalog := DefaultCatalog()
	data, err := GateFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	t3 := func(packagePath string, names ...string) *GateTest {
		return &GateTest{Repo: "server", Package: packagePath, Tags: gateT3Tags, Stores: true, Names: names}
	}
	t2 := func(names ...string) *GateTest {
		return &GateTest{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: names}
	}
	suite := &GateTest{Repo: "server", Package: ".", Tags: "sidecar_filecluster_t3", Names: []string{"TestFileClusterSuitePassesOnT3"}}
	want := map[string][]*GateTest{
		"FS-68":             {t2("TestFs68"), t3("./evshost", "TestFs68OnT3")},
		"FS-72's migration": {t2("TestFs72Migration"), t3("./evshost", "TestFs72MigrationOnT3")},
		"FS-72's rollback":  {t2("TestFs72Rollback"), t3("./evshost", "TestFs72RollbackOnT3")},
		"FS-73":             {t3("./evshost", "TestFs73OnT3")},
		"FS-74":             {t2("TestFs74OnEvs"), t3(".", "TestFs74OnT3")},
		"FS-75":             {t2("TestFs75OnEvs"), t3(".", "TestFs75OnT3")},
		"FS-83":             {t2("TestFs83"), t3(".", "TestFs83OnT3")},
		"FS-89":             {t2("TestFs89"), t3("./evshost", "TestFs89OnT3")},
		"FS-91":             {t2("TestFs91"), t3("./evshost", "TestFs91OnT3")},
		"FS-94":             {t2("TestFs94"), t3("./evshost", "TestFs94OnT3")},
		"FS-95":             {t2("TestFs95"), t3("./evshost", "TestFs95OnT3")},
		"FS-107":            {t2("TestFs107"), t3(".", "TestFs107OnT3")},
		"FS-108":            {t2("TestFs108"), t3(".", "TestFs108OnT3")},
		"FS-111":            {t2("TestFs111"), t3(".", "TestFs111OnT3")},
		"FS-114's purge":    {suite},
		"FS-114's drop":     {suite},
	}
	// the later-of cases as the held gate names them, each of which M10's exit holds too
	for caseName, tests := range gateHeldCases(catalog) {
		want[caseName] = tests
	}
	for caseName, tests := range map[string][]*GateTest{
		"FS-66's hold":    {t2("TestFs66Hold"), t3("./model", "TestFs66HoldPlacedByApiOnT3")},
		"FS-87's index":   {t2("TestFs87Index"), t3(".", "TestFs87IndexOnT3")},
		"FS-99's cards":   {t2("TestFs99Cards"), t3(".", "TestFs99CardsOnT3")},
		"FS-101's r-file": {t2("TestFs101File")},
	} {
		if !reflect.DeepEqual(want[caseName], tests) {
			t.Errorf("the held gate names %s by %s, want %s", caseName, gateTestsStringForTest(want[caseName]), gateTestsStringForTest(tests))
		}
	}
	swept := slices.Sorted(maps.Keys(gateM10Cases(catalog)))
	wantSwept := slices.Sorted(maps.Keys(want))
	if !slices.Equal(swept, wantSwept) {
		t.Errorf("M10's sweep names %v, want %v", swept, wantSwept)
	}
	for caseName, tests := range want {
		rowId, name, _ := strings.Cut(caseName, "'s ")
		testCase := catalog.Case(rowId, name)
		row := gateFileRow(file, "M10", rowId, name)
		if testCase == nil || row == nil {
			t.Errorf("M10 has no %s", caseName)
			continue
		}
		if tests := gateWithClausesForTest(testCase, tests); !reflect.DeepEqual(row.Tests, tests) {
			t.Errorf("%s at M10 runs %s, want %s", caseName, gateTestsStringForTest(row.Tests), gateTestsStringForTest(tests))
		}
		if row.External != gateCaseExternal(testCase, gateM10OutGate) || row.StoreClock != testCase.StoreClock {
			t.Errorf("%s at M10: external %q, store clock %t, not the catalog's", caseName, row.External, row.StoreClock)
		}
	}
	// the cases left to the convention: no builder (FS-64), world tests under the convention's names with no builder
	// (FS-76, FS-112), a T2-only builder on a T2+T3 row (FS-80, FS-100's format-2), and the later-of cases no owner wrote
	// a test of (FS-76's hold, FS-125's app-host)
	for _, caseName := range []string{"FS-64", "FS-76", "FS-76's hold", "FS-80", "FS-100's format-2", "FS-112", "FS-125", "FS-125's app-host"} {
		rowId, name, _ := strings.Cut(caseName, "'s ")
		testCase := catalog.Case(rowId, name)
		if row := gateFileRow(file, "M10", rowId, name); testCase == nil || row == nil || !reflect.DeepEqual(row.Tests, gateConventionalTests(testCase)) {
			t.Errorf("%s at M10 does not keep the convention: %+v", caseName, row)
		}
	}
}

// M10's items say what the exit shows: the rules item first, naming the unknown list's rows at M10; the written, FI,
// store clock and TLC items with their commands; the observe item asserting deletes stay off by default in the engine,
// the host and the checked-in config, with nothing it waits on; what the world owes reading open with the world named;
// exactly the four items no test shows yet reading missing; every §22.7 row and scenario part at M10 with its
// registered tests; and no item an audit (R-TEST-6).
func TestGateM10ItemsSayWhatTheExitShows(t *testing.T) {
	catalog := DefaultCatalog()
	items, find := gateItemsForTest(t, "M10")
	if len(items) == 0 || !strings.HasPrefix(items[0].Item, "§22.8's rules on every row") {
		t.Fatalf("M10's items open with %+v", items)
	}
	for _, rowId := range []string{"FS-65", "FS-72", "FS-75"} {
		if !strings.Contains(items[0].Item, rowId) {
			t.Errorf("the rules item does not name %s, which M10's unknown list holds: %q", rowId, items[0].Item)
		}
	}
	if written := find("every case of M10's rows written"); len(written.Commands) != 1 || !slices.Equal(written.Commands[0].Command, gateM10OutWrittenCommand()) || written.External != "" {
		t.Errorf("the written item: %+v", written)
	}
	if invariants := find("every FI the rows check"); len(invariants.Commands) != 1 || !slices.Equal(invariants.Commands[0].Command, gateInvariantsCommand(gateM10OutGate)) {
		t.Errorf("the invariants item: %+v", invariants)
	}
	if clock := find("T3's store clock"); !strings.Contains(clock.Item, "FS-89") || !strings.Contains(clock.Item, "FS-114 never does") {
		t.Errorf("the store clock item: %+v", clock)
	}
	tlc := find("EvsCommit.tla with the purger and the drop extension, and IndexRollup.tla")
	if len(tlc.Commands) != 1 || !slices.Equal(tlc.Commands[0].Command, gateM10OutTlcCommand()) || tlc.Commands[0].Repo != "sidecar" || tlc.External != "" || !strings.Contains(tlc.Item, "F2DropsEnd") {
		t.Errorf("the TLC item: %+v", tlc)
	}
	observe := find("purge and drops stay in observe by default")
	for _, name := range []string{"TestFormat2GateTable", "TestFormat2GateFollowsTheHostAndFailsClosed", "TestHostFormat2GateReadsServersSidecarYml", "TestHostFormat2GateWithoutGatesIsClosed", "TestSidecarConfigFilesAreDark"} {
		if !slices.Contains(gateRowNamesForTest(observe), name) {
			t.Errorf("the observe item does not name %s", name)
		}
	}
	if observe.External != "" {
		t.Errorf("the observe item waits on %q, and deletes off by default is this tree's to show", observe.External)
	}
	projection := find("D-TEST-13's projection")
	if !strings.Contains(projection.Item, "never measured") || !strings.Contains(projection.Item, "reads open") || !strings.Contains(projection.External, "M2's nvme run") || len(projection.Tests) == 0 {
		t.Errorf("the projection item: %+v", projection)
	}
	for prefix, world := range map[string]string{
		"testdata/index/ fixed, its vectors byte-equal on every leg": "hardware:",
		"D-TEST-13's projection":                       "hardware and production:",
		"targets.yml":                                  "hardware and production:",
		"peers.yml and §22.9's git-lfs row":            "hardware:",
		"§22.8's search, remote and phone rows":        "hardware:",
		"§22.8's index row":                            "hardware:",
		"§22.8's directory row":                        "hardware and production:",
		"D-TEST-17's reading at the Team limit":        "hardware:",
		"§22.8's drop row":                             "hardware:",
		"§22.8's hdd and trash rows at M10":            "production:",
		"T4 at M10":                                    "devices:",
		"FS-125 held with PROTO-M10-05":                "people:",
		"D-TEST-12's and D-TEST-18's production soaks": "production:",
		"format 2's bytes freeze at M10's Gn-out":      "people:",
	} {
		if row := find(prefix); !strings.HasPrefix(row.External, world) {
			t.Errorf("%q waits on %q, not on %s", prefix, row.External, world)
		}
	}
	// what no test shows yet: nothing to run and nothing waited on, so the tool reads each missing
	wantMissing := []string{
		"D-TEST-12's observe evidence on T3", "the migration of a format-1 repo set", "a format-1 repo migrated through evs and then indexed, in one run",
		"D-OPS-21's drop job pace", "D-TEST-17's runs in physical time beyond the Team limit's hour",
	}
	asserts := sidecartest.DefaultPrivacyAsserts()
	scenarios := sidecartest.DefaultScenarioRegistry()
	privacy, scenario := 0, 0
	for _, item := range items {
		if strings.HasPrefix(item.Item, "§22.7's ") {
			continue
		}
		bare := len(item.Tests) == 0 && len(item.Commands) == 0 && item.External == ""
		if bare != slices.ContainsFunc(wantMissing, func(prefix string) bool { return strings.HasPrefix(item.Item, prefix) }) {
			t.Errorf("%q has nothing to run and waits on nothing: %t, against the items meant to read missing", item.Item, bare)
		}
	}
	for _, row := range asserts.Rows() {
		if !slices.Contains(row.Gates, gateM10OutGate) {
			continue
		}
		privacy += 1
		if item := find("§22.7's " + row.Id + " assertion"); len(item.Tests) != len(asserts.Tests(row.Id)) {
			t.Errorf("%s's item names %d tests, the registry %d", row.Id, len(item.Tests), len(asserts.Tests(row.Id)))
		}
	}
	for _, row := range scenarios.Rows() {
		if !slices.Contains(row.Gates, gateM10OutGate) {
			continue
		}
		for _, clause := range row.Parts() {
			for _, tier := range row.Tiers {
				scenario += 1
				part := &sidecartest.ScenarioPart{Row: row, Clause: clause}
				if item := find(fmt.Sprintf("§22.7's %s on %s", part, tier)); len(item.Tests) != len(scenarios.Tests(row.Id, clause, tier)) {
					t.Errorf("%s on %s's item names %d tests, the registry %d", part, tier, len(item.Tests), len(scenarios.Tests(row.Id, clause, tier)))
				}
			}
		}
	}
	if privacy != 3 || scenario != 4 {
		t.Errorf("M10 shows %d §22.7 assertions and %d scenario parts by tier, want 3 and 4 (S11 and S12 on T2 and T3)", privacy, scenario)
	}
	// §22.10's order first: the rules, the written check, the FI bindings, the store clock, TLC, then the evidence
	order := []string{
		"§22.8's rules on every row", "every case of M10's rows written", "every FI the rows check", "T3's store clock", "EvsCommit.tla with the purger",
		"testdata/index/ fixed", "D-TEST-13's projection", "D-TEST-12's observe check", "D-TEST-12's observe evidence on T3", "a migration of a format-1 repo",
		"format 2's fuzz seeds", "§22.7's query-canaries assertion", "§22.7's S11 on T2", "the CROSSSLOT lints", "format 2's bytes freeze",
	}
	last := -1
	for _, prefix := range order {
		index := slices.IndexFunc(items, func(row *GateRow) bool { return strings.HasPrefix(row.Item, prefix) })
		if index <= last {
			t.Errorf("%q is at %d, after %d", prefix, index, last)
		}
		last = index
	}
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.Item+item.External), "audit") {
			t.Errorf("an item names an audit: %+v", item)
		}
	}
	if len(catalog.GateCases(gateM10OutGate)) == 0 {
		t.Fatal("the catalog holds no case at M10's exit")
	}
}

// One target of testdata/fuzz/registry.yml as this test reads it.
type gateFuzzTargetForTest struct {
	Name      string `yaml:"name"`
	Package   string `yaml:"package"`
	Milestone string `yaml:"milestone"`
}

// What this test reads of the registry: each row's milestone and targets.
type gateFuzzRegistryForTest struct {
	Rows []*struct {
		Id        string                   `yaml:"id"`
		Milestone string                   `yaml:"milestone"`
		Targets   []*gateFuzzTargetForTest `yaml:"targets"`
	} `yaml:"rows"`
}

// The nested modules a registry package names first.
var gateFuzzNestedModulesForTest = []string{"cli", "mlsinterop", "smtpproof"}

// The fuzz item names every target testdata/fuzz/registry.yml gives M10, by its row's milestone or its own, in its own
// package, nested modules from their directories, and directory.proto's decoders beside them; each named target is
// one of those, and each is declared where the item names it.
func TestGateM10FuzzItemNamesEveryM10Target(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fuzz", "registry.yml"))
	if err != nil {
		t.Fatal(err)
	}
	registry := &gateFuzzRegistryForTest{}
	if err := yaml.Unmarshal(data, registry); err != nil {
		t.Fatal(err)
	}
	place := func(packagePath string) (string, string) {
		if packagePath == "." {
			return "", "."
		}
		first, rest, _ := strings.Cut(packagePath, "/")
		if slices.Contains(gateFuzzNestedModulesForTest, first) {
			if rest == "" {
				return first, "."
			}
			return first, "./" + rest
		}
		return "", "./" + packagePath
	}
	want := map[string]bool{}
	for _, row := range registry.Rows {
		for _, target := range row.Targets {
			milestone := target.Milestone
			if milestone == "" {
				milestone = row.Milestone
			}
			if milestone != "M10" {
				continue
			}
			directory, packagePath := place(target.Package)
			want[directory+"|"+packagePath+"|"+target.Name] = true
		}
	}
	want["|.|FuzzDirectoryDecode"] = true
	if len(want) < 20 {
		t.Fatalf("the registry gives M10 only %d targets: %v", len(want), want)
	}
	have := map[string]bool{}
	for _, test := range gateM10FuzzTests() {
		for _, name := range test.Names {
			have[test.Dir+"|"+test.Package+"|"+name] = true
		}
	}
	for key := range want {
		if !have[key] {
			t.Errorf("the fuzz item does not name %s", key)
		}
	}
	for key := range have {
		if !want[key] {
			t.Errorf("the fuzz item names %s, which the registry does not give M10", key)
		}
	}
	item := &GateRow{}
	for _, row := range GateRows(DefaultCatalog(), "M10") {
		if strings.HasPrefix(row.Item, "format 2's fuzz seeds") {
			item = row
		}
	}
	for _, test := range gateM10FuzzTests() {
		if !slices.ContainsFunc(item.Tests, func(named *GateTest) bool { return reflect.DeepEqual(named, test) }) {
			t.Errorf("the fuzz item does not run %s", gateTestsStringForTest([]*GateTest{test}))
		}
	}
}

// A scenario part reads each tier apart: a part registered on T2 alone has its T2 item run that test and its T3 item run
// nothing, which reads missing; a part on T6 reads open; a server test runs on the private stores; and a registration
// no entry can reach is said in its item.
func TestGateScenarioItemsReadEachTierApart(t *testing.T) {
	registry := sidecartest.NewScenarioRegistry()
	if err := registry.Register("S11", "", sidecartest.ScenarioTierT2, &sidecartest.ScenarioTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestScenarioS11", Tags: "sidecar_testhooks"}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("S12", "", sidecartest.ScenarioTierT3, &sidecartest.ScenarioTest{Repo: "server", Package: "github.com/urnetwork/server/sidecart3", Name: "TestScenarioS12OnT3", Tags: gateT3Tags}); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("S12", "", sidecartest.ScenarioTierT2, &sidecartest.ScenarioTest{Repo: "server", Package: "github.com/urnetwork/serverless", Name: "TestOutsideTheModule"}); err != nil {
		t.Fatal(err)
	}
	items := gateScenarioItems(registry, gateM10OutGate)
	byName := map[string]*GateItem{}
	for _, item := range items {
		name, _, _ := strings.Cut(item.Item, " (")
		byName[name] = item
	}
	if len(items) != 4 {
		t.Fatalf("%d items: %+v", len(items), byName)
	}
	if item := byName["§22.7's S11 on T2"]; item == nil || !reflect.DeepEqual(item.Tests, []*GateTest{{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{"TestScenarioS11"}}}) || item.External != "" || !strings.Contains(item.Item, "F11; SEARCH-M10-39") {
		t.Errorf("S11 on T2: %+v", item)
	}
	if item := byName["§22.7's S11 on T3"]; item == nil || len(item.Tests) != 0 || item.External != "" {
		t.Errorf("S11 on T3, registered nowhere: %+v", item)
	}
	if item := byName["§22.7's S12 on T3"]; item == nil || !reflect.DeepEqual(item.Tests, []*GateTest{{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{"TestScenarioS12OnT3"}}}) {
		t.Errorf("S12 on T3: %+v", item)
	}
	if item := byName["§22.7's S12 on T2"]; item == nil || len(item.Tests) != 0 || !strings.Contains(item.Item, "registrations no entry reaches") || !strings.Contains(item.Item, "TestOutsideTheModule") {
		t.Errorf("S12 on T2, its registration unreachable: %+v", item)
	}
	// S5 runs on T2, T3 and T6 at M5's exit: its T6 part reads open
	for _, item := range gateScenarioItems(registry, "M5-out") {
		if strings.HasPrefix(item.Item, "§22.7's S5 on T6") && !strings.HasPrefix(item.External, "T6:") {
			t.Errorf("S5 on T6: %+v", item)
		}
	}
}

// Every test M10's rows and items name in this repo, for a row outside the convention or for an item, is declared in
// its package in a file that builds under the entry's tags, and so is each the sdk names, in the sdk's checkout beside
// this one: a rename or a tag an owner adds fails here rather than only reading missing at the gate.
func TestGateM10SweepNamesSidecarAndSdkTestsDeclaredUnderTheirTags(t *testing.T) {
	catalog := DefaultCatalog()
	rows := GateRows(catalog, "M10")
	for _, name := range gateUndeclaredSidecarTestsForTest(t, catalog, rows) {
		t.Errorf("M10 names %s, which is not declared so", name)
	}
	declared := gateDeclaredBesideThisCheckout(t)
	sdkNames := 0
	for _, row := range rows {
		for _, test := range row.Tests {
			if test.Repo != "sdk" {
				continue
			}
			for _, err := range declared(test) {
				t.Error(err)
			}
			sdkNames += len(test.Names)
		}
	}
	if sdkNames < 6 {
		t.Errorf("M10 names %d sdk tests", sdkNames)
	}
}
