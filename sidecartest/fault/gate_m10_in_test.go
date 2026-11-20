package fault

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The flags only sidecar-gate M10-in's commands pass (gate_m10_in.go): one case's written check, and the TLC check.
var (
	gateM10InWrittenFlagValue = flag.String(GateM10InWrittenFlag, "", "the case, <row> or <row>/<case>, whose written check this run reports for sidecar-gate M10-in")
	gateM10InTlcFlagValue     = flag.Bool(GateM10InTlcFlag, false, "report M10-in's TLC item for sidecar-gate M10-in")
)

// GateTestDeclared over the checkouts beside this one, the monoroot being three directories above this package.
func gateDeclaredBesideThisCheckout(t *testing.T) func(test *GateTest) []error {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return func(test *GateTest) []error {
		return GateTestDeclared(filepath.Join(root, test.Repo), test)
	}
}

// The cases M10's entry reads failing on this tree, each with the task whose builder it is: each schedule asserts in
// its steps and names no invariant in Check (TEST.md's contract for schedule authors, rule 4), so no FI is checked
// after its steps, and the gate reads it fail until its owner names the FI its row checks. The gate's command reads
// them fail; this list only keeps the merge's run below to new failures. A case here that reads written is logged, to
// come off the list.
var gateM10InKnownFailing = map[string]string{
	"FS-74":            "SEARCH-M10-35",
	"FS-75":            "SEARCH-M10-35",
	"FS-87's index":    "RECORD-M10-06",
	"FS-88's searches": "RECORD-M10-06",
}

// One case's written check, as M10-in's item for it runs it: its reason and outcome on the last two lines, failing
// the run only when the case fails. Without the flag, every case M10's entry looks for is checked and logged, and the
// test fails only on one whose builder is empty or broken and that gateM10InKnownFailing does not name, since a
// missing case is the gate's to report.
func TestGateM10InRowWritten(t *testing.T) {
	declared := gateDeclaredBesideThisCheckout(t)
	if *gateM10InWrittenFlagValue != "" {
		testCase, err := GateM10InWrittenCase(DefaultCatalog(), *gateM10InWrittenFlagValue)
		if err != nil {
			fmt.Printf("%v\n%s%s\n", err, GateOutcomeLinePrefix, GateOutcomeFail)
			t.Fatal(err)
		}
		result := GateM10InWritten(t.Context(), testCase, Lookup, declared, nil)
		// the tool reads the last outcome line and the line before it, so they are printed last
		fmt.Print(result.Lines())
		if result.Outcome == GateOutcomeFail {
			t.Fail()
		}
		return
	}
	cases := GateM10InCases(DefaultCatalog())
	counts := map[string]int{}
	for _, testCase := range cases {
		result := GateM10InWritten(t.Context(), testCase, Lookup, declared, nil)
		counts[result.Outcome] += 1
		t.Logf("%s: %s", result.Outcome, result.Reason)
		owner, known := gateM10InKnownFailing[testCase.String()]
		switch {
		case result.Outcome == GateOutcomeFail && known:
			t.Logf("%s reads fail at the gate until %s names the invariants its schedule checks", testCase, owner)
		case result.Outcome == GateOutcomeFail:
			t.Errorf("%s", result.Reason)
		case known && result.Outcome == GateOutcomePass:
			t.Logf("%s reads written now: take it off gateM10InKnownFailing", testCase)
		}
	}
	for caseName := range gateM10InKnownFailing {
		if !slices.ContainsFunc(cases, func(testCase *Case) bool { return testCase.String() == caseName }) {
			t.Errorf("gateM10InKnownFailing names %s, which M10's entry does not look for", caseName)
		}
	}
	t.Logf("M10's entry looks for %d cases: %d written, %d missing, %d open, %d failing", len(cases), counts[GateOutcomePass], counts[GateOutcomeMissing], counts[GateOutcomeOpen], counts[GateOutcomeFail])
}

// M10-in's TLC item: TEST-M2-08's tests of EvsCommit and IndexRollup in gate mode, with no TLC, so each passes only on
// the runs modelled.yml records at the models' sources, beside modelled.yml's own check, whose digest of EvsCommit's
// sources says whether the purger's stories stand. Runs only under the flag, since it builds and runs another
// package's tests.
func TestGateM10InModelsPassTlc(t *testing.T) {
	if !*gateM10InTlcFlagValue {
		t.Skip("runs from sidecar-gate M10-in's TLC item, under -" + GateM10InTlcFlag)
	}
	quoted := []string{}
	for _, name := range append(slices.Clone(gateM10InTlcTests), gateModelledSourcesTest) {
		quoted = append(quoted, regexp.QuoteMeta(name))
	}
	command := exec.CommandContext(t.Context(), "go", "test", "-count=1", "-v", "-tags", "sidecar_tlc", "-run", "^("+strings.Join(quoted, "|")+")$", ".")
	command.Dir = filepath.Join("..", "model")
	// gate mode, and no TLC: this report reads recorded runs and starts none
	command.Env = slices.DeleteFunc(os.Environ(), func(variable string) bool {
		return strings.HasPrefix(variable, "TLC=") || strings.HasPrefix(variable, "SIDECAR_TLC_MODE=")
	})
	command.Env = append(command.Env, "SIDECAR_TLC_MODE=gate")
	output, runErr := command.CombinedOutput()
	t.Logf("%s", output)
	modelled, err := os.ReadFile(filepath.Join("..", "model", "modelled.yml"))
	if err != nil {
		fmt.Printf("modelled.yml: %v\n%s%s\n", err, GateOutcomeLinePrefix, GateOutcomeFail)
		t.Fatal(err)
	}
	outcome, reason := GateM10InTlcOutcome(output, runErr, modelled, nil)
	fmt.Printf("%s\n%s%s\n", reason, GateOutcomeLinePrefix, outcome)
	if outcome == GateOutcomeFail {
		t.Fail()
	}
}

// What a fixture's declared check answers: every test declared, or none.
func gateFixtureDeclared(declared bool) func(test *GateTest) []error {
	return func(test *GateTest) []error {
		if declared {
			return nil
		}
		errs := []error{}
		for _, name := range test.Names {
			errs = append(errs, fmt.Errorf("%s's %s names %s, which no test file there declares", test.Repo, test.Package, name))
		}
		return errs
	}
}

// M10's entry looks for every case M10's exit holds of FS-64 to FS-81 and FS-83 to FS-96, later-of cases included,
// and for nothing else: not FS-82's, not the M6 parts of the directory's rows, not FS-85, which has no case at M10, not
// format 1's cases of FS-72 and FS-95 (M2's), and not the M10 rows past FS-96, whose writing is the exit's to read.
func TestGateM10InCasesAreTheLeftColumnsRows(t *testing.T) {
	catalog := DefaultCatalog()
	cases := GateM10InCases(catalog)
	inRange := func(number int) bool { return (64 <= number && number <= 81) || (83 <= number && number <= 96) }
	for _, testCase := range cases {
		if !inRange(testCase.Row.Number) || !testCase.AtGate("M10-out") {
			t.Errorf("M10's entry looks for %s, at %v", testCase, testCase.Gates)
		}
	}
	for _, testCase := range catalog.GateCases("M10-out") {
		if inRange(testCase.Row.Number) && !slices.Contains(cases, testCase) {
			t.Errorf("M10's entry leaves out %s", testCase)
		}
	}
	names := []string{}
	for _, testCase := range cases {
		names = append(names, testCase.String())
	}
	for _, want := range []string{
		"FS-64", "FS-66", "FS-66's hold", "FS-69", "FS-72's migration", "FS-72's rollback", "FS-73", "FS-76's team-record", "FS-76's mailbox",
		"FS-77's app-host", "FS-81", "FS-83", "FS-83's app-host", "FS-83's team", "FS-84's cards", "FS-86's cards", "FS-87's index", "FS-88's searches",
		"FS-92", "FS-95", "FS-96",
	} {
		if !slices.Contains(names, want) {
			t.Errorf("M10's entry does not look for %s: %v", want, names)
		}
	}
	for _, unwanted := range []string{
		"FS-72's format-1", "FS-82's statement", "FS-84's entries", "FS-85", "FS-86's announce-entries", "FS-87", "FS-88", "FS-95's format-1",
		"FS-107", "FS-114's purge", "FS-114's drop", "FS-125",
	} {
		if slices.Contains(names, unwanted) {
			t.Errorf("M10's entry looks for %s, which is not format 2's left column", unwanted)
		}
	}
	// FS-85 has no item because it has no case at M10, which this holds
	if fs85 := catalog.Row("FS-85"); slices.ContainsFunc(fs85.Cases, func(testCase *Case) bool { return testCase.AtGate("M10-out") }) {
		t.Errorf("FS-85 has a case at M10's exit, which M10's entry would look for: %+v", fs85.Cases)
	}
}

// A written row reports pass, on T2 where its case runs there, T4's cases too.
func TestGateM10InWrittenReportsAWrittenRowAsPass(t *testing.T) {
	catalog := DefaultCatalog()
	for _, c := range []struct {
		rowId    string
		caseName string
	}{{rowId: "FS-64"}, {rowId: "FS-77", caseName: "app-host"}, {rowId: "FS-84", caseName: "cards"}, {rowId: "FS-66", caseName: "hold"}} {
		testCase := catalog.Case(c.rowId, c.caseName)
		lookup := gateFixtureLookup(&Registration{Row: c.rowId, Case: c.caseName, Tiers: []Tier{TierT2}, Build: gateFixtureWritten})
		result := GateM10InWritten(t.Context(), testCase, lookup, gateFixtureDeclared(false), nil)
		if result.Outcome != GateOutcomePass || result.Tier != TierT2 || !strings.Contains(result.Reason, "1 steps checking FI-1") {
			t.Errorf("%s: %+v", testCase, result)
		}
	}
}

// An empty builder fails, and so does a builder with nothing to check, a refusal with no twin, or a panic: a declared
// test of the case elsewhere excuses none of it.
func TestGateM10InWrittenFailsAnEmptyBuilder(t *testing.T) {
	catalog := DefaultCatalog()
	cases := []struct {
		name    string
		rowId   string
		builder Builder
		want    string
	}{
		{name: "empty", rowId: "FS-65", builder: func(net *Net) *Schedule { return &Schedule{} }, want: "an empty builder"},
		{name: "no check", rowId: "FS-89", builder: func(net *Net) *Schedule {
			schedule := gateFixtureWritten(net)
			schedule.Check = nil
			return schedule
		}, want: "checks nothing"},
		{name: "a refusal with no twin", rowId: "FS-95", builder: func(net *Net) *Schedule {
			schedule := gateFixtureWritten(net)
			schedule.Refuses = "a fixture's refusal"
			return schedule
		}, want: "names no twin"},
		{name: "panics", rowId: "FS-96", builder: func(net *Net) *Schedule { panic("a fixture's builder") }, want: "panicked"},
	}
	for _, c := range cases {
		lookup := gateFixtureLookup(&Registration{Row: c.rowId, Tiers: []Tier{TierT2}, Build: c.builder})
		result := GateM10InWritten(t.Context(), catalog.Case(c.rowId, ""), lookup, gateFixtureDeclared(true), nil)
		if result.Outcome != GateOutcomeFail || !strings.Contains(result.Reason, c.want) {
			t.Errorf("%s: %+v", c.name, result)
		}
	}
	// FS-73 runs on T3 alone: a builder registered for it is read as any builder is, and an empty one fails, whatever
	// the sweep names
	lookup := gateFixtureLookup(&Registration{Row: "FS-73", Tiers: []Tier{TierT3}, Build: func(net *Net) *Schedule { return &Schedule{} }})
	result := GateM10InWritten(t.Context(), catalog.Case("FS-73", ""), lookup, gateFixtureDeclared(true), nil)
	if result.Outcome != GateOutcomeFail || result.Tier != TierT3 || !strings.Contains(result.Reason, "an empty builder") {
		t.Errorf("FS-73's empty builder: %+v", result)
	}
}

// A row no builder covers reads missing, never pass, a builder on the wrong tier being no cover either; FS-73, which
// no builder can cover, is written only once each test M10's exit sweep names for it is declared.
func TestGateM10InWrittenReportsAMissingRowAsMissing(t *testing.T) {
	catalog := DefaultCatalog()
	result := GateM10InWritten(t.Context(), catalog.Case("FS-89", ""), gateFixtureLookup(), gateFixtureDeclared(true), nil)
	if result.Outcome != GateOutcomeMissing || !strings.Contains(result.Reason, "no T2 builder is registered") {
		t.Fatalf("FS-89 unregistered: %+v", result)
	}
	// FS-64 runs on T2 and T3, and a T3 builder alone leaves its T2 schedule missing, a declared T3 test or not
	result = GateM10InWritten(t.Context(), catalog.Case("FS-64", ""), gateFixtureLookup(&Registration{Row: "FS-64", Tiers: []Tier{TierT3}, Build: gateFixtureWritten}), gateFixtureDeclared(true), nil)
	if result.Outcome != GateOutcomeMissing {
		t.Fatalf("a T3 builder for a T2 case: %+v", result)
	}
	// FS-72's rollback runs on T2 and T3 and its sweep names both tests: a declared test is no builder there
	result = GateM10InWritten(t.Context(), catalog.Case("FS-72", "rollback"), gateFixtureLookup(), gateFixtureDeclared(true), nil)
	if result.Outcome != GateOutcomeMissing {
		t.Fatalf("FS-72's rollback with no builder: %+v", result)
	}
	// FS-73 with its test not declared where the sweep names it
	result = GateM10InWritten(t.Context(), catalog.Case("FS-73", ""), gateFixtureLookup(), gateFixtureDeclared(false), nil)
	if result.Outcome != GateOutcomeMissing || result.Tier != TierT3 || !strings.Contains(result.Reason, "runs on T3 alone") || !strings.Contains(result.Reason, "TestFs73OnT3, which no test file there declares") {
		t.Fatalf("FS-73 undeclared: %+v", result)
	}
	// and declared: written, as the tests the sweep names
	result = GateM10InWritten(t.Context(), catalog.Case("FS-73", ""), gateFixtureLookup(), gateFixtureDeclared(true), nil)
	if result.Outcome != GateOutcomePass || result.Tier != TierT3 || !strings.Contains(result.Reason, "server's ./evshost TestFs73OnT3") || !strings.Contains(result.Reason, "QD-995") {
		t.Fatalf("FS-73 declared: %+v", result)
	}
}

// What M10-in's written check prints is what the tool reads, as M2-in's is: its outcome on the last line, its reason
// on the line before; and a command names its case so the test finds it again, a case M10's entry does not look for
// being refused.
func TestGateM10InWrittenCommandNamesItsCase(t *testing.T) {
	catalog := DefaultCatalog()
	for _, testCase := range GateM10InCases(catalog) {
		command := gateM10InWrittenCommand(testCase)
		argument, ok := strings.CutPrefix(command[len(command)-1], "-"+GateM10InWrittenFlag+"=")
		if !ok {
			t.Fatalf("%s's command: %v", testCase, command)
		}
		found, err := GateM10InWrittenCase(catalog, argument)
		if err != nil || found != testCase {
			t.Errorf("%s's argument %q finds %v: %v", testCase, argument, found, err)
		}
	}
	for _, argument := range []string{"FS-72/format-1", "FS-82/statement", "FS-84/entries", "FS-85", "FS-107", "FS-1", "FS-73/no-such-case", "FS-999", ""} {
		if _, err := GateM10InWrittenCase(catalog, argument); err == nil {
			t.Errorf("%q was taken", argument)
		}
	}
	result := &GateWrittenResult{Outcome: GateOutcomeMissing, Reason: "FS-89: no T2 builder is registered"}
	output := "=== RUN   TestGateM10InRowWritten\n" + result.Lines() + "--- PASS: TestGateM10InRowWritten (0.00s)\nPASS\n"
	matches := gateToolOutcomePattern.FindAllStringSubmatch(output, -1)
	if len(matches) != 1 || matches[0][1] != GateOutcomeMissing {
		t.Errorf("the tool reads %v", matches)
	}
}

// go test -v's output of M10-in's TLC run, each test given its verdict and lines, and modelled.yml's check logging
// EvsCommit's and IndexRollup's digests.
func gateM10InTlcFixtureOutput(verdicts map[string]string, lines map[string]string, evsCommitDigest string) []byte {
	var output strings.Builder
	for _, name := range gateM10InTlcTests {
		verdict, ok := verdicts[name]
		if !ok {
			verdict = "PASS"
		}
		if verdict == "" {
			continue
		}
		output.WriteString("=== RUN   " + name + "\n")
		line, ok := lines[name]
		if !ok {
			line = "model_test.go:66: its sources are unchanged since its passing runs, which stand; TLC need not rerun it"
		}
		output.WriteString("    " + line + "\n")
		output.WriteString(fmt.Sprintf("--- %s: %s (0.01s)\n", verdict, name))
	}
	modelledVerdict, ok := verdicts[gateModelledSourcesTest]
	if !ok {
		modelledVerdict = "PASS"
	}
	output.WriteString("=== RUN   " + gateModelledSourcesTest + "\n")
	if evsCommitDigest != "-" {
		output.WriteString("    modelled_test.go:478: EvsCommit: 121 source files, digest " + evsCommitDigest + ", 2 runs recorded\n")
	}
	output.WriteString("    modelled_test.go:478: StoreSettle: 9 source files, digest 5c09, 7 runs recorded\n")
	output.WriteString("    modelled_test.go:478: IndexRollup: 40 source files, digest 3835, 3 runs recorded\n")
	output.WriteString(fmt.Sprintf("--- %s: %s (0.02s)\n", modelledVerdict, gateModelledSourcesTest))
	output.WriteString("PASS\n")
	return []byte(output.String())
}

// M10-in's TLC item reads the recorded runs: each test passing and the purger's stories standing at EvsCommit's
// sources passes; the stories missing, recorded at other sources or failed reads open, never fail, as TLC not run at
// a model's sources does; any other failure, a test with no verdict, modelled.yml's check failing, no digest, or a run
// that never built fails. Nothing the drop extension owes reads fail here: its pass is M10's exit's.
func TestGateM10InTlcOutcomeReadsTheRecordedRuns(t *testing.T) {
	digest := "aa01"
	modelled := func(runs string) []byte {
		return []byte("models:\n  - spec: EvsCommit\n    owners: [EVS1-M2-02, EVSB-M10-07]\n    runs:\n" + runs + "  - spec: IndexRollup\n    runs: []\n")
	}
	standing := modelled("      - {at: 2026-11-19, mode: model, result: pass, sources_sha256: aa01}\n      - {at: 2026-11-19, mode: stories, result: pass, sources_sha256: aa01, states: 9}\n")
	passing := gateM10InTlcFixtureOutput(nil, nil, digest)
	if outcome, reason := GateM10InTlcOutcome(passing, nil, standing, nil); outcome != GateOutcomePass || !strings.Contains(reason, "stand at its sources too") {
		t.Errorf("all standing: %s %q", outcome, reason)
	}
	// the gate's three modes stand and the purger's stories do not: open, saying why, never pass and never fail
	for name, runs := range map[string][]byte{
		"none recorded":         modelled("      - {at: 2026-11-19, mode: model, result: pass, sources_sha256: aa01}\n"),
		"at other sources":      modelled("      - {at: 2026-11-18, mode: stories, result: pass, sources_sha256: bb02}\n"),
		"failed at the sources": modelled("      - {at: 2026-11-19, mode: stories, result: fail, sources_sha256: aa01}\n"),
		"another model's":       []byte("models:\n  - spec: IndexRollup\n    runs:\n      - {mode: stories, result: pass, sources_sha256: aa01}\n"),
	} {
		outcome, reason := GateM10InTlcOutcome(passing, nil, runs, nil)
		if outcome != GateOutcomeOpen || !strings.Contains(reason, "no passing stories run of EvsCommit") || !strings.Contains(reason, "digest aa01") {
			t.Errorf("stories %s: %s %q", name, outcome, reason)
		}
	}
	// TLC not run at a model's sources reads open, whatever the stories
	notRun := gateM10InTlcFixtureOutput(
		map[string]string{"TestIndexRollupPassesTlcAtItsBounds": "FAIL"},
		map[string]string{"TestIndexRollupPassesTlcAtItsBounds": "model_test.go:71: IndexRollup's sources changed since its last passing runs, or none is recorded, and TLC has not run: no tla2tools.jar"},
		digest)
	if outcome, reason := GateM10InTlcOutcome(notRun, errors.New("exit status 1"), standing, nil); outcome != GateOutcomeOpen || !strings.Contains(reason, "TLC has not run") || !strings.Contains(reason, "TestIndexRollupPassesTlcAtItsBounds") {
		t.Errorf("IndexRollup not run: %s %q", outcome, reason)
	}
	// a failure that is not TLC's absence fails
	failing := gateM10InTlcFixtureOutput(
		map[string]string{"TestEvsCommitMutantsFailTlc": "FAIL"},
		map[string]string{"TestEvsCommitMutantsFailTlc": "model_test.go:52: modelled.yml has no EvsCommit"},
		digest)
	if outcome, reason := GateM10InTlcOutcome(failing, errors.New("exit status 1"), standing, nil); outcome != GateOutcomeFail || !strings.Contains(reason, "TestEvsCommitMutantsFailTlc") {
		t.Errorf("a failure: %s %q", outcome, reason)
	}
	// IndexRollup's liveness with no verdict fails: each of its modes is the entry's
	noVerdict := gateM10InTlcFixtureOutput(map[string]string{"TestIndexRollupLivenessHolds": ""}, nil, digest)
	if outcome, _ := GateM10InTlcOutcome(noVerdict, nil, standing, nil); outcome != GateOutcomeFail {
		t.Errorf("a test with no verdict: %s", outcome)
	}
	// modelled.yml's own check failing
	refused := gateM10InTlcFixtureOutput(map[string]string{gateModelledSourcesTest: "FAIL"}, nil, digest)
	if outcome, reason := GateM10InTlcOutcome(refused, errors.New("exit status 1"), standing, nil); outcome != GateOutcomeFail || !strings.Contains(reason, gateModelledSourcesTest) {
		t.Errorf("modelled.yml's check failing: %s %q", outcome, reason)
	}
	// no digest logged for EvsCommit, or an empty one
	for _, logged := range []string{"-", ""} {
		output := gateM10InTlcFixtureOutput(nil, nil, logged)
		if outcome, reason := GateM10InTlcOutcome(output, nil, standing, nil); outcome != GateOutcomeFail || !strings.Contains(reason, "no sources digest") {
			t.Errorf("digest %q: %s %q", logged, outcome, reason)
		}
	}
	// a modelled.yml that does not parse
	if outcome, reason := GateM10InTlcOutcome(passing, nil, []byte("models: [\n"), nil); outcome != GateOutcomeFail || !strings.Contains(reason, "does not parse") {
		t.Errorf("an unparsed modelled.yml: %s %q", outcome, reason)
	}
	// a run that never built
	if outcome, reason := GateM10InTlcOutcome([]byte("# github.com/urnetwork/sidecar/sidecartest/model\nsyntax error\nFAIL\n"), errors.New("exit status 1"), standing, nil); outcome != GateOutcomeFail || !strings.Contains(reason, "did not build or run") {
		t.Errorf("no build: %s %q", outcome, reason)
	}
}

// M10-in's sweep: D-ARCH-4's assembly first, then §22.10's left column for format 2 in its order, each case M10's
// entry looks for its own written item, each review open with nothing to run, the vectors' families with their tests
// and the cards' vectors reading missing, and no item waiting on the drop extension or naming an audit.
func TestGateM10InSweepNamesItsItems(t *testing.T) {
	catalog := DefaultCatalog()
	rows := GateRows(catalog, "M10-in")
	if len(rows) == 0 || !strings.HasPrefix(rows[0].Item, "D-ARCH-4's assembly check") {
		t.Fatalf("M10-in opens with %+v", rows)
	}
	for _, row := range rows {
		if row.Row != "" {
			t.Errorf("M10-in holds the FS row %s, which runs at M10's exit, not its entry", row.Row)
		}
	}
	itemOf := func(prefix string) *GateRow {
		for _, row := range rows {
			if strings.HasPrefix(row.Item, prefix) {
				return row
			}
		}
		return nil
	}
	cases := GateM10InCases(catalog)
	for _, testCase := range cases {
		row := itemOf(testCase.String() + " written as a test against the fakes")
		if row == nil || len(row.Commands) != 1 || len(row.Tests) != 0 || row.External != "" {
			t.Errorf("%s's written item: %+v", testCase, row)
			continue
		}
		if !slices.Equal(row.Commands[0].Command, gateM10InWrittenCommand(testCase)) || row.Commands[0].Repo != "sidecar" {
			t.Errorf("%s's written command: %+v", testCase, row.Commands[0])
		}
	}
	written := 0
	for _, row := range rows {
		if strings.Contains(row.Item, " written as a test against the fakes") {
			written += 1
		}
	}
	if written != len(cases) {
		t.Errorf("%d written items for %d cases", written, len(cases))
	}
	// an open review: nothing to run, and what it waits on, so the tool reads it open
	for _, prefix := range []string{"peer review of format 2's schemas", "§23.6's M10 design closure", "the changes since the last gate"} {
		row := itemOf(prefix)
		if row == nil || len(row.Tests) != 0 || len(row.Commands) != 0 || !strings.HasPrefix(row.External, "people:") {
			t.Errorf("%q: %+v", prefix, row)
		}
	}
	tlc := itemOf("EvsCommit.tla with the purger and IndexRollup.tla passing TLC")
	if tlc == nil || len(tlc.Commands) != 1 || !slices.Equal(tlc.Commands[0].Command, gateM10InTlcCommand()) || tlc.Commands[0].Repo != "sidecar" || tlc.External != "" {
		t.Errorf("the TLC item: %+v", tlc)
	}
	for _, prefix := range []string{"the vector schemas fixed, §11's format 2", "the vector schemas fixed, the index", "the vector schemas fixed, format 2's protos"} {
		row := itemOf(prefix)
		if row == nil || len(row.Tests) == 0 || len(row.Commands) != 0 || row.External != "" {
			t.Errorf("%q: %+v", prefix, row)
			continue
		}
		for _, test := range row.Tests {
			if test.Repo != "sidecar" || test.Package == "" || len(test.Names) == 0 || test.Stores {
				t.Errorf("%q names an incomplete test: %+v", prefix, test)
			}
		}
	}
	// nothing to run and nothing it waits on: the tool reads it missing until a vector pins a card's bytes
	cards := itemOf("the vector schemas fixed, directory.proto's cards and repo files")
	if cards == nil || len(cards.Tests) != 0 || len(cards.Commands) != 0 || cards.External != "" {
		t.Errorf("the cards' vectors: %+v", cards)
	}
	// §22.10's order: the peer review, TLC, the rows, the vectors, then the closure and the review
	order := []string{"peer review of format 2's schemas", "EvsCommit.tla with the purger", "FS-64 written", "FS-96 written", "the vector schemas fixed, §11's format 2", "§23.6's M10 design closure", "the changes since the last gate"}
	last := -1
	for _, prefix := range order {
		index := slices.IndexFunc(rows, func(row *GateRow) bool { return strings.HasPrefix(row.Item, prefix) })
		if index <= last {
			t.Errorf("%q is at %d, after %d", prefix, index, last)
		}
		last = index
	}
	for _, row := range rows {
		text := strings.ToLower(row.Item + row.External)
		// no item is an external audit (R-TEST-6)
		if strings.Contains(text, "audit") {
			t.Errorf("an item names an audit: %+v", row)
		}
		// the drop extension's TLC pass is M10's exit's: no item here is its check, and only the TLC item says so
		if strings.Contains(text, "drop extension") && row != tlc {
			t.Errorf("an item other than the TLC item names the drop extension: %+v", row)
		}
	}
	if !strings.Contains(tlc.Item, "the drop extension's pass is M10's exit's") {
		t.Errorf("the TLC item does not say the drop extension's pass is the exit's: %q", tlc.Item)
	}
}

// Every sidecar test M10-in's items and commands name is declared in its package, in a file go test builds on this
// host with the entry's tags: the vectors' tests, the two tests the commands run here, and the model tests the TLC
// check runs under sidecar_tlc. A renamed test fails here before its item reads missing at the gate.
func TestGateM10InNamesSidecarTestsDeclaredUnderTheirTags(t *testing.T) {
	repoDirectory, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	tests := []*GateTest{
		{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{"TestGateM10InRowWritten", "TestGateM10InModelsPassTlc"}},
		{Repo: "sidecar", Package: "./sidecartest/model", Tags: "sidecar_tlc", Names: append(slices.Clone(gateM10InTlcTests), gateModelledSourcesTest)},
	}
	for _, row := range GateRows(DefaultCatalog(), "M10-in") {
		tests = append(tests, row.Tests...)
	}
	checked := 0
	for _, test := range tests {
		if test.Repo != "sidecar" {
			t.Errorf("M10-in names %s's %s, and its items name only sidecar tests", test.Repo, test.Package)
			continue
		}
		for _, err := range GateTestDeclared(repoDirectory, test) {
			t.Error(err)
		}
		checked += len(test.Names)
	}
	if checked < 50 {
		t.Errorf("only %d sidecar tests of M10-in's were checked", checked)
	}
}

// A fixture's written check never runs a schedule: a builder whose steps would fail still reads written, its run
// being the exit sweep's.
func TestGateM10InWrittenRunsNoStep(t *testing.T) {
	ran := false
	builder := func(net *Net) *Schedule {
		return &Schedule{
			Steps: []*Step{{Actor: "writer", Action: func(ctx context.Context, net *Net) error {
				ran = true
				return errors.New("a fixture's step that must not run")
			}}},
			Check: []Invariant{FI(16)},
		}
	}
	result := GateM10InWritten(t.Context(), DefaultCatalog().Case("FS-67", ""), gateFixtureLookup(&Registration{Row: "FS-67", Tiers: []Tier{TierT2}, Build: builder}), gateFixtureDeclared(true), nil)
	if result.Outcome != GateOutcomePass || ran || !strings.Contains(result.Reason, "checking FI-16") {
		t.Fatalf("%+v, ran %t", result, ran)
	}
}
