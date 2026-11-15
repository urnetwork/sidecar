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

// The flags only sidecar-gate M2-in's commands pass (gate_m2_in.go): one case's written check, and the TLC check.
var (
	gateWrittenFlagValue = flag.String(GateWrittenFlag, "", "the case, <row> or <row>/<case>, whose written check this run reports for sidecar-gate M2-in")
	gateTlcFlagValue     = flag.Bool(GateTlcFlag, false, "report M2-in's TLC item for sidecar-gate M2-in")
)

// How server's gate tool reads a command's outcome (server/local/sidecar-gate's runGateCommand).
var gateToolOutcomePattern = regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(GateOutcomeLinePrefix) + `(pass|fail|missing|open|listed)$`)

// One case's written check, as M2-in's item for it runs it: its reason and outcome on the last two lines, failing
// the run only when the case fails. Without the flag, every case M2's exit holds is checked and logged, and the test
// fails only on one whose builder is empty or broken, since a missing case is the gate's to report.
func TestGateM2InRowWritten(t *testing.T) {
	if *gateWrittenFlagValue != "" {
		testCase, err := GateWrittenCase(DefaultCatalog(), *gateWrittenFlagValue)
		if err != nil {
			fmt.Printf("%v\n%s%s\n", err, GateOutcomeLinePrefix, GateOutcomeFail)
			t.Fatal(err)
		}
		result := GateWritten(t.Context(), testCase, Lookup, nil)
		// the tool reads the last outcome line and the line before it, so they are printed last
		fmt.Print(result.Lines())
		if result.Outcome == GateOutcomeFail {
			t.Fail()
		}
		return
	}
	counts := map[string]int{}
	for _, testCase := range DefaultCatalog().GateCases(gateM2InRowsGate) {
		result := GateWritten(t.Context(), testCase, Lookup, nil)
		counts[result.Outcome] += 1
		t.Logf("%s: %s", result.Outcome, result.Reason)
		if result.Outcome == GateOutcomeFail {
			t.Errorf("%s", result.Reason)
		}
	}
	t.Logf("M2's exit holds %d cases: %d written, %d missing, %d open, %d failing", len(DefaultCatalog().GateCases(gateM2InRowsGate)), counts[GateOutcomePass], counts[GateOutcomeMissing], counts[GateOutcomeOpen], counts[GateOutcomeFail])
}

// M2-in's TLC item: TEST-M2-08's tests of EvsCommit and StoreSettle in gate mode, with no TLC, so each passes only on
// the runs modelled.yml records at the models' sources. Runs only under the flag, since it builds and runs another
// package's tests.
func TestGateM2InModelsPassTlc(t *testing.T) {
	if !*gateTlcFlagValue {
		t.Skip("runs from sidecar-gate M2-in's TLC item, under -" + GateTlcFlag)
	}
	quoted := []string{}
	for _, name := range gateM2InTlcTests {
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
	outcome, reason := GateTlcOutcome(output, runErr, gateM2InTlcTests)
	fmt.Printf("%s\n%s%s\n", reason, GateOutcomeLinePrefix, outcome)
	if outcome == GateOutcomeFail {
		t.Fail()
	}
}

// A fixture lookup: registrations by row and case, on the tiers each names.
func gateFixtureLookup(registrations ...*Registration) func(rowId string, caseName string, tier Tier) *Registration {
	return func(rowId string, caseName string, tier Tier) *Registration {
		for _, registration := range registrations {
			if registration.Row == rowId && registration.Case == caseName && slices.Contains(registration.Tiers, tier) {
				return registration
			}
		}
		return nil
	}
}

// A schedule that steps and checks, as a written row's builder builds one.
func gateFixtureWritten(net *Net) *Schedule {
	return &Schedule{
		Steps: []*Step{{Actor: "writer", Action: func(ctx context.Context, net *Net) error { return nil }}},
		Check: []Invariant{FI(1)},
	}
}

// A written row reports pass, naming its tier, its steps and what it checks.
func TestGateWrittenReportsAWrittenRowAsPass(t *testing.T) {
	catalog := DefaultCatalog()
	testCase := catalog.Case("FS-9", "")
	result := GateWritten(t.Context(), testCase, gateFixtureLookup(&Registration{Row: "FS-9", Tiers: []Tier{TierT2}, Build: gateFixtureWritten}), nil)
	if result.Outcome != GateOutcomePass || result.Tier != TierT2 || !strings.Contains(result.Reason, "1 steps checking FI-1") {
		t.Fatalf("%+v", result)
	}
	// a refusal with its twin is written when the twin steps too
	refusal := Twin(gateFixtureWritten, gateFixtureWritten)
	withTwin := func(net *Net) *Schedule {
		schedule := refusal(net)
		schedule.Refuses = "a fixture's refusal"
		return schedule
	}
	result = GateWritten(t.Context(), catalog.Case("FS-10", ""), gateFixtureLookup(&Registration{Row: "FS-10", Tiers: []Tier{TierT2}, Build: withTwin}), nil)
	if result.Outcome != GateOutcomePass || !strings.Contains(result.Reason, "its twin 1 steps") {
		t.Fatalf("a forged refusal with its twin: %+v", result)
	}
	// a case on T3 alone is looked up on T3 and built on T2's Net, where nothing runs
	result = GateWritten(t.Context(), catalog.Case("FS-5", ""), gateFixtureLookup(&Registration{Row: "FS-5", Tiers: []Tier{TierT3}, Build: gateFixtureWritten}), nil)
	if result.Outcome != GateOutcomePass || result.Tier != TierT3 {
		t.Fatalf("a T3 case: %+v", result)
	}
	// what the row checks and the schedule does not name is said, not failed
	if !strings.Contains(result.Reason, "names no FI-9 by id") {
		t.Errorf("FS-5's unnamed check: %q", result.Reason)
	}
}

// An empty builder fails, and so does every other way a builder can show nothing: no check, a nil step, no
// schedule, a panic, a refusal or forgery with no twin, and a twin that is empty or refuses.
func TestGateWrittenFailsAnEmptyBuilder(t *testing.T) {
	catalog := DefaultCatalog()
	empty := func(net *Net) *Schedule { return &Schedule{} }
	cases := []struct {
		name    string
		rowId   string
		builder Builder
		want    string
	}{
		{name: "empty", rowId: "FS-9", builder: empty, want: "an empty builder"},
		{name: "no check", rowId: "FS-9", builder: func(net *Net) *Schedule {
			schedule := gateFixtureWritten(net)
			schedule.Check = nil
			return schedule
		}, want: "checks nothing"},
		{name: "nil step", rowId: "FS-9", builder: func(net *Net) *Schedule {
			schedule := gateFixtureWritten(net)
			schedule.Steps = append(schedule.Steps, nil)
			return schedule
		}, want: "step 1 is nil"},
		{name: "no schedule", rowId: "FS-9", builder: func(net *Net) *Schedule { return nil }, want: "built no schedule"},
		{name: "panics", rowId: "FS-9", builder: func(net *Net) *Schedule { panic("a fixture's builder") }, want: "panicked"},
		{name: "a refusal with no twin", rowId: "FS-9", builder: func(net *Net) *Schedule {
			schedule := gateFixtureWritten(net)
			schedule.Refuses = "a fixture's refusal"
			return schedule
		}, want: "names no twin"},
		{name: "a forged case with no twin", rowId: "FS-10", builder: gateFixtureWritten, want: "forged"},
		{name: "an empty twin", rowId: "FS-9", builder: Twin(gateFixtureWritten, empty), want: "its twin: an empty builder"},
		{name: "a refusing twin", rowId: "FS-9", builder: Twin(gateFixtureWritten, func(net *Net) *Schedule {
			schedule := gateFixtureWritten(net)
			schedule.Refuses = "a fixture's refusal"
			return schedule
		}), want: "a twin is what must succeed"},
	}
	for _, c := range cases {
		result := GateWritten(t.Context(), catalog.Case(c.rowId, ""), gateFixtureLookup(&Registration{Row: c.rowId, Tiers: []Tier{TierT2}, Build: c.builder}), nil)
		if result.Outcome != GateOutcomeFail || !strings.Contains(result.Reason, c.want) {
			t.Errorf("%s: %+v", c.name, result)
		}
	}
}

// A row no builder covers reads missing, never pass, whatever tests of it exist; a builder on the wrong tier is no
// cover either.
func TestGateWrittenReportsAMissingRowAsMissing(t *testing.T) {
	catalog := DefaultCatalog()
	result := GateWritten(t.Context(), catalog.Case("FS-44", ""), gateFixtureLookup(), nil)
	if result.Outcome != GateOutcomeMissing || !strings.Contains(result.Reason, "no T2 builder is registered") {
		t.Fatalf("%+v", result)
	}
	// FS-1 runs on T2 and T3, and a T3 builder alone leaves its T2 schedule missing
	result = GateWritten(t.Context(), catalog.Case("FS-1", ""), gateFixtureLookup(&Registration{Row: "FS-1", Tiers: []Tier{TierT3}, Build: gateFixtureWritten}), nil)
	if result.Outcome != GateOutcomeMissing {
		t.Fatalf("a T3 builder for a T2 case: %+v", result)
	}
	result = GateWritten(t.Context(), catalog.Case("FS-114", "head"), gateFixtureLookup(), nil)
	if result.Outcome != GateOutcomeMissing || result.Tier != TierT3 || !strings.Contains(result.Reason, "runs on T3 alone") {
		t.Fatalf("a T3 case: %+v", result)
	}
}

// A case that waits on the world reads open, as fault.Missing leaves it out.
func TestGateWrittenReadsAnOpenCaseAsOpen(t *testing.T) {
	testCase := DefaultCatalog().Case("FS-40", "production")
	result := GateWritten(t.Context(), testCase, gateFixtureLookup(), nil)
	if result.Outcome != GateOutcomeOpen || !strings.Contains(result.Reason, "production") {
		t.Fatalf("%+v", result)
	}
}

// What a written check prints is what the tool reads: its outcome on the last line, its reason on the line before.
func TestGateWrittenLinesAreWhatTheToolReads(t *testing.T) {
	for _, outcome := range []string{GateOutcomePass, GateOutcomeFail, GateOutcomeMissing, GateOutcomeOpen} {
		result := &GateWrittenResult{Outcome: outcome, Reason: "a fixture's reason"}
		output := "=== RUN   TestGateM2InRowWritten\n" + result.Lines() + "--- PASS: TestGateM2InRowWritten (0.00s)\nPASS\n"
		matches := gateToolOutcomePattern.FindAllStringSubmatchIndex(output, -1)
		if len(matches) != 1 {
			t.Fatalf("%s: %d outcome lines", outcome, len(matches))
		}
		last := matches[0]
		if got := output[last[2]:last[3]]; got != outcome {
			t.Errorf("read %q, want %q", got, outcome)
		}
		if before := strings.TrimSpace(output[:last[0]]); !strings.HasSuffix(before, "a fixture's reason") {
			t.Errorf("the line before the outcome: %q", before)
		}
	}
}

// A command names its case so the test finds it again, and a case M2's exit does not hold is refused.
func TestGateWrittenCommandNamesItsCase(t *testing.T) {
	catalog := DefaultCatalog()
	for _, testCase := range catalog.GateCases(gateM2InRowsGate) {
		command := gateWrittenCommand(testCase)
		argument, ok := strings.CutPrefix(command[len(command)-1], "-"+GateWrittenFlag+"=")
		if !ok {
			t.Fatalf("%s's command: %v", testCase, command)
		}
		found, err := GateWrittenCase(catalog, argument)
		if err != nil || found != testCase {
			t.Errorf("%s's argument %q finds %v: %v", testCase, argument, found, err)
		}
	}
	for _, argument := range []string{"FS-25", "FS-19/grant", "FS-19/no-such-case", "FS-999", ""} {
		if _, err := GateWrittenCase(catalog, argument); err == nil {
			t.Errorf("%q was taken", argument)
		}
	}
}

// M2-in's TLC item reads recorded runs: each test passing passes; one that could not run TLC reads open, saying so;
// any other failure, or a run that never built, fails.
func TestGateTlcOutcomeReadsOpenWhenTlcHasNotRun(t *testing.T) {
	names := []string{"TestEvsCommitPassesTlcAtItsBounds", "TestStoreSettlePassesTlcAtItsBounds"}
	passing := "=== RUN   TestEvsCommitPassesTlcAtItsBounds\n    model_test.go:66: EvsCommit's sources are unchanged since its passing runs, which stand; TLC need not rerun model\n--- PASS: TestEvsCommitPassesTlcAtItsBounds (0.01s)\n" +
		"=== RUN   TestStoreSettlePassesTlcAtItsBounds\n--- PASS: TestStoreSettlePassesTlcAtItsBounds (0.01s)\nPASS\n"
	if outcome, reason := GateTlcOutcome([]byte(passing), nil, names); outcome != GateOutcomePass || !strings.Contains(reason, "stand") {
		t.Errorf("both standing: %s %q", outcome, reason)
	}
	notRun := "=== RUN   TestEvsCommitPassesTlcAtItsBounds\n    model_test.go:71: EvsCommit's sources changed since its last passing runs, or none is recorded, and TLC has not run: no tla2tools.jar (set TLC to a command that runs tlc2.TLC)\n--- FAIL: TestEvsCommitPassesTlcAtItsBounds (0.01s)\n" +
		"=== RUN   TestStoreSettlePassesTlcAtItsBounds\n--- PASS: TestStoreSettlePassesTlcAtItsBounds (0.01s)\nFAIL\n"
	if outcome, reason := GateTlcOutcome([]byte(notRun), errors.New("exit status 1"), names); outcome != GateOutcomeOpen || !strings.Contains(reason, "TLC has not run") || !strings.Contains(reason, "TestEvsCommitPassesTlcAtItsBounds") {
		t.Errorf("one not run: %s %q", outcome, reason)
	}
	// "TLC has not run" in another test's lines does not excuse this one's failure
	failing := "=== RUN   TestEvsCommitPassesTlcAtItsBounds\n    model_test.go:95: TLC d8fb231: EvsCommit model: an invariant violated\n--- FAIL: TestEvsCommitPassesTlcAtItsBounds (9.00s)\n" +
		"=== RUN   TestStoreSettlePassesTlcAtItsBounds\n    model_test.go:71: StoreSettle's sources changed since its last passing runs, or none is recorded, and TLC has not run: no tla2tools.jar\n--- FAIL: TestStoreSettlePassesTlcAtItsBounds (0.01s)\nFAIL\n"
	if outcome, reason := GateTlcOutcome([]byte(failing), errors.New("exit status 1"), names); outcome != GateOutcomeFail || !strings.Contains(reason, "TestEvsCommitPassesTlcAtItsBounds") {
		t.Errorf("one failing: %s %q", outcome, reason)
	}
	if outcome, reason := GateTlcOutcome([]byte("# github.com/urnetwork/sidecar/sidecartest/model\nsyntax error\nFAIL\n"), errors.New("exit status 1"), names); outcome != GateOutcomeFail || !strings.Contains(reason, "did not build or run") {
		t.Errorf("no build: %s %q", outcome, reason)
	}
	missingOne := "=== RUN   TestEvsCommitPassesTlcAtItsBounds\n--- PASS: TestEvsCommitPassesTlcAtItsBounds (0.01s)\nPASS\n"
	if outcome, _ := GateTlcOutcome([]byte(missingOne), nil, names); outcome != GateOutcomeFail {
		t.Errorf("a test with no verdict: %s", outcome)
	}
}

// M2-in's sweep: D-ARCH-4's assembly first, then §22.10's left column in its order, each FS case of M2's exit its
// own written item, each review open and nothing to run, and the reserved numbers RepoPrefixRules' among them.
func TestGateM2InSweepNamesItsItems(t *testing.T) {
	catalog := DefaultCatalog()
	rows := GateRows(catalog, "M2-in")
	if len(rows) == 0 || !strings.HasPrefix(rows[0].Item, "D-ARCH-4's assembly check") {
		t.Fatalf("M2-in opens with %+v", rows)
	}
	for _, row := range rows {
		if row.Row != "" {
			t.Errorf("M2-in holds the FS row %s, which runs at M2's exit, not its entry", row.Row)
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
	for _, testCase := range catalog.GateCases(gateM2InRowsGate) {
		row := itemOf(testCase.String() + " written as a test against the fakes")
		if row == nil || len(row.Commands) != 1 || len(row.Tests) != 0 || row.External != "" {
			t.Errorf("%s's written item: %+v", testCase, row)
			continue
		}
		if !slices.Equal(row.Commands[0].Command, gateWrittenCommand(testCase)) || row.Commands[0].Repo != "sidecar" {
			t.Errorf("%s's written command: %+v", testCase, row.Commands[0])
		}
	}
	// an open review: nothing to run, and what it waits on, so the tool reads it open
	for _, prefix := range []string{"peer review of the schemas", "RECORD.md reviewed", "§23.6's M2 design closure", "the changes since G0"} {
		row := itemOf(prefix)
		if row == nil || len(row.Tests) != 0 || len(row.Commands) != 0 || !strings.HasPrefix(row.External, "people:") {
			t.Errorf("%q: %+v", prefix, row)
		}
	}
	tlc := itemOf("EvsCommit.tla and StoreSettle.tla passing TLC")
	if tlc == nil || len(tlc.Commands) != 1 || !slices.Equal(tlc.Commands[0].Command, gateTlcCommand()) || tlc.External != "" {
		t.Errorf("the TLC item: %+v", tlc)
	}
	for _, prefix := range []string{"the vector schemas fixed", "format 2's reserved numbers", "acl.proto's RepoPrefixRules (SignedType 0x1111) and AclRepo.prefix_rules"} {
		row := itemOf(prefix)
		if row == nil || len(row.Tests) == 0 || row.External != "" {
			t.Errorf("%q: %+v", prefix, row)
			continue
		}
		for _, test := range row.Tests {
			if test.Repo != "sidecar" || test.Package == "" || len(test.Names) == 0 {
				t.Errorf("%q names an incomplete test: %+v", prefix, test)
			}
		}
	}
	// §22.10's order: the review, TLC, the rows, the vectors, RECORD.md, the reserved numbers
	order := []string{"peer review of the schemas", "EvsCommit.tla and StoreSettle.tla", "FS-1 written", "the vector schemas fixed", "RECORD.md reviewed", "format 2's reserved numbers"}
	last := -1
	for _, prefix := range order {
		index := slices.IndexFunc(rows, func(row *GateRow) bool { return strings.HasPrefix(row.Item, prefix) })
		if index <= last {
			t.Errorf("%q is at %d, after %d", prefix, index, last)
		}
		last = index
	}
	// no item is an external audit (R-TEST-6)
	for _, row := range rows {
		if strings.Contains(strings.ToLower(row.Item+row.External), "audit") {
			t.Errorf("an item names an audit: %+v", row)
		}
	}
}
