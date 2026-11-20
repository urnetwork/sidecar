package fault

// M2's exit sweep (TEST-M2-19): its rows name each T3 test where it runs, its items say what the exit shows and what
// waits on the world, the rules item holds §22.8's rules to what it says, and the invariants item reports each FI the
// rows check as the gate tool reads it.

import (
	"flag"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The flag only an invariants item's command passes (gate_m2_out.go), naming the catalog's gate.
var gateInvariantsFlagValue = flag.String(GateInvariantsFlag, "", "the catalog's gate, Mn-out, whose rows' FI checks this run reports for sidecar-gate")

// The invariants item's command: the gate's outcome and reason on the last two lines, failing the run only when the
// check cannot be read. Without the flag, M2's exit is read and logged, and the test passes, since an oracle not bound
// yet is the gate's to report missing.
func TestGateInvariantsBound(t *testing.T) {
	gate := *gateInvariantsFlagValue
	if gate == "" {
		outcome, reason := GateInvariantsBound(DefaultCatalog(), gateM2OutGate, nil)
		t.Logf("%s: %s", outcome, reason)
		return
	}
	if len(DefaultCatalog().GateCases(gate)) == 0 {
		fmt.Printf("%s holds no case\n%s%s\n", gate, GateOutcomeLinePrefix, GateOutcomeFail)
		t.Fatalf("%s holds no case", gate)
	}
	outcome, reason := GateInvariantsBound(DefaultCatalog(), gate, nil)
	// the tool reads the last outcome line and the line before it, so they are printed last
	fmt.Printf("%s\n%s%s\n", reason, GateOutcomeLinePrefix, outcome)
}

// Each outcome as the invariants item reports it: pass when every FI the cases check is bound, missing naming an
// unbound one with its oracle's task and the cases that check it, and missing for a gate whose cases check none.
func TestGateInvariantsBoundReadsEachOutcome(t *testing.T) {
	catalog := DefaultCatalog()
	outcome, reason := GateInvariantsBound(catalog, gateM2OutGate, func(n int) bool { return true })
	if outcome != GateOutcomePass || !strings.Contains(reason, "FI-1, FI-2") {
		t.Errorf("every FI bound: %s, %s", outcome, reason)
	}
	outcome, reason = GateInvariantsBound(catalog, gateM2OutGate, func(n int) bool { return n != 12 })
	for _, want := range []string{"FI-12 (TEST-M3-01's oracle; FS-20, FS-40)", "fails as unbuilt"} {
		if outcome != GateOutcomeMissing || !strings.Contains(reason, want) {
			t.Errorf("FI-12 unbound: %s, %s; want missing with %q", outcome, reason, want)
		}
	}
	if strings.Contains(reason, "FI-11") {
		t.Errorf("M2's cases check no FI-11, and the reason names it: %s", reason)
	}
	if outcome, reason := GateInvariantsBound(catalog, "M0-out", nil); outcome != GateOutcomeMissing {
		t.Errorf("a gate with no FI checked: %s, %s", outcome, reason)
	}
}

// The rules item says what §22.8's rules run every row with, and they do: 10 explorer seeds a merge on T2 and 100 a
// night on T3 (T3's settings are server's sidecart3's, whose TestGateT3RunsTheNightlySeeds holds them), the default
// rules taking the merge seeds and refusing a run with none, the unknown list as catalog.yml marks it, and every case
// at each gate whose sweep carries the item given a test on each tier it runs on, a forged case's twin on T3; FS-48's
// and FS-49's T2 tests are server's, pure tests of its abuse policy and clock, as §22.5's §21 row puts them.
func TestGateRunsItsRowsUnderSection228sRules(t *testing.T) {
	catalog := DefaultCatalog()
	if count := len(MergeSeeds()); count != 10 {
		t.Errorf("a T2 row runs %d explorer seeds, §22.8's 10", count)
	}
	if count := len(NightlySeeds()); count != 100 {
		t.Errorf("a T3 row runs %d nightly seeds, §22.8's 100", count)
	}
	if !slices.Equal(DefaultRuleSettings().Seeds, MergeSeeds()) {
		t.Errorf("the default rules run seeds %v", DefaultRuleSettings().Seeds)
	}
	noSeeds := DefaultRuleSettings()
	noSeeds.Seeds = nil
	if err := checkRuleSettings(noSeeds); err == nil {
		t.Error("rules with no explorer seed run")
	}
	// the plan's EveryWrite list is on M2's unknown list
	unknown := gateUnknownRows(catalog, gateM2OutGate)
	for _, rowId := range []string{"FS-1", "FS-3", "FS-15", "FS-57", "FS-63"} {
		if !slices.Contains(unknown, rowId) {
			t.Errorf("%s is not on M2's unknown list %v", rowId, unknown)
		}
	}
	checked := 0
	for _, gate := range GateNames() {
		catalogGate := gateCatalogName(gate)
		if catalogGate == "" {
			continue
		}
		rulesItem := gateRulesItem(catalog, catalogGate)
		carried := false
		for _, row := range GateRows(catalog, gate) {
			if row.Item == rulesItem.Item && reflect.DeepEqual(row.Tests, rulesItem.Tests) {
				carried = true
			}
		}
		if !carried {
			continue
		}
		checked += 1
		for _, rowId := range gateUnknownRows(catalog, catalogGate) {
			if !strings.Contains(rulesItem.Item, rowId) {
				t.Errorf("%s's rules item does not name %s, which its unknown list holds", gate, rowId)
			}
		}
		for _, row := range GateRows(catalog, gate) {
			if row.Row == "" {
				continue
			}
			testCase := catalog.Case(row.Row, row.Case)
			if testCase.Open != "" {
				continue
			}
			repos := []string{}
			for _, test := range row.Tests {
				repos = append(repos, test.Repo)
			}
			tiers := testCase.TwinTiers()
			if slices.Contains(tiers, TierT2) && slices.Contains(gateServerPolicyT2Rows, testCase.Row.Id) {
				// §22.5's §21 row: the row's T2 is a pure test of server's policy, on no store
				if !slices.ContainsFunc(row.Tests, func(test *GateTest) bool { return test.Repo == "server" && !test.Stores }) {
					t.Errorf("%s at %s runs on T2 as a pure test of server's policy and names none: %s", testCase, gate, gateTestsStringForTest(row.Tests))
				}
			} else if slices.Contains(tiers, TierT2) && !slices.Contains(repos, "sidecar") {
				t.Errorf("%s at %s runs on T2 and names no T2 test: %s", testCase, gate, gateTestsStringForTest(row.Tests))
			}
			if slices.Contains(tiers, TierT3) && !slices.Contains(repos, "server") {
				t.Errorf("%s at %s runs on T3 and names no T3 test: %s", testCase, gate, gateTestsStringForTest(row.Tests))
			}
		}
	}
	if checked == 0 {
		t.Fatal("no gate carries the rules item")
	}
}

// M2's rows name each T3 test where it runs: QD-1081's evshost cases and FS-10's twins by their real names, which the
// sweep names, and the sidecart3 cases, which the convention names under the local stack's tag (QD-1085), each on the
// private stores with the convention's T3 tags and each keeping the convention's T2 test; FS-5 runs on T3 alone.
func TestGateM2NamesEachT3TestWhereItRuns(t *testing.T) {
	catalog := DefaultCatalog()
	data, err := GateFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	for _, want := range []struct {
		rowId       string
		caseName    string
		packagePath string
		names       []string
	}{
		{rowId: "FS-1", packagePath: "./evshost", names: []string{"TestFs1OnT3"}},
		{rowId: "FS-2", packagePath: "./evshost", names: []string{"TestFs2OnT3"}},
		{rowId: "FS-3", packagePath: "./evshost", names: []string{"TestFs3OnT3"}},
		{rowId: "FS-4", packagePath: "./evshost", names: []string{"TestFs4OnT3"}},
		{rowId: "FS-5", packagePath: "./evshost", names: []string{"TestFs5OnT3"}},
		{rowId: "FS-6", packagePath: "./evshost", names: []string{"TestFs6OnT3"}},
		{rowId: "FS-7", packagePath: "./evshost", names: []string{"TestFs7OnT3"}},
		{rowId: "FS-10", packagePath: "./evshost", names: []string{"TestFs10TwinOnT3"}},
		{rowId: "FS-12", packagePath: "./evshost", names: []string{"TestFs12OnT3"}},
		{rowId: "FS-53", packagePath: "./evshost", names: []string{"TestFs53OnT3"}},
		{rowId: "FS-57", packagePath: "./evshost", names: []string{"TestFs57OnT3"}},
		{rowId: "FS-58", packagePath: "./evshost", names: []string{"TestFs58OnT3"}},
		{rowId: "FS-60", packagePath: "./evshost", names: []string{"TestFs60OnT3"}},
		{rowId: "FS-62", packagePath: "./evshost", names: []string{"TestFs62OnT3"}},
		{rowId: "FS-63", packagePath: "./evshost", names: []string{"TestFs63OnT3"}},
		{rowId: "FS-113", packagePath: "./evshost", names: []string{"TestFs113OnT3"}},
		{rowId: "FS-14", packagePath: "./sidecart3", names: []string{"TestFs14OnT3"}},
		{rowId: "FS-16", packagePath: "./sidecart3", names: []string{"TestFs16OnT3"}},
		{rowId: "FS-19", caseName: "config-read", packagePath: "./sidecart3", names: []string{"TestFs19ConfigReadOnT3"}},
		{rowId: "FS-102", packagePath: "./sidecart3", names: []string{"TestFs102OnT3"}},
		{rowId: "FS-102", caseName: "forged", packagePath: "./sidecart3", names: []string{"TestFs102ForgedOnT3"}},
		{rowId: "FS-124", packagePath: "./sidecart3", names: []string{"TestFs124OnT3"}},
		{rowId: "FS-124", caseName: "forged", packagePath: "./sidecart3", names: []string{"TestFs124ForgedOnT3"}},
	} {
		testCase := catalog.Case(want.rowId, want.caseName)
		if _, swept := gateM2Cases(catalog)[testCase.String()]; swept != (want.packagePath != "./sidecart3") {
			t.Errorf("%s: named by the sweep %t, but its T3 test is in %s", testCase, swept, want.packagePath)
		}
		row := gateFileRow(file, "M2", want.rowId, want.caseName)
		if testCase == nil || row == nil {
			t.Errorf("M2 has no %s %q", want.rowId, want.caseName)
			continue
		}
		wantTests := []*GateTest{}
		if want.rowId != "FS-5" {
			wantTests = append(wantTests, &GateTest{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{GateT2TestName(testCase)}})
		}
		wantTests = append(wantTests, &GateTest{Repo: "server", Package: want.packagePath, Tags: gateT3Tags, Stores: true, Names: want.names})
		wantTests = gateWithClausesForTest(testCase, wantTests)
		if !reflect.DeepEqual(row.Tests, wantTests) {
			t.Errorf("%s at M2 runs %s, want %s", testCase, gateTestsStringForTest(row.Tests), gateTestsStringForTest(wantTests))
		}
		if row.External != gateCaseExternal(testCase, gateM2OutGate) || row.StoreClock != testCase.StoreClock {
			t.Errorf("%s at M2: external %q, store clock %t, not the catalog's", testCase, row.External, row.StoreClock)
		}
	}
}

// The tests that were MLS's evidence alone, which left M2's gate with MLS (owner decision 610).
var gateMlsOnlyEvidenceForTest = []string{
	"TestTmcStacksUnderTheSuitePatch", "TestTmcLifecycleInBothDirections", "TestMlsInteropTranscripts", "TestMlsGoLifecycle",
	"TestMlsGoTranscripts", "TestMlsGoContinuation", "TestMlsVectorFilesEachHaveAnOutcome", "TestMlsCryptoBasicsVectors",
}

// M2's items say what the exit shows: the items gate_m1.go once carried are here, the nvme run and the twenty-agent
// hour read open on the hardware they wait for, every §22.7 row at M2-out has an item with its registered tests, the
// MLS evidence owner decision 610 took off the gate is named by no item and its leaving reads open, and no item is
// left with nothing to run that does not say what it waits on.
func TestGateM2ItemsSayWhatTheExitShows(t *testing.T) {
	catalog := DefaultCatalog()
	items := map[string]*GateRow{}
	order := []string{}
	for _, row := range GateRows(catalog, "M2") {
		if row.Item != "" {
			items[row.Item] = row
			order = append(order, row.Item)
		}
	}
	find := func(prefix string) *GateRow {
		for _, item := range order {
			if strings.HasPrefix(item, prefix) {
				return items[item]
			}
		}
		t.Errorf("M2 has no item %q...", prefix)
		return &GateRow{}
	}
	for _, prefix := range []string{"the nvme run (D-TEST-11", "twenty agents push for an hour"} {
		if row := find(prefix); !strings.HasPrefix(row.External, "hardware:") {
			t.Errorf("%q waits on %q, not on hardware", prefix, row.External)
		}
	}
	if row := find("the MLS legs of FS-15, FS-20, FS-24 and FS-104"); row.External == "" || 0 < len(row.Tests) {
		t.Errorf("the MLS item reads %+v", row)
	}
	if !strings.HasPrefix(order[0], "§22.8's rules on every row") {
		t.Errorf("M2's first item is %q", order[0])
	}
	for _, prefix := range []string{
		"every FI the rows check", "T3's store clock", "Porcupine passes", "§22.7's leak leg", "servers get only §2.8's", "the CROSSSLOT lints",
		"budgets.yml", "targets.yml", "peers.yml", "format 1's erasure and deposit bytes", "X-Wing KATs", "§10.6's sizes", "the format vectors in testdata/",
		"the fuzz seeds", "TLC passes EvsCommit.tla and StoreSettle.tla", "the ledger's named gaps", "§22.7's admission suite",
	} {
		find(prefix)
	}
	for _, assert := range sidecartest.DefaultPrivacyAsserts().Rows() {
		if !slices.Contains(assert.Gates, gateM2OutGate) {
			continue
		}
		row := find("§22.7's " + assert.Id + " assertion")
		if len(row.Tests) != len(sidecartest.DefaultPrivacyAsserts().Tests(assert.Id)) {
			t.Errorf("%s's item names %d tests, the registry %d", assert.Id, len(row.Tests), len(sidecartest.DefaultPrivacyAsserts().Tests(assert.Id)))
		}
	}
	for _, item := range order {
		row := items[item]
		if len(row.Tests) == 0 && len(row.Commands) == 0 && row.External == "" && !strings.HasPrefix(item, "§22.7's ") {
			t.Errorf("%q has nothing to run and waits on nothing", item)
		}
		if strings.Contains(item, "0x0010 interop artifact") && row.External == "" {
			t.Errorf("an item runs the 0x0010 interop, which left the gate: %q", item)
		}
		for _, test := range row.Tests {
			for _, name := range test.Names {
				if slices.Contains(gateMlsOnlyEvidenceForTest, name) {
					t.Errorf("%q names %s, MLS's evidence alone", item, name)
				}
			}
		}
	}
}

// A §22.7 row nothing is registered to gets an item with no test, which the gate reads missing; a registration's
// package is named from its module's root, a server test on the private stores; one no entry can reach is said.
func TestGatePrivacyItemsNameEachRegistration(t *testing.T) {
	asserts := sidecartest.NewPrivacyAsserts()
	items := gatePrivacyItems(asserts, gateM2OutGate)
	if len(items) == 0 {
		t.Fatal("no §22.7 row at M2-out")
	}
	for _, item := range items {
		if len(item.Tests) != 0 {
			t.Errorf("an unregistered row's item names tests: %+v", item)
		}
	}
	rowId := items[0].Item
	assertId := ""
	for _, row := range asserts.Rows() {
		if slices.Contains(row.Gates, gateM2OutGate) {
			assertId = row.Id
			break
		}
	}
	for _, test := range []*sidecartest.PrivacyAssertTest{
		{Repo: "sidecar", Package: "github.com/urnetwork/sidecar", Name: "TestAtTheRoot"},
		{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestInSidecartest"},
		{Repo: "server", Package: "github.com/urnetwork/server/sidecart3", Name: "TestOnT3", Tags: "sidecar_localstack"},
		{Repo: "server", Package: "github.com/urnetwork/serverless", Name: "TestOutsideTheModule"},
	} {
		if err := asserts.Register(assertId, test); err != nil {
			t.Fatal(err)
		}
	}
	items = gatePrivacyItems(asserts, gateM2OutGate)
	want := []*GateTest{
		{Repo: "sidecar", Package: ".", Names: []string{"TestAtTheRoot"}},
		{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestInSidecartest"}},
		{Repo: "server", Package: "./sidecart3", Tags: "sidecar_localstack", Stores: true, Names: []string{"TestOnT3"}},
	}
	if !reflect.DeepEqual(items[0].Tests, want) {
		t.Errorf("%s's tests: %s, want %s", rowId, gateTestsStringForTest(items[0].Tests), gateTestsStringForTest(want))
	}
	if !strings.Contains(items[0].Item, "registrations no entry reaches") || !strings.Contains(items[0].Item, "TestOutsideTheModule") {
		t.Errorf("an unreachable registration goes unsaid: %q", items[0].Item)
	}
}
