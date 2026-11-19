package fault

// M4's sweep (TEST-M4-04): each row names its tests where they run, a clause-test row is said to be one, the later
// cases of its rows are shown as not yet due and never as rows, and the items say what the exit shows and what the
// world owes.

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// M4's rows: FS-38, its forged case's twin and FS-56 on T3 in server's controller under sidecar_pending, each beside
// its convention T2 test; FS-37's clauses here and in server's taskworker/work; FS-97's clauses here and the
// convention's T3 test, which nobody has written; and every other case by convention.
func TestGateM4NamesEachRowsTestsWhereTheyRun(t *testing.T) {
	catalog := DefaultCatalog()
	data, err := GateFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)

	for _, place := range []struct {
		rowId    string
		caseName string
		name     string
	}{
		{rowId: "FS-38", name: "TestFs38OnT3"},
		{rowId: "FS-38", caseName: "forged", name: "TestFs38ForgedOnT3"},
		{rowId: "FS-56", name: "TestFs56OnT3"},
	} {
		testCase := catalog.Case(place.rowId, place.caseName)
		row := gateFileRow(file, "M4", place.rowId, place.caseName)
		want := []*GateTest{
			{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{GateT2TestName(testCase)}},
			{Repo: "server", Package: "./controller", Tags: "sidecar_pending", Stores: true, Names: []string{place.name}},
		}
		if row == nil || !reflect.DeepEqual(row.Tests, want) {
			t.Errorf("%s at M4 runs %+v, want %s", testCase, row, gateTestsStringForTest(want))
		}
	}

	fs37 := gateFileRow(file, "M4", "FS-37", "")
	if fs37 == nil || len(fs37.Tests) != 2 {
		t.Fatalf("FS-37 at M4: %+v", fs37)
	}
	if test := fs37.Tests[0]; test.Repo != "sidecar" || test.Package != "./sidecartest/fault" || len(test.Names) != 6 || !slices.Contains(test.Names, "TestFs37PageKilledWithNoUnloadReapsOnce") {
		t.Errorf("FS-37's T2 entry: %+v", *test)
	}
	if test := fs37.Tests[1]; test.Repo != "server" || test.Package != "./taskworker/work" || test.Tags != "sidecar_pending" || !test.Stores ||
		len(test.Names) != 7 || !slices.Contains(test.Names, "TestFs37PageKilledWithNoUnloadReapsOnceOnT3") {
		t.Errorf("FS-37's T3 entry: %+v", *test)
	}
	// each T2 clause but the reap job, which is server's alone, has its T3 twin
	for _, name := range gateFs37T2Names {
		twin := strings.Replace(name, "MemberPage", "PageWorker", 1) + "OnT3"
		if !slices.Contains(gateFs37T3Names, twin) {
			t.Errorf("FS-37's %s has no T3 twin %s among %v", name, twin, gateFs37T3Names)
		}
	}

	fs97 := gateFileRow(file, "M4", "FS-97", "")
	if fs97 == nil || len(fs97.Tests) != 2 {
		t.Fatalf("FS-97 at M4: %+v", fs97)
	}
	if test := fs97.Tests[0]; test.Repo != "sidecar" || !slices.Equal(test.Names, gateFs97T2Names) || len(test.Names) != 5 {
		t.Errorf("FS-97's T2 entry: %+v", *test)
	}
	// nothing runs FS-97's personal-network cases on T3, so the entry is the convention's, which reads missing
	wantT3 := &GateTest{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{"TestFs97OnT3"}}
	if !reflect.DeepEqual(fs97.Tests[1], wantT3) {
		t.Errorf("FS-97's T3 entry: %+v, want %+v", *fs97.Tests[1], *wantT3)
	}

	// every other case keeps the convention: FS-19's grant and share, FS-21 and FS-106's page Worker case
	swept := gateM4Cases(catalog)
	sweptNames := []string{}
	for caseName := range swept {
		sweptNames = append(sweptNames, caseName)
	}
	slices.Sort(sweptNames)
	if want := []string{"FS-37", "FS-38", "FS-38's forged", "FS-56", "FS-97"}; !slices.Equal(sweptNames, want) {
		t.Errorf("M4's sweep names %v, want %v", sweptNames, want)
	}
	conventional := []string{}
	for _, row := range GateRows(catalog, "M4") {
		if row.Row == "" {
			continue
		}
		testCase := catalog.Case(row.Row, row.Case)
		if _, ok := swept[testCase.String()]; ok {
			continue
		}
		conventional = append(conventional, testCase.String())
		if want := gateConventionalTests(testCase); !reflect.DeepEqual(row.Tests, want) {
			t.Errorf("%s at M4 runs %s, the convention %s", testCase, gateTestsStringForTest(row.Tests), gateTestsStringForTest(want))
		}
	}
	if want := []string{"FS-19's grant", "FS-19's share", "FS-21", "FS-106's page-worker"}; !slices.Equal(conventional, want) {
		t.Errorf("M4's convention cases are %v, want %v", conventional, want)
	}
	if row := gateFileRow(file, "M4", "FS-106", "page-worker"); row == nil || !row.StoreClock {
		t.Errorf("FS-106's page Worker case at M4: %+v", row)
	}
}

// The halves of M4's rows that are M6's and M8's are no row of M4's report, so none can read passed there, and one
// item names each as not yet due, open on its later gate.
func TestGateM4ShowsLaterCasesAsNotYetDue(t *testing.T) {
	catalog := DefaultCatalog()
	later := gateM4LaterCases(catalog)
	for _, want := range []string{"FS-38's shares at M6-out", "FS-97's team at M6-out", "FS-19's team at M6-out", "FS-19's invite at M6-out", "FS-21's team at M6-out", "FS-19's quick-burner at M8-out"} {
		if !slices.Contains(later, want) {
			t.Errorf("the later cases %v lack %q", later, want)
		}
	}
	// a case of an earlier gate is not a later one
	for _, entry := range later {
		if strings.Contains(entry, "M2-out") || strings.Contains(entry, "M4-out") {
			t.Errorf("%q is not later than M4", entry)
		}
	}
	rows := GateRows(catalog, "M4")
	var item *GateRow
	for _, row := range rows {
		if row.Row == "FS-38" && row.Case == "shares" || row.Row == "FS-97" && row.Case == "team" {
			t.Errorf("M4 shows %s %s as a row", row.Row, row.Case)
		}
		if strings.HasPrefix(row.Item, "not yet due at M4") {
			item = row
		}
	}
	if item == nil {
		t.Fatal("M4 has no not-yet-due item")
	}
	if item.External == "" || 0 < len(item.Tests) || 0 < len(item.Commands) {
		t.Errorf("the not-yet-due item can read passed: %+v", item)
	}
	for _, entry := range later {
		if !strings.Contains(item.Item, entry) {
			t.Errorf("the not-yet-due item does not name %q", entry)
		}
	}
}

// M4's items say what its exit shows and what the world owes: the rules with the clause rows beside them reading
// missing, FI-11 on both tiers, §22.7's M4 assertions through the registry, the dark escrow build, make size and the
// ledger, the memory rows, the cloud agent, the real site and the trust documents open, and the exit scenario nobody
// wrote with nothing to run.
func TestGateM4ItemsSayWhatTheExitShows(t *testing.T) {
	catalog := DefaultCatalog()
	items := []*GateRow{}
	for _, row := range GateRows(catalog, "M4") {
		if row.Item != "" {
			items = append(items, row)
		}
	}
	find := func(prefix string) *GateRow {
		for _, item := range items {
			if strings.HasPrefix(item.Item, prefix) {
				return item
			}
		}
		t.Errorf("M4 has no item %q...", prefix)
		return &GateRow{}
	}
	names := func(row *GateRow) []string {
		rowNames := []string{}
		for _, test := range row.Tests {
			rowNames = append(rowNames, test.Names...)
		}
		return rowNames
	}
	nothingToRun := func(row *GateRow) bool {
		return len(row.Tests) == 0 && len(row.Commands) == 0
	}

	find("§22.8's rules on every row")
	if row := find("every FI the rows check"); len(row.Commands) != 1 || !slices.Contains(row.Commands[0].Command, "-"+GateInvariantsFlag+"=M4-out") {
		t.Errorf("M4's invariants item: %+v", row)
	}
	// the clause rows are named, with nothing to run and nothing external: missing, never pass
	clauses := find("the rows that pass on clause tests alone")
	for _, rowId := range gateM4ClauseRows {
		if !strings.Contains(clauses.Item, rowId) {
			t.Errorf("the clause item does not name %s", rowId)
		}
		if catalog.Row(rowId) == nil || gateM4Cases(catalog)[rowId] == nil {
			t.Errorf("%s is no case M4's sweep names", rowId)
		}
	}
	if !nothingToRun(clauses) || clauses.External != "" {
		t.Errorf("the clause item can read passed or open: %+v", clauses)
	}
	// no builder is registered for a clause row; when one lands, its row leaves the list and takes the convention
	for _, rowId := range gateM4ClauseRows {
		if Lookup(rowId, "", TierT2) != nil {
			t.Errorf("%s has a T2 builder registered, so M4's sweep should run it by convention and drop it from the clause rows", rowId)
		}
	}

	fi11 := find("FI-11, path integrity")
	for _, name := range []string{"TestFi11FailsAByteBeforeTheAudienceCheck", "TestFi11FixtureReadsEachCaseOnT2", "TestFi11RunsAfterEveryStepOnT3"} {
		if !slices.Contains(names(fi11), name) {
			t.Errorf("FI-11's item lacks %s", name)
		}
	}
	if row := find("FS-38 and FS-56 read FI-11 from the path's own bytes"); !nothingToRun(row) || row.External != "" {
		t.Errorf("the rows' FI-11 gap, which no test shows yet, reads %+v", row)
	}

	// §22.7's rows at M4, each an item, a row nothing is registered to with nothing to run
	asserts := sidecartest.DefaultPrivacyAsserts()
	privacyCount := 0
	for _, assert := range asserts.Rows() {
		if !slices.Contains(assert.Gates, gateM4OutGate) {
			continue
		}
		privacyCount += 1
		row := find("§22.7's " + assert.Id + " assertion")
		if len(row.Tests) != len(asserts.Tests(assert.Id)) {
			t.Errorf("§22.7's %s runs %d tests, its registry holds %d", assert.Id, len(row.Tests), len(asserts.Tests(assert.Id)))
		}
	}
	if privacyCount != 4 {
		t.Errorf("M4 shows %d of §22.7's rows, want private-names, unsealed-peer, public-exits and flow-pins", privacyCount)
	}
	for _, missing := range asserts.Missing(gateM4OutGate) {
		if row := find("§22.7's " + missing.Id + " assertion"); !nothingToRun(row) || row.External != "" {
			t.Errorf("§22.7's %s, which nothing is registered to, reads %+v", missing.Id, row)
		}
	}
	if row := find("T3's store clock"); !strings.Contains(row.Item, "FS-106's page-worker") {
		t.Errorf("M4's store clock item: %q", row.Item)
	}

	escrow := find("§22.8's escrow benchmark harness, dark")
	if !slices.Contains(names(escrow), "TestEscrowBenchmarkMeasurements") || !strings.HasPrefix(escrow.External, "hardware") {
		t.Errorf("the escrow harness: %+v", escrow)
	}
	if row := find("the escrow comparator, dark"); !slices.Contains(names(row), "TestEscrowDrawLessIsAStrictTotalOrder") || row.External != "" {
		t.Errorf("the escrow comparator: %+v", row)
	}
	size := find("make size")
	if len(size.Tests) != 1 || size.Tests[0].Tags != "sidecar_check,sidecar_size" || !slices.Contains(size.Tests[0].Names, "TestSizeGateIosExtension") || !slices.Contains(size.Tests[0].Names, "TestSizeGateSidecarHttp") {
		t.Errorf("make size's item: %+v", size)
	}
	if row := find("the budget ledger's size rows"); !slices.Contains(names(row), "TestBudgetSizeRowsHoldTheSizeGatesNumbers") {
		t.Errorf("the ledger's size rows: %+v", row)
	}
	if row := find("per-target memory"); !nothingToRun(row) || !strings.HasPrefix(row.External, "hardware") {
		t.Errorf("per-target memory: %+v", row)
	}
	if row := find("§22.9's Browsers row on the page Worker"); !slices.Contains(names(row), "TestVaultRecordOpensOverHttpsAlone") || row.External == "" {
		t.Errorf("the Browsers row: %+v", row)
	}
	if row := find("the MLS legs of FS-97 and of FS-106's page Worker case"); !nothingToRun(row) || !strings.HasPrefix(row.External, "people") {
		t.Errorf("the MLS legs: %+v", row)
	}
	if row := find("suspension within one epoch"); !slices.Contains(names(row), "TestAclContractGateHoldsASuspensionWithinItsHeadsInterval") {
		t.Errorf("suspension: %+v", row)
	}
	// the exit scenario nobody wrote names no test, and waits on hosts this one is not
	if row := find("forwards, private IPs and model servers"); !nothingToRun(row) || !strings.HasPrefix(row.External, "hardware") {
		t.Errorf("the exit scenario: %+v", row)
	}
	for prefix, external := range map[string]string{
		"a Claude Code cloud agent reaches a granted port": "production",
		"ur.io/recurd opens a vault record":                "production",
		"trust documents drafted":                          "people",
	} {
		if row := find(prefix); !nothingToRun(row) || !strings.HasPrefix(row.External, external) {
			t.Errorf("%q, which the world owes, reads %+v", prefix, row)
		}
	}
	if gateSweep("M4").Gate != "M4" || len(gateSweep("M4").Items) != len(items) {
		t.Errorf("M4's sweeps add %d items, the file %d", len(gateSweep("M4").Items), len(items))
	}
}

// M4's entry review reads the assembly check and §23.6's design closure, which a person signs.
func TestGateM4InReadsItsDesignClosure(t *testing.T) {
	rows := GateRows(DefaultCatalog(), "M4-in")
	if len(rows) != 2 || rows[0].Item != gateAssemblyItem.Item {
		t.Fatalf("M4-in holds %d rows: %+v", len(rows), rows)
	}
	closure := rows[1]
	if !strings.HasPrefix(closure.Item, "§23.6's M4 design closure") || !strings.HasPrefix(closure.External, "people") || 0 < len(closure.Tests) {
		t.Errorf("M4-in's closure: %+v", closure)
	}
	for _, want := range []string{"control contracts", "dial fence", "HTTP liveness", "page Worker", "escrow comparator", "Q-BRIDGE-2", "Q-SDK-5", "Q-SDK-7"} {
		if !strings.Contains(closure.Item, want) {
			t.Errorf("M4-in's closure does not name %q", want)
		}
	}
}

// Every sidecar test M4's rows and items name is declared in its package, in a file go test builds on this host with
// the entry's tags, so a renamed test or a drifted tag fails here before its row reads missing at the gate. The
// convention's entries are left out: a test nobody wrote reads missing by design. server's sidecart3 holds the server
// entries of M4's items the same way, and its sidecar-gate those of the rows.
func TestGateM4NamesSidecarTestsDeclaredUnderTheirTags(t *testing.T) {
	catalog := DefaultCatalog()
	repoDirectory, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, gate := range []string{"M4", "M4-in"} {
		for _, row := range GateRows(catalog, gate) {
			conventional := []*GateTest{}
			if row.Row != "" {
				conventional = gateConventionalTests(catalog.Case(row.Row, row.Case))
			}
			for _, test := range row.Tests {
				if test.Repo != "sidecar" || slices.ContainsFunc(conventional, func(other *GateTest) bool { return reflect.DeepEqual(other, test) }) {
					continue
				}
				for _, err := range GateTestDeclared(repoDirectory, test) {
					t.Errorf("%s's %s%s: %v", gate, row.Row, row.Item, err)
				}
				checked += len(test.Names)
			}
		}
	}
	if checked < 40 {
		t.Errorf("only %d sidecar tests of M4's were checked", checked)
	}
	// a name no file declares, and one behind a tag the entry lacks, each fail
	if errs := GateTestDeclared(repoDirectory, &GateTest{Repo: "sidecar", Package: "./sidecartest/fault", Names: []string{"TestGateM4NoSuchTest"}}); len(errs) != 1 {
		t.Errorf("a test nobody declares: %v", errs)
	}
	if errs := GateTestDeclared(repoDirectory, &GateTest{Repo: "sidecar", Package: "./check", Names: []string{"TestSizeGateIosExtension"}}); len(errs) != 1 {
		t.Errorf("a test behind tags its entry lacks: %v", errs)
	}
}
