package fault

// M6's sweeps (gate_m6.go; TEST-M6-02) and QD-1008's cases as gates.yml shows them: FS-126 at M6 runs sidecartest's P2P
// tests on T2 beside the convention's T3 test, which nothing has written, so the row reads missing and never passes
// early; FS-25's dns-route case at M5 runs the convention's T3 test alone. Then the entry and the exit: each row names
// its tests where they run (QD-1081), a tier no owner's test runs keeps the convention's entry, the items say what the
// gates show and what production and people owe, and every test a sweep of M6, M7 or M8 names in this repo is declared
// under the tags its entry builds with.

import (
	"bytes"
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// FS-126's row names p2p_test.go's tests where they run and the convention's T3 test, nothing else, at M6 alone.
func TestGateFileShowsFs126BySidecartestsP2pTests(t *testing.T) {
	catalog := DefaultCatalog()
	data, err := GateFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	fs126 := gateFileRow(file, "M6", "FS-126", "")
	if fs126 == nil || len(fs126.Tests) != 2 || fs126.External != "" || fs126.StoreClock {
		t.Fatalf("FS-126 at M6: %+v", fs126)
	}
	t2 := fs126.Tests[0]
	if t2.Repo != "sidecar" || t2.Package != "./sidecartest" || t2.Tags != "" || t2.Stores ||
		!slices.Equal(t2.Names, []string{"TestP2pOffByDefault", "TestP2pPairMovesAndBackUnderALiveRpcAndStream", "TestP2pForgedControlIdStaysDroppedWithP2pOn"}) {
		t.Errorf("FS-126's T2 tests: %+v", t2)
	}
	// the T3 entry is the convention's, so the row reads missing until a T3 test of the schedule is named
	var convention *GateTest
	for _, test := range gateConventionalTests(catalog.Case("FS-126", "")) {
		if test.Repo == "server" {
			convention = test
		}
	}
	if convention == nil || !reflect.DeepEqual(gateFs126T3Test, convention) {
		t.Errorf("FS-126's T3 test %+v, the convention's %+v", gateFs126T3Test, convention)
	}
	if t3 := fs126.Tests[1]; t3.Repo != "server" || t3.Package != "./sidecart3" || !t3.Stores || !slices.Equal(t3.Names, []string{"TestFs126OnT3"}) {
		t.Errorf("FS-126's T3 test in gates.yml: %+v", t3)
	}
	for _, gate := range GateNames() {
		if gate != "M6" && gateFileRow(file, gate, "FS-126", "") != nil {
			t.Errorf("FS-126 sits at %s", gate)
		}
	}
}

// Each test the sweep names for FS-126 on T2 is declared in sidecartest/p2p_test.go, so a rename there fails here
// rather than only reading missing at the gate.
func TestGateFs126TestsAreDeclaredInP2pTest(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "p2p_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range gateFs126T2Test.Names {
		if !bytes.Contains(data, []byte("\nfunc "+name+"(t *testing.T) {")) {
			t.Errorf("sidecartest/p2p_test.go declares no %s", name)
		}
	}
}

// The names of a row's tests, in order.
func gateRowNamesForTest(row *GateRow) []string {
	names := []string{}
	for _, test := range row.Tests {
		names = append(names, test.Names...)
	}
	return names
}

// The items of a gate, and a find by an item's opening that fails the test for one the gate lacks.
func gateItemsForTest(t *testing.T, gate string) ([]*GateRow, func(prefix string) *GateRow) {
	t.Helper()
	items := []*GateRow{}
	for _, row := range GateRows(DefaultCatalog(), gate) {
		if row.Item != "" {
			items = append(items, row)
		}
	}
	return items, func(prefix string) *GateRow {
		t.Helper()
		for _, item := range items {
			if strings.HasPrefix(item.Item, prefix) {
				return item
			}
		}
		t.Errorf("%s has no item %q...", gate, prefix)
		return &GateRow{}
	}
}

var gateTestDeclarationPattern = regexp.MustCompile(`(?m)^func ((?:Test|Fuzz|Benchmark)[A-Za-z0-9_]*)\(`)

// The tests a gate names in this repo that no test file of their package declares in a file building under the
// entry's tags, each as "<name> in <package> under <tags>". A case's convention entry is passed over: a test not
// written yet reads missing at the gate, which is the convention's rule and no fault of a sweep.
func gateUndeclaredSidecarTestsForTest(t *testing.T, catalog *Catalog, rows []*GateRow) []string {
	t.Helper()
	declared := map[string]map[string][]string{}
	filesOf := func(directory string) map[string][]string {
		if nameFiles, ok := declared[directory]; ok {
			return nameFiles
		}
		paths, err := filepath.Glob(filepath.Join(directory, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		nameFiles := map[string][]string{}
		for _, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, match := range gateTestDeclarationPattern.FindAllSubmatch(data, -1) {
				nameFiles[string(match[1])] = append(nameFiles[string(match[1])], filepath.Base(path))
			}
		}
		declared[directory] = nameFiles
		return nameFiles
	}
	undeclared := []string{}
	for _, row := range rows {
		for _, test := range row.Tests {
			if test.Repo != "sidecar" {
				continue
			}
			if row.Row != "" {
				testCase := catalog.Case(row.Row, row.Case)
				if test.Package == "./sidecartest/fault" && slices.Equal(test.Names, []string{GateT2TestName(testCase)}) {
					continue
				}
			}
			directory := filepath.Join("..", "..", test.Dir, filepath.FromSlash(test.Package))
			buildContext := build.Default
			if test.Tags != "" {
				buildContext.BuildTags = strings.Split(test.Tags, ",")
			}
			for _, name := range test.Names {
				builds := false
				for _, fileName := range filesOf(directory)[name] {
					if match, err := buildContext.MatchFile(directory, fileName); err != nil {
						t.Fatal(err)
					} else if match {
						builds = true
					}
				}
				if !builds {
					undeclared = append(undeclared, fmt.Sprintf("%s in %s under %q", name, test.Package, test.Tags))
				}
			}
		}
	}
	return undeclared
}

// Every test M6's entry and exit and M7's and M8's exits name in this repo, for a row outside the convention or for
// an item, is declared in its package in a file that builds under the entry's tags, so a rename or a tag an owner adds
// fails here rather than only reading missing at the gate. A name no file declares, and one declared only under a tag
// the entry lacks, are both caught.
func TestGateM6ToM8SweepsNameSidecarTestsDeclaredUnderTheirTags(t *testing.T) {
	catalog := DefaultCatalog()
	for _, gate := range []string{"M6-in", "M6", "M7", "M8"} {
		for _, name := range gateUndeclaredSidecarTestsForTest(t, catalog, GateRows(catalog, gate)) {
			t.Errorf("%s names %s, which is not declared so", gate, name)
		}
	}
	wrong := []*GateRow{{Item: "a fixture", Tests: []*GateTest{
		{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{"TestGateNoSuchTestIsDeclaredAnywhere"}},
		// declared in fs13_test.go, which builds under the hooks alone
		{Repo: "sidecar", Package: "./sidecartest/fault", Names: []string{"TestFs13ErasedDepositAndIndexCopiesAfterAConsumeCrash"}},
		{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{"TestFs13ErasedDepositAndIndexCopiesAfterAConsumeCrash"}},
	}}}
	want := []string{
		`TestGateNoSuchTestIsDeclaredAnywhere in ./sidecartest/fault under "sidecar_testhooks"`,
		`TestFs13ErasedDepositAndIndexCopiesAfterAConsumeCrash in ./sidecartest/fault under ""`,
	}
	if got := gateUndeclaredSidecarTestsForTest(t, catalog, wrong); !slices.Equal(got, want) {
		t.Errorf("the fixture's undeclared tests read %q, want %q", got, want)
	}
}

// M6's entry is the one Gn-in that runs code: FS-46 by its owners' tests on T2 and on Postgres, §20.9's benchmark as
// server's tests run it and open on M4's dark build, directory.proto's specification on the owner's review, and
// D-PHASE-6's pilot measures open with nothing to run.
func TestGateM6InRunsFs46AndTheBenchmark(t *testing.T) {
	catalog := DefaultCatalog()
	rows := GateRows(catalog, "M6-in")
	var fs46 *GateRow
	for _, row := range rows {
		if row.Row == "FS-46" {
			fs46 = row
		}
	}
	want := []*GateTest{
		{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{"TestFs46LeaseTakesThePackFirstAndReturnsToTheLineFirst", "TestFs46KilledEdgeLeavesNoReservationAndNoDebit"}},
		{Repo: "server", Package: "./model", Tags: "sidecar_pending", Stores: true, Names: []string{"TestFs46EscrowOrder"}},
	}
	if fs46 == nil || !reflect.DeepEqual(fs46.Tests, want) {
		t.Fatalf("FS-46 at M6's entry runs %+v, want %s", fs46, gateTestsStringForTest(want))
	}
	items, find := gateItemsForTest(t, "M6-in")
	// every Gn-in's assembly item, and the sweep's three
	if count := len(gateSweep("M6-in").Items); count != 3 || len(items) != count+1 {
		t.Errorf("M6's entry holds %d items, its sweep %d", len(items), count)
	}
	benchmark := find("§20.9's escrow benchmark on M4's dark build")
	if !slices.Contains(gateRowNamesForTest(benchmark), "TestEscrowBenchmarkMeasurements") || !strings.HasPrefix(benchmark.External, "production") {
		t.Errorf("the benchmark's item: %+v", benchmark)
	}
	if row := find("directory.proto's specification freezes"); !strings.HasPrefix(row.External, "people") || 0 < len(row.Tests) {
		t.Errorf("directory.proto's specification: %+v", row)
	}
	if row := find("the design-partner pilot's measures"); !strings.HasPrefix(row.External, "people") || 0 < len(row.Tests) || 0 < len(row.Commands) ||
		!strings.Contains(row.Item, "D-PHASE-6") || !strings.Contains(row.Item, "pitch5.html:913-920") {
		t.Errorf("the pilot's measures: %+v", row)
	}
}

// M6's rows: server/api's T3 runs named there under the convention's tags beside the convention's T2 test (QD-1081),
// the directory rows by their thin tests' own names with the convention's T3 entry kept, the rows with no schedule by
// their owners' tests, FS-43 and FS-51 by the convention's T2 test, which nothing has written, and every other case by
// the convention.
func TestGateM6NamesEachRowsTestsWhereTheyRun(t *testing.T) {
	catalog := DefaultCatalog()
	data, err := GateFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	for _, want := range []struct {
		rowId    string
		caseName string
		names    []string
	}{
		{rowId: "FS-19", caseName: "team", names: []string{"TestFs19TeamOnT3"}},
		{rowId: "FS-19", caseName: "invite", names: []string{"TestFs19InviteOnT3"}},
		{rowId: "FS-21", caseName: "team", names: []string{"TestFs21TeamOnT3"}},
		{rowId: "FS-97", caseName: "team", names: []string{"TestFs97TeamOnT3", "TestFs97TeamAdminSetMemberOnT3", "TestFs97TeamCleanupOnT3"}},
		{rowId: "FS-124", caseName: "team", names: []string{"TestFs124TeamOnT3"}},
	} {
		testCase := catalog.Case(want.rowId, want.caseName)
		row := gateFileRow(file, "M6", want.rowId, want.caseName)
		if row == nil {
			t.Errorf("M6 has no %s", testCase)
			continue
		}
		wantTests := []*GateTest{}
		for _, test := range gateConventionalTests(testCase) {
			if test.Repo == "server" {
				test = &GateTest{Repo: "server", Package: "./api", Tags: gateT3Tags, Stores: true, Names: want.names}
			}
			wantTests = append(wantTests, test)
		}
		if !reflect.DeepEqual(row.Tests, wantTests) {
			t.Errorf("%s at M6 runs %s, want %s", testCase, gateTestsStringForTest(row.Tests), gateTestsStringForTest(wantTests))
		}
	}
	// a directory row's T2 test by its own name, and the convention's T3 entry where the case runs on T3
	for _, want := range []struct {
		rowId    string
		caseName string
		name     string
		t3       bool
	}{
		{rowId: "FS-84", caseName: "entries", name: "TestFs84M6"},
		{rowId: "FS-85", name: "TestFs85M6", t3: true},
		{rowId: "FS-86", caseName: "announce-entries", name: "TestFs86M6", t3: true},
		{rowId: "FS-87", name: "TestFs87M6", t3: true},
		{rowId: "FS-88", name: "TestFs88M6"},
		{rowId: "FS-99", caseName: "entries", name: "TestFs99M6", t3: true},
		{rowId: "FS-101", caseName: "entries", name: "TestFs101M6"},
	} {
		testCase := catalog.Case(want.rowId, want.caseName)
		row := gateFileRow(file, "M6", want.rowId, want.caseName)
		if row == nil || len(row.Tests) == 0 {
			t.Errorf("M6 has no %s", testCase)
			continue
		}
		if t2 := row.Tests[0]; t2.Repo != "sidecar" || t2.Package != "./sidecartest/fault" || t2.Tags != "sidecar_testhooks" || !slices.Contains(t2.Names, want.name) {
			t.Errorf("%s at M6 runs %+v on T2", testCase, t2)
		}
		t3 := row.Tests[1:]
		if want.t3 {
			if len(t3) != 1 || !reflect.DeepEqual(t3[0], &GateTest{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{GateT3TestName(testCase)}}) {
				t.Errorf("%s at M6 runs %s on T3, not the convention's test alone", testCase, gateTestsStringForTest(t3))
			}
		} else if 0 < len(t3) {
			t.Errorf("%s at M6, which runs on T2 alone, also runs %s", testCase, gateTestsStringForTest(t3))
		}
	}
	// rows with no schedule, by their owners' tests
	for _, want := range []struct {
		rowId    string
		caseName string
		names    []string
	}{
		{rowId: "FS-30", caseName: "audit", names: []string{"TestAclAuditReaderReadsOnlyWhatTheBlockNames", "TestRecordAuditReaderFilesASecondReadToTheTeamRecord", "TestAnAuditOptOutRotatesWithCauseRemove"}},
		{rowId: "FS-32", names: []string{"TestCertsCaaChecksRefuseAnAliasIntoAnOperatorZone", "TestCertsCaaChecksFailOnACanaryInTheWalksSet"}},
		{rowId: "FS-35", names: []string{"TestT3Fs35CustomHostThroughTheRealSplitter"}},
		{rowId: "FS-38", caseName: "shares", names: []string{"TestFs38Share", "TestFs38ShareOnT3"}},
		{rowId: "FS-122", names: []string{"TestT3Fs122AnLbRestartedOnAnOldMapLoadsTheCurrentVersionFirst", "TestT3Fs122TlsAlpnOrdersWaitForTheHostToBeReady"}},
		{rowId: "FS-41", caseName: "m6", names: []string{"TestT3Fs41CustomHostListenersComeBackByTheirNextHeartbeat", "TestRecomputeStripeMeterReportsResendsWithoutDoubleBilling"}},
		{rowId: "FS-42", caseName: "m6", names: []string{"TestT3Fs42CustomHostsAfterTheDumpLeaveOrReturnToTheRestoredMap", "TestBillingStepRecomputesFromTheSidecarDumpAfterTheRowsStep"}},
	} {
		row := gateFileRow(file, "M6", want.rowId, want.caseName)
		if row == nil {
			t.Errorf("M6 has no %s %q", want.rowId, want.caseName)
			continue
		}
		names := gateRowNamesForTest(row)
		for _, name := range want.names {
			if !slices.Contains(names, name) {
				t.Errorf("%s %q at M6 runs %v, which lacks %s", want.rowId, want.caseName, names, name)
			}
		}
	}
	// every other case keeps the convention: FS-43 and FS-51, whose T2 runs nothing has written, FS-98's Team case,
	// FS-100's format-1 case and the later-of cases among them
	swept := gateM6Cases(catalog)
	conventional := 0
	for _, row := range GateRows(catalog, "M6") {
		if row.Row == "" {
			continue
		}
		testCase := catalog.Case(row.Row, row.Case)
		if _, ok := swept[testCase.String()]; ok {
			continue
		}
		conventional += 1
		if tests := gateConventionalTests(testCase); !reflect.DeepEqual(row.Tests, tests) {
			t.Errorf("%s at M6 runs %s, the convention %s", testCase, gateTestsStringForTest(row.Tests), gateTestsStringForTest(tests))
		}
	}
	for _, key := range []string{"FS-43", "FS-51", "FS-98's team", "FS-100's format-1", "FS-84's cards", "FS-111's team-record"} {
		if _, ok := swept[key]; ok {
			t.Errorf("M6's sweep names %s, which keeps the convention", key)
		}
	}
	if conventional == 0 {
		t.Error("no case at M6 keeps the convention")
	}
}

// M6's items say what its exit shows and what production and people owe: the rules and the FI bindings, FI-25 and
// FI-26 where RECORD's worlds check them, directory.proto's freeze with its vectors and fuzz seeds, §22.7's rows at
// M6 with the directory's, the scenarios and the revocation suite's member form on both tiers, what is written of
// FS-43, FS-51 and the directory rows' T3 legs apart from their rows, Team billing, the benchmark again, FS-86's day at
// the Team limit as an item of its own, and the live IdP, Stripe, real CAs and the rota open.
func TestGateM6ItemsSayWhatProductionOwes(t *testing.T) {
	items, find := gateItemsForTest(t, "M6")
	find("§22.8's rules on every row")
	find("every FI the rows check")
	if row := find("FI-25 and FI-26 as RECORD's rows check them"); !slices.Contains(gateRowNamesForTest(row), "TestFs84M6") || !slices.Contains(gateRowNamesForTest(row), "TestFs85M6") {
		t.Errorf("FI-25 and FI-26's item: %+v", row)
	}
	freeze := gateRowNamesForTest(find("directory.proto's bytes freeze"))
	for _, name := range []string{"TestDirectoryPathVectors", "TestDirectoryRepoEntriesPadAlike", "FuzzDirectoryDecode"} {
		if !slices.Contains(freeze, name) {
			t.Errorf("the directory.proto item lacks %s", name)
		}
	}
	directory := gateRowNamesForTest(find("§22.7's directory-plaintext assertion"))
	for _, name := range []string{"TestDirectoryPlaintextHoldsNoCanary", "TestDirectoryACanaryPastAPromptsFirstLineInAnEntryFails", "TestDirectoryARevokedNameStillReadableFails"} {
		if !slices.Contains(directory, name) {
			t.Errorf("the directory's privacy row lacks %s", name)
		}
	}
	scenarios := find("S3b, S4b and S13 at M6")
	for _, name := range []string{"TestScenarioS3b", "TestScenarioS4b", "TestS13AtM6", "TestScenarioS3bOnT3", "TestScenarioS4bOnT3"} {
		if !slices.Contains(gateRowNamesForTest(scenarios), name) {
			t.Errorf("the scenarios' item lacks %s", name)
		}
	}
	suite := find("§22.7's revocation suite in its member form")
	for _, name := range []string{"TestRevocationSuiteMemberFormWhole", "TestRevocationSuiteMemberFormFailsARevokedMemberStillReading", "TestRevocationSuiteMemberFormOnT3"} {
		if !slices.Contains(gateRowNamesForTest(suite), name) {
			t.Errorf("the revocation suite's item lacks %s", name)
		}
	}
	if row := find("FS-43 as QUOTA-M6-04 wrote it"); !slices.Contains(gateRowNamesForTest(row), "TestFs43StripeMeters") {
		t.Errorf("FS-43's item: %+v", row)
	}
	if row := find("FS-51 as QUOTA-M6-05 and DNS-M6-07 wrote it"); !slices.Contains(gateRowNamesForTest(row), "TestApplyNetworkDowngradesTeamLapse") {
		t.Errorf("FS-51's item: %+v", row)
	}
	if row := find("what is written of the directory rows' T3 runs"); !slices.Contains(gateRowNamesForTest(row), "TestFs85AclRepoRequestOnT3") || !slices.Contains(gateRowNamesForTest(row), "TestFs99EvsScopeOnT3") {
		t.Errorf("the directory rows' T3 legs: %+v", row)
	}
	if row := find("Team billing under FS-46's order"); !slices.Contains(gateRowNamesForTest(row), "TestTeamBillingFs46T3") {
		t.Errorf("Team billing's item: %+v", row)
	}
	if row := find("§20.9's escrow benchmark again at M6's exit"); !strings.HasPrefix(row.External, "production") || len(row.Tests) != 1 {
		t.Errorf("the benchmark's rerun: %+v", row)
	}
	// D-TEST-17: the Team limit's day as an item of its own, in the gate's form with a real following daemon
	teamLimit := find("FS-86's M6 case against §16.11's cost table at the Team limit")
	if len(teamLimit.Tests) != 1 || teamLimit.External != "" || !strings.Contains(teamLimit.Item, "D-TEST-17") {
		t.Fatalf("FS-86's day at the Team limit: %+v", teamLimit)
	}
	if test := teamLimit.Tests[0]; test.Repo != "sidecar" || test.Package != "./sidecartest" ||
		!slices.Equal(test.Names, []string{"TestDirectoryLoadDayAtTheTeamLimit"}) || !slices.Equal(test.Args, []string{"-directory-load-full"}) {
		t.Errorf("FS-86's day at the Team limit runs %+v", test)
	}
	for prefix, waits := range map[string]string{
		"a live IdP run of SCIM and SSO":      "production and people",
		"Stripe's meters and the Team":        "production",
		"custom domains through real CAs":     "production",
		"the 24/7 rota staffed before Team's": "people",
	} {
		if row := find(prefix); !strings.HasPrefix(row.External, waits) || 0 < len(row.Tests) {
			t.Errorf("%q waits on %q and runs %d tests", prefix, row.External, len(row.Tests))
		}
	}
	// QD-1032: the prefix write rules are Later's, so no item or row of M6 names them
	for _, row := range GateRows(DefaultCatalog(), "M6") {
		if strings.Contains(strings.ToLower(row.Item), "prefix") {
			t.Errorf("M6 holds the deferred prefix rules: %q", row.Item)
		}
	}
	if count := len(gateSweep("M6").Items); count != len(items) {
		t.Errorf("M6's sweeps add %d items, the file %d", count, len(items))
	}
}
