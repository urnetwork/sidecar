package fault

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// What server/local/sidecar-gate reads of gates.yml, as strictly as this side can hold it: a field the tool
// does not read is a value no gate shows.
type gateFileForTest struct {
	Gates map[string][]*GateRow `yaml:"gates"`
}

func parseGateFileForTest(t *testing.T, data []byte) *gateFileForTest {
	t.Helper()
	file := &gateFileForTest{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(file); err != nil {
		t.Fatal(err)
	}
	return file
}

// Every gate the catalog names is in the file with each of its cases once, in the tool's names, and no case
// sits at a gate the catalog does not name for it.
func TestGateFileHoldsEveryCatalogCaseAtItsGate(t *testing.T) {
	catalog := DefaultCatalog()
	data, err := GateFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	if got := len(file.Gates); got != len(GateNames()) {
		t.Fatalf("%d gates, want %d", got, len(GateNames()))
	}
	for _, gate := range GateNames() {
		rows, ok := file.Gates[gate]
		if !ok {
			t.Errorf("gate %s is missing", gate)
			continue
		}
		want := []string{}
		if catalogGate := gateCatalogName(gate); catalogGate != "" {
			for _, testCase := range catalog.GateCases(catalogGate) {
				want = append(want, testCase.Row.Id+"/"+testCase.Name)
			}
		}
		got := []string{}
		for _, row := range rows {
			if row.Row != "" {
				got = append(got, row.Row+"/"+row.Case)
			} else if row.Item == "" {
				t.Errorf("%s holds a row with neither a row nor an item", gate)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s holds %v, the catalog %v", gate, got, want)
		}
	}
	if len(file.Gates["M2"]) < 40 || len(file.Gates["M1"]) == 0 || len(file.Gates["every"]) == 0 {
		t.Fatalf("the file is thin: M1 %d, M2 %d, every %d rows", len(file.Gates["M1"]), len(file.Gates["M2"]), len(file.Gates["every"]))
	}
	again, err := GateFile(catalog)
	if err != nil || !bytes.Equal(again, data) {
		t.Fatalf("a second GateFile differs: %v", err)
	}
}

// The row and case at gate, or nil.
func gateFileRow(file *gateFileForTest, gate string, rowId string, caseName string) *GateRow {
	for _, row := range file.Gates[gate] {
		if row.Row == rowId && row.Case == caseName {
			return row
		}
	}
	return nil
}

// A case's tests are its row's thin tests by name, on the tiers it runs on: T2 here under the hooks, T3 in
// server's sidecart3 on the stores, a forged case's twin on T3 too.
func TestGateFileNamesEachCasesConventionalTests(t *testing.T) {
	data, err := GateFile(DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	for _, want := range []struct {
		gate     string
		rowId    string
		caseName string
		t2       string
		t3       string
	}{
		// FS-1 and FS-10 were the examples until M2's exit sweep named their T3 tests in evshost (QD-1081)
		{gate: "M2", rowId: "FS-11", t2: "TestFs11", t3: "TestFs11OnT3"},
		{gate: "M2", rowId: "FS-19", caseName: "config-read", t2: "TestFs19ConfigRead", t3: "TestFs19ConfigReadOnT3"},
		{gate: "M2", rowId: "FS-9", t2: "TestFs9"},
		// forged: T2 alone, and its twin on T3
		{gate: "M2", rowId: "FS-17", t2: "TestFs17", t3: "TestFs17OnT3"},
		// T3 alone (FS-5 was the example until M2's sweep named its test in evshost, FS-35 until M6's named its test
		// in tlsedge, FS-52 until M5's named its test in cli/dns)
		{gate: "M2", rowId: "FS-40", t3: "TestFs40OnT3"},
		// FS-46 at M6's entry was the example until M6's sweep named its owners' tests
		{gate: "M6", rowId: "FS-98", caseName: "team", t2: "TestFs98Team", t3: "TestFs98TeamOnT3"},
	} {
		row := gateFileRow(file, want.gate, want.rowId, want.caseName)
		if row == nil {
			t.Errorf("%s has no %s %q", want.gate, want.rowId, want.caseName)
			continue
		}
		got := map[string]*GateTest{}
		for _, test := range row.Tests {
			for _, name := range test.Names {
				got[name] = test
			}
		}
		if want.t2 != "" {
			test := got[want.t2]
			if test == nil || test.Repo != "sidecar" || test.Package != "./sidecartest/fault" || test.Tags != "sidecar_testhooks" || test.Stores {
				t.Errorf("%s %q's T2 test: %+v", want.rowId, want.caseName, test)
			}
		}
		if want.t3 != "" {
			test := got[want.t3]
			if test == nil || test.Repo != "server" || test.Package != "./sidecart3" || !test.Stores || !strings.Contains(test.Tags, "sidecar_pending") {
				t.Errorf("%s %q's T3 test: %+v", want.rowId, want.caseName, test)
			}
		}
		wantCount := 0
		for _, name := range []string{want.t2, want.t3} {
			if name != "" {
				wantCount += 1
			}
		}
		if len(row.Tests) != wantCount {
			t.Errorf("%s %q runs %d tests, want %d", want.rowId, want.caseName, len(row.Tests), wantCount)
		}
	}
}

// The convention's T3 entry builds under the local stack's tag (QD-1085). Every sidecart3 FS test file is behind
// sidecar_localstack, since a T3 Net's stores are on the local stack's MinIO, so an entry without that tag builds the
// test out: a real gate run reads its row missing while -list reads it listed. The tags are written out here, not read
// from gate.go, so a drift there fails this test. Each T3 case that no sweep names gets the convention's entry. Every
// entry naming a case's conventional T3 test carries the tags, whether the convention or a sweep placed it.
func TestGateConventionT3EntryCarriesTheLocalStack(t *testing.T) {
	wantTags := []string{"sidecar_localstack", "sidecar_pending", "sidecar_testhooks"}
	sortedTags := func(tags string) []string {
		split := strings.Split(tags, ",")
		slices.Sort(split)
		return split
	}
	catalog := DefaultCatalog()
	data, err := GateFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	entryCount := 0
	for _, gate := range GateNames() {
		sweep := gateSweep(gate)
		for _, row := range file.Gates[gate] {
			if row.Row == "" {
				continue
			}
			testCase := catalog.Case(row.Row, row.Case)
			if testCase == nil {
				t.Errorf("%s holds %s %q, which the catalog does not", gate, row.Row, row.Case)
				continue
			}
			conventional := []*GateTest{}
			for _, test := range row.Tests {
				if test.Repo == "server" && test.Package == "./sidecart3" && slices.Equal(test.Names, []string{GateT3TestName(testCase)}) {
					conventional = append(conventional, test)
				}
			}
			if _, swept := sweep.Cases[testCase.String()]; !swept && slices.Contains(testCase.TwinTiers(), TierT3) && len(conventional) != 1 {
				t.Errorf("%s at %s runs %s, not the convention's one T3 entry", testCase, gate, gateTestsStringForTest(row.Tests))
			}
			for _, test := range conventional {
				entryCount += 1
				if !slices.Equal(sortedTags(test.Tags), wantTags) || !test.Stores {
					t.Errorf("%s at %s runs %v under tags %q, stores %t: the convention's T3 entry builds under %v on the stores", testCase, gate, test.Names, test.Tags, test.Stores, wantTags)
				}
			}
		}
	}
	if entryCount == 0 {
		t.Fatal("the file holds no convention T3 entry")
	}
	if !bytes.Contains(data, []byte("TestFs<n><Case>OnT3 in server's sidecart3 under sidecar_localstack too")) {
		t.Error("gates.yml's header does not say the convention's T3 tests build under sidecar_localstack")
	}
}

// FS-54 and FS-55 are OPS's server tests, no schedule, so their sweeps name them in place of the convention.
func TestGateFileShowsFs54AndFs55ByOpsTests(t *testing.T) {
	data, err := GateFile(DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	fs54 := gateFileRow(file, "M1", "FS-54", "")
	if fs54 == nil || len(fs54.Tests) != 3 || !slices.Contains(fs54.Tests[0].Names, "TestSidecarPendingBuildTags") {
		t.Fatalf("FS-54 at M1: %+v", fs54)
	}
	for _, test := range fs54.Tests {
		if slices.Contains(test.Names, "TestFs54OnT3") {
			t.Fatal("FS-54 kept the convention's T3 test beside OPS's")
		}
	}
	fs55 := gateFileRow(file, "every", "FS-55", "")
	if fs55 == nil || len(fs55.Tests) != 1 || fs55.Tests[0].Package != "./local/fs55" || !slices.Contains(fs55.Tests[0].Args, "-fs55.group={group}") {
		t.Fatalf("FS-55 at every: %+v", fs55)
	}
}

// A row's tests one after another, for a failure's message.
func gateTestsStringForTest(tests []*GateTest) string {
	parts := []string{}
	for _, test := range tests {
		parts = append(parts, fmt.Sprintf("%+v", *test))
	}
	return "[" + strings.Join(parts, "; ") + "]"
}

// FS-5's, FS-73's and FS-72's rollback case's T3 tests run in server's evshost behind sidecar_localstack, so M2's
// and M10's sweeps name them there (owner decision 548; QD-995). Each row's T3 entry is the convention's test by
// name, in ./evshost with sidecar_localstack added to the convention's tags. The rollback case keeps its T2 test
// as the convention names it. Each row keeps the external and store clock the catalog gives it.
func TestGateFileNamesFs5Fs73AndFs72RollbackInEvshost(t *testing.T) {
	catalog := DefaultCatalog()
	data, err := GateFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	evshostTags := "sidecar_testhooks,sidecar_pending,sidecar_localstack"
	for _, want := range []struct {
		gate     string
		rowId    string
		caseName string
		tests    []*GateTest
	}{
		{gate: "M2", rowId: "FS-5", tests: []*GateTest{
			{Repo: "server", Package: "./evshost", Tags: evshostTags, Stores: true, Names: []string{"TestFs5OnT3"}},
		}},
		{gate: "M10", rowId: "FS-73", tests: []*GateTest{
			{Repo: "server", Package: "./evshost", Tags: evshostTags, Stores: true, Names: []string{"TestFs73OnT3"}},
		}},
		{gate: "M10", rowId: "FS-72", caseName: "rollback", tests: []*GateTest{
			{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{"TestFs72Rollback"}},
			{Repo: "server", Package: "./evshost", Tags: evshostTags, Stores: true, Names: []string{"TestFs72RollbackOnT3"}},
		}},
	} {
		testCase := catalog.Case(want.rowId, want.caseName)
		row := gateFileRow(file, want.gate, want.rowId, want.caseName)
		if testCase == nil || row == nil {
			t.Errorf("%s has no %s %q", want.gate, want.rowId, want.caseName)
			continue
		}
		if !reflect.DeepEqual(row.Tests, want.tests) {
			t.Errorf("%s at %s runs %s, want %s", testCase, want.gate, gateTestsStringForTest(row.Tests), gateTestsStringForTest(want.tests))
		}
		if external := gateCaseExternal(testCase, gateCatalogName(want.gate)); row.External != external || row.StoreClock != testCase.StoreClock {
			t.Errorf("%s at %s: external %q, store clock %t; the catalog gives %q, %t", testCase, want.gate, row.External, row.StoreClock, external, testCase.StoreClock)
		}
		// the convention's names and tiers, moved: every entry but the evshost one is the convention's own
		conventionNames := []string{}
		for _, test := range gateConventionalTests(testCase) {
			conventionNames = append(conventionNames, test.Names...)
			if test.Repo == "sidecar" && !slices.ContainsFunc(row.Tests, func(named *GateTest) bool { return reflect.DeepEqual(named, test) }) {
				t.Errorf("%s at %s dropped the convention's T2 test %+v", testCase, want.gate, *test)
			}
		}
		rowNames := []string{}
		for _, test := range row.Tests {
			rowNames = append(rowNames, test.Names...)
		}
		if !slices.Equal(rowNames, conventionNames) {
			t.Errorf("%s at %s names %v, the convention %v", testCase, want.gate, rowNames, conventionNames)
		}
	}
}

// Apart from the cases their sweeps name, M2's and M10's rows follow the convention. Each case no sweep names runs
// its conventional tests and nothing else: M2's and M10's sweeps name the cases whose tests run outside the convention
// (gate_m2_out.go, gate_m10_out.go; QD-995, QD-1081); gate_m2_out_test.go and gate_m10_out_test.go hold their items.
func TestGateM2AndM10KeepTheConventionForEveryOtherCase(t *testing.T) {
	catalog := DefaultCatalog()
	wantM2 := []string{}
	for caseName := range gateM2Cases(catalog) {
		wantM2 = append(wantM2, caseName)
	}
	slices.Sort(wantM2)
	wantM10 := []string{}
	for caseName := range gateM10Cases(catalog) {
		wantM10 = append(wantM10, caseName)
	}
	slices.Sort(wantM10)
	wantSwept := map[string][]string{"M2": wantM2, "M10": wantM10}
	for _, gate := range []string{"M2", "M10"} {
		sweep := gateSweep(gate)
		swept := []string{}
		for caseName := range sweep.Cases {
			swept = append(swept, caseName)
		}
		slices.Sort(swept)
		if !slices.Equal(swept, wantSwept[gate]) {
			t.Errorf("%s's sweeps name %v, want %v", gate, swept, wantSwept[gate])
		}
		caseCount := 0
		for _, row := range GateRows(catalog, gate) {
			if row.Row == "" {
				continue
			}
			caseCount += 1
			testCase := catalog.Case(row.Row, row.Case)
			if testCase == nil {
				t.Errorf("%s holds %s %q, which the catalog does not", gate, row.Row, row.Case)
				continue
			}
			if _, ok := sweep.Cases[testCase.String()]; ok {
				continue
			}
			if conventional := gateConventionalTests(testCase); !reflect.DeepEqual(row.Tests, conventional) {
				t.Errorf("%s at %s runs %s, the convention %s", testCase, gate, gateTestsStringForTest(row.Tests), gateTestsStringForTest(conventional))
			}
		}
		if want := len(catalog.GateCases(gateCatalogName(gate))); caseCount != want {
			t.Errorf("%s holds %d cases, the catalog %d", gate, caseCount, want)
		}
	}
}

// A case that waits on the world, a T4 part, or a later gate reads open at the gate it cannot pass at, and a
// later-of case passes plainly at its later gate.
func TestGateFileMarksWhatACaseWaitsOn(t *testing.T) {
	data, err := GateFile(DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	if row := gateFileRow(file, "M3", "FS-40", "production"); row == nil || !strings.HasPrefix(row.External, "production") {
		t.Errorf("FS-40's production case at M3: %+v", row)
	}
	if row := gateFileRow(file, "M5", "FS-69", ""); row == nil || !strings.Contains(row.External, "M10-out") {
		t.Errorf("FS-69 at M5, the earlier of its gates: %+v", row)
	}
	if row := gateFileRow(file, "M10", "FS-69", ""); row == nil || row.External != "" {
		t.Errorf("FS-69 at M10, the later of its gates: %+v", row)
	}
	found := false
	for _, row := range file.Gates["M8"] {
		if strings.Contains(row.External, "T4") {
			found = true
		}
	}
	if !found {
		t.Error("no M8 case names its T4 part")
	}
}

// M1's sweep: its exit criteria and closure as items, the production halves open.
func TestGateM1SweepNamesItsItems(t *testing.T) {
	rows := GateRows(DefaultCatalog(), "M1")
	items := map[string]*GateRow{}
	for _, row := range rows {
		if row.Item != "" {
			items[row.Item] = row
		}
	}
	for _, prefix := range []string{
		"stage 1 and D-TEAM-14 enforced", "Required RPC after", "push resyncs after a resident restart", "envelope fuzzed",
		"daemon on darwin, linux and windows", "typed signing", "the keystore result", "Q-TEST-6's descriptor lint",
		"make check's rules", "§22.4's release fixture",
	} {
		var row *GateRow
		for item, candidate := range items {
			if strings.HasPrefix(item, prefix) {
				row = candidate
			}
		}
		if row == nil || len(row.Tests) == 0 {
			t.Errorf("M1 lacks %q or its tests: %+v", prefix, row)
			continue
		}
		for _, test := range row.Tests {
			if test.Repo == "" || test.Package == "" || len(test.Names) == 0 {
				t.Errorf("%q names an incomplete test: %+v", prefix, test)
			}
		}
		production := prefix == "stage 1 and D-TEAM-14 enforced" || prefix == "daemon on darwin, linux and windows"
		if production != (row.External != "") {
			t.Errorf("%q waits on %q", prefix, row.External)
		}
	}
}

// A sweep naming a case its gate does not hold, or a gate the tool does not take, panics where it is written,
// and two sweeps naming one case do too.
func TestRegisterGateSweepRefusesWhatTheCatalogDoesNotHold(t *testing.T) {
	for _, sweep := range []*GateSweep{
		{Gate: "M1", Cases: map[string][]*GateTest{"FS-1": nil}},
		{Gate: "M11", Items: []*GateItem{{Item: "past M10"}}},
		{Gate: "M1", Cases: map[string][]*GateTest{"FS-54": nil}},
	} {
		panicked := func() (panicked bool) {
			defer func() {
				panicked = recover() != nil
			}()
			RegisterGateSweep(sweep)
			return false
		}()
		if !panicked {
			t.Errorf("registering %+v did not panic", sweep)
		}
	}
}

// A test with a negative timeout panics where its sweep registers, named by a case or by an item, and leaves
// nothing behind: the tool refuses such a file when it loads, so the generator never writes one (QD-1058).
func TestRegisterGateSweepRefusesANegativeTimeout(t *testing.T) {
	negative := func() []*GateTest {
		return []*GateTest{{Repo: "server", Package: ".", Timeout: -time.Hour, Names: []string{"TestBoundedByNothing"}}}
	}
	// a case no sweep names, so only the timeout can refuse it
	unswept := ""
	for _, testCase := range DefaultCatalog().GateCases("M2-out") {
		if _, ok := gateSweep("M2").Cases[testCase.String()]; !ok {
			unswept = testCase.String()
			break
		}
	}
	if unswept == "" {
		t.Fatal("every M2-out case is named by a sweep, so none is left to plant on")
	}
	for _, sweep := range []*GateSweep{
		{Gate: "M2", Cases: map[string][]*GateTest{unswept: negative()}},
		{Gate: "M1", Items: []*GateItem{{Item: "a test bounded by nothing", Tests: negative()}}},
	} {
		panicked := func() (panicked bool) {
			defer func() {
				panicked = recover() != nil
			}()
			RegisterGateSweep(sweep)
			return false
		}()
		if !panicked {
			t.Errorf("registering %+v did not panic", sweep)
		}
	}
	if _, ok := gateSweep("M2").Cases[unswept]; ok {
		t.Errorf("the refused sweep left M2's %s behind", unswept)
	}
	for _, row := range GateRows(DefaultCatalog(), "M1") {
		if row.Item == "a test bounded by nothing" {
			t.Error("the refused sweep left its item behind")
		}
	}
}

// Only the tests known to outlast the tool's default run under timeouts of their own (QD-1058), each written beside
// its tags: §22.4's release fixture under 3h, as run.sh's BUILD_TEST runs it (QD-1056), and M10's reading of FS-86's
// card case at the Team limit, a whole peak hour in real time on T3's layouts, under 2h (D-TEST-17; QD-1068). Every
// other test the file names keeps the tool's default.
func TestGateFileGivesOwnTimeoutsOnlyToTestsThatOutlastTheDefault(t *testing.T) {
	data, err := GateFile(DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	bounded := map[string]struct {
		timeout time.Duration
		tags    string
		gate    string
	}{
		"TestSidecarReleaseFixture":                     {timeout: 3 * time.Hour, tags: "sidecar_release_fixture"},
		"TestFs86CardCommitsAtTheTeamLimitOnTheLayouts": {timeout: 2 * time.Hour, tags: "sidecar_testhooks,sidecar_pending,sidecar_filecluster_t3", gate: "M10"},
	}
	found := map[string]int{}
	for _, gate := range GateNames() {
		for _, row := range file.Gates[gate] {
			for _, test := range row.Tests {
				name := ""
				for candidate := range bounded {
					if slices.Contains(test.Names, candidate) {
						name = candidate
					}
				}
				if name == "" {
					if test.Timeout != 0 {
						t.Errorf("%s's %s%s gives %v a timeout of its own, %s", gate, row.Row, row.Item, test.Names, test.Timeout)
					}
					continue
				}
				found[name] += 1
				want := bounded[name]
				if test.Timeout != want.timeout || test.Tags != want.tags || !slices.Equal(test.Names, []string{name}) {
					t.Errorf("%s's %s runs under %s with tags %q beside %v", gate, name, test.Timeout, test.Tags, test.Names)
				}
				if want.gate != "" && gate != want.gate {
					t.Errorf("%s names %s, which is %s's", gate, name, want.gate)
				}
			}
		}
	}
	if found["TestSidecarReleaseFixture"] != 1 || found["TestFs86CardCommitsAtTheTeamLimitOnTheLayouts"] != 1 {
		t.Fatalf("the file names the bounded tests %v times", found)
	}
	for _, line := range []string{
		"tags: sidecar_release_fixture, timeout: 3h0m0s, names: [TestSidecarReleaseFixture]",
		"tags: 'sidecar_testhooks,sidecar_pending,sidecar_filecluster_t3', timeout: 2h0m0s, stores: true, names: [TestFs86CardCommitsAtTheTeamLimitOnTheLayouts]",
	} {
		if !bytes.Contains(data, []byte(line)) {
			t.Errorf("the file lacks %q", line)
		}
	}
}

func TestGateCaseCamelAndTestNames(t *testing.T) {
	for caseName, want := range map[string]string{"": "", "config-read": "ConfigRead", "format-1": "Format1", "m5-steps": "M5Steps", "section-21": "Section21"} {
		if got := gateCaseCamel(caseName); got != want {
			t.Errorf("%q camel %q, want %q", caseName, got, want)
		}
	}
	testCase := DefaultCatalog().Case("FS-19", "quick-burner")
	if GateT2TestName(testCase) != "TestFs19QuickBurner" || GateT3TestName(testCase) != "TestFs19QuickBurnerOnT3" {
		t.Fatalf("%s, %s", GateT2TestName(testCase), GateT3TestName(testCase))
	}
	for gate, want := range map[string]string{"M1": "M1-out", "M10": "M10-out", "M6-in": "M6-in", "every": GateEveryOut, "next": GateNextCluster, "G0": "", "M11": "", "M01": ""} {
		if got := gateCatalogName(gate); got != want {
			t.Errorf("%s reads %q, want %q", gate, got, want)
		}
	}
}

// G0 and every entry review open with D-ARCH-4's assembly check, which server's gate tool runs; no exit review
// carries it.
func TestGateFileRunsTheAssemblyAtEveryEntryReview(t *testing.T) {
	data, err := GateFile(DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	for _, gate := range GateNames() {
		found := false
		for _, row := range file.Gates[gate] {
			if strings.HasPrefix(row.Item, "D-ARCH-4's assembly check") {
				found = true
				if len(row.Commands) != 1 || row.Commands[0].Repo != "server" || !slices.Equal(row.Commands[0].Command, []string{"go", "run", "./local/sidecar-gate", "assembly"}) {
					t.Errorf("%s's assembly row runs %+v", gate, row.Commands)
				}
			}
		}
		if want := gate == "G0" || strings.HasSuffix(gate, "-in"); found != want {
			t.Errorf("%s carries the assembly row: %t, want %t", gate, found, want)
		}
	}
}
