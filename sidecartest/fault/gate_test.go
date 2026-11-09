package fault

import (
	"bytes"
	"slices"
	"strings"
	"testing"

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
		{gate: "M2", rowId: "FS-1", t2: "TestFs1", t3: "TestFs1OnT3"},
		{gate: "M2", rowId: "FS-19", caseName: "config-read", t2: "TestFs19ConfigRead", t3: "TestFs19ConfigReadOnT3"},
		{gate: "M2", rowId: "FS-9", t2: "TestFs9"},
		// forged: T2 alone, and its twin on T3
		{gate: "M2", rowId: "FS-10", t2: "TestFs10", t3: "TestFs10OnT3"},
		{gate: "M2", rowId: "FS-5", t3: "TestFs5OnT3"},
		{gate: "M6-in", rowId: "FS-46", t2: "TestFs46", t3: "TestFs46OnT3"},
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
