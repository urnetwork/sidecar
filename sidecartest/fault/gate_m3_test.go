package fault

// M3's exit sweep and the next cluster's (TEST-M3-02): each row names its tests where they run, the items say what
// the exit shows and what production owes, FS-115's matrix names this host's volume and opens the rest, and the next
// cluster's review runs §22.9's file-cluster suite and reads open on the new cluster's hosts.

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// M3's rows: FS-25's T3 legs in api beside its T2 test, FS-41's and FS-42's restores and their owners' clauses where
// they run, and FS-50's page classes in monitor; the CLI cases, FS-119 and every other case keep the convention, its
// T3 entry under the local stack's tag.
func TestGateM3NamesEachRowsTestsWhereTheyRun(t *testing.T) {
	catalog := DefaultCatalog()
	data, err := GateFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	named := map[string][]string{
		"FS-25":  {"TestFs25", "TestFs25GateResponseLostAfterCommit", "TestFs25TwoApiInstancesRacing", "TestFs25TwoUsesThreeActions", "TestFs25CancelThroughTheRouteRefusesTheRest"},
		"FS-41":  {"TestFs41SiteLossThroughTheCloseOnT3", "TestSiteCloseWithRestrictedUsersAcrossMetadataClusters", "TestFileClusterReseedStorageLossesOnT3", "TestAdoptConfigRunTakesNoPositionOneMemberHoldsAlone", "TestEvsReseedKeepsAnErasedKeyOutOfAStaleMirrorsSlotEndToEnd", "TestAVaultReformedByItsOwnersDeviceKeepsEveryReader", "TestACodeOnlyDeviceReadsOnlyItsWrapsBeforeAdmission"},
		"FS-42":  {"TestFs42MainDumpOlder", "TestFs42MainDumpNewer"},
		"FS-50":  {"TestPageClassAt0200PagesTheSecondPersonAt30MinutesNotBefore", "TestFileClusterPageConditionsAt0200ReachThePager", "TestPostgresPrimaryDownPages"},
		"FS-98":  {"TestFs98Cli", "TestFs98CliOnT3"},
		"FS-124": {"TestFs124Cli", "TestFs124CliOnT3"},
	}
	cases := map[string]string{"FS-98": "cli", "FS-124": "cli"}
	for rowId, names := range named {
		row := gateFileRow(file, "M3", rowId, cases[rowId])
		if row == nil {
			t.Errorf("M3 has no %s", rowId)
			continue
		}
		rowNames := []string{}
		for _, test := range row.Tests {
			rowNames = append(rowNames, test.Names...)
		}
		for _, name := range names {
			if !slices.Contains(rowNames, name) {
				t.Errorf("%s at M3 runs %v, which lacks %s", rowId, rowNames, name)
			}
		}
	}
	// the CLI cases by convention, their T3 tests in sidecart3 under the local stack's tag
	for _, rowId := range []string{"FS-98", "FS-124"} {
		testCase := catalog.Case(rowId, "cli")
		row := gateFileRow(file, "M3", rowId, "cli")
		want := []*GateTest{
			{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{GateT2TestName(testCase)}},
			{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{GateT3TestName(testCase)}},
		}
		if row == nil || !reflect.DeepEqual(row.Tests, want) {
			t.Errorf("%s at M3 runs %v, want %s", testCase, row, gateTestsStringForTest(want))
		}
	}
	// every other case keeps the convention, FS-119 among them
	swept := gateM3Cases(catalog)
	for _, row := range GateRows(catalog, "M3") {
		if row.Row == "" {
			continue
		}
		testCase := catalog.Case(row.Row, row.Case)
		if _, ok := swept[testCase.String()]; ok {
			continue
		}
		if conventional := gateConventionalTests(testCase); !reflect.DeepEqual(row.Tests, conventional) {
			t.Errorf("%s at M3 runs %s, the convention %s", testCase, gateTestsStringForTest(row.Tests), gateTestsStringForTest(conventional))
		}
	}
	if fs119 := gateFileRow(file, "M3", "FS-119", ""); fs119 == nil || !slices.Contains(fs119.Tests[0].Names, "TestFs119OnT3") {
		t.Errorf("FS-119 at M3 reads %+v, not the convention's T3 test", fs119)
	}
}

// M3's items say what its exit shows and what production owes: the record.proto freeze with its vectors and fuzz
// seeds, FI-7's and FI-8's item, FS-115 on this host's volume and every other volume open on hardware, the ledger's
// FS-41 gap with nothing to run, and production's runs, restore and drill open; nothing gate_m1.go once carried for
// M3 is left there.
func TestGateM3ItemsSayWhatProductionOwes(t *testing.T) {
	catalog := DefaultCatalog()
	items := []*GateRow{}
	for _, row := range GateRows(catalog, "M3") {
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
		t.Errorf("M3 has no item %q...", prefix)
		return &GateRow{}
	}
	record := find("record.proto's bytes freeze")
	recordNames := []string{}
	for _, test := range record.Tests {
		recordNames = append(recordNames, test.Names...)
	}
	for _, name := range []string{"TestRecordFreezeVectorsVerifyOnThisLeg", "TestRecordHashesCoverStoredBytes", "FuzzRecordHeader", "FuzzRecordEntry"} {
		if !slices.Contains(recordNames, name) {
			t.Errorf("the record.proto item lacks %s", name)
		}
	}
	if row := find("FI-7 and FI-8 answer"); len(row.Tests) == 0 {
		t.Error("FI-7 and FI-8's item names no test")
	}
	if row := find("FS-115's apply on this host's own volume"); row.External != "" || len(row.Tests) != 1 {
		t.Errorf("FS-115 on this host: %+v", row)
	}
	for _, volume := range gateRestoreVolumes {
		if row := find("FS-115's apply on " + volume); !strings.HasPrefix(row.External, "hardware:") || 0 < len(row.Tests) {
			t.Errorf("FS-115 on %s: %+v", volume, row)
		}
	}
	if row := find("the ledger's named gap in FS-41"); 0 < len(row.Tests) || 0 < len(row.Commands) || row.External != "" {
		t.Errorf("the FS-41 gap, which no test shows yet, reads %+v", row)
	}
	for _, prefix := range []string{"the nvme and hdd runs on the production hosts", "one restore of a real sidecar dump generation"} {
		if row := find(prefix); !strings.HasPrefix(row.External, "production") {
			t.Errorf("%q waits on %q", prefix, row.External)
		}
	}
	find("§22.8's rules on every row")
	find("every FI the rows check")
	find("TLC passes EvsCommit.tla")
	if gateSweep("M3").Gate != "M3" || len(gateSweep("M3").Items) != len(items) {
		t.Errorf("M3's sweeps add %d items, the file %d", len(gateSweep("M3").Items), len(items))
	}
}

// The next cluster's review holds FS-63's and FS-119's next-cluster cases, each open on production as catalog.yml
// marks them, and §22.9's file-cluster suite, run here on the local stack and T3's layouts and open on the new
// cluster's own hosts.
func TestGateNextRunsTheFileClusterSuite(t *testing.T) {
	catalog := DefaultCatalog()
	rows := GateRows(catalog, "next")
	cases := []string{}
	var suite *GateRow
	for _, row := range rows {
		if row.Row != "" {
			cases = append(cases, row.Row+"/"+row.Case)
			if !strings.HasPrefix(row.External, "production") {
				t.Errorf("%s at next waits on %q", row.Row, row.External)
			}
			continue
		}
		if strings.HasPrefix(row.Item, "§22.9's file-cluster suite") {
			suite = row
		}
	}
	if !slices.Equal(cases, []string{"FS-63/next-cluster", "FS-119/next-cluster"}) {
		t.Errorf("next holds %v", cases)
	}
	if suite == nil || len(suite.Tests) == 0 || !strings.HasPrefix(suite.External, "production") {
		t.Fatalf("next's file-cluster suite: %+v", suite)
	}
}
