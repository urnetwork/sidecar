package fault

// M7's exit sweep (gate_m7.go; TEST-M7-01): each row names its tests where they run, FS-33 by the two strict
// scenarios and its mixed arrangements, a tier no owner's test runs keeps the convention's entry, and the items carry
// §22.7's rows through the registry, the ledger's T4-05, the census harness, the mailbox re-form with nothing to run,
// and the census and DANE on real senders open; nothing gate_m1.go once carried for M7 is left there.

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// M7's rows: FS-13, FS-33, FS-39's labels case and FS-41's and FS-42's M7 steps by their owners' tests alone, FS-47's
// and FS-82's mail cases and FS-121 by their T2 tests beside the convention's T3 entry, and every other case by the
// convention, the later-of mailbox cases open on M10's exit.
func TestGateM7NamesEachRowsTestsWhereTheyRun(t *testing.T) {
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
		// the case runs on T3 by the convention's test alone, which nothing has written
		conventionT3 bool
	}{
		{rowId: "FS-13", names: []string{"TestFs13ErasedDepositAndIndexCopiesAfterAConsumeCrash"}},
		{rowId: "FS-33", names: []string{
			"TestStrictScenarioAUrnetworkZoneDirectMxIsRedirectable", "TestStrictScenarioACustomerSignedCustomMxCarriesTheClaim",
			"TestStrictMixedArrangements", "TestStrictMixedArrangementsCoverEveryMix",
		}},
		{rowId: "FS-39", caseName: "labels", names: []string{"TestFs39LabelsAsStatedThroughTheReceiver"}},
		{rowId: "FS-47", caseName: "mail", names: []string{"TestMailEraseRefused429WaitsAndResumes"}, conventionT3: true},
		{rowId: "FS-82", caseName: "mail", names: []string{"TestMailIndexerAnUndesignatedTagMailDeviceRegistersNoListener", "TestMailIndexerAScopeDepositFromAnotherMembersDeviceAlarms"}, conventionT3: true},
		{rowId: "FS-121", names: []string{"TestFs121MaximalSignaturesThroughTheReceiver", "TestFs121ArcChainsThroughTheReceiver", "TestFs121AlignmentThroughTheReceiver"}, conventionT3: true},
		{rowId: "FS-41", caseName: "m7", names: []string{"TestMailHostKeyRemovalEffectIsOneResult", "TestDnsKeyRecordPublishesTheCallersKeyOnly"}},
		{rowId: "FS-42", caseName: "m7", names: []string{"TestMailHostKeyRemovalEffectIsOneResult", "TestDnsTlsaRemovalEffectIsOneResult"}},
	} {
		testCase := catalog.Case(want.rowId, want.caseName)
		row := gateFileRow(file, "M7", want.rowId, want.caseName)
		if row == nil {
			t.Errorf("M7 has no %s %q", want.rowId, want.caseName)
			continue
		}
		names := gateRowNamesForTest(row)
		for _, name := range want.names {
			if !slices.Contains(names, name) {
				t.Errorf("%s at M7 runs %v, which lacks %s", testCase, names, name)
			}
		}
		serverTests := []*GateTest{}
		for _, test := range row.Tests {
			if test.Repo == "server" {
				serverTests = append(serverTests, test)
			}
		}
		convention := []*GateTest{{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{GateT3TestName(testCase)}}}
		if want.conventionT3 && !reflect.DeepEqual(serverTests, convention) {
			t.Errorf("%s at M7 runs %s on T3, not the convention's test alone", testCase, gateTestsStringForTest(serverTests))
		}
	}
	// every other case keeps the convention, FS-23's mailbox case and the later-of mailbox cases among them
	swept := gateM7Cases(catalog)
	for _, row := range GateRows(catalog, "M7") {
		if row.Row == "" {
			continue
		}
		testCase := catalog.Case(row.Row, row.Case)
		if _, ok := swept[testCase.String()]; ok {
			continue
		}
		if tests := gateConventionalTests(testCase); !reflect.DeepEqual(row.Tests, tests) {
			t.Errorf("%s at M7 runs %s, the convention %s", testCase, gateTestsStringForTest(row.Tests), gateTestsStringForTest(tests))
		}
	}
	for _, key := range []string{"FS-23's mailbox", "FS-76's mailbox", "FS-78's mailbox", "FS-111's mailbox", "FS-112's mailbox"} {
		if _, ok := swept[key]; ok {
			t.Errorf("M7's sweep names %s, which keeps the convention", key)
		}
	}
	for _, rowId := range []string{"FS-76", "FS-112"} {
		if row := gateFileRow(file, "M7", rowId, "mailbox"); row == nil || !strings.Contains(row.External, "M10-out") {
			t.Errorf("%s's mailbox case at M7, the earlier of its gates: %+v", rowId, row)
		}
	}
}

// M7's items: the rules and FI bindings, §22.7's four rows at M7, T4-05 closed by the mixed arrangements, the mailbox
// re-form with nothing to run, the census harness, and the census and DANE on real senders open on production; the
// census run once, moved from gate_m1.go, and nothing for the SNI loss.
func TestGateM7ItemsSayWhatProductionOwes(t *testing.T) {
	items, find := gateItemsForTest(t, "M7")
	find("§22.8's rules on every row")
	find("every FI the rows check")
	// §22.7's strict, splice, label and MTA-STS rows through the registry, each with what is registered to it
	for _, assertId := range []string{"strict-mode", "splices", "mail-labels", "mta-sts-claims"} {
		find("§22.7's " + assertId + " assertion")
	}
	if row := find("the ledger's T4-05 closed"); !slices.Equal(gateRowNamesForTest(row), []string{"TestStrictMixedArrangements", "TestStrictMixedArrangementsCoverEveryMix"}) {
		t.Errorf("T4-05's item: %+v", row)
	}
	if row := find("FS-41's M7 step, a mailbox re-formed after a site loss"); 0 < len(row.Tests) || 0 < len(row.Commands) || row.External != "" {
		t.Errorf("the mailbox re-form, which no test shows yet, reads %+v", row)
	}
	if row := find("the census run's harness"); !slices.Contains(gateRowNamesForTest(row), "TestCensusOnScriptedSenders") || row.External != "" {
		t.Errorf("the census harness: %+v", row)
	}
	census := find("D-MAIL-9's census run, with §14's outbound probe")
	if !strings.HasPrefix(census.External, "production") || 0 < len(census.Tests) || !strings.Contains(census.Item, "BS1") {
		t.Errorf("the census run: %+v", census)
	}
	if row := find("DANE on real senders"); !strings.HasPrefix(row.External, "production") || 0 < len(row.Tests) {
		t.Errorf("DANE on real senders: %+v", row)
	}
	// the owner's acceptance of the SNI loss is BS1's and no test, so no item stands for it
	for _, item := range items {
		if strings.Contains(item.Item, "SNI") {
			t.Errorf("M7 holds an item for the SNI loss: %q", item.Item)
		}
	}
	if count := len(gateSweep("M7").Items); count != len(items) {
		t.Errorf("M7's sweeps add %d items, the file %d", count, len(items))
	}
	censusItems := 0
	for _, item := range items {
		if strings.HasPrefix(item.Item, "D-MAIL-9's census run") {
			censusItems += 1
		}
	}
	if censusItems != 1 {
		t.Errorf("M7 holds the census run %d times", censusItems)
	}
}
