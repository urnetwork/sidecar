package fault

// M8's exit sweep (gate_m8.go; TEST-M8-01): FS-36, FS-120, FS-82's coverage case and FS-41's and FS-42's M8 steps by
// their owners' tests, every other case by the convention, and the items: §22.7's wake row on the wake vendors'
// capture, the ledger's T4-16 on the CGNAT fixture, §22.5's forwarding cases, the mail indexer paths and prompt, the
// two traps as items that fail nothing, T4 through the ledger, and the census gate open.

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// M8's rows: FS-36 on both tiers and FS-120 on server's rows by their owners' tests, FS-82's coverage case where MAIL
// wrote it, FS-41's and FS-42's push-token steps, and every other case by the convention, a T4 part reading open.
func TestGateM8NamesEachRowsTestsWhereTheyRun(t *testing.T) {
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
		{rowId: "FS-36", names: []string{"TestFs36LostClientsMailHintWakesOnceAt25s", "TestFs36LostClientsMailHintWakesOnceAt25sOverTheRows", "TestFs36TwoMastersRestartedWakesResumeAfterTheReconcile"}},
		{rowId: "FS-120", names: []string{"TestFs120TwoPostsApplyInReverseCommitOrder", "TestFs120Vendor410RacingANewPost", "TestFs120RemovedClientsRowAndKeysGoneAt24h"}},
		{rowId: "FS-82", caseName: "coverage", names: []string{"TestMailCoverageForegroundOnlyThenIndexer", "TestMailM8IndexerPathsTakeMailAndEndThePrompt", "TestT3MailM8IndexerPathsTakeMailAndEndThePrompt"}},
		{rowId: "FS-41", caseName: "m8", names: []string{"TestFs41PushTokensReRegister"}},
		{rowId: "FS-42", caseName: "m8", names: []string{"TestFs42PushTokenRevisionsRaisedPastTheLostPrimary", "TestFs42PushTokensRaisedOncePerIncident", "TestFs42PushTokenRaiseSkippedBeforeMg8"}},
	} {
		row := gateFileRow(file, "M8", want.rowId, want.caseName)
		if row == nil {
			t.Errorf("M8 has no %s %q", want.rowId, want.caseName)
			continue
		}
		names := gateRowNamesForTest(row)
		for _, name := range want.names {
			if !slices.Contains(names, name) {
				t.Errorf("%s %q at M8 runs %v, which lacks %s", want.rowId, want.caseName, names, name)
			}
		}
	}
	// every other case keeps the convention: the quick-burner run, the wakes and the app-host cases
	swept := gateM8Cases(catalog)
	for _, row := range GateRows(catalog, "M8") {
		if row.Row == "" {
			continue
		}
		testCase := catalog.Case(row.Row, row.Case)
		if _, ok := swept[testCase.String()]; ok {
			continue
		}
		if tests := gateConventionWithClausesForTest(testCase); !reflect.DeepEqual(row.Tests, tests) {
			t.Errorf("%s at M8 runs %s, the convention %s", testCase, gateTestsStringForTest(row.Tests), gateTestsStringForTest(tests))
		}
	}
	for _, key := range []string{"FS-19's quick-burner", "FS-85's wakes", "FS-100's wakes", "FS-98's app-host", "FS-124's app-host", "FS-77's app-host"} {
		if _, ok := swept[key]; ok {
			t.Errorf("M8's sweep names %s, which keeps the convention", key)
		}
	}
	// a case with a T4 part reads open on it whatever its tests do
	if row := gateFileRow(file, "M8", "FS-98", "app-host"); row == nil || !strings.Contains(row.External, "T4") {
		t.Errorf("FS-98's app-host case at M8: %+v", row)
	}
}

// M8's items: the rules and FI bindings, §22.7's wake row by its two tests and its MX scope row, T4-16 closed on the
// fixture, the forwarding cases, the indexer paths and prompt, the foreground-only trap waiting on nothing, and T4,
// the vendors and the census gate open.
func TestGateM8ItemsSayWhatDevicesAndProductionOwe(t *testing.T) {
	items, find := gateItemsForTest(t, "M8")
	find("§22.8's rules on every row")
	find("every FI the rows check")
	// §22.7's wake row: the payloads' shape and scan, and the mutant an id fails
	wake := find("§22.7's wake-payloads assertion")
	if !strings.Contains(wake.Item, "wake payloads carry only a topic class and version") ||
		!slices.Equal(gateRowNamesForTest(wake), []string{"TestWakePayloadsCarryOnlyATopicClassAndVersion", "TestAWakePayloadCarryingAnIdFails"}) {
		t.Errorf("the wake row: %+v", wake)
	}
	for _, test := range wake.Tests {
		if test.Repo != "sidecar" || test.Package != "./sidecartest" {
			t.Errorf("the wake row runs %+v", test)
		}
	}
	find("§22.7's mx-scope assertion")
	cgnat := find("the ledger's T4-16 closed")
	if !slices.Equal(gateRowNamesForTest(cgnat), []string{"TestBridgeCgnatCarrierResolverKeepsItsCarve", "TestBridgeCgnatDroppingTheResolverCarveFails", "TestBridgeCgnatCarrierResolverAtTheOverlayResolversAddress"}) ||
		cgnat.External != "" || !strings.Contains(cgnat.Item, "T6 form") {
		t.Errorf("T4-16's item: %+v", cgnat)
	}
	forwarding := gateRowNamesForTest(find("§22.5's forwarding cases"))
	for _, name := range []string{"TestForwardingSetupHandsOffAfterSixSteps", "TestFs38ForwardingDelegation", "TestFwdAppRollback", "TestFs38ForwardingOnT3", "TestForwardingClientMint"} {
		if !slices.Contains(forwarding, name) {
			t.Errorf("the forwarding item lacks %s", name)
		}
	}
	indexer := gateRowNamesForTest(find("the mail indexer paths and the prompt"))
	for _, name := range []string{"TestMailM8IndexerPathsTakeMailAndEndThePrompt", "TestT3MailM8IndexerPathsTakeMailAndEndThePrompt", "TestMailM8CreateBurnerShowsTheCopyBeforeAFirstBurner"} {
		if !slices.Contains(indexer, name) {
			t.Errorf("the indexer item lacks %s", name)
		}
	}
	// the traps: a foreground-only coverage fails nothing and waits on nothing, and T4 reads open on devices
	if row := find("a foreground-only coverage shows its copy and fails nothing"); row.External != "" || !slices.Contains(gateRowNamesForTest(row), "TestMailCoverageForegroundOnlyThenIndexer") {
		t.Errorf("the foreground-only item: %+v", row)
	}
	if row := find("T4 joins here through the ledger"); !strings.HasPrefix(row.External, "devices") || !strings.Contains(row.Item, "owner decision 100") {
		t.Errorf("T4's item: %+v", row)
	}
	if row := find("wakes through Apple's and Google's push services"); !strings.HasPrefix(row.External, "production") || 0 < len(row.Tests) {
		t.Errorf("the vendors' item: %+v", row)
	}
	if row := find("R-TEST-8's census gate on burners"); !strings.HasPrefix(row.External, "people") || 0 < len(row.Tests) || !strings.Contains(row.Item, "BS1") {
		t.Errorf("the census gate: %+v", row)
	}
	if count := len(gateSweep("M8").Items); count != len(items) {
		t.Errorf("M8's sweeps add %d items, the file %d", count, len(items))
	}
}
