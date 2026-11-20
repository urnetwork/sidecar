package fault

// The held gate (TEST-M10-06; gate_held.go): it holds each of §23.6's later-of cases once, by case, named where its
// tests run and as M10's exit names it, each earlier exit reading it open on the later gate; its written item reads
// fault.Missing at the held gate, with the outcome the tool reads; and its items say what the gate shows.

import (
	"flag"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The flag only sidecar-gate held's written item passes (gate_held.go).
var gateHeldWrittenFlagValue = flag.Bool(GateHeldWrittenFlag, false, "report the held gate's written item for sidecar-gate held")

// The held cases the written item reads failing on this tree, each with the task whose builder it is: their schedules
// assert in their steps and name no invariant in Check (TEST.md's contract for schedule authors, rule 4), which M10's
// entry and exit read failing too (gateM10InKnownFailing, gateM10OutKnownFailing). The gate's command reads them fail;
// this list only keeps the merge's run below to new failures, and a case here that reads written is logged, to come off
// the list.
var gateHeldKnownFailing = map[string]string{
	"FS-87's index":    "RECORD-M10-06",
	"FS-88's searches": "RECORD-M10-06",
	"FS-99's cards":    "RECORD-M10-06",
}

// §23.6's later-of cases as TEST-M10-06's Build line lists them, written out so a catalog that drops or adds one fails
// here: the hold cases (M5), the team and directory format-2 cases (M6), the mailbox cases (M7) and the app-host cases
// (M8), each with M10's exit, in row order.
var gateHeldCasesForTest = []string{
	"FS-66's hold",
	"FS-69",
	"FS-76's team-record", "FS-76's mailbox", "FS-76's hold",
	"FS-77's app-host",
	"FS-78's mailbox", "FS-78's hold",
	"FS-80's team-record",
	"FS-83's app-host", "FS-83's team",
	"FS-84's cards",
	"FS-86's cards",
	"FS-87's index",
	"FS-88's searches",
	"FS-92",
	"FS-99's cards",
	"FS-100's format-2",
	"FS-101's r-file",
	"FS-109's app-host",
	"FS-110's app-host",
	"FS-111's mailbox", "FS-111's team-record",
	"FS-112's mailbox",
	"FS-125's app-host",
}

// The held gate holds each later-of case once, in row order, and nothing else as a row: the catalog's GateHeld is its
// later_of flag, a case at the held gate waits on no later gate, only on its T4 part or what the catalog marks open,
// and keeps its store clock.
func TestGateHeldHoldsEachLaterOfCaseOnce(t *testing.T) {
	catalog := DefaultCatalog()
	data, err := GateFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	got := []string{}
	for _, row := range file.Gates["held"] {
		if row.Row == "" {
			continue
		}
		testCase := catalog.Case(row.Row, row.Case)
		if testCase == nil {
			t.Errorf("held holds %s %q, which the catalog does not", row.Row, row.Case)
			continue
		}
		got = append(got, testCase.String())
		if row.External != gateCaseExternal(testCase, GateHeld) || row.StoreClock != testCase.StoreClock {
			t.Errorf("%s at held: external %q, store clock %t, not the catalog's", testCase, row.External, row.StoreClock)
		}
		if strings.Contains(row.External, "the later of") {
			t.Errorf("%s at held waits on a later gate: %q", testCase, row.External)
		}
		if t4 := slices.Contains(testCase.Tiers(), TierT4); t4 != strings.Contains(row.External, "its T4 part") {
			t.Errorf("%s at held runs on T4 %t and its external reads %q", testCase, t4, row.External)
		}
	}
	if !slices.Equal(got, gateHeldCasesForTest) {
		t.Errorf("held holds %v, want %v", got, gateHeldCasesForTest)
	}
	rowIds := []string{}
	for _, testCase := range catalog.GateCases(GateHeld) {
		if !testCase.LaterOf || !testCase.AtGate(GateHeld) {
			t.Errorf("the catalog holds %s at the held gate, and it is no later-of case", testCase)
		}
		if !slices.Contains(rowIds, testCase.Row.Id) {
			rowIds = append(rowIds, testCase.Row.Id)
		}
	}
	if len(catalog.GateCases(GateHeld)) != 25 || len(rowIds) != 20 {
		t.Errorf("the held gate holds %d cases of %d rows, want 25 of 20", len(catalog.GateCases(GateHeld)), len(rowIds))
	}
	for _, row := range catalog.Rows {
		for _, testCase := range row.Cases {
			if testCase.AtGate(GateHeld) != testCase.LaterOf {
				t.Errorf("%s: later_of %t, at the held gate %t", testCase, testCase.LaterOf, testCase.AtGate(GateHeld))
			}
		}
	}
	if gateCatalogName("held") != GateHeld || !slices.Contains(GateNames(), "held") {
		t.Errorf("the tool's held gate reads %q in the catalog, and the tool's gates are %v", gateCatalogName("held"), GateNames())
	}
	// a case naming the held gate in catalog.yml is refused: it is the later_of flag's, never a case's own
	if _, err := ParseCatalog([]byte(strings.Replace(string(catalogYaml), "{name: hold, gates: [M5-out, M10-out], later_of: true, store_clock: true}", "{name: hold, gates: [held], store_clock: true}", 1))); err == nil || !strings.Contains(err.Error(), `names gate "held"`) {
		t.Errorf("a case naming the held gate parsed: %v", err)
	}
}

// Each earlier exit reads its later-of cases open on the later gate, never pass, and M10's exit, the later gate of every
// one, reads each by the tests the held gate names, so the two never read one case two ways.
func TestGateM10AndTheEarlierExitsReadEachHeldCaseAsTheHeldGate(t *testing.T) {
	catalog := DefaultCatalog()
	data, err := GateFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	earlier := map[string]int{}
	for _, testCase := range catalog.GateCases(GateHeld) {
		held := gateFileRow(file, "held", testCase.Row.Id, testCase.Name)
		m10 := gateFileRow(file, "M10", testCase.Row.Id, testCase.Name)
		if held == nil || m10 == nil {
			t.Errorf("%s: held %+v, M10 %+v", testCase, held, m10)
			continue
		}
		if !reflect.DeepEqual(m10.Tests, held.Tests) || m10.External != held.External || m10.StoreClock != held.StoreClock {
			t.Errorf("%s at M10 runs %s (external %q), and at held %s (external %q)", testCase, gateTestsStringForTest(m10.Tests), m10.External, gateTestsStringForTest(held.Tests), held.External)
		}
		for _, catalogGate := range testCase.Gates {
			if catalogGate == gateM10OutGate {
				continue
			}
			gate := strings.TrimSuffix(catalogGate, "-out")
			row := gateFileRow(file, gate, testCase.Row.Id, testCase.Name)
			if row == nil || !strings.Contains(row.External, "the later of "+catalogGate+" and M10-out, where it passes") {
				t.Errorf("%s at %s does not wait on the later gate: %+v", testCase, gate, row)
				continue
			}
			earlier[gate] += 1
		}
	}
	if want := map[string]int{"M5": 5, "M6": 11, "M7": 4, "M8": 5}; !reflect.DeepEqual(earlier, want) {
		t.Errorf("the earlier exits read %v held cases open, want %v", earlier, want)
	}
}

// The held gate names each case's tests where they run: the hold cases' T3 runs in server's model with every clause
// their owners wrote beside the registered run, FS-87's and FS-99's in server's root package, FS-101's r-file case by
// its thin test's own name, FS-86's card commits beside its card case, and the owners' tests of the mailbox cases and
// FS-78's hold clause beside the convention's entries, which no builder answers; every other case keeps the convention.
func TestGateHeldNamesEachCasesTestsWhereTheyRun(t *testing.T) {
	catalog := DefaultCatalog()
	data, err := GateFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	t2 := func(names ...string) *GateTest {
		return &GateTest{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: names}
	}
	t3 := func(packagePath string, names ...string) *GateTest {
		return &GateTest{Repo: "server", Package: packagePath, Tags: gateT3Tags, Stores: true, Names: names}
	}
	mailbox := func(rowId string, t2Name string, t3Name string) []*GateTest {
		testCase := catalog.Case(rowId, "mailbox")
		return append(gateConventionalTests(testCase),
			&GateTest{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{t2Name}},
			t3("./sidecart3", t3Name),
		)
	}
	want := map[string][]*GateTest{
		"FS-66's hold": {t2("TestFs66Hold"), t3("./model", "TestFs66HoldPlacedByApiOnT3")},
		"FS-69": {
			t2("TestFs69"),
			t3("./model", "TestFs69HoldsPlacedByApiOnT3", "TestFs69HoldBetweenSweepDeletesOnT3", "TestFs69EraseUnderTheHoldOnT3", "TestFs6NowShredUnderAHoldOnT3"),
			t2("TestFs69HoldBetweenSweepDeletes", "TestFs69EraseUnderTheHold", "TestFs6NowShredUnderAHold"),
		},
		"FS-78's hold": {t2("TestFs78Hold"), t3("./sidecart3", "TestFs78HoldOnT3"), t2("TestFs78UnderAHoldTheKeysGoAtOnceAndTheCiphertextStays")},
		"FS-92": {
			t2("TestFs92"),
			t3("./model", "TestFs92HoldsPlacedByApiOnT3", "TestFs92HoldBetweenVerifyAndDeleteOnT3", "TestFs92HoldBetweenDeletesOnT3", "TestFs92DeleteInFlightOnT3", "TestFs92SealedHoldAnswersEqualANoHoldTwinOnT3"),
			t2(
				"TestFs92HoldBetweenVerifyAndDelete", "TestFs92HoldBetweenDeletes", "TestFs92DeleteInFlight", "TestFs92HoldOutlastsTheDropTable",
				"TestFs92SecondDropDuringTheHold", "TestFs92SecondDropListsAsItsTwin", "TestFs92SealedHoldAnswersEqualANoHoldTwin",
				"TestFs92AHoldKeepsWhatTheDropWouldDeleteUntilItEnds", "TestFs92ASealedHoldsAnswersEqualANoHoldTwin",
			),
		},
		"FS-86's cards":    {t2("TestFs86Cards"), t3("./sidecart3", "TestFs86CardsOnT3"), t2("TestFs86CardsEvsCommits", "TestFs86CardsEvsCommitsFailPastTheirCeiling")},
		"FS-87's index":    {t2("TestFs87Index"), t3(".", "TestFs87IndexOnT3")},
		"FS-99's cards":    {t2("TestFs99Cards"), t3(".", "TestFs99CardsOnT3")},
		"FS-101's r-file":  {t2("TestFs101File")},
		"FS-76's mailbox":  mailbox("FS-76", "TestFs76MailboxCase", "TestT3MailM10Fs76MailboxCase"),
		"FS-78's mailbox":  mailbox("FS-78", "TestFs78MailboxCase", "TestT3MailM10Fs78MailboxCase"),
		"FS-111's mailbox": mailbox("FS-111", "TestFs111MailboxCase", "TestT3MailM10Fs111MailboxCase"),
		"FS-112's mailbox": mailbox("FS-112", "TestFs112MailboxCase", "TestT3MailM10Fs112MailboxCase"),
	}
	swept := []string{}
	for caseName := range gateSweep("held").Cases {
		swept = append(swept, caseName)
	}
	slices.Sort(swept)
	wantSwept := []string{}
	for caseName := range want {
		wantSwept = append(wantSwept, caseName)
	}
	slices.Sort(wantSwept)
	if !slices.Equal(swept, wantSwept) {
		t.Errorf("the held sweep names %v, want %v", swept, wantSwept)
	}
	for _, testCase := range catalog.GateCases(GateHeld) {
		row := gateFileRow(file, "held", testCase.Row.Id, testCase.Name)
		if row == nil {
			t.Errorf("held has no %s", testCase)
			continue
		}
		tests, ok := want[testCase.String()]
		if !ok {
			tests = gateConventionalTests(testCase)
		}
		if !reflect.DeepEqual(row.Tests, tests) {
			t.Errorf("%s at held runs %s, want %s", testCase, gateTestsStringForTest(row.Tests), gateTestsStringForTest(tests))
		}
	}
	// a case with no registered builder keeps every convention entry, so its row reads missing whatever its owners'
	// tests show, until a builder is registered on each of its tiers
	for _, caseName := range []string{"FS-76's mailbox", "FS-78's hold", "FS-78's mailbox", "FS-111's mailbox", "FS-112's mailbox"} {
		rowId, name, _ := strings.Cut(caseName, "'s ")
		testCase := catalog.Case(rowId, name)
		for _, tier := range testCase.Tiers() {
			if Lookup(rowId, name, tier) != nil {
				t.Logf("%s now has a builder on %s: its owners' tests can come out of the held sweep's also", testCase, tier)
			}
		}
		for _, convention := range gateConventionalTests(testCase) {
			if !slices.ContainsFunc(want[caseName], func(test *GateTest) bool { return reflect.DeepEqual(test, convention) }) {
				t.Errorf("%s drops the convention's %+v", testCase, *convention)
			}
		}
	}
	// a sweep naming a case the held gate does not hold panics where it is written
	panicked := func() (panicked bool) {
		defer func() {
			panicked = recover() != nil
		}()
		RegisterGateSweep(&GateSweep{Gate: "held", Cases: map[string][]*GateTest{"FS-66": {t2("TestFs66")}}})
		return false
	}()
	if !panicked {
		t.Error("the held gate took FS-66's main case, which is no later-of case")
	}
}

// The held gate's written item: its reason and outcome on the last two lines, failing the run only when a case fails.
// Without the flag, every held case is checked and logged with what fault.Missing reads at the held gate on each tier,
// and the test fails only on a failing builder gateHeldKnownFailing does not name, since a missing builder is the gate's
// to report and a known failure its owner's.
func TestGateHeldCasesWritten(t *testing.T) {
	cases := DefaultCatalog().GateCases(GateHeld)
	result := GateCasesWritten(t.Context(), cases, Lookup, nil)
	if *gateHeldWrittenFlagValue {
		// the tool reads the last outcome line and the line before it, so they are printed last
		fmt.Print(result.Lines())
		if result.Outcome == GateOutcomeFail {
			t.Fail()
		}
		return
	}
	t.Logf("%s: %s", result.Outcome, result.Reason)
	for _, tier := range []Tier{TierT2, TierT3} {
		names := []string{}
		for _, testCase := range Missing(GateHeld, tier) {
			names = append(names, testCase.String())
		}
		t.Logf("fault.Missing(GateHeld, %s): %d of %d cases: %s", tier, len(names), len(cases), strings.Join(names, ", "))
	}
	failed := []string{}
	for _, failure := range result.Failed {
		failed = append(failed, failure.Case.String())
		if owner, known := gateHeldKnownFailing[failure.Case.String()]; known {
			t.Logf("%s reads fail at the gate until %s names the invariants its schedule checks", failure.Case, owner)
			continue
		}
		t.Errorf("%s", failure.Reason)
	}
	for caseName := range gateHeldKnownFailing {
		if !slices.ContainsFunc(cases, func(testCase *Case) bool { return testCase.String() == caseName }) {
			t.Errorf("gateHeldKnownFailing names %s, which the held gate does not hold", caseName)
		}
		if !slices.Contains(failed, caseName) {
			t.Logf("%s reads written now: take it off gateHeldKnownFailing", caseName)
		}
	}
}

// The written item reads fault.Missing at the held gate: each case no builder covers on T2 reads missing there, each
// registered on T2 alone whose row runs on T3 reads missing on T3, and a case that reads written is in neither list. A
// fixture registry with every held case covered on each tier reads written, and one with none reads every case missing.
func TestGateHeldWrittenReadsFaultMissing(t *testing.T) {
	cases := DefaultCatalog().GateCases(GateHeld)
	result := GateCasesWritten(t.Context(), cases, Lookup, nil)
	for _, testCase := range Missing(GateHeld, TierT2) {
		if !slices.Contains(result.Missing, testCase.String()+" on T2") {
			t.Errorf("fault.Missing lists %s on T2, and the written item reads %v", testCase, result.Missing)
		}
	}
	for _, testCase := range Missing(GateHeld, TierT3) {
		if Lookup(testCase.Row.Id, testCase.Name, TierT2) == nil {
			continue
		}
		if !slices.Contains(result.Missing, testCase.String()+" on T3, registered on T2 alone") {
			t.Errorf("fault.Missing lists %s on T3, and the written item reads %v", testCase, result.Missing)
		}
	}
	for _, written := range result.Written {
		for _, tier := range written.Tiers() {
			if tier != TierT4 && slices.Contains(Missing(GateHeld, tier), written) {
				t.Errorf("%s reads written and fault.Missing lists it on %s", written, tier)
			}
		}
	}

	everyTier := func(rowId string, caseName string, tier Tier) *Registration {
		return &Registration{Row: rowId, Case: caseName, Tiers: []Tier{TierT2, TierT3}, Build: gateFixtureWritten}
	}
	if covered := GateCasesWritten(t.Context(), cases, everyTier, nil); covered.Outcome != GateOutcomePass || len(covered.Written) != len(cases) {
		t.Errorf("every held case covered: %s, %s", covered.Outcome, covered.Reason)
	}
	none := GateCasesWritten(t.Context(), cases, gateFixtureLookup(), nil)
	if none.Outcome != GateOutcomeMissing || len(none.Missing) != len(cases) || !strings.HasPrefix(none.Reason, "of 25 cases, 0 written, 25 missing") {
		t.Errorf("no held case covered: %s, %s", none.Outcome, none.Reason)
	}
}

// The held gate's items: §22.8's rules first, naming no unknown row, since none of the held rows is on the list; the
// written item with its command; the FI bindings at the held gate; the store clock naming the held cases flagged for it;
// D-TEST-17's readings of FS-86's card case and T4's search cells exactly as M10's exit carries them; FS-125's app-host
// case open on the owner; no assembly check, since the held gate is no entry review; and nothing else.
func TestGateHeldItemsSayWhatTheGateShows(t *testing.T) {
	catalog := DefaultCatalog()
	items, find := gateItemsForTest(t, "held")
	if len(items) != 9 || !strings.HasPrefix(items[0].Item, "§22.8's rules on every row") || !strings.Contains(items[0].Item, "(none at this gate)") {
		t.Fatalf("held's items: %d, opening with %+v", len(items), items[0])
	}
	if written := find("every held case written"); len(written.Commands) != 1 || !slices.Equal(written.Commands[0].Command, gateHeldWrittenCommand()) || written.Commands[0].Repo != "sidecar" || written.External != "" {
		t.Errorf("the written item: %+v", written)
	}
	if command := gateHeldWrittenCommand(); !slices.Contains(command, "-"+GateHeldWrittenFlag) || !slices.Contains(command, "^TestGateHeldCasesWritten$") {
		t.Errorf("the written item runs %v", command)
	}
	if invariants := find("every FI the rows check"); len(invariants.Commands) != 1 || !slices.Equal(invariants.Commands[0].Command, gateInvariantsCommand(GateHeld)) {
		t.Errorf("the invariants item: %+v", invariants)
	}
	clock := find("T3's store clock")
	for _, caseName := range []string{"FS-66's hold", "FS-69", "FS-86's cards", "FS-92", "FS-111's mailbox", "FS-111's team-record"} {
		if !strings.Contains(clock.Item, caseName) {
			t.Errorf("the store clock item does not name %s: %q", caseName, clock.Item)
		}
	}
	if !slices.Equal(gateStoreClockCases(catalog, GateHeld), []string{"FS-66's hold", "FS-69", "FS-86's cards", "FS-92", "FS-111's mailbox", "FS-111's team-record"}) {
		t.Errorf("the held store clock cases: %v", gateStoreClockCases(catalog, GateHeld))
	}
	m10Items := map[string]*GateRow{}
	for _, row := range GateRows(catalog, "M10") {
		if row.Item != "" {
			m10Items[row.Item] = row
		}
	}
	shared := append(gateFs86CardItems(), gateT4SearchCellsItem())
	for _, item := range shared {
		held := find(item.Item)
		m10 := m10Items[item.Item]
		if m10 == nil || !reflect.DeepEqual(held, m10) {
			t.Errorf("%q at held %+v, at M10 %+v", item.Item, held, m10)
		}
	}
	if fs125 := find("FS-125's app-host case held with PROTO-M10-05"); len(fs125.Tests) != 0 || !strings.HasPrefix(fs125.External, "people:") {
		t.Errorf("FS-125's item: %+v", fs125)
	}
	for _, item := range items {
		if strings.HasPrefix(item.Item, "D-ARCH-4's assembly check") || strings.Contains(item.Item, "versionless") {
			t.Errorf("held carries %q", item.Item)
		}
	}
	if outcome, reason := GateInvariantsBound(catalog, GateHeld, func(n int) bool { return true }); outcome != GateOutcomePass || !strings.Contains(reason, "FI-25, FI-26, FI-27") {
		t.Errorf("every FI the held cases check bound: %s, %s", outcome, reason)
	}
}

// Every test the held gate's rows and items name in this repo, outside a case's convention entry, is declared in its
// package in a file that builds under the entry's tags, and so is each the sdk names, in the sdk's checkout beside this
// one: a rename or a tag an owner adds fails here rather than only reading missing at the gate.
func TestGateHeldNamesSidecarAndSdkTestsDeclaredUnderTheirTags(t *testing.T) {
	catalog := DefaultCatalog()
	rows := GateRows(catalog, "held")
	for _, name := range gateUndeclaredSidecarTestsForTest(t, catalog, rows) {
		t.Errorf("held names %s, which is not declared so", name)
	}
	declared := gateDeclaredBesideThisCheckout(t)
	sdkNames := 0
	for _, row := range rows {
		for _, test := range row.Tests {
			if test.Repo != "sdk" {
				continue
			}
			for _, err := range declared(test) {
				t.Error(err)
			}
			sdkNames += len(test.Names)
		}
	}
	if sdkNames < 5 {
		t.Errorf("held names %d sdk tests", sdkNames)
	}
}
