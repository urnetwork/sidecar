// The held gate (TEST-M10-06; §23.6's later-of cases, §22.17's v1 cases "at the later of their rows' exits", D-TEST-9,
// D-TEST-17): the sweep `sidecar-gate held` reports, case by case, pass, fail, missing or open. §23.6 holds a case until
// two exits have both passed, the earlier exit's row saying "once M10's Gn-out has passed" and M10's "unless M5's,
// M6's, M7's or M8's exit follows", and with M0-M10 built straight through (owner decision 194) every such case falls
// due at M10's exit. catalog.yml marks each later_of, and GateHeld is the catalog's name for them all, so
// fault.Missing(GateHeld, tier) lists each held case no builder covers on that tier. They are 25 cases of 20 rows:
//
//   - the hold cases (M5 and M10): FS-66's, FS-76's and FS-78's hold cases, and FS-69 and FS-92 whole;
//   - the team cases (M6 and M10): FS-76's, FS-80's and FS-111's team-record cases and FS-83's team case;
//   - the directory's format-2 cases (M6 and M10): FS-84's, FS-86's and FS-99's card cases, FS-87's index case, FS-88's
//     searches, FS-100's format-2 case and FS-101's r-file case;
//   - the mailbox cases (M7 and M10): FS-76's, FS-78's, FS-111's and FS-112's;
//   - the app-host cases (M8 and M10): FS-77's, FS-83's, FS-109's, FS-110's and FS-125's.
//
// Each is a case of its own of a row other sweeps ran, so a row reading pass at M10 says nothing of its held case: the
// report is by case, and each earlier exit reads its held cases open, naming the later gate (gateCaseExternal). Like
// every sweep it adds no mechanism: a failure or a missing test goes back to the task that owns the mechanism and stays
// in the report until fixed. A case's tests are named by the rules M6's and M10's sweeps set out, and M10's exit names
// the same tests for each of these cases (gateM10Cases takes gateHeldCases), so the two gates never read one case two
// ways:
//
//   - A case with a registered builder keeps the convention but where a run is elsewhere: FS-66's hold case, FS-69 and
//     FS-92 on T3 in server's model against api's real hold/ writes (ABUSE-M10-01); FS-87's index case and FS-99's card
//     case on T3 in server's root package (RECORD-M10-06); and FS-101's r-file case by its thin test's own name.
//   - The clauses a case's owners run as fixed schedules beside its registered one (fault.RunClause) run with it, so
//     the case reads pass only when every clause does, as QD-1084's clause registry will have the convention name
//     them: FS-69's clauses between the sweep's deletes and of an ERASE under the hold, with FS-6's --now shred under
//     it, which FS-69 names; FS-92's (b) and (c) clauses with (a)'s long hold and second drop (QD-1113, QD-1127), and
//     EVSB-M10-06's drop world's (a) and (c); each on T3 where its owner wrote it there. FS-86's card commits on T2's
//     fakes run with its card case.
//   - A case with no registered builder keeps the convention's entries, so it reads missing whatever tests of it exist
//     (rule 1 of TEST.md's contract for schedule authors: a row is a registered builder, and a gate finds nothing else
//     as one), and the tests its owners wrote of it run beside them, so a failing one reads fail: the mailbox cases on
//     a real mailbox (MAIL-M10-04; sidecartest's mail_m10_test.go and server's sidecart3 mail_m10_t3_test.go), and
//     FS-78's hold clause on the search world (SEARCH-M10-37).
//   - A tier the catalog names and no builder runs keeps the convention's entry, which nothing has written: the T3 runs
//     of FS-86's card case and FS-100's format-2 case, whose builders are registered on T2 alone, in test files.
//   - Every other case keeps the convention and reads missing: FS-76's hold and team-record cases, FS-80's and
//     FS-111's team-record cases, FS-83's team case and the app-host cases, whose T4 parts read open besides.
//
// DESIGN-DETAILS 16.6's versionless row, with SEARCH-M10-24's mask of an ignored version and SEARCH-M10-12's coverage of
// an ignored push on its breach, is not here: it is a prefix-rules row, the rules moved to Later (QD-1032; DESIGN-DEFER's
// client-checked prefix write rules) and TEST-M6-03 is held with them, which left this gate's needs.
//
// Beside the rows, the items: §22.8's rules; every held case written, a builder registered on each tier it runs on,
// which is fault.Missing at the held gate ending empty; the FI bindings; T3's store clock for the hold, card and FS-111
// cases; D-TEST-17's readings of FS-86's card case and T4's search cells for the app-host cases' T4 parts, each the item
// M10's exit carries; and FS-125's app-host case held with C19's windows (QD-1038). An item that is no go test is a
// command whose last line says its outcome, as server's gate tool reads it (GateOutcomeLinePrefix): the written check
// runs as a test of this package, under a flag of gate_held_test.go that only the command passes.

package fault

// The flag gate_held_test.go reads, which only the held gate's written item passes.
const GateHeldWrittenFlag = "fault.gate-held-written"

// Where a held case's tests run outside the convention.
type gateHeldPlace struct {
	rowId    string
	caseName string
	// The thin T2 test's own name, where it is not the convention's.
	t2Name string
	// The server package the case's T3 run is in and its tests there, the registered run's first, under the
	// convention's tags on the private stores. Empty keeps the convention's T3 entry.
	t3Package string
	t3Names   []string
	// Tests of the case beside its entries: its clauses, and its owners' tests of a case no builder covers.
	also []*GateTest
}

// The place's tests for its case: the convention's entries, a run elsewhere replacing one, then the rest.
func (self *gateHeldPlace) tests(testCase *Case) []*GateTest {
	tests := []*GateTest{}
	for _, test := range gateConventionalTests(testCase) {
		switch {
		case test.Repo == "sidecar" && self.t2Name != "":
			test = gateFaultTests(self.t2Name)
		case test.Repo == "server" && self.t3Package != "":
			test = &GateTest{Repo: "server", Package: self.t3Package, Tags: gateT3Tags, Stores: true, Names: self.t3Names}
		}
		tests = append(tests, test)
	}
	return append(tests, self.also...)
}

// A mailbox case's runs on a real mailbox (MAIL-M10-04): T2 in sidecartest, T3 in server's sidecart3, beside the
// convention's entries, which no builder answers.
func gateHeldMailboxTests(t2Name string, t3Name string) []*GateTest {
	return []*GateTest{
		{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{t2Name}},
		{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{t3Name}},
	}
}

// The held cases whose tests run outside the convention, each as its tests: see the file header. A case the catalog
// does not hold as a later-of case panics, as its sweep's registration would.
func gateHeldCases(catalog *Catalog) map[string][]*GateTest {
	places := []*gateHeldPlace{
		// the hold cases on T3 against api's real hold/ writes, each case's clauses with it
		{rowId: "FS-66", caseName: "hold", t3Package: "./model", t3Names: []string{"TestFs66HoldPlacedByApiOnT3"}},
		{
			rowId:     "FS-69",
			t3Package: "./model",
			t3Names:   []string{"TestFs69HoldsPlacedByApiOnT3", "TestFs69HoldBetweenSweepDeletesOnT3", "TestFs69EraseUnderTheHoldOnT3", "TestFs6NowShredUnderAHoldOnT3"},
			also:      []*GateTest{gateFaultTests("TestFs69HoldBetweenSweepDeletes", "TestFs69EraseUnderTheHold", "TestFs6NowShredUnderAHold")},
		},
		{
			rowId:    "FS-78",
			caseName: "hold",
			also:     []*GateTest{gateFaultTests("TestFs78UnderAHoldTheKeysGoAtOnceAndTheCiphertextStays")},
		},
		{
			rowId:     "FS-92",
			t3Package: "./model",
			t3Names: []string{
				"TestFs92HoldsPlacedByApiOnT3", "TestFs92HoldBetweenVerifyAndDeleteOnT3", "TestFs92HoldBetweenDeletesOnT3", "TestFs92DeleteInFlightOnT3",
				"TestFs92SealedHoldAnswersEqualANoHoldTwinOnT3",
			},
			also: []*GateTest{gateFaultTests(
				"TestFs92HoldBetweenVerifyAndDelete", "TestFs92HoldBetweenDeletes", "TestFs92DeleteInFlight", "TestFs92HoldOutlastsTheDropTable",
				"TestFs92SecondDropDuringTheHold", "TestFs92SecondDropListsAsItsTwin", "TestFs92SealedHoldAnswersEqualANoHoldTwin",
				"TestFs92AHoldKeepsWhatTheDropWouldDeleteUntilItEnds", "TestFs92ASealedHoldsAnswersEqualANoHoldTwin",
			)},
		},

		// the directory's format-2 cases
		{rowId: "FS-86", caseName: "cards", also: []*GateTest{gateFaultTests("TestFs86CardsEvsCommits", "TestFs86CardsEvsCommitsFailPastTheirCeiling")}},
		{rowId: "FS-87", caseName: "index", t3Package: ".", t3Names: []string{"TestFs87IndexOnT3"}},
		{rowId: "FS-99", caseName: "cards", t3Package: ".", t3Names: []string{"TestFs99CardsOnT3"}},
		{rowId: "FS-101", caseName: "r-file", t2Name: "TestFs101File"},

		// the mailbox cases on a real mailbox, which no builder answers
		{rowId: "FS-76", caseName: "mailbox", also: gateHeldMailboxTests("TestFs76MailboxCase", "TestT3MailM10Fs76MailboxCase")},
		{rowId: "FS-78", caseName: "mailbox", also: gateHeldMailboxTests("TestFs78MailboxCase", "TestT3MailM10Fs78MailboxCase")},
		{rowId: "FS-111", caseName: "mailbox", also: gateHeldMailboxTests("TestFs111MailboxCase", "TestT3MailM10Fs111MailboxCase")},
		{rowId: "FS-112", caseName: "mailbox", also: gateHeldMailboxTests("TestFs112MailboxCase", "TestT3MailM10Fs112MailboxCase")},
	}
	cases := map[string][]*GateTest{}
	for _, place := range places {
		testCase := gateCaseOf(catalog, place.rowId, place.caseName)
		if !testCase.LaterOf {
			panic("the held gate's sweep names " + testCase.String() + ", which is no later-of case")
		}
		cases[testCase.String()] = place.tests(testCase)
	}
	return cases
}

// The command the held gate's written item runs in the sidecar repo: this package's test under the hooks, as T2 runs
// it.
func gateHeldWrittenCommand() []string {
	return []string{"go", "test", "-count=1", "-v", "-tags", "sidecar_testhooks", "-run", "^TestGateHeldCasesWritten$", "./sidecartest/fault", "-" + GateHeldWrittenFlag}
}

// Every item of the held gate: see the file header.
func gateHeldItems(catalog *Catalog) []*GateItem {
	items := []*GateItem{
		gateRulesItem(catalog, GateHeld),
		{
			Item:     "every held case written: a builder registered on T2 and on T3 wherever its row runs there, its schedule stepping and naming the invariants it checks after every step, its twin too where it refuses or is forged, so that fault.Missing at the held gate ends empty on each tier (TEST-M10-06; TEST.md's contract for schedule authors, rules 1 to 4); a case its owners show only in tests of their own reads missing here, since no gate finds those as a schedule, and T4's parts are SDK-M8-15's and SDK-M10-06's cells' to run",
			Commands: []*GateCommand{{Repo: "sidecar", Command: gateHeldWrittenCommand()}},
		},
		gateInvariantsItem(GateHeld),
		gateStoreClockItem(catalog, GateHeld),
	}
	items = append(items, gateFs86CardItems()...)
	return append(items,
		gateT4SearchCellsItem(),
		&GateItem{
			Item:     "FS-125's app-host case held with PROTO-M10-05 (owner decision 609; QD-1038): C19's window accounting is withdrawn, the remote-search pair's contracts being accounted like any peer's, as FS-83 checks; the row keeps its number and its sweep runs only if the windows return, so its app-host case above reads missing with no test, and open on its T4 part",
			External: "people: the owner, should C19's windows return",
		},
	)
}

var gateHeldSweep = RegisterGateSweep(&GateSweep{
	Gate:  "held",
	Cases: gateHeldCases(DefaultCatalog()),
	Items: gateHeldItems(DefaultCatalog()),
})
