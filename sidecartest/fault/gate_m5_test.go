package fault

// M5's sweeps (gate_m5.go; TEST-M5-02): each of M5's own rows names its owners' tests where they run, FS-47's §21 case
// keeps the convention's T2 test, which nobody has written, the hold cases keep the convention and read open on M10's
// exit, and the items carry §22.7's rows through the registry, the scenarios, §23.4's exit criteria, each area's gate
// and what the world owes; nothing gate_m1.go once carried for M5 is left there, and Pebble's 5% is the harness's own.

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// M5's rows: every case of its own by its owners' tests, on each tier where they run, and every other case, the
// later-of hold cases, by the convention and open on M10's exit.
func TestGateM5NamesEachRowsTestsWhereTheyRun(t *testing.T) {
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
		// the repos its tests run in, in order of first naming
		repos []string
	}{
		{rowId: "FS-25", caseName: "dns-route", repos: []string{"server"}, names: []string{
			"TestFs25RouteResponseLostAfterCommit", "TestFs25RouteTwoApiInstancesRacing", "TestFs25RouteCancelRefusesTheRest",
		}},
		{rowId: "FS-34", repos: []string{"sidecar", "server"}, names: []string{
			"TestTlsFrontZeroBytesBeforeAuthentication", "TestTlsFrontSuiteNoByteReachesAPrivateAudiencesService", "TestT3Fs34NoByteReachesAPrivateAudiencesService",
		}},
		{rowId: "FS-39", caseName: "report-intake", repos: []string{"sidecar"}, names: []string{
			"TestReportIntakeCountsAGzipXmlAggregateOncePerReporterAndReportId", "TestReportIntakeCountsAGzipJsonTlsRptAggregateOnce",
			"TestReportIntakeArfBodyCanaryInNoLogRowOrMetric", "TestPlatformCanaryReachesNoLogOrMetric", "TestPlatformScenarioArfCanaryJointWithReportIntake",
		}},
		{rowId: "FS-41", caseName: "m5", repos: []string{"server"}, names: []string{
			"TestFs42DnsStepThroughBothEdges", "TestDnsLabelReclaimRebindsTheName", "TestT3RedisLossHealsByTheNextHeartbeat", "TestT3TlsedgeKillsHoldThroughARedisLoss",
		}},
		{rowId: "FS-42", caseName: "m5", repos: []string{"server"}, names: []string{
			"TestFs42DnsStepThroughBothEdges", "TestFs42DnsStepOnTheRestoreFrame", "TestFs42DnsStepPersistsAnNsStopAcrossRerun", "TestT3TlsedgeKillsHoldThroughAPostgresRestore",
			"TestT3RedisLossHealsByTheNextHeartbeat", "TestM5StepsRunInTheFramesOrder",
		}},
		{rowId: "FS-47", caseName: "section-21", repos: []string{"sidecar", "server"}, names: []string{
			"TestFs47Section21", "TestFs47T3ClosureGrowthReads", "TestFs47T3ReviewedTightening", "TestAbuseClosureGrowthOpensOneCaseAndNoAction",
			"TestTightenNetworkLimitWritesRowsALiftClears",
		}},
		{rowId: "FS-48", repos: []string{"server", "sidecar"}, names: []string{
			"TestLegalHoldDeadlinesFollowTheStatutes", "TestFs48HoldsAcrossTheirDeadlinesOnPostgres", "TestFs48EraseAndNowReadNoHoldKind",
			"TestRepoShredUnderAHoldKeepsCiphertextAndDeletesKeys", "TestGkmHoldPausesEverySweepButNotShredGroup",
		}},
		{rowId: "FS-49", repos: []string{"server"}, names: []string{
			"TestFs49WeekendClocks", "TestFs49WeekendClocksOnPostgres", "TestFileAbuseNoticePagesEveryClassOnASaturdayNight",
		}},
		{rowId: "FS-52", repos: []string{"server"}, names: []string{"TestFs52BlocksNAndNextServeTogetherAndRollBack"}},
	} {
		testCase := catalog.Case(want.rowId, want.caseName)
		row := gateFileRow(file, "M5", want.rowId, want.caseName)
		if row == nil {
			t.Errorf("M5 has no %s %q", want.rowId, want.caseName)
			continue
		}
		if row.External != "" {
			t.Errorf("%s at M5 waits on %q", testCase, row.External)
		}
		names := gateRowNamesForTest(row)
		for _, name := range want.names {
			if !slices.Contains(names, name) {
				t.Errorf("%s at M5 runs %v, which lacks %s", testCase, names, name)
			}
		}
		repos := []string{}
		for _, test := range row.Tests {
			if !slices.Contains(repos, test.Repo) {
				repos = append(repos, test.Repo)
			}
			// a server test on rows that MG5 holds runs with the pending groups linked, or it skips and reads open
			if test.Repo == "server" && test.Stores && test.Package != "./cli/sockets" && !strings.Contains(test.Tags, "sidecar_pending") {
				t.Errorf("%s at M5 runs %s's %v on the stores with tags %q", testCase, test.Package, test.Names, test.Tags)
			}
		}
		if !slices.Equal(repos, want.repos) {
			t.Errorf("%s at M5 runs in %v, want %v", testCase, repos, want.repos)
		}
	}

	// FS-47's §21 case names the convention's T2 test first, in this package under the hooks, which nothing declares
	fs47 := gateFileRow(file, "M5", "FS-47", "section-21")
	if fs47 == nil || 0 == len(fs47.Tests) || !reflect.DeepEqual(fs47.Tests[0], gateFaultTests("TestFs47Section21")) {
		t.Fatalf("FS-47's §21 case at M5: %+v", fs47)
	}
	source, err := filepath.Glob("fs47*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range source {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "\nfunc TestFs47Section21(") {
			t.Errorf("%s declares TestFs47Section21: gate_m5.go's header and its clause-rows item say nobody has written it", path)
		}
	}

	// every other case keeps the convention: the hold cases, each open on M10's exit
	swept := gateM5Cases(catalog)
	conventional := []string{}
	for _, row := range GateRows(catalog, "M5") {
		if row.Row == "" {
			continue
		}
		testCase := catalog.Case(row.Row, row.Case)
		if _, ok := swept[testCase.String()]; ok {
			continue
		}
		if tests := gateConventionWithClausesForTest(testCase); !reflect.DeepEqual(row.Tests, tests) {
			t.Errorf("%s at M5 runs %s, the convention %s", testCase, gateTestsStringForTest(row.Tests), gateTestsStringForTest(tests))
		}
		if !testCase.LaterOf || !strings.Contains(row.External, "M10-out") {
			t.Errorf("%s at M5 keeps the convention and is no later-of case open on M10's exit: %+v", testCase, row)
		}
		if !slices.Contains(conventional, row.Row) {
			conventional = append(conventional, row.Row)
		}
	}
	if !slices.Equal(conventional, gateM5HoldRows) {
		t.Errorf("the rows M5 leaves to the convention are %v, the hold rows %v", conventional, gateM5HoldRows)
	}
	if len(swept)+5 != len(catalog.GateCases(gateM5OutGate)) {
		t.Errorf("M5's sweep names %d cases of the catalog's %d", len(swept), len(catalog.GateCases(gateM5OutGate)))
	}
}

// FS-25's dns-route case runs at M5 on T3 alone, in server's api through the real route, where MCP-M5-01 wrote its
// legs (QD-1081); its main case keeps M3 on both tiers.
func TestGateFileShowsFs25sDnsRouteCaseOnT3(t *testing.T) {
	data, err := GateFile(DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	dnsRoute := gateFileRow(file, "M5", "FS-25", "dns-route")
	if dnsRoute == nil || len(dnsRoute.Tests) != 1 || dnsRoute.External != "" {
		t.Fatalf("FS-25's dns-route at M5: %+v", dnsRoute)
	}
	if test := dnsRoute.Tests[0]; test.Repo != "server" || test.Package != "./api" || test.Tags != "sidecar_pending" || !test.Stores ||
		!slices.Equal(test.Names, []string{"TestFs25RouteResponseLostAfterCommit", "TestFs25RouteTwoApiInstancesRacing", "TestFs25RouteCancelRefusesTheRest"}) {
		t.Errorf("FS-25's dns-route test: %+v", test)
	}
	if main := gateFileRow(file, "M3", "FS-25", ""); main == nil || len(main.Tests) != 2 {
		t.Errorf("FS-25 at M3: %+v", main)
	}
	if gateFileRow(file, "M3", "FS-25", "dns-route") != nil || gateFileRow(file, "M5", "FS-25", "") != nil {
		t.Error("FS-25's cases moved gates")
	}
}

// The clause-rows item names exactly the cases the sweep names, so a row that gains a builder leaves both together,
// and the rows whose T2 is server's are FS-48 and FS-49 alone, each naming a pure test on no store.
func TestGateM5ClauseRowsAreTheSweptCases(t *testing.T) {
	catalog := DefaultCatalog()
	swept := []string{}
	for _, testCase := range catalog.GateCases(gateM5OutGate) {
		if _, ok := gateM5Cases(catalog)[testCase.String()]; ok {
			swept = append(swept, testCase.String())
		}
	}
	if !slices.Equal(swept, gateM5ClauseRows) {
		t.Errorf("the clause rows are %v, the swept cases %v", gateM5ClauseRows, swept)
	}
	_, find := gateItemsForTest(t, "M5")
	clauses := find("the rows that pass on clause tests alone")
	for _, name := range gateM5ClauseRows {
		if !strings.Contains(clauses.Item, name) {
			t.Errorf("the clause-rows item does not name %s", name)
		}
	}
	if 0 < len(clauses.Tests) || 0 < len(clauses.Commands) || clauses.External != "" {
		t.Errorf("the clause-rows item, which reads missing until each row has a builder: %+v", clauses)
	}
	if !slices.Equal(gateServerPolicyT2Rows, []string{"FS-48", "FS-49"}) {
		t.Errorf("the rows whose T2 is server's: %v", gateServerPolicyT2Rows)
	}
	for _, rowId := range gateServerPolicyT2Rows {
		testCase := catalog.Case(rowId, "")
		if !slices.Equal(testCase.TwinTiers(), []Tier{TierT2}) {
			t.Errorf("%s runs on %v, and §22.5's §21 row speaks of its T2 alone", rowId, testCase.TwinTiers())
		}
		pure := false
		for _, test := range gateM5Cases(catalog)[testCase.String()] {
			if test.Repo == "server" && !test.Stores {
				pure = true
			}
		}
		if !pure {
			t.Errorf("%s names no pure test of server's policy", rowId)
		}
	}
}

// M5's items: the rules and FI bindings, §22.7's rows at M5 through the registry, CC4's edge sources and the
// certificate rows, S5, the kill switch, the watches, S7's SNI-less case once and with its tests, each area's gate,
// the hold cases held for M10, and what the world owes read open, never pass.
func TestGateM5ItemsSayWhatTheWorldOwes(t *testing.T) {
	catalog := DefaultCatalog()
	items, find := gateItemsForTest(t, "M5")
	find("§22.8's rules on every row")
	find("every FI the rows check")
	asserts := sidecartest.DefaultPrivacyAsserts()
	assertCount := 0
	for _, row := range asserts.Rows() {
		if slices.Contains(row.Gates, gateM5OutGate) {
			find("§22.7's " + row.Id + " assertion")
			assertCount += 1
		}
	}
	if assertCount == 0 {
		t.Error("§22.7 holds no row at M5-out")
	}
	for _, assertId := range []string{"synthesized-dmarc", "certificates"} {
		find("§22.7's " + assertId + " assertion")
	}

	// each of these runs tests in both repos, or in the one named, and waits on nothing outside the build
	for prefix, want := range map[string][]string{
		"CC4's M5 sources":                          {"TestEdgeSourcesCatchEachPathsLeakInEachForm", "TestT3EdgeRecordsOfServersTlsStoreAreScanned"},
		"§22.7's leak leg at M5":                    {"TestEveryClassCatchesItsLeak", "TestTlsCanaryHostLeakedIntoEachClassIsCaught", "TestT3EveryEdgeClassCatchesItsLeak"},
		"§22.7's certificate and scope rows":        {"TestCertificateRowsFailAHeldKeysNetworkNames", "TestCertificateRowsFailAScopesCertificateOnAnotherDevice"},
		"the schema guard at M5":                    {"TestTlsRowsAndFamiliesMapBothWays", "TestAbuseSchemaHoldsNoAddress"},
		"the kill switch within 5 s":                {"TestTlsSuiteKillSwitchEndsNewAndOpenConnectionsWithinFiveSeconds", "TestT3TlsedgeKillSwitchEndsNewAndOpenConnections"},
		"S7's SNI-less abuse@<root> case":           {"TestPlatformScenarioSniLessAbuseMailReachesTheIntake", "TestRunHostOnThePrivateStores", "TestS7AbuseMailWithNoSniIsDroppedUnreadAndKeptNowhere"},
		"FS-39's report intake on Postgres":         {"TestReportIntakeCountsAnAggregateOnceOnPostgres", "TestAbuseSmtpSinkOpensCasesByClassAndType"},
		"§22.5's §21 row as ABUSE-M5-21 reports it": {"TestAbuseComposedPathFromTheFormToASecondReviewersGrant", "TestAbuseRetentionSkipsAHeldNetworkUntilItsHoldEnds", "TestEveryRetentionSweepHonorsHolds"},
		"the inline paths and the CROSSSLOT lints":  {"TestT3FindIsOneScriptWithPostgresRefused", "TestT3TlsedgeRouteHoldsToItsInlinePathRow", "TestDnsT3RedisCallsNameOneHashTag"},
		"the tls meter end to end":                  {"TestTlsMeterT3MoneyPath", "TestTlsMeterT3EmptyBalance"},
		"FS-50's M5 pages":                          {"TestFs50M5ConditionsAt0200ReachTheRota", "TestDnsCanaryNsDownAt0200PagesAndABlindMinuteHoldsIt"},
	} {
		row := find(prefix)
		names := gateRowNamesForTest(row)
		for _, name := range want {
			if !slices.Contains(names, name) {
				t.Errorf("%q runs %v, which lacks %s", prefix, names, name)
			}
		}
		if row.External != "" {
			t.Errorf("%q waits on %q", prefix, row.External)
		}
	}

	// these run what the build can and read open on the rest, whatever their tests show
	for prefix, want := range map[string]struct {
		name     string
		external string
	}{
		"S5, publish HTTPS":                                   {name: "TestTlsSuitePassthroughCompletesTlsOnTheDeviceKey", external: "production"},
		"the CT and zone watches alarm":                       {name: "TestTlsCtWatchAnUnattestedCertificateAlarms", external: "production"},
		"the dns edge serves the user root":                   {name: "TestDnsT3BothNsAnswerAlikeAtOneSerial", external: "hardware and production"},
		"§22.9's ACME row on Pebble with 5% bad nonces":       {name: "TestGateM5PebbleRunsAtFivePercentBadNonces", external: "production"},
		"§13.7's browser rows as the front's Go tests show":   {name: "TestTlsHttpAnswers421ForAnotherHost", external: "hardware and people"},
		"the sockets and tlsedge load harnesses' scaled runs": {name: "TestTlsEdgeLoadScaledDown", external: "hardware"},
		"holds refuse placement until counsel confirms":       {name: "TestLegalHoldRefusesUntilEnabled", external: "people"},
	} {
		row := find(prefix)
		if !slices.Contains(gateRowNamesForTest(row), want.name) || !strings.HasPrefix(row.External, want.external) {
			t.Errorf("%q: %+v", prefix, row)
		}
	}

	// these wait on the world alone
	for prefix, external := range map[string]string{
		"platform names and company MX off ur.network": "production",
		"the LE domain override for the user root":     "people and production",
		"abuse readiness and the rota from M5":         "people",
	} {
		if row := find(prefix); !strings.HasPrefix(row.External, external) || 0 < len(row.Tests) || 0 < len(row.Commands) {
			t.Errorf("%q: %+v", prefix, row)
		}
	}

	// the certificate re-order on T3 has nothing to run, so it reads missing
	if row := find("the certificate re-order of FS-42's M5 step on T3"); 0 < len(row.Tests) || 0 < len(row.Commands) || row.External != "" {
		t.Errorf("the certificate re-order on T3, which no test shows yet, reads %+v", row)
	}

	// the hold cases are held for M10's exit and are no test of this gate's
	holds := find("the hold cases of FS-66, FS-69, FS-76, FS-78, FS-92")
	if !strings.HasPrefix(holds.External, "a later gate: M10's Gn-out") || 0 < len(holds.Tests) || !strings.Contains(holds.Item, "TEST-M10-06") {
		t.Errorf("the hold cases' item: %+v", holds)
	}
	held := 0
	for _, testCase := range catalog.GateCases(gateM5OutGate) {
		if testCase.LaterOf {
			held += 1
			if !slices.Contains(gateM5HoldRows, testCase.Row.Id) {
				t.Errorf("%s is a later-of case at M5 the hold rows do not name", testCase)
			}
		}
	}
	if held != len(gateM5HoldRows) {
		t.Errorf("M5 holds %d later-of cases, the hold rows %d", held, len(gateM5HoldRows))
	}

	// what is not yet due names FS-39's labels and the later steps, and none of M5's own cases
	later := find("not yet due at M5")
	for _, name := range []string{"FS-39's labels at M7-out", "FS-41's m6 at M6-out", "FS-42's m9 at M9-out", "FS-47's mail at M7-out"} {
		if !strings.Contains(later.Item, name) {
			t.Errorf("the not-yet-due item lacks %s: %q", name, later.Item)
		}
	}
	for _, name := range []string{"FS-34", "FS-48", "FS-52", "dns-route", "report-intake", "section-21"} {
		if strings.Contains(later.Item, name) {
			t.Errorf("the not-yet-due item names %s, which is due here", name)
		}
	}
	if !strings.HasPrefix(later.External, "a later gate") {
		t.Errorf("the not-yet-due item: %+v", later)
	}

	// S7's case is carried once, by this sweep, with tests
	if count := len(gateSweep("M5").Items); count != len(items) {
		t.Errorf("M5's sweeps add %d items, the file %d", count, len(items))
	}
	s7 := 0
	for _, item := range items {
		if strings.HasPrefix(item.Item, "S7's SNI-less abuse@<root> case") {
			s7 += 1
			if len(item.Tests) == 0 {
				t.Errorf("S7's item runs nothing: %+v", item)
			}
		}
	}
	if s7 != 1 {
		t.Errorf("M5 holds S7's SNI-less case %d times", s7)
	}
	data, err := os.ReadFile("gate_m1.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `Gate:  "M5"`) || strings.Contains(string(data), "SNI-less") {
		t.Error("gate_m1.go still carries an item for M5")
	}
}

// M5's entry review reads the assembly check and its design closure, which a person signs, and runs no row.
func TestGateM5InReadsItsDesignClosure(t *testing.T) {
	rows := GateRows(DefaultCatalog(), "M5-in")
	if len(rows) != 2 {
		t.Fatalf("M5-in holds %d rows", len(rows))
	}
	if rows[0].Item != gateAssemblyItem.Item {
		t.Errorf("M5-in's first row: %+v", rows[0])
	}
	closure := rows[1]
	if !strings.HasPrefix(closure.Item, "§23.6's M5 design closure") || !strings.HasPrefix(closure.External, "people") || 0 < len(closure.Tests) {
		t.Errorf("M5-in's closure: %+v", closure)
	}
	for _, part := range []string{"ALPN audience", "custom-SNI map", "report parsing", "hold kinds and abuse clocks", "Q-OPS-5"} {
		if !strings.Contains(closure.Item, part) {
			t.Errorf("M5-in's closure lacks %q, which §23.6's M5 row names", part)
		}
	}
}

// Every test M5's entry and exit name in this repo, for a row outside the convention or for an item, is declared in
// its package in a file that builds under the entry's tags, so a rename or a tag an owner adds fails here rather than
// only reading missing at the gate. FS-47's §21 case's T2 test is the convention's, which is passed over.
func TestGateM5SweepsNameSidecarTestsDeclaredUnderTheirTags(t *testing.T) {
	catalog := DefaultCatalog()
	checked := 0
	for _, gate := range []string{"M5-in", "M5"} {
		rows := GateRows(catalog, gate)
		for _, name := range gateUndeclaredSidecarTestsForTest(t, catalog, rows) {
			t.Errorf("%s names %s, which is not declared so", gate, name)
		}
		for _, row := range rows {
			for _, test := range row.Tests {
				if test.Repo == "sidecar" {
					checked += len(test.Names)
				}
			}
		}
	}
	if checked < 60 {
		t.Errorf("M5's sweeps name %d tests in this repo", checked)
	}
}

// §22.9's "Pebble with 5% bad nonces" is the harness's own default, which this sweep confirms and never sets: the
// default rejects 5 in 100, StartPebble hands that rate to Pebble, and each file whose tests the ACME item names
// starts Pebble with the default settings.
func TestGateM5PebbleRunsAtFivePercentBadNonces(t *testing.T) {
	if percent := sidecartest.DefaultPebbleSettings().NonceRejectPercent; percent != 5 {
		t.Errorf("Pebble rejects %d%% of good nonces by default, §22.9's 5", percent)
	}
	harness, err := os.ReadFile(filepath.Join("..", "pebble.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(harness), `t.Setenv("PEBBLE_WFE_NONCEREJECT", strconv.Itoa(settings.NonceRejectPercent))`) {
		t.Error("StartPebble no longer hands its settings' rate to Pebble")
	}
	_, find := gateItemsForTest(t, "M5")
	item := find("§22.9's ACME row on Pebble with 5% bad nonces")
	started := 0
	for _, test := range item.Tests {
		if test.Repo != "sidecar" || test.Package != "./certsservice" {
			continue
		}
		paths, err := filepath.Glob(filepath.Join("..", "..", "certsservice", "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range test.Names {
			declared := false
			for _, path := range paths {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				source := string(data)
				start := strings.Index(source, "\nfunc "+name+"(t *testing.T) {")
				if start < 0 {
					continue
				}
				declared = true
				body := source[start+1:]
				if end := strings.Index(body, "\n}\n"); 0 <= end {
					body = body[:end]
				}
				if !strings.Contains(body, "sidecartest.StartPebble(t, nil)") {
					t.Errorf("%s starts no Pebble with the default settings", name)
				} else {
					started += 1
				}
			}
			if !declared {
				t.Errorf("certsservice declares no %s", name)
			}
		}
	}
	if started == 0 {
		t.Error("the ACME item names no test that starts Pebble")
	}
}
