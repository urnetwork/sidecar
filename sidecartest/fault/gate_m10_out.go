// M10's exit review (TEST-M10-05; §23.6's M10 row, §23.4's M10 exit criteria, §22.10's right column for format 2,
// §23.8's Gn-out; D-TEST-9, D-TEST-12 to D-TEST-18, R-TEST-10 to R-TEST-12, R-PHASE-11): the sweep `sidecar-gate M10`
// reports row by row and item by item, pass, fail, missing or open. Like every exit sweep before it (gate_m2_out.go,
// gate_m6.go) it adds no mechanism: each row runs the tests its owners wrote, and a failure or a missing test goes
// back to the task that owns the mechanism and stays in the report until fixed. Format 2's bytes freeze on this report
// at M10's Gn-out (§23.8; owner decision 169), and owner decision 194 keeps the build moving past it.
//
// The rows are catalog.yml's M10-out cases, the later-of cases among them, since M10's exit comes after M5's to M8's.
// Each keeps the convention (gate.go) but where its tests run elsewhere, by the rules M6's sweep set out:
//
//   - A case with a registered schedule whose T3 run is in another server package is named there, under the
//     convention's tags (QD-1081): evshost's FS-68, FS-72's migration and rollback cases, FS-89, FS-91, FS-94 and
//     FS-95; and the root package's FS-74, FS-75, FS-83, FS-107, FS-108 and FS-111. A T2+T3 case keeps its T2 test,
//     and no test moves.
//   - A case whose thin T2 test carries another name than the convention's is named by it: FS-74's and FS-75's
//     TestFs74OnEvs and TestFs75OnEvs.
//   - A case no builder can cover is named by its T3 tests alone (gateM10NoBuilderCases): FS-73, whose world drives
//     stock git and needs a testing.TB (QD-995, owner decision 548), and FS-114's purge and drop cases, which §22.9's
//     file-cluster suite runs on T3's clusters of the minio fork's hooked build (EVSB-M10-08) as cases of its own:
//     server's TestFileClusterSuitePassesOnT3, whole, so either case passes only when every case of the suite does.
//   - The later-of cases are named as the held gate names them (gate_held.go, TEST-M10-06), so the two gates read each
//     alike: model's FS-66's hold case, FS-69 and FS-92, ABUSE-M10-01's runs against api's real hold/ writes, with the
//     clauses their owners run beside each; the root package's FS-87's index case and FS-99's card case; FS-101's
//     r-file case's TestFs101File; and beside the convention's entries, the tests MAIL-M10-04 and SEARCH-M10-37 wrote
//     of the mailbox cases and FS-78's hold case, which no builder answers.
//
// Every case's registered clauses run with it by the convention (QD-1084): FS-68's, FS-89's, FS-94's and FS-95's,
// FS-72's migration killed at each step, and the hold cases', each on T3 in the package its clause names. Every other
// case keeps the convention, so a case nobody registered a builder for reads missing, whatever clause or world tests
// of it exist, since a clause counts only beside a registered case: FS-64, FS-65, FS-66, FS-67, FS-70, FS-71,
// FS-79, FS-81, FS-90, FS-93 and FS-96, and the later-of cases no owner wrote a test of. Three rows carry tests under
// the convention's T2 names that run no registered builder, FS-76's, FS-78's and FS-112's, and read missing on their
// unwritten T3 runs; the written item names them, so none passes on a test §22.8's rules never ran. FS-125 is held
// with C19's windows (owner decision 609; QD-1038), and an item says why its cases read missing.
//
// Beside the rows, the items, §22.10's right column's first and then §23.4's exit criteria: §22.8's rules on every row,
// with every write's lost answer over the unknown list (FS-65, FS-72, FS-75); each case written, its schedule naming
// what it checks; the FI bindings; the store clock; TLC on EvsCommit's every mode, the drop extension's among them
// (QD-1116, QD-1119), and on IndexRollup; testdata/index/ byte-equal on every leg (D-TEST-15); D-TEST-13's projection,
// computed and never measured; D-TEST-12's observe evidence, whose T3 run is missing; purge and drops in observe by
// default; D-TEST-18's verify and soak; a migration of a format-1 repo and a rollback (FS-72), and a migrated repo's
// first build searched against the oracle (D-TEST-14), each with what no run joins yet; format 2's fuzz seeds; §2.8's
// M10 rows; the schema guard and the leak leg; §22.7's assertions and S11 and S12 through their registries; the
// CROSSSLOT lints and the three ledgers; the search, phone, remote, index, directory and drop benchmark rows; the hdd
// row with purges; D-OPS-21's drop job bounds; T4's search cells; and what production and people owe. FS-55 and FS-54
// ride along as every Gn-out's, which the tool adds.
//
// Two traps the items hold to: purge and drops stay in observe, and deletes on is a production soak's and then the
// owner's (D-TEST-12, D-TEST-18), so an item asserts deletes are off by default in the engine, the host and the
// checked-in config; and D-TEST-13's projection is computed, never measured, so with no price table from M2's nvme run
// it reads open, which holds format 2's freeze.
//
// An item that is no go test is a command whose last line says its outcome, as server's gate tool reads it
// (GateOutcomeLinePrefix): the written check and the TLC check run as tests of this package, under flags of
// gate_m10_out_test.go that only the commands pass.

package fault

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The catalog's name for M10's exit.
const gateM10OutGate = "M10-out"

// The flags gate_m10_out_test.go reads, which only M10's commands pass: the cases' written check, and the TLC check.
const (
	GateM10OutWrittenFlag = "fault.gate-m10-written"
	GateM10OutTlcFlag     = "fault.gate-m10-tlc"
)

// §22.9's file-cluster suite on T3's clusters, whole (EVSB-M10-08), which runs FS-114's purge and drop cases among its
// own on the minio fork's hooked build: the clusters of local/file-cluster-t3, not the private stores.
var gateFileClusterSuiteT3Test = &GateTest{
	Repo:    "server",
	Package: ".",
	Tags:    "sidecar_filecluster_t3",
	Names:   []string{"TestFileClusterSuitePassesOnT3"},
}

// FS-73 on T3, as server's evshost runs it: on the private stores and the local stack, built with the convention's
// tags (QD-995).
var gateFs73T3Test = &GateTest{
	Repo:    "server",
	Package: "./evshost",
	Tags:    gateT3Tags,
	Stores:  true,
	Names:   []string{"TestFs73OnT3"},
}

// The cases M10's sweep names tests for in place of a builder, since no builder can cover them: see the file header.
// The written item passes over them, and their rows run only the tests the sweep names.
var gateM10NoBuilderCases = []string{"FS-73", "FS-114's purge", "FS-114's drop"}

// Where M10's cases run their tests outside the convention: see the file header. A case the catalog does not hold
// panics, as its sweep's registration would.
func gateM10Cases(catalog *Catalog) map[string][]*GateTest {
	caseOf := func(rowId string, caseName string) *Case {
		return gateCaseOf(catalog, rowId, caseName)
	}
	cases := map[string][]*GateTest{}

	// T3 runs in another server package, each the test that runs the registered case there (QD-1081)
	for _, place := range []struct {
		rowId       string
		caseName    string
		packagePath string
		names       []string
	}{
		{rowId: "FS-68", packagePath: "./evshost"},
		{rowId: "FS-72", caseName: "migration", packagePath: "./evshost"},
		{rowId: "FS-72", caseName: "rollback", packagePath: "./evshost"},
		{rowId: "FS-89", packagePath: "./evshost"},
		{rowId: "FS-91", packagePath: "./evshost"},
		{rowId: "FS-94", packagePath: "./evshost"},
		{rowId: "FS-95", packagePath: "./evshost"},
		{rowId: "FS-83", packagePath: "."},
		{rowId: "FS-107", packagePath: "."},
		{rowId: "FS-108", packagePath: "."},
		{rowId: "FS-111", packagePath: "."},
	} {
		testCase := caseOf(place.rowId, place.caseName)
		cases[testCase.String()] = gateCaseT3Elsewhere(testCase, place.packagePath, place.names...)
	}

	// thin T2 tests under names of their own, FS-74's and FS-75's beside their T3 runs in the root package
	for _, place := range []struct {
		rowId  string
		t2Name string
	}{
		{rowId: "FS-74", t2Name: "TestFs74OnEvs"},
		{rowId: "FS-75", t2Name: "TestFs75OnEvs"},
	} {
		testCase := caseOf(place.rowId, "")
		cases[testCase.String()] = []*GateTest{
			gateFaultTests(place.t2Name),
			{Repo: "server", Package: ".", Tags: gateT3Tags, Stores: true, Names: []string{GateT3TestName(testCase)}},
		}
	}

	// the later-of cases, as the held gate names them, so M10's exit and the held gate read each alike
	for caseName, tests := range gateHeldCases(catalog) {
		cases[caseName] = tests
	}

	// no builder can cover these
	cases[caseOf("FS-73", "").String()] = []*GateTest{gateFs73T3Test}
	cases[caseOf("FS-114", "purge").String()] = []*GateTest{gateFileClusterSuiteT3Test}
	cases[caseOf("FS-114", "drop").String()] = []*GateTest{gateFileClusterSuiteT3Test}
	return cases
}

// What a set of cases' written check found, as an item's command reports it: each case written, failing, missing a
// builder on a tier, or open on what the catalog says it waits on.
type GateCasesWrittenResult struct {
	Outcome string
	Reason  string
	Written []*Case
	// Each failing case's own check, with its reason.
	Failed []*GateWrittenResult
	// Each case and tier no builder covers: "FS-64 on T2".
	Missing []string
	Open    []*Case
}

// The lines the command prints last: the reason, then the outcome, as the gate tool reads them.
func (self *GateCasesWrittenResult) Lines() string {
	return self.Reason + "\n" + GateOutcomeLinePrefix + self.Outcome + "\n"
}

// Whether each of cases is written: on its first tier as GateWritten reads it, and on T3 too where its row runs there,
// since a case registered on T2 alone leaves its T3 run with nothing to run. A T4 part, which SDK-M8-15's and
// SDK-M10-06's cells run, is not looked for. The outcome is fail where any case's builder fails, missing where none
// fails and any case lacks a builder on a tier, open where the rest are written and a case waits on the world, and pass
// where every case is written: missing is never pass. lookup is Lookup but in a fixture, and settings nil takes the
// defaults.
func GateCasesWritten(ctx context.Context, cases []*Case, lookup func(rowId string, caseName string, tier Tier) *Registration, settings *GateWrittenSettings) *GateCasesWrittenResult {
	result := &GateCasesWrittenResult{}
	for _, testCase := range cases {
		written := GateWritten(ctx, testCase, lookup, settings)
		switch {
		case written.Outcome == GateOutcomeFail:
			result.Failed = append(result.Failed, written)
		case written.Outcome == GateOutcomeOpen:
			result.Open = append(result.Open, testCase)
		case written.Outcome == GateOutcomeMissing:
			result.Missing = append(result.Missing, fmt.Sprintf("%s on %s", testCase, written.Tier))
		case written.Tier != TierT3 && slices.Contains(testCase.Tiers(), TierT3) && lookup(testCase.Row.Id, testCase.Name, TierT3) == nil:
			result.Missing = append(result.Missing, fmt.Sprintf("%s on T3, registered on %s alone", testCase, written.Tier))
		default:
			result.Written = append(result.Written, testCase)
		}
	}
	counts := fmt.Sprintf("of %d cases, %d written, %d missing a builder on a tier, %d failing, %d open", len(cases), len(result.Written), len(result.Missing), len(result.Failed), len(result.Open))
	failedReasons := []string{}
	for _, failed := range result.Failed {
		failedReasons = append(failedReasons, failed.Reason)
	}
	openNames := []string{}
	for _, testCase := range result.Open {
		openNames = append(openNames, testCase.String())
	}
	switch {
	case 0 < len(result.Failed):
		result.Outcome = GateOutcomeFail
		result.Reason = fmt.Sprintf("%s: %s", counts, strings.Join(failedReasons, "; "))
		if 0 < len(result.Missing) {
			result.Reason += "; no builder is registered for " + strings.Join(result.Missing, ", ")
		}
	case 0 < len(result.Missing):
		result.Outcome = GateOutcomeMissing
		result.Reason = fmt.Sprintf("%s: no builder is registered for %s, so no schedule of it runs under §22.8's rules, whatever tests of it pass", counts, strings.Join(result.Missing, ", "))
	case 0 < len(result.Open):
		result.Outcome = GateOutcomeOpen
		result.Reason = fmt.Sprintf("%s: %s wait on the world, as catalog.yml marks them", counts, strings.Join(openNames, ", "))
	default:
		result.Outcome = GateOutcomePass
		result.Reason = counts
	}
	return result
}

// The cases M10's written item looks for: every case catalog.yml holds at M10's exit but those the sweep names tests
// for in place of a builder.
func GateM10OutWrittenCases(catalog *Catalog) []*Case {
	return slices.DeleteFunc(slices.Clone(catalog.GateCases(gateM10OutGate)), func(testCase *Case) bool {
		return slices.Contains(gateM10NoBuilderCases, testCase.String())
	})
}

// The command M10's written item runs in the sidecar repo: this package's test under the hooks, as T2 runs it.
func gateM10OutWrittenCommand() []string {
	return []string{"go", "test", "-count=1", "-v", "-tags", "sidecar_testhooks", "-run", "^TestGateM10CasesWritten$", "./sidecartest/fault", "-" + GateM10OutWrittenFlag}
}

// TEST-M2-08's tests at M10's exit: EvsCommit's every mode, its M2 part's, its purger's and its drop extension's, the
// liveness of drops among them (QD-1116, QD-1119), and IndexRollup's model, mutants and live. In gate mode at M10 each
// passes only where every mode the gate needs of its model stands at its sources. StoreSettle's are M2's exit's.
var gateM10OutTlcTests = []string{
	"TestEvsCommitPassesTlcAtItsBounds",
	"TestEvsCommitMutantsFailTlc",
	"TestEvsCommitLivenessHolds",
	"TestEvsCommitPurgerMutantsFailTlc",
	"TestEvsCommitPurgerStoriesPassTlc",
	"TestEvsCommitDropMutantsFailTlc",
	"TestEvsCommitDropStoriesPassTlc",
	"TestEvsCommitDropLivenessHolds",
	"TestIndexRollupPassesTlcAtItsBounds",
	"TestIndexRollupMutantsFailTlc",
	"TestIndexRollupLivenessHolds",
}

// The gate whose modes M10's TLC item asks TEST-M2-08's tests for (SIDECAR_TLC_GATE): M10's exit, whose milestones in
// modelled.yml add the drop extension's modes to every earlier gate's.
const gateM10OutTlcGate = "M10"

// The command M10's TLC item runs in the sidecar repo.
func gateM10OutTlcCommand() []string {
	return []string{"go", "test", "-count=1", "-v", "-tags", "sidecar_testhooks", "-run", "^TestGateM10ModelsPassTlc$", "./sidecartest/fault", "-" + GateM10OutTlcFlag}
}

// What M10's TLC item reports from TEST-M2-08's tests run together in gate mode at M10's exit with no TLC, as
// GateTlcOutcome reads them: pass when each passed, every mode the exit needs standing at its model's sources; open,
// saying so, when any failed only because TLC has not run there, a mode's record standing only at its sources' digest;
// fail for any other failure or a test that gave no verdict.
func GateM10OutTlcOutcome(output []byte, runErr error) (string, string) {
	return GateTlcOutcome(output, runErr, gateM10OutTlcTests)
}

// One item per part of each §22.7 scenario that must pass at the catalog's gate, on each tier its row names, with the
// tests registered to it there: a part with none on a tier reads missing there (ScenarioRegistry.Missing), never pass
// on another tier's run, and a part on T6 reads open, since T6 runs in main, dark, and never here.
func gateScenarioItems(registry *sidecartest.ScenarioRegistry, gate string) []*GateItem {
	// a scenario's test as a gate entry names it: its package from its module's root, a server one on the private stores
	gateTestOf := func(test *sidecartest.ScenarioTest) (*GateTest, error) {
		modulePath, ok := gateModulePaths[test.Repo]
		if !ok {
			return nil, fmt.Errorf("%s names repo %q, which no gate entry reaches", test, test.Repo)
		}
		packagePath, ok := strings.CutPrefix(test.Package, modulePath)
		if !ok || (packagePath != "" && !strings.HasPrefix(packagePath, "/")) {
			return nil, fmt.Errorf("%s's package is outside %s", test, modulePath)
		}
		return &GateTest{Repo: test.Repo, Package: "." + packagePath, Tags: test.Tags, Stores: test.Repo == "server", Names: []string{test.Name}}, nil
	}
	items := []*GateItem{}
	for _, row := range registry.Rows() {
		if !slices.Contains(row.Gates, gate) {
			continue
		}
		for _, clause := range row.Parts() {
			part := &sidecartest.ScenarioPart{Row: row, Clause: clause}
			for _, tier := range row.Tiers {
				item := &GateItem{Item: fmt.Sprintf("§22.7's %s on %s (%s; %s)", part, tier, row.Flow, strings.Join(row.Owners, ", "))}
				if tier == sidecartest.ScenarioTierT6 {
					item.External = "T6: tests/test-main.sh in main, dark, on test roots and LE staging, at each milestone (TEST-M4-03), which this build never runs"
					items = append(items, item)
					continue
				}
				errs := []string{}
				for _, test := range registry.Tests(row.Id, clause, tier) {
					gateTest, err := gateTestOf(test)
					if err != nil {
						errs = append(errs, err.Error())
						continue
					}
					item.Tests = append(item.Tests, gateTest)
				}
				if 0 < len(errs) {
					item.Item += "; registrations no entry reaches: " + strings.Join(errs, "; ")
				}
				items = append(items, item)
			}
		}
	}
	return items
}

// Format 2's and the index's fuzz targets, each §22.6 target testdata/fuzz/registry.yml gives M10, with their packages
// as gate entries name them: format 2's records, the index's files and normalizer, the search arguments, wire and
// merge, the MCP search tools' arguments and ur search's flags; and directory.proto's decoders, whose cards freeze
// with format 2 at M10.
func gateM10FuzzTests() []*GateTest {
	return []*GateTest{
		{Repo: "sidecar", Package: ".", Names: []string{
			"FuzzEvsDrop", "FuzzEvsFormat2Batch", "FuzzEvsKind5Segment", "FuzzEvsPurgeList", "FuzzEvsStaged", "FuzzEvsDropStatus", "FuzzEvsReadState",
			"FuzzIndexSlot", "FuzzIndexEntry", "FuzzIndexShard", "FuzzIndexSmallFile", "FuzzIndexLoneShard", "FuzzIndexLayoutWrites",
			"FuzzIndexNormalize", "FuzzIndexExtractMail", "FuzzIndexExtractFile", "FuzzIndexExtractAttachment", "FuzzIndexExtractStreamEqualsWhole",
			"FuzzSearchQuery", "FuzzSearchRequestBody", "FuzzSearchReplyBody", "FuzzSearchRemoteMerge", "FuzzDirectoryDecode",
		}},
		{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{"FuzzExtractOracleEqualsIndex"}},
		{Repo: "sidecar", Package: "./mcp", Names: []string{"FuzzSearchToolArguments"}},
		{Repo: "sidecar", Dir: "cli", Package: ".", Names: []string{"FuzzUrSearchFlags"}},
	}
}

// The items of §22.10's right column for format 2, the rows' rules first: see the file header.
func gateM10OutRuleItems(catalog *Catalog) []*GateItem {
	return []*GateItem{
		gateRulesItem(catalog, gateM10OutGate),
		{
			Item:     "every case of M10's rows written: a builder registered on T2 and on T3 wherever its row runs there, its schedule stepping and naming the invariants it checks after every step, its twin too where it refuses or is forged (TEST.md's contract for schedule authors, rules 1 to 4; fault.Missing at M10-out); FS-73 and FS-114's purge and drop cases are named by their tests in place of a builder, and T4's parts are SDK-M10-06's cells' to run",
			Commands: []*GateCommand{{Repo: "sidecar", Command: gateM10OutWrittenCommand()}},
		},
		gateInvariantsItem(gateM10OutGate),
		gateStoreClockItem(catalog, gateM10OutGate),
		{
			Item:     "EvsCommit.tla with the purger and the drop extension, and IndexRollup.tla, passing TLC at their bounds, their mutants refused and their liveness held, the drop extension's F2DropsEnd under weak fairness among them, by the runs sidecartest/model/modelled.yml records at these sources of each mode M10's exit needs (§22.10's format 2 row, §23.6's M10 row; D-PHASE-7, R-TEST-10, D-TEST-18; TEST-M2-08, EVSB-M10-07, SEARCH-M10-02; QD-1116, QD-1119); a mode's record stands only at its sources' digest, so where one does not, open: this report runs no TLC itself",
			Commands: []*GateCommand{{Repo: "sidecar", Command: gateM10OutTlcCommand()}},
		},
	}
}

// The items of format 2's evidence beside its rows: see the file header.
func gateM10OutEvidenceItems() []*GateItem {
	return []*GateItem{
		{
			Item: "testdata/index/ fixed, its vectors byte-equal on every leg (§22.10's format 2 row, §22.9's Index determinism row; D-TEST-15, R-TEST-10, FI-22; SEARCH-M10-41, SDK-M10-06): every file reproduced by the tests its README names, under GOMAXPROCS 1 and 16 and other time zones and locales, the header a writer records held to the linked build and to normalizer 1, each leg this host has running them, the sdk's module graph linking normalizer 1, and every leg selecting normalizer 1's golang.org/x/text",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{"TestIndexVectorFilesAreAllReproduced", "TestIndexVectorsUnderEveryRuntime", "TestIndexHeadersRecordTheLinkedBuild"}},
				{Repo: "sidecar", Package: "./sidecartest/legs", Tags: "sidecar_legs", Names: []string{"TestIndexVectorLegsCoverEveryTarget", "TestIndexVectorsOnEveryLeg"}},
				{Repo: "sidecar", Package: "./check", Tags: "sidecar_check", Names: []string{"TestDeps", "TestRowsThatStartLaterHoldNow"}},
				{Repo: "sdk", Package: ".", Names: []string{"TestSdkLinksNormalizerOne", "TestSdkLinksNormalizerOneFailsOnAnotherTextModule"}},
				{Repo: "sdk", Package: ".", Tags: "sidecar_testhooks", Names: []string{"TestSdkReproducesTheIndexVectors"}},
			},
			External: "hardware: the legs this host cannot run, which the runner reads not run and passes over: windows/amd64 with no attested runner (§22.9's peers), linux/amd64 and arm64 unless SIDECAR_LEGS_IMAGE names a container image, and the gomobile legs, which SDK-M10-06's T4 cells run on surrogates (sdk/test-t4.sh), never this tool",
		},
		{
			Item: "D-TEST-13's projection of format 2's drive writes, computed from M2's price table and T3's index counts and never measured on new drives, the index on in every eligible repo, purges and staging on, each companion push charged to the content pushes it indexes, the directory's pushes and drops among the increments, held to D-TEST-11's gate on the block size M2 chose; with no price table or with inferred counts it reads open and holds format 2's freeze (§22.10's format 2 row, §23.4's M10 exit; R-TEST-11, R-PHASE-11, D-TEST-17; owner decision 174; EVSB-M10-08)",
			Tests: []*GateTest{
				{Repo: "server", Package: "./cli/filecluster-bench", Names: []string{
					"TestProjectionOnT3CountsThatFitPasses", "TestProjectionMissFailsTheGate", "TestProjectionReadsOpenOnInferredRows", "TestProjectionReadsOpenOnAnIndexRowThatIsNoEvidence",
					"TestProjectionReadsOpenWithoutM2sChoice", "TestProjectionJudgesTheBlockSizeM2Chose", "TestProjectionModeExitsByItsVerdict",
				}},
			},
			External: "hardware and production: M2's nvme run on the production hosts' PM9A3 set (D-TEST-11), whose measured price table the projection multiplies, and the index row's run on T3's clusters, which this report does not start; after the freeze, production's measured over priced bytes within 10% while §19.11's format2 gate holds format 2 to internal networks and design partners",
		},
		{
			Item: "D-TEST-12's observe check: under purge: observe every candidate is kept and checked against every retained version that could name it, a candidate a later version names caught and paged, and taskworker's soak counts and sidecarctl's evs observe report saying when a threshold is unmet (EVS2-M10-33)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./evsservice", Names: []string{"TestPurgeObserveCleanOnAnHonestHistory", "TestPurgeObserveCatchesACandidateALaterVersionNames", "TestPurgeObserveCountsAMarkedListUnchecked", "TestSweepUnderObserveRunsTheCheckAndKeepsEverything"}},
				{Repo: "server", Package: "./taskworker/work", Names: []string{"TestEvsObserveSoaksMet", "TestEvsObserveSoaksStateEachUnmetThreshold", "TestEvsObserveSoaksFailOnAFinding", "TestEvsObserveSoakReadsARestartAsANewStart", "TestEvsObserveSoakReadsEachSeriesAlone"}},
				{Repo: "server", Package: "./sidecarctl", Names: []string{"TestEvsObserveReportPrintsBothSoaksMet", "TestEvsObserveReportStatesEachUnmetThresholdAndExitsZero"}},
			},
		},
		{
			// nothing to run, so the tool reads it missing until the observe check runs on T3's stores
			Item: "D-TEST-12's observe evidence on T3 (§22.10's format 2 row): the observe check run at evacuation's sweep on T3's stores under purge: observe, finding no retained version naming a candidate; no T3 run of it is written (EVS2-M10-33's report), so no test shows it yet",
		},
		{
			Item: "purge and drops stay in observe by default, deletes on being a production soak's and then the owner's (§19.11's format2 gate; D-TEST-12, D-TEST-18; TEST-M10-05's trap): the engine's gate and the host's read an absent file, an absent block, a file that does not parse and any mode but exactly on as observe, a host with no gates is closed, and every checked-in config/<env>/sidecar.yml keeps format2 closed with purge and drop in observe",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./evsservice", Names: []string{"TestFormat2GateTable", "TestFormat2GateFollowsTheHostAndFailsClosed"}},
				{Repo: "server", Package: "./evshost", Names: []string{"TestHostFormat2GateReadsServersSidecarYml", "TestHostFormat2GateWithoutGatesIsClosed"}},
				{Repo: "server", Package: ".", Names: []string{"TestSidecarConfigFilesAreDark"}},
			},
		},
		{
			Item: "D-TEST-18's check before any drop deletes: taskworker's verify, written apart from mark and sharing none of its scan code, agreeing with an honest mark in observe, a seeded mark bug refused as {verify}, and the soak counting jobs on repos with both a rename and a cross-ref copy (EVSB-M10-05, EVS2-M10-33)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./evsservice/dropverify", Names: []string{"TestVerifyAgreesWithAnHonestMark", "TestVerifyRefusesASeededMarkBug", "TestVerifySharesNoScanCodeWithMark"}},
				{Repo: "server", Package: "./taskworker/work", Names: []string{"TestEvsObserveDropSoakSharesJobsWithBothARenameAndACopy"}},
			},
		},
		{
			Item: "a migration of a format-1 repo and a rollback to format-1 binaries (§22.10's format 2 row; FS-72's M10 cases; R-TEST-10; EVS2-M10-30, QD-854): a repo migrated while a format-1 client pushes and reads, the migration killed at each step, and evs and taskworker rolled back with format-2 data, on T2 and on T3 through the block's config and on the binaries testdata/evs/format1_build.txt pins",
			Tests: []*GateTest{
				gateFaultTests(
					"TestFs72Migration", "TestFs72MigrationMigrationKilledAfterStep6", "TestFs72MigrationMigrationKilledBeforeTheRaise",
					"TestFs72MigrationMigrationKilledAfterTheRaise", "TestFs72MigrationMigrationKilledBeforeTheHeadCas", "TestFs72MigrationMigrationKilledAfterTheHeadCas",
					"TestFs72Rollback",
				),
				{Repo: "server", Package: "./evshost", Tags: gateT3Tags, Stores: true, Names: []string{
					"TestFs72MigrationOnT3", "TestFs72MigrationMigrationKilledAfterStep6OnT3", "TestFs72MigrationMigrationKilledBeforeTheRaiseOnT3",
					"TestFs72MigrationMigrationKilledAfterTheRaiseOnT3", "TestFs72MigrationMigrationKilledBeforeTheHeadCasOnT3", "TestFs72MigrationMigrationKilledAfterTheHeadCasOnT3",
					"TestFs72RollbackOnT3", "TestFs72RollbackThroughTheBlockConfigOnT3", "TestFs72RollbackOnThePinnedBuildOnT3",
				}},
			},
		},
		{
			// nothing to run: each world holds one repo
			Item: "the migration of a format-1 repo set (§22.10's format 2 row): each world FS-72's cases run on holds one repo, so no run migrates a set (EVS2-M10-30's report), and no test shows it yet",
		},
		{
			Item:  "a format-1 repo's first index build, its search equal to D-TEST-14's oracle (§23.4's M10 exit; R-TEST-10; SEARCH-M10-35): FS-79's migration clause, a ref a format-1 client wrote holding no index, every push not yet searchable until the first build, then every push indexed and found as SearchOracle finds it, on the search world's stand-in for evs",
			Tests: []*GateTest{gateFaultTests("TestFs79MigrationEndsWithItsFirstBuild")},
		},
		{
			// nothing to run: the two halves run in different worlds
			Item: "a format-1 repo migrated through evs and then indexed, in one run: FS-72's migration runs on the evs world with no index and FS-79's first build on the search world with no migration, so no run joins them (§23.4's M10 exit), and no test shows it yet",
		},
		{
			Item: "format 2's fuzz seeds, run as ordinary tests (§22.10's format 2 row, §22.6; D-TEST-4, D-TEST-14): every §22.6 target registered with its seeds and each target's seeds run under test.sh, and each target testdata/fuzz/registry.yml gives M10, the oracle's extractor held equal to the index's among them, its seeds run here; long campaigns run nowhere (owner decision 101)",
			Tests: slices.Concat(
				[]*GateTest{{Repo: "sidecar", Package: "./check", Tags: "sidecar_check", Names: []string{"TestFuzzRegistry", "TestFuzzSeedsRunUnderTestSh"}}},
				gateM10FuzzTests(),
			),
		},
		{
			Item: "§2.8 carries M10's rows before format 2's release (§23.4's M10 exit; I-18): connect-5, remote search's relay view; evs-26, the index's view; evs-27, the team directory with its cards; and evs-28, the drop job's state, each live with the line saying when its values land, and metadata_list.yml as §2.8's block",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestSchemaGuardCarriesV8sRows", "TestSchemaGuardMapsFormat2sValues", "TestSearchMetadataRowsNameTheIndex"}},
				{Repo: "sidecar", Package: "./check", Tags: "sidecar_check", Names: []string{"TestMetadataListIsSection2sBlock"}},
			},
		},
		{
			Item: "servers get only §2.8's fields: the schema guard over every proto field, object family and Redis family format 2, the index, remote search and the directory's cards add (§22.7's guard; I-18; TEST-M2-10)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestSchemaGuard", "TestSchemaGuardPassesACleanTree", "TestSchemaGuardFailsOnAProtoFieldNoRowNames", "TestSchemaGuardFailsOnANewObjectFamily", "TestSchemaGuardFailsOnANewRedisFamily", "TestCheckStoresReadsTheRealList"}},
				{Repo: "sidecar", Package: "./check", Tags: "sidecar_check", Names: []string{"TestSchemaGuard", "TestMetadataListRefusesAHandEdit"}},
			},
		},
		{
			Item: "§22.7's leak leg: a sidecar_leaktest build leaks into every class the scan covers, and the scan catches each, on T2 and on T3's stores (TEST-M2-09)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_leaktest", Names: []string{"TestEveryClassCatchesItsLeak", "TestAClassWithNoLeakFails", "TestRemovingAFormFromTheScannerFailsTheSelfTest"}},
				{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags + ",sidecar_leaktest", Stores: true, Names: []string{"TestT3EveryStoreClassCatchesItsLeak"}},
			},
		},
	}
}

// The items of the tree's checks every exit runs, §22.8's benchmark rows and what the world owes: see the file header.
func gateM10OutLedgerItems() []*GateItem {
	items := []*GateItem{
		{
			Item: "the CROSSSLOT lints: every script and multi-key call keeps its keys in one slot, read from the code and from T3's engines' calls, M10's engines among them (§22.4)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/crossslot", Names: []string{"TestThisModuleKeepsTheRule", "TestTheModuleWalkReachesTheCodeItGuards", "TestPlantedCallsReadAsTheirNamesSay"}},
				{Repo: "server", Package: "./sidecart3", Names: []string{"TestCrossslotKeysSpreadOverTheMasters", "TestCrossslotCallsKeepEachShapeOnce"}},
				// the lint's refusal of one node runs in server's test env, on the private stores
				{Repo: "server", Package: "./sidecart3", Stores: true, Names: []string{"TestRunCrossslotRefusesOneNode"}},
			},
		},
		{
			Item: "budgets.yml: §22.5's hot-path gates and §22.9's budgets, a raise only with a reviewed line, the inline paths run with no Postgres and op-counted Redis (D-TEST-3; TEST-M1-09)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./check", Tags: "sidecar_check", Names: []string{"TestBudgetsRiseOnlyWithAReviewedLine", "TestBudgetSizeRowsHoldTheSizeGatesNumbers", "TestBudgetBenchmarksHoldTheirAllocations"}},
				{Repo: "server", Package: "./sidecart3", Stores: true, Names: []string{"TestEveryPathRowResolvesOrReadsMissing", "TestInlinePathFailsAPlantedPostgresRead", "TestInlinePathFailsOneRedisCallOverItsRow"}},
			},
		},
		{
			Item: "targets.yml: R-TEST-7's numbers, §11.15's and §16.10's search targets among them, each with the test that shows it, the tier it runs on and its owner, a number nothing verified reading open (D-TEST-7; TEST-M2-13)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestTargetLedgerRowsResolveOrReadOpen", "TestTargetLedgerResolvesTestsByName"}},
			},
			External: "hardware and production: the targets T5's performance host and production show, which this host does not run (targets.yml's tier column)",
		},
		{
			Item: "peers.yml and §22.9's git-lfs row: every conformance peer pinned and rerun on each pin change, and stock git-lfs on the matrix's rows this host holds, each pointer byte-exact against the format git-lfs documents, export keeping git's oid, the required objects R finding every object the pointers name, the report naming what ran and what was skipped (D-TEST-7; X19; TEST-M2-17, EVS2-M10-29)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./check", Tags: "sidecar_check", Names: []string{"TestConformanceLedger"}},
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestGitLfsMatrixRunsEveryRowItsBinariesAnswer", "TestGitLfsMatrixSkipsWhatTheHostLacksSayingWhy", "TestGitLfsMatrixOnThisHost"}},
				{Repo: "server", Package: "./evshost", Names: []string{"TestLfsConformanceAcrossTheMatrix"}},
			},
			External: "hardware: the peers this host lacks (§22.9), git-lfs 3.0.2 and 3.4.1 with git 2.34 and 2.43 as Ubuntu 22.04 and 24.04 ship them, over ssh from a machine with no local ur; the flows through the daemon's transfer agent wait on the daemon's composition of its EvsClient and are not run",
		},
		{
			Item: "§22.8's search, remote and phone rows at reduced scale on T2, with production settings: search p50 and p99 over buckets and all, ranking and typo quality, a missed query failing; remote search's tap to first and next page and the indexer's service time; the phone's searches within its working set (SEARCH-M10-40)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/bench", Tags: "sidecar_testhooks", Names: []string{
					"TestSearchBenchGivesTheRowsFieldsAtReducedScale", "TestSearchBenchQualityFailsAMissedQuery", "TestRemoteBenchGivesTheRowsFieldsAtReducedScale", "TestPhoneBenchGivesTheRowsFieldsAtReducedScale",
				}},
			},
			External: "hardware: the rows at §22.8's scale on T5's performance host (five years at 100 and 300 messages a day, real relays and netem for remote search), which a reduced run here stands for and is no evidence of",
		},
		{
			Item: "§22.8's index row: the index writers' load driven through filecluster-bench's index mode, each leg's metadata writes counted through the counting store, a failed leg a smoke, and the off and indexed legs whose increments D-TEST-13's projection reads (SEARCH-M10-40, EVSB-M10-08)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/bench", Tags: "sidecar_testhooks", Names: []string{"TestIndexLoadRunsTheOffAndIndexedLegs", "TestIndexLoadRefusesAClassItDoesNotRun"}},
				{Repo: "server", Package: "./cli/filecluster-bench", Names: []string{"TestIndexRunCountsEachLegsWritesThroughTheCountingStore", "TestCountedOutcomesCountWhatMayHaveWritten", "TestIndexRunStopsAtAFailedLegAndIsASmoke", "TestIndexModeRefusesWithoutALoad"}},
				{Repo: "server", Package: "./cli/filecluster-bench", Tags: "sidecar_testhooks", Names: []string{"TestIndexModeRunsTheSearchNotesLoad"}},
			},
			External: "hardware: the index row's run on T3's clusters and on M2's staging PM9A3 set, whose counts are the projection's evidence; this report runs neither",
		},
	}
	items = append(items, gateFs86CardItems()...)
	return append(items, []*GateItem{
		{
			Item: "§22.8's drop row: drop scan rates and a 60 GB history's job time from the drop mode's windows, the load's pause holding past its line (EVSB-M10-08)",
			Tests: []*GateTest{
				{Repo: "server", Package: "./cli/filecluster-bench", Names: []string{"TestDropBenchRunsEachWindowAndComputesTheRow", "TestDropFiguresComputeTheHistorysJobTime", "TestLoadPauseHoldsPastItsLineAndKeepsTheTimeHeld"}},
			},
			External: "hardware: the drop row on a segment cluster of production's HDDs (§22.8), which a run here stands for and is no evidence of",
		},
		{
			Item: "§22.8's hdd and trash rows at M10: purges at year two's rate on synthetic objects in a bucket of their own beside the mix under the 50% pause, and slot purges beside the trash run's overwrites (EVSB-M10-08)",
			Tests: []*GateTest{
				{Repo: "server", Package: "./cli/filecluster-bench", Names: []string{
					"TestHddM10RunsTheMixWithPurgesBesideIt", "TestHddM10RefusesWithoutCapacityOrABucketOfItsOwn", "TestPurgeLoadDeletesEachObjectItsAllowanceAfterItsPut", "TestPurgeLoadDefaultsAreYearTwos",
					"TestTrashM10RunsSlotPurgesBesideTheOverwrites",
				}},
			},
			External: "production: the hdd run on the production segment cluster with purges in their own bucket (TEST.md's External, M10), and the trash run on the PM9A3 set",
		},
		{
			Item: "D-OPS-21's drop job bounds: one job a segment cluster, its start gated, its pause past half the HDD drives' measured capacity or while none is known (EVSB-M10-03, EVSB-M10-06)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./evsservice", Names: []string{"TestDropJobTakeIsOneInstances", "TestDropJobGatesStartNothing"}},
			},
		},
		{
			// nothing to run: the pace runs unmeasured
			Item: "D-OPS-21's drop job pace: at most 32 MB/s of reads and 10 DELETEs a second; no test holds a job's reads to DropSettings.ReadBytesPerSecond or its DELETEs to DeletesPerSecond (EVSB-M10-03's and EVSB-M10-06's reports), so no test shows it yet",
		},
		gateT4SearchCellsItem(),
		{
			Item:     "FS-125 held with PROTO-M10-05 (owner decision 609; QD-1038): C19's window accounting is withdrawn, the remote-search pair's contracts being accounted like any peer's, as FS-83 checks; the row keeps its number and its sweep runs only if the windows return, so its cases above read missing with no test",
			External: "people: the owner, should C19's windows return",
		},
		{
			Item:     "D-TEST-12's and D-TEST-18's production soaks before deletes turn on: at least 14 days and 10,000 candidates with none a retained version names before purge: on, and at least 30 days and 200 jobs, half on repos with renames and cross-ref copies, with no delete-set member a retained version names before drop: on",
			External: "production: internal networks and design partners after format 2's final freeze, then the owner",
		},
		{
			Item:     "format 2's bytes freeze at M10's Gn-out (§23.8, §22.10's format 2 row; D-PHASE-7, D-PHASE-10, owner decision 169): the owner's approval of this report and the merge of sidecar into main in §23.9's order, production only after, dark first, where D-TEST-13 confirms the projection (owner decision 174)",
			External: "people: the owner's sign-off at M10's Gn-out, which owner decision 194 lets the build move past",
		},
	}...)
}

// D-TEST-17's readings of FS-86's card case, which falls due at the later of M6's and M10's exits: §22.8's directory row
// against §16.11's cost table, the Team limit's reading on T3's layouts, read apart from every other failure (QD-1068),
// and the runs in physical time no one has built. M10's exit and the held gate (gate_held.go) both carry them.
func gateFs86CardItems() []*GateItem {
	return []*GateItem{
		{
			Item: "§22.8's directory row with FS-86's card case against §16.11's cost table (D-TEST-17; RECORD-M10-07): DirectoryCostOracle's cards, its three mutants failing, fake-clock days at 500, 2,000 and 5,000 members within the table's M10 row and the cards ref's ceilings, the Team limit's with a following daemon on the real client, each push priced on §11.13's directory rows, and the cards ref's commits on T3's local stack at reduced scale, whose p99 misses are logged and fail nothing (owner decision 598)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{
					"TestDirectoryCostOracleFetchesEachChangedCardsNewestVersion", "TestDirectoryCostOracleReadsCardsSixtyFourToARequest", "TestDirectoryCostOracleCardRemovalsAndVersionlessNotices",
					"TestDirectoryLoadCardDayHoldsToTheOracle", "TestDirectoryLoadCardMutantNoCoalescingFails", "TestDirectoryLoadCardMutantNoHeadReproductionFails", "TestDirectoryLoadCardMutantRefetchingUnchangedCardsFails",
					"TestDirectoryLoadCardDayAtFiveHundredMembers", "TestDirectoryLoadCardDayAtFiveThousandMembers", "TestDirectoryLoadCardQueueCountsARerunBehindACommit",
					"TestDirectoryLoadCardQueueAnswersBusyPastItsWaitingCommits", "TestDirectoryLoadCardCommitsFailUnderAnInjectedHeadDelay", "TestDirectoryLoadDrivePushesPriceEveryPush",
				}},
				// the day at the Team limit, with a following daemon on the real client, in this gate's form alone
				{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{"TestDirectoryLoadCardDayAtTheTeamLimit"}, Args: []string{"-directory-load-full"}},
				{Repo: "server", Package: ".", Tags: gateT3Tags, Stores: true, Names: []string{
					"TestFs86CardCommitsAtTheTeamLimitOnT3", "TestFs86CardCommitsAtTheStressCaseOnT3", "TestFs86CardCommitsOnTheLocalStackLogTheirP99MissesAndHoldTheRest",
				}},
			},
			External: "hardware and production: the price table those bytes are priced on is §11.13's inferred one until M2's nvme run measures it (D-TEST-11), and the directory's pushes join D-TEST-13's projection only once filecluster-bench takes their rows",
		},
		{
			Item: "D-TEST-17's reading at the Team limit: FS-86's card case for a whole peak hour at the Team limit's rate on T3's 4-host file-cluster layouts, then 15 s at three times it, held to the cards ref's p99, rerun, 429 and FOLD_BEHIND ceilings; a miss blocks this gate and the owner hears then, so it is an item of its own, read apart from every other failure (QD-1068; RECORD-M10-07)",
			Tests: []*GateTest{
				// the hour is real time, so the run has a bound of its own past the tool's default (QD-1058)
				{Repo: "server", Package: ".", Tags: "sidecar_testhooks,sidecar_pending,sidecar_filecluster_t3", Timeout: 2 * time.Hour, Stores: true, Names: []string{"TestFs86CardCommitsAtTheTeamLimitOnTheLayouts"}},
			},
			External: "hardware: a host running nothing else for the hour (owner decision 598), with local/file-cluster-t3's layouts up; the test logs the machine's load average, and on a shared build host a pass is no reading",
		},
		{
			// nothing to run: not built
			Item: "D-TEST-17's runs in physical time beyond the Team limit's hour: the 26 h run at 500 members on T3, and the stress case's physical hour beside §22.8's year-one mix; neither is built (RECORD-M10-07's report), so no test shows it yet",
		},
	}
}

// T4's search cells at M10 (SDK-M10-06), through which the T4 rows of FS-77, FS-83, FS-109 and FS-110 run, their
// app-host cases' T4 parts among them: M10's exit and the held gate both carry it, and it reads open on the devices.
func gateT4SearchCellsItem() *GateItem {
	return &GateItem{
		Item: "T4 at M10 (§22.4's T4 from M10, §18.4's search working sets; SDK-M10-06): the ios32 and Android cells with search on, each searching, downloading and asking through the app's own calls within §18.4's working set, a deliberate per-search key collection failing them; the T4 rows of FS-77, FS-83, FS-109 and FS-110 run through these cells",
		Tests: []*GateTest{
			{Repo: "sdk", Package: ".", Tags: "sidecar_testhooks", Names: []string{
				"TestIos32CellSearchesDownloadsAndAsks", "TestAndroidCellSearchesDownloadsAndAsks", "TestT4SearchBudgetCatchesAPerSearchKeyCollection",
				"TestIos32CellSearchesWithinItsWorkingSet", "TestAndroidCellSearchesWithinItsWorkingSet",
			}},
		},
		External: "devices: T4's physical runs on the ios32 and Android surrogates and Safari's wasm engine (owner decision 100), which no figure here stands for",
	}
}

// Every item of M10's exit: the rows' rules, format 2's evidence, §22.7's assertions and scenarios, then the ledgers,
// the benchmark rows and what the world owes.
func gateM10OutItems(catalog *Catalog) []*GateItem {
	items := gateM10OutRuleItems(catalog)
	items = append(items, gateM10OutEvidenceItems()...)
	items = append(items, gatePrivacyItems(sidecartest.DefaultPrivacyAsserts(), gateM10OutGate)...)
	items = append(items, gateScenarioItems(sidecartest.DefaultScenarioRegistry(), gateM10OutGate)...)
	return append(items, gateM10OutLedgerItems()...)
}

var gateM10Sweep = RegisterGateSweep(&GateSweep{
	Gate:  "M10",
	Cases: gateM10Cases(DefaultCatalog()),
	Items: gateM10OutItems(DefaultCatalog()),
})
