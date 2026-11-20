// M10's entry review (TEST-M10-04; §22.10's left column for format 2, §23.8's Gn-in, §23.6's M10 row; D-TEST-9,
// D-PHASE-7, R-TEST-10): what freezes format 2's specification, the DROP payload and directory.proto's cards with it,
// and search.proto (§23.8's M10 row), each item with what shows it, so `sidecar-gate M10-in` reports each pass, fail,
// missing or open. It reads as M2's entry does (gate_m2_in.go):
//
//   - peer review of format 2's schemas: people's work, open.
//   - EvsCommit.tla with the purger and IndexRollup.tla passing TLC: TEST-M2-08's tests of both models in gate mode,
//     which let a model's recorded runs stand while nothing it keeps has changed; the report runs no TLC of its own.
//     The purger is EvsCommit's M10 part, run story by story, and TEST-M2-08's gate verdict needs only the model,
//     mutants and live modes, so this item also reads modelled.yml for a passing stories run at EvsCommit's sources:
//     without one it reads open, never pass. Where no run stands it reads open and says TLC has not run.
//   - FS-64 to FS-81 and FS-83 to FS-96 written against the fakes: one item per case of those rows that M10's exit
//     holds, its later-of cases among them, since M0-M10 build straight through and M10's exit comes last. A case is
//     written as GateWritten finds it: registered, with a builder whose schedule steps and checks, its twin too where
//     it refuses or is forged. An empty builder fails, and a case no builder covers reads missing. The one other way a
//     case is written is a case that runs on T3 alone and that no builder can cover, whose T3 tests M10's exit sweep
//     names in place of the convention: FS-73, whose world drives stock git and needs a testing.TB (QD-995). It is
//     written when each test the sweep names is declared where it runs, under its tags. FS-85 has no case at M10, its
//     cases being M6's and M8's, so it has no item here.
//   - the vector schemas fixed: format 2's vector files and the tests that hold the code to them, and the protos
//     format 2 adds held to the design's fences. Nothing pins a directory card's or repo file's bytes yet, which an
//     item with nothing to run says, so it reads missing.
//   - §23.6's M10 design closure and §23.8's review of the changes since the last gate and of §22's exit-test plan:
//     people's work, open.
//
// The drop extension's TLC pass is M10's exit's (§22.10's right column; §22.17's blocking line), so no item here
// waits on it, and nothing here reads fail for want of it. modelled.yml records a mode's run whole, though, and
// run-tlc.sh's mutants and stories modes each hold the purger's runs and the drop extension's together, so the TLC
// item stands only on runs that show both: a drop run that does not pass leaves it open until the two parts are
// recorded apart, which is TEST-M2-08's harness to do (questions/test-m10-04-tlc-modes-split-purger-from-drops.md).
//
// No item here is an external audit (R-TEST-6; owner decisions 99, 119). Each command's last line says its outcome,
// as server's gate tool reads it (GateOutcomeLinePrefix): the written check and the TLC check run as tests of this
// package, under flags of gate_m10_in_test.go that only the commands pass.

package fault

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// The catalog's gate whose cases M10's entry review must find written, of the rows §22.10's left column names.
const gateM10InRowsGate = "M10-out"

// The rows §22.10's left column names written against the fakes, as first and last row numbers: FS-64 to FS-81 and
// FS-83 to FS-96. FS-82's cases are M2's, M7's and M8's, and the cases M10's exit holds past FS-96 are the exit's alone.
var gateM10InRowRanges = [][2]int{{64, 81}, {83, 96}}

// The flags gate_m10_in_test.go reads, which only M10-in's commands pass: a case's written check, and the TLC check.
const (
	GateM10InWrittenFlag = "fault.gate-m10-in-written"
	GateM10InTlcFlag     = "fault.gate-m10-in-tlc"
)

// TEST-M2-08's tests of EvsCommit and IndexRollup, in gate mode at the models' sources: EvsCommit's model, mutants,
// live and stories, the purger's stories and twins among the last two, and IndexRollup's model, mutants and live.
var gateM10InTlcTests = []string{
	"TestEvsCommitPassesTlcAtItsBounds",
	"TestEvsCommitMutantsFailTlc",
	"TestEvsCommitLivenessHolds",
	"TestEvsCommitStoriesPassTlc",
	"TestIndexRollupPassesTlcAtItsBounds",
	"TestIndexRollupMutantsFailTlc",
	"TestIndexRollupLivenessHolds",
}

// modelled.yml's own check in sidecartest/model, which logs each model's sources digest, the one a recorded run must
// carry to stand.
const gateModelledSourcesTest = "TestModelledNamesEachModelsSources"

// The model whose purger M10's entry needs, and the mode its M10 part's runs are recorded under (run-tlc.sh stories).
const (
	gateM10InPurgerSpec = "EvsCommit"
	gateM10InPurgerMode = "stories"
)

// The line gateModelledSourcesTest logs for each model under go test -v, with its sources digest, empty where a
// source repository is not beside this checkout.
var gateModelledDigestPattern = regexp.MustCompile(`(?m)^\s+\S+\.go:[0-9]+: ([A-Za-z]+): [0-9]+ source files, digest ([0-9a-f]*), [0-9]+ runs recorded$`)

// How M10-in's TLC item reads its run's output.
type GateM10InTlcSettings struct {
	// How many of the run's last lines a failure's reason quotes, when the failure names no test of its own: enough
	// for go test's verdict and what it printed just before.
	ReasonLineCount int
}

// Three lines, as M2-in's TLC item quotes a run that never built.
func DefaultGateM10InTlcSettings() *GateM10InTlcSettings {
	return &GateM10InTlcSettings{ReasonLineCount: 3}
}

// Every case M10's exit holds of the rows §22.10's left column names, in row order: each must be written at M10's
// entry.
func GateM10InCases(catalog *Catalog) []*Case {
	cases := []*Case{}
	for _, testCase := range catalog.GateCases(gateM10InRowsGate) {
		inRange := slices.ContainsFunc(gateM10InRowRanges, func(rowRange [2]int) bool {
			return rowRange[0] <= testCase.Row.Number && testCase.Row.Number <= rowRange[1]
		})
		if inRange {
			cases = append(cases, testCase)
		}
	}
	return cases
}

// The command a case's written check runs in the sidecar repo: this package's test under the hooks, as T2 runs it.
func gateM10InWrittenCommand(testCase *Case) []string {
	argument := testCase.Row.Id
	if testCase.Name != "" {
		argument += "/" + testCase.Name
	}
	return []string{"go", "test", "-count=1", "-v", "-tags", "sidecar_testhooks", "-run", "^TestGateM10InRowWritten$", "./sidecartest/fault", "-" + GateM10InWrittenFlag + "=" + argument}
}

// The command M10-in's TLC item runs in the sidecar repo.
func gateM10InTlcCommand() []string {
	return []string{"go", "test", "-count=1", "-v", "-tags", "sidecar_testhooks", "-run", "^TestGateM10InModelsPassTlc$", "./sidecartest/fault", "-" + GateM10InTlcFlag}
}

// The case a written check's flag names, <row> or <row>/<case>, which must be one M10's entry looks for.
func GateM10InWrittenCase(catalog *Catalog, argument string) (*Case, error) {
	rowId, caseName, _ := strings.Cut(argument, "/")
	testCase := catalog.Case(rowId, caseName)
	if testCase == nil {
		return nil, fmt.Errorf("%q names no case catalog.yml holds", argument)
	}
	if !slices.Contains(GateM10InCases(catalog), testCase) {
		return nil, fmt.Errorf("%s is no case of FS-64 to FS-81 or FS-83 to FS-96 that M10's exit holds, so M10's entry does not look for it", testCase)
	}
	return testCase, nil
}

// Whether testCase is written at M10's entry (§22.10's left column for format 2): GateWritten's reading, and for a
// case that runs on T3 alone and that no builder covers, whether each test M10's exit sweep names for it in place of
// the convention is declared where it runs, under its tags. Only a case no builder can cover is named that way
// (QD-995's FS-73), and a declared test is written, whether it passes being M10's exit's; with no such test, or one
// not declared, the case stays missing. declared is GateTestDeclared over the checkouts beside this one, but in a
// fixture; lookup and settings are as GateWritten takes them.
func GateM10InWritten(ctx context.Context, testCase *Case, lookup func(rowId string, caseName string, tier Tier) *Registration, declared func(test *GateTest) []error, settings *GateWrittenSettings) *GateWrittenResult {
	result := GateWritten(ctx, testCase, lookup, settings)
	if result.Outcome != GateOutcomeMissing || slices.Contains(testCase.Tiers(), TierT2) {
		return result
	}
	named := gateSweep("M10").Cases[testCase.String()]
	if len(named) == 0 {
		return result
	}
	errs := []string{}
	names := []string{}
	for _, test := range named {
		for _, err := range declared(test) {
			errs = append(errs, err.Error())
		}
		for _, name := range test.Names {
			names = append(names, fmt.Sprintf("%s's %s %s", test.Repo, test.Package, name))
		}
	}
	if 0 < len(errs) {
		result.Reason += fmt.Sprintf("; M10's exit sweep names its tests in place of a builder, and %s", strings.Join(errs, "; "))
		return result
	}
	result.Outcome = GateOutcomePass
	result.Reason = fmt.Sprintf("%s: written on %s as the tests M10's exit sweep names in place of a builder, QD-995's way for a case no builder can cover, whose world needs a testing.TB: %s, each declared where it runs under its tags; whether it passes is M10's exit's", testCase, result.Tier, strings.Join(names, ", "))
	return result
}

// What modelled.yml records of a model, as far as M10-in's TLC item reads it.
type gateModelledFile struct {
	Models []*gateModelledModel `yaml:"models"`
}

// One model by its spec, with its recorded runs, newest last.
type gateModelledModel struct {
	Spec string             `yaml:"spec"`
	Runs []*gateModelledRun `yaml:"runs"`
}

// One recorded run: its mode, its result, and the digest of the sources it ran at, which it stands at alone.
type gateModelledRun struct {
	Mode          string `yaml:"mode"`
	Result        string `yaml:"result"`
	SourcesSha256 string `yaml:"sources_sha256"`
}

// What M10-in's TLC item reports from TEST-M2-08's tests of EvsCommit and IndexRollup and modelled.yml's own check,
// run together in gate mode with no TLC, by their go test -v output and whether that run failed, and from modelled.yml's
// bytes. As GateTlcOutcome reads the tests: pass when each passed, its recorded runs standing; open, saying so, when
// any failed only because TLC has not run at its model's sources; fail for any other failure, a test that gave no
// verdict, or a modelled.yml its own check refuses. Where the tests pass, the purger's runs must stand too: a passing
// stories run of EvsCommit recorded at the digest the check logged for its sources, without which the item reads
// open, never pass, since TEST-M2-08's gate lets that mode stand on the other three. No outcome here comes from the
// drop extension alone, whose own pass is M10's exit's. settings nil takes the defaults.
func GateM10InTlcOutcome(output []byte, runErr error, modelled []byte, settings *GateM10InTlcSettings) (string, string) {
	if settings == nil {
		settings = DefaultGateM10InTlcSettings()
	}
	text := string(output)
	verdicts := map[string]string{}
	for _, match := range gateTestVerdictPattern.FindAllStringSubmatch(text, -1) {
		verdicts[match[2]] = match[1]
	}
	if len(verdicts) == 0 {
		return GateTlcOutcome(output, runErr, gateM10InTlcTests)
	}
	if verdicts[gateModelledSourcesTest] != "PASS" {
		return GateOutcomeFail, fmt.Sprintf("modelled.yml's own check, %s, did not pass, so no recorded run can stand: %s", gateModelledSourcesTest, gateLastLines(text, settings.ReasonLineCount))
	}
	outcome, reason := GateTlcOutcome(output, runErr, gateM10InTlcTests)
	if outcome != GateOutcomePass {
		return outcome, reason
	}

	digest := ""
	found := false
	for _, match := range gateModelledDigestPattern.FindAllStringSubmatch(text, -1) {
		if match[1] == gateM10InPurgerSpec {
			digest = match[2]
			found = true
		}
	}
	if !found || digest == "" {
		return GateOutcomeFail, fmt.Sprintf("%s logged no sources digest for %s, so whether its %s, the purger's runs, stand is unknown", gateModelledSourcesTest, gateM10InPurgerSpec, gateM10InPurgerMode)
	}
	file := &gateModelledFile{}
	if err := yaml.Unmarshal(modelled, file); err != nil {
		return GateOutcomeFail, fmt.Sprintf("modelled.yml does not parse: %v", err)
	}
	standing := false
	for _, model := range file.Models {
		if model.Spec != gateM10InPurgerSpec {
			continue
		}
		for _, run := range model.Runs {
			if run.Mode == gateM10InPurgerMode && run.Result == "pass" && run.SourcesSha256 == digest {
				standing = true
			}
		}
	}
	if !standing {
		return GateOutcomeOpen, fmt.Sprintf("%s; but no passing %s run of %s, which holds the purger's stories, stands at its sources (digest %s): TEST-M2-08's gate verdict needs only its model, mutants and live runs, so this item reads the purger's from modelled.yml itself; a gate's model phase runs them beside the other modes when %s's sources change, and run-tlc.sh %s %s runs them alone", reason, gateM10InPurgerMode, gateM10InPurgerSpec, digest, gateM10InPurgerSpec, gateM10InPurgerMode, gateM10InPurgerSpec)
	}
	return GateOutcomePass, fmt.Sprintf("%s; %s's %s, which hold the purger's, stand at its sources too", reason, gateM10InPurgerSpec, gateM10InPurgerMode)
}

// The items people sign at M10's entry, none of which a test shows.
func gateM10InPeopleItems() []*GateItem {
	return []*GateItem{
		{
			Item:     "peer review of format 2's schemas: §11's versionless fields and records, the index's objects and encodings, the rule, lock and migration records, the DROP push and its states, search.proto, directory.proto's cards, §11.14's field registry and RECORD.md's search fields (§22.10's M10 entry; owner decision 169)",
			External: "people: the owning sections' reviewers read and sign the schemas (owner decision 99: no external review stands in)",
		},
		{
			Item: "§23.6's M10 design closure: versioning per version, kind-5 and staged content, the purge with its allowance and sweep, the migration and git-lfs's store (§11), the network's rule (§7) and the repo lock (§8); the drop-history action: the DROP push, fence, job and states (§11); " +
				"the index's objects, encodings, field registry, partitions, coverage, exclusions, roll-up and lock, erasure cuts and rewrites; search.proto and the remote rules (§11); directory.proto's cards (§16); the search tools, scopes, caches and taint (§5, §16); the phone and page fetch rules (§18); §2.8's v7 rows as v8 amends them; RECORD.md's search fields",
			External: "people: the Gn-in review reads and signs the closure (§23.8)",
		},
		{
			Item:     "the changes since the last gate and §22's exit-test plan for M10 reviewed (§23.8's Gn-in)",
			External: "people: the Gn-in review reads them",
		},
	}
}

// What holds format 2's vectors and schemas to the code, each family its own item, and what no vector pins yet.
func gateM10InVectorItems() []*GateItem {
	return []*GateItem{
		{
			Item: "the vector schemas fixed, §11's format 2: testdata/evs/format2/'s schema (its messages, enums, the numbers format 2 relies on and its layouts) and vectors, the kind-5 segments, batches, windows and the DROP payload, and the citation and purge vectors, with the tests that hold the code to them byte for byte (§22.10's M10 entry; EVS2-M10-01, EVS2-M10-03, EVS2-M10-04)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{
					"TestEvsFormat2SegmentVectors", "TestEvsFormat2BatchVectors", "TestEvsFormat2LayoutsMatchTheSchema", "TestEvsDropVectors",
					"TestEvsFormat2VectorFilesMatchTheSchema", "TestEvsCitationVectors",
				}},
				{Repo: "sidecar", Package: "./evsservice", Names: []string{"TestPurgeCandidateVectors"}},
				{Repo: "sidecar", Package: "./protocol", Names: []string{
					"TestEvsFormat2MessagesKeepTheirNumbers", "TestEvsFormat2EnumsKeepTheirNumbers", "TestEvsFormat2RelyOnFormat1sNumbers",
					"TestEvsFormat2NamesNoKeepLastN", "TestEvsFormat2MetadataRowsComplete", "TestEvsFormat2MessagesRoundTrip",
				}},
			},
		},
		{
			Item: "the vector schemas fixed, the index (§11.14; D-TEST-15): every file of testdata/index/ reproduced by the test its README names, normalizer 1's tables and extractor 1's conformance among them, and the header a writer records held to the linked build, on this host; byte-equal on every leg is M10's exit's (§22.10's right column)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{
					"TestIndexVectorFilesAreAllReproduced", "TestIndexCharsetLabels", "TestIndexReferenceTableIsCurrent", "TestIndexReferenceTableIsEntitiesJson",
					"TestIndexConformanceFile", "TestIndexStreamConformanceFile", "TestIndexConformanceMail", "TestIndexStreamConformanceMail",
					"TestSearchSizeVectors", "TestIndexSkipVectors", "TestEntryVectors", "TestDocKeyVectors", "TestExtractVectors", "TestIndexHeadVectors",
					"TestIndexMergeVectors", "TestNormalizationVectors", "TestLinkedTablesAreNormalizerOne", "TestIndexRollupVectors", "TestShardVectors",
					"TestSlotVectors", "TestIndexHeadersRecordTheLinkedBuild",
				}},
			},
		},
		{
			Item: "the vector schemas fixed, format 2's protos: every fenced block, search.proto's, evsindex.proto's and directory.proto's cards among them, declared as DESIGN.md writes it, evsindex.proto and search.proto held to the numbers §11.14 prints, and a directory card's stored form, its 2 KiB steps, caps and file bound (§22.10's M10 entry; SEARCH-M10-01, RECORD-M10-02)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./protocol", Names: []string{
					"TestDeclarationsMatchTheirFences", "TestIndexAndSearchFieldNumbersAreAsPrinted", "TestIndexAndSearchHoldNoOneof", "TestOnlySearchRequestReservesNumbers",
					"TestIndexAndSearchEnumsOpenUnspecified", "TestRemoteSearchKeepsItsMessageTypes", "TestIndexMessagesEncodeInFieldOrder",
				}},
				{Repo: "sidecar", Package: ".", Names: []string{
					"TestDirectoryCardWrittenFoldedAndPadded", "TestDirectoryCardCaps", "TestDirectoryCardFileBound", "TestDirectoryCardDecoders",
				}},
			},
		},
		{
			// nothing to run, so the tool reads it missing until a vector file and its test exist
			Item: "the vector schemas fixed, directory.proto's cards and repo files: a vector file pinning a signed card's and repo file's bytes, as testdata/evs/format2/ and testdata/index/ pin theirs, whose bytes freeze with format 2 at M10's exit (§23.8; D-PHASE-11): none is checked in, so no test shows it yet",
		},
	}
}

// Every item of M10's entry review in §22.10's order, the people's peer review first, each case of FS-64 to FS-81 and
// FS-83 to FS-96 that M10's exit holds its own item, then the vectors, the design closure and the review.
func gateM10InItems(catalog *Catalog) []*GateItem {
	people := gateM10InPeopleItems()
	items := []*GateItem{people[0]}
	items = append(items, &GateItem{
		Item:     "EvsCommit.tla with the purger and IndexRollup.tla passing TLC at their bounds, their mutants refused and their liveness held, by the runs sidecartest/model/modelled.yml records at these sources, EvsCommit's stories, the purger's, among them (§22.10's M10 entry; D-PHASE-7, R-TEST-10; TEST-M2-08, EVSB-M10-07, SEARCH-M10-02); where none stands, open: this report runs no TLC itself; the drop extension's pass is M10's exit's, though its twins and stories are recorded in the same runs",
		Commands: []*GateCommand{{Repo: "sidecar", Command: gateM10InTlcCommand()}},
	})
	for _, testCase := range GateM10InCases(catalog) {
		items = append(items, &GateItem{
			Item:     testCase.String() + " written as a test against the fakes (§22.10's M10 entry)",
			Commands: []*GateCommand{{Repo: "sidecar", Command: gateM10InWrittenCommand(testCase)}},
		})
	}
	items = append(items, gateM10InVectorItems()...)
	return append(items, people[1], people[2])
}

var gateM10InSweep = RegisterGateSweep(&GateSweep{Gate: "M10-in", Items: gateM10InItems(DefaultCatalog())})
