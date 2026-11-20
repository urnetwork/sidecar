// M10's entry review (TEST-M10-04; §22.10's left column for format 2, §23.8's Gn-in, §23.6's M10 row; D-TEST-9,
// D-PHASE-7, R-TEST-10): what freezes format 2's specification, the DROP payload and directory.proto's cards with it,
// and search.proto (§23.8's M10 row), each item with what shows it, so `sidecar-gate M10-in` reports each pass, fail,
// missing or open. It reads as M2's entry does (gate_m2_in.go):
//
//   - peer review of format 2's schemas: people's work, open.
//   - EvsCommit.tla with the purger and IndexRollup.tla passing TLC: TEST-M2-08's tests of both models in gate mode at
//     M10's entry, which let a model's recorded runs stand while nothing it keeps has changed; the report runs no TLC
//     of its own. Each test takes the modes M10's entry needs of its model from modelled.yml's milestones: EvsCommit's
//     model, mutants and live, and its purger's mutants and stories, which run-tlc.sh runs and modelled.yml records
//     as modes of their own (QD-1116), and IndexRollup's model, mutants and live. A test passes only where every mode
//     its model needs here stands at its sources, so the purger's stories never stand on the other modes' runs. Where
//     one does not stand the item reads open and says TLC has not run, never pass.
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
// waits on it, and nothing here reads fail or open for want of it: its mutants, stories and liveness are modes of their
// own, which modelled.yml's milestones name only from M10's exit (QD-1116, QD-1119), so at M10's entry no test needs
// them and the TLC item runs none of the drop extension's tests.
//
// No item here is an external audit (R-TEST-6; owner decisions 99, 119). Each command's last line says its outcome,
// as server's gate tool reads it (GateOutcomeLinePrefix): the written check and the TLC check run as tests of this
// package, under flags of gate_m10_in_test.go that only the commands pass.

package fault

import (
	"context"
	"fmt"
	"slices"
	"strings"
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

// TEST-M2-08's tests of EvsCommit and IndexRollup, in gate mode at M10's entry: EvsCommit's model, mutants and live,
// its purger's mutants and stories, and IndexRollup's model, mutants and live. The drop extension's tests,
// TestEvsCommitDropMutantsFailTlc, TestEvsCommitDropStoriesPassTlc and TestEvsCommitDropLivenessHolds, are M10's
// exit's.
var gateM10InTlcTests = []string{
	"TestEvsCommitPassesTlcAtItsBounds",
	"TestEvsCommitMutantsFailTlc",
	"TestEvsCommitLivenessHolds",
	"TestEvsCommitPurgerMutantsFailTlc",
	"TestEvsCommitPurgerStoriesPassTlc",
	"TestIndexRollupPassesTlcAtItsBounds",
	"TestIndexRollupMutantsFailTlc",
	"TestIndexRollupLivenessHolds",
}

// The gate whose modes M10-in's TLC item asks TEST-M2-08's tests for (SIDECAR_TLC_GATE): M10's entry, whose
// milestones in modelled.yml name EvsCommit's purger and not its drop extension.
const gateM10InTlcGate = "M10-in"

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

// What M10-in's TLC item reports from TEST-M2-08's tests of EvsCommit and IndexRollup, run together in gate mode at
// M10's entry with no TLC, by their go test -v output and whether that run failed, as GateTlcOutcome reads them: pass
// when each passed, every mode M10's entry needs of its model standing at its sources, the purger's mutants and
// stories among EvsCommit's; open, saying so, when any failed only because TLC has not run there, the purger's stories
// test failing so where no stories-purge run stands; fail for any other failure or a test that gave no verdict. The
// tests read modelled.yml themselves, and none of the drop extension's runs: its pass is M10's exit's.
func GateM10InTlcOutcome(output []byte, runErr error) (string, string) {
	return GateTlcOutcome(output, runErr, gateM10InTlcTests)
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
		Item:     "EvsCommit.tla with the purger and IndexRollup.tla passing TLC at their bounds, their mutants refused and their liveness held, by the runs sidecartest/model/modelled.yml records at these sources of each mode M10's entry needs, the purger's mutants and stories, modes of their own, among them (§22.10's M10 entry; D-PHASE-7, R-TEST-10; TEST-M2-08, EVSB-M10-07, SEARCH-M10-02; QD-1116); where one does not stand, open: this report runs no TLC itself; the drop extension's pass is M10's exit's, whose modes are recorded apart",
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
