// M2's exit review (TEST-M2-19; §23.6's M2 row, §22.10's right column for M2, §23.8's Gn-out; D-TEST-9, D-TEST-11,
// R-TEST-5, R-TEST-6, R-TEST-7, R-PHASE-11): the largest gate, which `sidecar-gate M2` reports row by row and item by
// item, pass, fail, missing or open. It adds no mechanism: each row runs the tests its owners wrote, and a failure or
// a missing test goes back to the task that owns the mechanism and stays in the report until fixed.
//
// The rows are catalog.yml's M2-out cases, each run by convention (gate.go), whose T3 entry carries
// sidecar_localstack (QD-1085), but where its T3 tests run in server's evshost, which drives the evs block on the
// local stack's MinIO: FS-5's, which drives stock git through evsgit's world and has no builder (owner decision 548,
// QD-995), and FS-1's, FS-2's, FS-3's, FS-4's, FS-6's, FS-7's, FS-12's, FS-53's, FS-57's, FS-58's, FS-60's, FS-62's,
// FS-63's and FS-113's, each the convention's TestFs<n>OnT3 run through sidecart3.RunRow, and FS-10's twin by its real
// name, TestFs10TwinOnT3 (QD-1081). FS-44's, FS-45's and FS-47's T3 runs are server's quotahost's own tests, on
// NewLocalQuota's parts over the private stack's Postgres and Redis: QUOTA's hand copies of the schedules their
// registered builders run on T2, not those builders, so no explorer seed or lost answer reaches them there; their T2
// tests are the convention's (QD-1084). A case run on both tiers keeps its convention T2 test, and no test moves. Each case's
// registered clauses run with it by the convention (QD-1084), on T3 where each clause names its package: FS-1's, FS-4's,
// FS-6's, FS-10's rollback twin, FS-57's, FS-58's, FS-60's and FS-62's lease holder in evshost, FS-6's --now shred under a
// hold in model, and FS-62's ACL gate in sidecart3.
//
// If a named test is renamed or its tags drift, its row reads missing, never pass, and server's
// TestGateSweepsNameServerTestsDeclaredUnderTheirTags fails first. Every other case keeps the convention, so a case
// nobody registered a builder for reads missing, whatever clause tests of it exist: no gate can tell those from a
// schedule run under §22.8's rules, and a clause counts only beside a registered case.
//
// Beside the rows, the items: §22.8's rules on every row, the FI oracles the rows name, the store clock, Porcupine,
// §22.7's privacy assertions and leak leg, the schema guard, the CROSSSLOT lints, the three ledgers (budgets.yml,
// targets.yml, peers.yml), format 1's erasure and deposit bytes, the X-Wing KATs, §10.6's sizes, the format vectors
// with the wrap paths and wrap_aad, the fuzz seeds, TLC on both models, the ledger's named gaps in FS-14 and FS-17,
// §22.7's admission suite, and what waits on hardware: the nvme run (D-TEST-11) and the twenty-agent hour. FS-55
// and FS-54 ride along as every Gn-out's, which the tool adds.
//
// MLS is Later (owner decision 610; QD-1040, 2026-11-17): the MLS interop freeze, §22.10's 0x0010 artifact, with the
// mlswg vectors under 0x0001 and owner decision 43's differential runs, and the MLS legs of FS-15, FS-20, FS-24 and
// FS-104 leave the gates, so this sweep names none of the first, and reads the second open in an item of its own
// until KEYS reworks those rows onto deliveries. R2's resync half (the ledger's T2-23) is an epoch retention case,
// and v0 keeps no epochs or acks, so it went with MLS and no test of it is here. §22.10's table, §23.6's M2 row,
// §23.8's freezes and D-KEYS-10 still name the interop at M2's exit until design-records folds owner decision 610
// into them; the decision governs.

package fault

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The catalog's name for M2's exit.
const gateM2OutGate = "M2-out"

// The module path a privacy assertion's package names, by its repo, so a gate entry can name the package from the
// module's root.
var gateModulePaths = map[string]string{
	"sidecar": "github.com/urnetwork/sidecar",
	"server":  "github.com/urnetwork/server",
}

// A case's tests with its T3 run named where it is: the convention's T2 test kept, and the convention's T3 entry
// replaced by names in server's packagePath under the convention's tags. names empty takes the convention's T3
// name.
func gateCaseT3Elsewhere(testCase *Case, packagePath string, names ...string) []*GateTest {
	if len(names) == 0 {
		names = []string{GateT3TestName(testCase)}
	}
	tests := []*GateTest{}
	for _, test := range gateConventionalTests(testCase) {
		if test.Repo == "server" {
			test = &GateTest{Repo: "server", Package: packagePath, Tags: gateT3Tags, Stores: true, Names: names}
		}
		tests = append(tests, test)
	}
	return tests
}

// Where M2's cases run their T3 tests outside the convention: see the file header. A case the catalog does not hold
// panics, as its sweep's registration would.
func gateM2Cases(catalog *Catalog) map[string][]*GateTest {
	places := []struct {
		rowId       string
		caseName    string
		packagePath string
		names       []string
	}{
		{rowId: "FS-1", packagePath: "./evshost"},
		{rowId: "FS-2", packagePath: "./evshost"},
		{rowId: "FS-3", packagePath: "./evshost"},
		{rowId: "FS-4", packagePath: "./evshost"},
		{rowId: "FS-5", packagePath: "./evshost"},
		{rowId: "FS-6", packagePath: "./evshost"},
		{rowId: "FS-7", packagePath: "./evshost"},
		{rowId: "FS-10", packagePath: "./evshost", names: []string{"TestFs10TwinOnT3"}},
		{rowId: "FS-12", packagePath: "./evshost"},
		{rowId: "FS-44", packagePath: "./quotahost", names: []string{"TestFs44T3Producer", "TestFs44T3LeaseRows"}},
		{rowId: "FS-45", packagePath: "./quotahost", names: []string{"TestFs45T3RelayedPairs"}},
		{rowId: "FS-47", packagePath: "./quotahost", names: []string{"TestFs47T3QuotaClauses"}},
		{rowId: "FS-53", packagePath: "./evshost"},
		{rowId: "FS-57", packagePath: "./evshost"},
		{rowId: "FS-58", packagePath: "./evshost"},
		{rowId: "FS-60", packagePath: "./evshost"},
		{rowId: "FS-62", packagePath: "./evshost"},
		{rowId: "FS-63", packagePath: "./evshost"},
		{rowId: "FS-113", packagePath: "./evshost"},
	}
	cases := map[string][]*GateTest{}
	for _, place := range places {
		testCase := catalog.Case(place.rowId, place.caseName)
		if testCase == nil {
			panic(fmt.Sprintf("M2's sweep names %s %q, which the catalog does not hold", place.rowId, place.caseName))
		}
		cases[testCase.String()] = gateCaseT3Elsewhere(testCase, place.packagePath, place.names...)
	}
	return cases
}

// The rows catalog.yml puts on §22.8's unknown list among the catalog gate's cases, each once, in row order.
func gateUnknownRows(catalog *Catalog, gate string) []string {
	rowIds := []string{}
	for _, testCase := range catalog.GateCases(gate) {
		if testCase.Row.Unknown && !slices.Contains(rowIds, testCase.Row.Id) {
			rowIds = append(rowIds, testCase.Row.Id)
		}
	}
	return rowIds
}

// The cases catalog.yml flags store_clock among the catalog gate's, in row order.
func gateStoreClockCases(catalog *Catalog, gate string) []string {
	names := []string{}
	for _, testCase := range catalog.GateCases(gate) {
		if testCase.StoreClock {
			names = append(names, testCase.String())
		}
	}
	return names
}

// The item that says which of §22.8's rules every row of the catalog's gate runs under: the seeds on each tier, the
// unknown list and the twins. Its tests hold the rules to what the item says.
func gateRulesItem(catalog *Catalog, gate string) *GateItem {
	unknown := gateUnknownRows(catalog, gate)
	unknownText := "none at this gate"
	if 0 < len(unknown) {
		unknownText = strings.Join(unknown, ", ")
	}
	return &GateItem{
		Item: fmt.Sprintf("§22.8's rules on every row: on T2 each case's fixed schedule, its twin where it refuses, %d explorer seeds over both, every write's lost answer for the unknown list (%s) and each committed trace; on T3 the same with the nightly form's %d seeds, a forged case's twin among them; each row's FI checks after every step and at the end",
			len(MergeSeeds()), unknownText, len(NightlySeeds())),
		Tests: []*GateTest{
			{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{"TestGateRunsItsRowsUnderSection228sRules"}},
			{Repo: "server", Package: "./sidecart3", Names: []string{"TestGateT3RunsTheNightlySeeds"}},
		},
	}
}

// The flag an invariants item's command passes, naming the catalog's gate whose rows' FI checks it reads.
const GateInvariantsFlag = "fault.gate-invariants"

// The command an invariants item runs in the sidecar repo.
func gateInvariantsCommand(gate string) []string {
	return []string{"go", "test", "-count=1", "-v", "-tags", "sidecar_testhooks", "-run", "^TestGateInvariantsBound$", "./sidecartest/fault", "-" + GateInvariantsFlag + "=" + gate}
}

// The item that says every FI a row of the catalog's gate checks answers through a bound oracle.
func gateInvariantsItem(gate string) *GateItem {
	return &GateItem{
		Item:     "every FI the rows check answers through its oracle, bound with fault.RegisterInvariant, so no row's check fails as unbuilt (§22.8's oracle rule; TEST.md's FI table)",
		Commands: []*GateCommand{{Repo: "sidecar", Command: gateInvariantsCommand(gate)}},
	}
}

// Whether every FI the cases at the catalog's gate check is bound, as the invariants item reports it: pass when each
// is; missing naming each FI no oracle binds yet, with its oracle's task and the cases that check it, since a
// schedule naming one fails as unbuilt when it runs; missing too for a gate whose cases check none. bound is FI's
// binding but in a fixture; nil reads this package's bindings.
func GateInvariantsBound(catalog *Catalog, gate string, bound func(n int) bool) (string, string) {
	if bound == nil {
		bound = invariantBound
	}
	numberCases := map[int][]string{}
	numbers := []int{}
	for _, testCase := range catalog.GateCases(gate) {
		for _, check := range testCase.Row.Checks {
			match := catalogInvariantCheckPattern.FindStringSubmatch(check)
			if match == nil {
				continue
			}
			n, err := strconv.Atoi(match[1])
			if err != nil {
				continue
			}
			if !slices.Contains(numbers, n) {
				numbers = append(numbers, n)
			}
			if !slices.Contains(numberCases[n], testCase.String()) {
				numberCases[n] = append(numberCases[n], testCase.String())
			}
		}
	}
	slices.Sort(numbers)
	if len(numbers) == 0 {
		return GateOutcomeMissing, fmt.Sprintf("no case at %s checks an FI", gate)
	}
	unbound := []string{}
	boundIds := []string{}
	for _, n := range numbers {
		invariant := catalog.Invariant(n)
		switch {
		case invariant == nil:
			unbound = append(unbound, fmt.Sprintf("FI-%d, which §22.8 does not hold", n))
		case bound(n):
			boundIds = append(boundIds, invariant.Id)
		default:
			unbound = append(unbound, fmt.Sprintf("%s (%s's oracle; %s)", invariant.Id, invariant.Oracle, strings.Join(numberCases[n], ", ")))
		}
	}
	if 0 < len(unbound) {
		return GateOutcomeMissing, fmt.Sprintf("no oracle binds %s yet, so each case naming it fails as unbuilt; bound: %s", strings.Join(unbound, "; "), strings.Join(boundIds, ", "))
	}
	return GateOutcomePass, fmt.Sprintf("every FI the cases at %s check is bound: %s", gate, strings.Join(boundIds, ", "))
}

// Whether FI-n has a check bound.
func invariantBound(n int) bool {
	invariantLock.Lock()
	defer invariantLock.Unlock()
	_, ok := invariantChecks[n]
	return ok
}

// A test §22.7's assert registry names, as a gate entry names it: its package from its module's root, a server one
// on the private stores.
func gatePrivacyAssertTest(test *sidecartest.PrivacyAssertTest) (*GateTest, error) {
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

// One item per §22.7 assert row that must pass at the catalog's gate, each with the tests registered to it, in the
// design's order: a row nothing is registered to has none and reads missing (PrivacyAsserts.Missing), which is never
// pass. A registration naming a package no entry can reach is said in the item's text and run as nothing.
func gatePrivacyItems(asserts *sidecartest.PrivacyAsserts, gate string) []*GateItem {
	items := []*GateItem{}
	for _, row := range asserts.Rows() {
		if !slices.Contains(row.Gates, gate) {
			continue
		}
		item := &GateItem{Item: fmt.Sprintf("§22.7's %s assertion (%s): %s", row.Id, strings.Join(row.Owners, ", "), row.Opening)}
		errs := []error{}
		for _, test := range asserts.Tests(row.Id) {
			gateTest, err := gatePrivacyAssertTest(test)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			item.Tests = append(item.Tests, gateTest)
		}
		if err := errors.Join(errs...); err != nil {
			item.Item += fmt.Sprintf("; registrations no entry reaches: %v", err)
		}
		items = append(items, item)
	}
	return items
}

// The clock's own control tests and the catalog cases whose named T3 runs must separately show translation.
func gateStoreClockItem(catalog *Catalog, gate string) *GateItem {
	cases := gateStoreClockCases(catalog, gate)
	casesText := "The catalog flags no case at this gate."
	if 0 < len(cases) {
		casesText = "The named T3 tests for " + strings.Join(cases, ", ") + " each require their own observed translation."
	}
	return &GateItem{
		Item: "T3's store clock controls (QD-264, TEST-M2-07) check that LastModified and Redis expiries use schedule time and that FS-114 never does. " + casesText,
		Tests: []*GateTest{
			{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{"TestT3StoreClockReadsAgesOnTheScheduleClock", "TestT3AnAdvancePassesATtl", "TestT3EachNetHasItsOwnStoreClock"}},
			{Repo: "server", Package: "./sidecart3", Names: []string{"TestFs114RefusesTheStoreClock"}},
		},
	}
}

// The item TLC's runs at the two M2 models show, as M2's entry reads them (gate_m2_in.go): pass where the runs
// modelled.yml records stand at these sources, open where TLC has not run there, since this report runs none.
func gateTlcItem() *GateItem {
	return &GateItem{
		Item:     "TLC passes EvsCommit.tla and StoreSettle.tla at their bounds, their mutants refused and their liveness held, by the runs sidecartest/model/modelled.yml records at these sources (§22.10's M2 exit; TEST-M2-08, EVS1-M2-02); where none stands, open: this report runs no TLC itself",
		Commands: []*GateCommand{{Repo: "sidecar", Command: gateTlcCommand()}},
	}
}

// Every item of M2's exit in §22.10's order, then what waits on the world.
func gateM2OutItems(catalog *Catalog) []*GateItem {
	items := []*GateItem{
		gateRulesItem(catalog, gateM2OutGate),
		gateInvariantsItem(gateM2OutGate),
		gateStoreClockItem(catalog, gateM2OutGate),
		{
			Item: "Porcupine passes T3's histories with unknown outcomes, per ref, under §11.8's commit rule (§22.10's M2 exit; TEST-M2-02)",
			Tests: []*GateTest{
				{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{"TestFs1HistoriesLinearizeOnT3", "TestFs58HistoriesLinearizeOnT3"}},
				{Repo: "server", Package: "./sidecart3", Tags: "sidecar_testhooks", Names: []string{"TestFs1HistoriesLinearizeOnT2", "TestFs58HistoriesLinearizeOnT2", "TestFs1HistoryMutantsFailOnT2"}},
				{Repo: "server", Package: "./sidecart3", Names: []string{
					"TestCheckLinearizablePassesAnUnknownOutcomeThatCommitted", "TestCheckLinearizablePassesAnUnknownOutcomeThatDidNot",
					"TestCheckLinearizableRefusesAHistoryWithNoUnknownOutcome", "TestCheckLinearizableFailsALostUpdate", "TestCheckLinearizableFailsADoubleCommit",
				}},
			},
		},
	}
	items = append(items, gatePrivacyItems(sidecartest.DefaultPrivacyAsserts(), gateM2OutGate)...)
	items = append(items,
		&GateItem{
			Item: "§22.7's leak leg: a sidecar_leaktest build leaks into every class the scan covers, and the scan catches each, on T2 and on T3's stores (TEST-M2-09)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_leaktest", Names: []string{"TestEveryClassCatchesItsLeak", "TestAClassWithNoLeakFails", "TestRemovingAFormFromTheScannerFailsTheSelfTest"}},
				{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags + ",sidecar_leaktest", Stores: true, Names: []string{"TestT3EveryStoreClassCatchesItsLeak"}},
			},
		},
		&GateItem{
			Item: "servers get only §2.8's evs and gkm fields: the schema guard over every proto field, object family and Redis family, and metadata_list.yml as §2.8's block (§23.6's M2 exit; I-18; TEST-M2-10)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestSchemaGuard", "TestSchemaGuardPassesACleanTree", "TestSchemaGuardFailsOnAProtoFieldNoRowNames", "TestSchemaGuardFailsOnANewObjectFamily", "TestSchemaGuardFailsOnANewRedisFamily", "TestCheckStoresReadsTheRealList"}},
				{Repo: "sidecar", Package: "./check", Tags: "sidecar_check", Names: []string{"TestSchemaGuard", "TestMetadataListIsSection2sBlock", "TestMetadataListRefusesAHandEdit"}},
			},
		},
		&GateItem{
			Item: "the CROSSSLOT lints: every script and multi-key call keeps its keys in one slot, read from the code and from T3's engines' calls (§22.4)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/crossslot", Names: []string{"TestThisModuleKeepsTheRule", "TestTheModuleWalkReachesTheCodeItGuards", "TestPlantedCallsReadAsTheirNamesSay"}},
				{Repo: "server", Package: "./sidecart3", Names: []string{"TestCrossslotKeysSpreadOverTheMasters", "TestCrossslotCallsKeepEachShapeOnce"}},
				// the lint's refusal of one node runs in server's test env, on the private stores
				{Repo: "server", Package: "./sidecart3", Stores: true, Names: []string{"TestRunCrossslotRefusesOneNode"}},
			},
		},
		&GateItem{
			Item: "budgets.yml: §22.5's hot-path gates and §22.9's budgets, a raise only with a reviewed line, the inline paths run with no Postgres and op-counted Redis (D-TEST-3; TEST-M1-09)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./check", Tags: "sidecar_check", Names: []string{"TestBudgetsRiseOnlyWithAReviewedLine", "TestBudgetSizeRowsHoldTheSizeGatesNumbers", "TestBudgetBenchmarksHoldTheirAllocations"}},
				{Repo: "server", Package: "./sidecart3", Stores: true, Names: []string{"TestEveryPathRowResolvesOrReadsMissing", "TestInlinePathFailsAPlantedPostgresRead", "TestInlinePathFailsOneRedisCallOverItsRow"}},
			},
		},
		&GateItem{
			Item: "targets.yml: R-TEST-7's numbers, §11.15's targets among them, each with the test that shows it, the tier it runs on and its owner, a number nothing verified reading open (D-TEST-7; TEST-M2-13)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestTargetLedgerRowsResolveOrReadOpen", "TestTargetLedgerResolvesTestsByName"}},
			},
			External: "hardware and production: the targets T5's performance host and production show, which this host does not run (targets.yml's tier column)",
		},
		&GateItem{
			Item: "peers.yml: every §22.9 conformance peer pinned, rerun on each pin change, a peer this host lacks reading open (D-TEST-7; TEST-M2-17)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./check", Tags: "sidecar_check", Names: []string{"TestConformanceLedger"}},
			},
		},
		&GateItem{
			Item: "format 1's erasure and deposit bytes freeze on §22.5's §11 cases, beside FS-23's and FS-47's rows: an erasure leaves no prior version, openable body, deposit or decrypted copy, chains verifying, and a restarted ingest recreates no erased entry (§22.10; §23.8's freezes)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{"TestEvsErasureNoteLayout", "TestEvsClosureRefusesNoErasure", "TestEvsSlotErasureTakesARecordRowsWholeBlock", "TestEraseLeavesNoDecryptedCopy", "TestRecordIngestRecreatesNoErasedEntry", "TestEvsDepositKeyFromGenRotateBytes", "TestMailIngestErasedDepositConsumesWithNoMessage"}},
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestEvsEraseADeposit", "TestEvsDepositIngestAndConsume", "TestEvsEraseOfASlotKeyedVersionlessPathLeavesNoVersionEndToEnd", "TestEvsSlotKeyedPushInPartsLeavesAnErasedKeyNowhere", "TestEvsMirrorAppliesAnErasureBeforeTheNextSync"}},
				{Repo: "sidecar", Package: "./evsservice", Names: []string{"TestEraseLeavesNoCopyOfItsKeyInAPushInPartsRecords"}},
			},
		},
		&GateItem{
			Item: "X-Wing KATs: the draft's Appendix C and the hpke-pq draft's vectors through crypto/hpke's MLKEM768X25519, DeriveKeyPair included, the KEM every ReaderKey and KeyDelivery wrap seals under (§22.10's M2 exit; §10.4's kem row)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{"TestXWingKatKeyGeneration", "TestXWingKatDerandomizedEncapsulation", "TestXWingKatEncapsulationThroughHpke", "TestXWingKatDecapsulationThroughHpke", "TestXWingDeriveKeyPairMatchesHpkePq", "TestXWingHpkePqVectorBaseMode", "TestXWingRefusesBadCiphertexts", "TestXWingRefusesBadKeys"}},
				{Repo: "sidecar", Dir: "mlsinterop", Package: ".", Names: []string{"TestXWingHpkePqVectorsThroughCryptoHpke"}},
			},
		},
		&GateItem{
			Item: "§10.6's sizes measured (D-KEYS-10): the size table's 10-leaf column and per-object rows on the real ladder at reduced scale, its MLS rows counting toward nothing while MLS is Later (owner decision 610)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{"TestMlsSizesHoldSection106sTable"}},
				{Repo: "sidecar", Package: "./gkmservice", Names: []string{"TestGkmDelegationKeyByteCountIsXWings"}},
			},
		},
		&GateItem{
			Item: "the format vectors in testdata/, byte for byte, the wrap paths and wrap_aad among them, KeyDelivery's wrap_aad also written apart in mlsinterop's own code (§22.10's M2 exit; D-KEYS-10's delivery wire)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{
					"TestGkmWrapPathVectors", "TestGkmWrapAadVectors", "TestGkmLadderVectors", "TestEvsChainVectors", "TestEvsDigestVectors", "TestEvsTokenVectors",
					"TestEvsBatchVectors", "TestEvsWindowVectors", "TestEvsPushVectors", "TestEvsRecordVectors", "TestEvsSegmentVectors", "TestAuthChainVectors",
				}},
				{Repo: "sidecar", Package: "./protocol/bridge", Names: []string{"TestSignedVectorsAreByteEqual", "TestAuthEntryVectorsAreByteEqual"}},
				{Repo: "sidecar", Dir: "mlsinterop", Package: ".", Names: []string{"TestLadderWrapAadMatchesMls"}},
			},
		},
		&GateItem{
			Item: "the fuzz seeds: every §22.6 target registered with its seeds, each target's seeds run as ordinary tests under test.sh (§22.10's M2 exit; R-TEST-5; TEST-M1-10)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./check", Tags: "sidecar_check", Names: []string{"TestFuzzRegistry", "TestFuzzSeedsRunUnderTestSh"}},
			},
		},
		gateTlcItem(),
		&GateItem{
			Item: "the ledger's named gaps in this area ran (HANDOFF §10): FS-14's RepoRevoke, OwnerConfirm and rotation covering one of two same-base removals (ACL-M2-16), and FS-17's two peers advancing independently with no conflict (PROTO-M2-02)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{"TestFs14AclRepoRevoke", "TestFs14AclOwnerConfirm", "TestFs14AclTwoRemovals", "TestFs17CatchUpRefreshesAndStaleDoesNot"}},
			},
		},
		&GateItem{
			Item: "§22.7's admission suite, consent and the recovery veto included, on T2 and T3 (§23.6's M2 exit; TEAM-M2-19)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{
					"TestAdmissionSigners", "TestAdmissionOutsideTheAdminSet", "TestAdmissionRecoveryWindow", "TestAdmissionTwoFirstDevicesRacing", "TestAdmissionOwnerConsent",
					"TestAdmissionCommitters", "TestAdmissionSeats", "TestAdmissionAgentsCostNoCommit", "TestAdmissionReadOnlyPageWorkers", "TestAdmissionCompromiseCascade", "TestAdmissionAuthKeys",
				}},
				{Repo: "server", Package: "./api", Tags: gateT3Tags, Stores: true, Names: []string{
					"TestAdmissionSignersOnT3", "TestAdmissionOutsideTheAdminSetOnT3", "TestAdmissionRecoveryWindowOnT3", "TestAdmissionTwoFirstDevicesRacingOnT3", "TestAdmissionOwnerConsentOnT3",
					"TestAdmissionCommittersOnT3", "TestAdmissionSeatsOnT3", "TestAdmissionAgentsCostNoCommitOnT3", "TestAdmissionReadOnlyPageWorkersOnT3", "TestAdmissionCompromiseCascadeOnT3", "TestAdmissionAuthKeysOnT3",
				}},
			},
		},
		&GateItem{
			Item: "the nvme run (D-TEST-11; R-PHASE-11): at 2x year one's mix with the write budget refilled at 0.8 DWPD, no push refused, at most 43 KiB written per push per drive and 50% of rated write IOPS on the PM9A3 set, on the block size it chooses, its costs becoming §11.13's price table; the benchmark tool refuses a run that is no smoke without FS-116 first and exits by the gate",
			Tests: []*GateTest{
				{Repo: "server", Package: "./cli/filecluster-bench", Names: []string{"TestFs116ModeRecordsWhatPassedOnTheCommitSet", "TestRunsThatAreNotSmokesRefuseToStartWithoutFs116", "TestReportModeExitsByTheGate"}},
			},
			External: "hardware: the production hosts' PM9A3 staging set, before M2's exit; a run on this host is a smoke, which is no evidence",
		},
		&GateItem{
			Item:     "twenty agents push for an hour, the test published (R-TEST-7; §23.6's M2 exit)",
			External: "hardware: the twenty-agent hour on T5's performance host; a run on this host is a smoke, which is no evidence",
		},
		&GateItem{
			Item:     "the MLS legs of FS-15, FS-20, FS-24 and FS-104 left the gates with MLS (owner decision 610; QD-1040), as did the 0x0010 interop, the mlswg vectors, the differential runs and R2's epoch resync: until KEYS reworks those rows onto deliveries their drafted schedules still run, so a pass there counts only their delivery legs",
			External: "people: the review phase's rework of FS-15, FS-20, FS-24 and FS-104 onto deliveries (KF1-KF7), and design-records' fold of owner decision 610 into §22.8, §22.10, §23.6 and D-KEYS-10",
		},
	)
	return items
}

var gateM2Sweep = RegisterGateSweep(&GateSweep{
	Gate:  "M2",
	Cases: gateM2Cases(DefaultCatalog()),
	Items: gateM2OutItems(DefaultCatalog()),
})
