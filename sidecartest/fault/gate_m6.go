// M6's gates (TEST-M6-02; §23.6's M6 row, §23.8's freezes, §22.10's directory.proto row; D-TEST-9, D-TEST-17,
// D-PHASE-6, D-PHASE-7, FI-25, FI-26): the sweeps `sidecar-gate M6-in` and `sidecar-gate M6` report. M6's entry is the
// one Gn-in that runs code: FS-46 and §20.9's benchmark on M4's dark build, which freeze the escrow order. Like M2's
// and M3's (gate_m2_out.go, gate_m3.go) the sweeps add no mechanism: each row runs the tests its owners wrote, and a
// failure or a missing test goes back to the task that owns it.
//
// The rows are catalog.yml's M6-in and M6-out cases by convention but where their tests run elsewhere, by three rules:
//
//   - A case with a registered schedule whose thin test carries another name than the convention's is named by that
//     test: RECORD's directory rows end in M6 (TestFs84M6 and its like), and BRIDGE's shares case is TestFs38Share. A
//     case whose T3 run is in another server package is named there with that package's tags (QD-1081): server/api's
//     FS-19 Team and invite, FS-21, FS-97 and FS-124 Team runs, and server/controller's FS-38 shares run. A T2+T3 case
//     keeps its T2 test, and no test moves.
//   - A case with no schedule, whose owners wrote tests named for the row, is named by those tests where they run:
//     FS-30's audit reader, FS-32, FS-35, FS-46 and FS-122, and FS-41's and FS-42's M6 steps, each step by its owner's
//     test on that step's own fixture, as M3's sweep names the rows' M3 clauses. These run their own fixed orders, never
//     an explorer's seeds, which the rules item does not say of them.
//   - A tier the catalog names for a case and no owner's test runs keeps the convention's entry, which nothing has
//     written, so the row reads missing, never pass on the other tier's evidence (FS-126's rule, QD-1008): the T3 runs
//     of FS-85, FS-86, FS-87, FS-99 and FS-100's M6 cases, and FS-98's Team case, whose server tests run on server's
//     sequencer alone and under another name; and the T2 runs of FS-43 and FS-51, which the catalog puts on T2, FS-43
//     under every write's lost answer, and whose owners wrote them on server's rows in fixed orders. What is written of
//     those rows runs in items, apart from the rows: FS-43's and FS-51's tests on Postgres, and FS-99's evs scope's
//     mutant in server's root package. FS-85's ACL legs and FS-99's evs scope are registered clauses (QD-1084), which
//     run with their rows on both tiers by the convention, on T3 in server's api and root package.
//
// Every other case keeps the convention, the card, index and team-record cases among them, which sit at the later of
// M6-out and M10-out and are TEST-M10-06's. DESIGN-DETAILS 16's prefix-rules rows are not here: the rules moved to
// Later (QD-1032) and TEST-M6-03 is held.
//
// FS-126's T2 run is sidecartest/p2p_test.go's (PROTO-M6-02): plain tests of package sidecartest, which the
// convention's TestFs126 in this package does not find, so the sweep names them where they run, as owner decision 548
// has the sweeps name FS-5's and FS-73's T3 tests in server's evshost. A case a sweep names runs only the tests the
// sweep lists, so its T3 test is listed too, under the convention's name in server's sidecart3, which nothing has
// written: server/connect's TestSidecarP2pT3StreamLaneOnlyWhenEnabled, PROTO-M6-02's T3 half, runs on the in-process
// exchange, which has no P2P carrier, so it moves no pair onto P2P and back and forges no ControlId frame over P2P, and
// it reads the pair's contracts bound to its stream, not a debit. Naming it would read the row passing on clauses no T3
// test shows, so the row reads missing until a T3 test of the schedule is named. Of the row's clauses, HeadCheck
// holding across each move is asserted by no test yet: p2p_test.go checks each side's view of the other's Hello.
//
// Beside the rows, at the exit: §22.8's rules and FI bindings, FI-25 and FI-26 as RECORD's worlds check them after every
// step, neither bound as an oracle yet, §22.10's directory.proto freeze, §22.7's assertions at M6 with S3b, S4b, S13 and
// the revocation suite's member form, Team billing under FS-46's order, §20.9's benchmark again, FS-86's day at the
// Team limit apart from every other failure (D-TEST-17), and what production and people owe. At the entry: the
// benchmark, directory.proto's specification, and D-PHASE-6's pilot measures, which read open.

package fault

import (
	"github.com/urnetwork/sidecar/sidecartest"
)

// The catalog's names for M6's entry and exit.
const (
	gateM6InGate  = "M6-in"
	gateM6OutGate = "M6-out"
)

// FS-126 on T2, as sidecartest/p2p_test.go runs it: off by default, the move to P2P and back under a live RPC and
// stream, and a ControlId frame forged over P2P dropped.
var gateFs126T2Test = &GateTest{
	Repo:    "sidecar",
	Package: "./sidecartest",
	Names:   []string{"TestP2pOffByDefault", "TestP2pPairMovesAndBackUnderALiveRpcAndStream", "TestP2pForgedControlIdStaysDroppedWithP2pOn"},
}

// FS-126 on T3, the convention's test under the convention's tags (QD-1085), which reads missing until it is written
// or a sweep names another.
var gateFs126T3Test = &GateTest{
	Repo:    "server",
	Package: "./sidecart3",
	Tags:    gateT3Tags,
	Stores:  true,
	Names:   []string{"TestFs126OnT3"},
}

// A case of the default catalog, which a sweep's file names: one the catalog does not hold panics, as the sweep's
// registration would.
func gateCaseOf(catalog *Catalog, rowId string, caseName string) *Case {
	testCase := catalog.Case(rowId, caseName)
	if testCase == nil {
		panic("a gate's sweep names " + rowId + " " + caseName + ", which the catalog does not hold")
	}
	return testCase
}

// Tests of this package under the hooks, where every schedule's thin test runs.
func gateFaultTests(names ...string) *GateTest {
	return &GateTest{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: names}
}

// Tests of a server package that build under sidecar_pending and run on the private stores.
func gatePendingTests(packagePath string, names ...string) *GateTest {
	return &GateTest{Repo: "server", Package: packagePath, Tags: "sidecar_pending", Stores: true, Names: names}
}

// The convention's entries of a case on T3, none for a case that does not run there: for a case whose T2 run a sweep
// names, so the row reads missing until its T3 test is written.
func gateConventionT3Tests(testCase *Case) []*GateTest {
	tests := []*GateTest{}
	for _, test := range gateConventionalTests(testCase) {
		if test.Repo == "server" {
			tests = append(tests, test)
		}
	}
	return tests
}

// A case's tests with its T2 run named by names in this package, and the convention's T3 entry kept.
func gateCaseT2Named(testCase *Case, names ...string) []*GateTest {
	return append([]*GateTest{gateFaultTests(names...)}, gateConventionT3Tests(testCase)...)
}

// Where M6's entry runs FS-46: the lease's draw order on T2's fakes, and the escrow order on Postgres.
func gateM6InCases(catalog *Catalog) map[string][]*GateTest {
	return map[string][]*GateTest{
		gateCaseOf(catalog, "FS-46", "").String(): {
			gateFaultTests("TestFs46LeaseTakesThePackFirstAndReturnsToTheLineFirst", "TestFs46KilledEdgeLeavesNoReservationAndNoDebit"),
			gatePendingTests("./model", "TestFs46EscrowOrder"),
		},
	}
}

// Where M6's cases run their tests outside the convention: see the file header.
func gateM6Cases(catalog *Catalog) map[string][]*GateTest {
	caseOf := func(rowId string, caseName string) *Case {
		return gateCaseOf(catalog, rowId, caseName)
	}
	cases := map[string][]*GateTest{"FS-126": {gateFs126T2Test, gateFs126T3Test}}

	// T3 runs in server's api, under the convention's names (QD-1081)
	for _, place := range []struct {
		rowId    string
		caseName string
		names    []string
	}{
		{rowId: "FS-19", caseName: "team"},
		{rowId: "FS-19", caseName: "invite"},
		{rowId: "FS-21", caseName: "team"},
		{rowId: "FS-97", caseName: "team", names: []string{"TestFs97TeamOnT3", "TestFs97TeamAdminSetMemberOnT3", "TestFs97TeamCleanupOnT3"}},
		{rowId: "FS-124", caseName: "team"},
	} {
		testCase := caseOf(place.rowId, place.caseName)
		cases[testCase.String()] = gateCaseT3Elsewhere(testCase, "./api", place.names...)
	}

	// BRIDGE's shares case, its thin test's own name on T2 and server's controller on T3
	cases[caseOf("FS-38", "shares").String()] = []*GateTest{
		gateFaultTests("TestFs38Share"),
		{Repo: "server", Package: "./controller", Tags: gateT3Tags, Stores: true, Names: []string{"TestFs38ShareOnT3"}},
	}

	// RECORD's directory rows at M6, each by its thin test's own name
	for _, place := range []struct {
		rowId    string
		caseName string
		names    []string
	}{
		{rowId: "FS-84", caseName: "entries", names: []string{"TestFs84M6"}},
		{rowId: "FS-85", names: []string{"TestFs85M6"}},
		{rowId: "FS-86", caseName: "announce-entries", names: []string{"TestFs86M6"}},
		{rowId: "FS-87", names: []string{"TestFs87M6"}},
		{rowId: "FS-88", names: []string{"TestFs88M6"}},
		{rowId: "FS-99", caseName: "entries", names: []string{"TestFs99M6"}},
		{rowId: "FS-101", caseName: "entries", names: []string{"TestFs101M6"}},
	} {
		testCase := caseOf(place.rowId, place.caseName)
		cases[testCase.String()] = gateCaseT2Named(testCase, place.names...)
	}

	// rows with no schedule, by the tests their owners named for them
	cases[caseOf("FS-30", "audit").String()] = []*GateTest{
		{Repo: "sidecar", Package: ".", Names: []string{
			"TestAclAuditBlockCountsOnlyUnderAnOptIn", "TestAclAuditReaderReadsOnlyWhatTheBlockNames", "TestAclAuditOptInAndOutAreKOfN", "TestAclAuditLeavesAdminSharesRefused",
			"TestRecordAuditReaderFilesASecondReadToTheTeamRecord", "TestRecordAuditReaderRefusedWithoutTheTeamRecord",
			"TestTheAuditReaderGetsNoWrapBeforeItsBlockReachesEveryMembersConfig", "TestAMemberRefusesAWrapToAnAuditReaderItsListDoesNotShow", "TestAnAuditOptOutRotatesWithCauseRemove",
		}},
	}
	cases[caseOf("FS-32", "").String()] = []*GateTest{
		{Repo: "sidecar", Package: "./certsservice", Names: []string{
			"TestCertsCaaChecksRefuseAnAliasIntoAnOperatorZone", "TestCertsCaaChecksRefuseAWildcardAliasIntoAnOperatorZone", "TestCertsCaaChecksTellADelegatedChallengeFromADelegatedHost",
			"TestCertsCaaChecksRefuseAHostWithNoPin", "TestCertsCaaChecksAtSetupRefuseAFlatteningAliasAndPassAnAddressOnlyOne", "TestCertsCaaChecksAtRenewalExposeAFlatteningAliasAndKeepItMapped",
			"TestCertsCaaChecksPublishAgainOnStaleAndRestartTheWindow", "TestCertsCaaChecksFailOnACanaryInTheWalksSet", "TestCertsCaaChecksFailOnACachedCanaryInTheAnswers",
			"TestCertsCaaChecksReadCanaryFailingAsReady", "TestCertsCaaChecksFailOnACanaryRefusal", "TestCertsCaaChecksJudgeNothingWhileAServerNeverAnswers",
			"TestCertsCaaChecksWaitOutABusyOwner", "TestCertsCaaChecksApplyNothingToAHostThatWent",
		}},
	}
	cases[caseOf("FS-35", "").String()] = []*GateTest{
		gatePendingTests("./cli/tlsedge", "TestT3Fs35CustomHostThroughTheRealSplitter"),
	}
	cases[caseOf("FS-122", "").String()] = []*GateTest{
		gatePendingTests("./cli/tlsedge",
			"TestT3Fs122AnLbRestartedOnAnOldMapLoadsTheCurrentVersionFirst", "TestT3Fs122TheDnsApiDownAtStartLeavesTheSplitOnNoVersion",
			"TestT3Fs122AHostAddedWhileOneInterfaceIsDownStaysPendingNamingIt", "TestT3Fs122AMapNginxRefusesKeepsTheHostPending",
			"TestT3Fs122AnLbmapReportingAVersionItsNginxDidNotLoadStaysNotCurrent", "TestT3Fs122AMapThatDropsAnAddedHostFailsItsProbeUntilAReload",
			"TestT3Fs122ChangesInsideOneWindowLoadInOneReload",
		),
		{Repo: "server", Package: "./cli/tlsedge", Tags: "sidecar_pending,sidecar_testhooks", Stores: true, Names: []string{"TestT3Fs122TlsAlpnOrdersWaitForTheHostToBeReady"}},
	}

	// FS-41's and FS-42's M6 steps, meters and custom hosts, where their owners wrote each
	cases[caseOf("FS-41", "m6").String()] = []*GateTest{
		{Repo: "server", Package: "./cli/tlsedge", Tags: "sidecar_pending,sidecar_testhooks", Stores: true, Names: []string{"TestT3Fs41CustomHostListenersComeBackByTheirNextHeartbeat"}},
		gatePendingTests("./controller", "TestRecomputeStripeMeterReportsResendsWithoutDoubleBilling"),
	}
	cases[caseOf("FS-42", "m6").String()] = []*GateTest{
		gatePendingTests("./cli/tlsedge", "TestT3Fs42CustomHostsAfterTheDumpLeaveOrReturnToTheRestoredMap"),
		gatePendingTests("./model", "TestDnsRestoreRaisesTheCustomHostMapAndListsItsLoad"),
		gatePendingTests("./controller", "TestRecomputeStripeMeterReportsResendsWithoutDoubleBilling"),
		{Repo: "server", Package: "./sidecarrestore", Names: []string{"TestBillingStepRecomputesFromTheSidecarDumpAfterTheRowsStep", "TestBillingStepSkipsADatabaseBeforeMg6AndRefusesAnUnlinkedBinary"}},
	}
	return cases
}

// §20.9's benchmark as server's tests run it: the measurements on a database of the test's own, and the count of an
// added round trip, which is what the comparison would catch.
func gateEscrowBenchmarkTest() *GateTest {
	return gatePendingTests("./model", "TestEscrowBenchmarkMeasurements", "TestEscrowBenchmarkCountsAnAddedRoundTrip")
}

// What the benchmark waits on outside this tree.
const gateEscrowBenchmarkExternal = "production and people: the measurements on M4's dark build at twice the Y1 rates, compared against main's through server/cli/escrowbench on a host whose database is the benchmark's own"

// Every item of M6's entry: the escrow order's freeze, directory.proto's specification, and the pilot's measures.
func gateM6InItems() []*GateItem {
	return []*GateItem{
		{
			Item:     "§20.9's escrow benchmark on M4's dark build, with FS-46 above: the draw order costs admission and settlement nothing, which freezes the escrow order at M6's entry (§23.8; D-PHASE-7, owner decision 92, Q-QUOTA-3's residual; QUOTA-M4-03)",
			Tests:    []*GateTest{gateEscrowBenchmarkTest()},
			External: gateEscrowBenchmarkExternal,
		},
		{
			Item:     "directory.proto's specification freezes (§22.10's M6 row; §23.8's Gn-in): §16.11's announcement, request, decision, notice and erasure request messages reviewed and specified",
			External: "people: the owner's review of §16.11's messages at M6's entry",
		},
		{
			Item:     "the design-partner pilot's measures (D-PHASE-6; sidecar/design/pitch5.html:913-920), on which M6's entry review may re-plan the recURd track",
			External: "people and production: the pilot running since M3's exit, its measures read at the entry review",
		},
	}
}

// Every item of M6's exit: see the file header.
func gateM6OutItems(catalog *Catalog) []*GateItem {
	items := []*GateItem{
		gateRulesItem(catalog, gateM6OutGate),
		gateInvariantsItem(gateM6OutGate),
		{
			Item: "FI-25 and FI-26 as RECORD's rows check them (RECORD-M6-25, RECORD-M6-26; TEST.md's FI table), each in its own world after every step, since neither is bound with fault.RegisterInvariant and the item above reads both missing: FI-25 by the ledger of rights in FS-84's, FS-99's and FS-101's M6 cases, FI-26 by the directory world in FS-85's, FS-87's and FS-88's and by the wakes' world in FS-100's",
			Tests: []*GateTest{
				gateFaultTests("TestFs84M6", "TestFs99M6", "TestFs101M6", "TestFs85M6", "TestFs87M6", "TestFs88M6", "TestFs100Format1"),
			},
		},
		{
			Item: "directory.proto's bytes freeze (§22.10's M6 row; §23.8's Gn-out) on FS-84's, FS-85's, FS-87's, FS-88's, FS-100's and FS-101's M6 cases above: an announcement id, every path and a worker item as fixed vectors, repo entries padding alike, a notice of two decisions within its bound, and the decoder's fuzz seeds; its cards and repo files freeze with format 2 at M10",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{
					"TestDirectoryRepoAnnouncementIdVector", "TestDirectoryPathVectors", "TestDirectoryWorkerItemVector", "TestDirectoryPathsShardTheirOwnHex",
					"TestDirectoryRepoEntriesPadAlike", "TestDirectoryNoticeOfTwoDecisionsFitsItsByteCount", "FuzzDirectoryDecode",
				}},
			},
		},
	}
	items = append(items, gatePrivacyItems(sidecartest.DefaultPrivacyAsserts(), gateM6OutGate)...)
	if 0 < len(gateStoreClockCases(catalog, gateM6OutGate)) {
		items = append(items, gateStoreClockItem(catalog, gateM6OutGate))
	}
	items = append(items,
		&GateItem{
			Item: "S3b, S4b and S13 at M6 (§22.7; TEAM-M6-12, KEYS-M6-03, ACL-M6-05, RECORD-M6-26): a member's admission and removal with their key parts on T2 and T3, and the directory's scenario on T2",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{"TestScenarioS3b", "TestScenarioS4b", "TestS13AtM6"}},
				{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{"TestScenarioS3bOnT3", "TestScenarioS4bOnT3"}},
			},
		},
		&GateItem{
			Item: "§22.7's revocation suite in its member form (TEST-M6-01; D-TEST-6): an Admin's MemberRevoke and SCIM's active=false, TEAM's log clause in each, the keys check with evs's gate off, a removed member's tagged agents keeping their tags' grants with autogroup:sponsor resolving to autogroup:admin until a SponsorSet (owner decision 83), on T2 and T3; ACL's two schedules take no signer and read open under SCIM's way",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{
					"TestRevocationSuiteMemberFormWhole", "TestRevocationSuiteMemberFormFailsARevokedMemberStillReading", "TestRevocationSuiteMemberFormNeedsBothWays",
				}},
				gateFaultTests("TestRevocationSuiteMemberForm"),
				{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{"TestRevocationSuiteMemberFormOnT3"}},
				{Repo: "server", Package: "./api", Stores: true, Names: []string{"TestRevocationSuiteMemberFormOnServersSequencer"}},
			},
		},
		&GateItem{
			Item:  "FS-43 as QUOTA-M6-04 wrote it, on a fake Stripe and server's rows in a fixed order: FI-13 (b) after every step, and an old version refused after a newer; the row above stays the catalog's T2 run under every write's lost answer, which nothing has written",
			Tests: []*GateTest{gatePendingTests("./controller", "TestFs43StripeMeters", "TestFs43OracleRefusesAnOldVersionAfterANewer")},
		},
		&GateItem{
			Item: "FS-51 as QUOTA-M6-05 and DNS-M6-07 wrote it, on Postgres: a Team and a Pro lapse, a renewal inside the grace, releases in order under a lower tier, a killed pass resumed, and custom hosts withheld and released with mail still arriving; the row above stays the catalog's T2 run, which nothing has written",
			Tests: []*GateTest{gatePendingTests("./model",
				"TestApplyNetworkDowngradesTeamLapse", "TestApplyNetworkDowngradesRenewalInsideTheGraceCancels", "TestApplyNetworkDowngradesReleasesInOrderUnderALowerTier",
				"TestApplyNetworkDowngradesProLapse", "TestApplyNetworkDowngradesResumesAKilledPass", "TestDnsWithholdCustomHostsAndReleaseThem", "TestDnsWithholdCustomHostsKeepsMailArriving",
			)},
		},
		&GateItem{
			Item: "what is written of the directory rows' T3 runs beside their rows, which wait on the convention's tests: FS-99's evs scope's mutant in server's root package (RECORD-M6-25); FS-85's ACL legs (ACL-M6-05) and FS-99's evs scope itself run with their rows, registered clauses whose T3 tests are server's api's and root package's (QD-1084)",
			Tests: []*GateTest{
				{Repo: "server", Package: ".", Tags: gateT3Tags, Stores: true, Names: []string{"TestFs99EvsScopeMutantExchangeMintingXAdminFailsOnT3"}},
			},
		},
		&GateItem{
			Item: "Team billing under FS-46's order (§20.7, §23.6's M6 row; QUOTA-M6-06): a Team's lease takes the grant, the pack and then the line, bytes at apply draw the line last, a killed edge on the line leaves the living lease, and a renewal and a downgrade keep the lines last",
			Tests: []*GateTest{
				gateFaultTests("TestFs46TeamLeaseTakesTheGrantThePackAndThenTheLine", "TestFs46TeamBytesAtApplyDrawTheLineLast", "TestFs46TeamKilledEdgeOnTheLineLeavesTheLivingLease", "TestFs46TeamRenewalAndDowngradeKeepTheLinesLast"),
				gatePendingTests("./quotahost", "TestTeamBillingFs46T3"),
			},
		},
		&GateItem{
			Item:     "§20.9's escrow benchmark again at M6's exit (§23.8)",
			Tests:    []*GateTest{gateEscrowBenchmarkTest()},
			External: gateEscrowBenchmarkExternal,
		},
		&GateItem{
			Item: "FS-86's M6 case against §16.11's cost table at the Team limit, 2,000 members and 5,000 admissions (D-TEST-17; RECORD-M6-24): a miss here blocks this gate and the owner hears then, so it is an item of its own, read apart from every other failure; the day runs in this gate's form alone, with a following daemon on the real client, since it outlasts a merge's run, and the row's T3 run at that scale is the row's T3 test above, which nothing has written",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{"TestDirectoryLoadDayAtTheTeamLimit"}, Args: []string{"-directory-load-full"}},
			},
		},
		&GateItem{
			Item:     "a live IdP run of SCIM and SSO against a Team (§23.6's M6 row)",
			External: "production and people: an identity provider's tenant, which no local run reaches",
		},
		&GateItem{
			Item:     "Stripe's meters and the Team subscription on a live account (§23.6's M6 row; FS-43's fake stands in here)",
			External: "production: a Stripe account in live mode",
		},
		&GateItem{
			Item:     "custom domains through real CAs: issuance, CAA and renewal on a customer's zone (§23.6's M6 row; FS-32's and FS-35's fakes stand in here)",
			External: "production: public CAs and a customer-signed zone",
		},
		&GateItem{
			Item:     "the 24/7 rota staffed before Team's sale (§23.6's M6 row)",
			External: "people: the on-call rota",
		},
	)
	return items
}

var (
	gateM6InSweep = RegisterGateSweep(&GateSweep{
		Gate:  "M6-in",
		Cases: gateM6InCases(DefaultCatalog()),
		Items: gateM6InItems(),
	})
	gateM6Sweep = RegisterGateSweep(&GateSweep{
		Gate:  "M6",
		Cases: gateM6Cases(DefaultCatalog()),
		Items: gateM6OutItems(DefaultCatalog()),
	})
)
