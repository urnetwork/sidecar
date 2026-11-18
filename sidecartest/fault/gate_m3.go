// M3's exit review (TEST-M3-02; §23.6's M3 row, §22.10's record.proto row, §23.8's Gn-out; D-TEST-9, FI-7, FI-8): the
// sweep `sidecar-gate M3` reports, and the next metadata cluster's, `sidecar-gate next` (the catalog's next-cluster),
// which §23.6's last row runs before place_new names a new cluster. Like M2's (gate_m2_out.go) it adds no mechanism:
// each row runs the tests its owners wrote, and a failure or a missing test goes back to the task that owns it.
//
// The rows are catalog.yml's M3-out cases by convention but where their tests run elsewhere:
//
//   - FS-25's T3 legs run in server's api on real Postgres, the gate's own transaction with a test effect in it and
//     the cancel through the real POST /approval/cancel route (§23.6's M3 row, §22.8's real rule; MCP-M3-24),
//     beside the convention's T2 test; its dns route's legs are its M5 case's.
//   - FS-41 and FS-42 on M3's mechanisms are no schedules, as FS-54 is none: FS-41 is OPS-M3-05's site loss through
//     the close, with each owner's clauses where they wrote them, TEAM-M3-02's resumed log and uploads,
//     EVSB-M2-20's re-seeds, KEYS's re-formed vault and a recovery-code device's reach; FS-42 is OPS-M3-04's
//     Postgres loss in each order of the dumps. Both run only on a host SIDECAR_RESTORE_T3=1 names (they need
//     Docker, gpg, python3 and xops), so elsewhere they skip and read open, never pass.
//   - FS-50 is no schedule either: monitor's page classes at 02:00 on a fake clock reaching the rota, the second
//     person paged at 30 minutes; the out-of-hours host return is its hosts-drill case, open on production.
//
// FS-98's and FS-124's CLI cases run by convention, their T3 tests in sidecart3 under the convention's
// sidecar_localstack (QD-1085).
//
// FS-119 keeps the convention: its composed path runs on T2 (server's file_cluster_cohort_test.go and evsservice's
// cluster_limit_test.go), and its run on T3's stores is EVSB's review phase, so its T3 row reads missing rather than
// pass on T2's evidence. FS-30's audit reader is M6's case, and FS-98's and FS-124's team and app-host cases are M6's
// and M8's.
//
// Beside the rows: §22.8's rules and FI bindings, FI-12's own evidence (TEST-M3-01), FI-7's and FI-8's oracles named
// after every step of the rows that check them, §22.10's record.proto freeze (vectors over the stored bytes, the fuzz
// targets' seeds, FS-25 to FS-29's rows), §22.7's assertions at M3, FS-115's filesystem matrix volume by volume, TLC's
// recorded runs, the ledger's named gap in FS-41 (a crash during a re-seed, TEAM-M3-02's), and what production owes:
// the nvme and hdd runs on the production hosts, a restore of a real dump generation and a re-seed drill.

package fault

import (
	"github.com/urnetwork/sidecar/sidecartest"
)

// The catalog's name for M3's exit.
const gateM3OutGate = "M3-out"

// Where M3's cases run their tests outside the convention: see the file header.
func gateM3Cases(catalog *Catalog) map[string][]*GateTest {
	caseOf := func(rowId string, caseName string) *Case {
		testCase := catalog.Case(rowId, caseName)
		if testCase == nil {
			panic("M3's sweep names " + rowId + " " + caseName + ", which the catalog does not hold")
		}
		return testCase
	}
	cases := map[string][]*GateTest{}

	fs25 := caseOf("FS-25", "")
	cases[fs25.String()] = []*GateTest{
		{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{GateT2TestName(fs25)}},
		{Repo: "server", Package: "./api", Tags: "sidecar_pending", Stores: true, Names: []string{
			"TestFs25GateResponseLostAfterCommit", "TestFs25TwoApiInstancesRacing", "TestFs25TwoUsesThreeActions", "TestFs25CancelThroughTheRouteRefusesTheRest",
		}},
	}

	cases[caseOf("FS-41", "").String()] = []*GateTest{
		{Repo: "server", Package: "./sidecarrestore", Tags: "sidecar_pending", Stores: true, Names: []string{"TestFs41SiteLossThroughTheCloseOnT3"}},
		{Repo: "server", Package: ".", Tags: "sidecar_testhooks,sidecar_pending,sidecar_filecluster_t3", Names: []string{"TestFileClusterReseedStorageLossesOnT3"}},
		{Repo: "server", Package: "./model", Stores: true, Names: []string{
			"TestAdoptConfigRunTakesWhatTwoMembersHold", "TestAdoptConfigRunTakesNoPositionOneMemberHoldsAlone", "TestAdoptConfigRunHoldsToTheRestoredHead",
			"TestAdoptedRunResumesTheLogAtUnchangedPositions", "TestAdoptConfigRunCountsOnlyMembersThatMayUpload", "TestConfigReseedIsRefusedOutsideARestore",
		}},
		{Repo: "sidecar", Package: ".", Names: []string{
			"TestConfigClientUploadsItsFullTail", "TestConfigClientUploadsAPhonesPins", "TestConfigClientUploadRefusals",
			"TestAVaultReformedByItsOwnersDeviceKeepsEveryReader", "TestAReformIsRefusedFromADeviceThatMayNotFormTheGroup",
			"TestARepoReseededAsDeletedTakesItsFormAndLadderAlone", "TestACodeOnlyDeviceReadsOnlyItsWrapsBeforeAdmission",
		}},
		{Repo: "sidecar", Package: "./sidecartest", Names: []string{
			"TestEvsReseedReturnsAMirroredRepoEndToEnd", "TestEvsReseedKeepsAnErasedKeyOutOfAStaleMirrorsSlotEndToEnd", "TestEvsReseedReturnsAPushInPartsEndToEnd",
		}},
	}

	cases[caseOf("FS-42", "").String()] = []*GateTest{
		{Repo: "server", Package: "./sidecarrestore", Tags: "sidecar_pending", Stores: true, Names: []string{"TestFs42MainDumpOlder", "TestFs42MainDumpNewer"}},
	}

	cases[caseOf("FS-50", "").String()] = []*GateTest{
		{Repo: "server", Package: "./monitor", Names: []string{"TestPageClassAt0200PagesTheSecondPersonAt30MinutesNotBefore", "TestPageReachesTheRotaThroughTheLoopSenderAndWebhook", "TestPostgresPrimaryDownPages"}},
		{Repo: "server", Package: "./monitor", Stores: true, Names: []string{"TestFileClusterPageConditionsAt0200ReachThePager"}},
	}
	return cases
}

// The schedules that must name FI-7 or FI-8 among their checks, so the oracle runs after their every step: each M3
// row that checks one, by its registered T2 case.
func gateEffectsAndAttributionRows(catalog *Catalog) map[string][]string {
	rows := map[string][]string{}
	for _, testCase := range catalog.GateCases(gateM3OutGate) {
		for _, check := range testCase.Row.Checks {
			if check == "FI-7" || check == "FI-8" {
				rows[testCase.String()] = append(rows[testCase.String()], check)
			}
		}
	}
	return rows
}

// The volumes §22.9's Restore row runs FS-115's apply on, besides the one this host's test runs on.
var gateRestoreVolumes = []string{
	"linux on ext4", "linux on xfs", "linux on an NFS mount", "windows on NTFS", "a FAT volume on darwin, linux and windows",
	"symlinks on each system, Windows with and without the symlink privilege",
}

// Every item of M3's exit: the rules and the oracles, the record.proto freeze, the privacy rows, FS-115's volumes,
// TLC, the ledger's named gap, then what production owes.
func gateM3OutItems(catalog *Catalog) []*GateItem {
	items := []*GateItem{
		gateRulesItem(catalog, gateM3OutGate),
		gateInvariantsItem(gateM3OutGate),
		{
			Item: "FI-7 and FI-8 answer through MCP-M3-24's and MCP-M3-27's oracles, bound here and named among the checks of every M3 row that checks them, so each runs after every step (TEST.md's FI table)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{"TestGateM3EffectsAndAttributionRunAfterEveryStep", "TestChecksRunAfterEveryStepAndAtTheEnd"}},
			},
		},
		{
			Item: "FI-12, recovery, answers through TEST-M3-01's oracle for FS-40, FS-41 and FS-42: each mutant its row names caught, each loss the incident lists excused and nothing else, neither dump order assumed, and its check run after every step on T2's fakes and on T3's stores, server's rows read back as its identities",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{
					"TestFi12CatchesEachMutant", "TestFi12ReadsACleanRestoreClean", "TestFi12ReadsFs40sSecondHostCaseClean", "TestFi12TakesOnlyWhatTheIncidentLists",
					"TestFi12AssumesNeitherDumpOrder", "TestFi12RunsAfterEveryStepAndFailsClosed", "TestFi12FailsAHalfRecordedRecovery",
				}},
				{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{"TestFi12RunsAfterEveryStepOnT3", "TestRecoveryIdentitiesReadServersRowsOnT3", "TestRecoveryLineKindsAreTheFramesOwn"}},
			},
		},
		{
			Item: "record.proto's bytes freeze (§22.10's M3 row; §23.8): vectors over the stored bytes, the hashed bytes and the sealed entries byte for byte on this leg, a re-encoding changing nothing a verifier checks, an unknown field and kind kept, approvers refusing an unknown version, and the fuzz targets' seeds; FS-25 to FS-29 are the rows above",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{
					"TestRecordFreezeVectorsVerifyOnThisLeg", "TestRecordFreezeBodiesAreCanonicalOnThisLeg", "TestRecordFreezeReencodingChangesNothingAVerifierChecks",
					"TestRecordFreezeReaderKeepsAnUnknownFieldAndKind", "TestRecordHashVectors", "TestRecordHashesCoverStoredBytes", "TestRecordSealedGoldenEntries",
					"TestCanonicalActionVectors", "TestRecordApprovalsRefusesAnUnknownActionVersion", "FuzzRecordHeader", "FuzzRecordEntry", "FuzzCanonicalActionBuild",
				}},
			},
		},
	}
	items = append(items, gatePrivacyItems(sidecartest.DefaultPrivacyAsserts(), gateM3OutGate)...)
	if 0 < len(gateStoreClockCases(catalog, gateM3OutGate)) {
		items = append(items, gateStoreClockItem(catalog, gateM3OutGate))
	}
	items = append(items, &GateItem{
		Item: "FS-115's apply on this host's own volume (§22.9's Restore row; MCP-M3-27): its no-replace rename, its hard-link fallback or its refusal as the volume takes them, probed first; darwin's temporary directory is APFS",
		Tests: []*GateTest{
			{Repo: "sidecar", Package: "./mcp", Names: []string{"TestRestoreConformanceVolume"}},
		},
	})
	for _, volume := range gateRestoreVolumes {
		items = append(items, &GateItem{
			Item:     "FS-115's apply on " + volume + " (§22.9's Restore row; MCP-M3-27)",
			External: "hardware: a host holding " + volume + ", running TestRestoreConformanceVolume with UR_RESTORE_VOLUME naming it, its run recorded in peers.yml",
		})
	}
	items = append(items,
		gateTlcItem(),
		&GateItem{
			Item: "the ledger's named gap in FS-41 ran (HANDOFF §10): a crash during a re-seed, TEAM-M3-02's to add, which no test shows yet",
		},
		&GateItem{
			Item:     "the nvme and hdd runs on the production hosts before they hold data, the hdd run's admitted mix included (§23.6's M3 row; D-TEST-11)",
			External: "production: the production hosts' PM9A3 set and HDD cluster",
		},
		&GateItem{
			Item:     "one restore of a real sidecar dump generation, and a re-seed drill, through §19.10's runbook (§23.6's M3 row; D-OPS-14, D-OPS-18)",
			External: "production and people: a real sidecar dump generation and the owner's drill",
		},
	)
	return items
}

var gateM3Sweep = RegisterGateSweep(&GateSweep{
	Gate:  "M3",
	Cases: gateM3Cases(DefaultCatalog()),
	Items: gateM3OutItems(DefaultCatalog()),
})

// The next metadata cluster's review (§23.6's last row): §22.9's file-cluster suite on the new cluster, beside FS-63's
// and FS-119's next-cluster cases, which catalog.yml opens on production.
var gateNextClusterSweep = RegisterGateSweep(&GateSweep{
	Gate: "next",
	Items: []*GateItem{
		{
			Item: "§22.9's file-cluster suite on the new cluster, D-OPS-20's in-house MinIO build at its pinned commit (peers.yml's File clusters row): the store suite on the local stack and on T3's 4-host layouts, then on the new cluster's own hosts",
			Tests: []*GateTest{
				{Repo: "server", Package: ".", Tags: "sidecar_localstack", Names: []string{"TestFileClustersConformOnTheLocalStack"}},
				{Repo: "server", Package: "./sidecart3", Tags: "sidecar_testhooks,sidecar_pending,sidecar_filecluster_t3", Names: []string{"TestT3LayoutTakesRequestsOnAFakeClock", "TestT3QuorumLossGives503AndAnUnknownOutcome", "TestT3DriveMissLeavesTheObjectReadableUntilASecondHostGoesDown", "TestT3AHostReturningHeals"}},
			},
			External: "production: the new cluster's own hosts, before place_new names it, each build and upgrade on them a run",
		},
	},
})
