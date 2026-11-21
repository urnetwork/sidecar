// M5's reviews (TEST-M5-02; §23.4's M5 row, §23.6's M5 row, §22.17's M5 tests, §23.8's Gn-out; D-TEST-9, FI-11,
// FI-12): the sweep `sidecar-gate M5` reports, row by row and item by item, pass, fail, missing or open, and the one
// item its entry review, `sidecar-gate M5-in`, reads beside the assembly check. Like every sweep before it
// (gate_m4.go, gate_m6.go) it adds no mechanism: each row runs the tests its owners wrote, and a failure or a missing
// test goes back to the task that owns it and stays in the report until fixed.
//
// None of M5's own rows has a registered builder. Each is named by the tests its owners wrote for the row, where they
// run, with that package's tags (owner decision 548; QD-1081), a named clause test being one fixed schedule:
//
//   - FS-25's dns-route case runs on T3 alone, in server's api through the real POST /dns/records (MCP-M5-01).
//   - FS-34 runs on T2 through the front's own table in the sidecar package and through the whole edge path in
//     sidecartest, and on T3 in server's cli/tlsedge on the block and the production front (TLS-M5-25, TLS-M5-26).
//   - FS-39's report-intake case runs on T2 in smtpedgeservice, with the canary's listener half in mxedgeservice and
//     the joint run in sidecartest (SMTP-M5-05, MAIL-M5-04). What its owners ran on Postgres, which the catalog does
//     not ask for, is an item.
//   - FS-41's and FS-42's M5 steps run on T3 where SOCK, TLS, DNS and OPS wrote each: listeners back by their next
//     heartbeat in cli/sockets, the kill switch through a Redis loss and a Postgres restore in cli/tlsedge, the dns
//     step and the labels step through both edges in cli/dns with the reclaim's rows in model, and the frame's order
//     in sidecarrestore. The run through xops's real dumps skips outside server/local/sidecar-restore-t3/run.sh,
//     which reads open, never pass.
//   - FS-47's §21 case runs on T3 in server's quotahost, model and controller (QUOTA-M5-01, ABUSE-M5-19). Nothing
//     runs it on T2, where the catalog also puts it, so the row keeps the convention's T2 test, which nobody has
//     written, and reads missing.
//   - FS-48 and FS-49 are T2 in the catalog, which §22.5's §21 row reads as pure tests of server's abuse policy and
//     clock on an injected clock, whose schedules also run against Postgres: both run in server's model, FS-49's pages
//     in controller, and FS-48's --now and erasure cases in sidecar's evsservice and gkmservice (ABUSE-M5-21).
//   - FS-52 runs on T3 in server's cli/dns (DNS-M5-24).
//
// The hold cases of FS-66, FS-69, FS-76, FS-78 and FS-92 keep the convention: catalog.yml holds each at the later of
// M5-out and M10-out, so each reads open here on M10's exit and is TEST-M10-06's to pass, and an item says so.
//
// Beside the rows: §22.8's rules and FI bindings, with the rows that pass on clause tests alone named; §22.7's
// assertions at M5 through the registry, its synthesized-dmarc row registered by this sweep to the test DNS wrote for
// it (sidecartest's dns_privacy_asserts.go), CC4's edge sources with the leak leg and the certificate and scope
// asserts (TEST-M5-01); S5 and §23.4's exit criteria, passthrough publish, the kill switch within 5 s and the CT and
// zone watches; S7's SNI-less abuse@<root> case, which §22.17 runs at M5 and whose other cases are M7's; §22.5's §21
// row as ABUSE-M5-21 reports it; the two nameservers and §22.9's DNS row; §22.9's ACME row on Pebble at 5% bad
// nonces, which is sidecartest.StartPebble's default and the local stack's, confirmed here as run and never set here;
// §13.7's browser rows as the front's Go tests show them, the Playwright run open; the inline paths and the CROSSSLOT
// lints on M5's engines; the tls meter; the load harnesses' scaled runs; FS-50's M5 pages; and what the world owes:
// counsel on holds, the dns edge hosts, LE staging, CT on real logs, platform names and company MX off ur.network,
// and the rota.
// FS-55 is the every gate's, which the tool runs at each exit review with this gate's migration group.

package fault

import (
	"fmt"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The catalog's name for M5's exit.
const gateM5OutGate = "M5-out"

// The tags server's cli/tlsedge builds FS-34's T3 run under: the pending migration groups, and the hooks, which hand
// the block's stream to the front.
const gateM5FrontTags = "sidecar_pending,sidecar_testhooks"

// The cases of M5 that pass on their owners' clause tests alone, with no registered builder: see the file header.
var gateM5ClauseRows = []string{"FS-25's dns-route", "FS-34", "FS-39's report-intake", "FS-41's m5", "FS-42's m5", "FS-47's section-21", "FS-48", "FS-49", "FS-52"}

// The rows whose T2 run is a pure test of server's policy on an injected clock, on no store and no fake of sidecartest's
// (§22.5's §21 row: "FS-48's and FS-49's T2 are pure tests of server's abuse policy and clock on an injected clock,
// whose schedules also run against Postgres"), so no test in this repo can be their T2 run.
var gateServerPolicyT2Rows = []string{"FS-48", "FS-49"}

// Pure tests of server's model, on no store: built with the pending groups linked, as every other entry of this gate
// in that package is, so one build of its tests serves them all.
func gateServerPolicyTests(names ...string) *GateTest {
	return &GateTest{Repo: "server", Package: "./model", Tags: "sidecar_pending", Names: names}
}

// The rows whose hold cases sit at the later of M5-out and M10-out, FS-69 and FS-92 whole.
var gateM5HoldRows = []string{"FS-66", "FS-69", "FS-76", "FS-78", "FS-92"}

// Tests of the sidecar package, which run under no tag.
func gateSidecarTests(names ...string) *GateTest {
	return &GateTest{Repo: "sidecar", Package: ".", Names: names}
}

// The later cases of the catalog gate's rows, which catalog.yml holds at a later gate alone: each as its case and
// that gate.
func gateLaterCases(catalog *Catalog, gate string) []string {
	rowIds := []string{}
	for _, testCase := range catalog.GateCases(gate) {
		if !slices.Contains(rowIds, testCase.Row.Id) {
			rowIds = append(rowIds, testCase.Row.Id)
		}
	}
	later := []string{}
	for _, rowId := range rowIds {
		for _, testCase := range catalog.Row(rowId).Cases {
			if slices.Contains(testCase.Gates, gate) {
				continue
			}
			due := false
			for _, caseGate := range testCase.Gates {
				if gateOrder(gate) < gateOrder(caseGate) {
					due = true
				}
			}
			if due {
				later = append(later, fmt.Sprintf("%s at %s", testCase, strings.Join(testCase.Gates, " and ")))
			}
		}
	}
	return later
}

// FS-41's and FS-42's M5 socket step, which both rows run: after Redis loses every key, listeners come back by their
// next heartbeat with no other action.
func gateM5SocketStepTest() *GateTest {
	return &GateTest{Repo: "server", Package: "./cli/sockets", Stores: true, Names: []string{"TestT3RedisLossHealsByTheNextHeartbeat"}}
}

// Where M5's cases run their tests outside the convention: see the file header.
func gateM5Cases(catalog *Catalog) map[string][]*GateTest {
	caseOf := func(rowId string, caseName string) *Case {
		return gateCaseOf(catalog, rowId, caseName)
	}
	cases := map[string][]*GateTest{}

	// the two gate legs and the cancel through the real route, its zone write the gated effect
	cases[caseOf("FS-25", "dns-route").String()] = []*GateTest{
		gatePendingTests("./api", "TestFs25RouteResponseLostAfterCommit", "TestFs25RouteTwoApiInstancesRacing", "TestFs25RouteCancelRefusesTheRest"),
	}

	cases[caseOf("FS-34", "").String()] = []*GateTest{
		gateSidecarTests("TestTlsFrontZeroBytesBeforeAuthentication"),
		{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{"TestTlsFrontSuiteNoByteReachesAPrivateAudiencesService"}},
		{Repo: "server", Package: "./cli/tlsedge", Tags: gateM5FrontTags, Stores: true, Names: []string{"TestT3Fs34NoByteReachesAPrivateAudiencesService"}},
	}

	cases[caseOf("FS-39", "report-intake").String()] = []*GateTest{
		{Repo: "sidecar", Package: "./smtpedgeservice", Names: []string{
			"TestReportIntakeCountsAGzipXmlAggregateOncePerReporterAndReportId", "TestReportIntakeCountsAGzipJsonTlsRptAggregateOnce",
			"TestReportIntakeUnverifyingReporterCountsNothing", "TestReportIntakeUnknownTokenDropsUnread", "TestReportIntakeArfBodyCanaryInNoLogRowOrMetric",
			"TestAggregateGzipXmlParsesToRows", "TestAggregateGzipTlsRptJsonParsesToRows",
		}},
		{Repo: "sidecar", Package: "./mxedgeservice", Names: []string{"TestPlatformCanaryReachesNoLogOrMetric"}},
		{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestPlatformScenarioArfCanaryJointWithReportIntake"}},
	}

	// FS-41's M5 step: CT replay re-binds a label allocated after the dump, and TLS endpoints re-register
	cases[caseOf("FS-41", "m5").String()] = []*GateTest{
		gatePendingTests("./cli/dns", "TestFs42DnsStepThroughBothEdges"),
		gatePendingTests("./model", "TestDnsCtReplayInsertsOnlyMissingNames", "TestDnsLabelReclaimRebindsTheName", "TestDnsLabelReclaimRefusals"),
		gateM5SocketStepTest(),
		gatePendingTests("./cli/tlsedge", "TestT3TlsedgeKillsHoldThroughARedisLoss"),
		{Repo: "server", Package: "./sidecarrestore", Names: []string{"TestLabelsStepSchedulesEachRootsReplayFromTheSidecarDump"}},
	}

	// FS-42's M5 step: labels re-bind and TLS endpoints re-register, a kill, a suspension and a lift mailed after
	// the dump hold through the edges' first reloads, and §19.10's dns step, every clause
	cases[caseOf("FS-42", "m5").String()] = []*GateTest{
		gatePendingTests("./cli/dns", "TestFs42DnsStepThroughBothEdges", "TestFs42DnsStepOnTheRestoreFrame", "TestFs42DnsStepPersistsAnNsStopAcrossRerun"),
		gatePendingTests("./cli/tlsedge", "TestT3TlsedgeKillsHoldThroughAPostgresRestore", "TestT3TlsedgeTakesASnapshotAfterALabelMapRestore"),
		gateM5SocketStepTest(),
		{Repo: "server", Package: "./sidecarrestore", Names: []string{
			"TestM5StepsAreRegisteredInTheProcesssFrame", "TestM5StepsRunInTheFramesOrder", "TestAbuseStepPlansFirstAndAppliesOnlyWhenTold",
			"TestM5StepsSkipADatabaseBeforeMg5AndRefuseAnUnlinkedBinary", "TestDnsStepRunsEachRootToItsEndUnderTheIncident",
			"TestLabelsStepSchedulesEachRootsReplayFromTheSidecarDump",
		}},
	}

	// FS-47's §21 case: the convention's T2 test, which nobody has written, beside its T3 run on quota's and
	// abuse's real rows
	fs47 := caseOf("FS-47", "section-21")
	cases[fs47.String()] = []*GateTest{
		gateFaultTests(GateT2TestName(fs47)),
		gatePendingTests("./quotahost", "TestFs47T3ClosureGrowthReads", "TestFs47T3ReviewedTightening"),
		gatePendingTests("./model", "TestAbuseClosureGrowthOpensOneCaseAndNoAction", "TestNetworkSidecarLimitRefusesFloorAndPacingRows", "TestNetworkSidecarLimitDirectRowsClampedOrIgnored"),
		gatePendingTests("./controller", "TestTightenNetworkLimitWritesRowsALiftClears"),
	}

	cases[caseOf("FS-48", "").String()] = []*GateTest{
		gateServerPolicyTests("TestLegalHoldDeadlinesFollowTheStatutes", "TestFs48EraseAndNowReadNoHoldKind"),
		gatePendingTests("./model", "TestFs48HoldsAcrossTheirDeadlinesOnPostgres"),
		{Repo: "sidecar", Package: "./evsservice", Names: []string{
			"TestRepoShredUnderAHoldKeepsCiphertextAndDeletesKeys", "TestEraseUnderAHoldDestroysAVersionlessPathsKeyAndKeepsItsCiphertext",
		}},
		{Repo: "sidecar", Package: "./gkmservice", Names: []string{"TestGkmHoldPausesEverySweepButNotShredGroup"}},
	}

	cases[caseOf("FS-49", "").String()] = []*GateTest{
		gateServerPolicyTests("TestFs49WeekendClocks"),
		gatePendingTests("./model", "TestFs49WeekendClocksOnPostgres"),
		gatePendingTests("./controller",
			"TestFileAbuseNoticePagesEveryClassOnASaturdayNight", "TestFileAbuseNoticeRegistrarAt0200PagesBothWithNoEscalationWait",
			"TestAbuseClockPassCountsOverdueReviewsAndLiftsNothing",
		),
	}

	cases[caseOf("FS-52", "").String()] = []*GateTest{
		gatePendingTests("./cli/dns", "TestFs52BlocksNAndNextServeTogetherAndRollBack"),
	}
	return cases
}

// Every item of M5's exit: the rules and the oracles, the privacy rows and CC4's edge sources, the scenarios and
// §23.4's exit criteria, each area's gate, the conformance rows, the inline paths, then what is held for M10, what is
// not yet due and what the world owes.
func gateM5OutItems(catalog *Catalog) []*GateItem {
	items := []*GateItem{
		gateRulesItem(catalog, gateM5OutGate),
		{
			Item: "the rows that pass on clause tests alone run under no explorer seed, lost answer or twin but their owners': " + strings.Join(gateM5ClauseRows, ", ") +
				" are plain tests on one fixed schedule each, with no registered builder, so §22.8's rules above reach only the hold cases at this gate until each has one (QD-1084's clause registry)",
		},
		gateInvariantsItem(gateM5OutGate),
	}
	items = append(items, gatePrivacyItems(sidecartest.DefaultPrivacyAsserts(), gateM5OutGate)...)
	if 0 < len(gateStoreClockCases(catalog, gateM5OutGate)) {
		items = append(items, gateStoreClockItem(catalog, gateM5OutGate))
	}
	items = append(items,
		&GateItem{
			Item: "CC4's M5 sources (§22.7; TEST-M5-01): edge records, report parse output, Find calls, dns edge queries and a fake upstream resolver, each read by the scan and each path into each class catching a canary put through it, a private name never reaching the upstream resolver; on T3 the edge records are the rows server's own stores wrote",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{
					"TestEdgeSourcesCatchEachPathsLeakInEachForm", "TestEdgeSourcesReadACleanWorldClean", "TestEdgeRecordItemsHoldEveryField",
					"TestFindTransportCapturesACallAndChangesNothing", "TestFakeUpstreamResolverHoldsEveryQuery", "TestEdgeQueryValueDeclaredAgainstDns2PassesAtAnEdgeAlone",
					"TestDnsHarnessCapturesEveryEdgeQuery",
				}},
				{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{
					"TestT3EdgeRecordsOfServersTlsStoreAreScanned", "TestT3EdgeRecordsOfServersMxStoreAreScanned", "TestT3EdgeQueriesAndFindsAreScanned",
				}},
			},
		},
		&GateItem{
			Item: "§22.7's leak leg at M5 (TEST-M5-01, TLS-M5-25): a sidecar_leaktest build leaks into every class the scan covers, M5's edge classes among them, and a published host's name into each class, and the scan catches each, on T2 and on a T3 Net",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_leaktest", Names: []string{
					"TestEveryClassCatchesItsLeak", "TestAClassWithNoLeakFails", "TestEdgeSourcesCatchEachPathsLeakInEachForm", "TestTlsCanaryHostLeakedIntoEachClassIsCaught",
				}},
				{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags + ",sidecar_leaktest", Stores: true, Names: []string{"TestT3EveryEdgeClassCatchesItsLeak"}},
			},
		},
		&GateItem{
			Item: "§22.7's certificate and scope rows no area holds whole (TEST-M5-01; I-13, I-14): a world that keeps them passes, a planted certificate naming the network's names under a held key fails, and a device outside a scope holding its certificate, or getting its key into the scope's TLSA, fails; no tls certificate rests on a key URnetwork holds (TLS-M5-25)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{
					"TestCertificateRowsPassAWorldThatKeepsThem", "TestCertificateRowsFailAHeldKeysNetworkNames", "TestCertificateRowsFailAScopesCertificateOnAnotherDevice",
					"TestCertificateRowsFailAScopesTlsaPinningAnotherDevicesKey", "TestTlsNoCertificateRestsOnAKeyUrnetworkHolds",
				}},
			},
		},
		&GateItem{
			Item: "the schema guard at M5 (I-18): every tls field, table and Redis family maps to its row both ways, with none left planned (TLS-M5-25), and §21's columns hold no address (ABUSE-M5-21)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestTlsRowsAndFamiliesMapBothWays", "TestTlsRowsAreNoLongerPlanned", "TestTlsCanariesReachOnlyTheirRows"}},
				gatePendingTests("./model", "TestAbuseSchemaHoldsNoAddress"),
			},
		},
		&GateItem{
			Item: "S5, publish HTTPS (§22.7; §3.7's F4; §23.4's M5 exit, passthrough publish; TLS-M5-25, TLS-M5-26): each §13.7 audience admitted and Community held to 7 days, what the grants or facts do not allow refused, a visitor completing TLS on the device's key while tlsedge holds only ciphertext and the hello, a members visitor with no session reaching only edge login, the edge's Find under each audience's publish and denied with none, and a removed device's certificate revoked with its sockets ended, on T2; the passthrough and the Find on T3",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{
					"TestTlsSuiteAdmitsEachAudienceAndHoldsCommunityToSevenDays", "TestTlsSuiteRefusesWhatTheGrantsOrFactsDoNotAllow", "TestTlsSuitePassthroughCompletesTlsOnTheDeviceKey",
					"TestTlsSuiteEdgeFindPassesUnderEachAudiencesPublish", "TestTlsSuiteEdgeFindIsDeniedWithNoPublish", "TestTlsFrontSuiteMembersVisitorWithoutASessionReachesEdgeLogin",
					"TestTlsRevocationEndsARemovedDevicesCertificateAndSockets",
				}},
				gateSidecarTests("TestTlsEdgeLoginFullFlow", "TestTlsEdgeLoginRefusesBadTokens", "TestTlsEdgeLoginRefusesANonMember", "TestTlsEdgeLoginStateIsSingleUse"),
				gatePendingTests("./cli/tlsedge", "TestT3TlsedgePassthroughEndsOnTheDeviceKey"),
				{Repo: "server", Package: "./cli/sockets", Stores: true, Names: []string{"TestT3EdgeFindPassesUnderEachAudiencesPublish"}},
			},
			External: "production: S5's T6 cell in main, dark, on test roots and LE staging (§19.11)",
		},
		&GateItem{
			Item: "the kill switch within 5 s (§23.4's M5 exit; §13.9; TLS-M5-25, TLS-M5-26): new and open connections of a killed host end within five seconds on the fake clock and Find refuses too, a kill read in the middle of a Find keeps the listener's lease, and a publish ends its sweep before a kill can meet it, on T2; new and open connections on T3",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{
					"TestTlsSuiteKillSwitchEndsNewAndOpenConnectionsWithinFiveSeconds", "TestTlsSuiteKillWaitKeepsTheListenersLeaseThroughAKillReadMidFind",
					"TestTlsSuitePublishEndsItsSweepBeforeAKillCanMeetIt",
				}},
				gatePendingTests("./cli/tlsedge", "TestT3TlsedgeKillSwitchEndsNewAndOpenConnections"),
			},
		},
		&GateItem{
			Item: "the CT and zone watches alarm on a test certificate and record (§23.4's M5 exit; owner decision 98): a certificate no attestation covers and one on a key no row holds alarm while an attested one and an order in flight do not, and an operator's change to a watched record, split answers and resolvers disagreeing with the zone alarm while a requested change does not, each on fixtures",
			Tests: []*GateTest{
				gateSidecarTests(
					"TestTlsCtWatchAnUnattestedCertificateAlarms", "TestTlsCtWatchAnAttestedCertificateDoesNotAlarm", "TestTlsCtWatchAnOrderInFlightDoesNotAlarm",
					"TestTlsCtWatchATamperedAttestationAlarms", "TestTlsCtWatchACustomCertificateOnAKeyNoRowHoldsAlarms", "TestTlsComponentRunsTheCtWatch",
					"TestDnsWatchAlarmsOnAnOperatorChangeAndNotARequestedOne", "TestDnsWatchSplitAnswersAlarm", "TestDnsWatchResolversDisagreeingWithTheZoneAlarm",
				),
			},
			External: "production: CT on real logs, since staging CT is unreliable (§22.9's ACME row), and the zone watch against the production zone through two public resolvers",
		},
		&GateItem{
			Item: "S7's SNI-less abuse@<root> case, which §22.17 runs at M5 (§22.7; MAIL-M5-04, ABUSE-M5-21; S7's other cases are M7's): a reporter that sends no SNI reaches the platform listener through the lb's PROXY line and its mail reaches the intake after a 250, a connection with no PROXY header dropped, on T2; on T3 the block on the private stores, and the mail parsed header-only, dropped unread and kept nowhere, no log line or metric holding an address",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestPlatformScenarioSniLessAbuseMailReachesTheIntake", "TestPlatformScenarioDropsAConnectionWithNoProxyHeader"}},
				gatePendingTests("./mxedgehost", "TestRunHostOnThePrivateStores", "TestProxyListenerWrapTakesOnlyTheLbsConnections", "TestBlockWithNoCertificateIsNeverReady"),
				gatePendingTests("./cli/mxedge", "TestS7AbuseMailWithNoSniIsDroppedUnreadAndKeptNowhere"),
			},
		},
		&GateItem{
			Item: "FS-39's report intake on Postgres and its case leg, which the catalog does not ask for and the owners wrote (SMTP-M5-06, ABUSE-M5-09): an aggregate counted once per reporter and report id through the real store, <root>'s rows split by §12's label map, and the abuse sink opening cases by class and type and never reading a body",
			Tests: []*GateTest{
				gatePendingTests("./cli/mxedge", "TestReportIntakeCountsAnAggregateOnceOnPostgres", "TestReportIntakeSplitsRootRowsByTheLabelMapOnPostgres"),
				gatePendingTests("./model", "TestAbuseIntakeNeverReadsBody", "TestAbuseSmtpSinkOpensCasesByClassAndType", "TestAbuseSmtpSinkRefusals"),
			},
		},
		&GateItem{
			Item: "§22.5's §21 row as ABUSE-M5-21 reports it, clause by clause, beside FS-48 and FS-49 above: the composed path from the form to a second reviewer's grant, TTL sweeps on an injected clock with a held network skipped until its hold ends, an access-log row per read, every retention sweep honoring holds, a held network's deletion copying what it removes, a forged or tampered mailed record refused at the restore step, and canaries in reported mail reaching no store, log or metric",
			Tests: []*GateTest{
				gatePendingTests("./controller",
					"TestAbuseComposedPathFromTheFormToASecondReviewersGrant", "TestAbusePrivacyCanariesInReportedMailReachNoStoreLogOrMetric", "TestEveryAbuseReadLogs",
					"TestLegalHoldDeadlinesEndOnThePass", "TestParseAbuseRecordsOpensAndVerifies", "TestAbuseMailboxForgeryOpensButDoesNotVerify", "TestAbuseMailboxSealRefusesTampering",
					"TestAcceptAbuseReportKeepsNoThirdPartyData",
				),
				gatePendingTests("./model",
					"TestAbuseRetentionTtlsAtTheirBoundaries", "TestAbuseRetentionSkipsAHeldNetworkUntilItsHoldEnds", "TestAbuseRetentionResumesAStoppedPass",
					"TestAbuseReaderLogsEachReadBeforeItAnswers", "TestAbuseReaderAnswersNothingWhenItCannotLog", "TestEveryRetentionSweepHonorsHolds",
					"TestRemoveNetworkUnderAHoldCopiesWhatItRemoves",
				),
			},
		},
		&GateItem{
			Item: "the dns edge serves the user root, signed without a DS (§23.4's M5 exit; owner decision 109; §22.5's §12 row, R-DNS-7; DNS-M5-24): both NS alike at one serial, a failed or drained interface gone from every answer on both, a key set failing its self-check never serving, a challenge served at both NS within 60 s, and no name or key in the edges' queries or metrics, on T3; §22.9's DNS row beside it, delv, Unbound, Knot Resolver and BIND validating compact denial and wildcards against the KSK as a trust anchor, each reading open where its tool or image is not on the host",
			Tests: []*GateTest{
				gatePendingTests("./cli/dns",
					"TestDnsT3BothNsAnswerAlikeAtOneSerial", "TestDnsT3FailedOrDrainedInterfaceLeavesEveryAnswerOnBothNs", "TestDnsT3KeySetFailingSelfCheckNeverServes",
					"TestDnsT3ChallengeServedAtBothNsWithinSixtySeconds", "TestDnsT3NoNameOrKeyReachesTheEdgesQueriesOrMetrics",
					"TestDnsConformanceDelvValidatesAgainstTheKsk", "TestDnsConformanceUnboundValidatesAgainstTheKsk", "TestDnsConformanceKnotResolverValidatesAgainstTheKsk",
					"TestDnsConformanceBindResolverValidatesAgainstTheKsk", "TestDnsConformanceZonemasterChecksTheTestRoot",
				),
			},
			External: "hardware and production: the two dns edge hosts at the site with their own addresses (OPS-M5-04; owner decisions 69, 71, 123), zonemaster over test roots at T6, two public resolvers, and DNSSEC's 30 clean days before M7's DS (§12.6)",
		},
		&GateItem{
			Item: "§22.9's ACME row on Pebble with 5% bad nonces (TLS-M5-15, TLS-M5-25, TLS-M5-26): the rate is sidecartest.StartPebble's default, which every T2 run below takes, and the local stack's pebble's on T3, this sweep setting none; orders to a chain by DNS-01, ARI and renewal, replaces, revocation, rollover and the suite's own orders pass through the rejected nonces",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{"TestGateM5PebbleRunsAtFivePercentBadNonces"}},
				{Repo: "sidecar", Package: "./certsservice", Names: []string{
					"TestCertsAcmeOrderToChain", "TestCertsAcmeAriAndOfflineRenewal", "TestCertsAcmeReplacesNamesTheCertificateIdOnTheWire", "TestCertsAcmeRevokeWithReason",
					"TestCertsAcmeRolloverBetweenOrders", "TestCertsRunOnPebbleKeepsTheChainAndTheReason",
				}},
				{Repo: "server", Package: "./local/sidecar-stack/pebble", Names: []string{"TestPebbleServesItsDirectoryAndRoots"}},
			},
			External: "production: LE staging, which alone refuses URnetwork's account under a customer accounturi and checks CAA, and GTS and ZeroSSL (§22.9)",
		},
		&GateItem{
			Item: "§13.7's browser rows as the front's Go tests show them (§22.9's Browsers row; TLS-M5-19 to TLS-M5-21): 421 for a request naming another host than its connection's, a hello cut at every boundary and across two records, X25519MLKEM768 negotiated first, other origins' requests arriving anonymous with and without Fetch Metadata, a WebSocket passing only after the check, and the front's cookies never reaching the backend; FS-34 above is the row's private audiences without a usable ALPN. SDK-M4-09's Playwright harness drives the key origin alone and holds no spec for these rows",
			Tests: []*GateTest{
				gateSidecarTests(
					"TestTlsHttpAnswers421ForAnotherHost", "TestTlsHttpOtherOriginsArriveAnonymous", "TestTlsHttpSessionViewRows", "TestTlsHttpWebSocketPassesAfterTheCheck",
					"TestTlsHttpFrontCookiesNeverReachTheBackend", "TestTlsFrontNegotiatesX25519MLKEM768First", "TestTlsFrontServesHttpOverEachAlpn",
				),
				{Repo: "sidecar", Package: "./tlsedgeservice", Names: []string{"TestClientHelloSeedsAtEveryBoundary", "TestReadClientHelloKeepsRecordFramingVerbatim"}},
			},
			External: "hardware and people: Chrome, Firefox, Safari and curl against a published host, through Playwright specs nobody has written for §13.7's rows",
		},
		&GateItem{
			Item: "the inline paths and the CROSSSLOT lints on M5's engines (§22.5's hot-path gates, §22.4; I-12; SOCK-M5-17, TLS-M5-26, DNS-M5-24): Find one script with Postgres refused, every script of the sockets engine in one slot, tlsedge's route holding to its inline-path row with its keys sharing their slot, a route probe making no Find, and dns's Redis calls naming one hash tag",
			Tests: []*GateTest{
				{Repo: "server", Package: "./cli/sockets", Stores: true, Names: []string{"TestT3FindIsOneScriptWithPostgresRefused", "TestT3EveryScriptOfTheEngineKeepsToOneSlot", "TestT3ThreeThousandNamesInThreePages"}},
				gatePendingTests("./cli/tlsedge", "TestT3TlsedgeRouteHoldsToItsInlinePathRow", "TestT3TlsedgeKeysShareTheirSlot", "TestT3TlsedgeRouteProbeMakesNoFind"),
				gatePendingTests("./cli/dns", "TestDnsT3RedisCallsNameOneHashTag"),
			},
		},
		&GateItem{
			Item: "the tls meter end to end (§20.6; D-QUOTA-3, D-QUOTA-4; QUOTA-M5-01): a lease, its spends, a batch, the journal rows, the flush and network_service_usage on T3 under FI-13 (a), and an empty balance marking spent, Find answering quota and open streams resetting as leases run out",
			Tests: []*GateTest{
				gatePendingTests("./quotahost", "TestTlsMeterT3MoneyPath", "TestTlsMeterT3EmptyBalance"),
			},
		},
		&GateItem{
			Item: "the sockets and tlsedge load harnesses' scaled runs (§22.8; SOCK-M5-17, TLS-M5-26): in-flight share held to weight, a scaled-down connection run, and a run the harness cannot make refused",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestSocketLoadKeepsInflightToWeight", "TestTlsEdgeLoadScaledDown", "TestTlsEdgeLoadRefusesWhatItCannotRun"}},
			},
			External: "hardware: the evidence runs on T5's performance host, 100,000 listeners with about 6,700 registration calls a second and 50,000 connections per process against §13.5's setup targets; a run on this host is a smoke, which is no evidence",
		},
		&GateItem{
			Item: "FS-50's M5 pages (§19.8's M5 rows; owner decisions 134, 143; DNS-M5-17, OPS-M5-08): at 02:00 on the fake clock both nameservers failing, a broken 443 split and a registrar notice reach the rota's pager, the split paging the second person at 30 minutes unacknowledged and the notice both at once, and a failing canary signature raises its class at page tier; FS-50's row itself is M3's",
			Tests: []*GateTest{
				{Repo: "server", Package: "./monitor", Names: []string{"TestFs50M5ConditionsAt0200ReachTheRota", "TestDnsCanaryNsDownAt0200PagesAndABlindMinuteHoldsIt", "TestDnsCanaryEachFailureRaisesItsClass"}},
			},
		},
		&GateItem{
			Item: "the certificate re-order of FS-42's M5 step on T3 (TLS-M5-26's plan reading 7): a chain newer than the dump ordered again with replaces through server's certs routes, which no test this sweep found shows; the certificate manager's half is T2's TestTlsCertManagerReordersALostRowWithReplaces",
		},
		&GateItem{
			Item:     "the hold cases of " + strings.Join(gateM5HoldRows, ", ") + " (§23.6's M5 row; D-PHASE-8): the rows above read open on M10's exit, since each runs once M10's Gn-out has passed, and are TEST-M10-06's to pass, never this gate's; holds pause format 1's sweeps and GC here, in §21's row and FS-48 above",
			External: "a later gate: M10's Gn-out, where TEST-M10-06 runs each hold case against format 2 and api's real writes (ABUSE-M10-01)",
		},
		&GateItem{
			Item: "holds refuse placement until counsel confirms (§21.9; owner decision 133; §23.6's lead times): abuse.yml's holds_enabled is off until then, and a placement while it is off is refused with nothing written",
			Tests: []*GateTest{
				gatePendingTests("./model", "TestLegalHoldRefusesUntilEnabled"),
			},
			External: "people: counsel's confirmation of owner decision 133's condition and of each hold kind's applicability, preserve_2703f and report_2258a, before holds ship, with the deferral, contract-row, copyright-count and weekend-wait readings beside them (owner decisions 525, 526, 528, 529)",
		},
		&GateItem{
			Item:     "platform names and company MX off ur.network before the NS switch (§23.4's M5 exit; §12.4)",
			External: "production: the registrar's and the company's own zones, which no local run reaches",
		},
		&GateItem{
			Item:     "the LE domain override for the user root (§23.6's lead times; mmm/lag.dev/ops/letsencrypt.md)",
			External: "people and production: Let's Encrypt's rate-limit override, asked at M0 and untimed",
		},
		&GateItem{
			Item:     "abuse readiness and the rota from M5 (§19.8, §21.8; owner decisions 95, 134, 143, 498, 530): a DMCA agent, registrar and Search Console contacts, business-hours abuse review, and registrar, registry and law-enforcement notices reaching the pager through the company mailbox's rule",
			External: "people: the owner's pager service and mailbox, the registered agent and the two-person out-of-hours rota",
		},
	)
	if later := gateLaterCases(catalog, gateM5OutGate); 0 < len(later) {
		items = append(items, &GateItem{
			Item:     "not yet due at M5, and shown here as no row and no pass: " + strings.Join(later, ", ") + " (§23.6's gate map)",
			External: "a later gate: each case passes at the gate catalog.yml holds it at, FS-39's labels and S7's other cases at M7's exit among them",
		})
	}
	return items
}

var gateM5Sweep = RegisterGateSweep(&GateSweep{
	Gate:  "M5",
	Cases: gateM5Cases(DefaultCatalog()),
	Items: gateM5OutItems(DefaultCatalog()),
})

// M5's entry review reads its design closure, which a person signs.
var gateM5InSweep = RegisterGateSweep(&GateSweep{
	Gate: "M5-in",
	Items: []*GateItem{
		{
			Item:     "§23.6's M5 design closure: the ALPN audience and the custom-SNI map (§13); report parsing (§14); hold kinds and abuse clocks (§21); Q-OPS-5",
			External: "people: the Gn-in review reads and signs the closure (§23.8), re-reading M10's hold cases for this gate (D-PHASE-8)",
		},
	},
})
