// M8's exit (TEST-M8-01; §23.6's M8 row; D-TEST-9, R-TEST-8; owner decisions 12, 88, 100, 197): the sweep
// `sidecar-gate M8` reports. Like M6's and M7's (gate_m6.go, gate_m7.go) it adds no mechanism, and names a case outside
// the convention by the same rules:
//
//   - FS-36 and FS-120 have no registered schedule and run on T3 alone in the catalog: each is named by its owner's
//     tests over server's rows, and FS-36 by its T2 tests in this package beside them, which the catalog does not ask
//     for and the owner wrote.
//   - FS-82's coverage case is MAIL's tests where they run: coverage and its copy in the sidecar package, the indexer
//     paths and the prompt in sidecartest on T2 and in server's sidecart3 on T3.
//   - FS-41's and FS-42's M8 steps, push tokens, are named where their owners wrote each, on server's rows.
//
// FS-19's quick-burner run, FS-85's and FS-100's wakes and FS-98's and FS-124's app-host cases keep the convention: their
// T2 tests carry its names, and their T3 tests are not written, so those rows read missing (the app-host cases' server
// tests run on server's sequencer alone, under another name). The app-host cases of FS-77, FS-83, FS-109, FS-110 and
// FS-125 keep it too: they sit at the later of M8-out and M10-out. A case with a T4 part reads open on it whatever its
// tests do: T4's cells are SDK-M8-15's and report through the ledger, never through this tool.
//
// Beside the rows: §22.8's rules and FI bindings; §22.7's wake row and its MX scope row through the registry, the wake
// row on what FakeWakeVendor was sent as a CC4 source (privacy_wake.go); the ledger's T4-16 closed on BridgeNet, a
// carrier resolver inside 100.64/10 keeping its /32 carve (bridge_net_carrier.go); §22.5's forwarding cases; the mail
// indexer paths and prompt; and what devices, production and people owe. Two traps are items so no reader takes them
// for failures: a foreground-only coverage shows copy and fails nothing, since release readiness is never a per-user
// gate (owner decision 12), and §18.4's budgets rest on surrogates with no iPhone (owner decision 100). R-TEST-8's
// census gate is BS1's and reads open until the owner calls it.

package fault

import (
	"github.com/urnetwork/sidecar/sidecartest"
)

// The catalog's name for M8's exit.
const gateM8OutGate = "M8-out"

// The mail indexer paths and the prompt on T2 and T3 (MAIL-M8-10), which FS-82's coverage case and an item both run.
func gateMailIndexerPathTests() []*GateTest {
	return []*GateTest{
		{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{"TestMailM8IndexerPathsTakeMailAndEndThePrompt"}},
		{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{"TestT3MailM8IndexerPathsTakeMailAndEndThePrompt"}},
	}
}

// Where M8's cases run their tests outside the convention: see the file header.
func gateM8Cases(catalog *Catalog) map[string][]*GateTest {
	caseOf := func(rowId string, caseName string) *Case {
		return gateCaseOf(catalog, rowId, caseName)
	}
	cases := map[string][]*GateTest{}

	cases[caseOf("FS-36", "").String()] = []*GateTest{
		gateFaultTests(
			"TestFs36LostClientsMailHintWakesOnceAt25s", "TestFs36AckedHintIsNotWoken", "TestFs36ForcedRouterMissWakesAtOnce", "TestFs36XaddPastItsRetriesIsCountedHintIntact",
			"TestFs36KillBetweenScriptAndXaddDropsTheWakeHintIntact", "TestFs36SenderKillsGiveAtMostOneSubmissionPer10s", "TestFs36WakesResumeOnATokenPostAfterAFlush",
		),
		gatePendingTests("./model",
			"TestFs36LostClientsMailHintWakesOnceAt25sOverTheRows", "TestFs36AckedHintIsNotWokenOverTheRows", "TestFs36ForcedRouterMissWakesAtOnceOverTheRows",
			"TestFs36WakesResumeAfterAFlushOnATokenPostOrTheSentinelPass", "TestFs36TwoMastersRestartedWakesResumeAfterTheReconcile",
		),
	}
	cases[caseOf("FS-120", "").String()] = []*GateTest{
		gatePendingTests("./model",
			"TestFs120TwoPostsApplyInReverseCommitOrder", "TestFs120PostAndEmptyPostApplyInReverseCommitOrder", "TestFs120RemovalApplyInReverseCommitOrder",
			"TestFs120Vendor410RacingANewPost", "TestFs120HeldApplyExpiresThenRetryOrSweepLands", "TestFs120ReconcileBeforeDuringAndAfterAHeldApply",
			"TestFs120MasterRestartedFromAnOlderDump", "TestFs120FirstPostDuringAReconcileKeepsItsToken", "TestFs120RemovedClientsRowAndKeysGoneAt24h",
		),
	}
	cases[caseOf("FS-82", "coverage").String()] = append([]*GateTest{
		{Repo: "sidecar", Package: ".", Names: []string{
			"TestMailCoverageCopyIsTheGolden", "TestMailCoverageForegroundOnlyThenIndexer", "TestMailCoverageCountsOnlyReceiversThatRegister", "TestMailClientReceiverCoverage",
		}},
	}, gateMailIndexerPathTests()...)

	// FS-41's and FS-42's M8 steps: push tokens re-register after a site loss, and their revisions are raised past
	// a lost primary's, once an incident
	cases[caseOf("FS-41", "m8").String()] = []*GateTest{
		gatePendingTests("./model", "TestFs41PushTokensReRegister"),
	}
	cases[caseOf("FS-42", "m8").String()] = []*GateTest{
		gatePendingTests("./model", "TestFs42PushTokenRevisionsRaisedPastTheLostPrimary"),
		gatePendingTests("./sidecarrestore", "TestFs42PushTokensRaisedOncePerIncident", "TestFs42PushTokenRaiseSkippedBeforeMg8"),
	}
	return cases
}

// Every item of M8's exit: see the file header.
func gateM8OutItems(catalog *Catalog) []*GateItem {
	items := []*GateItem{
		gateRulesItem(catalog, gateM8OutGate),
		gateInvariantsItem(gateM8OutGate),
	}
	items = append(items, gatePrivacyItems(sidecartest.DefaultPrivacyAsserts(), gateM8OutGate)...)
	if 0 < len(gateStoreClockCases(catalog, gateM8OutGate)) {
		items = append(items, gateStoreClockItem(catalog, gateM8OutGate))
	}
	items = append(items,
		&GateItem{
			Item: "the ledger's T4-16 closed (HANDOFF §10; TEST-M8-01; §17.4, D-BRIDGE-12): on BridgeNet's CGNAT fixture a carrier resolver inside 100.64/10 keeps its /32 carve over UDP and TCP, also at the overlay resolver's own address, and a mutant dropping the carve fails; BRIDGE-M8-03's T6 form, tests/bridge-cgnat-fixture.sh, takes a system resolver among its carrier addresses and runs on T6's host, never here",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{
					"TestBridgeCgnatCarrierResolverKeepsItsCarve", "TestBridgeCgnatDroppingTheResolverCarveFails", "TestBridgeCgnatCarrierResolverAtTheOverlayResolversAddress",
				}},
			},
		},
		&GateItem{
			Item: "§22.5's forwarding cases (§23.6's M8 row; owner decision 197; BRIDGE-M8-06, BRIDGE-M8-07, TEAM-M8-02): the forwarding Delegation's setup and its resumes, FS-38's forwarding-key delegations with their refusals, forgeries, revocation and supersession, the app host's compile and its races, and the forward_only client's mint",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{
					"TestForwardingSetupHandsOffAfterSixSteps", "TestForwardingSetupResumesAfterEachStep", "TestForwardingSetupIsDueAtANewGenerationAndAfterNinetyDays",
					"TestForwardingSetupHandsOnNoUnmarkedClient", "TestForwardingSetupRefusesKeysItCannotTake",
				}},
				gateFaultTests(
					"TestFs38ForwardingDelegation", "TestFs38ForwardingRefusals", "TestFs38ForwardingForged", "TestFs38ForwardingRevokeEndsItsFlows", "TestFs38ForwardingSupersessionEndsItsFlows",
					"TestFwdAppHostAdmits", "TestFwdAppWithinTargets", "TestFwdAppRevokeRacesCompile", "TestFwdAppSupersedeRacesContract", "TestFwdAppCompileBelowANewerState",
					"TestFwdAppUnsuspend", "TestFwdAppNoCompile", "TestFwdAppRollback",
				),
				gatePendingTests("./controller",
					"TestFs38ForwardingOnT3", "TestFs38ForwardingRevocationOnT3", "TestFs38ForwardingForgedOnT3", "TestFwdAppHostOnT3", "TestFwdAppCompileBelowANewerStateOnT3",
					"TestFwdAppUnsuspendOnT3", "TestFwdAppNoCompileOnT3", "TestFwdAppRollbackOnT3",
				),
				gatePendingTests("./model", "TestForwardingClientMint", "TestForwardingClientMintRefusals"),
			},
		},
		&GateItem{
			Item: "the mail indexer paths and the prompt (§23.6's M8 row; MAIL-M8-10; R-MAIL-8, D-MAIL-15): an indexer path takes mail and ends the prompt, the copy shows before a first burner, a receiver enabled on a real daemon files its designation, and a forced router miss wakes the receiver once, at once",
			Tests: append(gateMailIndexerPathTests(), &GateTest{Repo: "sidecar", Package: "./sidecartest", Tags: "sidecar_testhooks", Names: []string{
				"TestMailM8CreateBurnerShowsTheCopyBeforeAFirstBurner", "TestMailM8ReceiverEnabledOnARealDaemonFilesItsDesignation", "TestMailM8Fs36ForcedRouterMissWakesTheReceiverOnceAtOnce",
			}}),
		},
		&GateItem{
			Item: "a foreground-only coverage shows its copy and fails nothing: release readiness is never a per-user gate (owner decision 12), so FS-82's coverage case reads that state as a result, never a failure",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{"TestMailCoverageCopyIsTheGolden", "TestMailCoverageForegroundOnlyThenIndexer"}},
			},
		},
		&GateItem{
			Item: "T4 joins here through the ledger (SDK-M8-15, SDK-M8-06): the surrogate cells' harness holds §18.4's budgets as assertions on this host, whose figures are no evidence for a device (owner decision 100)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/t4cell", Names: []string{
					"TestSampleCatchesATransientTheTimedSamplesMiss", "TestProfilesHoldTheSearchWorkingSets", "TestMeasureSearchCatchesAPerSearchKeyCollection", "TestKeptBytesCountSteady",
				}},
			},
			External: "devices: SDK-M8-15's ios32 and android surrogate cells and SDK-M8-06's binding gates, which run in sdk and tests and report through the ledger; jetsam on a physical iPhone stays unmeasured",
		},
		&GateItem{
			Item:     "wakes through Apple's and Google's push services to real devices (§23.6's M8 row; FakeWakeVendor stands in here)",
			External: "production and devices: APNs and FCM credentials and enrolled phones",
		},
		&GateItem{
			Item:     "R-TEST-8's census gate on burners: BS1's, open until the owner calls it on D-MAIL-9's census run (M7's item)",
			External: "people and production: the owner's call at BS1",
		},
	)
	return items
}

var gateM8Sweep = RegisterGateSweep(&GateSweep{
	Gate:  "M8",
	Cases: gateM8Cases(DefaultCatalog()),
	Items: gateM8OutItems(DefaultCatalog()),
})
