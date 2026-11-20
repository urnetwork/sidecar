// M4's reviews (TEST-M4-04; §23.4's M4 row, §23.6's M4 row, §22.17's M4 tests, §23.8's Gn-out; D-TEST-9, FI-2, FI-10,
// FI-11): the sweep `sidecar-gate M4` reports, row by row and item by item, pass, fail, missing or open, and the one
// item its entry review, `sidecar-gate M4-in`, reads beside the assembly check. Like M2's and M3's (gate_m2_out.go,
// gate_m3.go) it adds no mechanism: each row runs the tests its owners wrote, and a failure or a missing test goes back
// to the task that owns it and stays in the report until fixed.
//
// The rows are catalog.yml's M4-out cases by convention but where their tests run elsewhere (owner decision 548;
// QD-1081):
//
//   - FS-38, its forged case's twin and FS-56 run on T3 in server's controller, on sidecartest's BridgeNet with every
//     contract server's own (BRIDGE-M4-22), under that package's sidecar_pending, beside their convention T2 tests.
//   - FS-37 is no registered builder: SDK-M4-08's clauses are plain tests, on T2 here and on T3 in server's
//     taskworker/work on its model and Postgres, each on one fixed schedule on a fake clock.
//   - FS-97's personal-network cases are no registered builder either: TEAM-M4-01's clauses are plain T2 tests here, and
//     nothing runs them on T3, so the row names the convention's T3 test, which nobody has written, and reads missing.
//
// FS-19's grant and share cases, FS-21 and FS-106's page Worker case keep the convention. FS-106's page Worker case has
// no builder, only KEYS-M4-01's unit-level tests on a fake of gkm's routes and on the MLS subset, which are no run of
// the schedule, so it reads missing, and an item names what does run.
//
// A named clause test is one fixed schedule: it runs under no explorer seed, no lost answer and no twin but what its
// owner wrote, so an item beside the rules item says which rows pass on clause tests alone, and reads missing until
// their builders are registered (QD-1084's clause registry).
//
// MLS is Later (owner decision 610; QD-1040): FS-97's leaf legs left the gates, and FS-106's page Worker case is MLS
// through and through, so an item reads both open until KEYS reworks them onto deliveries.
//
// Not yet due, never passed: FS-38's shares case, FS-97's Team cases, FS-19's team and invite cases and FS-21 on a Team
// default document are M6's, and catalog.yml holds them at M6-out, so M4's report shows none of them as a row; an item
// says so.
//
// Beside the rows: §22.8's rules and FI bindings, FI-11's own evidence on both tiers, §22.7's assertions at M4 through
// the registry, CC4's intercepting proxy, S8, the escrow comparator and its benchmark harness, dark, `make size` with
// the budget ledger's size rows and the per-target memory rows, §22.9's Browsers row on the page Worker, §23.4's exit
// criteria, and what the world owes: a Claude Code cloud agent reaching a granted port, ur.io/recurd on the real site,
// the forwards on Linux and WSL2 hosts, and the trust documents.
//
// This file also holds FI-11's fixture schedule, which sidecart3 runs on T3's Net as fi11_test.go's steps run on T2's.

package fault

import (
	"context"
	"errors"
	"io"
	stdnet "net"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The catalog's name for M4's exit.
const gateM4OutGate = "M4-out"

// The tags server's controller builds BRIDGE-M4-22's T3 rows under, and taskworker/work SDK-M4-08's: the pending
// migration groups alone.
const gateM4PendingTags = "sidecar_pending"

// FS-37's clauses on T2, as SDK-M4-08's fs37_test.go runs them.
var gateFs37T2Names = []string{
	"TestFs37PageKilledWithNoUnloadReapsOnce", "TestFs37CloseBeaconReapsAtOnce", "TestFs37OldGenerationPollsKeepNothingAlive",
	"TestFs37TwoTabsReapIndependently", "TestFs37ConnectedEphemeralSurvivesAShortDisconnect", "TestFs37MemberPageRefreshingForThirtyOneDaysStaysActive",
}

// FS-37's clauses on T3, on server's lease, reap, close and idle sweep (server/taskworker/work/fs37_db_test.go).
var gateFs37T3Names = []string{
	"TestFs37PageKilledWithNoUnloadReapsOnceOnT3", "TestFs37CloseBeaconReapsAtOnceOnT3", "TestFs37OldGenerationPollsKeepNothingAliveOnT3",
	"TestFs37TwoTabsReapIndependentlyOnT3", "TestFs37ConnectedEphemeralSurvivesAShortDisconnectOnT3", "TestFs37PageWorkerRefreshingForThirtyOneDaysStaysActiveOnT3",
	"TestFs37ReapJobRunsTheReapOnT3",
}

// FS-97's personal-network clauses on T2, as TEAM-M4-01's fs97_test.go runs them.
var gateFs97T2Names = []string{
	"TestFs97WeeklyReEnrollmentForAYearStopsGrowingAfterThirteenWeeks", "TestFs97AWorkerBackByAResyncOrAReAddIsNeverRevoked",
	"TestFs97AWorkerNoGroupOfTheDeviceSeatedIsNeverRevoked", "TestFs97AKillBetweenTheRevocationsAndTheAdmissionLandsEachOnce",
	"TestFs97AWorkerThatResyncsBeforeThePostOrDuringARetryIsNotRevoked",
}

// The cases of M4 that pass on their owners' clause tests alone, with no registered builder: see the file header.
var gateM4ClauseRows = []string{"FS-37", "FS-97"}

// A case's tests with its T3 run named in server's packagePath under tags, the convention's T2 test kept. names empty
// takes the convention's T3 name.
func gateCaseT3ElsewhereTagged(testCase *Case, packagePath string, tags string, names ...string) []*GateTest {
	tests := gateCaseT3Elsewhere(testCase, packagePath, names...)
	for _, test := range tests {
		if test.Repo == "server" {
			test.Tags = tags
		}
	}
	return tests
}

// Where M4's cases run their tests outside the convention: see the file header. A case the catalog does not hold
// panics, as its sweep's registration would.
func gateM4Cases(catalog *Catalog) map[string][]*GateTest {
	caseOf := func(rowId string, caseName string) *Case {
		testCase := catalog.Case(rowId, caseName)
		if testCase == nil {
			panic("M4's sweep names " + rowId + " " + caseName + ", which the catalog does not hold")
		}
		return testCase
	}
	cases := map[string][]*GateTest{}

	for _, place := range []struct {
		rowId    string
		caseName string
	}{
		{rowId: "FS-38"},
		{rowId: "FS-38", caseName: "forged"},
		{rowId: "FS-56"},
	} {
		testCase := caseOf(place.rowId, place.caseName)
		cases[testCase.String()] = gateCaseT3ElsewhereTagged(testCase, "./controller", gateM4PendingTags)
	}

	cases[caseOf("FS-37", "").String()] = []*GateTest{
		{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: gateFs37T2Names},
		{Repo: "server", Package: "./taskworker/work", Tags: gateM4PendingTags, Stores: true, Names: gateFs37T3Names},
	}

	// the convention's T3 entry, which reads missing until TEAM-M4-01's schedule has a builder a T3 test runs
	fs97 := caseOf("FS-97", "")
	cases[fs97.String()] = []*GateTest{
		{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: gateFs97T2Names},
		{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{GateT3TestName(fs97)}},
	}
	return cases
}

// The later cases of M4's rows, which catalog.yml holds at a later gate: each as its case and that gate.
func gateM4LaterCases(catalog *Catalog) []string {
	return gateLaterCases(catalog, gateM4OutGate)
}

// Every item of M4's exit: the rules and the oracles, the privacy rows, the fixtures and scenario, the dark escrow
// build, the size and memory budgets, the browsers, §23.4's exit criteria, then what is not yet due and what the world
// owes.
func gateM4OutItems(catalog *Catalog) []*GateItem {
	items := []*GateItem{
		gateRulesItem(catalog, gateM4OutGate),
		{
			Item: "the rows that pass on clause tests alone run under no explorer seed, lost answer or twin but their owners': " + strings.Join(gateM4ClauseRows, " and ") +
				" are plain tests on one fixed schedule each, with no registered builder (SDK-M4-08, TEAM-M4-01), so §22.8's rules above do not reach them until each has one (QD-1084's clause registry)",
		},
		gateInvariantsItem(gateM4OutGate),
		{
			Item: "FI-11, path integrity, answers through TEST-M4-01's oracle on both tiers: a byte before a backend's audience check or after its flow's revocation fails at the step it arrived in, a positive twin must reach its backend admitted, and a proof is held to its MX's own transactions, read after every step on T2's Net and on T3's",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{
					"TestFi11FailsAByteBeforeTheAudienceCheck", "TestFi11FailsAByteAfterARevocationSwap", "TestFi11PassesATwinThatReachesTheBackend", "TestFi11FailsAProofTheMxRefused",
					"TestFi11FixtureReadsEachCaseOnT2",
				}},
				{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{"TestFi11RunsAfterEveryStepOnT3"}},
			},
		},
		{
			Item: "FS-38 and FS-56 read FI-11 from the path's own bytes, a RecordingBackend over BridgeNet's upstream, which nothing has built: both still check their NAT's dials through FsBridgePathIntegrity, the bridge world's own account (BRIDGE-M4-22, TEST-M4-01)",
		},
	}
	items = append(items, gatePrivacyItems(sidecartest.DefaultPrivacyAsserts(), gateM4OutGate)...)
	if 0 < len(gateStoreClockCases(catalog, gateM4OutGate)) {
		items = append(items, gateStoreClockItem(catalog, gateM4OutGate))
	}
	items = append(items,
		&GateItem{
			Item: "CC4's TLS-intercepting proxy, a cloud sandbox's stand-in with its own CA (§22.7; TEST-M4-02): every byte it decrypts reaches the capture, canaries stay sealed inside, a bearer token is declared, and what it cannot capture it refuses",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{
					"TestInterceptingProxyCapturesWhatItDecrypts", "TestInterceptingProxyTerminatesTlsWithItsOwnCa", "TestInterceptingProxyRefusesWhatItCannotCapture",
					"TestInterceptingProxyListensForAClientThatDialsByAddress",
				}},
			},
		},
		&GateItem{
			Item: "S8, reach a subnet (§22.7; §3.7's F7; BRIDGE-M4-22): the flow under the scenario harness on T2, and on T3 with every contract server's controller's",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/scenario", Names: []string{"TestScenarioS8"}},
				{Repo: "server", Package: "./controller", Tags: gateM4PendingTags, Stores: true, Names: []string{"TestScenarioS8OnT3", "TestBridgeFlowPathReadsNoPostgresOnT3"}},
			},
			External: "production: S8's T6 cell in main, dark, which tests/sidecar-main.sh skips while its gates are off (TEST-M4-03)",
		},
		&GateItem{
			Item: "witnesses' control contracts (§23.6's M4 closure; D-PROTO-18; PROTO-M4-03): a control contract carries Hello, HeadCheck and its proof and no data, an unset class reads as control, and a stream opened on one is denied; FS-21 is its schedule above",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{
					"TestContractClassTable", "TestControlContractCarriesHelloAndHeadCheckOnly", "TestUnsetContractClassIsControl", "TestContractClassReadPerFrame",
					"TestControlBothWaysOpenStreamAnswersDenied", "TestControlContractRejectsStreamOpenDenied",
				}},
			},
		},
		&GateItem{
			Item: "the escrow comparator, dark (§23.4's M4 row; D-QUOTA-9, §20.9; QUOTA-M4-01): one strict total draw order, its reads with the gate off today's, and the gate refusing on without MG6's index and off under a live team_credit line",
			Tests: []*GateTest{
				{Repo: "server", Package: "./model", Stores: true, Names: []string{
					"TestEscrowDrawLessTable", "TestEscrowDrawLessIsAStrictTotalOrder", "TestEscrowDrawOrderReadsGateOffAreTodays", "TestEscrowDrawOrderGateNeedsMg6",
					"TestEscrowDrawOrderGateOffWithoutAName", "TestEscrowDrawOrderGateRefusesOffUnderALiveLine",
				}},
			},
		},
		&GateItem{
			Item: "§22.8's escrow benchmark harness, dark (QUOTA-M4-03; §20.9's gate, owner decision 92): admission and settlement measured with escrow_draw_order off and on in a database of the run's own, the gate adding no round trip to an admission, an added one counted, and escrowbench's verdict on two builds' files; M6's entry reads its run at twice the Y1 rates beside FS-46",
			Tests: []*GateTest{
				{Repo: "server", Package: "./model", Tags: gateM4PendingTags, Stores: true, Names: []string{"TestEscrowBenchmarkMeasurements", "TestEscrowBenchmarkCountsAnAddedRoundTrip"}},
				{Repo: "server", Package: "./cli/escrowbench", Names: []string{
					"TestEntryPassesWithinFivePercent", "TestEntryFailsAnAddedRoundTrip", "TestEntryFailsPastFivePercent", "TestFailedAttemptsAndShortRunsFail",
					"TestExitHoldsTheRerunToTheEntryRun", "TestExitFailsAnEntryRunThatIsNoYardstick", "TestRunsPacedDifferentlyFail",
				}},
			},
			External: "hardware: the evidence run on T5's performance host at twice the Y1 rates, main's baseline beside the dark build's, before M6's entry; a run on this host is a smoke, which is no evidence",
		},
		&GateItem{
			Item: "make size (§18.10, §22.9; D-SDK-20, Q-SDK-7): what the forwarding leg adds to the ios_extension leg, stripped as sdk ships it, within 7.5 MiB, the limit owner decisions 215 and 491 put where the 1 MiB gate stood, and the page Worker's sidecar_http leg within its goal or its recorded miss; a real build over a limit trips the gate. It links, and the ios_extension leg needs Xcode",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./check", Tags: "sidecar_check,sidecar_size", Names: []string{
					"TestSizeGateIosExtension", "TestSizeGateSidecarHttp", "TestSizeGateFindsATablePlantedInDevice", "TestSizeGateFindsATablePlantedInAListedRootFile",
					"TestSizeGateLeavesOutARootTableNoForwardingFileReads", "TestSizeGateFindsATablePlantedInTheRoot",
				}},
			},
		},
		&GateItem{
			Item: "the budget ledger's size rows hold make size's own numbers, ios-extension-device-role and page-worker-wasm, a raise only with a reviewed line (budgets.yml; D-TEST-3; TEST-M1-09)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./check", Tags: "sidecar_check", Names: []string{
					"TestBudgetsRiseOnlyWithAReviewedLine", "TestBudgetsFailOnARaiseWithNoReviewedLine", "TestBudgetSizeRowsHoldTheSizeGatesNumbers",
					"TestSizeVerdictsHoldTheirLimits", "TestSizeFailsOnAForwardingLegOverItsLimit", "TestSizeFailsOnSidecarHttpOverItsGoal", "TestSizeFailsOnSidecarHttpOverItsMissGate",
				}},
			},
		},
		&GateItem{
			Item:     "per-target memory, before any iOS bridge link (§18.4, §22.9; budgets.yml's memory rows: ios-sidecar-role-memory, android-sidecar-role-memory, desktop-daemon-memory, page-worker-heap), which name no test yet: each is measured on T4's cells and on T5, never on a merge (SDK-M8-15)",
			External: "hardware: T4's darwin/arm64 and Android surrogate cells, a T5 host for the daemon, and the page Worker's heap in Node and Playwright",
		},
		&GateItem{
			Item: "§22.9's Browsers row on the page Worker (§22.17's M4 tests; SDK-M4-09): pagestack serves T2's fake api, evs and gkm to the key origin alone on loopback, and a device of a vault's owner opens a record over HTTPS alone; the Playwright harness in mmm/sidecar.ur.io/test/playwright drives the key origin in a browser",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/cmd/pagestack", Names: []string{
					"TestVaultRecordOpensOverHttpsAlone", "TestFixtureIdsAnswerAtTheHarnessAddressAlone", "TestServicesHonorNothingTheFixtureDoesNotHold",
					"TestKeyOriginServesOnlyItsFilesWithItsCsp", "TestServicesAnswerCorsForTheKeyOriginAlone", "TestProxyTunnelsOnlyTheFixtureNames",
					"TestListenersBindOnlyLoopbackAboveFiftyThousand",
				}},
			},
			External: "hardware and people: the Playwright run on Chromium, Firefox and WebKit, which this build ran on Chromium alone with re-enrollment after eviction, no network by_jwt and a vault record opening in the page Worker left fixme until the Worker enrolls and reads; Safari's real 7-day cap and storage pressure",
		},
		&GateItem{
			Item: "FS-106's page Worker case and FS-97's leaf legs below their rows (KEYS-M4-01): the Worker's upkeep and the stale-leaf view at unit level on a fake of gkm's routes, and the Worker's leaf on the MLS subset; these are no run of FS-106's schedule on gkmservice, so its row above reads missing whatever they show",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{"TestAPageWorkersLeafOnTheRealSubset", "TestAPageWorkersEngineYieldsInsideAnMlsOperation"}},
			},
		},
		&GateItem{
			Item:     "the MLS legs of FS-97 and of FS-106's page Worker case left the gates with MLS (owner decision 610; QD-1040): §10.9's stale Removes, KF5's resync and KF2's re-add, path-only and external commits, GroupInfo, KeyPackages, epochs and acks; until KEYS reworks both rows onto deliveries their drafted clauses still run, so a pass there counts only what v0's wraps keep",
			External: "people: the review phase's rework of FS-97 and FS-106's page Worker case onto deliveries, and design-records' fold of owner decision 610 into §22.8's two rows",
		},
		&GateItem{
			Item: "suspension within one epoch (§23.4's M4 exit; §8.6, D-ACL-8; ACL-M4-04): the contract gate holds a suspension within its head's interval, a suspend swaps the policy before its other effects, and a suspended device's keys and delegations drop until the unsuspend",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{
					"TestAclContractGateHoldsASuspensionWithinItsHeadsInterval", "TestAclSuspendEffectsSwapThePolicyFirst", "TestAclSuspendEffectsRetryIsANoOp",
					"TestAclSuspendSigners", "TestAclSuspendAndUnsuspendInBothOrders", "TestAclSuspendDropsTheDelegationsKey", "TestAclGateHonorScopeClosesAtASuspend",
				}},
			},
		},
		&GateItem{
			Item:     "forwards, private IPs and model servers behind approved, expiring grants (§23.4's M4 exit; §17 v0): the exit scenario, a forward behind an approved grant that then expires and a tagged ephemeral cloud-agent sidecar over the userspace stack, which no test runs yet (BRIDGE-M4-22's to add); FS-19's grant case, FS-38, FS-56 and S8 above show its parts",
			External: "hardware: the forwards and private IPs on Linux and WSL2 hosts, since this host runs darwin",
		},
		&GateItem{
			Item:     "a Claude Code cloud agent reaches a granted port (§23.4's M4 exit; §18.9)",
			External: "production and people: a real cloud sandbox's agent behind its proxy, which the intercepting-proxy fixture above only stands in for",
		},
		&GateItem{
			Item:     "ur.io/recurd opens a vault record (§23.4's M4 exit; §18.8; owner decisions 219, 223)",
			External: "production: the real site and its key origin, where the page Worker enrolls by hand-off from the ur.io session; here a device of the owner opens the fixture's record over HTTPS alone (the Browsers item above)",
		},
		&GateItem{
			Item:     "trust documents drafted (§23.4's M4 exit; D-TRUST-4)",
			External: "people: the owner's drafts, which no test reads",
		},
	)
	if later := gateM4LaterCases(catalog); 0 < len(later) {
		items = append(items, &GateItem{
			Item:     "not yet due at M4, and shown here as no row and no pass: " + strings.Join(later, ", ") + " (§23.6's gate map)",
			External: "a later gate: each case passes at the gate catalog.yml holds it at, FS-38's shares and FS-97's Team cases at M6's exit among them",
		})
	}
	return items
}

var gateM4Sweep = RegisterGateSweep(&GateSweep{
	Gate:  "M4",
	Cases: gateM4Cases(DefaultCatalog()),
	Items: gateM4OutItems(DefaultCatalog()),
})

// M4's entry review reads its design closure, which a person signs.
var gateM4InSweep = RegisterGateSweep(&GateSweep{
	Gate: "M4-in",
	Items: []*GateItem{
		{
			Item:     "§23.6's M4 design closure: witnesses' control contracts (§6, §8); C13's sealed source and the dial fence (§17); HTTP liveness (§18); the page Worker; the escrow comparator and index (D-QUOTA-9; §20); Q-BRIDGE-2, Q-SDK-5; the forwarding leg's file list and budget, Q-SDK-7's (§4.7, §18.10; owner decisions 197, 215, 216, 491)",
			External: "people: the Gn-in review reads and signs the closure (§23.8)",
		},
	},
})

// How FI-11's fixture drives its one backend.
type Fi11FixtureCase string

const (
	// The audience check passes, a request reaches the backend and is echoed: clean.
	Fi11FixtureTwin Fi11FixtureCase = "twin"
	// A request reaches the backend before its audience check: fails at the step it arrived in.
	Fi11FixtureBeforeCheck Fi11FixtureCase = "before-check"
	// A byte reaches the backend after its flow's revocation swapped in: fails at that step.
	Fi11FixtureAfterRevocation Fi11FixtureCase = "after-revocation"
	// A positive twin whose backend nothing reaches: fails at the end.
	Fi11FixtureDeadPath Fi11FixtureCase = "dead-path"
)

type Fi11FixtureSettings struct {
	// How long one loopback exchange inside a step may take before the step fails: a guard, never the proof.
	ExchangeTimeout time.Duration
}

func DefaultFi11FixtureSettings() *Fi11FixtureSettings {
	return &Fi11FixtureSettings{
		ExchangeTimeout: 8 * time.Second,
	}
}

// The step at which each failing case of FI-11's fixture fails: Result.FailedStep, -1 for the end.
func Fi11FixtureFailedStep(fixtureCase Fi11FixtureCase) int {
	switch fixtureCase {
	case Fi11FixtureBeforeCheck:
		return 1
	case Fi11FixtureAfterRevocation:
		return 4
	default:
		return -1
	}
}

var errFi11FixtureNoBackend = errors.New("FI-11's fixture has no backend, which its first step makes")

// FI-11's own schedule, a fixture both tiers run (sidecart3 on T3's Net): one RecordingBackend on the run's Net,
// echoing what reaches it, a client on loopback, and the world's audience check moved as fixtureCase says, FI(11)
// checked after every step. settings nil takes the defaults.
func Fi11BackendSchedule(fixtureCase Fi11FixtureCase, settings *Fi11FixtureSettings) Builder {
	if settings == nil {
		settings = DefaultFi11FixtureSettings()
	}
	return func(net *Net) *Schedule {
		var backend *sidecartest.RecordingBackend
		var conn stdnet.Conn
		setup := &Step{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
			backendSettings := sidecartest.DefaultRecordingBackendSettings()
			backendSettings.Name = "the fixture's private backend"
			backendSettings.Serve = sidecartest.RecordingBackendEcho
			backendSettings.MustReach = fixtureCase == Fi11FixtureTwin || fixtureCase == Fi11FixtureDeadPath
			created, err := sidecartest.NewRecordingBackend(net, backendSettings)
			if err != nil {
				return err
			}
			backend = created
			return nil
		}}
		// sends data and reads its echo, so it arrived within the step
		send := func(data string) *Step {
			return &Step{Actor: "client", Action: func(ctx context.Context, net *Net) error {
				if backend == nil {
					return errFi11FixtureNoBackend
				}
				if conn == nil {
					dialer := &stdnet.Dialer{Timeout: settings.ExchangeTimeout}
					dialed, err := dialer.DialContext(ctx, "tcp", backend.Addr().String())
					if err != nil {
						return err
					}
					conn = dialed
				}
				conn.SetDeadline(time.Now().Add(settings.ExchangeTimeout))
				if _, err := conn.Write([]byte(data)); err != nil {
					return err
				}
				echoed := make([]byte, len(data))
				_, err := io.ReadFull(conn, echoed)
				return err
			}}
		}
		audience := func(audience sidecartest.RecordingBackendAudience, reason string) *Step {
			return &Step{Actor: "world", Action: func(ctx context.Context, net *Net) error {
				if backend == nil {
					return errFi11FixtureNoBackend
				}
				backend.SetAudience(audience, reason)
				return nil
			}}
		}
		hangUp := &Step{Actor: "client", Action: func(ctx context.Context, net *Net) error {
			if conn != nil {
				conn.Close()
			}
			return nil
		}}
		admitted := audience(sidecartest.RecordingBackendAdmitted, "the listener's audience check passed")
		steps := []*Step{setup}
		switch fixtureCase {
		case Fi11FixtureBeforeCheck:
			steps = append(steps, send("GET / HTTP/1.1\r\n"))
		case Fi11FixtureAfterRevocation:
			steps = append(steps, admitted, send("admitted"), audience(sidecartest.RecordingBackendRevoked, "a SidecarRevoke swapped the policy"), send("x"))
		case Fi11FixtureDeadPath:
			steps = append(steps, admitted)
		default:
			steps = append(steps, admitted, send("the twin's request"))
		}
		steps = append(steps, hangUp)
		return &Schedule{Id: "FI-11's backend fixture, " + string(fixtureCase), Steps: steps, Check: []Invariant{FI(11)}, Tiers: []Tier{TierT2, TierT3}}
	}
}
